// jvt.qnt — Jellyfish Verkle Tree Formal Specification
//
// Models the JVT combining JMT's version-based persistent storage
// with verkle tree vector commitments.
//
// Key constraint: Quint does not support recursion, so tree traversal
// is modeled as a fold over bounded depth (max 31 levels for 256-ary).

module jvt {
    import commitment.* from "./commitment"

    // ============================================================
    // Type Definitions
    // ============================================================

    type Byte = int
    type Key = List[Byte]
    type Value = int
    type Stem = List[Byte]

    // NodeKey = (version, byte_path)
    type NodeKey = { version: int, bytePath: List[Byte] }

    // Child reference in internal nodes
    type Child = { version: int, commitment: Commitment }

    // Node types: Internal, EaS, or Empty
    type Node =
        | Internal({ children: int -> Child, commitment: Commitment })
        | EaS({ stem: Stem, values: int -> Value, c1: Commitment, c2: Commitment, extC: Commitment })
        | Empty

    // Stale node index entry
    type StaleNodeEntry = { staleVersion: int, nodeKey: NodeKey }

    // Insert result (returned by pure insert logic)
    type InsertResult = {
        newStore: NodeKey -> Node,
        newRootKey: NodeKey,
        staleEntries: List[StaleNodeEntry],
        rootCommitment: Commitment
    }

    // ============================================================
    // State Variables
    // ============================================================

    var nodeStore: NodeKey -> Node
    var currentVersion: int
    var rootKeys: int -> NodeKey
    var staleIndex: List[StaleNodeEntry]
    // Tracks the latest key->value mapping for invariant checking
    var kvMap: Key -> Value

    // ============================================================
    // Helpers
    // ============================================================

    pure def treePath(key: Key): List[Byte] = key.slice(0, 31)
    pure def suffixByte(key: Key): Byte = key[31]

    pure def mkNodeKey(v: int, path: List[Byte]): NodeKey = {
        { version: v, bytePath: path }
    }

    pure def commonPrefixLen(a: Stem, b: Stem): int = {
        val maxLen = if (a.length() < b.length()) a.length() else b.length()
        0.to(maxLen - 1).fold(0, (count, i) =>
            if (count == i and a[i] == b[i]) count + 1 else count
        )
    }

    pure def loadNode(store: NodeKey -> Node, nk: NodeKey): Node = {
        if (store.keys().contains(nk)) store.get(nk) else Empty
    }

    // ============================================================
    // Commitment Helpers
    // ============================================================

    pure def computeC1(values: int -> Value): Commitment = {
        val entries = values.keys().filter(k => k < 128)
        commit(entries.fold(Map(), (acc, k) => acc.put(k, valueToField(values.get(k)))))
    }

    pure def computeC2(values: int -> Value): Commitment = {
        val entries = values.keys().filter(k => k >= 128)
        commit(entries.fold(Map(), (acc, k) => acc.put(k - 128, valueToField(values.get(k)))))
    }

    pure def computeExtC(stem: Stem, c1: Commitment, c2: Commitment): Commitment = {
        // commit(1, stem[0], ..., stem[n-1], c1, c2)
        val base = Map(0 -> 1)
        val withStem = 0.to(stem.length() - 1).fold(base, (acc, i) =>
            acc.put(i + 1, stem[i])
        )
        val withAll = withStem.put(stem.length() + 1, c1).put(stem.length() + 2, c2)
        commit(withAll)
    }

    pure def mkEaSNode(stem: Stem, suffix: Byte, value: Value): Node = {
        val values = Map(suffix -> value)
        val c1 = computeC1(values)
        val c2 = computeC2(values)
        val ec = computeExtC(stem, c1, c2)
        EaS({ stem: stem, values: values, c1: c1, c2: c2, extC: ec })
    }

    pure def recomputeEaSNode(stem: Stem, values: int -> Value): Node = {
        val c1 = computeC1(values)
        val c2 = computeC2(values)
        val ec = computeExtC(stem, c1, c2)
        EaS({ stem: stem, values: values, c1: c1, c2: c2, extC: ec })
    }

    pure def computeInternalC(children: int -> Child): Commitment = {
        commit(children.keys().fold(Map(), (acc, i) =>
            acc.put(i, children.get(i).commitment)
        ))
    }

    pure def nodeCommitment(node: Node): Commitment = {
        match node {
            | Internal(n) => n.commitment
            | EaS(n) => n.extC
            | Empty => ZERO_COMMITMENT
        }
    }

    // ============================================================
    // LOOKUP (non-recursive, fold-based)
    // ============================================================

    // Walk state for iterative traversal
    type WalkState = {
        currentNode: Node,
        depth: int,
        done: bool,
        result: int,       // -1 means not found
        found: bool
    }

    pure def lookup(store: NodeKey -> Node, roots: int -> NodeKey, key: Key, ver: int): { found: bool, value: int } = {
        if (not(roots.keys().contains(ver))) { found: false, value: 0 }
        else {
            val rootKey = roots.get(ver)
            val rootNode = loadNode(store, rootKey)
            val initState: WalkState = {
                currentNode: rootNode, depth: 0, done: false, result: 0, found: false
            }
            // Walk up to 31 levels (max depth for 256-ary tree with 32-byte keys)
            val finalState = 0.to(30).fold(initState, (st, _level) =>
                if (st.done) st
                else match st.currentNode {
                    | Empty => { ...st, done: true, found: false }
                    | EaS(eas) =>
                        val expectedStem = treePath(key).slice(st.depth, 31)
                        if (eas.stem == expectedStem and eas.values.keys().contains(suffixByte(key)))
                            { ...st, done: true, found: true, result: eas.values.get(suffixByte(key)) }
                        else
                            { ...st, done: true, found: false }
                    | Internal(n) =>
                        val ci = key[st.depth]
                        if (n.children.keys().contains(ci)) {
                            val child = n.children.get(ci)
                            val childKey = mkNodeKey(child.version, treePath(key).slice(0, st.depth + 1))
                            val childNode = loadNode(store, childKey)
                            { ...st, currentNode: childNode, depth: st.depth + 1 }
                        } else {
                            { ...st, done: true, found: false }
                        }
                }
            )
            { found: finalState.found, value: finalState.result }
        }
    }

    // ============================================================
    // INSERT (non-recursive, simplified for bounded depth)
    //
    // Strategy: walk down collecting the path, then apply the mutation
    // at the leaf level, and propagate commitments back up.
    // ============================================================

    // Path element collected during walk-down
    type PathElem = {
        nodeKey: NodeKey,
        node: Node,
        childIndex: int,  // which child we descended into
        depth: int
    }

    // Walk-down state
    type WalkDownState = {
        path: List[PathElem],
        leafNode: Node,
        leafKey: NodeKey,
        leafDepth: int,
        done: bool
    }

    // Walk down from root collecting internal nodes on the path
    pure def walkDown(store: NodeKey -> Node, rootKey: NodeKey, key: Key): WalkDownState = {
        val rootNode = loadNode(store, rootKey)
        val initState: WalkDownState = {
            path: [],
            leafNode: rootNode,
            leafKey: rootKey,
            leafDepth: 0,
            done: false
        }
        // At each step: if current node is Internal, record it and descend
        0.to(30).fold(initState, (st, _level) =>
            if (st.done) st
            else match st.leafNode {
                | Internal(n) =>
                    val ci = key[st.leafDepth]
                    val elem: PathElem = {
                        nodeKey: st.leafKey, node: st.leafNode,
                        childIndex: ci, depth: st.leafDepth
                    }
                    if (n.children.keys().contains(ci)) {
                        val child = n.children.get(ci)
                        val childKey = mkNodeKey(child.version, treePath(key).slice(0, st.leafDepth + 1))
                        val childNode = loadNode(store, childKey)
                        { ...st, path: st.path.append(elem), leafNode: childNode,
                          leafKey: childKey, leafDepth: st.leafDepth + 1 }
                    } else {
                        // Empty child slot — stop, leafNode stays as the Internal
                        { ...st, done: true }
                    }
                | _ => { ...st, done: true }  // EaS or Empty — stop
            }
        )
    }

    // Apply the insert at the leaf level, returning the new node(s) and their commitment
    pure def applyLeafInsert(
        store: NodeKey -> Node,
        walkResult: WalkDownState,
        key: Key,
        value: Value,
        version: int
    ): InsertResult = {
        val depth = walkResult.leafDepth
        val leafNode = walkResult.leafNode
        val leafKey = walkResult.leafKey
        val path = walkResult.path
        val suffix = suffixByte(key)

        // Determine mutation at leaf level
        val leafResult: InsertResult = match leafNode {
            | Empty =>
                // Create new EaS (root was empty / first insert)
                val stem = treePath(key).slice(depth, 31)
                val eas = mkEaSNode(stem, suffix, value)
                val nk = mkNodeKey(version, treePath(key).slice(0, depth))
                { newStore: store.put(nk, eas), newRootKey: nk,
                  staleEntries: [], rootCommitment: nodeCommitment(eas) }

            | EaS(eas) =>
                val expectedStem = treePath(key).slice(depth, 31)
                if (eas.stem == expectedStem) {
                    // Same stem — update value
                    val newValues = eas.values.put(suffix, value)
                    val newEaS = recomputeEaSNode(eas.stem, newValues)
                    val nk = mkNodeKey(version, treePath(key).slice(0, depth))
                    { newStore: store.put(nk, newEaS), newRootKey: nk,
                      staleEntries: [{ staleVersion: version, nodeKey: leafKey }],
                      rootCommitment: nodeCommitment(newEaS) }
                } else {
                    // SPLIT: different stem
                    val existingStem = eas.stem
                    val newStem = treePath(key).slice(depth, 31)
                    val prefixLen = commonPrefixLen(existingStem, newStem)
                    val existingByte = existingStem[prefixLen]
                    val newByte = newStem[prefixLen]

                    // New EaS for existing data
                    val existNewStem = existingStem.slice(prefixLen + 1, existingStem.length())
                    val existNewEaS = recomputeEaSNode(existNewStem, eas.values)
                    // New EaS for new key
                    val newEaStem = newStem.slice(prefixLen + 1, newStem.length())
                    val newEaS = mkEaSNode(newEaStem, suffix, value)

                    // Internal node at divergence
                    val divergeChildren: int -> Child = Map(
                        existingByte -> { version: version, commitment: nodeCommitment(existNewEaS) },
                        newByte -> { version: version, commitment: nodeCommitment(newEaS) }
                    )
                    val divergeC = computeInternalC(divergeChildren)
                    val divergeNode = Internal({ children: divergeChildren, commitment: divergeC })

                    val basePath = treePath(key).slice(0, depth)
                    val divergePath = basePath.concat(treePath(key).slice(depth, depth + prefixLen))
                    val existEaSKey = mkNodeKey(version, divergePath.concat([existingByte]))
                    val newEaSKey = mkNodeKey(version, divergePath.concat([newByte]))

                    // Build chain for shared prefix (if prefixLen > 0)
                    val chainStore = store
                        .put(existEaSKey, existNewEaS)
                        .put(newEaSKey, newEaS)
                        .put(mkNodeKey(version, divergePath), divergeNode)

                    // Fold backwards through intermediate single-child nodes
                    val chainState = if (prefixLen == 0) {
                        { s: chainStore, c: divergeC }
                    } else {
                        // Build from prefixLen-1 down to 0
                        0.to(prefixLen - 1).fold({ s: chainStore, c: divergeC }, (acc, idx) => {
                            val i = prefixLen - 1 - idx  // iterate from prefixLen-1 to 0
                            val iPath = basePath.concat(treePath(key).slice(depth, depth + i))
                            val cByte = treePath(key)[depth + i]
                            val iChildren: int -> Child = Map(
                                cByte -> { version: version, commitment: acc.c }
                            )
                            val iC = computeInternalC(iChildren)
                            val iNode = Internal({ children: iChildren, commitment: iC })
                            { s: acc.s.put(mkNodeKey(version, iPath), iNode), c: iC }
                        })
                    }

                    val resultKey = mkNodeKey(version, basePath)
                    { newStore: chainState.s, newRootKey: resultKey,
                      staleEntries: [{ staleVersion: version, nodeKey: leafKey }],
                      rootCommitment: chainState.c }
                }

            | Internal(n) =>
                // walkDown stopped because child slot was empty
                // The last path element is this internal node
                val ci = key[depth]
                val stem = treePath(key).slice(depth + 1, 31)
                val eas = mkEaSNode(stem, suffix, value)
                val easKey = mkNodeKey(version, treePath(key).slice(0, depth + 1))
                val newChildren = n.children.put(ci, {
                    version: version, commitment: nodeCommitment(eas)
                })
                val newC = computeInternalC(newChildren)
                val newInternal = Internal({ children: newChildren, commitment: newC })
                val nk = mkNodeKey(version, treePath(key).slice(0, depth))
                { newStore: store.put(easKey, eas).put(nk, newInternal),
                  newRootKey: nk,
                  staleEntries: [{ staleVersion: version, nodeKey: leafKey }],
                  rootCommitment: newC }
        }

        // Propagate commitment updates back up through the path
        val finalResult = path.indices().fold(
            { r: leafResult, currentC: leafResult.rootCommitment },
            (acc, revIdx) => {
                // Walk path in reverse: last element first
                val idx = path.length() - 1 - revIdx
                val elem = path[idx]
                match elem.node {
                    | Internal(n) =>
                        val newChildren = n.children.put(elem.childIndex, {
                            version: version, commitment: acc.currentC
                        })
                        val newC = computeInternalC(newChildren)
                        val newNode = Internal({ children: newChildren, commitment: newC })
                        val nk = mkNodeKey(version, treePath(key).slice(0, elem.depth))
                        val staleEntry: StaleNodeEntry = { staleVersion: version, nodeKey: elem.nodeKey }
                        {
                            r: {
                                newStore: acc.r.newStore.put(nk, newNode),
                                newRootKey: nk,
                                staleEntries: acc.r.staleEntries.append(staleEntry),
                                rootCommitment: newC
                            },
                            currentC: newC
                        }
                    | _ =>
                        // Should never happen — path only contains Internal nodes
                        acc
                }
            }
        )
        finalResult.r
    }

    // Full insert: walk down, apply, propagate up
    pure def doInsert(
        store: NodeKey -> Node,
        roots: int -> NodeKey,
        key: Key,
        value: Value,
        oldVersion: int,
        newVersion: int
    ): InsertResult = {
        if (not(roots.keys().contains(oldVersion))) {
            // First insert
            val eas = mkEaSNode(treePath(key), suffixByte(key), value)
            val nk = mkNodeKey(newVersion, [])
            { newStore: store.put(nk, eas), newRootKey: nk,
              staleEntries: [], rootCommitment: nodeCommitment(eas) }
        } else {
            val rootKey = roots.get(oldVersion)
            val walkResult = walkDown(store, rootKey, key)
            applyLeafInsert(store, walkResult, key, value, newVersion)
        }
    }

    // ============================================================
    // State Machine Actions
    // ============================================================

    action init = all {
        nodeStore' = Map(),
        currentVersion' = 0,
        rootKeys' = Map(),
        staleIndex' = [],
        kvMap' = Map()
    }

    action insert(key: Key, value: Value): bool = {
        val newVersion = currentVersion + 1
        val result = doInsert(nodeStore, rootKeys, key, value, currentVersion, newVersion)
        all {
            nodeStore' = result.newStore,
            currentVersion' = newVersion,
            rootKeys' = rootKeys.put(newVersion, result.newRootKey),
            staleIndex' = staleIndex.concat(result.staleEntries),
            kvMap' = kvMap.put(key, value),
        }
    }

    // Non-deterministic step for simulation
    action step = {
        nondet key0 = 0.to(3).oneOf()
        nondet key1 = 0.to(3).oneOf()
        nondet suffix = 0.to(3).oneOf()
        nondet value = 1.to(10).oneOf()
        val key = [key0, key1, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, suffix]
        insert(key, value)
    }

    // ============================================================
    // Invariants
    // ============================================================

    // INV 1: Get-after-insert — all keys in kvMap are retrievable
    val getAfterInsert = {
        if (currentVersion == 0) true
        else {
            kvMap.keys().forall(key => {
                val res = lookup(nodeStore, rootKeys, key, currentVersion)
                res.found and res.value == kvMap.get(key)
            })
        }
    }

    // INV 2: Version monotonicity
    val versionMonotonicity = {
        nodeStore.keys().forall(nk => nk.version <= currentVersion)
    }

    // INV 3: Commitment consistency
    val commitmentConsistency = {
        nodeStore.keys().forall(nk => {
            val node = nodeStore.get(nk)
            match node {
                | Internal(n) => n.commitment == computeInternalC(n.children)
                | EaS(eas) =>
                    eas.c1 == computeC1(eas.values)
                    and eas.c2 == computeC2(eas.values)
                    and eas.extC == computeExtC(eas.stem, eas.c1, eas.c2)
                | Empty => true
            }
        })
    }

    // INV 4: Root exists for each version
    val rootExistsForAllVersions = {
        1.to(currentVersion).forall(v => rootKeys.keys().contains(v))
    }

    // Combined invariant
    val allInvariants = {
        getAfterInsert
        and versionMonotonicity
        and commitmentConsistency
        and rootExistsForAllVersions
    }
}
