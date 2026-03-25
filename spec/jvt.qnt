// jvt.qnt — Jellyfish Verkle Tree Formal Specification
//
// Models the JVT combining JMT's version-based persistent storage
// with verkle tree vector commitments.
//
// Features modeled:
//   - Insert (with stem splits and chain propagation)
//   - Delete (with EaS collapse when internal nodes lose children)
//   - Versioned lookup (history preservation)
//   - Abstract proof generation and verification
//   - Stale node tracking
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

    // Delete result
    type DeleteResult = {
        newStore: NodeKey -> Node,
        newRootKey: NodeKey,
        staleEntries: List[StaleNodeEntry],
        rootCommitment: Commitment,
        changed: bool
    }

    // Walk-down types (shared by insert and delete)
    type PathElem = {
        nodeKey: NodeKey,
        node: Node,
        childIndex: int,
        depth: int
    }

    type WalkDownState = {
        path: List[PathElem],
        leafNode: Node,
        leafKey: NodeKey,
        leafDepth: int,
        done: bool
    }

    // Propagation state for delete
    type DeletePropState = {
        store: NodeKey -> Node,
        staleEntries: List[StaleNodeEntry],
        removed: bool,
        commitment: Commitment,
        nodeKey: NodeKey
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
    // History: snapshot of kvMap at each version (for history preservation)
    var kvHistory: int -> (Key -> Value)

    // ============================================================
    // Map Utilities
    // ============================================================

    pure def removeChild(m: int -> Child, idx: int): int -> Child = {
        m.keys().filter(k => k != idx).fold(Map(), (acc, k) => acc.put(k, m.get(k)))
    }

    pure def removeValue(m: int -> Value, idx: int): int -> Value = {
        m.keys().filter(k => k != idx).fold(Map(), (acc, k) => acc.put(k, m.get(k)))
    }

    pure def removeKeyEntry(m: Key -> Value, key: Key): Key -> Value = {
        m.keys().filter(k => k != key).fold(Map(), (acc, k) => acc.put(k, m.get(k)))
    }

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

    // Extension commitment: commit(1, stem[0], ..., stem[n-1], c2f(c1), c2f(c2))
    // Uses commitmentToField for sub-commitments, matching the Rust implementation.
    pure def computeExtC(stem: Stem, c1: Commitment, c2: Commitment): Commitment = {
        val base = Map(0 -> 1)
        val withStem = 0.to(stem.length() - 1).fold(base, (acc, i) =>
            acc.put(i + 1, stem[i])
        )
        val withAll = withStem
            .put(stem.length() + 1, commitmentToField(c1))
            .put(stem.length() + 2, commitmentToField(c2))
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

    // Internal node commitment uses commitmentToField on each child's commitment,
    // matching the Rust InternalNode::compute_commitment.
    pure def computeInternalC(children: int -> Child): Commitment = {
        commit(children.keys().fold(Map(), (acc, i) =>
            acc.put(i, commitmentToField(children.get(i).commitment))
        ))
    }

    pure def nodeCommitment(node: Node): Commitment = {
        match node {
            | Internal(n) => n.commitment
            | EaS(n) => n.extC
            | Empty => ZERO_COMMITMENT
        }
    }

    // Prepend a byte to an EaS node's stem and recompute extension commitment.
    // Models EaSNode::with_prepended_stem — c1 and c2 are preserved.
    pure def withPrependedStem(
        eas: { stem: Stem, values: int -> Value, c1: Commitment, c2: Commitment, extC: Commitment },
        byte: Byte
    ): Node = {
        val newStem = [byte].concat(eas.stem)
        val newExtC = computeExtC(newStem, eas.c1, eas.c2)
        EaS({ stem: newStem, values: eas.values, c1: eas.c1, c2: eas.c2, extC: newExtC })
    }

    // ============================================================
    // LOOKUP (non-recursive, fold-based)
    // ============================================================

    type WalkState = {
        currentNode: Node,
        depth: int,
        done: bool,
        result: int,
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
    // WALK DOWN (shared by insert and delete)
    //
    // Walk from root collecting internal nodes on the path until
    // we reach a leaf (EaS, Empty) or an empty child slot.
    // ============================================================

    pure def walkDown(store: NodeKey -> Node, rootKey: NodeKey, key: Key): WalkDownState = {
        val rootNode = loadNode(store, rootKey)
        val initState: WalkDownState = {
            path: [],
            leafNode: rootNode,
            leafKey: rootKey,
            leafDepth: 0,
            done: false
        }
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
                        { ...st, done: true }
                    }
                | _ => { ...st, done: true }
            }
        )
    }

    // ============================================================
    // INSERT
    //
    // Strategy: walk down collecting the path, apply the mutation
    // at the leaf level, and propagate commitments back up.
    // ============================================================

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

        val leafResult: InsertResult = match leafNode {
            | Empty =>
                val stem = treePath(key).slice(depth, 31)
                val eas = mkEaSNode(stem, suffix, value)
                val nk = mkNodeKey(version, treePath(key).slice(0, depth))
                { newStore: store.put(nk, eas), newRootKey: nk,
                  staleEntries: [], rootCommitment: nodeCommitment(eas) }

            | EaS(eas) =>
                val expectedStem = treePath(key).slice(depth, 31)
                if (eas.stem == expectedStem) {
                    val newValues = eas.values.put(suffix, value)
                    val newEaS = recomputeEaSNode(eas.stem, newValues)
                    val nk = mkNodeKey(version, treePath(key).slice(0, depth))
                    { newStore: store.put(nk, newEaS), newRootKey: nk,
                      staleEntries: [{ staleVersion: version, nodeKey: leafKey }],
                      rootCommitment: nodeCommitment(newEaS) }
                } else {
                    val existingStem = eas.stem
                    val newStem = treePath(key).slice(depth, 31)
                    val prefixLen = commonPrefixLen(existingStem, newStem)
                    val existingByte = existingStem[prefixLen]
                    val newByte = newStem[prefixLen]

                    val existNewStem = existingStem.slice(prefixLen + 1, existingStem.length())
                    val existNewEaS = recomputeEaSNode(existNewStem, eas.values)
                    val newEaStem = newStem.slice(prefixLen + 1, newStem.length())
                    val newEaS = mkEaSNode(newEaStem, suffix, value)

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

                    val chainStore = store
                        .put(existEaSKey, existNewEaS)
                        .put(newEaSKey, newEaS)
                        .put(mkNodeKey(version, divergePath), divergeNode)

                    val chainState = if (prefixLen == 0) {
                        { s: chainStore, c: divergeC }
                    } else {
                        0.to(prefixLen - 1).fold({ s: chainStore, c: divergeC }, (acc, idx) => {
                            val i = prefixLen - 1 - idx
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
                    | _ => acc
                }
            }
        )
        finalResult.r
    }

    pure def doInsert(
        store: NodeKey -> Node,
        roots: int -> NodeKey,
        key: Key,
        value: Value,
        oldVersion: int,
        newVersion: int
    ): InsertResult = {
        if (not(roots.keys().contains(oldVersion))) {
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
    // DELETE
    //
    // Walk down to find the leaf, remove the value, propagate up.
    // If an internal node is left with a single EaS child, collapse
    // the EaS by prepending the child index byte to its stem.
    // Collapse cascades: if collapsing at one level creates a
    // single-EaS-child situation at the parent, that collapses too.
    // ============================================================

    // Apply delete at the leaf level
    pure def applyLeafDelete(
        store: NodeKey -> Node,
        walkResult: WalkDownState,
        key: Key,
        version: int
    ): { prop: DeletePropState, changed: bool } = {
        val depth = walkResult.leafDepth
        val leafNode = walkResult.leafNode
        val leafKey = walkResult.leafKey
        val suffix = suffixByte(key)

        match leafNode {
            | Empty =>
                { prop: { store: store, staleEntries: [], removed: false,
                          commitment: ZERO_COMMITMENT, nodeKey: leafKey },
                  changed: false }

            | Internal(_) =>
                // walkDown stopped at empty child slot — key not in tree
                { prop: { store: store, staleEntries: [], removed: false,
                          commitment: ZERO_COMMITMENT, nodeKey: leafKey },
                  changed: false }

            | EaS(eas) =>
                val expectedStem = treePath(key).slice(depth, 31)
                if (eas.stem != expectedStem or not(eas.values.keys().contains(suffix))) {
                    { prop: { store: store, staleEntries: [], removed: false,
                              commitment: eas.extC, nodeKey: leafKey },
                      changed: false }
                } else {
                    val newValues = removeValue(eas.values, suffix)
                    val staleEntry: StaleNodeEntry = { staleVersion: version, nodeKey: leafKey }
                    if (newValues.keys().size() == 0) {
                        { prop: { store: store, staleEntries: [staleEntry],
                                  removed: true, commitment: ZERO_COMMITMENT,
                                  nodeKey: leafKey },
                          changed: true }
                    } else {
                        val newEaS = recomputeEaSNode(eas.stem, newValues)
                        val nk = mkNodeKey(version, treePath(key).slice(0, depth))
                        { prop: { store: store.put(nk, newEaS),
                                  staleEntries: [staleEntry],
                                  removed: false,
                                  commitment: nodeCommitment(newEaS),
                                  nodeKey: nk },
                          changed: true }
                    }
                }
        }
    }

    // Try to collapse an internal node with a single child into that
    // child if it's an EaS. Returns the collapsed result or a normal
    // internal node update.
    pure def tryCollapse(
        acc: DeletePropState,
        newChildren: int -> Child,
        elemNodeKey: NodeKey,
        elemDepth: int,
        key: Key,
        version: int
    ): DeletePropState = {
        val ci = newChildren.keys().fold(0, (_, k) => k)
        val child = newChildren.get(ci)
        val childNK = mkNodeKey(child.version,
            treePath(key).slice(0, elemDepth).concat([ci]))
        val childNode = loadNode(acc.store, childNK)
        match childNode {
            | EaS(remainingEas) =>
                val collapsedNode = withPrependedStem(remainingEas, ci)
                val collapsedNK = mkNodeKey(version, treePath(key).slice(0, elemDepth))
                val staleEntry: StaleNodeEntry = { staleVersion: version, nodeKey: elemNodeKey }
                val staleChild: StaleNodeEntry = { staleVersion: version, nodeKey: childNK }
                { store: acc.store.put(collapsedNK, collapsedNode),
                  staleEntries: acc.staleEntries.append(staleEntry).append(staleChild),
                  removed: false,
                  commitment: nodeCommitment(collapsedNode),
                  nodeKey: collapsedNK }
            | _ =>
                val newC = computeInternalC(newChildren)
                val newNode = Internal({ children: newChildren, commitment: newC })
                val nk = mkNodeKey(version, treePath(key).slice(0, elemDepth))
                val staleEntry: StaleNodeEntry = { staleVersion: version, nodeKey: elemNodeKey }
                { store: acc.store.put(nk, newNode),
                  staleEntries: acc.staleEntries.append(staleEntry),
                  removed: false, commitment: newC, nodeKey: nk }
        }
    }

    // Update an internal node's children and recompute its commitment.
    pure def updateInternal(
        acc: DeletePropState,
        newChildren: int -> Child,
        elemNodeKey: NodeKey,
        elemDepth: int,
        key: Key,
        version: int
    ): DeletePropState = {
        val newC = computeInternalC(newChildren)
        val newNode = Internal({ children: newChildren, commitment: newC })
        val nk = mkNodeKey(version, treePath(key).slice(0, elemDepth))
        val staleEntry: StaleNodeEntry = { staleVersion: version, nodeKey: elemNodeKey }
        { store: acc.store.put(nk, newNode),
          staleEntries: acc.staleEntries.append(staleEntry),
          removed: false, commitment: newC, nodeKey: nk }
    }

    // Propagate delete results up through the collected path.
    pure def propagateDelete(
        initProp: DeletePropState,
        path: List[PathElem],
        key: Key,
        version: int
    ): DeletePropState = {
        path.indices().fold(initProp, (acc, revIdx) => {
            val idx = path.length() - 1 - revIdx
            val elem = path[idx]
            match elem.node {
                | Internal(n) =>
                    if (not(acc.removed)) {
                        // Child was updated — update reference, check for cascading collapse
                        val newChildren = n.children.put(elem.childIndex, {
                            version: version, commitment: acc.commitment
                        })
                        if (newChildren.keys().size() == 1) {
                            tryCollapse(acc, newChildren, elem.nodeKey, elem.depth, key, version)
                        } else {
                            updateInternal(acc, newChildren, elem.nodeKey, elem.depth, key, version)
                        }
                    } else {
                        // Child was removed
                        val newChildren = removeChild(n.children, elem.childIndex)
                        val staleEntry: StaleNodeEntry = { staleVersion: version, nodeKey: elem.nodeKey }

                        if (newChildren.keys().size() == 0) {
                            { store: acc.store,
                              staleEntries: acc.staleEntries.append(staleEntry),
                              removed: true, commitment: ZERO_COMMITMENT,
                              nodeKey: elem.nodeKey }
                        } else if (newChildren.keys().size() == 1) {
                            tryCollapse(acc, newChildren, elem.nodeKey, elem.depth, key, version)
                        } else {
                            updateInternal(acc, newChildren, elem.nodeKey, elem.depth, key, version)
                        }
                    }
                | _ => acc
            }
        })
    }

    // Full delete: walk down, apply at leaf, propagate up
    pure def doDelete(
        store: NodeKey -> Node,
        roots: int -> NodeKey,
        key: Key,
        oldVersion: int,
        newVersion: int
    ): DeleteResult = {
        if (not(roots.keys().contains(oldVersion))) {
            { newStore: store, newRootKey: mkNodeKey(newVersion, []),
              staleEntries: [], rootCommitment: ZERO_COMMITMENT, changed: false }
        } else {
            val rootKey = roots.get(oldVersion)
            val walkResult = walkDown(store, rootKey, key)
            val leafResult = applyLeafDelete(store, walkResult, key, newVersion)

            if (not(leafResult.changed)) {
                { newStore: store, newRootKey: rootKey, staleEntries: [],
                  rootCommitment: nodeCommitment(loadNode(store, rootKey)), changed: false }
            } else {
                val propagated = propagateDelete(
                    leafResult.prop, walkResult.path, key, newVersion
                )
                if (propagated.removed) {
                    { newStore: propagated.store,
                      newRootKey: mkNodeKey(newVersion, []),
                      staleEntries: propagated.staleEntries,
                      rootCommitment: ZERO_COMMITMENT, changed: true }
                } else {
                    { newStore: propagated.store,
                      newRootKey: propagated.nodeKey,
                      staleEntries: propagated.staleEntries,
                      rootCommitment: propagated.commitment, changed: true }
                }
            }
        }
    }

    // ============================================================
    // ABSTRACT PROOF MODEL
    //
    // Generates proofs by traversing the tree and collecting
    // (commitment, eval_point, eval_result) openings. Verifies
    // proofs structurally without store access, checking the
    // commitment chain from root to leaf.
    // ============================================================

    // A single polynomial opening
    type Opening = { commitment: Commitment, evalPoint: int, evalResult: int }

    // How a key lookup terminated
    type TerminationKind =
        | FoundEaS
        | EmptySlot
        | StemMismatch({ divergeIndex: int, actualByte: int })

    // Abstract verkle proof for a single key
    type KeyProof = {
        openings: List[Opening],
        found: bool,
        value: int,
        termination: TerminationKind
    }

    // Generate a proof for a key at a given version
    pure def generateProof(
        store: NodeKey -> Node,
        roots: int -> NodeKey,
        key: Key,
        ver: int
    ): KeyProof = {
        if (not(roots.keys().contains(ver))) {
            { openings: [], found: false, value: 0, termination: EmptySlot }
        } else {
            val rootKey = roots.get(ver)
            val rootNode = loadNode(store, rootKey)
            val initState = {
                currentNode: rootNode, depth: 0, done: false,
                openings: List(), found: false, value: 0,
                termination: EmptySlot
            }
            val finalState = 0.to(30).fold(initState, (st, _level) =>
                if (st.done) st
                else match st.currentNode {
                    | Empty =>
                        { ...st, done: true, found: false, termination: EmptySlot }
                    | EaS(eas) =>
                        val expectedStem = treePath(key).slice(st.depth, 31)
                        if (eas.stem == expectedStem) {
                            val suffix = suffixByte(key)
                            val hasValue = eas.values.keys().contains(suffix)
                            val value = if (hasValue) eas.values.get(suffix) else 0
                            val isC2 = suffix >= 128
                            val subC = if (isC2) eas.c2 else eas.c1
                            val subIndex = if (isC2) suffix - 128 else suffix
                            val stemLen = eas.stem.length()
                            val subPoint = if (isC2) stemLen + 2 else stemLen + 1

                            val markerO: Opening = {
                                commitment: eas.extC, evalPoint: 0, evalResult: 1
                            }
                            val subO: Opening = {
                                commitment: eas.extC, evalPoint: subPoint,
                                evalResult: commitmentToField(subC)
                            }
                            val valO: Opening = {
                                commitment: subC, evalPoint: subIndex,
                                evalResult: if (hasValue) valueToField(value) else 0
                            }
                            { ...st, done: true, found: hasValue, value: value,
                              openings: st.openings.append(markerO).append(subO).append(valO),
                              termination: FoundEaS }
                        } else {
                            val divergePos = commonPrefixLen(eas.stem, expectedStem)
                            val markerO: Opening = {
                                commitment: eas.extC, evalPoint: 0, evalResult: 1
                            }
                            if (divergePos < eas.stem.length()) {
                                val stemByte = eas.stem[divergePos]
                                val stemO: Opening = {
                                    commitment: eas.extC,
                                    evalPoint: divergePos + 1,
                                    evalResult: stemByte
                                }
                                { ...st, done: true, found: false, value: 0,
                                  openings: st.openings.append(markerO).append(stemO),
                                  termination: StemMismatch({ divergeIndex: divergePos, actualByte: stemByte }) }
                            } else {
                                { ...st, done: true, found: false, value: 0,
                                  openings: st.openings.append(markerO),
                                  termination: StemMismatch({ divergeIndex: divergePos, actualByte: -1 }) }
                            }
                        }
                    | Internal(n) =>
                        val ci = key[st.depth]
                        if (n.children.keys().contains(ci)) {
                            val child = n.children.get(ci)
                            val childKey = mkNodeKey(child.version, treePath(key).slice(0, st.depth + 1))
                            val childNode = loadNode(store, childKey)
                            val opening: Opening = {
                                commitment: n.commitment, evalPoint: ci,
                                evalResult: commitmentToField(child.commitment)
                            }
                            { ...st, currentNode: childNode, depth: st.depth + 1,
                              openings: st.openings.append(opening) }
                        } else {
                            val opening: Opening = {
                                commitment: n.commitment, evalPoint: ci, evalResult: 0
                            }
                            { ...st, done: true, found: false, value: 0,
                              openings: st.openings.append(opening),
                              termination: EmptySlot }
                        }
                }
            )
            { openings: finalState.openings, found: finalState.found,
              value: finalState.value, termination: finalState.termination }
        }
    }

    // Verify the structural chain of a proof without store access.
    // Models the verifier's checks (minus the IPA cryptographic proof).
    //
    // Chain rules:
    //   - First opening's commitment == root commitment
    //   - Internal → next: evalResult == commitmentToField(next.commitment)
    //   - Marker: evalResult == 1
    //   - Same-commitment openings (marker + sub): no cross-link needed
    //   - Sub → value: evalResult == commitmentToField(value_opening.commitment)
    //   - Value: evalResult matches expected
    pure def verifyProofChain(
        proof: KeyProof,
        rootC: Commitment,
        key: Key,
        expectedValue: int,
        expectFound: bool
    ): bool = {
        if (proof.openings.length() == 0) {
            not(expectFound)
        } else if (proof.found != expectFound) {
            false
        } else if (proof.found and proof.value != expectedValue) {
            false
        } else {
            val numO = proof.openings.length()
            val rootOk = proof.openings[0].commitment == rootC

            match proof.termination {
                | FoundEaS =>
                    // [internal_0, ..., internal_{d-1}, marker, sub, value]
                    if (numO < 3) false
                    else {
                        val d = numO - 3
                        val chainOk = 0.to(d - 1).forall(i =>
                            proof.openings[i].evalResult ==
                                commitmentToField(proof.openings[i + 1].commitment)
                        )
                        val intToEasOk = if (d > 0) {
                            proof.openings[d - 1].evalResult ==
                                commitmentToField(proof.openings[d].commitment)
                        } else true
                        val markerOk = proof.openings[d].evalResult == 1
                        val sameExtC = proof.openings[d].commitment ==
                            proof.openings[d + 1].commitment
                        val subToVal = proof.openings[d + 1].evalResult ==
                            commitmentToField(proof.openings[d + 2].commitment)
                        val valOk = if (proof.found) {
                            proof.openings[d + 2].evalResult == valueToField(proof.value)
                        } else {
                            proof.openings[d + 2].evalResult == 0
                        }
                        rootOk and chainOk and intToEasOk and markerOk
                            and sameExtC and subToVal and valOk
                    }

                | EmptySlot =>
                    // [internal_0, ..., internal_d]
                    if (numO < 1) false
                    else {
                        val chainOk = 0.to(numO - 2).forall(i =>
                            proof.openings[i].evalResult ==
                                commitmentToField(proof.openings[i + 1].commitment)
                        )
                        val emptyOk = proof.openings[numO - 1].evalResult == 0
                        rootOk and chainOk and emptyOk and not(proof.found)
                    }

                | StemMismatch(info) =>
                    // [internal_0, ..., internal_{d-1}, marker, (opt: stem_byte)]
                    val hasStemByte = info.actualByte >= 0
                    val d = if (hasStemByte) numO - 2 else numO - 1
                    if (d < 0) false
                    else {
                        val chainOk = 0.to(d - 1).forall(i =>
                            proof.openings[i].evalResult ==
                                commitmentToField(proof.openings[i + 1].commitment)
                        )
                        val intToEasOk = if (d > 0) {
                            proof.openings[d - 1].evalResult ==
                                commitmentToField(proof.openings[d].commitment)
                        } else true
                        val markerOk = proof.openings[d].evalResult == 1
                        val stemOk = if (hasStemByte) {
                            val expectedByte = key[d + info.divergeIndex]
                            proof.openings[d + 1].commitment == proof.openings[d].commitment
                            and info.actualByte != expectedByte
                        } else true
                        rootOk and chainOk and intToEasOk and markerOk
                            and stemOk and not(proof.found)
                    }
            }
        }
    }

    // ============================================================
    // State Machine
    // ============================================================

    action init = all {
        nodeStore' = Map(),
        currentVersion' = 0,
        rootKeys' = Map(),
        staleIndex' = [],
        kvMap' = Map(),
        kvHistory' = Map(),
    }

    action insert(key: Key, value: Value): bool = {
        val newVersion = currentVersion + 1
        val result = doInsert(nodeStore, rootKeys, key, value, currentVersion, newVersion)
        val newKvMap = kvMap.put(key, value)
        all {
            nodeStore' = result.newStore,
            currentVersion' = newVersion,
            rootKeys' = rootKeys.put(newVersion, result.newRootKey),
            staleIndex' = staleIndex.concat(result.staleEntries),
            kvMap' = newKvMap,
            kvHistory' = kvHistory.put(newVersion, newKvMap),
        }
    }

    action deleteKey(key: Key): bool = {
        val newVersion = currentVersion + 1
        if (currentVersion == 0) {
            all {
                nodeStore' = nodeStore,
                currentVersion' = newVersion,
                rootKeys' = rootKeys.put(newVersion, mkNodeKey(newVersion, [])),
                staleIndex' = staleIndex,
                kvMap' = kvMap,
                kvHistory' = kvHistory.put(newVersion, kvMap),
            }
        } else {
            val result = doDelete(nodeStore, rootKeys, key, currentVersion, newVersion)
            val newKvMap = if (result.changed) removeKeyEntry(kvMap, key) else kvMap
            all {
                nodeStore' = result.newStore,
                currentVersion' = newVersion,
                rootKeys' = rootKeys.put(newVersion, result.newRootKey),
                staleIndex' = staleIndex.concat(result.staleEntries),
                kvMap' = newKvMap,
                kvHistory' = kvHistory.put(newVersion, newKvMap),
            }
        }
    }

    // Non-deterministic step: insert or delete
    action step = {
        nondet opKind = 0.to(1).oneOf()
        nondet key0 = 0.to(3).oneOf()
        nondet key1 = 0.to(3).oneOf()
        nondet suffix = 0.to(3).oneOf()
        nondet value = 1.to(10).oneOf()
        val key = [key0, key1, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, suffix]
        if (opKind == 0) insert(key, value)
        else deleteKey(key)
    }

    // ============================================================
    // Invariants
    // ============================================================

    // --- Core ---

    // INV 1: All keys in kvMap are retrievable at the current version
    val getAfterInsert = {
        if (currentVersion == 0) true
        else {
            kvMap.keys().forall(key => {
                val res = lookup(nodeStore, rootKeys, key, currentVersion)
                res.found and res.value == kvMap.get(key)
            })
        }
    }

    // INV 2: All node keys have version ≤ current version
    val versionMonotonicity = {
        nodeStore.keys().forall(nk => nk.version <= currentVersion)
    }

    // INV 3: Stored commitments match recomputation from children/values
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

    // INV 4: A root key exists for every version from 1 to current
    val rootExistsForAllVersions = {
        1.to(currentVersion).forall(v => rootKeys.keys().contains(v))
    }

    // --- History ---

    // INV 5: Reading at any past version returns the values that were current then
    val historyPreservation = {
        1.to(currentVersion).forall(v => {
            if (not(kvHistory.keys().contains(v))) true
            else {
                val snapshot = kvHistory.get(v)
                snapshot.keys().forall(key => {
                    val res = lookup(nodeStore, rootKeys, key, v)
                    res.found and res.value == snapshot.get(key)
                })
            }
        })
    }

    // --- Structural (use BFS reachability) ---

    // BFS helper: collect all NodeKeys reachable from a root
    pure def reachableNodes(store: NodeKey -> Node, rootKey: NodeKey): Set[NodeKey] = {
        val init = { visited: Set(rootKey), frontier: Set(rootKey) }
        val final_ = 0.to(30).fold(init, (st, _) => {
            val nextLevel = st.frontier.fold(Set(), (acc, nk) => {
                match loadNode(store, nk) {
                    | Internal(n) =>
                        n.children.keys().fold(acc, (acc2, ci) => {
                            val child = n.children.get(ci)
                            acc2.union(Set(mkNodeKey(child.version,
                                nk.bytePath.concat([ci]))))
                        })
                    | _ => acc
                }
            })
            { visited: st.visited.union(nextLevel), frontier: nextLevel }
        })
        final_.visited
    }

    // INV 6: No reachable internal node has a single EaS child
    val noUncollapsedSingleChild = {
        if (currentVersion == 0) true
        else {
            val root = rootKeys.get(currentVersion)
            val reachable = reachableNodes(nodeStore, root)
            reachable.forall(nk => {
                match loadNode(nodeStore, nk) {
                    | Internal(n) =>
                        if (n.children.keys().size() == 1) {
                            val ci = n.children.keys().fold(0, (_, k) => k)
                            val child = n.children.get(ci)
                            val childNK = mkNodeKey(child.version, nk.bytePath.concat([ci]))
                            match loadNode(nodeStore, childNK) {
                                | EaS(_) => false
                                | _ => true
                            }
                        } else true
                    | _ => true
                }
            })
        }
    }

    // INV 7: No stale node is reachable from the current root
    val staleNodesUnreachable = {
        if (currentVersion == 0) true
        else {
            val root = rootKeys.get(currentVersion)
            val reachable = reachableNodes(nodeStore, root)
            val staleNKs = staleIndex.foldl(Set(), (acc, entry) =>
                acc.union(Set(entry.nodeKey))
            )
            staleNKs.intersect(reachable) == Set()
        }
    }

    // --- Proof model ---

    // INV 8: For every key in kvMap, generateProof + verifyProofChain succeeds
    val proofCompleteness = {
        if (currentVersion == 0) true
        else {
            val rootNK = rootKeys.get(currentVersion)
            val rootC = nodeCommitment(loadNode(nodeStore, rootNK))
            kvMap.keys().forall(key => {
                val proof = generateProof(nodeStore, rootKeys, key, currentVersion)
                proof.found and verifyProofChain(proof, rootC, key, kvMap.get(key), true)
            })
        }
    }

    // INV 9: Proof returns same value as lookup
    val proofConsistency = {
        if (currentVersion == 0) true
        else {
            kvMap.keys().forall(key => {
                val res = lookup(nodeStore, rootKeys, key, currentVersion)
                val proof = generateProof(nodeStore, rootKeys, key, currentVersion)
                proof.found == res.found and
                    (if (proof.found) proof.value == res.value else true)
            })
        }
    }

    // INV 10: For keys not in kvMap, absence proofs generate and verify correctly
    val proofAbsenceCorrectness = {
        if (currentVersion == 0) true
        else {
            val rootNK = rootKeys.get(currentVersion)
            val rootC = nodeCommitment(loadNode(nodeStore, rootNK))
            0.to(3).forall(k0 =>
                0.to(3).forall(k1 =>
                    0.to(3).forall(s => {
                        val key = [k0, k1, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, s]
                        if (kvMap.keys().contains(key)) true
                        else {
                            val proof = generateProof(nodeStore, rootKeys, key, currentVersion)
                            not(proof.found) and verifyProofChain(proof, rootC, key, 0, false)
                        }
                    })
                )
            )
        }
    }

    // --- Commitment scheme ---

    // INV 11: commitUpdate matches full recomputation for test vectors
    val homomorphicUpdateEquivalence = {
        0.to(5).forall(i => {
            val v = Map(0 -> (i + 1), 1 -> (i + 3), 2 -> (i * 7))
            val c = commit(v)
            val newVal = (i + 13) % 50
            val cInc = commitUpdate(c, 1, i + 3, newVal)
            val cFresh = commit(v.put(1, newVal))
            cInc == cFresh
        })
    }

    // ============================================================
    // Invariant Groups
    // ============================================================

    val coreInvariants = {
        getAfterInsert
        and versionMonotonicity
        and commitmentConsistency
        and rootExistsForAllVersions
    }

    val structuralInvariants = {
        noUncollapsedSingleChild
        and staleNodesUnreachable
    }

    val proofInvariants = {
        proofCompleteness
        and proofConsistency
        and proofAbsenceCorrectness
    }

    val allInvariants = {
        coreInvariants
        and historyPreservation
        and structuralInvariants
        and proofInvariants
        and homomorphicUpdateEquivalence
    }
}
