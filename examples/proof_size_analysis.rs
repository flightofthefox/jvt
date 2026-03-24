//! Proof size analysis: JVT (verkle) vs hypothetical JMT (Merkle).
//!
//! Compares proof sizes using:
//! - Actual measured sizes from real IPA and multiproof implementations (pedersen feature)
//! - Structural estimates from tree depth analysis (mock)
//!
//! Run with mock:     cargo run --example proof_size_analysis
//! Run with Pedersen: cargo run --example proof_size_analysis --features pedersen

use jellyfish_verkle_tree::node::NodeKey;
use jellyfish_verkle_tree::proof;
use jellyfish_verkle_tree::{Key, MemoryStore, JVT};

fn make_key(i: u32) -> Key {
    let mut key = [0u8; 32];
    key[0..4].copy_from_slice(&i.to_be_bytes());
    key[31] = (i & 0xFF) as u8;
    key
}

// ============================================================
// Size constants from actual implementations
// ============================================================

/// IPA proof size for 256-element vector: 8 rounds × 2 points × 32 bytes + 1 scalar × 32 bytes.
const IPA_PROOF_BYTES: usize = 8 * 2 * 32 + 32; // = 544

/// Multipoint proof size: 1 group element (D) + 1 IPA proof = 32 + 544.
const MULTIPROOF_BYTES: usize = 32 + IPA_PROOF_BYTES; // = 576

/// JMT single proof per level: 15 sibling hashes × 32 bytes = 480 bytes.
const JMT_SIBLINGS_PER_LEVEL: usize = 15 * 32; // = 480

/// JMT leaf overhead: key hash + value hash.
const JMT_LEAF_BYTES: usize = 64;

fn jmt_single_proof_size(depth: usize) -> usize {
    depth * JMT_SIBLINGS_PER_LEVEL + JMT_LEAF_BYTES
}

fn main() {
    println!("JVT Proof Size Analysis");
    println!("=======================\n");

    #[cfg(feature = "pedersen")]
    println!("Mode: REAL Pedersen commitments + IPA/Multipoint proofs\n");
    #[cfg(not(feature = "pedersen"))]
    println!("Mode: Mock commitments (structural estimates)\n");

    println!("Constants (from implementation):");
    println!(
        "  IPA proof (256-element vector): {} bytes",
        IPA_PROOF_BYTES
    );
    println!(
        "  Multipoint proof (any N queries): {} bytes",
        MULTIPROOF_BYTES
    );
    println!(
        "  JMT sibling hashes per level: {} bytes",
        JMT_SIBLINGS_PER_LEVEL
    );
    println!();

    // Build trees and measure actual proof depths
    let sizes = [10u32, 100, 1000, 10_000];

    for &n in &sizes {
        let mut tree = JVT::new(MemoryStore::new());
        for i in 0..n {
            tree.insert(make_key(i), vec![(i & 0xFF) as u8; 32]);
        }

        let root_key = NodeKey::root(tree.current_version());

        // Measure proof depth for sample keys
        let sample_keys: Vec<Key> = (0..n.min(100)).map(make_key).collect();
        let mut depths = Vec::new();

        for key in &sample_keys {
            if let Some(p) = proof::prove(&tree.store, &root_key, key) {
                depths.push(p.commitments.len());
            }
        }

        let avg_depth = depths.iter().sum::<usize>() as f64 / depths.len().max(1) as f64;
        let max_depth = depths.iter().copied().max().unwrap_or(0);
        let jmt_depth = if n > 1 {
            (n as f64).log(16.0).ceil() as usize
        } else {
            1
        };

        println!("Tree: {} keys", n);
        println!(
            "  JVT depth: avg {:.1}, max {} (256-ary)",
            avg_depth, max_depth
        );
        println!("  JMT depth: ~{} (16-ary)", jmt_depth);

        // Single proof comparison (estimated)
        let jvt_single = max_depth * IPA_PROOF_BYTES + 96;
        let jmt_single = jmt_single_proof_size(jmt_depth);
        println!("  Single-key proof:");
        println!(
            "    JVT: {} bytes ({} levels × {} + 96 EaS)",
            jvt_single, max_depth, IPA_PROOF_BYTES
        );
        println!(
            "    JMT: {} bytes ({} levels × {} + {} leaf)",
            jmt_single, jmt_depth, JMT_SIBLINGS_PER_LEVEL, JMT_LEAF_BYTES
        );
        if jvt_single > 0 {
            println!("    Ratio: {:.1}×", jmt_single as f64 / jvt_single as f64);
        }

        // Batch proof comparison (estimated)
        println!("  Batch proof (multipoint aggregation):");
        for &batch_n in &[10usize, 100, 1000] {
            if batch_n as u32 > n {
                continue;
            }
            let jmt_batch = batch_n * jmt_single;
            println!(
                "    {} keys: JVT = {} bytes (constant!), JMT = {} bytes ({:.0}× smaller)",
                batch_n,
                MULTIPROOF_BYTES,
                jmt_batch,
                jmt_batch as f64 / MULTIPROOF_BYTES as f64
            );
        }

        // Real measured proof sizes (pedersen only)
        #[cfg(feature = "pedersen")]
        {
            use jellyfish_verkle_tree::verkle_proof::inner as vp;

            println!("  Real measured proofs:");

            // Single-key IPA proof
            let sample_key = make_key(0);
            if let Some(real_proof) = vp::prove(&tree.store, &root_key, &sample_key) {
                println!(
                    "    Single IPA proof: {} bytes ({} levels)",
                    real_proof.byte_size(),
                    real_proof.level_proofs.len()
                );
            }

            // Aggregated multiproofs at various batch sizes
            for &batch_n in &[2usize, 10, 50, 100] {
                if batch_n as u32 > n {
                    continue;
                }
                let batch_keys: Vec<Key> = (0..batch_n as u32).map(make_key).collect();
                let start = std::time::Instant::now();
                if let Some(agg_proof) = vp::prove_aggregated(&tree.store, &root_key, &batch_keys) {
                    let elapsed = start.elapsed();
                    println!(
                        "    Multiproof ({:>3} keys): {:>5} B proof, {:>6} B total, {:>3} openings, {:.1?}",
                        batch_n,
                        agg_proof.proof_byte_size(),
                        agg_proof.total_byte_size(),
                        agg_proof.verifier_queries.len(),
                        elapsed,
                    );
                }
            }
        }

        println!();
    }

    // Summary tables
    println!("========================================");
    println!("Summary: Single-key proof sizes");
    println!("========================================");
    println!(
        "{:>10} | {:>10} | {:>10} | {:>8}",
        "Keys", "JVT", "JMT", "Ratio"
    );
    println!("{}", "-".repeat(46));
    for &n in &sizes {
        let jvt_depth = if n <= 256 {
            1
        } else if n <= 65536 {
            2
        } else {
            3
        };
        let jmt_depth = (n as f64).log(16.0).ceil() as usize;
        let jvt = jvt_depth * IPA_PROOF_BYTES + 96;
        let jmt = jmt_single_proof_size(jmt_depth);
        println!(
            "{:>10} | {:>8} B | {:>8} B | {:>6.1}×",
            n,
            jvt,
            jmt,
            jmt as f64 / jvt as f64
        );
    }
    println!();

    println!("========================================");
    println!("Summary: Batch proof sizes (multipoint)");
    println!("========================================");
    println!(
        "{:>10} | {:>6} | {:>10} | {:>12} | {:>8}",
        "Keys", "Batch", "JVT proof", "JMT N×indiv", "Ratio"
    );
    println!("{}", "-".repeat(58));
    for &n in &sizes {
        let jmt_depth = (n as f64).log(16.0).ceil() as usize;
        let jmt_single = jmt_single_proof_size(jmt_depth);
        for &batch in &[10usize, 100, 1000] {
            if batch as u32 > n {
                continue;
            }
            let jmt_batch = batch * jmt_single;
            println!(
                "{:>10} | {:>6} | {:>8} B | {:>10} B | {:>6.0}×",
                n,
                batch,
                MULTIPROOF_BYTES,
                jmt_batch,
                jmt_batch as f64 / MULTIPROOF_BYTES as f64
            );
        }
    }
    println!();

    println!(
        "Key insight: The JVT multipoint proof is {} bytes CONSTANT,",
        MULTIPROOF_BYTES
    );
    println!("regardless of how many keys are included. This is the core");
    println!("verkle tree advantage over Merkle trees.");
}
