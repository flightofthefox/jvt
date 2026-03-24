//! Structural proof size analysis: JVT (verkle) vs hypothetical JMT (Merkle).
//!
//! Computes and compares proof sizes for both single-key and batch proofs.
//! This analysis is structural — it measures the number of components in each
//! proof, not the byte sizes of real cryptographic proofs (since the mock
//! backend doesn't produce realistic proof sizes).
//!
//! Run with: cargo run --example proof_size_analysis

use jellyfish_verkle_tree::node::NodeKey;
use jellyfish_verkle_tree::proof;
use jellyfish_verkle_tree::{Key, MemoryStore, JVT};

fn make_key(i: u32) -> Key {
    let mut key = [0u8; 32];
    key[0..4].copy_from_slice(&i.to_be_bytes());
    key[31] = (i & 0xFF) as u8;
    key
}

/// Estimate JMT (Merkle) single proof size for a given depth.
/// Each level requires 15 sibling hashes (radix-16) × 32 bytes = 480 bytes.
/// Plus the leaf itself (32 bytes key hash + 32 bytes value hash).
fn jmt_single_proof_size(depth: usize) -> usize {
    depth * 15 * 32 + 64 // siblings + leaf
}

/// Estimate JVT (verkle) single proof size for a given depth.
/// Each level requires 1 IPA opening proof ≈ 64 bytes (real IPA).
/// Plus the EaS proof ≈ 96 bytes (stem + c1/c2 openings).
fn jvt_single_proof_size_real(depth: usize) -> usize {
    depth * 64 + 96 // IPA openings + EaS proof
}

/// Estimate JVT aggregated proof size for N keys.
/// The multipoint argument compresses all openings to ~200 bytes.
/// Per-key overhead is just key (32 bytes) + value commitment info (~32 bytes).
fn jvt_batch_proof_size_real(n: usize) -> usize {
    200 + n * 64 // multipoint proof + per-key data
}

fn main() {
    println!("JVT Proof Size Analysis");
    println!("=======================\n");

    // Build trees of various sizes
    let sizes = [10u32, 100, 1000, 10_000];

    for &n in &sizes {
        let mut tree = JVT::new(MemoryStore::new());
        for i in 0..n {
            tree.insert(make_key(i), vec![(i & 0xFF) as u8; 32]);
        }

        let root_key = NodeKey::root(tree.current_version());

        // Measure structural proof depth for several keys
        let sample_keys: Vec<Key> = (0..n.min(100)).map(|i| make_key(i)).collect();
        let mut depths = Vec::new();

        for key in &sample_keys {
            if let Some(p) = proof::prove(&tree.store, &root_key, key) {
                depths.push(p.commitments.len()); // number of internal node levels
            }
        }

        let avg_depth = if depths.is_empty() {
            0.0
        } else {
            depths.iter().sum::<usize>() as f64 / depths.len() as f64
        };
        let max_depth = depths.iter().copied().max().unwrap_or(0);

        // JMT comparison: radix-16, so depth would be roughly log16(n)
        let jmt_avg_depth = if n > 1 {
            (n as f64).log(16.0).ceil() as usize
        } else {
            1
        };

        println!("Tree size: {} keys", n);
        println!(
            "  JVT (256-ary) avg proof depth: {:.1} levels (max {})",
            avg_depth, max_depth
        );
        println!("  JMT (16-ary)  est proof depth: {} levels", jmt_avg_depth);
        println!();

        // Single proof size comparison
        let jvt_depth = max_depth;
        let jvt_single = jvt_single_proof_size_real(jvt_depth);
        let jmt_single = jmt_single_proof_size(jmt_avg_depth);
        println!("  Single proof size (estimated with real crypto):");
        println!(
            "    JVT: {} bytes ({} levels × 64B IPA + 96B EaS)",
            jvt_single, jvt_depth
        );
        println!(
            "    JMT: {} bytes ({} levels × 480B siblings + 64B leaf)",
            jmt_single, jmt_avg_depth
        );
        println!(
            "    Reduction: {:.1}×",
            jmt_single as f64 / jvt_single as f64
        );
        println!();

        // Batch proof comparison for various batch sizes
        let batch_sizes = [10, 100, 1000];
        println!("  Batch proof sizes (estimated):");
        println!(
            "    {:>6} | {:>10} | {:>14} | {}",
            "N keys", "JVT agg", "JMT individual", "Reduction"
        );
        for &batch_n in &batch_sizes {
            if batch_n as u32 > n {
                continue;
            }
            let jvt_batch = jvt_batch_proof_size_real(batch_n);
            let jmt_batch = batch_n * jmt_single; // N individual Merkle proofs
            println!(
                "    {:>6} keys | {:>8} B | {:>10} B | {:.0}×",
                batch_n,
                jvt_batch,
                jmt_batch,
                jmt_batch as f64 / jvt_batch as f64
            );
        }
        println!();

        // Commitment update cost analysis
        println!("  Commitment update (single leaf change):");
        println!(
            "    JVT: {} EC scalar-muls ({} levels, O(1) per level)",
            jvt_depth, jvt_depth
        );
        println!(
            "    JMT: {} hash operations ({} levels, {} sibling reads per level)",
            jmt_avg_depth * 16,
            jmt_avg_depth,
            15
        );
        println!();
        println!("  ---");
        println!();
    }

    // Summary table
    println!("Summary: Proof size comparison (single key, estimated real crypto)");
    println!(
        "{:>10} | {:>12} | {:>12} | {:>10}",
        "Tree size", "JVT (bytes)", "JMT (bytes)", "Reduction"
    );
    println!("{}", "-".repeat(52));
    for &n in &sizes {
        let jvt_depth = if n <= 256 {
            1
        } else if n <= 65536 {
            2
        } else {
            3
        };
        let jmt_depth = if n > 1 {
            (n as f64).log(16.0).ceil() as usize
        } else {
            1
        };
        let jvt = jvt_single_proof_size_real(jvt_depth);
        let jmt = jmt_single_proof_size(jmt_depth);
        println!(
            "{:>10} | {:>10} B | {:>10} B | {:>8.1}×",
            n,
            jvt,
            jmt,
            jmt as f64 / jvt as f64
        );
    }
    println!();

    println!("Summary: Batch proof size (100 keys, estimated real crypto)");
    println!(
        "{:>10} | {:>12} | {:>12} | {:>10}",
        "Tree size", "JVT agg", "JMT 100×ind", "Reduction"
    );
    println!("{}", "-".repeat(52));
    for &n in &sizes {
        if n < 100 {
            continue;
        }
        let jmt_depth = (n as f64).log(16.0).ceil() as usize;
        let jvt_batch = jvt_batch_proof_size_real(100);
        let jmt_batch = 100 * jmt_single_proof_size(jmt_depth);
        println!(
            "{:>10} | {:>8} B | {:>10} B | {:>8.0}×",
            n,
            jvt_batch,
            jmt_batch,
            jmt_batch as f64 / jvt_batch as f64
        );
    }
}
