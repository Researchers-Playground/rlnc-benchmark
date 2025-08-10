use rlnc_benchmark::rlnc::storage::NodeStorage;

use rlnc_benchmark::commitments::ristretto::pedersen::PedersenCommitter;
use rlnc_benchmark::networks::node::Node;
use rlnc_benchmark::utils::blocks::create_random_block;
use rlnc_benchmark::utils::bytes::bytes_to_human_readable;
use rlnc_benchmark::utils::eds::{extended_data_share, FlatMatrix};

use std::collections::HashMap;
use std::time::Instant;
use sysinfo::System;

use rlnc_benchmark::rlnc::storage::BlockId;

struct NetworkConfig {
    num_nodes: usize,
    degree: usize,
    aggressive: usize,
    num_chunks: usize,
    num_shreds: usize,
    bandwidth_limit: usize,
}

impl NetworkConfig {
    fn new(
        num_nodes: usize,
        degree: usize,
        aggressive: usize,
        num_chunks: usize,
        num_shreds: usize,
        bandwidth_limit: usize,
    ) -> Self {
        NetworkConfig {
            num_nodes,
            degree,
            aggressive,
            num_chunks,
            num_shreds,
            bandwidth_limit,
        }
    }
}

struct BenchmarkResult {
    time_ms: f64,
    bandwidth_bytes: usize,
    round_trips: usize,
    cpu_usage: f32,
}

/// Simulate network using the new Node API (Node::new_source, Node::new, Node::send, Node::receive_messages)
fn simulate_network(config: &NetworkConfig, committer: &PedersenCommitter) -> BenchmarkResult {
    const BLOCK_SIZE: usize = 128 * 1024; // 128KB
    const SHARE_SIZE: usize = 512;
    // k used to compute number of shreds in original script (keeps same semantics)
    let k = (BLOCK_SIZE / SHARE_SIZE).isqrt(); // k=16
    let block = create_random_block(BLOCK_SIZE);

    println!(
        "Step 1: Block created - size: {} bytes, k: {}",
        block.len(),
        k
    );

    // Create 2D erasure-coded matrix (unchanged from original)
    println!(
        "Step 2: Creating FlatMatrix with k={} ({}x{} matrix)",
        k, k, k
    );
    let original_matrix = FlatMatrix::new(&block, SHARE_SIZE, k);
    let extended_matrix = extended_data_share(&original_matrix, k);
    println!(
        "Step 2: Extended matrix dimensions: {:?}, data size: {}",
        extended_matrix.dimensions(),
        bytes_to_human_readable(extended_matrix.data().len())
    );

    // We'll use block_id = 0 for this run
    let block_id: BlockId = 0;

    // Build nodes map using the new Node API
    let mut nodes: HashMap<usize, Node<PedersenCommitter>> = HashMap::new();

    // 1) Create source node: new_source will split extended_data into shreds and produce per-shred RLNC-coded pieces + commitments in storage
    // Node::new signature (id, committer, neighbors, bandwidth_limit, num_shreds, num_chunks_per_shred)
    let mut source_node = Node::new(
        0,
        committer,
        Vec::new(),
        config.bandwidth_limit,
        config.num_shreds,
        config.num_chunks,
    );

    source_node
        .new_source(block_id, extended_matrix.data().to_vec(), true)
        .expect("Step 3: Failed to create source node (new_source)");

    nodes.insert(0, source_node);

    // 2) Create other nodes (empty, no data)
    for id in 1..config.num_nodes {
        let node = Node::new(
            id,
            committer,
            Vec::new(),
            config.bandwidth_limit,
            config.num_shreds,
            config.num_chunks,
        );
        nodes.insert(id, node);
    }

    // 3) Setup neighbors (graph)
    for id in 0..config.num_nodes {
        let mut neighbors = Vec::new();
        for i in 1..=config.degree {
            let neighbor_id = (id + i) % config.num_nodes;
            neighbors.push(neighbor_id);
        }
        println!("Step 4: Node {} neighbors: {:?}", id, neighbors);
        if let Some(node) = nodes.get_mut(&id) {
            node.neighbors = neighbors;
        }
    }

    // Metrics + loop state
    let start = Instant::now();
    let mut round_count: usize = 0;
    let mut bandwidth_bytes: usize = 0;
    let mut cpu_usages: Vec<f32> = Vec::new();
    let mut system = System::new_all();

    // 4) For logging: fetch one example commitment length (per-shred commitment)
    // We'll fetch commitment from source storage for shred 0 (source has already stored commitments in new_source)
    let example_commitment_len = nodes
        .get(&0)
        .and_then(|n| n.storage.get_commitment(block_id, 0))
        .map(|c| c.len())
        .unwrap_or(0);
    println!(
        "Step 5: Example commitment obtained for shred 0, length: {}",
        example_commitment_len
    );

    // 5) Main rounds: run until all nodes have reconstructed the block
    loop {
        // Check termination: all nodes reconstructed the block (try_reconstruct_block returns Some)
        let all_decoded = nodes
            .values()
            .all(|n| n.try_reconstruct_block(block_id, true).is_some());
        if all_decoded {
            break;
        }

        round_count += 1;
        println!("Step 6: Starting round {}", round_count);

        system.refresh_cpu();
        let cpu_usage = system.global_cpu_info().cpu_usage();
        cpu_usages.push(cpu_usage);

        for _ in 0..config.aggressive {
            // collect messages to deliver in this micro-iteration
            let mut neighbor_msgs: Vec<(usize, Vec<_>, usize)> = Vec::new();
            for id in 0..config.num_nodes {
                if let Some(node) = nodes.get(&id) {
                    // Node::send returns Vec<(neighbor_id, Vec<Message<Commitment>>)>
                    let outbound = node.send(block_id, id);
                    for (neighbor_id, msgs) in outbound {
                        // measure bandwidth for each message piece
                        for msg in &msgs {
                            // sized in bytes: data scalars * 32 + coeffs * 32
                            let piece = &msg.piece;
                            let bytes = piece.data.len() * 32 + piece.coefficients.len() * 32;
                            bandwidth_bytes += bytes;
                        }
                        neighbor_msgs.push((neighbor_id, msgs, id));
                    }
                }
            }

            // deliver collected messages
            for (neighbor_id, msgs, source_id) in neighbor_msgs.drain(..) {
                if let Some(neighbor) = nodes.get_mut(&neighbor_id) {
                    neighbor.receive_messages(msgs).unwrap_or_else(|e| {
                        println!(
                            "Step 8: Node {} failed to receive from {}: {:?}",
                            neighbor_id, source_id, e
                        );
                    });
                }
            }
        }

        // Log decoding progress
        for id in 0..config.num_nodes {
            if let Some(node) = nodes.get(&id) {
                let decoded = node.try_reconstruct_block(block_id, true).is_some();
                let stored_pieces = node
                    .storage
                    .pieces_index
                    .get(&(block_id, 0))
                    .map(|s| s.len())
                    .unwrap_or(0);
                println!(
                    "Step 9: Node {}: decoded={}, stored_pieces_example_shred0={}",
                    id, decoded, stored_pieces
                );
            }
        }

        // safety: prevent infinite loop in pathological cases
        if round_count > 10000 {
            println!("Terminating after excessive rounds");
            break;
        }
    }

    let duration = start.elapsed();
    let avg_cpu_usage = if !cpu_usages.is_empty() {
        cpu_usages.iter().sum::<f32>() / cpu_usages.len() as f32
    } else {
        0.0
    };

    BenchmarkResult {
        time_ms: duration.as_secs_f64() * 1000.0,
        bandwidth_bytes,
        round_trips: round_count,
        cpu_usage: avg_cpu_usage,
    }
}

fn main() {
    // Giảm mạnh để chạy nhanh hơn
    const BLOCK_SIZE: usize = 4 * 1024; // 4KB thay vì 128KB
    const SHARE_SIZE: usize = 512; // Giữ nguyên như reference
    let k: usize = (BLOCK_SIZE / SHARE_SIZE).isqrt(); // k=2
    let num_chunks = 2; // giảm từ 8 xuống 2
    let num_shreds = k; // 2
    let chunk_size_in_scalars = SHARE_SIZE / 32; // 512 / 32 = 16 scalars
    let committer = PedersenCommitter::new(chunk_size_in_scalars);

    // Chỉ 1 config nhỏ để chạy nhanh
    let configs = vec![NetworkConfig::new(2, 1, 1, num_chunks, num_shreds, 1)];

    for config in configs {
        let result = simulate_network(&config, &committer);
        println!(
            "Config: nodes={}, degree={}, aggressive={}, num_chunks={}, num_shreds={}, bandwidth_limit={}",
            config.num_nodes,
            config.degree,
            config.aggressive,
            config.num_chunks,
            config.num_shreds,
            config.bandwidth_limit
        );
        println!(
            "Time: {:.2} ms, Bandwidth: {} ({} bytes), Round trips: {}, Avg CPU Usage: {:.2}%",
            result.time_ms,
            bytes_to_human_readable(result.bandwidth_bytes),
            result.bandwidth_bytes,
            result.round_trips,
            result.cpu_usage
        );
    }
}

