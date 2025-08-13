use rayon::prelude::*;
use rlnc_benchmark::commitments::ristretto::pedersen::PedersenCommitter;
use rlnc_benchmark::networks::node::Node;
use rlnc_benchmark::networks::storage::core::{BlockId, NodeStorage};
use rlnc_benchmark::utils::blocks::create_random_block;
use rlnc_benchmark::utils::bytes::bytes_to_human_readable;
use rlnc_benchmark::utils::eds::{extended_data_share, FlatMatrix};
use rlnc_benchmark::utils::rlnc::RLNCError;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use sysinfo::System;

struct NetworkConfig {
    num_nodes: usize,
    degree: usize,
    aggressive: usize,
    num_chunks: usize,
    num_shreds: usize,
    custody_size: usize,
}

impl NetworkConfig {
    fn new(
        num_nodes: usize,
        degree: usize,
        aggressive: usize,
        num_chunks: usize,
        num_shreds: usize,
        custody_size: usize,
    ) -> Self {
        NetworkConfig {
            num_nodes,
            degree,
            aggressive,
            num_chunks,
            num_shreds,
            custody_size,
        }
    }
}

struct BenchmarkResult {
    time_ms: f64,
    wasted_bandwidth: usize,
    round_trips: usize,
    cpu_usage: f32,
}

/// Simulate network using the new Node API
fn simulate_network(
    config: &NetworkConfig,
    committer: &PedersenCommitter,
    block_size: usize,
    share_size: usize,
) -> BenchmarkResult {
    // Validate constraints
    assert_eq!(
        block_size % share_size,
        0,
        "block_size must be divisible by share_size"
    );
    let k = ((block_size / share_size) as u64).isqrt() as usize; // 16
    assert!(
        k > 0,
        "Invalid k: block_size too small or share_size too large"
    );

    let block = create_random_block(block_size);

    println!(
        "Step 1: Block created - size: {} bytes, k: {}",
        block.len(),
        k
    );

    // Create 2D erasure-coded matrix
    println!(
        "Step 2: Creating FlatMatrix with k={} ({}x{} matrix)",
        k, k, k
    );
    let original_matrix = FlatMatrix::new(&block, share_size, k);
    let extended_matrix = extended_data_share(&original_matrix, k);
    println!(
        "Step 2: Extended matrix dimensions: {:?}, data size: {}",
        extended_matrix.dimensions(),
        bytes_to_human_readable(extended_matrix.data().len())
    );

    // Use block_id = 0 for this run
    let block_id: BlockId = 0;

    // Build nodes map
    let mut nodes: HashMap<usize, Node<PedersenCommitter>> = HashMap::new();

    // 1) Create source node
    let mut source_node = Node::new(
        0,
        committer,
        Vec::new(),
        config.num_shreds,
        config.num_chunks,
        config.custody_size,
    );

    source_node
        .new_source(block_id, block, true, share_size)
        .expect("Step 3: Failed to create source node (new_source)");

    // all shreds
    // let mut raw_extend_block = source_node.storage.list_shreds(block_id);

    nodes.insert(0, source_node);

    // 2) Create other nodes (empty, no data)
    for id in 1..config.num_nodes {
        let node = Node::new(
            id,
            committer,
            Vec::new(),
            config.num_shreds,
            config.num_chunks,
            config.custody_size,
        );
        nodes.insert(id, node);
    }

    // 3) Setup neighbors (graph) - parallel generation
    let all_neighbors: Vec<(usize, Vec<usize>)> = (0..config.num_nodes)
        .into_par_iter()
        .map(|id| {
            let mut neighbors = HashSet::new();
            while neighbors.len() < config.degree && neighbors.len() < config.num_nodes - 1 {
                let neighbor_id = rand::random::<u64>() % (config.num_nodes as u64);
                if neighbor_id as usize != id {
                    neighbors.insert(neighbor_id as usize);
                }
            }
            let neighbors_vec: Vec<usize> = neighbors.into_iter().collect();
            println!("Step 4: Node {} neighbors: {:?}", id, neighbors_vec);
            (id, neighbors_vec)
        })
        .collect();

    // Apply neighbors to nodes
    for (id, neighbors) in all_neighbors {
        if let Some(node) = nodes.get_mut(&id) {
            node.neighbors = neighbors;
        }
    }

    println!(
        "All nodes ids: {}",
        nodes
            .keys()
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Metrics + loop state
    let start = Instant::now();
    let mut round_count: usize = 0;
    let mut wasted_bandwidth: usize = 0;
    let mut cpu_usages: Vec<f32> = Vec::new();
    let mut system = System::new_all();

    loop {
        round_count += 1;
        system.refresh_cpu();
        cpu_usages.push(system.global_cpu_info().cpu_usage());

        for i in 0..config.num_nodes {
            let mut neighbor_and_msgs = Vec::new();

            let source = nodes.get_mut(&i).expect("Node not found in map");
            let neighbors_ids = source.neighbors.clone();
            for neighbor_id in neighbors_ids {
                if let Ok(message) = source.publish(block_id, source.id) {
                    neighbor_and_msgs.push((neighbor_id, message));
                }
            }

            if neighbor_and_msgs.is_empty() {
                continue;
            }

            for (destination_id, msg) in neighbor_and_msgs {
                if destination_id == i {
                    continue;
                }
                if let Some(destination) = nodes.get_mut(&destination_id) {
                    let sz = msg.coded_piece_size_in_bytes();
                    match destination.subcribe(msg) {
                        Ok(_) => {}
                        Err(RLNCError::ReceivedAllPieces) | Err(RLNCError::PieceNotUseful) => {
                            wasted_bandwidth += sz;
                        }
                        Err(_) => {}
                    }
                }
            }
        }

        println!(
            "Wasted Bandwidth: {}, Round trips: {}, Active nodes: {}",
            bytes_to_human_readable(wasted_bandwidth),
            round_count,
            nodes
                .values()
                .filter(|n| n.is_active_node(block_id))
                .count()
        );

        if nodes.values().all(|n| n.is_active_node(block_id)) {
            break;
        }

        if round_count > 200 {
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
        wasted_bandwidth,
        round_trips: round_count,
        cpu_usage: avg_cpu_usage,
    }
}

fn main() {
    let block_size = 2 * 1024 * 1024; // 16KB = 16384 bytes
    let share_size = 512; // share size
    let num_chunks = 16;
    let num_nodes = 100;
    let degree = 12;
    let aggressive = 1; // TODO: currently only do with aggressive = 1

    if block_size % share_size != 0 {
        panic!(
            "Invalid config: block_size={} share_size={} (not divisible)",
            block_size, share_size
        );
    }

    let k = ((block_size / share_size) as u64).isqrt() as usize; // 16
    if k == 0 {
        panic!(
            "Invalid config: block_size={} share_size={} (k=0)",
            block_size, share_size
        );
    }

    let num_shreds = k; // 16
    let extended_matrix_data_len = 4 * block_size;
    let shreds_size = (extended_matrix_data_len as f64 / num_shreds as f64).ceil() as usize; // 64
    let chunk_size_in_scalars = shreds_size / num_chunks;
    if chunk_size_in_scalars == 0 {
        panic!(
            "Invalid config: block_size={} share_size={} (chunk_size_in_scalars=0)",
            block_size, share_size
        );
    }

    // Tạo PedersenCommitter
    let committer = PedersenCommitter::new(chunk_size_in_scalars);
    let bandwidth_limit = num_shreds * num_chunks; // to let benchmark run slow, decrease bw
    let config = NetworkConfig::new(
        num_nodes,
        degree,
        aggressive,
        num_chunks,
        num_shreds,
        bandwidth_limit,
    );

    println!(
        "Running benchmark with block_size={} ({}), share_size={}, k={}",
        block_size,
        bytes_to_human_readable(block_size),
        share_size,
        k
    );

    // Chạy benchmark
    let result = simulate_network(&config, &committer, block_size, share_size);

    // In kết quả
    println!(
        "Config: nodes={}, degree={}, aggressive={}, num_chunks={}, num_shreds={}, custody_size={}",
        config.num_nodes,
        config.degree,
        config.aggressive,
        config.num_chunks,
        config.num_shreds,
        config.custody_size
    );
    println!(
        "Time: {:.2} ms, Wasted Bandwidth: {} ({} bytes), Round trips: {}, Avg CPU Usage: {:.2}%",
        result.time_ms,
        bytes_to_human_readable(result.wasted_bandwidth),
        result.wasted_bandwidth,
        result.round_trips,
        result.cpu_usage
    );
}
