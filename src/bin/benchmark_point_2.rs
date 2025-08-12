use curve25519_dalek::RistrettoPoint;
use rlnc_benchmark::commitments::ristretto::pedersen::PedersenCommitter;
use rlnc_benchmark::networks::message::BroadcastCodedBlockMsg;
use rlnc_benchmark::networks::node::Node;
use rlnc_benchmark::networks::storage::core::{BlockId, NodeStorage};
use rlnc_benchmark::utils::blocks::create_random_block;
use rlnc_benchmark::utils::bytes::bytes_to_human_readable;
use rlnc_benchmark::utils::eds::{extended_data_share, FlatMatrix};
use std::collections::HashMap;
use std::time::Instant;
use sysinfo::System;

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

/// Simulate network using the new Node API with detailed timing logs
fn simulate_network(
    config: &NetworkConfig,
    committer: &PedersenCommitter,
    block_size: usize, // raw, no extend 2mb
    share_size: usize, // 512
) -> BenchmarkResult {
    // Validate constraints
    assert_eq!(
        block_size % share_size,
        0,
        "block_size must be divisible by share_size"
    );
    let k = ((block_size / share_size) as u64).isqrt() as usize; // kxk = 64x64 matrix
    assert!(
        k > 0,
        "Invalid k: block_size too small or share_size too large"
    );

    let block = create_random_block(block_size); // 2mb

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
    let original_matrix = FlatMatrix::new(&block, share_size, k); // 2mb
    let extended_matrix = extended_data_share(&original_matrix, k); // 8mb
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
    let start_step = Instant::now();
    let mut source_node = Node::new(
        0,
        committer,
        Vec::new(),
        config.bandwidth_limit,
        config.num_shreds,
        config.num_chunks,
    );
    println!(
        "Step 3: Created source node in {:.2} ms",
        start_step.elapsed().as_secs_f64() * 1000.0
    );

    // already extended inside
    let start_new_source = Instant::now();
    source_node
        .new_source(block_id, block, true, share_size)
        .expect("Step 3: Failed to create source node (new_source)");
    // new_source in 24s!!!!
    println!(
        "Step 3: new_source completed in {:.2} ms",
        start_new_source.elapsed().as_secs_f64() * 1000.0
    );

    // all shreds
    let start_shred_collect = Instant::now();
    let mut all_raw_shreds = Vec::new();
    for shred_id in 0..config.num_shreds {
        if let Some(shred_data) = source_node.storage.get_shred(block_id, shred_id) {
            all_raw_shreds.extend_from_slice(&shred_data);
        } else {
            println!("Warning: shred {} is missing", shred_id);
        }
    }
    let raw_extend_block = all_raw_shreds; // Vec<u8> chứa toàn bộ dữ liệu extended
    println!(
        "Step 3: Collected shreds in {:.2} ms",
        start_shred_collect.elapsed().as_secs_f64() * 1000.0
    );

    nodes.insert(0, source_node);

    // 2) Create other nodes (empty, no data)
    let start_create_nodes = Instant::now();
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
    println!(
        "Step 4: Created {} nodes in {:.2} ms",
        config.num_nodes - 1,
        start_create_nodes.elapsed().as_secs_f64() * 1000.0
    );

    // 3) Setup neighbors (graph)
    let start_setup_neighbors = Instant::now();
    for id in 0..config.num_nodes {
        let mut neighbors = Vec::new();
        for i in 1..=config.degree {
            let neighbor_id = (id + i) % config.num_nodes;
            neighbors.push(neighbor_id);
        }
        println!("Step 5: Node {} neighbors: {:?}", id, neighbors);
        if let Some(node) = nodes.get_mut(&id) {
            node.neighbors = neighbors;
        }
    }
    println!(
        "Step 5: Setup neighbors in {:.2} ms",
        start_setup_neighbors.elapsed().as_secs_f64() * 1000.0
    );

    // Metrics + loop state
    let start = Instant::now();
    let mut round_count: usize = 0;
    let mut bandwidth_bytes: usize = 0;
    let mut cpu_usages: Vec<f32> = Vec::new();
    let mut system = System::new_all();

    // 5) Main rounds: run until all nodes have reconstructed the block
    loop {
        let round_start = Instant::now();
        // Check termination
        let start_check_decode = Instant::now();
        let all_decoded = nodes.values().all(|n| n.already_decode_block(block_id));
        println!(
            "Step 6.1: Round {} - Checked decode status in {:.2} ms",
            round_count + 1,
            start_check_decode.elapsed().as_secs_f64() * 1000.0
        );
        if all_decoded {
            println!("Step 6: All nodes decoded block in round {}", round_count);
            break;
        }

        round_count += 1;
        println!("Step 6: Starting round {}", round_count);

        let start_cpu_refresh = Instant::now();
        system.refresh_cpu();
        let cpu_usage = system.global_cpu_info().cpu_usage();
        cpu_usages.push(cpu_usage);
        println!(
            "Step 6.2: CPU refresh in {:.2} ms, usage: {:.2}%",
            start_cpu_refresh.elapsed().as_secs_f64() * 1000.0,
            cpu_usage
        );

        for aggressive_iter in 0..config.aggressive {
            let aggressive_start = Instant::now();
            // Collect messages
            let start_publish = Instant::now();
            let mut neighbor_msgs: Vec<(usize, BroadcastCodedBlockMsg<Vec<RistrettoPoint>>)> =
                Vec::new();
            for id in 0..config.num_nodes {
                if let Some(node) = nodes.get(&id) {
                    let publish_start = Instant::now();
                    // time publish if that node has data is about 23s now!!!
                    if let Ok(messages) = node.publish(block_id, id) {
                        neighbor_msgs.extend(messages);
                    }
                    println!(
                        "Step 6.3: Node {} publish in {:.2} ms",
                        id,
                        publish_start.elapsed().as_secs_f64() * 1000.0
                    );
                }
            }
            println!(
                "Step 6.3: Publish phase for aggressive iter {} in {:.2} ms",
                aggressive_iter,
                start_publish.elapsed().as_secs_f64() * 1000.0
            );

            // Deliver messages
            let start_subscribe = Instant::now();
            for (neighbor_id, msg) in neighbor_msgs.drain(..) {
                if let Some(neighbor) = nodes.get_mut(&neighbor_id) {
                    let subscribe_start = Instant::now();
                    // a node if has a messages receive, subcribe in about 1.5s
                    neighbor.subcribe(msg).unwrap_or_else(|e| {
                        println!(
                            "Step 6.4: Node {} failed to subscribe: {:?}",
                            neighbor_id, e
                        );
                    });
                    println!(
                        "Step 6.4: Node {} subscribe in {:.2} ms",
                        neighbor_id,
                        subscribe_start.elapsed().as_secs_f64() * 1000.0
                    );
                }
            }
            println!(
                "Step 6.4: Subscribe phase for aggressive iter {} in {:.2} ms",
                aggressive_iter,
                start_subscribe.elapsed().as_secs_f64() * 1000.0
            );

            println!(
                "Step 6: Aggressive iter {} completed in {:.2} ms",
                aggressive_iter,
                aggressive_start.elapsed().as_secs_f64() * 1000.0
            );
        }

        // Log decoding progress
        let start_log_progress = Instant::now();
        for id in 0..config.num_nodes {
            if let Some(node) = nodes.get(&id) {
                let decoded = node.already_decode_block(block_id);
                let stored_pieces = node.storage.list_piece_indices(block_id, 0).len();
                println!(
                    "Step 6.5: Node {}: decoded={}, stored_pieces_example_shred0={}",
                    id, decoded, stored_pieces
                );
            }
        }
        println!(
            "Step 6.5: Log progress in {:.2} ms",
            start_log_progress.elapsed().as_secs_f64() * 1000.0
        );

        println!(
            "Step 6: Round {} completed in {:.2} ms",
            round_count,
            round_start.elapsed().as_secs_f64() * 1000.0
        );

        // Prevent infinite loop
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

    // just to get the result
    let start_reconstruct = Instant::now();
    let a_neighbor = nodes.get(&1).unwrap();
    let reconstructed_block = a_neighbor
        .try_reconstruct_block(block_id, true)
        .unwrap_or_else(|| {
            println!("Node 1 failed to reconstruct block");
            Vec::new()
        });
    println!(
        "Step 7: Reconstruct block in {:.2} ms",
        start_reconstruct.elapsed().as_secs_f64() * 1000.0
    );

    if reconstructed_block == raw_extend_block {
        println!("reconstructed_block == raw_extend_block CHECKED!");
    } else {
        println!("reconstruct failed, the data is different!");
    }

    BenchmarkResult {
        time_ms: duration.as_secs_f64() * 1000.0,
        bandwidth_bytes,
        round_trips: round_count,
        cpu_usage: avg_cpu_usage,
    }
}

fn main() {
    let block_size = 2 * 1024 * 1024; // 2MB
    let share_size = 512; // 512 bytes per share
    let num_chunks = 16; // 1 share contains 16 chunks
    let num_nodes = 100; // network with 100 nodes
    let degree = 12; // a node will connect with 12 neighbors
    let aggressive = 1; // TODO: check later this config
    let k = ((block_size / share_size) as u64).isqrt() as usize; // a share is 512 bytes -> there are 4096 cells -> divide to 64x64 matrix

    if block_size % share_size != 0 {
        panic!(
            "Invalid config: block_size={} share_size={} (not divisible)",
            block_size, share_size
        );
    }

    if k == 0 {
        panic!(
            "Invalid config: block_size={} share_size={} (k=0)",
            block_size, share_size
        );
    }

    let num_shreds = k; // current here a shred is bigger than a cell, we have 64 shreds in this config
    let extended_matrix_data_len = 4 * block_size; // 8MB
    let shreds_size = (extended_matrix_data_len as f64 / num_shreds as f64).ceil() as usize; // extend first -> divide to shreds -> so the size of shred is 128KB
    let chunk_size_in_scalars = shreds_size / num_chunks; // a shred is 128kb so a chunk is 128kb / 16 = 8kb
    if chunk_size_in_scalars == 0 {
        panic!(
            "Invalid config: block_size={} share_size={} chunk_size_in_scalars={}",
            block_size, share_size, chunk_size_in_scalars
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
