use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rlnc_benchmark::commitments::ristretto::pedersen::PedersenCommitter;
use rlnc_benchmark::erase_code_methods::network_coding::{NetworkCodingError, RLNCErasureCoder};
use rlnc_benchmark::networks::node::Node;
use rlnc_benchmark::utils::blocks::create_random_block;
use rlnc_benchmark::utils::bytes::bytes_to_human_readable;
use rlnc_benchmark::utils::eds::{extended_data_share, FlatMatrix};
use std::collections::HashMap;
use std::time::Instant;
use sysinfo::System;

const ONE_MEGABYTE: usize = 1024 * 1024;

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

fn simulate_network(config: &NetworkConfig, committer: &PedersenCommitter) -> BenchmarkResult {
    const BLOCK_SIZE: usize = 128 * 1024; // 128KB
    const SHARE_SIZE: usize = 512;
    let k = (BLOCK_SIZE / SHARE_SIZE).isqrt(); // k=16
    let block = create_random_block(BLOCK_SIZE);
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
    let original_matrix = FlatMatrix::new(&block, SHARE_SIZE, k);
    let extended_matrix = extended_data_share(&original_matrix, k);
    println!(
        "Step 2: Extended matrix dimensions: {:?}, data size: {}",
        extended_matrix.dimensions(),
        bytes_to_human_readable(extended_matrix.data().len())
    );

    let mut nodes = HashMap::new();

    // Khởi tạo source node with extended matrix data
    nodes.insert(
        0,
        Node::new_source(
            0,
            committer,
            extended_matrix.data().to_vec(),
            config.num_chunks,
            config.num_shreds,
            true, // Sử dụng RLNC
            config.bandwidth_limit,
        )
        .expect("Step 3: Failed to create source node"),
    );

    // Khởi tạo các node khác
    for id in 1..config.num_nodes {
        let erasure_coder = rlnc_benchmark::erase_code_methods::ErasureCoderType::RLNC(
            RLNCErasureCoder::new(committer, None, config.num_chunks)
                .expect("Step 3: Failed to create RLNC coder"),
        );
        nodes.insert(
            id,
            Node::new(
                id,
                committer,
                erasure_coder,
                Vec::new(),
                config.bandwidth_limit,
            ),
        );
    }

    // Khởi tạo neighbors
    for id in 0..config.num_nodes {
        let mut neighbors = Vec::new();
        for i in 1..=config.degree {
            let neighbor_id = (id + i) % config.num_nodes;
            neighbors.push(neighbor_id);
        }
        println!("Step 4: Node {} neighbors: {:?}", id, neighbors);
        let node = nodes.get_mut(&id).unwrap();
        node.neighbors = neighbors;
    }

    let start = Instant::now();
    let mut round_count = 0;
    let mut bandwidth_bytes = 0;
    let mut cpu_usages = Vec::new();
    let mut system = System::new_all();

    // Lấy commitment từ source node
    let commitment = nodes
        .get(&0)
        .and_then(|source| match &source.erasure_coder {
            rlnc_benchmark::erase_code_methods::ErasureCoderType::RLNC(coder) => {
                Some(coder.encoder.get_commitment())
            }
            _ => None,
        })
        .expect("Step 5: Source node is not RLNC")
        .expect("Step 5: Failed to get commitment from source node");
    println!("Step 5: Commitment obtained, length: {}", commitment.len());

    while !nodes.values().all(|node| node.erasure_coder.is_decoded()) {
        round_count += 1;
        println!("Step 6: Starting round {}", round_count);

        system.refresh_cpu();
        let cpu_usage = system.global_cpu_info().cpu_usage();
        cpu_usages.push(cpu_usage);

        for _ in 0..config.aggressive {
            let mut neighbor_msgs = Vec::new();
            for id in 0..config.num_nodes {
                if let Some(node) = nodes.get(&id) {
                    if let Ok(messages) = node.send() {
                        for (neighbor_id, shreds) in messages {
                            for shred in &shreds {
                                match shred {
                                    rlnc_benchmark::erase_code_methods::CodedData::RLNC(piece) => {
                                        println!(
                                            "Step 7: Shred from node {} to {}: coefficients_len={:?}, data_len={}",
                                            id, neighbor_id, piece.coefficients.len(), piece.data.len()
                                        );
                                        bandwidth_bytes +=
                                            piece.data.len() * 32 + piece.coefficients.len() * 32;
                                    }
                                    rlnc_benchmark::erase_code_methods::CodedData::RS(data) => {
                                        bandwidth_bytes += data.len();
                                    }
                                }
                            }
                            neighbor_msgs.push((neighbor_id, shreds, id));
                        }
                    }
                }
            }

            for (neighbor_id, shreds, source_id) in neighbor_msgs {
                if let Some(neighbor) = nodes.get_mut(&neighbor_id) {
                    neighbor
                        .receive(shreds, Some(&commitment))
                        .unwrap_or_else(|e| {
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
                println!(
                    "Step 9: Node {}: decoded={}, coded_block_size={}",
                    id,
                    node.erasure_coder.is_decoded(),
                    node.coded_block.len()
                );
            }
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
    const BLOCK_SIZE: usize = 128 * 1024; // 128KB
    const SHARE_SIZE: usize = 512; // Same as reference
    let k: usize = (BLOCK_SIZE / SHARE_SIZE).isqrt(); // k=16
    let num_chunks = 8;
    let num_shreds = k; // 16
    let extended_size = 4 * BLOCK_SIZE; // 32x32 matrix = 524,288 bytes
    let chunk_size_in_scalars = (extended_size / num_chunks) / 32; // 524,288 / 8 / 32 = 2,048 scalars

    // Initialize PedersenCommitter with enough generators
    let committer = PedersenCommitter::new(chunk_size_in_scalars); // n = 2,048

    let configs = vec![NetworkConfig::new(5, 3, 1, num_chunks, num_shreds, 8)];

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
