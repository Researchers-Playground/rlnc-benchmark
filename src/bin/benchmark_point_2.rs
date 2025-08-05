// use rand::Rng;
use rlnc_benchmark::commitments::ristretto::pedersen::PedersenCommitter;
use rlnc_benchmark::networks::nodes::Node;
use rlnc_benchmark::utils::blocks::create_random_block;
use rlnc_benchmark::utils::bytes::bytes_to_human_readable;
use std::collections::HashMap;
use std::time::Instant;
use sysinfo::System;

struct NetworkConfig {
    num_nodes: usize,
    degree: usize,
    aggressive: usize,
    num_chunks: usize,
    chunk_size: usize,
}

impl NetworkConfig {
    fn new(
        num_nodes: usize,
        degree: usize,
        aggressive: usize,
        num_chunks: usize,
        chunk_size: usize,
    ) -> Self {
        NetworkConfig {
            num_nodes,
            degree,
            aggressive,
            num_chunks,
            chunk_size,
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
    let block = create_random_block(config.num_chunks * config.chunk_size * 32);
    let mut nodes = HashMap::new();

    // insert all node
    nodes.insert(
        0,
        Node::new_source(0, committer, &block, config.num_chunks).unwrap(),
    );
    for id in 1..config.num_nodes {
        nodes.insert(id, Node::new(id, committer, config.num_chunks));
    }

    // init neighbors
    for id in 0..config.num_nodes {
        let mut neighbors = Vec::new();
        for i in 1..=config.degree {
            let neighbor_id = (id + i) % config.num_nodes;
            neighbors.push(neighbor_id);
        }
        let node = nodes.get_mut(&id).unwrap();
        for &neighbor_id in &neighbors {
            node.add_neighbor(neighbor_id);
        }
    }

    let start = Instant::now();
    let mut round_count = 0;
    let mut bandwidth_bytes = 0;
    let mut cpu_usages = Vec::new();
    let mut system = System::new_all();

    while !nodes.values().all(|node| node.decoder.is_already_decoded()) {
        round_count += 1;

        system.refresh_cpu();
        let cpu_usage = system.global_cpu_info().cpu_usage();
        cpu_usages.push(cpu_usage);

        for _ in 0..config.aggressive {
            for id in 0..config.num_nodes {
                let mut neighbor_msgs = Vec::new();
                if let Some(node) = nodes.get_mut(&id) {
                    if let Ok(message) = node.send() {
                        // println!("created message: {:?}", message);

                        bandwidth_bytes += message.piece.data.len() * 32
                            + message.piece.coefficients.len() * 32
                            + message.commitments.len() * 32;

                        for &neighbor_id in &node.neighbors {
                            neighbor_msgs.push((neighbor_id, message.clone()));
                        }
                    }
                }

                for (neighbor_id, msg) in neighbor_msgs {
                    if let Some(neighbor) = nodes.get_mut(&neighbor_id) {
                        neighbor.receive(msg).unwrap_or_else(|e| {
                            println!(
                                "Node {} failed to receive from {}: {:?}",
                                neighbor_id, id, e
                            )
                        });
                    }
                }
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
    let committer = PedersenCommitter::new(256);
    let configs = vec![
        NetworkConfig::new(10, 3, 1, 8, 256),
    ];

    for config in configs {
        let result = simulate_network(&config, &committer);
        println!(
            "Config: nodes={}, degree={}, aggressive={}, num_chunks={}, chunk_size={}",
            config.num_nodes,
            config.degree,
            config.aggressive,
            config.num_chunks,
            config.chunk_size
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