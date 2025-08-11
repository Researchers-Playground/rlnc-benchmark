// use rlnc_benchmark::commitments::ristretto::pedersen::PedersenCommitter;
// use rlnc_benchmark::networks::node::Node;
// use rlnc_benchmark::networks::storage::core::{BlockId, NodeStorage};
// use rlnc_benchmark::utils::blocks::create_random_block;
// use rlnc_benchmark::utils::bytes::bytes_to_human_readable;
// use rlnc_benchmark::utils::eds::{extended_data_share, FlatMatrix};
// use std::collections::HashMap;
// use std::time::Instant;
// use sysinfo::System;

// struct NetworkConfig {
//     num_nodes: usize,
//     degree: usize,
//     aggressive: usize,
//     num_chunks: usize,
//     num_shreds: usize,
//     bandwidth_limit: usize,
// }

// impl NetworkConfig {
//     fn new(
//         num_nodes: usize,
//         degree: usize,
//         aggressive: usize,
//         num_chunks: usize,
//         num_shreds: usize,
//         bandwidth_limit: usize,
//     ) -> Self {
//         NetworkConfig {
//             num_nodes,
//             degree,
//             aggressive,
//             num_chunks,
//             num_shreds,
//             bandwidth_limit,
//         }
//     }
// }

// struct BenchmarkResult {
//     time_ms: f64,
//     bandwidth_bytes: usize,
//     round_trips: usize,
//     cpu_usage: f32,
// }

// /// Simulate network using the new Node API
// fn simulate_network(
//     config: &NetworkConfig,
//     committer: &PedersenCommitter,
//     block_size: usize,
//     share_size: usize,
// ) -> BenchmarkResult {
//     // Validate constraints
//     assert_eq!(
//         block_size % share_size,
//         0,
//         "block_size must be divisible by share_size"
//     );
//     let k = ((block_size / share_size) as u64).isqrt() as usize; // 16
//     assert!(
//         k > 0,
//         "Invalid k: block_size too small or share_size too large"
//     );

//     let block = create_random_block(block_size);

//     println!(
//         "Step 1: Block created - size: {} bytes, k: {}",
//         block.len(),
//         k
//     );

//     // Create 2D erasure-coded matrix
//     println!(
//         "Step 2: Creating FlatMatrix with k={} ({}x{} matrix)",
//         k, k, k
//     );
//     let original_matrix = FlatMatrix::new(&block, share_size, k);
//     let extended_matrix = extended_data_share(&original_matrix, k);
//     println!(
//         "Step 2: Extended matrix dimensions: {:?}, data size: {}",
//         extended_matrix.dimensions(),
//         bytes_to_human_readable(extended_matrix.data().len())
//     );

//     // Use block_id = 0 for this run
//     let block_id: BlockId = 0;

//     // Build nodes map
//     let mut nodes: HashMap<usize, Node<PedersenCommitter>> = HashMap::new();

//     // 1) Create source node
//     let mut source_node = Node::new(
//         0,
//         committer,
//         Vec::new(),
//         config.bandwidth_limit,
//         config.num_shreds,
//         config.num_chunks,
//     );

//     source_node
//         .new_source(block_id, block, true, share_size)
//         .expect("Step 3: Failed to create source node (new_source)");

//     // all shreds
//     let mut all_raw_shreds = Vec::new();
//     for shred_id in 0..config.num_shreds {
//         if let Some(shred_data) = source_node.storage.get_shred(block_id, shred_id) {
//             all_raw_shreds.extend_from_slice(&shred_data);
//         } else {
//             println!("Warning: shred {} is missing", shred_id);
//         }
//     }

//     // combine to raw extended block
//     let raw_extend_block = all_raw_shreds; // Vec<u8> chứa toàn bộ dữ liệu extended

//     nodes.insert(0, source_node);

//     // 2) Create other nodes (empty, no data)
//     for id in 1..config.num_nodes {
//         let node = Node::new(
//             id,
//             committer,
//             Vec::new(),
//             config.bandwidth_limit,
//             config.num_shreds,
//             config.num_chunks,
//         );
//         nodes.insert(id, node);
//     }

//     // 3) Setup neighbors (graph)
//     for id in 0..config.num_nodes {
//         let mut neighbors = Vec::new();
//         for i in 1..=config.degree {
//             let neighbor_id = (id + i) % config.num_nodes;
//             neighbors.push(neighbor_id);
//         }
//         println!("Step 4: Node {} neighbors: {:?}", id, neighbors);
//         if let Some(node) = nodes.get_mut(&id) {
//             node.neighbors = neighbors;
//         }
//     }

//     // Metrics + loop state
//     let start = Instant::now();
//     let mut round_count: usize = 0;
//     let mut bandwidth_bytes: usize = 0;
//     let mut cpu_usages: Vec<f32> = Vec::new();
//     let mut system = System::new_all();

//     // 5) Main rounds: run until all nodes have reconstructed the block
//     loop {
//         // Check termination
//         let all_decoded = nodes
//             .values()
//             .all(|n| n.try_reconstruct_block(block_id, true).is_some());
//         if all_decoded {
//             break;
//         }

//         round_count += 1;
//         println!("Step 6: Starting round {}", round_count);

//         system.refresh_cpu();
//         let cpu_usage = system.global_cpu_info().cpu_usage();
//         cpu_usages.push(cpu_usage);

//         for _ in 0..config.aggressive {
//             // Collect messages
//             let mut neighbor_msgs: Vec<(usize, Vec<_>, usize)> = Vec::new();
//             for id in 0..config.num_nodes {
//                 if let Some(node) = nodes.get(&id) {
//                     let outbound = node.send(block_id, id);
//                     for (neighbor_id, msgs) in outbound {
//                         for msg in &msgs {
//                             let piece = &msg.piece;
//                             let bytes = piece.data.len() * 32 + piece.coefficients.len() * 32;
//                             bandwidth_bytes += bytes;
//                         }
//                         neighbor_msgs.push((neighbor_id, msgs, id));
//                     }
//                 }
//             }

//             // Deliver messages
//             for (neighbor_id, msgs, source_id) in neighbor_msgs.drain(..) {
//                 if let Some(neighbor) = nodes.get_mut(&neighbor_id) {
//                     neighbor.receive_messages(msgs).unwrap_or_else(|e| {
//                         println!(
//                             "Step 8: Node {} failed to receive from {}: {:?}",
//                             neighbor_id, source_id, e
//                         );
//                     });
//                 }
//             }
//         }

//         // Log decoding progress
//         for id in 0..config.num_nodes {
//             if let Some(node) = nodes.get(&id) {
//                 let decoded = node.try_reconstruct_block(block_id, true).is_some();
//                 let stored_pieces = node
//                     .storage
//                     .pieces_index
//                     .get(&(block_id, 0))
//                     .map(|s| s.len())
//                     .unwrap_or(0);
//                 println!(
//                     "Step 9: Node {}: decoded={}, stored_pieces_example_shred0={}",
//                     id, decoded, stored_pieces
//                 );
//             }
//         }

//         // Prevent infinite loop
//         if round_count > 10000 {
//             println!("Terminating after excessive rounds");
//             break;
//         }
//     }

//     let duration = start.elapsed();
//     let avg_cpu_usage = if !cpu_usages.is_empty() {
//         cpu_usages.iter().sum::<f32>() / cpu_usages.len() as f32
//     } else {
//         0.0
//     };

//     // just to get the result
//     let a_neighbor = nodes.get(&1).unwrap();
//     let reconstructed_block = a_neighbor.try_reconstruct_block(block_id, true).unwrap();

//     if reconstructed_block == raw_extend_block {
//         println!("reconstructed_block == raw_extend_block CHECKED!")
//     } else {
//         println!("reconstruct failed, the data is different!")
//     }

//     BenchmarkResult {
//         time_ms: duration.as_secs_f64() * 1000.0,
//         bandwidth_bytes,
//         round_trips: round_count,
//         cpu_usage: avg_cpu_usage,
//     }
// }

fn main() {
    // let block_size = 2 * 1024 * 1024; // 16KB = 16384 bytes
    // let share_size = 512; // share size
    // let num_chunks = 16;
    // let num_nodes = 100;
    // let degree = 12;
    // let aggressive = 1;

    // if block_size % share_size != 0 {
    //     panic!(
    //         "Invalid config: block_size={} share_size={} (not divisible)",
    //         block_size, share_size
    //     );
    // }

    // let k = ((block_size / share_size) as u64).isqrt() as usize; // 16
    // if k == 0 {
    //     panic!(
    //         "Invalid config: block_size={} share_size={} (k=0)",
    //         block_size, share_size
    //     );
    // }

    // let num_shreds = k; // 16
    // let extended_matrix_data_len = 4 * block_size;
    // let shreds_size = (extended_matrix_data_len as f64 / num_shreds as f64).ceil() as usize; // 64
    // let chunk_size_in_scalars = shreds_size / num_chunks;
    // if chunk_size_in_scalars == 0 {
    //     panic!(
    //         "Invalid config: block_size={} share_size={} (chunk_size_in_scalars=0)",
    //         block_size, share_size
    //     );
    // }

    // // Tạo PedersenCommitter
    // let committer = PedersenCommitter::new(chunk_size_in_scalars);
    // let bandwidth_limit = num_shreds * num_chunks; // to let benchmark run slow, decrease bw
    // let config = NetworkConfig::new(
    //     num_nodes,
    //     degree,
    //     aggressive,
    //     num_chunks,
    //     num_shreds,
    //     bandwidth_limit,
    // );

    // println!(
    //     "Running benchmark with block_size={} ({}), share_size={}, k={}",
    //     block_size,
    //     bytes_to_human_readable(block_size),
    //     share_size,
    //     k
    // );

    // // Chạy benchmark
    // let result = simulate_network(&config, &committer, block_size, share_size);

    // // In kết quả
    // println!(
    //     "Config: nodes={}, degree={}, aggressive={}, num_chunks={}, num_shreds={}, bandwidth_limit={}",
    //     config.num_nodes,
    //     config.degree,
    //     config.aggressive,
    //     config.num_chunks,
    //     config.num_shreds,
    //     config.bandwidth_limit
    // );
    // println!(
    //     "Time: {:.2} ms, Bandwidth: {} ({} bytes), Round trips: {}, Avg CPU Usage: {:.2}%",
    //     result.time_ms,
    //     bytes_to_human_readable(result.bandwidth_bytes),
    //     result.bandwidth_bytes,
    //     result.round_trips,
    //     result.cpu_usage
    // );
}
