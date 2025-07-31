use std::time::Instant;

// network coding
use rlnc::full::encoder::Encoder;

use utils::blocks::create_random_block;
use utils::eds::{create_matrix, extended_data_share};
mod utils;

const ONE_MEGABYTE: usize = 1024 * 1024;

fn main() {
    const BLOCK_SIZE: usize = 2 * ONE_MEGABYTE; // 2MB như Celestia
    let k: usize = 128;

    let block: Vec<u8> = create_random_block(BLOCK_SIZE);

    // <BEGIN: 2D ERASURE BLOCK>
    let rs_start = Instant::now();
    let original_matrix = create_matrix(&block, BLOCK_SIZE, k);
    let extended_matrix = extended_data_share(&original_matrix, BLOCK_SIZE, k);
    let rs_time = rs_start.elapsed();
    println!("📊 RS time for encoding with 2D: {:?}", rs_time);
    // <END: 2D ERASURE BLOCK>

    // RLNC on each cell, create new encoded block
    let piece_size = 10;
    let nums_of_coded_block = 20;
    let sample_data = extended_matrix[0][0].clone();
    let sample_encoder =
        Encoder::new(sample_data.clone(), piece_size).expect("Failed to create sample encoder");
    let encoded_piece_size = sample_encoder.get_full_coded_piece_byte_len();
    let encoded_start = Instant::now();
    let mut encoded_block_len = 0;
    for _ in 0..nums_of_coded_block {
        let mut rlnc_rng = rand::rng();
        let total_encoded_size = k * k * encoded_piece_size;
        let mut encoded_block: Vec<u8> = Vec::with_capacity(total_encoded_size);
        for row in 0..k {
            for col in 0..k {
                let raw_data = extended_matrix[row][col].clone();
                let encoder = Encoder::new(raw_data.clone(), piece_size)
                    .expect("Failed to create RLNC encoder");
                let encoded_data = encoder.code(&mut rlnc_rng);
                encoded_block.extend_from_slice(&encoded_data);
            }
        }
        encoded_block_len = encoded_block.len();
    }
    let encoded_time = encoded_start.elapsed();

    // before encode
    println!("📋 RLNC Configuration:");
    println!("  - Original cell size: {} bytes", sample_data.len());
    println!("  - Pieces per cell: {}", piece_size);
    println!(
        "  - Original piece size: {} bytes",
        sample_encoder.get_piece_byte_len()
    );
    println!("  - Encoded piece size: {} bytes", encoded_piece_size);
    println!("  - Total cells to encode: {}", k * k);

    // after encode
    println!("\n🎉 RLNC Encoding Results:");
    println!("  - Encoding time: {:?}", encoded_time);
    println!(
        "  - Encoded size: {} bytes ({:.2} MB)",
        encoded_block_len,
        encoded_block_len as f64 / ONE_MEGABYTE as f64
    );
    println!(
        "  - Size reduction: {:.1}%",
        (1.0 - encoded_block_len as f64 / BLOCK_SIZE as f64) * 100.0
    );
}
