use rand::RngCore;
use std::sync::Arc;
use std::time::Instant;

// network coding
use rand::rngs::StdRng;
use rand::SeedableRng;
use reed_solomon_erasure::galois_8::ReedSolomon;
use rlnc::full::encoder::Encoder;

use utils::eds::{create_extended_matrix, create_matrix};
mod utils;

const ONE_MEGABYTE: usize = 1024 * 1024;

fn main() {
    const BLOCK_SIZE: usize = 2 * ONE_MEGABYTE; // 2MB như Celestia
    let mut block: Vec<u8> = vec![0; BLOCK_SIZE];

    let mut rng = rand::rng();
    rng.fill_bytes(&mut block);

    let k: usize = 128; // same like celestia

    let original_matrix = create_matrix(&block, BLOCK_SIZE, k);
    let mut extended_matrix = create_extended_matrix(&original_matrix, BLOCK_SIZE, k); // 8MB in size

    let rs = Arc::new(ReedSolomon::new(k, k).unwrap());
    let seq_start = Instant::now();
    for row in 0..k {
        rs.encode(&mut extended_matrix[row]).unwrap();
    }
    for col in 0..2 * k {
        let mut column_shares: Vec<Vec<u8>> = Vec::new();
        for row in 0..2 * k {
            column_shares.push(extended_matrix[row][col].clone());
        }
        rs.encode(&mut column_shares).unwrap();
        for row in 0..2 * k {
            extended_matrix[row][col] = column_shares[row].clone();
        }
    }
    let seq_time = seq_start.elapsed();
    println!("📊 Sequential time for encoding with 2D: {:?}", seq_time);

    for row in 0..k {
        for col in 0..k {
            if original_matrix[row][col] != extended_matrix[row][col] {
                println!("🚨 Error at row: {}, col: {}", row, col);
            }
        }
    }

    // RLNC on each cell, create new encoded block
    let piece_size = 10;
    let nums_of_coded_piece = 20;
    let sample_data = extended_matrix[0][0].clone();
    let sample_encoder =
        Encoder::new(sample_data.clone(), piece_size).expect("Failed to create sample encoder");
    let encoded_piece_size = sample_encoder.get_full_coded_piece_byte_len();
    let encoded_start = Instant::now();
    let mut encoded_block_len = 0;
    for i in 0..nums_of_coded_piece {
        let mut rlnc_rng = StdRng::seed_from_u64(42);

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
