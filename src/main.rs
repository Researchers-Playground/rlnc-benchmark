use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::Scalar;
use rlnc::full::encoder::Encoder;
use std::time::Instant;
// network coding
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use rlnc_benchmark::commitments::pedersen::Committer;
use utils::blocks::create_random_block;
use utils::eds::{extended_data_share, FlatMatrix};
mod utils;
use rayon::prelude::*;

const ONE_MEGABYTE: usize = 1024 * 1024;

fn pad_and_chunk(data: &[u8], num_chunks: usize, boundary_marker: u8) -> Vec<Vec<u8>> {
    let in_data_len = data.len();
    let boundary_marker_len = 1;
    let piece_byte_len = (in_data_len + boundary_marker_len).div_ceil(num_chunks);
    let padded_data_len = num_chunks * piece_byte_len;
    let mut padded = data.to_vec();
    padded.resize(padded_data_len, 0);
    padded[in_data_len] = boundary_marker;
    padded.chunks(piece_byte_len).map(|c| c.to_vec()).collect()
}

fn main() {
    const BLOCK_SIZE: usize = 2 * ONE_MEGABYTE; // 2MB như Celestia
    const SHARE_SIZE: usize = 512; // 512 bytes
    let k: usize = (BLOCK_SIZE / SHARE_SIZE).isqrt();
    println!("Block will have size {}x{}", k, k);

    let block: Vec<u8> = create_random_block(BLOCK_SIZE);

    // <BEGIN: 2D ERASURE BLOCK>
    let rs_start = Instant::now();
    let original_matrix = FlatMatrix::new(&block, SHARE_SIZE, k);
    let extended_matrix = extended_data_share(&original_matrix, k);
    let rs_time = rs_start.elapsed();
    println!("📊 RS time for encoding with 2D: {:?}", rs_time);
    // <END: 2D ERASURE BLOCK>

    println!(
        "Extended matrix dimensions: {:?}",
        extended_matrix.dimensions()
    );
    println!("Share size: {} bytes", extended_matrix.share_size());

    // <BEGIN: RLNC configuration>
    let num_shreds: usize = k;
    let num_chunks = 64;
    let shreds_size = extended_matrix.data().len() / num_shreds;
    let chunk_size = shreds_size / num_chunks;
    println!("Shreds size: {} bytes", shreds_size);
    println!("Chunk size: {} bytes", chunk_size);
    // <END: RLNC configuration>

    // <BEGIN: Create encoded block>
    let shreds = extended_matrix
        .data()
        .chunks(shreds_size)
        .collect::<Vec<&[u8]>>();
    let encode_start = Instant::now();
    let mut rng = rand::rng();
    let mut coded_block: Vec<Vec<u8>> = vec![];
    // for i in 0..num_shreds {
    let shred = shreds[0];
    let encoder = Encoder::new(shred.to_vec(), num_chunks).unwrap();
    println!("get_piece_count: {:?}", encoder.get_piece_count());
    println!("get_piece_byte_len: {:?}", encoder.get_piece_byte_len());
    println!(
        "get_full_coded_piece_byte_len: {:?}",
        encoder.get_full_coded_piece_byte_len()
    );
    let coded_piece = encoder.code(&mut rng);
    coded_block.push(coded_piece.clone());
    // }
    let encode_time = encode_start.elapsed();
    println!("📊 RLNC time for encoding: {:?}", encode_time);
    // <END: Create encoded block>

    // <BEGIN: Create commitment for each chunk>
    let commiter = Committer::new(chunk_size);
    let commitment_start = Instant::now();
    let chunks_: Vec<Vec<Vec<u8>>> = vec![pad_and_chunk(shreds[0], num_chunks, 0x81)];
    let chunks_commitments: Vec<Vec<RistrettoPoint>> = chunks_
        .par_iter()
        .map(|chunk| {
            chunk
                .iter()
                .map(|chunk| {
                    let commitment = commiter.commit(chunk).unwrap();
                    commitment
                })
                .collect::<Vec<RistrettoPoint>>()
        })
        .collect();
    let commitment_start = commitment_start.elapsed();
    println!(
        "Chunks commitments size in bytes: {:?}",
        chunks_commitments
            .iter()
            .map(|chunk| chunk.len() * 32) // mỗi commitment là 32 bytes
            .sum::<usize>()
    );
    println!("📊 RLNC time for commitment: {:?}", commitment_start);
    // <END: Create commitment for each chunk>

    // <BEGIN: Verify encoded block>
    let verify_start = Instant::now();
    // for i in 0..coded_block.len() {
    let commitment = commiter.commit(&coded_piece[num_chunks..]).unwrap();
    let coding_vector = coded_piece[0..num_chunks].to_vec();
    let coding_vector_in_scalar = coding_vector
        .iter()
        .map(|x| Scalar::from(*x))
        .collect::<Vec<Scalar>>();
    let calculated_commitment =
        RistrettoPoint::multiscalar_mul(&coding_vector_in_scalar, &chunks_commitments[0]);
    if calculated_commitment != commitment {
        println!("❌ Verification failed for shred {}", 0);
    } else {
        println!("✅ Verification passed for shred {}", 0);
    }
    // }
    let verify_time = verify_start.elapsed();
    println!("📊 RLNC time for verification: {:?}", verify_time);
    // <END: Verify encoded block>
}
