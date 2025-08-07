use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{rngs::StdRng, SeedableRng};
use rlnc_benchmark::commitments::ristretto::discrete_log::DiscreteLogCommitter;
use rlnc_benchmark::utils::bytes::bytes_to_human_readable;
use rlnc_benchmark::utils::ristretto::chunk_to_scalars;
use std::time::Instant;
// network coding
use rayon::prelude::*;
use rlnc_benchmark::utils::blocks::create_random_block;
use rlnc_benchmark::utils::eds::{extended_data_share, FlatMatrix};
use rlnc_benchmark::utils::rlnc::{NetworkDecoder, NetworkEncoder};

const ONE_MEGABYTE: usize = 1024 * 1024;

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
    println!(
        "Share size: {}",
        bytes_to_human_readable(extended_matrix.share_size())
    );

    // <BEGIN: RLNC configuration>
    let num_shreds: usize = k;
    let num_chunks = 16;
    let shreds_size = (extended_matrix.data().len() as f64 / num_shreds as f64).ceil() as usize;
    let chunk_size = shreds_size / num_chunks;
    println!("Shreds size: {}", bytes_to_human_readable(shreds_size));
    println!("Chunk size: {}", bytes_to_human_readable(chunk_size));
    // <END: RLNC configuration>

    // <BEGIN: RLNC create commitment one block>
    let shreds = extended_matrix
        .data()
        .chunks(shreds_size)
        .collect::<Vec<_>>();
    let shreds_commiters = shreds
        .par_iter()
        .map(|shred| {
            let mut rng = StdRng::seed_from_u64(42);
            let data_chunk: Vec<Vec<Scalar>> = shred
                .chunks(chunk_size)
                .map(|chunk| chunk_to_scalars(chunk).unwrap())
                .collect();
            let committer = DiscreteLogCommitter::new(&data_chunk, &mut rng).unwrap();
            committer
        })
        .collect::<Vec<_>>();
    let shreds_encoders = shreds
        .par_iter()
        .zip(shreds_commiters.par_iter())
        .map(|(shred, commiter)| {
            let encoder = NetworkEncoder::new(commiter, Some(shred.to_vec()), num_chunks).unwrap();
            encoder
        })
        .collect::<Vec<_>>();
    let encode_time = Instant::now();

    let coded_block = shreds_encoders
        .par_iter()
        .map(|encoder| encoder.encode().unwrap())
        .collect::<Vec<_>>();
    let encode_time = encode_time.elapsed();
    println!("📊 Encode time: {:?}", encode_time);
    println!(
        "📊 Encoded chunks in byte: {}",
        bytes_to_human_readable(
            coded_block.len()
                * (coded_block[0].coefficients.len() * 32 + coded_block[0].data.len())
        )
    );

    let commitments_time = Instant::now();
    let shreds_commitments = shreds_encoders
        .par_iter()
        .map(|encoder| encoder.get_commitment().unwrap())
        .collect::<Vec<_>>();
    let commitments_time = commitments_time.elapsed();
    println!("📊 Commitments time: {:?}", commitments_time);
    println!(
        "📊 Commitments size: {}",
        bytes_to_human_readable(shreds_commitments.len() * size_of::<RistrettoPoint>())
    );
    // <END: RLNC encoding + create commitment one block>

    // <BEGIN: RLNC verify>
    let verify_time = Instant::now();
    let decoded_block = coded_block
        .par_iter()
        .zip(shreds_commitments.par_iter())
        .zip(shreds_commiters.par_iter())
        .map(|((packet, commitments), committer)| {
            let decoder = NetworkDecoder::new(committer, num_chunks);
            let result = decoder.verify_coded_piece(packet, &commitments);
            match result {
                Ok(_) => true,
                Err(_) => false,
            }
        })
        .collect::<Vec<_>>();
    let all_true = decoded_block.iter().all(|&row| row);
    assert!(all_true);
    let verify_time = verify_time.elapsed();
    println!("📊 Verify time: {:?}", verify_time);
    // <END: RLNC verify>
}
