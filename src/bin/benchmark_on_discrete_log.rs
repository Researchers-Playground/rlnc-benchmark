use curve25519_dalek::Scalar;
use rlnc_benchmark::commitments::ristretto::discrete_log::DiscreteLogCommitter;
use rlnc_benchmark::commitments::Committer;
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
    const BLOCK_SIZE: usize = 2 * ONE_MEGABYTE / 4; // 2MB như Celestia
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
    let num_shreds: usize = 4 * k * k;
    let num_chunks: usize = 16;
    let shreds_size: usize =
        (extended_matrix.data().len() as f64 / num_shreds as f64).ceil() as usize;
    let chunk_size: usize = shreds_size / num_chunks;
    println!("Shreds size: {}", bytes_to_human_readable(shreds_size));
    println!("Chunk size: {}", bytes_to_human_readable(chunk_size));
    // <END: RLNC configuration>

    // <BEGIN: RLNC create commitment one block>
    let shreds = extended_matrix
        .data()
        .chunks(shreds_size)
        .collect::<Vec<_>>();

    let commitments_time = Instant::now();
    let shreds_commiters = shreds
        .par_iter()
        .map(|shred| {
            let data_chunk: Vec<Vec<Scalar>> = shred
                .chunks(chunk_size)
                .map(|chunk| chunk_to_scalars(chunk).unwrap())
                .collect();
            let mut committer =
                DiscreteLogCommitter::new(data_chunk.len(), data_chunk[0].len()).unwrap();

            // Generate commitment (generators and signature_vector) from the data chunks
            let signature_vector = committer.commit(&data_chunk).unwrap();

            // Set the generated keys in the committer
            committer
                .set_signature_vector(signature_vector.clone())
                .unwrap();

            committer
        })
        .collect::<Vec<_>>();
    let commitments_time = commitments_time.elapsed();
    println!("📊 Commitments time: {:?}", commitments_time);

    let mut shreds_encoders = shreds
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
    println!("📊 Time to create one coded block: {:?}", encode_time);
    println!(
        "📊 Coded block size: {}, Piece len: {}, Coded piece size: {}",
        bytes_to_human_readable(coded_block.len() * coded_block[0].size_in_bytes()),
        bytes_to_human_readable(coded_block.len()),
        bytes_to_human_readable(coded_block[0].size_in_bytes())
    );

    let shreds_commitments = shreds_encoders
        .par_iter()
        .map(|encoder| {
            let signature_vector = encoder.get_commitment().unwrap();
            signature_vector
        })
        .collect::<Vec<_>>();
    println!(
        "📊 Commitment size: {}",
        bytes_to_human_readable(
            shreds_commitments[0].len() * shreds_commitments.len() * std::mem::size_of::<Scalar>()
        )
    );

    // <END: RLNC encoding + create commitment one block>

    // <BEGIN: RLNC verify>
    let verify_time = Instant::now();
    let decoded_block = coded_block
        .par_iter()
        .zip(shreds_commitments.par_iter())
        .zip(shreds_commiters.par_iter())
        .map(|((packet, commitments), committer)| {
            let decoder = NetworkDecoder::new(Some(committer), num_chunks);
            let result = decoder.verify_coded_piece(packet, commitments, None);
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
