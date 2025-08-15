use std::time::Instant;

use curve25519_dalek::Scalar;
use rand::{rngs::StdRng, SeedableRng};
use rlnc_benchmark::{
    commitments::{
        ristretto::{discrete_log::DiscreteLogCommitter, pedersen::PedersenCommitter},
        Committer,
    },
    utils::{blocks::create_random_block, ristretto::chunk_to_scalars},
};

const ONE_MEGABYTE: usize = 1024 * 1024;

fn main() {
    const BLOCK_SIZE: usize = 4 * ONE_MEGABYTE;
    let k: usize = 64;
    let chunk_size = BLOCK_SIZE / k;
    let block: Vec<u8> = create_random_block(BLOCK_SIZE);

    let pedersen = PedersenCommitter::new(chunk_size);
    let data_chunk: Vec<Vec<Scalar>> = block
        .chunks(chunk_size)
        .map(|chunk| chunk_to_scalars(chunk).unwrap())
        .collect();
    let rs_start = Instant::now();
    let discrete_log = DiscreteLogCommitter::new(data_chunk.len(), data_chunk[0].len()).unwrap();
    let _ = discrete_log.commit(&data_chunk).unwrap();
    let rs_time = rs_start.elapsed();
    println!(
        "📊 Discrete Log time for committing one block: {:?}",
        rs_time
    );
}
