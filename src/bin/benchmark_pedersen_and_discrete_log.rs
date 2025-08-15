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
    let mut rng = StdRng::seed_from_u64(42);
    let rs_start = Instant::now();
    let discrete_log = DiscreteLogCommitter::new(&data_chunk, &mut rng).unwrap();
    let rs_time = rs_start.elapsed();
    println!(
        "📊 Discrete Log time for committing one block: {:?}",
        rs_time
    );
}
