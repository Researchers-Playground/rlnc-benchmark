use crate::utils::ristretto::random_u8_slice;

pub fn create_random_block(block_size: usize) -> Vec<u8> {
    let block: Vec<u8> = random_u8_slice(block_size);
    block
}
