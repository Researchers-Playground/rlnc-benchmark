use rand::RngCore;

pub fn create_random_block(block_size: usize) -> Vec<u8> {
    let mut block: Vec<u8> = vec![0; block_size];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut block);
    block
}
