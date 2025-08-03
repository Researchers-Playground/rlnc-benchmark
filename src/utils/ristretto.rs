use curve25519_dalek::scalar::Scalar;
use rand::Rng;

pub fn chunk_to_scalars(chunk: &[u8]) -> Result<Vec<Scalar>, String> {
    let mut padding_size = 0;
    if chunk.len() % 32 != 0 {
        padding_size = 32 - chunk.len() % 32;
    }
    let mut padded_chunk = chunk.to_vec();
    padded_chunk.resize(chunk.len() + padding_size, 0);
    Ok(padded_chunk
        .chunks_exact(32)
        .map(|x| {
            let mut array = [0u8; 32];
            array.copy_from_slice(x);
            Scalar::from_bytes_mod_order(array)
        })
        .collect())
}

pub fn random_u8_slice(length: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let mut ret: Vec<u8> = (0..length).map(|_| rng.random::<u8>()).collect();
    for i in (31..length).step_by(32) {
        ret[i] = 0;
    }
    ret
}

pub fn block_to_chunks(block: &[u8], num_chunks: usize) -> Result<Vec<&[u8]>, String> {
    if block.len() % num_chunks != 0 {
        return Err("Block size is not divisible by num_chunks".to_string());
    }
    let chunk_size = block.len() / num_chunks;
    Ok(block.chunks(chunk_size).collect())
}
