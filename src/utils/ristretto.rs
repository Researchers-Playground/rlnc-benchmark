use curve25519_dalek::scalar::Scalar;
use rand::Rng;

pub fn chunk_to_scalars(chunk: &[u8]) -> Result<Vec<Scalar>, String> {
    if chunk.len() % 32 != 0 {
        return Err("Chunk size is not divisible by 32".to_string());
    }
    Ok(chunk
        .chunks_exact(32)
        .map(|x| {
            let mut array = [0u8; 32];
            array.copy_from_slice(x);
            Scalar::from_bytes_mod_order(array)
        })
        .collect())
}

pub fn pad_data_for_scalars(data: &[u8], num_chunks: usize) -> Vec<u8> {
    let mut result = Vec::new();
    for chunk in data.chunks(31) {
        result.extend_from_slice(chunk);
        result.push(0);
    }
    let chunk_size = (result.len() + num_chunks - 1) / num_chunks; // Round up
    let chunk_size_32_aligned = ((chunk_size + 31) / 32) * 32; // Round up to multiple of 32
    let target_size = chunk_size_32_aligned * num_chunks;
    result.resize(target_size, 0);
    result
}

pub fn unpad_data_from_scalars(padded_data: &[u8], original_length: usize) -> Vec<u8> {
    let mut result = Vec::new();
    for chunk in padded_data.chunks(32) {
        let data_bytes = if chunk.len() >= 31 {
            &chunk[..31]
        } else {
            chunk
        };
        result.extend_from_slice(data_bytes);
    }
    result.truncate(original_length);
    result
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
