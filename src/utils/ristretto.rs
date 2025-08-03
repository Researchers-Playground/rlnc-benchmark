use curve25519_dalek::scalar::Scalar;

pub fn chunk_to_scalars(chunk: &[u8]) -> Result<Vec<Scalar>, String> {
    // fix cho tôi hàm này, nếu ko chia hết cho 32 thì padding
    let mut padding_size = 0;
    if chunk.len() % 32 != 0 {
        padding_size = 32 - chunk.len() % 32;
    }
    let mut padded_chunk = chunk.to_vec();
    padded_chunk.resize(chunk.len() + padding_size, 0);
    Ok(chunk
        .chunks_exact(32)
        .map(|x| {
            let mut array = [0u8; 32];
            array.copy_from_slice(x);
            Scalar::from_bytes_mod_order(array)
        })
        .collect())
}
