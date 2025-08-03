// src/commitments/bitwise.rs
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand::Rng;
use rayon::prelude::*;
use rlnc::common::gf256::Gf256;

pub struct BitwiseCommitter {
    generators: Vec<RistrettoPoint>,
    chunk_size: usize,
}

impl BitwiseCommitter {
    pub fn new(chunk_size: usize) -> Self {
        let num_generators = chunk_size * 8;
        let mut rng = rand::rng();
        let generators: Vec<RistrettoPoint> = (0..num_generators)
            .map(|_| RISTRETTO_BASEPOINT_POINT * Scalar::from(rng.random::<u128>()))
            .collect();

        Self {
            generators,
            chunk_size,
        }
    }

    /// Highly optimized bit decomposition that works directly with bytes
    #[inline(always)]
    fn process_byte_to_scalars(byte: u8) -> [Scalar; 8] {
        // Unroll all 8 bits for maximum performance - no extra storage needed
        [
            if byte & 0x01 != 0 {
                Scalar::ONE
            } else {
                Scalar::ZERO
            },
            if byte & 0x02 != 0 {
                Scalar::ONE
            } else {
                Scalar::ZERO
            },
            if byte & 0x04 != 0 {
                Scalar::ONE
            } else {
                Scalar::ZERO
            },
            if byte & 0x08 != 0 {
                Scalar::ONE
            } else {
                Scalar::ZERO
            },
            if byte & 0x10 != 0 {
                Scalar::ONE
            } else {
                Scalar::ZERO
            },
            if byte & 0x20 != 0 {
                Scalar::ONE
            } else {
                Scalar::ZERO
            },
            if byte & 0x40 != 0 {
                Scalar::ONE
            } else {
                Scalar::ZERO
            },
            if byte & 0x80 != 0 {
                Scalar::ONE
            } else {
                Scalar::ZERO
            },
        ]
    }

    pub fn commit(&self, chunk: &[u8]) -> RistrettoPoint {
        assert_eq!(chunk.len(), self.chunk_size);

        // Create scalars on-demand without storing them - more memory efficient
        let scalars: Vec<Scalar> = chunk
            .iter()
            .flat_map(|&byte| Self::process_byte_to_scalars(byte))
            .collect();

        RistrettoPoint::multiscalar_mul(&scalars, &self.generators)
    }

    /// Parallel batch commit for maximum performance - no extra state needed
    pub fn batch_commit_parallel(&self, chunks: &[Vec<u8>]) -> Vec<RistrettoPoint> {
        chunks.par_iter().map(|chunk| self.commit(chunk)).collect()
    }

    /// Sequential batch commit
    pub fn batch_commit(&self, chunks: &[Vec<u8>]) -> Vec<RistrettoPoint> {
        chunks.iter().map(|chunk| self.commit(chunk)).collect()
    }
}

pub fn gf256_mul(a: u8, b: u8) -> u8 {
    (Gf256::new(a) * Gf256::new(b)).get()
}

pub fn gf256_combine_chunks(chunks: &[Vec<u8>], coding_vector: &[u8]) -> Vec<u8> {
    let chunk_len = chunks[0].len();
    let mut result = vec![0u8; chunk_len];

    for (chunk, &coeff) in chunks.iter().zip(coding_vector.iter()) {
        if coeff == 0 {
            continue;
        }

        if coeff == 1 {
            for i in 0..chunk_len {
                result[i] ^= chunk[i];
            }
        } else {
            for i in 0..chunk_len {
                result[i] ^= gf256_mul(chunk[i], coeff);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rlnc::full::encoder::Encoder;

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

    #[test]
    fn verify_rlnc_commitment_against_encoder() {
        let chunk_size = 64;
        let num_chunks = 4;
        let mut rng = rand::rng();
        let original_data: Vec<u8> = (0..chunk_size * num_chunks).map(|_| rng.random()).collect();
        let encoder = Encoder::new(original_data.clone(), num_chunks).unwrap();
        let padded_original_data = pad_and_chunk(&original_data, num_chunks, 0x81);
        let chunks: Vec<Vec<u8>> = padded_original_data;
        let coded_piece = encoder.code(&mut rng);
        let (coding_vector, payload) = coded_piece.split_at(num_chunks);
        let committer = BitwiseCommitter::new(encoder.get_piece_byte_len());
        let _chunk_commits: Vec<RistrettoPoint> = committer.batch_commit(&chunks);
        let reconstructed = gf256_combine_chunks(&chunks, coding_vector);
        let recomputed_commitment = committer.commit(&reconstructed);
        let payload_commitment = committer.commit(payload);
        assert_eq!(
            payload_commitment.compress(),
            recomputed_commitment.compress()
        );
        println!("✅ Verified RLNC commitment using optimized GF256 operations");
    }
}
