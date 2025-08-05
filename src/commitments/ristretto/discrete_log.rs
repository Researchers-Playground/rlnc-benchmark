use crate::commitments::{CodedPiece, Committer};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::{Identity, MultiscalarMul},
};
use rand::{CryptoRng, Rng, RngCore};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DiscreteLogError {
    #[error("Invalid vector dimensions: expected {expected}, got {actual}")]
    InvalidDimensions { expected: usize, actual: usize },
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Key generation failed - could not find orthogonal vector")]
    KeyGenerationFailed,
    #[error("Vector not in valid subspace")]
    VectorNotInSubspace,
    #[error("Decompression failed")]
    DecompressionFailed,
    #[error("Chunk size too large: {size} > {max}")]
    ChunkTooLarge { size: usize, max: usize },
    #[error("Invalid scalar inversion")]
    ScalarInversionFailed,
    #[error("Matrix rank insufficient")]
    InsufficientRank,
}

/// Parameters for the discrete log signature scheme
#[derive(Debug, Clone)]
pub struct DiscreteLogParams {
    pub original_dim: usize,
    pub data_dim: usize,
    pub total_dim: usize,
}

impl DiscreteLogParams {
    pub fn new(original_dim: usize, data_dim: usize) -> Self {
        Self {
            original_dim,
            data_dim,
            total_dim: original_dim + data_dim,
        }
    }
}

pub struct DiscreteLogCommitter {
    generators: Vec<RistrettoPoint>,
    signature_vector: Vec<Scalar>,
    params: DiscreteLogParams,
}

impl DiscreteLogCommitter {
    pub fn new<R: RngCore + CryptoRng>(
        original_packets: &[Vec<Scalar>],
        rng: &mut R,
    ) -> Result<Self, DiscreteLogError> {
        if (original_packets.is_empty()) {
            return Err(DiscreteLogError::InvalidDimensions {
                expected: 1,
                actual: original_packets.len(),
            });
        }
        let params = DiscreteLogParams::new(
            original_packets.len(),
            original_packets[0].len(),
        );
        let structured_packets = Self::convert_to_structured_packets(&params, original_packets)?;

        let (generators, signature_vector) = Self::generate_keys(
            &params,
            &structured_packets,
            rng,
        )?;

        Ok(Self {
            generators,
            signature_vector,
            params,
        })
    }
    
    /// Convert pure data packets to [I|D] structure automatically
    /// This hides the mathematical structure from users
    fn convert_to_structured_packets(
        params: &DiscreteLogParams,
        original_packets: &[Vec<Scalar>],
    ) -> Result<Vec<Vec<Scalar>>, DiscreteLogError> {
        if original_packets.len() != params.original_dim {
            return Err(DiscreteLogError::InvalidDimensions {
                expected: params.original_dim,
                actual: original_packets.len(),
            });
        }
        
        let mut structured_packets = Vec::new();
        
        for (i, packet) in original_packets.iter().enumerate() {
            if packet.len() == params.total_dim {
                structured_packets.push(packet.clone());
            } else if packet.len() == params.data_dim {
                // Pure data packet, add identity part
                let mut structured_packet = vec![Scalar::ZERO; params.total_dim];
                structured_packet[i] = Scalar::ONE; // Identity part
                structured_packet[params.original_dim..].copy_from_slice(packet); // Data part
                structured_packets.push(structured_packet);
            } else {
                return Err(DiscreteLogError::InvalidDimensions {
                    expected: params.data_dim,
                    actual: packet.len(),
                });
            }
        }
        
        Ok(structured_packets)
    }

    pub fn from_keys(
        params: DiscreteLogParams,
        generators: Vec<RistrettoPoint>,
        signature_vector: Vec<Scalar>,
    ) -> Result<Self, DiscreteLogError> {
        if generators.len() != params.total_dim {
            return Err(DiscreteLogError::InvalidDimensions {
                expected: params.total_dim,
                actual: generators.len(),
            });
        }

        if signature_vector.len() != params.total_dim {
            return Err(DiscreteLogError::InvalidDimensions {
                expected: params.total_dim,
                actual: signature_vector.len(),
            });
        }

        Ok(Self {
            generators,
            signature_vector,
            params,
        })
    }

    fn generate_keys<R: RngCore + CryptoRng>(
        params: &DiscreteLogParams,
        original_packets: &[Vec<Scalar>],
        rng: &mut R,
    ) -> Result<(Vec<RistrettoPoint>, Vec<Scalar>), DiscreteLogError> {
        if original_packets.len() != params.original_dim {
            return Err(DiscreteLogError::InvalidDimensions {
                expected: params.original_dim,
                actual: original_packets.len(),
            });
        }
        for packet in original_packets {
            if packet.len() != params.total_dim {
                return Err(DiscreteLogError::InvalidDimensions {
                    expected: params.total_dim,
                    actual: packet.len(),
                });
            }
        }
        let mut alphas: Vec<Scalar> = Vec::new();
        for _ in 0..params.total_dim {
            loop {
                let alpha = Scalar::from(rng.random::<u64>());
                if alpha != Scalar::ZERO {
                    alphas.push(alpha);
                    break;
                }
            }
        }
        let generators: Vec<RistrettoPoint> = alphas
            .iter()
            .map(|&alpha| RISTRETTO_BASEPOINT_POINT * alpha)
            .collect();
        let orthogonal_vector = Self::find_orthogonal_vector(original_packets, rng)?;
        let mut signature_vector: Vec<Scalar> = Vec::new();
        for (&u_i, &alpha_i) in orthogonal_vector.iter().zip(alphas.iter()) {
            let alpha_inv = alpha_i.invert();
            signature_vector.push(u_i * alpha_inv);
        }

        Ok((generators, signature_vector))
    }

    fn find_orthogonal_vector<R: RngCore + CryptoRng>(
        original_packets: &[Vec<Scalar>],
        rng: &mut R,
    ) -> Result<Vec<Scalar>, DiscreteLogError> {
        let m = original_packets.len();
        let n = original_packets[0].len();
        if m >= n {
            return Err(DiscreteLogError::InsufficientRank);
        }

        let mut orthogonal = vec![Scalar::ZERO; n];
        
        let mut has_nonzero = false;
        for i in m..n {
            let val = Scalar::from(rng.random::<u64>());
            orthogonal[i] = val;
            if val != Scalar::ZERO {
                has_nonzero = true;
            }
        }
        
        if !has_nonzero {
            orthogonal[m] = Scalar::ONE;
        }
        
        for i in 0..m {
            let mut sum = Scalar::ZERO;
            for j in m..n {
                sum += orthogonal[j] * original_packets[i][j];
            }
            orthogonal[i] = -sum;
        }
        
        #[cfg(debug_assertions)]
        {
            for packet in original_packets {
                let dot_prod = Self::dot_product(&orthogonal, packet);
                debug_assert_eq!(dot_prod, Scalar::ZERO, "Orthogonality verification failed");
            }
        }
        Ok(orthogonal)
    }

    fn dot_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
        a.iter()
            .zip(b.iter())
            .map(|(&a_i, &b_i)| a_i * b_i)
            .fold(Scalar::ZERO, |acc, x| acc + x)
    }

    pub fn generators(&self) -> &[RistrettoPoint] {
        &self.generators
    }

    pub fn signature_vector(&self) -> &[Scalar] {
        &self.signature_vector
    }

    pub fn params(&self) -> &DiscreteLogParams {
        &self.params
    }

    pub fn commit_vector(&self, vector: &[Scalar]) -> Result<RistrettoPoint, DiscreteLogError> {
        if vector.len() > self.generators.len() {
            return Err(DiscreteLogError::ChunkTooLarge {
                size: vector.len(),
                max: self.generators.len(),
            });
        }

        Ok(RistrettoPoint::multiscalar_mul(
            vector,
            &self.generators[..vector.len()],
        ))
    }

    /// Verify if a coded piece is valid using the discrete log signature
    /// This is the main verification function implementing: d = ∏h_i^{x_i * w_i} = 1
    pub fn verify_signature(&self, coded_piece: &CodedPiece<Scalar>) -> bool {
        // Combine coding coefficients and data into full vector w
        let mut full_vector = coded_piece.coefficients.clone();
        full_vector.extend(coded_piece.data.iter().cloned());

        if full_vector.len() != self.params.total_dim {
            return false;
        }

        // Compute d = ∏h_i^{x_i * w_i} where w_i are vector elements
        // Using multiscalar multiplication: d = sum(x_i * w_i * h_i)
        let exponents: Vec<Scalar> = self
            .signature_vector
            .iter()
            .zip(full_vector.iter())
            .map(|(&x_i, &w_i)| x_i * w_i)
            .collect();

        let result = RistrettoPoint::multiscalar_mul(&exponents, &self.generators);
        result == RistrettoPoint::identity()
    }
}

impl Committer for DiscreteLogCommitter {
    type Scalar = Scalar;
    type Commitment = Vec<RistrettoPoint>;
    type Error = DiscreteLogError;

    fn commit(&self, chunks: &Vec<Vec<Self::Scalar>>) -> Result<Self::Commitment, Self::Error> {
        chunks
            .iter()
            .map(|chunk| self.commit_vector(chunk))
            .collect()
    }

    fn verify(&self, _params: Option<&Self::Commitment>, piece: &CodedPiece<Scalar>) -> bool {
        // Primary verification using discrete log signature
        if !self.verify_signature(piece) {
            return false;
        }

        // Optional: Additional verification using standard params if provided
        // if let Some(comm) = params {
        //     let msm = RistrettoPoint::multiscalar_mul(&piece.coefficients, comm);
        //     if let Ok(piece_params) = self.commit(&vec![piece.data.clone()]) {
        //         return msm == piece_params[0];
        //     }
        // }

        true
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use crate::utils::ristretto::{random_u8_slice, chunk_to_scalars};
    use crate::utils::rlnc::{NetworkDecoder, NetworkEncoder};

    #[test]
    fn test_discrete_log_committer_creation() {
        let mut rng = StdRng::seed_from_u64(42);
        let num_packets = 3;
        let data_per_packet = 4;
        let data = random_u8_slice(num_packets * data_per_packet * 32);
        let data_chunks: Vec<Vec<Scalar>> = data
            .chunks(data_per_packet * 32)
            .map(|chunk| chunk_to_scalars(chunk).unwrap())
            .collect();
        let committer = DiscreteLogCommitter::new(&data_chunks, &mut rng);
        assert!(committer.is_ok());
    }

    #[test]
    fn test_commit_and_verify() {
        let mut rng = StdRng::seed_from_u64(42);
        let num_packets = 2;
        let data_per_packet = 3;
        // Create real data for D part
        let data = random_u8_slice(num_packets * data_per_packet * 32);
        let data_chunks: Vec<Vec<Scalar>> = data
            .chunks(data_per_packet * 32)
            .map(|chunk| chunk_to_scalars(chunk).unwrap())
            .collect();

        let mut padded_packets = Vec::new();
        for (i, data_chunk) in data_chunks.iter().enumerate() {
            let mut packet = vec![Scalar::ZERO; num_packets + data_per_packet];
            packet[i] = Scalar::ONE; // Identity part
            packet[num_packets..].copy_from_slice(data_chunk); // Real data part
            padded_packets.push(packet);
        }
        let committer = DiscreteLogCommitter::new(&data_chunks, &mut rng).unwrap();
        for packet in &padded_packets {
            let coding_vector = packet[..num_packets].to_vec();
            let data = packet[num_packets..].to_vec();
            let coded_piece = CodedPiece {
                coefficients: coding_vector,
                data,
            };
            assert!(committer.verify_signature(&coded_piece));
        }
    }

    #[test]
    fn test_linear_combination() {
        let mut rng = StdRng::seed_from_u64(42);
        let num_packets = 2;
        let data_per_packet = 2;
        let data = random_u8_slice(num_packets * data_per_packet * 32);
        let data_chunks: Vec<Vec<Scalar>> = data
            .chunks(data_per_packet * 32)
            .map(|chunk| chunk_to_scalars(chunk).unwrap())
            .collect();
            
        let committer = DiscreteLogCommitter::new(&data_chunks, &mut rng).unwrap();
        let encoder = NetworkEncoder::new(&committer, Some(data), num_packets).unwrap();
        let coded_piece = encoder.encode().unwrap();
        let commitment = encoder.get_commitment().unwrap();
        assert!(committer.verify_signature(&coded_piece));

        let decoder = NetworkDecoder::new(&committer, num_packets);
        let verify_result = decoder.verify_coded_piece(&coded_piece, &commitment).is_ok();
        assert!(verify_result);
    }

    #[test]
    fn test_invalid_packet_detection() {
        let mut rng = StdRng::seed_from_u64(42);
        let num_packets = 2;
        let data_per_packet = 2;
        let data = random_u8_slice(num_packets * data_per_packet * 32);
        let data_chunks: Vec<Vec<Scalar>> = data
            .chunks(data_per_packet * 32)
            .map(|chunk| chunk_to_scalars(chunk).unwrap())
            .collect();
        let committer = DiscreteLogCommitter::new(&data_chunks, &mut rng).unwrap();

        // Should fail verification with very high probability
        // (There's a negligible chance it might pass due to randomness)
        let mut failed_count = 0;
        for _ in 0..10 {
            let test_coefficients = vec![Scalar::from(rng.random::<u64>()); num_packets];
            let test_data = vec![Scalar::from(rng.random::<u64>()); data_per_packet];
            let test_piece = CodedPiece {
                coefficients: test_coefficients,
                data: test_data,
            };
            if !committer.verify_signature(&test_piece) {
                failed_count += 1;
            }
        }
        // Most random packets should fail verification
        assert!(failed_count >= 8);
    }

    #[test]
    fn test_orthogonality() {
        let mut rng = StdRng::seed_from_u64(42);
        let num_packets = 3;
        let data_per_packet = 4;
        let params = DiscreteLogParams::new(num_packets, data_per_packet);
        
        let data = random_u8_slice(num_packets * data_per_packet * 32);
        let data_chunks: Vec<Vec<Scalar>> = data
            .chunks(data_per_packet * 32)
            .map(|chunk| chunk_to_scalars(chunk).unwrap())
            .collect();
            
        // Build packets with [I|D] structure: [unit_vector | real_data]
        let mut original_packets = Vec::new();
        for (i, data_chunk) in data_chunks.iter().enumerate() {
            let mut packet = vec![Scalar::ZERO; params.total_dim];
            packet[i] = Scalar::ONE; // Identity part
            packet[num_packets..].copy_from_slice(data_chunk); // Real data part
            original_packets.push(packet);
        }

        let result = DiscreteLogCommitter::find_orthogonal_vector(&original_packets, &mut rng);
        assert!(result.is_ok());

        if let Ok(orthogonal) = result {
            for packet in &original_packets {
                let dot_prod = DiscreteLogCommitter::dot_product(&orthogonal, packet);
                assert_eq!(dot_prod, Scalar::ZERO);
            }
        }
    }
}
