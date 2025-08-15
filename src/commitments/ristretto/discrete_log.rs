use crate::{
    commitments::{CodedPiece, Committer},
    utils::ristretto::coefficients_to_scalars,
};
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

#[derive(Clone)]
pub struct DiscreteLogCommitter {
    alphas: Vec<Scalar>,
    generators: Vec<RistrettoPoint>,
    signature_vector: Vec<Scalar>,
    params: DiscreteLogParams,
}

impl DiscreteLogCommitter {
    pub fn new(
        total_packets: usize,
        total_data_in_single_packet: usize,
    ) -> Result<Self, DiscreteLogError> {
        let rng = &mut rand::rng();
        let params = DiscreteLogParams::new(total_packets, total_data_in_single_packet);
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
        Ok(Self {
            alphas,
            generators,
            signature_vector: Vec::new(),
            params,
        })
    }

    pub fn from_keys(
        params: DiscreteLogParams,
        alphas: Vec<Scalar>,
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
            alphas,
            generators,
            signature_vector,
            params,
        })
    }

    fn generate_keys<R: RngCore + CryptoRng>(
        &self,
        params: &DiscreteLogParams,
        original_packets: &[Vec<Scalar>],
        rng: &mut R,
    ) -> Result<Vec<Scalar>, DiscreteLogError> {
        if original_packets.len() != params.original_dim {
            return Err(DiscreteLogError::InvalidDimensions {
                expected: params.original_dim,
                actual: original_packets.len(),
            });
        }
        for packet in original_packets {
            if packet.len() != params.data_dim {
                return Err(DiscreteLogError::InvalidDimensions {
                    expected: params.data_dim,
                    actual: packet.len(),
                });
            }
        }
        let orthogonal_vector =
            Self::find_orthogonal_vector_implicit(params, original_packets, rng)?;
        let mut signature_vector: Vec<Scalar> = Vec::new();
        for (&u_i, &alpha_i) in orthogonal_vector.iter().zip(self.alphas.iter()) {
            let alpha_inv = alpha_i.invert();
            signature_vector.push(u_i * alpha_inv);
        }

        Ok(signature_vector)
    }

    /// Find orthogonal vector for implicit [I|D] structure without constructing full packets
    fn find_orthogonal_vector_implicit<R: RngCore + CryptoRng>(
        params: &DiscreteLogParams,
        packets: &[Vec<Scalar>],
        rng: &mut R,
    ) -> Result<Vec<Scalar>, DiscreteLogError> {
        let m = params.original_dim;
        let n = params.total_dim;

        if m >= n {
            return Err(DiscreteLogError::InsufficientRank);
        }

        let mut orthogonal = vec![Scalar::ZERO; n];

        // Set random values for data part (columns m..n)
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

        // For implicit [I|D] structure, each row i has:
        // - Identity part: 1 at position i, 0 elsewhere
        // - Data part: packets[i]
        // So dot product with orthogonal[0..m] | orthogonal[m..n] is:
        // orthogonal[i] + sum(packets[i][j] * orthogonal[m+j] for j in 0..data_dim)
        for i in 0..m {
            let mut data_sum = Scalar::ZERO;
            for (j, &data_val) in packets[i].iter().enumerate() {
                data_sum += data_val * orthogonal[m + j];
            }
            orthogonal[i] = -data_sum; // Make dot product zero
        }

        #[cfg(debug_assertions)]
        {
            // Verify orthogonality for implicit structure
            for (packet_idx, data_packet) in packets.iter().enumerate() {
                let mut dot_prod = orthogonal[packet_idx]; // Identity part contribution
                for (j, &data_val) in data_packet.iter().enumerate() {
                    dot_prod += data_val * orthogonal[m + j];
                }
                debug_assert_eq!(
                    dot_prod,
                    Scalar::ZERO,
                    "Orthogonality verification failed for packet {}",
                    packet_idx
                );
            }
        }

        Ok(orthogonal)
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
        let mut full_vector = coefficients_to_scalars(&coded_piece.coefficients.clone());
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
            .map(|(&x_i, &w_i)| x_i * Scalar::from(w_i))
            .collect();

        let result = RistrettoPoint::multiscalar_mul(&exponents, &self.generators);
        result == RistrettoPoint::identity()
    }

    pub fn set_signature_vector(
        &mut self,
        signature_vector: Vec<Scalar>,
    ) -> Result<(), DiscreteLogError> {
        self.signature_vector = signature_vector;
        Ok(())
    }
}

impl Committer for DiscreteLogCommitter {
    type Scalar = Scalar;
    type Commitment = Vec<Scalar>;
    type Error = DiscreteLogError;

    fn commit(&self, chunks: &Vec<Vec<Self::Scalar>>) -> Result<Self::Commitment, Self::Error> {
        let rng = &mut rand::rng();
        let signature_vector = self.generate_keys(&self.params, chunks, rng)?;
        Ok(signature_vector)
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
    use crate::utils::ristretto::{chunk_to_scalars, random_u8_slice};
    use crate::utils::rlnc::{NetworkDecoder, NetworkEncoder};
    use rand::{rngs::StdRng, SeedableRng};

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
        let committer = DiscreteLogCommitter::new(data_chunks.len(), data_chunks[0].len());
        assert!(committer.is_ok());
    }

    #[test]
    fn test_commit_and_verify() {
        let num_packets = 2;
        let data_per_packet = 3;
        // Create real data for D part
        let data = random_u8_slice(num_packets * data_per_packet * 32);
        let data_chunks: Vec<Vec<Scalar>> = data
            .chunks(data_per_packet * 32)
            .map(|chunk| chunk_to_scalars(chunk).unwrap())
            .collect();

        let mut committer =
            DiscreteLogCommitter::new(data_chunks.len(), data_chunks[0].len()).unwrap();
        let signature_vector = committer.commit(&data_chunks).unwrap();
        committer.set_signature_vector(signature_vector).unwrap();
        // Test original packets with implicit identity structure
        for (i, data_chunk) in data_chunks.iter().enumerate() {
            let mut coding_vector = vec![0; num_packets];
            coding_vector[i] = 1; // Identity part for this packet

            let coded_piece = CodedPiece {
                coefficients: coding_vector,
                data: data_chunk.clone(),
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

        let mut committer =
            DiscreteLogCommitter::new(data_chunks.len(), data_chunks[0].len()).unwrap();
        let signature_vector = committer.commit(&data_chunks).unwrap();
        committer.set_signature_vector(signature_vector).unwrap();
        let encoder = NetworkEncoder::new(&committer, Some(data), num_packets).unwrap();
        let coded_piece = encoder.encode().unwrap();
        let commitment = encoder.get_commitment().unwrap();
        assert!(committer.verify_signature(&coded_piece));

        let decoder = NetworkDecoder::new(Some(&committer), num_packets);
        let verify_result = decoder
            .verify_coded_piece(&coded_piece, &commitment)
            .is_ok();
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
        let committer = DiscreteLogCommitter::new(data_chunks.len(), data_chunks[0].len()).unwrap();
        let signature_vector = committer.commit(&data_chunks).unwrap();
        let mut committer = committer;
        committer.set_signature_vector(signature_vector).unwrap();

        // Should fail verification with very high probability
        // (There's a negligible chance it might pass due to randomness)
        let mut failed_count = 0;
        for _ in 0..10 {
            let test_coefficients = vec![rng.random::<u8>(); num_packets];
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

        // Test the implicit orthogonal vector finding
        let result =
            DiscreteLogCommitter::find_orthogonal_vector_implicit(&params, &data_chunks, &mut rng);
        assert!(result.is_ok());

        if let Ok(orthogonal) = result {
            // Verify orthogonality for implicit [I|D] structure
            for (packet_idx, data_packet) in data_chunks.iter().enumerate() {
                let mut dot_prod = orthogonal[packet_idx]; // Identity part contribution
                for (j, &data_val) in data_packet.iter().enumerate() {
                    dot_prod += data_val * orthogonal[params.original_dim + j];
                }
                assert_eq!(dot_prod, Scalar::ZERO);
            }
        }
    }
}
