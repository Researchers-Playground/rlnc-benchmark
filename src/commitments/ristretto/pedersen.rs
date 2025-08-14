use crate::commitments::{CodedPiece, Committer};
use crate::utils::ristretto::coefficients_to_scalars;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand::Rng;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PedersenError {
    #[error("Invalid chunk size: {0}")]
    InvalidChunkSize(String),
    #[error("Commitment failed: {0}")]
    CommitFailed(String),
}

#[derive(Clone)]
pub struct PedersenCommitter {
    generators: Vec<RistrettoPoint>,
}

impl PedersenCommitter {
    pub fn new(n: usize) -> Self {
        PedersenCommitter {
            generators: generators(n),
        }
    }

    pub fn len(&self) -> usize {
        self.generators.len()
    }

    pub fn commit(&self, scalars: &[Scalar]) -> Result<RistrettoPoint, PedersenError> {
        if scalars.len() > self.generators.len() {
            return Err(PedersenError::InvalidChunkSize(format!(
                "Chunk size is too large, {} > {}",
                scalars.len(),
                self.generators.len()
            )));
        }
        Ok(RistrettoPoint::multiscalar_mul(
            scalars,
            &self.generators[..scalars.len()],
        ))
    }
}

impl Committer for PedersenCommitter {
    type Scalar = Scalar;
    type Commitment = Vec<RistrettoPoint>;
    type Error = PedersenError;

    fn commit(&self, chunks: &Vec<Vec<Self::Scalar>>) -> Result<Self::Commitment, Self::Error> {
        chunks
            .iter()
            .map(|chunk| {
                self.commit(chunk).map_err(|e| match e {
                    PedersenError::InvalidChunkSize(msg) => PedersenError::InvalidChunkSize(msg),
                    PedersenError::CommitFailed(msg) => PedersenError::CommitFailed(msg),
                })
            })
            .collect()
    }

    fn verify(&self, commitment: Option<&Self::Commitment>, piece: &CodedPiece<Scalar>) -> bool {
        if commitment.is_none() {
            return false;
        }
        let msm = RistrettoPoint::multiscalar_mul(
            coefficients_to_scalars(&piece.coefficients),
            commitment.unwrap(),
        );
        match self.commit(&piece.data) {
            Ok(commitment_result) => msm == commitment_result,
            Err(_) => false,
        }
    }
}

fn generators(n: usize) -> Vec<RistrettoPoint> {
    let mut rng = rand::rng();
    (0..n)
        .map(|_| RISTRETTO_BASEPOINT_POINT * Scalar::from(rng.random::<u128>()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ristretto::chunk_to_scalars;

    #[test]
    fn test_pedersen_commit() {
        let committer = PedersenCommitter::new(4); // 4 generators
                                                   // Valid chunk: 32 bytes (1 Scalar)
        let chunk = vec![1u8; 32];
        let scalars = chunk_to_scalars(&chunk).expect("Failed to convert chunk to scalars");
        let commitment = committer.commit(&scalars).expect("Failed to commit");
        assert_eq!(
            commitment,
            RistrettoPoint::multiscalar_mul(&scalars, &committer.generators[..scalars.len()])
        );

        // Invalid chunk: too many scalars (5 Scalars > 4 generators)
        let invalid_chunk = vec![1u8; 32 * 5]; // 160 bytes -> 5 Scalars
        let invalid_scalars =
            chunk_to_scalars(&invalid_chunk).expect("Failed to convert invalid chunk to scalars");
        let result = committer.commit(&invalid_scalars);
        assert!(matches!(result, Err(PedersenError::InvalidChunkSize(_))));
    }
}
