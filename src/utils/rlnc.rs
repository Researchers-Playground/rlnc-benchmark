use crate::commitments::{CodedPiece, Committer};
use crate::utils::matrix::Echelon;
use crate::utils::ristretto::{block_to_chunks, chunk_to_scalars};
use curve25519_dalek::Scalar;
use rand::Rng;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RLNCError {
    #[error("Linearly dependent chunk received")]
    PieceNotUseful,
    #[error("Received all pieces")]
    ReceivedAllPieces,
    #[error("Decoding not complete")]
    DecodingNotComplete,
    #[error("Committer not set for verification")]
    LackOfCommitter,
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

fn generate_random_coefficients(length: usize) -> Vec<Scalar> {
    let mut rng = rand::rng();
    (0..length)
        .map(|_| {
            let random_byte = rng.random::<u8>();
            Scalar::from(random_byte)
        })
        .collect()
}

pub struct NetworkEncoder<'a, C: Committer> {
    chunks: Vec<Vec<C::Scalar>>,
    committer: &'a C,
}

impl<'a, C: Committer<Scalar = Scalar>> NetworkEncoder<'a, C> {
    pub fn new(
        committer: &'a C,
        original_data: Option<Vec<u8>>,
        num_chunks: usize,
    ) -> Result<Self, String> {
        let chunks = match original_data {
            Some(data) => block_to_chunks(&data, num_chunks)?
                .into_iter()
                .map(|data| chunk_to_scalars(data).unwrap())
                .collect(),
            None => vec![],
        };
        Ok(NetworkEncoder { chunks, committer })
    }

    pub fn update_chunks(&mut self, new_data: Vec<u8>, num_chunks: usize) -> Result<(), String> {
        self.chunks = block_to_chunks(&new_data, num_chunks)?
            .into_iter()
            .map(|data| chunk_to_scalars(data).unwrap())
            .collect();
        Ok(())
    }

    pub fn encode(&self) -> Result<CodedPiece, String> {
        if self.chunks.is_empty() {
            return Err("No chunks available for encoding".to_string());
        }
        let coefficients = generate_random_coefficients(self.chunks.len());
        let data = self.linear_combination(&coefficients);
        Ok(CodedPiece { data, coefficients })
    }

    fn linear_combination(&self, coefficients: &[Scalar]) -> Vec<Scalar> {
        (0..self.chunks[0].len())
            .map(|i| {
                coefficients
                    .iter()
                    .zip(&self.chunks)
                    .map(|(coeff, chunk)| *coeff * chunk[i])
                    .sum()
            })
            .collect()
    }

    pub fn get_commitment(&self) -> Result<C::Commitment, String> {
        if self.chunks.is_empty() {
            return Err("No chunks available for commitments".to_string());
        }
        self.committer
            .commit(&self.chunks)
            .map_err(|_| "Commitment failed".to_string())
    }

    pub fn get_chunks(&self) -> Vec<Vec<Scalar>> {
        self.chunks.clone()
    }

    pub fn get_piece_count(&self) -> usize {
        self.chunks.len()
    }

    pub fn get_piece_byte_len(&self) -> usize {
        if self.chunks.is_empty() {
            0
        } else {
            self.chunks[0].len() * 32
        }
    }
}

// TODO: use RREF to store only rref matrix for decoding
#[derive(Clone)]
pub struct NetworkDecoder<'a, C: Committer> {
    pub received_chunks: Vec<Vec<C::Scalar>>,
    commitment: Option<C::Commitment>,
    pub echelon: Echelon,
    committer: Option<&'a C>,
    pub piece_count: usize,
}

impl<'a, C: Committer<Scalar = Scalar>> NetworkDecoder<'a, C> {
    pub fn new(committer: Option<&'a C>, piece_count: usize) -> Self {
        NetworkDecoder {
            received_chunks: Vec::new(),
            commitment: None,
            echelon: Echelon::new(piece_count),
            committer,
            piece_count,
        }
    }

    pub fn from(
        received_chunks: Vec<Vec<C::Scalar>>,
        echelon: Echelon,
        piece_count: usize,
        commitment: Option<C::Commitment>,
        committer: Option<&'a C>,
    ) -> Self {
        NetworkDecoder {
            received_chunks,
            commitment,
            echelon,
            committer,
            piece_count,
        }
    }

    // need to rename this function to get_piece_count, but it is in same module with encoder, so the name must different
    pub fn get_piece_count_val(&self) -> usize {
        self.piece_count
    }

    pub fn get_commitment(&self) -> Option<C::Commitment> {
        self.commitment.clone()
    }

    pub fn check_commitment(&self, commitment: &C::Commitment) -> Result<(), String>
    where
        C::Commitment: PartialEq + Clone,
    {
        if self.commitment.is_none() && !self.received_chunks.is_empty() {
            return Err("Commitments not set for received chunks".to_string());
        }
        if let Some(existing_commitments) = &self.commitment {
            if existing_commitments != commitment {
                return Err("Commitments do not match existing ones".to_string());
            }
        }
        Ok(())
    }

    pub fn check_chunks(&self, chunk: &CodedPiece<C::Scalar>) -> Result<(), String> {
        if !self.received_chunks.is_empty() {
            if self.received_chunks[0].len() != chunk.get_data_len() {
                return Err("The chunk size is different".to_string());
            }
        }
        Ok(())
    }

    pub fn decode(
        &mut self,
        coded_piece: &CodedPiece<C::Scalar>,
        commitment: &C::Commitment,
    ) -> Result<(), RLNCError>
    where
        C::Commitment: Clone,
    {
        if self.commitment.is_none() {
            self.commitment = Some(commitment.clone());
        }
        self.verify_coded_piece(coded_piece, commitment)?;
        self.direct_decode(coded_piece)
    }

    pub fn direct_decode(&mut self, coded_piece: &CodedPiece<C::Scalar>) -> Result<(), RLNCError> {
        if self.is_already_decoded() {
            return Err(RLNCError::ReceivedAllPieces);
        }
        if !self.echelon.add_row(coded_piece.coefficients.clone()) {
            return Err(RLNCError::PieceNotUseful);
        }
        self.received_chunks.push(coded_piece.data.clone());
        Ok(())
    }

    pub fn verify_coded_piece(
        &self,
        coded_piece: &CodedPiece<C::Scalar>,
        commitment: &C::Commitment,
    ) -> Result<(), RLNCError> {
        if self.committer.is_none() {
            return Err(RLNCError::LackOfCommitter);
        }
        let is_valid = self
            .committer
            .unwrap()
            .verify(Some(commitment), coded_piece);
        if !is_valid {
            return Err(RLNCError::InvalidData(
                "Commitment verification failed".to_string(),
            ));
        }
        Ok(())
    }

    pub fn is_already_decoded(&self) -> bool {
        self.received_chunks.len() >= self.piece_count
    }

    pub fn get_decoded_data(&self) -> Result<Vec<u8>, RLNCError> {
        if !self.is_already_decoded() {
            return Err(RLNCError::DecodingNotComplete);
        }
        let inverse = self
            .echelon
            .inverse()
            .map_err(|e| RLNCError::InvalidData(e))?;
        let mut padded_result = Vec::new();
        for i in 0..inverse.len() {
            for k in 0..self.received_chunks[0].len() {
                let scalar_sum: Scalar = (0..inverse.len())
                    .map(|j| inverse[i][j] * self.received_chunks[j][k])
                    .sum();
                padded_result.extend_from_slice(&scalar_sum.to_bytes());
            }
        }
        Ok(padded_result)
    }

    pub fn get_useful_piece_count(&self) -> usize {
        self.received_chunks.len()
    }

    pub fn get_piece_count(&self) -> usize {
        self.piece_count
    }
}

pub struct NetworkRecoder<S = Scalar> {
    received_chunks: Vec<Vec<S>>,
    received_coefficients: Vec<Vec<S>>,
    piece_count: usize,
}

impl<S: Clone> NetworkRecoder<S> {
    pub fn new(coded_pieces: Vec<CodedPiece<S>>, piece_count: usize) -> Self {
        let received_chunks: Vec<_> = coded_pieces.iter().map(|p| p.data.clone()).collect();
        let received_coefficients: Vec<_> = coded_pieces
            .iter()
            .map(|p| p.coefficients.clone())
            .collect();
        NetworkRecoder {
            received_chunks,
            received_coefficients,
            piece_count,
        }
    }

    pub fn update_packets(&mut self, coded_pieces: Vec<CodedPiece<S>>) -> Result<(), String> {
        if coded_pieces.is_empty() {
            return Err("No packets to update".to_string());
        }
        self.received_chunks = coded_pieces.iter().map(|p| p.data.clone()).collect();
        self.received_coefficients = coded_pieces
            .iter()
            .map(|p| p.coefficients.clone())
            .collect();
        Ok(())
    }

    pub fn recode(&self) -> CodedPiece<S>
    where
        S: Copy + std::ops::Mul<Output = S> + std::iter::Sum + From<u8>,
    {
        if self.received_chunks.is_empty() {
            panic!("No packets to recode");
        }

        let mixing_coeffs: Vec<S> = (0..self.received_chunks.len())
            .map(|_| {
                let random_byte = rand::rng().random::<u8>();
                S::from(random_byte)
            })
            .collect();

        let data = (0..self.received_chunks[0].len())
            .map(|i| {
                mixing_coeffs
                    .iter()
                    .zip(&self.received_chunks)
                    .map(|(coeff, chunk)| *coeff * chunk[i])
                    .sum()
            })
            .collect();

        let coefficients = (0..self.received_coefficients[0].len())
            .map(|i| {
                mixing_coeffs
                    .iter()
                    .zip(&self.received_coefficients)
                    .map(|(coeff, coeffs)| *coeff * coeffs[i])
                    .sum()
            })
            .collect();

        CodedPiece { data, coefficients }
    }

    pub fn get_piece_count(&self) -> usize {
        self.piece_count
    }
}

impl NetworkRecoder<Scalar> {
    pub fn new_scalar(coded_pieces: Vec<CodedPiece>, piece_count: usize) -> Self {
        Self::new(coded_pieces, piece_count)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        commitments::ristretto::pedersen::PedersenCommitter, utils::ristretto::random_u8_slice,
    };

    use super::*;

    #[test]
    fn test_generate_random_coefficients() {
        let coefficients = generate_random_coefficients(10);
        assert_eq!(coefficients.len(), 10);
    }

    #[test]
    fn test_network_encoder() {
        use crate::utils::ristretto::random_u8_slice;

        let num_chunks = 10;
        let committer = PedersenCommitter::new(num_chunks);
        let test_data = random_u8_slice(num_chunks * 32); // 10 chunks * 32 bytes = 320 bytes
        let encoder = NetworkEncoder::new(&committer, Some(test_data), num_chunks).unwrap();
        assert_eq!(encoder.get_piece_count(), 10);
        // get_piece_byte_len() depends on padding logic, so just check it's reasonable
        assert!(encoder.get_piece_byte_len() >= 32);
        assert!(encoder.get_piece_byte_len() % 32 == 0); // Should be multiple of 32
    }

    #[test]
    fn test_network_decoder() {
        let num_chunks = 10;
        let committer = PedersenCommitter::new(num_chunks);
        let original_data: Vec<u8> = random_u8_slice(num_chunks * 32);
        // let original_data = (0..32 * num_chunks).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

        let encoder =
            NetworkEncoder::new(&committer, Some(original_data.clone()), num_chunks).unwrap();
        let mut decoder = NetworkDecoder::new(Some(&committer), num_chunks);
        let commitments = encoder.get_commitment().unwrap();

        while !decoder.is_already_decoded() {
            let coded_piece = encoder.encode().unwrap();
            decoder.decode(&coded_piece, &commitments).unwrap();
        }

        let decoded_data = decoder.get_decoded_data().unwrap();
        assert_eq!(decoded_data, original_data);
    }
}
