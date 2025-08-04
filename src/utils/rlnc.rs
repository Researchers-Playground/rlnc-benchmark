use crate::commitments::ristretto::pedersen::PedersenCommitter;
use crate::utils::matrix::Echelon;
use crate::utils::ristretto::{block_to_chunks, chunk_to_scalars};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::Scalar;
use rand::Rng;

#[derive(Clone, Debug)]
pub struct CodedPacket {
    pub data: Vec<Scalar>,
    pub coefficients: Vec<Scalar>,
}

impl CodedPacket {
    pub fn get_data_len(&self) -> usize {
        self.data.len()
    }
}

#[derive(Debug)]
pub enum RLNCError {
    PieceNotUseful,
    ReceivedAllPieces,
    DecodingNotComplete,
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

pub struct NetworkEncoder<'a> {
    chunks: Vec<Vec<Scalar>>,
    committer: &'a PedersenCommitter,
}

impl<'a> NetworkEncoder<'a> {
    pub fn new(
        committer: &'a PedersenCommitter,
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

    pub fn encode(&self) -> Result<CodedPacket, String> {
        if self.chunks.is_empty() {
            return Err("No chunks available for encoding".to_string());
        }
        let coefficients = generate_random_coefficients(self.chunks.len());
        let data = self.linear_combination(&coefficients);
        Ok(CodedPacket { data, coefficients })
    }

    /// Create linear combination of chunks using given coefficients
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

    pub fn get_commitments(&self) -> Result<Vec<RistrettoPoint>, String> {
        if self.chunks.is_empty() {
            return Err("No chunks available for commitments".to_string());
        }
        let commitments = self
            .chunks
            .iter()
            .map(|chunk| self.committer.commit(&chunk).unwrap())
            .collect();
        Ok(commitments)
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

pub struct NetworkDecoder<'a> {
    received_chunks: Vec<Vec<Scalar>>,
    commitments: Option<Vec<RistrettoPoint>>,
    echelon: Echelon,
    committer: &'a PedersenCommitter,
    piece_count: usize,
}

impl<'a> NetworkDecoder<'a> {
    pub fn new(committer: &'a PedersenCommitter, piece_count: usize) -> Self {
        NetworkDecoder {
            received_chunks: Vec::new(),
            commitments: None,
            echelon: Echelon::new(piece_count),
            committer,
            piece_count,
        }
    }

    // need to rename this function to get_piece_count, but it is in same module with encoder, so the name must different
    pub fn get_piece_count_val(&self) -> usize {
        self.piece_count
    }

    pub fn get_commitments(&self) -> Option<Vec<RistrettoPoint>> {
        self.commitments.clone()
    }

    pub fn check_commitments(&self, commitments: &[RistrettoPoint]) -> Result<(), String> {
        if self.commitments.is_none() && !self.received_chunks.is_empty() {
            return Err("Commitments not set for received chunks".to_string());
        }
        if let Some(existing_commitments) = &self.commitments {
            if existing_commitments.len() != commitments.len() {
                return Err("Number of commitments does not match".to_string());
            }
            if existing_commitments != commitments {
                return Err("Commitments do not match existing ones".to_string());
            }
        }
        Ok(())
    }

    pub fn check_chunks(&self, chunk: &CodedPacket) -> Result<(), String> {
        if !self.received_chunks.is_empty() {
            if self.received_chunks[0].len() != chunk.get_data_len() {
                return Err("The chunk size is different".to_string());
            }
        }
        Ok(())
    }

    pub fn decode(
        &mut self,
        coded_packet: &CodedPacket,
        commitments: &[RistrettoPoint],
    ) -> Result<(), RLNCError> {
        if self.commitments.is_none() {
            self.commitments = Some(commitments.to_vec());
        }
        self.verify_coded_packet(coded_packet, commitments)?;
        self.direct_decode(coded_packet)
    }

    pub fn direct_decode(&mut self, coded_packet: &CodedPacket) -> Result<(), RLNCError> {
        if self.is_already_decoded() {
            return Err(RLNCError::ReceivedAllPieces);
        }
        if !self.echelon.add_row(coded_packet.coefficients.clone()) {
            return Err(RLNCError::PieceNotUseful);
        }
        self.received_chunks.push(coded_packet.data.clone());
        Ok(())
    }

    pub fn verify_coded_packet(
        &self,
        coded_packet: &CodedPacket,
        commitments: &[RistrettoPoint],
    ) -> Result<(), RLNCError> {
        use curve25519_dalek::traits::MultiscalarMul;

        let expected_commitment =
            RistrettoPoint::multiscalar_mul(&coded_packet.coefficients, commitments);
        let actual_commitment = self
            .committer
            .commit(&coded_packet.data)
            .map_err(|e| RLNCError::InvalidData(e))?;

        if expected_commitment != actual_commitment {
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

pub struct NetworkRecoder {
    received_chunks: Vec<Vec<Scalar>>,
    received_coefficients: Vec<Vec<Scalar>>,
    piece_count: usize,
}

impl NetworkRecoder {
    pub fn new(coded_packets: Vec<CodedPacket>, piece_count: usize) -> Self {
        let received_chunks: Vec<_> = coded_packets.iter().map(|p| p.data.clone()).collect();
        let received_coefficients: Vec<_> = coded_packets
            .iter()
            .map(|p| p.coefficients.clone())
            .collect();
        NetworkRecoder {
            received_chunks,
            received_coefficients,
            piece_count,
        }
    }

    pub fn update_packets(&mut self, coded_packets: Vec<CodedPacket>) -> Result<(), String> {
        if coded_packets.is_empty() {
            return Err("No packets to update".to_string());
        }
        self.received_chunks = coded_packets.iter().map(|p| p.data.clone()).collect();
        self.received_coefficients = coded_packets
            .iter()
            .map(|p| p.coefficients.clone())
            .collect();
        Ok(())
    }

    pub fn recode(&self) -> CodedPacket {
        if self.received_chunks.is_empty() {
            panic!("No packets to recode");
        }

        let mixing_coeffs = generate_random_coefficients(self.received_chunks.len());

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

        CodedPacket { data, coefficients }
    }

    pub fn get_piece_count(&self) -> usize {
        self.piece_count
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::ristretto::random_u8_slice;

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

        let encoder =
            NetworkEncoder::new(&committer, Some(original_data.clone()), num_chunks).unwrap();
        let mut decoder = NetworkDecoder::new(&committer, num_chunks);
        let commitments = encoder.get_commitments().unwrap();

        while !decoder.is_already_decoded() {
            let coded_packet = encoder.encode().unwrap();
            decoder.decode(&coded_packet, &commitments).unwrap();
        }

        let decoded_data = decoder.get_decoded_data().unwrap();
        assert_eq!(decoded_data, original_data);
    }
}
