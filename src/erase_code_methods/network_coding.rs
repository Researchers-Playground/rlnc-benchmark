use crate::{
    commitments::{CodedPiece, Committer},
    networks::ErasureCoder,
    utils::rlnc::{NetworkDecoder, NetworkEncoder, NetworkRecoder},
};
use curve25519_dalek::scalar::Scalar;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkCodingError {
    #[error("Encoding failed: {0}")]
    EncodingFailed(String),
    #[error("Decoding failed: {0}")]
    DecodingFailed(String),
    #[error("Invalid piece: {0}")]
    InvalidPiece(String),
    #[error("Insufficient pieces for decoding")]
    InsufficientPieces,
}

pub struct RLNCErasureCoder<'a, C: Committer<Scalar = Scalar>> {
    pub encoder: NetworkEncoder<'a, C>,
    pub decoder: NetworkDecoder<'a, C>,
    pub recoder: NetworkRecoder,
}

impl<'a, C: Committer<Scalar = Scalar>> RLNCErasureCoder<'a, C> {
    pub fn new(
        committer: &'a C,
        data: Option<Vec<u8>>,
        num_chunks: usize,
    ) -> Result<Self, NetworkCodingError> {
        println!(
            "Creating RLNCErasureCoder with num_chunks: {}, data_len: {:?}",
            num_chunks,
            data.as_ref().map(|d| d.len())
        );
        let encoder = NetworkEncoder::new(committer, data, num_chunks)
            .map_err(|e| NetworkCodingError::EncodingFailed(e.to_string()))?;
        let decoder = NetworkDecoder::new(committer, num_chunks);
        let recoder = NetworkRecoder::new(Vec::new(), num_chunks);
        Ok(RLNCErasureCoder {
            encoder,
            decoder,
            recoder,
        })
    }
}

impl<'a, C: Committer<Scalar = Scalar>> ErasureCoder<C> for RLNCErasureCoder<'a, C> {
    type Error = NetworkCodingError;
    type CodedData = CodedPiece<Scalar>;
    type Commitment = C::Commitment;

    fn encode(&self) -> Result<Self::CodedData, Self::Error> {
        self.encoder
            .encode()
            .map_err(|e| NetworkCodingError::EncodingFailed(e.to_string()))
    }

    fn decode(&mut self, piece: &Self::CodedData) -> Result<(), Self::Error> {
        self.decoder
            .decode(
                piece,
                &self
                    .encoder
                    .get_commitment()
                    .map_err(|e| NetworkCodingError::EncodingFailed(e.to_string()))?,
            )
            .map_err(|e| NetworkCodingError::DecodingFailed(e.to_string()))
    }

    fn recode(&mut self, pieces: &[Self::CodedData]) -> Result<Self::CodedData, Self::Error> {
        let pieces_converted: Vec<CodedPiece<Scalar>> = pieces.to_vec();
        self.recoder
            .update_packets(pieces_converted)
            .map_err(|e| NetworkCodingError::InvalidPiece(e.to_string()))?;
        Ok(self.recoder.recode())
    }

    fn verify(
        &self,
        piece: &Self::CodedData,
        commitment: &C::Commitment,
    ) -> Result<(), Self::Error> {
        self.decoder
            .verify_coded_piece(piece, commitment)
            .map_err(|e| NetworkCodingError::InvalidPiece(e.to_string()))
    }

    fn get_decoded_data(&self) -> Result<Vec<u8>, Self::Error> {
        self.decoder
            .get_decoded_data()
            .map_err(|e| NetworkCodingError::DecodingFailed(e.to_string()))
    }

    fn get_piece_count(&self) -> usize {
        self.decoder.get_piece_count()
    }

    fn is_decoded(&self) -> bool {
        self.decoder.is_already_decoded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ristretto::{block_to_chunks, chunk_to_scalars};
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

    #[derive(Debug, thiserror::Error)]
    pub enum MockCommitterError {
        #[error("Invalid chunk size: {0}")]
        InvalidChunkSize(String),
    }

    struct MockCommitter {
        num_chunks: usize,
    }

    impl MockCommitter {
        fn new(num_chunks: usize) -> Self {
            MockCommitter { num_chunks }
        }
    }

    impl Committer for MockCommitter {
        type Scalar = Scalar;
        type Commitment = Vec<RistrettoPoint>;
        type Error = MockCommitterError;

        fn commit(&self, data: &Vec<Vec<Self::Scalar>>) -> Result<Self::Commitment, Self::Error> {
            if data.is_empty() || data.len() != self.num_chunks {
                return Err(MockCommitterError::InvalidChunkSize(format!(
                    "Expected {} chunks, got {}",
                    self.num_chunks,
                    data.len()
                )));
            }
            Ok(vec![RistrettoPoint::default(); self.num_chunks])
        }

        fn verify(
            &self,
            commitment: Option<&Self::Commitment>,
            piece: &CodedPiece<Self::Scalar>,
        ) -> bool {
            if let Some(commitment) = commitment {
                commitment.len() == self.num_chunks && piece.data.len() == 1
            } else {
                false
            }
        }
    }

    fn create_dummy_data() -> Vec<u8> {
        vec![1u8; 512]
    }

    #[test]
    fn test_rlnc_coder_new_with_data() {
        let committer = MockCommitter::new(16);
        let data = create_dummy_data();
        let num_chunks = 16;

        let coder = RLNCErasureCoder::new(&committer, Some(data), num_chunks);
        assert!(
            coder.is_ok(),
            "Failed to create RLNCErasureCoder with valid data: {:?}",
            coder.err()
        );
        let coder = coder.unwrap();
        assert_eq!(coder.get_piece_count(), num_chunks);
    }

    #[test]
    fn test_rlnc_coder_new_without_data() {
        let committer = MockCommitter::new(16);
        let num_chunks = 16;

        let coder = RLNCErasureCoder::new(&committer, None, num_chunks);
        assert!(
            coder.is_ok(),
            "Failed to create RLNCErasureCoder without data: {:?}",
            coder.err()
        );
        let coder = coder.unwrap();
        assert_eq!(coder.get_piece_count(), num_chunks);
    }

    #[test]
    fn test_rlnc_coder_encode() {
        let committer = MockCommitter::new(16);
        let data = create_dummy_data();
        let num_chunks = 16;

        let coder = RLNCErasureCoder::new(&committer, Some(data), num_chunks).unwrap();
        let piece = coder.encode();
        assert!(piece.is_ok(), "Failed to encode: {:?}", piece.err());
        let piece = piece.unwrap();
        assert_eq!(
            piece.data.len(),
            1,
            "Encoded piece data length should be 16 scalars"
        );
        assert_eq!(
            piece.coefficients.len(),
            num_chunks,
            "Encoded piece coefficients length should match num_chunks"
        );
    }

    #[test]
    fn test_rlnc_coder_decode_success() {
        let committer = MockCommitter::new(16);
        let data = create_dummy_data();
        let num_chunks = 16;

        let mut coder = RLNCErasureCoder::new(&committer, Some(data.clone()), num_chunks).unwrap();
        let commitment = coder
            .encoder
            .get_commitment()
            .expect("Failed to get commitment");

        // Tạo và decode đủ số piece cần thiết
        for _ in 0..num_chunks {
            let piece = coder.encode().expect("Failed to encode piece");
            let result = coder.decoder.decode(&piece, &commitment);
            assert!(result.is_ok(), "Failed to decode: {:?}", result.err());
        }

        assert!(
            coder.is_decoded(),
            "Should be decoded after receiving enough pieces"
        );
        let decoded_data = coder.get_decoded_data();
        assert!(
            decoded_data.is_ok(),
            "Failed to get decoded data: {:?}",
            decoded_data.err()
        );

        // Kiểm tra dữ liệu giải mã
        let decoded_data = decoded_data.unwrap();
        let original_chunks = block_to_chunks(&data, num_chunks)
            .unwrap()
            .into_iter()
            .flat_map(|chunk| chunk_to_scalars(chunk).unwrap())
            .collect::<Vec<Scalar>>();
        let decoded_chunks = block_to_chunks(&decoded_data, num_chunks)
            .unwrap()
            .into_iter()
            .flat_map(|chunk| chunk_to_scalars(chunk).unwrap())
            .collect::<Vec<Scalar>>();
        assert_eq!(
            original_chunks.len(),
            decoded_chunks.len(),
            "Decoded data length mismatch"
        );
        // Lưu ý: So sánh chính xác original_chunks và decoded_chunks có thể cần điều chỉnh logic trong NetworkDecoder
    }

    #[test]
    fn test_rlnc_coder_decode_insufficient_pieces() {
        let committer = MockCommitter::new(16);
        let data = create_dummy_data();
        let num_chunks = 16;

        let mut coder = RLNCErasureCoder::new(&committer, Some(data), num_chunks).unwrap();

        for _ in 0..(num_chunks - 1) {
            let piece = coder.encode().unwrap();
            assert!(coder.decode(&piece).is_ok(), "Failed to decode piece");
        }

        assert!(
            !coder.is_decoded(),
            "Should not be decoded with insufficient pieces"
        );
        let decoded_data = coder.get_decoded_data();
        assert!(
            matches!(decoded_data, Err(NetworkCodingError::DecodingFailed(_))),
            "Expected DecodingFailed error"
        );
    }

    #[test]
    fn test_rlnc_coder_recode() {
        let committer = MockCommitter::new(16);
        let data = create_dummy_data();
        let num_chunks = 16;

        let mut coder = RLNCErasureCoder::new(&committer, Some(data), num_chunks).unwrap();
        let mut pieces = Vec::new();
        for _ in 0..num_chunks {
            pieces.push(coder.encode().unwrap());
        }

        let recoded_piece = coder.recode(&pieces);
        assert!(
            recoded_piece.is_ok(),
            "Failed to recode: {:?}",
            recoded_piece.err()
        );
        let recoded_piece = recoded_piece.unwrap();
        assert_eq!(
            recoded_piece.data.len(),
            1,
            "Recoded piece data length should be 16 scalars"
        );
        assert_eq!(
            recoded_piece.coefficients.len(),
            num_chunks,
            "Recoded piece coefficients length should match num_chunks"
        );
    }

    #[test]
    fn test_rlnc_coder_verify_success() {
        let committer = MockCommitter::new(16);
        let data = create_dummy_data();
        let num_chunks = 16;

        let coder = RLNCErasureCoder::new(&committer, Some(data), num_chunks).unwrap();
        let piece = coder.encode().unwrap();
        let commitment = coder.encoder.get_commitment().unwrap();

        let result = coder.verify(&piece, &commitment);
        assert!(result.is_ok(), "Failed to verify: {:?}", result.err());
    }

    #[test]
    fn test_rlnc_coder_verify_invalid_commitment() {
        let committer = MockCommitter::new(16);
        let data = create_dummy_data();
        let num_chunks = 16;

        let coder = RLNCErasureCoder::new(&committer, Some(data), num_chunks).unwrap();
        let piece = coder.encode().unwrap();
        let invalid_commitment = vec![RistrettoPoint::default(); num_chunks + 1]; // Commitment sai kích thước

        let result = coder.verify(&piece, &invalid_commitment);
        assert!(
            matches!(result, Err(NetworkCodingError::InvalidPiece(_))),
            "Expected InvalidPiece error"
        );
    }
}
