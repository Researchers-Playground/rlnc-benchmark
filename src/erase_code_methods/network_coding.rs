use crate::{
    commitments::{Committer, CodedPiece},
    utils::rlnc::{NetworkEncoder, NetworkDecoder, NetworkRecoder},
    networks::ErasureCoder,
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
    encoder: NetworkEncoder<'a, C>,
    decoder: NetworkDecoder<'a, C>,
    recoder: NetworkRecoder,
}

impl<'a, C: Committer<Scalar = Scalar>> RLNCErasureCoder<'a, C> {
    pub fn new(committer: &'a C, data: Option<Vec<u8>>, num_chunks: usize) -> Result<Self, NetworkCodingError> {
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
        self.encoder.encode()
            .map_err(|e| NetworkCodingError::EncodingFailed(e.to_string()))
    }

    fn decode(&mut self, piece: &Self::CodedData) -> Result<(), Self::Error> {
        self.decoder.decode(piece, &self.encoder.get_commitment().unwrap())
            .map_err(|e| NetworkCodingError::DecodingFailed(e.to_string()))
    }

    fn recode(&mut self, pieces: &[Self::CodedData]) -> Result<Self::CodedData, Self::Error> {
        let pieces_converted: Vec<CodedPiece<Scalar>> = pieces.to_vec();
        self.recoder.update_packets(pieces_converted)
            .map_err(|e| NetworkCodingError::InvalidPiece(e.to_string()))?;
        Ok(self.recoder.recode())
    }

    fn verify(&self, piece: &Self::CodedData, commitment: &C::Commitment) -> Result<(), Self::Error> {
        self.decoder.verify_coded_piece(piece, commitment)
            .map_err(|e| NetworkCodingError::InvalidPiece(e.to_string()))
    }

    fn get_decoded_data(&self) -> Result<Vec<u8>, Self::Error> {
        self.decoder.get_decoded_data()
            .map_err(|e| NetworkCodingError::DecodingFailed(e.to_string()))
    }

    fn get_piece_count(&self) -> usize {
        self.decoder.get_piece_count()
    }

    fn is_decoded(&self) -> bool {
        self.decoder.is_already_decoded()
    }
}