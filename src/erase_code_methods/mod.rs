pub mod reed_solomon;
pub mod network_coding;

use crate::{
    commitments::{ristretto::{discrete_log::DiscreteLogError, pedersen::PedersenError}, CodedPiece, Committer}, erase_code_methods::{network_coding::{NetworkCodingError, RLNCErasureCoder}, reed_solomon::{RSErasureCoder, RSError}}, networks::ErasureCoder
};
use curve25519_dalek::scalar::Scalar;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ErasureError {
    #[error("RLNC error: {0}")]
    RLNC(NetworkCodingError),
    #[error("RS error: {0}")]
    RS(RSError),
    #[error("Pedersen commitment error: {0}")]
    PedersenCommitment(PedersenError),
    #[error("DiscreteLog commitment error: {0}")]
    DiscreteLogCommitment(DiscreteLogError),
    #[error("Network error: {0}")]
    Network(String),
}

pub enum ErasureCoderType<'a, C: Committer<Scalar = Scalar>> {
    RLNC(RLNCErasureCoder<'a, C>),
    RS(RSErasureCoder<C>),
}

impl<'a, C: Committer<Scalar = Scalar>> ErasureCoderType<'a, C> {
    pub fn encode(&self) -> Result<CodedData, ErasureError> {
        match self {
            ErasureCoderType::RLNC(coder) => coder.encode().map_err(ErasureError::RLNC).map(|p| CodedData::RLNC(p)),
            ErasureCoderType::RS(coder) => coder.encode().map_err(ErasureError::RS).map(|p| CodedData::RS(p)),
        }
    }

    pub fn decode(&mut self, piece: &CodedData) -> Result<(), ErasureError> {
        match (self, piece) {
            (ErasureCoderType::RLNC(coder), CodedData::RLNC(piece)) => coder.decode(piece).map_err(ErasureError::RLNC),
            (ErasureCoderType::RS(coder), CodedData::RS(piece)) => coder.decode(piece).map_err(ErasureError::RS),
            _ => Err(ErasureError::Network("Mismatched coder and data type".to_string())),
        }
    }

    pub fn recode(&mut self, pieces: &[CodedData]) -> Result<CodedData, ErasureError> {
        match self {
            ErasureCoderType::RLNC(coder) => {
                let pieces: Vec<_> = pieces.iter().filter_map(|p| if let CodedData::RLNC(p) = p { Some(p.clone()) } else { None }).collect();
                coder.recode(&pieces).map_err(ErasureError::RLNC).map(|p| CodedData::RLNC(p))
            }
            ErasureCoderType::RS(coder) => {
                let pieces: Vec<_> = pieces.iter().filter_map(|p| if let CodedData::RS(p) = p { Some(p.clone()) } else { None }).collect();
                coder.recode(&pieces).map_err(ErasureError::RS).map(|p| CodedData::RS(p))
            }
        }
    }

    pub fn verify(&self, piece: &CodedData, commitment: &C::Commitment) -> Result<(), ErasureError> {
        match (self, piece) {
            (ErasureCoderType::RLNC(coder), CodedData::RLNC(piece)) => coder.verify(piece, commitment).map_err(ErasureError::RLNC),
            (ErasureCoderType::RS(coder), CodedData::RS(piece)) => coder.verify(piece, commitment).map_err(ErasureError::RS),
            _ => Err(ErasureError::Network("Mismatched coder and data type".to_string())),
        }
    }

    pub fn get_decoded_data(&self) -> Result<Vec<u8>, ErasureError> {
        match self {
            ErasureCoderType::RLNC(coder) => coder.get_decoded_data().map_err(ErasureError::RLNC),
            ErasureCoderType::RS(coder) => <RSErasureCoder<C> as ErasureCoder<C>>::get_decoded_data(coder).map_err(ErasureError::RS),
        }
    }

    pub fn get_piece_count(&self) -> usize {
        match self {
            ErasureCoderType::RLNC(coder) => coder.get_piece_count(),
            ErasureCoderType::RS(coder) => coder.get_piece_count(),
        }
    }

    pub fn is_decoded(&self) -> bool {
        match self {
            ErasureCoderType::RLNC(coder) => coder.is_decoded(),
            ErasureCoderType::RS(coder) => coder.is_decoded(),
        }
    }
}

#[derive(Clone)]
pub enum CodedData {
    RLNC(CodedPiece<Scalar>),
    RS(Vec<u8>),
}