use crate::{commitments::Committer, networks::ErasureCoder, utils::ristretto::chunk_to_scalars};
use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::marker::PhantomData;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RSError {
    #[error("Encoding failed: {0}")]
    EncodingFailed(String),
    #[error("Decoding failed: {0}")]
    DecodingFailed(String),
    #[error("Invalid share: {0}")]
    InvalidShare(String),
    #[error("Insufficient shares for decoding")]
    InsufficientShares,
}

// currently does not benchmark enviroment having this so consider the compability later
pub struct RSErasureCoder<C: Committer<Scalar = Scalar>> {
    rs: ReedSolomon,
    data: Vec<u8>,
    shares: Vec<Vec<u8>>,
    num_data_shares: usize,
    num_parity_shares: usize,
    share_size: usize,
    received_shares: Vec<(usize, Vec<u8>)>,
    _phantom: PhantomData<C>,
}

impl<C: Committer<Scalar = Scalar>> RSErasureCoder<C> {
    pub fn new(
        data: Vec<u8>,
        num_data_shares: usize,
        num_parity_shares: usize,
        share_size: usize,
    ) -> Result<Self, RSError> {
        if data.len() % num_data_shares != 0 {
            return Err(RSError::EncodingFailed(
                "Data length not divisible by num_data_shares".to_string(),
            ));
        }
        let rs = ReedSolomon::new(num_data_shares, num_parity_shares)
            .map_err(|e| RSError::EncodingFailed(e.to_string()))?;
        let mut shares: Vec<Vec<u8>> = data
            .chunks(share_size)
            .map(|chunk| chunk.to_vec())
            .chain((0..num_parity_shares).map(|_| vec![0u8; share_size]))
            .collect();
        rs.encode(&mut shares)
            .map_err(|e| RSError::EncodingFailed(e.to_string()))?;
        Ok(RSErasureCoder {
            rs,
            data,
            shares,
            num_data_shares,
            num_parity_shares,
            share_size,
            received_shares: Vec::new(),
            _phantom: PhantomData,
        })
    }
}

impl<C: Committer<Scalar = Scalar>> ErasureCoder<C> for RSErasureCoder<C> {
    type Error = RSError;
    type CodedData = Vec<u8>;
    type Commitment = C::Commitment;

    fn encode(&self) -> Result<Self::CodedData, Self::Error> {
        let mut rng = rand::rng();
        if self.shares.is_empty() {
            return Err(RSError::EncodingFailed("No shares available".to_string()));
        }
        let index = rng.random_range(0..self.shares.len());
        Ok(self.shares[index].clone())
    }

    fn decode(&mut self, piece: &Self::CodedData) -> Result<(), Self::Error> {
        if piece.len() != self.share_size {
            return Err(RSError::InvalidShare("Invalid share size".to_string()));
        }
        self.received_shares
            .push((self.received_shares.len(), piece.clone()));
        Ok(())
    }

    fn recode(&mut self, pieces: &[Self::CodedData]) -> Result<Self::CodedData, Self::Error> {
        if pieces.is_empty() {
            return Err(RSError::InvalidShare("No shares to recode".to_string()));
        }
        let mut rng = rand::rng();
        let index = rng.random_range(0..pieces.len());
        Ok(pieces[index].clone())
    }

    fn verify(
        &self,
        piece: &Self::CodedData,
        _commitment: &C::Commitment,
    ) -> Result<(), Self::Error> {
        let _scalars = chunk_to_scalars(piece).map_err(|e| RSError::InvalidShare(e.to_string()))?;
        // Placeholder: Implement commitment verification
        Ok(())
    }

    fn get_decoded_data(&self) -> Result<Vec<u8>, Self::Error> {
        if self.received_shares.len() < self.num_data_shares {
            return Err(RSError::InsufficientShares);
        }
        let rs = self.rs.clone();
        let mut shares = vec![None; self.num_data_shares + self.num_parity_shares];
        for (index, share) in self.received_shares.iter().take(self.num_data_shares) {
            shares[*index] = Some(share.clone());
        }
        rs.reconstruct(&mut shares)
            .map_err(|e| RSError::DecodingFailed(e.to_string()))?;
        let mut result = Vec::new();
        for share in shares.iter().take(self.num_data_shares) {
            result.extend_from_slice(share.as_ref().unwrap());
        }
        Ok(result)
    }

    fn get_piece_count(&self) -> usize {
        self.num_data_shares
    }

    fn is_decoded(&self) -> bool {
        self.received_shares.len() >= self.num_data_shares
    }
}
