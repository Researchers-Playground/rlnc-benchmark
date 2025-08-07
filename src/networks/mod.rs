use std::error::Error;

use crate::commitments::Committer;

pub mod message;
pub mod node;
pub mod nodes;
pub mod storage;

pub trait ErasureCoder<C: Committer> {
    type Error: Error;
    type CodedData: Clone;
    type Commitment;

    fn encode(&self) -> Result<Self::CodedData, Self::Error>;
    fn decode(&mut self, piece: &Self::CodedData) -> Result<(), Self::Error>;
    fn recode(&mut self, pieces: &[Self::CodedData]) -> Result<Self::CodedData, Self::Error>;
    fn verify(
        &self,
        piece: &Self::CodedData,
        commitment: &C::Commitment,
    ) -> Result<(), Self::Error>;
    fn get_decoded_data(&self) -> Result<Vec<u8>, Self::Error>;
    fn get_piece_count(&self) -> usize;
    fn is_decoded(&self) -> bool;
}
