use curve25519_dalek::scalar::Scalar;
use std::error::Error;

use crate::utils::field::FieldScalar;

pub mod blst;
pub mod ristretto;

#[derive(Clone, PartialEq, Debug)]
pub struct CodedPiece<S = Scalar> {
    pub data: Vec<S>,
    pub coefficients: Vec<u8>,
}

impl<S> CodedPiece<S> {
    pub fn get_data_len(&self) -> usize {
        self.data.len()
    }

    pub fn size_in_bytes(&self) -> usize {
        self.data.len() * std::mem::size_of::<S>() + self.coefficients.len()
    }
}

pub trait Committer: Clone + Send + Sync {
    type Scalar: FieldScalar;
    type Commitment: Clone + Send + Sync + PartialEq;
    type Error: Error;
    type AdditionalData;

    fn commit(&self, chunks: &Vec<Vec<Scalar>>) -> Result<Self::Commitment, Self::Error>;
    fn verify(
        &self,
        commitment: Option<&Self::Commitment>,
        piece: &CodedPiece<Self::Scalar>,
        additional_data: Option<&Self::AdditionalData>,
    ) -> bool;
}
