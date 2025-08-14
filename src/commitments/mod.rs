use curve25519_dalek::scalar::Scalar;
use std::error::Error;

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
    type Scalar: Clone + std::ops::Mul<Output = Self::Scalar> + std::iter::Sum + From<u8>;
    type Commitment: Clone + Send + Sync + PartialEq;
    type Error: Error;

    fn commit(&self, chunks: &Vec<Vec<Scalar>>) -> Result<Self::Commitment, Self::Error>;
    fn verify(&self, commitment: Option<&Self::Commitment>, piece: &CodedPiece<Scalar>) -> bool;
}
