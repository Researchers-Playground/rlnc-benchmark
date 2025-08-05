use curve25519_dalek::scalar::Scalar;

pub mod ristretto;

#[derive(Clone, Debug)]
pub struct CodedPiece<S = Scalar> {
    pub data: Vec<S>,
    pub coefficients: Vec<S>,
}

impl<S> CodedPiece<S> {
    pub fn get_data_len(&self) -> usize {
        self.data.len()
    }
}


pub trait Committer {
  type Scalar;
  type Commitment: Clone;
  type Error;

  fn commit(&self, chunks: &Vec<Vec<Scalar>>) -> Result<Self::Commitment, Self::Error>;
  fn verify(&self, commitment: Option<&Self::Commitment>, piece: &CodedPiece<Scalar>) -> bool;
}
