pub mod pedersen;

pub trait CommitmentScheme {
    type Commitment;
    type Error;

    fn commit(&self, data: &[u8]) -> Result<Self::Commitment, Self::Error>;
    fn verify(&self, commitment: &Self::Commitment, data: &[u8]) -> Result<bool, Self::Error>;
}

pub trait HomomorphicCommitment {
    type Commitment;
    type Error;
    type Scalar;

    fn verify_linear_combination(
        &self,
        a: Self::Scalar,
        c1: &Self::Commitment,
        b: Self::Scalar,
        c2: &Self::Commitment,
        c3: &Self::Commitment,
    ) -> Result<bool, Self::Error>;

    fn linear_combination(
        &self,
        a: Self::Scalar,
        c1: &Self::Commitment,
        b: Self::Scalar,
        c2: &Self::Commitment,
    ) -> Result<Self::Commitment, Self::Error>;
}
