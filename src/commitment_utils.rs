use crate::commitments::pedersen::Committer;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

/// Tạo commitment cho từng chunk trong một vector các chunk.
/// Trả về Vec<RistrettoPoint> với mỗi phần tử là commitment của một chunk.
pub fn commit_chunks(committer: &Committer, chunks: &[Vec<u8>]) -> Vec<RistrettoPoint> {
    chunks
        .iter()
        .map(|chunk| committer.commit(chunk).unwrap())
        .collect()
}

/// Tính linear combination của các commitment với coding vector (đã chuyển sang Scalar).
/// coding_vector_in_scalar và chunk_commitments phải cùng độ dài.
pub fn linear_combine_commitments(
    coding_vector_in_scalar: &[Scalar],
    chunk_commitments: &[RistrettoPoint],
) -> RistrettoPoint {
    RistrettoPoint::multiscalar_mul(coding_vector_in_scalar, chunk_commitments)
}
