use crate::commitments::CodedPiece;
use crate::commitments::Committer;
use curve25519_dalek::Scalar;
use rand::Rng;

use crate::rlnc::storage::{BlockId, NodeStorage, PieceIdx, ShredId};

/// NetworkRecoder is stateless and only needs to know piece_count (k)
pub struct NetworkRecoder {
    pub piece_count: usize,
}

fn rand_scalar<S: From<u8>>() -> S {
    let random_byte = rand::rng().random::<u8>();
    S::from(random_byte)
}

impl NetworkRecoder {
    pub fn new(piece_count: usize) -> Self {
        Self { piece_count }
    }

    /// Recode: take available piece indices for a shred (from storage), read pieces, mix them,
    /// and produce a new CodedPiece for forwarding.
    pub fn recode<C: Committer<Scalar = Scalar>, S: NodeStorage<C>>(
        &self,
        storage: &S,
        block_id: BlockId,
        shred_id: ShredId,
        use_piece_indices: &[PieceIdx], // indices to read & mix
    ) -> Result<CodedPiece<Scalar>, String> {
        // collect pieces
        let mut collected: Vec<CodedPiece<Scalar>> = Vec::new();
        for &idx in use_piece_indices.iter() {
            if let Some(p) = storage.get_coded_piece(block_id, shred_id, idx) {
                collected.push(p.clone());
            }
        }
        if collected.is_empty() {
            return Err("No pieces available to recode".to_string());
        }

        let n = collected.len();
        // mixing coefficients
        let mixing: Vec<Scalar> = (0..n).map(|_| rand_scalar::<Scalar>()).collect();

        // data length expects all pieces same len; take from first
        let data_len = collected[0].data.len();
        let coeffs_len = collected[0].coefficients.len();

        // mix data
        let mut new_data: Vec<Scalar> = vec![Scalar::ZERO; data_len];
        for i in 0..data_len {
            let mut acc = Scalar::ZERO;
            for (j, piece) in collected.iter().enumerate() {
                acc += mixing[j] * piece.data[i];
            }
            new_data[i] = acc;
        }

        // new coefficients = mixing * old_coeffs
        let mut new_coeffs: Vec<Scalar> = vec![Scalar::ZERO; coeffs_len];
        for i in 0..coeffs_len {
            let mut acc = Scalar::ZERO;
            for (j, piece) in collected.iter().enumerate() {
                acc += mixing[j] * piece.coefficients[i];
            }
            new_coeffs[i] = acc;
        }

        Ok(CodedPiece {
            data: new_data,
            coefficients: new_coeffs,
        })
    }
}
