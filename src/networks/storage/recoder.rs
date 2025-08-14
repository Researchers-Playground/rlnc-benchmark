use crate::commitments::CodedPiece;
use crate::commitments::Committer;
use crate::utils::rlnc::NetworkRecoder;
use curve25519_dalek::Scalar;

use super::core::{BlockId, NodeStorage, PieceIdx, ShredId};

pub struct StorageRecoder {
    pub piece_count: usize,
}

impl StorageRecoder {
    pub fn new(piece_count: usize) -> Self {
        Self { piece_count }
    }

    /// Recode: take available piece indices for a shred (from storage), read pieces, mix them,
    /// and produce a new CodedPiece for forwarding.
    pub fn recode<'a, C: Committer<Scalar = Scalar>, S: NodeStorage<'a, C>>(
        &self,
        storage: &S,
        block_id: BlockId,
        shred_id: ShredId,
        use_piece_indices: &[PieceIdx],
    ) -> Result<CodedPiece<Scalar>, String> {
        let mut collected: Vec<CodedPiece<Scalar>> = Vec::new();
        for &idx in use_piece_indices.iter() {
            if let Some(p) = storage.get_coded_piece(block_id, shred_id, idx) {
                collected.push(p.clone());
            }
        }
        if collected.is_empty() {
            return Err("No pieces available to recode".to_string());
        }

        let recoder = NetworkRecoder::new(collected, self.piece_count);
        Ok(recoder.recode())
    }
}
