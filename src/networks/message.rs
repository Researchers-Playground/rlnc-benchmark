// message.rs
use crate::commitments::CodedPiece;
use curve25519_dalek::scalar::Scalar;

pub type BlockId = usize;
pub type ShredId = usize;
pub type PieceIdx = usize;

#[derive(Clone, Debug)]
pub struct Message<C> {
    pub block_id: BlockId,
    pub shred_id: ShredId,
    pub piece_idx: PieceIdx,
    pub piece: CodedPiece<Scalar>,
    pub commitment: C,
    pub source_id: usize,
}
