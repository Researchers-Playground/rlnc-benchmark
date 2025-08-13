// message.rs
use crate::commitments::CodedPiece;
use curve25519_dalek::scalar::Scalar;

pub type BlockId = usize;
pub type ShredId = usize;
pub type PieceIdx = usize;

// TODO: implement some verification proof here if wanting to reflect true overhead.
#[derive(Clone, Debug)]
pub struct RetrieveShredMsg<C> {
    _type: String,
    pub block_id: BlockId,
    pub shred_id: ShredId,
    pub piece_idx: PieceIdx,
    pub piece: CodedPiece<Scalar>,
    pub commitment: C,
    pub source_id: usize,
}

impl<C> RetrieveShredMsg<C> {
    pub fn new(
        block_id: BlockId,
        shred_id: ShredId,
        piece_idx: PieceIdx,
        piece: CodedPiece<Scalar>,
        commitment: C,
        source_id: usize,
    ) -> Self {
        Self {
            _type: "IWANT".to_string(),
            block_id,
            shred_id,
            piece_idx,
            piece,
            commitment,
            source_id,
        }
    }

    pub fn get_type(self) -> String {
        self._type
    }
}

// TODO: implement some verification proof here if wanting to reflect true overhead.
#[derive(Clone, Debug)]
pub struct BroadcastCodedBlockMsg<C> {
    _type: String,
    pub block_id: BlockId,
    pub coded_pieces: Vec<CodedPiece<Scalar>>,
    pub commitments: Vec<C>,
    pub source_id: usize,
}

impl<C> BroadcastCodedBlockMsg<C> {
    pub fn new(
        block_id: BlockId,
        coded_pieces: Vec<CodedPiece<Scalar>>,
        commitments: Vec<C>,
        source_id: usize,
    ) -> Self {
        Self {
            _type: "PUBLISH".to_string(),
            block_id,
            coded_pieces,
            commitments,
            source_id,
        }
    }

    pub fn get_type(self) -> String {
        self._type
    }

    pub fn coded_piece_size_in_bytes(&self) -> usize {
        self.coded_pieces.len() * size_of::<CodedPiece<Scalar>>()
    }
}
