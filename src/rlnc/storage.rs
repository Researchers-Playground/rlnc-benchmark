use crate::commitments::CodedPiece;
use crate::commitments::Committer;
use curve25519_dalek::Scalar;
use std::collections::{HashMap, HashSet};

/// BlockId: bạn có thể thay bằng kiểu phù hợp
pub type BlockId = usize;
pub type ShredId = usize;
pub type PieceIdx = usize;

/// NodeStorage trait: storage giả lập (RAM) - generic theo Committer C
pub trait NodeStorage<C: Committer<Scalar = Scalar>> {
    type Commitment;

    // Shred (raw bytes)
    fn store_shred(&mut self, block: BlockId, shred: ShredId, bytes: Vec<u8>);
    fn get_shred(&self, block: BlockId, shred: ShredId) -> Option<&Vec<u8>>;

    // Coded piece (RLNC output)
    fn store_coded_piece(
        &mut self,
        block: BlockId,
        shred: ShredId,
        idx: PieceIdx,
        piece: CodedPiece<Scalar>,
    );
    fn get_coded_piece(
        &self,
        block: BlockId,
        shred: ShredId,
        idx: PieceIdx,
    ) -> Option<&CodedPiece<Scalar>>;

    // get list of piece indices available for a shred
    fn list_piece_indices(&self, block: BlockId, shred: ShredId) -> Vec<PieceIdx>;

    // Commitment per-shred (one commitment identifies all coded pieces for that shred)
    fn store_commitment(&mut self, block: BlockId, shred: ShredId, commitment: Self::Commitment);
    fn get_commitment(&self, block: BlockId, shred: ShredId) -> Option<&Self::Commitment>;

    // decoded shred storage (bytes)
    fn store_decoded_shred(&mut self, block: BlockId, shred: ShredId, bytes: Vec<u8>);
    fn get_decoded_shred(&self, block: BlockId, shred: ShredId) -> Option<&Vec<u8>>;

    // helper: check if a block is fully reconstructed
    fn list_decoded_shreds(&self, block: BlockId) -> Vec<ShredId>;
}

/// InMemory implementation (for testing & local simulation)
pub struct InMemoryStorage<C: Committer<Scalar = Scalar>> {
    shreds: HashMap<(BlockId, ShredId), Vec<u8>>,
    coded: HashMap<(BlockId, ShredId, PieceIdx), CodedPiece<Scalar>>,
    pub pieces_index: HashMap<(BlockId, ShredId), HashSet<PieceIdx>>,
    commitments: HashMap<(BlockId, ShredId), C::Commitment>,
    decoded_shreds: HashMap<(BlockId, ShredId), Vec<u8>>,
}

impl<C: Committer<Scalar = Scalar>> InMemoryStorage<C> {
    pub fn new() -> Self {
        Self {
            shreds: HashMap::new(),
            coded: HashMap::new(),
            pieces_index: HashMap::new(),
            commitments: HashMap::new(),
            decoded_shreds: HashMap::new(),
        }
    }
}

impl<C: Committer<Scalar = Scalar>> NodeStorage<C> for InMemoryStorage<C> {
    type Commitment = C::Commitment;

    fn store_shred(&mut self, block: BlockId, shred: ShredId, bytes: Vec<u8>) {
        self.shreds.insert((block, shred), bytes);
    }

    fn get_shred(&self, block: BlockId, shred: ShredId) -> Option<&Vec<u8>> {
        self.shreds.get(&(block, shred))
    }

    fn store_coded_piece(
        &mut self,
        block: BlockId,
        shred: ShredId,
        idx: PieceIdx,
        piece: CodedPiece<Scalar>,
    ) {
        self.coded.insert((block, shred, idx), piece);
        self.pieces_index
            .entry((block, shred))
            .or_insert_with(HashSet::new)
            .insert(idx);
    }

    fn get_coded_piece(
        &self,
        block: BlockId,
        shred: ShredId,
        idx: PieceIdx,
    ) -> Option<&CodedPiece<Scalar>> {
        self.coded.get(&(block, shred, idx))
    }

    fn list_piece_indices(&self, block: BlockId, shred: ShredId) -> Vec<PieceIdx> {
        self.pieces_index
            .get(&(block, shred))
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn store_commitment(&mut self, block: BlockId, shred: ShredId, commitment: Self::Commitment) {
        self.commitments.insert((block, shred), commitment);
    }

    fn get_commitment(&self, block: BlockId, shred: ShredId) -> Option<&Self::Commitment> {
        self.commitments.get(&(block, shred))
    }

    fn store_decoded_shred(&mut self, block: BlockId, shred: ShredId, bytes: Vec<u8>) {
        self.decoded_shreds.insert((block, shred), bytes);
    }

    fn get_decoded_shred(&self, block: BlockId, shred: ShredId) -> Option<&Vec<u8>> {
        self.decoded_shreds.get(&(block, shred))
    }

    fn list_decoded_shreds(&self, block: BlockId) -> Vec<ShredId> {
        self.decoded_shreds
            .keys()
            .filter(|(b, _)| *b == block)
            .map(|(_, s)| *s)
            .collect()
    }
}
