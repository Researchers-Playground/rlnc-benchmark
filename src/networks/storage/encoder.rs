use super::core::{BlockId, NodeStorage, ShredId};
use crate::commitments::CodedPiece;
use crate::commitments::Committer;
use crate::utils::rlnc::NetworkEncoder;
use curve25519_dalek::Scalar;
use rand::Rng;

pub struct StorageEncoder {
    pub block_id: BlockId,
    pub num_shreds: usize,
    pub num_chunks_per_shred: usize,
}

impl StorageEncoder {
    pub fn new(block_id: BlockId, num_shreds: usize, num_chunks_per_shred: usize) -> Self {
        Self {
            block_id,
            num_shreds,
            num_chunks_per_shred,
        }
    }

    /// Encode one shred (read shred bytes from storage, split it into chunks, map to scalars, produce a coded piece)
    /// `piece_idx` is an index used by caller to store pieces deterministically (e.g., sequence number).
    pub fn encode_one_shred<'a, C: Committer<Scalar = Scalar>, S: NodeStorage<'a, C>>(
        &self,
        storage: &S,
        committer: &C,
        shred_id: ShredId,
    ) -> Result<CodedPiece<Scalar>, String> {
        // get shred bytes from storage
        let shred_bytes = storage
            .get_shred(self.block_id, shred_id)
            .ok_or_else(|| "Shred bytes not found in storage".to_string())?;

        let encoder = NetworkEncoder::new(
            committer,
            Some(shred_bytes.to_vec()),
            self.num_chunks_per_shred,
        )
        .unwrap();
        let coded_piece = encoder.encode().unwrap();

        Ok(coded_piece)
    }

    /// Produce the commitment for one shred (delegates to committer.commit on shredded chunks).
    pub fn get_shred_commitment<'a, C: Committer<Scalar = Scalar>, S: NodeStorage<'a, C>>(
        &self,
        storage: &S,
        committer: &C,
        shred_id: ShredId,
    ) -> Result<C::Commitment, String> {
        let shred_bytes = storage
            .get_shred(self.block_id, shred_id)
            .ok_or_else(|| "Shred bytes not found".to_string())?;

        let encoder = NetworkEncoder::new(
            committer,
            Some(shred_bytes.to_vec()),
            self.num_chunks_per_shred,
        )?;
        let commitment = encoder.get_commitment();

        commitment
    }
}
