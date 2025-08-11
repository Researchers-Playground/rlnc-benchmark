use crate::commitments::CodedPiece;
use crate::commitments::Committer;
use curve25519_dalek::Scalar;
use super::core::{BlockId, NodeStorage, ShredId};
use crate::utils::rlnc::NetworkEncoder;
use rand::Rng;

pub struct StorageEncoder {
    pub block_id: BlockId,
    pub num_shreds: usize,
    pub num_chunks_per_shred: usize,
}

fn generate_random_coefficients(length: usize) -> Vec<Scalar> {
    let mut rng = rand::rng();
    (0..length)
        .map(|_| {
            let random_byte = rng.random::<u8>();
            Scalar::from(random_byte)
        })
        .collect()
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
    pub fn encode_one_shred<C: Committer<Scalar = Scalar>, S: NodeStorage<C>>(
        &self,
        storage: &S,
        committer: &C,
        shred_id: ShredId,
    ) -> Result<CodedPiece<Scalar>, String> {
        // get shred bytes from storage
        let shred_bytes = storage
            .get_shred(self.block_id, shred_id)
            .ok_or_else(|| "Shred bytes not found in storage".to_string())?;

        let encoder = NetworkEncoder::new(committer, Some(shred_bytes.to_vec()), self.num_chunks_per_shred).unwrap();
        let coded_piece = encoder
            .encode().unwrap();

        Ok(coded_piece)
    }

    /// Produce the commitment for one shred (delegates to committer.commit on shredded chunks).
    pub fn get_shred_commitment<C: Committer<Scalar = Scalar>, S: NodeStorage<C>>(
        &self,
        storage: &S,
        committer: &C,
        shred_id: ShredId,
    ) -> Result<C::Commitment, String> {
        let shred_bytes = storage
            .get_shred(self.block_id, shred_id)
            .ok_or_else(|| "Shred bytes not found".to_string())?;

        let encoder = NetworkEncoder::new(committer, Some(shred_bytes.to_vec()), self.num_chunks_per_shred).unwrap();
        let commitment = encoder.get_commitment();

        commitment
    }
}
