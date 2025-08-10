use crate::commitments::CodedPiece;
use crate::commitments::Committer;
use crate::utils::ristretto::{block_to_chunks, chunk_to_scalars};
use curve25519_dalek::Scalar;

use crate::rlnc::storage::{BlockId, NodeStorage, ShredId};
use rand::Rng;

/// NetworkEncoder is stateless except for metadata:
/// - block: id of extended block (or logical block)
/// - num_chunks_per_shred: number of chunks RLNC expects per shred
/// - rand seed/choice for piece indices is left to caller (we return a CodedPiece)
pub struct NetworkEncoder {
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

impl NetworkEncoder {
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
        _committer: &C,
        shred_id: ShredId,
    ) -> Result<CodedPiece<Scalar>, String> {
        // get shred bytes from storage
        let shred_bytes = storage
            .get_shred(self.block_id, shred_id)
            .ok_or_else(|| "Shred bytes not found in storage".to_string())?;

        // split shred into chunks then into scalars
        let chunks = block_to_chunks(shred_bytes, self.num_chunks_per_shred)?
            .into_iter()
            .map(|data| chunk_to_scalars(data).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;

        if chunks.is_empty() {
            return Err("no chunks in shred".to_string());
        }

        // linear combination
        let coefficients = generate_random_coefficients(chunks.len());
        let data = (0..chunks[0].len())
            .map(|i| {
                coefficients
                    .iter()
                    .zip(&chunks)
                    .map(|(coeff, chunk)| *coeff * chunk[i])
                    .sum()
            })
            .collect();

        Ok(CodedPiece { data, coefficients })
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

        let chunks = block_to_chunks(shred_bytes, self.num_chunks_per_shred)?
            .into_iter()
            .map(|data| chunk_to_scalars(data).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;

        committer
            .commit(&chunks)
            .map_err(|_| "commit failed".to_string())
    }
}
