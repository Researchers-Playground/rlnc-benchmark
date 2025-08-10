use crate::commitments::CodedPiece;
use crate::commitments::Committer;
use crate::utils::matrix::Echelon;
use curve25519_dalek::Scalar;

use crate::rlnc::storage::{BlockId, NodeStorage, PieceIdx, ShredId};

#[derive(thiserror::Error, Debug)]
pub enum RLNCError {
    #[error("Linearly dependent chunk received")]
    PieceNotUseful,
    #[error("Received all pieces")]
    ReceivedAllPieces,
    #[error("Decoding not complete")]
    DecodingNotComplete,
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

/// Stateless decoder metadata: just knows how many pieces needed per shred
pub struct NetworkDecoder {
    pub piece_count: usize, // number of chunks per shred (k)
}

impl NetworkDecoder {
    pub fn new(piece_count: usize) -> Self {
        Self { piece_count }
    }

    /// Verify a coded piece against commitment (commitment should be retrieved from storage by caller or via storage)
    pub fn verify_piece<C: Committer<Scalar = Scalar>, S: NodeStorage<C>>(
        &self,
        committer: &C,
        piece: &CodedPiece<Scalar>,
        commitment: &C::Commitment,
    ) -> Result<(), RLNCError> {
        let ok = committer.verify(Some(commitment), piece);
        if !ok {
            return Err(RLNCError::InvalidData(
                "Commitment verification failed".to_string(),
            ));
        }
        Ok(())
    }

    /// Try decode a shred from storage given a list of piece indices available.
    /// This method loads the pieces from storage, attempts to solve linear system and returns Ok(decoded_bytes)
    /// or Err(RLNCError::DecodingNotComplete) if insufficient useful pieces.
    pub fn try_decode_shred<C: Committer<Scalar = Scalar>, S: NodeStorage<C>>(
        &self,
        storage: &S,
        block_id: BlockId,
        shred_id: ShredId,
        piece_indices: &[PieceIdx],
        _commitment: &C::Commitment,
    ) -> Result<Vec<u8>, RLNCError> {
        // collect pieces from storage
        let mut pieces = Vec::new();
        for &idx in piece_indices.iter() {
            if let Some(p) = storage.get_coded_piece(block_id, shred_id, idx) {
                pieces.push(p.clone());
            }
        }

        if pieces.len() < self.piece_count {
            println!("go here pieces.len() < self.piece_count");
            return Err(RLNCError::DecodingNotComplete);
        }

        // echelon solve like original code
        let mut echelon = Echelon::new(self.piece_count);
        let mut received_chunks: Vec<Vec<Scalar>> = Vec::new();

        for piece in &pieces {
            if !echelon.add_row(piece.coefficients.clone()) {
                // skip dependent row
                continue;
            }
            received_chunks.push(piece.data.clone());
            if received_chunks.len() >= self.piece_count {
                break;
            }
        }

        if received_chunks.len() < self.piece_count {
            println!(
                "go here received_chunks.len() < self.piece_count, chunks lens {:?}",
                received_chunks.len()
            );
            return Err(RLNCError::DecodingNotComplete);
        }

        let inverse = echelon.inverse().map_err(|e| RLNCError::InvalidData(e))?;
        let mut padded_result = Vec::new();
        for i in 0..inverse.len() {
            for k in 0..received_chunks[0].len() {
                let scalar_sum: Scalar = (0..inverse.len())
                    .map(|j| inverse[i][j] * received_chunks[j][k])
                    .sum();
                padded_result.extend_from_slice(&scalar_sum.to_bytes());
            }
        }
        Ok(padded_result)
    }
}
