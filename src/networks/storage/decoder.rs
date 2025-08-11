use crate::commitments::CodedPiece;
use crate::commitments::Committer;
use crate::utils::rlnc::NetworkDecoder;
use crate::utils::rlnc::RLNCError;
use curve25519_dalek::Scalar;
use super::core::{BlockId, NodeStorage, PieceIdx, ShredId};


/// Stateless decoder metadata: just knows how many pieces needed per shred
pub struct StorageDecoder {
    pub piece_count: usize, // number of chunks per shred (k)
}

impl StorageDecoder {
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
            return Err(RLNCError::DecodingNotComplete);
        }

        let mut decoder: NetworkDecoder<C> = NetworkDecoder::new(
            None,
            self.piece_count,
        );

        for (index, piece) in pieces.iter().enumerate() {
            if let Err(err) = decoder.direct_decode(piece) {
                eprintln!("Failed to decode piece at index {}: {:?}", index, err);
            }
        }
        if !decoder.is_already_decoded() {
            return Err(RLNCError::DecodingNotComplete);
        }
        decoder.get_decoded_data()
    }
}
