use super::core::{BlockId, NodeStorage, PieceIdx, ShredId};
use crate::commitments::CodedPiece;
use crate::commitments::Committer;
use crate::utils::rlnc::NetworkDecoder;
use crate::utils::rlnc::RLNCError;
use curve25519_dalek::Scalar;

/// Stateless decoder metadata: just knows how many pieces needed per shred
pub struct StorageDecoder {
    pub piece_count: usize, // number of chunks per shred (k)
}

impl StorageDecoder {
    pub fn new(piece_count: usize) -> Self {
        Self { piece_count }
    }

    /// Verify a coded piece against commitment (commitment should be retrieved from storage by caller or via storage)
    pub fn verify_piece<'a, C: Committer<Scalar = Scalar>, S: NodeStorage<'a, C>>(
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

    pub fn decode_shred<'a, C: Committer<Scalar = Scalar> + 'a, S: NodeStorage<'a, C>>(
        &self,
        storage: &mut S,
        block_id: BlockId,
        shred_id: ShredId,
        coded_piece: &CodedPiece<Scalar>,
    ) -> Result<bool, RLNCError> {
        let mut decoder = if let Some(d) = storage.get_mut_decoded(block_id, shred_id) {
            d.clone()
        } else {
            let new_decoder = NetworkDecoder::new(None, self.piece_count);
            storage.store_decoded(block_id, shred_id, new_decoder.clone());
            new_decoder
        };

        let res = decoder.direct_decode(coded_piece);

        if res.is_ok() {
            let piece_indices = storage
                .list_piece_indices(block_id, shred_id)
                .into_iter()
                .collect::<Vec<PieceIdx>>();
            storage.store_coded_piece(block_id, shred_id, piece_indices.len(), coded_piece.clone());
            storage.store_decoded(block_id, shred_id, decoder.clone());
        }

        Ok(decoder.is_already_decoded())
    }

    pub fn get_raw_from_decoded_shred<
        'a,
        C: Committer<Scalar = Scalar> + 'a,
        S: NodeStorage<'a, C>,
    >(
        &self,
        storage: &S,
        block_id: BlockId,
        shred_id: ShredId,
    ) -> Result<Vec<u8>, RLNCError> {
        let decoder: &NetworkDecoder<C> = storage
            .get_decoded(block_id, shred_id)
            .ok_or(RLNCError::DecodingNotComplete)?;

        if !decoder.is_already_decoded() {
            return Err(RLNCError::DecodingNotComplete);
        }

        let res = decoder.get_decoded_data();
        match res {
            Ok(data) => Ok(data),
            Err(_err) => Err(RLNCError::DecodingNotComplete),
        }
    }

    /// Try decode a shred from storage given a list of piece indices available.
    /// This method loads the pieces from storage, attempts to solve linear system and returns Ok(decoded_bytes)
    /// or Err(RLNCError::DecodingNotComplete) if insufficient useful pieces.
    pub fn try_decode_shred<'a, C: Committer<Scalar = Scalar>, S: NodeStorage<'a, C>>(
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

        let mut decoder: NetworkDecoder<C> = NetworkDecoder::new(None, self.piece_count);

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
