// node.rs
use crate::commitments::{CodedPiece, Committer};
use crate::rlnc::decoder::NetworkDecoder;
use crate::rlnc::encoder::NetworkEncoder;
use crate::rlnc::recoder::NetworkRecoder;
use crate::rlnc::storage::{BlockId, InMemoryStorage, NodeStorage, PieceIdx, ShredId};

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

/// Message structure used for network send/receive (shred + commitment + metadata)
#[derive(Clone, Debug)]
pub struct Message<C: Clone> {
    pub block_id: BlockId,
    pub shred_id: ShredId,
    pub piece_idx: PieceIdx,
    pub piece: CodedPiece<Scalar>,
    pub commitment: C,
    pub source_id: usize,
}

/// Node struct (uses InMemoryStorage as internal storage)
pub struct Node<'a, C: Committer<Scalar = Scalar, Commitment = Vec<RistrettoPoint>>> {
    pub id: usize,
    pub committer: &'a C,
    pub neighbors: Vec<usize>,

    // storage: in-memory simulated storage local to node
    pub storage: InMemoryStorage<C>,

    // metadata for the blocks this node is working with
    // here we support a single active block_id for simplicity; can be extended
    pub active_block: Option<BlockId>,
    pub num_shreds: usize,
    pub num_chunks_per_shred: usize,
    pub bandwidth_limit: usize,

    // helpers
    pub encoder: NetworkEncoder,
    pub decoder: NetworkDecoder,
    pub recoder: NetworkRecoder,
}

impl<'a, C: Committer<Scalar = Scalar, Commitment = Vec<RistrettoPoint>>> Node<'a, C> {
    /// create an empty node
    pub fn new(
        id: usize,
        committer: &'a C,
        neighbors: Vec<usize>,
        bandwidth_limit: usize,
        num_shreds: usize,
        num_chunks_per_shred: usize,
    ) -> Self {
        let storage = InMemoryStorage::<C>::new();
        let encoder = NetworkEncoder::new(0, num_shreds, num_chunks_per_shred); // block_id replaced when source created
        let decoder = NetworkDecoder::new(num_chunks_per_shred);
        let recoder = NetworkRecoder::new(num_chunks_per_shred);
        Node {
            id,
            committer,
            neighbors,
            storage,
            active_block: None,
            num_shreds,
            num_chunks_per_shred,
            bandwidth_limit,
            encoder,
            decoder,
            recoder,
        }
    }

    /// new_source: take `data` (original block), optionally apply RS-extend,
    /// split into num_shreds and store shreds -> create RLNC coded pieces per shred and store them + commitments.
    ///
    /// NOTE: RS extend here is a simple splitter/padder placeholder.
    /// Replace with real RSErasureCoder usage if desired.
    pub fn new_source(
        &mut self,
        block_id: BlockId,
        data: Vec<u8>,
        use_rs: bool,
    ) -> Result<(), String> {
        // 1) optionally extend using RS (placeholder implementation).
        // Ideally replace with RSErasureCoder::new(...) and extract shares.
        let num_shreds = self.num_shreds;
        let mut extended: Vec<u8> = Vec::new();

        if use_rs {
            // Placeholder RS extend: simply pad to multiple of num_shreds and split.
            // Replace with real reed-solomon extension if needed.
            let shred_size = (data.len() + num_shreds - 1) / num_shreds;
            let mut padded = data.clone();
            padded.resize(shred_size * num_shreds, 0u8);
            extended = padded;
        } else {
            // No RS: just split original block across shreds (if divisible)
            if data.len() % num_shreds != 0 {
                return Err(format!(
                    "data.len() {} not divisible by num_shreds {}",
                    data.len(),
                    num_shreds
                ));
            }
            extended = data;
        }

        // 2) split extended into shreds and store
        let shred_size = extended.len() / num_shreds;
        for sid in 0..num_shreds {
            let start = sid * shred_size;
            let end = start + shred_size;
            let shred_bytes = extended[start..end].to_vec();
            self.storage.store_shred(block_id, sid, shred_bytes);
        }

        // 3) For each shred: compute commitment and produce initial coded pieces (a few), store them in storage
        self.active_block = Some(block_id);
        self.encoder = NetworkEncoder::new(block_id, num_shreds, self.num_chunks_per_shred);

        for sid in 0..num_shreds {
            // create and store commitment for shred
            let commitment = self
                .encoder
                .get_shred_commitment::<C, _>(&self.storage, self.committer, sid)
                .map_err(|e| format!("commit failed for shred {}: {}", sid, e))?;
            self.storage
                .store_commitment(block_id, sid, commitment.clone());

            // produce several initial coded pieces for this shred (like num_chunks_per_shred + extras)
            let initial_pieces = self.num_chunks_per_shred + 2;
            for idx in 0..initial_pieces {
                let piece = self
                    .encoder
                    .encode_one_shred::<C, _>(&self.storage, self.committer, sid)
                    .map_err(|e| format!("encode failed shred {}: {}", sid, e))?;
                // store with deterministic piece idx (caller chooses idx)
                let piece_idx = idx; // choose idx scheme; here simple
                self.storage
                    .store_coded_piece(block_id, sid, piece_idx, piece);
            }
        }

        Ok(())
    }

    /// Send: collect up to bandwidth_limit pieces (across shreds) and form messages to each neighbor.
    /// For each neighbor, we clone the same batch.
    pub fn send(
        &self,
        block_id: BlockId,
        source_id: usize,
    ) -> Vec<(usize, Vec<Message<Vec<RistrettoPoint>>>)> {
        let mut messages_per_neighbor: Vec<(usize, Vec<Message<Vec<RistrettoPoint>>>)> = Vec::new();

        // gather candidate pieces: choose by iterating shreds and their indices
        let mut candidates: Vec<Message<Vec<RistrettoPoint>>> = Vec::new();

        for sid in 0..self.num_shreds {
            let indices = self.storage.list_piece_indices(block_id, sid);
            for &idx in indices.iter() {
                if let Some(piece) = self.storage.get_coded_piece(block_id, sid, idx) {
                    if let Some(commit) = self.storage.get_commitment(block_id, sid) {
                        let msg = Message {
                            block_id,
                            shred_id: sid,
                            piece_idx: idx,
                            piece: piece.clone(),
                            commitment: commit.clone(),
                            source_id,
                        };
                        candidates.push(msg);
                    }
                }
                if candidates.len() >= self.bandwidth_limit {
                    break;
                }
            }
            if candidates.len() >= self.bandwidth_limit {
                break;
            }
        }

        for &nbr in &self.neighbors {
            messages_per_neighbor.push((nbr, candidates.clone()));
        }

        messages_per_neighbor
    }

    /// Receive messages: verify commit, store coded piece, try recode (generate new piece) and try decode shred.
    /// Return Ok(()) or Err(String)
    pub fn receive_messages(
        &mut self,
        msgs: Vec<Message<Vec<RistrettoPoint>>>,
    ) -> Result<(), String> {
        for msg in msgs.into_iter() {
            // verify commitment first via decoder
            let commitment = msg.commitment.clone();
            let piece = msg.piece.clone();
            // verify using stateless decoder API
            self.decoder
                .verify_piece::<C, InMemoryStorage<C>>(self.committer, &piece, &commitment)
                .map_err(|e| format!("verify failed: {:?}", e))?;

            // store the coded piece to storage
            // choose piece_idx scheme: we use provided piece_idx if free, otherwise append at max_index+1
            let existing = self
                .storage
                .get_coded_piece(msg.block_id, msg.shred_id, msg.piece_idx);
            let store_idx = if existing.is_some() {
                // find next free index
                let mut next = 0usize;
                loop {
                    if self
                        .storage
                        .get_coded_piece(msg.block_id, msg.shred_id, next)
                        .is_none()
                    {
                        break next;
                    }
                    next += 1;
                }
            } else {
                msg.piece_idx
            };
            self.storage
                .store_coded_piece(msg.block_id, msg.shred_id, store_idx, piece.clone());

            // update recoder: we decide to recode if we have at least 2 pieces for that shred
            let indices = self.storage.list_piece_indices(msg.block_id, msg.shred_id);
            if indices.len() >= 2 {
                // choose some indices to mix (for example all present)
                let mix_idxs = indices.clone();
                let new_piece = self
                    .recoder
                    .recode::<C, _>(&self.storage, msg.block_id, msg.shred_id, &mix_idxs)
                    .map_err(|e| format!("recode failed: {}", e))?;
                // store new recoded piece (use next free index)
                let mut next_idx = 0usize;
                loop {
                    if self
                        .storage
                        .get_coded_piece(msg.block_id, msg.shred_id, next_idx)
                        .is_none()
                    {
                        break;
                    }
                    next_idx += 1;
                }
                self.storage
                    .store_coded_piece(msg.block_id, msg.shred_id, next_idx, new_piece);
            }

            // try decode shred: gather indices and call decoder.try_decode_shred
            let piece_indices = self.storage.list_piece_indices(msg.block_id, msg.shred_id);
            if piece_indices.len() >= self.num_chunks_per_shred {
                // attempt decode
                if let Some(commit) = self.storage.get_commitment(msg.block_id, msg.shred_id) {
                    match self.decoder.try_decode_shred::<C, _>(
                        &self.storage,
                        msg.block_id,
                        msg.shred_id,
                        &piece_indices,
                        commit,
                    ) {
                        Ok(decoded_bytes) => {
                            // store decoded shred
                            self.storage.store_decoded_shred(
                                msg.block_id,
                                msg.shred_id,
                                decoded_bytes,
                            );
                        }
                        Err(_) => {
                            // decoding incomplete or failed -> ignore for now
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Try reconstruct full block if all shreds decoded.
    /// If RS was used originally, you should call RS reconstruct here (placeholder returns concatenated shreds).
    pub fn try_reconstruct_block(&self, block_id: BlockId, use_rs: bool) -> Option<Vec<u8>> {
        let decoded = self.storage.list_decoded_shreds(block_id);
        if decoded.len() < self.num_shreds {
            return None;
        }
        // assemble in order
        let mut out = Vec::new();
        for sid in 0..self.num_shreds {
            if let Some(bytes) = self.storage.get_decoded_shred(block_id, sid) {
                out.extend_from_slice(bytes);
            } else {
                return None;
            }
        }
        if use_rs {
            // placeholder: if RS was used, you should run RS reconstruct to get original block
            // For now, return ext block (concatenated shreds)
            Some(out)
        } else {
            Some(out)
        }
    }
}
