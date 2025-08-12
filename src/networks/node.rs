// node.rs
use super::storage::core::{BlockId, InMemoryStorage, NodeStorage, PieceIdx, ShredId};
use crate::commitments::{CodedPiece, Committer};
use crate::networks::message::{BroadcastCodedBlockMsg, RetrieveShredMsg};
use crate::networks::storage::decoder::StorageDecoder;
use crate::networks::storage::encoder::StorageEncoder;
use crate::networks::storage::recoder::StorageRecoder;
use crate::utils::eds::{extended_data_share, FlatMatrix};
use rayon::prelude::*;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

/// Node struct (uses InMemoryStorage as internal storage)
pub struct Node<'a, C: Committer<Scalar = Scalar, Commitment = Vec<RistrettoPoint>>> {
    pub id: usize,
    pub committer: &'a C,
    pub neighbors: Vec<usize>,

    // storage: in-memory simulated storage local to node
    pub storage: InMemoryStorage<'a, C>,

    // metadata for the blocks this node is working with
    // here we support a single active block_id for simplicity; can be extended
    pub active_block: Option<BlockId>,
    pub num_shreds: usize,
    pub num_chunks_per_shred: usize,

    // coded custody size
    pub custody_size: usize,

    // helpers
    pub encoder: StorageEncoder,
    pub decoder: StorageDecoder,
    pub recoder: StorageRecoder,
}

impl<'a, C: Committer<Scalar = Scalar, Commitment = Vec<RistrettoPoint>>> Node<'a, C> {
    /// create an empty node
    pub fn new(
        id: usize,
        committer: &'a C,
        neighbors: Vec<usize>,
        num_shreds: usize,
        num_chunks_per_shred: usize,
        custody_size: usize,
    ) -> Self {
        let storage = InMemoryStorage::<C>::new();
        let encoder = StorageEncoder::new(0, num_shreds, num_chunks_per_shred); // block_id replaced when source created
        let decoder = StorageDecoder::new(num_chunks_per_shred);
        let recoder = StorageRecoder::new(num_chunks_per_shred);
        Node {
            id,
            committer,
            neighbors,
            storage,
            active_block: None,
            num_shreds,
            num_chunks_per_shred,
            custody_size,
            encoder,
            decoder,
            recoder,
        }
    }

    /// Hàm helper để extend block thành 2D matrix (k x k -> 2k x 2k)
    fn extend_2d_matrix(data: &[u8], share_size: usize, k: usize) -> Result<Vec<u8>, String> {
        // Kiểm tra kích thước dữ liệu
        let expected_size = k * k * share_size;
        if data.len() != expected_size {
            return Err(format!(
                "data.len() {} does not match expected size {} (k={} x k={} x share_size={})",
                data.len(),
                expected_size,
                k,
                k,
                share_size
            ));
        }

        // Tạo ma trận gốc
        let original_matrix = FlatMatrix::new(data, share_size, k);

        // Tạo ma trận mở rộng 2D (k x k -> 2k x 2k)
        let extended_matrix = extended_data_share(&original_matrix, k);

        // Kiểm tra kích thước ma trận mở rộng
        let (rows, cols) = extended_matrix.dimensions();
        if rows != 2 * k || cols != 2 * k {
            return Err(format!(
                "Extended matrix dimensions ({}, {}) do not match expected (2k={}, 2k={})",
                rows,
                cols,
                2 * k,
                2 * k
            ));
        }

        // Lấy dữ liệu đã mở rộng
        Ok(extended_matrix.data().to_vec())
    }

    /// new_source: take `data` (original block), optionally apply 2D matrix extension,
    /// split into num_shreds and store shreds -> create RLNC coded pieces per shred and store them + commitments.
    pub fn new_source(
        &mut self,
        block_id: BlockId,
        data: Vec<u8>,
        use_rs: bool,
        share_size: usize, // New parameter for share_size
    ) -> Result<(), String> {
        let mut num_shreds = self.num_shreds;
        let extended: Vec<u8>;

        if use_rs {
            // Calculate k based on data size and share_size
            let num_shares = (data.len() as f64 / share_size as f64).ceil() as usize;
            let k = (num_shares as f64).sqrt().ceil() as usize;
            if k == 0 {
                return Err("Invalid k: data size too small or share_size too large".to_string());
            }

            // Extend data with 2D matrix
            extended = Self::extend_2d_matrix(&data, share_size, k)?;

            // Update num_shreds = k for RS coding
            num_shreds = k;
        } else {
            // Non-RS: check if data is divisible by num_shreds
            if data.len() % self.num_shreds != 0 {
                return Err(format!(
                    "data.len() {} not divisible by num_shreds {}",
                    data.len(),
                    self.num_shreds
                ));
            }
            extended = data;
        }

        // Update num_shreds of node
        self.num_shreds = num_shreds;

        // Split extended into shreds and store
        let shred_size = (extended.len() as f64 / num_shreds as f64).ceil() as usize;
        self.encoder = StorageEncoder::new(block_id, num_shreds, self.num_chunks_per_shred);
        for sid in 0..num_shreds {
            let start = sid * shred_size;
            let end = std::cmp::min(start + shred_size, extended.len());
            let shred_bytes = extended[start..end].to_vec();
            self.storage.store_shred(block_id, sid, shred_bytes.clone());

            let commitment = self
                .encoder
                .get_shred_commitment::<C, _>(&self.storage, self.committer, sid)
                .map_err(|e| format!("Commit failed for shred {}: {}", sid, e))?;
            self.storage
                .store_commitment(block_id, sid, commitment.clone());

            println!(
                "Store shred id {:?}, value: {:?} and it's commitment",
                sid,
                &shred_bytes[..8]
            );
        }

        // Activate block and initialize encoder
        self.active_block = Some(block_id);
        Ok(())
    }

    /// Publish: publish a coded block to neighbors in publisher's mesh.
    pub fn publish(
        &self,
        block_id: BlockId,
        source_id: usize,
    ) -> Result<Vec<(usize, BroadcastCodedBlockMsg<Vec<RistrettoPoint>>)>, String> {
        // If not own commitments
        if self.storage.list_commitments(block_id).len() != self.num_shreds {
            return Ok(Vec::new());
        }

        let (commitments, coded_pieces) = if self.is_active_node(block_id) {
            let all_shreds = self.storage.list_shreds(block_id);
            all_shreds
                .par_iter()
                .map(|(id, _)| {
                    let coded_piece = self
                        .encoder
                        .encode_one_shred(&self.storage, self.committer, *id)
                        .map_err(|e| format!("Encode failed for shred {}: {}", id, e))?;

                    // This should be passed all the time since active node always has commitments in store.
                    let commitment = self.storage.get_commitment(block_id, *id).unwrap().clone();

                    Ok((commitment, coded_piece))
                })
                .collect::<Result<Vec<(Vec<RistrettoPoint>, CodedPiece)>, String>>()?
                .into_par_iter()
                .unzip()
        } else {
            // If any shreds are missing
            if (0..self.num_shreds)
                .any(|shred_id| self.storage.list_piece_indices(block_id, shred_id).len() == 0)
            {
                return Ok(Vec::new());
            }

            (0..self.num_shreds)
                .into_par_iter()
                .map(|shred_id| {
                    let piece_indices = self.storage.list_piece_indices(block_id, shred_id);
                    let recoded_piece = self
                        .recoder
                        .recode(&self.storage, block_id, shred_id, &piece_indices)
                        .map_err(|e| format!("Recode failed for shred {}: {}", shred_id, e))?;
                    let commitment = self
                        .storage
                        .get_commitment(block_id, shred_id)
                        .unwrap()
                        .clone();
                    Ok((commitment, recoded_piece))
                })
                .collect::<Result<Vec<(Vec<RistrettoPoint>, CodedPiece)>, String>>()?
                .into_par_iter()
                .unzip()
        };

        let message = BroadcastCodedBlockMsg::new(block_id, coded_pieces, commitments, source_id);
        let mut messages_per_neighbor: Vec<(usize, BroadcastCodedBlockMsg<Vec<RistrettoPoint>>)> =
            Vec::new();
        for &nbr in &self.neighbors {
            messages_per_neighbor.push((nbr, message.clone()));
        }

        Ok(messages_per_neighbor)
    }

    /// TODO: for now, just use 'subcribe'. In real implementation, this function will subcribe to a topic.
    /// Then handled by handler's functions.
    pub fn subcribe(
        &mut self,
        msg: BroadcastCodedBlockMsg<Vec<RistrettoPoint>>,
    ) -> Result<(), String> {
        for (commitment, (id, coded_piece)) in msg
            .commitments
            .iter()
            .zip(msg.coded_pieces.iter().enumerate())
        {
            let commitment_in_storage = self.storage.get_commitment(msg.block_id, id);

            match commitment_in_storage {
                Some(stored_commitment) if *stored_commitment == *commitment => {}
                _ => {
                    self.storage
                        .store_commitment(msg.block_id, id, commitment.clone());
                }
            };

            // verify each piece
            self.decoder
                .verify_piece::<C, InMemoryStorage<C>>(self.committer, coded_piece, commitment)
                .map_err(|e| format!("Commitment verification failed at index {}: {:?}", id, e))?;

            // decode gradually instead of all at once (which is not practical)
            let is_fully_decoded = self
                .decoder
                .decode_shred(&mut self.storage, msg.block_id, id, coded_piece)
                .map_err(|e| format!("Failed to decode shred {}: {}", id, e))?;

            if is_fully_decoded {
                // store decoded shred
                let raw_data = self
                    .decoder
                    .get_raw_from_decoded_shred(&self.storage, msg.block_id, id)
                    .map_err(|e| {
                        format!("Failed to get raw data from decoded shred {}: {}", id, e)
                    })?;
                self.storage.store_shred(msg.block_id, id, raw_data);
            }
        }
        Ok(())
    }

    // NOTE: this will be true if node is publisher or decoded all data
    pub fn is_active_node(&self, block_id: BlockId) -> bool {
        // Check if we have decoded all shreds for this block
        let decoded_shreds = self.storage.list_shreds(block_id);
        let non_empty_count = decoded_shreds
            .iter()
            .filter(|(_, data)| !data.is_empty())
            .count();
        non_empty_count == self.num_shreds
    }

    // TODO: request da message from neighbor nodes
    pub fn request_da_message(
        &self,
        _block_id: BlockId,
        _shred_ids: Vec<ShredId>,
    ) -> Result<Vec<RetrieveShredMsg<Vec<RistrettoPoint>>>, String> {
        Ok(Vec::new())
    }

    /// TODO: handle received DA message.
    pub fn receive_da_message(
        &mut self,
        _msgs: Vec<RetrieveShredMsg<Vec<RistrettoPoint>>>,
    ) -> Result<(), String> {
        Ok(())
    }

    /// TODO: this function will reconstruct the block from its peers.
    pub fn reconstruct_block(&self, block_id: BlockId) {}
}

#[cfg(test)]
mod tests {
    use crate::utils::blocks::create_random_block;

    use super::*;
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use thiserror::Error;

    // Mock Committer để mô phỏng
    #[derive(Error, Debug)]
    struct MockError(String);

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    #[derive(Clone)]
    struct MockCommitter;

    impl Committer for MockCommitter {
        type Scalar = Scalar;
        type Commitment = Vec<RistrettoPoint>;
        type Error = MockError;

        fn commit(&self, chunks: &Vec<Vec<Scalar>>) -> Result<Self::Commitment, Self::Error> {
            let mut commitment = vec![];
            // Use a fixed scalar to generate deterministic RistrettoPoint
            for i in 0..chunks.len() {
                // Derive a unique scalar for each chunk using index
                let scalar = Scalar::from((i as u64) + 1);
                let point = RistrettoPoint::mul_base(&scalar);
                commitment.push(point);
            }
            Ok(commitment)
        }

        fn verify(
            &self,
            _commitment: Option<&Self::Commitment>,
            _piece: &CodedPiece<Scalar>,
        ) -> bool {
            true
        }
    }

    #[test]
    fn test_node_new() {
        let committer = MockCommitter;
        let node = Node::new(1, &committer, vec![2, 3], 4, 16, 1);
        assert_eq!(node.id, 1);
        assert_eq!(node.neighbors, vec![2, 3]);
        assert_eq!(node.num_shreds, 4);
        assert_eq!(node.num_chunks_per_shred, 16);
        assert_eq!(node.custody_size, 1);
        assert!(node.active_block.is_none());
    }

    #[test]
    fn test_new_source_no_rs() {
        let committer = MockCommitter;
        let mut node = Node::new(1, &committer, vec![2], 4, 16, 1);
        let block_id = 1;
        let data = create_random_block(2048); // 2KB, chia hết cho 4
        let result = node.new_source(block_id, data.clone(), false, 512);
        assert!(result.is_ok());
        assert_eq!(node.active_block, Some(block_id));
        assert_eq!(node.num_shreds, 4);

        // Kiểm tra storage
        for sid in 0..4 {
            assert!(node.storage.get_shred(block_id, sid).is_some());
            assert!(node.storage.get_commitment(block_id, sid).is_some());
        }
    }

    #[test]
    fn test_new_source_no_rs_invalid_size() {
        let committer = MockCommitter;
        let mut node = Node::new(1, &committer, vec![2], 4, 16, 1);
        let block_id = 1;
        let data = create_random_block(1000); // Không chia hết cho 4
        let result = node.new_source(block_id, data, false, 512);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not divisible"));
    }

    #[test]
    fn test_new_source_with_rs() {
        const SHARE_SIZE: usize = 512;
        const BLOCK_SIZE: usize = 2 * 1024 * 1024; // 2MB
        let k = ((BLOCK_SIZE / SHARE_SIZE) as f64).sqrt().ceil() as usize; // k=64
        let committer = MockCommitter;
        let mut node = Node::new(1, &committer, vec![2], 4, 16, 1);
        let block_id = 1;
        let data = create_random_block(BLOCK_SIZE);
        let result = node.new_source(block_id, data.clone(), true, 512);
        assert!(result.is_ok());
        assert_eq!(node.active_block, Some(block_id));
        assert_eq!(node.num_shreds, k); // num_shreds = k = 64

        // // Kiểm tra storage
        for sid in 0..k {
            let shred = node.storage.get_shred(block_id, sid).unwrap();
            assert_eq!(shred.len(), (4 * k * k * SHARE_SIZE) / k); // 4k^2 shares chia thành k shred
            assert!(node.storage.get_commitment(block_id, sid).is_some());
        }
    }

    #[test]
    fn test_send_receive_reconstruct_no_rs() {
        let committer = MockCommitter;
        let block_id = 1;
        let num_shreds = 2;
        let num_chunks = 4;
        let data = create_random_block(512);
        println!("Block data len: {}", data.len());

        let mut source = Node::new(1, &committer, vec![2], num_shreds, num_chunks, 1);
        assert!(source
            .new_source(block_id, data.clone(), false, 512)
            .is_ok());

        let mut receiver = Node::new(2, &committer, vec![1], num_shreds, num_chunks, 1);

        assert!(!receiver.is_active_node(block_id));
        // Send and receive unique messages multiple times to ensure 4+ independent pieces
        for i in 0..num_chunks {
            let messages = source.publish(block_id, 1).unwrap();
            let message = messages[0].1.clone();

            let result = receiver.subcribe(message);
            if let Err(e) = result {
                panic!("receive_messages FAILED at iteration {}: {}", i, e);
            }
        }

        // node should have all shreds decoded
        assert!(receiver.is_active_node(block_id));
    }

    #[test]
    fn test_send_receive_reconstruct_with_rs_poc() {
        const SHARE_SIZE: usize = 64; // nhỏ hơn 512
        const BLOCK_SIZE: usize = 4 * 64 * SHARE_SIZE; // k=4 (vì sqrt( (BLOCK_SIZE / SHARE_SIZE) ) = 4)
        let k = ((BLOCK_SIZE / SHARE_SIZE) as f64).sqrt().ceil() as usize; // k=4
        let committer = MockCommitter;
        let block_id = 1;
        let num_chunks = 4; // nhỏ hơn 16
        let data = create_random_block(BLOCK_SIZE);

        let mut source = Node::new(1, &committer, vec![2], k, num_chunks, 1);
        assert!(source
            .new_source(block_id, data.clone(), true, SHARE_SIZE)
            .is_ok());

        let mut receiver = Node::new(2, &committer, vec![1], k, num_chunks, 1);

        for (_, _) in (0..num_chunks).enumerate() {
            let messages = source.publish(block_id, 1).unwrap();
            assert_eq!(messages.len(), 1);
            let message = messages[0].1.clone();
            assert!(receiver.subcribe(message).is_ok());
        }
        assert!(receiver.is_active_node(block_id));
    }

    #[test]
    fn test_send_receive_reconstruct_with_rs_poc_equals_original() {
        const SHARE_SIZE: usize = 64;
        // Chọn k=4 ⇒ BLOCK_SIZE = k*k*SHARE_SIZE
        const K: usize = 4;
        const BLOCK_SIZE: usize = K * K * SHARE_SIZE;
        let k = K;
        let committer = MockCommitter;
        let block_id = 1;
        let num_chunks = 4; // cần >= rank để decode một shred
        let data = create_random_block(BLOCK_SIZE); // không cần pad

        let mut source = Node::new(1, &committer, vec![2], k, num_chunks, 1);
        assert!(source
            .new_source(block_id, data.clone(), true, SHARE_SIZE)
            .is_ok());

        let mut receiver = Node::new(2, &committer, vec![1], k, num_chunks, 1);

        for _ in 0..num_chunks {
            let messages = source.publish(block_id, 1).unwrap();
            let message = messages[0].1.clone();
            assert!(receiver.subcribe(message).is_ok());
        }

        assert!(receiver.is_active_node(block_id));

        // Kiểm tra dữ liệu đã được phục hồi đúng
        let decoded_shred = receiver.storage.list_shreds(block_id);
        // check whether it is equal the original data
        let mut reconstructed_data: Vec<u8> = Vec::new();
        for (_, shred_data) in decoded_shred {
            reconstructed_data.extend(shred_data.to_vec());
        }

        let original_matrix = FlatMatrix::new(&data, SHARE_SIZE, k);
        let extended_matrix = extended_data_share(&original_matrix, k);
        assert_eq!(reconstructed_data, *extended_matrix.data());
    }
}
