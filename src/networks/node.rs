// node.rs
use crate::commitments::{CodedPiece, Committer};
use crate::networks::storage::decoder::StorageDecoder;
use crate::networks::storage::encoder::StorageEncoder;
use crate::networks::storage::recoder::StorageRecoder;
use super::storage::core::{BlockId, InMemoryStorage, NodeStorage, PieceIdx, ShredId};
use crate::utils::eds::{extended_data_share, FlatMatrix};

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
        bandwidth_limit: usize,
        num_shreds: usize,
        num_chunks_per_shred: usize,
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
            bandwidth_limit,
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

            // Pad data to match k * k * share_size
            let padded_size = k * k * share_size;
            let mut padded = data.clone();
            if padded.len() < padded_size {
                padded.resize(padded_size, 0u8);
            } else if padded.len() > padded_size {
                return Err(format!(
                    "Data size {} exceeds maximum block size {} (k={} x k={} x share_size={})",
                    data.len(),
                    padded_size,
                    k,
                    k,
                    share_size
                ));
            }

            // Extend data with 2D matrix
            extended = Self::extend_2d_matrix(&padded, share_size, k)?;

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
        println!("Extended block len: {:?}", extended.len());
        let shred_size = (extended.len() as f64 / num_shreds as f64).ceil() as usize;
        for sid in 0..num_shreds {
            let start = sid * shred_size;
            let end = std::cmp::min(start + shred_size, extended.len());
            let shred_bytes = extended[start..end].to_vec();
            self.storage.store_shred(block_id, sid, shred_bytes.clone());
            println!("Store shred id {:?}, value: {:?}", sid, &shred_bytes[..8]);
        }

        // Activate block and initialize encoder
        self.active_block = Some(block_id);
        self.encoder = StorageEncoder::new(block_id, num_shreds, self.num_chunks_per_shred);

        // Process each shred: compute commitment and create coded pieces
        for sid in 0..num_shreds {
            // Compute and store commitment
            let commitment = self
                .encoder
                .get_shred_commitment::<C, _>(&self.storage, self.committer, sid)
                .map_err(|e| format!("Commit failed for shred {}: {}", sid, e))?;
            self.storage
                .store_commitment(block_id, sid, commitment.clone());

            // Create initial coded pieces
            let initial_pieces = self.num_chunks_per_shred + 2;
            for idx in 0..initial_pieces {
                let piece = self
                    .encoder
                    .encode_one_shred::<C, _>(&self.storage, self.committer, sid)
                    .map_err(|e| format!("Encode failed shred {}: {}", sid, e))?;
                let piece_idx = idx;
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

        // Gather candidate pieces: distribute across all shreds
        let mut candidates: Vec<Message<Vec<RistrettoPoint>>> = Vec::new();
        let pieces_per_shred = (self.bandwidth_limit + self.num_shreds - 1) / self.num_shreds; // Ceiling division
        for sid in 0..self.num_shreds {
            let indices = self.storage.list_piece_indices(block_id, sid);
            let mut count = 0;
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
                        count += 1;
                        if count >= pieces_per_shred || candidates.len() >= self.bandwidth_limit {
                            break;
                        }
                    }
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

            // Store the commitment
            self.storage
                .store_commitment(msg.block_id, msg.shred_id, commitment.clone());

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
                                decoded_bytes.clone(),
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
    /// If RS was used, we assume successful decode of all shreds implies block can be reconstructed by concatenation.
    pub fn try_reconstruct_block(&self, block_id: BlockId, _use_rs: bool) -> Option<Vec<u8>> {
        // Kiểm tra xem tất cả shred có được giải mã không
        let decoded_shreds = self.storage.list_decoded_shreds(block_id);
        println!("decoded shreds {:?}", decoded_shreds);
        if decoded_shreds.len() < self.num_shreds {
            return None; // Thiếu shred, không thể tái tạo
        }

        // Ghép tất cả shred đã giải mã theo thứ tự
        let mut out = Vec::new();
        for sid in 0..self.num_shreds {
            if let Some(bytes) = self.storage.get_decoded_shred(block_id, sid) {
                out.extend_from_slice(bytes);
            } else {
                return None; // Thiếu một shred, thất bại
            }
        }

        // Không cần logic RS decode phức tạp, chỉ ghép là đủ
        // Nếu use_rs = true, ta giả định các shred đã decode đúng (đã verify ở receive_messages)
        Some(out)
    }
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
        let node = Node::new(1, &committer, vec![2, 3], 10, 4, 16);
        assert_eq!(node.id, 1);
        assert_eq!(node.neighbors, vec![2, 3]);
        assert_eq!(node.bandwidth_limit, 10);
        assert_eq!(node.num_shreds, 4);
        assert_eq!(node.num_chunks_per_shred, 16);
        assert!(node.active_block.is_none());
        assert!(node.storage.list_decoded_shreds(0).is_empty());
    }

    #[test]
    fn test_new_source_no_rs() {
        let committer = MockCommitter;
        let mut node = Node::new(1, &committer, vec![2], 10, 4, 16);
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
            let indices = node.storage.list_piece_indices(block_id, sid);
            assert_eq!(indices.len(), 18); // num_chunks_per_shred + 2 = 16 + 2
        }
    }

    #[test]
    fn test_new_source_no_rs_invalid_size() {
        let committer = MockCommitter;
        let mut node = Node::new(1, &committer, vec![2], 10, 4, 16);
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
        let mut node = Node::new(1, &committer, vec![2], 10, 4, 16);
        let block_id = 1;
        let data = create_random_block(BLOCK_SIZE);
        let result = node.new_source(block_id, data.clone(), true, 512);
        assert!(result.is_ok());
        assert_eq!(node.active_block, Some(block_id));
        assert_eq!(node.num_shreds, k); // num_shreds = k = 64

        // Kiểm tra storage
        for sid in 0..k {
            let shred = node.storage.get_shred(block_id, sid).unwrap();
            assert_eq!(shred.len(), (4 * k * k * SHARE_SIZE) / k); // 4k^2 shares chia thành k shred
            assert!(node.storage.get_commitment(block_id, sid).is_some());
            let indices = node.storage.list_piece_indices(block_id, sid);
            assert_eq!(indices.len(), 18); // num_chunks_per_shred + 2
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

        let mut source = Node::new(
            1,
            &committer,
            vec![2],
            num_shreds * (num_chunks + 2),
            num_shreds,
            num_chunks,
        );
        assert!(source
            .new_source(block_id, data.clone(), false, 512)
            .is_ok());

        let mut receiver = Node::new(
            2,
            &committer,
            vec![1],
            num_shreds * (num_chunks + 2),
            num_shreds,
            num_chunks,
        );

        // Send and receive unique messages multiple times to ensure 4+ independent pieces
        for i in 0..num_shreds {
            let messages = source.send(block_id, 1);
            assert_eq!(messages.len(), 1);
            let (_, sent_msgs) = messages[0].clone();
            assert!(!sent_msgs.is_empty(), "No messages sent at iteration {}", i);
            println!("Iteration {}: Sent {} messages", i, sent_msgs.len());
            for msg in &sent_msgs {
                println!(
                    "Message: block_id={}, shred_id={}, piece_idx={}",
                    msg.block_id, msg.shred_id, msg.piece_idx
                );
            }

            let result = receiver.receive_messages(sent_msgs);
            if let Err(e) = result {
                panic!("receive_messages FAILED at iteration {}: {}", i, e);
            }

            // Generate new independent pieces by recoding for each shred
            for sid in 0..num_shreds {
                let indices = source.storage.list_piece_indices(block_id, sid);
                if indices.len() >= 2 {
                    let new_piece = source
                        .recoder
                        .recode(&source.storage, block_id, sid, &indices)
                        .expect("Recode failed");
                    let mut next_idx = indices.iter().max().unwrap_or(&0) + 1;
                    while source
                        .storage
                        .get_coded_piece(block_id, sid, next_idx)
                        .is_some()
                    {
                        next_idx += 1;
                    }
                    source
                        .storage
                        .store_coded_piece(block_id, sid, next_idx, new_piece);
                }
            }
        }

        // Debug: Check number of pieces and decoded shreds
        for sid in 0..num_shreds {
            let indices = receiver.storage.list_piece_indices(block_id, sid);
            println!("Shred {} has {} pieces", sid, indices.len());
            assert!(
                indices.len() >= num_chunks,
                "Not enough pieces for shred {}: {}",
                sid,
                indices.len()
            );
            if receiver.storage.get_decoded_shred(block_id, sid).is_some() {
                println!("Shred {} decoded successfully", sid);
            } else {
                println!("Shred {} not decoded", sid);
            }
        }

        let reconstructed = receiver.try_reconstruct_block(block_id, false);
        if reconstructed.is_none() {
            println!("Reconstruction failed: no block returned");
        } else {
            let reconstructed_data = reconstructed.clone().unwrap();
            println!("Reconstructed block len: {}", reconstructed_data.len());
            // Print differences if assertion fails
            if reconstructed_data != data {
                for i in 0..data.len() {
                    if reconstructed_data[i] != data[i] {
                        println!(
                            "Difference at index {}: reconstructed = {}, original = {}",
                            i, reconstructed_data[i], data[i]
                        );
                    }
                }
            }
        }
        assert!(reconstructed.is_some(), "Reconstruction failed");
        assert_eq!(
            reconstructed.unwrap(),
            data,
            "Reconstructed block does not match original"
        );
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

        // đủ để gửi tất cả pieces của tất cả shreds
        let bw = k * (num_chunks + 2);

        let mut source = Node::new(1, &committer, vec![2], bw, k, num_chunks);
        assert!(source
            .new_source(block_id, data.clone(), true, SHARE_SIZE)
            .is_ok());

        let mut receiver = Node::new(2, &committer, vec![1], bw, k, num_chunks);

        // gửi 1 lần là đủ
        let messages = source.send(block_id, 1);
        assert_eq!(messages.len(), 1);
        let (_, sent_msgs) = messages[0].clone();
        assert!(!sent_msgs.is_empty());

        assert!(receiver.receive_messages(sent_msgs).is_ok());

        // reconstruct block mở rộng (4*k^2*share_size)
        let reconstructed = receiver.try_reconstruct_block(block_id, true);
        assert!(reconstructed.is_some());
        assert_eq!(reconstructed.unwrap().len(), 4 * k * k * SHARE_SIZE);
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

        // đủ băng thông để gửi (num_chunks+2) pieces cho MỖI shred trong 1 lần
        let bw = k * (num_chunks + 2);

        let mut source = Node::new(1, &committer, vec![2], bw, k, num_chunks);
        assert!(source
            .new_source(block_id, data.clone(), true, SHARE_SIZE)
            .is_ok());

        let mut receiver = Node::new(2, &committer, vec![1], bw, k, num_chunks);

        // Gửi 1 lần là đủ
        let messages = source.send(block_id, 1);
        assert_eq!(messages.len(), 1);
        let (_, sent_msgs) = messages[0].clone();
        assert!(!sent_msgs.is_empty());

        assert!(receiver.receive_messages(sent_msgs).is_ok());

        // Reconstruct ra ma trận mở rộng 2k×2k
        let reconstructed_ext = receiver
            .try_reconstruct_block(block_id, true)
            .expect("should reconstruct extended block");
        assert_eq!(reconstructed_ext.len(), 4 * k * k * SHARE_SIZE);

        // === Thu gọn 2k×2k -> k×k để so với dữ liệu gốc ===
        // reconstructed_ext là row-major theo shares: tổng 2k * 2k shares, mỗi share SHARE_SIZE bytes
        // Mỗi hàng có 2k shares ⇒ 2k * SHARE_SIZE bytes
        let row_bytes = 2 * k * SHARE_SIZE;

        let mut recovered_original = Vec::with_capacity(k * k * SHARE_SIZE);
        for r in 0..k {
            // offset đầu hàng r trong extended
            let row_start = r * row_bytes;
            // lấy k shares đầu tiên của hàng này (bỏ k shares parity cột)
            let take_len = k * SHARE_SIZE;
            recovered_original
                .extend_from_slice(&reconstructed_ext[row_start..row_start + take_len]);
        }

        // So sánh với data gốc
        assert_eq!(recovered_original.len(), BLOCK_SIZE);
        assert_eq!(recovered_original, data, "Recovered original != input data");

        println!("{:?}", data);
        println!("{:?}", recovered_original);
    }
}
