use rand::Rng;
use crate::{
    commitments::Committer,
    erase_code_methods::{network_coding::RLNCErasureCoder, reed_solomon::RSErasureCoder, CodedData, ErasureCoderType, ErasureError}, utils::rlnc::RLNCError,
};
use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint};

type CodedShred = CodedData;

pub struct Node<'a, C: Committer<Scalar = Scalar, Commitment = Vec<RistrettoPoint>>> {
    pub id: usize,
    pub erasure_coder: ErasureCoderType<'a, C>,
    pub committer: &'a C,
    pub neighbors: Vec<usize>,
    pub coded_block: Vec<CodedShred>, 
    pub bandwidth_limit: usize, 
}

impl<'a, C: Committer<Scalar = Scalar, Commitment = Vec<RistrettoPoint>>> Node<'a, C> {
    pub fn new(id: usize, committer: &'a C, erasure_coder: ErasureCoderType<'a, C>, neighbors: Vec<usize>, bandwidth_limit: usize) -> Self {
        Node {
            id,
            erasure_coder,
            committer,
            neighbors,
            coded_block: Vec::new(),
            bandwidth_limit,
        }
    }

    pub fn new_source(
        id: usize,
        committer: &'a C,
        data: Vec<u8>,
        num_chunks: usize,
        use_rlnc: bool,
        bandwidth_limit: usize,
    ) -> Result<Self, ErasureError> {
        let erasure_coder = if use_rlnc {
            ErasureCoderType::RLNC(RLNCErasureCoder::new(committer, Some(data), num_chunks)
                .map_err(ErasureError::RLNC)?)
        } else {
            ErasureCoderType::RS(RSErasureCoder::new(data, num_chunks, num_chunks / 2, 512)
                .map_err(ErasureError::RS)?)
        };
        let mut coded_block = Vec::new();
        // Giả sử cần 62 shred (2MB / 512 bytes)
        for _ in 0..(2 * 1024 * 1024 / 512) {
            let coded_shred = erasure_coder.encode()?;
            coded_block.push(coded_shred);
        }
        Ok(Node {
            id,
            erasure_coder,
            committer,
            neighbors: Vec::new(),
            coded_block,
            bandwidth_limit,
        })
    }

    pub fn send(&self) -> Result<Vec<(usize, Vec<CodedShred>)>, ErasureError> {
        let mut messages = Vec::new();
        let rng = rand::rng();

        let available_shreds: Vec<_> = self.coded_block.iter().collect();
        let num_to_send = self.bandwidth_limit.min(available_shreds.len());
        let selected_shreds: Vec<CodedShred> = available_shreds
            .into_iter()
            .take(num_to_send)
            .cloned()
            .collect();

        for &neighbor_id in &self.neighbors {
            messages.push((neighbor_id, selected_shreds.clone()));
        }

        Ok(messages)
    }

    pub fn receive(&mut self, coded_shreds: Vec<CodedShred>) -> Result<(), ErasureError> {
        for shred in coded_shreds {
            // Tạm thời bỏ qua verify commitment vì placeholder
            // Nếu cần verify, thêm commitment vào Vec<CodedShred> và gọi verify
            self.erasure_coder.decode(&shred)?;
            self.coded_block.push(shred);
        }
        Ok(())
    }

    pub fn sample(&self) -> Result<&CodedShred, ErasureError> {
        let mut rng = rand::rng();
        if self.coded_block.is_empty() {
            return Err(ErasureError::RLNC(RLNCError::InvalidPiece("No coded shreds available for sampling".to_string())));
        }
        let index = rng.random_range(0..self.coded_block.len());
        Ok(&self.coded_block[index])
    }

    pub fn reconstruct_block(&mut self, neighbors: &mut [&mut Node<C>]) -> Result<Vec<u8>, ErasureError> {
        while !self.erasure_coder.is_decoded() {
            for neighbor in neighbors.iter_mut() {
                if self.neighbors.contains(&neighbor.id) {
                    let coded_shreds = neighbor.coded_block.clone();
                    self.receive(coded_shreds)?;
                }
            }
        }
        self.erasure_coder.get_decoded_data()
    }
}