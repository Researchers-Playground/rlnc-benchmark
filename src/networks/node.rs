use crate::{
    commitments::Committer,
    erase_code_methods::{
        network_coding::{NetworkCodingError, RLNCErasureCoder},
        reed_solomon::RSErasureCoder,
        CodedData, ErasureCoderType, ErasureError,
    },
    networks::ErasureCoder,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::Rng;

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
    pub fn new(
        id: usize,
        committer: &'a C,
        erasure_coder: ErasureCoderType<'a, C>,
        neighbors: Vec<usize>,
        bandwidth_limit: usize,
    ) -> Self {
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
        num_shreds: usize,
        use_rlnc: bool,
        bandwidth_limit: usize,
    ) -> Result<Self, ErasureError> {
        if data.len() % num_chunks != 0 {
            return Err(ErasureError::RLNC(NetworkCodingError::InvalidPiece(
                format!(
                    "Data length {} must be divisible by num_chunks {}",
                    data.len(),
                    num_chunks
                ),
            )));
        }
        let erasure_coder = if use_rlnc {
            ErasureCoderType::RLNC(
                RLNCErasureCoder::new(committer, Some(data), num_chunks)
                    .map_err(ErasureError::RLNC)?,
            )
        } else {
            ErasureCoderType::RS(
                RSErasureCoder::new(data, num_chunks, num_chunks / 4, 512)
                    .map_err(ErasureError::RS)?,
            )
        };
        let mut coded_block = Vec::new();
        for _ in 0..num_shreds {
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
        let _rng = rand::rng();

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

    pub fn receive(
        &mut self,
        coded_shreds: Vec<CodedShred>,
        commitment: Option<&Vec<RistrettoPoint>>,
    ) -> Result<(), ErasureError> {
        for shred in coded_shreds {
            match (&mut self.erasure_coder, &shred) {
                (ErasureCoderType::RLNC(coder), CodedData::RLNC(coded_piece)) => {
                    if let Some(commit) = commitment {
                        coder.decoder.decode(coded_piece, commit).map_err(|e| {
                            ErasureError::RLNC(NetworkCodingError::DecodingFailed(e.to_string()))
                        })?;
                    } else {
                        return Err(ErasureError::RLNC(NetworkCodingError::DecodingFailed(
                            "No commitment provided".to_string(),
                        )));
                    }
                }
                (ErasureCoderType::RS(coder), CodedData::RS(data)) => {
                    coder.decode(data).map_err(ErasureError::RS)?;
                }
                _ => {
                    return Err(ErasureError::RLNC(NetworkCodingError::InvalidPiece(
                        "Mismatched coder and shred type".to_string(),
                    )))
                }
            }
            self.coded_block.push(shred);
        }
        Ok(())
    }

    pub fn sample(&self) -> Result<&CodedShred, ErasureError> {
        let mut rng = rand::rng();
        if self.coded_block.is_empty() {
            return Err(ErasureError::RLNC(NetworkCodingError::InvalidPiece(
                "No coded shreds available for sampling".to_string(),
            )));
        }
        let index = rng.random_range(0..self.coded_block.len());
        Ok(&self.coded_block[index])
    }

    pub fn reconstruct_block(
        &mut self,
        neighbors: &mut [&mut Node<C>],
        commitment: Option<&Vec<RistrettoPoint>>,
    ) -> Result<Vec<u8>, ErasureError> {
        while !self.erasure_coder.is_decoded() {
            for neighbor in neighbors.iter_mut() {
                if self.neighbors.contains(&neighbor.id) {
                    let coded_shreds = neighbor.coded_block.clone();
                    self.receive(coded_shreds, commitment)?;
                }
            }
        }
        self.erasure_coder.get_decoded_data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitments::CodedPiece;

    #[derive(Debug, thiserror::Error)]
    pub enum MockCommitterError {
        #[error("Invalid chunk size: {0}")]
        InvalidChunkSize(String),
    }

    struct MockCommitter {
        num_chunks: usize,
    }

    impl MockCommitter {
        fn new(num_chunks: usize) -> Self {
            MockCommitter { num_chunks }
        }
    }

    impl Committer for MockCommitter {
        type Scalar = Scalar;
        type Commitment = Vec<RistrettoPoint>;
        type Error = MockCommitterError;

        fn commit(&self, data: &Vec<Vec<Self::Scalar>>) -> Result<Self::Commitment, Self::Error> {
            if data.is_empty() || data.len() != self.num_chunks {
                return Err(MockCommitterError::InvalidChunkSize(format!(
                    "Expected {} chunks, got {}",
                    self.num_chunks,
                    data.len()
                )));
            }
            Ok(vec![RistrettoPoint::default(); self.num_chunks])
        }

        fn verify(
            &self,
            commitment: Option<&Self::Commitment>,
            _piece: &CodedPiece<Self::Scalar>,
        ) -> bool {
            commitment.is_some()
        }
    }

    fn create_dummy_data(num_shreds: usize, chunk_size: usize) -> Vec<u8> {
        vec![1u8; num_shreds * chunk_size]
    }

    #[test]
    fn test_node_new() {
        let committer = MockCommitter::new(16);
        let erasure_coder = ErasureCoderType::RLNC(
            RLNCErasureCoder::new(&committer, None, 16).expect("Failed to create RLNC coder"),
        );
        let neighbors = vec![1, 2, 3];
        let bandwidth_limit = 5;

        let node = Node::new(
            0,
            &committer,
            erasure_coder,
            neighbors.clone(),
            bandwidth_limit,
        );

        assert_eq!(node.id, 0);
        assert_eq!(node.neighbors, neighbors);
        assert_eq!(node.bandwidth_limit, bandwidth_limit);
        assert!(node.coded_block.is_empty());
    }

    #[test]
    fn test_node_new_source_rlnc() {
        let committer = MockCommitter::new(16);
        let num_chunks = 16;
        let chunk_size = 512;
        let num_shreds = 16;
        let data = create_dummy_data(num_shreds, chunk_size);
        let bandwidth_limit = 5;

        let node = Node::new_source(
            0,
            &committer,
            data,
            num_chunks,
            num_shreds,
            true,
            bandwidth_limit,
        );
        assert!(
            node.is_ok(),
            "Failed to create source node: {:?}",
            node.err()
        );
        let node = node.unwrap();

        assert_eq!(node.id, 0);
        assert_eq!(node.neighbors, Vec::<usize>::new());
        assert_eq!(node.bandwidth_limit, bandwidth_limit);
        assert_eq!(
            node.coded_block.len(),
            num_shreds,
            "Expected {} shreds",
            num_shreds
        );
    }

    #[test]
    fn test_node_new_source_rs() {
        let committer = MockCommitter::new(16);
        let num_chunks = 16;
        let chunk_size = 512;
        let num_shreds = 16;
        let data = create_dummy_data(num_shreds, chunk_size);
        let bandwidth_limit = 5;

        let node = Node::new_source(
            0,
            &committer,
            data,
            num_chunks,
            num_shreds,
            false,
            bandwidth_limit,
        );
        assert!(
            node.is_ok(),
            "Failed to create source node: {:?}",
            node.err()
        );
        let node = node.unwrap();

        assert_eq!(node.id, 0);
        assert_eq!(node.neighbors, Vec::<usize>::new());
        assert_eq!(node.bandwidth_limit, bandwidth_limit);
        assert_eq!(
            node.coded_block.len(),
            num_shreds,
            "Expected {} shreds",
            num_shreds
        );
    }

    #[test]
    fn test_node_send() {
        let committer = MockCommitter::new(16);
        let num_chunks = 16;
        let chunk_size = 512;
        let num_shreds = 16;
        let data = create_dummy_data(num_shreds, chunk_size);
        let bandwidth_limit = 5;

        let node = Node::new_source(
            0,
            &committer,
            data,
            num_chunks,
            num_shreds,
            true,
            bandwidth_limit,
        )
        .expect("Failed to create source node");
        let neighbors = vec![1, 2];
        let node = Node { neighbors, ..node };

        let messages = node.send().expect("Failed to send");
        assert_eq!(messages.len(), 2, "Should send to 2 neighbors");
        for (neighbor_id, shreds) in messages {
            assert!(neighbor_id == 1 || neighbor_id == 2, "Invalid neighbor ID");
            assert_eq!(
                shreds.len(),
                bandwidth_limit,
                "Should send 5 shreds per neighbor"
            );
        }
    }

    #[test]
    fn test_node_receive() {
        let committer = MockCommitter::new(16);
        let num_chunks = 16;
        let chunk_size = 512;
        let num_shreds = 16;
        let data = create_dummy_data(num_shreds, chunk_size);

        let source_node = Node::new_source(0, &committer, data, num_chunks, num_shreds, true, 5)
            .expect("Failed to create source node");
        let erasure_coder = ErasureCoderType::RLNC(
            RLNCErasureCoder::new(&committer, None, num_chunks)
                .expect("Failed to create RLNC coder"),
        );
        let mut receiver_node = Node::new(1, &committer, erasure_coder, vec![0], 5);

        let shreds = source_node.coded_block[..5].to_vec();
        let commitment = match &source_node.erasure_coder {
            ErasureCoderType::RLNC(coder) => coder.encoder.get_commitment().ok(),
            _ => None,
        };
        let result = receiver_node.receive(shreds, commitment.as_ref());
        assert!(result.is_ok(), "Failed to receive: {:?}", result.err());
        assert_eq!(
            receiver_node.coded_block.len(),
            5,
            "Should have received 5 shreds"
        );
    }

    #[test]
    fn test_node_sample() {
        let committer = MockCommitter::new(16);
        let num_chunks = 16;
        let chunk_size = 512;
        let num_shreds = 16;
        let data = create_dummy_data(num_shreds, chunk_size);

        let node = Node::new_source(0, &committer, data, num_chunks, num_shreds, true, 5)
            .expect("Failed to create source node");
        let sample = node.sample();
        assert!(sample.is_ok(), "Failed to sample: {:?}", sample.err());

        let erasure_coder = ErasureCoderType::RLNC(
            RLNCErasureCoder::new(&committer, None, num_chunks)
                .expect("Failed to create RLNC coder"),
        );
        let empty_node = Node::new(1, &committer, erasure_coder, vec![], 5);
        let sample = empty_node.sample();
        assert!(
            matches!(
                sample,
                Err(ErasureError::RLNC(NetworkCodingError::InvalidPiece(_)))
            ),
            "Expected InvalidPiece error"
        );
    }

    #[test]
    fn test_node_reconstruct_block_rlnc() {
        let committer = MockCommitter::new(16);
        let num_chunks = 16;
        let chunk_size = 512;
        let num_shreds = 16;
        let data = create_dummy_data(num_shreds, chunk_size);

        let source_node =
            Node::new_source(0, &committer, data.clone(), num_chunks, num_shreds, true, 5)
                .expect("Failed to create source node");
        let commitment = match &source_node.erasure_coder {
            ErasureCoderType::RLNC(coder) => coder
                .encoder
                .get_commitment()
                .expect("Failed to get commitment"),
            _ => panic!("Expected RLNC coder"),
        };

        let erasure_coder = ErasureCoderType::RLNC(
            RLNCErasureCoder::new(&committer, None, num_chunks)
                .expect("Failed to create RLNC coder"),
        );
        let mut receiver_node = Node::new(1, &committer, erasure_coder, vec![0], 5);

        let erasure_coder_neighbor = ErasureCoderType::RLNC(
            RLNCErasureCoder::new(&committer, None, num_chunks)
                .expect("Failed to create RLNC coder"),
        );
        let mut neighbor_node = Node {
            id: source_node.id,
            erasure_coder: erasure_coder_neighbor,
            committer: source_node.committer,
            neighbors: source_node.neighbors.clone(),
            coded_block: source_node.coded_block.clone(),
            bandwidth_limit: source_node.bandwidth_limit,
        };
        let mut neighbors = vec![&mut neighbor_node];

        let reconstructed_data = receiver_node.reconstruct_block(&mut neighbors, Some(&commitment));
        assert!(
            reconstructed_data.is_ok(),
            "Failed to reconstruct block: {:?}",
            reconstructed_data.err()
        );

        let reconstructed_data = reconstructed_data.unwrap();
        assert_eq!(
            reconstructed_data.len(),
            data.len(),
            "Reconstructed data length mismatch"
        );
    }

    #[test]
    fn test_node_reconstruct_block_rs() {
        let committer = MockCommitter::new(16);
        let num_chunks = 16;
        let chunk_size = 512;
        let num_shreds = 16;
        let data = create_dummy_data(num_shreds, chunk_size);

        let source_node = Node::new_source(
            0,
            &committer,
            data.clone(),
            num_chunks,
            num_shreds,
            false,
            5,
        )
        .expect("Failed to create source node");

        let erasure_coder = ErasureCoderType::RS(
            RSErasureCoder::new(
                vec![0u8; num_shreds * chunk_size],
                num_chunks,
                num_chunks / 4,
                chunk_size,
            )
            .expect("Failed to create RS coder"),
        );
        let mut receiver_node = Node::new(1, &committer, erasure_coder, vec![0], 5);

        let erasure_coder_neighbor = ErasureCoderType::RS(
            RSErasureCoder::new(
                vec![0u8; num_shreds * chunk_size],
                num_chunks,
                num_chunks / 4,
                chunk_size,
            )
            .expect("Failed to create RS coder"),
        );
        let mut neighbor_node = Node {
            id: source_node.id,
            erasure_coder: erasure_coder_neighbor,
            committer: source_node.committer,
            neighbors: source_node.neighbors.clone(),
            coded_block: source_node.coded_block.clone(),
            bandwidth_limit: source_node.bandwidth_limit,
        };
        let mut neighbors = vec![&mut neighbor_node];

        let reconstructed_data = receiver_node.reconstruct_block(&mut neighbors, None);
        assert!(
            reconstructed_data.is_ok(),
            "Failed to reconstruct block: {:?}",
            reconstructed_data.err()
        );

        let reconstructed_data = reconstructed_data.unwrap();
        assert_eq!(
            reconstructed_data.len(),
            data.len(),
            "Reconstructed data length mismatch"
        );
    }
}
