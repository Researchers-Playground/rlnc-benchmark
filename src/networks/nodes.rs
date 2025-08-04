use crate::{
    commitments::ristretto::pedersen::PedersenCommitter,
    utils::rlnc::{CodedPacket, NetworkDecoder, NetworkEncoder, NetworkRecoder, RLNCError},
};
use curve25519_dalek::{traits::MultiscalarMul, RistrettoPoint, Scalar};
use rand::Rng;

#[derive(Clone, Debug)]
pub struct Message {
    chunk: CodedPacket,
    commitments: Vec<RistrettoPoint>,
}

pub struct Node<'a> {
    encoder: NetworkEncoder<'a>,
    decoder: NetworkDecoder<'a>,
    recoder: NetworkRecoder,
    committer: &'a PedersenCommitter,
    neighbors: Vec<usize>,
}

#[derive(Debug)]
pub enum ReceiveError {
    ExistingCommitmentsMismatch(String),
    ExistingChunksMismatch(String),
    InvalidMessage(String),
    LinearlyDependentChunk,
    NetworkError(String),
}

impl Message {
    pub fn new(chunk: CodedPacket, commitments: Vec<RistrettoPoint>) -> Self {
        Message { chunk, commitments }
    }

    fn coefficients_to_scalars(&self) -> Vec<Scalar> {
        self.chunk.coefficients.clone()
    }

    pub fn verify(&self, committer: &PedersenCommitter) -> Result<(), String> {
        let msm =
            RistrettoPoint::multiscalar_mul(&self.coefficients_to_scalars(), &self.commitments);

        let commitment = committer.commit(&self.chunk.data)?;
        if msm != commitment {
            return Err("The commitment does not match".to_string());
        }
        Ok(())
    }
}

impl<'a> Node<'a> {
    pub fn new(committer: &'a PedersenCommitter, num_chunks: usize) -> Self {
        let encoder = NetworkEncoder::new(committer, None, num_chunks).unwrap();
        let decoder = NetworkDecoder::new(committer, num_chunks);
        let recoder = NetworkRecoder::new(Vec::new(), num_chunks);
        Node {
            encoder,
            decoder,
            recoder,
            committer,
            neighbors: Vec::new(),
        }
    }

    pub fn new_source(
        committer: &'a PedersenCommitter,
        block: &[u8],
        num_chunks: usize,
    ) -> Result<Self, String> {
        let encoder = NetworkEncoder::new(committer, Some(block.to_vec()), num_chunks)?;
        let decoder = NetworkDecoder::new(committer, num_chunks);
        let recoder = NetworkRecoder::new(Vec::new(), num_chunks);
        Ok(Node {
            encoder,
            decoder,
            recoder,
            committer,
            neighbors: Vec::new(),
        })
    }

    fn check_existing_commitments(&self, commitments: &[RistrettoPoint]) -> Result<(), String> {
        self.decoder.check_commitments(commitments)?;
        Ok(())
    }

    fn check_existing_chunks(&self, chunk: &CodedPacket) -> Result<(), String> {
        self.decoder.check_chunks(chunk)?;
        Ok(())
    }

    pub fn receive(&mut self, message: Message) -> Result<(), ReceiveError> {
        self.check_existing_commitments(&message.commitments)
            .map_err(ReceiveError::ExistingCommitmentsMismatch)?;
        self.check_existing_chunks(&message.chunk)
            .map_err(ReceiveError::ExistingChunksMismatch)?;

        message
            .verify(self.committer)
            .map_err(ReceiveError::InvalidMessage)?;

        let coded_packet = CodedPacket {
            data: message.chunk.data,
            coefficients: message.chunk.coefficients,
        };
        self.decoder
            .decode(&coded_packet, &message.commitments)
            .map_err(|e| match e {
                RLNCError::PieceNotUseful => ReceiveError::LinearlyDependentChunk,
                RLNCError::InvalidData(msg) => ReceiveError::InvalidMessage(msg),
                _ => ReceiveError::NetworkError("Decoding failed".to_string()),
            })?;

        if self.decoder.is_already_decoded() {
            if let Ok(decoded_data) = self.decode() {
                self.encoder
                    .update_chunks(decoded_data, self.decoder.get_piece_count_val())
                    .unwrap();
            }
        }
        Ok(())
    }

    pub fn send(&self) -> Result<Message, String> {
        let coded_packet = self.encoder.encode()?;
        let commitments = self.encoder.get_commitments()?;
        let chunk = CodedPacket {
            data: coded_packet.data,
            coefficients: coded_packet.coefficients,
        };
        let message = Message::new(chunk, commitments);
        message.verify(self.committer)?;
        Ok(message)
    }

    pub fn recode(&mut self, received_packets: Vec<CodedPacket>) -> Result<Message, String> {
        self.recoder.update_packets(received_packets)?;

        let coded_packet = self.recoder.recode();
        let chunk = CodedPacket {
            data: coded_packet.data,
            coefficients: coded_packet.coefficients,
        };
        let commitments = self
            .decoder
            .get_commitments()
            .clone()
            .unwrap_or_else(Vec::new);
        let message = Message::new(chunk, commitments);
        message.verify(self.committer)?;
        Ok(message)
    }

    pub fn decode(&self) -> Result<Vec<u8>, String> {
        self.decoder.get_decoded_data().map_err(|e| match e {
            RLNCError::DecodingNotComplete => "Decoding not complete".to_string(),
            RLNCError::InvalidData(msg) => msg,
            _ => "Decoding failed".to_string(),
        })
    }

    pub fn add_neighbor(&mut self, neighbor: usize) {
        if !self.neighbors.contains(&neighbor) {
            self.neighbors.push(neighbor);
        }
    }

    pub fn simulate_network(
        &mut self,
        packet_loss_rate: f32,
        neighbors: &mut [&mut Node],
        self_id: usize,
    ) -> Result<(), ReceiveError> {
        let mut rng = rand::rng();
        for &neighbor_id in &self.neighbors {
            if let Ok(message) = self.send() {
                if rng.random::<f32>() >= packet_loss_rate {
                    println!("Sent to neighbor {}", neighbor_id);
                    for neighbor in neighbors.iter_mut() {
                        if neighbor.neighbors.contains(&self_id) {
                            neighbor
                                .receive(message.clone())
                                .unwrap_or_else(|e| println!("Failed to receive: {:?}", e));
                            break;
                        }
                    }
                } else {
                    return Err(ReceiveError::NetworkError("Packet lost".to_string()));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ristretto::random_u8_slice;

    #[test]
    fn test_new_node() {
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size);
        let node = Node::new(&committer, num_chunks);
        assert_eq!(node.decoder.get_piece_count(), num_chunks);
        assert!(node.encoder.get_chunks().is_empty());
        assert_eq!(node.recoder.get_piece_count(), num_chunks);
    }

    #[test]
    fn test_new_source_node() {
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size);
        let block = random_u8_slice(num_chunks * chunk_size * 32);
        let source_node = Node::new_source(&committer, &block, num_chunks).unwrap();
        assert_eq!(source_node.decoder.get_piece_count(), num_chunks);
        assert!(!source_node.encoder.get_chunks().is_empty());
    }

    #[test]
    fn test_send_receive() {
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size);
        let block: Vec<u8> = (0..num_chunks * chunk_size * 32)
            .map(|_| rand::random::<u8>())
            .collect();
        let source_node = Node::new_source(&committer, &block, num_chunks).unwrap();
        let mut dest_node = Node::new(&committer, num_chunks);
        let message = source_node.send().unwrap();
        dest_node.receive(message).unwrap();
        assert_eq!(dest_node.decoder.get_useful_piece_count(), 1);
    }

    #[test]
    fn test_decode_and_update() {
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size + 1);
        let block = random_u8_slice(num_chunks * chunk_size * 32);
        let source_node = Node::new_source(&committer, &block, num_chunks).unwrap();
        let mut dest_node = Node::new(&committer, num_chunks);
        for _ in 0..num_chunks {
            let message = source_node.send().unwrap();
            dest_node.receive(message).unwrap();
        }
        let decoded = dest_node.decode().unwrap();
        assert_eq!(decoded.len(), block.len());
        assert_eq!(decoded, block);
        assert!(!dest_node.encoder.get_chunks().is_empty());
    }

    #[test]
    fn test_recode() {
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size);
        let block = random_u8_slice(num_chunks * chunk_size * 32);
        let source_node = Node::new_source(&committer, &block, num_chunks).unwrap();
        let mut dest_node = Node::new(&committer, num_chunks);

        let initial_message = source_node.send().unwrap();
        dest_node.receive(initial_message).unwrap();

        let mut packets = Vec::new();
        for _ in 0..num_chunks {
            let message = source_node.send().unwrap();
            packets.push(CodedPacket {
                data: message.chunk.data,
                coefficients: message.chunk.coefficients,
            });
        }

        let recoded_message = dest_node.recode(packets).unwrap();
        assert!(recoded_message.verify(&committer).is_ok());
    }

    #[test]
    fn test_simulate_network() {
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size);
        let block = random_u8_slice(num_chunks * chunk_size * 32);
        let mut source_node = Node::new_source(&committer, &block, num_chunks).unwrap();
        let mut dest_node = Node::new(&committer, num_chunks);
        source_node.add_neighbor(1); // ID 1 cho dest_node
        dest_node.add_neighbor(0); // ID 0 cho source_node
        let mut neighbors = vec![&mut dest_node]; // Truyền dest_node làm neighbor
        source_node
            .simulate_network(0.0, &mut neighbors[..], 0)
            .unwrap();
        assert!(dest_node.decoder.get_useful_piece_count() > 0);
    }
}
