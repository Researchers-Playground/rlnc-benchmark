use crate::{
    commitments::ristretto::pedersen::PedersenCommitter,
    utils::rlnc::{CodedPacket, NetworkDecoder, NetworkEncoder, NetworkRecoder, RLNCError},
};
use curve25519_dalek::{traits::MultiscalarMul, RistrettoPoint, Scalar};
use rand::Rng;

///! Note that: all variables is public for easily to benchmark

#[derive(Clone, Debug)]
pub struct Message {
    pub chunk: CodedPacket,
    pub commitments: Vec<RistrettoPoint>,
    pub source_id: usize,
}

pub struct Node<'a> {
    pub id: usize,
    pub encoder: NetworkEncoder<'a>,
    pub decoder: NetworkDecoder<'a>,
    pub recoder: NetworkRecoder,
    pub committer: &'a PedersenCommitter,
    pub neighbors: Vec<usize>,
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
    pub fn new(chunk: CodedPacket, commitments: Vec<RistrettoPoint>, source_id: usize) -> Self {
        Message {
            chunk,
            commitments,
            source_id,
        }
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

    pub fn get_source_id(&self) -> usize {
        self.source_id
    }
}

impl<'a> Node<'a> {
    pub fn new(id: usize, committer: &'a PedersenCommitter, num_chunks: usize) -> Self {
        let encoder = NetworkEncoder::new(committer, None, num_chunks).unwrap();
        let decoder = NetworkDecoder::new(committer, num_chunks);
        let recoder = NetworkRecoder::new(Vec::new(), num_chunks);
        Node {
            id,
            encoder,
            decoder,
            recoder,
            committer,
            neighbors: Vec::new(),
        }
    }

    pub fn new_source(
        id: usize,
        committer: &'a PedersenCommitter,
        block: &[u8],
        num_chunks: usize,
    ) -> Result<Self, String> {
        let encoder = NetworkEncoder::new(committer, Some(block.to_vec()), num_chunks)?;
        let decoder = NetworkDecoder::new(committer, num_chunks);
        let recoder = NetworkRecoder::new(Vec::new(), num_chunks);
        Ok(Node {
            id,
            encoder,
            decoder,
            recoder,
            committer,
            neighbors: Vec::new(),
        })
    }

    pub fn get_id(&self) -> usize {
        self.id
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
        let message = Message::new(chunk, commitments, self.id);
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
        let message = Message::new(chunk, commitments, self.id);
        message.verify(self.committer)?;
        Ok(message)
    }

    pub fn decode(&self) -> Result<Vec<u8>, String> {
        self.decoder.get_decoded_data().map_err(|e| match e {
            RLNCError::DecodingNotComplete => "Decoding not complete".to_string(),
            RLNCError::InvalidData(msg) => msg + "LOL",
            RLNCError::ReceivedAllPieces => "Received all pieces".to_string(),
            RLNCError::PieceNotUseful => "Piece not useful".to_string(),
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
                    println!("Node {} sent to neighbor {}", self.id, neighbor_id);
                    for neighbor in neighbors.iter_mut() {
                        if neighbor.get_id() == neighbor_id {
                            neighbor.receive(message.clone()).unwrap_or_else(|e| {
                                println!(
                                    "Node {} failed to receive from {}: {:?}",
                                    neighbor_id, self.id, e
                                )
                            });
                            break;
                        }
                    }
                } else {
                    println!("Packet from node {} to {} lost", self.id, neighbor_id);
                    return Err(ReceiveError::NetworkError(format!(
                        "Packet lost from node {} to {}",
                        self.id, neighbor_id
                    )));
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
        let node = Node::new(0, &committer, num_chunks);
        assert_eq!(node.decoder.get_piece_count(), num_chunks);
        assert!(node.encoder.get_chunks().is_empty());
        assert_eq!(node.recoder.get_piece_count(), num_chunks);
        assert_eq!(node.get_id(), 0);
    }

    #[test]
    fn test_new_source_node() {
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size);
        let block = random_u8_slice(num_chunks * chunk_size * 32);
        let source_node = Node::new_source(1, &committer, &block, num_chunks).unwrap();
        assert_eq!(source_node.decoder.get_piece_count(), num_chunks);
        assert!(!source_node.encoder.get_chunks().is_empty());
        assert_eq!(source_node.get_id(), 1);
    }

    #[test]
    fn test_send_receive() {
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size);
        let block = random_u8_slice(num_chunks * chunk_size * 32);
        let source_node = Node::new_source(1, &committer, &block, num_chunks).unwrap();
        let mut dest_node = Node::new(2, &committer, num_chunks);
        let message = source_node.send().unwrap();
        assert_eq!(message.get_source_id(), 1);
        dest_node.receive(message).unwrap();
        assert_eq!(dest_node.decoder.get_useful_piece_count(), 1);
    }

    #[test]
    fn test_decode_and_update() {
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size + 1);
        let block = random_u8_slice(num_chunks * chunk_size * 32);
        let source_node = Node::new_source(1, &committer, &block, num_chunks).unwrap();
        let mut dest_node = Node::new(2, &committer, num_chunks);
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
        let source_node = Node::new_source(1, &committer, &block, num_chunks).unwrap();
        let mut dest_node = Node::new(2, &committer, num_chunks);

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
        assert_eq!(recoded_message.get_source_id(), 2);
        assert!(recoded_message.verify(&committer).is_ok());
    }

    #[test]
    fn test_simulate_network() {
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size);
        let block = random_u8_slice(num_chunks * chunk_size * 32);
        let mut source_node = Node::new_source(0, &committer, &block, num_chunks).unwrap();
        let mut dest_node = Node::new(1, &committer, num_chunks);
        source_node.add_neighbor(1);
        dest_node.add_neighbor(0);
        let mut neighbors = vec![&mut dest_node];
        source_node
            .simulate_network(0.0, &mut neighbors[..], 0)
            .unwrap();
        assert!(dest_node.decoder.get_useful_piece_count() > 0);
    }
}
