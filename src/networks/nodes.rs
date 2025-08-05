use crate::{
    commitments::ristretto::pedersen::PedersenCommitter,
    utils::rlnc::{CodedPacket, NetworkDecoder, NetworkEncoder, NetworkRecoder, RLNCError},
};
use curve25519_dalek::{traits::MultiscalarMul, RistrettoPoint, Scalar};
use rand::Rng;

///! Note that: all variables is public for easily to benchmark

#[derive(Clone, Debug)]
pub struct Message {
    pub coded_block: Vec<CodedPacket>,
    pub commitments: Vec<Vec<RistrettoPoint>>,
    pub source_id: usize,
}

pub struct Node<'a> {
    pub id: usize,
    pub encoders: Vec<NetworkEncoder<'a>>,
    pub decoders: Vec<NetworkDecoder<'a>>,
    pub recoders: Vec<NetworkRecoder>,
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
    pub fn new(coded_block: Vec<CodedPacket>, commitments: Vec<Vec<RistrettoPoint>>, source_id: usize) -> Self {
        Message {
            coded_block,
            commitments,
            source_id,
        }
    }

    fn coefficients_to_scalars(&self, chunk: CodedPacket) -> Vec<Scalar> {
        chunk.coefficients.clone()
    }

    pub fn verify(&self, committer: &PedersenCommitter) -> Result<(), String> {
        assert_eq!(self.coded_block.len(), self.commitments.len(), "Commitments and coded block lengths must match");
        for (chunk, commitment) in self.coded_block.iter().zip(&self.commitments) {
            if chunk.coefficients.len() != commitment.len() {
                return Err("Chunk coefficients and commitments lengths do not match".to_string());
            }
            let msm = RistrettoPoint::multiscalar_mul(self.coefficients_to_scalars((*chunk).clone()), commitment);
            let commitment = committer.commit(&chunk.data)?;
            if msm != commitment {
                return Err("The commitment does not match".to_string());
            }
        }

        Ok(())
    }

    pub fn get_source_id(&self) -> usize {
        self.source_id
    }
}

impl<'a> Node<'a> {
    pub fn new(id: usize, committer: &'a PedersenCommitter, num_shreds: usize, num_chunks: usize) -> Self {
        let encoders: Vec<NetworkEncoder<'a>> = (0..num_shreds).map(|_| NetworkEncoder::new(committer, None, num_chunks).unwrap()).collect();
        let decoders = (0..num_shreds).map(|_| NetworkDecoder::new(committer, num_chunks)).collect();
        let recoders = (0..num_shreds).map(|_| NetworkRecoder::new(Vec::new(), num_chunks)).collect();
        Node {
            id,
            encoders,
            decoders,
            recoders,
            committer,
            neighbors: Vec::new(),
        }
    }

    pub fn new_source(
        id: usize,
        committer: &'a PedersenCommitter,
        block: &[u8],
        num_shreds: usize,
        num_chunks: usize,
    ) -> Result<Self, String> {
        let shred_size = (block.len() as f64 / num_shreds as f64).ceil() as usize;
        let encoders: Vec<NetworkEncoder<'a>> = block.chunks(shred_size).map(|shred_block| NetworkEncoder::new(committer, Some(shred_block.to_vec()), num_chunks).unwrap()).collect();
        let decoders = (0..num_shreds).map(|_| NetworkDecoder::new(committer, num_chunks)).collect();
        let recoders = (0..num_shreds).map(|_| NetworkRecoder::new(Vec::new(), num_chunks)).collect();
        Ok(Node {
            id,
            encoders,
            decoders,
            recoders,
            committer,
            neighbors: Vec::new(),
        })
    }

    pub fn get_id(&self) -> usize {
        self.id
    }

    fn check_existing_commitments(&self, index: usize, commitments: &[RistrettoPoint]) -> Result<(), String> {
        self.decoders[index].check_commitments(commitments)?;
        Ok(())
    }

    fn check_existing_chunks(&self, index: usize, chunk: &CodedPacket) -> Result<(), String> {
        self.decoders[index].check_chunks(chunk)?;
        Ok(())
    }

    pub fn receive(&mut self, message: Message) -> Result<(), ReceiveError> {
        let coded_block = &message.coded_block;
        let commitments = &message.commitments;

        // check
        if coded_block.len() != commitments.len() {
            return Err(ReceiveError::ExistingCommitmentsMismatch(
                "Coded block and commitments lengths do not match".to_string(),
            ));
        }
        if coded_block.is_empty() || commitments.is_empty() {
            return Err(ReceiveError::InvalidMessage(
                "Coded block or commitments cannot be empty".to_string(),
            ));
        }
        if coded_block.len() != self.decoders.len() {
            return Err(ReceiveError::InvalidMessage(
                "Coded block length does not match the number of decoders".to_string(),
            ));
        }

        message
        .verify(self.committer)
        .map_err(ReceiveError::InvalidMessage)?;

        for (index, chunk) in coded_block.iter().enumerate() {
            let commitment = &commitments[index];
            if commitment.len() != chunk.clone().coefficients.len() {
                return Err(ReceiveError::InvalidMessage(
                    "Commitments and chunk coefficients lengths do not match".to_string(),
                ));
            }

            self.check_existing_commitments(index, &commitment)
            .map_err(ReceiveError::ExistingCommitmentsMismatch)?;
            self.check_existing_chunks(index, &chunk)
            .map_err(ReceiveError::ExistingChunksMismatch)?;


            let coded_packet = chunk.clone();
            match self.decoders[index].decode(&coded_packet, &commitment) {
                Ok(_) => {}
                Err(RLNCError::DecodingNotComplete) => {
                    println!("Node {}: Decoding not complete", self.id);
                }
                Err(RLNCError::ReceivedAllPieces) => {
                    println!("Node {}: Received all pieces", self.id);
                }
                Err(RLNCError::PieceNotUseful) => return Err(ReceiveError::LinearlyDependentChunk),
                Err(RLNCError::InvalidData(msg)) => return Err(ReceiveError::InvalidMessage(msg)),
            }
            if self.decoders[index].is_already_decoded() {
                if let Ok(decoded_data) = self.decode(index) {
                    self.encoders[index]
                        .update_chunks(decoded_data, self.decoders[index].get_piece_count_val())
                        .unwrap();
                }
            }
        }

        Ok(())
    }

    pub fn send(&self) -> Result<Message, String> {
        let coded_packet: Vec<CodedPacket> = self.encoders.iter().map(|encoder| encoder.encode().unwrap()).collect();
        let commitments = self.encoders.iter().map(|encoder: &NetworkEncoder<'_>| encoder.get_commitments().unwrap()).collect();
        let message = Message::new(coded_packet, commitments, self.id);
        message.verify(self.committer)?;
        Ok(message)
    }

    pub fn is_fully_decode(&self) -> bool {
        self.decoders.iter().all(|decoder| decoder.is_already_decoded())
    }

    // TODO: update later since we need a proper structure for recode a single shred of a packet
    // pub fn recode(&mut self, index: usize, received_packets: Vec<CodedPacket>) -> Result<Message, String> {
    //     self.recoders[index].update_packets(received_packets)?;

    //     let coded_packet = self.recoders[index].recode();
    //     let chunk = CodedPacket {
    //         data: coded_packet.data,
    //         coefficients: coded_packet.coefficients,
    //     };
    //     let commitments = self
    //         .decoders[index]
    //         .get_commitments()
    //         .clone()
    //         .unwrap_or_else(Vec::new);
    //     let message = Message::new(chunk, commitments, self.id);
    //     message.verify(self.committer)?;
    //     Ok(message)
    // }

    pub fn decode(&self, index: usize) -> Result<Vec<u8>, String> {
        self.decoders[index].get_decoded_data().map_err(|e| match e {
            RLNCError::DecodingNotComplete => "Decoding not complete".to_string(),
            RLNCError::InvalidData(msg) => format!("Invalid data: {}", msg),
            RLNCError::ReceivedAllPieces => "Received all pieces".to_string(),
            RLNCError::PieceNotUseful => "Piece not useful".to_string(),
        })
    }

    pub fn full_decode(&self) -> Result<Vec<u8>, String> {
        let mut decoded_data = Vec::new();
        for (index, decoder) in self.decoders.iter().enumerate() {
            if decoder.is_already_decoded() {
                let data = decoder.get_decoded_data().unwrap();
                decoded_data.extend(data);
            } else {
                return Err(format!("Decoder {} is not fully decoded", index));
            }
        }
        Ok(decoded_data)
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
    use rand::seq::index;

    use super::*;
    use crate::utils::ristretto::random_u8_slice;

    #[test]
    fn test_new_node() {
        let num_shreds = 3;
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size);
        let node = Node::new(0, &committer, num_shreds, num_chunks);
        for (index, encoder) in node.encoders.iter().enumerate() {
            assert!(encoder.get_chunks().is_empty());
            let decoder = &node.decoders[index];
            assert_eq!(decoder.get_piece_count(), num_chunks);
            let recoder = &node.recoders[index];
            assert_eq!(recoder.get_piece_count(), num_chunks);
        }
        assert_eq!(node.get_id(), 0);
    }

    #[test]
    fn test_new_source_node() {
        let num_shreds = 2;
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size);
        let block = random_u8_slice(num_shreds * num_chunks * chunk_size * 32);
        let source_node = Node::new_source(1, &committer, &block, num_shreds, num_chunks).unwrap();
        for (index, encoder) in source_node.encoders.iter().enumerate() {
            assert!(encoder.get_chunks().is_empty());
            let decoder = &source_node.decoders[index];
            assert_eq!(decoder.get_piece_count(), num_chunks);
        }
        assert_eq!(source_node.get_id(), 1);
    }

    #[test]
    fn test_send_receive() {
        let num_shreds = 2;
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size);
        let block = random_u8_slice(num_shreds * num_chunks * chunk_size * 32);
        let source_node = Node::new_source(1, &committer, &block, num_shreds, num_chunks).unwrap();
        let mut dest_node = Node::new(2, &committer, num_shreds, num_chunks);
        let message = source_node.send().unwrap();
        assert_eq!(message.get_source_id(), 1);
        dest_node.receive(message).unwrap();

        for (index, decoder) in dest_node.decoders.iter().enumerate() {
            assert_eq!(decoder.get_useful_piece_count(), 1, "Expected one useful piece after receiving message on shred {}", index);
        }
    }

    #[test]
    fn test_decode_and_update() {
        let num_shreds = 2;
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size + 1);
        let block = random_u8_slice(num_shreds * num_chunks * chunk_size * 32);
        let source_node = Node::new_source(1, &committer, &block, num_shreds, num_chunks).unwrap();
        let mut dest_node = Node::new(2, &committer, num_shreds, num_chunks);
        for _ in 0..num_chunks {
            let message = source_node.send().unwrap();
            dest_node.receive(message).unwrap();
        }
        let decoded = dest_node.full_decode().unwrap();
        assert_eq!(decoded.len(), block.len());
        assert_eq!(decoded, block);
    }

    // TODO: update later since we need a proper structure for recode a single shred of a packet
    // #[test]
    // fn test_recode() {
    //     let num_chunks = 3;
    //     let chunk_size = 4;
    //     let committer = PedersenCommitter::new(chunk_size);
    //     let block = random_u8_slice(num_chunks * chunk_size * 32);
    //     let source_node = Node::new_source(1, &committer, &block, num_chunks).unwrap();
    //     let mut dest_node = Node::new(2, &committer, num_chunks);

    //     let initial_message = source_node.send().unwrap();
    //     dest_node.receive(initial_message).unwrap();

    //     let mut packets = Vec::new();
    //     for _ in 0..num_chunks {
    //         let message = source_node.send().unwrap();
    //         packets.push(CodedPacket {
    //             data: message.chunk.data,
    //             coefficients: message.chunk.coefficients,
    //         });
    //     }

    //     let recoded_message = dest_node.recode(packets).unwrap();
    //     assert_eq!(recoded_message.get_source_id(), 2);
    //     assert!(recoded_message.verify(&committer).is_ok());
    // }

    #[test]
    fn test_simulate_network() {
        let num_shreds = 2;
        let num_chunks = 3;
        let chunk_size = 4;
        let committer = PedersenCommitter::new(chunk_size);
        let block = random_u8_slice(num_shreds * num_chunks * chunk_size * 32);
        let mut source_node = Node::new_source(0, &committer, &block, num_shreds, num_chunks).unwrap();
        let mut dest_node = Node::new(1, &committer, num_shreds, num_chunks);
        source_node.add_neighbor(1);
        dest_node.add_neighbor(0);
        let mut neighbors = vec![&mut dest_node];
        source_node
            .simulate_network(0.0, &mut neighbors[..], 0)
            .unwrap();
        dest_node.decoders.iter().for_each(|decoder| {
            assert!(decoder.get_useful_piece_count() > 0);
        });
    }
}
