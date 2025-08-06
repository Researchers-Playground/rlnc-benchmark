use std::collections::HashMap;
use rand::Rng;
use crate::{
    commitments::{ristretto::pedersen::PedersenError, Committer}, erase_code_methods::{network_coding::RLNCErasureCoder, reed_solomon::RSErasureCoder, CodedData, ErasureCoderType, ErasureError}, networks::{message::Message, storage::Storages, virtual_oracle::Oracle}, utils::rlnc::RLNCError
};
use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint};

pub struct Node<'a, C: Committer<Scalar = Scalar, Commitment = Vec<RistrettoPoint>, Error = PedersenError>> {
    pub id: usize,
    pub erasure_coder: ErasureCoderType<'a, C>,
    pub committer: &'a C,
    pub neighbors: Vec<usize>,
    pub storages: Storages<Vec<RistrettoPoint>, CodedData>,
}

impl<'a, C: Committer<Scalar = Scalar, Commitment = Vec<RistrettoPoint>, Error = PedersenError>> Node<'a, C> {
    pub fn new(id: usize, committer: &'a C, erasure_coder: ErasureCoderType<'a, C>, neighbors: Vec<usize>) -> Self {
        Node {
            id,
            erasure_coder,
            committer,
            neighbors,
            storages: Storages {
                commitments: HashMap::new(),
                coded_data: HashMap::new(),
            },
        }
    }

    pub fn new_source(
        id: usize,
        committer: &'a C,
        data: Vec<u8>,
        num_chunks: usize,
        use_rlnc: bool,
    ) -> Result<Self, ErasureError> {
        let erasure_coder = if use_rlnc {
            ErasureCoderType::RLNC(RLNCErasureCoder::new(committer, Some(data), num_chunks)
                .map_err(ErasureError::RLNC)?)
        } else {
            ErasureCoderType::RS(RSErasureCoder::new(data, num_chunks, num_chunks / 2, 512)
                .map_err(ErasureError::RS)?)
        };
        Ok(Node {
            id,
            erasure_coder,
            committer,
            neighbors: Vec::new(),
            storages: Storages {
                commitments: HashMap::new(),
                coded_data: HashMap::new(),
            },
        })
    }

    pub fn send(&mut self, oracle: &Oracle) -> Result<Vec<(usize, Message<Vec<RistrettoPoint>, CodedData>)>, ErasureError> {
        let mut messages = Vec::new();
        let binding = Vec::new();
        let shred_ids = oracle.get_shreds_for_node(self.id).unwrap_or(&binding);
        for &shred_id in shred_ids {
            if let Some(coded_data) = self.storages.coded_data.get(&shred_id) {
                let commitment = self.storages.commitments.get(&shred_id)
                    .ok_or_else(|| ErasureError::Commitment(PedersenError::InvalidChunkSize("No commitment for shred".to_string())))?;
                let message = Message {
                    piece: coded_data.clone(),
                    commitment: commitment.clone(),
                    source_id: self.id,
                    shred_id,
                };
                let target_nodes = oracle.get_nodes_for_shred(shred_id);
                for &target_node_id in &target_nodes {
                    messages.push((target_node_id, message.clone()));
                }
            } else {
                let coded_data = self.erasure_coder.encode()?;
                let commitment = self.committer.commit(&vec![vec![Scalar::from(1u8)]])
                    .map_err(ErasureError::Commitment)?;
                let message = Message {
                    piece: coded_data.clone(),
                    commitment,
                    source_id: self.id,
                    shred_id,
                };
                self.storages.coded_data.insert(shred_id, coded_data);
                self.storages.commitments.insert(shred_id, message.commitment.clone());
                let target_nodes = oracle.get_nodes_for_shred(shred_id);
                for &target_node_id in &target_nodes {
                    messages.push((target_node_id, message.clone()));
                }
            }
        }
        Ok(messages)
    }

    pub fn receive(&mut self, message: Message<Vec<RistrettoPoint>, CodedData>) -> Result<(), ErasureError> {
        if self.storages.commitments.contains_key(&message.shred_id) && 
           self.storages.commitments.get(&message.shred_id) != Some(&message.commitment) {
            return Err(ErasureError::Commitment(PedersenError::InvalidChunkSize("Commitment mismatch".to_string())));
        }
        self.erasure_coder.verify(&message.piece, &message.commitment)?;
        self.erasure_coder.decode(&message.piece)?;
        self.storages.commitments.insert(message.shred_id, message.commitment);
        self.storages.coded_data.insert(message.shred_id, message.piece);
        Ok(())
    }

    pub fn sample(&self) -> Result<(usize, &CodedData, &Vec<RistrettoPoint>), ErasureError> {
        let mut rng = rand::rng();
        let keys: Vec<usize> = self.storages.coded_data.keys().cloned().collect();
        if keys.is_empty() {
            return Err(ErasureError::RLNC(RLNCError::InvalidPiece("No data available for sampling".to_string())));
        }
        let shred_id = keys[rng.random_range(0..keys.len())];
        let coded_data = self.storages.coded_data.get(&shred_id).unwrap();
        let commitment = self.storages.commitments.get(&shred_id)
            .ok_or_else(|| ErasureError::Commitment(PedersenError::InvalidChunkSize("No commitment for shred".to_string())))?;
        self.erasure_coder.verify(coded_data, commitment)?;
        Ok((shred_id, coded_data, commitment))
    }

    pub fn request_shred(
        &mut self,
        oracle: &Oracle,
        shred_id: usize,
        neighbors: &mut [&mut Node<C>],
    ) -> Result<(), ErasureError> {
        let target_nodes = oracle.get_nodes_for_shred(shred_id);
        for &neighbor_id in &target_nodes {
            if self.neighbors.contains(&neighbor_id) {
                for neighbor in neighbors.iter_mut() {
                    if neighbor.id == neighbor_id {
                        if let Ok((_, coded_data, commitment)) = neighbor.sample() {
                            let message = Message {
                                piece: coded_data.clone(),
                                commitment: commitment.clone(),
                                source_id: neighbor_id,
                                shred_id,
                            };
                            self.receive(message)?;
                        }
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn reconstruct_block(&mut self, oracle: &Oracle, neighbors: &mut [&mut Node<C>]) -> Result<Vec<u8>, ErasureError> {
        while !self.erasure_coder.is_decoded() {
            let required_shreds = (0..oracle.num_shreds)
                .filter(|&id| !self.storages.coded_data.contains_key(&id))
                .collect::<Vec<_>>();
            for shred_id in required_shreds {
                self.request_shred(oracle, shred_id, neighbors)?;
            }
        }
        self.erasure_coder.get_decoded_data()
    }
}