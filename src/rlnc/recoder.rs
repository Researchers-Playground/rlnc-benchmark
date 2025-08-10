use crate::commitments::CodedPiece;
use crate::commitments::Committer;
use curve25519_dalek::Scalar;
use rand::Rng;

use crate::rlnc::storage::{BlockId, NodeStorage, PieceIdx, ShredId};

/// NetworkRecoder is stateless and only needs to know piece_count (k)
pub struct NetworkRecoder {
    pub piece_count: usize,
}

impl NetworkRecoder {
    pub fn new(piece_count: usize) -> Self {
        Self { piece_count }
    }

    /// Recode: take available piece indices for a shred (from storage), read pieces, mix them,
    /// and produce a new CodedPiece for forwarding.
    pub fn recode<C: Committer<Scalar = Scalar>, S: NodeStorage<C>>(
        &self,
        storage: &S,
        block_id: BlockId,
        shred_id: ShredId,
        use_piece_indices: &[PieceIdx],
    ) -> Result<CodedPiece<Scalar>, String> {
        let mut collected: Vec<CodedPiece<Scalar>> = Vec::new();
        for &idx in use_piece_indices.iter() {
            if let Some(p) = storage.get_coded_piece(block_id, shred_id, idx) {
                collected.push(p.clone());
            }
        }
        if collected.is_empty() {
            return Err("No pieces available to recode".to_string());
        }

        let n = collected.len();
        let mut rng = rand::rng();
        // Use non-zero u8-based mixing coefficients (1-255)
        let mixing: Vec<Scalar> = (0..n)
            .map(|_| Scalar::from(rng.random_range(1u8..=255u8)))
            .collect();
        // println!("Mixing coefficients: {:?}", mixing);

        let data_len = collected[0].data.len(); // e.g., 32 for 32-byte chunks
        let coeffs_len = collected[0].coefficients.len(); // e.g., 4 for num_chunks

        // Compute new data: sum(mixing[j] * piece.data[i])
        let data: Vec<Scalar> = (0..data_len)
            .map(|i| {
                let sum: Scalar = mixing
                    .iter()
                    .zip(&collected)
                    .map(|(&coeff, piece)| {
                        let product = coeff * piece.data[i];
                        // println!(
                        //     "Data contribution: coeff={:?}, piece.data[{}]={:?}, product={:?}",
                        //     coeff, i, piece.data[i], product
                        // );
                        product
                    })
                    .sum();
                sum
            })
            .collect();

        // Compute new coefficients: sum(mixing[j] * piece.coefficients[i])
        let coefficients: Vec<Scalar> = (0..coeffs_len)
            .map(|i| {
                mixing
                    .iter()
                    .zip(&collected)
                    .map(|(&coeff, piece)| coeff * piece.coefficients[i])
                    .sum()
            })
            .collect();

        Ok(CodedPiece { data, coefficients })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitments::{CodedPiece, Committer};
    use crate::rlnc::storage::{BlockId, NodeStorage, PieceIdx, ShredId};
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use std::error::Error;

    // Mock Error for Committer
    #[derive(Debug)]
    struct MockError(String);

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Error for MockError {}

    // Mock Committer
    struct MockCommitter;

    impl Committer for MockCommitter {
        type Scalar = Scalar;
        type Commitment = Vec<RistrettoPoint>;
        type Error = MockError;

        fn commit(&self, chunks: &Vec<Vec<Scalar>>) -> Result<Self::Commitment, Self::Error> {
            let mut commitment = vec![];
            for i in 0..chunks.len() {
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
            true // Always pass for testing
        }
    }

    // Mock Storage for testing recoder
    struct MockStorage {
        pieces: Vec<(BlockId, ShredId, PieceIdx, CodedPiece<Scalar>)>,
        commitments: Vec<(BlockId, ShredId, Vec<RistrettoPoint>)>,
        decoded_shreds: Vec<(BlockId, ShredId, Vec<u8>)>,
        shreds: Vec<(BlockId, ShredId, Vec<u8>)>,
    }

    impl MockStorage {
        fn new() -> Self {
            MockStorage {
                pieces: Vec::new(),
                commitments: Vec::new(),
                decoded_shreds: Vec::new(),
                shreds: Vec::new(),
            }
        }
    }

    impl NodeStorage<MockCommitter> for MockStorage {
        type Commitment = Vec<RistrettoPoint>;

        fn store_coded_piece(
            &mut self,
            block_id: BlockId,
            shred_id: ShredId,
            piece_idx: PieceIdx,
            piece: CodedPiece<Scalar>,
        ) {
            self.pieces.push((block_id, shred_id, piece_idx, piece));
        }

        fn get_coded_piece(
            &self,
            block_id: BlockId,
            shred_id: ShredId,
            piece_idx: PieceIdx,
        ) -> Option<&CodedPiece<Scalar>> {
            self.pieces
                .iter()
                .find(|(bid, sid, pid, _)| {
                    *bid == block_id && *sid == shred_id && *pid == piece_idx
                })
                .map(|(_, _, _, piece)| piece)
        }

        fn list_piece_indices(&self, block_id: BlockId, shred_id: ShredId) -> Vec<PieceIdx> {
            self.pieces
                .iter()
                .filter(|(bid, sid, _, _)| *bid == block_id && *sid == shred_id)
                .map(|(_, _, pid, _)| *pid)
                .collect()
        }

        fn store_commitment(
            &mut self,
            block_id: BlockId,
            shred_id: ShredId,
            commitment: Vec<RistrettoPoint>,
        ) {
            self.commitments.push((block_id, shred_id, commitment));
        }

        fn get_commitment(
            &self,
            block_id: BlockId,
            shred_id: ShredId,
        ) -> Option<&Vec<RistrettoPoint>> {
            self.commitments
                .iter()
                .find(|(bid, sid, _)| *bid == block_id && *sid == shred_id)
                .map(|(_, _, c)| c)
        }

        fn store_decoded_shred(&mut self, block_id: BlockId, shred_id: ShredId, shred: Vec<u8>) {
            self.decoded_shreds.push((block_id, shred_id, shred));
        }

        fn get_decoded_shred(&self, block_id: BlockId, shred_id: ShredId) -> Option<&Vec<u8>> {
            self.decoded_shreds
                .iter()
                .find(|(bid, sid, _)| *bid == block_id && *sid == shred_id)
                .map(|(_, _, s)| s)
        }

        fn get_shred(&self, block_id: BlockId, shred_id: ShredId) -> Option<&Vec<u8>> {
            self.shreds
                .iter()
                .find(|(bid, sid, _)| *bid == block_id && *sid == shred_id)
                .map(|(_, _, s)| s)
        }

        fn list_decoded_shreds(&self, block_id: BlockId) -> Vec<ShredId> {
            self.decoded_shreds
                .iter()
                .filter(|(bid, _, _)| *bid == block_id)
                .map(|(_, sid, _)| *sid)
                .collect()
        }

        fn store_shred(&mut self, block_id: BlockId, shred_id: ShredId, bytes: Vec<u8>) {
            self.shreds.push((block_id, shred_id, bytes));
        }
    }

    #[test]
    fn test_recoder_empty_input() {
        let recoder = NetworkRecoder::new(4);
        let storage = MockStorage::new();
        let block_id = 1;
        let shred_id = 0;
        let indices = vec![];

        let result =
            recoder.recode::<MockCommitter, MockStorage>(&storage, block_id, shred_id, &indices);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "No pieces available to recode");
    }

    #[test]
    fn test_recoder_single_piece() {
        let recoder = NetworkRecoder::new(4);
        let mut storage = MockStorage::new();
        let block_id = 1;
        let shred_id = 0;

        // Create a single piece
        let piece = CodedPiece {
            data: vec![Scalar::from(1u8), Scalar::from(2u8), Scalar::from(3u8)],
            coefficients: vec![
                Scalar::from(1u8),
                Scalar::from(0u8),
                Scalar::from(0u8),
                Scalar::from(0u8),
            ],
        };
        storage.store_coded_piece(block_id, shred_id, 0, piece.clone());
        let indices = vec![0];

        let result =
            recoder.recode::<MockCommitter, MockStorage>(&storage, block_id, shred_id, &indices);
        assert!(result.is_ok());
        let new_piece = result.unwrap();

        // Verify lengths
        assert_eq!(new_piece.data.len(), piece.data.len());
        assert_eq!(new_piece.coefficients.len(), piece.coefficients.len());

        // Since only one piece, new_piece should be scaled by a random coefficient
        let ratio = if new_piece.data[0] != Scalar::ZERO && piece.data[0] != Scalar::ZERO {
            new_piece.data[0] * piece.data[0].invert()
        } else {
            new_piece.data[1] * piece.data[1].invert()
        };
        for i in 0..piece.data.len() {
            assert_eq!(new_piece.data[i], piece.data[i] * ratio);
        }
        for i in 0..piece.coefficients.len() {
            assert_eq!(new_piece.coefficients[i], piece.coefficients[i] * ratio);
        }
    }

    #[test]
    fn test_recoder_multiple_pieces() {
        let recoder = NetworkRecoder::new(4);
        let mut storage = MockStorage::new();
        let block_id = 1;
        let shred_id = 0;

        // Create three pieces
        let pieces = vec![
            CodedPiece {
                data: vec![Scalar::from(1u8), Scalar::from(2u8), Scalar::from(3u8)],
                coefficients: vec![
                    Scalar::from(1u8),
                    Scalar::from(0u8),
                    Scalar::from(0u8),
                    Scalar::from(0u8),
                ],
            },
            CodedPiece {
                data: vec![Scalar::from(4u8), Scalar::from(5u8), Scalar::from(6u8)],
                coefficients: vec![
                    Scalar::from(0u8),
                    Scalar::from(1u8),
                    Scalar::from(0u8),
                    Scalar::from(0u8),
                ],
            },
            CodedPiece {
                data: vec![Scalar::from(7u8), Scalar::from(8u8), Scalar::from(9u8)],
                coefficients: vec![
                    Scalar::from(0u8),
                    Scalar::from(0u8),
                    Scalar::from(1u8),
                    Scalar::from(0u8),
                ],
            },
        ];
        for (i, piece) in pieces.iter().enumerate() {
            storage.store_coded_piece(block_id, shred_id, i as PieceIdx, piece.clone());
        }
        let indices = vec![0, 1, 2];

        let result =
            recoder.recode::<MockCommitter, MockStorage>(&storage, block_id, shred_id, &indices);
        assert!(result.is_ok());
        let new_piece = result.unwrap();

        // Verify lengths
        assert_eq!(new_piece.data.len(), 3);
        assert_eq!(new_piece.coefficients.len(), 4);

        // Check that mixing occurred (non-zero output)
        assert!(new_piece.data.iter().any(|&x| x != Scalar::ZERO));
        assert!(new_piece.coefficients.iter().any(|&x| x != Scalar::ZERO));
    }

    #[test]
    fn test_recoder_linear_independence() {
        let recoder = NetworkRecoder::new(4);
        let mut storage = MockStorage::new();
        let block_id = 1;
        let shred_id = 0;

        // Create initial pieces
        let pieces = vec![
            CodedPiece {
                data: vec![Scalar::from(1u8), Scalar::from(2u8), Scalar::from(3u8)],
                coefficients: vec![
                    Scalar::from(1u8),
                    Scalar::from(0u8),
                    Scalar::from(0u8),
                    Scalar::from(0u8),
                ],
            },
            CodedPiece {
                data: vec![Scalar::from(4u8), Scalar::from(5u8), Scalar::from(6u8)],
                coefficients: vec![
                    Scalar::from(0u8),
                    Scalar::from(1u8),
                    Scalar::from(0u8),
                    Scalar::from(0u8),
                ],
            },
        ];
        for (i, piece) in pieces.iter().enumerate() {
            storage.store_coded_piece(block_id, shred_id, i as PieceIdx, piece.clone());
        }
        let indices = vec![0, 1];

        // Generate 4 recoded pieces
        let mut recoded_pieces = vec![];
        for i in 0..4 {
            let new_piece = recoder
                .recode::<MockCommitter, MockStorage>(&storage, block_id, shred_id, &indices)
                .expect("Recode failed");
            storage.store_coded_piece(block_id, shred_id, (i + 2) as PieceIdx, new_piece.clone());
            recoded_pieces.push(new_piece);
        }

        // Check for linear independence
        for i in 0..recoded_pieces.len() {
            for j in (i + 1)..recoded_pieces.len() {
                let coeffs_i = &recoded_pieces[i].coefficients;
                let coeffs_j = &recoded_pieces[j].coefficients;
                let mut is_multiple = false;
                if coeffs_i.iter().any(|&x| x != Scalar::ZERO)
                    && coeffs_j.iter().any(|&x| x != Scalar::ZERO)
                {
                    let mut ratio = None;
                    for k in 0..coeffs_i.len() {
                        if coeffs_i[k] != Scalar::ZERO && coeffs_j[k] != Scalar::ZERO {
                            ratio = Some(coeffs_i[k] * coeffs_j[k].invert());
                            break;
                        }
                    }
                    if let Some(r) = ratio {
                        is_multiple = coeffs_i.iter().zip(coeffs_j.iter()).all(|(&ci, &cj)| {
                            ci == cj * r || (ci == Scalar::ZERO && cj == Scalar::ZERO)
                        });
                    }
                }
                assert!(
                    !is_multiple,
                    "Recoded pieces {} and {} are linearly dependent",
                    i, j
                );
            }
        }
    }
}
