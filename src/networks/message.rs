#[derive(Clone, Debug, PartialEq)]
pub struct Message<Commitment, CodedData> {
    pub piece: CodedData,
    pub commitment: Commitment,
    pub source_id: usize,
}

impl<Commitment: Clone + PartialEq, CodedData: Clone> Message<Commitment, CodedData> {
    pub fn new(piece: CodedData, commitment: Commitment, source_id: usize) -> Self {
        Message {
            piece,
            commitment,
            source_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::erase_code_methods::CodedData;
    use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint};
    use crate::commitments::CodedPiece;

    fn create_dummy_coded_piece() -> CodedPiece<Scalar> {
        let data = vec![Scalar::from(1u8); 16]; 
        let coefficients = vec![Scalar::from(2u8); 16];
        CodedPiece { data, coefficients }
    }

    fn create_dummy_commitment() -> Vec<RistrettoPoint> {
        vec![RistrettoPoint::default(); 16] 
    }

    #[test]
    fn test_message_new_rs() {
        let piece = CodedData::RS(vec![1u8; 512]); // Shred 512 byte
        let commitment = create_dummy_commitment();
        let source_id = 1;

        let message = Message::new(piece.clone(), commitment.clone(), source_id);

        assert_eq!(message.piece, piece);
        assert_eq!(message.commitment, commitment);
        assert_eq!(message.source_id, source_id);
    }

    #[test]
    fn test_message_new_rlnc() {
        let piece = CodedData::RLNC(create_dummy_coded_piece());
        let commitment = create_dummy_commitment();
        let source_id = 2;

        let message = Message::new(piece.clone(), commitment.clone(), source_id);

        assert_eq!(message.piece, piece);
        assert_eq!(message.commitment, commitment);
        assert_eq!(message.source_id, source_id);
    }

    #[test]
    fn test_message_clone() {
        let piece = CodedData::RS(vec![1u8; 512]);
        let commitment = create_dummy_commitment();
        let source_id = 1;

        let message = Message::new(piece.clone(), commitment.clone(), source_id);
        let cloned_message = message.clone();

        assert_eq!(message.piece, cloned_message.piece);
        assert_eq!(message.commitment, cloned_message.commitment);
        assert_eq!(message.source_id, cloned_message.source_id);
    }

    #[test]
    fn test_message_partial_eq() {
        let piece = CodedData::RS(vec![1u8; 512]);
        let commitment = create_dummy_commitment();
        let source_id = 1;

        let message1 = Message::new(piece.clone(), commitment.clone(), source_id);
        let message2 = Message::new(piece, commitment, source_id);

        assert_eq!(message1, message2);

        let different_message = Message::new(
            CodedData::RS(vec![2u8; 512]),
            create_dummy_commitment(),
            source_id,
        );
        assert_ne!(message1, different_message);
    }

    #[test]
    fn test_message_debug() {
        let piece = CodedData::RS(vec![1u8; 512]);
        let commitment = create_dummy_commitment();
        let source_id = 1;

        let message = Message::new(piece, commitment, source_id);
        let debug_output = format!("{:?}", message);

        assert!(debug_output.contains("source_id: 1"));
        assert!(debug_output.contains("piece: RS("));
        assert!(debug_output.contains("commitment: ["));
    }

    #[test]
    fn test_message_different_commitment_types() {
        let piece = CodedData::RS(vec![1u8; 512]);
        let commitment = vec![0u8; 32]; 
        let source_id = 3;

        let message = Message::new(piece.clone(), commitment.clone(), source_id);

        assert_eq!(message.piece, piece);
        assert_eq!(message.commitment, commitment);
        assert_eq!(message.source_id, source_id);
    }
}