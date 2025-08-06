#[derive(Clone, Debug)]
pub struct Message<Commitment, CodedData> {
    pub piece: CodedData,
    pub commitment: Commitment,
    pub source_id: usize,
    pub shred_id: usize,
}

impl<Commitment: Clone + PartialEq, CodedData: Clone> Message<Commitment, CodedData> {
    pub fn new(piece: CodedData, commitment: Commitment, source_id: usize, shred_id: usize) -> Self {
        Message {
            piece,
            commitment,
            source_id,
            shred_id,
        }
    }
}