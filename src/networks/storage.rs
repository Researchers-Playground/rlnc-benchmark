use std::collections::HashMap;

pub struct Storages<Commitment, CodedData> {
    pub commitments: HashMap<usize, Commitment>, // shred_id/cell_id -> commitment
    pub coded_data: HashMap<usize, CodedData>,  // shred_id/cell_id -> shred/cell
}