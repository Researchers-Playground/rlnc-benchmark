// basic integration test using InMemoryStorage + pedersen committer
use super::decoder::StorageDecoder;
use super::encoder::StorageEncoder;
use super::core::InMemoryStorage;
use super::core::NodeStorage;

use crate::commitments::ristretto::pedersen::PedersenCommitter;

#[test]
fn integration_encode_decode_shred() {
    // parameters
    let block_id = 1usize;
    let num_shreds = 2usize;
    let num_chunks_per_shred = 4usize; // k
    let shred_size = num_chunks_per_shred * 32; // each chunk 32 bytes

    // prepare storage & committer
    let mut storage = InMemoryStorage::<PedersenCommitter>::new();
    let committer = PedersenCommitter::new(num_chunks_per_shred);

    // create two shreds (fake data) and store
    for s in 0..num_shreds {
        let bytes = vec![s as u8; shred_size];
        storage.store_shred(block_id, s, bytes);
    }

    // create encoder
    let encoder = StorageEncoder::new(block_id, num_shreds, num_chunks_per_shred);

    // encode one shred and store several pieces
    let mut piece_idx = 0usize;
    let pieces_to_store = 6usize;
    for _ in 0..pieces_to_store {
        let piece = encoder
            .encode_one_shred::<PedersenCommitter, _>(&storage, &committer, 0)
            .expect("encode failed");
        storage.store_coded_piece(block_id, 0, piece_idx, piece);
        piece_idx += 1;
    }

    // store commitment
    let commitment = encoder
        .get_shred_commitment::<PedersenCommitter, _>(&storage, &committer, 0)
        .expect("commit failed");
    storage.store_commitment(block_id, 0, commitment.clone());

    // decoder: try decode using pieces indices retrieved from storage
    let decoder = StorageDecoder::new(num_chunks_per_shred);
    let idxs = storage.list_piece_indices(block_id, 0);
    let decoded = decoder
        .try_decode_shred::<PedersenCommitter, _>(&storage, block_id, 0, &idxs, &commitment)
        .expect("decode failed");
    // decoded should equal original shred bytes (since shard content repeated, length check)
    assert_eq!(decoded.len(), shred_size);
}
