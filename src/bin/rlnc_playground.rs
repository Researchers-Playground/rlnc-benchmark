use rand::Rng;
use rlnc::{
    full::{decoder::Decoder, encoder::Encoder, recoder::Recoder},
    RLNCError,
};

fn main() {
    let mut rng = rand::rng();

    // 1. Define original data parameters
    let original_data_len = 1024 * 10; // 10 KB
    let piece_count = 32; // Data will be split into 32 pieces
    let original_data: Vec<u8> = (0..original_data_len).map(|_| rng.random()).collect();
    let original_data_copy = original_data.clone();

    // 2. Initialize the Encoder
    let encoder = Encoder::new(original_data, piece_count).expect("Failed to create RLNC encoder");
    println!(
        "Initialized Encoder with {} bytes of data, split into {} pieces, each of {} bytes. Each coded piece will be of {} bytes.",
        original_data_len,
        piece_count,
        encoder.get_piece_byte_len(),
        encoder.get_full_coded_piece_byte_len()
    );

    // 3. Initialize the Decoder
    println!(
        "Initializing Decoder, expecting {} original pieces of {} bytes each.",
        encoder.get_piece_count(),
        encoder.get_piece_byte_len()
    );
    let mut decoder = Decoder::new(encoder.get_piece_byte_len(), encoder.get_piece_count())
        .expect("Failed to create RLNC decoder");

    // 4. Simulate a sender generating initial coded pieces
    let num_initial_coded_pieces_from_sender = encoder.get_piece_count() / 2; // Send half directly
    println!("\nSender generating {num_initial_coded_pieces_from_sender} initial coded pieces...");
    let mut pieces_for_recoder = Vec::new();

    for i in 0..num_initial_coded_pieces_from_sender {
        let coded_piece = encoder.code(&mut rng);
        pieces_for_recoder.extend_from_slice(&coded_piece); // Collect the same coded piece for recoder

        match decoder.decode(&coded_piece) {
            Ok(_) => println!("  Decoded direct piece {}: Useful.", i + 1),
            Err(RLNCError::PieceNotUseful) => {
                println!("  Decoded direct piece {}: Not useful.", i + 1)
            }
            Err(RLNCError::ReceivedAllPieces) => {
                println!(
                    "  Decoded direct piece {}: All pieces received, breaking.",
                    i + 1
                );
                break;
            }
            Err(e) => panic!("Unexpected error during direct decoding: {e:?}"),
        }
    }

    // 5. Initialize the Recoder with same coded pieces which were already used for decoding
    println!(
        "\nInitializing Recoder with {} bytes of received coded pieces.",
        pieces_for_recoder.len()
    );
    let recoder = Recoder::new(
        decoder.matrix.clone().extract_data(),
        encoder.get_full_coded_piece_byte_len(),
        encoder.get_piece_count(),
    )
    .expect("Failed to create RLNC recoder");

    // reinit again
    decoder = Decoder::new(encoder.get_piece_byte_len(), encoder.get_piece_count())
        .expect("Failed to create RLNC decoder");

    for i in 0..num_initial_coded_pieces_from_sender {
        let new_coded_piece = recoder.recode(&mut rng);
        match decoder.decode(&new_coded_piece) {
            Ok(_) => println!("  Decoded direct piece {}: Useful.", i + 1),
            Err(RLNCError::PieceNotUseful) => {
                println!("  Decoded direct piece {}: Not useful.", i + 1)
            }
            Err(RLNCError::ReceivedAllPieces) => {
                println!(
                    "  Decoded direct piece {}: All pieces received, breaking.",
                    i + 1
                );
                break;
            }
            Err(e) => panic!("Unexpected error during direct decoding: {e:?}"),
        }
    }

    let mut i = decoder.get_useful_piece_count();
    while !decoder.is_already_decoded() {
        let new_coded_piece = encoder.code(&mut rng);
        match decoder.decode(&new_coded_piece) {
            Ok(_) => {
                println!("  Decoded direct piece {}: Useful.", i + 1);
                i += 1;
            }
            Err(RLNCError::PieceNotUseful) => {
                println!("  Decoded direct piece {}: Not useful.", i + 1)
            }
            Err(RLNCError::ReceivedAllPieces) => {
                println!(
                    "  Decoded direct piece {}: All pieces received, breaking.",
                    i + 1
                );
                break;
            }
            Err(e) => panic!("Unexpected error during direct decoding: {e:?}"),
        }
    }
    // 8. Retrieve the decoded data
    println!("\nRetrieving decoded data...");
    let decoded_data = decoder
        .get_decoded_data()
        .expect("Failed to retrieve decoded data after all pieces received");

    // 9. Verify that the decoded data matches the original data
    assert_eq!(original_data_copy, decoded_data);
    println!("\nRLNC workflow completed successfully! Original data matches decoded data.");
}
