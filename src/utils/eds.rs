use rayon::prelude::*;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::sync::Arc;

pub fn create_matrix(block: &[u8], block_size: usize, k: usize) -> Vec<Vec<Vec<u8>>> {
    let share_size = block_size / (k * k);
    let mut original_matrix: Vec<Vec<Vec<u8>>> = Vec::new();

    for row in 0..k {
        let mut row_shares: Vec<Vec<u8>> = Vec::new();
        for col in 0..k {
            let share_idx = row * k + col;
            let start_idx = share_idx * share_size;
            let end_idx = (start_idx + share_size).min(block_size);
            let mut share_data = block[start_idx..end_idx].to_vec();
            if share_data.len() < share_size {
                share_data.extend_from_slice(&vec![0; share_size - share_data.len()]);
            }
            row_shares.push(share_data);
        }
        original_matrix.push(row_shares);
    }

    println!(
        "Create {}x{} matrix successfully with share size {}",
        k, k, share_size
    );
    original_matrix
}

pub fn create_extended_matrix(
    original_matrix: &[Vec<Vec<u8>>],
    block_size: usize,
    k: usize,
) -> Vec<Vec<Vec<u8>>> {
    let share_size = block_size / (k * k);
    let zero_share = vec![0u8; share_size];

    let mut extended_matrix = Vec::with_capacity(2 * k);
    for row in 0..k {
        let mut extended_row = Vec::with_capacity(2 * k);
        extended_row.extend_from_slice(&original_matrix[row]);
        extended_row.extend(std::iter::repeat(zero_share.clone()).take(k));
        extended_matrix.push(extended_row);
    }
    extended_matrix.extend(std::iter::repeat_with(|| vec![zero_share.clone(); 2 * k]).take(k));

    println!("Create extended {}x{} matrix successfully", 2 * k, 2 * k);
    extended_matrix
}

pub fn extended_data_share(
    original_matrix: &[Vec<Vec<u8>>],
    block_size: usize,
    k: usize,
) -> Vec<Vec<Vec<u8>>> {
    let mut extended_matrix = create_extended_matrix(&original_matrix, block_size, k);
    let rs = Arc::new(ReedSolomon::new(k, k).unwrap());
    for col in 0..k {
        let mut column_shares = Vec::with_capacity(2 * k);
        column_shares.extend(extended_matrix.iter().take(k).map(|row| row[col].clone()));
        let share_size = block_size / (k * k);
        let zero_share = vec![0u8; share_size];
        column_shares.extend(std::iter::repeat(zero_share).take(k));
        rs.encode(&mut column_shares).unwrap();

        for (row_idx, share) in column_shares.into_iter().enumerate() {
            extended_matrix[row_idx][col] = share;
        }
    }
    extended_matrix.par_iter_mut().for_each(|row| {
        rs.encode(row).unwrap();
    });
    extended_matrix
}
