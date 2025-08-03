use rayon::prelude::*;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct FlatMatrix {
    data: Vec<u8>,
    rows: usize,
    cols: usize,
    share_size: usize,
}

impl FlatMatrix {
    pub fn new(block: &[u8], share_size: usize, k: usize) -> Self {
        let total_size = k * k * share_size;
        let mut data = block.to_vec();
        if data.len() < total_size {
            data.resize(total_size, 0);
        }
        data.truncate(total_size);
        println!(
            "Create {} x {} matrix successfully with share size {}",
            k, k, share_size
        );
        Self {
            data,
            rows: k,
            cols: k,
            share_size,
        }
    }

    /// Creates an empty matrix with specified dimensions (for extended matrices)
    pub fn empty(rows: usize, cols: usize, share_size: usize) -> Self {
        let total_size = rows * cols * share_size;
        Self {
            data: vec![0u8; total_size],
            rows,
            cols,
            share_size,
        }
    }

    pub fn get_share(&self, row: usize, col: usize) -> &[u8] {
        let start_idx = (row * self.cols + col) * self.share_size;
        &self.data[start_idx..start_idx + self.share_size]
    }

    pub fn get_share_mut(&mut self, row: usize, col: usize) -> &mut [u8] {
        let start_idx = (row * self.cols + col) * self.share_size;
        &mut self.data[start_idx..start_idx + self.share_size]
    }

    pub fn set_share(&mut self, row: usize, col: usize, share_data: &[u8]) {
        let share = self.get_share_mut(row, col);
        share.copy_from_slice(share_data);
    }

    pub fn get_row(&self, row: usize) -> Vec<Vec<u8>> {
        (0..self.cols)
            .map(|col| self.get_share(row, col).to_vec())
            .collect()
    }

    pub fn get_column(&self, col: usize) -> Vec<Vec<u8>> {
        (0..self.rows)
            .map(|row| self.get_share(row, col).to_vec())
            .collect()
    }

    pub fn set_row(&mut self, row: usize, row_data: &[Vec<u8>]) {
        for (col, share_data) in row_data.iter().enumerate() {
            self.set_share(row, col, share_data);
        }
    }

    pub fn set_column(&mut self, col: usize, col_data: &[Vec<u8>]) {
        for (row, share_data) in col_data.iter().enumerate() {
            self.set_share(row, col, share_data);
        }
    }

    pub fn dimensions(&self) -> (usize, usize) {
        (self.rows, self.cols)
    }

    pub fn share_size(&self) -> usize {
        self.share_size
    }

    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

pub fn create_extended_matrix(original_matrix: &FlatMatrix, k: usize) -> FlatMatrix {
    let share_size = original_matrix.share_size();
    let mut extended_matrix = FlatMatrix::empty(2 * k, 2 * k, share_size);
    for row in 0..k {
        for col in 0..k {
            let share_data = original_matrix.get_share(row, col);
            extended_matrix.set_share(row, col, share_data);
        }
    }
    println!("Create extended {} x {} matrix successfully", 2 * k, 2 * k);
    extended_matrix
}

pub fn extended_data_share(original_matrix: &FlatMatrix, k: usize) -> FlatMatrix {
    let mut extended_matrix = create_extended_matrix(original_matrix, k);
    let rs = Arc::new(ReedSolomon::new(k, k).unwrap());
    for col in 0..k {
        let mut column_shares = extended_matrix.get_column(col);
        rs.encode(&mut column_shares).unwrap();
        extended_matrix.set_column(col, &column_shares);
    }
    let share_size = extended_matrix.share_size();
    let cols_count = 2 * k;
    extended_matrix
        .data_mut()
        .par_chunks_mut(cols_count * share_size)
        .enumerate()
        .for_each(|(_row_idx, row_data)| {
            let mut row_shares: Vec<Vec<u8>> = (0..cols_count)
                .map(|col| {
                    let start = col * share_size;
                    row_data[start..start + share_size].to_vec()
                })
                .collect();
            rs.encode(&mut row_shares).unwrap();
            for (col, share) in row_shares.iter().enumerate() {
                let start = col * share_size;
                row_data[start..start + share_size].copy_from_slice(share);
            }
        });
    extended_matrix
}
