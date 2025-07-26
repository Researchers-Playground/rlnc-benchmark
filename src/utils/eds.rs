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
    let mut extended_matrix: Vec<Vec<Vec<u8>>> = Vec::new();

    // Create 2k×2k matrix
    for row in 0..2 * k {
        let mut extended_row: Vec<Vec<u8>> = Vec::new();

        for col in 0..2 * k {
            if row < k && col < k {
                // Quadrant 1: Original data
                extended_row.push(original_matrix[row][col].clone());
            } else {
                // Quadrants 2, 3, 4: Parity data (will be filled)
                extended_row.push(vec![0u8; share_size]);
            }
        }

        extended_matrix.push(extended_row);
    }

    println!("Create extended {}x{} matrix successfully", 2 * k, 2 * k);
    extended_matrix
}
