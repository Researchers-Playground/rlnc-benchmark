use rand::Rng;
use std::collections::HashMap;

// A perfect hash function -> mock
pub struct Oracle {
    assignments: HashMap<usize, Vec<usize>>,
    block_size: usize,
    share_size: usize,
    pub num_shreds: usize,
}

impl Oracle {
    pub fn new(block_size: usize, share_size: usize) -> Self {
        let k = (block_size / share_size).isqrt();
        Oracle {
            assignments: HashMap::new(),
            block_size,
            share_size,
            num_shreds: k,
        }
    }

    pub fn assign_shreds(&mut self, node_ids: &[usize], num_shreds_per_node: usize) {
        let mut rng = rand::rng();
        let mut available_shreds: Vec<usize> = (0..self.num_shreds).collect();
        for &node_id in node_ids {
            let mut node_shreds = Vec::new();
            for _ in 0..num_shreds_per_node {
                if available_shreds.is_empty() {
                    break;
                }
                let index = rng.random_range(0..available_shreds.len());
                node_shreds.push(available_shreds.remove(index));
            }
            self.assignments.insert(node_id, node_shreds);
        }
    }

    pub fn get_shreds_for_node(&self, node_id: usize) -> Option<&Vec<usize>> {
        self.assignments.get(&node_id)
    }

    pub fn get_nodes_for_shred(&self, shred_id: usize) -> Vec<usize> {
        self.assignments
            .iter()
            .filter(|(_, shreds)| shreds.contains(&shred_id))
            .map(|(&node_id, _)| node_id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle_assign_shreds() {
        let mut oracle = Oracle::new(2 * 1024 * 1024, 512); // block 2MB, share size 512
        let node_ids = vec![0, 1, 2];
        oracle.assign_shreds(&node_ids, 2);
        assert_eq!(oracle.get_shreds_for_node(0).unwrap().len(), 2);
        assert_eq!(oracle.get_shreds_for_node(1).unwrap().len(), 2);
        assert_eq!(oracle.get_shreds_for_node(2).unwrap().len(), 2);
        // Kiểm tra shred_id hợp lệ
        let shred_id = oracle.get_shreds_for_node(0).unwrap()[0];
        assert!(oracle.get_nodes_for_shred(shred_id).contains(&0));
    }
}