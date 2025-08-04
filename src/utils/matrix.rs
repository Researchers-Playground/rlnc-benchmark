use curve25519_dalek::Scalar;
/*
Echelon is a structure that keeps both the echelon form of a matrix and the transoformations
necessary to obtain these form. Self consistency
of the matrices is enforced as transform * coefficients = echelon. The matrix transform consists
of products of elementary row operations, it is built sequentially as each incoming message arrives.
as such, when importing the i-th message, no elementary transformation has touched that row before,
thus the matrix before importing this message has a block structure
[ A | 0 ]
[ 0 | I ]
where A is the transformation matrix for the first i-1 messages and I is the identity
for the rest of the rows.

We could in principle work with smaller integer matrices like u64 instead of Scalar, but care
needs to be taken to prevent the integers to grow with the number of rows. Implementing something
like Bareiss' seems overkill at this stage.
*/
pub struct Echelon {
    coefficients: Vec<Vec<Scalar>>,
    echelon: Vec<Vec<Scalar>>,
    transform: Vec<Vec<Scalar>>,
}

impl Echelon {
    pub fn new(size: usize) -> Self {
        let mut transform = vec![vec![Scalar::ZERO; size]; size];
        (0..size).for_each(|i| transform[i][i] = Scalar::ONE);

        Echelon {
            coefficients: Vec::new(),
            echelon: Vec::new(),
            transform,
        }
    }

    pub fn new_identity(size: usize) -> Self {
        let mut echelon = vec![vec![Scalar::ZERO; size]; size];
        (0..size).for_each(|i| echelon[i][i] = Scalar::ONE);
        let transform = echelon.clone();
        let coefficients = echelon.clone();

        Echelon {
            coefficients,
            echelon,
            transform,
        }
    }

    // is_full returns if the echelon form is square.
    pub fn is_full(&self) -> bool {
        if self.coefficients.is_empty() {
            return false;
        }
        self.coefficients.len() == self.coefficients[0].len()
    }

    // add_row adds a row to the coefficients matrix and updates the echelon form and the transform.
    // It returns false if the row is linearly dependent with the previous ones.
    pub fn add_row(&mut self, row: Vec<Scalar>) -> bool {
        if row.iter().all(|x| *x == Scalar::ZERO) {
            return false;
        }
        let current_size = self.coefficients.len();
        if current_size == row.len() {
            return false;
        }
        if current_size == 0 {
            self.echelon
                .push(row.iter().map(|x| Scalar::from(*x)).collect());
            self.coefficients.push(row);
            return true;
        }
        let mut tr = self.transform[current_size].clone();
        let mut i = 0;
        let mut j: usize;
        let mut new_echelon_row: Vec<Scalar> = row.iter().map(|x| Scalar::from(*x)).collect();
        while i < current_size {
            j = first_entry(&self.echelon[i]).unwrap();
            let k = match first_entry(&new_echelon_row) {
                Some(val) => val,
                None => return false,
            };
            if j < k {
                i += 1;
                continue;
            }
            if j > k {
                break;
            }
            let pivot = self.echelon[i][j];
            let f = new_echelon_row[j];
            new_echelon_row
                .iter_mut()
                .zip(self.echelon[i].iter())
                .for_each(|(x, y)| *x = pivot * (*x) - y * f);
            tr.iter_mut()
                .zip(self.transform[i].iter())
                .for_each(|(x, y)| *x = pivot * (*x) - y * f);
            i += 1;
        }
        if new_echelon_row.iter().all(|x| *x == Scalar::ZERO) {
            return false;
        }
        self.echelon.insert(i, new_echelon_row);
        self.coefficients.push(row);
        if i < current_size {
            self.transform.remove(current_size);
            self.transform.insert(i, tr);
            return true;
        }
        self.transform[i] = tr;
        return true;
    }

    // compound_scalars performs a matrix multiplications. The node coefficients are kept as u32
    // while the chosen scalars are u8, we are under the assumption that there are less than 24 hops
    // and thus this operation will not overflow.
    pub fn compound_scalars(&self, scalars: &[u8]) -> Vec<Scalar> {
        (0..self.transform.len())
            .map(|j| {
                scalars
                    .iter()
                    .zip(self.coefficients.iter())
                    .map(|(x, coeffs)| Scalar::from(*x) * coeffs[j])
                    .sum()
            })
            .collect()
    }

    pub fn inverse(&self) -> Result<Vec<Vec<Scalar>>, String> {
        if self.coefficients.is_empty() {
            return Err("No coefficients to decode".to_string());
        }
        if self.echelon.len() != self.coefficients[0].len() {
            return Err("The echelon form is not square".to_string());
        }
        let mut inverse = self.transform.clone();
        for i in (0..self.echelon.len()).rev() {
            let pivot = self.echelon[i][i].invert();
            inverse[i].iter_mut().for_each(|x| *x = *x * pivot);
            for j in (i + 1)..self.echelon.len() {
                let diff = self.echelon[i][j] * pivot;
                for k in 0..self.echelon.len() {
                    let actual_diff = inverse[j][k] * diff;
                    inverse[i][k] -= actual_diff;
                }
            }
        }
        Ok(inverse)
    }
}

fn first_entry<T: PartialEq + Default>(slice: &[T]) -> Option<usize> {
    let zero = T::default();
    slice.iter().position(|x| x != &zero)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::Scalar;

    #[test]
    fn test_add_row() {
        let mut echelon = Echelon::new(3);
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(0u32),
                Scalar::from(0u32),
                Scalar::from(0u32)
            ]),
            false
        );
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(0u32),
                Scalar::from(0u32),
                Scalar::from(1u32)
            ]),
            true
        );
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(0u32),
                Scalar::from(0u32),
                Scalar::from(1u32)
            ]),
            false
        );
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(0u32),
                Scalar::from(1u32),
                Scalar::from(0u32)
            ]),
            true
        );
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(0u32),
                Scalar::from(1u32),
                Scalar::from(0u32)
            ]),
            false
        );
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(1u32),
                Scalar::from(0u32),
                Scalar::from(0u32)
            ]),
            true
        );
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(1u32),
                Scalar::from(0u32),
                Scalar::from(0u32)
            ]),
            false
        );
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(1u32),
                Scalar::from(1u32),
                Scalar::from(1u32)
            ]),
            false
        );
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(0u32),
                Scalar::from(1u32),
                Scalar::from(1u32)
            ]),
            false
        );
        echelon = Echelon::new(3);
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(0u32),
                Scalar::from(1u32),
                Scalar::from(0u32)
            ]),
            true
        );
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(0u32),
                Scalar::from(2u32),
                Scalar::from(3u32)
            ]),
            true
        );
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(5u32),
                Scalar::from(0u32),
                Scalar::from(1u32)
            ]),
            true
        );
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(2u32),
                Scalar::from(0u32),
                Scalar::from(1u32)
            ]),
            false
        );
        echelon = Echelon::new(3);
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(2u32),
                Scalar::from(1u32),
                Scalar::from(0u32)
            ]),
            true
        );
        assert_eq!(
            echelon.add_row(vec![
                Scalar::from(3u32),
                Scalar::from(2u32),
                Scalar::from(1u32)
            ]),
            true
        );
    }

    #[test]
    fn test_inverse() {
        let mut echelon = Echelon::new(3);
        assert_eq!(echelon.inverse().is_err(), true);
        echelon.add_row(vec![
            Scalar::from(1u32),
            Scalar::from(0u32),
            Scalar::from(0u32),
        ]);
        echelon.add_row(vec![
            Scalar::from(0u32),
            Scalar::from(1u32),
            Scalar::from(0u32),
        ]);
        echelon.add_row(vec![
            Scalar::from(0u32),
            Scalar::from(0u32),
            Scalar::from(1u32),
        ]);
        let inverse = echelon.inverse().unwrap();
        assert_eq!(inverse[0][0], Scalar::from(1u32));
        assert_eq!(inverse[0][1], Scalar::from(0u32));

        echelon = Echelon::new(2);
        assert_eq!(echelon.inverse().is_err(), true);
        echelon.add_row(vec![Scalar::from(2u32), Scalar::from(5u32)]);
        echelon.add_row(vec![Scalar::from(1u32), Scalar::from(3u32)]);
        let inverse = echelon.inverse().unwrap();
        assert_eq!(inverse[0][0], Scalar::from(3u32));
        assert_eq!(inverse[0][1], -Scalar::from(5u32));
        assert_eq!(inverse[1][0], -Scalar::from(1u32));
        assert_eq!(inverse[1][1], Scalar::from(2u32));
    }

    #[test]
    fn test_compound_scalars() {
        let echelon = Echelon::new(3);
        assert_eq!(
            echelon.compound_scalars(&[1, 2, 3]),
            vec![Scalar::from(0u32), Scalar::from(0u32), Scalar::from(0u32)]
        );
        let mut echelon = Echelon::new(3);
        echelon.add_row(vec![
            Scalar::from(2u32),
            Scalar::from(0u32),
            Scalar::from(0u32),
        ]);
        echelon.add_row(vec![
            Scalar::from(0u32),
            Scalar::from(3u32),
            Scalar::from(1u32),
        ]);
        assert_eq!(
            echelon.compound_scalars(&[3, 5]),
            vec![Scalar::from(6u32), Scalar::from(15u32), Scalar::from(5u32)]
        );
    }
}
