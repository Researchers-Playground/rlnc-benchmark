use crate::utils::ristretto::chunk_to_scalars;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand::Rng;

pub struct Committer {
    generators: Vec<RistrettoPoint>,
}

impl Committer {
    pub fn new(n: usize) -> Self {
        Committer {
            generators: generators(n),
        }
    }

    pub fn len(&self) -> usize {
        self.generators.len()
    }

    pub fn commit(&self, data: &[u8]) -> Result<RistrettoPoint, String> {
        let scalars = chunk_to_scalars(data)?;
        if scalars.len() > self.generators.len() {
            return Err("Chunk size is too large".to_string());
        }
        let point =
            RistrettoPoint::multiscalar_mul(scalars.clone(), &self.generators[..scalars.len()]);
        Ok(point)
    }
}

fn generators(n: usize) -> Vec<RistrettoPoint> {
    let mut rng = rand::rng();
    (0..n)
        .map(|_| RISTRETTO_BASEPOINT_POINT * Scalar::from(rng.random::<u128>()))
        .collect()
}
