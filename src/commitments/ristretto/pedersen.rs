use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand::Rng;

pub struct PedersenCommitter {
    generators: Vec<RistrettoPoint>,
}

impl PedersenCommitter {
    pub fn new(n: usize) -> Self {
        PedersenCommitter {
            generators: generators(n),
        }
    }

    pub fn len(&self) -> usize {
        self.generators.len()
    }

    pub fn commit(&self, scalars: &[Scalar]) -> Result<RistrettoPoint, String> {
        if scalars.len() > self.generators.len() {
            return Err(format!(
                "Chunk size is too large, {} > {}",
                scalars.len(),
                self.generators.len()
            ));
        }
        Ok(RistrettoPoint::multiscalar_mul(
            scalars,
            &self.generators[..scalars.len()],
        ))
    }
}

fn generators(n: usize) -> Vec<RistrettoPoint> {
    let mut rng = rand::rng();
    (0..n)
        .map(|_| RISTRETTO_BASEPOINT_POINT * Scalar::from(rng.random::<u128>()))
        .collect()
}
