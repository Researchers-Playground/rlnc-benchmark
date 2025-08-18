use crate::commitments::blst::scalar::Scalar;

pub fn coefficients_to_scalars(coefficients: &[u8]) -> Vec<Scalar> {
    coefficients.iter().map(|&x| Scalar::from(x)).collect()
}
