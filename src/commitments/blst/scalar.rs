use blst::*;
use rand::Rng;
use std::fmt;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use thiserror::Error;

use crate::utils::field::FieldScalar;

#[derive(Error, Debug)]
pub enum ScalarError {
    #[error("Invalid: {0}")]
    Invalid(String),
}

/// Blst-based scalar field element
/// Uses byte array for Copy trait support
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Scalar {
    pub bytes: [u8; 32],
}

impl Scalar {
    pub fn new() -> Self {
        Self { bytes: [0u8; 32] }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ScalarError> {
        if bytes.len() != 32 {
            return Err(ScalarError::Invalid(
                "Invalid scalar byte length".to_string(),
            ));
        }

        let mut byte_array = [0u8; 32];
        byte_array.copy_from_slice(bytes);
        Ok(Self { bytes: byte_array })
    }

    pub fn from_u64(val: u64) -> Self {
        let mut fr = blst_fr::default();
        unsafe {
            blst_fr_from_uint64(&mut fr, [val, 0, 0, 0].as_ptr());
        }
        let mut bytes = [0u8; 32];
        unsafe {
            // Convert fr to bytes via scalar
            let mut scalar = blst_scalar::default();
            blst_scalar_from_fr(&mut scalar, &fr);
            blst_bendian_from_scalar(bytes.as_mut_ptr(), &scalar);
        }
        Self { bytes }
    }

    pub fn random<R: Rng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        // Ensure the scalar is valid by reducing modulo field order
        let scalar = Self::from_bytes_unchecked(bytes);
        scalar
    }

    fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn to_blst_fr(&self) -> blst_fr {
        let mut scalar = blst_scalar::default();
        let mut fr = blst_fr::default();
        unsafe {
            blst_scalar_from_be_bytes(&mut scalar, self.bytes.as_ptr(), 32);
            blst_fr_from_scalar(&mut fr, &scalar);
        }
        fr
    }

    pub fn from_blst_fr(fr: &blst_fr) -> Self {
        let mut scalar = blst_scalar::default();
        let mut bytes = [0u8; 32];
        unsafe {
            blst_scalar_from_fr(&mut scalar, fr);
            blst_bendian_from_scalar(bytes.as_mut_ptr(), &scalar);
        }
        Self { bytes }
    }

    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    pub fn neg(&self) -> Self {
        let fr = self.to_blst_fr();
        let mut result = blst_fr::default();
        unsafe {
            blst_fr_cneg(&mut result, &fr, true);
        }
        Self::from_blst_fr(&result)
    }

    pub fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        let fr = self.to_blst_fr();
        let mut result = blst_fr::default();
        unsafe {
            blst_fr_inverse(&mut result, &fr);
        }
        Some(Self::from_blst_fr(&result))
    }

    pub fn pow(&self, exp: u64) -> Self {
        let mut result = Self::one();
        let mut base = *self;
        let mut e = exp;

        while e > 0 {
            if e & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            e >>= 1;
        }

        result
    }

    /// Get the internal bytes representation
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Create from raw bytes without validation
    pub fn from_raw_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

// Arithmetic operations
impl Add for Scalar {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let a = self.to_blst_fr();
        let b = other.to_blst_fr();
        let mut result = blst_fr::default();
        unsafe {
            blst_fr_add(&mut result, &a, &b);
        }
        Self::from_blst_fr(&result)
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let a = self.to_blst_fr();
        let b = other.to_blst_fr();
        let mut result = blst_fr::default();
        unsafe {
            blst_fr_sub(&mut result, &a, &b);
        }
        Self::from_blst_fr(&result)
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let a = self.to_blst_fr();
        let b = other.to_blst_fr();
        let mut result = blst_fr::default();
        unsafe {
            blst_fr_mul(&mut result, &a, &b);
        }
        Self::from_blst_fr(&result)
    }
}

impl AddAssign for Scalar {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl SubAssign for Scalar {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl MulAssign for Scalar {
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self {
        // Use the explicit method to avoid infinite recursion
        let fr = self.to_blst_fr();
        let mut result = blst_fr::default();
        unsafe {
            blst_fr_cneg(&mut result, &fr, true);
        }
        Self::from_blst_fr(&result)
    }
}

impl Sum for Scalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |acc, x| acc + x)
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_string = self
            .bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        write!(f, "Scalar({})", hex_string)
    }
}

// Conversions
impl From<u8> for Scalar {
    fn from(val: u8) -> Self {
        Self::from_u64(val as u64)
    }
}

impl From<u32> for Scalar {
    fn from(val: u32) -> Self {
        Self::from_u64(val as u64)
    }
}

impl From<u64> for Scalar {
    fn from(val: u64) -> Self {
        Self::from_u64(val)
    }
}

// FieldScalar trait implementation
impl FieldScalar for Scalar {
    fn zero() -> Self {
        Self::new()
    }

    fn one() -> Self {
        Self::from_u64(1)
    }

    fn invert(self) -> Self {
        if self.is_zero() {
            panic!("Cannot invert zero element");
        }

        let fr = self.to_blst_fr();
        let mut result = blst_fr::default();
        unsafe {
            blst_fr_inverse(&mut result, &fr);
        }
        Self::from_blst_fr(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_scalar_basic_operations() {
        let zero = Scalar::zero();
        let one = Scalar::one();
        let two = Scalar::from(2u32);
        let three = Scalar::from(3u32);

        // Test zero
        assert!(zero.is_zero());
        assert!(!one.is_zero());

        // Test addition
        assert_eq!(one + one, two);
        assert_eq!(two + one, three);
        assert_eq!(zero + one, one);

        // Test subtraction
        assert_eq!(three - one, two);
        assert_eq!(two - two, zero);

        // Test multiplication
        assert_eq!(two * two, Scalar::from(4u32));
        assert_eq!(three * two, Scalar::from(6u32));
        assert_eq!(zero * three, zero);
        assert_eq!(one * three, three);
    }

    #[test]
    fn test_scalar_assign_operations() {
        let mut a = Scalar::from(5u32);
        let b = Scalar::from(3u32);

        // Test AddAssign
        a += b;
        assert_eq!(a, Scalar::from(8u32));

        // Test SubAssign
        a -= b;
        assert_eq!(a, Scalar::from(5u32));

        // Test MulAssign
        a *= b;
        assert_eq!(a, Scalar::from(15u32));
    }

    #[test]
    fn test_scalar_inversion() {
        let two = Scalar::from(2u32);
        let three = Scalar::from(3u32);

        // Test inversion
        let two_inv = two.invert();
        assert_eq!(two * two_inv, Scalar::one());

        let three_inv = three.invert();
        assert_eq!(three * three_inv, Scalar::one());

        // Test optional inversion
        assert!(two.inverse().is_some());
        assert!(Scalar::zero().inverse().is_none());
    }

    #[test]
    #[should_panic(expected = "Cannot invert zero element")]
    fn test_scalar_invert_zero_panics() {
        let zero = Scalar::zero();
        zero.invert();
    }

    #[test]
    fn test_scalar_field_properties() {
        let a = Scalar::from(7u32);
        let b = Scalar::from(13u32);
        let c = Scalar::from(19u32);

        // Commutativity: a + b = b + a
        assert_eq!(a + b, b + a);
        assert_eq!(a * b, b * a);

        // Associativity: (a + b) + c = a + (b + c)
        assert_eq!((a + b) + c, a + (b + c));
        assert_eq!((a * b) * c, a * (b * c));

        // Distributivity: a * (b + c) = a * b + a * c
        assert_eq!(a * (b + c), a * b + a * c);

        // Identity elements
        assert_eq!(a + Scalar::zero(), a);
        assert_eq!(a * Scalar::one(), a);
    }

    #[test]
    fn test_scalar_pow() {
        let base = Scalar::from(2u32);

        assert_eq!(base.pow(0), Scalar::one());
        assert_eq!(base.pow(1), base);
        assert_eq!(base.pow(2), Scalar::from(4u32));
        assert_eq!(base.pow(3), Scalar::from(8u32));
        assert_eq!(base.pow(10), Scalar::from(1024u32));

        // Test with zero
        assert_eq!(Scalar::zero().pow(5), Scalar::zero());
        assert_eq!(Scalar::zero().pow(0), Scalar::one()); // 0^0 = 1 by convention
    }

    #[test]
    fn test_scalar_negation() {
        let a = Scalar::from(5u32);
        let neg_a = a.neg();

        // a + (-a) = 0
        assert_eq!(a + neg_a, Scalar::zero());

        // -(-a) = a
        assert_eq!(neg_a.neg(), a);

        // -(0) = 0
        assert_eq!(Scalar::zero().neg(), Scalar::zero());

        // Test Neg trait (unary minus operator)
        let b = Scalar::from(7u32);
        let neg_b = -b;
        assert_eq!(b + neg_b, Scalar::zero());
        assert_eq!(neg_b, b.neg());

        // Test chaining: -(-a) = a using operator
        assert_eq!(-(-a), a);
    }

    #[test]
    fn test_scalar_conversions() {
        // Test From<u8>
        let from_u8 = Scalar::from(255u8);
        assert_eq!(from_u8, Scalar::from_u64(255));

        // Test From<u32>
        let from_u32 = Scalar::from(0xDEADBEEFu32);
        assert_eq!(from_u32, Scalar::from_u64(0xDEADBEEF));

        // Test From<u64>
        let from_u64 = Scalar::from(0x123456789ABCDEFu64);
        assert_eq!(from_u64, Scalar::from_u64(0x123456789ABCDEF));
    }

    #[test]
    fn test_scalar_bytes_roundtrip() {
        let original = Scalar::from(0x123456789ABCDEFu64);
        let bytes = original.to_bytes();
        let reconstructed = Scalar::from_raw_bytes(bytes);

        assert_eq!(original, reconstructed);
    }

    #[test]
    fn test_scalar_blst_roundtrip() {
        let original = Scalar::from(42u32);
        let blst_fr = original.to_blst_fr();
        let reconstructed = Scalar::from_blst_fr(&blst_fr);

        assert_eq!(original, reconstructed);
    }

    #[test]
    fn test_scalar_random() {
        let mut rng = StdRng::seed_from_u64(42);

        let s1 = Scalar::random(&mut rng);
        let s2 = Scalar::random(&mut rng);

        // Random scalars should be different (with very high probability)
        assert_ne!(s1, s2);

        // Random scalars should satisfy field properties
        let s3 = Scalar::random(&mut rng);
        assert_eq!(s1 + s2, s2 + s1);
        assert_eq!(s1 * (s2 + s3), s1 * s2 + s1 * s3);
    }

    #[test]
    fn test_scalar_sum() {
        let scalars = vec![
            Scalar::from(1u32),
            Scalar::from(2u32),
            Scalar::from(3u32),
            Scalar::from(4u32),
        ];

        let sum: Scalar = scalars.into_iter().sum();
        assert_eq!(sum, Scalar::from(10u32));

        // Empty sum should be zero
        let empty_sum: Scalar = vec![].into_iter().sum();
        assert_eq!(empty_sum, Scalar::zero());
    }

    #[test]
    fn test_field_scalar_trait() {
        // Test FieldScalar trait methods
        assert_eq!(Scalar::zero(), Scalar::new());
        assert_eq!(Scalar::one(), Scalar::from(1u32));

        let a = Scalar::from(7u32);
        let a_inv = a.invert();
        assert_eq!(a * a_inv, Scalar::one());
    }

    #[test]
    fn test_scalar_display() {
        let zero = Scalar::zero();
        let one = Scalar::one();

        // Should not panic and should contain "Scalar"
        let zero_str = format!("{}", zero);
        let one_str = format!("{}", one);

        assert!(zero_str.contains("Scalar"));
        assert!(one_str.contains("Scalar"));
        assert_ne!(zero_str, one_str);
    }

    #[test]
    fn test_large_numbers() {
        let large1 = Scalar::from(u64::MAX);
        let large2 = Scalar::from(u64::MAX - 1);

        // Should not panic with large numbers
        let sum = large1 + large2;
        let product = large1 * large2;
        let difference = large1 - large2;

        // These operations should complete without panic
        assert!(!sum.is_zero());
        assert!(!product.is_zero());
        assert_eq!(difference, Scalar::one());
    }

    #[test]
    fn test_bytes_validation() {
        // Valid 32-byte array
        let valid_bytes = [1u8; 32];
        assert!(Scalar::from_bytes(&valid_bytes).is_ok());

        // Invalid length arrays
        let short_bytes = [1u8; 16];
        let long_bytes = [1u8; 64];

        assert!(Scalar::from_bytes(&short_bytes).is_err());
        assert!(Scalar::from_bytes(&long_bytes).is_err());
    }
}
