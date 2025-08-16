pub trait FieldScalar:
    Clone
    + Default
    + PartialEq
    + std::ops::Add<Output = Self>
    + std::ops::Sub<Output = Self>
    + std::ops::Mul<Output = Self>
    + std::ops::SubAssign
    + Copy
    + std::iter::Sum
    + std::fmt::Debug
{
    fn zero() -> Self;
    fn one() -> Self;
    fn invert(self) -> Self;
}
