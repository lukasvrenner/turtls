pub mod affine;
pub mod projective;

pub use affine::AffinePoint;
pub use projective::ProjectivePoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AffineInfinity;

impl core::fmt::Display for AffineInfinity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the point at inifinity cannot be represented in affine coordinates")
    }
}

impl core::error::Error for AffineInfinity {}
