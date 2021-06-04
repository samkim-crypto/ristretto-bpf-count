//! Group operations for Curve25519, in Edwards form.
//!
//! ## Encoding and Decoding
//!
//! Encoding is done by converting to and from a `CompressedEdwardsY`
//! struct, which is a typed wrapper around `[u8; 32]`.
//!
//! ## Equality Testing
//!
//! The `EdwardsPoint` struct implements the `subtle::ConstantTimeEq`
//! trait for constant-time equality checking, and the Rust `Eq` trait
//! for variable-time equality checking.
//!
//! ## Cofactor-related functions
//!
//! The order of the group of points on the curve \\(\mathcal E\\)
//! is \\(|\mathcal E| = 8\ell \\), so its structure is \\( \mathcal
//! E = \mathcal E[8] \times \mathcal E[\ell]\\).  The torsion
//! subgroup \\( \mathcal E[8] \\) consists of eight points of small
//! order.  Technically, all of \\(\mathcal E\\) is torsion, but we
//! use the word only to refer to the small \\(\mathcal E[8]\\) part, not
//! the large prime-order \\(\mathcal E[\ell]\\) part.
//!
//! To test if a point is in \\( \mathcal E[8] \\), use
//! `EdwardsPoint::is_small_order()`.
//!
//! To test if a point is in \\( \mathcal E[\ell] \\), use
//! `EdwardsPoint::is_torsion_free()`.
//!
//! To multiply by the cofactor, use `EdwardsPoint::mul_by_cofactor()`.
//!
//! To avoid dealing with cofactors entirely, consider using Ristretto.
//!
//! ## Scalars
//!
//! Scalars are represented by the `Scalar` struct.  To construct a scalar with a specific bit
//! pattern, see `Scalar::from_bits()`.
//!
//! ## Scalar Multiplication
//!
//! Scalar multiplication on Edwards points is provided by:
//!
//! * the `*` operator between a `Scalar` and a `EdwardsPoint`, which
//! performs constant-time variable-base scalar multiplication;
//!
//! * the `*` operator between a `Scalar` and a
//! `EdwardsBasepointTable`, which performs constant-time fixed-base
//! scalar multiplication;
//!
//! * an implementation of the
//! [`MultiscalarMul`](../traits/trait.MultiscalarMul.html) trait for
//! constant-time variable-base multiscalar multiplication;
//!
//! * an implementation of the
//! [`VartimeMultiscalarMul`](../traits/trait.VartimeMultiscalarMul.html)
//! trait for variable-time variable-base multiscalar multiplication;
//!
//! ## Implementation
//!
//! The Edwards arithmetic is implemented using the “extended twisted
//! coordinates” of Hisil, Wong, Carter, and Dawson, and the
//! corresponding complete formulas.  For more details,
//! see the [`curve_models` submodule][curve_models]
//! of the internal documentation.
//!
//! ## Validity Checking
//!
//! There is no function for checking whether a point is valid.
//! Instead, the `EdwardsPoint` struct is guaranteed to hold a valid
//! point on the curve.
//!
//! We use the Rust type system to make invalid points
//! unrepresentable: `EdwardsPoint` objects can only be created via
//! successful decompression of a compressed point, or else by
//! operations on other (valid) `EdwardsPoint`s.
//!
//! [curve_models]: https://doc-internal.dalek.rs/curve25519_dalek/backend/serial/curve_models/index.html

// We allow non snake_case names because coordinates in projective space are
// traditionally denoted by the capitalisation of their respective
// counterparts in affine space.  Yeah, you heard me, rustc, I'm gonna have my
// affine and projective cakes and eat both of them too.
#![allow(non_snake_case)]

use core::borrow::Borrow;
use core::fmt::Debug;
use core::iter::Iterator;
use core::iter::Sum;
use core::ops::{Add, Neg, Sub};
use core::ops::{AddAssign, SubAssign};
use core::ops::{Mul, MulAssign};

use subtle::Choice;
use subtle::ConditionallyNegatable;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;

use crate::constants;

use crate::field::FieldElement;
use crate::scalar::Scalar;

use crate::backend::variable_base;

// use montgomery::MontgomeryPoint;

use crate::backend::curve_models::AffineNielsPoint;
use crate::backend::curve_models::CompletedPoint;
use crate::backend::curve_models::ProjectiveNielsPoint;
use crate::backend::curve_models::ProjectivePoint;

use crate::window::LookupTable;
use crate::window::LookupTableRadix16;
use crate::window::LookupTableRadix32;
use crate::window::LookupTableRadix64;
use crate::window::LookupTableRadix128;
use crate::window::LookupTableRadix256;

// use crate::traits::BasepointTable;
use crate::traits::ValidityCheck;
use crate::traits::{Identity, IsIdentity};

use borsh::BorshSerialize;
use borsh::BorshDeserialize;

// use traits::MultiscalarMul;
// use traits::{VartimeMultiscalarMul, VartimePrecomputedMultiscalarMul};

// use backend::serial::scalar_mul;

// ------------------------------------------------------------------------
// Compressed points
// ------------------------------------------------------------------------

/// In "Edwards y" / "Ed25519" format, the curve point \\((x,y)\\) is
/// determined by the \\(y\\)-coordinate and the sign of \\(x\\).
///
/// The first 255 bits of a `CompressedEdwardsY` represent the
/// \\(y\\)-coordinate.  The high bit of the 32nd byte gives the sign of \\(x\\).
#[derive(Copy, Clone, Eq, PartialEq, Hash, BorshSerialize, BorshDeserialize)]
pub struct CompressedEdwardsY(pub [u8; 32]);

impl ConstantTimeEq for CompressedEdwardsY {
    fn ct_eq(&self, other: &CompressedEdwardsY) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl Debug for CompressedEdwardsY {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "CompressedEdwardsY: {:?}", self.as_bytes())
    }
}

impl CompressedEdwardsY {
    /// View this `CompressedEdwardsY` as an array of bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Copy this `CompressedEdwardsY` to an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Attempt to decompress to an `EdwardsPoint`.
    ///
    /// Returns `None` if the input is not the \\(y\\)-coordinate of a
    /// curve point.
    pub fn decompress(&self) -> Option<EdwardsPoint> {
        let Y = FieldElement::from_bytes(self.as_bytes());
        let Z = FieldElement::one();
        let YY = Y.square();
        let u = &YY - &Z;                            // u =  y²-1
        let v = &(&YY * &constants::EDWARDS_D) + &Z; // v = dy²+1
        let (is_valid_y_coord, mut X) = FieldElement::sqrt_ratio_i(&u, &v);

        if is_valid_y_coord.unwrap_u8() != 1u8 { return None; }

         // FieldElement::sqrt_ratio_i always returns the nonnegative square root,
         // so we negate according to the supplied sign bit.
        let compressed_sign_bit = Choice::from(self.as_bytes()[31] >> 7);
        X.conditional_negate(compressed_sign_bit);

        Some(EdwardsPoint{ X, Y, Z, T: &X * &Y })
    }
}

// ------------------------------------------------------------------------
// Internal point representations
// ------------------------------------------------------------------------

/// An `EdwardsPoint` represents a point on the Edwards form of Curve25519.
#[derive(Copy, Clone)]
#[allow(missing_docs)]
pub struct EdwardsPoint {
    pub(crate) X: FieldElement,
    pub(crate) Y: FieldElement,
    pub(crate) Z: FieldElement,
    pub(crate) T: FieldElement,
}

// ------------------------------------------------------------------------
// Constructors
// ------------------------------------------------------------------------

impl Identity for CompressedEdwardsY {
    fn identity() -> CompressedEdwardsY {
        CompressedEdwardsY([1, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0])
    }
}

impl Default for CompressedEdwardsY {
    fn default() -> CompressedEdwardsY {
        CompressedEdwardsY::identity()
    }
}

impl CompressedEdwardsY {
    /// Construct a `CompressedEdwardsY` from a slice of bytes.
    ///
    /// # Panics
    ///
    /// If the input `bytes` slice does not have a length of 32.
    pub fn from_slice(bytes: &[u8]) -> CompressedEdwardsY {
        let mut tmp = [0u8; 32];

        tmp.copy_from_slice(bytes);

        CompressedEdwardsY(tmp)
    }
}

impl Identity for EdwardsPoint {
    fn identity() -> EdwardsPoint {
        EdwardsPoint {
            X: FieldElement::zero(),
            Y: FieldElement::one(),
            Z: FieldElement::one(),
            T: FieldElement::zero(),
        }
    }
}

impl Default for EdwardsPoint {
    fn default() -> EdwardsPoint {
        EdwardsPoint::identity()
    }
}

// ------------------------------------------------------------------------
// Validity checks (for debugging, not CT)
// ------------------------------------------------------------------------

impl ValidityCheck for EdwardsPoint {
    fn is_valid(&self) -> bool {
        let point_on_curve = self.to_projective().is_valid();
        let on_segre_image = (&self.X * &self.Y) == (&self.Z * &self.T);

        point_on_curve && on_segre_image
    }
}

// ------------------------------------------------------------------------
// Constant-time assignment
// ------------------------------------------------------------------------

impl ConditionallySelectable for EdwardsPoint {
    fn conditional_select(a: &EdwardsPoint, b: &EdwardsPoint, choice: Choice) -> EdwardsPoint {
        EdwardsPoint {
            X: FieldElement::conditional_select(&a.X, &b.X, choice),
            Y: FieldElement::conditional_select(&a.Y, &b.Y, choice),
            Z: FieldElement::conditional_select(&a.Z, &b.Z, choice),
            T: FieldElement::conditional_select(&a.T, &b.T, choice),
        }
    }
}

// ------------------------------------------------------------------------
// Equality
// ------------------------------------------------------------------------

impl ConstantTimeEq for EdwardsPoint {
    fn ct_eq(&self, other: &EdwardsPoint) -> Choice {
        // We would like to check that the point (X/Z, Y/Z) is equal to
        // the point (X'/Z', Y'/Z') without converting into affine
        // coordinates (x, y) and (x', y'), which requires two inversions.
        // We have that X = xZ and X' = x'Z'. Thus, x = x' is equivalent to
        // (xZ)Z' = (x'Z')Z, and similarly for the y-coordinate.

        (&self.X * &other.Z).ct_eq(&(&other.X * &self.Z))
            & (&self.Y * &other.Z).ct_eq(&(&other.Y * &self.Z))
    }
}

impl PartialEq for EdwardsPoint {
    fn eq(&self, other: &EdwardsPoint) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl Eq for EdwardsPoint {}

// ------------------------------------------------------------------------
// Point conversions
// ------------------------------------------------------------------------

impl EdwardsPoint {
    /// Convert to a ProjectiveNielsPoint
    pub(crate) fn to_projective_niels(&self) -> ProjectiveNielsPoint {
        ProjectiveNielsPoint{
            Y_plus_X:  &self.Y + &self.X,
            Y_minus_X: &self.Y - &self.X,
            Z:          self.Z,
            T2d:       &self.T * &constants::EDWARDS_D2,
        }
    }

    /// Convert the representation of this point from extended
    /// coordinates to projective coordinates.
    ///
    /// Free.
    pub(crate) fn to_projective(&self) -> ProjectivePoint {
        ProjectivePoint{
            X: self.X,
            Y: self.Y,
            Z: self.Z,
        }
    }

    /// Dehomogenize to a AffineNielsPoint.
    /// Mainly for testing.
    pub(crate) fn to_affine_niels(&self) -> AffineNielsPoint {
        let recip = self.Z.invert();
        let x = &self.X * &recip;
        let y = &self.Y * &recip;
        let xy2d = &(&x * &y) * &constants::EDWARDS_D2;
        AffineNielsPoint{
            y_plus_x:  &y + &x,
            y_minus_x: &y - &x,
            xy2d
        }
    }

    /// Convert this `EdwardsPoint` on the Edwards model to the
    /// corresponding `MontgomeryPoint` on the Montgomery model.
    ///
    /// This function has one exceptional case; the identity point of
    /// the Edwards curve is sent to the 2-torsion point \\((0,0)\\)
    /// on the Montgomery curve.
    ///
    /// Note that this is a one-way conversion, since the Montgomery
    /// model does not retain sign information.
//     pub fn to_montgomery(&self) -> MontgomeryPoint {
//         // We have u = (1+y)/(1-y) = (Z+Y)/(Z-Y).
//         //
//         // The denominator is zero only when y=1, the identity point of
//         // the Edwards curve.  Since 0.invert() = 0, in this case we
//         // compute the 2-torsion point (0,0).
//         let U = &self.Z + &self.Y;
//         let W = &self.Z - &self.Y;
//         let u = &U * &W.invert();
//         MontgomeryPoint(u.to_bytes())
//     }

    /// Compress this point to `CompressedEdwardsY` format.
    pub fn compress(&self) -> CompressedEdwardsY {
        let recip = self.Z.invert();
        let x = &self.X * &recip;
        let y = &self.Y * &recip;
        let mut s: [u8; 32];

        s = y.to_bytes();
        s[31] ^= x.is_negative().unwrap_u8() << 7;
        CompressedEdwardsY(s)
    }
}

// ------------------------------------------------------------------------
// Doubling
// ------------------------------------------------------------------------

impl EdwardsPoint {
    /// Add this point to itself.
    pub(crate) fn double(&self) -> EdwardsPoint {
        self.to_projective().double().to_extended()
    }
}

// ------------------------------------------------------------------------
// Addition and Subtraction
// ------------------------------------------------------------------------

impl<'a, 'b> Add<&'b EdwardsPoint> for &'a EdwardsPoint {
    type Output = EdwardsPoint;
    fn add(self, other: &'b EdwardsPoint) -> EdwardsPoint {
        (self + &other.to_projective_niels()).to_extended()
    }
}

define_add_variants!(LHS = EdwardsPoint, RHS = EdwardsPoint, Output = EdwardsPoint);

impl<'b> AddAssign<&'b EdwardsPoint> for EdwardsPoint {
    fn add_assign(&mut self, _rhs: &'b EdwardsPoint) {
        *self = (self as &EdwardsPoint) + _rhs;
    }
}

define_add_assign_variants!(LHS = EdwardsPoint, RHS = EdwardsPoint);

impl<'a, 'b> Sub<&'b EdwardsPoint> for &'a EdwardsPoint {
    type Output = EdwardsPoint;
    fn sub(self, other: &'b EdwardsPoint) -> EdwardsPoint {
        (self - &other.to_projective_niels()).to_extended()
    }
}

define_sub_variants!(LHS = EdwardsPoint, RHS = EdwardsPoint, Output = EdwardsPoint);

impl<'b> SubAssign<&'b EdwardsPoint> for EdwardsPoint {
    fn sub_assign(&mut self, _rhs: &'b EdwardsPoint) {
        *self = (self as &EdwardsPoint) - _rhs;
    }
}

define_sub_assign_variants!(LHS = EdwardsPoint, RHS = EdwardsPoint);

impl<T> Sum<T> for EdwardsPoint
where
    T: Borrow<EdwardsPoint>
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>
    {
        iter.fold(EdwardsPoint::identity(), |acc, item| acc + item.borrow())
    }
}


// ------------------------------------------------------------------------
// Negation
// ------------------------------------------------------------------------

impl<'a> Neg for &'a EdwardsPoint {
    type Output = EdwardsPoint;

    fn neg(self) -> EdwardsPoint {
        EdwardsPoint{
            X: -(&self.X),
            Y:  self.Y,
            Z:  self.Z,
            T: -(&self.T),
        }
    }
}

impl Neg for EdwardsPoint {
    type Output = EdwardsPoint;

    fn neg(self) -> EdwardsPoint {
        -&self
    }
}

// ------------------------------------------------------------------------
// Scalar multiplication
// ------------------------------------------------------------------------

impl<'b> MulAssign<&'b Scalar> for EdwardsPoint {
    fn mul_assign(&mut self, scalar: &'b Scalar) {
        let result = (self as &EdwardsPoint) * scalar;
        *self = result;
    }
}

define_mul_assign_variants!(LHS = EdwardsPoint, RHS = Scalar);

define_mul_variants!(LHS = EdwardsPoint, RHS = Scalar, Output = EdwardsPoint);
define_mul_variants!(LHS = Scalar, RHS = EdwardsPoint, Output = EdwardsPoint);

impl<'a, 'b> Mul<&'b Scalar> for &'a EdwardsPoint {
    type Output = EdwardsPoint;
    /// Scalar multiplication: compute `scalar * self`.
    ///
    /// For scalar multiplication of a basepoint,
    /// `EdwardsBasepointTable` is approximately 4x faster.
    fn mul(self, scalar: &'b Scalar) -> EdwardsPoint {
        variable_base::mul(self, scalar)
    }
}

impl<'a, 'b> Mul<&'b EdwardsPoint> for &'a Scalar {
    type Output = EdwardsPoint;

    /// Scalar multiplication: compute `scalar * self`.
    ///
    /// For scalar multiplication of a basepoint,
    /// `EdwardsBasepointTable` is approximately 4x faster.
    fn mul(self, point: &'b EdwardsPoint) -> EdwardsPoint {
        point * self
    }
}

// ------------------------------------------------------------------------
// Multiscalar Multiplication impls
// ------------------------------------------------------------------------

// These use the iterator's size hint and the target settings to
// forward to a specific backend implementation.

#[cfg(feature = "alloc")]
impl MultiscalarMul for EdwardsPoint {
    type Point = EdwardsPoint;

    fn multiscalar_mul<I, J>(scalars: I, points: J) -> EdwardsPoint
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<EdwardsPoint>,
    {
        // Sanity-check lengths of input iterators
        let mut scalars = scalars.into_iter();
        let mut points = points.into_iter();

        // Lower and upper bounds on iterators
        let (s_lo, s_hi) = scalars.by_ref().size_hint();
        let (p_lo, p_hi) = points.by_ref().size_hint();

        // They should all be equal
        assert_eq!(s_lo, p_lo);
        assert_eq!(s_hi, Some(s_lo));
        assert_eq!(p_hi, Some(p_lo));

        // Now we know there's a single size.  When we do
        // size-dependent algorithm dispatch, use this as the hint.
        let _size = s_lo;

        scalar_mul::straus::Straus::multiscalar_mul(scalars, points)
    }
}

#[cfg(feature = "alloc")]
impl VartimeMultiscalarMul for EdwardsPoint {
    type Point = EdwardsPoint;

    fn optional_multiscalar_mul<I, J>(scalars: I, points: J) -> Option<EdwardsPoint>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<EdwardsPoint>>,
    {
        // Sanity-check lengths of input iterators
        let mut scalars = scalars.into_iter();
        let mut points = points.into_iter();

        // Lower and upper bounds on iterators
        let (s_lo, s_hi) = scalars.by_ref().size_hint();
        let (p_lo, p_hi) = points.by_ref().size_hint();

        // They should all be equal
        assert_eq!(s_lo, p_lo);
        assert_eq!(s_hi, Some(s_lo));
        assert_eq!(p_hi, Some(p_lo));

        // Now we know there's a single size.
        // Use this as the hint to decide which algorithm to use.
        let size = s_lo;

        if size < 190 {
            scalar_mul::straus::Straus::optional_multiscalar_mul(scalars, points)
        } else {
            scalar_mul::pippenger::Pippenger::optional_multiscalar_mul(scalars, points)
        }
    }
}

/// Precomputation for variable-time multiscalar multiplication with `EdwardsPoint`s.
// This wraps the inner implementation in a facade type so that we can
// decouple stability of the inner type from the stability of the
// outer type.
#[cfg(feature = "alloc")]
pub struct VartimeEdwardsPrecomputation(scalar_mul::precomputed_straus::VartimePrecomputedStraus);

#[cfg(feature = "alloc")]
impl VartimePrecomputedMultiscalarMul for VartimeEdwardsPrecomputation {
    type Point = EdwardsPoint;

    fn new<I>(static_points: I) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<Self::Point>,
    {
        Self(scalar_mul::precomputed_straus::VartimePrecomputedStraus::new(static_points))
    }

    fn optional_mixed_multiscalar_mul<I, J, K>(
        &self,
        static_scalars: I,
        dynamic_scalars: J,
        dynamic_points: K,
    ) -> Option<Self::Point>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Scalar>,
        K: IntoIterator<Item = Option<Self::Point>>,
    {
        self.0
            .optional_mixed_multiscalar_mul(static_scalars, dynamic_scalars, dynamic_points)
    }
}

// impl EdwardsPoint {
//     /// Compute \\(aA + bB\\) in variable time, where \\(B\\) is the Ed25519 basepoint.
//     pub fn vartime_double_scalar_mul_basepoint(
//         a: &Scalar,
//         A: &EdwardsPoint,
//         b: &Scalar,
//     ) -> EdwardsPoint {
//         scalar_mul::vartime_double_base::mul(a, A, b)
//     }
// }

// macro_rules! impl_basepoint_table {
//     (Name = $name:ident, LookupTable = $table:ident, Point = $point:ty, Radix = $radix:expr, Additions = $adds:expr) => {
// 
// /// A precomputed table of multiples of a basepoint, for accelerating
// /// fixed-base scalar multiplication.  One table, for the Ed25519
// /// basepoint, is provided in the `constants` module.
// ///
// /// The basepoint tables are reasonably large, so they should probably be boxed.
// ///
// /// The sizes for the tables and the number of additions required for one scalar
// /// multiplication are as follows:
// ///
// /// * [`EdwardsBasepointTableRadix16`]: 30KB, 64A
// ///   (this is the default size, and is used for [`ED25519_BASEPOINT_TABLE`])
// /// * [`EdwardsBasepointTableRadix64`]: 120KB, 43A
// /// * [`EdwardsBasepointTableRadix128`]: 240KB, 37A
// /// * [`EdwardsBasepointTableRadix256`]: 480KB, 33A
// ///
// /// # Why 33 additions for radix-256?
// ///
// /// Normally, the radix-256 tables would allow for only 32 additions per scalar
// /// multiplication.  However, due to the fact that standardised definitions of
// /// legacy protocols—such as x25519—require allowing unreduced 255-bit scalar
// /// invariants, when converting such an unreduced scalar's representation to
// /// radix-\\(2^{8}\\), we cannot guarantee the carry bit will fit in the last
// /// coefficient (the coefficients are `i8`s).  When, \\(w\\), the power-of-2 of
// /// the radix, is \\(w < 8\\), we can fold the final carry onto the last
// /// coefficient, \\(d\\), because \\(d < 2^{w/2}\\), so
// /// $$
// ///     d + carry \cdot 2^{w} = d + 1 \cdot 2^{w} < 2^{w+1} < 2^{8}
// /// $$
// /// When \\(w = 8\\), we can't fit \\(carry \cdot 2^{w}\\) into an `i8`, so we
// /// add the carry bit onto an additional coefficient.
// #[derive(Clone)]
// pub struct $name(pub(crate) [$table<AffineNielsPoint>; 32]);
// 
// impl BasepointTable for $name {
//     type Point = $point;
// 
//     /// Create a table of precomputed multiples of `basepoint`.
//     fn create(basepoint: &$point) -> $name {
//         // XXX use init_with
//         let mut table = $name([$table::default(); 32]);
//         let mut P = *basepoint;
//         for i in 0..32 {
//             // P = (2w)^i * B
//             table.0[i] = $table::from(&P);
//             P = P.mul_by_pow_2($radix + $radix);
//         }
//         table
//     }
// 
//     /// Get the basepoint for this table as an `EdwardsPoint`.
//     fn basepoint(&self) -> $point {
//         // self.0[0].select(1) = 1*(16^2)^0*B
//         // but as an `AffineNielsPoint`, so add identity to convert to extended.
//         (&<$point>::identity() + &self.0[0].select(1)).to_extended()
//     }
// 
//     /// The computation uses Pippeneger's algorithm, as described for the
//     /// specific case of radix-16 on page 13 of the Ed25519 paper.
//     ///
//     /// # Piggenger's Algorithm Generalised
//     ///
//     /// Write the scalar \\(a\\) in radix-\\(w\\), where \\(w\\) is a power of
//     /// 2, with coefficients in \\([\frac{-w}{2},\frac{w}{2})\\), i.e.,
//     /// $$
//     ///     a = a\_0 + a\_1 w\^1 + \cdots + a\_{x} w\^{x},
//     /// $$
//     /// with
//     /// $$
//     ///     \frac{-w}{2} \leq a_i < \frac{w}{2}, \cdots, \frac{-w}{2} \leq a\_{x} \leq \frac{w}{2}
//     /// $$
//     /// and the number of additions, \\(x\\), is given by \\(x = \lceil \frac{256}{w} \rceil\\).
//     /// Then
//     /// $$
//     ///     a B = a\_0 B + a\_1 w\^1 B + \cdots + a\_{x-1} w\^{x-1} B.
//     /// $$
//     /// Grouping even and odd coefficients gives
//     /// $$
//     /// \begin{aligned}
//     ///     a B = \quad a\_0 w\^0 B +& a\_2 w\^2 B + \cdots + a\_{x-2} w\^{x-2} B    \\\\
//     ///               + a\_1 w\^1 B +& a\_3 w\^3 B + \cdots + a\_{x-1} w\^{x-1} B    \\\\
//     ///         = \quad(a\_0 w\^0 B +& a\_2 w\^2 B + \cdots + a\_{x-2} w\^{x-2} B)   \\\\
//     ///             + w(a\_1 w\^0 B +& a\_3 w\^2 B + \cdots + a\_{x-1} w\^{x-2} B).  \\\\
//     /// \end{aligned}
//     /// $$
//     /// For each \\(i = 0 \ldots 31\\), we create a lookup table of
//     /// $$
//     /// [w\^{2i} B, \ldots, \frac{w}{2}\cdotw\^{2i} B],
//     /// $$
//     /// and use it to select \\( y \cdot w\^{2i} \cdot B \\) in constant time.
//     ///
//     /// The radix-\\(w\\) representation requires that the scalar is bounded
//     /// by \\(2\^{255}\\), which is always the case.
//     ///
//     /// The above algorithm is trivially generalised to other powers-of-2 radices.
//     fn basepoint_mul(&self, scalar: &Scalar) -> $point {
//         let a = scalar.to_radix_2w($radix);
// 
//         let tables = &self.0;
//         let mut P = <$point>::identity();
// 
//         for i in (0..$adds).filter(|x| x % 2 == 1) {
//             P = (&P + &tables[i/2].select(a[i])).to_extended();
//         }
// 
//         P = P.mul_by_pow_2($radix);
// 
//         for i in (0..$adds).filter(|x| x % 2 == 0) {
//             P = (&P + &tables[i/2].select(a[i])).to_extended();
//         }
// 
//         P
//     }
// }
// 
// impl<'a, 'b> Mul<&'b Scalar> for &'a $name {
//     type Output = $point;
// 
//     /// Construct an `EdwardsPoint` from a `Scalar` \\(a\\) by
//     /// computing the multiple \\(aB\\) of this basepoint \\(B\\).
//     fn mul(self, scalar: &'b Scalar) -> $point {
//         // delegate to a private function so that its documentation appears in internal docs
//         self.basepoint_mul(scalar)
//     }
// }
// 
// impl<'a, 'b> Mul<&'a $name> for &'b Scalar {
//     type Output = $point;
// 
//     /// Construct an `EdwardsPoint` from a `Scalar` \\(a\\) by
//     /// computing the multiple \\(aB\\) of this basepoint \\(B\\).
//     fn mul(self, basepoint_table: &'a $name) -> $point {
//         basepoint_table * self
//     }
// }
// 
// impl Debug for $name {
//     fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
//         write!(f, "{:?}([\n", stringify!($name))?;
//         for i in 0..32 {
//             write!(f, "\t{:?},\n", &self.0[i])?;
//         }
//         write!(f, "])")
//     }
// }
// 
// }} // End macro_rules! impl_basepoint_table

// The number of additions required is ceil(256/w) where w is the radix representation.
// impl_basepoint_table! {Name = EdwardsBasepointTableRadix16, LookupTable = LookupTableRadix16, Point = EdwardsPoint, Radix = 4, Additions = 64}
// impl_basepoint_table! {Name = EdwardsBasepointTableRadix32, LookupTable = LookupTableRadix32, Point = EdwardsPoint, Radix = 5, Additions = 52}
// impl_basepoint_table! {Name = EdwardsBasepointTableRadix64, LookupTable = LookupTableRadix64, Point = EdwardsPoint, Radix = 6, Additions = 43}
// impl_basepoint_table! {Name = EdwardsBasepointTableRadix128, LookupTable = LookupTableRadix128, Point = EdwardsPoint, Radix = 7, Additions = 37}
// impl_basepoint_table! {Name = EdwardsBasepointTableRadix256, LookupTable = LookupTableRadix256, Point = EdwardsPoint, Radix = 8, Additions = 33}

// -------------------------------------------------------------------------------------
// BEGIN legacy 3.x series code for backwards compatibility with BasepointTable trait
// -------------------------------------------------------------------------------------

/// A precomputed table of multiples of a basepoint, for accelerating
/// fixed-base scalar multiplication.  One table, for the Ed25519
/// basepoint, is provided in the `constants` module.
///
/// The basepoint tables are reasonably large, so they should probably be boxed.
///
/// The sizes for the tables and the number of additions required for one scalar
/// multiplication are as follows:
///
/// * [`EdwardsBasepointTableRadix16`]: 30KB, 64A
///   (this is the default size, and is used for [`ED25519_BASEPOINT_TABLE`])
/// * [`EdwardsBasepointTableRadix64`]: 120KB, 43A
/// * [`EdwardsBasepointTableRadix128`]: 240KB, 37A
/// * [`EdwardsBasepointTableRadix256`]: 480KB, 33A
///
/// # Why 33 additions for radix-256?
///
/// Normally, the radix-256 tables would allow for only 32 additions per scalar
/// multiplication.  However, due to the fact that standardised definitions of
/// legacy protocols—such as x25519—require allowing unreduced 255-bit scalar
/// invariants, when converting such an unreduced scalar's representation to
/// radix-\\(2^{8}\\), we cannot guarantee the carry bit will fit in the last
/// coefficient (the coefficients are `i8`s).  When, \\(w\\), the power-of-2 of
/// the radix, is \\(w < 8\\), we can fold the final carry onto the last
/// coefficient, \\(d\\), because \\(d < 2^{w/2}\\), so
/// $$
///     d + carry \cdot 2^{w} = d + 1 \cdot 2^{w} < 2^{w+1} < 2^{8}
/// $$
/// When \\(w = 8\\), we can't fit \\(carry \cdot 2^{w}\\) into an `i8`, so we
/// add the carry bit onto an additional coefficient.
// #[derive(Clone)]
// pub struct EdwardsBasepointTable(pub(crate) [LookupTable<AffineNielsPoint>; 32]);
// 
// impl EdwardsBasepointTable {
//     /// Create a table of precomputed multiples of `basepoint`.
//     #[allow(warnings)]
//     pub fn create(basepoint: &EdwardsPoint) -> EdwardsBasepointTable {
//         Self(EdwardsBasepointTableRadix16::create(basepoint).0)
//     }
// 
//     /// The computation uses Pippenger's algorithm, as described on
//     /// page 13 of the Ed25519 paper.  Write the scalar \\(a\\) in radix \\(16\\) with
//     /// coefficients in \\([-8,8)\\), i.e.,
//     /// $$
//     ///     a = a\_0 + a\_1 16\^1 + \cdots + a\_{63} 16\^{63},
//     /// $$
//     /// with \\(-8 \leq a_i < 8\\), \\(-8 \leq a\_{63} \leq 8\\).  Then
//     /// $$
//     ///     a B = a\_0 B + a\_1 16\^1 B + \cdots + a\_{63} 16\^{63} B.
//     /// $$
//     /// Grouping even and odd coefficients gives
//     /// $$
//     /// \begin{aligned}
//     ///     a B = \quad a\_0 16\^0 B +& a\_2 16\^2 B + \cdots + a\_{62} 16\^{62} B    \\\\
//     ///               + a\_1 16\^1 B +& a\_3 16\^3 B + \cdots + a\_{63} 16\^{63} B    \\\\
//     ///         = \quad(a\_0 16\^0 B +& a\_2 16\^2 B + \cdots + a\_{62} 16\^{62} B)   \\\\
//     ///            + 16(a\_1 16\^0 B +& a\_3 16\^2 B + \cdots + a\_{63} 16\^{62} B).  \\\\
//     /// \end{aligned}
//     /// $$
//     /// For each \\(i = 0 \ldots 31\\), we create a lookup table of
//     /// $$
//     /// [16\^{2i} B, \ldots, 8\cdot16\^{2i} B],
//     /// $$
//     /// and use it to select \\( x \cdot 16\^{2i} \cdot B \\) in constant time.
//     ///
//     /// The radix-\\(16\\) representation requires that the scalar is bounded
//     /// by \\(2\^{255}\\), which is always the case.
//     #[allow(warnings)]
//     pub fn basepoint_mul(&self, scalar: &Scalar) -> EdwardsPoint {
//         let a = scalar.to_radix_16();
// 
//         let tables = &self.0;
//         let mut P = EdwardsPoint::identity();
// 
//         for i in (0..64).filter(|x| x % 2 == 1) {
//             P = (&P + &tables[i/2].select(a[i])).to_extended();
//         }
// 
//         P = P.mul_by_pow_2(4);
// 
//         for i in (0..64).filter(|x| x % 2 == 0) {
//             P = (&P + &tables[i/2].select(a[i])).to_extended();
//         }
// 
//         P
//     }
// 
//     /// Get the basepoint for this table as an `EdwardsPoint`.
//     #[allow(warnings)]
//     pub fn basepoint(&self) -> EdwardsPoint {
//         (&EdwardsPoint::identity() + &self.0[0].select(1)).to_extended()
//     }
// }
// 
// impl<'a, 'b> Mul<&'b Scalar> for &'a EdwardsBasepointTable {
//     type Output = EdwardsPoint;
// 
//     /// Construct an `EdwardsPoint` from a `Scalar` \\(a\\) by
//     /// computing the multiple \\(aB\\) of this basepoint \\(B\\).
//     fn mul(self, scalar: &'b Scalar) -> EdwardsPoint {
//         // delegate to a private function so that its documentation appears in internal docs
//         self.basepoint_mul(scalar)
//     }
// }
// 
// impl<'a, 'b> Mul<&'a EdwardsBasepointTable> for &'b Scalar {
//     type Output = EdwardsPoint;
// 
//     /// Construct an `EdwardsPoint` from a `Scalar` \\(a\\) by
//     /// computing the multiple \\(aB\\) of this basepoint \\(B\\).
//     fn mul(self, basepoint_table: &'a EdwardsBasepointTable) -> EdwardsPoint {
//         basepoint_table * self
//     }
// }
// 
// // -------------------------------------------------------------------------------------
// // END legacy 3.x series code for backwards compatibility with BasepointTable trait
// // -------------------------------------------------------------------------------------
// 
// macro_rules! impl_basepoint_table_conversions {
//     (LHS = $lhs:ty, RHS = $rhs:ty) => {
//         impl<'a> From<&'a $lhs> for $rhs {
//             fn from(table: &'a $lhs) -> $rhs {
//                 <$rhs>::create(&table.basepoint())
//             }
//         }
// 
//         impl<'a> From<&'a $rhs> for $lhs {
//             fn from(table: &'a $rhs) -> $lhs {
//                 <$lhs>::create(&table.basepoint())
//             }
//         }
//     }
// }
// 
// impl_basepoint_table_conversions!{LHS = EdwardsBasepointTableRadix16, RHS = EdwardsBasepointTableRadix32}
// impl_basepoint_table_conversions!{LHS = EdwardsBasepointTableRadix16, RHS = EdwardsBasepointTableRadix64}
// impl_basepoint_table_conversions!{LHS = EdwardsBasepointTableRadix16, RHS = EdwardsBasepointTableRadix128}
// impl_basepoint_table_conversions!{LHS = EdwardsBasepointTableRadix16, RHS = EdwardsBasepointTableRadix256}
// 
// impl_basepoint_table_conversions!{LHS = EdwardsBasepointTableRadix32, RHS = EdwardsBasepointTableRadix64}
// impl_basepoint_table_conversions!{LHS = EdwardsBasepointTableRadix32, RHS = EdwardsBasepointTableRadix128}
// impl_basepoint_table_conversions!{LHS = EdwardsBasepointTableRadix32, RHS = EdwardsBasepointTableRadix256}
// 
// impl_basepoint_table_conversions!{LHS = EdwardsBasepointTableRadix64, RHS = EdwardsBasepointTableRadix128}
// impl_basepoint_table_conversions!{LHS = EdwardsBasepointTableRadix64, RHS = EdwardsBasepointTableRadix256}
// 
// impl_basepoint_table_conversions!{LHS = EdwardsBasepointTableRadix128, RHS = EdwardsBasepointTableRadix256}

impl EdwardsPoint {
    /// Multiply by the cofactor: return \\([8]P\\).
    pub fn mul_by_cofactor(&self) -> EdwardsPoint {
        self.mul_by_pow_2(3)
    }

    /// Compute \\([2\^k] P \\) by successive doublings. Requires \\( k > 0 \\).
    pub(crate) fn mul_by_pow_2(&self, k: u32) -> EdwardsPoint {
        debug_assert!( k > 0 );
        let mut r: CompletedPoint;
        let mut s = self.to_projective();
        for _ in 0..(k-1) {
            r = s.double(); s = r.to_projective();
        }
        // Unroll last iteration so we can go directly to_extended()
        s.double().to_extended()
    }

    /// Determine if this point is of small order.
    ///
    /// # Return
    ///
    /// * `true` if `self` is in the torsion subgroup \\( \mathcal E[8] \\);
    /// * `false` if `self` is not in the torsion subgroup \\( \mathcal E[8] \\).
    ///
    /// # Example
    ///
    /// ```
    /// use curve25519_dalek::constants;
    ///
    /// // Generator of the prime-order subgroup
    /// let P = constants::ED25519_BASEPOINT_POINT;
    /// // Generator of the torsion subgroup
    /// let Q = constants::EIGHT_TORSION[1];
    ///
    /// // P has large order
    /// assert_eq!(P.is_small_order(), false);
    ///
    /// // Q has small order
    /// assert_eq!(Q.is_small_order(), true);
    /// ```
    pub fn is_small_order(&self) -> bool {
        self.mul_by_cofactor().is_identity()
    }

    /// Determine if this point is “torsion-free”, i.e., is contained in
    /// the prime-order subgroup.
    ///
    /// # Return
    ///
    /// * `true` if `self` has zero torsion component and is in the
    /// prime-order subgroup;
    /// * `false` if `self` has a nonzero torsion component and is not
    /// in the prime-order subgroup.
    ///
    /// # Example
    ///
    /// ```
    /// use curve25519_dalek::constants;
    ///
    /// // Generator of the prime-order subgroup
    /// let P = constants::ED25519_BASEPOINT_POINT;
    /// // Generator of the torsion subgroup
    /// let Q = constants::EIGHT_TORSION[1];
    ///
    /// // P is torsion-free
    /// assert_eq!(P.is_torsion_free(), true);
    ///
    /// // P + Q is not torsion-free
    /// assert_eq!((P+Q).is_torsion_free(), false);
    /// ```
    pub fn is_torsion_free(&self) -> bool {
        (self * constants::BASEPOINT_ORDER).is_identity()
    }
}

// ------------------------------------------------------------------------
// Debug traits
// ------------------------------------------------------------------------

impl Debug for EdwardsPoint {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "EdwardsPoint{{\n\tX: {:?},\n\tY: {:?},\n\tZ: {:?},\n\tT: {:?}\n}}",
               &self.X, &self.Y, &self.Z, &self.T)
    }
}

