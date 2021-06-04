//! Various constants, such as the Ristretto and Ed25519 basepoints.
//!
//! Most of the constants are given with
//! `LONG_DESCRIPTIVE_UPPER_CASE_NAMES`, but they can be brought into
//! scope using a `let` binding:
//!
//! ```
//! use curve25519_dalek::constants;
//! use curve25519_dalek::traits::IsIdentity;
//!
//! let B = &constants::RISTRETTO_BASEPOINT_TABLE;
//! let l = &constants::BASEPOINT_ORDER;
//!
//! let A = l * B;
//! assert!(A.is_identity());
//! ```

#![allow(non_snake_case)]

use crate::edwards::CompressedEdwardsY;
// use ristretto::RistrettoPoint;
// use ristretto::CompressedRistretto;
// use montgomery::MontgomeryPoint;
use crate::scalar::Scalar;

pub use crate::backend::constants::*;

/// The Ed25519 basepoint, in `CompressedEdwardsY` format.
///
/// This is the little-endian byte encoding of \\( 4/5 \pmod p \\),
/// which is the \\(y\\)-coordinate of the Ed25519 basepoint.
///
/// The sign bit is 0 since the basepoint has \\(x\\) chosen to be positive.
pub const ED25519_BASEPOINT_COMPRESSED: CompressedEdwardsY =
    CompressedEdwardsY([0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66]);

// /// The X25519 basepoint, in `MontgomeryPoint` format.
// pub const X25519_BASEPOINT: MontgomeryPoint =
//     MontgomeryPoint([0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
// 
// /// The Ristretto basepoint, in `CompressedRistretto` format.
// pub const RISTRETTO_BASEPOINT_COMPRESSED: CompressedRistretto =
//     CompressedRistretto([0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71,
//                          0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
//                          0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d,
//                          0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76]);

/// The Ristretto basepoint, as a `RistrettoPoint`.
///
/// This is called `_POINT` to distinguish it from `_TABLE`, which
/// provides fast scalar multiplication.
// pub const RISTRETTO_BASEPOINT_POINT: RistrettoPoint = RistrettoPoint(ED25519_BASEPOINT_POINT);

/// `BASEPOINT_ORDER` is the order of the Ristretto group and of the Ed25519 basepoint, i.e.,
/// $$
/// \ell = 2^\{252\} + 27742317777372353535851937790883648493.
/// $$
pub const BASEPOINT_ORDER: Scalar = Scalar{
    bytes: [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ],
};

// use ristretto::RistrettoBasepointTable;
// /// The Ristretto basepoint, as a `RistrettoBasepointTable` for scalar multiplication.
// pub const RISTRETTO_BASEPOINT_TABLE: RistrettoBasepointTable
//     = RistrettoBasepointTable(ED25519_BASEPOINT_TABLE);

