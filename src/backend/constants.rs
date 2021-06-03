use crate::backend::field::FieldElement51;
// use crate::backend::scalar::Scalar52;

/// Edwards `d` value, equal to `-121665/121666 mod p`.
pub(crate) const EDWARDS_D: FieldElement51 = FieldElement51([
    929955233495203,
    466365720129213,
    1662059464998953,
    2033849074728123,
    1442794654840575,
]);

/// Edwards `2*d` value, equal to `2*(-121665/121666) mod p`.
pub(crate) const EDWARDS_D2: FieldElement51 = FieldElement51([
    1859910466990425,
    932731440258426,
    1072319116312658,
    1815898335770999,
    633789495995903,
]);

/// Precomputed value of one of the square roots of -1 (mod p)
pub const SQRT_M1: FieldElement51 = FieldElement51([
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
]);

// /// `R` = R % L where R = 2^260
// pub(crate) const R: Scalar52 = Scalar52([
//     0x000f48bd6721e6ed,
//     0x0003bab5ac67e45a,
//     0x000fffffeb35e51b,
//     0x000fffffffffffff,
//     0x00000fffffffffff,
// ]);
