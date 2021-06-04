//! Program instructions

use crate::id;
use {
    borsh::{BorshDeserialize, BorshSerialize},
    solana_program::instruction::Instruction,
    crate::field::FieldElement,
    crate::edwards::CompressedEdwardsY,
    crate::scalar::Scalar,
};

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, PartialEq)]
pub enum ECInstruction {
    /// Calculate a addition of two field elements in
    /// \\( \mathbb Z / (2\^{255} - 19)\\).
    ///
    /// No accounts required for this instruction.
    FieldAdd {
        element1: FieldElement,
        element2: FieldElement,
    },
    /// Calculate a multiplication of two field elements in
    /// \\( \mathbb Z / (2\^{255} - 19)\\).
    ///
    /// No accounts required for this instruction.
    FieldMul {
        element1: FieldElement,
        element2: FieldElement,
    },
    /// Calculate a inverse square root of a field element in
    /// \\( \mathbb Z / (2\^{255} - 19)\\).
    ///
    /// No accounts required for this instruction.
    FieldInvSqrt {
        element: FieldElement,
    },
    /// Calculate a addition of two scalars mod
    /// \\( \ell = 2\^{252} + 27742317777372353535851937790883648493 \\).
    ///
    /// No accounts required for this instruction.
    ScalarAdd {
        scalar1: Scalar,
        scalar2: Scalar,
    },
    /// Calculate a multiplication of two scalars mod
    /// \\( \ell = 2\^{252} + 27742317777372353535851937790883648493 \\).
    ///
    /// No accounts required for this instruction.
    ScalarMul {
        scalar1: Scalar,
        scalar2: Scalar,
    },
    /// Calculate a decompression of a compressed Edwards curve
    /// element.
    ///
    /// No accounts required for this instruction.
    EdwardsDecompress {
        element: CompressedEdwardsY,
    },
    /// Calculate a decompression of a compressed Edwards curve
    /// element.
    ///
    /// No accounts required for this instruction.
    EdwardsAdd {
        element1: CompressedEdwardsY,
        element2: CompressedEdwardsY,
    },
    /// Calculate a multiplication of an Edwards curve element
    /// and a scalar.
    ///
    /// No accounts required for this instruction.
    EdwardsMul {
        element: CompressedEdwardsY,
        scalar: Scalar,
    },
    /// Calculate a batched multiplication of a sequence of 8 scalars
    /// and Edwards curve elements.
    ///
    /// No accounts required for this instruction.
    /// - I am running out of stack for 16 or higher batched multiplications
    EdwardsMultiScalarMul {
        elements: [CompressedEdwardsY; 8],
        scalars: [Scalar; 8],
    },

}

/// Create a FieldAdd instruction
pub fn field_add(element1: FieldElement, element2: FieldElement) -> Instruction {
    Instruction {
        program_id: id(),
        accounts: vec![],
        data: ECInstruction::FieldAdd { element1, element2 }
            .try_to_vec()
            .unwrap(),
    }
}

/// Create a FieldMul instruction
pub fn field_mul(element1: FieldElement, element2: FieldElement) -> Instruction {
    Instruction {
        program_id: id(),
        accounts: vec![],
        data: ECInstruction::FieldMul { element1, element2 }
            .try_to_vec()
            .unwrap(),
    }
}

/// Create a FieldInvSqrt instruction
pub fn field_invsqrt(element: FieldElement) -> Instruction {
    Instruction {
        program_id: id(),
        accounts:vec![],
        data: ECInstruction::FieldInvSqrt { element }
            .try_to_vec()
            .unwrap(),
    }
}

/// Create a ScalarAdd instruction
pub fn scalar_add(scalar1: Scalar, scalar2: Scalar) -> Instruction {
    Instruction {
        program_id: id(),
        accounts: vec![],
        data: ECInstruction::ScalarAdd { scalar1, scalar2 }
            .try_to_vec()
            .unwrap(),
    }
}

/// Create a ScalarMul instruction
pub fn scalar_mul(scalar1: Scalar, scalar2: Scalar) -> Instruction {
    Instruction {
        program_id: id(),
        accounts: vec![],
        data: ECInstruction::ScalarMul { scalar1, scalar2 }
            .try_to_vec()
            .unwrap(),
    }
}

/// Create a EdwardsDecompress instruction
pub fn edwards_decompress(element: CompressedEdwardsY) -> Instruction {
    Instruction {
        program_id: id(),
        accounts:vec![],
        data: ECInstruction::EdwardsDecompress { element }
            .try_to_vec()
            .unwrap(),
    }
}

/// Create a EdwardsAdd instruction
pub fn edwards_add(element1: CompressedEdwardsY, element2: CompressedEdwardsY) -> Instruction {
    Instruction {
        program_id: id(),
        accounts:vec![],
        data: ECInstruction::EdwardsAdd { element1, element2 }
            .try_to_vec()
            .unwrap(),
    }
}

/// Create a EdwardsMul instruction
pub fn edwards_mul(element: CompressedEdwardsY, scalar: Scalar) -> Instruction {
    Instruction {
        program_id: id(),
        accounts:vec![],
        data: ECInstruction::EdwardsMul { element, scalar }
            .try_to_vec()
            .unwrap(),
    }
}

/// Create a EdwardsMultiScalarMul instruction
pub fn edwards_multiscalar_mul(elements: [CompressedEdwardsY; 8], scalars: [Scalar; 8]) 
-> Instruction {
    Instruction {
        program_id: id(),
        accounts:vec![],
        data: ECInstruction::EdwardsMultiScalarMul { elements, scalars }
            .try_to_vec()
            .unwrap(),
    }
}
