//! Program instructions

use crate::id;
use crate::field::FieldElement;
use {
    borsh::{BorshDeserialize, BorshSerialize},
    solana_program::instruction::Instruction,
};

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, PartialEq)]
pub enum ECInstruction {
    /// Calculate the addition of u64 integers
    ///
    /// No accounts required for this instruction
    FieldAdd {
        element1: FieldElement,
        element2: FieldElement,
    },
    FieldMul {
        element1: FieldElement,
        element2: FieldElement,
    },
    FieldInvSqrt {
        element: FieldElement,
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
