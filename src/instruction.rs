//! Program instructions

use crate::id;
use {
    borsh::{BorshDeserialize, BorshSerialize},
    solana_program::instruction::Instruction,
};

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, PartialEq)]
pub enum ECInstruction {
    /// Calculate the addition of u64 integers
    ///
    /// No accounts required for this instruction
    U64Add {
        num1: u64,
        num2: u64,
    },
}

/// Create U64Add instruction
pub fn u64_add(num1: u64, num2: u64) -> Instruction {
    Instruction {
        program_id: id(),
        accounts: vec![],
        data: ECInstruction::U64Add { num1, num2 }
            .try_to_vec()
            .unwrap(),
    }
}
