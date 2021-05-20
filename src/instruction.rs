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
        point1: u64,
        point2: u64,
    },
}

/// Create ECAdd instruction
pub fn ec_add(point1: u64, point2: u64) -> Instruction {
    Instruction {
        program_id: id(),
        accounts: vec![],
        data: ECInstruction::U64Add { point1, point2 }
            .try_to_vec()
            .unwrap(),
    }
}
