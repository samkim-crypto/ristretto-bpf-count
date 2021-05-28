//! Program state processor

use {
    crate::instruction::ECInstruction,
    solana_program::{
        account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey, msg,
    },
    borsh::BorshDeserialize,
};

/// Instruction processor
pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let instruction = ECInstruction::try_from_slice(input).unwrap();
    match instruction {
        ECInstruction::FieldAdd { element1, element2 } => {
            msg!("Adding two field elements");
            let result = &element1 + &element2;
            msg!("{:?}", result);
            Ok(())
        }
        ECInstruction::FieldMul { element1, element2 } => {
            msg!("Multiplying two field elements");
            let result = &element1 * &element2;
            msg!("{:?}", result);
            Ok(())
        }
        ECInstruction::FieldInvSqrt { element } => {
            msg!("Computing the inverse square root of an element");
            let result = element.invsqrt();
            msg!("{:?}", result);
            Ok(())
        }
    }
}
