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
        ECInstruction::EdwardsDecompress { element } => {
            msg!("Computing the decompression of a compressed Edwards curve element");
            let _result = element.decompress().unwrap();
            msg!("Decompression complete");
            Ok(())
        }
        ECInstruction::EdwardsAdd { element1, element2 } => {
            msg!("Computing the addition of two Edwards curve elements");
            let element1_decompressed = element1.decompress().unwrap();
            let element2_decompressed = element2.decompress().unwrap();
            let _result = element1_decompressed + element2_decompressed;
            msg!("Addition complete");
            Ok(())
        }
    }
}
