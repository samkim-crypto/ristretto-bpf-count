//! Program state processor

use {
    crate::instruction::ECInstruction,
    solana_program::{
        account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey, msg,
        log::sol_log_compute_units,
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
        ECInstruction::U64Add { num1, num2 } => {
            msg!("Adding two u64 integers");
            sol_log_compute_units();
            let result = num1 + num2;
            sol_log_compute_units();
            msg!("{}", result);
            Ok(())
        }
    }
}
