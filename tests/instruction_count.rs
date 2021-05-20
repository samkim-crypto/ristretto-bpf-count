#![cfg(feature = "test-bpf")]

use {
    solana_program::pubkey::Pubkey,
    solana_program_test::*,
    solana_sdk::{signature::Signer, transaction::Transaction},
    solana_instruction_count::{id, instruction, processor::process_instruction},
    solana_program::msg,
};

#[tokio::test]
async fn test_ec_add() {
    let mut pc = ProgramTest::new("ec_math", id(), processor!(process_instruction));
    
    // Arbitrary number for now
    pc.set_bpf_compute_max_units(350_000);

    let (mut banks_client, payer, recent_blockhash) = pc.start().await;

    let mut transaction = Transaction::new_with_payer(
        &[instruction::ec_add(1 as u64, 2 as u64)],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}
