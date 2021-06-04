#![cfg(feature = "test-bpf")]

use {
    solana_program::pubkey::Pubkey,
    solana_program_test::*,
    solana_sdk::{signature::Signer, transaction::Transaction},
    ec_math::{id, instruction, processor::process_instruction, field::FieldElement,
              edwards::CompressedEdwardsY, scalar::Scalar},
    // curve25519_bpf_test::field::FieldElement,
};

#[tokio::test]
async fn test_ec_add() {
    let mut pc = ProgramTest::new("ec_math", id(), processor!(process_instruction));

    // Arbitrary number for now
    pc.set_bpf_compute_max_units(350_000);

    let (mut banks_client, payer, recent_blockhash) = pc.start().await;

    let mut transaction = Transaction::new_with_payer(
        &[instruction::field_add(FieldElement::minus_one(), FieldElement::minus_one())],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}

#[tokio::test]
async fn test_ec_mult() {
    let mut pc = ProgramTest::new("ec_math", id(), processor!(process_instruction));

    // Arbitrary number for now
    pc.set_bpf_compute_max_units(30_500_000);

    let (mut banks_client, payer, recent_blockhash) = pc.start().await;

    let two = &FieldElement::one() + &FieldElement::one();
    let minus_one = FieldElement::minus_one();

    let mut transaction = Transaction::new_with_payer(
        &[instruction::field_mul(two, minus_one)],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}

#[tokio::test]
async fn test_ec_invsqrt() {
    let mut pc = ProgramTest::new("ec_math", id(), processor!(process_instruction));

    // Arbitrary number for now
    pc.set_bpf_compute_max_units(30_500_000);

    let (mut banks_client, payer, recent_blockhash) = pc.start().await;

    let mut transaction = Transaction::new_with_payer(
        &[instruction::field_invsqrt(FieldElement::one())],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}

#[tokio::test]
async fn test_edwards_decompress() {
    let mut pc = ProgramTest::new("ec_math", id(), processor!(process_instruction));

    // Arbitrary number for now
    pc.set_bpf_compute_max_units(30_500_000);

    let (mut banks_client, payer, recent_blockhash) = pc.start().await;

    let mut transaction = Transaction::new_with_payer(
        &[instruction::edwards_decompress(CompressedEdwardsY::default())],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}

#[tokio::test]
async fn test_edwards_add() {
    let mut pc = ProgramTest::new("ec_math", id(), processor!(process_instruction));

    // Arbitrary number for now
    pc.set_bpf_compute_max_units(30_500_000);

    let (mut banks_client, payer, recent_blockhash) = pc.start().await;

    let mut transaction = Transaction::new_with_payer(
        &[instruction::edwards_add(CompressedEdwardsY::default(), CompressedEdwardsY::default())],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}

#[tokio::test]
async fn test_edwards_mul() {
    let mut pc = ProgramTest::new("ec_math", id(), processor!(process_instruction));

    // Arbitrary number for now
    pc.set_bpf_compute_max_units(30_500_000);

    let (mut banks_client, payer, recent_blockhash) = pc.start().await;

    let mut transaction = Transaction::new_with_payer(
        &[instruction::edwards_mul(CompressedEdwardsY::default(), Scalar::one())],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}
