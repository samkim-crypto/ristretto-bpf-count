
#[macro_use]
pub(crate) mod macros;

pub mod entrypoint;
pub mod processor;
pub mod instruction;
pub mod field;
// pub mod scalar;
pub mod backend;
pub mod edwards;
pub mod traits;

solana_program::declare_id!("ECMath1111111111111111111111111111111111111");
