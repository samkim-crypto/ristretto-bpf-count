
#[macro_use]
pub(crate) mod macros;

pub mod entrypoint;
pub mod processor;
pub mod instruction;
pub mod field;
pub mod scalar;
pub mod backend;
pub mod edwards;
pub mod traits;
pub mod window;
pub mod constants;

solana_program::declare_id!("ECMath1111111111111111111111111111111111111");
