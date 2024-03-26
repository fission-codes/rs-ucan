//! Storage interface for [`Delegation`][super::Delegation]s.

mod memory;
mod traits;

pub use memory::MemoryStore;
pub use traits::*;
