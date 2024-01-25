pub mod any;
pub mod crud;
pub mod msg;
pub mod traits;
pub mod wasm;

// TODO move to crate::wasm?
#[cfg(feature = "wasm")]
pub mod dynamic;
