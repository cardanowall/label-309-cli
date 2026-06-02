//! Cross-cutting CLI utilities: the exit-code-bearing error type, hex helpers,
//! and the build-stamped version string.

pub mod base64;
pub mod color;
pub mod error;
pub mod hex;
pub mod version;

pub use color::{should_color, ColorChoice, ColorEnv, Stream, SystemColorEnv};
pub use error::CliError;
pub use hex::{bytes_to_hex, hex_to_bytes};
