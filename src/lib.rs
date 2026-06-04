//! The `cardanowall` CLI library crate.
//!
//! A standalone Label 309 Proof-of-Existence toolkit built on the `cardanowall`
//! SDK. The binary (`main.rs`) is a thin shell; the command tree, argument
//! parsing, gateway resolution, and output formatting live here so integration
//! tests can drive [`run`] directly and assert on the resulting exit code.
//!
//! ## Commands
//!
//! - `verify <tx-hash>` — the standalone verifier; maps the verifier report's
//!   exit code through verbatim.
//! - `submit` — anchor a PoE via a gateway (hash / file / Merkle).
//! - `sign record|prepare|assemble` — off-host COSE_Sign1 record signing.
//! - `identity` — derive and print the public identity from a 32-byte seed.
//! - `merkle verify|build` — off-chain Merkle tooling.
//! - `inbox sync|list|decrypt` — sealed-PoE inbox over a raw recipient key.
//!
//! ## Exit codes
//!
//! `0` valid · `1` integrity · `2` network · `3` pending · `4` CLI input error.
//! Clap parse failures and `--help`/`--version` are mapped by [`run`].

#![forbid(unsafe_code)]

pub mod cli;
pub mod commands;
pub mod config;
pub mod inbox;
pub mod output;
pub mod secret;
pub mod state;
pub mod util;

pub use cli::{run, Cli};
pub use util::CliError;
