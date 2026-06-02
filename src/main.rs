//! The `cardanowall` binary entry point.
//!
//! Parses argv with clap, dispatches to the command tree in the library crate,
//! and exits with the mapped exit code. All real logic lives in
//! [`cardanowall_cli`]; this file only owns process wiring.

use std::process::ExitCode;

fn main() -> ExitCode {
    let code = cardanowall_cli::run(std::env::args_os());
    // `ExitCode::from` takes a u8; the contract codes are 0..=4.
    ExitCode::from(code as u8)
}
