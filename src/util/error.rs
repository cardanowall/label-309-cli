//! The CLI error type that drives the process exit code.
//!
//! Every subcommand handler returns `Result<(), CliError>`. A `CliError` carries
//! the numeric exit code and an optional diagnostic message; `main` prints the
//! message to stderr (prefixed `cardanowall: `) and exits with the code.
//!
//! Exit-code contract (the public UX, identical to the reference CLI):
//!
//! - `0` — success (verdict valid, or a non-verdict happy path).
//! - `1` — integrity-class failure (verdict invalid, service-independence
//!   violation, server rejection).
//! - `2` — network-class failure (unrecoverable runtime / IO / unparseable
//!   response).
//! - `3` — pending (insufficient confirmations / unconfirmed tx).
//! - `4` — CLI input error (bad args, malformed positional, conflicting modes).

use std::fmt;

/// A subcommand failure carrying its process exit code and a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    /// The process exit code (`1`–`4`; `0` never travels as an error).
    pub code: i32,
    /// The diagnostic written to stderr. Empty for a silent non-zero exit.
    pub message: String,
}

impl CliError {
    /// Build an error with an explicit code and message.
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// A CLI input error (`4`): bad args, malformed positional, conflicting modes.
    pub fn input(message: impl Into<String>) -> Self {
        Self::new(4, message)
    }

    /// An integrity-class error (`1`): invalid verdict, server rejection.
    pub fn integrity(message: impl Into<String>) -> Self {
        Self::new(1, message)
    }

    /// A network-class error (`2`): IO / transport / unparseable response.
    pub fn network(message: impl Into<String>) -> Self {
        Self::new(2, message)
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CliError {}
