//! `cardanowall completion <shell>` — print a shell completion script to stdout.
//!
//! Generated from the same clap command tree the binary uses, so the completions
//! never drift from the real flags. Install instructions live in the crate README.

use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::{generate, Shell};

use crate::cli::Cli;
use crate::util::CliError;

/// Arguments for `cardanowall completion`.
#[derive(Debug, Args)]
pub struct CompletionArgs {
    /// the shell to generate a completion script for.
    #[arg(value_enum)]
    pub shell: CompletionShell,
}

/// The shells we emit completions for (a thin mirror of [`clap_complete::Shell`]
/// so the value-enum surface is part of our own help text).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CompletionShell {
    /// Bash.
    Bash,
    /// Zsh.
    Zsh,
    /// Fish.
    Fish,
    /// PowerShell.
    Powershell,
}

impl From<CompletionShell> for Shell {
    fn from(value: CompletionShell) -> Self {
        match value {
            CompletionShell::Bash => Shell::Bash,
            CompletionShell::Zsh => Shell::Zsh,
            CompletionShell::Fish => Shell::Fish,
            CompletionShell::Powershell => Shell::PowerShell,
        }
    }
}

/// Run the `completion` command: write the script to stdout.
///
/// # Errors
///
/// Infallible in practice; returns `Ok(())`.
pub fn run(args: CompletionArgs) -> Result<(), CliError> {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    generate(
        Shell::from(args.shell),
        &mut cmd,
        bin_name,
        &mut std::io::stdout(),
    );
    Ok(())
}
