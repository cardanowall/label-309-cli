//! Color / TTY policy for human-facing output.
//!
//! The CLI colorizes ONLY human diagnostics (never `--json`). The decision
//! follows a documented order so a CI log, a piped consumer, and an interactive
//! terminal each get the right behaviour without per-command logic:
//!
//! 1. the explicit `--color <auto|always|never>` / `--no-color` flag,
//! 2. `NO_COLOR` (any non-empty value → off; the de-facto cross-tool standard),
//! 3. `CLICOLOR_FORCE` (any non-empty value → on),
//! 4. the stream's own `is_terminal()`.
//!
//! `--json` short-circuits to "no color" before any of this runs.

use std::io::IsTerminal;

/// The user's color intent from `--color` / `--no-color`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorChoice {
    /// Decide from env + TTY (the default).
    #[default]
    Auto,
    /// Always colorize (subject only to the `--json` short-circuit).
    Always,
    /// Never colorize.
    Never,
}

/// The two output streams a command may colorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// The env reads the policy needs, injected so tests need no real env/TTY.
pub trait ColorEnv {
    /// Read an environment variable (empty string counts as unset here).
    fn var(&self, key: &str) -> Option<String>;
    /// Whether the given stream is a terminal.
    fn is_terminal(&self, stream: Stream) -> bool;
}

/// The production color environment: real env + real `is_terminal()`.
pub struct SystemColorEnv;

impl ColorEnv for SystemColorEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|v| !v.is_empty())
    }
    fn is_terminal(&self, stream: Stream) -> bool {
        match stream {
            Stream::Stdout => std::io::stdout().is_terminal(),
            Stream::Stderr => std::io::stderr().is_terminal(),
        }
    }
}

/// Decide whether to colorize `stream`, given the flag choice, `--json` mode, and
/// the environment. Pure over its inputs so it is exhaustively testable.
#[must_use]
pub fn should_color(
    choice: ColorChoice,
    json_mode: bool,
    stream: Stream,
    env: &dyn ColorEnv,
) -> bool {
    // Machine output is never colorized.
    if json_mode {
        return false;
    }
    match choice {
        ColorChoice::Never => false,
        ColorChoice::Always => true,
        ColorChoice::Auto => {
            if env.var("NO_COLOR").is_some() {
                return false;
            }
            if env.var("CLICOLOR_FORCE").is_some() {
                return true;
            }
            env.is_terminal(stream)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakeEnv {
        vars: HashMap<String, String>,
        stdout_tty: bool,
        stderr_tty: bool,
    }
    impl ColorEnv for FakeEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned().filter(|v| !v.is_empty())
        }
        fn is_terminal(&self, stream: Stream) -> bool {
            match stream {
                Stream::Stdout => self.stdout_tty,
                Stream::Stderr => self.stderr_tty,
            }
        }
    }

    #[test]
    fn json_mode_is_always_off() {
        let env = FakeEnv {
            stderr_tty: true,
            ..FakeEnv::default()
        };
        assert!(!should_color(
            ColorChoice::Always,
            true,
            Stream::Stderr,
            &env
        ));
    }

    #[test]
    fn never_is_off_always_is_on() {
        let env = FakeEnv::default();
        assert!(!should_color(
            ColorChoice::Never,
            false,
            Stream::Stderr,
            &env
        ));
        assert!(should_color(
            ColorChoice::Always,
            false,
            Stream::Stderr,
            &env
        ));
    }

    #[test]
    fn no_color_env_forces_off_in_auto() {
        let env = FakeEnv {
            vars: HashMap::from([("NO_COLOR".to_string(), "1".to_string())]),
            stderr_tty: true,
            ..FakeEnv::default()
        };
        assert!(!should_color(
            ColorChoice::Auto,
            false,
            Stream::Stderr,
            &env
        ));
    }

    #[test]
    fn clicolor_force_turns_on_without_tty() {
        let env = FakeEnv {
            vars: HashMap::from([("CLICOLOR_FORCE".to_string(), "1".to_string())]),
            ..FakeEnv::default()
        };
        assert!(should_color(ColorChoice::Auto, false, Stream::Stderr, &env));
    }

    #[test]
    fn no_color_beats_clicolor_force() {
        let env = FakeEnv {
            vars: HashMap::from([
                ("NO_COLOR".to_string(), "1".to_string()),
                ("CLICOLOR_FORCE".to_string(), "1".to_string()),
            ]),
            ..FakeEnv::default()
        };
        assert!(!should_color(
            ColorChoice::Auto,
            false,
            Stream::Stderr,
            &env
        ));
    }

    #[test]
    fn auto_follows_tty_when_env_silent() {
        let on = FakeEnv {
            stderr_tty: true,
            ..FakeEnv::default()
        };
        let off = FakeEnv::default();
        assert!(should_color(ColorChoice::Auto, false, Stream::Stderr, &on));
        assert!(!should_color(
            ColorChoice::Auto,
            false,
            Stream::Stderr,
            &off
        ));
    }
}
