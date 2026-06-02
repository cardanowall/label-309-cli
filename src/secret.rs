//! The single shared secret + config resolution layer used by every command.
//!
//! Two distinct precedence chains live here, so no command re-implements either:
//!
//! ## High-secrets (`--seed`, `--secret-key`)
//!
//! These decode to private key material. The resolution order is:
//!
//! 1. `--<name>-file <path>`  — read the file, trim trailing whitespace.
//! 2. `--<name>-stdin` (or the literal value `-`) — read all of stdin, trim the
//!    trailing newline. Only one stdin reader may run per process.
//! 3. the raw `--<name> <hex>` argv flag — explicit, so it wins over env, but it
//!    is the documented-INSECURE path (shell history / `ps` / CI logs).
//! 4. the env var (`CARDANOWALL_SEED` / `CARDANOWALL_RECIPIENT_KEY`).
//! 5. an interactive hidden prompt — ONLY when the secret is required AND stdin
//!    is a TTY. The prompt text goes to stderr; the typed bytes never echo.
//! 6. otherwise: a CLI input error (exit `4`).
//!
//! A high-secret is NEVER a required argv flag — automation supplies it through a
//! file, stdin, or the environment; humans get the hidden prompt. The decoded hex
//! buffer is zeroized after the bytes are produced.
//!
//! ## Non-secret gateway config (`--base-url`, `--api-key`)
//!
//! The order is `explicit flag > env > active gateway profile > built-in default
//! (data gateways only) > error`. The profile lookup is resolved by the caller
//! (it already holds the parsed config); this module only sequences the chain.

use std::io::{IsTerminal, Read};

use zeroize::Zeroize;

use crate::util::{hex_to_bytes, CliError};

/// Which high-secret is being resolved — drives the env var, the flag names in
/// error messages, and the interactive prompt text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// The 32-byte master identity seed.
    Seed,
    /// The X25519 recipient secret key (recipient-sealed decryption).
    RecipientKey,
}

impl SecretKind {
    /// The canonical env var that supplies this secret on every command.
    #[must_use]
    pub fn env_var(self) -> &'static str {
        match self {
            SecretKind::Seed => "CARDANOWALL_SEED",
            SecretKind::RecipientKey => "CARDANOWALL_RECIPIENT_KEY",
        }
    }

    /// The base flag name (without the leading dashes), e.g. `seed`.
    #[must_use]
    pub fn flag(self) -> &'static str {
        match self {
            SecretKind::Seed => "seed",
            SecretKind::RecipientKey => "secret-key",
        }
    }

    /// The interactive hidden-prompt line written to stderr.
    fn prompt(self) -> &'static str {
        match self {
            SecretKind::Seed => "Enter 32-byte identity seed (hex): ",
            SecretKind::RecipientKey => "Enter X25519 recipient secret key (hex): ",
        }
    }
}

/// The argv inputs for one high-secret, as collected by clap. The four sources
/// are mutually-exclusive in practice but resolved by documented precedence here
/// rather than rejected, so a power user mixing `--seed-file` with an env var
/// still gets deterministic behaviour.
#[derive(Debug, Clone, Default)]
pub struct SecretArgs {
    /// `--<name> <hex>` — the raw, documented-insecure argv value.
    pub value: Option<String>,
    /// `--<name>-file <path>`.
    pub file: Option<String>,
    /// `--<name>-stdin` — read the secret from stdin.
    pub stdin: bool,
}

impl SecretArgs {
    /// Whether the user supplied any source on argv (file/stdin/value).
    #[must_use]
    pub fn any_present(&self) -> bool {
        self.file.is_some() || self.stdin || self.value.as_deref().is_some_and(|v| !v.is_empty())
    }
}

/// A terminal probe + reader surface, injected so tests never touch a real TTY.
///
/// Production wiring uses [`SystemSecretEnv`]; tests supply a fake that reports a
/// non-terminal stdin and canned stdin/file/env reads.
pub trait SecretEnv {
    /// Read an environment variable.
    fn var(&self, key: &str) -> Option<String>;
    /// Read the whole of stdin to a `String`.
    fn read_stdin(&self) -> Result<String, CliError>;
    /// Read a file to a `String`.
    fn read_file(&self, path: &str) -> Result<String, CliError>;
    /// Whether stdin is a TTY (gates the interactive prompt).
    fn stdin_is_terminal(&self) -> bool;
    /// Prompt on stderr and read a line WITHOUT echo (the hidden prompt).
    fn prompt_hidden(&self, prompt: &str) -> Result<String, CliError>;
}

/// The production secret environment: real env, real stdin, real `rpassword`.
pub struct SystemSecretEnv;

impl SecretEnv for SystemSecretEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|v| !v.is_empty())
    }

    fn read_stdin(&self) -> Result<String, CliError> {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| CliError::network(format!("cannot read stdin: {e}")))?;
        Ok(buf)
    }

    fn read_file(&self, path: &str) -> Result<String, CliError> {
        std::fs::read_to_string(path)
            .map_err(|e| CliError::input(format!("cannot read secret file {path}: {e}")))
    }

    fn stdin_is_terminal(&self) -> bool {
        std::io::stdin().is_terminal()
    }

    fn prompt_hidden(&self, prompt: &str) -> Result<String, CliError> {
        // rpassword writes the prompt to the controlling terminal and reads the
        // line with echo disabled, so the secret never lands in scrollback.
        rpassword::prompt_password(prompt)
            .map_err(|e| CliError::input(format!("cannot read hidden prompt: {e}")))
    }
}

/// Trim a secret read from a file or stdin: drop a single trailing newline (and
/// any other surrounding whitespace) so a `printf '%s\n' hex > seed` round-trips.
fn trim_secret(raw: &str) -> String {
    raw.trim().to_string()
}

/// Resolve a high-secret to its raw bytes, length-checked to `expected_len`.
///
/// `required` decides whether a missing secret triggers the interactive prompt
/// (TTY only) or a hard error. `cmd` and `kind` shape the error/prompt text.
///
/// The intermediate hex string is zeroized before returning.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) for a malformed value, a wrong byte length, a
/// missing required secret on a non-TTY, or a file/stdin read failure.
pub fn resolve_secret_bytes(
    kind: SecretKind,
    args: &SecretArgs,
    expected_len: usize,
    required: bool,
    cmd: &str,
    env: &dyn SecretEnv,
) -> Result<Option<Vec<u8>>, CliError> {
    let mut hex = match resolve_secret_hex(kind, args, required, cmd, env)? {
        Some(hex) => hex,
        None => return Ok(None),
    };
    let result = decode_and_check(kind, &hex, expected_len, cmd);
    hex.zeroize();
    result.map(Some)
}

/// The hex-string half of the resolution chain (no decode), so callers that want
/// the raw string (e.g. comma-list recipient keys) can post-process it.
fn resolve_secret_hex(
    kind: SecretKind,
    args: &SecretArgs,
    required: bool,
    cmd: &str,
    env: &dyn SecretEnv,
) -> Result<Option<String>, CliError> {
    // 1. file.
    if let Some(path) = args.file.as_deref().filter(|p| !p.is_empty()) {
        return Ok(Some(trim_secret(&env.read_file(path)?)));
    }
    // 2. stdin (explicit flag or the literal value `-`).
    let stdin_sentinel = args.value.as_deref() == Some("-");
    if args.stdin || stdin_sentinel {
        return Ok(Some(trim_secret(&env.read_stdin()?)));
    }
    // 3. raw argv value (explicit → beats env), excluding the `-` sentinel.
    if let Some(value) = args.value.as_deref().filter(|v| !v.is_empty()) {
        return Ok(Some(value.trim().to_string()));
    }
    // 4. env var.
    if let Some(value) = env.var(kind.env_var()) {
        return Ok(Some(value.trim().to_string()));
    }
    // 5. interactive hidden prompt — only when required AND stdin is a TTY.
    if required && env.stdin_is_terminal() {
        let entered = env.prompt_hidden(kind.prompt())?;
        let trimmed = trim_secret(&entered);
        if trimmed.is_empty() {
            return Err(CliError::input(format!(
                "{cmd}: no {} provided",
                kind.flag()
            )));
        }
        return Ok(Some(trimmed));
    }
    // 6. nothing.
    if required {
        Err(CliError::input(format!(
            "{cmd}: --{flag} is required — pass --{flag}-file <path>, --{flag}-stdin, \
             set {env}, or run interactively for a hidden prompt",
            flag = kind.flag(),
            env = kind.env_var(),
        )))
    } else {
        Ok(None)
    }
}

fn decode_and_check(
    kind: SecretKind,
    hex: &str,
    expected_len: usize,
    cmd: &str,
) -> Result<Vec<u8>, CliError> {
    let bytes =
        hex_to_bytes(hex).map_err(|e| CliError::input(format!("{cmd}: --{} {e}", kind.flag())))?;
    if bytes.len() != expected_len {
        return Err(CliError::input(format!(
            "{cmd}: --{} must decode to exactly {expected_len} bytes (got {})",
            kind.flag(),
            bytes.len()
        )));
    }
    Ok(bytes)
}

// ===========================================================================
// Non-secret gateway config resolution (base-url, api-key)
// ===========================================================================

/// Resolve one non-secret config value through `flag > env > profile > error`.
///
/// `default` (data gateways only) is appended by the caller for slots that have a
/// built-in fallback; the API key and base URL have none, so `None` flows through.
#[must_use]
pub fn resolve_config_value(
    flag: Option<&str>,
    env: Option<&str>,
    profile: Option<&str>,
) -> Option<String> {
    for candidate in [flag, env, profile] {
        if let Some(value) = candidate.map(str::trim).filter(|v| !v.is_empty()) {
            return Some(value.to_string());
        }
    }
    None
}

/// The resolved service-gateway endpoint: the base URL plus the opaque bearer.
#[derive(Debug, Clone, Default)]
pub struct ServiceGateway {
    /// The required base URL.
    pub base_url: String,
    /// The opaque bearer API key, when supplied anywhere.
    pub api_key: Option<String>,
}

/// Resolve the service-gateway base URL + API key for a network command, applying
/// `explicit flag > env > active gateway profile` to each, and reading both env
/// vars through the injected [`SecretEnv`].
///
/// The base URL is required; the API key is optional (a key-less public gateway).
/// `profile` is the active [`GatewayProfile`](crate::config::GatewayProfile)
/// selected by the caller (the `--gateway-profile` flag or the config default).
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when no base URL resolves from any source.
pub fn resolve_service_gateway(
    base_url_flag: Option<&str>,
    api_key_flag: Option<&str>,
    profile: Option<&crate::config::GatewayProfile>,
    cmd: &str,
    env: &dyn SecretEnv,
) -> Result<ServiceGateway, CliError> {
    let profile_base = profile.map(|p| p.base_url.as_str());
    let profile_key = profile.and_then(|p| p.api_key.as_deref());

    let base_url = resolve_config_value(
        base_url_flag,
        env.var("CARDANOWALL_BASE_URL").as_deref(),
        profile_base,
    )
    .ok_or_else(|| {
        CliError::input(format!(
            "{cmd}: a gateway base URL is required — pass --base-url, set CARDANOWALL_BASE_URL, \
             or configure a gateway profile (cardanowall gateway add …)"
        ))
    })?;

    let api_key = resolve_config_value(
        api_key_flag,
        env.var("CARDANOWALL_API_KEY").as_deref(),
        profile_key,
    );

    Ok(ServiceGateway { base_url, api_key })
}

/// Test doubles for the secret environment, shared by this module's tests and the
/// command modules' tests so each command can exercise the file/stdin/env/error
/// paths without a real TTY.
#[cfg(test)]
pub mod test_support {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// A fake env where stdin is NOT a terminal (so the prompt branch is skipped)
    /// unless a test opts into `terminal = true`.
    pub struct FakeSecretEnv {
        /// Environment variables visible to the fake.
        pub vars: HashMap<String, String>,
        /// Canned file contents keyed by path.
        pub files: HashMap<String, String>,
        /// Canned stdin contents.
        pub stdin: Option<String>,
        /// Whether stdin reports as a TTY (gates the prompt branch).
        pub terminal: bool,
        /// The string the hidden prompt returns when invoked.
        pub prompt_response: Option<String>,
        /// Records whether the prompt branch was hit.
        pub prompted: RefCell<bool>,
    }

    impl Default for FakeSecretEnv {
        fn default() -> Self {
            Self {
                vars: HashMap::new(),
                files: HashMap::new(),
                stdin: None,
                terminal: false,
                prompt_response: None,
                prompted: RefCell::new(false),
            }
        }
    }

    impl SecretEnv for FakeSecretEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned().filter(|v| !v.is_empty())
        }
        fn read_stdin(&self) -> Result<String, CliError> {
            self.stdin
                .clone()
                .ok_or_else(|| CliError::network("no stdin in fake".to_string()))
        }
        fn read_file(&self, path: &str) -> Result<String, CliError> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| CliError::input(format!("no fake file {path}")))
        }
        fn stdin_is_terminal(&self) -> bool {
            self.terminal
        }
        fn prompt_hidden(&self, _prompt: &str) -> Result<String, CliError> {
            *self.prompted.borrow_mut() = true;
            self.prompt_response
                .clone()
                .ok_or_else(|| CliError::input("no prompt response in fake".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FakeSecretEnv as FakeEnv;
    use super::*;
    use std::collections::HashMap;

    fn seed_hex() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn file_beats_stdin_env_value() {
        let env = FakeEnv {
            files: HashMap::from([("/s".to_string(), format!("{}\n", seed_hex()))]),
            stdin: Some("cd".repeat(32)),
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), "ef".repeat(32))]),
            ..FakeEnv::default()
        };
        let args = SecretArgs {
            value: Some("12".repeat(32)),
            file: Some("/s".to_string()),
            stdin: true,
        };
        let bytes = resolve_secret_bytes(SecretKind::Seed, &args, 32, true, "identity", &env)
            .unwrap()
            .unwrap();
        assert_eq!(bytes, hex_to_bytes(&seed_hex()).unwrap());
    }

    #[test]
    fn stdin_beats_env_and_trims_newline() {
        let env = FakeEnv {
            stdin: Some(format!("{}\n", seed_hex())),
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), "ef".repeat(32))]),
            ..FakeEnv::default()
        };
        let args = SecretArgs {
            stdin: true,
            ..SecretArgs::default()
        };
        let bytes = resolve_secret_bytes(SecretKind::Seed, &args, 32, true, "identity", &env)
            .unwrap()
            .unwrap();
        assert_eq!(bytes, hex_to_bytes(&seed_hex()).unwrap());
    }

    #[test]
    fn dash_value_means_stdin() {
        let env = FakeEnv {
            stdin: Some(seed_hex()),
            ..FakeEnv::default()
        };
        let args = SecretArgs {
            value: Some("-".to_string()),
            ..SecretArgs::default()
        };
        let bytes = resolve_secret_bytes(SecretKind::Seed, &args, 32, true, "identity", &env)
            .unwrap()
            .unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn argv_value_beats_env() {
        let env = FakeEnv {
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), "ef".repeat(32))]),
            ..FakeEnv::default()
        };
        let args = SecretArgs {
            value: Some(seed_hex()),
            ..SecretArgs::default()
        };
        let bytes = resolve_secret_bytes(SecretKind::Seed, &args, 32, true, "identity", &env)
            .unwrap()
            .unwrap();
        assert_eq!(bytes, hex_to_bytes(&seed_hex()).unwrap());
    }

    #[test]
    fn env_used_when_no_flag() {
        let env = FakeEnv {
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), seed_hex())]),
            ..FakeEnv::default()
        };
        let bytes = resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            32,
            true,
            "identity",
            &env,
        )
        .unwrap()
        .unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn missing_required_non_tty_is_input_error_no_prompt() {
        let env = FakeEnv::default(); // terminal = false
        let err = resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            32,
            true,
            "identity",
            &env,
        )
        .unwrap_err();
        assert_eq!(err.code, 4);
        assert!(!*env.prompted.borrow(), "must not prompt on a non-TTY");
    }

    #[test]
    fn missing_optional_is_none() {
        let env = FakeEnv::default();
        let out = resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            32,
            false,
            "submit",
            &env,
        )
        .unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn prompt_used_only_on_tty_when_required() {
        let env = FakeEnv {
            terminal: true,
            prompt_response: Some(format!("{}\n", seed_hex())),
            ..FakeEnv::default()
        };
        let bytes = resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            32,
            true,
            "identity",
            &env,
        )
        .unwrap()
        .unwrap();
        assert_eq!(bytes.len(), 32);
        assert!(*env.prompted.borrow());
    }

    #[test]
    fn rejects_wrong_length() {
        let env = FakeEnv {
            vars: HashMap::from([("CARDANOWALL_SEED".to_string(), "abcd".to_string())]),
            ..FakeEnv::default()
        };
        let err = resolve_secret_bytes(
            SecretKind::Seed,
            &SecretArgs::default(),
            32,
            true,
            "identity",
            &env,
        )
        .unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn config_value_precedence() {
        assert_eq!(
            resolve_config_value(Some("flag"), Some("env"), Some("prof")),
            Some("flag".to_string())
        );
        assert_eq!(
            resolve_config_value(None, Some("env"), Some("prof")),
            Some("env".to_string())
        );
        assert_eq!(
            resolve_config_value(None, None, Some("prof")),
            Some("prof".to_string())
        );
        assert_eq!(resolve_config_value(None, None, None), None);
        // Empty strings are skipped.
        assert_eq!(
            resolve_config_value(Some("  "), None, Some("prof")),
            Some("prof".to_string())
        );
    }
}
