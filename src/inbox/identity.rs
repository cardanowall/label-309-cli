//! Identity resolution for the inbox subcommands — raw-seed-first, no envelope.
//!
//! Two input paths:
//!
//! - `--seed <hex32>`        → the 32-byte master identity seed. Runs the full
//!   derivation (Ed25519 + X25519 + X-Wing), so this is the only path that can
//!   locate the bookmark file (keyed by the Ed25519 public key) AND read hybrid
//!   (`mlkem768x25519`) sealed records.
//! - `--secret-key <hex32>`  → raw X25519 secret bytes (testing + power users).
//!   The Ed25519 pubkey is NOT recoverable from this path, so the
//!   bookmark-locating commands need the seed path; this surface returns `None`
//!   for the Ed25519 fields and callers must check.

use cardanowall::sealed_poe::RecipientKeyBundle;
use cardanowall::seed_derive::{
    derive_ed25519_keypair, derive_mlkem768x25519_keypair, derive_x25519_keypair,
};
use clap::Args;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::secret::{resolve_secret_bytes, SecretArgs, SecretEnv, SecretKind};
use crate::util::{hex_to_bytes, CliError};

/// The identity-input flags shared by every inbox verb: exactly one of the seed
/// family or the secret-key family, each with raw / `*-file` / `*-stdin` variants.
///
/// `seed` and `secret_key` carry raw secret material passed on argv, so `Debug`
/// is hand-written to redact both: no `{:?}`, log, or panic-backtrace path can
/// ever surface the value.
#[derive(Args, Clone, Default)]
pub struct IdentitySource {
    /// 32-byte master identity seed: 64-digit hex or the checksummed
    /// L309-SEED-1... form. INSECURE on argv (shell history / ps / CI logs);
    /// prefer --seed-file / --seed-stdin / CARDANOWALL_SEED.
    #[arg(long)]
    pub seed: Option<String>,
    /// read the seed from a file (trailing whitespace trimmed).
    #[arg(long = "seed-file")]
    pub seed_file: Option<String>,
    /// read the seed from stdin (also `--seed -`).
    #[arg(long = "seed-stdin")]
    pub seed_stdin: bool,
    /// X25519 identity private key as 64-char lowercase hex. INSECURE on argv;
    /// prefer --secret-key-file / --secret-key-stdin / CARDANOWALL_RECIPIENT_KEY.
    #[arg(long = "secret-key")]
    pub secret_key: Option<String>,
    /// read the X25519 secret key from a file.
    #[arg(long = "secret-key-file")]
    pub secret_key_file: Option<String>,
    /// read the X25519 secret key from stdin.
    #[arg(long = "secret-key-stdin")]
    pub secret_key_stdin: bool,
}

impl std::fmt::Debug for IdentitySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentitySource")
            .field("seed", &self.seed.as_ref().map(|_| "[redacted]"))
            .field("seed_file", &self.seed_file)
            .field("seed_stdin", &self.seed_stdin)
            .field(
                "secret_key",
                &self.secret_key.as_ref().map(|_| "[redacted]"),
            )
            .field("secret_key_file", &self.secret_key_file)
            .field("secret_key_stdin", &self.secret_key_stdin)
            .finish()
    }
}

impl IdentitySource {
    fn seed_args(&self) -> SecretArgs {
        SecretArgs {
            value: self.seed.clone(),
            file: self.seed_file.clone(),
            stdin: self.seed_stdin,
        }
    }

    fn secret_key_args(&self) -> SecretArgs {
        SecretArgs {
            value: self.secret_key.clone(),
            file: self.secret_key_file.clone(),
            stdin: self.secret_key_stdin,
        }
    }

    /// Resolve to exactly one identity, choosing the family the user supplied and
    /// routing its value through the shared secret layer (file > stdin > argv >
    /// env > prompt-on-TTY). Rejects supplying both families, or neither.
    ///
    /// # Errors
    ///
    /// Returns [`CliError`] (exit `4`) when neither or both families are present,
    /// or the chosen value is malformed / wrong length.
    pub fn resolve(&self, cmd: &str, env: &dyn SecretEnv) -> Result<ResolvedIdentity, CliError> {
        let seed_present =
            self.seed_args().any_present() || env.var(SecretKind::Seed.env_var()).is_some();
        let key_present = self.secret_key_args().any_present()
            || env.var(SecretKind::RecipientKey.env_var()).is_some();

        match (seed_present, key_present) {
            (true, true) => Err(CliError::input(format!(
                "{cmd}: exactly one of --seed / --secret-key MUST be supplied (got both)"
            ))),
            (true, false) => {
                let bytes = resolve_secret_bytes(
                    SecretKind::Seed,
                    &self.seed_args(),
                    true,
                    cmd,
                    env,
                )?
                .expect("required seed resolves or errors");
                resolve_from_seed_bytes(&bytes)
            }
            (false, true) => {
                let bytes = resolve_secret_bytes(
                    SecretKind::RecipientKey,
                    &self.secret_key_args(),
                    true,
                    cmd,
                    env,
                )?
                .expect("required secret-key resolves or errors");
                resolve_from_secret_key_bytes(&bytes)
            }
            (false, false) => Err(CliError::input(format!(
                "{cmd}: exactly one of --seed / --secret-key MUST be supplied \
                 (also accepts --seed-file/--seed-stdin/CARDANOWALL_SEED or the secret-key variants)"
            ))),
        }
    }
}

/// A resolved inbox identity. Holds live private-key material, so it wipes
/// itself on drop and its `Debug` impl redacts every field (a derived debug
/// print of this struct would be a key leak).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ResolvedIdentity {
    /// The raw X25519 private key (always present).
    pub x25519_private_key: Vec<u8>,
    /// The X-Wing secret seed for hybrid records; `None` on the `--secret-key`
    /// path (no seed to derive it from, so hybrid records cleanly non-match).
    pub mlkem768x25519_secret_seed: Option<Vec<u8>>,
    /// The Ed25519 public key; `None` on the `--secret-key` path.
    pub ed25519_public_key: Option<Vec<u8>>,
}

impl std::fmt::Debug for ResolvedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedIdentity")
            .field("x25519_private_key", &"<redacted>")
            .field(
                "mlkem768x25519_secret_seed",
                &self
                    .mlkem768x25519_secret_seed
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("ed25519_public_key", &self.ed25519_public_key)
            .finish()
    }
}

/// The identity input selection: exactly one of seed / secret-key. Carries the
/// secret as typed by the user, so it wipes on drop and its `Debug` impl
/// redacts the value.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub enum IdentityInput {
    /// A 32-byte master identity seed (hex).
    Seed(String),
    /// A raw X25519 private key as 64-char lowercase hex.
    SecretKey(String),
}

impl std::fmt::Debug for IdentityInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityInput::Seed(_) => f.write_str("IdentityInput::Seed(<redacted>)"),
            IdentityInput::SecretKey(_) => f.write_str("IdentityInput::SecretKey(<redacted>)"),
        }
    }
}

impl ResolvedIdentity {
    /// Assemble the unified [`RecipientKeyBundle`] the trial-decrypt / unwrap
    /// dispatch consumes. The single active identity contributes a one-element
    /// X25519 chain plus, when seed-derived, a one-element X-Wing seed list.
    #[must_use]
    pub fn recipient_key_bundle(&self) -> RecipientKeyBundle {
        RecipientKeyBundle {
            x25519_private_keys: vec![self.x25519_private_key.clone()],
            mlkem768x25519_secret_seeds: self
                .mlkem768x25519_secret_seed
                .clone()
                .map(|s| vec![s])
                .unwrap_or_default(),
        }
    }
}

/// Resolve an identity from exactly one of `--seed` / `--secret-key`.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when neither or both are supplied, or the
/// supplied value is malformed / the wrong length.
pub fn resolve_identity(
    seed: Option<&str>,
    secret_key: Option<&str>,
    cmd: &str,
) -> Result<ResolvedIdentity, CliError> {
    let input = pick_identity_input(seed, secret_key, cmd)?;
    // Match by reference: `IdentityInput` zeroizes on drop, so the secret hex
    // must stay inside it rather than being moved out into an unmanaged String.
    match &input {
        IdentityInput::Seed(hex) => resolve_from_seed_hex(hex),
        IdentityInput::SecretKey(hex) => resolve_from_secret_key_hex(hex),
    }
}

/// Pick exactly one identity input, rejecting "none" and "both".
fn pick_identity_input(
    seed: Option<&str>,
    secret_key: Option<&str>,
    cmd: &str,
) -> Result<IdentityInput, CliError> {
    match (seed, secret_key) {
        (Some(s), None) => Ok(IdentityInput::Seed(s.to_string())),
        (None, Some(k)) => Ok(IdentityInput::SecretKey(k.to_string())),
        (None, None) => Err(CliError::input(format!(
            "{cmd}: exactly one of --seed / --secret-key MUST be supplied"
        ))),
        (Some(_), Some(_)) => Err(CliError::input(format!(
            "{cmd}: exactly one of --seed / --secret-key MUST be supplied (got both)"
        ))),
    }
}

fn resolve_from_seed_hex(seed_hex: &str) -> Result<ResolvedIdentity, CliError> {
    let bytes = hex_to_bytes(seed_hex)
        .map(Zeroizing::new)
        .map_err(|e| CliError::input(format!("inbox: --seed {e}")))?;
    if bytes.len() != 32 {
        return Err(CliError::input(format!(
            "inbox: seed MUST be exactly 32 bytes, got {}",
            bytes.len()
        )));
    }
    resolve_from_seed_bytes(&bytes)
}

/// Derive the full identity (Ed25519 + X25519 + X-Wing) from a 32-byte seed.
/// The derived keypair locals are wiped once their needed halves are copied
/// into the (self-zeroizing) `ResolvedIdentity`.
fn resolve_from_seed_bytes(bytes: &[u8]) -> Result<ResolvedIdentity, CliError> {
    let mut x25519 =
        derive_x25519_keypair(bytes).map_err(|e| CliError::input(format!("inbox: --seed {e}")))?;
    let mut ed25519 =
        derive_ed25519_keypair(bytes).map_err(|e| CliError::input(format!("inbox: --seed {e}")))?;
    let mut xwing = derive_mlkem768x25519_keypair(bytes)
        .map_err(|e| CliError::input(format!("inbox: --seed {e}")))?;
    let resolved = ResolvedIdentity {
        x25519_private_key: x25519.secret_key.to_vec(),
        mlkem768x25519_secret_seed: Some(xwing.secret_seed.to_vec()),
        ed25519_public_key: Some(ed25519.public_key.to_vec()),
    };
    x25519.secret_key.zeroize();
    ed25519.secret_key.zeroize();
    xwing.secret_seed.zeroize();
    Ok(resolved)
}

fn resolve_from_secret_key_hex(secret_key_hex: &str) -> Result<ResolvedIdentity, CliError> {
    // Enforce the strict lowercase-hex shape the reference CLI requires for this
    // power-user path (no `0x` prefix, no uppercase).
    if secret_key_hex.len() != 64
        || !secret_key_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        // Report only the length: the value is a secret key and must never be
        // echoed back into the terminal, shell history, or CI logs.
        return Err(CliError::input(format!(
            "inbox: --secret-key must be a 64-char lowercase-hex string; got a {}-char value",
            secret_key_hex.chars().count()
        )));
    }
    let bytes = hex_to_bytes(secret_key_hex)
        .map(Zeroizing::new)
        .map_err(|e| CliError::input(format!("inbox: --secret-key {e}")))?;
    resolve_from_secret_key_bytes(&bytes)
}

/// Build an X25519-only identity from 32 raw secret-key bytes (no seed → no
/// Ed25519 derivation, no X-Wing hybrid secret).
fn resolve_from_secret_key_bytes(bytes: &[u8]) -> Result<ResolvedIdentity, CliError> {
    Ok(ResolvedIdentity {
        x25519_private_key: bytes.to_vec(),
        mlkem768x25519_secret_seed: None,
        ed25519_public_key: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_path_yields_full_identity() {
        let id = resolve_identity(Some(&"01".repeat(32)), None, "inbox sync").unwrap();
        assert!(id.ed25519_public_key.is_some());
        assert!(id.mlkem768x25519_secret_seed.is_some());
        let bundle = id.recipient_key_bundle();
        assert_eq!(bundle.x25519_private_keys.len(), 1);
        assert_eq!(bundle.mlkem768x25519_secret_seeds.len(), 1);
    }

    #[test]
    fn secret_key_path_has_no_ed25519_or_hybrid() {
        let id = resolve_identity(None, Some(&"ab".repeat(32)), "inbox sync").unwrap();
        assert!(id.ed25519_public_key.is_none());
        assert!(id.mlkem768x25519_secret_seed.is_none());
        let bundle = id.recipient_key_bundle();
        assert!(bundle.mlkem768x25519_secret_seeds.is_empty());
    }

    #[test]
    fn rejects_neither_or_both() {
        assert_eq!(
            resolve_identity(None, None, "inbox sync").unwrap_err().code,
            4
        );
        assert_eq!(
            resolve_identity(Some("a"), Some("b"), "inbox sync")
                .unwrap_err()
                .code,
            4
        );
    }

    #[test]
    fn secret_key_rejects_uppercase() {
        assert_eq!(
            resolve_identity(None, Some(&"AB".repeat(32)), "inbox sync")
                .unwrap_err()
                .code,
            4
        );
    }

    #[test]
    fn secret_key_shape_error_reports_length_not_value() {
        // A malformed (uppercase) secret-key must reject without echoing the key
        // bytes; the message reports only the observed length.
        let bad = "AB".repeat(32);
        let err = resolve_identity(None, Some(&bad), "inbox sync").unwrap_err();
        assert_eq!(err.code, 4);
        assert!(!err.message.contains(&bad));
        assert!(err.message.contains("64-char"));
    }

    #[test]
    fn seed_hex_decode_error_reports_length_not_value() {
        // A 64-char seed-shaped value with a stray non-hex byte rejects via the
        // shared hex decoder, which never echoes the input.
        let mut bad = "ab".repeat(31);
        bad.push_str("ax");
        let err = resolve_identity(Some(&bad), None, "inbox sync").unwrap_err();
        assert_eq!(err.code, 4);
        assert!(!err.message.contains(&bad));
        assert!(!err.message.contains(&"ab".repeat(31)));
    }

    #[test]
    fn debug_redacts_seed_and_secret_key() {
        // A `{:?}` of IdentitySource (log line, panic backtrace) must never
        // surface the raw seed or secret-key argv values; the file/stdin flags
        // are not secret and stay visible for debugging.
        let source = IdentitySource {
            seed: Some("ab".repeat(32)),
            seed_file: Some("/path/to/seed".to_string()),
            seed_stdin: false,
            secret_key: Some("cd".repeat(32)),
            secret_key_file: None,
            secret_key_stdin: true,
        };
        let rendered = format!("{source:?}");
        assert!(!rendered.contains(&"ab".repeat(32)));
        assert!(!rendered.contains(&"cd".repeat(32)));
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("/path/to/seed"));
    }
}
