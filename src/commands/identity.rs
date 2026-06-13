//! `cardanowall identity --seed <hex>` — offline identity inspector.
//!
//! Derives the full key set from the 32-byte master identity seed and prints the
//! public keys, both age recipient strings, and a short display fingerprint.
//! Performs ZERO chain / storage / API interaction; it never needs an API key.
//!
//! The fingerprint is a deterministic short tag for an identity: the first
//! 8 bytes of `sha2-256(ed25519_pubkey)`, grouped `xxxx-xxxx-xxxx-xxxx`. It lets
//! a human eyeball that two derivations produced the same identity; it is not a
//! security primitive.
//!
//! `--json` always emits the FULL (non-abbreviated) X-Wing key; the human view
//! abbreviates it because the raw hex is ~2.4 KB.
//!
//! Exit codes: `0` ok / `4` CLI input error (bad / short seed).

use cardanowall::hash::sha256;
use cardanowall::recipient::{encode_age_x25519_recipient, encode_age_xwing_recipient};
use cardanowall::seed_derive::{
    derive_ed25519_keypair, derive_mlkem768x25519_keypair, derive_x25519_keypair,
};
use clap::Args;
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use crate::secret::{resolve_secret_bytes, SecretArgs, SecretEnv, SecretKind, SystemSecretEnv};
use crate::util::{bytes_to_hex, CliError};

/// Chars of X-Wing hex shown at each end in the human view before the ellipsis.
const XWING_HEX_ABBREV_HEAD: usize = 16;

/// Arguments for `cardanowall identity`.
///
/// `seed` carries raw secret material passed on argv, so `Debug` is hand-written
/// to redact it: no `{:?}`, log, or panic-backtrace path can ever surface the
/// value.
#[derive(Args)]
pub struct IdentityArgs {
    /// 32-byte master identity seed: 64-digit hex or the checksummed
    /// L309-SEED-1... form. INSECURE on argv (shell history / ps / CI logs);
    /// prefer --seed-file / --seed-stdin / CARDANOWALL_SEED / the prompt.
    #[arg(long)]
    pub seed: Option<String>,
    /// read the seed from a file (trailing whitespace trimmed).
    #[arg(long = "seed-file")]
    pub seed_file: Option<String>,
    /// read the seed from stdin.
    #[arg(long = "seed-stdin")]
    pub seed_stdin: bool,
    /// Emit a machine-readable JSON summary on stdout.
    #[arg(long)]
    pub json: bool,
}

impl std::fmt::Debug for IdentityArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityArgs")
            .field("seed", &self.seed.as_ref().map(|_| "[redacted]"))
            .field("seed_file", &self.seed_file)
            .field("seed_stdin", &self.seed_stdin)
            .field("json", &self.json)
            .finish()
    }
}

impl IdentityArgs {
    fn secret_args(&self) -> SecretArgs {
        SecretArgs {
            value: self.seed.clone(),
            file: self.seed_file.clone(),
            stdin: self.seed_stdin,
        }
    }
}

/// The derived public identity, serialised to the JSON contract shape.
#[derive(Debug, Serialize)]
pub struct IdentityOutcome {
    /// The short display fingerprint, `xxxx-xxxx-xxxx-xxxx`.
    pub fingerprint: String,
    /// Ed25519 public key (lowercase hex).
    pub ed25519_pubkey_hex: String,
    /// X25519 public key (lowercase hex).
    pub x25519_pubkey_hex: String,
    /// X-Wing (ML-KEM-768 + X25519) public key (lowercase hex, full).
    pub xwing_pubkey_hex: String,
    /// The `age1…` X25519 recipient string.
    pub age_recipient: String,
    /// The `age1pqc…` X-Wing recipient string.
    pub age1pqc_recipient: String,
}

/// The 8-byte `sha2-256(ed25519_pub)` fingerprint, grouped `xxxx-xxxx-xxxx-xxxx`.
fn display_fingerprint(ed25519_public_key: &[u8]) -> String {
    let digest = sha256(ed25519_public_key);
    let hex = bytes_to_hex(&digest[..8]); // 16 hex chars
    format!(
        "{}-{}-{}-{}",
        &hex[0..4],
        &hex[4..8],
        &hex[8..12],
        &hex[12..16]
    )
}

/// Derive the full public-identity outcome from a 32-byte seed.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) if the SDK rejects the seed length (should not
/// happen — the caller pre-checks) or recipient encoding fails.
pub fn build_identity_outcome(seed: &[u8]) -> Result<IdentityOutcome, CliError> {
    // Only the public halves are read; the derived secret halves are local
    // copies and are wiped before this function returns.
    let mut ed25519 =
        derive_ed25519_keypair(seed).map_err(|e| CliError::input(format!("identity: {e}")))?;
    let mut x25519 =
        derive_x25519_keypair(seed).map_err(|e| CliError::input(format!("identity: {e}")))?;
    let mut xwing = derive_mlkem768x25519_keypair(seed)
        .map_err(|e| CliError::input(format!("identity: {e}")))?;
    ed25519.secret_key.zeroize();
    x25519.secret_key.zeroize();
    xwing.secret_seed.zeroize();

    let age_recipient = encode_age_x25519_recipient(&x25519.public_key)
        .map_err(|e| CliError::input(format!("identity: {e}")))?;
    let age1pqc_recipient = encode_age_xwing_recipient(&xwing.public_key)
        .map_err(|e| CliError::input(format!("identity: {e}")))?;

    Ok(IdentityOutcome {
        fingerprint: display_fingerprint(&ed25519.public_key),
        ed25519_pubkey_hex: bytes_to_hex(&ed25519.public_key),
        x25519_pubkey_hex: bytes_to_hex(&x25519.public_key),
        xwing_pubkey_hex: bytes_to_hex(&xwing.public_key),
        age_recipient,
        age1pqc_recipient,
    })
}

/// Resolve and length-check the master seed through the shared secret layer
/// (file > stdin > argv > env > hidden prompt on a TTY > error). The seed is
/// required for `identity`.
fn resolve_seed(args: &IdentityArgs, env: &dyn SecretEnv) -> Result<Zeroizing<Vec<u8>>, CliError> {
    resolve_secret_bytes(SecretKind::Seed, &args.secret_args(), true, "identity", env)
        .map(|opt| opt.expect("a required seed resolves to Some or errors"))
}

/// Abbreviate a long hex string for the human view, appending a byte count.
fn abbreviate(hex: &str, head: usize) -> String {
    if hex.len() <= head * 2 + 1 {
        return hex.to_string();
    }
    format!(
        "{}…{} ({} bytes)",
        &hex[..head],
        &hex[hex.len() - head..],
        hex.len() / 2
    )
}

fn emit(outcome: &IdentityOutcome, json: bool) {
    if json {
        // The JSON shape is a contract; serialise the snake_case struct directly.
        println!(
            "{}",
            serde_json::to_string(outcome).expect("IdentityOutcome serialises")
        );
        return;
    }
    println!("fingerprint:   {}", outcome.fingerprint);
    println!("ed25519:       {}", outcome.ed25519_pubkey_hex);
    println!("x25519:        {}", outcome.x25519_pubkey_hex);
    println!(
        "x-wing:        {}",
        abbreviate(&outcome.xwing_pubkey_hex, XWING_HEX_ABBREV_HEAD)
    );
    println!("age:           {}", outcome.age_recipient);
    println!("age1pqc:       {}", outcome.age1pqc_recipient);
}

/// Run the `identity` command.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) for a missing, malformed, or wrong-length seed.
pub fn run(args: IdentityArgs) -> Result<(), CliError> {
    let seed = resolve_seed(&args, &SystemSecretEnv)?;
    let outcome = build_identity_outcome(&seed)?;
    emit(&outcome, args.json);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::test_support::FakeSecretEnv;

    fn args_with_seed(seed: Option<&str>) -> IdentityArgs {
        IdentityArgs {
            seed: seed.map(str::to_string),
            seed_file: None,
            seed_stdin: false,
            json: false,
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        let seed = [7u8; 32];
        let a = build_identity_outcome(&seed).unwrap();
        let b = build_identity_outcome(&seed).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.ed25519_pubkey_hex, b.ed25519_pubkey_hex);
        assert_eq!(a.age_recipient, b.age_recipient);
        assert!(a.age_recipient.starts_with("age1"));
        assert!(a.age1pqc_recipient.starts_with("age1pqc1"));
    }

    #[test]
    fn rejects_short_seed() {
        let env = FakeSecretEnv::default();
        assert_eq!(
            resolve_seed(&args_with_seed(Some("dead")), &env)
                .unwrap_err()
                .code,
            4
        );
    }

    #[test]
    fn rejects_missing_seed_on_non_tty() {
        // No flag, no env, stdin not a TTY → required-secret input error, no prompt.
        let env = FakeSecretEnv::default();
        assert_eq!(
            resolve_seed(&args_with_seed(None), &env).unwrap_err().code,
            4
        );
    }

    #[test]
    fn resolves_seed_via_argv() {
        let env = FakeSecretEnv::default();
        let seed = resolve_seed(&args_with_seed(Some(&"ab".repeat(32))), &env).unwrap();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn fingerprint_groups_16_hex_chars() {
        let outcome = build_identity_outcome(&[1u8; 32]).unwrap();
        // xxxx-xxxx-xxxx-xxxx → 16 hex + 3 dashes.
        assert_eq!(outcome.fingerprint.len(), 19);
        assert_eq!(outcome.fingerprint.matches('-').count(), 3);
    }

    #[test]
    fn identity_args_debug_redacts_seed() {
        let mut args = args_with_seed(Some(&"ab".repeat(32)));
        args.seed_file = Some("/path/to/seed".to_string());
        let rendered = format!("{args:?}");
        assert!(!rendered.contains(&"ab".repeat(32)));
        assert!(rendered.contains("[redacted]"));
        // The file path is not secret and stays visible for debugging.
        assert!(rendered.contains("/path/to/seed"));
    }
}
