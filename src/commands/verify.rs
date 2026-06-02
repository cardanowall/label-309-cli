//! `cardanowall verify <tx-hash>` — the standalone CIP-309 verifier.
//!
//! A thin shell over the SDK's `verify_tx`: it owns option parsing, gateway
//! resolution, output formatting, and the verdict → exit-code mapping. The
//! verdict's exit code is passed through verbatim, so the public exit-code
//! contract (`0` valid / `1` integrity / `2` network / `3` pending / `4` CLI
//! input) is whatever the verifier decided, plus `4` for CLI-input failures.
//!
//! The verifier is service-independent: given only the transaction hash, public
//! gateways, and optional recipient keys, it fetches the label-309 metadata,
//! validates the record, and runs the profile-gated signature / decryption /
//! Merkle checks — trusting no publisher and no issuer server.

use cardanowall::verifier::fetch::DENY_HOSTS_DEFAULT;
use cardanowall::verifier::{
    verify_report_to_dict, verify_tx, Decryption, Profile, VerifyTxInput,
    CONFIRMATION_DEPTH_THRESHOLD_DEFAULT,
};
use clap::Args;

use crate::config::{
    read_config_file, resolve_gateways, GatewayFlags, SystemConfigEnv, SystemGatewayEnv,
};
use crate::output::render_human_report;
use crate::secret::{SecretEnv, SystemSecretEnv};
use crate::util::{hex_to_bytes, CliError};

/// Arguments for `cardanowall verify`.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// 64-hex Cardano transaction hash.
    pub tx_hash: String,
    /// core | signed | sealed | recipient-sealed (default: signed).
    #[arg(long)]
    pub profile: Option<String>,
    /// Cardano data-source gateway URL (repeatable; Koios-compatible; or env
    /// CARDANOWALL_CARDANO_GATEWAY). The legacy `--gateway` spelling remains as a
    /// hidden alias.
    #[arg(long = "cardano-gateway", visible_alias = "gateway")]
    pub cardano_gateway: Vec<String>,
    /// Blockfrost project id (enables Blockfrost fallback; or env
    /// CARDANOWALL_BLOCKFROST_PROJECT_ID).
    #[arg(long)]
    pub blockfrost: Option<String>,
    /// Arweave gateway URL (repeatable; or env CARDANOWALL_ARWEAVE_GATEWAY).
    #[arg(long = "arweave-gateway")]
    pub arweave_gateway: Vec<String>,
    /// IPFS gateway URL (repeatable; or env CARDANOWALL_IPFS_GATEWAY).
    #[arg(long = "ipfs-gateway")]
    pub ipfs_gateway: Vec<String>,
    /// Confirmation depth threshold (non-negative integer; or env
    /// CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD).
    #[arg(long)]
    pub threshold: Option<String>,
    /// Extra deny-list entries (repeatable; or env CARDANOWALL_DENY_HOST).
    #[arg(long = "deny-host")]
    pub deny_host: Vec<String>,
    /// X25519 recipient secret key for sealed PoE (repeatable; `itemIndex:hex` or
    /// `hex`). INSECURE on argv; prefer --secret-key-file / --secret-key-stdin /
    /// CARDANOWALL_RECIPIENT_KEY (comma/space-separated for several).
    #[arg(long = "secret-key")]
    pub secret_key: Vec<String>,
    /// read recipient secret key(s) from a file (one per line; `itemIndex:hex` ok).
    #[arg(long = "secret-key-file")]
    pub secret_key_file: Option<String>,
    /// read recipient secret key(s) from stdin (one per line).
    #[arg(long = "secret-key-stdin")]
    pub secret_key_stdin: bool,
    /// Skip URI / leaves-list fetches (offline switch).
    #[arg(long = "no-fetch")]
    pub no_fetch: bool,
    /// Emit machine-readable VerifyReport JSON on stdout.
    #[arg(long)]
    pub json: bool,
    /// Pretty-print JSON output (only with --json).
    #[arg(long)]
    pub pretty: bool,
}

const PROFILES: [(&str, Profile); 4] = [
    ("core", Profile::Core),
    ("signed", Profile::Signed),
    ("sealed", Profile::Sealed),
    ("recipient-sealed", Profile::RecipientSealed),
];

/// A parsed `--secret-key` decryption spec.
struct DecryptionSpec {
    item_index: i64,
    recipient_secret_key: Vec<u8>,
}

fn parse_threshold(raw: Option<&str>) -> Result<Option<u32>, CliError> {
    let Some(raw) = raw else { return Ok(None) };
    match raw.parse::<i64>() {
        Ok(n) if n >= 0 && n.to_string() == raw => Ok(Some(n as u32)),
        _ => Err(CliError::input(format!(
            "verify: --threshold must be a non-negative integer; got \"{raw}\""
        ))),
    }
}

/// Gather the raw recipient-secret-key specs from the four sources, in priority
/// order: explicit `--secret-key` flags, then `--secret-key-file`, then
/// `--secret-key-stdin`, then `CARDANOWALL_RECIPIENT_KEY`. The first non-empty
/// source wins (these are alternative inputs, not merged). Each source may carry
/// several keys (repeated flag, one-per-line in a file/stdin, or a comma/space
/// list in the env var).
fn collect_secret_key_specs(
    args: &VerifyArgs,
    env: &dyn SecretEnv,
) -> Result<Vec<String>, CliError> {
    // 1. explicit repeatable flags.
    if !args.secret_key.is_empty() {
        return Ok(args.secret_key.clone());
    }
    // 2. file (one spec per line).
    if let Some(path) = args.secret_key_file.as_deref().filter(|p| !p.is_empty()) {
        let raw = env.read_file(path)?;
        return Ok(split_secret_lines(&raw));
    }
    // 3. stdin.
    if args.secret_key_stdin {
        let raw = env.read_stdin()?;
        return Ok(split_secret_lines(&raw));
    }
    // 4. env var (comma / whitespace separated).
    if let Some(value) = env.var("CARDANOWALL_RECIPIENT_KEY") {
        return Ok(split_secret_list(&value));
    }
    Ok(Vec::new())
}

/// Split file/stdin content into specs: one per non-empty, non-comment line.
fn split_secret_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Split an env value into specs on commas and/or whitespace.
fn split_secret_list(raw: &str) -> Vec<String> {
    raw.split([',', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_secret_key(raw: &str) -> Result<DecryptionSpec, CliError> {
    let (idx, hex) = match raw.split_once(':') {
        Some((idx_raw, hex)) => {
            let idx: i64 = idx_raw.parse().map_err(|_| {
                CliError::input(format!(
                    "verify: --secret-key index must be a non-negative integer; got \"{raw}\""
                ))
            })?;
            if idx < 0 || idx.to_string() != idx_raw {
                return Err(CliError::input(format!(
                    "verify: --secret-key index must be a non-negative integer; got \"{raw}\""
                )));
            }
            (idx, hex)
        }
        None => (0, raw),
    };
    let bytes =
        hex_to_bytes(hex).map_err(|e| CliError::input(format!("verify: --secret-key {e}")))?;
    Ok(DecryptionSpec {
        item_index: idx,
        recipient_secret_key: bytes,
    })
}

/// Default profile discriminator when the user does not pass `--profile`:
/// at least one recipient secret key → `recipient-sealed`; otherwise `signed`.
fn choose_profile(args: &VerifyArgs, have_secret_keys: bool) -> Result<Profile, CliError> {
    if let Some(name) = &args.profile {
        return PROFILES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, p)| *p)
            .ok_or_else(|| {
                CliError::input(format!(
                    "verify: --profile must be one of {{core, signed, sealed, recipient-sealed}}; got \"{name}\""
                ))
            });
    }
    if have_secret_keys {
        return Ok(Profile::RecipientSealed);
    }
    Ok(Profile::Signed)
}

/// Run the `verify` command.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) for CLI-input failures; otherwise returns an
/// error carrying the verifier's own exit code (`1` / `2` / `3`) with an empty
/// message so the report — already emitted — is the user-facing output.
pub fn run(args: VerifyArgs) -> Result<(), CliError> {
    if args.tx_hash.len() != 64 || !args.tx_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::input(format!(
            "verify: <tx-hash> must be 64 hex chars; got \"{}\"",
            args.tx_hash
        )));
    }
    let threshold = parse_threshold(args.threshold.as_deref())?;
    let secret_key_specs = collect_secret_key_specs(&args, &SystemSecretEnv)?;
    let mut decryption: Vec<DecryptionSpec> = Vec::new();
    for raw in &secret_key_specs {
        decryption.push(parse_secret_key(raw)?);
    }
    let profile = choose_profile(&args, !decryption.is_empty())?;

    let config = read_config_file(&SystemConfigEnv)?;
    let flags = GatewayFlags {
        gateway: args.cardano_gateway.clone(),
        blockfrost: args.blockfrost.clone(),
        arweave_gateway: args.arweave_gateway.clone(),
        ipfs_gateway: args.ipfs_gateway.clone(),
        threshold,
        deny_host: args.deny_host.clone(),
    };
    let resolved = resolve_gateways(&flags, &SystemGatewayEnv, config.as_ref())?;

    // SSRF posture: when the user supplies no `--deny-host`, fall back to the
    // canonical deny-list so a `verify` run can never be coaxed into fetching from
    // the operator's own host or localhost.
    let deny_hosts = resolved.deny_hosts.clone().unwrap_or_else(|| {
        DENY_HOSTS_DEFAULT
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    });

    let mut input = VerifyTxInput::new(args.tx_hash.to_lowercase());
    input.profile = profile;
    input.cardano_gateway_chain = Some(resolved.cardano_gateway_chain.clone());
    input.arweave_gateway_chain = Some(resolved.arweave_gateway_chain.clone());
    input.ipfs_gateway_chain = resolved.ipfs_gateway_chain.clone();
    input.blockfrost_project_id = resolved.blockfrost_project_id.clone();
    input.confirmation_depth_threshold = Some(
        resolved
            .confirmation_depth_threshold
            .unwrap_or(CONFIRMATION_DEPTH_THRESHOLD_DEFAULT),
    );
    input.deny_hosts = Some(deny_hosts);
    if !decryption.is_empty() {
        input.decryption = Some(
            decryption
                .into_iter()
                .map(|d| Decryption::Recipient {
                    item_index: d.item_index,
                    recipient_secret_key: d.recipient_secret_key,
                })
                .collect(),
        );
    }
    // `--no-fetch` is the offline switch: it suppresses the verifier's outbound
    // URI / Merkle-leaves fetches. The Rust verifier honours this by omitting the
    // gateway chains used for content fetch (the resolve step still runs); we
    // signal it by clearing the arweave/ipfs chains so no item ciphertext or
    // leaves-list fetch is attempted.
    if args.no_fetch {
        input.arweave_gateway_chain = Some(Vec::new());
        input.ipfs_gateway_chain = Some(Vec::new());
    }

    let report = verify_tx(&input);

    if args.json {
        let dict = verify_report_to_dict(&report);
        let rendered = if args.pretty {
            serde_json::to_string_pretty(&dict)
        } else {
            serde_json::to_string(&dict)
        }
        .expect("VerifyReport dict serialises");
        println!("{rendered}");
    } else {
        render_human_report(&report);
    }

    exit_code_for_report(&report)
}

/// Map a verifier report onto the CLI exit-code contract.
///
/// The verdict's own exit code (`0`/`1`/`2`/`3`) is passed through verbatim; a
/// non-zero code becomes a silent [`CliError`] (the already-emitted report is the
/// user-facing output, so no extra stderr line is added).
pub fn exit_code_for_report(report: &cardanowall::verifier::VerifyReport) -> Result<(), CliError> {
    let code = i32::from(report.exit_code.as_u8());
    if code == 0 {
        Ok(())
    } else {
        Err(CliError {
            code,
            message: String::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args(tx_hash: &str) -> VerifyArgs {
        VerifyArgs {
            tx_hash: tx_hash.to_string(),
            profile: None,
            cardano_gateway: vec![],
            blockfrost: None,
            arweave_gateway: vec![],
            ipfs_gateway: vec![],
            threshold: None,
            deny_host: vec![],
            secret_key: vec![],
            secret_key_file: None,
            secret_key_stdin: false,
            no_fetch: false,
            json: true,
            pretty: false,
        }
    }

    #[test]
    fn rejects_non_hex_tx_hash() {
        assert_eq!(run(base_args("not-a-hex-string")).unwrap_err().code, 4);
    }

    #[test]
    fn rejects_bad_threshold() {
        assert_eq!(parse_threshold(Some("banana")).unwrap_err().code, 4);
        assert_eq!(parse_threshold(Some("-1")).unwrap_err().code, 4);
        assert_eq!(parse_threshold(Some("15")).unwrap(), Some(15));
        assert_eq!(parse_threshold(None).unwrap(), None);
    }

    #[test]
    fn secret_key_parses_index_prefix() {
        let spec = parse_secret_key(&format!("3:{}", "ab".repeat(32))).unwrap();
        assert_eq!(spec.item_index, 3);
        assert_eq!(spec.recipient_secret_key.len(), 32);
        let bare = parse_secret_key(&"cd".repeat(32)).unwrap();
        assert_eq!(bare.item_index, 0);
    }

    #[test]
    fn unknown_profile_is_input_error() {
        let mut args = base_args(&"0".repeat(64));
        args.profile = Some("nope".to_string());
        assert_eq!(choose_profile(&args, false).unwrap_err().code, 4);
    }

    #[test]
    fn secret_key_specs_from_flags_take_priority() {
        use crate::secret::test_support::FakeSecretEnv;
        let mut args = base_args(&"0".repeat(64));
        args.secret_key = vec![format!("0:{}", "ab".repeat(32))];
        let env = FakeSecretEnv {
            vars: std::collections::HashMap::from([(
                "CARDANOWALL_RECIPIENT_KEY".to_string(),
                "cd".repeat(32),
            )]),
            ..FakeSecretEnv::default()
        };
        let specs = collect_secret_key_specs(&args, &env).unwrap();
        assert_eq!(specs, vec![format!("0:{}", "ab".repeat(32))]);
        // And drives the auto profile to recipient-sealed.
        assert_eq!(
            choose_profile(&args, !specs.is_empty()).unwrap(),
            Profile::RecipientSealed
        );
    }

    #[test]
    fn secret_key_specs_from_env_when_no_flag() {
        use crate::secret::test_support::FakeSecretEnv;
        let args = base_args(&"0".repeat(64));
        let env = FakeSecretEnv {
            vars: std::collections::HashMap::from([(
                "CARDANOWALL_RECIPIENT_KEY".to_string(),
                format!("{}, 1:{}", "ab".repeat(32), "cd".repeat(32)),
            )]),
            ..FakeSecretEnv::default()
        };
        let specs = collect_secret_key_specs(&args, &env).unwrap();
        assert_eq!(specs.len(), 2);
    }
}
