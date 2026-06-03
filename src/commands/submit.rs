//! `cardanowall submit` — anchor a CIP-309 PoE from the command line.
//!
//! Wraps the high-level publish helpers (`publish_content` / `publish_prehashed`
//! / `publish_merkle`) and surfaces them as one subcommand with three mutually
//! exclusive modes:
//!
//! - `--hash <64-hex>`         anchor a precomputed digest (no I/O)
//! - `--file <path>`           hash the file contents and anchor the digest
//! - `--merkle <leaves-file>`  read one 64-hex leaf per line, build a Merkle tree,
//!   anchor the root + leaves-list (Arweave)
//!
//! Pricing protocol: each submit quotes the price, then passes the `quote_id` to
//! the publish helper; the server consumes the quote atomically with the record
//! insert.
//!
//! Signer architecture: the SDK never holds identity keys. The optional `--seed`
//! is the 32-byte master identity seed; the record-signing Ed25519 key is derived
//! from it (the same key `identity --seed` prints). Omit it to publish unsigned.
//!
//! Gateway-agnostic: `--base-url` (or `CARDANOWALL_BASE_URL`) and `--api-key` (or
//! `CARDANOWALL_API_KEY`) are required; the key is an opaque bearer forwarded
//! verbatim, never inspected.
//!
//! Exit codes: `0` ok / `1` server rejection / `2` network or partial-upload
//! failure / `4` CLI input error.

use cardanowall::client::types::{PublishContentInput, SupportedHashAlg};
use cardanowall::client::{
    Cip309Client, Cip309ClientConfig, ClientError, MerkleLeaf, PublishError, PublishHelperError,
    PublishMerkleInput, PublishPrehashedInput, QuoteInput,
};
use cardanowall::seed_derive::{signer_from_seed, SeedSigner};
use clap::Args;
use serde::Serialize;

use crate::config::{load_config_for_edit, SystemConfigEnv};
use crate::secret::{
    resolve_secret_bytes, resolve_service_gateway, SecretArgs, SecretEnv, SecretKind,
    ServiceGateway, SystemSecretEnv,
};
use crate::util::{bytes_to_hex, hex_to_bytes, CliError};

const SHA2_256_DIGEST_BYTES: usize = 32;
const MASTER_SEED_BYTES: usize = 32;
const HEX_PREFIX_BYTES_PER_LEAF: u64 = 32;
// Conservative byte-budget inputs to the quote; the server re-prices.
const HASH_RECORD_BYTES_ESTIMATE: u64 = 256;
const MERKLE_RECORD_BYTES_ESTIMATE: u64 = 320;

/// Arguments for `cardanowall submit`.
#[derive(Debug, Args)]
pub struct SubmitArgs {
    /// 64-hex precomputed digest (default alg sha2-256).
    #[arg(long)]
    pub hash: Option<String>,
    /// path to a file whose contents will be hashed and anchored.
    #[arg(long)]
    pub file: Option<String>,
    /// file with one 64-hex sha2-256 leaf per line; anchors a Merkle root.
    #[arg(long)]
    pub merkle: Option<String>,
    /// hash algorithm: 'sha2-256' (default) or 'blake2b-256' (--merkle: sha2-256 only).
    #[arg(long)]
    pub alg: Option<String>,
    /// opaque bearer API key (or env CARDANOWALL_API_KEY, or the active gateway
    /// profile). Required.
    #[arg(long = "api-key")]
    pub api_key: Option<String>,
    /// 32-byte master identity seed (hex). Omit to publish unsigned. INSECURE on
    /// argv (shell history / ps / CI logs); prefer --seed-file / --seed-stdin /
    /// CARDANOWALL_SEED.
    #[arg(long)]
    pub seed: Option<String>,
    /// read the seed from a file (trailing whitespace trimmed).
    #[arg(long = "seed-file")]
    pub seed_file: Option<String>,
    /// read the seed from stdin (also `--seed -`).
    #[arg(long = "seed-stdin")]
    pub seed_stdin: bool,
    /// target CIP-309 gateway base URL (or env CARDANOWALL_BASE_URL, or the active
    /// gateway profile). Required.
    #[arg(long = "base-url")]
    pub base_url: Option<String>,
    /// use this saved gateway profile (overrides the config default_gateway).
    #[arg(long = "gateway-profile")]
    pub gateway_profile: Option<String>,
    /// emit a machine-readable JSON summary on stdout.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct SubmitOutcome {
    mode: &'static str,
    id: String,
    tx_hash: Option<String>,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    items_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ar_uri: Option<String>,
    balance_after_usd_micros: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Hash,
    File,
    Merkle,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Hash => "hash",
            Mode::File => "file",
            Mode::Merkle => "merkle",
        }
    }
}

impl SubmitArgs {
    fn seed_secret_args(&self) -> SecretArgs {
        SecretArgs {
            value: self.seed.clone(),
            file: self.seed_file.clone(),
            stdin: self.seed_stdin,
        }
    }
}

/// Resolve the required service gateway (base URL + optional API key) through
/// `flag > env > active gateway profile`, and require a non-empty API key.
fn resolve_gateway(args: &SubmitArgs, env: &dyn SecretEnv) -> Result<ServiceGateway, CliError> {
    let config = load_config_for_edit(&SystemConfigEnv)?;
    resolve_gateway_with(args, &config, env)
}

/// The config-injected core of [`resolve_gateway`], so tests need no on-disk file.
fn resolve_gateway_with(
    args: &SubmitArgs,
    config: &crate::config::CardanoWallConfig,
    env: &dyn SecretEnv,
) -> Result<ServiceGateway, CliError> {
    let profile = config.select_gateway(args.gateway_profile.as_deref(), "submit")?;
    let gateway = resolve_service_gateway(
        args.base_url.as_deref(),
        args.api_key.as_deref(),
        profile,
        "submit",
        env,
    )?;
    if gateway.api_key.as_deref().is_none_or(str::is_empty) {
        return Err(CliError::input(
            "submit: an API key is required — pass --api-key, set CARDANOWALL_API_KEY, \
             or configure a gateway profile with a key",
        ));
    }
    Ok(gateway)
}

/// Build the optional seed signer via the shared secret layer; a malformed seed is
/// a CLI input error. The seed is OPTIONAL (omit to publish unsigned), so the
/// hidden prompt never fires — only file/stdin/argv/env supply it.
fn resolve_signer(args: &SubmitArgs, env: &dyn SecretEnv) -> Result<Option<SeedSigner>, CliError> {
    let Some(seed) = resolve_secret_bytes(
        SecretKind::Seed,
        &args.seed_secret_args(),
        MASTER_SEED_BYTES,
        false,
        "submit",
        env,
    )?
    else {
        return Ok(None);
    };
    signer_from_seed(&seed)
        .map(Some)
        .map_err(|e| CliError::input(format!("submit: --seed {e}")))
}

fn choose_mode(args: &SubmitArgs) -> Result<Mode, CliError> {
    let mut modes = Vec::new();
    if args.hash.is_some() {
        modes.push(Mode::Hash);
    }
    if args.file.is_some() {
        modes.push(Mode::File);
    }
    if args.merkle.is_some() {
        modes.push(Mode::Merkle);
    }
    match modes.len() {
        0 => Err(CliError::input(
            "submit: exactly one of --hash / --file / --merkle is required",
        )),
        1 => Ok(modes[0]),
        _ => Err(CliError::input(format!(
            "submit: --hash / --file / --merkle are mutually exclusive (got: {})",
            modes
                .iter()
                .map(|m| m.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

fn resolve_hash_alg(args: &SubmitArgs) -> Result<SupportedHashAlg, CliError> {
    match args
        .alg
        .as_deref()
        .map(str::to_lowercase)
        .as_deref()
        .unwrap_or("sha2-256")
    {
        "sha2-256" => Ok(SupportedHashAlg::Sha2_256),
        "blake2b-256" => Ok(SupportedHashAlg::Blake2b256),
        other => Err(CliError::input(format!(
            "submit: --alg must be 'sha2-256' or 'blake2b-256' (got '{other}')"
        ))),
    }
}

fn parse_leaves_file(text: &str, path: &str) -> Result<Vec<String>, CliError> {
    let mut leaves = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CliError::input(format!(
                "submit: --merkle {path}: line {} is not a 64-hex sha2-256 leaf: \"{t}\"",
                i + 1
            )));
        }
        leaves.push(t.to_lowercase());
    }
    if leaves.is_empty() {
        return Err(CliError::input(format!(
            "submit: --merkle {path} contains no leaves"
        )));
    }
    Ok(leaves)
}

/// Render USD micro-cents as `$X.XX`.
fn format_usd_micros(micros_str: &str) -> String {
    let Ok(micros) = micros_str.parse::<i128>() else {
        return micros_str.to_string();
    };
    let negative = micros < 0;
    let abs = micros.unsigned_abs();
    let dollars = abs / 1_000_000;
    let fractional = abs % 1_000_000;
    let cents = (fractional + 5_000) / 10_000;
    let (whole_cents, display_cents) = if cents == 100 {
        (dollars + 1, 0)
    } else {
        (dollars, cents)
    };
    let sign = if negative { "-" } else { "" };
    format!("{sign}${whole_cents}.{display_cents:02}")
}

fn emit_outcome(outcome: &SubmitOutcome, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string(outcome).expect("SubmitOutcome serialises")
        );
        return;
    }
    println!("ok: {}", outcome.id);
    println!("  status:      {}", outcome.status);
    println!(
        "  tx_hash:     {}",
        outcome.tx_hash.as_deref().unwrap_or("<pending>")
    );
    if let Some(items) = outcome.items_count {
        println!("  items_count: {items}");
    }
    if let Some(root) = &outcome.root {
        println!("  root:        {root}");
        println!("  leaf_count:  {}", outcome.leaf_count.unwrap_or(0));
        println!("  ar_uri:      {}", outcome.ar_uri.as_deref().unwrap_or(""));
    }
    println!(
        "  balance:     {}",
        format_usd_micros(&outcome.balance_after_usd_micros)
    );
}

/// Map a publish-helper error onto the submit exit-code contract.
fn map_publish_error(err: PublishHelperError) -> CliError {
    match err {
        PublishHelperError::Validation(e) => {
            // Pre-network input/shape error → CLI input error (4).
            CliError::new(4, format!("submit: {}: {e}", PublishError::code(e)))
        }
        PublishHelperError::Signer(e) => CliError::new(4, format!("submit: signer: {e}")),
        PublishHelperError::PartialUpload(e) => {
            let indices = e
                .failed_indices()
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            CliError::network(format!(
                "submit: partial-upload-failure (indices: {indices})"
            ))
        }
        PublishHelperError::Http(ClientError::Http(http)) => {
            let request_id = if http.request_id().is_empty() {
                String::new()
            } else {
                format!(" (x-request-id: {})", http.request_id())
            };
            CliError::integrity(format!(
                "submit: HTTP {} {}: {}{request_id}",
                http.http_status(),
                http.code(),
                http.problem().detail
            ))
        }
        PublishHelperError::Http(other) => CliError::network(format!("submit: {other}")),
        PublishHelperError::Crypto(msg) => CliError::network(format!("submit: {msg}")),
    }
}

/// Run the `submit` command.
///
/// # Errors
///
/// Returns [`CliError`] with the mapped exit code.
pub fn run(args: SubmitArgs) -> Result<(), CliError> {
    let mode = choose_mode(&args)?;
    let gateway = resolve_gateway(&args, &SystemSecretEnv)?;
    let signer = resolve_signer(&args, &SystemSecretEnv)?;
    let signer_ref: Option<&dyn cardanowall::client::Signer> = signer
        .as_ref()
        .map(|s| s as &dyn cardanowall::client::Signer);

    let client = Cip309Client::new(Cip309ClientConfig {
        api_key: gateway.api_key,
        base_url: Some(gateway.base_url),
    })
    .map_err(|e| CliError::input(format!("submit: {e}")))?;
    let poe = client.poe();

    match mode {
        Mode::Hash => {
            let hex = args.hash.as_ref().unwrap().trim().to_lowercase();
            let digest =
                hex_to_bytes(&hex).map_err(|e| CliError::input(format!("submit: --hash {e}")))?;
            if digest.len() != SHA2_256_DIGEST_BYTES {
                return Err(CliError::input(format!(
                    "submit: --hash must decode to exactly {SHA2_256_DIGEST_BYTES} bytes (got {})",
                    digest.len()
                )));
            }
            let alg = resolve_hash_alg(&args)?;
            let quote = poe
                .quote(&QuoteInput {
                    record_bytes: HASH_RECORD_BYTES_ESTIMATE,
                    recipient_count: 0,
                    file_bytes_total: 0,
                })
                .map_err(map_client_error)?;
            let res = poe
                .publish_prehashed(&PublishPrehashedInput {
                    hashes: vec![(alg, bytes_to_hex(&digest))],
                    quote_id: quote.quote_id,
                    signer: signer_ref,
                    idempotency_key: None,
                })
                .map_err(map_publish_error)?;
            emit_outcome(
                &SubmitOutcome {
                    mode: "hash",
                    id: res.id,
                    tx_hash: res.tx_hash,
                    status: res.status,
                    items_count: Some(res.items_count),
                    root: None,
                    leaf_count: None,
                    ar_uri: None,
                    balance_after_usd_micros: res.balance_after_usd_micros,
                },
                args.json,
            );
            Ok(())
        }
        Mode::File => {
            let path = args.file.as_ref().unwrap();
            let content = std::fs::read(path).map_err(|e| {
                CliError::network(format!("submit: cannot read --file {path}: {e}"))
            })?;
            let alg = resolve_hash_alg(&args)?;
            let quote = poe
                .quote(&QuoteInput {
                    record_bytes: HASH_RECORD_BYTES_ESTIMATE,
                    recipient_count: 0,
                    file_bytes_total: 0,
                })
                .map_err(map_client_error)?;
            let res = poe
                .publish_content(&PublishContentInput {
                    content,
                    quote_id: quote.quote_id,
                    hash_alg: Some(alg),
                    signer: signer_ref,
                    idempotency_key: None,
                })
                .map_err(map_publish_error)?;
            emit_outcome(
                &SubmitOutcome {
                    mode: "file",
                    id: res.id,
                    tx_hash: res.tx_hash,
                    status: res.status,
                    items_count: Some(res.items_count),
                    root: None,
                    leaf_count: None,
                    ar_uri: None,
                    balance_after_usd_micros: res.balance_after_usd_micros,
                },
                args.json,
            );
            Ok(())
        }
        Mode::Merkle => {
            let path = args.merkle.as_ref().unwrap();
            let text = std::fs::read_to_string(path).map_err(|e| {
                CliError::network(format!("submit: cannot read --merkle {path}: {e}"))
            })?;
            let leaves = parse_leaves_file(&text, path)?;
            let alg = args
                .alg
                .as_deref()
                .map(str::to_lowercase)
                .unwrap_or_else(|| "sha2-256".to_string());
            if alg != "sha2-256" {
                return Err(CliError::input(format!(
                    "submit: --merkle currently supports only sha2-256 leaves (got '{alg}')"
                )));
            }
            let leaf_count = leaves.len() as u64;
            let quote = poe
                .quote(&QuoteInput {
                    record_bytes: MERKLE_RECORD_BYTES_ESTIMATE,
                    recipient_count: 0,
                    file_bytes_total: leaf_count * HEX_PREFIX_BYTES_PER_LEAF + 64,
                })
                .map_err(map_client_error)?;
            let res = poe
                .publish_merkle(&PublishMerkleInput {
                    leaves: leaves.into_iter().map(MerkleLeaf::Hex).collect(),
                    quote_id: quote.quote_id,
                    hash_alg: None,
                    signer: signer_ref,
                    idempotency_key: None,
                })
                .map_err(map_publish_error)?;
            emit_outcome(
                &SubmitOutcome {
                    mode: "merkle",
                    id: res.id,
                    tx_hash: res.tx_hash,
                    status: res.status,
                    items_count: None,
                    root: Some(res.root),
                    leaf_count: Some(res.leaf_count),
                    ar_uri: Some(res.ar_uri),
                    balance_after_usd_micros: res.balance_after_usd_micros,
                },
                args.json,
            );
            Ok(())
        }
    }
}

/// Map a bare `ClientError` (from `quote`) onto the submit exit-code contract.
fn map_client_error(err: ClientError) -> CliError {
    match err {
        ClientError::Http(http) => {
            let request_id = if http.request_id().is_empty() {
                String::new()
            } else {
                format!(" (x-request-id: {})", http.request_id())
            };
            CliError::integrity(format!(
                "submit: HTTP {} {}: {}{request_id}",
                http.http_status(),
                http.code(),
                http.problem().detail
            ))
        }
        other => CliError::network(format!("submit: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::test_support::FakeSecretEnv;

    fn base_args() -> SubmitArgs {
        SubmitArgs {
            hash: None,
            file: None,
            merkle: None,
            alg: None,
            api_key: None,
            seed: None,
            seed_file: None,
            seed_stdin: false,
            base_url: None,
            gateway_profile: None,
            json: false,
        }
    }

    #[test]
    fn requires_exactly_one_mode() {
        let mut args = base_args();
        assert_eq!(choose_mode(&args).unwrap_err().code, 4);
        args.hash = Some("aa".repeat(32));
        args.file = Some("/x".to_string());
        assert_eq!(choose_mode(&args).unwrap_err().code, 4);
    }

    #[test]
    fn requires_base_url() {
        // No base URL from any source → input error before any network call.
        let args = base_args();
        let env = FakeSecretEnv::default();
        let config = crate::config::CardanoWallConfig::default();
        let profile = config.select_gateway(None, "submit").unwrap();
        let err = resolve_service_gateway(
            args.base_url.as_deref(),
            args.api_key.as_deref(),
            profile,
            "submit",
            &env,
        )
        .unwrap_err();
        assert_eq!(err.code, 4);
    }

    #[test]
    fn requires_api_key_even_with_base_url() {
        // A base URL but no API key → input error (the gateway API is key-only).
        let mut args = base_args();
        args.base_url = Some("https://gw.example".to_string());
        let env = FakeSecretEnv::default();
        let config = crate::config::CardanoWallConfig::default();
        assert_eq!(
            resolve_gateway_with(&args, &config, &env).unwrap_err().code,
            4
        );
    }

    #[test]
    fn gateway_profile_supplies_base_url_and_key() {
        // With no flags/env, the active profile fills both slots.
        let mut config = crate::config::CardanoWallConfig::default();
        config.gateways.insert(
            "prod".to_string(),
            crate::config::GatewayProfile {
                base_url: "https://gw.example".to_string(),
                api_key: Some("k".to_string()),
            },
        );
        config.default_gateway = Some("prod".to_string());
        let env = FakeSecretEnv::default();
        let gw = resolve_gateway_with(&base_args(), &config, &env).unwrap();
        assert_eq!(gw.base_url, "https://gw.example");
        assert_eq!(gw.api_key.as_deref(), Some("k"));
    }

    #[test]
    fn rejects_malformed_seed() {
        let mut args = base_args();
        args.seed = Some("dead".to_string());
        let env = FakeSecretEnv::default();
        assert_eq!(resolve_signer(&args, &env).unwrap_err().code, 4);
    }

    #[test]
    fn no_seed_is_unsigned() {
        let args = base_args();
        let env = FakeSecretEnv::default();
        assert!(resolve_signer(&args, &env).unwrap().is_none());
    }

    #[test]
    fn formats_usd_micros() {
        assert_eq!(format_usd_micros("1500000"), "$1.50");
        assert_eq!(format_usd_micros("0"), "$0.00");
        assert_eq!(format_usd_micros("999995"), "$1.00");
        assert_eq!(format_usd_micros("-2500000"), "-$2.50");
    }

    #[test]
    fn parses_leaves_file() {
        let text = format!("# header\n{}\n\n{}\n", "ab".repeat(32), "cd".repeat(32));
        let leaves = parse_leaves_file(&text, "f").unwrap();
        assert_eq!(leaves.len(), 2);
    }

    #[test]
    fn rejects_bad_leaf() {
        assert_eq!(parse_leaves_file("zzz\n", "f").unwrap_err().code, 4);
    }
}
