//! `cardanowall inbox` — sealed-PoE inbox over a raw recipient key. Raw-seed-first;
//! no account envelope.
//!
//! Three verbs:
//!
//! - `sync`    — page sealed records from a CIP-309 gateway
//!   (`/api/v1/records?sealed=true`), trial-decrypt each item with the recipient
//!   key bundle, and persist confirmed matches to the local bookmark. Records
//!   below the confirmation-depth threshold are reported as pending and
//!   re-evaluated on the next sync.
//! - `list`    — print the locally-persisted bookmark (optionally tip-refreshed
//!   via `--gateway`).
//! - `decrypt` — fetch a sealed record's ciphertext, unwrap it with the recipient
//!   X25519 key, and recompute the plaintext content hashes.
//!
//! Identity is raw-seed-first: `--seed <hex>` (full key set, locates the bookmark
//! and reads hybrid records) or `--secret-key <hex>` (X25519-only, classical
//! records, cannot locate the bookmark). Gateway reads require `--base-url`
//! (+ `--api-key` when the gateway needs auth).
//!
//! Exit codes: `0` ok / `1` integrity (bad record, hash mismatch, wrong key) /
//! `2` network / `4` CLI input error.

use std::collections::HashMap;

use cardanowall::client::{Cip309Client, Cip309ClientConfig, ClientError, RecordsListInput};
use cardanowall::poe_standard::{validate_poe_record, ValidateResult};
use cardanowall::sealed_poe::{
    ecies_sealed_poe_trial_decrypt, ecies_sealed_poe_unwrap, TrialDecryptKeys, TrialDecryptResult,
    UnwrapKeys, UnwrapResult,
};
use cardanowall::verifier::extract_label_309_metadata;
use cardanowall::verifier::fetch::{ReqwestTransport, DENY_HOSTS_DEFAULT};
use cardanowall::verifier::{
    fetch_item_ciphertext, resolve_cardano_tx, GatewayFetcher, CONFIRMATION_DEPTH_THRESHOLD_DEFAULT,
};
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::config::{
    load_config_for_edit, read_config_file, resolve_gateways, GatewayFlags, ResolvedGateways,
    SystemConfigEnv, SystemGatewayEnv,
};
use crate::inbox::identity::ResolvedIdentity;
use crate::inbox::{envelope_from_item, recompute_item_hashes, RecomputeResult};
use crate::output::render_inbox_list_human;
use crate::secret::SystemSecretEnv;
use crate::state::{
    bookmark_path, ed25519_prefix, ed25519_pubkey_hex, load_or_init, save, SealedMatchEntry,
};
use crate::util::{base64::decode_standard, CliError};

/// Arguments for `cardanowall inbox`.
#[derive(Debug, Args)]
pub struct InboxArgs {
    /// The inbox verb to run.
    #[command(subcommand)]
    pub verb: InboxVerb,
}

/// The three inbox verbs.
#[derive(Debug, Subcommand)]
pub enum InboxVerb {
    /// Pull sealed records from a gateway and trial-decrypt them locally.
    Sync(InboxSyncArgs),
    /// Print sealed-PoE matches from the local bookmark.
    List(InboxListArgs),
    /// Decrypt sealed-PoE items at the given tx-hash using your X25519 key.
    Decrypt(InboxDecryptArgs),
}

impl InboxArgs {
    /// Whether the active verb was invoked with `--json`.
    #[must_use]
    pub fn json_mode(&self) -> bool {
        match &self.verb {
            InboxVerb::Sync(a) => a.json,
            InboxVerb::List(a) => a.json,
            InboxVerb::Decrypt(a) => a.json,
        }
    }
}

/// Run the `inbox` command.
///
/// # Errors
///
/// Returns [`CliError`] with the verb's mapped exit code.
pub fn run(args: InboxArgs) -> Result<(), CliError> {
    match args.verb {
        InboxVerb::Sync(a) => run_sync(a),
        InboxVerb::List(a) => run_list(a),
        InboxVerb::Decrypt(a) => run_decrypt(a),
    }
}

// ===========================================================================
// Shared identity + gateway plumbing
// ===========================================================================

/// Resolve the identity and require the seed-derived Ed25519 key so the
/// bookmark-locating commands have a per-identity path.
fn resolve_identity_with_ed25519(
    source: &crate::inbox::IdentitySource,
    cmd: &str,
) -> Result<(ResolvedIdentity, Vec<u8>), CliError> {
    let identity = source.resolve(cmd, &SystemSecretEnv)?;
    let Some(ed25519) = identity.ed25519_public_key.clone() else {
        return Err(CliError::input(format!(
            "{cmd}: --secret-key alone is insufficient to locate the bookmark file \
             (no Ed25519 derivation path; the bookmark path is keyed by the Ed25519 public key). \
             Use --seed instead."
        )));
    };
    Ok((identity, ed25519))
}

/// Resolve the service gateway (base URL + API key) for an inbox network verb via
/// `flag > env > active gateway profile`.
fn resolve_service_gateway_for(
    base_url: Option<&str>,
    api_key: Option<&str>,
    gateway_profile: Option<&str>,
    cmd: &str,
) -> Result<crate::secret::ServiceGateway, CliError> {
    let config = load_config_for_edit(&SystemConfigEnv)?;
    let profile = config.select_gateway(gateway_profile, cmd)?;
    crate::secret::resolve_service_gateway(base_url, api_key, profile, cmd, &SystemSecretEnv)
}

fn resolve_gateways_for(flags: GatewayFlags, cmd: &str) -> Result<ResolvedGateways, CliError> {
    let config = read_config_file(&SystemConfigEnv).map_err(|e| relabel(e, cmd))?;
    resolve_gateways(&flags, &SystemGatewayEnv, config.as_ref()).map_err(|e| relabel(e, cmd))
}

/// Relabel a `verify:`-prefixed gateway error to the active inbox command.
fn relabel(err: CliError, cmd: &str) -> CliError {
    CliError {
        code: err.code,
        message: err.message.replacen("verify:", &format!("{cmd}:"), 1),
    }
}

// ===========================================================================
// inbox sync
// ===========================================================================

/// Arguments for `cardanowall inbox sync`.
#[derive(Debug, Args)]
pub struct InboxSyncArgs {
    /// target CIP-309 gateway base URL (or env CARDANOWALL_BASE_URL, or a profile).
    #[arg(long = "base-url")]
    pub base_url: Option<String>,
    /// opaque bearer API key (or env CARDANOWALL_API_KEY, or a profile).
    #[arg(long = "api-key")]
    pub api_key: Option<String>,
    /// use this saved gateway profile (overrides the config default_gateway).
    #[arg(long = "gateway-profile")]
    pub gateway_profile: Option<String>,
    /// confirmation-depth threshold (non-negative integer; default 15).
    #[arg(long)]
    pub threshold: Option<u32>,
    /// The identity source (seed or X25519 secret key; raw / file / stdin / env).
    #[command(flatten)]
    pub identity: crate::inbox::IdentitySource,
    /// emit machine-readable summary JSON on stdout.
    #[arg(long)]
    pub json: bool,
    /// pretty-print --json output.
    #[arg(long)]
    pub pretty: bool,
}

#[derive(Debug, Serialize)]
struct SyncSummary {
    scanned: usize,
    matched: usize,
    pending: usize,
    tampered: usize,
    dropped: usize,
    last_cursor: u64,
}

const SYNC_PAGE_LIMIT: u64 = 100;
const MAX_SYNC_PAGES: usize = 10_000;

fn build_client(
    base_url: String,
    api_key: Option<&str>,
    cmd: &str,
) -> Result<Cip309Client, CliError> {
    Cip309Client::new(Cip309ClientConfig {
        api_key: api_key.map(str::to_string).filter(|s| !s.is_empty()),
        base_url: Some(base_url),
    })
    .map_err(|e| CliError::input(format!("{cmd}: {e}")))
}

fn run_sync(args: InboxSyncArgs) -> Result<(), CliError> {
    let (identity, ed25519) = resolve_identity_with_ed25519(&args.identity, "inbox sync")?;
    let threshold = args
        .threshold
        .unwrap_or(CONFIRMATION_DEPTH_THRESHOLD_DEFAULT);

    let gateway = resolve_service_gateway_for(
        args.base_url.as_deref(),
        args.api_key.as_deref(),
        args.gateway_profile.as_deref(),
        "inbox sync",
    )?;
    let client = build_client(gateway.base_url, gateway.api_key.as_deref(), "inbox sync")?;
    let records = client.records();

    let prefix = ed25519_prefix(&ed25519)?;
    let ed25519_hex = ed25519_pubkey_hex(&ed25519)?;
    let path = bookmark_path(&prefix)?;
    let mut bookmark = load_or_init(&path, &ed25519_hex)?;

    let bundle = identity.recipient_key_bundle();
    let now = current_iso8601();

    let mut existing: std::collections::HashSet<(String, usize, usize)> = bookmark
        .matched
        .iter()
        .map(|m| (m.tx_hash.clone(), m.item_idx, m.slot_idx))
        .collect();

    let mut scanned = 0usize;
    let mut new_matches = 0usize;
    let mut pending = 0usize;
    let mut tampered = 0usize;
    let mut dropped = 0usize;
    let mut tip_block_height = bookmark.last_processed_block_height;

    let mut cursor: Option<String> = None;
    let mut pages = 0usize;
    loop {
        let page = records
            .list(Some(&RecordsListInput {
                cursor: cursor.clone(),
                limit: Some(SYNC_PAGE_LIMIT),
                sealed: Some(true),
            }))
            .map_err(|e| map_inbox_client_error(e, "inbox sync"))?;
        // The gateway may not report the chain tip; when it does, advance the
        // durable progress marker. When it doesn't, the SDK's per-page
        // derivation fills it from the rows, and an absent value (an empty
        // page) leaves the marker unchanged.
        if let Some(tip) = page.tip_block_height {
            tip_block_height = tip_block_height.max(tip);
        }

        for record in &page.data {
            scanned += 1;
            let metadata = match decode_standard(&record.metadata_cbor_base64) {
                Ok(bytes) => bytes,
                Err(_) => {
                    dropped += 1;
                    continue;
                }
            };
            let validated = match validate_poe_record(&metadata) {
                ValidateResult::Ok { record, .. } => *record,
                ValidateResult::Fail { .. } => {
                    dropped += 1;
                    continue;
                }
            };
            let confirmed = record.num_confirmations >= u64::from(threshold);
            let items = validated.items.unwrap_or_default();
            // A poisoned record must never abort the whole sync; drop just this row.
            let mut row_dropped = false;
            for (i, item) in items.iter().enumerate() {
                let Some(envelope) = envelope_from_item(item) else {
                    continue;
                };
                match ecies_sealed_poe_trial_decrypt(
                    &envelope,
                    TrialDecryptKeys::Bundle(&bundle),
                    true,
                    None,
                ) {
                    Ok(TrialDecryptResult::Match { slot_idx, .. }) => {
                        if confirmed {
                            let key = (record.tx_hash.clone(), i, slot_idx);
                            if existing.insert(key) {
                                bookmark.matched.push(SealedMatchEntry {
                                    tx_hash: record.tx_hash.clone(),
                                    item_idx: i,
                                    slot_idx,
                                    first_seen: now.clone(),
                                    block_height: record.block_height,
                                    num_confirmations_at_first_seen: Some(record.num_confirmations),
                                });
                                new_matches += 1;
                            }
                        } else {
                            pending += 1;
                        }
                    }
                    Ok(TrialDecryptResult::AeadPassNoMacMatch) => tampered += 1,
                    Ok(TrialDecryptResult::NoAeadPass) => {}
                    Err(_) => {
                        row_dropped = true;
                        break;
                    }
                }
            }
            if row_dropped {
                dropped += 1;
            }
        }

        pages += 1;
        if !page.has_more || page.next_cursor.is_none() || pages >= MAX_SYNC_PAGES {
            cursor = page.next_cursor;
            break;
        }
        cursor = page.next_cursor;
    }

    bookmark.last_processed_block_height = tip_block_height;
    // The indexer cursor is an opaque string; we persist the block-height tip as
    // the durable progress marker and reset the numeric cursor to the tip.
    bookmark.last_processed_cursor = tip_block_height;
    save(&path, &bookmark)?;

    let summary = SyncSummary {
        scanned,
        matched: new_matches,
        pending,
        tampered,
        dropped,
        last_cursor: bookmark.last_processed_cursor,
    };
    if args.json {
        let value = serde_json::json!({
            "schema_version": 1,
            "scanned": summary.scanned,
            "matched": summary.matched,
            "pending": summary.pending,
            "tampered": summary.tampered,
            "dropped": summary.dropped,
            "last_cursor": summary.last_cursor,
            "last_block_height": bookmark.last_processed_block_height,
        });
        let rendered = if args.pretty {
            serde_json::to_string_pretty(&value)
        } else {
            serde_json::to_string(&value)
        }
        .expect("sync summary serialises");
        println!("{rendered}");
    } else {
        println!(
            "synced: {} records scanned, {} matched, {} pending (below threshold), {} tampered, {} dropped. last_cursor={}",
            summary.scanned, summary.matched, summary.pending, summary.tampered, summary.dropped, summary.last_cursor
        );
    }
    let _ = cursor;
    Ok(())
}

// ===========================================================================
// inbox list
// ===========================================================================

/// Arguments for `cardanowall inbox list`.
#[derive(Debug, Args)]
pub struct InboxListArgs {
    /// Cardano gateway URL (optional; refreshes num_confirmations).
    #[arg(long = "cardano-gateway", visible_alias = "gateway")]
    pub gateway: Vec<String>,
    /// Blockfrost project id (enables Blockfrost fallback).
    #[arg(long)]
    pub blockfrost: Option<String>,
    /// extra deny-list entries (repeatable).
    #[arg(long = "deny-host")]
    pub deny_host: Vec<String>,
    /// The identity source (seed or X25519 secret key; raw / file / stdin / env).
    #[command(flatten)]
    pub identity: crate::inbox::IdentitySource,
    /// emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// pretty-print JSON output.
    #[arg(long)]
    pub pretty: bool,
}

fn run_list(args: InboxListArgs) -> Result<(), CliError> {
    let (_identity, ed25519) = resolve_identity_with_ed25519(&args.identity, "inbox list")?;
    let prefix = ed25519_prefix(&ed25519)?;
    let ed25519_hex = ed25519_pubkey_hex(&ed25519)?;
    let path = bookmark_path(&prefix)?;

    if !path.exists() {
        eprintln!(
            "inbox: no bookmark file at {} — run 'cardanowall inbox sync' first",
            path.display()
        );
        if args.json {
            let value = serde_json::json!({
                "schema_version": 1,
                "identity_pubkey_ed25519_hex": ed25519_hex,
                "bookmark_path": path.display().to_string(),
                "last_processed_cursor": 0,
                "last_processed_block_height": 0,
                "matched": [],
                "pending": [],
            });
            print_json(&value, args.pretty);
        }
        return Ok(());
    }

    let bookmark = load_or_init(&path, &ed25519_hex)?;

    // Optional tip refresh: only when --gateway is supplied.
    let mut tip_refreshed: Option<HashMap<String, u32>> = None;
    if !args.gateway.is_empty() {
        let flags = GatewayFlags {
            gateway: args.gateway.clone(),
            blockfrost: args.blockfrost.clone(),
            deny_host: args.deny_host.clone(),
            ..GatewayFlags::default()
        };
        let resolved = resolve_gateways_for(flags, "inbox list")?;
        let transport = ReqwestTransport::new();
        let deny_hosts = deny_hosts_or_default(&resolved);
        let mut fetcher = GatewayFetcher::new(&transport, Some(&deny_hosts));
        let mut refreshed = HashMap::new();
        let unique: Vec<String> = {
            let mut seen = std::collections::HashSet::new();
            bookmark
                .matched
                .iter()
                .map(|m| m.tx_hash.clone())
                .filter(|h| seen.insert(h.clone()))
                .collect()
        };
        for tx_hash in unique {
            match resolve_cardano_tx(
                &tx_hash,
                Some(&resolved.cardano_gateway_chain),
                resolved.blockfrost_project_id.as_deref(),
                &mut fetcher,
            ) {
                Ok(r) => {
                    refreshed.insert(tx_hash, r.num_confirmations);
                }
                Err(e) => {
                    eprintln!("inbox list: tip refresh failed for {tx_hash}: {e}");
                }
            }
        }
        tip_refreshed = Some(refreshed);
    }

    if args.json {
        let mut matched: Vec<serde_json::Value> = bookmark
            .matched
            .iter()
            .map(|m| {
                let refreshed = tip_refreshed.as_ref().and_then(|t| t.get(&m.tx_hash));
                let num_confirmations = refreshed
                    .copied()
                    .map(serde_json::Value::from)
                    .or_else(|| {
                        m.num_confirmations_at_first_seen
                            .map(serde_json::Value::from)
                    })
                    .unwrap_or(serde_json::Value::Null);
                serde_json::json!({
                    "tx_hash": m.tx_hash,
                    "item_idx": m.item_idx,
                    "slot_idx": m.slot_idx,
                    "first_seen": m.first_seen,
                    "num_confirmations": num_confirmations,
                    "num_confirmations_stale": refreshed.is_none(),
                })
            })
            .collect();
        matched.sort_by(|a, b| b["first_seen"].as_str().cmp(&a["first_seen"].as_str()));
        let value = serde_json::json!({
            "schema_version": 1,
            "identity_pubkey_ed25519_hex": bookmark.identity_pubkey_ed25519_hex,
            "bookmark_path": path.display().to_string(),
            "last_processed_cursor": bookmark.last_processed_cursor,
            "last_processed_block_height": bookmark.last_processed_block_height,
            "matched": matched,
            "pending": [],
        });
        print_json(&value, args.pretty);
    } else {
        render_inbox_list_human(&bookmark, tip_refreshed.as_ref());
    }
    Ok(())
}

// ===========================================================================
// inbox decrypt
// ===========================================================================

/// Arguments for `cardanowall inbox decrypt`.
#[derive(Debug, Args)]
pub struct InboxDecryptArgs {
    /// 64-hex Cardano transaction hash.
    pub tx_hash: String,
    /// restrict decryption to a single item index.
    #[arg(long)]
    pub item: Option<usize>,
    /// write plaintext to this path (or prefix for multi-item).
    #[arg(long)]
    pub out: Option<String>,
    /// target CIP-309 gateway base URL (or env CARDANOWALL_BASE_URL, or a profile).
    #[arg(long = "base-url")]
    pub base_url: Option<String>,
    /// opaque bearer API key (or env CARDANOWALL_API_KEY, or a profile).
    #[arg(long = "api-key")]
    pub api_key: Option<String>,
    /// use this saved gateway profile (overrides the config default_gateway).
    #[arg(long = "gateway-profile")]
    pub gateway_profile: Option<String>,
    /// Cardano data-source gateway URL (repeatable; fetches the record from chain).
    #[arg(long = "cardano-gateway", visible_alias = "gateway")]
    pub gateway: Vec<String>,
    /// Blockfrost project id (enables Blockfrost fallback).
    #[arg(long)]
    pub blockfrost: Option<String>,
    /// Arweave gateway URL (repeatable).
    #[arg(long = "arweave-gateway")]
    pub arweave_gateway: Vec<String>,
    /// IPFS gateway URL (repeatable).
    #[arg(long = "ipfs-gateway")]
    pub ipfs_gateway: Vec<String>,
    /// extra deny-list entries (repeatable).
    #[arg(long = "deny-host")]
    pub deny_host: Vec<String>,
    /// The identity source (seed or X25519 secret key; raw / file / stdin / env).
    #[command(flatten)]
    pub identity: crate::inbox::IdentitySource,
    /// emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// pretty-print JSON output.
    #[arg(long)]
    pub pretty: bool,
}

#[derive(Debug, Serialize)]
struct DecryptItemResult {
    tx_hash: String,
    item_idx: usize,
    decrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext_hash_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    bytes_written_to: Option<String>,
    byte_count: Option<usize>,
}

fn run_decrypt(args: InboxDecryptArgs) -> Result<(), CliError> {
    if args.tx_hash.len() != 64 || !args.tx_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::input(format!(
            "inbox decrypt: <tx-hash> must be 64 hex chars; got \"{}\"",
            args.tx_hash
        )));
    }
    let tx_hash = args.tx_hash.to_lowercase();

    // The identity here may be a raw --secret-key (X25519 only) — decrypt does
    // not need the bookmark, so we don't require the Ed25519 path.
    let identity = args.identity.resolve("inbox decrypt", &SystemSecretEnv)?;
    let bundle = identity.recipient_key_bundle();

    // Fetch the record's label-309 metadata. Prefer the chain (gateway) path so a
    // third-party record (not submitted via this gateway) is still reachable; fall
    // back to the agnostic records API when --base-url is supplied without a
    // Cardano --gateway.
    let flags = GatewayFlags {
        gateway: args.gateway.clone(),
        blockfrost: args.blockfrost.clone(),
        arweave_gateway: args.arweave_gateway.clone(),
        ipfs_gateway: args.ipfs_gateway.clone(),
        deny_host: args.deny_host.clone(),
        ..GatewayFlags::default()
    };
    let resolved = resolve_gateways_for(flags, "inbox decrypt")?;
    let deny_hosts = deny_hosts_or_default(&resolved);
    let transport = ReqwestTransport::new();
    let mut fetcher = GatewayFetcher::new(&transport, Some(&deny_hosts));

    let metadata = fetch_metadata(&tx_hash, &args, &resolved, &mut fetcher)?;
    let validated = match validate_poe_record(&metadata) {
        ValidateResult::Ok { record, .. } => *record,
        ValidateResult::Fail { issues } => {
            let code = issues.first().map_or("UNKNOWN", |i| i.code.code());
            return Err(CliError::integrity(format!(
                "inbox decrypt: record fails validator: {code}"
            )));
        }
    };
    let items = validated.items.unwrap_or_default();

    let target_indices: Vec<usize> = match args.item {
        Some(i) => vec![i],
        None => (0..items.len()).collect(),
    };
    let multi = target_indices.len() > 1;

    let mut results: Vec<DecryptItemResult> = Vec::new();
    // 0 ok / 1 integrity / 2 network. Escalate integrity over network.
    let mut exit_code = 0i32;
    let mut escalate = |c: i32| {
        if c == 1 {
            exit_code = 1;
        } else if c == 2 && exit_code != 1 {
            exit_code = 2;
        }
    };

    for idx in target_indices {
        let Some(item) = items.get(idx) else {
            eprintln!("inbox decrypt: {tx_hash}:{idx}: item index out of range");
            results.push(fail_result(&tx_hash, idx, "ITEM_INDEX_OUT_OF_RANGE"));
            escalate(1);
            continue;
        };
        let Some(envelope) = envelope_from_item(item) else {
            eprintln!("inbox decrypt: {tx_hash}:{idx}: item has no sealed envelope");
            results.push(fail_result(&tx_hash, idx, "NO_SEALED_ENVELOPE"));
            escalate(1);
            continue;
        };

        let uris: Vec<Vec<String>> = item.uris.clone().unwrap_or_default();
        let mut uri_checks = Vec::new();
        let ciphertext = match fetch_item_ciphertext(
            &uris,
            &mut fetcher,
            &mut uri_checks,
            idx as i64,
            Some(&resolved.arweave_gateway_chain),
            resolved.ipfs_gateway_chain.as_deref(),
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("inbox decrypt: {tx_hash}:{idx}: {e}");
                results.push(fail_result(&tx_hash, idx, &e.to_string()));
                escalate(2);
                continue;
            }
        };

        let unwrap = ecies_sealed_poe_unwrap(
            &envelope,
            &ciphertext,
            UnwrapKeys::Bundle(&bundle),
            true,
            None,
        );
        let plaintext = match unwrap {
            Ok(UnwrapResult::Matched { plaintext }) => plaintext,
            Ok(UnwrapResult::NotMatched { reason }) => {
                eprintln!(
                    "inbox decrypt: {tx_hash}:{idx}: URI_INTEGRITY_MISMATCH ({})",
                    reason.as_str()
                );
                results.push(fail_result(&tx_hash, idx, "URI_INTEGRITY_MISMATCH"));
                escalate(1);
                continue;
            }
            Err(e) => {
                eprintln!("inbox decrypt: {tx_hash}:{idx}: {e}");
                results.push(fail_result(&tx_hash, idx, "URI_INTEGRITY_MISMATCH"));
                escalate(1);
                continue;
            }
        };

        match recompute_item_hashes(item, &plaintext) {
            RecomputeResult::Ok => {}
            RecomputeResult::Mismatch { alg } | RecomputeResult::UnsupportedAlg { alg } => {
                eprintln!("inbox decrypt: {tx_hash}:{idx}: URI_INTEGRITY_MISMATCH (alg {alg})");
                let mut r = fail_result(&tx_hash, idx, "URI_INTEGRITY_MISMATCH");
                r.plaintext_hash_ok = Some(false);
                results.push(r);
                escalate(1);
                continue;
            }
        }

        let target_path = args.out.as_ref().map(|o| {
            if multi {
                format!("{o}.item-{idx}.bin")
            } else {
                o.clone()
            }
        });
        let written_to = if let Some(path) = target_path {
            write_new_file(&path, &plaintext)?;
            path
        } else {
            if multi {
                eprintln!(
                    "inbox decrypt: {tx_hash} item={idx} ({} bytes)",
                    plaintext.len()
                );
            }
            use std::io::Write;
            std::io::stdout().write_all(&plaintext).map_err(|e| {
                CliError::network(format!("inbox decrypt: stdout write failed: {e}"))
            })?;
            "stdout".to_string()
        };

        results.push(DecryptItemResult {
            tx_hash: tx_hash.clone(),
            item_idx: idx,
            decrypted: true,
            plaintext_hash_ok: Some(true),
            reason: None,
            bytes_written_to: Some(written_to),
            byte_count: Some(plaintext.len()),
        });
    }

    if args.json {
        let value = serde_json::json!({
            "tx_hash": tx_hash,
            "items": results,
        });
        print_json(&value, args.pretty);
    }

    if exit_code == 0 {
        Ok(())
    } else {
        Err(CliError {
            code: exit_code,
            message: String::new(),
        })
    }
}

/// Resolve a service gateway (base URL + API key) when one is configured anywhere
/// (`flag > env > profile`), returning `None` when no base URL is set — `inbox
/// decrypt` then falls back to the Cardano chain path.
fn optional_service_gateway(
    base_url: Option<&str>,
    api_key: Option<&str>,
    gateway_profile: Option<&str>,
    cmd: &str,
) -> Result<Option<crate::secret::ServiceGateway>, CliError> {
    let config = load_config_for_edit(&SystemConfigEnv)?;
    let profile = config.select_gateway(gateway_profile, cmd)?;
    let env = crate::secret::SystemSecretEnv;
    let profile_base = profile.map(|p| p.base_url.as_str());
    let profile_key = profile.and_then(|p| p.api_key.as_deref());

    let Some(base) = crate::secret::resolve_config_value(
        base_url,
        crate::secret::SecretEnv::var(&env, "CARDANOWALL_BASE_URL").as_deref(),
        profile_base,
    ) else {
        return Ok(None);
    };
    let key = crate::secret::resolve_config_value(
        api_key,
        crate::secret::SecretEnv::var(&env, "CARDANOWALL_API_KEY").as_deref(),
        profile_key,
    );
    Ok(Some(crate::secret::ServiceGateway {
        base_url: base,
        api_key: key,
    }))
}

/// Fetch the record's label-309 metadata bytes: the agnostic records API when a
/// service gateway (base URL via flag / env / profile) is configured, otherwise
/// the Cardano gateway chain.
fn fetch_metadata(
    tx_hash: &str,
    args: &InboxDecryptArgs,
    resolved: &ResolvedGateways,
    fetcher: &mut GatewayFetcher<'_>,
) -> Result<Vec<u8>, CliError> {
    if let Some(service) = optional_service_gateway(
        args.base_url.as_deref(),
        args.api_key.as_deref(),
        args.gateway_profile.as_deref(),
        "inbox decrypt",
    )? {
        let client = build_client(
            service.base_url,
            service.api_key.as_deref(),
            "inbox decrypt",
        )?;
        let record = client
            .records()
            .get(tx_hash)
            .map_err(|e| map_inbox_client_error(e, "inbox decrypt"))?;
        return decode_standard(&record.metadata_cbor_base64).map_err(|e| {
            CliError::network(format!("inbox decrypt: metadata base64 decode failed: {e}"))
        });
    }
    // Chain path: resolve the tx and extract label-309.
    let resolved_tx = resolve_cardano_tx(
        tx_hash,
        Some(&resolved.cardano_gateway_chain),
        resolved.blockfrost_project_id.as_deref(),
        fetcher,
    )
    .map_err(|e| {
        // A definitive no-record / deny-host is integrity-class; transient is network.
        match &e {
            cardanowall::verifier::ResolveError::ProviderUnavailable(_) => {
                CliError::network(format!("inbox decrypt: {e}"))
            }
            _ => CliError::integrity(format!("inbox decrypt: {e}")),
        }
    })?;
    match extract_label_309_metadata(&resolved_tx.tx_cbor) {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(CliError::integrity(format!(
            "inbox decrypt: tx {tx_hash} has no label-309 metadata"
        ))),
        Err(e) => Err(CliError::network(format!(
            "inbox decrypt: failed to decode tx CBOR: {e}"
        ))),
    }
}

fn write_new_file(path: &str, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => f.write_all(bytes).map_err(|e| {
            CliError::network(format!("inbox decrypt: cannot write {path}: {e}"))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(CliError::input(format!(
            "inbox decrypt: refusing to overwrite existing file {path}; remove it or choose a different --out"
        ))),
        Err(e) => Err(CliError::network(format!(
            "inbox decrypt: cannot create {path}: {e}"
        ))),
    }
}

// ===========================================================================
// Shared helpers
// ===========================================================================

fn fail_result(tx_hash: &str, idx: usize, reason: &str) -> DecryptItemResult {
    DecryptItemResult {
        tx_hash: tx_hash.to_string(),
        item_idx: idx,
        decrypted: false,
        plaintext_hash_ok: None,
        reason: Some(reason.to_string()),
        bytes_written_to: None,
        byte_count: None,
    }
}

fn deny_hosts_or_default(resolved: &ResolvedGateways) -> Vec<String> {
    resolved.deny_hosts.clone().unwrap_or_else(|| {
        DENY_HOSTS_DEFAULT
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    })
}

fn map_inbox_client_error(err: ClientError, cmd: &str) -> CliError {
    match err {
        ClientError::Http(http) => {
            // A record-not-found is integrity-class; other gateway errors keep
            // their HTTP framing as integrity (server-attributable) vs network.
            CliError::integrity(format!(
                "{cmd}: HTTP {} {}: {}",
                http.http_status(),
                http.code(),
                http.problem().detail
            ))
        }
        other => CliError::network(format!("{cmd}: {other}")),
    }
}

fn print_json(value: &serde_json::Value, pretty: bool) {
    let rendered = if pretty {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    }
    .expect("inbox JSON serialises");
    println!("{rendered}");
}

/// The current UTC time as an RFC 3339 / ISO-8601 string (second precision).
fn current_iso8601() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (now / 86_400) as i64;
    let secs_of_day = now % 86_400;
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Days since the Unix epoch → `(year, month, day)` (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_source(seed: Option<&str>, secret_key: Option<&str>) -> crate::inbox::IdentitySource {
        crate::inbox::IdentitySource {
            seed: seed.map(str::to_string),
            seed_file: None,
            seed_stdin: false,
            secret_key: secret_key.map(str::to_string),
            secret_key_file: None,
            secret_key_stdin: false,
        }
    }

    #[test]
    fn decrypt_rejects_bad_tx_hash() {
        let args = InboxDecryptArgs {
            tx_hash: "short".to_string(),
            item: None,
            out: None,
            base_url: None,
            api_key: None,
            gateway_profile: None,
            gateway: vec![],
            blockfrost: None,
            arweave_gateway: vec![],
            ipfs_gateway: vec![],
            deny_host: vec![],
            identity: seed_source(Some(&"00".repeat(32)), None),
            json: false,
            pretty: false,
        };
        assert_eq!(run_decrypt(args).unwrap_err().code, 4);
    }

    #[test]
    fn list_secret_key_alone_is_input_error() {
        let args = InboxListArgs {
            gateway: vec![],
            blockfrost: None,
            deny_host: vec![],
            identity: seed_source(None, Some(&"ab".repeat(32))),
            json: false,
            pretty: false,
        };
        assert_eq!(run_list(args).unwrap_err().code, 4);
    }

    #[test]
    fn civil_date_epoch_is_1970() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }
}
