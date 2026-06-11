//! `cardanowall verify` integration tests.
//!
//! The exit-code contract (`0` valid / `1` integrity / `2` network / `3` pending
//! / `4` CLI input) is a public UX promise. These tests pin it three ways:
//!
//! 1. **Corpus replay** — for every captured mainnet record, drive the SDK
//!    verifier with a deterministic mock transport and confirm the CLI's
//!    verdict → exit-code mapping reproduces the golden report's `exitCode`. The
//!    same replay asserts service-independence: no call ever reaches a
//!    deny-listed host.
//! 2. **Network-class replay** — an NXDOMAIN-style transport that fails every
//!    gateway call yields an `unverifiable` verdict and exit `2`, with no
//!    deny-listed egress.
//! 3. **CLI-input cases** — bad tx hash, unparseable gateway URL, bad threshold,
//!    and an unknown subcommand all exit `4`, driven through the real arg parser.

mod common;

use std::collections::HashMap;
use std::sync::Mutex;

use cardanowall::verifier::fetch::{
    FetchOutboundOptions, FetchOutboundResult, FetchTransport, OutboundError,
};
use cardanowall::verifier::{verify_tx, Decryption, VerifyTxInput};
use cardanowall_cli::commands::verify::exit_code_for_report;

const KOIOS_URL: &str = "https://api.koios.rest/api/v1";
const CONFORMANCE_DENY: [&str; 4] = [
    "operator.example",
    "*.operator.example",
    "localhost",
    "127.0.0.1",
];

// ---------------------------------------------------------------------------
// Mock transport (mirrors the SDK corpus harness)
// ---------------------------------------------------------------------------

struct MockTransport {
    tx_cbor_body: Option<Vec<u8>>,
    tx_info_body: Option<Vec<u8>>,
    tip_body: Option<Vec<u8>>,
    bf_tx_cbor_body: Option<Vec<u8>>,
    bf_tx_body: Option<Vec<u8>>,
    bf_blocks_latest_body: Option<Vec<u8>>,
    arweave: HashMap<String, Vec<u8>>,
    misses: Mutex<Vec<String>>,
}

fn compact_json(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("corpus capture re-serialises")
}

impl MockTransport {
    fn from_corpus_record(record: &serde_json::Value) -> Self {
        let captures = &record["captured_gateway_responses"];
        let capture = |key: &str| captures.get(key).map(compact_json);
        let mut arweave = HashMap::new();
        if let Some(map) = captures
            .get("arweave_responses")
            .and_then(serde_json::Value::as_object)
        {
            for (ar_tx_id, hex_str) in map {
                if let Some(hex) = hex_str.as_str() {
                    if let Ok(bytes) = hex::decode(hex) {
                        arweave.insert(format!("https://arweave.net/{ar_tx_id}"), bytes);
                    }
                }
            }
        }
        Self {
            tx_cbor_body: capture("koios_tx_cbor"),
            tx_info_body: capture("koios_tx_info"),
            tip_body: capture("koios_tip"),
            bf_tx_cbor_body: capture("blockfrost_tx_cbor"),
            bf_tx_body: capture("blockfrost_tx"),
            bf_blocks_latest_body: capture("blockfrost_blocks_latest"),
            arweave,
            misses: Mutex::new(Vec::new()),
        }
    }

    fn ok(bytes: &[u8]) -> Result<FetchOutboundResult, OutboundError> {
        Ok(FetchOutboundResult {
            status: 200,
            bytes: bytes.to_vec(),
            duration_ms: 1,
        })
    }
}

impl FetchTransport for MockTransport {
    fn fetch(
        &self,
        url: &str,
        _opts: &FetchOutboundOptions,
    ) -> Result<FetchOutboundResult, OutboundError> {
        if url.ends_with("/tx_cbor") {
            if let Some(b) = &self.tx_cbor_body {
                return Self::ok(b);
            }
        } else if url.ends_with("/tx_info") {
            if let Some(b) = &self.tx_info_body {
                return Self::ok(b);
            }
        } else if url.ends_with("/tip") {
            if let Some(b) = &self.tip_body {
                return Self::ok(b);
            }
        } else if url.ends_with("/blocks/latest") {
            if let Some(b) = &self.bf_blocks_latest_body {
                return Self::ok(b);
            }
        } else if url.ends_with("/cbor") && url.contains("/txs/") {
            if let Some(b) = &self.bf_tx_cbor_body {
                return Self::ok(b);
            }
        } else if url.contains("/txs/") {
            if let Some(b) = &self.bf_tx_body {
                return Self::ok(b);
            }
        } else if let Some(bytes) = self.arweave.get(url) {
            return Self::ok(bytes);
        }
        self.misses.lock().unwrap().push(url.to_string());
        Err(OutboundError::Transport {
            url: url.to_string(),
            message: format!("no captured response for {url}"),
        })
    }
}

/// Build the recipient keyring for a corpus record from its
/// `recipient_secret_keys` field (absent for non-sealed records). The keyring
/// is global to the run; per-entry item indices in the corpus identify which
/// item the key was minted for but are not part of the input shape.
fn corpus_decryption_inputs(record: &serde_json::Value) -> Vec<Decryption> {
    record
        .get("recipient_secret_keys")
        .and_then(serde_json::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| {
                    let secret_key =
                        hex::decode(e.get("secret_key").and_then(serde_json::Value::as_str)?)
                            .ok()?;
                    Some(Decryption::Recipient {
                        recipient_secret_key: secret_key,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn load_corpus() -> Vec<serde_json::Value> {
    let path = common::sdk_py_fixtures().join("mainnet-corpus.json");
    let value = common::read_fixture_json(&path);
    value["records"]
        .as_array()
        .expect("corpus.records is an array")
        .clone()
}

/// Collapse the CLI exit-code mapping to its numeric code (`0` on `Ok`).
fn cli_exit_code(report: &cardanowall::verifier::VerifyReport) -> i32 {
    match exit_code_for_report(report) {
        Ok(()) => 0,
        Err(e) => e.code,
    }
}

#[test]
fn corpus_exit_codes_match_golden_through_cli_mapping() {
    let corpus = load_corpus();
    assert!(
        corpus.len() >= 100,
        "corpus truncated: {} records",
        corpus.len()
    );
    let deny: Vec<String> = CONFORMANCE_DENY.iter().map(|s| (*s).to_string()).collect();
    let mut replayed = 0usize;

    for record in &corpus {
        let tx_hash = record["tx_hash"].as_str().expect("tx_hash is a string");
        let transport = MockTransport::from_corpus_record(record);
        let use_blockfrost =
            record.get("provider").and_then(serde_json::Value::as_str) == Some("blockfrost");
        let decryption = corpus_decryption_inputs(record);

        let mut input = VerifyTxInput::new(tx_hash);
        if use_blockfrost {
            input.cardano_gateway_chain = Some(vec![]);
            input.blockfrost_project_id = Some("corpus".to_string());
        } else {
            input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
        }
        if !decryption.is_empty() {
            input.decryption = Some(decryption);
        }
        input.deny_hosts = Some(deny.clone());
        input.fetch_outbound = Some(&transport);

        let report = verify_tx(&input);

        // The CLI passes the verifier's verdict-paired exit code straight
        // through; assert it equals the golden report's exitCode.
        let golden_path = common::sdk_ts_fixtures()
            .join("verify-reports")
            .join(format!("{tx_hash}.json"));
        let golden = common::read_fixture_json(&golden_path);
        let expected_exit = golden["exitCode"].as_i64().expect("golden exitCode") as i32;
        assert_eq!(
            cli_exit_code(&report),
            expected_exit,
            "CLI exit-code diverged from golden for tx {tx_hash}"
        );

        // Service-independence: no call ever reached the operator's own host.
        assert!(
            report
                .audit_trail
                .iter()
                .all(|c| !c.url.contains("operator.example")),
            "a call reached a deny-listed host for tx {tx_hash}"
        );
        replayed += 1;
    }
    assert!(replayed >= 100, "only replayed {replayed} corpus records");
}

#[test]
fn corpus_exercises_the_happy_path_end_to_end() {
    // The captured mainnet corpus is the full set of well-formed, sufficiently
    // confirmed records, so every golden is exit-0 (valid). This test pins that
    // the happy path is exercised across the whole corpus (≥100 records); the
    // non-zero classes (1/2/3) are covered by the targeted network / deny-host
    // cases below and by the SDK's own pipeline unit tests.
    let corpus = load_corpus();
    assert!(corpus.len() >= 100, "corpus truncated: {}", corpus.len());
    for record in &corpus {
        let tx_hash = record["tx_hash"].as_str().unwrap();
        let golden = common::read_fixture_json(
            &common::sdk_ts_fixtures()
                .join("verify-reports")
                .join(format!("{tx_hash}.json")),
        );
        assert_eq!(
            golden["exitCode"].as_i64().unwrap(),
            0,
            "golden for {tx_hash} is not exit-0; the corpus-replay test must cover its class"
        );
    }
}

#[test]
fn network_failure_maps_to_exit_2_with_service_independence() {
    // An NXDOMAIN / connection-refused transport: every gateway call fails. The
    // verifier exhausts the chain → unverifiable verdict → network class
    // (exit 2). No call may reach a deny-listed host.
    struct NxdomainTransport {
        seen: Mutex<Vec<String>>,
    }
    impl FetchTransport for NxdomainTransport {
        fn fetch(
            &self,
            url: &str,
            _opts: &FetchOutboundOptions,
        ) -> Result<FetchOutboundResult, OutboundError> {
            self.seen.lock().unwrap().push(url.to_string());
            Err(OutboundError::Transport {
                url: url.to_string(),
                message: "nodename nor servname provided, or not known".to_string(),
            })
        }
    }
    let transport = NxdomainTransport {
        seen: Mutex::new(Vec::new()),
    };
    let mut input = VerifyTxInput::new("ab".repeat(32));
    input.cardano_gateway_chain = Some(vec![KOIOS_URL.to_string()]);
    input.deny_hosts = Some(CONFORMANCE_DENY.iter().map(|s| (*s).to_string()).collect());
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(cli_exit_code(&report), 2, "network failure must exit 2");
    assert!(
        report
            .audit_trail
            .iter()
            .all(|c| !c.url.contains("operator.example")),
        "a call reached a deny-listed host"
    );
}

#[test]
fn deny_host_violation_maps_to_exit_1() {
    // Pointing the gateway at the operator's own host trips the deny-host short
    // circuit before any transport call: a service-independence violation, which
    // is integrity-class (exit 1).
    struct UnusedTransport;
    impl FetchTransport for UnusedTransport {
        fn fetch(
            &self,
            url: &str,
            _opts: &FetchOutboundOptions,
        ) -> Result<FetchOutboundResult, OutboundError> {
            panic!("transport must not be called: {url}");
        }
    }
    let transport = UnusedTransport;
    let mut input = VerifyTxInput::new("cd".repeat(32));
    input.cardano_gateway_chain = Some(vec!["https://api.operator.example/v1".to_string()]);
    input.deny_hosts = Some(CONFORMANCE_DENY.iter().map(|s| (*s).to_string()).collect());
    input.fetch_outbound = Some(&transport);

    let report = verify_tx(&input);
    assert_eq!(
        cli_exit_code(&report),
        1,
        "deny-host violation must be integrity-class (exit 1)"
    );
}

// ---------------------------------------------------------------------------
// CLI-input cases (exit 4), driven through the real arg parser.
// ---------------------------------------------------------------------------

/// Drive the CLI through its real arg parser from `&str` args.
fn run_cli(args: &[&str]) -> i32 {
    cardanowall_cli::run(args.iter().map(|s| s.to_string()))
}

#[test]
fn malformed_tx_hash_exits_4() {
    assert_eq!(run_cli(&["cardanowall", "verify", "not-a-hex"]), 4);
}

#[test]
fn unparseable_gateway_url_exits_4() {
    let tx = "0".repeat(64);
    assert_eq!(
        run_cli(&["cardanowall", "verify", &tx, "--gateway", "not-a-url"]),
        4
    );
}

#[test]
fn bad_threshold_exits_4() {
    let tx = "0".repeat(64);
    assert_eq!(
        run_cli(&["cardanowall", "verify", &tx, "--threshold", "banana"]),
        4
    );
}

#[test]
fn unknown_subcommand_exits_4() {
    assert_eq!(run_cli(&["cardanowall", "no-such-subcommand"]), 4);
}

#[test]
fn help_and_version_exit_0() {
    assert_eq!(run_cli(&["cardanowall", "--help"]), 0);
    assert_eq!(run_cli(&["cardanowall", "--version"]), 0);
}
