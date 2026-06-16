//! Cross-tool byte-parity anchor for `cardanowall certificate build`.
//!
//! The SDK already pins the inclusion-certificate root and COSE proof against
//! the shared conformance vector. This drives the same canonical inputs through
//! the CLI's real `certificate build` command and confirms the artifact it
//! emits — the certificate's root and the per-item COSE proof — matches the
//! shared vector byte-for-byte, so the CLI and SDK agree on the wire format.

mod common;

use cardanowall::merkle::encode_leaves_list;

/// Drive the CLI through its real arg parser, returning the process exit code.
fn run_cli(args: &[&str]) -> i32 {
    cardanowall_cli::run(args.iter().map(|s| s.to_string()))
}

#[test]
fn certificate_build_root_and_cose_match_shared_vector() {
    // The inclusion-certificate vector is vendored into the SDK fixture trees
    // (byte-identical to the conformance corpus); read the TypeScript mirror,
    // which the standalone export repoints to a package-local copy.
    let corpus = common::read_fixture_json(
        &common::sdk_ts_fixtures().join("certificate/inclusion-certificate-kat.json"),
    );
    let vector = &corpus["vectors"].as_array().expect("vectors")[0];
    let input = &vector["input"];
    let expected = &vector["expected"];

    // The leaves are the canonical content hashes; build the leaves-list CBOR
    // file the CLI consumes with `--leaves-list`.
    let leaves: Vec<[u8; 32]> = input["leaves"]
        .as_array()
        .expect("input.leaves")
        .iter()
        .map(|v| {
            let bytes = hex::decode(v.as_str().expect("leaf hex")).expect("leaf hex decodes");
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        })
        .collect();
    let root = cardanowall::merkle::merkle_root(&leaves).unwrap();
    let leaves_cbor = encode_leaves_list(&leaves, &root, Some("sha2-256")).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let leaves_path = dir.path().join("leaves.cbor");
    std::fs::write(&leaves_path, &leaves_cbor).unwrap();
    let cert_path = dir.path().join("cert.json");
    let cbor_dir = dir.path().join("cbor");

    let target_index = input["target"]["index"].as_u64().expect("target.index") as usize;
    let target_leaf_hex = hex::encode(leaves[target_index]);
    let tx_hash = input["anchor"]["tx_hash"].as_str().expect("tx_hash");
    let block_time = input["anchor"]["block_time"]
        .as_i64()
        .expect("block_time")
        .to_string();

    // A fully-offline build: explicit leaves-list + block-time, default mainnet
    // network (matching the vector's anchor), and the COSE proof written out.
    let code = run_cli(&[
        "cardanowall",
        "certificate",
        "build",
        "--leaves-list",
        leaves_path.to_str().unwrap(),
        "--leaf",
        &target_leaf_hex,
        "--tx",
        tx_hash,
        "--network",
        "mainnet",
        "--block-time",
        &block_time,
        "--out",
        cert_path.to_str().unwrap(),
        "--cbor-dir",
        cbor_dir.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "build of an all-present target exits 0");

    // The emitted certificate's root matches the shared vector.
    let cert_text = std::fs::read_to_string(&cert_path).unwrap();
    let cert: serde_json::Value = serde_json::from_str(&cert_text).unwrap();
    assert_eq!(
        cert["merkle"]["root"].as_str().unwrap(),
        expected["root"].as_str().unwrap(),
        "certificate root matches the shared vector"
    );

    // The per-item COSE proof the CLI wrote matches the vector byte-for-byte.
    // The single target is item 0, so its proof is `0.cbor`.
    let cose = std::fs::read(cbor_dir.join("0.cbor")).unwrap();
    assert_eq!(
        hex::encode(&cose),
        expected["cose_inclusion_proof_cbor_hex"].as_str().unwrap(),
        "CLI-emitted COSE proof matches the shared vector"
    );
}
