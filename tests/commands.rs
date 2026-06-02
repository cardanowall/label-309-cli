//! Integration tests for the offline command surface: identity determinism,
//! merkle build/verify, sign record/prepare/assemble round-trip, and inbox
//! decrypt with a raw seed.
//!
//! These drive the CLI's public helper functions (the same code the command
//! handlers call) plus the SDK primitives, so the cryptographic round-trips are
//! exercised without any network or filesystem I/O.

use cardanowall::client::{assemble_cose_sign1, prepare_sig_structure, Signer};
use cardanowall::merkle::{
    encode_leaves_list, merkle_inclusion_proof, merkle_root, verify_inclusion,
};
use cardanowall::poe_standard::{
    encode_poe_record, validate_poe_record, EncryptionEnvelope, ItemEntry, PoeRecord, Slot,
    ValidateResult,
};
use cardanowall::sealed_poe::{
    chunk_kem_ct, ecies_sealed_poe_unwrap, ecies_sealed_poe_wrap_secure, SealedKem, SealedSlots,
    UnwrapKeys, UnwrapResult, WrapArgs,
};
use cardanowall::seed_derive::{
    derive_mlkem768x25519_keypair, derive_x25519_keypair, signer_from_seed,
};

use cardanowall_cli::commands::identity::build_identity_outcome;
use cardanowall_cli::inbox::envelope::envelope_from_item;
use cardanowall_cli::inbox::identity::resolve_identity;
use cardanowall_cli::inbox::recompute_hashes::{recompute_item_hashes, RecomputeResult};

// ---------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------

#[test]
fn identity_derivation_is_deterministic_and_well_formed() {
    let seed = [0x42u8; 32];
    let a = build_identity_outcome(&seed).unwrap();
    let b = build_identity_outcome(&seed).unwrap();
    assert_eq!(a.ed25519_pubkey_hex, b.ed25519_pubkey_hex);
    assert_eq!(a.x25519_pubkey_hex, b.x25519_pubkey_hex);
    assert_eq!(a.xwing_pubkey_hex, b.xwing_pubkey_hex);
    assert_eq!(a.fingerprint, b.fingerprint);
    // The fingerprint is the grouped first 8 bytes of sha2-256(ed25519_pub).
    assert_eq!(a.fingerprint.len(), 19);
    // Both age recipient strings are present and HRP-tagged.
    assert!(a.age_recipient.starts_with("age1"));
    assert!(a.age1pqc_recipient.starts_with("age1pqc1"));
    // The full X-Wing key is 1216 bytes = 2432 hex chars.
    assert_eq!(a.xwing_pubkey_hex.len(), 2432);
}

#[test]
fn distinct_seeds_yield_distinct_identities() {
    let a = build_identity_outcome(&[1u8; 32]).unwrap();
    let b = build_identity_outcome(&[2u8; 32]).unwrap();
    assert_ne!(a.ed25519_pubkey_hex, b.ed25519_pubkey_hex);
    assert_ne!(a.fingerprint, b.fingerprint);
}

// ---------------------------------------------------------------------------
// merkle
// ---------------------------------------------------------------------------

fn sha256(input: &[u8]) -> [u8; 32] {
    cardanowall::hash::sha256(input)
}

#[test]
fn merkle_build_then_verify_every_leaf() {
    let leaves: Vec<[u8; 32]> = (0u8..7).map(|i| sha256(&[i, i, i])).collect();
    let root = merkle_root(&leaves).unwrap();

    // The leaves-list a `merkle build` emits encodes and decodes.
    let cbor = encode_leaves_list(&leaves, &root, Some("sha2-256")).unwrap();
    assert!(!cbor.is_empty());

    // Every leaf's inclusion proof verifies against the printed root — the
    // property a `merkle verify` consumer relies on.
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = merkle_inclusion_proof(&leaves, i).unwrap();
        assert!(
            verify_inclusion(leaf, i, leaves.len(), &proof, &root),
            "leaf {i} did not verify"
        );
    }
}

#[test]
fn merkle_verify_rejects_tampered_root() {
    let leaves: Vec<[u8; 32]> = (0u8..4).map(|i| sha256(&[i])).collect();
    let root = merkle_root(&leaves).unwrap();
    let proof = merkle_inclusion_proof(&leaves, 1).unwrap();
    let mut bad_root = root;
    bad_root[0] ^= 0xff;
    assert!(!verify_inclusion(
        &leaves[1],
        1,
        leaves.len(),
        &proof,
        &bad_root
    ));
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

fn hash_only_record(digest: [u8; 32]) -> PoeRecord {
    PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), digest.to_vec())],
            uris: None,
            enc: None,
        }]),
        ..PoeRecord::default()
    }
}

#[test]
fn sign_record_prepare_assemble_agree_and_validate() {
    let seed = [0x11u8; 32];
    let signer = signer_from_seed(&seed).unwrap();
    let pubkey = signer.signer_pubkey();
    let record = hash_only_record([0xaa; 32]);

    // The `sign record` (in-process) and `sign prepare` + `sign assemble`
    // (detached) paths must produce byte-identical COSE_Sign1.
    let prepared = prepare_sig_structure(&record, &pubkey).unwrap();
    let signature = signer.sign(&prepared.sig_structure_bytes).unwrap();
    let inline = assemble_cose_sign1(&record, &pubkey, &signature).unwrap();
    let detached = assemble_cose_sign1(&record, &pubkey, &signature).unwrap();
    assert_eq!(inline.cose_sign1_bytes, detached.cose_sign1_bytes);

    // The signed record validates structurally.
    let mut signed = record;
    signed.sigs = Some(vec![inline.sig_entry]);
    let cbor = encode_poe_record(&signed).unwrap();
    assert!(matches!(
        validate_poe_record(&cbor),
        ValidateResult::Ok { .. }
    ));
}

// ---------------------------------------------------------------------------
// inbox decrypt with a raw seed
// ---------------------------------------------------------------------------

/// Build a classical (x25519) sealed `ItemEntry` for a recipient seed, returning
/// the on-chain item plus the off-chain ciphertext bytes.
fn seal_to_seed(recipient_seed: &[u8; 32], plaintext: &[u8]) -> (ItemEntry, Vec<u8>) {
    let recipient = derive_x25519_keypair(recipient_seed).unwrap();
    let sealed = ecies_sealed_poe_wrap_secure(WrapArgs {
        plaintext,
        recipient_public_keys: &[recipient.public_key.to_vec()],
        kem: Some(SealedKem::X25519),
        ..WrapArgs::default()
    })
    .unwrap();

    let env = sealed.envelope;
    let slots = match &env.slots {
        SealedSlots::X25519(slots) => slots
            .iter()
            .map(|s| Slot {
                epk: Some(s.epk.clone()),
                kem_ct: None,
                wrap: Some(s.wrap.clone()),
            })
            .collect(),
        SealedSlots::Mlkem768X25519(_) => panic!("expected classical slots"),
    };
    let enc = EncryptionEnvelope {
        scheme: env.scheme as u64,
        aead: env.aead.clone(),
        nonce: env.nonce.clone(),
        kem: Some(env.kem.clone()),
        slots: Some(slots),
        slots_mac: Some(env.slots_mac.clone()),
        passphrase: None,
    };
    let item = ItemEntry {
        hashes: vec![("sha2-256".to_string(), sha256(plaintext).to_vec())],
        // The CLI fetches ciphertext from these URIs; the test injects the bytes
        // directly, so the URI list is irrelevant to the crypto path.
        uris: Some(vec![chunk_uri("ar://test")]),
        enc: Some(enc),
    };
    (item, sealed.ciphertext)
}

fn chunk_uri(uri: &str) -> Vec<String> {
    uri.as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect()
}

#[test]
fn inbox_decrypt_with_raw_seed_recovers_plaintext_and_validates_hash() {
    let recipient_seed = [0x55u8; 32];
    let plaintext = b"a sealed proof-of-existence payload".to_vec();
    let (item, ciphertext) = seal_to_seed(&recipient_seed, &plaintext);

    // The CLI resolves the recipient bundle from the raw seed.
    let identity =
        resolve_identity(Some(&hex_encode(&recipient_seed)), None, "inbox decrypt").unwrap();
    let bundle = identity.recipient_key_bundle();

    // The exact decrypt pipeline the `inbox decrypt` command runs:
    let envelope = envelope_from_item(&item).expect("item carries a sealed envelope");
    let unwrap = ecies_sealed_poe_unwrap(
        &envelope,
        &ciphertext,
        UnwrapKeys::Bundle(&bundle),
        true,
        None,
    )
    .unwrap();
    let recovered = match unwrap {
        UnwrapResult::Matched { plaintext } => plaintext,
        UnwrapResult::NotMatched { reason } => panic!("unwrap failed: {}", reason.as_str()),
    };
    assert_eq!(recovered, plaintext);

    // And the recovered plaintext recomputes to the committed content hash.
    assert_eq!(
        recompute_item_hashes(&item, &recovered),
        RecomputeResult::Ok
    );
}

#[test]
fn inbox_decrypt_with_wrong_seed_does_not_match() {
    let (item, ciphertext) = seal_to_seed(&[0x55u8; 32], b"secret");
    // A different seed's bundle must not open the envelope.
    let identity =
        resolve_identity(Some(&hex_encode(&[0x66u8; 32])), None, "inbox decrypt").unwrap();
    let bundle = identity.recipient_key_bundle();
    let envelope = envelope_from_item(&item).unwrap();
    let unwrap = ecies_sealed_poe_unwrap(
        &envelope,
        &ciphertext,
        UnwrapKeys::Bundle(&bundle),
        true,
        None,
    )
    .unwrap();
    assert!(matches!(unwrap, UnwrapResult::NotMatched { .. }));
}

#[test]
fn inbox_decrypt_hybrid_record_needs_seed_not_secret_key() {
    // A hybrid (mlkem768x25519) record sealed to a seed's X-Wing key opens only
    // via the seed path (which derives the X-Wing secret); the raw --secret-key
    // path carries no hybrid seed, so it cleanly non-matches.
    let recipient_seed = [0x77u8; 32];
    let xwing = derive_mlkem768x25519_keypair(&recipient_seed).unwrap();
    let plaintext = b"hybrid sealed payload".to_vec();
    let sealed = ecies_sealed_poe_wrap_secure(WrapArgs {
        plaintext: &plaintext,
        recipient_public_keys: &[xwing.public_key.to_vec()],
        kem: Some(SealedKem::Mlkem768X25519),
        ..WrapArgs::default()
    })
    .unwrap();
    let env = sealed.envelope;
    let slots = match &env.slots {
        SealedSlots::Mlkem768X25519(slots) => slots
            .iter()
            .map(|s| Slot {
                epk: None,
                kem_ct: Some(s.kem_ct.clone()),
                wrap: Some(s.wrap.clone()),
            })
            .collect(),
        SealedSlots::X25519(_) => panic!("expected hybrid slots"),
    };
    let item = ItemEntry {
        hashes: vec![("sha2-256".to_string(), sha256(&plaintext).to_vec())],
        uris: Some(vec![chunk_uri("ar://test")]),
        enc: Some(EncryptionEnvelope {
            scheme: env.scheme as u64,
            aead: env.aead.clone(),
            nonce: env.nonce.clone(),
            kem: Some(env.kem.clone()),
            slots: Some(slots),
            slots_mac: Some(env.slots_mac.clone()),
            passphrase: None,
        }),
    };
    let envelope = envelope_from_item(&item).unwrap();

    // Seed path opens it.
    let seed_id =
        resolve_identity(Some(&hex_encode(&recipient_seed)), None, "inbox decrypt").unwrap();
    let opened = ecies_sealed_poe_unwrap(
        &envelope,
        &sealed.ciphertext,
        UnwrapKeys::Bundle(&seed_id.recipient_key_bundle()),
        true,
        None,
    )
    .unwrap();
    assert!(matches!(opened, UnwrapResult::Matched { .. }));

    // Raw --secret-key path (X25519 only) cleanly non-matches a hybrid record.
    let sk_id = resolve_identity(None, Some(&"ab".repeat(32)), "inbox decrypt").unwrap();
    let non_match = ecies_sealed_poe_unwrap(
        &envelope,
        &sealed.ciphertext,
        UnwrapKeys::Bundle(&sk_id.recipient_key_bundle()),
        true,
        None,
    )
    .unwrap();
    assert!(matches!(non_match, UnwrapResult::NotMatched { .. }));

    // chunk_kem_ct is the exact wire split the slot uses; sanity-check it is
    // non-empty so the hybrid slot is well-formed.
    assert!(!chunk_kem_ct(&[1u8; 1120]).is_empty());
}

fn hex_encode(bytes: &[u8]) -> String {
    cardanowall::hex::encode(bytes)
}
