//! Recompute an item's committed content hashes against a decrypted plaintext.
//!
//! After a sealed item is unwrapped, the recovered plaintext must hash back to
//! every committed digest in `items[i].hashes`; otherwise the off-chain
//! ciphertext does not match what the on-chain record claims. The comparison is
//! constant-time so a mismatch does not leak which byte diverged.

use cardanowall::hash::{blake2b256, sha256};
use cardanowall::poe_standard::ItemEntry;

/// The outcome of a plaintext-hash recompute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecomputeResult {
    /// Every committed hash recomputed to the plaintext.
    Ok,
    /// A committed digest did not match. Carries the offending algorithm.
    Mismatch {
        /// The algorithm whose digest did not match.
        alg: String,
    },
    /// A committed hash used an algorithm this verifier does not implement.
    UnsupportedAlg {
        /// The unsupported algorithm identifier.
        alg: String,
    },
}

/// Recompute every committed digest in `item.hashes` against `plaintext`.
#[must_use]
pub fn recompute_item_hashes(item: &ItemEntry, plaintext: &[u8]) -> RecomputeResult {
    for (alg, expected) in &item.hashes {
        let computed: Vec<u8> = match alg.as_str() {
            "sha2-256" => sha256(plaintext).to_vec(),
            "blake2b-256" => blake2b256(plaintext).to_vec(),
            _ => {
                return RecomputeResult::UnsupportedAlg { alg: alg.clone() };
            }
        };
        if !ct_eq(&computed, expected) {
            return RecomputeResult::Mismatch { alg: alg.clone() };
        }
    }
    RecomputeResult::Ok
}

/// Constant-time equality of two byte slices (length-aware).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item_with(alg: &str, digest: Vec<u8>) -> ItemEntry {
        ItemEntry {
            hashes: vec![(alg.to_string(), digest)],
            uris: None,
            enc: None,
        }
    }

    #[test]
    fn matches_correct_sha256() {
        let pt = b"hello";
        let item = item_with("sha2-256", sha256(pt).to_vec());
        assert_eq!(recompute_item_hashes(&item, pt), RecomputeResult::Ok);
    }

    #[test]
    fn flags_mismatch() {
        let item = item_with("sha2-256", vec![0u8; 32]);
        assert_eq!(
            recompute_item_hashes(&item, b"hello"),
            RecomputeResult::Mismatch {
                alg: "sha2-256".to_string()
            }
        );
    }

    #[test]
    fn flags_unsupported_alg() {
        let item = item_with("md5", vec![0u8; 16]);
        assert!(matches!(
            recompute_item_hashes(&item, b"x"),
            RecomputeResult::UnsupportedAlg { .. }
        ));
    }
}
