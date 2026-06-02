//! The local inbox bookmark: a plaintext-on-device JSON record of matched sealed
//! PoEs, keyed per identity by the Ed25519 public-key prefix.
//!
//! The bookmark lives at `<HOME>/.cardanowall/<ed25519_prefix>/inbox.json`, where
//! the prefix is the lowercase-hex first 8 bytes (16 hex chars) of the Ed25519
//! public key. It is a local-only artefact and is NEVER uploaded. Writes are
//! atomic (`.tmp` → rename) under `0600` perms on Unix.
//!
//! Wire-vocabulary triple: `(tx_hash, item_idx, slot_idx)`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::util::CliError;

/// The bookmark schema version (the only supported value).
pub const BOOKMARK_SCHEMA_VERSION: u32 = 1;

/// One matched sealed-PoE entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedMatchEntry {
    /// The carrying transaction hash (lowercase hex).
    pub tx_hash: String,
    /// The matched item index.
    pub item_idx: usize,
    /// The matched slot index.
    pub slot_idx: usize,
    /// The ISO-8601 timestamp this match was first seen.
    pub first_seen: String,
    /// The block height, when known.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub block_height: Option<u64>,
    /// The confirmation depth at first sight, when known.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub num_confirmations_at_first_seen: Option<u64>,
}

/// The full on-disk bookmark.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboxBookmark {
    /// The schema version (always `1`).
    pub schema_version: u32,
    /// The identity Ed25519 public key the bookmark belongs to (lowercase hex).
    pub identity_pubkey_ed25519_hex: String,
    /// The last indexer cursor processed.
    pub last_processed_cursor: u64,
    /// The last block height processed.
    pub last_processed_block_height: u64,
    /// The confirmed matches.
    pub matched: Vec<SealedMatchEntry>,
    /// Dismissed transaction hashes.
    pub dismissed: Vec<String>,
}

impl InboxBookmark {
    /// An empty bookmark for a fresh identity.
    #[must_use]
    pub fn empty(identity_pubkey_ed25519_hex: String) -> Self {
        Self {
            schema_version: BOOKMARK_SCHEMA_VERSION,
            identity_pubkey_ed25519_hex,
            last_processed_cursor: 0,
            last_processed_block_height: 0,
            matched: Vec::new(),
            dismissed: Vec::new(),
        }
    }
}

const PREFIX_HEX_LEN: usize = 16;

/// The 16-hex-char (8-byte) lowercase prefix of an Ed25519 public key.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when the key is not 32 bytes.
pub fn ed25519_prefix(pubkey: &[u8]) -> Result<String, CliError> {
    if pubkey.len() != 32 {
        return Err(CliError::input(format!(
            "inbox: Ed25519 public key MUST be 32 bytes; got {}",
            pubkey.len()
        )));
    }
    Ok(crate::util::bytes_to_hex(&pubkey[..PREFIX_HEX_LEN / 2]))
}

/// The full lowercase-hex Ed25519 public key.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when the key is not 32 bytes.
pub fn ed25519_pubkey_hex(pubkey: &[u8]) -> Result<String, CliError> {
    if pubkey.len() != 32 {
        return Err(CliError::input(format!(
            "inbox: Ed25519 public key MUST be 32 bytes; got {}",
            pubkey.len()
        )));
    }
    Ok(crate::util::bytes_to_hex(pubkey))
}

/// The home directory, for locating the per-identity bookmark dir.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// The bookmark directory for an Ed25519 prefix.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) for a malformed prefix or no home directory.
pub fn bookmark_dir(prefix_hex: &str) -> Result<PathBuf, CliError> {
    if prefix_hex.len() != PREFIX_HEX_LEN
        || !prefix_hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(CliError::input(format!(
            "inbox: identity prefix MUST be 16 lowercase-hex chars; got \"{prefix_hex}\""
        )));
    }
    let home = home_dir()
        .ok_or_else(|| CliError::input("inbox: no home directory to locate the bookmark"))?;
    Ok(home.join(".cardanowall").join(prefix_hex))
}

/// The bookmark file path for an Ed25519 prefix.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) for a malformed prefix.
pub fn bookmark_path(prefix_hex: &str) -> Result<PathBuf, CliError> {
    Ok(bookmark_dir(prefix_hex)?.join("inbox.json"))
}

/// Load the bookmark at `path`, or return an empty one if the file is absent.
///
/// Validates the schema and the identity binding. Emits a permission-drift nudge
/// on stderr when the on-disk mode is not `0600` (Unix only).
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) for a symlink path, a malformed file, a schema
/// mismatch, or an identity mismatch.
pub fn load_or_init(
    path: &Path,
    identity_pubkey_ed25519_hex: &str,
) -> Result<InboxBookmark, CliError> {
    refuse_if_symlink(path)?;
    if !path.exists() {
        return Ok(InboxBookmark::empty(
            identity_pubkey_ed25519_hex.to_string(),
        ));
    }
    let raw = std::fs::read_to_string(path).map_err(|e| {
        CliError::input(format!(
            "inbox: cannot read bookmark file at {}: {e}",
            path.display()
        ))
    })?;
    let bookmark: InboxBookmark = serde_json::from_str(&raw).map_err(|e| {
        CliError::input(format!(
            "inbox: bookmark file at {} is malformed: {e}",
            path.display()
        ))
    })?;
    if bookmark.schema_version != BOOKMARK_SCHEMA_VERSION {
        return Err(CliError::input(format!(
            "inbox: bookmark file at {} has unsupported schema_version {}",
            path.display(),
            bookmark.schema_version
        )));
    }
    if bookmark.identity_pubkey_ed25519_hex != identity_pubkey_ed25519_hex {
        return Err(CliError::input(format!(
            "inbox: bookmark identity mismatch at {}: expected {identity_pubkey_ed25519_hex}, got {}",
            path.display(),
            bookmark.identity_pubkey_ed25519_hex
        )));
    }
    check_perms_and_nudge(path);
    Ok(bookmark)
}

/// Persist the bookmark to `path` atomically, under `0600` perms on Unix.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) for a symlink path or a write failure.
pub fn save(path: &Path, bookmark: &InboxBookmark) -> Result<(), CliError> {
    refuse_if_symlink(path)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            CliError::input(format!(
                "inbox: cannot create bookmark dir {}: {e}",
                dir.display()
            ))
        })?;
    }
    let serialised = serde_json::to_string_pretty(bookmark)
        .map_err(|e| CliError::input(format!("inbox: cannot serialise bookmark: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, format!("{serialised}\n")).map_err(|e| {
        CliError::input(format!(
            "inbox: cannot write bookmark tmp at {}: {e}",
            tmp.display()
        ))
    })?;
    set_owner_only(&tmp);
    std::fs::rename(&tmp, path).map_err(|e| {
        CliError::input(format!(
            "inbox: cannot finalise bookmark at {}: {e}",
            path.display()
        ))
    })?;
    set_owner_only(path);
    Ok(())
}

fn refuse_if_symlink(path: &Path) -> Result<(), CliError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(CliError::input(format!(
            "inbox: bookmark path {} is a symbolic link; refusing to read/write through it",
            path.display()
        ))),
        _ => Ok(()),
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) {}

#[cfg(unix)]
fn check_perms_and_nudge(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            eprintln!(
                "inbox: bookmark file {} has permissions {:04o}; expected 0600. Run 'chmod 600 {}' to restore.",
                path.display(),
                mode,
                path.display()
            );
        }
    }
}

#[cfg(not(unix))]
fn check_perms_and_nudge(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_16_hex_of_pubkey() {
        let pubkey = [0xabu8; 32];
        assert_eq!(ed25519_prefix(&pubkey).unwrap(), "abababababababab");
    }

    #[test]
    fn rejects_wrong_pubkey_length() {
        assert_eq!(ed25519_prefix(&[0u8; 31]).unwrap_err().code, 4);
    }

    #[test]
    fn rejects_bad_prefix_for_dir() {
        assert_eq!(bookmark_dir("XYZ").unwrap_err().code, 4);
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inbox.json");
        let mut bm = InboxBookmark::empty("aa".repeat(32));
        bm.matched.push(SealedMatchEntry {
            tx_hash: "bb".repeat(32),
            item_idx: 0,
            slot_idx: 1,
            first_seen: "2026-06-01T00:00:00Z".to_string(),
            block_height: Some(42),
            num_confirmations_at_first_seen: Some(20),
        });
        save(&path, &bm).unwrap();
        let loaded = load_or_init(&path, &"aa".repeat(32)).unwrap();
        assert_eq!(loaded, bm);
    }

    #[test]
    fn identity_mismatch_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inbox.json");
        save(&path, &InboxBookmark::empty("aa".repeat(32))).unwrap();
        assert_eq!(load_or_init(&path, &"cc".repeat(32)).unwrap_err().code, 4);
    }
}
