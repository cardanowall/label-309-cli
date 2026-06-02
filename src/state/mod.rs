//! Local on-device state: the per-identity inbox bookmark.

pub mod bookmark;

pub use bookmark::{
    bookmark_path, ed25519_prefix, ed25519_pubkey_hex, load_or_init, save, InboxBookmark,
    SealedMatchEntry,
};
