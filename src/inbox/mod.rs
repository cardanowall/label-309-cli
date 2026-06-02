//! Inbox subsystem helpers: identity resolution, envelope projection, and the
//! plaintext-hash recompute. The command handlers live in
//! [`crate::commands::inbox`].

pub mod envelope;
pub mod identity;
pub mod recompute_hashes;

pub use envelope::envelope_from_item;
pub use identity::{resolve_identity, IdentitySource, ResolvedIdentity};
pub use recompute_hashes::{recompute_item_hashes, RecomputeResult};
