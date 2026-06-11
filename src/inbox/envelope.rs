//! Project a validated record item's `enc` block onto the discriminated
//! [`SealedEnvelope`] the unwrap / trial-decrypt path consumes.
//!
//! The structural validator yields an [`EncryptionEnvelope`] whose typed
//! scheme-1 arm keeps every per-slot field optional (the schema layer cannot
//! know the KEM from a slot in isolation). This bridges that arm to the
//! sealed-PoE [`ParsedEnvelope`] and dispatches on `enc.kem`; it returns `None`
//! for anything that is not a recognised sealed-recipient envelope (an opaque
//! envelope, a passphrase-only block, a missing field, or an unknown KEM).

use cardanowall::poe_standard::{EncScheme1, EncryptionEnvelope, ItemEntry};
use cardanowall::sealed_poe::{
    sealed_envelope_from_parsed, ParsedEnvelope, ParsedSlot, SealedEnvelope,
};

/// Convert an item's `enc` block to a [`SealedEnvelope`], or `None` when the item
/// carries no trial-decryptable sealed-recipient envelope.
#[must_use]
pub fn envelope_from_item(item: &ItemEntry) -> Option<SealedEnvelope> {
    let EncryptionEnvelope::Scheme1(enc) = item.enc.as_ref()? else {
        // An opaque envelope (unsupported identifiers, preserved verbatim) has
        // no recipient key path this implementation can attempt.
        return None;
    };
    sealed_envelope_from_parsed(&parsed_from_scheme1(enc))
}

fn parsed_from_scheme1(enc: &EncScheme1) -> ParsedEnvelope {
    ParsedEnvelope {
        scheme: i64::try_from(enc.scheme).ok(),
        aead: Some(enc.aead.clone()),
        kem: enc.kem.clone(),
        nonce: Some(enc.nonce.clone()),
        slots: enc.slots.as_ref().map(|slots| {
            slots
                .iter()
                .map(|s| ParsedSlot {
                    epk: s.epk.clone(),
                    kem_ct: s.kem_ct.clone(),
                    wrap: s.wrap.clone(),
                })
                .collect()
        }),
        slots_mac: enc.slots_mac.clone(),
    }
}
