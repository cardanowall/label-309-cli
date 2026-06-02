//! Project a validated record item's `enc` block onto the discriminated
//! [`SealedEnvelope`] the unwrap / trial-decrypt path consumes.
//!
//! The structural validator yields a permissive [`EncryptionEnvelope`] whose
//! per-slot fields are all optional (the schema layer cannot know the KEM from a
//! slot in isolation). This bridges that to the sealed-PoE [`ParsedEnvelope`] and
//! dispatches on `enc.kem`; it returns `None` for anything that is not a
//! recognised sealed-recipient envelope (a passphrase-only block, a missing
//! field, or an unknown KEM).

use cardanowall::poe_standard::{EncryptionEnvelope, ItemEntry};
use cardanowall::sealed_poe::{
    sealed_envelope_from_parsed, ParsedEnvelope, ParsedSlot, SealedEnvelope,
};

/// Convert an item's `enc` block to a [`SealedEnvelope`], or `None` when the item
/// carries no trial-decryptable sealed-recipient envelope.
#[must_use]
pub fn envelope_from_item(item: &ItemEntry) -> Option<SealedEnvelope> {
    let enc = item.enc.as_ref()?;
    sealed_envelope_from_parsed(&parsed_from_encryption_envelope(enc))
}

fn parsed_from_encryption_envelope(enc: &EncryptionEnvelope) -> ParsedEnvelope {
    ParsedEnvelope {
        scheme: Some(enc.scheme as i64),
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
