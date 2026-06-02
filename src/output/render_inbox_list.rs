//! Fixed-width human-readable table renderer for the inbox bookmark.
//!
//! Sorts newest-first by `first_seen`. The bookmark persists only confirmed
//! records, so the renderer surfaces only the `matched[]` section. A `*` on the
//! CONFIRMS column flags a snapshot value (taken at sync time) that a live
//! `--gateway` tip refresh did not override.

use std::collections::HashMap;

use crate::state::InboxBookmark;

const COL_TX: usize = 64;
const COL_ITEM: usize = 5;
const COL_SLOT: usize = 5;
const COL_FIRST_SEEN: usize = 24;
const COL_CONFIRMS: usize = 9;
const COL_STATUS: usize = 12;

fn pad_r(s: &str, n: usize) -> String {
    if s.len() >= n {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(n - s.len()))
    }
}

fn pad_l(s: &str, n: usize) -> String {
    if s.len() >= n {
        s.to_string()
    } else {
        format!("{}{s}", " ".repeat(n - s.len()))
    }
}

/// Render the bookmark's matches as a fixed-width table on stdout.
///
/// `tip_refreshed` maps a tx hash to a freshly fetched confirmation count; when
/// `None`, every row shows the stale snapshot value (flagged with `*`).
pub fn render_inbox_list_human(
    bookmark: &InboxBookmark,
    tip_refreshed: Option<&HashMap<String, u32>>,
) {
    let mut matches = bookmark.matched.clone();
    matches.sort_by(|a, b| b.first_seen.cmp(&a.first_seen));

    if matches.is_empty() {
        println!("(no matches in inbox; run 'cardanowall inbox sync' to fetch new sealed records)");
        return;
    }

    let header = format!(
        "{}  {}  {}  {}  {}  {}",
        pad_r("TX_HASH", COL_TX),
        pad_r("ITEM", COL_ITEM),
        pad_r("SLOT", COL_SLOT),
        pad_r("FIRST_SEEN", COL_FIRST_SEEN),
        pad_r("CONFIRMS", COL_CONFIRMS),
        pad_r("STATUS", COL_STATUS),
    );
    println!("{header}");

    for m in &matches {
        let mut stale = false;
        let mut confirms = if let Some(refreshed) = tip_refreshed.and_then(|t| t.get(&m.tx_hash)) {
            refreshed.to_string()
        } else if let Some(n) = m.num_confirmations_at_first_seen {
            stale = true;
            n.to_string()
        } else {
            stale = true;
            "?".to_string()
        };
        if stale {
            confirms.push('*');
        }
        println!(
            "{}  {}  {}  {}  {}  {}",
            pad_r(&m.tx_hash, COL_TX),
            pad_l(&m.item_idx.to_string(), COL_ITEM),
            pad_l(&m.slot_idx.to_string(), COL_SLOT),
            pad_r(&m.first_seen, COL_FIRST_SEEN),
            pad_l(&confirms, COL_CONFIRMS),
            pad_r("confirmed", COL_STATUS),
        );
    }

    if tip_refreshed.is_none() {
        println!("(* CONFIRMS column shows the snapshot at sync time; pass --gateway to refresh)");
    }
}
