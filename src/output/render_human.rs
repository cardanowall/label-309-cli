//! Human-readable transcript of a [`VerifyReport`].
//!
//! A read-only renderer of the verifier report into a structured transcript. The
//! rendered transcript goes to stdout; diagnostics belong on stderr (the caller's
//! concern). The field labels mirror the wire-shaped report so a reader can map
//! the human view back to the `--json` output one-to-one: the flat issue list,
//! the positional `items[]` / `merkle[]` per-claim entries, and the audit trail.
//! An absent confirmation depth renders as `unknown` — the verifier never
//! fabricates a depth, and neither does this view.

use cardanowall::verifier::{
    ItemReportEntry, MerkleReportEntry, SignatureCheck, VerifierIssue, VerifyReport,
};

use crate::util::bytes_to_hex;

/// Render the report as a multi-line human transcript on stdout.
pub fn render_human_report(report: &VerifyReport) {
    let mut out = String::new();
    macro_rules! line {
        ($($arg:tt)*) => {{
            out.push_str(&format!($($arg)*));
            out.push('\n');
        }};
    }

    line!("Transaction:    {}", report.tx_hash);
    line!("Network:        {}", report.network);
    line!("Verdict:        {}", report.verdict.as_str());
    line!("Profile:        {}", report.profile.as_str());
    let depth = report
        .confirmation_depth
        .map_or_else(|| "unknown".to_string(), |d| d.to_string());
    line!(
        "Confirmations:  {}  (threshold: {})",
        depth,
        report.confirmation_threshold
    );
    if let Some(t) = report.block_time {
        line!("Block time:     {t}");
    }
    if let Some(s) = report.block_slot {
        line!("Block slot:     {s}");
    }
    line!("");

    render_issues(&report.issues, &mut out);
    render_signatures(report.record_signatures.as_deref(), &mut out);
    render_items(&report.items, &mut out);
    render_merkle(&report.merkle, &mut out);
    render_audit_trail(report, &mut out);

    // Single write; trailing newline already included per line.
    print!("{out}");
}

/// Render an issue path as its dotted display form (empty path → `(record)`).
fn path_display(issue: &VerifierIssue) -> String {
    if issue.path.is_empty() {
        return "(record)".to_string();
    }
    issue
        .path
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn render_issues(issues: &[VerifierIssue], out: &mut String) {
    if issues.is_empty() {
        out.push_str("Issues:         none\n");
    } else {
        out.push_str(&format!("Issues:         {}\n", issues.len()));
        for i in issues {
            out.push_str(&format!(
                "  - [{}] {} at {}: {}\n",
                severity_str(i.severity),
                i.code.code(),
                path_display(i),
                i.message
            ));
        }
    }
    out.push('\n');
}

fn severity_str(severity: cardanowall::poe_standard::Severity) -> &'static str {
    match severity {
        cardanowall::poe_standard::Severity::Error => "error",
        cardanowall::poe_standard::Severity::Warning => "warning",
        cardanowall::poe_standard::Severity::Info => "info",
    }
}

fn render_signatures(sigs: Option<&[SignatureCheck]>, out: &mut String) {
    let Some(sigs) = sigs.filter(|s| !s.is_empty()) else {
        return;
    };
    out.push_str(&format!("Signatures ({}):\n", sigs.len()));
    for s in sigs {
        let type_part = s
            .signer_type
            .map(|t| format!("signer_type={}  ", t.as_str()))
            .unwrap_or_default();
        out.push_str(&format!(
            "  [{}]  {}verdict={}\n",
            s.index,
            type_part,
            s.verdict_str()
        ));
        if let Some(pub_) = &s.signer_pub {
            out.push_str(&format!("       signer_pub={pub_}\n"));
        }
        if let Some(reason) = s.reason {
            out.push_str(&format!("       reason={}\n", reason.as_str()));
        }
    }
    out.push('\n');
}

fn render_items(items: &[ItemReportEntry], out: &mut String) {
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("Items ({}):\n", items.len()));
    for (i, entry) in items.iter().enumerate() {
        out.push_str(&format!(
            "  [{i}]  content_check={}\n",
            entry.content_check.as_str()
        ));
        if let Some(d) = &entry.decryption {
            out.push_str(&format!("       decrypted={}\n", d.decrypted));
            if let Some(ok) = d.plaintext_hash_ok {
                out.push_str(&format!("       plaintext_hash_ok={ok}\n"));
            }
            if let Some(code) = d.code {
                out.push_str(&format!("       code={}\n", code.code()));
            }
        }
    }
    out.push('\n');
}

fn render_merkle(entries: &[MerkleReportEntry], out: &mut String) {
    if entries.is_empty() {
        return;
    }
    out.push_str(&format!("Merkle ({}):\n", entries.len()));
    for (i, entry) in entries.iter().enumerate() {
        out.push_str(&format!(
            "  [{i}]  content_check={}\n",
            entry.content_check.as_str()
        ));
    }
    out.push('\n');
}

fn render_audit_trail(report: &VerifyReport, out: &mut String) {
    let calls = &report.audit_trail;
    out.push_str(&format!("HTTP audit ({} calls):\n", calls.len()));
    for c in calls {
        // A refused or transport-failed call has no HTTP status; render the
        // no-response reading explicitly rather than a fabricated code.
        let status = c.status.map_or_else(|| "-".to_string(), |s| s.to_string());
        out.push_str(&format!(
            "  {} {}  →  status={}  duration_ms={}\n",
            c.method.as_str(),
            c.url,
            status,
            c.duration_ms
        ));
    }
}

/// Render a 32-byte digest as lowercase hex (for any caller that needs it).
#[must_use]
pub fn digest_hex(bytes: &[u8]) -> String {
    bytes_to_hex(bytes)
}
