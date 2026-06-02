//! Human-readable transcript of a [`VerifyReport`].
//!
//! A read-only renderer of the verifier report into a structured transcript. The
//! rendered transcript goes to stdout; diagnostics belong on stderr (the caller's
//! concern). The field labels mirror the wire-shaped report so a reader can map
//! the human view back to the `--json` output one-to-one.

use cardanowall::verifier::{DecryptResult, MerkleCheck, SignatureCheck, UriCheck, VerifyReport};

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
    line!(
        "Confirmations:  {}  (threshold: {})",
        report.num_confirmations,
        report.confirmation_depth_threshold
    );
    line!("");

    render_validation(report, &mut out);
    render_signatures(report.record_signatures.as_deref(), &mut out);
    render_decryptions(report.item_decryptions.as_deref(), &mut out);
    render_merkle_checks(report.merkle_checks.as_deref(), &mut out);
    render_uri_checks(report.uri_checks.as_deref(), &mut out);
    render_http_calls(report, &mut out);

    // Single write; trailing newline already included per line.
    print!("{out}");
}

fn render_validation(report: &VerifyReport, out: &mut String) {
    let v = &report.validation;
    let total = v.issues.len() + v.warnings.len() + v.info.len();
    if total == 0 {
        out.push_str("Validation:     ok\n");
    } else {
        out.push_str(&format!("Validation:     {total} issue(s)\n"));
        for i in &v.issues {
            out.push_str(&format!("  - [error] {}: {}\n", i.code.code(), i.message));
        }
        for w in &v.warnings {
            out.push_str(&format!("  - [warning] {}: {}\n", w.code.code(), w.message));
        }
        for f in &v.info {
            out.push_str(&format!("  - [info] {}: {}\n", f.code.code(), f.message));
        }
    }
    out.push('\n');
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

fn render_decryptions(decs: Option<&[DecryptResult]>, out: &mut String) {
    let Some(decs) = decs.filter(|d| !d.is_empty()) else {
        return;
    };
    out.push_str(&format!("Item decryptions ({}):\n", decs.len()));
    for d in decs {
        out.push_str(&format!(
            "  [{}]  verdict={}\n",
            d.item_index,
            d.verdict_str()
        ));
        if let Some(ok) = d.plaintext_hash_ok {
            out.push_str(&format!("       plaintext_hash_ok={ok}\n"));
        }
        if let Some(reason) = d.reason_str() {
            out.push_str(&format!("       reason={reason}\n"));
        }
    }
    out.push('\n');
}

fn render_merkle_checks(checks: Option<&[MerkleCheck]>, out: &mut String) {
    let Some(checks) = checks.filter(|c| !c.is_empty()) else {
        return;
    };
    out.push_str(&format!("Merkle checks ({}):\n", checks.len()));
    for c in checks {
        out.push_str(&format!(
            "  [{}]  alg={}  verdict={}\n",
            c.merkle_index,
            c.alg,
            c.verdict_str()
        ));
        if let Some(reason) = c.reason {
            out.push_str(&format!("       reason={}\n", reason.as_str()));
        }
    }
    out.push('\n');
}

fn render_uri_checks(checks: Option<&[UriCheck]>, out: &mut String) {
    let Some(checks) = checks.filter(|c| !c.is_empty()) else {
        return;
    };
    out.push_str(&format!("URI checks ({}):\n", checks.len()));
    for c in checks {
        let tail = if c.ok {
            "ok".to_string()
        } else {
            format!("FAILED: {}", c.reason.map_or("unknown", |r| r.as_str()))
        };
        out.push_str(&format!("  [item {}]  {}  {}\n", c.item_index, c.uri, tail));
    }
    out.push('\n');
}

fn render_http_calls(report: &VerifyReport, out: &mut String) {
    let calls = &report.http_calls;
    out.push_str(&format!("HTTP audit ({} calls):\n", calls.len()));
    for c in calls {
        out.push_str(&format!(
            "  {} {}  →  status={}  duration_ms={}\n",
            c.method.as_str(),
            c.url,
            c.status,
            c.duration_ms
        ));
    }
}

/// Render a 32-byte digest as lowercase hex (for any caller that needs it).
#[must_use]
pub fn digest_hex(bytes: &[u8]) -> String {
    bytes_to_hex(bytes)
}
