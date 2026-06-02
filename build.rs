//! Stamp the build-time provenance the `--version` flag prints: the package
//! version, the short git SHA, and the UTC build date. The values are emitted as
//! `cargo:rustc-env` instructions so `env!(...)` resolves them at compile time.
//!
//! Git SHA and date are derived by shelling out to `git` and the system clock
//! rather than pulling a build-info crate, keeping the dependency graph minimal
//! and the stamping fully explicit. A build outside a git checkout (e.g. an
//! unpacked source tarball) falls back to `unknown`, never failing the build.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!(
        "cargo:rustc-env=CARDANOWALL_CLI_VERSION={}",
        env!("CARGO_PKG_VERSION")
    );
    println!("cargo:rustc-env=CARDANOWALL_CLI_GIT_SHA={}", git_sha());
    println!(
        "cargo:rustc-env=CARDANOWALL_CLI_BUILD_DATE={}",
        build_date()
    );

    // Re-run when HEAD moves so the stamped SHA stays current across commits.
    println!("cargo:rerun-if-changed=build.rs");
    if let Some(git_dir) = git_dir() {
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
    }
}

/// The short (12-char) HEAD commit SHA, or `unknown` outside a git checkout.
fn git_sha() -> String {
    run_git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_string())
}

/// The absolute path to the `.git` directory, when inside a checkout.
fn git_dir() -> Option<String> {
    run_git(&["rev-parse", "--absolute-git-dir"])
}

/// Run `git <args>` from the crate root and return its trimmed stdout on success.
fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// The UTC build date as `YYYY-MM-DD`, derived from the wall clock with a
/// dependency-free civil-date conversion (Howard Hinnant's `days_from_civil`
/// inverse). Falls back to `unknown` if the clock is before the Unix epoch.
fn build_date() -> String {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return "unknown".to_string(),
    };
    let days = (now / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Convert a count of days since 1970-01-01 to a `(year, month, day)` civil date.
/// Port of Howard Hinnant's `civil_from_days`, valid for the full proleptic
/// Gregorian range.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
