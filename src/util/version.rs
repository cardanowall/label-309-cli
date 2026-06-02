//! The `--version` string, stamped at compile time by `build.rs`.
//!
//! Carries the package version, the short git SHA, and the UTC build date so a
//! deployed binary self-identifies its provenance.

/// The version line clap appends after the binary name, e.g.
/// `0.0.0 (git abc123, built 2026-06-01)` — clap renders it as
/// `cardanowall 0.0.0 (git abc123, built 2026-06-01)`.
///
/// Returned as a `&'static str` so it can feed clap's `version` attribute (which
/// requires a value convertible to a static string). The components are all
/// compile-time `env!` constants, so the line is assembled once and cached. The
/// binary name is omitted here because clap prepends it.
#[must_use]
pub fn version_string() -> &'static str {
    use std::sync::OnceLock;
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            format!(
                "{} (git {}, built {})",
                env!("CARDANOWALL_CLI_VERSION"),
                env!("CARDANOWALL_CLI_GIT_SHA"),
                env!("CARDANOWALL_CLI_BUILD_DATE"),
            )
        })
        .as_str()
}
