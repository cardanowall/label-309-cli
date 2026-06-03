//! Load + persist the `config.toml` that holds the gateway profiles.
//!
//! Reads round-trip EVERY known field (the data-gateway chains, thresholds, and
//! deny-hosts as well as the profiles), so a `gateway add` never drops a hand-
//! edited `cardano_gateway`. Writes are atomic (`.tmp` → rename) and the file is
//! created / kept at `0600`; an existing wider mode is tightened, never widened.

use std::path::Path;

use crate::config::read_config_file::{config_path, parse_config_str, ConfigEnv, SystemConfigEnv};
use crate::config::CardanoWallConfig;
use crate::util::CliError;

/// Load the full config for editing — an absent file (even when
/// `CARDANOWALL_CONFIG_PATH` points at one that does not exist yet) yields the
/// default (empty) config so `gateway add` can create it from scratch. This is the
/// key difference from [`read_config_file`](fn@crate::config::read_config_file),
/// which treats a missing explicit path as a read-time error.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) when the file exists but cannot be read or
/// fails to parse, or no config path can be resolved.
pub fn load_config_for_edit(env: &dyn ConfigEnv) -> Result<CardanoWallConfig, CliError> {
    let path = config_path(env)?;
    match env.read_to_string(&path) {
        Ok(raw) => parse_config_str(&raw, &path, env),
        // A missing file is fine here — we are about to create it.
        Err(None) => Ok(CardanoWallConfig::default()),
        Err(Some(e)) => Err(CliError::input(format!(
            "config: cannot read {}: {e}",
            path.display()
        ))),
    }
}

/// Serialise `config` to TOML and write it to the resolved config path at `0600`.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) on a serialise, directory-create, or write
/// failure.
pub fn write_config(env: &dyn ConfigEnv, config: &CardanoWallConfig) -> Result<(), CliError> {
    let path = config_path(env)?;
    let serialised = toml::to_string_pretty(config)
        .map_err(|e| CliError::input(format!("config: cannot serialise config.toml: {e}")))?;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            CliError::input(format!(
                "config: cannot create config dir {}: {e}",
                dir.display()
            ))
        })?;
    }

    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, serialised).map_err(|e| {
        CliError::input(format!(
            "config: cannot write config tmp at {}: {e}",
            tmp.display()
        ))
    })?;
    set_owner_only(&tmp);
    std::fs::rename(&tmp, &path).map_err(|e| {
        CliError::input(format!(
            "config: cannot finalise config at {}: {e}",
            path.display()
        ))
    })?;
    set_owner_only(&path);
    Ok(())
}

/// Convenience: the resolved config path with the production env.
///
/// # Errors
///
/// Propagates [`config_path`]'s error.
pub fn system_config_path() -> Result<std::path::PathBuf, CliError> {
    config_path(&SystemConfigEnv)
}

#[cfg(unix)]
fn set_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) {}
