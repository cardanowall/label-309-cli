//! TOML config + multi-gateway resolution.
//!
//! A user may define named defaults in `~/.cardanowall/config.toml` (overridable
//! via `CARDANOWALL_CONFIG_PATH`) so they need not pass `--gateway` /
//! `--arweave-gateway` / `--blockfrost` on every invocation. The resolver applies
//! the precedence `flags > env > config-file > built-in default`.

pub mod gateway_store;
pub mod read_config_file;
pub mod resolve_gateways;

pub use gateway_store::{load_config_for_edit, system_config_path, write_config};
pub use read_config_file::{
    config_path, parse_config_str, read_config_file, CardanoWallConfig, ConfigEnv, GatewayProfile,
    SystemConfigEnv,
};
pub use resolve_gateways::{resolve_gateways, GatewayFlags, ResolvedGateways, SystemGatewayEnv};
