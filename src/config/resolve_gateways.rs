//! Resolve the gateway slots (cardano, arweave, ipfs, blockfrost) plus the two
//! scalar slots (threshold, deny-hosts) using the precedence:
//!
//! ```text
//! flag (repeatable / comma-list)  →
//! env  (comma-separated)          →
//! config-file (string or array)   →
//! built-in default chain
//! ```
//!
//! First non-empty source wins; lower-precedence sources are NOT merged in. URL
//! shape is validated here (https-only, except loopback).

use cardanowall::verifier::KOIOS_MAINNET_URL;

use crate::config::read_config_file::CardanoWallConfig;
use crate::util::CliError;

/// The resolved gateway chains and scalars the verifier / inbox paths consume.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedGateways {
    /// Cardano (Koios-compatible) gateway chain.
    pub cardano_gateway_chain: Vec<String>,
    /// Blockfrost project id, when configured.
    pub blockfrost_project_id: Option<String>,
    /// Arweave gateway chain.
    pub arweave_gateway_chain: Vec<String>,
    /// IPFS gateway chain, when configured (no baked-in default).
    pub ipfs_gateway_chain: Option<Vec<String>>,
    /// Confirmation-depth threshold, when set anywhere.
    pub confirmation_depth_threshold: Option<u32>,
    /// Deny-host patterns, when set anywhere (the canonical default applies
    /// downstream when this is `None`).
    pub deny_hosts: Option<Vec<String>>,
}

/// Flag inputs, already collected by clap (empty vec = flag not given).
#[derive(Debug, Clone, Default)]
pub struct GatewayFlags {
    /// `--cardano-gateway` (repeatable).
    pub gateway: Vec<String>,
    /// `--blockfrost`.
    pub blockfrost: Option<String>,
    /// `--arweave-gateway` (repeatable).
    pub arweave_gateway: Vec<String>,
    /// `--ipfs-gateway` (repeatable).
    pub ipfs_gateway: Vec<String>,
    /// `--threshold` (already parsed to a non-negative integer).
    pub threshold: Option<u32>,
    /// `--deny-host` (repeatable).
    pub deny_host: Vec<String>,
}

/// The environment lookups the resolver needs, injected for tests.
pub trait GatewayEnv {
    /// Read an environment variable.
    fn var(&self, key: &str) -> Option<String>;
}

/// The production env: real process environment.
pub struct SystemGatewayEnv;

impl GatewayEnv for SystemGatewayEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

fn default_cardano_chain() -> Vec<String> {
    vec![KOIOS_MAINNET_URL.to_string()]
}

fn default_arweave_chain() -> Vec<String> {
    vec![
        "https://ar-io.net".to_string(),
        "https://arweave.net".to_string(),
        "https://g8way.io".to_string(),
    ]
}

/// Split a comma-separated env value into a trimmed, non-empty list.
fn split_env_list(value: Option<&str>) -> Option<Vec<String>> {
    let trimmed = value?.trim();
    if trimmed.is_empty() {
        return None;
    }
    let list: Vec<String> = trimmed
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if list.is_empty() {
        None
    } else {
        Some(list)
    }
}

fn pick_chain(
    flag: &[String],
    env: Option<&str>,
    cfg: Option<Vec<String>>,
    fallback: Vec<String>,
) -> Vec<String> {
    if !flag.is_empty() {
        return flag.to_vec();
    }
    if let Some(list) = split_env_list(env) {
        return list;
    }
    if let Some(list) = cfg {
        if !list.is_empty() {
            return list;
        }
    }
    fallback
}

fn pick_scalar_string(flag: Option<&str>, env: Option<&str>, cfg: Option<&str>) -> Option<String> {
    if let Some(f) = flag {
        if !f.is_empty() {
            return Some(f.to_string());
        }
    }
    if let Some(e) = env {
        let t = e.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    if let Some(c) = cfg {
        if !c.is_empty() {
            return Some(c.to_string());
        }
    }
    None
}

fn pick_threshold(
    flag: Option<u32>,
    env: Option<&str>,
    cfg: Option<i64>,
) -> Result<Option<u32>, CliError> {
    if let Some(f) = flag {
        return Ok(Some(f));
    }
    if let Some(e) = env {
        let t = e.trim();
        if !t.is_empty() {
            let n: i64 = t.parse().map_err(|_| {
                CliError::input(format!(
                    "verify: CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD must be a non-negative integer; got \"{e}\""
                ))
            })?;
            if n < 0 {
                return Err(CliError::input(format!(
                    "verify: CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD must be a non-negative integer; got \"{e}\""
                )));
            }
            return Ok(Some(n as u32));
        }
    }
    if let Some(c) = cfg {
        if c < 0 {
            return Err(CliError::input(format!(
                "verify: config-file confirmation_depth_threshold must be a non-negative integer; got {c}"
            )));
        }
        return Ok(Some(c as u32));
    }
    Ok(None)
}

fn pick_deny_hosts(
    flag: &[String],
    env: Option<&str>,
    cfg: Option<&[String]>,
) -> Option<Vec<String>> {
    if !flag.is_empty() {
        return Some(flag.to_vec());
    }
    if let Some(list) = split_env_list(env) {
        return Some(list);
    }
    if let Some(c) = cfg {
        if !c.is_empty() {
            return Some(c.to_vec());
        }
    }
    None
}

/// Validate a single gateway URL: https only, except http on loopback.
fn validate_url(url: &str, slot: &str) -> Result<(), CliError> {
    // Minimal scheme + host check without a URL crate: parse `scheme://host…`.
    let lowered = url.trim();
    let (scheme, rest) = match lowered.split_once("://") {
        Some(parts) => parts,
        None => {
            return Err(CliError::input(format!(
                "verify: {slot} URL is not a valid URL; got \"{url}\""
            )))
        }
    };
    let host = rest
        .split('/')
        .next()
        .unwrap_or("")
        .split('@')
        .next_back()
        .unwrap_or("");
    // Strip a port for the loopback comparison.
    let host_only = if host.starts_with('[') {
        // bracketed IPv6 literal
        host.split(']')
            .next()
            .map(|h| format!("{h}]"))
            .unwrap_or_default()
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h).to_string()
    };
    match scheme {
        "https" => Ok(()),
        "http" => {
            let is_loopback = matches!(
                host_only.as_str(),
                "localhost" | "127.0.0.1" | "::1" | "[::1]"
            );
            if is_loopback {
                Ok(())
            } else {
                Err(CliError::input(format!(
                    "verify: {slot} URL must use https (http is only permitted for localhost); got \"{url}\""
                )))
            }
        }
        _ => Err(CliError::input(format!(
            "verify: {slot} URL must be https (or http on localhost); got \"{url}\""
        ))),
    }
}

fn validate_chain(chain: &[String], slot: &str) -> Result<(), CliError> {
    for url in chain {
        validate_url(url, slot)?;
    }
    Ok(())
}

/// Resolve all gateway slots, applying precedence and validating URL shape.
///
/// # Errors
///
/// Returns [`CliError`] (exit `4`) on an invalid URL or a malformed threshold.
pub fn resolve_gateways(
    flags: &GatewayFlags,
    env: &dyn GatewayEnv,
    config: Option<&CardanoWallConfig>,
) -> Result<ResolvedGateways, CliError> {
    let cardano_gateway_chain = pick_chain(
        &flags.gateway,
        env.var("CARDANOWALL_CARDANO_GATEWAY").as_deref(),
        config.and_then(|c| c.cardano_gateway.as_ref().map(|v| v.to_vec())),
        default_cardano_chain(),
    );
    validate_chain(&cardano_gateway_chain, "--cardano-gateway")?;

    let arweave_gateway_chain = pick_chain(
        &flags.arweave_gateway,
        env.var("CARDANOWALL_ARWEAVE_GATEWAY").as_deref(),
        config.and_then(|c| c.arweave_gateway.as_ref().map(|v| v.to_vec())),
        default_arweave_chain(),
    );
    validate_chain(&arweave_gateway_chain, "--arweave-gateway")?;

    let ipfs_gateway_chain = {
        let from_flag = &flags.ipfs_gateway;
        let from_env = split_env_list(env.var("CARDANOWALL_IPFS_GATEWAY").as_deref());
        let from_cfg = config.and_then(|c| c.ipfs_gateway.as_ref().map(|v| v.to_vec()));
        let chain = if !from_flag.is_empty() {
            Some(from_flag.clone())
        } else if let Some(list) = from_env {
            Some(list)
        } else {
            from_cfg.filter(|l| !l.is_empty())
        };
        if let Some(ref c) = chain {
            validate_chain(c, "--ipfs-gateway")?;
        }
        chain
    };

    let blockfrost_project_id = pick_scalar_string(
        flags.blockfrost.as_deref(),
        env.var("CARDANOWALL_BLOCKFROST_PROJECT_ID").as_deref(),
        config.and_then(|c| c.blockfrost_project_id.as_deref()),
    );

    let confirmation_depth_threshold = pick_threshold(
        flags.threshold,
        env.var("CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD")
            .as_deref(),
        config.and_then(|c| c.confirmation_depth_threshold),
    )?;

    let deny_hosts = pick_deny_hosts(
        &flags.deny_host,
        env.var("CARDANOWALL_DENY_HOST").as_deref(),
        config.and_then(|c| c.deny_host.as_deref()),
    );

    Ok(ResolvedGateways {
        cardano_gateway_chain,
        blockfrost_project_id,
        arweave_gateway_chain,
        ipfs_gateway_chain,
        confirmation_depth_threshold,
        deny_hosts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::read_config_file::StringOrList;
    use std::collections::HashMap;

    struct FakeEnv(HashMap<String, String>);
    impl GatewayEnv for FakeEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }
    fn env(pairs: &[(&str, &str)]) -> FakeEnv {
        FakeEnv(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn falls_back_to_koios_default() {
        let out = resolve_gateways(&GatewayFlags::default(), &env(&[]), None).unwrap();
        assert_eq!(out.cardano_gateway_chain, vec![KOIOS_MAINNET_URL]);
    }

    #[test]
    fn flag_overrides_env_and_config() {
        let flags = GatewayFlags {
            gateway: vec!["https://flag-1.example".to_string()],
            ..GatewayFlags::default()
        };
        let cfg = CardanoWallConfig {
            cardano_gateway: Some(StringOrList::One("https://config.example".to_string())),
            ..CardanoWallConfig::default()
        };
        let out = resolve_gateways(
            &flags,
            &env(&[("CARDANOWALL_CARDANO_GATEWAY", "https://env.example")]),
            Some(&cfg),
        )
        .unwrap();
        assert_eq!(out.cardano_gateway_chain, vec!["https://flag-1.example"]);
    }

    #[test]
    fn env_comma_splits_into_chain() {
        let out = resolve_gateways(
            &GatewayFlags::default(),
            &env(&[(
                "CARDANOWALL_CARDANO_GATEWAY",
                "https://a.example,https://b.example",
            )]),
            None,
        )
        .unwrap();
        assert_eq!(
            out.cardano_gateway_chain,
            vec!["https://a.example", "https://b.example"]
        );
    }

    #[test]
    fn rejects_non_https_non_loopback() {
        let flags = GatewayFlags {
            gateway: vec!["http://evil.example".to_string()],
            ..GatewayFlags::default()
        };
        assert_eq!(
            resolve_gateways(&flags, &env(&[]), None).unwrap_err().code,
            4
        );
    }

    #[test]
    fn allows_http_loopback() {
        let flags = GatewayFlags {
            gateway: vec!["http://localhost:8080/api".to_string()],
            ..GatewayFlags::default()
        };
        assert!(resolve_gateways(&flags, &env(&[]), None).is_ok());
    }

    #[test]
    fn rejects_unparseable_url() {
        let flags = GatewayFlags {
            gateway: vec!["not-a-url".to_string()],
            ..GatewayFlags::default()
        };
        assert_eq!(
            resolve_gateways(&flags, &env(&[]), None).unwrap_err().code,
            4
        );
    }
}
