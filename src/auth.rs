// SPDX-License-Identifier: GPL-3.0-only
//! Authentication policy: unconditional acceptance, the plugin dance modern
//! clients need, and the random login delay.

use rand::RngExt;

use crate::config::AuthConfig;

/// Plugin advertised in the initial handshake.
pub const DEFAULT_PLUGIN: &str = CACHING_SHA2;
/// MySQL 8.x default authentication plugin.
pub const CACHING_SHA2: &str = "caching_sha2_password";
/// Legacy (5.x / pre-8.0) authentication plugin.
pub const NATIVE: &str = "mysql_native_password";
/// RSA / TLS based plugin some clients still request.
pub const SHA256: &str = "sha256_password";
/// Cleartext plugin, only legal over TLS in a real server.
pub const CLEAR_TEXT: &str = "mysql_clear_password";

/// `caching_sha2_password` fast-auth-succeeded marker.
pub const FAST_AUTH_SUCCESS: u8 = 0x03;
/// `caching_sha2_password` "send the full password" marker (never used: it would
/// require RSA or TLS, and the honeypot needs neither).
pub const PERFORM_FULL_AUTH: u8 = 0x04;

/// Bytes in the handshake scramble.
pub const SALT_LEN: usize = 20;

/// How the honeypot answers a given handshake response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPlan {
    /// `AuthMoreData` with the fast-auth marker, then an OK packet. Required by
    /// `caching_sha2_password` clients, which reject a bare OK.
    CachingSha2FastPath,
    /// A single OK packet. Correct for `mysql_native_password` and accepted by
    /// the sha256/cleartext plugins as their terminal state.
    PlainOk,
}

impl AuthPlan {
    /// Whether the plan needs the `AuthMoreData` frame first.
    pub fn needs_more_data(self) -> bool {
        matches!(self, Self::CachingSha2FastPath)
    }
}

/// Pick the response plan from the plugin the client answered for.
///
/// A client that sent no plugin name negotiated on `mysql_native_password`
/// semantics, which is the plain OK path.
pub fn plan_for(plugin: Option<&str>) -> AuthPlan {
    match plugin {
        Some(name) if name.eq_ignore_ascii_case(CACHING_SHA2) => AuthPlan::CachingSha2FastPath,
        Some(name)
            if name.eq_ignore_ascii_case(NATIVE)
                || name.eq_ignore_ascii_case(SHA256)
                || name.eq_ignore_ascii_case(CLEAR_TEXT) =>
        {
            AuthPlan::PlainOk
        }
        // Unknown plugin: an OK packet is the protocol's terminal success state
        // for any plugin, so the session continues instead of erroring out.
        _ => AuthPlan::PlainOk,
    }
}

/// Whether the advertised plugin should be the modern one.
pub fn handshake_plugin() -> &'static str {
    DEFAULT_PLUGIN
}

/// Fresh 20 byte scramble, printable ASCII with no interior NUL so the
/// handshake's NUL terminated auth-data block stays parseable.
pub fn random_salt() -> Vec<u8> {
    let mut rng = rand::rng();
    (0..SALT_LEN)
        .map(|_| rng.random_range(0x21u8..=0x7e))
        .collect()
}

/// Draw an independent delay in `[delay_min_ms, delay_max_ms]`.
pub fn random_delay_millis(config: &AuthConfig) -> u64 {
    let min = config.delay_min_ms.min(config.delay_max_ms);
    let max = config.delay_max_ms.max(config.delay_min_ms);
    var_delay(min, max)
}

fn var_delay(min: u64, max: u64) -> u64 {
    if min == max {
        return min;
    }
    let mut rng = rand::rng();
    rng.random_range(min..=max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_is_printable_and_null_free() {
        let salt = random_salt();
        assert_eq!(salt.len(), SALT_LEN);
        assert!(salt.iter().all(|b| (0x21..=0x7e).contains(b)));
        let other = random_salt();
        assert_ne!(salt, other, "salts must differ between sessions");
    }

    #[test]
    fn plugin_plans() {
        assert_eq!(plan_for(Some(CACHING_SHA2)), AuthPlan::CachingSha2FastPath);
        assert_eq!(
            plan_for(Some("CACHING_SHA2_PASSWORD")),
            AuthPlan::CachingSha2FastPath
        );
        assert_eq!(plan_for(Some(NATIVE)), AuthPlan::PlainOk);
        assert_eq!(plan_for(Some(SHA256)), AuthPlan::PlainOk);
        assert_eq!(plan_for(Some(CLEAR_TEXT)), AuthPlan::PlainOk);
        assert_eq!(plan_for(Some("auth_gssapi_client")), AuthPlan::PlainOk);
        assert_eq!(plan_for(None), AuthPlan::PlainOk);
        assert!(AuthPlan::CachingSha2FastPath.needs_more_data());
        assert!(!AuthPlan::PlainOk.needs_more_data());
    }

    #[test]
    fn default_delay_stays_inside_the_configured_window() {
        let config = AuthConfig::default();
        for _ in 0..2_000 {
            let delay = random_delay_millis(&config);
            assert!(
                (2_000..=6_000).contains(&delay),
                "delay {delay} outside 2000..=6000"
            );
        }
    }

    #[test]
    fn delay_window_is_respected_and_varies() {
        let config = AuthConfig {
            always_accept: true,
            delay_min_ms: 10,
            delay_max_ms: 12,
        };
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            let delay = random_delay_millis(&config);
            assert!((10..=12).contains(&delay));
            seen.insert(delay);
        }
        assert!(seen.len() > 1, "delay must not be constant");
    }

    #[test]
    fn degenerate_window_is_safe() {
        let config = AuthConfig {
            always_accept: true,
            delay_min_ms: 7,
            delay_max_ms: 7,
        };
        assert_eq!(random_delay_millis(&config), 7);
    }
}
