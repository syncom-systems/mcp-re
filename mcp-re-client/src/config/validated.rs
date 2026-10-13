// SPDX-License-Identifier: Apache-2.0
//! A configuration document that passed every check, and the only form the client runs on.
//!
//! [`ClientConfig`] is what an operator writes: every field public, the type
//! `Deserialize`, so a value of it says nothing about whether it was ever checked. This
//! type is what the client may run on. Its representation is private to this module and
//! its one constructor runs the checks, so holding one means they passed; [`crate::build`]
//! and the serving entry points take it and run no check of their own.
//!
//! The bind decision is made once, here, and carried: [`ValidatedClientConfig::bind_scope`]
//! hands the listener the [`BindScope`] the checks produced, so the seam that opens the
//! socket holds the permission rather than deciding it again.

use std::path::Path;
use std::time::Duration;

use mcp_re_core::MaxClockSkew;

use super::err;
use super::validation;
use super::BindScope;
use super::ClientConfig;
use super::ConfigError;
use super::DelegationConfig;
use super::IdentityConfig;
use super::LocalConfig;
use super::RemoteConfig;
use super::RouteConfig;
use super::TrustConfig;

/// A [`ClientConfig`] every check has admitted, with the bind scope those checks decided.
#[derive(Debug, Clone)]
pub struct ValidatedClientConfig {
    config: ClientConfig,
    bind_scope: BindScope,
    max_clock_skew: MaxClockSkew,
}

impl ValidatedClientConfig {
    /// Run every check on `config`, and keep it only if all of them pass.
    ///
    /// The checks that cannot be expressed in the type: non-empty collections, unique route
    /// ids, a resolvable binding source, bounded windows, and the loopback guard.
    pub fn new(config: ClientConfig) -> Result<Self, ConfigError> {
        let bind_scope = validation::check_local(&config.local)?;
        let max_clock_skew = validation::check_trust_and_delegation(&config)?;
        validation::check_routes(&config)?;
        Ok(Self {
            config,
            bind_scope,
            max_clock_skew,
        })
    }

    /// Parse and check a configuration document.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        let config: ClientConfig =
            serde_json::from_slice(bytes).map_err(|e| err(format!("config: {e}")))?;
        Self::new(config)
    }

    /// Read, parse and check a configuration file.
    pub fn read(path: &Path) -> Result<Self, ConfigError> {
        let bytes =
            std::fs::read(path).map_err(|e| err(format!("config {}: {e}", path.display())))?;
        Self::from_json(&bytes)
    }

    /// The local, plain-MCP leg.
    pub fn local(&self) -> &LocalConfig {
        &self.config.local
    }

    /// Where the local listener is permitted to bind, as the checks decided it.
    pub fn bind_scope(&self) -> BindScope {
        self.bind_scope
    }

    /// This client's signing identity.
    pub fn identity(&self) -> &IdentityConfig {
        &self.config.identity
    }

    /// The remote server and the mTLS material used to reach it.
    pub fn remote(&self) -> &RemoteConfig {
        &self.config.remote
    }

    /// Where the trust anchors come from, and the floor under them.
    pub fn trust(&self) -> &TrustConfig {
        &self.config.trust
    }

    /// The manifest re-read cadence, inside the bound the checks enforce.
    pub fn reload_interval(&self) -> Duration {
        Duration::from_secs(self.config.trust.reload_secs)
    }

    /// The delegated-response policy every route verifies under.
    pub fn delegation(&self) -> &DelegationConfig {
        &self.config.delegation
    }

    /// The clock-skew tolerance the checks admitted, for both the credential window and the
    /// response-signature freshness gate.
    pub fn max_clock_skew(&self) -> MaxClockSkew {
        self.max_clock_skew
    }

    /// The route table, non-empty with unique ids.
    pub fn routes(&self) -> &[RouteConfig] {
        &self.config.routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(local: &str, epochs: &str) -> String {
        format!(
            r#"{{
  "local": {local},
  "identity": {{ "key_id": "c1", "signing_key_seed_path": "/dev/null" }},
  "remote": {{
    "addr": "10.0.0.5:8600",
    "expected_server_name": "proxy.internal",
    "client_cert_path": "/dev/null",
    "client_key_path": "/dev/null",
    "server_ca_path": "/dev/null"
  }},
  "trust": {{
    "manifest_path": "/dev/null",
    "profile": "mcp-re-http-v1",
    "org_keys": [{{ "kid": "org-1", "public_key": "AAAA" }}],
    "floor": {{ "kind": "durable", "dir": "/var/lib/mcp-re/floor" }},
    "reload_secs": 120
  }},
  "delegation": {{
    "verifier_audiences": ["v1"],
    "expected_audience_hash": "v1",
    "accepted_epochs": {epochs}
  }},
  "routes": [{{
    "route_id": "r1",
    "target_uri": "https://mcp.example.com/mcp",
    "audience": {{ "audience_id": "v1", "target_uri": "https://mcp.example.com/mcp", "route": "a" }},
    "extra_headers": [{{ "name": "Authorization", "value": "Bearer tok" }}],
    "artifact_bindings": [{{ "artifact_type": "oauth-dpop", "source": {{ "kind": "header", "name": "Authorization" }} }}]
  }}]
}}"#
        )
    }

    /// The scope carried is the one the checks decided, so the listener needs no decision of
    /// its own.
    #[test]
    fn the_bind_scope_is_the_one_the_checks_decided() {
        let config = ValidatedClientConfig::from_json(
            document(r#"{ "bind": "127.0.0.1:8640" }"#, r#"["e1"]"#).as_bytes(),
        )
        .expect("a valid document");
        assert_eq!(
            config.bind_scope(),
            BindScope::decide("127.0.0.1:8640".parse().expect("an address"), false)
                .expect("loopback")
        );
        assert_eq!(config.reload_interval(), Duration::from_secs(120));
        assert_eq!(config.routes().len(), 1);
    }

    /// A raw document the checks refuse yields no validated value, whether it arrived as
    /// bytes or was built and mutated as a struct.
    #[test]
    fn a_document_the_checks_refuse_yields_no_validated_value() {
        assert!(ValidatedClientConfig::from_json(
            document(r#"{ "bind": "127.0.0.1:8640" }"#, "[]").as_bytes()
        )
        .is_err());
        let mut raw: ClientConfig =
            serde_json::from_str(&document(r#"{ "bind": "127.0.0.1:8640" }"#, r#"["e1"]"#))
                .expect("the raw document parses");
        raw.local.bind = "192.0.2.1:8640".parse().expect("an address");
        assert!(ValidatedClientConfig::new(raw).is_err());
    }
}
