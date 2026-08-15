//! Per-boot identity for the supervised inspector sidecar.
//!
//! When `mcpg --inspector` supervises an `mcpg-inspector` child, the
//! supervisor mints a random credential, hands it to the child through
//! its environment, and installs it here. A request presenting that
//! credential from a loopback peer resolves to a Verified principal —
//! so the inspector clears the default tool-access trust floor on a
//! stock config without the operator lowering it. The check runs
//! before the bearer-verifier cascade (like the EMA arm): the token is
//! process-minted, so it must never be shopped to another verifier.
//!
//! Process-global on purpose: supervision is process-scoped, and a
//! config reload must not drop the sidecar's identity. Without a
//! supervisor nothing installs a token and the check is inert.

use std::net::IpAddr;
use std::sync::OnceLock;

use crate::runtime::RequestIdentity;

/// The principal the supervised inspector resolves to.
pub const INSPECTOR_SUBJECT: &str = "mcpg-inspector";

static TOKEN: OnceLock<String> = OnceLock::new();

/// Install the supervised inspector's credential. First install wins;
/// the supervisor calls this once, before the listener starts.
pub fn install(token: String) {
    let _ = TOKEN.set(token);
}

/// Resolve the inspector identity: a bearer equal to the installed
/// token, presented from a loopback peer. `None` (no token installed,
/// no bearer, non-loopback peer, or mismatch) falls through to the
/// normal cascade unchanged.
pub fn verify(bearer: Option<&str>, peer_ip: Option<IpAddr>) -> Option<RequestIdentity> {
    let expected = TOKEN.get()?;
    let bearer = bearer?;
    if !peer_ip.is_some_and(|ip| ip.is_loopback()) {
        return None;
    }
    if !constant_time_eq(bearer.as_bytes(), expected.as_bytes()) {
        return None;
    }
    Some(RequestIdentity::Verified {
        subject_id: INSPECTOR_SUBJECT.to_owned(),
        issuer: "mcpg-gateway".to_owned(),
        auth_provider: "inspector_supervisor".to_owned(),
        source: "supervised_inspector_token".to_owned(),
        roles: Vec::new(),
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes: std::collections::BTreeMap::new(),
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> Option<IpAddr> {
        Some(IpAddr::from([127, 0, 0, 1]))
    }

    #[test]
    fn resolves_only_with_token_loopback_and_match() {
        // OnceLock is process-wide; one test exercises every branch in
        // order around the single install.
        assert!(
            verify(Some("tok"), loopback()).is_none(),
            "nothing installed yet"
        );

        install("secret-token".to_owned());
        install("second-install-ignored".to_owned());

        assert!(verify(None, loopback()).is_none(), "no bearer");
        assert!(
            verify(Some("secret-token"), Some(IpAddr::from([10, 0, 0, 7]))).is_none(),
            "non-loopback peer"
        );
        assert!(verify(Some("secret-token"), None).is_none(), "unknown peer");
        assert!(verify(Some("wrong"), loopback()).is_none(), "mismatch");

        let identity = verify(Some("secret-token"), loopback()).expect("resolves");
        assert_eq!(
            identity.trust_level(),
            crate::runtime::RequestTrustLevel::Verified
        );
        assert_eq!(identity.principal_id(), Some(INSPECTOR_SUBJECT));

        let v6 = verify(
            Some("secret-token"),
            Some(IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1])),
        );
        assert!(v6.is_some(), "IPv6 loopback counts");
    }
}
