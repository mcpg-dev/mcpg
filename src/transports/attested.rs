//! What the connection a request arrived on vouches for: the TLS session
//! the gateway terminated, and a caller identity an `http`-wire transport
//! established (for a tailnet: the owner of the peer node).

use std::sync::Arc;

use mcpg_plugin_protocol::transport::TransportPeer;

use crate::runtime::RequestIdentity;
use crate::transports::tls::TlsInfoArc;

/// A caller identity a transport plugin attested, with the plugin's id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedPeer {
    /// The plugin id of the transport that attests the peer.
    pub transport: String,
    pub peer: TransportPeer,
}

/// The request extension an `http`-wire transport's request carries.
pub type AttestedPeerArc = Arc<AttestedPeer>;

/// The connection facts identity resolution reads.
#[derive(Debug, Clone, Default)]
pub struct ConnectionFacts {
    pub tls: Option<TlsInfoArc>,
    pub peer: Option<AttestedPeerArc>,
}

impl ConnectionFacts {
    /// The facts the request's extensions hold.
    #[must_use]
    pub fn from_extensions(extensions: &axum::http::Extensions) -> Self {
        Self {
            tls: extensions.get::<TlsInfoArc>().cloned(),
            peer: extensions.get::<AttestedPeerArc>().cloned(),
        }
    }
}

impl From<Option<TlsInfoArc>> for ConnectionFacts {
    fn from(tls: Option<TlsInfoArc>) -> Self {
        Self { tls, peer: None }
    }
}

/// The identity source an attested peer is recorded under.
#[must_use]
pub fn peer_source(transport: &str) -> String {
    format!("transport:{transport}")
}

/// The identity `attested` gives a request whose own credentials
/// established only `current`. A caller that presented a verified
/// credential keeps it; an anonymous or header-asserted caller takes the
/// transport's identity. `None` leaves `current` as it is.
#[must_use]
pub fn identity_from_peer(
    current: &RequestIdentity,
    attested: &AttestedPeer,
) -> Option<RequestIdentity> {
    if matches!(current, RequestIdentity::Verified { .. }) {
        return None;
    }
    let peer = &attested.peer;
    if peer.subject_id.trim().is_empty() {
        return None;
    }
    let source = peer_source(&attested.transport);
    match peer.trust_level.as_str() {
        "verified" => Some(RequestIdentity::Verified {
            subject_id: peer.subject_id.clone(),
            issuer: peer.issuer.clone().unwrap_or_else(|| peer.provider.clone()),
            auth_provider: peer.provider.clone(),
            source,
            roles: peer.roles.clone(),
            groups: peer.groups.clone(),
            scopes: peer.scopes.clone(),
            attributes: peer.attributes.clone(),
        }),
        "header_asserted" if matches!(current, RequestIdentity::Anonymous { .. }) => {
            Some(RequestIdentity::HttpHeader {
                subject_id: peer.subject_id.clone(),
                source,
            })
        }
        "header_asserted" => None,
        other => {
            tracing::warn!(
                transport = %attested.transport,
                trust_level = other,
                "a transport attested a peer with an unknown trust level; ignoring it"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attested(trust_level: &str) -> AttestedPeer {
        AttestedPeer {
            transport: "dev.mcpg.transport.tailscale".into(),
            peer: TransportPeer {
                provider: "tailscale".into(),
                trust_level: trust_level.into(),
                subject_id: "alice@example.com".into(),
                issuer: Some("tailscale:example.com".into()),
                roles: vec!["admin".into()],
                groups: vec!["tag:dev".into()],
                scopes: vec!["tools:read".into()],
                attributes: [(
                    "tailscale.node".to_owned(),
                    "laptop.example.ts.net".to_owned(),
                )]
                .into(),
            },
        }
    }

    fn anonymous() -> RequestIdentity {
        RequestIdentity::Anonymous {
            source: "http".into(),
        }
    }

    #[test]
    fn a_verified_peer_becomes_a_verified_identity_under_its_transport() {
        let id = identity_from_peer(&anonymous(), &attested("verified")).unwrap();
        let RequestIdentity::Verified {
            subject_id,
            issuer,
            auth_provider,
            source,
            roles,
            groups,
            scopes,
            attributes,
        } = id
        else {
            panic!("expected a verified identity");
        };
        assert_eq!(subject_id, "alice@example.com");
        assert_eq!(issuer, "tailscale:example.com");
        assert_eq!(auth_provider, "tailscale");
        assert_eq!(source, "transport:dev.mcpg.transport.tailscale");
        assert_eq!(roles, ["admin"]);
        assert_eq!(groups, ["tag:dev"]);
        assert_eq!(scopes, ["tools:read"]);
        assert_eq!(attributes["tailscale.node"], "laptop.example.ts.net");
    }

    #[test]
    fn a_verified_peer_outranks_a_header_assertion_but_not_a_credential() {
        let header = RequestIdentity::HttpHeader {
            subject_id: "mallory".into(),
            source: "header".into(),
        };
        assert!(matches!(
            identity_from_peer(&header, &attested("verified")),
            Some(RequestIdentity::Verified { .. })
        ));
        let bearer = RequestIdentity::Verified {
            subject_id: "bob".into(),
            issuer: "https://idp.example".into(),
            auth_provider: "oidc".into(),
            source: "oidc".into(),
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: Default::default(),
        };
        assert!(identity_from_peer(&bearer, &attested("verified")).is_none());
    }

    #[test]
    fn a_header_asserted_peer_names_only_an_anonymous_caller() {
        let named = identity_from_peer(&anonymous(), &attested("header_asserted")).unwrap();
        assert!(matches!(
            named,
            RequestIdentity::HttpHeader { ref subject_id, ref source }
                if subject_id == "alice@example.com" && source == "transport:dev.mcpg.transport.tailscale"
        ));
        let header = RequestIdentity::HttpHeader {
            subject_id: "carol".into(),
            source: "header".into(),
        };
        assert!(identity_from_peer(&header, &attested("header_asserted")).is_none());
    }

    #[test]
    fn an_unknown_trust_level_or_an_empty_subject_changes_nothing() {
        assert!(identity_from_peer(&anonymous(), &attested("root")).is_none());
        let mut empty = attested("verified");
        empty.peer.subject_id = " ".into();
        assert!(identity_from_peer(&anonymous(), &empty).is_none());
    }
}
