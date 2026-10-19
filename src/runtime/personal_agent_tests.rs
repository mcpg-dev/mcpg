use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

use super::*;
use crate::config::personal_agent::PersonalAgentConfig;

fn profile(config: serde_json::Value) -> PersonalAgentProfile {
    let config: PersonalAgentConfig = serde_json::from_value(config).expect("config parses");
    config.validate().expect("config validates");
    PersonalAgentProfile::from_config(&config).expect("profile builds")
}

fn verified(attributes: &[(&str, &str)]) -> RequestIdentity {
    RequestIdentity::Verified {
        subject_id: "user-7".into(),
        issuer: "https://auth.example.com".into(),
        auth_provider: "oidc:https://auth.example.com".into(),
        source: "authorization:oidc_oauth".into(),
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: attributes
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
    }
}

#[tokio::test]
async fn the_caller_reads_its_values_and_its_signed_in_state() {
    let profile = profile(json!({ "agent_extensions": { "source": "none" } }));

    let signed_out = profile
        .caller(&verified(&[
            ("client_id", "https://agent.example/agent.json"),
            ("session_id", "ses_1"),
            ("user_id", "u_1"),
        ]))
        .await
        .expect("a verified caller");
    assert!(signed_out.is_personal_agent());
    assert!(!signed_out.signed_in);
    assert_eq!(signed_out.session_id.as_deref(), Some("ses_1"));
    assert_eq!(signed_out.user_id.as_deref(), Some("u_1"));

    let by_account = profile
        .caller(&verified(&[("account", "acc_1")]))
        .await
        .expect("a verified caller");
    assert!(by_account.signed_in);
    assert!(!by_account.is_personal_agent(), "a plain MCP client");

    for (flag, signed_in) in [("true", true), ("TRUE", true), ("false", false)] {
        let caller = profile
            .caller(&verified(&[("account", "acc_1"), ("signed_in", flag)]))
            .await
            .expect("a verified caller");
        assert_eq!(caller.signed_in, signed_in, "{flag}");
    }

    let renamed = self::profile(json!({
        "attributes": { "client_id": "azp", "signed_in": "poppy_signed_in" },
        "agent_extensions": { "source": "none" },
    }));
    let caller = renamed
        .caller(&verified(&[
            ("azp", "https://a.example/x.json"),
            ("poppy_signed_in", "true"),
        ]))
        .await
        .expect("a verified caller");
    assert_eq!(
        caller.client_id.as_deref(),
        Some("https://a.example/x.json")
    );
    assert!(caller.signed_in);

    assert!(
        profile
            .caller(&RequestIdentity::Anonymous {
                source: "anonymous".into()
            })
            .await
            .is_none()
    );
}

#[tokio::test]
async fn extensions_come_from_an_attribute_as_json_or_names() {
    let profile = profile(json!({
        "agent_extensions": { "source": "attribute", "attribute": "agent_extensions" },
        "require_extensions": ["operations"],
    }));
    let agent = |extensions: &str| {
        verified(&[
            ("client_id", "https://agent.example/agent.json"),
            ("agent_extensions", extensions),
        ])
    };

    let json = profile
        .caller(&agent(
            r#"{"operations":{"version":"1"},"example.com/x":{"version":2}}"#,
        ))
        .await
        .expect("caller");
    assert!(json.lists("operations", "1"));
    assert!(!json.lists("operations", "2"));
    assert!(json.lists("example.com/x", "2"));
    assert_eq!(profile.missing_extension(&json), None);

    let names = profile
        .caller(&agent("operations other"))
        .await
        .expect("caller");
    assert!(names.lists("operations", "1"), "no version given lists any");
    assert_eq!(profile.missing_extension(&names), None);

    let none = profile.caller(&agent("")).await.expect("caller");
    assert_eq!(profile.missing_extension(&none), Some("operations"));

    // A plain MCP client is never refused for an extension.
    let plain = profile
        .caller(&verified(&[("account", "acc_1")]))
        .await
        .expect("caller");
    assert_eq!(profile.missing_extension(&plain), None);
}

#[tokio::test]
async fn operations_that_refuse_agents_require_version_1_of_the_extension() {
    let profile = profile(json!({
        "agent_extensions": { "source": "attribute", "attribute": "agent_extensions" },
        "operations": {
            "endpoint": "https://mcp.example.com/poppy/operations",
            "tools": [{ "tool": "refund", "summary": "Refund." }],
            "without_extension": "refuse_agent",
        },
    }));
    let agent = |extensions: &str| {
        verified(&[
            ("client_id", "https://agent.example/agent.json"),
            ("agent_extensions", extensions),
        ])
    };

    let listed = profile
        .caller(&agent(r#"{"operations":{"version":"1"}}"#))
        .await
        .expect("caller");
    assert_eq!(profile.missing_extension(&listed), None);

    let other_version = profile
        .caller(&agent(r#"{"operations":{"version":"2"}}"#))
        .await
        .expect("caller");
    assert_eq!(
        profile.missing_extension(&other_version),
        Some("operations")
    );

    let none = profile.caller(&agent("")).await.expect("caller");
    assert_eq!(profile.missing_extension(&none), Some("operations"));

    let plain = profile
        .caller(&verified(&[("account", "acc_1")]))
        .await
        .expect("caller");
    assert_eq!(profile.missing_extension(&plain), None);
}

/// A client metadata document server on loopback, at `/agent.json`: the
/// document `document` makes of the server's own URL, with
/// `cache_control`; and the count of requests it answered.
async fn serve_document(
    document: impl FnOnce(&str) -> serde_json::Value,
    cache_control: &'static str,
) -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let url = format!(
        "http://{}/agent.json",
        listener.local_addr().expect("address")
    );
    let document = document(&url);
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    let app = axum::Router::new().route(
        "/agent.json",
        axum::routing::get(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            let document = document.clone();
            async move {
                (
                    [(header::CACHE_CONTROL, cache_control)],
                    axum::Json(document),
                )
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, hits)
}

fn fetching() -> PersonalAgentProfile {
    profile(json!({
        "agent_extensions": { "source": "client_metadata", "allow_private_network": true },
    }))
}

#[tokio::test]
async fn extensions_come_from_the_client_metadata_document_and_are_cached() {
    let (url, hits) = serve_document(
        |url| {
            json!({
                "client_id": url,
                "extensions": { "operations": { "version": "1" } },
            })
        },
        "max-age=600",
    )
    .await;
    let profile = fetching();
    let agent = verified(&[("client_id", url.as_str())]);

    let caller = profile.caller(&agent).await.expect("caller");
    assert!(caller.lists("operations", "1"), "{caller:?}");
    let again = profile.caller(&agent).await.expect("caller");
    assert!(again.lists("operations", "1"));
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the second read is cached");
}

#[tokio::test]
async fn a_document_that_names_another_client_or_cannot_be_read_lists_nothing() {
    let (url, _) = serve_document(
        |_| {
            json!({
                "client_id": "https://someone-else.example/agent.json",
                "extensions": { "operations": { "version": "1" } },
            })
        },
        "max-age=600",
    )
    .await;
    let profile = fetching();
    let caller = profile
        .caller(&verified(&[("client_id", url.as_str())]))
        .await
        .expect("caller");
    assert!(caller.extensions.is_empty(), "{caller:?}");

    let unreachable = profile
        .caller(&verified(&[("client_id", "http://127.0.0.1:9/agent.json")]))
        .await
        .expect("caller");
    assert!(unreachable.extensions.is_empty());

    let not_a_url = profile
        .caller(&verified(&[("client_id", "claude-ema")]))
        .await
        .expect("caller");
    assert!(not_a_url.is_personal_agent());
    assert!(not_a_url.extensions.is_empty());
}

#[test]
fn cache_control_bounds_how_long_a_document_is_used() {
    let lifetime = |value: &'static str| {
        let mut headers = HeaderMap::new();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(value));
        cache_lifetime(&headers)
    };
    assert_eq!(
        lifetime("public, max-age=120"),
        Some(Duration::from_secs(120))
    );
    assert_eq!(lifetime("no-store"), Some(Duration::ZERO));
    assert_eq!(lifetime("private"), None);
    assert_eq!(cache_lifetime(&HeaderMap::new()), None);
}
