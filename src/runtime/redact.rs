//! Shared credential redactor for outbound notification payloads.
//!
//! Applied to any JSON payload that leaves the gateway via
//! `notifications/message` so an operator that accidentally shoves a
//! bearer token or private-key blob into a log line does not replay it
//! into the SSE stream or the event store on reconnect.
//!
//! The canonical key list, the bare-credential heuristic, and the JSON
//! walk live in `mcpg-sensitive`; the URL-userinfo scrub for otherwise
//! ordinary string leaves comes from `mcpg-plugin-protocol`. The audit
//! plugin consumes the same two pieces, so the gateway and the audit sink
//! share one implementation and cannot drift.

use serde_json::Value;

pub use mcpg_sensitive::redact::CREDENTIAL_KEYS;

/// Recursively walk a JSON value, replacing any credential-shaped string
/// with `[redacted]` and scrubbing credential userinfo from URLs embedded
/// in ordinary string leaves.
pub fn redact_credentials(value: &Value) -> Value {
    mcpg_sensitive::redact::redact_credentials_with(
        value,
        mcpg_plugin_protocol::redact::redact_in_text,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_authorization_header_key() {
        let v = json!({"authorization": "Bearer abc.def.ghi", "other": "ok"});
        let r = redact_credentials(&v);
        assert_eq!(r["authorization"], "[redacted]");
        assert_eq!(r["other"], "ok");
    }

    #[test]
    fn redacts_bearer_value_even_under_neutral_key() {
        let v = json!({"note": "Bearer abcdef0123456789abcdef"});
        let r = redact_credentials(&v);
        assert_eq!(r["note"], "[redacted]");
    }

    #[test]
    fn redacts_jwt_like_string() {
        let v = json!("eyJhbGciOi.eyJzdWIiOi.signaturepart");
        let r = redact_credentials(&v);
        assert_eq!(r, "[redacted]");
    }

    #[test]
    fn leaves_ordinary_strings_alone() {
        let v = json!({"status": "ok", "count": 3});
        assert_eq!(redact_credentials(&v), v);
    }

    #[test]
    fn scrubs_url_userinfo_in_ordinary_leaves() {
        let v = json!({"reason": "connect nats://user:secret@host:4222 failed"});
        let r = redact_credentials(&v);
        assert_eq!(r["reason"], "connect nats://host:4222 failed");
    }

    #[test]
    fn recurses_into_arrays_and_nested_objects() {
        let v = json!({
            "events": [
                {"token": "Bearer xxx"},
                {"msg": "normal"},
            ]
        });
        let r = redact_credentials(&v);
        assert_eq!(r["events"][0]["token"], "[redacted]");
        assert_eq!(r["events"][1]["msg"], "normal");
    }
}
