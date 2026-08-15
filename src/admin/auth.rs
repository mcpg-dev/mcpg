//! Authentication middleware for the admin API.
//!
//! Supports static bearer tokens and trusted-header schemes,
//! applied as an Axum `from_fn` layer on admin routes.

/// Floor on the admin bearer token, matching the approvals signing key and
/// the EMA signing secret. Below this it is not a credential.
const MIN_ADMIN_BEARER_LEN: usize = 32;

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

use super::service::AdminService;
use crate::config::AdminAuthConfig;

/// Tower middleware for admin API authentication.
pub async fn admin_auth_middleware(
    State(svc): State<Arc<AdminService>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    match svc.config().auth {
        AdminAuthConfig::Disabled => Ok(next.run(request).await),
        AdminAuthConfig::StaticBearer {
            ref bearer_token_env,
        } => {
            let expected = std::env::var(bearer_token_env).map_err(|_| {
                tracing::error!(
                    env_var = %bearer_token_env,
                    "admin auth: bearer token env var not set"
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            // `env::var` errors only when the variable is UNSET; set-but-empty
            // returns Ok(""). With an empty expected token a request carrying
            // no Authorization header also yields "", and the constant-time
            // compare then succeeds — admin access with no credential at all.
            // A short token is refused for the same reason the approvals key
            // and the EMA signing secret have a floor: it is not a secret.
            if expected.len() < MIN_ADMIN_BEARER_LEN {
                tracing::error!(
                    env_var = %bearer_token_env,
                    minimum = MIN_ADMIN_BEARER_LEN,
                    "admin auth: bearer token is empty or too short; refusing all admin requests"
                );
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }

            let auth_header = request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            let provided = auth_header.strip_prefix("Bearer ").unwrap_or("");

            // Security: constant-time comparison prevents timing attacks
            if constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                Ok(next.run(request).await)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        AdminAuthConfig::TrustedHeader {
            ref header_name,
            ref trusted_value_env,
        } => {
            let header_value = request
                .headers()
                .get(header_name.as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if header_value.is_empty() {
                return Err(StatusCode::UNAUTHORIZED);
            }

            // Security: when trusted_value_env is set, compare the
            // header against the env-var secret with constant-time eq.
            // When unset, fall through to presence-only (backward compat)
            // but warn loudly on every request.
            if let Some(env_var) = trusted_value_env {
                let expected = std::env::var(env_var).map_err(|_| {
                    tracing::error!(
                        env_var = %env_var,
                        "admin auth: trusted_value_env not set"
                    );
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
                if constant_time_eq(header_value.as_bytes(), expected.as_bytes()) {
                    Ok(next.run(request).await)
                } else {
                    Err(StatusCode::UNAUTHORIZED)
                }
            } else {
                // Legacy presence-only mode — warn on every hit.
                tracing::warn!(
                    header = %header_name,
                    "admin TrustedHeader auth: no trusted_value_env configured; \
                     header-presence-only mode is INSECURE on non-loopback networks"
                );
                metrics::counter!("mcpg_admin_trusted_header_insecure_total").increment(1);
                Ok(next.run(request).await)
            }
        }
    }
}

/// Security: constant-time byte comparison prevents timing attacks on auth tokens.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_same() {
        assert!(constant_time_eq(b"secret", b"secret"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"secret", b"wrong!"));
    }

    #[test]
    fn constant_time_eq_different_length() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }
}
