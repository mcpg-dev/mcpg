//! Admin API — operator-facing management endpoints.
//!
//! Provides health, readiness, session inspection, binding listing,
//! config validation, and policy preview. Protected by `auth` middleware.

mod auth;
mod handlers;
pub mod service;

pub use service::AdminService;

use axum::{Router, routing::get, routing::post};

/// Build the admin API router with all endpoints.
pub fn admin_router(service: AdminService) -> Router {
    let base = &service.config().base_path.clone();
    let state = std::sync::Arc::new(service);

    // axum 0.8 capture syntax is `{id}`, not `:id`. axum 0.8 also
    // disallows capture + literal in the same segment, so the
    // legacy `:id:action` form is replaced with `{id}/action`.
    // Static-segment colon-actions (`/config:reload`,
    // `/policy:preview`) keep the `:` because the segment text
    // doesn't open with `:` and there's no capture to compose with.
    let api = Router::new()
        .route("/health", get(handlers::health))
        .route("/readiness", get(handlers::readiness))
        .route("/runtime", get(handlers::runtime_info))
        .route("/sessions", get(handlers::list_sessions))
        .route("/sessions/{id}", get(handlers::get_session))
        .route(
            "/sessions/{id}/terminate",
            post(handlers::terminate_session),
        )
        .route("/bindings", get(handlers::list_bindings))
        .route("/bindings/{id}", get(handlers::get_binding))
        .route("/plugins", get(handlers::list_plugins))
        .route("/plugins/{id}", get(handlers::get_plugin))
        .route("/plugins/{id}/disable", post(handlers::disable_plugin))
        .route("/plugins/{id}/enable", post(handlers::enable_plugin))
        .route("/plugins/{id}/drain", post(handlers::drain_plugin))
        .route("/config:validate", post(handlers::validate_config))
        .route("/config:reload", post(handlers::reload_config_handler))
        .route("/policy:preview", post(handlers::policy_preview))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::admin_auth_middleware,
        ))
        .with_state(state);

    Router::new().nest(base, api)
}
