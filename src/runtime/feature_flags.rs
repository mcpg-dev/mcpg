//! Process-wide atomic mirror of the operator's `feature_flags:` block.
//!
//! `app::build_from_config` calls [`install`] at boot and again on
//! every SIGHUP-triggered reload. Hot-path code (e.g.
//! `runtime::execution::format_request_headers`) reads the flags
//! via the cheap [`allow_header_passthrough`] / [`sep2260_panic`]
//! accessors instead of threading `&FeatureFlagsConfig` through every
//! call frame.
//!
//! This module replaced the `MCPG_*` env-var reads that previously
//! did the same job — operators now flip flags via the typed config,
//! and the values reach the runtime through this boot-installed
//! atomic mirror.
use std::sync::atomic::{AtomicBool, Ordering};

use crate::config::FeatureFlagsConfig;

static ALLOW_HEADER_PASSTHROUGH: AtomicBool = AtomicBool::new(false);
static SEP2260_PANIC: AtomicBool = AtomicBool::new(false);

/// Install the active feature-flag values into the process-wide
/// atomic mirror. Called from `app::build_from_config` at boot
/// and from `app::reload_config` on every SIGHUP.
pub(crate) fn install(flags: &FeatureFlagsConfig) {
    ALLOW_HEADER_PASSTHROUGH.store(flags.allow_header_passthrough, Ordering::Relaxed);
    SEP2260_PANIC.store(flags.sep2260_panic_on_orphan, Ordering::Relaxed);
}

/// True when the operator has opted in to forwarding credential-shaped
/// inbound headers (Authorization, Cookie, X-API-Key, …) to outbound
/// bindings. Default: false.
pub(crate) fn allow_header_passthrough() -> bool {
    ALLOW_HEADER_PASSTHROUGH.load(Ordering::Relaxed)
}

/// True when the operator wants SEP-2260 violations to panic instead
/// of warn + metric. Default: false.
pub(crate) fn sep2260_panic() -> bool {
    SEP2260_PANIC.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_round_trips_both_flags() {
        // Atomic state is process-wide; restore defaults at the end
        // so the rest of the suite isn't surprised.
        let original_pass = allow_header_passthrough();
        let original_panic = sep2260_panic();

        install(&FeatureFlagsConfig {
            allow_header_passthrough: true,
            sep2260_panic_on_orphan: true,
            debug_tools_enabled: false,
        });
        assert!(allow_header_passthrough());
        assert!(sep2260_panic());

        install(&FeatureFlagsConfig::default());
        assert!(!allow_header_passthrough());
        assert!(!sep2260_panic());

        install(&FeatureFlagsConfig {
            allow_header_passthrough: original_pass,
            sep2260_panic_on_orphan: original_panic,
            debug_tools_enabled: false,
        });
    }
}
