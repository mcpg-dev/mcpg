//! MCP Events (the experimental `io.modelcontextprotocol/events` extension):
//! the gateway-side machinery behind `events/*`.
//!
//! - [`catalog`] compiles the declared event types.
//! - [`sources`] runs `watch` and `resource` sources on the events owner;
//!   [`inbound`] verifies the signed webhooks of `inbound` sources;
//!   [`federated`] reads the event types a federation imported from their
//!   upstream, and [`upstream_webhook`] takes what an upstream delivers by
//!   webhook.
//! - [`occurrence`] shapes what a source reports into a stored occurrence.
//! - [`log`] keeps one ordered, retained log per source, written by the
//!   events owner alone, with an inbox for the other replicas.
//! - [`cursor`] seals positions in a log for clients.
//! - [`subscriptions`] keeps the webhook subscription records;
//!   [`keys`] derives their ids, sealed secrets and every other key;
//!   [`index`] is the owner's view of the subscriptions of each type.
//! - [`engine`] ties these together across config reloads and runs the
//!   owner loop; [`handler`] serves the `events/*` methods from it.
//! - [`webhook`] serves `events/subscribe` and `events/unsubscribe`;
//!   [`verifier`] proves a callback wants the deliveries; [`dispatcher`]
//!   delivers on the owner; [`delivery`] signs and sends each request.
//! - [`poll`] serves `events/poll` from the logs, on any replica; [`push`]
//!   serves `events/stream` from them.
//! - [`admin`] is the operator surface: list, suspend, terminate, pause,
//!   purge.

pub mod admin;
mod audit;
pub mod builtin;
pub mod catalog;
pub mod cursor;
pub mod delivery;
pub mod dispatcher;
pub mod engine;
mod federated;
pub mod handler;
pub mod inbound;
pub mod index;
pub mod keys;
pub mod log;
pub mod occurrence;
#[cfg(test)]
mod plan_tests;
pub mod poll;
pub mod push;
pub mod sources;
pub mod subscriptions;
#[cfg(test)]
pub(crate) mod test_support;
pub mod upstream_webhook;
pub mod verifier;
pub mod webhook;

use std::sync::{Arc, OnceLock};

pub use self::engine::{EventsCore, EventsStores, InboundReply, PreparedEvents};

/// Where the events core is installed, beside the dispatch seam's handler
/// slot. Set once; the core lives across config reloads.
#[derive(Default)]
pub struct EventsCoreSlot(OnceLock<Arc<EventsCore>>);

impl EventsCoreSlot {
    /// Install `core`. Fails, handing it back, when one is installed.
    pub fn install(&self, core: Arc<EventsCore>) -> Result<(), Arc<EventsCore>> {
        self.0.set(core)
    }

    pub fn get(&self) -> Option<&Arc<EventsCore>> {
        self.0.get()
    }
}

impl std::fmt::Debug for EventsCoreSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventsCoreSlot")
            .field("installed", &self.0.get().is_some())
            .finish()
    }
}

/// Install a fresh events core into `services` (the typed slot and the
/// dispatch seam) unless one is installed, and return the installed core.
pub fn install_core(services: &crate::runtime::shared_services::SharedServices) -> Arc<EventsCore> {
    if let Some(core) = services.events_core.get() {
        return Arc::clone(core);
    }
    let core = Arc::new(EventsCore::new());
    match services.events_core.install(Arc::clone(&core)) {
        Ok(()) => {
            let _ = services.events.install(Arc::clone(&core) as _);
            core
        }
        Err(_) => Arc::clone(
            services
                .events_core
                .get()
                .expect("a failed install means a core is installed"),
        ),
    }
}
