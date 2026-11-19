//! Per-method dispatch arms the [`Handler`](super::Handler) calls, and the
//! MRTR `requestState` codec they share.

pub mod completion;
pub mod events;
pub mod lifecycle;
pub mod mrtr;
pub mod prompts;
pub mod request_state;
pub mod resources;
pub mod support;
pub mod tasks;
pub mod tools;
