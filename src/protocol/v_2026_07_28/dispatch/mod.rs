//! Modern dispatch helpers — codecs, stores, and per-method
//! dispatch arms that the `v_2026_07_28::Handler` reaches into.
//!
//! Today this module hosts the [`request_state`] codec used by
//! MRTR. Further modules are added here as per-method dispatch arms
//! grow large enough to warrant their own file.

pub mod completion;
pub mod lifecycle;
pub mod mrtr;
pub mod prompts;
pub mod request_state;
pub mod resources;
pub mod support;
pub mod tasks;
pub mod tools;
