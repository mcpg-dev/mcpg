//! In-process primitive impls used by the built-in single-node
//! cluster plugin.
//!
//! Two backings:
//! - [`memory`] — `DashMap` KV + `tokio::broadcast` pub/sub. Default
//!   when `cluster.dir` is unset. Lost on restart. Cheapest option.
//! - [`file`] — directory-backed primitives. Each KV key is its own
//!   atomic-rename JSON file; each pub/sub topic is an append-only
//!   NDJSON log file. The KV survives restart; the pub/sub is best-
//!   effort (poll-tail) and the on-disk log is human-readable —
//!   operators inspect / replay / analyze with normal Unix tools.
//!
//! Leases are served via the coordinator-level surface
//! (`acquire_lock` / `acquire_leadership`) — the always-acquire
//! single-node lease has no need for split-brain fencing.

pub mod file;
pub mod memory;

pub use file::{FileBus, FileKv};
pub use memory::{MemoryBus, MemoryKv};
