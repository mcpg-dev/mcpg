//! In-process primitive impls used by the built-in single-node
//! cluster plugin.
//!
//! Two backings:
//! - [`memory`] — `DashMap` KV + `tokio::broadcast` pub/sub. Default
//!   when `cluster.dir` is unset. Lost on restart. Cheapest option.
//!   Includes a [`memory::WatchHub`] / [`memory::MemoryWatch`] pair
//!   that broadcasts in-process `WatchEvent`s on every `put` /
//!   `delete` through a `MemoryKv` constructed via
//!   [`memory::MemoryKv::with_watch_hub`].
//! - [`file`] — directory-backed primitives. Each KV key is its own
//!   atomic-rename JSON file; each pub/sub topic is an append-only
//!   NDJSON log file. The KV survives restart; the pub/sub is best-
//!   effort (poll-tail) and the on-disk log is human-readable —
//!   operators inspect / replay / analyze with normal Unix tools.
//!   The file backend doesn't ship a [`mcpg_cluster_api::Watch`] impl
//!   today (no cross-process change-notification primitive); the
//!   single-node coordinator falls back to the in-memory `WatchHub`
//!   for operators running file-backed durability.
//!
//! `lease` is still served via the coordinator-level surface
//! (`acquire_lock` / `acquire_leadership`) — the always-acquire
//! single-node lease has no need for split-brain fencing.

pub mod file;
pub mod memory;

pub use file::{FileBus, FileKv};
pub use memory::{MemoryBus, MemoryKv, MemoryWatch, WatchHub};
