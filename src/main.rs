//! MCPG gateway entry point. The command itself lives in [`mcpg::entry`].

// Fast allocator on glibc-linux (see apps/gateway/Cargo.toml). Only wired for
// the glibc-linux target; every other target keeps the system allocator.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> anyhow::Result<()> {
    mcpg::entry::main()
}
