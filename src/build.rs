//! What this binary is: its git revision and version string.

use std::sync::LazyLock;

pub fn rev() -> &'static str {
    static REV: LazyLock<String> = LazyLock::new(crate::profiling::git_rev);
    &REV
}

/// `1.0.0+<rev>` (semver build metadata), as `/xrpc/_health` reports it.
pub fn version() -> &'static str {
    static V: LazyLock<String> = LazyLock::new(|| format!("{}+{}", env!("CARGO_PKG_VERSION"), rev()));
    &V
}
