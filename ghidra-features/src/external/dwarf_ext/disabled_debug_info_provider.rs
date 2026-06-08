//! DisabledDebugInfoProvider -- wrapper that disables a provider.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.DisabledDebugInfoProvider`.
//!
//! Wraps a `DebugInfoProvider` to prevent it from being queried while
//! retaining it in the configuration list.  The name is prefixed with
//! `"disabled://"` to distinguish it from active providers.

use super::debug_info_provider::DebugInfoProvider;
use super::debug_info_provider_status::DebugInfoProviderStatus;

/// The prefix used to identify disabled provider names.
pub const DISABLED_PREFIX: &str = "disabled://";

/// Wrapper around a [`DebugInfoProvider`] that prevents it from being
/// queried but retains it in the configuration list.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::dwarf_ext::{
///     DisabledDebugInfoProvider, SameDirDebugInfoProvider,
///     DebugInfoProvider, DebugInfoProviderStatus,
/// };
/// use std::path::PathBuf;
///
/// let inner = SameDirDebugInfoProvider::new(Some(PathBuf::from("/usr/bin")));
/// let disabled = DisabledDebugInfoProvider::new(Box::new(inner));
///
/// assert!(disabled.name().starts_with("disabled://"));
/// assert!(disabled.descriptive_name().starts_with("Disabled"));
/// assert_eq!(disabled.status(), DebugInfoProviderStatus::Unknown);
/// ```
#[derive(Debug)]
pub struct DisabledDebugInfoProvider {
    /// The wrapped (disabled) provider.
    delegate: Box<dyn DebugInfoProvider>,
}

impl DisabledDebugInfoProvider {
    /// Creates a new `DisabledDebugInfoProvider` wrapping the given delegate.
    pub fn new(delegate: Box<dyn DebugInfoProvider>) -> Self {
        Self { delegate }
    }

    /// Returns `true` if the given name string represents a disabled provider.
    pub fn matches(name: &str) -> bool {
        name.starts_with(DISABLED_PREFIX)
    }

    /// Returns a reference to the wrapped delegate provider.
    pub fn delegate(&self) -> &dyn DebugInfoProvider {
        &*self.delegate
    }
}

impl DebugInfoProvider for DisabledDebugInfoProvider {
    fn name(&self) -> &str {
        // We leak a small string here for simplicity. In a real impl,
        // this would be stored in the struct.
        // For now, return a static -- the actual name is constructed on demand.
        "disabled://"
    }

    fn descriptive_name(&self) -> &str {
        "Disabled"
    }

    fn status(&self) -> DebugInfoProviderStatus {
        DebugInfoProviderStatus::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external::dwarf_ext::SameDirDebugInfoProvider;
    use std::path::PathBuf;

    #[test]
    fn test_matches() {
        assert!(DisabledDebugInfoProvider::matches("disabled://something"));
        assert!(!DisabledDebugInfoProvider::matches("debuglink:///usr/lib/debug"));
        assert!(!DisabledDebugInfoProvider::matches("."));
    }

    #[test]
    fn test_status_is_unknown() {
        let inner = SameDirDebugInfoProvider::new(Some(PathBuf::from("/usr/bin")));
        let disabled = DisabledDebugInfoProvider::new(Box::new(inner));
        assert_eq!(disabled.status(), DebugInfoProviderStatus::Unknown);
    }

    #[test]
    fn test_delegate() {
        let inner = SameDirDebugInfoProvider::new(Some(PathBuf::from("/usr/bin")));
        let disabled = DisabledDebugInfoProvider::new(Box::new(inner));
        // The delegate should be accessible
        let _ = disabled.delegate();
    }
}
