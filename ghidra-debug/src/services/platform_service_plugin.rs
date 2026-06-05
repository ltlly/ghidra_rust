//! Platform service plugin implementation.
//!
//! Ported from Ghidra's `DebuggerPlatformServicePlugin` in
//! `ghidra.app.plugin.core.debug.service.platform`.

use serde::{Deserialize, Serialize};

/// The platform service plugin manages platform detection and
/// assignment for traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformServicePlugin {
    /// The current language ID.
    pub language_id: String,
    /// The current compiler spec ID.
    pub compiler_spec_id: String,
    /// Whether a platform has been assigned.
    pub assigned: bool,
}

impl PlatformServicePlugin {
    /// Create a new platform service plugin.
    pub fn new() -> Self {
        Self {
            language_id: String::new(),
            compiler_spec_id: String::new(),
            assigned: false,
        }
    }

    /// Set the platform.
    pub fn set_platform(&mut self, language_id: impl Into<String>, compiler_spec_id: impl Into<String>) {
        self.language_id = language_id.into();
        self.compiler_spec_id = compiler_spec_id.into();
        self.assigned = true;
    }

    /// Check if a platform is assigned.
    pub fn is_assigned(&self) -> bool {
        self.assigned
    }
}

impl Default for PlatformServicePlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_plugin_new() {
        let p = PlatformServicePlugin::new();
        assert!(!p.is_assigned());
    }

    #[test]
    fn test_platform_plugin_set() {
        let mut p = PlatformServicePlugin::new();
        p.set_platform("x86:LE:64:default", "default");
        assert!(p.is_assigned());
        assert_eq!(p.language_id, "x86:LE:64:default");
    }
}
