//! Platform override types ported from Java.
//!
//! Ported from `OverrideDebuggerPlatformOpinion` in the Debugger module.
//! Provides the ability to override the automatically-detected platform
//! for a debug target.

use std::collections::HashMap;

/// A platform override specification.
#[derive(Debug, Clone)]
pub struct PlatformOverride {
    /// The target type this override applies to (e.g., "gdb", "lldb").
    pub target_type: String,
    /// The override language ID.
    pub language_id: String,
    /// The override compiler spec ID.
    pub compiler_spec_id: String,
    /// Whether this override is enabled.
    pub enabled: bool,
    /// Additional configuration.
    pub config: HashMap<String, String>,
}

impl PlatformOverride {
    /// Create a new platform override.
    pub fn new(
        target_type: impl Into<String>,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            target_type: target_type.into(),
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            enabled: true,
            config: HashMap::new(),
        }
    }

    /// Set a configuration value.
    pub fn set_config(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.config.insert(key.into(), value.into());
    }

    /// Get a configuration value.
    pub fn get_config(&self, key: &str) -> Option<&str> {
        self.config.get(key).map(|s| s.as_str())
    }

    /// Check if this override matches a target type.
    pub fn matches(&self, target_type: &str) -> bool {
        self.enabled && self.target_type == target_type
    }
}

/// Manages platform overrides for debug targets.
#[derive(Debug, Default)]
pub struct PlatformOverrideManager {
    /// Registered overrides.
    overrides: Vec<PlatformOverride>,
}

impl PlatformOverrideManager {
    /// Create a new manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a platform override.
    pub fn register(&mut self, override_spec: PlatformOverride) {
        self.overrides.push(override_spec);
    }

    /// Find the first matching override for a target type.
    pub fn find_override(&self, target_type: &str) -> Option<&PlatformOverride> {
        self.overrides.iter().find(|o| o.matches(target_type))
    }

    /// Get all registered overrides.
    pub fn overrides(&self) -> &[PlatformOverride] {
        &self.overrides
    }

    /// Remove all overrides for a given target type.
    pub fn remove_for_target(&mut self, target_type: &str) {
        self.overrides.retain(|o| o.target_type != target_type);
    }

    /// Enable or disable an override.
    pub fn set_enabled(&mut self, target_type: &str, enabled: bool) {
        for o in &mut self.overrides {
            if o.target_type == target_type {
                o.enabled = enabled;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_override() {
        let mut ovr = PlatformOverride::new("gdb", "x86:LE:64:default", "default");
        assert!(ovr.matches("gdb"));
        assert!(!ovr.matches("lldb"));

        ovr.enabled = false;
        assert!(!ovr.matches("gdb"));
    }

    #[test]
    fn test_override_manager() {
        let mut manager = PlatformOverrideManager::new();
        manager.register(PlatformOverride::new("gdb", "x86:LE:64:default", "default"));
        manager.register(PlatformOverride::new("lldb", "x86:LE:64:default", "default"));

        assert!(manager.find_override("gdb").is_some());
        assert!(manager.find_override("lldb").is_some());
        assert!(manager.find_override("frida").is_none());

        manager.remove_for_target("gdb");
        assert!(manager.find_override("gdb").is_none());
    }

    #[test]
    fn test_config() {
        let mut ovr = PlatformOverride::new("gdb", "x86:LE:64:default", "default");
        ovr.set_config("remote_arch", "x86-64");
        assert_eq!(ovr.get_config("remote_arch"), Some("x86-64"));
        assert!(ovr.get_config("unknown").is_none());
    }
}
