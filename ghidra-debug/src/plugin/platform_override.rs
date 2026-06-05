//! Override platform opinion.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.platform.OverrideDebuggerPlatformOpinion`.
//! Provides a mechanism for overriding the default platform selection
//! for a debugger connection.

use serde::{Deserialize, Serialize};

use super::platform_opinion::PlatformOpinion;

/// An override platform opinion that takes priority over default opinions.
///
/// This allows users to force a specific platform for a debugger connection,
/// regardless of the detected architecture or environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideDebuggerPlatformOpinion {
    /// The language ID to override with.
    pub language_id: String,
    /// The compiler spec ID to use.
    pub compiler_spec_id: String,
    /// A description of why this override is active.
    pub reason: String,
}

impl OverrideDebuggerPlatformOpinion {
    /// Create a new override opinion.
    pub fn new(
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            reason: reason.into(),
        }
    }

    /// Convert this opinion into a platform opinion.
    pub fn to_opinion(&self) -> PlatformOpinion {
        PlatformOpinion::new(
            "override",
            &self.language_id,
            &self.compiler_spec_id,
            "unknown",
            1.0,
        )
    }
}

/// A registry of platform overrides.
#[derive(Debug, Default)]
pub struct PlatformOverrideRegistry {
    overrides: Vec<OverrideDebuggerPlatformOpinion>,
}

impl PlatformOverrideRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an override opinion.
    pub fn register(&mut self, opinion: OverrideDebuggerPlatformOpinion) {
        self.overrides.push(opinion);
    }

    /// Check if there are any active overrides.
    pub fn has_overrides(&self) -> bool {
        !self.overrides.is_empty()
    }

    /// Get all registered overrides.
    pub fn overrides(&self) -> &[OverrideDebuggerPlatformOpinion] {
        &self.overrides
    }

    /// Get the first matching override (highest priority).
    pub fn first_override(&self) -> Option<&OverrideDebuggerPlatformOpinion> {
        self.overrides.first()
    }

    /// Clear all overrides.
    pub fn clear(&mut self) {
        self.overrides.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_override_opinion() {
        let opinion = OverrideDebuggerPlatformOpinion::new(
            "x86:LE:64:default",
            "default",
            "User preference",
        );
        assert_eq!(opinion.language_id, "x86:LE:64:default");
        assert_eq!(opinion.compiler_spec_id, "default");
    }

    #[test]
    fn test_override_to_opinion() {
        let opinion = OverrideDebuggerPlatformOpinion::new(
            "ARM:LE:32:v8",
            "default",
            "Force ARM mode",
        );
        let plat_opinion = opinion.to_opinion();
        assert_eq!(plat_opinion.language_id, "ARM:LE:32:v8");
        assert_eq!(plat_opinion.confidence, 1.0);
    }

    #[test]
    fn test_override_registry() {
        let mut registry = PlatformOverrideRegistry::new();
        assert!(!registry.has_overrides());
        assert!(registry.first_override().is_none());

        registry.register(OverrideDebuggerPlatformOpinion::new(
            "x86:LE:64:default",
            "default",
            "test",
        ));
        assert!(registry.has_overrides());
        assert!(registry.first_override().is_some());

        registry.clear();
        assert!(!registry.has_overrides());
    }
}
