//! Extended GUI action specifications.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.action` package:
//! - `BasicAutoReadMemorySpecFactory`: Factory for basic auto-read spec.
//! - `BasicLocationTrackingSpecFactory`: Factory for basic location tracking.
//! - `DebuggerReadsMemoryTrait`: Trait for debugger memory read actions.
//! - `DebuggerTrackLocationTrait`: Trait for debugger location tracking actions.
//! - `WatchLocationTrackingSpecFactory`: Factory for watch-based tracking.

use serde::{Deserialize, Serialize};

/// Auto-read memory mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AutoReadMode {
    /// Do not auto-read.
    None,
    /// Read on activation.
    OnActivation,
    /// Read on each snap change.
    OnSnapChange,
    /// Read continuously.
    Continuous,
}

impl Default for AutoReadMode {
    fn default() -> Self {
        Self::None
    }
}

/// Factory for creating basic auto-read memory specifications.
///
/// Ported from Ghidra's `BasicAutoReadMemorySpecFactory`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAutoReadMemorySpecFactory {
    /// The default mode.
    pub default_mode: AutoReadMode,
    /// Display name.
    pub name: String,
    /// Description.
    pub description: String,
}

impl BasicAutoReadMemorySpecFactory {
    /// Create a new factory.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            default_mode: AutoReadMode::OnSnapChange,
            name: name.into(),
            description: String::new(),
        }
    }

    /// Create a spec with the given mode.
    pub fn create_spec(&self, mode: AutoReadMode) -> AutoReadMemorySpecResult {
        AutoReadMemorySpecResult {
            mode,
            factory_name: self.name.clone(),
        }
    }
}

/// Result of creating an auto-read memory spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoReadMemorySpecResult {
    /// The mode.
    pub mode: AutoReadMode,
    /// The factory that created it.
    pub factory_name: String,
}

/// Location tracking strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LocationTrackingStrategy {
    /// Track the program counter.
    Pc,
    /// Track the stack pointer.
    Sp,
    /// Track a specific register.
    Register,
    /// Track by watch expression.
    Watch,
    /// No tracking.
    None,
}

impl Default for LocationTrackingStrategy {
    fn default() -> Self {
        Self::Pc
    }
}

/// Factory for creating basic location tracking specifications.
///
/// Ported from Ghidra's `BasicLocationTrackingSpecFactory`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicLocationTrackingSpecFactory {
    /// The default strategy.
    pub default_strategy: LocationTrackingStrategy,
    /// Display name.
    pub name: String,
}

impl BasicLocationTrackingSpecFactory {
    /// Create a new factory.
    pub fn new(name: impl Into<String>, strategy: LocationTrackingStrategy) -> Self {
        Self {
            default_strategy: strategy,
            name: name.into(),
        }
    }

    /// Create a tracking spec.
    pub fn create_spec(&self) -> LocationTrackingSpecResult {
        LocationTrackingSpecResult {
            strategy: self.default_strategy,
            factory_name: self.name.clone(),
            register_name: None,
        }
    }
}

/// Result of creating a location tracking spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationTrackingSpecResult {
    /// The strategy.
    pub strategy: LocationTrackingStrategy,
    /// The factory name.
    pub factory_name: String,
    /// Optional register name for Register strategy.
    pub register_name: Option<String>,
}

impl LocationTrackingSpecResult {
    /// Set the register name for register-based tracking.
    pub fn with_register(mut self, name: impl Into<String>) -> Self {
        self.register_name = Some(name.into());
        self
    }
}

/// Trait for debugger actions that read memory.
///
/// Ported from Ghidra's `DebuggerReadsMemoryTrait`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerReadsMemoryTrait {
    /// Whether to auto-read on activation.
    pub auto_read_on_activation: bool,
    /// Whether to auto-read on snap change.
    pub auto_read_on_snap_change: bool,
    /// The number of bytes to read (0 = all).
    pub read_limit: usize,
}

impl Default for DebuggerReadsMemoryTrait {
    fn default() -> Self {
        Self {
            auto_read_on_activation: true,
            auto_read_on_snap_change: true,
            read_limit: 0,
        }
    }
}

/// Trait for debugger actions that track location.
///
/// Ported from Ghidra's `DebuggerTrackLocationTrait`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerTrackLocationTrait {
    /// Whether tracking is enabled.
    pub enabled: bool,
    /// The strategy to use.
    pub strategy: LocationTrackingStrategy,
    /// Whether to follow the tracked address into the listing.
    pub follow_in_listing: bool,
}

impl Default for DebuggerTrackLocationTrait {
    fn default() -> Self {
        Self {
            enabled: true,
            strategy: LocationTrackingStrategy::Pc,
            follow_in_listing: true,
        }
    }
}

/// Factory for watch-expression-based location tracking.
///
/// Ported from Ghidra's `WatchLocationTrackingSpecFactory`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchLocationTrackingSpecFactory {
    /// Display name.
    pub name: String,
    /// The watch expression.
    pub expression: String,
}

impl WatchLocationTrackingSpecFactory {
    /// Create a new watch tracking factory.
    pub fn new(name: impl Into<String>, expression: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            expression: expression.into(),
        }
    }

    /// Create a tracking spec for a specific watch expression.
    pub fn create_spec(&self, expression: impl Into<String>) -> LocationTrackingSpecResult {
        LocationTrackingSpecResult {
            strategy: LocationTrackingStrategy::Watch,
            factory_name: self.name.clone(),
            register_name: Some(expression.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_read_mode_default() {
        assert_eq!(AutoReadMode::default(), AutoReadMode::None);
    }

    #[test]
    fn test_basic_auto_read_memory_spec_factory() {
        let factory = BasicAutoReadMemorySpecFactory::new("Basic");
        let spec = factory.create_spec(AutoReadMode::OnSnapChange);
        assert_eq!(spec.mode, AutoReadMode::OnSnapChange);
        assert_eq!(spec.factory_name, "Basic");
    }

    #[test]
    fn test_location_tracking_strategy_default() {
        assert_eq!(LocationTrackingStrategy::default(), LocationTrackingStrategy::Pc);
    }

    #[test]
    fn test_basic_location_tracking_spec_factory() {
        let factory = BasicLocationTrackingSpecFactory::new("PC", LocationTrackingStrategy::Pc);
        let spec = factory.create_spec();
        assert_eq!(spec.strategy, LocationTrackingStrategy::Pc);
    }

    #[test]
    fn test_location_tracking_spec_with_register() {
        let factory = BasicLocationTrackingSpecFactory::new("Reg", LocationTrackingStrategy::Register);
        let spec = factory.create_spec().with_register("R0");
        assert_eq!(spec.register_name.as_deref(), Some("R0"));
    }

    #[test]
    fn test_debugger_reads_memory_trait_default() {
        let t = DebuggerReadsMemoryTrait::default();
        assert!(t.auto_read_on_activation);
        assert!(t.auto_read_on_snap_change);
        assert_eq!(t.read_limit, 0);
    }

    #[test]
    fn test_debugger_track_location_trait_default() {
        let t = DebuggerTrackLocationTrait::default();
        assert!(t.enabled);
        assert_eq!(t.strategy, LocationTrackingStrategy::Pc);
        assert!(t.follow_in_listing);
    }

    #[test]
    fn test_watch_location_tracking_spec_factory() {
        let factory = WatchLocationTrackingSpecFactory::new("Watch", "RSP");
        let spec = factory.create_spec("RBP");
        assert_eq!(spec.strategy, LocationTrackingStrategy::Watch);
        assert_eq!(spec.register_name.as_deref(), Some("RBP"));
    }

    #[test]
    fn test_auto_read_mode_serde() {
        let modes = [AutoReadMode::None, AutoReadMode::OnActivation, AutoReadMode::OnSnapChange, AutoReadMode::Continuous];
        for mode in &modes {
            let json = serde_json::to_string(mode).unwrap();
            let back: AutoReadMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, *mode);
        }
    }
}
