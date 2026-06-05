//! Default emulator factory implementation.
//!
//! Ported from Ghidra's `DefaultEmulatorFactory` in
//! `ghidra.app.plugin.core.debug.service.emulation`. Provides the
//! default factory for creating pcode emulators integrated with
//! the trace database.

use serde::{Deserialize, Serialize};

/// Emulation mode for the factory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmulationMode {
    /// Execute with full instruction semantics.
    Full,
    /// Execute with simplified semantics (faster, less accurate).
    Simplified,
    /// Execute with symbolic semantics (for analysis).
    Symbolic,
}

impl Default for EmulationMode {
    fn default() -> Self {
        Self::Full
    }
}

/// Configuration for an emulator instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulatorConfig {
    /// The language ID (processor).
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// The emulation mode.
    pub mode: EmulationMode,
    /// Whether to track memory state.
    pub track_memory_state: bool,
    /// Whether to track register state.
    pub track_register_state: bool,
    /// Maximum number of steps before stopping.
    pub max_steps: u64,
}

impl EmulatorConfig {
    /// Create a new emulator config.
    pub fn new(language_id: impl Into<String>, compiler_spec_id: impl Into<String>) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            mode: EmulationMode::default(),
            track_memory_state: true,
            track_register_state: true,
            max_steps: 1_000_000,
        }
    }

    /// Set the emulation mode.
    pub fn with_mode(mut self, mode: EmulationMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set whether to track memory state.
    pub fn with_memory_tracking(mut self, track: bool) -> Self {
        self.track_memory_state = track;
        self
    }

    /// Set maximum steps.
    pub fn with_max_steps(mut self, max: u64) -> Self {
        self.max_steps = max;
        self
    }
}

/// The default emulator factory.
///
/// Creates pcode emulators configured for trace integration.
#[derive(Debug)]
pub struct DefaultEmulatorFactory {
    /// Default configuration.
    default_config: EmulatorConfig,
    /// Number of emulators created.
    created_count: u64,
}

impl DefaultEmulatorFactory {
    /// Create a new emulator factory with default settings.
    pub fn new(language_id: impl Into<String>, compiler_spec_id: impl Into<String>) -> Self {
        Self {
            default_config: EmulatorConfig::new(language_id, compiler_spec_id),
            created_count: 0,
        }
    }

    /// Create an emulator configuration.
    pub fn create_config(&mut self) -> EmulatorConfig {
        self.created_count += 1;
        self.default_config.clone()
    }

    /// Create an emulator configuration with overrides.
    pub fn create_config_with_mode(&mut self, mode: EmulationMode) -> EmulatorConfig {
        self.created_count += 1;
        self.default_config.clone().with_mode(mode)
    }

    /// Get the number of emulators created.
    pub fn created_count(&self) -> u64 {
        self.created_count
    }

    /// Get the default language ID.
    pub fn language_id(&self) -> &str {
        &self.default_config.language_id
    }

    /// Get the default compiler spec ID.
    pub fn compiler_spec_id(&self) -> &str {
        &self.default_config.compiler_spec_id
    }
}

/// An out-of-memory error during emulation.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Emulator out of memory: {message}")]
pub struct EmulatorOutOfMemoryError {
    /// Error message.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulator_config_new() {
        let config = EmulatorConfig::new("x86:LE:64:default", "default");
        assert_eq!(config.language_id, "x86:LE:64:default");
        assert_eq!(config.mode, EmulationMode::Full);
        assert!(config.track_memory_state);
    }

    #[test]
    fn test_emulator_config_builder() {
        let config = EmulatorConfig::new("x86:LE:64:default", "default")
            .with_mode(EmulationMode::Simplified)
            .with_max_steps(1000);
        assert_eq!(config.mode, EmulationMode::Simplified);
        assert_eq!(config.max_steps, 1000);
    }

    #[test]
    fn test_emulation_mode_default() {
        assert_eq!(EmulationMode::default(), EmulationMode::Full);
    }

    #[test]
    fn test_factory_new() {
        let factory = DefaultEmulatorFactory::new("x86:LE:64:default", "default");
        assert_eq!(factory.language_id(), "x86:LE:64:default");
        assert_eq!(factory.created_count(), 0);
    }

    #[test]
    fn test_factory_create_config() {
        let mut factory = DefaultEmulatorFactory::new("ARM:LE:32:v8", "default");
        let config = factory.create_config();
        assert_eq!(config.language_id, "ARM:LE:32:v8");
        assert_eq!(factory.created_count(), 1);
    }

    #[test]
    fn test_factory_create_with_mode() {
        let mut factory = DefaultEmulatorFactory::new("x86:LE:64:default", "default");
        let config = factory.create_config_with_mode(EmulationMode::Symbolic);
        assert_eq!(config.mode, EmulationMode::Symbolic);
    }

    #[test]
    fn test_out_of_memory_error() {
        let err = EmulatorOutOfMemoryError {
            message: "test".to_string(),
        };
        assert!(err.to_string().contains("test"));
    }
}
