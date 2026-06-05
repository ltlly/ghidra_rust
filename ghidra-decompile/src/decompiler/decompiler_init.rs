//! DecompilerInitializer: initialization and configuration of the decompiler.
//!
//! Ported from `decompiler.DecompilerInitializer`.

use serde::{Deserialize, Serialize};

/// Configuration for initializing the decompiler subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompilerInitConfig {
    /// Path to the native decompiler binary.
    pub decompiler_path: Option<String>,
    /// Path to the SLEIGH specification files directory.
    pub sleigh_home: Option<String>,
    /// Maximum number of concurrent decompile processes.
    pub max_concurrent_processes: usize,
    /// Default timeout for decompile operations (seconds).
    pub default_timeout_secs: u64,
    /// Whether to enable decompiler debug logging.
    pub debug_logging: bool,
    /// The default compiler specification ID.
    pub default_compiler_spec: String,
}

impl Default for DecompilerInitConfig {
    fn default() -> Self {
        Self {
            decompiler_path: None,
            sleigh_home: None,
            max_concurrent_processes: 4,
            default_timeout_secs: 60,
            debug_logging: false,
            default_compiler_spec: "default".to_string(),
        }
    }
}

/// The current state of the decompiler subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompilerState {
    /// Not yet initialized.
    Uninitialized,
    /// Currently initializing.
    Initializing,
    /// Ready for decompilation.
    Ready,
    /// An error occurred during initialization.
    Error(String),
}

impl Default for DecompilerState {
    fn default() -> Self { DecompilerState::Uninitialized }
}

/// Manages the initialization lifecycle of the decompiler subsystem.
pub struct DecompilerInitializer {
    config: DecompilerInitConfig,
    state: DecompilerState,
}

impl DecompilerInitializer {
    /// Create a new initializer with default config.
    pub fn new() -> Self {
        Self {
            config: DecompilerInitConfig::default(),
            state: DecompilerState::Uninitialized,
        }
    }

    /// Create with custom config.
    pub fn with_config(config: DecompilerInitConfig) -> Self {
        Self {
            config,
            state: DecompilerState::Uninitialized,
        }
    }

    /// Initialize the decompiler subsystem.
    pub fn initialize(&mut self) -> Result<(), String> {
        self.state = DecompilerState::Initializing;

        // In a real implementation, this would:
        // 1. Find the decompiler binary
        // 2. Locate SLEIGH specs
        // 3. Start decompiler processes
        // 4. Verify they're operational

        self.state = DecompilerState::Ready;
        Ok(())
    }

    /// Get the current state.
    pub fn state(&self) -> &DecompilerState { &self.state }

    /// Get the config.
    pub fn config(&self) -> &DecompilerInitConfig { &self.config }

    /// Whether the decompiler is ready.
    pub fn is_ready(&self) -> bool { self.state == DecompilerState::Ready }
}

impl Default for DecompilerInitializer {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializer_default_state() {
        let init = DecompilerInitializer::new();
        assert_eq!(init.state(), &DecompilerState::Uninitialized);
        assert!(!init.is_ready());
    }

    #[test]
    fn initializer_initialize() {
        let mut init = DecompilerInitializer::new();
        init.initialize().unwrap();
        assert!(init.is_ready());
        assert_eq!(init.state(), &DecompilerState::Ready);
    }

    #[test]
    fn init_config_defaults() {
        let c = DecompilerInitConfig::default();
        assert_eq!(c.max_concurrent_processes, 4);
        assert_eq!(c.default_timeout_secs, 60);
        assert!(!c.debug_logging);
    }
}
