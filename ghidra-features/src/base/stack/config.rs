//! Stack analysis configuration -- common parameters for all stack
//! analysis commands.

use serde::{Deserialize, Serialize};

/// Configuration for stack analysis commands.
///
/// Controls which kinds of stack variables are created and whether
/// existing definitions are re-processed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackAnalysisConfig {
    /// Whether to create stack parameter variables.
    pub create_stack_params: bool,
    /// Whether to create local stack variables.
    pub create_local_stack_vars: bool,
    /// Whether to force re-analysis even if the stack is already defined.
    pub force_processing: bool,
    /// Maximum allowed positive (parameter) offset from frame base.
    pub max_param_offset: i32,
    /// Maximum allowed negative (local) offset from frame base.
    /// Stored as a positive magnitude; the actual limit is `-max_local_offset`.
    pub max_local_offset: i32,
}

impl StackAnalysisConfig {
    /// Default configuration: create locals, skip params, no forced processing.
    pub fn new() -> Self {
        Self {
            create_stack_params: false,
            create_local_stack_vars: true,
            force_processing: false,
            max_param_offset: 2048,
            max_local_offset: 64 * 1024,
        }
    }

    /// Configuration for full analysis (locals + params, forced).
    pub fn full() -> Self {
        Self {
            create_stack_params: true,
            create_local_stack_vars: true,
            force_processing: true,
            max_param_offset: 2048,
            max_local_offset: 64 * 1024,
        }
    }

    /// Configuration with custom flags.
    pub fn with_flags(
        create_stack_params: bool,
        create_local_stack_vars: bool,
        force_processing: bool,
    ) -> Self {
        Self {
            create_stack_params,
            create_local_stack_vars,
            force_processing,
            ..Self::new()
        }
    }

    /// Whether the given stack offset is within the valid parameter
    /// range.
    pub fn is_valid_param_offset(&self, offset: i32) -> bool {
        offset >= 0 && offset <= self.max_param_offset
    }

    /// Whether the given stack offset is within the valid local
    /// variable range.
    pub fn is_valid_local_offset(&self, offset: i32) -> bool {
        offset < 0 && offset >= -self.max_local_offset
    }

    /// Whether the given stack offset is within either the valid
    /// parameter or local variable range.
    pub fn is_valid_offset(&self, offset: i32) -> bool {
        self.is_valid_param_offset(offset) || self.is_valid_local_offset(offset)
    }
}

impl Default for StackAnalysisConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = StackAnalysisConfig::new();
        assert!(!cfg.create_stack_params);
        assert!(cfg.create_local_stack_vars);
        assert!(!cfg.force_processing);
        assert_eq!(cfg.max_param_offset, 2048);
        assert_eq!(cfg.max_local_offset, 64 * 1024);
    }

    #[test]
    fn test_full_config() {
        let cfg = StackAnalysisConfig::full();
        assert!(cfg.create_stack_params);
        assert!(cfg.create_local_stack_vars);
        assert!(cfg.force_processing);
    }

    #[test]
    fn test_with_flags() {
        let cfg = StackAnalysisConfig::with_flags(true, false, true);
        assert!(cfg.create_stack_params);
        assert!(!cfg.create_local_stack_vars);
        assert!(cfg.force_processing);
    }

    #[test]
    fn test_param_offset_validation() {
        let cfg = StackAnalysisConfig::new();
        assert!(cfg.is_valid_param_offset(0));
        assert!(cfg.is_valid_param_offset(8));
        assert!(cfg.is_valid_param_offset(2048));
        assert!(!cfg.is_valid_param_offset(2049));
        assert!(!cfg.is_valid_param_offset(-1));
    }

    #[test]
    fn test_local_offset_validation() {
        let cfg = StackAnalysisConfig::new();
        assert!(cfg.is_valid_local_offset(-1));
        assert!(cfg.is_valid_local_offset(-64));
        assert!(cfg.is_valid_local_offset(-65536));
        assert!(!cfg.is_valid_local_offset(-65537));
        assert!(!cfg.is_valid_local_offset(0));
        assert!(!cfg.is_valid_local_offset(8));
    }

    #[test]
    fn test_is_valid_offset() {
        let cfg = StackAnalysisConfig::new();
        assert!(cfg.is_valid_offset(0));     // param
        assert!(cfg.is_valid_offset(8));     // param
        assert!(cfg.is_valid_offset(-8));    // local
        assert!(!cfg.is_valid_offset(3000)); // too large
        assert!(!cfg.is_valid_offset(-100000)); // too negative
    }

    #[test]
    fn test_default_trait() {
        let cfg = StackAnalysisConfig::default();
        assert_eq!(cfg, StackAnalysisConfig::new());
    }

    #[test]
    fn test_clone_eq() {
        let cfg1 = StackAnalysisConfig::full();
        let cfg2 = cfg1.clone();
        assert_eq!(cfg1, cfg2);
    }
}
