//! Decompiler analysis commands.
//!
//! Ported from `ghidra.app.cmd.function.*`:
//! - DecompilerParallelConventionAnalysisCmd
//! - DecompilerParameterIdCmd
//! - DecompilerSwitchAnalysisCmd

use serde::{Deserialize, Serialize};

/// The type of analysis to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecompilerAnalysisKind {
    /// Detect calling conventions using the decompiler.
    ConventionAnalysis,
    /// Identify function parameters.
    ParameterId,
    /// Analyze switch statements.
    SwitchAnalysis,
    /// Full function analysis (all of the above).
    FullAnalysis,
}

/// Configuration for a decompiler analysis command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompilerCommandConfig {
    /// The type of analysis.
    pub kind: DecompilerAnalysisKind,
    /// The function entry point address.
    pub function_address: u64,
    /// Maximum decompile time in seconds.
    pub timeout_secs: u64,
    /// Whether to run in parallel across multiple functions.
    pub parallel: bool,
    /// Batch size for parallel analysis.
    pub batch_size: usize,
}

impl DecompilerCommandConfig {
    /// Create a convention analysis command.
    pub fn convention_analysis(address: u64) -> Self {
        Self {
            kind: DecompilerAnalysisKind::ConventionAnalysis,
            function_address: address,
            timeout_secs: 60,
            parallel: false,
            batch_size: 1,
        }
    }

    /// Create a parameter ID command.
    pub fn parameter_id(address: u64) -> Self {
        Self {
            kind: DecompilerAnalysisKind::ParameterId,
            function_address: address,
            timeout_secs: 60,
            parallel: false,
            batch_size: 1,
        }
    }

    /// Create a switch analysis command.
    pub fn switch_analysis(address: u64) -> Self {
        Self {
            kind: DecompilerAnalysisKind::SwitchAnalysis,
            function_address: address,
            timeout_secs: 30,
            parallel: false,
            batch_size: 1,
        }
    }

    /// Create a parallel batch command for convention analysis.
    pub fn parallel_convention(addresses: Vec<u64>, batch_size: usize) -> Vec<Self> {
        addresses.into_iter().map(|addr| Self {
            kind: DecompilerAnalysisKind::ConventionAnalysis,
            function_address: addr,
            timeout_secs: 60,
            parallel: true,
            batch_size,
        }).collect()
    }
}

/// Result of a decompiler analysis command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompilerCommandResult {
    /// The function entry point.
    pub function_address: u64,
    /// The analysis kind that was performed.
    pub kind: DecompilerAnalysisKind,
    /// Whether the analysis succeeded.
    pub success: bool,
    /// Discovered calling convention (for ConventionAnalysis).
    pub calling_convention: Option<String>,
    /// Discovered parameters (for ParameterId).
    pub parameters: Vec<ParameterInfo>,
    /// Discovered switch cases (for SwitchAnalysis).
    pub switch_cases: Vec<SwitchCaseInfo>,
    /// Error message (if failed).
    pub error: Option<String>,
}

/// Information about a discovered function parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInfo {
    /// Parameter name.
    pub name: String,
    /// Parameter data type.
    pub data_type: String,
    /// Storage location (register or stack offset).
    pub storage: String,
    /// Parameter index (0-based).
    pub index: usize,
}

/// Information about a switch case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchCaseInfo {
    /// The case value.
    pub value: u64,
    /// The target address.
    pub target_address: u64,
    /// Whether this is the default case.
    pub is_default: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_config_convention() {
        let c = DecompilerCommandConfig::convention_analysis(0x1000);
        assert_eq!(c.kind, DecompilerAnalysisKind::ConventionAnalysis);
        assert_eq!(c.function_address, 0x1000);
    }

    #[test]
    fn command_config_parameter() {
        let c = DecompilerCommandConfig::parameter_id(0x2000);
        assert_eq!(c.kind, DecompilerAnalysisKind::ParameterId);
    }

    #[test]
    fn parallel_convention_batch() {
        let configs = DecompilerCommandConfig::parallel_convention(vec![0x1000, 0x2000, 0x3000], 2);
        assert_eq!(configs.len(), 3);
        assert!(configs.iter().all(|c| c.parallel));
    }

    #[test]
    fn command_result_default() {
        let r = DecompilerCommandResult {
            function_address: 0x1000,
            kind: DecompilerAnalysisKind::SwitchAnalysis,
            success: true,
            calling_convention: None,
            parameters: vec![],
            switch_cases: vec![
                SwitchCaseInfo { value: 0, target_address: 0x1100, is_default: true },
                SwitchCaseInfo { value: 1, target_address: 0x1200, is_default: false },
            ],
            error: None,
        };
        assert!(r.success);
        assert_eq!(r.switch_cases.len(), 2);
    }
}
