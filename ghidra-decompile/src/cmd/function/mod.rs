//! Decompiler function analysis commands.
//!
//! Port of `ghidra.app.cmd.function`:
//! - [`DecompilerParameterIdCmd`]: identify function parameters via decompilation
//! - [`DecompilerParallelConventionAnalysisCmd`]: parallel calling convention analysis
//! - [`DecompilerSwitchAnalysisCmd`]: decompiler-based switch analysis

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Command to identify function parameters using the decompiler.
///
/// Runs the decompiler on a function and extracts parameter information
/// (register or stack-based) from the decompiled output.
#[derive(Debug, Clone)]
pub struct DecompilerParameterIdCmd {
    /// Function address to analyze.
    pub function_address: u64,
    /// Whether to override existing parameters.
    pub override_existing: bool,
    /// Timeout in seconds.
    pub timeout_secs: u64,
    /// Discovered parameters (filled after execution).
    parameters: Vec<ParameterInfo>,
}

/// Information about a discovered function parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInfo {
    /// Parameter name.
    pub name: String,
    /// Parameter type (e.g., "int", "char*").
    pub param_type: String,
    /// Storage location (register name or stack offset).
    pub storage: String,
    /// Parameter index (0-based).
    pub ordinal: usize,
}

impl DecompilerParameterIdCmd {
    /// Create a new parameter ID command.
    pub fn new(function_address: u64) -> Self {
        Self {
            function_address,
            override_existing: false,
            timeout_secs: 60,
            parameters: Vec::new(),
        }
    }

    /// Set whether to override existing parameters.
    pub fn with_override(mut self, override_existing: bool) -> Self {
        self.override_existing = override_existing;
        self
    }

    /// Set the timeout.
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Get discovered parameters.
    pub fn parameters(&self) -> &[ParameterInfo] {
        &self.parameters
    }

    /// Add a discovered parameter (used during execution).
    pub fn add_parameter(&mut self, param: ParameterInfo) {
        self.parameters.push(param);
    }
}

/// Command for parallel calling convention analysis using the decompiler.
///
/// Analyzes multiple functions in parallel to determine their calling
/// conventions, which is useful for large binaries.
#[derive(Debug, Clone)]
pub struct DecompilerParallelConventionAnalysisCmd {
    /// Function addresses to analyze.
    pub function_addresses: Vec<u64>,
    /// Maximum parallel workers.
    pub max_workers: usize,
    /// Results map: address -> detected convention.
    results: HashMap<u64, String>,
}

impl DecompilerParallelConventionAnalysisCmd {
    /// Create a new parallel convention analysis command.
    pub fn new(max_workers: usize) -> Self {
        Self {
            function_addresses: Vec::new(),
            max_workers,
            results: HashMap::new(),
        }
    }

    /// Add a function address to analyze.
    pub fn add_function(&mut self, address: u64) {
        self.function_addresses.push(address);
    }

    /// Get the detected convention for an address.
    pub fn get_convention(&self, address: u64) -> Option<&str> {
        self.results.get(&address).map(|s| s.as_str())
    }

    /// Set a convention result.
    pub fn set_convention(&mut self, address: u64, convention: String) {
        self.results.insert(address, convention);
    }

    /// Get the number of analyzed functions.
    pub fn analyzed_count(&self) -> usize {
        self.results.len()
    }
}

/// Command to perform decompiler-based convention analysis.
///
/// Single-function convention detection via decompilation.
#[derive(Debug, Clone)]
pub struct DecompilerConventionAnalysisCmd {
    /// Function address.
    pub function_address: u64,
    /// Detected convention (filled after execution).
    detected_convention: Option<String>,
}

impl DecompilerConventionAnalysisCmd {
    /// Create a new convention analysis command.
    pub fn new(function_address: u64) -> Self {
        Self {
            function_address,
            detected_convention: None,
        }
    }

    /// Get the detected convention.
    pub fn detected_convention(&self) -> Option<&str> {
        self.detected_convention.as_deref()
    }

    /// Set the detected convention.
    pub fn set_convention(&mut self, convention: impl Into<String>) {
        self.detected_convention = Some(convention.into());
    }
}

// ============================================================================
// DecompilerSwitchAnalysisCmd
// ============================================================================

/// Information about a single case in a switch statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchCaseInfo {
    /// The case value (the constant that is matched).
    pub case_value: i64,
    /// The target address for this case.
    pub target_address: u64,
    /// Whether this is the default case.
    pub is_default: bool,
}

/// Command to perform decompiler-based switch analysis.
///
/// Analyzes a switch statement by decompiling the function and
/// extracting the switch structure (number of cases, targets,
/// jump table address, etc.).
///
/// Port of `ghidra.app.plugin.core.analysis.DecompilerSwitchAnalyzer`.
#[derive(Debug, Clone)]
pub struct DecompilerSwitchAnalysisCmd {
    /// Function address containing the switch.
    pub function_address: u64,
    /// Address of the switch body (the indirect jump instruction).
    pub body_address: u64,
    /// Whether this is an indirect (computed) switch.
    indirect: bool,
    /// Jump table address (for indirect switches).
    jump_table_address: Option<u64>,
    /// Discovered switch cases.
    cases: Vec<SwitchCaseInfo>,
    /// The switch analysis style (e.g., "computed goto", "jump table").
    analysis_style: Option<String>,
}

impl DecompilerSwitchAnalysisCmd {
    /// Create a new switch analysis command.
    pub fn new(function_address: u64, body_address: u64) -> Self {
        Self {
            function_address,
            body_address,
            indirect: false,
            jump_table_address: None,
            cases: Vec::new(),
            analysis_style: None,
        }
    }

    /// Whether this is an indirect (computed) switch.
    pub fn is_indirect(&self) -> bool {
        self.indirect
    }

    /// Set whether this is an indirect switch.
    pub fn set_indirect(&mut self, indirect: bool) {
        self.indirect = indirect;
    }

    /// Get the jump table address (if any).
    pub fn jump_table_address(&self) -> Option<u64> {
        self.jump_table_address
    }

    /// Set the jump table address.
    pub fn set_jump_table_address(&mut self, addr: Option<u64>) {
        self.jump_table_address = addr;
    }

    /// Get the discovered switch cases.
    pub fn cases(&self) -> &[SwitchCaseInfo] {
        &self.cases
    }

    /// Add a switch case.
    pub fn add_case(&mut self, case: SwitchCaseInfo) {
        self.cases.push(case);
    }

    /// Get the analysis style.
    pub fn analysis_style(&self) -> Option<&str> {
        self.analysis_style.as_deref()
    }

    /// Set the analysis style.
    pub fn set_analysis_style(&mut self, style: impl Into<String>) {
        self.analysis_style = Some(style.into());
    }

    /// Get the number of cases (including default).
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }

    /// Get the default case (if any).
    pub fn default_case(&self) -> Option<&SwitchCaseInfo> {
        self.cases.iter().find(|c| c.is_default)
    }

    /// Get all non-default cases.
    pub fn non_default_cases(&self) -> Vec<&SwitchCaseInfo> {
        self.cases.iter().filter(|c| !c.is_default).collect()
    }

    /// Sort cases by their value.
    pub fn sort_cases(&mut self) {
        self.cases.sort_by_key(|c| c.case_value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_id_cmd() {
        let mut cmd = DecompilerParameterIdCmd::new(0x1000)
            .with_override(true)
            .with_timeout(120);
        assert_eq!(cmd.function_address, 0x1000);
        assert!(cmd.override_existing);
        assert_eq!(cmd.timeout_secs, 120);
        assert!(cmd.parameters().is_empty());

        cmd.add_parameter(ParameterInfo {
            name: "arg1".to_string(),
            param_type: "int".to_string(),
            storage: "RDI".to_string(),
            ordinal: 0,
        });
        assert_eq!(cmd.parameters().len(), 1);
    }

    #[test]
    fn test_parallel_convention_cmd() {
        let mut cmd = DecompilerParallelConventionAnalysisCmd::new(4);
        cmd.add_function(0x1000);
        cmd.add_function(0x2000);
        assert_eq!(cmd.function_addresses.len(), 2);

        cmd.set_convention(0x1000, "cdecl".to_string());
        assert_eq!(cmd.get_convention(0x1000), Some("cdecl"));
        assert_eq!(cmd.analyzed_count(), 1);
    }

    #[test]
    fn test_convention_analysis_cmd() {
        let mut cmd = DecompilerConventionAnalysisCmd::new(0x1000);
        assert!(cmd.detected_convention().is_none());
        cmd.set_convention("__fastcall");
        assert_eq!(cmd.detected_convention(), Some("__fastcall"));
    }

    #[test]
    fn test_switch_analysis_cmd() {
        let mut cmd = DecompilerSwitchAnalysisCmd::new(0x1000, 0x2000);
        assert_eq!(cmd.function_address, 0x1000);
        assert_eq!(cmd.body_address, 0x2000);

        cmd.add_case(SwitchCaseInfo {
            case_value: 1,
            target_address: 0x3000,
            is_default: false,
        });
        cmd.add_case(SwitchCaseInfo {
            case_value: 0,
            target_address: 0x4000,
            is_default: true,
        });

        assert_eq!(cmd.cases().len(), 2);
        assert!(cmd.cases()[1].is_default);
        assert!(!cmd.cases()[0].is_default);
    }

    #[test]
    fn test_switch_analysis_with_indirection() {
        let mut cmd = DecompilerSwitchAnalysisCmd::new(0x1000, 0x2000);
        cmd.set_indirect(true);
        assert!(cmd.is_indirect());
        cmd.set_jump_table_address(Some(0x5000));
        assert_eq!(cmd.jump_table_address(), Some(0x5000));
    }

    #[test]
    fn test_switch_case_info() {
        let case = SwitchCaseInfo {
            case_value: 5,
            target_address: 0x6000,
            is_default: false,
        };
        assert_eq!(case.case_value, 5);
        assert_eq!(case.target_address, 0x6000);
    }
}
