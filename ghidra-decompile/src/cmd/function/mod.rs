//! Decompiler function analysis commands.
//!
//! Port of `ghidra.app.cmd.function`:
//! - [`DecompilerParameterIdCmd`]: identify function parameters via decompilation
//! - [`DecompilerParallelConventionAnalysisCmd`]: parallel calling convention analysis

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
}
