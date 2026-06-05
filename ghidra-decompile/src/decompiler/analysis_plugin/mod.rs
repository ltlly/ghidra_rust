//! Decompiler analysis plugin analyzers.
//!
//! Ports Ghidra's `ghidra.app.plugin.core.analysis` package:
//! - [`DecompilerFunctionAnalyzer`]: runs the decompiler during auto-analysis
//!   to recover function signatures, parameters, and calling conventions.
//! - [`DecompilerCallConventionAnalyzer`]: detects calling conventions
//!   via decompilation.
//! - [`DecompilerSwitchAnalyzer`]: recovers switch / jump-table structures
//!   from decompiler output.
//!
//! These are analysis-phase components that integrate with the auto-analysis
//! manager.  In the Rust port they operate on program metadata and produce
//! analysis results without requiring a live Swing tool.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ============================================================================
// DecompilerFunctionAnalyzer
// ============================================================================

/// Configuration for the decompiler function analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompilerFunctionAnalyzerConfig {
    /// Whether to recover function signatures.
    pub recover_signatures: bool,
    /// Whether to analyze stack variables.
    pub analyze_stack_vars: bool,
    /// Whether to detect non-returning functions.
    pub detect_non_returning: bool,
    /// Maximum number of functions to analyze per pass.
    pub max_functions_per_pass: usize,
    /// Timeout per function (seconds).
    pub per_function_timeout_secs: u64,
}

impl Default for DecompilerFunctionAnalyzerConfig {
    fn default() -> Self {
        Self {
            recover_signatures: true,
            analyze_stack_vars: true,
            detect_non_returning: true,
            max_functions_per_pass: 10_000,
            per_function_timeout_secs: 30,
        }
    }
}

/// Result of analyzing a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAnalysisResult {
    /// The function entry address.
    pub address: u64,
    /// Whether the analysis succeeded.
    pub success: bool,
    /// Recovered return type (e.g., "int", "void").
    pub return_type: Option<String>,
    /// Recovered parameter list.
    pub parameters: Vec<AnalyzedParameter>,
    /// Detected calling convention.
    pub calling_convention: Option<String>,
    /// Whether this function is detected as non-returning.
    pub non_returning: bool,
    /// Stack frame size (bytes), if recoverable.
    pub stack_frame_size: Option<u32>,
    /// Error message if analysis failed.
    pub error: Option<String>,
}

/// A parameter discovered by decompiler function analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzedParameter {
    /// Parameter ordinal (0-based).
    pub ordinal: usize,
    /// Parameter name.
    pub name: String,
    /// Parameter data type.
    pub data_type: String,
    /// Storage description (register or stack offset).
    pub storage: String,
}

/// Decompiler-based function analyzer.
///
/// Runs the decompiler on each function in the program to recover
/// high-level information (signatures, parameters, calling convention,
/// non-returning detection, stack frame layout).
///
/// # Ported from
/// `ghidra.app.plugin.core.analysis.DecompilerFunctionAnalyzer`
#[derive(Debug)]
pub struct DecompilerFunctionAnalyzer {
    /// Analyzer configuration.
    pub config: DecompilerFunctionAnalyzerConfig,
    /// Accumulated results keyed by function address.
    results: HashMap<u64, FunctionAnalysisResult>,
    /// Number of functions analyzed so far.
    analyzed_count: usize,
    /// Whether the analyzer has been cancelled.
    cancelled: bool,
}

impl DecompilerFunctionAnalyzer {
    /// Create a new analyzer with default configuration.
    pub fn new() -> Self {
        Self {
            config: DecompilerFunctionAnalyzerConfig::default(),
            results: HashMap::new(),
            analyzed_count: 0,
            cancelled: false,
        }
    }

    /// Create a new analyzer with custom configuration.
    pub fn with_config(config: DecompilerFunctionAnalyzerConfig) -> Self {
        Self {
            config,
            results: HashMap::new(),
            analyzed_count: 0,
            cancelled: false,
        }
    }

    /// Record a function analysis result.
    pub fn record_result(&mut self, result: FunctionAnalysisResult) {
        self.analyzed_count += 1;
        self.results.insert(result.address, result);
    }

    /// Get the result for a function address.
    pub fn get_result(&self, address: u64) -> Option<&FunctionAnalysisResult> {
        self.results.get(&address)
    }

    /// Get the total number of analyzed functions.
    pub fn analyzed_count(&self) -> usize {
        self.analyzed_count
    }

    /// Get all results.
    pub fn results(&self) -> &HashMap<u64, FunctionAnalysisResult> {
        &self.results
    }

    /// Cancel the analysis.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Whether the analysis has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Reset the analyzer for a new run.
    pub fn reset(&mut self) {
        self.results.clear();
        self.analyzed_count = 0;
        self.cancelled = false;
    }
}

impl Default for DecompilerFunctionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DecompilerCallConventionAnalyzer
// ============================================================================

/// Known calling conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallingConvention {
    /// C default (cdecl on x86).
    Cdecl,
    /// Standard call (Win32).
    Stdcall,
    /// Fast call (register-based, MSVC/GCC).
    Fastcall,
    /// Microsoft x64 ABI.
    MicrosoftX64,
    /// System V AMD64 ABI.
    SystemVAMD64,
    /// ARM AAPCS.
    ArmAapcs,
    /// ARM64 AAPCS.
    Arm64Aapcs,
    /// Unknown / could not determine.
    Unknown,
}

impl CallingConvention {
    /// Return a human-readable name for the convention.
    pub fn name(&self) -> &'static str {
        match self {
            CallingConvention::Cdecl => "cdecl",
            CallingConvention::Stdcall => "stdcall",
            CallingConvention::Fastcall => "fastcall",
            CallingConvention::MicrosoftX64 => "Microsoft x64",
            CallingConvention::SystemVAMD64 => "System V AMD64",
            CallingConvention::ArmAapcs => "ARM AAPCS",
            CallingConvention::Arm64Aapcs => "ARM64 AAPCS",
            CallingConvention::Unknown => "unknown",
        }
    }
}

/// Result of calling convention analysis for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConventionAnalysisResult {
    /// Function entry address.
    pub address: u64,
    /// Detected calling convention.
    pub convention: CallingConvention,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// Register usage: register name -> parameter ordinal mapping.
    pub register_params: HashMap<String, usize>,
    /// Stack parameter offsets (byte offsets from frame pointer).
    pub stack_params: Vec<i64>,
}

/// Decompiler-based calling convention analyzer.
///
/// Analyzes functions using the decompiler to determine their calling
/// conventions.  Useful for annotating the disassembly listing and
/// for auto-analysis of binaries with unknown compilers.
///
/// # Ported from
/// `ghidra.app.plugin.core.analysis.DecompilerCallConventionAnalyzer`
#[derive(Debug)]
pub struct DecompilerCallConventionAnalyzer {
    /// Results keyed by function address.
    results: HashMap<u64, ConventionAnalysisResult>,
    /// Statistics: convention -> count.
    convention_counts: HashMap<CallingConvention, usize>,
}

impl DecompilerCallConventionAnalyzer {
    /// Create a new analyzer.
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
            convention_counts: HashMap::new(),
        }
    }

    /// Record a convention analysis result.
    pub fn record_result(&mut self, result: ConventionAnalysisResult) {
        *self.convention_counts.entry(result.convention).or_insert(0) += 1;
        self.results.insert(result.address, result);
    }

    /// Get the result for a function address.
    pub fn get_result(&self, address: u64) -> Option<&ConventionAnalysisResult> {
        self.results.get(&address)
    }

    /// Get the most commonly detected convention.
    pub fn dominant_convention(&self) -> CallingConvention {
        self.convention_counts
            .iter()
            .max_by_key(|(_, &count)| count)
            .map(|(&conv, _)| conv)
            .unwrap_or(CallingConvention::Unknown)
    }

    /// Get the total number of analyzed functions.
    pub fn result_count(&self) -> usize {
        self.results.len()
    }

    /// Get convention distribution.
    pub fn convention_counts(&self) -> &HashMap<CallingConvention, usize> {
        &self.convention_counts
    }
}

impl Default for DecompilerCallConventionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DecompilerSwitchAnalyzer
// ============================================================================

/// Analysis style for a recovered switch statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SwitchStyle {
    /// A computed goto table (jump table in .rodata).
    JumpTable,
    /// If-else chain reconstructed by the decompiler.
    IfElseChain,
    /// Bit-test cascades.
    BitTestCascade,
    /// A computed goto via indirect branch.
    ComputedGoto,
    /// Could not determine style.
    Unknown,
}

/// A single case in a recovered switch statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchCaseEntry {
    /// The case value.
    pub value: i64,
    /// The target address for this case branch.
    pub target: u64,
    /// Whether this is the default case.
    pub is_default: bool,
}

/// Result of switch analysis for one switch statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchAnalysisResult {
    /// Address of the indirect jump / switch dispatch instruction.
    pub dispatch_address: u64,
    /// The function containing this switch.
    pub function_address: u64,
    /// Detected switch style.
    pub style: SwitchStyle,
    /// Recovered cases.
    pub cases: Vec<SwitchCaseEntry>,
    /// Jump table base address (if style == JumpTable).
    pub jump_table_address: Option<u64>,
    /// Size of each jump table entry in bytes (if applicable).
    pub entry_size: Option<u32>,
}

/// Decompiler-based switch analyzer.
///
/// Recovers switch/jump-table structures from the decompiler's output.
/// During auto-analysis, this analyzer decompiles functions containing
/// indirect jumps and extracts the switch structure (case values,
/// targets, default branch, table layout).
///
/// # Ported from
/// `ghidra.app.plugin.core.analysis.DecompilerSwitchAnalyzer`
#[derive(Debug)]
pub struct DecompilerSwitchAnalyzer {
    /// Results keyed by dispatch address.
    results: HashMap<u64, SwitchAnalysisResult>,
    /// Total number of switches recovered.
    switch_count: usize,
}

impl DecompilerSwitchAnalyzer {
    /// Create a new switch analyzer.
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
            switch_count: 0,
        }
    }

    /// Record a switch analysis result.
    pub fn record_result(&mut self, result: SwitchAnalysisResult) {
        self.switch_count += 1;
        self.results.insert(result.dispatch_address, result);
    }

    /// Get the result for a dispatch address.
    pub fn get_result(&self, dispatch_address: u64) -> Option<&SwitchAnalysisResult> {
        self.results.get(&dispatch_address)
    }

    /// Get all recovered switches for a given function.
    pub fn switches_in_function(&self, function_address: u64) -> Vec<&SwitchAnalysisResult> {
        self.results
            .values()
            .filter(|r| r.function_address == function_address)
            .collect()
    }

    /// Get the total number of switches recovered.
    pub fn switch_count(&self) -> usize {
        self.switch_count
    }

    /// Get all results.
    pub fn results(&self) -> &HashMap<u64, SwitchAnalysisResult> {
        &self.results
    }
}

impl Default for DecompilerSwitchAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ConventionAnalysisDecompileConfigurer
// ============================================================================

/// Configurer for a decompile session used by the convention analyzer.
///
/// Sets the decompiler options appropriate for calling-convention
/// detection (e.g., disables simplification to preserve raw register
/// usage patterns).
#[derive(Debug, Clone)]
pub struct ConventionAnalysisDecompileConfigurer {
    /// Whether to preserve raw P-code.
    pub preserve_raw_pcode: bool,
    /// Whether to analyze register usage only (skip data-flow).
    pub register_usage_only: bool,
}

impl Default for ConventionAnalysisDecompileConfigurer {
    fn default() -> Self {
        Self {
            preserve_raw_pcode: true,
            register_usage_only: false,
        }
    }
}

// ============================================================================
// SwitchAnalysisDecompileConfigurer
// ============================================================================

/// Configurer for a decompile session used by the switch analyzer.
///
/// Sets the decompiler options appropriate for switch recovery (e.g.,
/// enables jump-table detection heuristics).
#[derive(Debug, Clone)]
pub struct SwitchAnalysisDecompileConfigurer {
    /// Whether to enable the decompiler's built-in switch recovery.
    pub enable_switch_recovery: bool,
    /// Maximum number of switch cases to recover.
    pub max_cases: usize,
    /// Whether to analyze indirect branches.
    pub analyze_indirect_branches: bool,
}

impl Default for SwitchAnalysisDecompileConfigurer {
    fn default() -> Self {
        Self {
            enable_switch_recovery: true,
            max_cases: 1024,
            analyze_indirect_branches: true,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_analyzer_new() {
        let analyzer = DecompilerFunctionAnalyzer::new();
        assert_eq!(analyzer.analyzed_count(), 0);
        assert!(!analyzer.is_cancelled());
    }

    #[test]
    fn function_analyzer_record_result() {
        let mut analyzer = DecompilerFunctionAnalyzer::new();
        analyzer.record_result(FunctionAnalysisResult {
            address: 0x1000,
            success: true,
            return_type: Some("int".into()),
            parameters: vec![
                AnalyzedParameter {
                    ordinal: 0,
                    name: "argc".into(),
                    data_type: "int".into(),
                    storage: "RDI".into(),
                },
            ],
            calling_convention: Some("System V AMD64".into()),
            non_returning: false,
            stack_frame_size: Some(32),
            error: None,
        });
        assert_eq!(analyzer.analyzed_count(), 1);
        let result = analyzer.get_result(0x1000).unwrap();
        assert_eq!(result.return_type.as_deref(), Some("int"));
        assert_eq!(result.parameters.len(), 1);
    }

    #[test]
    fn function_analyzer_cancel() {
        let mut analyzer = DecompilerFunctionAnalyzer::new();
        assert!(!analyzer.is_cancelled());
        analyzer.cancel();
        assert!(analyzer.is_cancelled());
    }

    #[test]
    fn function_analyzer_reset() {
        let mut analyzer = DecompilerFunctionAnalyzer::new();
        analyzer.record_result(FunctionAnalysisResult {
            address: 0x1000,
            success: true,
            return_type: None,
            parameters: vec![],
            calling_convention: None,
            non_returning: false,
            stack_frame_size: None,
            error: None,
        });
        assert_eq!(analyzer.analyzed_count(), 1);
        analyzer.reset();
        assert_eq!(analyzer.analyzed_count(), 0);
        assert!(analyzer.results().is_empty());
    }

    #[test]
    fn function_analyzer_config_default() {
        let config = DecompilerFunctionAnalyzerConfig::default();
        assert!(config.recover_signatures);
        assert!(config.analyze_stack_vars);
        assert!(config.detect_non_returning);
        assert_eq!(config.max_functions_per_pass, 10_000);
    }

    #[test]
    fn convention_analyzer_new() {
        let analyzer = DecompilerCallConventionAnalyzer::new();
        assert_eq!(analyzer.result_count(), 0);
    }

    #[test]
    fn convention_analyzer_dominant() {
        let mut analyzer = DecompilerCallConventionAnalyzer::new();
        analyzer.record_result(ConventionAnalysisResult {
            address: 0x1000,
            convention: CallingConvention::Cdecl,
            confidence: 0.9,
            register_params: HashMap::new(),
            stack_params: vec![],
        });
        analyzer.record_result(ConventionAnalysisResult {
            address: 0x2000,
            convention: CallingConvention::Fastcall,
            confidence: 0.8,
            register_params: HashMap::new(),
            stack_params: vec![],
        });
        analyzer.record_result(ConventionAnalysisResult {
            address: 0x3000,
            convention: CallingConvention::Cdecl,
            confidence: 0.95,
            register_params: HashMap::new(),
            stack_params: vec![],
        });
        assert_eq!(analyzer.dominant_convention(), CallingConvention::Cdecl);
        assert_eq!(analyzer.result_count(), 3);
    }

    #[test]
    fn convention_name_variants() {
        assert_eq!(CallingConvention::Cdecl.name(), "cdecl");
        assert_eq!(CallingConvention::SystemVAMD64.name(), "System V AMD64");
        assert_eq!(CallingConvention::Arm64Aapcs.name(), "ARM64 AAPCS");
        assert_eq!(CallingConvention::Unknown.name(), "unknown");
    }

    #[test]
    fn switch_analyzer_new() {
        let analyzer = DecompilerSwitchAnalyzer::new();
        assert_eq!(analyzer.switch_count(), 0);
    }

    #[test]
    fn switch_analyzer_record_and_lookup() {
        let mut analyzer = DecompilerSwitchAnalyzer::new();
        analyzer.record_result(SwitchAnalysisResult {
            dispatch_address: 0x4000,
            function_address: 0x1000,
            style: SwitchStyle::JumpTable,
            cases: vec![
                SwitchCaseEntry { value: 0, target: 0x5000, is_default: false },
                SwitchCaseEntry { value: 1, target: 0x5010, is_default: false },
                SwitchCaseEntry { value: -1, target: 0x5100, is_default: true },
            ],
            jump_table_address: Some(0x8000),
            entry_size: Some(4),
        });
        assert_eq!(analyzer.switch_count(), 1);
        let result = analyzer.get_result(0x4000).unwrap();
        assert_eq!(result.style, SwitchStyle::JumpTable);
        assert_eq!(result.cases.len(), 3);
        assert_eq!(result.jump_table_address, Some(0x8000));
    }

    #[test]
    fn switch_analyzer_function_lookup() {
        let mut analyzer = DecompilerSwitchAnalyzer::new();
        analyzer.record_result(SwitchAnalysisResult {
            dispatch_address: 0x4000,
            function_address: 0x1000,
            style: SwitchStyle::JumpTable,
            cases: vec![],
            jump_table_address: None,
            entry_size: None,
        });
        analyzer.record_result(SwitchAnalysisResult {
            dispatch_address: 0x4100,
            function_address: 0x1000,
            style: SwitchStyle::IfElseChain,
            cases: vec![],
            jump_table_address: None,
            entry_size: None,
        });
        let switches = analyzer.switches_in_function(0x1000);
        assert_eq!(switches.len(), 2);
    }

    #[test]
    fn switch_style_variants() {
        assert_ne!(SwitchStyle::JumpTable, SwitchStyle::IfElseChain);
        assert_ne!(SwitchStyle::BitTestCascade, SwitchStyle::ComputedGoto);
    }

    #[test]
    fn convention_configurer_default() {
        let config = ConventionAnalysisDecompileConfigurer::default();
        assert!(config.preserve_raw_pcode);
        assert!(!config.register_usage_only);
    }

    #[test]
    fn switch_configurer_default() {
        let config = SwitchAnalysisDecompileConfigurer::default();
        assert!(config.enable_switch_recovery);
        assert_eq!(config.max_cases, 1024);
        assert!(config.analyze_indirect_branches);
    }

    #[test]
    fn analyzed_parameter_serialization() {
        let param = AnalyzedParameter {
            ordinal: 0,
            name: "x".into(),
            data_type: "int".into(),
            storage: "RDI".into(),
        };
        let json = serde_json::to_string(&param).unwrap();
        assert!(json.contains("RDI"));
        let back: AnalyzedParameter = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "x");
    }
}
