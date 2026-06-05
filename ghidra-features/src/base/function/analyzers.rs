//! Function analyzers -- ported from `ghidra.app.plugin.core.function`.
//!
//! Provides the analysis passes that discover, create, and refine
//! functions during automatic analysis.  Each analyzer struct carries
//! its configuration (priority, enablement, options) and exposes an
//! `analyze()` method that operates on a simplified program/address-set
//! model.
//!
//! # Analyzers ported
//!
//! | Rust struct | Java class |
//! |---|---|
//! | `FunctionAnalyzer` | `FunctionAnalyzer` (Subroutine References) |
//! | `CreateThunkAnalyzer` | `CreateThunkAnalyzer` |
//! | `SharedReturnAnalyzer` | `SharedReturnAnalyzer` |
//! | `StackVariableAnalyzer` | `StackVariableAnalyzer` |
//! | `ExternalEntryFunctionAnalyzer` | `ExternalEntryFunctionAnalyzer` |

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Analysis priority
// ---------------------------------------------------------------------------

/// Priority ordering for analyzers within the analysis pipeline.
///
/// Ported from `ghidra.app.services.AnalysisPriority`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AnalysisPriority {
    /// Very early -- block-level analysis (e.g., creating basic blocks).
    BlockAnalysis,
    /// Early -- instruction-level analysis (e.g., subroutine references).
    InstructionAnalysis,
    /// Code analysis (e.g., shared return detection).
    CodeAnalysis,
    /// Data-type propagation.
    DataTypePropagation,
    /// Final cleanup and formatting.
    FinalAnalysis,
}

impl AnalysisPriority {
    /// A priority one step after (lower priority) this one.
    pub fn after(self) -> Self {
        match self {
            Self::BlockAnalysis => Self::InstructionAnalysis,
            Self::InstructionAnalysis => Self::CodeAnalysis,
            Self::CodeAnalysis => Self::DataTypePropagation,
            Self::DataTypePropagation | Self::FinalAnalysis => Self::FinalAnalysis,
        }
    }

    /// A priority one step before (higher priority) this one.
    pub fn before(self) -> Self {
        match self {
            Self::BlockAnalysis | Self::InstructionAnalysis => Self::BlockAnalysis,
            Self::CodeAnalysis => Self::InstructionAnalysis,
            Self::DataTypePropagation => Self::CodeAnalysis,
            Self::FinalAnalysis => Self::DataTypePropagation,
        }
    }
}

// ---------------------------------------------------------------------------
// Analyzer type
// ---------------------------------------------------------------------------

/// The type of analyzer (determines when it runs in the analysis flow).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnalyzerType {
    /// Runs after instructions are created.
    InstructionAnalyzer,
    /// Runs at the function level (after function creation).
    FunctionAnalyzer,
    /// Runs after data type propagation.
    DataTypeAnalyzer,
    /// Runs on binary load (before any instructions).
    BinaryAnalyzer,
}

// ---------------------------------------------------------------------------
// Analysis option
// ---------------------------------------------------------------------------

/// A user-configurable analysis option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOption {
    /// Option name.
    pub name: String,
    /// Option description.
    pub description: String,
    /// Current boolean value (for boolean options).
    pub bool_value: Option<bool>,
    /// Current integer value (for integer options).
    pub int_value: Option<i32>,
}

impl AnalysisOption {
    /// Create a boolean option.
    pub fn bool_option(
        name: impl Into<String>,
        description: impl Into<String>,
        default: bool,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            bool_value: Some(default),
            int_value: None,
        }
    }

    /// Create an integer option.
    pub fn int_option(
        name: impl Into<String>,
        description: impl Into<String>,
        default: i32,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            bool_value: None,
            int_value: Some(default),
        }
    }
}

// ---------------------------------------------------------------------------
// Analysis result
// ---------------------------------------------------------------------------

/// Result of an analysis pass.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Whether the analysis completed successfully.
    pub success: bool,
    /// Number of functions discovered or modified.
    pub functions_found: usize,
    /// Number of addresses analyzed.
    pub addresses_analyzed: u64,
    /// Log messages produced during analysis.
    pub messages: Vec<String>,
}

impl AnalysisResult {
    /// Create a successful result.
    pub fn success(functions_found: usize, addresses_analyzed: u64) -> Self {
        Self {
            success: true,
            functions_found,
            addresses_analyzed,
            messages: Vec::new(),
        }
    }

    /// Create a failed result.
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            functions_found: 0,
            addresses_analyzed: 0,
            messages: vec![message.into()],
        }
    }

    /// Add a log message.
    pub fn add_message(&mut self, msg: impl Into<String>) {
        self.messages.push(msg.into());
    }
}

// ---------------------------------------------------------------------------
// Call reference model
// ---------------------------------------------------------------------------

/// A simplified call reference for analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallReference {
    /// The address of the calling instruction.
    pub from_address: u64,
    /// The target address (function entry).
    pub to_address: u64,
    /// Whether this is a direct call (vs. indirect/computed).
    pub is_direct: bool,
    /// Whether this is a call vs. a jump to another function.
    pub is_call: bool,
    /// The flow type mnemonic (e.g., "CALL", "JMP").
    pub flow_type: String,
}

impl CallReference {
    /// Create a new call reference.
    pub fn new(
        from_address: u64,
        to_address: u64,
        is_direct: bool,
        is_call: bool,
        flow_type: impl Into<String>,
    ) -> Self {
        Self {
            from_address,
            to_address,
            is_direct,
            is_call,
            flow_type: flow_type.into(),
        }
    }

    /// Whether this is a fallthrough call (the call target is
    /// immediately after the call instruction).
    pub fn is_fallthrough_call(&self, instruction_size: u32) -> bool {
        self.to_address == self.from_address + instruction_size as u64
    }
}

// ---------------------------------------------------------------------------
// FunctionAnalyzer (Subroutine References)
// ---------------------------------------------------------------------------

/// Analyzer that discovers function entry points from call references.
///
/// Ported from `ghidra.app.plugin.core.function.FunctionAnalyzer`.
///
/// This analyzer scans call references in the analyzed address set and
/// creates function definitions at the called locations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAnalyzer {
    /// Whether to only create thunk functions.
    pub create_only_thunks: bool,
    /// Analysis priority.
    pub priority: AnalysisPriority,
    /// Whether this analyzer is enabled.
    pub enabled: bool,
    /// Notification interval (log progress every N addresses).
    pub notification_interval: usize,
}

impl FunctionAnalyzer {
    /// The analyzer name.
    pub const NAME: &'static str = "Subroutine References";
    /// The analyzer description.
    pub const DESCRIPTION: &'static str = "Create Function definitions for code that is called.";

    /// Create a new function analyzer with default settings.
    pub fn new() -> Self {
        Self {
            create_only_thunks: false,
            priority: AnalysisPriority::CodeAnalysis.before(),
            enabled: true,
            notification_interval: 256,
        }
    }

    /// Analyze a set of call references and return the addresses where
    /// new functions should be created.
    ///
    /// This is the core logic ported from the Java `added()` method.
    pub fn find_function_starts(
        &self,
        call_refs: &[CallReference],
    ) -> Vec<u64> {
        let mut func_starts = Vec::new();
        for cr in call_refs {
            // Only consider direct call/jump references.
            if !cr.is_direct {
                continue;
            }
            if self.create_only_thunks && cr.flow_type != "JMP" {
                continue;
            }
            // Skip fallthrough calls (call target immediately after
            // the call instruction).
            if cr.is_fallthrough_call(0) {
                continue;
            }
            func_starts.push(cr.to_address);
        }
        func_starts.sort_unstable();
        func_starts.dedup();
        func_starts
    }

    /// Register user-configurable options.
    pub fn options(&self) -> Vec<AnalysisOption> {
        vec![AnalysisOption::bool_option(
            "Create Thunks Only",
            "If checked, only create thunk functions.",
            self.create_only_thunks,
        )]
    }
}

impl Default for FunctionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CreateThunkAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that creates thunk functions early in the analysis pipeline.
///
/// Ported from `ghidra.app.plugin.core.function.CreateThunkAnalyzer`.
///
/// A thunk function's body consists entirely of a jump or call to
/// another function.  This analyzer runs early (after block analysis)
/// to identify and create such functions before other analyzers run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateThunkAnalyzer {
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Whether to create only thunks (always true for this analyzer).
    pub create_only_thunks: bool,
}

impl CreateThunkAnalyzer {
    /// The analyzer name.
    pub const NAME: &'static str = "Create Thunks Early";

    /// Create a new thunk analyzer.
    pub fn new() -> Self {
        Self {
            enabled: true,
            create_only_thunks: true,
        }
    }

    /// The analysis priority (after block analysis).
    pub fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::BlockAnalysis.after().after()
    }

    /// Analyze call references for thunk targets.
    ///
    /// Returns a list of `(thunk_entry, target_address)` pairs.
    pub fn find_thunks(
        &self,
        call_refs: &[CallReference],
    ) -> Vec<(u64, u64)> {
        if !self.create_only_thunks {
            return Vec::new();
        }
        call_refs
            .iter()
            .filter(|cr| cr.is_direct && cr.is_call)
            .map(|cr| (cr.from_address, cr.to_address))
            .collect()
    }

    /// Register options.
    pub fn options(&self) -> Vec<AnalysisOption> {
        vec![AnalysisOption::bool_option(
            Self::NAME,
            "If checked, create thunk functions early in analysis flow.",
            self.create_only_thunks,
        )]
    }
}

impl Default for CreateThunkAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SharedReturnAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that converts cross-function jumps into call-return
/// sequences.
///
/// Ported from `ghidra.app.plugin.core.function.SharedReturnAnalyzer`.
///
/// When a branch instruction targets another function's body, this
/// analyzer converts it into a call followed by an immediate return.
/// This is common for "shared return" or "tail call" patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedReturnAnalyzer {
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Whether to assume all function bodies are contiguous (all jumps
    /// across functions are treated as call-return).
    pub assume_contiguous_functions: bool,
    /// Whether to consider conditional branches for shared-return
    /// conversion.
    pub consider_conditional_branches: bool,
    /// Whether this analyzer supports one-time analysis.
    pub supports_one_time_analysis: bool,
}

impl SharedReturnAnalyzer {
    /// The analyzer name.
    pub const NAME: &'static str = "Shared Return Calls";

    /// The analyzer description.
    pub const DESCRIPTION: &'static str =
        "Converts branches to calls, followed by an immediate return, \
         when the destination is a function.";

    /// Create a new shared return analyzer.
    pub fn new() -> Self {
        Self {
            enabled: true,
            assume_contiguous_functions: true,
            consider_conditional_branches: false,
            supports_one_time_analysis: true,
        }
    }

    /// The analysis priority (before code analysis).
    pub fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::CodeAnalysis.before().before()
    }

    /// Analyze branch references and return those that should be
    /// converted to call-return pairs.
    ///
    /// Returns a list of `branch_address` values where a jump to
    /// another function should be rewritten as call+return.
    pub fn find_shared_returns(
        &self,
        call_refs: &[CallReference],
        existing_function_entries: &[u64],
    ) -> Vec<u64> {
        call_refs
            .iter()
            .filter(|cr| {
                // Must be a branch (not already a call).
                if cr.is_call {
                    return false;
                }
                // Must target an existing function.
                if !existing_function_entries.contains(&cr.to_address) {
                    return false;
                }
                // Skip conditional branches if not configured.
                if !self.consider_conditional_branches
                    && !cr.flow_type.to_uppercase().starts_with("JMP")
                {
                    // Only unconditional jumps.
                    return false;
                }
                true
            })
            .map(|cr| cr.from_address)
            .collect()
    }

    /// Register options.
    pub fn options(&self) -> Vec<AnalysisOption> {
        vec![
            AnalysisOption::bool_option(
                "Assume Contiguous Functions Only",
                "Signals to assume all function bodies are contiguous and all jumps \
                 across other functions should be treated as a call-return.",
                self.assume_contiguous_functions,
            ),
            AnalysisOption::bool_option(
                "Allow Conditional Jumps",
                "Signals to allow conditional jumps to be considered for shared return \
                 jumps to other functions.",
                self.consider_conditional_branches,
            ),
        ]
    }
}

impl Default for SharedReturnAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// StackVariableAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that creates stack variables for functions.
///
/// Ported from `ghidra.app.plugin.core.function.StackVariableAnalyzer`.
///
/// After function bodies have been identified, this analyzer examines
/// stack references within each function to create local variables and
/// parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackVariableAnalyzer {
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Maximum number of threads for parallel stack analysis.
    pub max_thread_count: usize,
    /// Whether to create local stack variables.
    pub create_local_stack_vars: bool,
    /// Whether to create stack parameters.
    pub create_stack_params: bool,
    /// Whether this analyzer supports one-time analysis.
    pub supports_one_time_analysis: bool,
}

impl StackVariableAnalyzer {
    /// The analyzer name.
    pub const NAME: &'static str = "Stack";

    /// The analyzer description.
    pub const DESCRIPTION: &'static str = "Creates stack variables for a function.";

    /// Default maximum thread count.
    pub const DEFAULT_MAX_THREAD_COUNT: usize = 2;

    /// Create a new stack variable analyzer.
    pub fn new() -> Self {
        Self {
            enabled: true,
            max_thread_count: Self::DEFAULT_MAX_THREAD_COUNT,
            create_local_stack_vars: true,
            create_stack_params: false,
            supports_one_time_analysis: true,
        }
    }

    /// The analysis priority (after data-type propagation).
    pub fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::DataTypePropagation.after().after().after()
    }

    /// Analyze a single function's stack layout.
    ///
    /// Returns the number of stack variables created.
    pub fn analyze_function_stack(
        &self,
        stack_references: &[(u64, i32)],
    ) -> usize {
        if stack_references.is_empty() {
            return 0;
        }

        let mut unique_offsets: Vec<i32> = stack_references.iter().map(|(_, off)| *off).collect();
        unique_offsets.sort_unstable();
        unique_offsets.dedup();

        let mut count = 0;
        for offset in &unique_offsets {
            if self.create_local_stack_vars && *offset < 0 {
                count += 1;
            }
            if self.create_stack_params && *offset >= 0 {
                count += 1;
            }
        }
        count
    }

    /// Register options.
    pub fn options(&self) -> Vec<AnalysisOption> {
        vec![
            AnalysisOption::int_option(
                "Max Threads",
                "Maximum threads for stack variable reference creation. \
                 Too many threads causes thrashing in DB.",
                self.max_thread_count as i32,
            ),
            AnalysisOption::bool_option(
                "Create Local Stack Variables",
                "Whether to create local stack variables during analysis.",
                self.create_local_stack_vars,
            ),
            AnalysisOption::bool_option(
                "Create Stack Parameters",
                "Whether to create stack parameter variables during analysis.",
                self.create_stack_params,
            ),
        ]
    }
}

impl Default for StackVariableAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ExternalEntryFunctionAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that creates function definitions at external entry points.
///
/// Ported from
/// `ghidra.app.plugin.core.function.ExternalEntryFunctionAnalyzer`.
///
/// When a program has external entry points (import table entries),
/// this analyzer ensures function definitions exist at those locations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalEntryFunctionAnalyzer {
    /// Whether the analyzer is enabled.
    pub enabled: bool,
}

impl ExternalEntryFunctionAnalyzer {
    /// The analyzer name.
    pub const NAME: &'static str = "External Entry References";

    /// Create a new external entry function analyzer.
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Analyze external entries and return addresses where functions
    /// should be created.
    pub fn find_external_entries(
        &self,
        external_entries: &[u64],
        existing_function_entries: &[u64],
    ) -> Vec<u64> {
        external_entries
            .iter()
            .filter(|addr| !existing_function_entries.contains(addr))
            .copied()
            .collect()
    }
}

impl Default for ExternalEntryFunctionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- AnalysisPriority --

    #[test]
    fn test_analysis_priority_ordering() {
        assert!(AnalysisPriority::BlockAnalysis < AnalysisPriority::CodeAnalysis);
        assert!(AnalysisPriority::CodeAnalysis < AnalysisPriority::FinalAnalysis);
    }

    #[test]
    fn test_analysis_priority_after() {
        assert_eq!(
            AnalysisPriority::BlockAnalysis.after(),
            AnalysisPriority::InstructionAnalysis
        );
        assert_eq!(
            AnalysisPriority::FinalAnalysis.after(),
            AnalysisPriority::FinalAnalysis
        );
    }

    #[test]
    fn test_analysis_priority_before() {
        assert_eq!(
            AnalysisPriority::FinalAnalysis.before(),
            AnalysisPriority::DataTypePropagation
        );
        assert_eq!(
            AnalysisPriority::BlockAnalysis.before(),
            AnalysisPriority::BlockAnalysis
        );
    }

    // -- CallReference --

    #[test]
    fn test_call_reference_is_fallthrough() {
        let cr = CallReference::new(0x1000, 0x1005, true, true, "CALL");
        assert!(cr.is_fallthrough_call(5));
        assert!(!cr.is_fallthrough_call(4));
    }

    #[test]
    fn test_call_reference_not_fallthrough() {
        let cr = CallReference::new(0x1000, 0x2000, true, true, "CALL");
        assert!(!cr.is_fallthrough_call(5));
    }

    // -- FunctionAnalyzer --

    #[test]
    fn test_function_analyzer_find_starts() {
        let analyzer = FunctionAnalyzer::new();
        let refs = vec![
            CallReference::new(0x1000, 0x2000, true, true, "CALL"),
            CallReference::new(0x1004, 0x2000, true, true, "CALL"),
            CallReference::new(0x1008, 0x3000, true, true, "CALL"),
        ];
        let starts = analyzer.find_function_starts(&refs);
        assert_eq!(starts, vec![0x2000, 0x3000]);
    }

    #[test]
    fn test_function_analyzer_skips_indirect() {
        let analyzer = FunctionAnalyzer::new();
        let refs = vec![
            CallReference::new(0x1000, 0x2000, false, true, "CALLIND"),
        ];
        let starts = analyzer.find_function_starts(&refs);
        assert!(starts.is_empty());
    }

    #[test]
    fn test_function_analyzer_thunks_only() {
        let mut analyzer = FunctionAnalyzer::new();
        analyzer.create_only_thunks = true;
        let refs = vec![
            CallReference::new(0x1000, 0x2000, true, true, "CALL"),
            CallReference::new(0x1004, 0x3000, true, false, "JMP"),
        ];
        let starts = analyzer.find_function_starts(&refs);
        // Only the JMP should be found when create_only_thunks is true.
        assert_eq!(starts, vec![0x3000]);
    }

    #[test]
    fn test_function_analyzer_default() {
        let a = FunctionAnalyzer::default();
        assert_eq!(a.priority, AnalysisPriority::CodeAnalysis.before());
        assert!(a.enabled);
        assert!(!a.create_only_thunks);
    }

    // -- CreateThunkAnalyzer --

    #[test]
    fn test_create_thunk_analyzer_find_thunks() {
        let analyzer = CreateThunkAnalyzer::new();
        let refs = vec![
            CallReference::new(0x1000, 0x2000, true, true, "CALL"),
            CallReference::new(0x1004, 0x3000, true, true, "CALL"),
        ];
        let thunks = analyzer.find_thunks(&refs);
        assert_eq!(thunks.len(), 2);
        assert_eq!(thunks[0], (0x1000, 0x2000));
    }

    #[test]
    fn test_create_thunk_analyzer_disabled() {
        let mut analyzer = CreateThunkAnalyzer::new();
        analyzer.create_only_thunks = false;
        let refs = vec![CallReference::new(0x1000, 0x2000, true, true, "CALL")];
        let thunks = analyzer.find_thunks(&refs);
        assert!(thunks.is_empty());
    }

    #[test]
    fn test_create_thunk_analyzer_priority() {
        let analyzer = CreateThunkAnalyzer::new();
        assert_eq!(
            analyzer.priority(),
            AnalysisPriority::BlockAnalysis.after().after()
        );
    }

    // -- SharedReturnAnalyzer --

    #[test]
    fn test_shared_return_analyzer_find() {
        let analyzer = SharedReturnAnalyzer::new();
        let refs = vec![
            CallReference::new(0x1000, 0x2000, true, false, "JMP"),
        ];
        let entries = vec![0x2000u64];
        let results = analyzer.find_shared_returns(&refs, &entries);
        assert_eq!(results, vec![0x1000]);
    }

    #[test]
    fn test_shared_return_analyzer_skips_calls() {
        let analyzer = SharedReturnAnalyzer::new();
        let refs = vec![
            CallReference::new(0x1000, 0x2000, true, true, "CALL"),
        ];
        let entries = vec![0x2000u64];
        let results = analyzer.find_shared_returns(&refs, &entries);
        assert!(results.is_empty());
    }

    #[test]
    fn test_shared_return_analyzer_skips_non_function() {
        let analyzer = SharedReturnAnalyzer::new();
        let refs = vec![
            CallReference::new(0x1000, 0x9999, true, false, "JMP"),
        ];
        let entries = vec![0x2000u64];
        let results = analyzer.find_shared_returns(&refs, &entries);
        assert!(results.is_empty());
    }

    #[test]
    fn test_shared_return_analyzer_conditional() {
        let mut analyzer = SharedReturnAnalyzer::new();
        analyzer.consider_conditional_branches = true;
        let refs = vec![
            CallReference::new(0x1000, 0x2000, true, false, "JZ"),
        ];
        let entries = vec![0x2000u64];
        let results = analyzer.find_shared_returns(&refs, &entries);
        assert_eq!(results, vec![0x1000]);
    }

    #[test]
    fn test_shared_return_analyzer_default() {
        let a = SharedReturnAnalyzer::default();
        assert!(a.enabled);
        assert!(a.assume_contiguous_functions);
        assert!(!a.consider_conditional_branches);
        assert!(a.supports_one_time_analysis);
    }

    // -- StackVariableAnalyzer --

    #[test]
    fn test_stack_variable_analyzer_locals_only() {
        let analyzer = StackVariableAnalyzer::new();
        // Negative offsets = local variables.
        let refs = vec![
            (0x1000, -4i32),
            (0x1004, -8),
            (0x1008, -4), // duplicate
        ];
        let count = analyzer.analyze_function_stack(&refs);
        assert_eq!(count, 2); // -4 and -8 (unique)
    }

    #[test]
    fn test_stack_variable_analyzer_with_params() {
        let mut analyzer = StackVariableAnalyzer::new();
        analyzer.create_stack_params = true;
        let refs = vec![
            (0x1000, -4i32),
            (0x1004, 4),
            (0x1008, 8),
        ];
        let count = analyzer.analyze_function_stack(&refs);
        assert_eq!(count, 3); // -4 (local), 4 and 8 (params)
    }

    #[test]
    fn test_stack_variable_analyzer_empty() {
        let analyzer = StackVariableAnalyzer::new();
        assert_eq!(analyzer.analyze_function_stack(&[]), 0);
    }

    #[test]
    fn test_stack_variable_analyzer_default() {
        let a = StackVariableAnalyzer::default();
        assert!(a.enabled);
        assert_eq!(a.max_thread_count, 2);
        assert!(a.create_local_stack_vars);
        assert!(!a.create_stack_params);
    }

    // -- ExternalEntryFunctionAnalyzer --

    #[test]
    fn test_external_entry_find_new() {
        let analyzer = ExternalEntryFunctionAnalyzer::new();
        let externals = vec![0x1000, 0x2000, 0x3000];
        let existing = vec![0x2000];
        let new_entries = analyzer.find_external_entries(&externals, &existing);
        assert_eq!(new_entries, vec![0x1000, 0x3000]);
    }

    #[test]
    fn test_external_entry_all_exist() {
        let analyzer = ExternalEntryFunctionAnalyzer::new();
        let externals = vec![0x1000, 0x2000];
        let existing = vec![0x1000, 0x2000];
        let new_entries = analyzer.find_external_entries(&externals, &existing);
        assert!(new_entries.is_empty());
    }

    // -- AnalysisResult --

    #[test]
    fn test_analysis_result_success() {
        let r = AnalysisResult::success(5, 1000);
        assert!(r.success);
        assert_eq!(r.functions_found, 5);
        assert_eq!(r.addresses_analyzed, 1000);
    }

    #[test]
    fn test_analysis_result_failure() {
        let r = AnalysisResult::failure("cancelled");
        assert!(!r.success);
        assert_eq!(r.messages, vec!["cancelled"]);
    }

    // -- AnalysisOption --

    #[test]
    fn test_analysis_option_bool() {
        let opt = AnalysisOption::bool_option("MyOpt", "desc", true);
        assert_eq!(opt.bool_value, Some(true));
        assert!(opt.int_value.is_none());
    }

    #[test]
    fn test_analysis_option_int() {
        let opt = AnalysisOption::int_option("Threads", "desc", 4);
        assert_eq!(opt.int_value, Some(4));
        assert!(opt.bool_value.is_none());
    }
}
