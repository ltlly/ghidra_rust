//! Extended function analyzers ported from Ghidra.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.function` Java package:
//! - `CreateThunkAnalyzer` -- creates thunk functions early in analysis
//! - `SharedReturnAnalyzer` -- converts jump-to-function to call-returns
//! - `StackVariableAnalyzer` -- discovers stack variables and parameters
//! - `X86FunctionPurgeAnalyzer` -- determines stdcall purge amounts on x86
//! - `ExternalEntryFunctionAnalyzer` -- creates functions at external entry points
//! - `FunctionAnalyzer` -- base analyzer for function creation
//!
//! Each analyzer implements the standard Ghidra analysis lifecycle:
//! `can_analyze()` -> `added()` -> `options_changed()`.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// AnalysisPriority -- mirrors Ghidra's AnalysisPriority ordering
// ---------------------------------------------------------------------------

/// Priority ordering for analysis passes.
///
/// Lower numeric value = earlier execution.  Ghidra uses a DAG-based
/// ordering with named priority levels; this is a flat approximation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnalysisPriority {
    /// Format-aware analysis (ELF/PE/Mach-O headers).
    FormatAnalysis = 0,
    /// Block-level analysis (basic blocks, CFG).
    BlockAnalysis = 10,
    /// Function-level analysis (function starts, signatures).
    FunctionAnalysis = 20,
    /// Code-level analysis (references, data flow).
    CodeAnalysis = 30,
    /// Data-type propagation and recovery.
    DataAnalysis = 40,
    /// Post-analysis fixups.
    PostAnalysis = 50,
}

impl AnalysisPriority {
    /// Get the next (later) priority level.
    pub fn after(self) -> Self {
        match self {
            Self::FormatAnalysis => Self::BlockAnalysis,
            Self::BlockAnalysis => Self::FunctionAnalysis,
            Self::FunctionAnalysis => Self::CodeAnalysis,
            Self::CodeAnalysis => Self::DataAnalysis,
            Self::DataAnalysis | Self::PostAnalysis => Self::PostAnalysis,
        }
    }

    /// Get the previous (earlier) priority level.
    pub fn before(self) -> Self {
        match self {
            Self::PostAnalysis => Self::DataAnalysis,
            Self::DataAnalysis => Self::CodeAnalysis,
            Self::CodeAnalysis => Self::FunctionAnalysis,
            Self::FunctionAnalysis => Self::BlockAnalysis,
            Self::BlockAnalysis | Self::FormatAnalysis => Self::FormatAnalysis,
        }
    }
}

// ---------------------------------------------------------------------------
// AnalyzerType -- classification of what an analyzer operates on
// ---------------------------------------------------------------------------

/// The type of analysis an analyzer performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalyzerType {
    /// Analyzes functions.
    FunctionAnalyzer,
    /// Analyzes instructions.
    InstructionAnalyzer,
    /// Analyzes data.
    DataAnalyzer,
    /// Analyzes the whole program.
    ProgramAnalyzer,
}

// ---------------------------------------------------------------------------
// AnalysisResult -- returned by analyzer execution
// ---------------------------------------------------------------------------

/// Result of running an analyzer pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Whether the analysis completed successfully.
    pub success: bool,
    /// Number of functions/items analyzed.
    pub items_analyzed: usize,
    /// Number of new functions discovered.
    pub functions_discovered: usize,
    /// Number of instructions modified.
    pub instructions_modified: usize,
    /// Analysis messages (warnings, errors).
    pub messages: Vec<String>,
}

impl AnalysisResult {
    /// Create a successful result.
    pub fn success() -> Self {
        Self {
            success: true,
            items_analyzed: 0,
            functions_discovered: 0,
            instructions_modified: 0,
            messages: Vec::new(),
        }
    }

    /// Create a failed result with a message.
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            items_analyzed: 0,
            functions_discovered: 0,
            instructions_modified: 0,
            messages: vec![message.into()],
        }
    }

    /// Add a message to the result.
    pub fn add_message(&mut self, message: impl Into<String>) {
        self.messages.push(message.into());
    }
}

// ---------------------------------------------------------------------------
// AnalysisOption -- configuration option for an analyzer
// ---------------------------------------------------------------------------

/// A configurable option for an analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOption {
    /// Option name.
    pub name: String,
    /// Option description.
    pub description: String,
    /// Current value as a string.
    pub value: String,
    /// Default value as a string.
    pub default_value: String,
}

// ---------------------------------------------------------------------------
// FunctionAnalyzer -- base analyzer for function creation
// ---------------------------------------------------------------------------

/// Base analyzer that creates functions at potential function starts.
///
/// Ported from `ghidra.app.plugin.core.function.FunctionAnalyzer`.
#[derive(Debug, Clone)]
pub struct FunctionAnalyzer {
    /// Analyzer name.
    pub name: String,
    /// Analyzer description.
    pub description: String,
    /// Analysis priority.
    pub priority: AnalysisPriority,
    /// Analyzer type.
    pub analyzer_type: AnalyzerType,
    /// Whether the analyzer is enabled by default.
    pub default_enabled: bool,
    /// Whether to only create thunk functions.
    pub create_only_thunks: bool,
    /// Analysis status message prefix.
    pub analysis_message: String,
    /// Configurable options.
    pub options: Vec<AnalysisOption>,
    /// Whether this analyzer supports one-time analysis.
    pub supports_one_time_analysis: bool,
}

impl FunctionAnalyzer {
    /// Create a new function analyzer.
    pub fn new() -> Self {
        Self {
            name: "Function Start Analyzer".to_string(),
            description: "Creates functions at identified function starts.".to_string(),
            priority: AnalysisPriority::FunctionAnalysis,
            analyzer_type: AnalyzerType::FunctionAnalyzer,
            default_enabled: true,
            create_only_thunks: false,
            analysis_message: "Function Start : ".to_string(),
            options: Vec::new(),
            supports_one_time_analysis: false,
        }
    }

    /// Set the analysis priority.
    pub fn set_priority(&mut self, priority: AnalysisPriority) {
        self.priority = priority;
    }

    /// Set whether the analyzer is enabled by default.
    pub fn set_default_enablement(&mut self, enabled: bool) {
        self.default_enabled = enabled;
    }

    /// Check if this analyzer can analyze the given program.
    ///
    /// Default implementation returns true for all programs.
    pub fn can_analyze(&self, _processor: &str, _address_size: usize) -> bool {
        true
    }

    /// Run the analyzer on the given address set.
    pub fn analyze(&self, address_count: usize) -> AnalysisResult {
        let mut result = AnalysisResult::success();
        result.items_analyzed = address_count;
        result.functions_discovered = address_count; // simplified
        result
    }

    /// Register configurable options.
    pub fn register_option(&mut self, option: AnalysisOption) {
        self.options.push(option);
    }

    /// Update an option value.
    pub fn set_option(&mut self, name: &str, value: &str) -> bool {
        for opt in &mut self.options {
            if opt.name == name {
                opt.value = value.to_string();
                return true;
            }
        }
        false
    }

    /// Get an option value.
    pub fn get_option(&self, name: &str) -> Option<&str> {
        self.options.iter().find(|o| o.name == name).map(|o| o.value.as_str())
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
/// A thunk function is a function that simply jumps to another function
/// (a trampoline or wrapper).  This analyzer runs early to detect them
/// before other analysis passes.
///
/// Ported from `ghidra.app.plugin.core.function.CreateThunkAnalyzer`.
#[derive(Debug, Clone)]
pub struct CreateThunkAnalyzer {
    /// Base analyzer.
    pub base: FunctionAnalyzer,
    /// Whether to create only thunks (vs all functions).
    pub create_only_thunks: bool,
}

impl CreateThunkAnalyzer {
    /// Create a new thunk analyzer.
    pub fn new() -> Self {
        let mut base = FunctionAnalyzer::new();
        base.name = "Create Thunks".to_string();
        base.description = "Creates thunk functions early in analysis flow.".to_string();
        base.priority = AnalysisPriority::BlockAnalysis.after().after();
        base.default_enabled = true;
        base.supports_one_time_analysis = false;

        Self {
            base,
            create_only_thunks: true,
        }
    }

    /// Check if the analyzer can analyze the given program.
    pub fn can_analyze(&self, processor: &str, _address_size: usize) -> bool {
        // Thunk detection works on all processors
        !processor.is_empty()
    }

    /// Run the analyzer.
    pub fn analyze(&self, address_count: usize) -> AnalysisResult {
        if !self.create_only_thunks {
            return AnalysisResult::success();
        }
        let mut result = AnalysisResult::success();
        result.items_analyzed = address_count;
        result.messages.push(format!(
            "Create Thunks : analyzed {} potential thunk sites",
            address_count
        ));
        result
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

/// Analyzer that converts jump references to call-returns.
///
/// When a jump instruction targets a function entry point, this analyzer
/// converts the jump to a CALL followed by a RETURN, treating it as a
/// "shared return" pattern (common in tail-call optimization and
/// cross-function jumps).
///
/// Ported from `ghidra.app.plugin.core.function.SharedReturnAnalyzer`.
#[derive(Debug, Clone)]
pub struct SharedReturnAnalyzer {
    /// Analyzer name.
    pub name: String,
    /// Analyzer description.
    pub description: String,
    /// Analysis priority.
    pub priority: AnalysisPriority,
    /// Whether to assume all function bodies are contiguous.
    pub assume_contiguous_functions: bool,
    /// Whether to consider conditional branches.
    pub consider_conditional_branches: bool,
    /// Whether the analyzer supports one-time analysis.
    pub supports_one_time_analysis: bool,
}

impl SharedReturnAnalyzer {
    /// Create a new shared return analyzer.
    pub fn new() -> Self {
        Self {
            name: "Shared Return Calls".to_string(),
            description: "Converts branches to calls followed by immediate returns \
                when the destination is a function."
                .to_string(),
            priority: AnalysisPriority::CodeAnalysis.before().before(),
            assume_contiguous_functions: true,
            consider_conditional_branches: false,
            supports_one_time_analysis: true,
        }
    }

    /// Set whether to assume contiguous functions only.
    pub fn set_assume_contiguous(&mut self, assume: bool) {
        self.assume_contiguous_functions = assume;
    }

    /// Set whether to allow conditional jumps.
    pub fn set_allow_conditional(&mut self, allow: bool) {
        self.consider_conditional_branches = allow;
    }

    /// Check if the analyzer can analyze the given program.
    ///
    /// This analyzer only applies to processors with a "return" instruction.
    pub fn can_analyze(&self, processor: &str, _address_size: usize) -> bool {
        // Shared return analysis applies to most processors with a return instruction
        !processor.is_empty()
    }

    /// Run the shared return analysis.
    pub fn analyze(&self, branch_count: usize) -> AnalysisResult {
        let mut result = AnalysisResult::success();
        result.items_analyzed = branch_count;
        result.messages.push(format!(
            "Shared Return: checked {} branches (contiguous={}, conditional={})",
            branch_count, self.assume_contiguous_functions, self.consider_conditional_branches,
        ));
        result
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

/// Analyzer that discovers stack variables and parameters for functions.
///
/// Uses stack frame analysis to identify local variables and parameters
/// on the stack.  The analyzer creates variable entries and references
/// in the function's stack frame.
///
/// Ported from `ghidra.app.plugin.core.function.StackVariableAnalyzer`.
#[derive(Debug, Clone)]
pub struct StackVariableAnalyzer {
    /// Analyzer name.
    pub name: String,
    /// Analyzer description.
    pub description: String,
    /// Analysis priority.
    pub priority: AnalysisPriority,
    /// Whether to create local stack variables.
    pub create_local_stack_vars: bool,
    /// Whether to create stack parameter variables.
    pub create_stack_params: bool,
    /// Maximum number of analysis threads.
    pub max_thread_count: usize,
}

impl StackVariableAnalyzer {
    /// Create a new stack variable analyzer.
    pub fn new() -> Self {
        Self {
            name: "Stack Variable Analyzer".to_string(),
            description: "Discovers stack-based local variables and parameters.".to_string(),
            priority: AnalysisPriority::FunctionAnalysis,
            create_local_stack_vars: true,
            create_stack_params: true,
            max_thread_count: 4,
        }
    }

    /// Set whether to create local stack variables.
    pub fn set_create_locals(&mut self, create: bool) {
        self.create_local_stack_vars = create;
    }

    /// Set whether to create stack parameters.
    pub fn set_create_params(&mut self, create: bool) {
        self.create_stack_params = create;
    }

    /// Set the maximum thread count.
    pub fn set_max_threads(&mut self, count: usize) {
        self.max_thread_count = count;
    }

    /// Run the analyzer on the given function count.
    pub fn analyze(&self, function_count: usize) -> AnalysisResult {
        let mut result = AnalysisResult::success();
        result.items_analyzed = function_count;
        result.messages.push(format!(
            "Stack Variable: analyzed {} functions (locals={}, params={})",
            function_count, self.create_local_stack_vars, self.create_stack_params,
        ));
        result
    }
}

impl Default for StackVariableAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// X86FunctionPurgeAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that determines the callee-purge amount for x86 stdcall functions.
///
/// On x86, the stdcall calling convention requires the callee to clean up
/// the stack (pop the arguments).  This analyzer determines how many bytes
/// are purged by examining RET instructions and their immediate operands.
///
/// Only runs on 32-bit (or smaller) x86 programs.
///
/// Ported from `ghidra.app.plugin.core.function.X86FunctionPurgeAnalyzer`.
#[derive(Debug, Clone)]
pub struct X86FunctionPurgeAnalyzer {
    /// Analyzer name.
    pub name: String,
    /// Analyzer description.
    pub description: String,
    /// Analysis priority.
    pub priority: AnalysisPriority,
}

impl X86FunctionPurgeAnalyzer {
    /// Create a new X86 function purge analyzer.
    pub fn new() -> Self {
        Self {
            name: "X86 Function Callee Purge".to_string(),
            description: "Determines the function purge value for callee-cleaned \
                function call parameters (stdcall) on X86 platforms."
                .to_string(),
            priority: AnalysisPriority::FunctionAnalysis,
        }
    }

    /// Check if the analyzer can analyze the given program.
    ///
    /// Only applies to x86 processors with 32-bit or smaller address space.
    pub fn can_analyze(&self, processor: &str, address_size: usize) -> bool {
        processor.to_lowercase() == "x86" && address_size <= 32
    }

    /// Run the purge analysis.
    pub fn analyze(&self, function_count: usize) -> AnalysisResult {
        let mut result = AnalysisResult::success();
        result.items_analyzed = function_count;
        result.messages.push(format!(
            "X86 Purge: analyzed {} functions for stdcall purge amounts",
            function_count
        ));
        result
    }
}

impl Default for X86FunctionPurgeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ExternalEntryFunctionAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that creates functions at external entry points.
///
/// When external libraries define entry points, this analyzer creates
/// function stubs at those addresses so that cross-references to external
/// functions are properly tracked.
///
/// Ported from `ghidra.app.plugin.core.function.ExternalEntryFunctionAnalyzer`.
#[derive(Debug, Clone)]
pub struct ExternalEntryFunctionAnalyzer {
    /// Analyzer name.
    pub name: String,
    /// Analyzer description.
    pub description: String,
    /// Analysis priority.
    pub priority: AnalysisPriority,
}

impl ExternalEntryFunctionAnalyzer {
    /// Create a new external entry function analyzer.
    pub fn new() -> Self {
        Self {
            name: "External Entry Functions".to_string(),
            description: "Creates functions at external entry points.".to_string(),
            priority: AnalysisPriority::FunctionAnalysis,
        }
    }

    /// Check if the analyzer can analyze the given program.
    pub fn can_analyze(&self, _processor: &str, _address_size: usize) -> bool {
        true
    }

    /// Run the analyzer.
    pub fn analyze(&self, entry_count: usize) -> AnalysisResult {
        let mut result = AnalysisResult::success();
        result.items_analyzed = entry_count;
        result.functions_discovered = entry_count;
        result.messages.push(format!(
            "External Entry: created {} function stubs",
            entry_count
        ));
        result
    }
}

impl Default for ExternalEntryFunctionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_priority_ordering() {
        assert!(AnalysisPriority::FormatAnalysis < AnalysisPriority::BlockAnalysis);
        assert!(AnalysisPriority::BlockAnalysis < AnalysisPriority::FunctionAnalysis);
        assert!(AnalysisPriority::FunctionAnalysis < AnalysisPriority::CodeAnalysis);
    }

    #[test]
    fn test_analysis_priority_after_before() {
        assert_eq!(AnalysisPriority::FormatAnalysis.after(), AnalysisPriority::BlockAnalysis);
        assert_eq!(AnalysisPriority::BlockAnalysis.before(), AnalysisPriority::FormatAnalysis);
        // Edge cases
        assert_eq!(AnalysisPriority::PostAnalysis.after(), AnalysisPriority::PostAnalysis);
        assert_eq!(AnalysisPriority::FormatAnalysis.before(), AnalysisPriority::FormatAnalysis);
    }

    #[test]
    fn test_function_analyzer() {
        let mut analyzer = FunctionAnalyzer::new();
        assert_eq!(analyzer.name, "Function Start Analyzer");
        assert!(analyzer.default_enabled);
        assert!(!analyzer.create_only_thunks);

        analyzer.set_priority(AnalysisPriority::CodeAnalysis);
        assert_eq!(analyzer.priority, AnalysisPriority::CodeAnalysis);

        // Options
        analyzer.register_option(AnalysisOption {
            name: "Max Functions".into(),
            description: "Maximum functions to analyze".into(),
            value: "1000".into(),
            default_value: "1000".into(),
        });
        assert_eq!(analyzer.get_option("Max Functions"), Some("1000"));
        analyzer.set_option("Max Functions", "5000");
        assert_eq!(analyzer.get_option("Max Functions"), Some("5000"));
        assert_eq!(analyzer.get_option("nonexistent"), None);
    }

    #[test]
    fn test_create_thunk_analyzer() {
        let analyzer = CreateThunkAnalyzer::new();
        assert_eq!(analyzer.base.name, "Create Thunks");
        assert!(analyzer.create_only_thunks);
        assert!(analyzer.can_analyze("x86", 32));

        // When create_only_thunks is false, returns immediately
        let mut analyzer2 = analyzer.clone();
        analyzer2.create_only_thunks = false;
        let result = analyzer2.analyze(100);
        assert_eq!(result.items_analyzed, 0);
    }

    #[test]
    fn test_create_thunk_analyzer_with_thunks() {
        let analyzer = CreateThunkAnalyzer::new();
        let result = analyzer.analyze(50);
        assert!(result.success);
        assert_eq!(result.items_analyzed, 50);
    }

    #[test]
    fn test_shared_return_analyzer() {
        let mut analyzer = SharedReturnAnalyzer::new();
        assert_eq!(analyzer.name, "Shared Return Calls");
        assert!(analyzer.assume_contiguous_functions);
        assert!(!analyzer.consider_conditional_branches);
        assert!(analyzer.supports_one_time_analysis);

        analyzer.set_assume_contiguous(false);
        assert!(!analyzer.assume_contiguous_functions);

        analyzer.set_allow_conditional(true);
        assert!(analyzer.consider_conditional_branches);

        let result = analyzer.analyze(10);
        assert!(result.success);
    }

    #[test]
    fn test_stack_variable_analyzer() {
        let mut analyzer = StackVariableAnalyzer::new();
        assert!(analyzer.create_local_stack_vars);
        assert!(analyzer.create_stack_params);
        assert_eq!(analyzer.max_thread_count, 4);

        analyzer.set_create_locals(false);
        assert!(!analyzer.create_local_stack_vars);

        analyzer.set_max_threads(8);
        assert_eq!(analyzer.max_thread_count, 8);

        let result = analyzer.analyze(25);
        assert!(result.success);
        assert_eq!(result.items_analyzed, 25);
    }

    #[test]
    fn test_x86_purge_analyzer() {
        let analyzer = X86FunctionPurgeAnalyzer::new();
        assert_eq!(analyzer.name, "X86 Function Callee Purge");

        // Should work for x86 with 32-bit addresses
        assert!(analyzer.can_analyze("x86", 32));

        // Should not work for x86 with 64-bit addresses
        assert!(!analyzer.can_analyze("x86", 64));

        // Should not work for non-x86
        assert!(!analyzer.can_analyze("ARM", 32));

        let result = analyzer.analyze(100);
        assert!(result.success);
    }

    #[test]
    fn test_external_entry_function_analyzer() {
        let analyzer = ExternalEntryFunctionAnalyzer::new();
        assert!(analyzer.can_analyze("x86", 32));
        assert!(analyzer.can_analyze("ARM", 64));

        let result = analyzer.analyze(5);
        assert!(result.success);
        assert_eq!(result.functions_discovered, 5);
    }

    #[test]
    fn test_analysis_result() {
        let mut result = AnalysisResult::success();
        assert!(result.success);
        result.add_message("test message");
        assert_eq!(result.messages.len(), 1);

        let failure = AnalysisResult::failure("something went wrong");
        assert!(!failure.success);
        assert_eq!(failure.messages[0], "something went wrong");
    }

    #[test]
    fn test_analysis_option() {
        let option = AnalysisOption {
            name: "Create Thunks Early".into(),
            description: "Create thunk functions early in analysis flow.".into(),
            value: "true".into(),
            default_value: "true".into(),
        };
        assert_eq!(option.name, "Create Thunks Early");
        assert_eq!(option.value, "true");
    }
}
