//! ConstantPropagationAnalyzer and AnalysisConstantPropagationEvaluator.
//!
//! Ported from Ghidra's:
//! - `ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer`
//! - `ghidra.app.plugin.core.analysis.AnalysisConstantPropagationEvaluator`
//!
//! The constant propagation analyzer performs multi-instruction constant
//! propagation using a symbolic evaluator. It tracks register values
//! through instruction sequences and creates references when a computed
//! value resolves to a constant address.

use std::collections::{HashMap, HashSet};

use crate::base::analyzer::{
    AbstractAnalyzer, Address, AddressSet, AnalysisOption, AnalysisOptionValue,
    AnalysisPriority, Analyzer, AnalyzerType, CancelledError, MessageLog, Program, TaskMonitor,
};

// ---------------------------------------------------------------------------
// ConstantPropagationAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that finds constant references computed via multiple instructions.
///
/// Ported from Ghidra's `ConstantPropagationAnalyzer`. This analyzer uses
/// symbolic propagation to track values through register assignments and
/// identifies when a computed value is a constant that can be used as a
/// memory reference.
///
/// # Options
///
/// - `check_param_refs` -- Check parameter references (default: true)
/// - `check_pointer_param_refs` -- Check pointer parameter refs (default: true)
/// - `check_stored_refs` -- Check stored references (default: true)
/// - `trust_write_mem` -- Trust reads from writable memory (default: false)
/// - `create_complex_data_from_pointers` -- Create data from pointers (default: false)
/// - `max_speculative_ref_address` -- Max speculative reference offset (default: 256)
pub struct ConstantPropagationAnalyzer {
    base: AbstractAnalyzer,
    check_param_refs: bool,
    check_pointer_param_refs: bool,
    check_stored_refs: bool,
    trust_write_mem: bool,
    create_complex_data_from_pointers: bool,
    max_speculative_ref_address: i64,
}

impl ConstantPropagationAnalyzer {
    /// Option name for checking parameter references.
    pub const OPTION_PARAM_REFS: &'static str = "Param Refs";
    /// Option name for checking pointer parameter references.
    pub const OPTION_POINTER_PARAM_REFS: &'static str = "Pointer Param Refs";
    /// Option name for checking stored references.
    pub const OPTION_STORED_REFS: &'static str = "Stored Refs";
    /// Option name for trusting writable memory reads.
    pub const OPTION_TRUST_WRITE_MEM: &'static str = "Trust Write Mem";
    /// Option name for creating complex data from pointers.
    pub const OPTION_CREATE_COMPLEX_DATA: &'static str = "Create Data from pointer";
    /// Option name for max speculative reference address.
    pub const OPTION_MAX_SPECULATIVE_REF: &'static str = "Speculative reference max";

    /// Default values for options.
    pub const PARAM_REFS_DEFAULT: bool = true;
    pub const POINTER_PARAM_REFS_DEFAULT: bool = true;
    pub const STORED_REFS_DEFAULT: bool = true;
    pub const TRUST_WRITE_MEM_DEFAULT: bool = false;
    pub const CREATE_COMPLEX_DATA_DEFAULT: bool = false;
    pub const MAX_SPECULATIVE_REF_DEFAULT: i64 = 256;

    /// Notification interval for progress updates.
    pub const NOTIFICATION_INTERVAL: usize = 100;

    /// Create a new constant propagation analyzer.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Constant Reference Analyzer",
            "Constant Propagation Analyzer for constant references computed with multiple instructions.",
            AnalyzerType::Function,
        );
        base.set_priority(AnalysisPriority::LOW_PRIORITY);
        base.set_supports_one_time_analysis(true);

        Self {
            base,
            check_param_refs: Self::PARAM_REFS_DEFAULT,
            check_pointer_param_refs: Self::POINTER_PARAM_REFS_DEFAULT,
            check_stored_refs: Self::STORED_REFS_DEFAULT,
            trust_write_mem: Self::TRUST_WRITE_MEM_DEFAULT,
            create_complex_data_from_pointers: Self::CREATE_COMPLEX_DATA_DEFAULT,
            max_speculative_ref_address: Self::MAX_SPECULATIVE_REF_DEFAULT,
        }
    }

    /// Whether to check parameter references.
    pub fn check_param_refs(&self) -> bool {
        self.check_param_refs
    }

    /// Whether to trust reads from writable memory.
    pub fn trust_write_mem(&self) -> bool {
        self.trust_write_mem
    }

    /// Maximum speculative reference address offset.
    pub fn max_speculative_ref_address(&self) -> i64 {
        self.max_speculative_ref_address
    }

    /// Perform constant propagation on a function.
    ///
    /// This is the core analysis logic that propagates constants through
    /// the function's instruction flow.
    fn propagate_constants(
        &self,
        _program: &mut Program,
        _func_addr: &Address,
        monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        // In the full implementation, this would:
        // 1. Create a SymbolicPropagator for the function
        // 2. Set up the AnalysisConstantPropagationEvaluator
        // 3. Run the propagation to collect constant values
        // 4. Create references for discovered constant addresses
        monitor.check_cancelled()?;
        Ok(false)
    }
}

impl Analyzer for ConstantPropagationAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn description(&self) -> &str {
        self.base.description()
    }

    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }

    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }

    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    fn can_analyze(&self, program: &Program) -> bool {
        // Can analyze any program
        !program.memory.is_empty()
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        let mut changes = false;
        for range in set.iter() {
            monitor.check_cancelled()?;
            if self.propagate_constants(program, &range.start, monitor, log)? {
                changes = true;
            }
        }
        Ok(changes)
    }

    fn register_options(&self, _program: &Program) -> Vec<AnalysisOption> {
        vec![
            AnalysisOption {
                name: Self::OPTION_PARAM_REFS.to_string(),
                description: "Check parameter references".to_string(),
                default_value: AnalysisOptionValue::Bool(Self::PARAM_REFS_DEFAULT),
                current_value: AnalysisOptionValue::Bool(Self::PARAM_REFS_DEFAULT),
            },
            AnalysisOption {
                name: Self::OPTION_POINTER_PARAM_REFS.to_string(),
                description: "Check pointer parameter references".to_string(),
                default_value: AnalysisOptionValue::Bool(Self::POINTER_PARAM_REFS_DEFAULT),
                current_value: AnalysisOptionValue::Bool(Self::POINTER_PARAM_REFS_DEFAULT),
            },
            AnalysisOption {
                name: Self::OPTION_STORED_REFS.to_string(),
                description: "Check stored references".to_string(),
                default_value: AnalysisOptionValue::Bool(Self::STORED_REFS_DEFAULT),
                current_value: AnalysisOptionValue::Bool(Self::STORED_REFS_DEFAULT),
            },
            AnalysisOption {
                name: Self::OPTION_TRUST_WRITE_MEM.to_string(),
                description: "Trust reads from writable memory".to_string(),
                default_value: AnalysisOptionValue::Bool(Self::TRUST_WRITE_MEM_DEFAULT),
                current_value: AnalysisOptionValue::Bool(Self::TRUST_WRITE_MEM_DEFAULT),
            },
            AnalysisOption {
                name: Self::OPTION_CREATE_COMPLEX_DATA.to_string(),
                description: "Create complex data types from pointers if the data type is known".to_string(),
                default_value: AnalysisOptionValue::Bool(Self::CREATE_COMPLEX_DATA_DEFAULT),
                current_value: AnalysisOptionValue::Bool(Self::CREATE_COMPLEX_DATA_DEFAULT),
            },
            AnalysisOption {
                name: Self::OPTION_MAX_SPECULATIVE_REF.to_string(),
                description: "Maximum speculative reference address offset from the end of memory".to_string(),
                default_value: AnalysisOptionValue::Integer(Self::MAX_SPECULATIVE_REF_DEFAULT),
                current_value: AnalysisOptionValue::Integer(Self::MAX_SPECULATIVE_REF_DEFAULT),
            },
        ]
    }

    fn options_changed(&mut self, options: &HashMap<String, AnalysisOptionValue>) {
        if let Some(AnalysisOptionValue::Bool(v)) = options.get(Self::OPTION_PARAM_REFS) {
            self.check_param_refs = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = options.get(Self::OPTION_POINTER_PARAM_REFS) {
            self.check_pointer_param_refs = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = options.get(Self::OPTION_STORED_REFS) {
            self.check_stored_refs = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = options.get(Self::OPTION_TRUST_WRITE_MEM) {
            self.trust_write_mem = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = options.get(Self::OPTION_CREATE_COMPLEX_DATA) {
            self.create_complex_data_from_pointers = *v;
        }
        if let Some(AnalysisOptionValue::Integer(v)) = options.get(Self::OPTION_MAX_SPECULATIVE_REF) {
            self.max_speculative_ref_address = *v;
        }
    }

    fn supports_one_time_analysis(&self) -> bool {
        true
    }
}

impl Default for ConstantPropagationAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AnalysisConstantPropagationEvaluator
// ---------------------------------------------------------------------------

/// Evaluator used by the symbolic propagator during constant propagation.
///
/// Ported from Ghidra's `AnalysisConstantPropagationEvaluator`. This evaluator
/// determines whether computed values are valid for creating references.
/// It filters out problematic values like small constants (0-256),
/// `0xffffffff`, `0xffff`, `0xfffffffe` that would create false references.
///
/// Extend this (in Rust, compose with additional logic) for
/// processor-specific behaviors (e.g., PowerPC).
///
/// # Default Filtering
///
/// The base implementation skips references to:
/// - Addresses in the range 0-256 (null page / interrupt vectors)
/// - `0xFFFFFFFF` (common sentinel)
/// - `0xFFFF` (16-bit sentinel)
/// - `0xFFFFFFFE` (near-max sentinel)
pub struct AnalysisConstantPropagationEvaluator {
    /// Address set of computed jump destinations where the flow is unknown.
    dest_set: AddressSet,
    /// Whether to trust values read from writable memory.
    trust_memory_write: bool,
    /// Minimum storage address offset from the end of memory.
    min_speculative_ref_address: i64,
    /// Maximum storage address offset from the end of memory.
    max_speculative_ref_address: i64,
    /// Maximum Unicode string length to check.
    max_unicode_string_len: usize,
    /// Maximum character string length to check.
    max_char_string_len: usize,
    /// Values to reject as invalid constants.
    rejected_values: HashSet<u64>,
}

impl AnalysisConstantPropagationEvaluator {
    /// The null terminator probe value.
    pub const NULL_TERMINATOR_PROBE: i32 = -1;

    /// Create a new evaluator with default settings.
    pub fn new() -> Self {
        let mut rejected_values = HashSet::new();
        // Common problematic values that should not create references
        for v in 0..=256u64 {
            rejected_values.insert(v);
        }
        rejected_values.insert(0xFFFF);
        rejected_values.insert(0xFFFFFFFE);
        rejected_values.insert(0xFFFFFFFF);
        rejected_values.insert(0xFFFFFFFF_FFFFFFFF);

        Self {
            dest_set: AddressSet::new(),
            trust_memory_write: false,
            min_speculative_ref_address: 0,
            max_speculative_ref_address: 256,
            max_unicode_string_len: 200,
            max_char_string_len: 100,
            rejected_values,
        }
    }

    /// Create a new evaluator with specified trust setting.
    pub fn with_trust_memory_write(trust: bool) -> Self {
        let mut eval = Self::new();
        eval.trust_memory_write = trust;
        eval
    }

    /// Create a new evaluator with full configuration.
    pub fn with_config(
        trust_memory_write: bool,
        min_speculative_ref: i64,
        max_speculative_ref: i64,
    ) -> Self {
        let mut eval = Self::new();
        eval.trust_memory_write = trust_memory_write;
        eval.min_speculative_ref_address = min_speculative_ref;
        eval.max_speculative_ref_address = max_speculative_ref;
        eval
    }

    /// Get the destination address set (computed jump flows where flow is unknown).
    pub fn dest_set(&self) -> &AddressSet {
        &self.dest_set
    }

    /// Get a mutable reference to the destination address set.
    pub fn dest_set_mut(&mut self) -> &mut AddressSet {
        &mut self.dest_set
    }

    /// Whether memory writes are trusted.
    pub fn trust_memory_write(&self) -> bool {
        self.trust_memory_write
    }

    /// Evaluate whether a constant value is valid for creating a reference.
    ///
    /// Returns `true` if the value should be used to create a reference.
    pub fn evaluate_constant(&self, value: u64) -> bool {
        !self.rejected_values.contains(&value)
    }

    /// Evaluate whether a reference to the given address should be created.
    ///
    /// Returns `true` if the reference is valid.
    pub fn evaluate_reference(&self, addr: &Address) -> bool {
        if self.rejected_values.contains(&addr.offset) {
            return false;
        }
        true
    }

    /// Add a destination address (computed jump target with unknown flow).
    pub fn add_destination(&mut self, addr: Address) {
        self.dest_set.add(addr);
    }

    /// Check if a value is within the speculative reference range.
    pub fn is_speculative_reference(&self, value: u64, memory_end: u64) -> bool {
        let offset = value as i64 - memory_end as i64;
        offset >= self.min_speculative_ref_address && offset <= self.max_speculative_ref_address
    }
}

impl Default for AnalysisConstantPropagationEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_propagation_analyzer_creation() {
        let analyzer = ConstantPropagationAnalyzer::new();
        assert_eq!(analyzer.name(), "Constant Reference Analyzer");
        assert_eq!(analyzer.analysis_type(), AnalyzerType::Function);
        assert!(analyzer.supports_one_time_analysis());
        assert!(analyzer.check_param_refs());
        assert!(!analyzer.trust_write_mem());
        assert_eq!(analyzer.max_speculative_ref_address(), 256);
    }

    #[test]
    fn test_analyzer_options() {
        let analyzer = ConstantPropagationAnalyzer::new();
        let options = analyzer.register_options(&Program::default());
        assert_eq!(options.len(), 6);
        assert!(options.iter().any(|o| o.name == ConstantPropagationAnalyzer::OPTION_PARAM_REFS));
        assert!(options.iter().any(|o| o.name == ConstantPropagationAnalyzer::OPTION_TRUST_WRITE_MEM));
    }

    #[test]
    fn test_analyzer_options_changed() {
        let mut analyzer = ConstantPropagationAnalyzer::new();
        let mut options = HashMap::new();
        options.insert(
            ConstantPropagationAnalyzer::OPTION_TRUST_WRITE_MEM.to_string(),
            AnalysisOptionValue::Bool(true),
        );
        options.insert(
            ConstantPropagationAnalyzer::OPTION_MAX_SPECULATIVE_REF.to_string(),
            AnalysisOptionValue::Integer(512),
        );
        analyzer.options_changed(&options);
        assert!(analyzer.trust_write_mem());
        assert_eq!(analyzer.max_speculative_ref_address(), 512);
    }

    #[test]
    fn test_context_evaluator_default() {
        let eval = AnalysisConstantPropagationEvaluator::new();
        assert!(!eval.trust_memory_write());
        assert!(eval.dest_set().is_empty());
    }

    #[test]
    fn test_context_evaluator_rejected_values() {
        let eval = AnalysisConstantPropagationEvaluator::new();
        // Small values should be rejected
        assert!(!eval.evaluate_constant(0));
        assert!(!eval.evaluate_constant(1));
        assert!(!eval.evaluate_constant(256));
        assert!(!eval.evaluate_constant(0xFFFF));
        assert!(!eval.evaluate_constant(0xFFFFFFFE));
        assert!(!eval.evaluate_constant(0xFFFFFFFF));
        // Valid values should pass
        assert!(eval.evaluate_constant(0x10000));
        assert!(eval.evaluate_constant(0x400000));
    }

    #[test]
    fn test_context_evaluator_with_trust() {
        let eval = AnalysisConstantPropagationEvaluator::with_trust_memory_write(true);
        assert!(eval.trust_memory_write());
    }

    #[test]
    fn test_context_evaluator_with_config() {
        let eval = AnalysisConstantPropagationEvaluator::with_config(true, 0, 512);
        assert!(eval.trust_memory_write());
        assert!(eval.is_speculative_reference(0x1000 + 100, 0x1000));
        assert!(!eval.is_speculative_reference(0x1000 + 600, 0x1000));
    }

    #[test]
    fn test_context_evaluator_dest_set() {
        let mut eval = AnalysisConstantPropagationEvaluator::new();
        eval.add_destination(Address::new(0x401000));
        eval.add_destination(Address::new(0x402000));
        assert!(!eval.dest_set().is_empty());
        assert!(eval.dest_set().contains(&Address::new(0x401000)));
    }

    #[test]
    fn test_context_evaluator_evaluate_reference() {
        let eval = AnalysisConstantPropagationEvaluator::new();
        assert!(!eval.evaluate_reference(&Address::new(0)));
        assert!(!eval.evaluate_reference(&Address::new(256)));
        assert!(eval.evaluate_reference(&Address::new(0x400000)));
    }
}
