//! Lisa analyzer -- orchestrates abstract interpretation analyses on p-code CFGs.
//!
//! Ported from the analysis logic inside `LisaPlugin.java` and
//! `LisaTaintState.java` in Ghidra's Lisa extension.
//!
//! The analyzer coordinates:
//! 1. CFG collection (building control-flow graphs via [`PcodeFrontend`])
//! 2. Configuration of abstract domains (heap, type, value)
//! 3. Fixpoint execution over the collected CFGs
//! 4. Result collection per function
//!
//! # Key Types
//!
//! - [`LisaAnalyzer`] -- The top-level analyzer that runs abstract interpretation
//! - [`AnalysisConfig`] -- Configuration controlling which abstract domains to use
//! - [`AnalysisResult`] -- Results produced for a single function
//! - [`DomainConfig`] -- Enum-based domain selection for heap, type, and value domains

use std::collections::{HashMap, HashSet};

use super::pcode_frontend::{PcodeFrontend, PcodeOp};

// ---------------------------------------------------------------------------
// Domain configuration enums
// ---------------------------------------------------------------------------

/// Heap abstract domain selection.
///
/// Ported from `LisaOptions.HeapDomainOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeapDomainOption {
    /// Monolithic heap abstraction.
    Monolithic,
    /// Point-based heap abstraction.
    PointBased,
    /// Field-sensitive point-based heap.
    FieldSensitivePointBased,
    /// Type-based heap abstraction.
    TypeBased,
    /// Default (monolithic).
    Default,
}

impl Default for HeapDomainOption {
    fn default() -> Self {
        Self::Default
    }
}

impl std::fmt::Display for HeapDomainOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monolithic => write!(f, "Monolithic"),
            Self::PointBased => write!(f, "PointBased"),
            Self::FieldSensitivePointBased => write!(f, "FieldSensitivePointBased"),
            Self::TypeBased => write!(f, "TypeBased"),
            Self::Default => write!(f, "DEFAULT(Monolithic)"),
        }
    }
}

/// Type abstract domain selection.
///
/// Ported from `LisaOptions.TypeDomainOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeDomainOption {
    /// Inferred types.
    Inferred,
    /// Static types.
    Static,
    /// Default (inferred).
    Default,
}

impl Default for TypeDomainOption {
    fn default() -> Self {
        Self::Default
    }
}

impl std::fmt::Display for TypeDomainOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inferred => write!(f, "Inferred"),
            Self::Static => write!(f, "Static"),
            Self::Default => write!(f, "DEFAULT(Inferred)"),
        }
    }
}

/// Value abstract domain selection.
///
/// Ported from `LisaOptions.ValueDomainOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueDomainOption {
    /// Constant propagation (byte-based).
    ConstantPropagation,
    /// Interval domain.
    Interval,
    /// Interval domain (low x86 variant).
    IntervalLowX86,
    /// Non-redundant powerset of intervals.
    PowersetInterval,
    /// Parity domain.
    Parity,
    /// Pentagon domain (interval + parity + sign + relations).
    Pentagon,
    /// Pentagon domain (low x86 variant).
    PentagonLowX86,
    /// Sign domain.
    Sign,
    /// Upper bounds domain.
    UpperBounds,
    /// Dataflow: available expressions.
    AvailableExpressions,
    /// Dataflow: constant propagation (dataflow version).
    DataflowConstantPropagation,
    /// Dataflow: reaching definitions.
    ReachingDefinitions,
    /// Dataflow: liveness.
    Liveness,
    /// Taint analysis (two-level).
    Taint,
    /// Three-level taint analysis.
    ThreeLevelTaint,
    /// Non-interference.
    NonInterference,
    /// Stability domain.
    Stability,
    /// Default (interval).
    Default,
}

impl Default for ValueDomainOption {
    fn default() -> Self {
        Self::Default
    }
}

impl std::fmt::Display for ValueDomainOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConstantPropagation => write!(f, "Numeric: ConstantPropagation"),
            Self::Interval => write!(f, "Numeric: Interval"),
            Self::IntervalLowX86 => write!(f, "Numeric: Interval (Low X86)"),
            Self::PowersetInterval => write!(f, "Numeric: NonRedundantPowersetOfInterval"),
            Self::Parity => write!(f, "Numeric: Parity"),
            Self::Pentagon => write!(f, "Numeric: Pentagon"),
            Self::PentagonLowX86 => write!(f, "Numeric: Pentagon (Low X86)"),
            Self::Sign => write!(f, "Numeric: Sign"),
            Self::UpperBounds => write!(f, "Numeric: UpperBound"),
            Self::AvailableExpressions => write!(f, "Dataflow: AvailableExpressions"),
            Self::DataflowConstantPropagation => write!(f, "Dataflow: ConstantPropagation"),
            Self::ReachingDefinitions => write!(f, "Dataflow: ReachingDefinitions"),
            Self::Liveness => write!(f, "Dataflow: Liveness"),
            Self::Taint => write!(f, "Dataflow: Taint"),
            Self::ThreeLevelTaint => write!(f, "Dataflow: ThreeLevelTaint"),
            Self::NonInterference => write!(f, "NonInterference"),
            Self::Stability => write!(f, "Stability"),
            Self::Default => write!(f, "DEFAULT(Interval)"),
        }
    }
}

/// Interprocedural analysis policy.
///
/// Ported from `LisaOptions.InterproceduralOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterproceduralOption {
    /// Context-based analysis.
    ContextBased,
    /// Context-based with full-stack token.
    ContextBasedFullStack,
    /// Context-based with k-depth token.
    ContextBasedKDepth,
    /// Context-based with last-call token.
    ContextBasedLastCall,
    /// Context-based with context-insensitive token.
    ContextBasedInsensitive,
    /// Backward modular worst-case analysis.
    BackwardModularWorstCase,
    /// Modular worst-case analysis (default).
    ModularWorstCase,
}

impl Default for InterproceduralOption {
    fn default() -> Self {
        Self::ModularWorstCase
    }
}

/// Descending phase type for fixpoint iteration.
///
/// Ported from `LisaOptions.DescendingPhaseOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DescendingPhaseOption {
    /// Narrowing phase.
    Narrowing,
    /// GLB k-times.
    Glb,
    /// None (default).
    None,
}

impl Default for DescendingPhaseOption {
    fn default() -> Self {
        Self::None
    }
}

/// Open call policy.
///
/// Ported from `LisaOptions.CallOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallPolicyOption {
    /// Return top for unresolved calls.
    ReturnTop,
    /// Worst-case assumption (default).
    WorstCase,
}

impl Default for CallPolicyOption {
    fn default() -> Self {
        Self::WorstCase
    }
}

/// Output graph format.
///
/// Ported from `LisaOptions.GraphOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GraphOption {
    /// HTML output.
    Html,
    /// HTML with subnodes.
    HtmlWithSubnodes,
    /// Dot (Graphviz) output.
    Dot,
    /// GraphML output.
    GraphMl,
    /// GraphML with subnodes.
    GraphMlWithSubnodes,
    /// No output (default).
    None,
}

impl Default for GraphOption {
    fn default() -> Self {
        Self::None
    }
}

/// Call graph construction algorithm.
///
/// Ported from `LisaOptions.CallGraphOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallGraphOption {
    /// Class Hierarchy Analysis.
    Cha,
    /// Rapid Type Analysis (default).
    Rta,
}

impl Default for CallGraphOption {
    fn default() -> Self {
        Self::Rta
    }
}

// ---------------------------------------------------------------------------
// AnalysisConfig -- full configuration for a LISA analysis run
// ---------------------------------------------------------------------------

/// Full configuration for a LISA analysis run.
///
/// Ported from `LisaOptions` -- combines all domain and policy options
/// into a single configuration struct.
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Heap abstract domain.
    pub heap_domain: HeapDomainOption,
    /// Type abstract domain.
    pub type_domain: TypeDomainOption,
    /// Value abstract domain.
    pub value_domain: ValueDomainOption,
    /// Interprocedural analysis policy.
    pub interprocedural: InterproceduralOption,
    /// Descending phase type.
    pub descending_phase: DescendingPhaseOption,
    /// Open call policy.
    pub call_policy: CallPolicyOption,
    /// Output graph format.
    pub graph_format: GraphOption,
    /// Call graph algorithm.
    pub call_graph: CallGraphOption,
    /// Whether to evaluate post-state (vs pre-state).
    pub post_state: bool,
    /// Whether to display top values.
    pub show_top: bool,
    /// Whether to display unique values.
    pub show_unique: bool,
    /// Whether to use high p-code (experimental).
    pub use_high_pcode: bool,
    /// Depth for CFG computation (0 = only current function).
    pub cfg_depth: usize,
    /// Threshold for GLB or k-depth token.
    pub threshold: usize,
    /// Output working directory.
    pub output_dir: String,
    /// Whether to serialize results.
    pub serialize_results: bool,
    /// Whether to optimize results.
    pub optimize: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            heap_domain: HeapDomainOption::default(),
            type_domain: TypeDomainOption::default(),
            value_domain: ValueDomainOption::default(),
            interprocedural: InterproceduralOption::default(),
            descending_phase: DescendingPhaseOption::default(),
            call_policy: CallPolicyOption::default(),
            graph_format: GraphOption::default(),
            call_graph: CallGraphOption::default(),
            post_state: false,
            show_top: false,
            show_unique: false,
            use_high_pcode: false,
            cfg_depth: 0,
            threshold: 5,
            output_dir: String::new(),
            serialize_results: false,
            optimize: false,
        }
    }
}

impl AnalysisConfig {
    /// Get the top value representation string for the current value domain.
    ///
    /// Ported from `LisaOptions.getTopValue()`.
    pub fn top_value_representation(&self) -> &'static str {
        match self.value_domain {
            ValueDomainOption::Interval
            | ValueDomainOption::IntervalLowX86
            | ValueDomainOption::Pentagon
            | ValueDomainOption::PentagonLowX86
            | ValueDomainOption::PowersetInterval => "[-Inf, +Inf]",
            ValueDomainOption::UpperBounds => "{}",
            ValueDomainOption::Stability => "=",
            ValueDomainOption::NonInterference => "HL",
            ValueDomainOption::Taint | ValueDomainOption::ThreeLevelTaint => "_",
            _ => "#TOP#",
        }
    }

    /// Build the active query name for display.
    ///
    /// Ported from `LisaPlugin.getActiveQueryName()`.
    pub fn active_query_name(&self, current_function: Option<&str>) -> String {
        let mut name = self.value_domain.to_string();
        if self.heap_domain != HeapDomainOption::Default {
            name.push(':');
            name.push_str(&self.heap_domain.to_string());
        }
        if self.type_domain != TypeDomainOption::Default {
            name.push(':');
            name.push_str(&self.type_domain.to_string());
        }
        if let Some(func) = current_function {
            name.push_str(" @ ");
            name.push_str(func);
        }
        name
    }
}

// ---------------------------------------------------------------------------
// Taint mark types
// ---------------------------------------------------------------------------

/// Taint mark type for source/sink/gate labeling.
///
/// Ported from `TaintState.MarkType` used in `LisaTaintState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MarkType {
    /// Taint source.
    Source,
    /// Taint sink.
    Sink,
    /// Taint gate (sanitizer).
    Gate,
}

// ---------------------------------------------------------------------------
// AnalysisResult -- per-function results
// ---------------------------------------------------------------------------

/// Results produced by the analyzer for a single function.
///
/// Ported from the per-function result collection in
/// `LisaPlugin.performAnalysis()`.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Function entry point address.
    pub function_address: u64,
    /// Function name.
    pub function_name: String,
    /// Per-statement analysis states (statement address -> state representation).
    pub statement_states: HashMap<u64, StatementState>,
}

/// Analysis state for a single statement.
///
/// Represents the abstract state before or after a p-code statement,
/// as produced by the fixpoint analysis.
#[derive(Debug, Clone)]
pub struct StatementState {
    /// Statement address.
    pub address: u64,
    /// Key-value pairs for value domain state (identifier -> value representation).
    pub value_state: HashMap<String, String>,
    /// Key-value pairs for type domain state (identifier -> type representation).
    pub type_state: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// LisaAnalyzer -- the top-level analyzer
// ---------------------------------------------------------------------------

/// Top-level LISA analyzer that orchestrates abstract interpretation.
///
/// Ported from the analysis logic in `LisaPlugin.java`. This struct
/// manages:
/// - CFG collection via [`PcodeFrontend`]
/// - Configuration of abstract domains
/// - Taint source/sink/gate markers
/// - Result collection per function
///
/// # Usage
///
/// ```rust
/// use ghidra_features::lisa::lisa_analyzer::*;
/// use ghidra_features::lisa::pcode_frontend::PcodeFrontend;
///
/// let mut analyzer = LisaAnalyzer::new();
/// analyzer.config_mut().value_domain = ValueDomainOption::Taint;
/// analyzer.config_mut().cfg_depth = 2;
/// // ... register CFGs via frontend, then call analyze()
/// ```
#[derive(Debug)]
pub struct LisaAnalyzer {
    /// The p-code frontend for CFG construction.
    frontend: PcodeFrontend,
    /// Analysis configuration.
    config: AnalysisConfig,
    /// Taint markers: (mark_type, function_address, varnode_id).
    taint_markers: Vec<TaintMarker>,
    /// Whether the analyzer is initialized.
    initialized: bool,
    /// Analysis results per function.
    results: HashMap<u64, AnalysisResult>,
    /// Set of function addresses that have been processed by the frontend.
    processed_functions: HashSet<u64>,
    /// Current function being analyzed.
    current_function: Option<u64>,
    /// Cancelled flag.
    cancelled: bool,
}

/// A taint marker set by the user.
///
/// Ported from `LisaTaintState.setTaint()`.
#[derive(Debug, Clone)]
pub struct TaintMarker {
    /// The type of taint mark.
    pub mark_type: MarkType,
    /// The function address containing the marker.
    pub function_address: u64,
    /// The statement address to annotate.
    pub statement_address: u64,
    /// The varnode identifier (token ID).
    pub varnode_id: String,
}

impl TaintMarker {
    /// Create a new taint marker.
    pub fn new(
        mark_type: MarkType,
        function_address: u64,
        statement_address: u64,
        varnode_id: impl Into<String>,
    ) -> Self {
        Self {
            mark_type,
            function_address,
            statement_address,
            varnode_id: varnode_id.into(),
        }
    }
}

impl LisaAnalyzer {
    /// Create a new LISA analyzer with default configuration.
    pub fn new() -> Self {
        Self {
            frontend: PcodeFrontend::new(),
            config: AnalysisConfig::default(),
            taint_markers: Vec::new(),
            initialized: false,
            results: HashMap::new(),
            processed_functions: HashSet::new(),
            current_function: None,
            cancelled: false,
        }
    }

    /// Get a reference to the analysis configuration.
    pub fn config(&self) -> &AnalysisConfig {
        &self.config
    }

    /// Get a mutable reference to the analysis configuration.
    pub fn config_mut(&mut self) -> &mut AnalysisConfig {
        &mut self.config
    }

    /// Set the analysis configuration.
    pub fn set_config(&mut self, config: AnalysisConfig) {
        self.config = config;
    }

    /// Get a reference to the p-code frontend.
    pub fn frontend(&self) -> &PcodeFrontend {
        &self.frontend
    }

    /// Get a mutable reference to the p-code frontend.
    pub fn frontend_mut(&mut self) -> &mut PcodeFrontend {
        &mut self.frontend
    }

    /// Mark the analyzer as initialized (frontend is ready).
    pub fn initialize(&mut self) {
        self.initialized = true;
    }

    /// Whether the analyzer has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Register a function as processed.
    ///
    /// Ported from `PcodeFrontend.hasProcessed()` / `addFunction()` logic.
    pub fn register_function(&mut self, function_address: u64) {
        self.processed_functions.insert(function_address);
    }

    /// Check if a function has been processed.
    pub fn has_processed(&self, function_address: u64) -> bool {
        self.processed_functions.contains(&function_address)
    }

    /// Set the current function being analyzed.
    pub fn set_current_function(&mut self, function_address: Option<u64>) {
        self.current_function = function_address;
    }

    /// Get the current function address.
    pub fn current_function(&self) -> Option<u64> {
        self.current_function
    }

    /// Cancel the running analysis.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Whether the analysis has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Add a taint marker.
    ///
    /// Ported from `LisaTaintState.setTaint()`.
    pub fn add_taint_marker(&mut self, marker: TaintMarker) {
        self.taint_markers.push(marker);
    }

    /// Get all taint markers.
    pub fn taint_markers(&self) -> &[TaintMarker] {
        &self.taint_markers
    }

    /// Clear all taint markers.
    pub fn clear_taint_markers(&mut self) {
        self.taint_markers.clear();
    }

    /// Set taint for a specific function, address, and varnode.
    ///
    /// Ported from `LisaTaintState.setTaint(MarkType, Function, Address, String)`.
    pub fn set_taint(
        &mut self,
        mark_type: MarkType,
        function_address: u64,
        statement_address: u64,
        varnode_id: impl Into<String>,
    ) {
        self.taint_markers.push(TaintMarker::new(
            mark_type,
            function_address,
            statement_address,
            varnode_id,
        ));
    }

    /// Run the analysis on the collected CFGs.
    ///
    /// Ported from `LisaPlugin.performAnalysis()`.
    ///
    /// This is the main entry point that:
    /// 1. Validates the analyzer state
    /// 2. Runs the fixpoint analysis on collected CFGs
    /// 3. Collects results per function
    ///
    /// Returns a map of function addresses to their analysis results,
    /// or `None` if the analyzer is not properly initialized.
    pub fn analyze(&mut self) -> Option<HashMap<u64, AnalysisResult>> {
        if !self.initialized || self.frontend.num_instructions() == 0 {
            return None;
        }

        if self.cancelled {
            return Some(HashMap::new());
        }

        self.results.clear();

        // In the full implementation, this would:
        // 1. Build LiSA configuration from self.config
        // 2. Create abstract state with selected domains
        // 3. Run fixpoint iteration on collected CFGs
        // 4. Extract per-statement states
        //
        // For now, we produce empty results for each processed function.
        for &func_addr in &self.processed_functions.clone() {
            if self.cancelled {
                break;
            }
            let result = AnalysisResult {
                function_address: func_addr,
                function_name: format!("sub_{:x}", func_addr),
                statement_states: HashMap::new(),
            };
            self.results.insert(func_addr, result);
        }

        Some(self.results.clone())
    }

    /// Get the active query name for display.
    ///
    /// Ported from `LisaPlugin.getActiveQueryName()`.
    pub fn active_query_name(&self) -> String {
        let func_name = self
            .current_function
            .map(|addr| format!("sub_{:x}", addr));
        self.config
            .active_query_name(func_name.as_deref())
    }

    /// Get the top value representation for the current configuration.
    pub fn top_value(&self) -> &'static str {
        self.config.top_value_representation()
    }

    /// Reset the analyzer state.
    pub fn reset(&mut self) {
        self.frontend.clear();
        self.taint_markers.clear();
        self.results.clear();
        self.processed_functions.clear();
        self.current_function = None;
        self.cancelled = false;
        self.initialized = false;
    }

    /// Get the number of processed functions.
    pub fn processed_function_count(&self) -> usize {
        self.processed_functions.len()
    }

    /// Get the number of taint markers.
    pub fn taint_marker_count(&self) -> usize {
        self.taint_markers.len()
    }

    /// Get the analysis results.
    pub fn results(&self) -> &HashMap<u64, AnalysisResult> {
        &self.results
    }

    /// Generate a register name mapping from address and size to register name.
    ///
    /// Ported from `LisaTaintState.generateRegisterMap()`.
    pub fn generate_register_map(
        &self,
        registers: &[(String, u64, u32)], // (name, address, bit_length)
    ) -> HashMap<String, HashMap<u32, String>> {
        let mut register_names: HashMap<String, HashMap<u32, String>> = HashMap::new();
        for (name, addr, bit_length) in registers {
            let addr_str = format!("0x{:x}", addr);
            let size_map = register_names.entry(addr_str).or_default();
            size_map.insert(*bit_length, name.clone());
            // Also map 0 -> base register name (for size-agnostic lookup)
            size_map.entry(0).or_insert_with(|| name.clone());
        }
        register_names
    }
}

impl Default for LisaAnalyzer {
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
    fn test_domain_option_display() {
        assert_eq!(HeapDomainOption::Monolithic.to_string(), "Monolithic");
        assert_eq!(HeapDomainOption::Default.to_string(), "DEFAULT(Monolithic)");
        assert_eq!(TypeDomainOption::Inferred.to_string(), "Inferred");
        assert_eq!(ValueDomainOption::Interval.to_string(), "Numeric: Interval");
        assert_eq!(
            ValueDomainOption::Taint.to_string(),
            "Dataflow: Taint"
        );
    }

    #[test]
    fn test_domain_option_defaults() {
        assert_eq!(HeapDomainOption::default(), HeapDomainOption::Default);
        assert_eq!(TypeDomainOption::default(), TypeDomainOption::Default);
        assert_eq!(ValueDomainOption::default(), ValueDomainOption::Default);
        assert_eq!(
            InterproceduralOption::default(),
            InterproceduralOption::ModularWorstCase
        );
        assert_eq!(
            DescendingPhaseOption::default(),
            DescendingPhaseOption::None
        );
        assert_eq!(CallPolicyOption::default(), CallPolicyOption::WorstCase);
        assert_eq!(GraphOption::default(), GraphOption::None);
        assert_eq!(CallGraphOption::default(), CallGraphOption::Rta);
    }

    #[test]
    fn test_analysis_config_default() {
        let config = AnalysisConfig::default();
        assert_eq!(config.heap_domain, HeapDomainOption::Default);
        assert_eq!(config.type_domain, TypeDomainOption::Default);
        assert_eq!(config.value_domain, ValueDomainOption::Default);
        assert!(!config.post_state);
        assert!(!config.show_top);
        assert!(!config.show_unique);
        assert!(!config.use_high_pcode);
        assert_eq!(config.cfg_depth, 0);
        assert_eq!(config.threshold, 5);
        assert!(!config.serialize_results);
        assert!(!config.optimize);
    }

    #[test]
    fn test_analysis_config_top_value() {
        let mut config = AnalysisConfig::default();

        config.value_domain = ValueDomainOption::Default;
        assert_eq!(config.top_value_representation(), "#TOP#");

        config.value_domain = ValueDomainOption::Interval;
        assert_eq!(config.top_value_representation(), "[-Inf, +Inf]");

        config.value_domain = ValueDomainOption::UpperBounds;
        assert_eq!(config.top_value_representation(), "{}");

        config.value_domain = ValueDomainOption::Stability;
        assert_eq!(config.top_value_representation(), "=");

        config.value_domain = ValueDomainOption::NonInterference;
        assert_eq!(config.top_value_representation(), "HL");

        config.value_domain = ValueDomainOption::Taint;
        assert_eq!(config.top_value_representation(), "_");

        config.value_domain = ValueDomainOption::ThreeLevelTaint;
        assert_eq!(config.top_value_representation(), "_");
    }

    #[test]
    fn test_analysis_config_query_name() {
        let config = AnalysisConfig::default();
        assert_eq!(
            config.active_query_name(None),
            "DEFAULT(Interval)"
        );
        assert_eq!(
            config.active_query_name(Some("main")),
            "DEFAULT(Interval) @ main"
        );

        let mut config2 = AnalysisConfig::default();
        config2.heap_domain = HeapDomainOption::PointBased;
        assert_eq!(
            config2.active_query_name(None),
            "DEFAULT(Interval):PointBased"
        );

        let mut config3 = AnalysisConfig::default();
        config3.type_domain = TypeDomainOption::Static;
        assert_eq!(
            config3.active_query_name(None),
            "DEFAULT(Interval):Static"
        );
    }

    #[test]
    fn test_lisa_analyzer_new() {
        let analyzer = LisaAnalyzer::new();
        assert!(!analyzer.is_initialized());
        assert!(!analyzer.is_cancelled());
        assert_eq!(analyzer.processed_function_count(), 0);
        assert_eq!(analyzer.taint_marker_count(), 0);
        assert!(analyzer.current_function().is_none());
    }

    #[test]
    fn test_lisa_analyzer_initialize() {
        let mut analyzer = LisaAnalyzer::new();
        assert!(!analyzer.is_initialized());
        analyzer.initialize();
        assert!(analyzer.is_initialized());
    }

    #[test]
    fn test_lisa_analyzer_config() {
        let mut analyzer = LisaAnalyzer::new();
        assert_eq!(analyzer.config().value_domain, ValueDomainOption::Default);

        analyzer.config_mut().value_domain = ValueDomainOption::Taint;
        assert_eq!(analyzer.config().value_domain, ValueDomainOption::Taint);
    }

    #[test]
    fn test_lisa_analyzer_set_config() {
        let mut analyzer = LisaAnalyzer::new();
        let mut config = AnalysisConfig::default();
        config.value_domain = ValueDomainOption::Pentagon;
        config.cfg_depth = 3;
        analyzer.set_config(config);

        assert_eq!(analyzer.config().value_domain, ValueDomainOption::Pentagon);
        assert_eq!(analyzer.config().cfg_depth, 3);
    }

    #[test]
    fn test_lisa_analyzer_function_tracking() {
        let mut analyzer = LisaAnalyzer::new();
        assert!(!analyzer.has_processed(0x1000));

        analyzer.register_function(0x1000);
        assert!(analyzer.has_processed(0x1000));
        assert!(!analyzer.has_processed(0x2000));
        assert_eq!(analyzer.processed_function_count(), 1);

        analyzer.register_function(0x2000);
        assert_eq!(analyzer.processed_function_count(), 2);
    }

    #[test]
    fn test_lisa_analyzer_current_function() {
        let mut analyzer = LisaAnalyzer::new();
        assert!(analyzer.current_function().is_none());

        analyzer.set_current_function(Some(0x401000));
        assert_eq!(analyzer.current_function(), Some(0x401000));

        analyzer.set_current_function(None);
        assert!(analyzer.current_function().is_none());
    }

    #[test]
    fn test_lisa_analyzer_taint_markers() {
        let mut analyzer = LisaAnalyzer::new();
        assert_eq!(analyzer.taint_marker_count(), 0);

        analyzer.set_taint(MarkType::Source, 0x1000, 0x1010, "RAX");
        analyzer.set_taint(MarkType::Sink, 0x2000, 0x2010, "RBX");
        assert_eq!(analyzer.taint_marker_count(), 2);

        assert_eq!(analyzer.taint_markers()[0].mark_type, MarkType::Source);
        assert_eq!(analyzer.taint_markers()[0].varnode_id, "RAX");
        assert_eq!(analyzer.taint_markers()[1].mark_type, MarkType::Sink);

        analyzer.clear_taint_markers();
        assert_eq!(analyzer.taint_marker_count(), 0);
    }

    #[test]
    fn test_lisa_analyzer_taint_marker_new() {
        let marker = TaintMarker::new(MarkType::Gate, 0x1000, 0x1010, "RSP");
        assert_eq!(marker.mark_type, MarkType::Gate);
        assert_eq!(marker.function_address, 0x1000);
        assert_eq!(marker.statement_address, 0x1010);
        assert_eq!(marker.varnode_id, "RSP");
    }

    #[test]
    fn test_lisa_analyzer_analyze_not_initialized() {
        let mut analyzer = LisaAnalyzer::new();
        // Not initialized, should return None
        assert!(analyzer.analyze().is_none());
    }

    #[test]
    fn test_lisa_analyzer_analyze_empty() {
        let mut analyzer = LisaAnalyzer::new();
        analyzer.initialize();
        // Initialized but no instructions, should return None
        assert!(analyzer.analyze().is_none());
    }

    #[test]
    fn test_lisa_analyzer_analyze_with_functions() {
        let mut analyzer = LisaAnalyzer::new();
        analyzer.initialize();

        // Register some p-code ops and functions
        analyzer
            .frontend_mut()
            .register(0x1000, vec![PcodeOp::new("COPY", 0x1000, 0, vec![0], Some(8), 8)]);
        analyzer.register_function(0x1000);
        analyzer.register_function(0x2000);

        let results = analyzer.analyze();
        assert!(results.is_some());
        let results = results.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.contains_key(&0x1000));
        assert!(results.contains_key(&0x2000));
    }

    #[test]
    fn test_lisa_analyzer_cancel() {
        let mut analyzer = LisaAnalyzer::new();
        analyzer.initialize();
        analyzer
            .frontend_mut()
            .register(0x1000, vec![PcodeOp::new("COPY", 0x1000, 0, vec![0], Some(8), 8)]);
        analyzer.register_function(0x1000);

        analyzer.cancel();
        assert!(analyzer.is_cancelled());

        let results = analyzer.analyze();
        assert!(results.is_some());
        assert!(results.unwrap().is_empty());
    }

    #[test]
    fn test_lisa_analyzer_cancel_before_functions() {
        let mut analyzer = LisaAnalyzer::new();
        analyzer.initialize();
        analyzer
            .frontend_mut()
            .register(0x1000, vec![PcodeOp::new("COPY", 0x1000, 0, vec![0], Some(8), 8)]);
        analyzer.register_function(0x1000);

        analyzer.cancel();
        let results = analyzer.analyze();
        // Should return empty results (cancelled before processing)
        assert_eq!(results.unwrap().len(), 0);
    }

    #[test]
    fn test_lisa_analyzer_reset() {
        let mut analyzer = LisaAnalyzer::new();
        analyzer.initialize();
        analyzer.register_function(0x1000);
        analyzer.set_taint(MarkType::Source, 0x1000, 0x1010, "RAX");
        analyzer.set_current_function(Some(0x1000));

        analyzer.reset();
        assert!(!analyzer.is_initialized());
        assert_eq!(analyzer.processed_function_count(), 0);
        assert_eq!(analyzer.taint_marker_count(), 0);
        assert!(analyzer.current_function().is_none());
    }

    #[test]
    fn test_lisa_analyzer_active_query_name() {
        let mut analyzer = LisaAnalyzer::new();
        assert_eq!(analyzer.active_query_name(), "DEFAULT(Interval)");

        analyzer.set_current_function(Some(0x401000));
        assert_eq!(
            analyzer.active_query_name(),
            "DEFAULT(Interval) @ sub_401000"
        );
    }

    #[test]
    fn test_lisa_analyzer_top_value() {
        let analyzer = LisaAnalyzer::new();
        assert_eq!(analyzer.top_value(), "#TOP#");
    }

    #[test]
    fn test_lisa_analyzer_generate_register_map() {
        let analyzer = LisaAnalyzer::new();
        let registers = vec![
            ("RAX".to_string(), 0x0u64, 64u32),
            ("EAX".to_string(), 0x0u64, 32u32),
            ("RSP".to_string(), 0x20u64, 64u32),
        ];

        let map = analyzer.generate_register_map(&registers);
        assert!(map.contains_key("0x0"));
        assert!(map.contains_key("0x20"));

        let rax_map = &map["0x0"];
        assert_eq!(rax_map.get(&64), Some(&"RAX".to_string()));
        assert_eq!(rax_map.get(&32), Some(&"EAX".to_string()));
        // Size 0 maps to the last registered name at that address
        assert!(rax_map.contains_key(&0));
    }

    #[test]
    fn test_mark_type_equality() {
        assert_eq!(MarkType::Source, MarkType::Source);
        assert_ne!(MarkType::Source, MarkType::Sink);
        assert_ne!(MarkType::Sink, MarkType::Gate);
    }

    #[test]
    fn test_analysis_result() {
        let result = AnalysisResult {
            function_address: 0x1000,
            function_name: "main".to_string(),
            statement_states: HashMap::new(),
        };
        assert_eq!(result.function_address, 0x1000);
        assert_eq!(result.function_name, "main");
        assert!(result.statement_states.is_empty());
    }

    #[test]
    fn test_statement_state() {
        let state = StatementState {
            address: 0x1000,
            value_state: HashMap::new(),
            type_state: HashMap::new(),
        };
        assert_eq!(state.address, 0x1000);
    }
}
