//! Lisa plugin -- top-level Ghidra plugin for abstract interpretation via LiSA.
//!
//! Ported from `LisaPlugin.java` and `LisaOptions.java` in Ghidra's Lisa
//! extension.
//!
//! The plugin provides:
//! 1. Abstract interpretation analysis actions (Add CFGs, Clear CFGs, Set Taint)
//! 2. Configuration of analysis domains and policies
//! 3. Program lifecycle management (activation, location tracking, closure)
//! 4. Integration with the [`LisaAnalyzer`] for running analyses
//!
//! # Key Types
//!
//! - [`LisaPlugin`] -- The main plugin managing LISA analysis
//! - [`LisaPluginOptions`] -- Configurable options for the analysis
//! - [`AddCfgsAction`] -- Action to add CFGs for analysis
//! - [`ClearCfgsAction`] -- Action to clear collected CFGs
//! - [`SetTaintAction`] -- Action to mark a varnode as taint source
//! - [`PluginEvent`] -- Events consumed/produced by the plugin

use std::collections::{HashMap, HashSet};

use super::lisa_analyzer::{
    AnalysisConfig, AnalysisResult, CallGraphOption, CallPolicyOption, DescendingPhaseOption,
    GraphOption, HeapDomainOption, InterproceduralOption, LisaAnalyzer, MarkType, TaintMarker,
    TypeDomainOption, ValueDomainOption,
};
use super::pcode_frontend::PcodeOp;

// ---------------------------------------------------------------------------
// Plugin events
// ---------------------------------------------------------------------------

/// Events consumed by the Lisa plugin.
///
/// Ported from `@PluginInfo(eventsConsumed = ...)` in `LisaPlugin.java`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginEvent {
    /// A program was activated (made active in the tool).
    ProgramActivated { program_name: String },
    /// A program was opened.
    ProgramOpened { program_name: String },
    /// The user's location in the program changed.
    ProgramLocationChanged { address: u64, function_address: Option<u64> },
    /// The user's selection changed.
    ProgramSelectionChanged { addresses: Vec<u64> },
    /// A program was closed.
    ProgramClosed { program_name: String },
}

// ---------------------------------------------------------------------------
// Action definitions
// ---------------------------------------------------------------------------

/// Action to add CFGs for analysis.
///
/// Ported from `LisaPlugin.AddCfgsAction`.
#[derive(Debug, Clone)]
pub struct AddCfgsAction {
    /// Internal action name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Menu path.
    pub menu_path: Vec<String>,
    /// Help anchor.
    pub help_anchor: String,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl AddCfgsAction {
    /// Create the default "Add CFG" action.
    pub fn new() -> Self {
        Self {
            name: "Add CFG".into(),
            description: "Compute called CFGs prior to analysis".into(),
            menu_path: vec!["Abstract Interpretation".into(), "Add CFG".into()],
            help_anchor: "add_cfgs".into(),
            enabled: true,
        }
    }
}

impl Default for AddCfgsAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action to clear collected CFGs.
///
/// Ported from `LisaPlugin.ClearCfgsAction`.
#[derive(Debug, Clone)]
pub struct ClearCfgsAction {
    /// Internal action name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Menu path.
    pub menu_path: Vec<String>,
    /// Help anchor.
    pub help_anchor: String,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl ClearCfgsAction {
    /// Create the default "Clear CFGs" action.
    pub fn new() -> Self {
        Self {
            name: "Clear CFGs".into(),
            description: "Clear CFGs prior to analysis".into(),
            menu_path: vec!["Abstract Interpretation".into(), "Clear CFGs".into()],
            help_anchor: "clear_cfgs".into(),
            enabled: true,
        }
    }
}

impl Default for ClearCfgsAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action to set taint for a varnode.
///
/// Ported from `LisaPlugin.SetTaintAction`.
#[derive(Debug, Clone)]
pub struct SetTaintAction {
    /// Internal action name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Menu path.
    pub menu_path: Vec<String>,
    /// Help anchor.
    pub help_anchor: String,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl SetTaintAction {
    /// Create the default "Set Taint" action.
    pub fn new() -> Self {
        Self {
            name: "Set Taint".into(),
            description: "Set taint for given varnode".into(),
            menu_path: vec!["Abstract Interpretation".into(), "Set Taint".into()],
            help_anchor: "set_taint".into(),
            enabled: true,
        }
    }
}

impl Default for SetTaintAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Function tracking
// ---------------------------------------------------------------------------

/// Lightweight function representation used by the plugin.
///
/// Ported from the `Function` references tracked in `LisaPlugin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionInfo {
    /// Function entry point address.
    pub entry_point: u64,
    /// Function name.
    pub name: String,
    /// Whether this function is a thunk.
    pub is_thunk: bool,
    /// Called function entry points.
    pub called_functions: HashSet<u64>,
}

impl FunctionInfo {
    /// Create a new function info.
    pub fn new(entry_point: u64, name: impl Into<String>) -> Self {
        Self {
            entry_point,
            name: name.into(),
            is_thunk: false,
            called_functions: HashSet::new(),
        }
    }

    /// Mark this function as a thunk.
    pub fn as_thunk(mut self) -> Self {
        self.is_thunk = true;
        self
    }

    /// Add a called function.
    pub fn add_callee(&mut self, callee_address: u64) {
        self.called_functions.insert(callee_address);
    }
}

// ---------------------------------------------------------------------------
// LisaPluginOptions -- persisted options
// ---------------------------------------------------------------------------

/// Configurable options for the Lisa plugin.
///
/// Ported from `LisaOptions.java` -- all the configurable parameters
/// that control the abstract interpretation analysis.
#[derive(Debug, Clone)]
pub struct LisaPluginOptions {
    /// Analysis configuration (domain and policy options).
    pub config: AnalysisConfig,
    /// Decompiler simplification style.
    pub simplification_style: String,
    /// Whether the options have been loaded from the tool.
    loaded: bool,
}

impl Default for LisaPluginOptions {
    fn default() -> Self {
        Self {
            config: AnalysisConfig::default(),
            simplification_style: "normalize".into(),
            loaded: false,
        }
    }
}

impl LisaPluginOptions {
    /// Create new options with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the options have been loaded from the tool.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Mark the options as loaded.
    pub fn set_loaded(&mut self, loaded: bool) {
        self.loaded = loaded;
    }

    /// Register default option values.
    ///
    /// Ported from `LisaOptions.registerOptions()`.
    pub fn register_defaults(&mut self) {
        self.config = AnalysisConfig::default();
        self.simplification_style = "normalize".into();
        self.loaded = true;
    }

    /// Grab current option values from a settings map.
    ///
    /// Ported from `LisaOptions.grabFromToolAndProgram()`.
    pub fn grab_from_settings(&mut self, settings: &HashMap<String, String>) {
        if let Some(val) = settings.get("Domain.Heap") {
            self.config.heap_domain = parse_heap_domain(val);
        }
        if let Some(val) = settings.get("Domain.Type") {
            self.config.type_domain = parse_type_domain(val);
        }
        if let Some(val) = settings.get("Domain.Value") {
            self.config.value_domain = parse_value_domain(val);
        }
        if let Some(val) = settings.get("Interprocedural") {
            self.config.interprocedural = parse_interprocedural(val);
        }
        if let Some(val) = settings.get("DescendingPhase") {
            self.config.descending_phase = parse_descending_phase(val);
        }
        if let Some(val) = settings.get("OpenCallPolicy") {
            self.config.call_policy = parse_call_policy(val);
        }
        if let Some(val) = settings.get("Output.GraphFormat") {
            self.config.graph_format = parse_graph_option(val);
        }
        if let Some(val) = settings.get("CallGraph") {
            self.config.call_graph = parse_call_graph(val);
        }
        if let Some(val) = settings.get("Post-State") {
            self.config.post_state = val == "true";
        }
        if let Some(val) = settings.get("Display 'top' values") {
            self.config.show_top = val == "true";
        }
        if let Some(val) = settings.get("Display 'unique' values") {
            self.config.show_unique = val == "true";
        }
        if let Some(val) = settings.get("Use high pcode") {
            self.config.use_high_pcode = val == "true";
        }
        if let Some(val) = settings.get("Compute CFGs to Depth") {
            if let Ok(n) = val.parse::<usize>() {
                self.config.cfg_depth = n;
            }
        }
        if let Some(val) = settings.get("Threshhold") {
            if let Ok(n) = val.parse::<usize>() {
                self.config.threshold = n;
            }
        }
        if let Some(val) = settings.get("Output.WorkDir") {
            self.config.output_dir = val.clone();
        }
        if let Some(val) = settings.get("Output.SerializeResults") {
            self.config.serialize_results = val == "true";
        }
        if let Some(val) = settings.get("OptimizeResults") {
            self.config.optimize = val == "true";
        }
        if let Some(val) = settings.get("SimplificationStyle") {
            self.simplification_style = val.clone();
        }
        self.loaded = true;
    }
}

// Settings parsing helpers

fn parse_heap_domain(s: &str) -> HeapDomainOption {
    match s {
        "Monolithic" => HeapDomainOption::Monolithic,
        "PointBased" => HeapDomainOption::PointBased,
        "FieldSensitivePointBased" => HeapDomainOption::FieldSensitivePointBased,
        "TypeBased" => HeapDomainOption::TypeBased,
        _ => HeapDomainOption::Default,
    }
}

fn parse_type_domain(s: &str) -> TypeDomainOption {
    match s {
        "Inferred" => TypeDomainOption::Inferred,
        "Static" => TypeDomainOption::Static,
        _ => TypeDomainOption::Default,
    }
}

fn parse_value_domain(s: &str) -> ValueDomainOption {
    match s {
        "Numeric: ConstantPropagation" => ValueDomainOption::ConstantPropagation,
        "Numeric: Interval" => ValueDomainOption::Interval,
        "Numeric: Interval (Low X86)" => ValueDomainOption::IntervalLowX86,
        "Numeric: NonRedundantPowersetOfInterval" => ValueDomainOption::PowersetInterval,
        "Numeric: Parity" => ValueDomainOption::Parity,
        "Numeric: Pentagon" => ValueDomainOption::Pentagon,
        "Numeric: Pentagon (Low X86)" => ValueDomainOption::PentagonLowX86,
        "Numeric: Sign" => ValueDomainOption::Sign,
        "Numeric: UpperBound" => ValueDomainOption::UpperBounds,
        "Dataflow: AvailableExpressions" => ValueDomainOption::AvailableExpressions,
        "Dataflow: ConstantPropagation" => ValueDomainOption::DataflowConstantPropagation,
        "Dataflow: ReachingDefinitions" => ValueDomainOption::ReachingDefinitions,
        "Dataflow: Liveness" => ValueDomainOption::Liveness,
        "Dataflow: Taint" => ValueDomainOption::Taint,
        "Dataflow: ThreeLevelTaint" => ValueDomainOption::ThreeLevelTaint,
        "NonInterference" => ValueDomainOption::NonInterference,
        "Stability" => ValueDomainOption::Stability,
        _ => ValueDomainOption::Default,
    }
}

fn parse_interprocedural(s: &str) -> InterproceduralOption {
    match s {
        "ContextBased" => InterproceduralOption::ContextBased,
        "ContextBased(FullStackToken)" => InterproceduralOption::ContextBasedFullStack,
        "ContextBased(KDepthToken)" => InterproceduralOption::ContextBasedKDepth,
        "ContextBased(LastCallToken)" => InterproceduralOption::ContextBasedLastCall,
        "ContextBased(ContextInsensitiveToken)" => InterproceduralOption::ContextBasedInsensitive,
        "BackwardModularWorstCaseAnalysis" => InterproceduralOption::BackwardModularWorstCase,
        _ => InterproceduralOption::ModularWorstCase,
    }
}

fn parse_descending_phase(s: &str) -> DescendingPhaseOption {
    match s {
        "Narrowing" => DescendingPhaseOption::Narrowing,
        "GLB k-times" => DescendingPhaseOption::Glb,
        _ => DescendingPhaseOption::None,
    }
}

fn parse_call_policy(s: &str) -> CallPolicyOption {
    match s {
        "ReturnTop" => CallPolicyOption::ReturnTop,
        _ => CallPolicyOption::WorstCase,
    }
}

fn parse_graph_option(s: &str) -> GraphOption {
    match s {
        "HTML" => GraphOption::Html,
        "HTML w/ subnodes" => GraphOption::HtmlWithSubnodes,
        "Dot" => GraphOption::Dot,
        "GraphML" => GraphOption::GraphMl,
        "GraphML w/ subnodes" => GraphOption::GraphMlWithSubnodes,
        _ => GraphOption::None,
    }
}

fn parse_call_graph(s: &str) -> CallGraphOption {
    match s {
        "Call Hierarchy Analysis" => CallGraphOption::Cha,
        _ => CallGraphOption::Rta,
    }
}

// ---------------------------------------------------------------------------
// LisaPlugin -- the main plugin
// ---------------------------------------------------------------------------

/// Main Lisa plugin for abstract interpretation analysis.
///
/// Ported from `LisaPlugin.java` (extends `ProgramPlugin`).
///
/// The plugin manages:
/// - Analysis configuration via [`LisaPluginOptions`]
/// - The [`LisaAnalyzer`] instance for running analyses
/// - Program lifecycle (activation, location tracking, closure)
/// - Actions: Add CFGs, Clear CFGs, Set Taint
/// - Current function tracking
///
/// # Usage
///
/// ```rust
/// use ghidra_features::lisa::lisa_plugin::*;
///
/// let mut plugin = LisaPlugin::new();
/// plugin.process_event(PluginEvent::ProgramActivated {
///     program_name: "test.exe".into(),
/// });
/// plugin.location_changed(0x401000);
/// ```
#[derive(Debug)]
pub struct LisaPlugin {
    /// The LISA analyzer.
    analyzer: LisaAnalyzer,
    /// Plugin options.
    options: LisaPluginOptions,
    /// Add CFGs action.
    add_cfgs_action: AddCfgsAction,
    /// Clear CFGs action.
    clear_cfgs_action: ClearCfgsAction,
    /// Set Taint action.
    set_taint_action: SetTaintAction,
    /// Current program name (if any).
    current_program: Option<String>,
    /// Current function entry point.
    current_function: Option<u64>,
    /// Function registry: address -> info.
    functions: HashMap<u64, FunctionInfo>,
    /// Whether the options have been initialized for the current program.
    options_initialized: bool,
}

impl LisaPlugin {
    /// Create a new Lisa plugin.
    pub fn new() -> Self {
        Self {
            analyzer: LisaAnalyzer::new(),
            options: LisaPluginOptions::new(),
            add_cfgs_action: AddCfgsAction::new(),
            clear_cfgs_action: ClearCfgsAction::new(),
            set_taint_action: SetTaintAction::new(),
            current_program: None,
            current_function: None,
            functions: HashMap::new(),
            options_initialized: false,
        }
    }

    // -- Plugin lifecycle --

    /// Process a plugin event.
    ///
    /// Ported from `LisaPlugin.processEvent()`.
    pub fn process_event(&mut self, event: PluginEvent) {
        match event {
            PluginEvent::ProgramActivated { program_name } => {
                self.current_program = Some(program_name);
                self.options_initialized = false;
            }
            PluginEvent::ProgramOpened { program_name } => {
                self.current_program = Some(program_name);
            }
            PluginEvent::ProgramLocationChanged { address, function_address } => {
                self.location_changed(address);
                if let Some(func_addr) = function_address {
                    self.current_function = Some(func_addr);
                }
            }
            PluginEvent::ProgramSelectionChanged { .. } => {
                // Selection changes are not tracked by this plugin.
            }
            PluginEvent::ProgramClosed { program_name } => {
                if self.current_program.as_deref() == Some(&program_name) {
                    self.current_program = None;
                    self.current_function = None;
                    self.options_initialized = false;
                }
            }
        }
    }

    /// Notify that the program location has changed.
    ///
    /// Ported from the `ProgramLocationPluginEvent` handling in
    /// `LisaPlugin.processEvent()`.
    pub fn location_changed(&mut self, address: u64) {
        // In the full implementation, this resolves the function containing
        // the address and updates current_function if it changed.
        let _ = address;
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Get the current function entry point.
    pub fn current_function(&self) -> Option<u64> {
        self.current_function
    }

    // -- Options --

    /// Get a reference to the plugin options.
    pub fn options(&self) -> &LisaPluginOptions {
        &self.options
    }

    /// Get a mutable reference to the plugin options.
    pub fn options_mut(&mut self) -> &mut LisaPluginOptions {
        &mut self.options
    }

    /// Initialize options for the current program.
    ///
    /// Ported from `LisaPlugin.initOptions()`.
    pub fn init_options(&mut self) {
        if !self.options_initialized {
            self.options.register_defaults();
            self.options_initialized = true;
        }
    }

    /// Handle an options change notification.
    ///
    /// Ported from `LisaPlugin.optionsChanged()`.
    pub fn options_changed(&mut self, option_name: &str, _old_value: &str, _new_value: &str) {
        // The "Use high pcode" change triggers CFG clearing.
        if option_name == "Use high pcode (experimental)" {
            self.clear_cfgs();
        }
    }

    /// Refresh options from the tool.
    ///
    /// Ported from `LisaPlugin.doRefresh()`.
    pub fn refresh_options(&mut self, settings: &HashMap<String, String>) {
        self.options.grab_from_settings(settings);
    }

    // -- Actions --

    /// Get a reference to the Add CFGs action.
    pub fn add_cfgs_action(&self) -> &AddCfgsAction {
        &self.add_cfgs_action
    }

    /// Get a reference to the Clear CFGs action.
    pub fn clear_cfgs_action(&self) -> &ClearCfgsAction {
        &self.clear_cfgs_action
    }

    /// Get a reference to the Set Taint action.
    pub fn set_taint_action(&self) -> &SetTaintAction {
        &self.set_taint_action
    }

    // -- CFG management --

    /// Add a CFG for a function and optionally its callees.
    ///
    /// Ported from `LisaPlugin.addCfg()`.
    pub fn add_cfg(&mut self, function_address: u64, recurse: bool) {
        if !self.analyzer.is_initialized() {
            self.init_program();
        }

        let depth = if recurse {
            self.options.config.cfg_depth
        } else {
            0
        };

        self.add_function(function_address);

        if depth > 0 {
            // Collect callees and their inner callees upfront to avoid borrow conflicts.
            let callees: Vec<u64> = self
                .functions
                .get(&function_address)
                .map(|f| f.called_functions.iter().copied().collect())
                .unwrap_or_default();

            // Collect all addresses to process (callees + their callees if depth > 1).
            let mut to_process: Vec<u64> = Vec::new();
            for callee in &callees {
                if let Some(func) = self.functions.get(callee) {
                    if !func.is_thunk {
                        to_process.push(*callee);
                        if depth > 1 {
                            for inner in &func.called_functions {
                                to_process.push(*inner);
                            }
                        }
                    }
                }
            }

            for addr in to_process {
                if self.analyzer.is_cancelled() {
                    break;
                }
                self.add_function(addr);
            }
        }
    }

    /// Add a single function's CFG.
    ///
    /// Ported from `LisaPlugin.addFunction()`.
    fn add_function(&mut self, function_address: u64) {
        if self.analyzer.has_processed(function_address) || self.analyzer.is_cancelled() {
            return;
        }
        // In the full implementation, this would call frontend.visitFunction()
        // and register the resulting CFG ops.
        self.analyzer.register_function(function_address);
    }

    /// Clear all collected CFGs.
    ///
    /// Ported from `LisaPlugin.clearCfgs()`.
    pub fn clear_cfgs(&mut self) {
        self.analyzer.frontend_mut().clear();
        self.analyzer.reset();
    }

    /// Register a function with the plugin.
    pub fn register_function(&mut self, info: FunctionInfo) {
        self.functions.insert(info.entry_point, info);
    }

    /// Get a function by address.
    pub fn get_function(&self, address: u64) -> Option<&FunctionInfo> {
        self.functions.get(&address)
    }

    /// Get the number of registered functions.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    // -- Taint management --

    /// Set taint for a varnode at an address.
    ///
    /// Ported from `LisaPlugin.setTaint()`.
    pub fn set_taint(
        &mut self,
        function_address: u64,
        statement_address: u64,
        varnode_id: impl Into<String>,
    ) {
        self.analyzer.set_taint(
            MarkType::Source,
            function_address,
            statement_address,
            varnode_id,
        );
    }

    /// Clear all taint annotations.
    ///
    /// Ported from `LisaTaintState.clearAnnotations()`.
    pub fn clear_taint(&mut self) {
        self.analyzer.clear_taint_markers();
    }

    // -- Analysis --

    /// Run the analysis on collected CFGs.
    ///
    /// Ported from `LisaPlugin.performAnalysis()`.
    pub fn perform_analysis(&mut self) -> Option<HashMap<u64, AnalysisResult>> {
        if self.current_function.is_none() {
            return None;
        }

        let func_addr = self.current_function.unwrap();

        // Ensure the current function is added
        self.add_cfg(func_addr, true);

        // Initialize LiSA configuration from options
        self.init_lisa();

        // Run the analysis
        self.analyzer.analyze()
    }

    /// Initialize the LiSA analysis engine.
    ///
    /// Ported from `LisaPlugin.initLisa()`.
    fn init_lisa(&mut self) {
        // In the full implementation, this creates the LiSA configuration
        // from the current options (heap domain, value domain, type domain,
        // interprocedural policy, etc.) and initializes the LiSA engine.
        //
        // The configuration includes:
        // - Abstract state: simpleState(heap, value, type)
        // - Interprocedural analysis policy
        // - Descending phase type
        // - Open call policy
        // - Analysis graphs setting
        // - Call graph construction
        // - Serialization and optimization flags
        // - Working directory
    }

    /// Initialize the p-code frontend.
    ///
    /// Ported from `LisaPlugin.initProgram()`.
    fn init_program(&mut self) {
        self.analyzer.initialize();
    }

    /// Get a reference to the analyzer.
    pub fn analyzer(&self) -> &LisaAnalyzer {
        &self.analyzer
    }

    /// Get a mutable reference to the analyzer.
    pub fn analyzer_mut(&mut self) -> &mut LisaAnalyzer {
        &mut self.analyzer
    }

    /// Get the active query name for display.
    ///
    /// Ported from `LisaPlugin.getActiveQueryName()`.
    pub fn active_query_name(&self) -> String {
        let mut name = self.options.config.value_domain.to_string();
        if self.options.config.heap_domain != HeapDomainOption::Default {
            name.push(':');
            name.push_str(&self.options.config.heap_domain.to_string());
        }
        if self.options.config.type_domain != TypeDomainOption::Default {
            name.push(':');
            name.push_str(&self.options.config.type_domain.to_string());
        }
        if let Some(func_addr) = self.current_function {
            name.push_str(&format!(" @ sub_{:x}", func_addr));
        }
        name
    }

    /// Dispose the plugin, releasing all resources.
    pub fn dispose(&mut self) {
        self.analyzer.reset();
        self.functions.clear();
        self.current_program = None;
        self.current_function = None;
        self.options_initialized = false;
    }
}

impl Default for LisaPlugin {
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
    fn test_plugin_event_variants() {
        let events = vec![
            PluginEvent::ProgramActivated { program_name: "test.exe".into() },
            PluginEvent::ProgramOpened { program_name: "test.exe".into() },
            PluginEvent::ProgramLocationChanged { address: 0x1000, function_address: Some(0x1000) },
            PluginEvent::ProgramSelectionChanged { addresses: vec![0x1000] },
            PluginEvent::ProgramClosed { program_name: "test.exe".into() },
        ];
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn test_add_cfgs_action() {
        let action = AddCfgsAction::new();
        assert_eq!(action.name, "Add CFG");
        assert_eq!(action.description, "Compute called CFGs prior to analysis");
        assert_eq!(action.menu_path, vec!["Abstract Interpretation", "Add CFG"]);
        assert_eq!(action.help_anchor, "add_cfgs");
        assert!(action.enabled);
    }

    #[test]
    fn test_clear_cfgs_action() {
        let action = ClearCfgsAction::new();
        assert_eq!(action.name, "Clear CFGs");
        assert_eq!(action.description, "Clear CFGs prior to analysis");
        assert_eq!(action.menu_path, vec!["Abstract Interpretation", "Clear CFGs"]);
        assert!(action.enabled);
    }

    #[test]
    fn test_set_taint_action() {
        let action = SetTaintAction::new();
        assert_eq!(action.name, "Set Taint");
        assert_eq!(action.description, "Set taint for given varnode");
        assert_eq!(action.menu_path, vec!["Abstract Interpretation", "Set Taint"]);
        assert!(action.enabled);
    }

    #[test]
    fn test_function_info() {
        let mut func = FunctionInfo::new(0x401000, "main");
        assert_eq!(func.entry_point, 0x401000);
        assert_eq!(func.name, "main");
        assert!(!func.is_thunk);

        func.add_callee(0x402000);
        assert!(func.called_functions.contains(&0x402000));

        let thunk = FunctionInfo::new(0x403000, "__thunk").as_thunk();
        assert!(thunk.is_thunk);
    }

    #[test]
    fn test_lisa_plugin_new() {
        let plugin = LisaPlugin::new();
        assert!(plugin.current_program().is_none());
        assert!(plugin.current_function().is_none());
        assert_eq!(plugin.function_count(), 0);
    }

    #[test]
    fn test_lisa_plugin_program_lifecycle() {
        let mut plugin = LisaPlugin::new();

        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.exe".into(),
        });
        assert_eq!(plugin.current_program(), Some("test.exe"));

        plugin.process_event(PluginEvent::ProgramClosed {
            program_name: "test.exe".into(),
        });
        assert!(plugin.current_program().is_none());
        assert!(plugin.current_function().is_none());
    }

    #[test]
    fn test_lisa_plugin_close_wrong_program() {
        let mut plugin = LisaPlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.exe".into(),
        });

        // Close a different program -- should not affect current
        plugin.process_event(PluginEvent::ProgramClosed {
            program_name: "other.exe".into(),
        });
        assert_eq!(plugin.current_program(), Some("test.exe"));
    }

    #[test]
    fn test_lisa_plugin_location_changed() {
        let mut plugin = LisaPlugin::new();
        plugin.process_event(PluginEvent::ProgramLocationChanged {
            address: 0x401000,
            function_address: Some(0x401000),
        });
        assert_eq!(plugin.current_function(), Some(0x401000));
    }

    #[test]
    fn test_lisa_plugin_options() {
        let mut plugin = LisaPlugin::new();
        assert!(!plugin.options().is_loaded());

        plugin.init_options();
        assert!(plugin.options().is_loaded());
    }

    #[test]
    fn test_lisa_plugin_options_changed_high_pcode() {
        let mut plugin = LisaPlugin::new();
        plugin.analyzer_mut().initialize();

        // Changing "Use high pcode" should clear CFGs
        plugin.options_changed("Use high pcode (experimental)", "false", "true");
        // The clear happens internally; verify analyzer is reset
        assert!(!plugin.analyzer().is_initialized());
    }

    #[test]
    fn test_lisa_plugin_register_function() {
        let mut plugin = LisaPlugin::new();
        let func = FunctionInfo::new(0x401000, "main");
        plugin.register_function(func);
        assert_eq!(plugin.function_count(), 1);

        let f = plugin.get_function(0x401000);
        assert!(f.is_some());
        assert_eq!(f.unwrap().name, "main");

        assert!(plugin.get_function(0x999999).is_none());
    }

    #[test]
    fn test_lisa_plugin_add_cfg() {
        let mut plugin = LisaPlugin::new();
        plugin.options_mut().config.cfg_depth = 1;
        let mut func = FunctionInfo::new(0x401000, "main");
        func.add_callee(0x402000);
        plugin.register_function(func);
        plugin.register_function(FunctionInfo::new(0x402000, "helper"));

        plugin.add_cfg(0x401000, true);
        assert!(plugin.analyzer().has_processed(0x401000));
        assert!(plugin.analyzer().has_processed(0x402000));
    }

    #[test]
    fn test_lisa_plugin_add_cfg_no_recurse() {
        let mut plugin = LisaPlugin::new();
        let mut func = FunctionInfo::new(0x401000, "main");
        func.add_callee(0x402000);
        plugin.register_function(func);

        plugin.add_cfg(0x401000, false);
        assert!(plugin.analyzer().has_processed(0x401000));
        // Callee should not be processed without recursion
        assert!(!plugin.analyzer().has_processed(0x402000));
    }

    #[test]
    fn test_lisa_plugin_add_cfg_thunk() {
        let mut plugin = LisaPlugin::new();
        let mut func = FunctionInfo::new(0x401000, "main");
        func.add_callee(0x403000);
        plugin.register_function(func);
        plugin.register_function(FunctionInfo::new(0x403000, "__thunk").as_thunk());

        plugin.add_cfg(0x401000, true);
        assert!(plugin.analyzer().has_processed(0x401000));
        // Thunks should be skipped
        assert!(!plugin.analyzer().has_processed(0x403000));
    }

    #[test]
    fn test_lisa_plugin_clear_cfgs() {
        let mut plugin = LisaPlugin::new();
        plugin.register_function(FunctionInfo::new(0x401000, "main"));
        plugin.add_cfg(0x401000, false);
        assert!(plugin.analyzer().has_processed(0x401000));

        plugin.clear_cfgs();
        assert!(!plugin.analyzer().has_processed(0x401000));
    }

    #[test]
    fn test_lisa_plugin_set_taint() {
        let mut plugin = LisaPlugin::new();
        plugin.set_taint(0x401000, 0x401010, "RAX");
        assert_eq!(plugin.analyzer().taint_marker_count(), 1);
        assert_eq!(plugin.analyzer().taint_markers()[0].mark_type, MarkType::Source);
        assert_eq!(plugin.analyzer().taint_markers()[0].varnode_id, "RAX");
    }

    #[test]
    fn test_lisa_plugin_clear_taint() {
        let mut plugin = LisaPlugin::new();
        plugin.set_taint(0x401000, 0x401010, "RAX");
        plugin.set_taint(0x402000, 0x402010, "RBX");
        assert_eq!(plugin.analyzer().taint_marker_count(), 2);

        plugin.clear_taint();
        assert_eq!(plugin.analyzer().taint_marker_count(), 0);
    }

    #[test]
    fn test_lisa_plugin_active_query_name() {
        let mut plugin = LisaPlugin::new();
        assert_eq!(plugin.active_query_name(), "DEFAULT(Interval)");

        plugin.current_function = Some(0x401000);
        assert_eq!(plugin.active_query_name(), "DEFAULT(Interval) @ sub_401000");
    }

    #[test]
    fn test_lisa_plugin_perform_analysis_no_function() {
        let mut plugin = LisaPlugin::new();
        // No current function, should return None
        assert!(plugin.perform_analysis().is_none());
    }

    #[test]
    fn test_lisa_plugin_perform_analysis() {
        let mut plugin = LisaPlugin::new();
        plugin.register_function(FunctionInfo::new(0x401000, "main"));
        plugin.current_function = Some(0x401000);

        // Register a p-code op so the frontend has instructions (required by analyzer).
        plugin
            .analyzer_mut()
            .frontend_mut()
            .register(0x401000, vec![PcodeOp::new("COPY", 0x401000, 0, vec![0], Some(8), 8)]);

        let results = plugin.perform_analysis();
        assert!(results.is_some());
        let results = results.unwrap();
        assert!(results.contains_key(&0x401000));
    }

    #[test]
    fn test_lisa_plugin_dispose() {
        let mut plugin = LisaPlugin::new();
        plugin.process_event(PluginEvent::ProgramActivated {
            program_name: "test.exe".into(),
        });
        plugin.register_function(FunctionInfo::new(0x401000, "main"));
        plugin.current_function = Some(0x401000);

        plugin.dispose();
        assert!(plugin.current_program().is_none());
        assert!(plugin.current_function().is_none());
        assert_eq!(plugin.function_count(), 0);
    }

    #[test]
    fn test_lisa_plugin_options_grab_from_settings() {
        let mut options = LisaPluginOptions::new();
        let mut settings = HashMap::new();
        settings.insert("Domain.Heap".into(), "PointBased".into());
        settings.insert("Domain.Type".into(), "Static".into());
        settings.insert("Domain.Value".into(), "Dataflow: Taint".into());
        settings.insert("Interprocedural".into(), "ContextBased".into());
        settings.insert("DescendingPhase".into(), "Narrowing".into());
        settings.insert("OpenCallPolicy".into(), "ReturnTop".into());
        settings.insert("Output.GraphFormat".into(), "HTML".into());
        settings.insert("CallGraph".into(), "Call Hierarchy Analysis".into());
        settings.insert("Post-State".into(), "true".into());
        settings.insert("Display 'top' values".into(), "true".into());
        settings.insert("Display 'unique' values".into(), "true".into());
        settings.insert("Use high pcode".into(), "true".into());
        settings.insert("Compute CFGs to Depth".into(), "3".into());
        settings.insert("Threshhold".into(), "10".into());
        settings.insert("Output.WorkDir".into(), "/tmp/lisa".into());
        settings.insert("Output.SerializeResults".into(), "true".into());
        settings.insert("OptimizeResults".into(), "true".into());

        options.grab_from_settings(&settings);

        assert_eq!(options.config.heap_domain, HeapDomainOption::PointBased);
        assert_eq!(options.config.type_domain, TypeDomainOption::Static);
        assert_eq!(options.config.value_domain, ValueDomainOption::Taint);
        assert_eq!(
            options.config.interprocedural,
            InterproceduralOption::ContextBased
        );
        assert_eq!(
            options.config.descending_phase,
            DescendingPhaseOption::Narrowing
        );
        assert_eq!(options.config.call_policy, CallPolicyOption::ReturnTop);
        assert_eq!(options.config.graph_format, GraphOption::Html);
        assert_eq!(options.config.call_graph, CallGraphOption::Cha);
        assert!(options.config.post_state);
        assert!(options.config.show_top);
        assert!(options.config.show_unique);
        assert!(options.config.use_high_pcode);
        assert_eq!(options.config.cfg_depth, 3);
        assert_eq!(options.config.threshold, 10);
        assert_eq!(options.config.output_dir, "/tmp/lisa");
        assert!(options.config.serialize_results);
        assert!(options.config.optimize);
        assert!(options.is_loaded());
    }

    #[test]
    fn test_lisa_plugin_options_grab_defaults() {
        let mut options = LisaPluginOptions::new();
        options.grab_from_settings(&HashMap::new());

        assert_eq!(options.config.heap_domain, HeapDomainOption::Default);
        assert_eq!(options.config.value_domain, ValueDomainOption::Default);
        assert!(!options.config.post_state);
        assert_eq!(options.config.cfg_depth, 0);
        assert_eq!(options.config.threshold, 5);
        assert!(options.is_loaded());
    }

    #[test]
    fn test_parse_helpers() {
        assert_eq!(parse_heap_domain("PointBased"), HeapDomainOption::PointBased);
        assert_eq!(parse_heap_domain("unknown"), HeapDomainOption::Default);

        assert_eq!(parse_type_domain("Static"), TypeDomainOption::Static);
        assert_eq!(parse_type_domain("unknown"), TypeDomainOption::Default);

        assert_eq!(parse_value_domain("Dataflow: Taint"), ValueDomainOption::Taint);
        assert_eq!(parse_value_domain("unknown"), ValueDomainOption::Default);

        assert_eq!(
            parse_interprocedural("ContextBased"),
            InterproceduralOption::ContextBased
        );
        assert_eq!(
            parse_interprocedural("unknown"),
            InterproceduralOption::ModularWorstCase
        );

        assert_eq!(
            parse_descending_phase("Narrowing"),
            DescendingPhaseOption::Narrowing
        );
        assert_eq!(
            parse_descending_phase("unknown"),
            DescendingPhaseOption::None
        );

        assert_eq!(parse_call_policy("ReturnTop"), CallPolicyOption::ReturnTop);
        assert_eq!(parse_call_policy("unknown"), CallPolicyOption::WorstCase);

        assert_eq!(parse_graph_option("HTML"), GraphOption::Html);
        assert_eq!(parse_graph_option("unknown"), GraphOption::None);

        assert_eq!(
            parse_call_graph("Call Hierarchy Analysis"),
            CallGraphOption::Cha
        );
        assert_eq!(parse_call_graph("unknown"), CallGraphOption::Rta);
    }

    #[test]
    fn test_plugin_event_clone_eq() {
        let e1 = PluginEvent::ProgramActivated { program_name: "test".into() };
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_action_default() {
        assert_eq!(AddCfgsAction::default().name, "Add CFG");
        assert_eq!(ClearCfgsAction::default().name, "Clear CFGs");
        assert_eq!(SetTaintAction::default().name, "Set Taint");
    }
}
