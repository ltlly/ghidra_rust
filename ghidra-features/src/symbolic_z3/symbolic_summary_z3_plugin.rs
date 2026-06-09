//! Symbolic Summary Z3 Plugin.
//!
//! Ported from `SymbolicSummaryZ3Plugin.java` in the SymbolicSummaryZ3
//! extension.
//!
//! Provides the Ghidra plugin interface for running symbolic Z3 summary
//! analysis on functions. The plugin manages the analyzer lifecycle,
//! user-facing settings, and result presentation through a dockable panel.

use super::gui::{Z3SummaryPlugin, Z3SummaryProvider};
use super::state::SymZ3PcodeExecutorState;
use super::symbolic_summary_z3_analyzer::{
    SymbolicSummaryZ3Analyzer, SymbolicSummaryZ3AnalyzerConfig, SymbolicSummaryZ3AnalyzerResult,
};

// ---------------------------------------------------------------------------
// SymbolicSummaryZ3Plugin
// ---------------------------------------------------------------------------

/// Plugin for running symbolic Z3 summary analysis.
///
/// Manages the analyzer lifecycle and integrates with Ghidra's plugin
/// framework. Provides methods to configure and run symbolic execution,
/// and presents results through the GUI components.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::symbolic_z3::symbolic_summary_z3_plugin::SymbolicSummaryZ3Plugin;
///
/// let mut plugin = SymbolicSummaryZ3Plugin::new("x86:LE:64:default");
/// plugin.set_max_instructions(500);
///
/// // Simulate analysis
/// plugin.begin_analysis();
/// plugin.analyze_instruction(0x401000, "MOV RAX, 42");
/// plugin.set_register("RAX", 0x42, 64);
/// let result = plugin.end_analysis();
///
/// assert!(result.is_some());
/// ```
pub struct SymbolicSummaryZ3Plugin {
    /// The summary GUI plugin.
    summary_plugin: Z3SummaryPlugin,
    /// The summary provider (panel manager).
    summary_provider: Z3SummaryProvider,
    /// Analysis configuration.
    config: SymbolicSummaryZ3AnalyzerConfig,
    /// Language for the current program.
    language: String,
    /// Whether the program is big-endian.
    big_endian: bool,
    /// Whether the plugin is enabled.
    enabled: bool,
    /// Current analyzer (active during analysis).
    current_analyzer: Option<SymbolicSummaryZ3Analyzer>,
    /// Last analysis result.
    last_result: Option<SymbolicSummaryZ3AnalyzerResult>,
    /// Number of analyses performed.
    analysis_count: usize,
}

impl SymbolicSummaryZ3Plugin {
    /// Create a new plugin for the given language.
    pub fn new(language: impl Into<String>) -> Self {
        let lang = language.into();
        let big_endian = lang.contains(":BE:");
        Self {
            summary_plugin: Z3SummaryPlugin::new(),
            summary_provider: Z3SummaryProvider::new("Z3 Symbolic Summary"),
            config: SymbolicSummaryZ3AnalyzerConfig::default(),
            language: lang,
            big_endian,
            enabled: true,
            current_analyzer: None,
            last_result: None,
            analysis_count: 0,
        }
    }

    /// Get the language name.
    pub fn language(&self) -> &str {
        &self.language
    }

    /// Whether the language is big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Set the maximum number of instructions to analyze.
    pub fn set_max_instructions(&mut self, max: usize) {
        self.config.max_instructions = max;
    }

    /// Set the maximum number of p-code operations.
    pub fn set_max_pcode_ops(&mut self, max: usize) {
        self.config.max_pcode_ops = max;
    }

    /// Set whether to record instruction logs.
    pub fn set_record_instruction_log(&mut self, record: bool) {
        self.config.record_instruction_log = record;
    }

    /// Set whether to record p-code logs.
    pub fn set_record_pcode_log(&mut self, record: bool) {
        self.config.record_pcode_log = record;
    }

    /// Set whether to use infix notation.
    pub fn set_use_infix_notation(&mut self, use_infix: bool) {
        self.config.use_infix_notation = use_infix;
    }

    /// Set whether to track memory witnesses.
    pub fn set_track_memory_witness(&mut self, track: bool) {
        self.config.track_memory_witness = track;
    }

    /// Get the analysis configuration.
    pub fn config(&self) -> &SymbolicSummaryZ3AnalyzerConfig {
        &self.config
    }

    /// Get a mutable reference to the analysis configuration.
    pub fn config_mut(&mut self) -> &mut SymbolicSummaryZ3AnalyzerConfig {
        &mut self.config
    }

    /// Get the summary GUI plugin.
    pub fn summary_plugin(&self) -> &Z3SummaryPlugin {
        &self.summary_plugin
    }

    /// Get a mutable reference to the summary GUI plugin.
    pub fn summary_plugin_mut(&mut self) -> &mut Z3SummaryPlugin {
        &mut self.summary_plugin
    }

    /// Get the summary provider.
    pub fn summary_provider(&self) -> &Z3SummaryProvider {
        &self.summary_provider
    }

    /// Get a mutable reference to the summary provider.
    pub fn summary_provider_mut(&mut self) -> &mut Z3SummaryProvider {
        &mut self.summary_provider
    }

    /// Begin a new symbolic analysis.
    ///
    /// Creates a new analyzer and prepares it for processing instructions.
    /// Returns `false` if the plugin is disabled or an analysis is already
    /// in progress.
    pub fn begin_analysis(&mut self) -> bool {
        if !self.enabled {
            return false;
        }
        if self.current_analyzer.is_some() {
            return false;
        }

        let analyzer = SymbolicSummaryZ3Analyzer::new(
            &self.language,
            self.big_endian,
            self.config.clone(),
        );
        self.current_analyzer = Some(analyzer);
        self.summary_plugin.clear();
        true
    }

    /// Analyze a single instruction.
    ///
    /// Records the instruction in the current analysis. Returns `false`
    /// if no analysis is in progress.
    pub fn analyze_instruction(&mut self, address: u64, mnemonic: &str) -> bool {
        if let Some(ref mut analyzer) = self.current_analyzer {
            analyzer.record_instruction(address, mnemonic)
        } else {
            false
        }
    }

    /// Record a p-code operation in the current analysis.
    pub fn record_pcode_op(
        &mut self,
        mnemonic: &str,
        output: Option<&str>,
        inputs: &[&str],
    ) -> bool {
        if let Some(ref mut analyzer) = self.current_analyzer {
            analyzer.record_pcode_op(mnemonic, output, inputs)
        } else {
            false
        }
    }

    /// Set a register value in the current analysis.
    pub fn set_register(&mut self, name: &str, value: u64, size_bits: u32) {
        if let Some(ref mut analyzer) = self.current_analyzer {
            analyzer.set_register(name, value, size_bits);
        }
    }

    /// Set a symbolic register value in the current analysis.
    pub fn set_register_symbolic(&mut self, name: &str, size_bits: u32) {
        if let Some(ref mut analyzer) = self.current_analyzer {
            analyzer.set_register_symbolic(name, size_bits);
        }
    }

    /// Store a value to symbolic memory in the current analysis.
    pub fn store_memory(&mut self, address: u64, value: u64, size_bits: u32) {
        if let Some(ref mut analyzer) = self.current_analyzer {
            analyzer.store_memory(address, value, size_bits);
        }
    }

    /// Add a precondition to the current analysis.
    pub fn add_precondition(&mut self, condition: impl Into<String>) {
        if let Some(ref mut analyzer) = self.current_analyzer {
            analyzer.add_precondition(condition);
        }
    }

    /// End the current analysis and return the result.
    ///
    /// Returns `None` if no analysis was in progress.
    pub fn end_analysis(&mut self) -> Option<&SymbolicSummaryZ3AnalyzerResult> {
        let analyzer = self.current_analyzer.take()?;
        let result = analyzer.finish();

        // Update the GUI
        self.summary_plugin
            .set_summary_text(&result.summary_text);
        for entry in &result.instruction_log {
            self.summary_plugin.add_instruction_log(entry);
        }
        for entry in &result.pcode_log {
            self.summary_plugin.add_pcode_log(entry);
        }

        self.last_result = Some(result);
        self.analysis_count += 1;
        self.last_result.as_ref()
    }

    /// Get the last analysis result.
    pub fn last_result(&self) -> Option<&SymbolicSummaryZ3AnalyzerResult> {
        self.last_result.as_ref()
    }

    /// Get the number of analyses performed.
    pub fn analysis_count(&self) -> usize {
        self.analysis_count
    }

    /// Whether an analysis is currently in progress.
    pub fn is_analyzing(&self) -> bool {
        self.current_analyzer.is_some()
    }

    /// Show the summary panel.
    pub fn show_panel(&mut self) {
        self.summary_provider.show();
    }

    /// Hide the summary panel.
    pub fn hide_panel(&mut self) {
        self.summary_provider.hide();
    }

    /// Whether the summary panel is visible.
    pub fn is_panel_visible(&self) -> bool {
        self.summary_provider.is_visible()
    }

    /// Dispose of the plugin.
    pub fn dispose(&mut self) {
        self.current_analyzer = None;
        self.last_result = None;
        self.enabled = false;
        self.summary_plugin.clear();
        self.summary_provider.hide();
    }
}

impl Default for SymbolicSummaryZ3Plugin {
    fn default() -> Self {
        Self::new("x86:LE:64:default")
    }
}

impl std::fmt::Debug for SymbolicSummaryZ3Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymbolicSummaryZ3Plugin")
            .field("language", &self.language)
            .field("big_endian", &self.big_endian)
            .field("enabled", &self.enabled)
            .field("is_analyzing", &self.is_analyzing())
            .field("analysis_count", &self.analysis_count)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// SymbolicSummaryZ3PluginState
// ---------------------------------------------------------------------------

/// Serializable state for the symbolic summary Z3 plugin.
///
/// Captures the plugin configuration that can be persisted across sessions.
#[derive(Debug, Clone)]
pub struct SymbolicSummaryZ3PluginState {
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Maximum instructions per analysis.
    pub max_instructions: usize,
    /// Maximum p-code ops per analysis.
    pub max_pcode_ops: usize,
    /// Whether to record instruction log.
    pub record_instruction_log: bool,
    /// Whether to record p-code log.
    pub record_pcode_log: bool,
    /// Whether to use infix notation.
    pub use_infix_notation: bool,
    /// Whether to track memory witness.
    pub track_memory_witness: bool,
}

impl SymbolicSummaryZ3PluginState {
    /// Save the current plugin state.
    pub fn from_plugin(plugin: &SymbolicSummaryZ3Plugin) -> Self {
        Self {
            enabled: plugin.enabled,
            max_instructions: plugin.config.max_instructions,
            max_pcode_ops: plugin.config.max_pcode_ops,
            record_instruction_log: plugin.config.record_instruction_log,
            record_pcode_log: plugin.config.record_pcode_log,
            use_infix_notation: plugin.config.use_infix_notation,
            track_memory_witness: plugin.config.track_memory_witness,
        }
    }

    /// Restore plugin state.
    pub fn apply_to(&self, plugin: &mut SymbolicSummaryZ3Plugin) {
        plugin.enabled = self.enabled;
        plugin.config.max_instructions = self.max_instructions;
        plugin.config.max_pcode_ops = self.max_pcode_ops;
        plugin.config.record_instruction_log = self.record_instruction_log;
        plugin.config.record_pcode_log = self.record_pcode_log;
        plugin.config.use_infix_notation = self.use_infix_notation;
        plugin.config.track_memory_witness = self.track_memory_witness;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = SymbolicSummaryZ3Plugin::new("x86:LE:64:default");
        assert!(plugin.is_enabled());
        assert_eq!(plugin.language(), "x86:LE:64:default");
        assert!(!plugin.is_big_endian());
        assert!(!plugin.is_analyzing());
        assert_eq!(plugin.analysis_count(), 0);
    }

    #[test]
    fn test_plugin_big_endian() {
        let plugin = SymbolicSummaryZ3Plugin::new("PowerPC:BE:64:default");
        assert!(plugin.is_big_endian());
    }

    #[test]
    fn test_plugin_set_enabled() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.set_enabled(false);
        assert!(!plugin.is_enabled());
    }

    #[test]
    fn test_plugin_set_max_instructions() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.set_max_instructions(500);
        assert_eq!(plugin.config().max_instructions, 500);
    }

    #[test]
    fn test_plugin_set_max_pcode_ops() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.set_max_pcode_ops(5000);
        assert_eq!(plugin.config().max_pcode_ops, 5000);
    }

    #[test]
    fn test_plugin_begin_end_analysis() {
        let mut plugin = SymbolicSummaryZ3Plugin::new("x86:LE:64:default");
        assert!(plugin.begin_analysis());
        assert!(plugin.is_analyzing());

        plugin.analyze_instruction(0x401000, "MOV RAX, 42");
        plugin.set_register("RAX", 0x42, 64);

        let result = plugin.end_analysis();
        assert!(result.is_some());
        assert!(!plugin.is_analyzing());
        assert_eq!(plugin.analysis_count(), 1);
    }

    #[test]
    fn test_plugin_begin_when_disabled() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.set_enabled(false);
        assert!(!plugin.begin_analysis());
    }

    #[test]
    fn test_plugin_begin_twice() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        assert!(plugin.begin_analysis());
        assert!(!plugin.begin_analysis()); // Already in progress
    }

    #[test]
    fn test_plugin_end_without_begin() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        assert!(plugin.end_analysis().is_none());
    }

    #[test]
    fn test_plugin_analyze_instruction_no_analysis() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        assert!(!plugin.analyze_instruction(0x401000, "NOP"));
    }

    #[test]
    fn test_plugin_record_pcode_op() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.begin_analysis();
        assert!(plugin.record_pcode_op("INT_ADD", Some("RAX"), &["RBX", "RCX"]));
    }

    #[test]
    fn test_plugin_set_register_symbolic() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.begin_analysis();
        plugin.set_register_symbolic("RAX", 64);
        plugin.end_analysis();
    }

    #[test]
    fn test_plugin_store_memory() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.begin_analysis();
        plugin.store_memory(0x1000, 0xFF, 8);
        plugin.end_analysis();
    }

    #[test]
    fn test_plugin_add_precondition() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.begin_analysis();
        plugin.add_precondition("RAX != 0");
        plugin.end_analysis();
    }

    #[test]
    fn test_plugin_panel_visibility() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        assert!(!plugin.is_panel_visible());

        plugin.show_panel();
        assert!(plugin.is_panel_visible());

        plugin.hide_panel();
        assert!(!plugin.is_panel_visible());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.begin_analysis();
        plugin.dispose();
        assert!(!plugin.is_enabled());
        assert!(!plugin.is_analyzing());
    }

    #[test]
    fn test_plugin_multiple_analyses() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();

        // First analysis
        plugin.begin_analysis();
        plugin.analyze_instruction(0x1000, "NOP");
        plugin.end_analysis();
        assert_eq!(plugin.analysis_count(), 1);

        // Second analysis
        plugin.begin_analysis();
        plugin.analyze_instruction(0x2000, "RET");
        plugin.end_analysis();
        assert_eq!(plugin.analysis_count(), 2);
    }

    #[test]
    fn test_plugin_state_save_restore() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.set_max_instructions(500);
        plugin.set_record_instruction_log(false);

        let state = SymbolicSummaryZ3PluginState::from_plugin(&plugin);
        assert_eq!(state.max_instructions, 500);
        assert!(!state.record_instruction_log);

        // Restore to a new plugin
        let mut plugin2 = SymbolicSummaryZ3Plugin::default();
        state.apply_to(&mut plugin2);
        assert_eq!(plugin2.config().max_instructions, 500);
        assert!(!plugin2.config().record_instruction_log);
    }

    #[test]
    fn test_plugin_debug_format() {
        let plugin = SymbolicSummaryZ3Plugin::new("x86:LE:64:default");
        let debug = format!("{:?}", plugin);
        assert!(debug.contains("SymbolicSummaryZ3Plugin"));
        assert!(debug.contains("x86:LE:64:default"));
    }

    #[test]
    fn test_plugin_default() {
        let plugin = SymbolicSummaryZ3Plugin::default();
        assert_eq!(plugin.language(), "x86:LE:64:default");
        assert!(!plugin.is_big_endian());
    }

    #[test]
    fn test_plugin_config_mut() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.config_mut().max_instructions = 2000;
        assert_eq!(plugin.config().max_instructions, 2000);
    }

    #[test]
    fn test_plugin_summary_plugin_access() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.summary_plugin_mut().set_summary_text("test");
        assert_eq!(plugin.summary_plugin().summary_text(), "test");
    }

    #[test]
    fn test_plugin_summary_provider_access() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.summary_provider_mut().show();
        assert!(plugin.summary_provider().is_visible());
    }

    #[test]
    fn test_plugin_analysis_updates_gui() {
        let mut plugin = SymbolicSummaryZ3Plugin::default();
        plugin.begin_analysis();
        plugin.set_register("RAX", 0x42, 64);
        plugin.end_analysis();

        // The summary plugin should have been updated
        assert!(!plugin.summary_plugin().summary_text().is_empty());
    }
}
