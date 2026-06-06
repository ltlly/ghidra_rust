//! Decompiler analysis commands.
//!
//! Port of Ghidra's decompiler analysis commands:
//! - `DecompilerFunctionAnalyzer`: analyzes functions via decompilation
//! - `DecompilerSwitchAnalyzer`: identifies switch tables via decompilation
//! - `DecompilerCallConventionAnalyzer`: analyzes calling conventions
//! - `ConventionAnalysisDecompileConfigurer`: configurer for convention analysis
//! - `SwitchAnalysisDecompileConfigurer`: configurer for switch analysis

use serde::{Deserialize, Serialize};

/// Result of a decompiler analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Whether the analysis was successful.
    pub success: bool,
    /// The function entry point analyzed.
    pub function_entry: u64,
    /// Number of discoveries made.
    pub discovery_count: u32,
    /// Analysis message.
    pub message: String,
}

impl AnalysisResult {
    /// Create a successful result.
    pub fn success(function_entry: u64, discovery_count: u32) -> Self {
        Self {
            success: true,
            function_entry,
            discovery_count,
            message: String::new(),
        }
    }

    /// Create a failure result.
    pub fn failure(function_entry: u64, message: impl Into<String>) -> Self {
        Self {
            success: false,
            function_entry,
            discovery_count: 0,
            message: message.into(),
        }
    }
}

/// Decompiler function analyzer.
///
/// Port of `ghidra.app.plugin.core.analysis.DecompilerFunctionAnalyzer`.
#[derive(Debug, Clone)]
pub struct DecompilerFunctionAnalyzer {
    /// Analyzer name.
    pub name: String,
    /// Whether enabled.
    pub enabled: bool,
    /// Timeout per function in seconds.
    pub timeout_secs: u32,
}

impl DecompilerFunctionAnalyzer {
    /// Create a new function analyzer.
    pub fn new() -> Self {
        Self {
            name: "DecompilerFunctionAnalyzer".into(),
            enabled: true,
            timeout_secs: 30,
        }
    }

    /// Analyze a function (placeholder).
    pub fn analyze(&self, function_entry: u64) -> AnalysisResult {
        if self.enabled {
            AnalysisResult::success(function_entry, 0)
        } else {
            AnalysisResult::failure(function_entry, "Analyzer disabled")
        }
    }
}

impl Default for DecompilerFunctionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Decompiler switch analyzer.
///
/// Port of `ghidra.app.plugin.core.analysis.DecompilerSwitchAnalyzer`.
#[derive(Debug, Clone)]
pub struct DecompilerSwitchAnalyzer {
    /// Analyzer name.
    pub name: String,
    /// Whether enabled.
    pub enabled: bool,
    /// Whether to override existing switch analysis.
    pub override_existing: bool,
}

impl DecompilerSwitchAnalyzer {
    /// Create a new switch analyzer.
    pub fn new() -> Self {
        Self {
            name: "DecompilerSwitchAnalyzer".into(),
            enabled: true,
            override_existing: false,
        }
    }

    /// Analyze switch tables in a function (placeholder).
    pub fn analyze(&self, function_entry: u64) -> AnalysisResult {
        if self.enabled {
            AnalysisResult::success(function_entry, 0)
        } else {
            AnalysisResult::failure(function_entry, "Analyzer disabled")
        }
    }
}

impl Default for DecompilerSwitchAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Decompiler calling convention analyzer.
///
/// Port of `ghidra.app.plugin.core.analysis.DecompilerCallConventionAnalyzer`.
#[derive(Debug, Clone)]
pub struct DecompilerCallConventionAnalyzer {
    /// Analyzer name.
    pub name: String,
    /// Whether enabled.
    pub enabled: bool,
    /// Whether to analyze in parallel.
    pub parallel: bool,
}

impl DecompilerCallConventionAnalyzer {
    /// Create a new calling convention analyzer.
    pub fn new() -> Self {
        Self {
            name: "DecompilerCallConventionAnalyzer".into(),
            enabled: true,
            parallel: true,
        }
    }

    /// Analyze calling conventions (placeholder).
    pub fn analyze(&self, function_entry: u64) -> AnalysisResult {
        if self.enabled {
            AnalysisResult::success(function_entry, 0)
        } else {
            AnalysisResult::failure(function_entry, "Analyzer disabled")
        }
    }
}

impl Default for DecompilerCallConventionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Configurer for calling convention analysis.
///
/// Port of `ghidra.app.plugin.core.analysis.ConventionAnalysisDecompileConfigurer`.
#[derive(Debug, Clone)]
pub struct ConventionAnalysisDecompileConfigurer {
    /// Whether to use simplified output.
    pub simplified: bool,
    /// Decompiler timeout in seconds.
    pub timeout_secs: u32,
}

impl ConventionAnalysisDecompileConfigurer {
    /// Create a new configurer.
    pub fn new() -> Self {
        Self { simplified: true, timeout_secs: 60 }
    }
}

impl Default for ConventionAnalysisDecompileConfigurer {
    fn default() -> Self {
        Self::new()
    }
}

/// Configurer for switch analysis.
///
/// Port of `ghidra.app.plugin.core.analysis.SwitchAnalysisDecompileConfigurer`.
#[derive(Debug, Clone)]
pub struct SwitchAnalysisDecompileConfigurer {
    /// Whether to normalize switch tables.
    pub normalize: bool,
    /// Decompiler timeout in seconds.
    pub timeout_secs: u32,
}

impl SwitchAnalysisDecompileConfigurer {
    /// Create a new configurer.
    pub fn new() -> Self {
        Self { normalize: true, timeout_secs: 30 }
    }
}

impl Default for SwitchAnalysisDecompileConfigurer {
    fn default() -> Self {
        Self::new()
    }
}

/// P-code CFG display listener.
///
/// Port of `ghidra.app.plugin.core.decompile.actions.PCodeCfgDisplayListener`.
pub trait PcodeCfgDisplayListener: std::fmt::Debug {
    /// Called when the CFG is displayed.
    fn cfg_displayed(&self, function_entry: u64, block_count: usize);

    /// Called when the display is cleared.
    fn cfg_cleared(&self);
}

/// P-code DFG (Data Flow Graph) display listener.
///
/// Port of `ghidra.app.plugin.core.decompile.actions.PCodeDfgDisplayListener`.
pub trait PcodeDfgDisplayListener: std::fmt::Debug {
    /// Called when the DFG is displayed.
    fn dfg_displayed(&self, function_entry: u64, node_count: usize);

    /// Called when the display is cleared.
    fn dfg_cleared(&self);
}

/// P-code DFG display options.
///
/// Port of `ghidra.app.plugin.core.decompile.actions.PCodeDfgDisplayOptions`.
#[derive(Debug, Clone)]
pub struct PcodeDfgDisplayOptions {
    /// Whether to show register names.
    pub show_registers: bool,
    /// Whether to show constant values.
    pub show_constants: bool,
    /// Whether to show memory addresses.
    pub show_addresses: bool,
    /// Whether to collapse trivial sequences.
    pub collapse_trivial: bool,
}

impl Default for PcodeDfgDisplayOptions {
    fn default() -> Self {
        Self {
            show_registers: true,
            show_constants: true,
            show_addresses: false,
            collapse_trivial: true,
        }
    }
}

impl PcodeDfgDisplayOptions {
    /// Create new default options.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Slice highlight color provider.
///
/// Port of `ghidra.app.plugin.core.decompile.actions.SliceHighlightColorProvider`.
#[derive(Debug, Clone)]
pub struct SliceHighlightColorProvider {
    /// Colors for different slice depths.
    pub depth_colors: Vec<String>,
}

impl Default for SliceHighlightColorProvider {
    fn default() -> Self {
        Self {
            depth_colors: vec![
                "#ff8080".into(),
                "#80ff80".into(),
                "#8080ff".into(),
                "#ffff80".into(),
                "#ff80ff".into(),
                "#80ffff".into(),
            ],
        }
    }
}

impl SliceHighlightColorProvider {
    /// Create a new provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the color for a given depth.
    pub fn color_for_depth(&self, depth: usize) -> &str {
        if self.depth_colors.is_empty() {
            "#ffffff"
        } else {
            &self.depth_colors[depth % self.depth_colors.len()]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_analyzer() {
        let analyzer = DecompilerFunctionAnalyzer::new();
        let result = analyzer.analyze(0x401000);
        assert!(result.success);
        assert_eq!(result.function_entry, 0x401000);
    }

    #[test]
    fn test_function_analyzer_disabled() {
        let mut analyzer = DecompilerFunctionAnalyzer::new();
        analyzer.enabled = false;
        let result = analyzer.analyze(0x401000);
        assert!(!result.success);
    }

    #[test]
    fn test_switch_analyzer() {
        let analyzer = DecompilerSwitchAnalyzer::new();
        let result = analyzer.analyze(0x401000);
        assert!(result.success);
    }

    #[test]
    fn test_convention_analyzer() {
        let analyzer = DecompilerCallConventionAnalyzer::new();
        assert!(analyzer.parallel);
        let result = analyzer.analyze(0x401000);
        assert!(result.success);
    }

    #[test]
    fn test_analysis_result() {
        let ok = AnalysisResult::success(0x1000, 5);
        assert!(ok.success);
        assert_eq!(ok.discovery_count, 5);

        let fail = AnalysisResult::failure(0x2000, "timeout");
        assert!(!fail.success);
        assert_eq!(fail.message, "timeout");
    }

    #[test]
    fn test_convention_configurer() {
        let c = ConventionAnalysisDecompileConfigurer::new();
        assert!(c.simplified);
        assert_eq!(c.timeout_secs, 60);
    }

    #[test]
    fn test_switch_configurer() {
        let c = SwitchAnalysisDecompileConfigurer::new();
        assert!(c.normalize);
    }

    #[test]
    fn test_pcode_dfg_options() {
        let opts = PcodeDfgDisplayOptions::new();
        assert!(opts.show_registers);
        assert!(opts.collapse_trivial);
    }

    #[test]
    fn test_slice_highlight_color_provider() {
        let p = SliceHighlightColorProvider::new();
        assert!(!p.color_for_depth(0).is_empty());
        assert_eq!(p.color_for_depth(0), p.color_for_depth(6)); // cycles
    }
}
