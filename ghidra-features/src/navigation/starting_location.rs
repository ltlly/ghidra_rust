//! Program starting location options -- ported from
//! `ghidra.app.plugin.core.navigation.ProgramStartingLocationOptions`.
//!
//! Manages configuration for where a newly opened program's listing
//! cursor is initially positioned: at the lowest address, the lowest
//! code address, a preferred symbol name (e.g., `main`), or the last
//! known location.
//!
//! Also controls post-analysis repositioning behavior.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// StartLocationType
// ---------------------------------------------------------------------------

/// Determines the initial listing cursor position for a newly opened
/// program.
///
/// Ported from
/// `ProgramStartingLocationOptions.StartLocationType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StartLocationType {
    /// Position at the lowest mapped address.
    LowestAddress,
    /// Position at the lowest code (executable) address.
    LowestCodeBlock,
    /// Position at the first matching preferred symbol name.
    SymbolName,
    /// Position at the address where the user last left the program.
    LastLocation,
}

impl StartLocationType {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::LowestAddress => "Lowest Address",
            Self::LowestCodeBlock => "Lowest Code Block Address",
            Self::SymbolName => "Preferred Symbol Name",
            Self::LastLocation => "Location When Last Closed",
        }
    }
}

impl Default for StartLocationType {
    fn default() -> Self {
        Self::LastLocation
    }
}

impl std::fmt::Display for StartLocationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// ProgramStartingLocationOptions
// ---------------------------------------------------------------------------

/// Configuration for program starting location and post-analysis
/// repositioning.
///
/// Ported from
/// `ghidra.app.plugin.core.navigation.ProgramStartingLocationOptions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramStartingLocationOptions {
    /// The strategy for positioning the cursor when a program is opened.
    pub start_location_type: StartLocationType,
    /// Ordered list of preferred starting symbol names (e.g.,
    /// `["main", "_main", "start", "entry"]`).
    pub start_symbols: Vec<String>,
    /// When searching for starting symbols, also search for names
    /// prepended with `_` and `__`.
    pub use_underscore_prefixes: bool,
    /// After the initial analysis pass, ask the user whether to
    /// reposition to a newly discovered starting symbol.
    pub ask_to_move_after_analysis: bool,
    /// After the initial analysis pass, automatically reposition to a
    /// newly discovered starting symbol if the user has not manually
    /// moved.
    pub auto_move_after_analysis: bool,
}

impl ProgramStartingLocationOptions {
    /// Default starting symbol names (comma-separated in Java source).
    pub const DEFAULT_START_SYMBOLS: &'static [&'static str] = &[
        "main.main",
        "main",
        "wmain",
        "WinMain",
        "wWinMain",
        "DriverEntry",
        "libc_start_main",
        "WinMainStartup",
        "start",
        "entry",
    ];

    /// Create options with all default values.
    pub fn new() -> Self {
        Self {
            start_location_type: StartLocationType::default(),
            start_symbols: Self::DEFAULT_START_SYMBOLS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            use_underscore_prefixes: true,
            ask_to_move_after_analysis: true,
            auto_move_after_analysis: true,
        }
    }

    /// Parse a comma-separated symbol names string (mirrors the Java
    /// `parse()` helper).
    pub fn parse_symbol_names(comma_separated: &str) -> Vec<String> {
        comma_separated
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Get the expanded list of symbol names to search for, including
    /// underscore-prefixed variants when enabled.
    pub fn expanded_symbol_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for name in &self.start_symbols {
            names.push(name.clone());
            if self.use_underscore_prefixes {
                names.push(format!("_{}", name));
                names.push(format!("__{}", name));
            }
        }
        names
    }
}

impl Default for ProgramStartingLocationOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ProgramStartingLocationPlugin (model)
// ---------------------------------------------------------------------------

/// Plugin model for managing program starting location.
///
/// Ported from
/// `ghidra.app.plugin.core.navigation.ProgramStartingLocationPlugin`.
/// This is the non-GUI model; the UI component provider lives in
/// `ghidra-gui`.
#[derive(Debug)]
pub struct ProgramStartingLocationPlugin {
    /// Current options.
    pub options: ProgramStartingLocationOptions,
    /// Whether this is the first time analysis has completed for the
    /// current program.
    pub is_first_analysis: bool,
    /// Whether the user has manually navigated since the program was
    /// opened.
    pub user_has_moved: bool,
}

impl ProgramStartingLocationPlugin {
    /// Create a new plugin model.
    pub fn new(options: ProgramStartingLocationOptions) -> Self {
        Self {
            options,
            is_first_analysis: true,
            user_has_moved: false,
        }
    }

    /// Called when analysis completes.  Returns the address to navigate
    /// to, or `None` if no repositioning is needed.
    ///
    /// The `discovered_symbols` parameter is a list of
    /// `(symbol_name, address)` pairs found during analysis.
    pub fn on_analysis_complete(
        &mut self,
        discovered_symbols: &[(String, u64)],
    ) -> Option<u64> {
        if !self.is_first_analysis {
            return None;
        }
        self.is_first_analysis = false;

        // If the user has already moved, only auto-move if configured.
        if self.user_has_moved && !self.options.auto_move_after_analysis {
            return None;
        }

        // Try to find a matching starting symbol.
        let expanded = self.options.expanded_symbol_names();
        for symbol_name in &expanded {
            for (name, addr) in discovered_symbols {
                if name == symbol_name {
                    return Some(*addr);
                }
            }
        }

        None
    }

    /// Mark that the user has manually navigated.
    pub fn mark_user_moved(&mut self) {
        self.user_has_moved = true;
    }
}

impl Default for ProgramStartingLocationPlugin {
    fn default() -> Self {
        Self::new(ProgramStartingLocationOptions::default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_location_type_display() {
        assert_eq!(StartLocationType::LowestAddress.label(), "Lowest Address");
        assert_eq!(
            StartLocationType::LastLocation.label(),
            "Location When Last Closed"
        );
    }

    #[test]
    fn test_start_location_type_default() {
        assert_eq!(StartLocationType::default(), StartLocationType::LastLocation);
    }

    #[test]
    fn test_parse_symbol_names() {
        let names =
            ProgramStartingLocationOptions::parse_symbol_names("main, _start, entry,, ");
        assert_eq!(names, vec!["main", "_start", "entry"]);
    }

    #[test]
    fn test_parse_symbol_names_single() {
        let names = ProgramStartingLocationOptions::parse_symbol_names("main");
        assert_eq!(names, vec!["main"]);
    }

    #[test]
    fn test_parse_symbol_names_empty() {
        let names = ProgramStartingLocationOptions::parse_symbol_names("");
        assert!(names.is_empty());
    }

    #[test]
    fn test_expanded_symbol_names_with_prefixes() {
        let opts = ProgramStartingLocationOptions {
            start_symbols: vec!["main".into()],
            use_underscore_prefixes: true,
            ..Default::default()
        };
        let expanded = opts.expanded_symbol_names();
        assert_eq!(expanded, vec!["main", "_main", "__main"]);
    }

    #[test]
    fn test_expanded_symbol_names_without_prefixes() {
        let opts = ProgramStartingLocationOptions {
            start_symbols: vec!["main".into()],
            use_underscore_prefixes: false,
            ..Default::default()
        };
        let expanded = opts.expanded_symbol_names();
        assert_eq!(expanded, vec!["main"]);
    }

    #[test]
    fn test_default_options() {
        let opts = ProgramStartingLocationOptions::default();
        assert_eq!(
            opts.start_location_type,
            StartLocationType::LastLocation
        );
        assert!(!opts.start_symbols.is_empty());
        assert!(opts.use_underscore_prefixes);
        assert!(opts.ask_to_move_after_analysis);
        assert!(opts.auto_move_after_analysis);
    }

    #[test]
    fn test_plugin_on_analysis_first_time() {
        let mut plugin = ProgramStartingLocationPlugin::default();
        let symbols = vec![
            ("other_func".to_string(), 0x1000u64),
            ("main".to_string(), 0x400000u64),
        ];
        // Should find "main" (first in expanded list).
        let result = plugin.on_analysis_complete(&symbols);
        assert_eq!(result, Some(0x400000));
    }

    #[test]
    fn test_plugin_on_analysis_no_match() {
        let mut plugin = ProgramStartingLocationPlugin::default();
        let symbols = vec![("unknown_func".to_string(), 0x1000u64)];
        let result = plugin.on_analysis_complete(&symbols);
        assert!(result.is_none());
    }

    #[test]
    fn test_plugin_on_analysis_not_first() {
        let mut plugin = ProgramStartingLocationPlugin::default();
        let symbols = vec![("main".to_string(), 0x400000u64)];
        // First call
        plugin.on_analysis_complete(&symbols);
        // Second call should return None (not first analysis).
        let result = plugin.on_analysis_complete(&symbols);
        assert!(result.is_none());
    }

    #[test]
    fn test_plugin_user_moved_no_auto_move() {
        let opts = ProgramStartingLocationOptions {
            auto_move_after_analysis: false,
            ..Default::default()
        };
        let mut plugin = ProgramStartingLocationPlugin::new(opts);
        plugin.mark_user_moved();

        let symbols = vec![("main".to_string(), 0x400000u64)];
        let result = plugin.on_analysis_complete(&symbols);
        assert!(result.is_none());
    }

    #[test]
    fn test_plugin_user_moved_with_auto_move() {
        let opts = ProgramStartingLocationOptions {
            auto_move_after_analysis: true,
            ..Default::default()
        };
        let mut plugin = ProgramStartingLocationPlugin::new(opts);
        plugin.mark_user_moved();

        let symbols = vec![("main".to_string(), 0x400000u64)];
        let result = plugin.on_analysis_complete(&symbols);
        // Auto-move is enabled, so even though user moved, we should still reposition.
        assert_eq!(result, Some(0x400000));
    }

    #[test]
    fn test_plugin_underscore_expansion() {
        let opts = ProgramStartingLocationOptions {
            start_symbols: vec!["main".into()],
            use_underscore_prefixes: true,
            ..Default::default()
        };
        let mut plugin = ProgramStartingLocationPlugin::new(opts);
        let symbols = vec![("_main".to_string(), 0x500000u64)];
        let result = plugin.on_analysis_complete(&symbols);
        // "_main" should match the underscore-prefixed variant.
        assert_eq!(result, Some(0x500000));
    }

    #[test]
    fn test_plugin_default() {
        let plugin = ProgramStartingLocationPlugin::default();
        assert!(plugin.is_first_analysis);
        assert!(!plugin.user_has_moved);
    }
}
