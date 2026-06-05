//! Call tree options and configuration.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.calltree.CallTreeOptions` Java class.

/// Configuration options for the call tree view.
///
/// Ported from `ghidra.app.plugin.core.calltree.CallTreeOptions`.
#[derive(Debug, Clone)]
pub struct CallTreeOptions {
    /// Maximum depth to expand the tree.
    pub max_depth: usize,
    /// Whether to show external (library) functions.
    pub show_externals: bool,
    /// Whether to show dead-end nodes (functions with no callees/callers).
    pub show_dead_ends: bool,
    /// Whether to group by namespace.
    pub group_by_namespace: bool,
    /// Whether to show references in addition to calls.
    pub show_references: bool,
    /// Whether to auto-expand the first level.
    pub auto_expand_first_level: bool,
    /// The maximum number of nodes to display (0 = unlimited).
    pub max_display_nodes: usize,
    /// Whether to sort children alphabetically.
    pub sort_alphabetically: bool,
}

impl CallTreeOptions {
    /// Create new options with default values.
    pub fn new() -> Self {
        Self {
            max_depth: 10,
            show_externals: false,
            show_dead_ends: true,
            group_by_namespace: false,
            show_references: true,
            auto_expand_first_level: true,
            max_display_nodes: 0,
            sort_alphabetically: true,
        }
    }

    /// Create options optimized for large binaries.
    pub fn large_binary() -> Self {
        Self {
            max_depth: 3,
            show_externals: false,
            show_dead_ends: false,
            group_by_namespace: true,
            show_references: false,
            auto_expand_first_level: true,
            max_display_nodes: 1000,
            sort_alphabetically: true,
        }
    }

    /// Create options that show everything.
    pub fn verbose() -> Self {
        Self {
            max_depth: 50,
            show_externals: true,
            show_dead_ends: true,
            group_by_namespace: false,
            show_references: true,
            auto_expand_first_level: true,
            max_display_nodes: 0,
            sort_alphabetically: false,
        }
    }

    /// Validate the options.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_depth == 0 {
            return Err("Max depth must be greater than 0".into());
        }
        if self.max_depth > 100 {
            return Err("Max depth must not exceed 100".into());
        }
        Ok(())
    }
}

impl Default for CallTreeOptions {
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

    #[test]
    fn test_call_tree_options_default() {
        let opts = CallTreeOptions::default();
        assert_eq!(opts.max_depth, 10);
        assert!(!opts.show_externals);
        assert!(opts.show_dead_ends);
        assert!(opts.show_references);
        assert!(opts.sort_alphabetically);
    }

    #[test]
    fn test_call_tree_options_large_binary() {
        let opts = CallTreeOptions::large_binary();
        assert_eq!(opts.max_depth, 3);
        assert!(!opts.show_externals);
        assert!(!opts.show_dead_ends);
        assert!(opts.group_by_namespace);
        assert!(!opts.show_references);
        assert_eq!(opts.max_display_nodes, 1000);
    }

    #[test]
    fn test_call_tree_options_verbose() {
        let opts = CallTreeOptions::verbose();
        assert_eq!(opts.max_depth, 50);
        assert!(opts.show_externals);
        assert!(opts.show_dead_ends);
        assert!(opts.show_references);
        assert!(!opts.sort_alphabetically);
    }

    #[test]
    fn test_call_tree_options_validate() {
        let mut opts = CallTreeOptions::default();
        assert!(opts.validate().is_ok());

        opts.max_depth = 0;
        assert!(opts.validate().is_err());

        opts.max_depth = 200;
        assert!(opts.validate().is_err());

        opts.max_depth = 50;
        assert!(opts.validate().is_ok());
    }
}
