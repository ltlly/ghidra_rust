//! Port of Ghidra's `ghidra.graph.viewer.options.RelayoutOption`.
//!
//! Controls how the graph layout is recalculated when changes occur.

/// Options for controlling graph relayout behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayoutOption {
    /// Do not relayout.
    None,
    /// Relayout the entire graph from scratch.
    FullRelayout,
    /// Relayout only the affected area around changed vertices.
    PartialRelayout,
    /// Preserve existing layout positions; only add new vertices.
    PreserveLayout,
}

impl Default for RelayoutOption {
    fn default() -> Self { Self::None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() { assert_eq!(RelayoutOption::default(), RelayoutOption::None); }

    #[test]
    fn test_inequality() { assert_ne!(RelayoutOption::None, RelayoutOption::FullRelayout); }

    #[test]
    fn test_copy() {
        let a = RelayoutOption::PartialRelayout;
        let b = a;
        assert_eq!(a, b);
    }
}
