//! Function Edge -- a simple edge between two functions.
//!
//! Ported from Ghidra's `functioncalls.plugin.FunctionEdge` Java class.
//!
//! An edge between two functions that is never added to the visual graph,
//! but exists to maintain relationships between functions outside of
//! the visual graph.  Used by the [`FunctionEdgeCache`] to track known
//! call/reference relationships.

use std::fmt;

/// A simple edge between two functions (by address).
///
/// Ported from `functioncalls.plugin.FunctionEdge`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionEdge {
    /// The source function address (caller).
    start: u64,
    /// The target function address (callee).
    end: u64,
}

impl FunctionEdge {
    /// Create a new function edge.
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Get the source function address.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// Get the target function address.
    pub fn end(&self) -> u64 {
        self.end
    }
}

impl fmt::Display for FunctionEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[0x{:x}, 0x{:x}]", self.start, self.end)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_edge_creation() {
        let edge = FunctionEdge::new(0x1000, 0x2000);
        assert_eq!(edge.start(), 0x1000);
        assert_eq!(edge.end(), 0x2000);
    }

    #[test]
    fn test_function_edge_equality() {
        let e1 = FunctionEdge::new(0x1000, 0x2000);
        let e2 = FunctionEdge::new(0x1000, 0x2000);
        let e3 = FunctionEdge::new(0x1000, 0x3000);
        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
    }

    #[test]
    fn test_function_edge_display() {
        let edge = FunctionEdge::new(0x401000, 0x402000);
        assert_eq!(edge.to_string(), "[0x401000, 0x402000]");
    }

    #[test]
    fn test_function_edge_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FunctionEdge::new(0x1000, 0x2000));
        assert!(set.contains(&FunctionEdge::new(0x1000, 0x2000)));
        assert!(!set.contains(&FunctionEdge::new(0x1000, 0x3000)));
    }
}
