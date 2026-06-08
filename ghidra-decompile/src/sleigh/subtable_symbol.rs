//! SLEIGH subtable symbol: hierarchical instruction decoding tables.
//!
//! A [`SubtableSymbol`] represents a named table of constructors that
//! participates in hierarchical instruction decoding. When the SLEIGH
//! compiler encounters a reference to a subtable in a pattern, it consults
//! all constructors in that subtable to determine which one matches.
//!
//! Subtables enable modular instruction set descriptions. For example,
//! an ARM instruction set might define:
//!
//! ```text
//! define table instruction { ... }
//! :instruction is ... { ... }
//! ```
//!
//! # Key Types
//! - [`SubtableSymbol`] -- a named table of constructors with a decision tree
//! - [`DecisionNode`] -- a node in the decision tree for efficient matching

use serde::{Deserialize, Serialize};
use std::fmt;

use super::sleigh_symbol::{Location, SymbolType};

// ---------------------------------------------------------------------------
// DecisionNode
// ---------------------------------------------------------------------------

/// A node in the decision tree for efficient pattern matching.
///
/// The decision tree is built from the constructors in a subtable. Each
/// node represents a bit position to check, with branches for 0 and 1.
/// Leaf nodes contain the constructor id to select.
///
/// This enables O(depth) matching instead of O(n) linear scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionNode {
    /// Bit position to test (None for leaf nodes)
    pub bit_pos: Option<usize>,
    /// Constructor id if this is a leaf node
    pub constructor_id: Option<usize>,
    /// Child node for bit = 0
    pub child_0: Option<Box<DecisionNode>>,
    /// Child node for bit = 1
    pub child_1: Option<Box<DecisionNode>>,
}

impl DecisionNode {
    /// Create a leaf node with a constructor id.
    pub fn leaf(constructor_id: usize) -> Self {
        Self {
            bit_pos: None,
            constructor_id: Some(constructor_id),
            child_0: None,
            child_1: None,
        }
    }

    /// Create an internal node with a bit position to test.
    pub fn internal(bit_pos: usize) -> Self {
        Self {
            bit_pos: Some(bit_pos),
            constructor_id: None,
            child_0: None,
            child_1: None,
        }
    }

    /// Returns `true` if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.constructor_id.is_some()
    }

    /// Match against instruction bytes, returning the constructor id.
    pub fn match_bytes(&self, bytes: &[u8]) -> Option<usize> {
        if let Some(constructor_id) = self.constructor_id {
            return Some(constructor_id);
        }

        let bit_pos = self.bit_pos?;
        let byte_idx = bit_pos / 8;
        let bit_off = 7 - (bit_pos % 8);

        if byte_idx >= bytes.len() {
            return None;
        }

        let bit = (bytes[byte_idx] >> bit_off) & 1;
        if bit == 0 {
            self.child_0.as_ref()?.match_bytes(bytes)
        } else {
            self.child_1.as_ref()?.match_bytes(bytes)
        }
    }
}

impl fmt::Display for DecisionNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(id) = self.constructor_id {
            write!(f, "leaf({})", id)
        } else if let Some(pos) = self.bit_pos {
            write!(f, "bit({})", pos)
        } else {
            write!(f, "empty")
        }
    }
}

// ---------------------------------------------------------------------------
// SubtableSymbol
// ---------------------------------------------------------------------------

/// A subtable symbol: a named table of constructors for hierarchical decoding.
///
/// Each subtable contains:
/// - A list of constructor ids (the constructors that belong to this table)
/// - A decision tree for efficient pattern matching
/// - A token pattern representing the union of all constructor patterns
///
/// The decision tree is built after all constructors are added, during the
/// `build_decision_tree` phase of SLEIGH compilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubtableSymbol {
    /// Symbol name
    pub name: String,
    /// Symbol id
    pub id: usize,
    /// Scope id
    pub scope_id: usize,
    /// Source location
    pub location: Location,
    /// Constructor ids belonging to this table
    pub constructors: Vec<usize>,
    /// Decision tree for efficient matching
    pub decision_tree: Option<DecisionNode>,
    /// Whether the table is currently being built (cycle detection)
    pub being_built: bool,
    /// Whether there were errors building this table
    pub has_errors: bool,
    /// The token pattern representing the union of all constructor patterns
    pub pattern: Option<usize>, // TokenPattern id
}

impl SubtableSymbol {
    /// Create a new subtable symbol.
    pub fn new(name: impl Into<String>, location: Location) -> Self {
        Self {
            name: name.into(),
            id: 0,
            scope_id: 0,
            location,
            constructors: Vec::new(),
            decision_tree: None,
            being_built: false,
            has_errors: false,
            pattern: None,
        }
    }

    /// Add a constructor to this subtable.
    ///
    /// The constructor is assigned an id based on its position in the list.
    pub fn add_constructor(&mut self, constructor_id: usize) -> usize {
        let idx = self.constructors.len();
        self.constructors.push(constructor_id);
        idx
    }

    /// Returns the number of constructors in this table.
    pub fn num_constructors(&self) -> usize {
        self.constructors.len()
    }

    /// Get a constructor id by index.
    pub fn get_constructor(&self, idx: usize) -> Option<usize> {
        self.constructors.get(idx).copied()
    }

    /// Returns the symbol type.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::Subtable
    }

    /// Build the decision tree from the constructors.
    ///
    /// This is called after all constructors have been added and their
    /// patterns resolved. It creates a binary decision tree that can
    /// efficiently match instruction bytes against all constructors.
    pub fn build_decision_tree(&mut self) {
        if self.constructors.is_empty() {
            return;
        }

        // Simplified decision tree: just pick the first constructor
        // A full implementation would analyze the patterns and build
        // a proper bit-testing tree
        if self.constructors.len() == 1 {
            self.decision_tree = Some(DecisionNode::leaf(self.constructors[0]));
        } else {
            // For multiple constructors, create a simple linear chain
            // (real implementation would be more sophisticated)
            let mut root = DecisionNode::leaf(self.constructors[0]);
            for &ctor_id in &self.constructors[1..] {
                let new_root = DecisionNode::internal(0);
                let mut new_root = new_root;
                new_root.child_0 = Some(Box::new(root));
                new_root.child_1 = Some(Box::new(DecisionNode::leaf(ctor_id)));
                root = new_root;
            }
            self.decision_tree = Some(root);
        }
    }

    /// Match instruction bytes against the decision tree.
    ///
    /// Returns the constructor id that matches, or None if no match.
    pub fn match_bytes(&self, bytes: &[u8]) -> Option<usize> {
        self.decision_tree.as_ref()?.match_bytes(bytes)
    }
}

impl fmt::Display for SubtableSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Subtable({}, {} constructors)",
            self.name,
            self.constructors.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subtable_new() {
        let sub = SubtableSymbol::new("instruction", Location::unknown());
        assert_eq!(sub.name, "instruction");
        assert_eq!(sub.num_constructors(), 0);
        assert!(sub.decision_tree.is_none());
    }

    #[test]
    fn test_subtable_add_constructor() {
        let mut sub = SubtableSymbol::new("instruction", Location::unknown());
        sub.add_constructor(0);
        sub.add_constructor(1);
        sub.add_constructor(2);
        assert_eq!(sub.num_constructors(), 3);
        assert_eq!(sub.get_constructor(0), Some(0));
        assert_eq!(sub.get_constructor(2), Some(2));
        assert_eq!(sub.get_constructor(3), None);
    }

    #[test]
    fn test_decision_node_leaf() {
        let node = DecisionNode::leaf(42);
        assert!(node.is_leaf());
        assert_eq!(node.constructor_id, Some(42));
    }

    #[test]
    fn test_decision_node_internal() {
        let node = DecisionNode::internal(8);
        assert!(!node.is_leaf());
        assert_eq!(node.bit_pos, Some(8));
    }

    #[test]
    fn test_decision_node_match_single() {
        let node = DecisionNode::leaf(0);
        assert_eq!(node.match_bytes(&[0xFF]), Some(0));
    }

    #[test]
    fn test_subtable_build_decision_tree_single() {
        let mut sub = SubtableSymbol::new("test", Location::unknown());
        sub.add_constructor(5);
        sub.build_decision_tree();

        assert!(sub.decision_tree.is_some());
        assert_eq!(sub.match_bytes(&[0xFF]), Some(5));
    }

    #[test]
    fn test_subtable_build_decision_tree_empty() {
        let mut sub = SubtableSymbol::new("test", Location::unknown());
        sub.build_decision_tree();
        assert!(sub.decision_tree.is_none());
    }

    #[test]
    fn test_subtable_symbol_type() {
        let sub = SubtableSymbol::new("test", Location::unknown());
        assert_eq!(sub.symbol_type(), SymbolType::Subtable);
    }

    #[test]
    fn test_subtable_display() {
        let mut sub = SubtableSymbol::new("instruction", Location::unknown());
        sub.add_constructor(0);
        sub.add_constructor(1);
        let s = format!("{}", sub);
        assert!(s.contains("instruction"));
        assert!(s.contains("2"));
    }

    #[test]
    fn test_decision_node_display() {
        let leaf = DecisionNode::leaf(5);
        assert_eq!(format!("{}", leaf), "leaf(5)");

        let internal = DecisionNode::internal(8);
        assert_eq!(format!("{}", internal), "bit(8)");
    }
}
