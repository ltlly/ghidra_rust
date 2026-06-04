//! Constant propagation abstract domain.
//!
//! Ported from `PcodeDataflowConstantPropagation.java` in the Lisa extension.
//!
//! Implements an overflow-insensitive constant propagation dataflow analysis
//! that tracks whether identifiers have known constant values.

use crate::lisa::lattice::LatticeElement;
use std::collections::{HashMap, HashSet};
use std::fmt;

/// A single dataflow element in the constant propagation domain.
///
/// Tracks that a particular identifier holds a specific constant value
/// at a given program point.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PcodeDataflowConstantPropagation {
    /// The identifier (variable/register name).
    pub identifier: String,
    /// The constant value.
    pub value: i64,
}

impl PcodeDataflowConstantPropagation {
    /// Create a new constant propagation element.
    pub fn new(identifier: impl Into<String>, value: i64) -> Self {
        Self {
            identifier: identifier.into(),
            value,
        }
    }
}

impl fmt::Display for PcodeDataflowConstantPropagation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.identifier, self.value)
    }
}

/// The definite dataflow domain for constant propagation.
///
/// Maps identifiers to their constant values. If an identifier is not
/// in the map, its value is unknown (not constant). If an identifier
/// maps to multiple different values along different paths, it is
/// removed from the map (becomes non-constant).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConstantPropagationDomain {
    /// Maps identifier name -> constant value (only if all paths agree).
    constants: HashMap<String, i64>,
    /// Identifiers that have been assigned conflicting values.
    non_constant: HashSet<String>,
}

impl ConstantPropagationDomain {
    /// Create a new empty domain.
    pub fn new() -> Self {
        Self {
            constants: HashMap::new(),
            non_constant: HashSet::new(),
        }
    }

    /// Get the constant value for an identifier, if known.
    pub fn get_constant(&self, identifier: &str) -> Option<i64> {
        self.constants.get(identifier).copied()
    }

    /// Check if an identifier is known to be non-constant.
    pub fn is_non_constant(&self, identifier: &str) -> bool {
        self.non_constant.contains(identifier)
    }

    /// Record a constant assignment for an identifier.
    ///
    /// If the identifier already has a different constant, it becomes
    /// non-constant.
    pub fn assign(&mut self, identifier: &str, value: i64) {
        if self.non_constant.contains(identifier) {
            return;
        }
        match self.constants.get(identifier) {
            Some(&existing) if existing != value => {
                self.constants.remove(identifier);
                self.non_constant.insert(identifier.to_string());
            }
            None => {
                if !self.non_constant.contains(identifier) {
                    self.constants.insert(identifier.to_string(), value);
                }
            }
            _ => {} // Same value, no change
        }
    }

    /// Mark an identifier as non-constant.
    pub fn mark_non_constant(&mut self, identifier: &str) {
        self.constants.remove(identifier);
        self.non_constant.insert(identifier.to_string());
    }

    /// Get all known constant assignments.
    pub fn constants(&self) -> &HashMap<String, i64> {
        &self.constants
    }

    /// Number of known constants.
    pub fn len(&self) -> usize {
        self.constants.len()
    }

    /// Whether the domain has any known constants.
    pub fn is_empty(&self) -> bool {
        self.constants.is_empty()
    }
}

impl LatticeElement for ConstantPropagationDomain {
    fn top() -> Self {
        Self::new()
    }

    fn bottom() -> Self {
        // Bottom: all identifiers are non-constant
        Self {
            constants: HashMap::new(),
            non_constant: HashSet::new(),
        }
    }

    fn is_top(&self) -> bool {
        self.constants.is_empty() && self.non_constant.is_empty()
    }

    fn is_bottom(&self) -> bool {
        // In the definite domain, bottom and top are both "empty"
        self.constants.is_empty() && self.non_constant.is_empty()
    }

    fn lub(&self, other: &Self) -> Result<Self, String> {
        let mut result = Self::new();

        // Keep only identifiers that are constant in both and have the
        // same value.
        for (id, val) in &self.constants {
            if let Some(other_val) = other.constants.get(id) {
                if *val == *other_val {
                    result.constants.insert(id.clone(), *val);
                } else {
                    result.non_constant.insert(id.clone());
                }
            } else if other.non_constant.contains(id) {
                result.non_constant.insert(id.clone());
            }
            // If not in other at all, don't include (might not be
            // assigned on all paths)
        }

        // Mark identifiers that are non-constant in either
        for id in &self.non_constant {
            result.non_constant.insert(id.clone());
        }
        for id in &other.non_constant {
            result.non_constant.insert(id.clone());
        }

        // Identifiers only in other's constants but not in self's
        // constants or non-constant set are dropped (not assigned on
        // all paths).

        Ok(result)
    }

    fn less_or_equal(&self, other: &Self) -> bool {
        // self <= other iff every constant in other is also in self with
        // the same value, and every non-constant in other is also
        // non-constant in self.
        for (id, val) in &other.constants {
            match self.constants.get(id) {
                Some(v) if v == val => {}
                _ => return false,
            }
        }
        for id in &other.non_constant {
            if !self.non_constant.contains(id)
                && !self.constants.contains_key(id)
            {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assign_and_get() {
        let mut domain = ConstantPropagationDomain::new();
        domain.assign("x", 42);
        assert_eq!(domain.get_constant("x"), Some(42));
        assert!(domain.get_constant("y").is_none());
    }

    #[test]
    fn test_assign_conflicting() {
        let mut domain = ConstantPropagationDomain::new();
        domain.assign("x", 42);
        domain.assign("x", 99);
        assert!(domain.get_constant("x").is_none());
        assert!(domain.is_non_constant("x"));
    }

    #[test]
    fn test_assign_same_value() {
        let mut domain = ConstantPropagationDomain::new();
        domain.assign("x", 42);
        domain.assign("x", 42);
        assert_eq!(domain.get_constant("x"), Some(42));
    }

    #[test]
    fn test_mark_non_constant() {
        let mut domain = ConstantPropagationDomain::new();
        domain.assign("x", 42);
        domain.mark_non_constant("x");
        assert!(domain.get_constant("x").is_none());
        assert!(domain.is_non_constant("x"));
    }

    #[test]
    fn test_lub_same_values() {
        let mut a = ConstantPropagationDomain::new();
        a.assign("x", 42);
        a.assign("y", 10);

        let mut b = ConstantPropagationDomain::new();
        b.assign("x", 42);
        b.assign("z", 99);

        let lub = a.lub(&b).unwrap();
        assert_eq!(lub.get_constant("x"), Some(42));
        // y only in a -> not included in lub
        assert!(lub.get_constant("y").is_none());
        // z only in b -> not included in lub
        assert!(lub.get_constant("z").is_none());
    }

    #[test]
    fn test_lub_different_values() {
        let mut a = ConstantPropagationDomain::new();
        a.assign("x", 42);

        let mut b = ConstantPropagationDomain::new();
        b.assign("x", 99);

        let lub = a.lub(&b).unwrap();
        assert!(lub.get_constant("x").is_none());
        assert!(lub.is_non_constant("x"));
    }

    #[test]
    fn test_len_and_is_empty() {
        let mut domain = ConstantPropagationDomain::new();
        assert!(domain.is_empty());
        assert_eq!(domain.len(), 0);
        domain.assign("x", 1);
        domain.assign("y", 2);
        assert_eq!(domain.len(), 2);
    }

    #[test]
    fn test_display() {
        let elem = PcodeDataflowConstantPropagation::new("RAX", 42);
        assert_eq!(elem.to_string(), "RAX = 42");
    }
}
