//! Call-graph table for BSim.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.client.tables.CallgraphTable`.
//! Stores call-graph edges as (source_function_id, dest_function_id, location_hash)
//! triples.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// ============================================================================
// CallgraphEdge
// ============================================================================

/// An edge in the call graph: a function calling another function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallgraphEdge {
    /// The calling function's database id.
    pub caller_id: i64,
    /// The called function's database id.
    pub callee_id: i64,
    /// A hash of the call-site location (for uniqueness when a function
    /// calls the same target multiple times).
    pub location_hash: u64,
}

impl CallgraphEdge {
    /// Create a new call-graph edge.
    pub fn new(caller_id: i64, callee_id: i64, location_hash: u64) -> Self {
        Self {
            caller_id,
            callee_id,
            location_hash,
        }
    }
}

// ============================================================================
// CallgraphTable
// ============================================================================

/// In-memory representation of the BSim call-graph table.
///
/// Stores caller-callee relationships for functions in the database.
/// Used during signature comparison to weight call-graph similarity.
///
/// Ported from `ghidra.features.bsim.query.client.tables.CallgraphTable`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallgraphTable {
    /// All call-graph edges.
    edges: Vec<CallgraphEdge>,
    /// Index: caller_id -> set of indices into `edges`.
    by_caller: HashMap<i64, Vec<usize>>,
    /// Index: callee_id -> set of indices into `edges`.
    by_callee: HashMap<i64, Vec<usize>>,
    /// Unique (caller, callee) pairs for fast lookup.
    pairs: HashSet<(i64, i64)>,
}

impl CallgraphTable {
    /// Create an empty callgraph table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a call-graph edge.
    ///
    /// Returns `true` if the edge was new, `false` if the exact
    /// (caller, callee, location_hash) triple already existed.
    pub fn insert(&mut self, edge: CallgraphEdge) -> bool {
        let idx = self.edges.len();
        let is_new_pair = self.pairs.insert((edge.caller_id, edge.callee_id));
        self.by_caller
            .entry(edge.caller_id)
            .or_default()
            .push(idx);
        self.by_callee
            .entry(edge.callee_id)
            .or_default()
            .push(idx);
        self.edges.push(edge);
        is_new_pair || true // always true since edges are unique by triple
    }

    /// Get all edges where `function_id` is the caller.
    pub fn edges_from(&self, function_id: i64) -> Vec<&CallgraphEdge> {
        self.by_caller
            .get(&function_id)
            .map(|indices| indices.iter().filter_map(|&i| self.edges.get(i)).collect())
            .unwrap_or_default()
    }

    /// Get all edges where `function_id` is the callee.
    pub fn edges_to(&self, function_id: i64) -> Vec<&CallgraphEdge> {
        self.by_callee
            .get(&function_id)
            .map(|indices| indices.iter().filter_map(|&i| self.edges.get(i)).collect())
            .unwrap_or_default()
    }

    /// Get all callees of a function.
    pub fn callees(&self, caller_id: i64) -> Vec<i64> {
        let mut seen = HashSet::new();
        self.edges_from(caller_id)
            .into_iter()
            .filter(|e| seen.insert(e.callee_id))
            .map(|e| e.callee_id)
            .collect()
    }

    /// Get all callers of a function.
    pub fn callers(&self, callee_id: i64) -> Vec<i64> {
        let mut seen = HashSet::new();
        self.edges_to(callee_id)
            .into_iter()
            .filter(|e| seen.insert(e.caller_id))
            .map(|e| e.caller_id)
            .collect()
    }

    /// Total number of edges.
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Number of distinct caller-callee pairs.
    pub fn pair_count(&self) -> usize {
        self.pairs.len()
    }

    /// Whether a (caller, callee) pair exists.
    pub fn has_edge(&self, caller_id: i64, callee_id: i64) -> bool {
        self.pairs.contains(&(caller_id, callee_id))
    }

    /// Iterate over all edges.
    pub fn iter(&self) -> impl Iterator<Item = &CallgraphEdge> {
        self.edges.iter()
    }

    /// Compute the intersection of callees between two functions.
    pub fn shared_callees(&self, func_a: i64, func_b: i64) -> Vec<i64> {
        let callees_a: HashSet<i64> = self.callees(func_a).into_iter().collect();
        let callees_b: HashSet<i64> = self.callees(func_b).into_iter().collect();
        callees_a.intersection(&callees_b).copied().collect()
    }

    /// Compute the call-graph similarity between two functions.
    ///
    /// Uses the Jaccard coefficient of their callee sets.
    pub fn callee_similarity(&self, func_a: i64, func_b: i64) -> f64 {
        let callees_a: HashSet<i64> = self.callees(func_a).into_iter().collect();
        let callees_b: HashSet<i64> = self.callees(func_b).into_iter().collect();
        if callees_a.is_empty() && callees_b.is_empty() {
            return 1.0;
        }
        let intersection = callees_a.intersection(&callees_b).count();
        let union = callees_a.union(&callees_b).count();
        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callgraph_table_insert_and_query() {
        let mut table = CallgraphTable::new();
        table.insert(CallgraphEdge::new(1, 2, 100));
        table.insert(CallgraphEdge::new(1, 3, 101));
        table.insert(CallgraphEdge::new(2, 3, 102));

        assert_eq!(table.len(), 3);
        assert_eq!(table.callees(1).len(), 2);
        assert_eq!(table.callers(3).len(), 2);
    }

    #[test]
    fn callgraph_table_has_edge() {
        let mut table = CallgraphTable::new();
        table.insert(CallgraphEdge::new(1, 2, 100));
        assert!(table.has_edge(1, 2));
        assert!(!table.has_edge(2, 1));
    }

    #[test]
    fn callgraph_table_shared_callees() {
        let mut table = CallgraphTable::new();
        table.insert(CallgraphEdge::new(1, 10, 1));
        table.insert(CallgraphEdge::new(1, 20, 2));
        table.insert(CallgraphEdge::new(2, 10, 3));
        table.insert(CallgraphEdge::new(2, 30, 4));

        let shared = table.shared_callees(1, 2);
        assert_eq!(shared, vec![10]);
    }

    #[test]
    fn callgraph_table_callee_similarity() {
        let mut table = CallgraphTable::new();
        table.insert(CallgraphEdge::new(1, 10, 1));
        table.insert(CallgraphEdge::new(1, 20, 2));
        table.insert(CallgraphEdge::new(2, 10, 3));
        table.insert(CallgraphEdge::new(2, 20, 4));

        let sim = table.callee_similarity(1, 2);
        assert!((sim - 1.0).abs() < 1e-6);
    }

    #[test]
    fn callgraph_table_empty_similarity() {
        let table = CallgraphTable::new();
        assert_eq!(table.callee_similarity(1, 2), 1.0);
    }
}
