//! Internal GUI diagnostics (R* tree viewer).
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.internal` package.
//! Provides data model types for the R*-tree diagnostics panels used
//! for inspecting the spatial indexing structures in trace databases.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// R* tree node
// ---------------------------------------------------------------------------

/// A node in an R*-tree used for spatial indexing.
///
/// Ported from Ghidra's `RStarTreeProvider`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RStarTreeNode {
    /// The node ID (unique within a tree).
    pub id: u64,
    /// The bounding box minimum coordinates (per dimension).
    pub bounds_min: Vec<i64>,
    /// The bounding box maximum coordinates (per dimension).
    pub bounds_max: Vec<i64>,
    /// Child node IDs (empty for leaf nodes).
    pub children: Vec<u64>,
    /// Whether this is a leaf node.
    pub is_leaf: bool,
    /// The number of entries in this node.
    pub entry_count: usize,
    /// The level in the tree (0 = leaf level).
    pub level: u32,
}

impl RStarTreeNode {
    /// Create a new R*-tree node.
    pub fn new(id: u64, dimensions: usize) -> Self {
        Self {
            id,
            bounds_min: vec![i64::MAX; dimensions],
            bounds_max: vec![i64::MIN; dimensions],
            children: Vec::new(),
            is_leaf: true,
            entry_count: 0,
            level: 0,
        }
    }

    /// Calculate the area of the bounding box.
    pub fn area(&self) -> u128 {
        self.bounds_min
            .iter()
            .zip(self.bounds_max.iter())
            .map(|(&min, &max)| {
                let w = (max - min).max(0) as u128;
                if w == 0 { 1 } else { w }
            })
            .product()
    }

    /// Calculate the margin of the bounding box (sum of edge lengths).
    pub fn margin(&self) -> u128 {
        self.bounds_min
            .iter()
            .zip(self.bounds_max.iter())
            .map(|(&min, &max)| (max - min).max(0) as u128)
            .sum()
    }

    /// Expand this node's bounding box to contain the given point.
    pub fn expand_to_include_point(&mut self, point: &[i64]) {
        for (i, &coord) in point.iter().enumerate() {
            if i < self.bounds_min.len() {
                self.bounds_min[i] = self.bounds_min[i].min(coord);
                self.bounds_max[i] = self.bounds_max[i].max(coord);
            }
        }
    }

    /// Expand this node's bounding box to contain another node's bounds.
    pub fn expand_to_include(&mut self, other: &RStarTreeNode) {
        for i in 0..self.bounds_min.len().min(other.bounds_min.len()) {
            self.bounds_min[i] = self.bounds_min[i].min(other.bounds_min[i]);
            self.bounds_max[i] = self.bounds_max[i].max(other.bounds_max[i]);
        }
    }

    /// Check if this node's bounding box contains a point.
    pub fn contains_point(&self, point: &[i64]) -> bool {
        point.iter().enumerate().all(|(i, &coord)| {
            i >= self.bounds_min.len()
                || (coord >= self.bounds_min[i] && coord <= self.bounds_max[i])
        })
    }

    /// Check if this node's bounding box overlaps with another.
    pub fn overlaps(&self, other: &RStarTreeNode) -> bool {
        self.bounds_min
            .iter()
            .zip(self.bounds_max.iter())
            .zip(other.bounds_min.iter().zip(other.bounds_max.iter()))
            .all(|((&amin, &amax), (&bmin, &bmax))| amin <= bmax && bmin <= amax)
    }
}

// ---------------------------------------------------------------------------
// R* tree statistics
// ---------------------------------------------------------------------------

/// Statistics for an R*-tree.
///
/// Ported from Ghidra's `RStarDiagnosticsPlugin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RStarTreeStats {
    /// Total number of nodes.
    pub node_count: usize,
    /// Total number of leaf entries.
    pub entry_count: usize,
    /// The height of the tree.
    pub height: u32,
    /// The fill factor (average entries per node / max entries).
    pub fill_factor: f64,
    /// Number of leaf nodes.
    pub leaf_count: usize,
    /// Number of internal nodes.
    pub internal_count: usize,
    /// Number of dimensions.
    pub dimensions: usize,
}

impl RStarTreeStats {
    /// Create empty statistics.
    pub fn new(dimensions: usize) -> Self {
        Self {
            node_count: 0,
            entry_count: 0,
            height: 0,
            fill_factor: 0.0,
            leaf_count: 0,
            internal_count: 0,
            dimensions,
        }
    }
}

// ---------------------------------------------------------------------------
// R* tree diagnostics model
// ---------------------------------------------------------------------------

/// The data model for R*-tree diagnostics visualization.
///
/// Ported from Ghidra's `RStarTreeProvider` and `RStarPlotProvider`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RStarTreeDiagnosticsModel {
    /// All nodes in the tree.
    pub nodes: Vec<RStarTreeNode>,
    /// Tree statistics.
    pub stats: RStarTreeStats,
    /// The currently selected node ID.
    pub selected_node_id: Option<u64>,
    /// The trace space name this tree indexes.
    pub space_name: String,
}

impl RStarTreeDiagnosticsModel {
    /// Create a new diagnostics model.
    pub fn new(space_name: impl Into<String>, dimensions: usize) -> Self {
        Self {
            nodes: Vec::new(),
            stats: RStarTreeStats::new(dimensions),
            selected_node_id: None,
            space_name: space_name.into(),
        }
    }

    /// Add a node to the model.
    pub fn add_node(&mut self, node: RStarTreeNode) {
        self.stats.node_count += 1;
        self.stats.entry_count += node.entry_count;
        if node.is_leaf {
            self.stats.leaf_count += 1;
        } else {
            self.stats.internal_count += 1;
        }
        self.nodes.push(node);
    }

    /// Find a node by ID.
    pub fn find_node(&self, id: u64) -> Option<&RStarTreeNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Select a node.
    pub fn select_node(&mut self, id: Option<u64>) {
        self.selected_node_id = id;
    }

    /// Get the selected node.
    pub fn selected_node(&self) -> Option<&RStarTreeNode> {
        self.selected_node_id
            .and_then(|id| self.find_node(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rstar_node_new() {
        let node = RStarTreeNode::new(1, 2);
        assert_eq!(node.id, 1);
        assert_eq!(node.bounds_min.len(), 2);
        assert!(node.is_leaf);
        assert_eq!(node.entry_count, 0);
    }

    #[test]
    fn test_rstar_node_expand_to_include_point() {
        let mut node = RStarTreeNode::new(1, 2);
        node.expand_to_include_point(&[10, 20]);
        assert_eq!(node.bounds_min, [10, 20]);
        assert_eq!(node.bounds_max, [10, 20]);
        node.expand_to_include_point(&[30, 5]);
        assert_eq!(node.bounds_min, [10, 5]);
        assert_eq!(node.bounds_max, [30, 20]);
    }

    #[test]
    fn test_rstar_node_area() {
        let mut node = RStarTreeNode::new(1, 2);
        node.bounds_min = vec![0, 0];
        node.bounds_max = vec![10, 5];
        assert_eq!(node.area(), 50);
    }

    #[test]
    fn test_rstar_node_margin() {
        let mut node = RStarTreeNode::new(1, 2);
        node.bounds_min = vec![0, 0];
        node.bounds_max = vec![10, 5];
        assert_eq!(node.margin(), 15);
    }

    #[test]
    fn test_rstar_node_contains_point() {
        let mut node = RStarTreeNode::new(1, 2);
        node.bounds_min = vec![0, 0];
        node.bounds_max = vec![10, 10];
        assert!(node.contains_point(&[5, 5]));
        assert!(node.contains_point(&[0, 0]));
        assert!(node.contains_point(&[10, 10]));
        assert!(!node.contains_point(&[11, 5]));
    }

    #[test]
    fn test_rstar_node_overlaps() {
        let mut n1 = RStarTreeNode::new(1, 2);
        n1.bounds_min = vec![0, 0];
        n1.bounds_max = vec![10, 10];

        let mut n2 = RStarTreeNode::new(2, 2);
        n2.bounds_min = vec![5, 5];
        n2.bounds_max = vec![15, 15];
        assert!(n1.overlaps(&n2));

        let mut n3 = RStarTreeNode::new(3, 2);
        n3.bounds_min = vec![20, 20];
        n3.bounds_max = vec![30, 30];
        assert!(!n1.overlaps(&n3));
    }

    #[test]
    fn test_rstar_node_expand_to_include_node() {
        let mut n1 = RStarTreeNode::new(1, 2);
        n1.bounds_min = vec![0, 0];
        n1.bounds_max = vec![10, 10];

        let mut n2 = RStarTreeNode::new(2, 2);
        n2.bounds_min = vec![-5, 3];
        n2.bounds_max = vec![15, 8];

        n1.expand_to_include(&n2);
        assert_eq!(n1.bounds_min, vec![-5, 0]);
        assert_eq!(n1.bounds_max, vec![15, 10]);
    }

    #[test]
    fn test_rstar_diagnostics_model() {
        let mut model = RStarTreeDiagnosticsModel::new(".ram", 2);
        assert_eq!(model.space_name, ".ram");

        let mut node = RStarTreeNode::new(1, 2);
        node.entry_count = 5;
        model.add_node(node);
        assert_eq!(model.stats.node_count, 1);
        assert_eq!(model.stats.entry_count, 5);
        assert_eq!(model.stats.leaf_count, 1);

        model.select_node(Some(1));
        assert!(model.selected_node().is_some());
        assert_eq!(model.selected_node().unwrap().id, 1);
    }

    #[test]
    fn test_rstar_tree_stats() {
        let stats = RStarTreeStats::new(4);
        assert_eq!(stats.dimensions, 4);
        assert_eq!(stats.node_count, 0);
    }
}
