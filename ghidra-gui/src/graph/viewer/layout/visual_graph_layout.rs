//! Port of Ghidra's `ghidra.graph.viewer.layout.VisualGraphLayout`.
//!
//! Defines the trait for graph layout algorithms that position vertices.

use super::super::Point2D;

/// Trait for visual graph layout algorithms.
pub trait VisualGraphLayout: Send + Sync + std::fmt::Debug {
    /// Unique name for this layout algorithm.
    fn name(&self) -> &str;
    /// Compute positions for vertices.
    fn compute_positions(&self, vertex_ids: &[String], edges: &[(String, String)]) -> Vec<(String, Point2D)>;
    /// Whether this layout supports incremental updates.
    fn supports_incremental(&self) -> bool { false }
    /// The preferred spacing between vertices.
    fn vertex_spacing(&self) -> (f64, f64) { (150.0, 80.0) }
}

/// A simple grid layout implementation.
#[derive(Debug, Clone)]
pub struct GridLayout { pub h_spacing: f64, pub v_spacing: f64, pub max_cols: usize }
impl GridLayout {
    pub fn new() -> Self { Self { h_spacing: 150.0, v_spacing: 80.0, max_cols: 5 } }
}
impl Default for GridLayout { fn default() -> Self { Self::new() } }
impl VisualGraphLayout for GridLayout {
    fn name(&self) -> &str { "grid" }
    fn compute_positions(&self, vertex_ids: &[String], _edges: &[(String, String)]) -> Vec<(String, Point2D)> {
        vertex_ids.iter().enumerate().map(|(i, id)| {
            let col = i % self.max_cols;
            let row = i / self.max_cols;
            (id.clone(), Point2D::new(col as f64 * self.h_spacing, row as f64 * self.v_spacing))
        }).collect()
    }
}

/// A hierarchical (top-down) layout.
#[derive(Debug, Clone)]
pub struct HierarchicalLayout { pub level_gap: f64, pub sibling_gap: f64 }
impl HierarchicalLayout {
    pub fn new() -> Self { Self { level_gap: 100.0, sibling_gap: 80.0 } }
}
impl Default for HierarchicalLayout { fn default() -> Self { Self::new() } }
impl VisualGraphLayout for HierarchicalLayout {
    fn name(&self) -> &str { "hierarchical" }
    fn compute_positions(&self, vertex_ids: &[String], edges: &[(String, String)]) -> Vec<(String, Point2D)> {
        use std::collections::{HashMap, VecDeque};
        let mut levels: HashMap<String, usize> = HashMap::new();
        let mut adj: HashMap<String, Vec<String>> = HashMap::new();
        for (from, to) in edges { adj.entry(from.clone()).or_default().push(to.clone()); }
        let targets: std::collections::HashSet<&String> = edges.iter().map(|(_, t)| t).collect();
        let roots: Vec<&String> = vertex_ids.iter().filter(|id| !targets.contains(id)).collect();
        let mut queue = VecDeque::new();
        for r in &roots { levels.insert((*r).clone(), 0); queue.push_back((*r).clone()); }
        while let Some(node) = queue.pop_front() {
            let level = levels[&node];
            for child in adj.get(&node).unwrap_or(&vec![]) {
                if !levels.contains_key(child) { levels.insert(child.clone(), level + 1); queue.push_back(child.clone()); }
            }
        }
        let mut level_counts: HashMap<usize, usize> = HashMap::new();
        vertex_ids.iter().map(|id| {
            let level = levels.get(id).copied().unwrap_or(0);
            let idx = level_counts.entry(level).or_insert(0);
            let pos = Point2D::new(*idx as f64 * self.sibling_gap, level as f64 * self.level_gap);
            *idx += 1;
            (id.clone(), pos)
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grid_layout() {
        let layout = GridLayout::new();
        let ids = vec!["a".into(), "b".into(), "c".into()];
        let pos = layout.compute_positions(&ids, &[]);
        assert_eq!(pos.len(), 3);
        assert_eq!(pos[0].1, Point2D::new(0.0, 0.0));
        assert_eq!(pos[1].1, Point2D::new(150.0, 0.0));
    }

    #[test]
    fn test_hierarchical_layout() {
        let layout = HierarchicalLayout::new();
        let ids = vec!["root".into(), "a".into(), "b".into()];
        let edges = vec![("root".into(), "a".into()), ("root".into(), "b".into())];
        let pos = layout.compute_positions(&ids, &edges);
        assert_eq!(pos.len(), 3);
    }

    #[test]
    fn test_layout_name() {
        assert_eq!(GridLayout::new().name(), "grid");
        assert_eq!(HierarchicalLayout::new().name(), "hierarchical");
    }
}
