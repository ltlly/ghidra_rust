//! Well-known layout algorithm names.
//!
//! Ports `ghidra.service.graph.LayoutAlgorithmNames`.

/// Layout algorithm name constants.
pub mod names {
    /// Circular layout: vertices arranged in a circle.
    pub const CIRCULAR: &str = "Circular Layout";
    /// Fruchterman-Reingold force-directed layout.
    pub const FRUCHTERMAN_REINGOLD: &str = "FRLayout";
    /// Kamada-Kawai spring layout.
    pub const KAMADA_KAWAI: &str = "KKLayout";
    /// ISOM layout (self-organizing map).
    pub const ISOM: &str = "ISOMLayout";
    /// Spring layout.
    pub const SPRING: &str = "Spring Layout";
    /// DAG layout (directed acyclic graph).
    pub const DAG: &str = "DAG Layout";
    /// Hierarchical layout.
    pub const HIERARCHICAL: &str = "Hierarchical Layout";
    /// Grid layout.
    pub const GRID: &str = "Grid Layout";
    /// Tree layout.
    pub const TREE: &str = "Tree Layout";
    /// Organic layout.
    pub const ORGANIC: &str = "Organic Layout";
}

/// Get all known layout algorithm names.
pub fn all_layout_names() -> Vec<&'static str> {
    vec![
        names::CIRCULAR,
        names::FRUCHTERMAN_REINGOLD,
        names::KAMADA_KAWAI,
        names::ISOM,
        names::SPRING,
        names::DAG,
        names::HIERARCHICAL,
        names::GRID,
        names::TREE,
        names::ORGANIC,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_layout_names() {
        let names = all_layout_names();
        assert!(!names.is_empty());
        assert!(names.contains(&"Circular Layout"));
        assert!(names.contains(&"DAG Layout"));
    }

    #[test]
    fn test_layout_name_constants() {
        assert!(!names::CIRCULAR.is_empty());
        assert!(!names::TREE.is_empty());
    }
}
