//! Port of `ghidra.service.graph.LayoutAlgorithmNames`.
//!
//! Constants for well-known layout algorithm names.

/// Constants for layout algorithm names.
///
/// Mirrors `ghidra.service.graph.LayoutAlgorithmNames`.
pub struct LayoutAlgorithmNames;

impl LayoutAlgorithmNames {
    /// Hierarchical / Sugiyama layout (top-down or left-right).
    pub const HIERARCHICAL: &'static str = "Hierarchical";
    /// Spring-embedder / force-directed layout.
    pub const SPRING: &'static str = "Spring";
    /// Circular layout.
    pub const CIRCULAR: &'static str = "Circular";
    /// Grid layout.
    pub const GRID: &'static str = "Grid";
    /// Orthogonal layout.
    pub const ORTHOGONAL: &'static str = "Orthogonal";
    /// Radial layout.
    pub const RADIAL: &'static str = "Radial";
    /// Directed (similar to hierarchical but with different edge routing).
    pub const DIRECTED: &'static str = "Directed";

    /// Get the default layout algorithm name.
    pub fn default_name() -> &'static str {
        Self::HIERARCHICAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_names() {
        assert_eq!(LayoutAlgorithmNames::HIERARCHICAL, "Hierarchical");
        assert_eq!(LayoutAlgorithmNames::SPRING, "Spring");
        assert_eq!(LayoutAlgorithmNames::CIRCULAR, "Circular");
    }

    #[test]
    fn test_default_name() {
        assert_eq!(LayoutAlgorithmNames::default_name(), "Hierarchical");
    }
}
