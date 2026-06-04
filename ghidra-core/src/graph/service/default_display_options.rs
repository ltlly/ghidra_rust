//! Port of `ghidra.service.graph.DefaultGraphDisplayOptions`.
//!
//! Provides a convenient way to create display options with default settings.

use super::graph_type::GraphType;
use super::graph_display_options::GraphDisplayOptions;

/// Default display options factory.
///
/// Mirrors `ghidra.service.graph.DefaultGraphDisplayOptions`.
pub struct DefaultGraphDisplayOptions;

impl DefaultGraphDisplayOptions {
    /// Create default display options for the given graph type.
    pub fn create(graph_type: GraphType) -> GraphDisplayOptions {
        GraphDisplayOptions::new(graph_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_display_options() {
        let gt = GraphType::new("cfg", "CFG");
        let opts = DefaultGraphDisplayOptions::create(gt);
        assert_eq!(opts.font_size(), 12);
    }
}
