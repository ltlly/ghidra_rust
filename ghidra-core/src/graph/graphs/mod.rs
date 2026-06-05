//! Visual graph implementations.
//!
//! Port of `ghidra.graph.graphs`:
//! - [`DefaultVisualGraph`]: base visual graph with selection/focus/change listeners
//! - [`FilteringVisualGraph`]: visual graph with vertex/edge filtering
//! - [`GroupingVisualGraph`]: visual graph with vertex grouping

pub mod default_visual_graph;
pub mod filtering_visual_graph;
pub mod grouping_visual_graph;

pub use default_visual_graph::DefaultVisualGraph;
pub use filtering_visual_graph::FilteringVisualGraph;
pub use grouping_visual_graph::GroupingVisualGraph;
