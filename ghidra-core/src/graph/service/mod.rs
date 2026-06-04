//! Graph service types ported from Ghidra's `ghidra.service.graph` package.
//!
//! Provides attributed graph types for representing and displaying graphs:
//! - Core traits: [`Attributed`] for objects with named attributes
//! - Graph types: [`AttributedGraph`], [`AttributedVertex`], [`AttributedEdge`]
//! - Display configuration: [`GraphDisplayOptions`], [`GraphLabelPosition`]
//! - Graph type registration: [`GraphType`], [`EmptyGraphType`], [`GraphTypeBuilder`]
//! - Layout: [`LayoutAlgorithmNames`], [`VertexShape`]
//! - Builder: [`GraphDisplayOptionsBuilder`], [`DefaultGraphDisplayOptions`]

pub mod attributed;
pub mod attributed_graph;
pub mod attributed_vertex;
pub mod attributed_edge;
pub mod graph_type;
pub mod graph_display_options;
pub mod graph_label_position;
pub mod vertex_shape;
pub mod layout_names;
pub mod empty_graph_type;
pub mod graph_type_builder;
pub mod graph_display_options_builder;
pub mod default_display_options;

pub use attributed::Attributed;
pub use attributed_graph::AttributedGraph;
pub use attributed_vertex::AttributedVertex;
pub use attributed_edge::AttributedEdge;
pub use graph_type::GraphType;
pub use graph_display_options::GraphDisplayOptions;
pub use graph_label_position::GraphLabelPosition;
pub use vertex_shape::VertexShape;
pub use layout_names::LayoutAlgorithmNames;
pub use empty_graph_type::EmptyGraphType;
pub use graph_type_builder::GraphTypeBuilder;
pub use graph_display_options_builder::GraphDisplayOptionsBuilder;
pub use default_display_options::DefaultGraphDisplayOptions;
