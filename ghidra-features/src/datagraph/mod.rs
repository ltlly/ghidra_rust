//! Data graph visualization for program data exploration.
//!
//! Ported from Ghidra's `datagraph` Java package (Features/DataGraph).
//!
//! Provides a visual graph for exploring data structures in a program:
//!
//! - **DataExplorationGraph**: The main graph for data exploration.
//! - **DegVertex / DegEdge**: Vertex and edge types for the data graph.
//! - **DegLayout**: Custom layout algorithm for the data graph.
//! - **DataVertexPanel**: Panel for displaying vertex data.
//! - **Column/Row models**: Table models for data display.

pub mod data_exploration_graph;
pub mod data_graph_options;
pub mod data_graph_plugin;
pub mod deg_vertex;
pub mod deg_edge;
pub mod deg_layout;
pub mod deg_controller;
pub mod panel;
pub mod exploration_graph;

pub use data_exploration_graph::*;
pub use data_graph_options::*;
pub use data_graph_plugin::*;
pub use deg_vertex::*;
pub use deg_edge::*;
pub use deg_layout::*;
pub use deg_controller::*;
