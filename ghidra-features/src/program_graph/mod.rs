//! Program graph generation and display.
//!
//! Ported from Ghidra's `ghidra.graph.program` Java package (Features/ProgramGraph).
//!
//! Provides graph types for visualizing program structure:
//!
//! - **Block flow graphs**: Control flow between code blocks.
//! - **Code flow graphs**: Instruction-level control flow.
//! - **Call graphs**: Function call relationships.
//! - **Data reference graphs**: Data cross-references between addresses.
//!
//! # Key types
//!
//! - [`ProgramGraphType`] -- enum of available graph types
//! - [`DataReferenceGraph`] -- graph for data cross-references
//! - [`BlockGraphTask`] -- background task for generating block graphs
//! - [`DataReferenceGraphTask`] -- background task for generating data ref graphs
//! - [`ProgramGraphPlugin`] -- plugin that manages program graph actions
//! - [`DataFlowGraphType`] -- graph type for data flow visualization

pub mod data_reference_graph;
pub mod block_graph_task;
pub mod data_reference_graph_task;
pub mod program_graph_plugin;
pub mod graph_types;

pub use data_reference_graph::*;
pub use block_graph_task::*;
pub use data_reference_graph_task::*;
pub use program_graph_plugin::*;
pub use graph_types::*;
