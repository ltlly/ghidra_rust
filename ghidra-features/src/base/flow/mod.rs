//! Flow analysis module -- ported from Ghidra's
//! `ghidra.program.model.block.FollowFlow` and
//! `ghidra.app.plugin.core.flowarrow` and
//! `ghidra.app.plugin.core.select.flow`.
//!
//! This module provides:
//!
//! - [`FollowFlow`] -- follows program code flow forward or backward
//! - [`FlowArrow`] -- represents a flow arrow for UI visualization
//! - [`FlowArrowType`] -- types of flow arrows (conditional, fallthrough, etc.)
//! - [`SelectByFlow`] -- selects code based on program flow
//! - [`FlowFollowOptions`] -- configuration for which flow types to follow

mod follow_flow;
mod flow_arrow;
mod flow_arrow_shapes;
mod select_by_flow;

pub use follow_flow::*;
pub use flow_arrow::*;
pub use flow_arrow_shapes::*;
pub use select_by_flow::*;
