//! Layout infrastructure for graph services.
//!
//! Ported from Ghidra's `ghidra.graph.viewer.layout` and
//! `ghidra.service.graph` Java packages.
//!
//! Provides layout providers, grid location maps, and layout result types
//! for positioning vertices in graph visualizations.

pub mod layout_provider;

pub use layout_provider::{
    Column, GridBounds, GridLocationMap, GridPoint, LayoutPositions, LayoutProvider,
    LayoutProviderRegistry, RelayoutOption, Row, SimpleRowLayout, ViewRestoreOption,
};
