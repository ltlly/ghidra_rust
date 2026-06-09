//! Listing Plugin -- manages the program listing display.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.listing` package.
//!
//! This module provides the listing plugin that manages how program data
//! (instructions, data, comments, labels) is displayed in the code browser.
//!
//! # Modules
//!
//! - [`listing_plugin`] -- The main plugin struct and lifecycle

pub mod listing_plugin;

pub use listing_plugin::{
    CodeUnitFormat, CodeUnitType, FieldAlignment, FieldLayout, ListingOption, ListingPlugin,
};
