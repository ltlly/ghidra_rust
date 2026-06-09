//! Listing Module -- program listing display management.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.listing` package.
//!
//! This module provides the listing display system that manages how program
//! data (instructions, data, comments, labels) is displayed in the code browser.
//!
//! # Modules
//!
//! - [`listing_plugin`] -- The main plugin struct and lifecycle
//! - [`listing_provider`] -- Component provider for listing views
//!
//! # Architecture
//!
//! ```text
//! ListingPlugin
//!   ├── ListingProvider[] (connected providers)
//!   ├── ListingLayoutManager (field layout)
//!   ├── ListingFormatService (formatting rules)
//!   └── ListingModel (data model)
//! ```

pub mod listing_plugin;
pub mod listing_provider;

pub use listing_plugin::{
    CodeUnitFormat, CodeUnitType, FieldAlignment, FieldLayout, ListingOption, ListingPlugin,
};
pub use listing_provider::{
    CursorPosition, DisplayConfig, ListingProvider,
};
