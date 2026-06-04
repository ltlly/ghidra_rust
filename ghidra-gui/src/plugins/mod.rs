//! Ghidra Base viewers and plugins ported from Java to Rust.
//!
//! This module contains Rust implementations of the core Ghidra GUI
//! plugins originally found in
//! `ghidra.app.plugin.core.*`:
//!
//! - **`overview`** -- Overview color bar: maps program addresses to
//!   colors for the Listing margin area.
//! - **`goto`** -- Go-to-address service: navigate to addresses, labels,
//!   external linkages, and cross-program locations.
//! - **`comments`** -- Comment management: add, edit, and delete
//!   EOL / PRE / POST / PLATE / Repeatable comments.
//! - **`search_text`** -- Text search across the program database and
//!   listing display fields.
//! - **`program_tree`** -- Program tree view: hierarchical fragment/module
//!   tree with drag-and-drop reordering.
//! - **`navigation`** -- Navigation helpers: next/previous actions,
//!   location references, and reference descriptors.

pub mod comments;
pub mod goto;
pub mod navigation;
pub mod overview;
pub mod program_tree;
pub mod search_text;
