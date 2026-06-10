//! Search text feature for Features/Base.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.searchtext` Java package.
//!
//! Searches program text as displayed in the listing fields, providing
//! both a "program database" search (fast, searches the DB) and a
//! "listing display" search (slower, searches rendered text).
//!
//! This module provides:
//!
//! - [`search_text_plugin`] -- the [`SearchTextPlugin`] type that
//!   coordinates search operations, manages actions, and dispatches events
//! - [`search_text_provider`] -- the [`SearchTextProvider`] type that
//!   manages the search panel UI, history, and status display

pub mod search_text_plugin;
pub mod search_text_provider;
