//! String analysis plugins for Features/Base.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.string` and
//! `ghidra.app.plugin.core.strings` Java packages.
//!
//! This module provides two plugins for working with strings in a program:
//!
//! - [`string_table_plugin`] -- Searches memory for strings and displays them
//!   in a table.  Provides the "Search for Strings" action under the Search
//!   menu.  Ported from `ghidra.app.plugin.core.string.StringTablePlugin`.
//!
//! - [`defined_string_table_plugin`] -- Displays all already-defined string
//!   data items in the program listing.  Listens for domain object changes
//!   and supports incremental updates.  Ported from
//!   `ghidra.app.plugin.core.strings.DefinedStringsPlugin`.

/// String Table Plugin -- searches memory for strings and displays them.
///
/// Ported from `ghidra.app.plugin.core.string.StringTablePlugin`,
/// `StringTableProvider`, `StringTableOptions`, `FoundString`,
/// `StringSearchModel`, and related types.
pub mod string_table_plugin;

/// Defined Strings Table Plugin -- displays all defined string data.
///
/// Ported from `ghidra.app.plugin.core.strings.DefinedStringsPlugin`,
/// `DefinedStringsProvider`, `DefinedStringsTableModel`,
/// `DefinedStringsContext`, and related types.
pub mod defined_string_table_plugin;
