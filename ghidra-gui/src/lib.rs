//! Ghidra Rust -- GUI crate.
//!
//! An [`egui`]-based graphical interface for the Ghidra Rust reverse-engineering
//! platform.  Provides a docking framework inspired by Ghidra's own docking
//! system, together with views for code listing, decompiler output, symbol
//! trees, byte views, and menus.
//!
//! # New Modules (ported from Ghidra's Java GUI framework)
//!
//! - **`options`** -- Framework options system: hierarchical key/value store
//!   with typed getters/setters, change listeners, and JSON file persistence.
//!   Ports `ghidra.framework.options`.
//!
//! - **`theme`** -- Theme system for managing colors, fonts, and icons.
//!   Includes `ThemeValue` with indirection support, `GThemeValueMap`,
//!   `GTheme`, `LafType`, and `ThemeManager`. Ports `generic.theme`.
//!
//! - **`resources`** -- Resource and icon management. Ports
//!   `resources.ResourceManager`.
//!
//! - **`gui_util`** -- GUI utilities: `HTMLUtilities`, `WebColors`,
//!   `ColorUtils`, `HelpLocation`. Ports `ghidra.util.*`.
//!
//! - **`gui_event`** -- Mouse and keyboard event bindings. Ports
//!   `gui.event.MouseBinding`.
//!
//! - **`graph`** -- Graph framework: directed graph types, algorithms
//!   (Tarjan SCC, Dijkstra, DFS sort, Johnson circuits, dominance,
//!   find-paths, graph-to-tree), service-layer attributed graphs,
//!   visual graph viewer with layout providers, and graph jobs.
//!   Ports `ghidra.graph.*`, `ghidra.service.graph.*`.

pub mod actions;
pub mod app;
pub mod bean;
pub mod swing_exception_handler;
pub mod bytes_view;
pub mod chooser;
pub mod decompiler_view;
pub mod docking;
pub mod graph;
pub mod gui_event;
pub mod gui_util;
pub mod layout_util;
pub mod listing;
pub mod mainview;
pub mod menus;
pub mod options;
pub mod plugins;
pub mod resources;
pub mod symboltree;
pub mod task;
pub mod theme;
pub mod util;

pub use app::GhidraApp;
