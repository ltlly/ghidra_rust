//! Ghidra Rust -- GUI crate.
//!
//! An [`egui`]-based graphical interface for the Ghidra Rust reverse-engineering
//! platform.  Provides a docking framework inspired by Ghidra's own docking
//! system, together with views for code listing, decompiler output, symbol
//! trees, byte views, and menus.

pub mod actions;
pub mod app;
pub mod bytes_view;
pub mod decompiler_view;
pub mod docking;
pub mod listing;
pub mod mainview;
pub mod menus;
pub mod symboltree;

pub use app::GhidraApp;
