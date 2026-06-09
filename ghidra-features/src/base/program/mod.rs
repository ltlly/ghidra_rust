//! Program management -- lifecycle, events, and service interface.
//!
//! Ported from Ghidra's `Features/Base` program-related Java packages:
//!
//! - [`program_plugin`] -- base plugin class that tracks program state and
//!   dispatches lifecycle callbacks (ported from `ghidra.app.plugin.ProgramPlugin`)
//! - [`program_manager`] -- service trait for managing open programs, with an
//!   in-memory implementation (ported from `ghidra.app.services.ProgramManager`)
//!
//! # Relationship to `progmgr`
//!
//! The sibling [`crate::progmgr`] module provides the full
//! `ProgramManagerPlugin` implementation with caching, save management,
//! and transaction monitoring.  This module provides the abstract base
//! class and service trait that `progmgr` builds upon.

/// Base plugin class for tracking program state.
/// Ported from `ghidra.app.plugin.ProgramPlugin`.
pub mod program_plugin;

/// Service interface for managing open programs.
/// Ported from `ghidra.app.services.ProgramManager`.
pub mod program_manager;

pub use program_plugin::{ProgramPlugin, ProgramPluginEvent, ProgramHandle};
pub use program_manager::{ProgramManager, ProgramRef, OpenMode, DomainFileRef};
