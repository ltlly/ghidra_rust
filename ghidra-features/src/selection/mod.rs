//! Selection Plugin and Service.
//!
//! Ported from Ghidra's `Features/Selection` Java package:
//!
//! - `ghidra.plugin.core.selection.SelectionPlugin` -- the plugin that
//!   registers selection actions and manages the program selection.
//! - `ghidra.app.services.SelectionService` -- the service interface that
//!   other plugins use to query or modify the current selection.
//! - `ghidra.app.services.SelectionServiceListener` -- listener for
//!   selection change events.
//! - `ghidra.framework.model.ProgramSelection` -- the address range set
//!   representing a user's selection in a program.
//!
//! # Overview
//!
//! The **Selection** feature provides the machinery for managing address
//! selections in a Ghidra program. When the user selects a range of
//! addresses in the code browser, the [`SelectionPlugin`] captures that
//! selection and exposes it via the [`SelectionService`]. Other plugins
//! can then query the current selection, react to changes via
//! [`SelectionServiceListener`], or programmatically modify the selection.
//!
//! # Key Types
//!
//! | Type | Description |
//! |------|-------------|
//! | [`SelectionPlugin`] | Top-level plugin managing selection actions |
//! | [`SelectionService`] | Service trait for selection access |
//! | [`DefaultSelectionService`] | In-process service implementation |
//! | [`ProgramSelection`] | Address range set for a selection |
//! | [`SelectionServiceListener`] | Listener for selection changes |
//! | [`SelectionAction`] | Enum of available selection actions |

/// The Features/Selection plugin.
///
/// Ported from `ghidra.plugin.core.selection.SelectionPlugin`.
pub mod selection_plugin;

/// The selection service interface and program selection type.
///
/// Ported from `ghidra.app.services.SelectionService` and
/// `ghidra.framework.model.ProgramSelection`.
pub mod selection_service;

// Re-export key types at the module level for convenience.
pub use selection_plugin::{SelectionAction, SelectionPlugin};
pub use selection_service::{
    DefaultSelectionService, ProgramSelection, SelectionService, SelectionServiceListener,
};
