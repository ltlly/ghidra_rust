//! Program Manager -- ported from Ghidra's
//! `ghidra.app.plugin.core.progmgr` Java package.
//!
//! This module provides the program management layer that tracks open
//! programs, handles caching, save/undo/redo, and coordinates between
//! multiple programs in a tool.  It provides:
//!
//! - [`ProgramManagerPlugin`] -- top-level plugin managing open programs
//! - [`MultiProgramManager`] -- tracks open programs and their state
//! - [`ProgramCache`] -- time-based LRU caching for programs
//! - [`ProgramLocator`] -- identifies program locations (file or URL)
//! - [`TransactionMonitor`] -- monitors transaction state
//! - [`ProgramSaveManager`] -- handles save/save-as operations
//!
//! Swing-specific UI code (actions, menus) is simplified to the
//! logical dispatch only.

pub mod actions;
pub mod program_locator;
pub mod program_cache;
pub mod multi_program_manager;
pub mod transaction_monitor;
pub mod save_manager;
pub mod plugin;

pub use actions::{ProgramAction, ProgramActionKind, ProgramActionContext};
pub use program_locator::ProgramLocator;
pub use program_cache::ProgramCache;
pub use multi_program_manager::MultiProgramManager;
pub use transaction_monitor::TransactionMonitor;
pub use save_manager::ProgramSaveManager;
pub use plugin::ProgramManagerPlugin;
