//! Save feature -- saving modified domain files and tool configurations.
//!
//! Ported from Ghidra's `ghidra.framework.main.SaveDataDialog`,
//! `ghidra.framework.plugintool.dialog.SaveToolConfigDialog`, and
//! related save infrastructure.
//!
//! This module provides:
//!
//! - [`save_plugin`] -- The [`SaveDataDialog`] for selecting and saving
//!   modified domain files, and the [`SaveTask`] background task that
//!   performs the actual save with progress and cancellation support.
//!
//! - [`save_service`] -- The [`SaveService`] trait defining the save
//!   contract, the [`ToolConfigSaveDialog`] for saving tool configurations,
//!   and supporting types like [`ToolChest`], [`ToolTemplate`], and
//!   [`ToolServices`].

pub mod save_plugin;
pub mod save_service;

pub use save_plugin::{
    DomainFile, SaveDataDialog, SaveDataEntry, SaveDialogResult, SaveResult, SaveTask,
    SimpleTaskMonitor, TaskMonitor,
};
pub use save_service::{
    NamingUtilities, SaveService, SaveToolConfigResult, SimpleSaveService, ToolChest,
    ToolConfigSaveDialog, ToolIconUrl, ToolServices, ToolTemplate,
};
