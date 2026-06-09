//! Navigation History sub-module.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.navigation` history
//! classes and `ghidra.app.services.NavigationHistoryService`.
//!
//! # Key Types
//!
//! - [`history_plugin`] -- The full-featured [`NavigationHistoryPlugin`] with
//!   next/prev function navigation, serialization, and tool integration.
//! - [`history_service`] -- The [`NavigationHistoryService`] trait defining the
//!   service contract that other plugins consume.

pub mod history_plugin;
pub mod history_service;
