//! Overview plugin and provider -- Base-level overview bar management.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.overview` Java package.
//!
//! This module provides the plugin and provider components that integrate
//! the overview color bar into Ghidra's Base feature layer:
//!
//! - [`OverviewPlugin`] -- plugin managing [`OverviewColorService`] instances,
//!   toggle actions, config persistence, and program lifecycle
//! - [`OverviewProvider`] -- provider that renders the color bar, handles
//!   mouse-click navigation, tooltips, and batched refresh
//!
//! The core color service trait and component types are provided by the
//! parent [`crate::overview`] module.

pub mod overview_plugin;
pub mod overview_provider;

pub use overview_plugin::{
    OverviewAction, OverviewPlugin, OverviewPluginConfig, OverviewPluginEvent,
    OverviewToggleAction,
};
pub use overview_provider::{
    AddressIndexMap, DomainChangeEvent, Navigatable, OverviewProvider, ProviderAction, RefreshState,
};
