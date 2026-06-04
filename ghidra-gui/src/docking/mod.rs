//! Ghidra-inspired docking framework for egui.
//!
//! This module provides the core abstractions for building a docking-based GUI
//! application, inspired by Ghidra's docking framework but reimplemented for
//! use with the [`egui`] immediate-mode GUI library.
//!
//! # Architecture
//!
//! - **[`action`]** — The action system: named, key-bound operations that can
//!   appear in menus, toolbars, and context menus.  Actions can be global,
//!   contextual (depending on the program element under focus), toggleable, or
//!   nested sub-menus.  Includes [`action::GuiActionManager`] with undo/redo
//!   support and [`action::ContextActionCallback`] for context-aware actions.
//!
//! - **[`component`]** — Dockable component abstractions.  The
//!   [`component::DockingComponent`] trait is implemented by every view /
//!   window, and [`component::ComponentProvider`] enumerates the well-known
//!   provider types (Listing, Decompiler, Symbol Tree, etc.).  The
//!   [`component::ComponentProviderInfo`] trait provides rich metadata
//!   (tool name, owner, menu groups, default size/position).
//!
//! - **[`layout`]** — Layout management.  [`layout::DockingLayout`] describes
//!   where every window sits, which tab groups exist, and how toolbars are
//!   configured.  Includes [`layout::SplitNode`] for recursive split-pane
//!   trees and docking operations (`dock`, `float`, `tab_with`, `split_with`).
//!   Layouts can be serialized / deserialized via JSON for persistence.
//!
//! - **[`tool`]** — The top-level [`tool::DockingTool`].  It owns the layout,
//!   the action registry, the plugin manager, the event system
//!   ([`tool::ToolEvent`]), the service registry, and the set of active
//!   dockable components.
//!
//! - **[`plugin`]** — The plugin system.  Plugins implement the
//!   [`plugin::Plugin`] trait and are managed by
//!   [`plugin::PluginManager`].  Supports dependency resolution,
//!   lifecycle phases ([`plugin::PluginLifecycle`]), and bulk loading.
//!
//! # Usage
//!
//! ```ignore
//! use ghidra_gui::docking::tool::DockingTool;
//! use ghidra_gui::docking::layout::DockingLayout;
//!
//! // Create a tool with the default Ghidra-style layout.
//! let mut tool = DockingTool::new();
//!
//! // Restore a previously-saved layout.
//! let saved = std::fs::read_to_string("layout.json").unwrap_or_default();
//! if !saved.is_empty() {
//!     tool.load_layout(&saved).ok();
//! }
//!
//! // Later, persist the layout.
//! std::fs::write("layout.json", tool.save_layout()).ok();
//! ```

pub mod action;
pub mod component;
pub mod layout;
pub mod plugin;
pub mod tool;

// Re-export the most commonly-used types at the docking module level for
// convenience.
pub use action::{
    ActionCallback, ActionContext, ActionContextInfo, ActionType, ContextActionCallback,
    DockingAction, GuiActionManager, Key, KeyBinding, Modifiers, UndoEntry,
};
pub use component::{
    ComponentProvider, ComponentProviderInfo, DockingComponent, SimpleComponent, WindowPosition,
};
pub use layout::{
    DockArea, DockingLayout, DockingWindowPlacement, SplitDirection, SplitNode, TabGroup,
    ToolbarConfig,
};
pub use plugin::{
    Plugin, PluginConfig, PluginDependency, PluginError, PluginInfo, PluginLifecycle, PluginManager,
};
pub use tool::{DockingTool, ToolEvent, ToolEventCallback, ToolService};
