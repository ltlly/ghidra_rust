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
//! - **[`actions`]** — Higher-level action management: [`actions::DockingToolActions`]
//!   (global/local/placeholder registry), [`actions::PopupActionManager`],
//!   [`actions::MenuBarManager`], [`actions::ToolBarManager`],
//!   [`actions::WindowActionManager`], and [`actions::DockingActionProxy`].
//!
//! - **[`component`]** — Dockable component abstractions.  The
//!   [`component::DockingComponent`] trait is implemented by every view /
//!   window, and [`component::ComponentProvider`] enumerates the well-known
//!   provider types (Listing, Decompiler, Symbol Tree, etc.).  The
//!   [`component::ComponentProviderInfo`] trait provides rich metadata
//!   (tool name, owner, menu groups, default size/position).
//!
//! - **[`context`]** — Action context system: [`context::ActionContext`] trait,
//!   [`context::DefaultActionContext`], [`context::DialogActionContext`],
//!   [`context::DockingContextListener`], and [`context::ContextManager`].
//!
//! - **[`dialog`]** — Dialog abstractions: [`dialog::DialogComponentProvider`]
//!   and [`dialog::ReusableDialogComponentProvider`] with status lines,
//!   button panels, dismiss actions, and accessibility support.
//!
//! - **[`drop`]** — Drag-and-drop support: [`drop::DropCode`],
//!   [`drop::DropRegion`], [`drop::DropTarget`], and [`drop::DropState`].
//!
//! - **[`keybinding`]** — Key binding precedence and dispatch:
//!   [`keybinding::KeyBindingPrecedence`], [`keybinding::ExecutableAction`],
//!   [`keybinding::KeyBindingEntry`], and [`keybinding::KeyBindingDispatcher`].
//!
//! - **[`layout`]** — Layout management.  [`layout::DockingLayout`] describes
//!   where every window sits, which tab groups exist, and how toolbars are
//!   configured.  Includes [`layout::SplitNode`] for recursive split-pane
//!   trees and docking operations (`dock`, `float`, `tab_with`, `split_with`).
//!   Layouts can be serialized / deserialized via JSON for persistence.
//!
//! - **[`menu`]** — Menu items and dockable UI chrome: [`menu::DockingMenuItem`],
//!   [`menu::MenuModel`], and [`menu::DockableHeader`].
//!
//! - **[`plugin`]** — The plugin system.  Plugins implement the
//!   [`plugin::Plugin`] trait and are managed by
//!   [`plugin::PluginManager`].  Supports dependency resolution,
//!   lifecycle phases ([`plugin::PluginLifecycle`]), and bulk loading.
//!
//! - **[`statusbar`]** — Status bar: [`statusbar::StatusBar`] with message
//!   history, custom items, fading, and flash support.
//!
//! - **[`tool`]** — The top-level [`tool::DockingTool`].  It owns the layout,
//!   the action registry, the plugin manager, the event system
//!   ([`tool::ToolEvent`]), the service registry, and the set of active
//!   dockable components.
//!
//! - **[`window_manager`]** — Window hierarchy management:
//!   [`window_manager::DockingWindowManager`],
//!   [`window_manager::ComponentPlaceholder`], and
//!   [`window_manager::WindowContainer`].
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
pub mod actions;
pub mod component;
pub mod context;
pub mod dialog;
pub mod drop;
pub mod keybinding;
pub mod layout;
pub mod menu;
pub mod plugin;
pub mod statusbar;
pub mod tool;
pub mod window_manager;

// Re-export the most commonly-used types at the docking module level for
// convenience.
pub use action::{
    ActionCallback, ActionContext, ActionContextInfo, ActionType,
    ContextActionCallback, DockingAction, GuiActionManager, Key, KeyBinding, Modifiers, UndoEntry,
};
pub use actions::{
    ClosurePopupProvider, DockingActionProxy, DockingToolActions, MenuBarManager,
    PopupActionManager, ToolBarManager, WindowActionManager,
};
pub use component::{
    ComponentProvider, ComponentProviderInfo, DockingComponent, SimpleComponent, WindowPosition,
};
pub use context::{
    ClosureContextListener, ContextManager, DefaultActionContext,
    DialogActionContext, DockingContextListener,
};
pub use context::ActionContext as ActionContextApi;
pub use dialog::{ButtonSpec, DialogComponentProvider, MessageType, ReusableDialogComponentProvider};
pub use drop::{DropCode, DropRegion, DropState, DropTarget};
pub use keybinding::{
    ExecutableAction, KeyBindingDispatcher, KeyBindingEntry, KeyBindingPrecedence,
    SimpleExecutableAction,
};
pub use layout::{
    DockArea, DockingLayout, DockingWindowPlacement, SplitDirection, SplitNode, TabGroup,
    ToolbarConfig,
};
pub use menu::{DockableHeader, DockingMenuItem, MenuModel};
pub use plugin::{
    Plugin, PluginConfig, PluginDependency, PluginError, PluginInfo, PluginLifecycle, PluginManager,
};
pub use statusbar::{StatusBar, StatusItem, StatusMessage};
pub use tool::{DockingTool, ToolEvent, ToolEventCallback, ToolService};
pub use window_manager::{ComponentPlaceholder, DockingWindowManager, WindowContainer};
