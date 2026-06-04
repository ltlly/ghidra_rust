//! Menu items and dockable UI components for the docking framework.
//!
//! Port of Ghidra's `DockingMenuItem`, `DockingCheckBoxMenuItem`,
//! `GenericHeader`, `DockableHeader`, and related UI abstractions.

use std::sync::Arc;

use super::action::{ActionCallback, DockingAction, KeyBinding};

// ---------------------------------------------------------------------------
// MenuItemKind — the type of a menu item
// ---------------------------------------------------------------------------

/// The kind of a menu item.
#[derive(Debug, Clone, PartialEq)]
pub enum MenuItemKind {
    /// A normal clickable item.
    Action,
    /// A checkbox/toggle item.
    CheckBox {
        /// Current checked state.
        checked: bool,
    },
    /// A radio-button item within a group.
    Radio {
        /// Radio group identifier.
        group: String,
        /// Current selected state.
        selected: bool,
    },
    /// A separator line.
    Separator,
    /// A sub-menu container.
    SubMenu,
}

// ---------------------------------------------------------------------------
// DockingMenuItem
// ---------------------------------------------------------------------------

/// A menu item in the docking framework.
///
/// Represents a single entry in a menu or context menu, with an
/// associated action, keyboard shortcut, icon, and enablement state.
#[derive(Debug, Clone)]
pub struct DockingMenuItem {
    /// Display text for the item.
    pub text: String,
    /// Optional key binding shown as accelerator text.
    pub key_binding: Option<KeyBinding>,
    /// Optional icon name / resource path.
    pub icon: Option<String>,
    /// Whether the item is enabled.
    pub enabled: bool,
    /// Whether the item is visible.
    pub visible: bool,
    /// The kind of this menu item.
    pub kind: MenuItemKind,
    /// Optional tooltip text.
    pub tooltip: Option<String>,
    /// The name of the associated action.
    pub action_name: Option<String>,
    /// Optional mnemonic character (underlined in the label).
    pub mnemonic: Option<char>,
    /// Menu group for ordering.
    pub menu_group: String,
    /// Priority within the group (lower = earlier).
    pub priority: u32,
}

impl DockingMenuItem {
    /// Create a new action menu item.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            key_binding: None,
            icon: None,
            enabled: true,
            visible: true,
            kind: MenuItemKind::Action,
            tooltip: None,
            action_name: None,
            mnemonic: None,
            menu_group: String::new(),
            priority: 100,
        }
    }

    /// Create a separator.
    pub fn separator() -> Self {
        Self {
            text: String::new(),
            key_binding: None,
            icon: None,
            enabled: false,
            visible: true,
            kind: MenuItemKind::Separator,
            tooltip: None,
            action_name: None,
            mnemonic: None,
            menu_group: String::new(),
            priority: 100,
        }
    }

    /// Create a checkbox menu item.
    pub fn checkbox(text: impl Into<String>, checked: bool) -> Self {
        Self {
            kind: MenuItemKind::CheckBox { checked },
            ..Self::new(text)
        }
    }

    /// Create a radio menu item.
    pub fn radio(text: impl Into<String>, group: impl Into<String>, selected: bool) -> Self {
        Self {
            kind: MenuItemKind::Radio {
                group: group.into(),
                selected,
            },
            ..Self::new(text)
        }
    }

    /// Set the key binding.
    pub fn with_key_binding(mut self, binding: KeyBinding) -> Self {
        self.key_binding = Some(binding);
        self
    }

    /// Set the icon.
    pub fn with_icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    /// Set the tooltip.
    pub fn with_tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = Some(tooltip.into());
        self
    }

    /// Set the action name.
    pub fn with_action_name(mut self, name: impl Into<String>) -> Self {
        self.action_name = Some(name.into());
        self
    }

    /// Set the mnemonic.
    pub fn with_mnemonic(mut self, ch: char) -> Self {
        self.mnemonic = Some(ch);
        self
    }

    /// Set the menu group.
    pub fn with_menu_group(mut self, group: impl Into<String>) -> Self {
        self.menu_group = group.into();
        self
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Set enabled.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Whether this is a separator.
    pub fn is_separator(&self) -> bool {
        matches!(self.kind, MenuItemKind::Separator)
    }

    /// Whether this is a checkbox item.
    pub fn is_checkbox(&self) -> bool {
        matches!(self.kind, MenuItemKind::CheckBox { .. })
    }

    /// Whether this is a radio item.
    pub fn is_radio(&self) -> bool {
        matches!(self.kind, MenuItemKind::Radio { .. })
    }

    /// Get the checkbox checked state (if applicable).
    pub fn is_checked(&self) -> bool {
        match &self.kind {
            MenuItemKind::CheckBox { checked } => *checked,
            MenuItemKind::Radio { selected, .. } => *selected,
            _ => false,
        }
    }

    /// Set the checkbox checked state (if applicable).
    pub fn set_checked(&mut self, checked: bool) {
        match &mut self.kind {
            MenuItemKind::CheckBox {
                checked: ref mut c,
            } => *c = checked,
            MenuItemKind::Radio {
                selected: ref mut s,
                ..
            } => *s = checked,
            _ => {}
        }
    }

    /// Toggle the checked state (if applicable).
    pub fn toggle_checked(&mut self) {
        let current = self.is_checked();
        self.set_checked(!current);
    }
}

// ---------------------------------------------------------------------------
// MenuModel — a complete menu
// ---------------------------------------------------------------------------

/// A menu model containing ordered items.
#[derive(Debug, Clone, Default)]
pub struct MenuModel {
    /// Display name of this menu.
    pub title: String,
    /// Ordered items.
    pub items: Vec<DockingMenuItem>,
}

impl MenuModel {
    /// Create a new menu model.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            items: Vec::new(),
        }
    }

    /// Add an item.
    pub fn add_item(&mut self, item: DockingMenuItem) {
        self.items.push(item);
    }

    /// Add a separator.
    pub fn add_separator(&mut self) {
        self.items.push(DockingMenuItem::separator());
    }

    /// Remove an item by text.
    pub fn remove_item(&mut self, text: &str) -> bool {
        if let Some(pos) = self.items.iter().position(|i| i.text == text) {
            self.items.remove(pos);
            true
        } else {
            false
        }
    }

    /// Find an item by text.
    pub fn find_item(&self, text: &str) -> Option<&DockingMenuItem> {
        self.items.iter().find(|i| i.text == text)
    }

    /// Find a mutable item by text.
    pub fn find_item_mut(&mut self, text: &str) -> Option<&mut DockingMenuItem> {
        self.items.iter_mut().find(|i| i.text == text)
    }

    /// Number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the menu is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Number of non-separator items.
    pub fn action_count(&self) -> usize {
        self.items.iter().filter(|i| !i.is_separator()).count()
    }
}

// ---------------------------------------------------------------------------
// DockableHeader — the title/header bar of a dockable component
// ---------------------------------------------------------------------------

/// Describes the header bar of a dockable component.
///
/// In Ghidra, `DockableHeader` contains the title, close button, and
/// drag handle for a dockable window.  This Rust equivalent describes
/// the header's logical state.
#[derive(Debug, Clone)]
pub struct DockableHeader {
    /// Title text.
    pub title: String,
    /// Sub-title text (e.g. the program name).
    pub subtitle: String,
    /// Whether the close button is shown.
    pub show_close_button: bool,
    /// Whether the drag handle is shown.
    pub show_drag_handle: bool,
    /// Optional icon.
    pub icon: Option<String>,
    /// Whether the header is currently active (focused).
    pub active: bool,
    /// Whether to highlight the header (e.g. during drag-over).
    pub highlighted: bool,
}

impl DockableHeader {
    /// Create a new dockable header.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            subtitle: String::new(),
            show_close_button: true,
            show_drag_handle: true,
            icon: None,
            active: false,
            highlighted: false,
        }
    }

    /// Set the subtitle.
    pub fn with_subtitle(mut self, subtitle: impl Into<String>) -> Self {
        self.subtitle = subtitle.into();
        self
    }

    /// Set the icon.
    pub fn with_icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    /// Hide the close button.
    pub fn without_close_button(mut self) -> Self {
        self.show_close_button = false;
        self
    }

    /// Hide the drag handle.
    pub fn without_drag_handle(mut self) -> Self {
        self.show_drag_handle = false;
        self
    }

    /// Get the display title (title + subtitle if present).
    pub fn display_title(&self) -> String {
        if self.subtitle.is_empty() {
            self.title.clone()
        } else {
            format!("{} - {}", self.title, self.subtitle)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::action::{Key, Modifiers};

    #[test]
    fn test_menu_item_new() {
        let item = DockingMenuItem::new("Open");
        assert_eq!(item.text, "Open");
        assert!(item.enabled);
        assert!(item.visible);
        assert_eq!(item.kind, MenuItemKind::Action);
        assert!(!item.is_separator());
    }

    #[test]
    fn test_menu_item_separator() {
        let item = DockingMenuItem::separator();
        assert!(item.is_separator());
        assert!(!item.enabled);
    }

    #[test]
    fn test_menu_item_checkbox() {
        let mut item = DockingMenuItem::checkbox("Show Line Numbers", true);
        assert!(item.is_checkbox());
        assert!(item.is_checked());
        item.toggle_checked();
        assert!(!item.is_checked());
        item.set_checked(true);
        assert!(item.is_checked());
    }

    #[test]
    fn test_menu_item_radio() {
        let mut item = DockingMenuItem::radio("Hex", "radix", false);
        assert!(item.is_radio());
        assert!(!item.is_checked());
        item.set_checked(true);
        assert!(item.is_checked());
    }

    #[test]
    fn test_menu_item_builder() {
        let item = DockingMenuItem::new("Save")
            .with_key_binding(KeyBinding::ctrl(Key::S))
            .with_icon("save-icon")
            .with_tooltip("Save the current file")
            .with_action_name("save")
            .with_mnemonic('S')
            .with_menu_group("File")
            .with_priority(10);

        assert!(item.key_binding.is_some());
        assert_eq!(item.icon.as_deref(), Some("save-icon"));
        assert_eq!(item.tooltip.as_deref(), Some("Save the current file"));
        assert_eq!(item.action_name.as_deref(), Some("save"));
        assert_eq!(item.mnemonic, Some('S'));
        assert_eq!(item.menu_group, "File");
        assert_eq!(item.priority, 10);
    }

    #[test]
    fn test_menu_model() {
        let mut menu = MenuModel::new("File");
        menu.add_item(DockingMenuItem::new("New"));
        menu.add_item(DockingMenuItem::new("Open"));
        menu.add_separator();
        menu.add_item(DockingMenuItem::new("Save"));

        assert_eq!(menu.len(), 4);
        assert_eq!(menu.action_count(), 3);

        assert!(menu.find_item("Open").is_some());
        assert!(menu.find_item("Nonexistent").is_none());

        assert!(menu.remove_item("Open"));
        assert_eq!(menu.len(), 3);
        assert!(menu.find_item("Open").is_none());
    }

    #[test]
    fn test_menu_model_find_mut() {
        let mut menu = MenuModel::new("Edit");
        menu.add_item(DockingMenuItem::new("Undo").with_enabled(false));

        assert!(!menu.find_item("Undo").unwrap().enabled);
        menu.find_item_mut("Undo").unwrap().enabled = true;
        assert!(menu.find_item("Undo").unwrap().enabled);
    }

    #[test]
    fn test_dockable_header() {
        let header = DockableHeader::new("Decompiler")
            .with_subtitle("main() - test.elf")
            .with_icon("decompiler-icon");

        assert_eq!(header.title, "Decompiler");
        assert_eq!(header.subtitle, "main() - test.elf");
        assert!(header.show_close_button);
        assert!(header.show_drag_handle);
        assert_eq!(
            header.display_title(),
            "Decompiler - main() - test.elf"
        );
    }

    #[test]
    fn test_dockable_header_no_subtitle() {
        let header = DockableHeader::new("Console");
        assert_eq!(header.display_title(), "Console");
    }

    #[test]
    fn test_dockable_header_without_close() {
        let header = DockableHeader::new("Fixed").without_close_button();
        assert!(!header.show_close_button);
        assert!(header.show_drag_handle);
    }

    #[test]
    fn test_dockable_header_active_highlighted() {
        let mut header = DockableHeader::new("Test");
        assert!(!header.active);
        assert!(!header.highlighted);
        header.active = true;
        header.highlighted = true;
        assert!(header.active);
        assert!(header.highlighted);
    }
}
