//! Popup/context menu support for graph viewers.
//!
//! Ports `ghidra.graph.viewer.popup` package.

/// A popup menu item.
#[derive(Debug, Clone)]
pub struct PopupMenuItem {
    /// Menu item label.
    pub label: String,
    /// Whether the item is enabled.
    pub enabled: bool,
    /// Optional keyboard shortcut description.
    pub shortcut: Option<String>,
    /// Menu item id for identifying the action.
    pub action_id: String,
    /// Whether this is a separator.
    pub is_separator: bool,
}

impl PopupMenuItem {
    /// Create a new menu item.
    pub fn new(label: impl Into<String>, action_id: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            enabled: true,
            shortcut: None,
            action_id: action_id.into(),
            is_separator: false,
        }
    }

    /// Create a separator item.
    pub fn separator() -> Self {
        Self {
            label: String::new(),
            enabled: false,
            shortcut: None,
            action_id: String::new(),
            is_separator: true,
        }
    }

    /// Set the shortcut description.
    pub fn with_shortcut(mut self, shortcut: impl Into<String>) -> Self {
        self.shortcut = Some(shortcut.into());
        self
    }

    /// Set whether the item is enabled.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// A popup context menu for graph elements.
#[derive(Debug, Clone, Default)]
pub struct PopupMenu {
    /// Menu items.
    items: Vec<PopupMenuItem>,
}

impl PopupMenu {
    /// Create an empty popup menu.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a menu item.
    pub fn add_item(&mut self, item: PopupMenuItem) {
        self.items.push(item);
    }

    /// Add a separator.
    pub fn add_separator(&mut self) {
        self.items.push(PopupMenuItem::separator());
    }

    /// Get all menu items.
    pub fn items(&self) -> &[PopupMenuItem] {
        &self.items
    }

    /// Number of items (including separators).
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the menu is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Find a menu item by action id.
    pub fn find_item(&self, action_id: &str) -> Option<&PopupMenuItem> {
        self.items.iter().find(|i| i.action_id == action_id)
    }
}

/// Builder for constructing popup menus fluently.
#[derive(Debug, Clone, Default)]
pub struct PopupMenuBuilder {
    menu: PopupMenu,
}

impl PopupMenuBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a menu item.
    pub fn item(mut self, label: &str, action_id: &str) -> Self {
        self.menu.add_item(PopupMenuItem::new(label, action_id));
        self
    }

    /// Add a disabled item.
    pub fn disabled_item(mut self, label: &str, action_id: &str) -> Self {
        self.menu.add_item(PopupMenuItem::new(label, action_id).with_enabled(false));
        self
    }

    /// Add a separator.
    pub fn separator(mut self) -> Self {
        self.menu.add_separator();
        self
    }

    /// Build the menu.
    pub fn build(self) -> PopupMenu {
        self.menu
    }
}

/// Trait for components that provide context menus.
pub trait PopupMenuProvider: Send + Sync {
    /// Build a popup menu for a vertex.
    fn vertex_popup(&self, vertex_id: &str) -> PopupMenu;

    /// Build a popup menu for an edge.
    fn edge_popup(&self, edge_id: &str) -> PopupMenu;

    /// Build a popup menu for the graph background.
    fn background_popup(&self) -> PopupMenu;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn popup_menu_item_creation() {
        let item = PopupMenuItem::new("Copy", "copy");
        assert_eq!(item.label, "Copy");
        assert_eq!(item.action_id, "copy");
        assert!(item.enabled);
        assert!(!item.is_separator);
    }

    #[test]
    fn separator_item() {
        let sep = PopupMenuItem::separator();
        assert!(sep.is_separator);
        assert!(!sep.enabled);
    }

    #[test]
    fn popup_menu_builder() {
        let menu = PopupMenuBuilder::new()
            .item("Copy", "copy")
            .item("Paste", "paste")
            .separator()
            .disabled_item("Delete", "delete")
            .build();

        assert_eq!(menu.len(), 4);
        assert_eq!(menu.items()[0].label, "Copy");
        assert!(menu.items()[0].enabled);
        assert!(menu.items()[2].is_separator);
        assert!(!menu.items()[3].enabled);
    }

    #[test]
    fn find_item_by_action_id() {
        let menu = PopupMenuBuilder::new()
            .item("Copy", "copy")
            .item("Paste", "paste")
            .build();

        assert!(menu.find_item("copy").is_some());
        assert!(menu.find_item("nonexistent").is_none());
    }

    #[test]
    fn empty_menu() {
        let menu = PopupMenu::new();
        assert!(menu.is_empty());
        assert_eq!(menu.len(), 0);
    }
}
