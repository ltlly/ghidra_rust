//! Popup/context menu support for graph viewers.
//!
//! Ports `ghidra.graph.viewer.popup` package.
//!
//! Includes:
//! - [`PopupMenu`] / [`PopupMenuBuilder`]: context menu construction.
//! - [`PopupRegulator`]: manages popup show/hide delays and target tracking.

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

// ============================================================================
// PopupRegulator (port of ghidra.graph.viewer.popup.PopupRegulator)
// ============================================================================

/// A target for a popup (a vertex or an edge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PopupTarget {
    /// A vertex popup target.
    Vertex(String),
    /// An edge popup target.
    Edge(String),
}

/// Controls popup display for graph clients.
///
/// Manages popup show/hide delays, target tracking (prevents showing
/// the same popup twice while hovering over a single element), and
/// show/hide lifecycle.
///
/// Ported from `ghidra.graph.viewer.popup.PopupRegulator<V, E>`.
#[derive(Debug)]
pub struct PopupRegulator {
    /// Delay in milliseconds before showing a popup.
    pub popup_delay_ms: u32,
    /// The current popup target (the element the mouse is over).
    next_popup_target: Option<PopupTarget>,
    /// The target for which a popup is currently shown.
    last_shown_target: Option<PopupTarget>,
    /// Whether popups are enabled.
    show_popups: bool,
    /// Whether a popup is currently visible.
    popup_visible: bool,
    /// Time when the mouse entered the current target (in milliseconds).
    hover_start_time_ms: u64,
}

impl PopupRegulator {
    /// Create a new popup regulator with default settings.
    pub fn new() -> Self {
        Self {
            popup_delay_ms: 1000,
            next_popup_target: None,
            last_shown_target: None,
            show_popups: true,
            popup_visible: false,
            hover_start_time_ms: 0,
        }
    }

    /// Enable or disable popup display.
    pub fn set_show_popups(&mut self, show: bool) {
        self.show_popups = show;
        if !show {
            self.dismiss_popup();
        }
    }

    /// Whether popups are enabled.
    pub fn show_popups(&self) -> bool {
        self.show_popups
    }

    /// Called when the mouse moves over a graph element.
    ///
    /// Updates the next popup target and records the hover start time.
    /// Returns `true` if the target changed.
    pub fn mouse_entered_target(&mut self, target: PopupTarget, current_time_ms: u64) -> bool {
        let changed = self.next_popup_target.as_ref() != Some(&target);
        if changed {
            self.next_popup_target = Some(target);
            self.hover_start_time_ms = current_time_ms;
            self.popup_visible = false;
        }
        changed
    }

    /// Called when the mouse leaves all graph elements.
    pub fn mouse_left_target(&mut self) {
        self.next_popup_target = None;
        self.dismiss_popup();
    }

    /// Check if enough time has elapsed to show a popup.
    ///
    /// Returns `true` if the popup delay has been exceeded and a popup
    /// should be shown.
    pub fn should_show_popup(&self, current_time_ms: u64) -> bool {
        if !self.show_popups || self.popup_visible {
            return false;
        }
        if self.next_popup_target.is_none() {
            return false;
        }
        // Don't re-show for the same target that's already been shown.
        if self.next_popup_target == self.last_shown_target {
            return false;
        }
        current_time_ms.saturating_sub(self.hover_start_time_ms) >= self.popup_delay_ms as u64
    }

    /// Mark a popup as shown for the current target.
    pub fn mark_popup_shown(&mut self) {
        self.last_shown_target = self.next_popup_target.clone();
        self.popup_visible = true;
    }

    /// Dismiss the current popup.
    pub fn dismiss_popup(&mut self) {
        self.popup_visible = false;
        self.last_shown_target = None;
    }

    /// Get the current popup target (if any).
    pub fn current_target(&self) -> Option<&PopupTarget> {
        self.next_popup_target.as_ref()
    }

    /// Whether a popup is currently visible.
    pub fn is_popup_visible(&self) -> bool {
        self.popup_visible
    }
}

impl Default for PopupRegulator {
    fn default() -> Self {
        Self::new()
    }
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

    #[test]
    fn popup_regulator_new() {
        let reg = PopupRegulator::new();
        assert!(reg.show_popups());
        assert!(!reg.is_popup_visible());
        assert!(reg.current_target().is_none());
    }

    #[test]
    fn popup_regulator_delay() {
        let mut reg = PopupRegulator::new();
        reg.popup_delay_ms = 500;
        reg.mouse_entered_target(PopupTarget::Vertex("v1".into()), 1000);
        // Before delay
        assert!(!reg.should_show_popup(1200));
        // After delay
        assert!(reg.should_show_popup(1501));
    }

    #[test]
    fn popup_regulator_no_repeat() {
        let mut reg = PopupRegulator::new();
        reg.popup_delay_ms = 0;
        reg.mouse_entered_target(PopupTarget::Vertex("v1".into()), 0);
        assert!(reg.should_show_popup(0));
        reg.mark_popup_shown();
        // Should not re-show for the same target.
        assert!(!reg.should_show_popup(1000));
    }

    #[test]
    fn popup_regulator_target_change() {
        let mut reg = PopupRegulator::new();
        reg.popup_delay_ms = 0;
        reg.mouse_entered_target(PopupTarget::Vertex("v1".into()), 0);
        reg.mark_popup_shown();
        // Change target to v2.
        reg.mouse_entered_target(PopupTarget::Vertex("v2".into()), 100);
        assert!(reg.should_show_popup(100));
    }

    #[test]
    fn popup_regulator_leave_target() {
        let mut reg = PopupRegulator::new();
        reg.popup_delay_ms = 0;
        reg.mouse_entered_target(PopupTarget::Vertex("v1".into()), 0);
        reg.mark_popup_shown();
        reg.mouse_left_target();
        assert!(!reg.is_popup_visible());
        assert!(reg.current_target().is_none());
    }

    #[test]
    fn popup_regulator_disabled() {
        let mut reg = PopupRegulator::new();
        reg.set_show_popups(false);
        reg.popup_delay_ms = 0;
        reg.mouse_entered_target(PopupTarget::Vertex("v1".into()), 0);
        assert!(!reg.should_show_popup(0));
        assert!(!reg.is_popup_visible());
    }

    #[test]
    fn popup_target_equality() {
        assert_eq!(
            PopupTarget::Vertex("v1".into()),
            PopupTarget::Vertex("v1".into())
        );
        assert_ne!(
            PopupTarget::Vertex("v1".into()),
            PopupTarget::Edge("e1".into())
        );
    }
}
