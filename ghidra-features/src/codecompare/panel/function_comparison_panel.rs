//! Function comparison panel for managing multiple comparison views.
//!
//! Ported from Ghidra's `FunctionComparisonPanel` Java class in
//! `ghidra.features.base.codecompare.panel`.
//!
//! The FunctionComparisonPanel is the top-level container that manages
//! multiple code comparison views (Listing, Decompiler, FunctionGraph)
//! as tabs. It handles tab switching, scroll synchronization, state
//! persistence, and comparison data lifecycle.
//!
//! In the original Java, the panel uses a `JTabbedPane` and discovers
//! views via `ClassSearcher`. In this Rust port, we capture the logical
//! state and behavior without the Swing layer.
//!
//! # Key types
//!
//! - [`TabInfo`] -- information about a comparison view tab
//! - [`FunctionComparisonPanelState`] -- the full state of the panel
//! - [`PanelEvent`] -- events emitted by the panel

use std::collections::HashMap;

use super::{
    AddressSet, ComparisonData, ComparisonPanelState, ComparisonViewState, EmptyComparisonData,
    FunctionComparisonData, FunctionComparisonInfo, ProgramInfo,
};
use crate::codecompare::model::ComparisonSide;

/// Information about a comparison view tab.
#[derive(Debug, Clone)]
pub struct TabInfo {
    /// The display name of this tab (e.g., "Listing View", "Decompiler View").
    pub name: String,
    /// The sort order for this tab.
    pub sort_order: usize,
    /// Whether this tab is currently selected.
    pub selected: bool,
    /// Per-tab save state.
    pub save_state: ComparisonViewState,
    /// Whether this tab's view is side-by-side (vs. stacked).
    pub side_by_side: bool,
}

impl TabInfo {
    /// Create a new tab info.
    pub fn new(name: impl Into<String>, sort_order: usize) -> Self {
        Self {
            name: name.into(),
            sort_order,
            selected: false,
            save_state: ComparisonViewState::new(),
            side_by_side: true,
        }
    }
}

/// Events emitted by the function comparison panel.
#[derive(Debug, Clone)]
pub enum PanelEvent {
    /// The active tab changed.
    TabChanged {
        /// The name of the newly active tab.
        new_tab: String,
        /// The name of the previously active tab (if any).
        old_tab: Option<String>,
    },
    /// The comparison data was loaded.
    DataLoaded {
        /// Whether the left side has data.
        has_left: bool,
        /// Whether the right side has data.
        has_right: bool,
    },
    /// The comparison data was cleared.
    DataCleared,
    /// The scroll synchronization state changed.
    ScrollSyncChanged {
        /// Whether scrolling is now synchronized.
        synchronized: bool,
    },
    /// The panel was disposed.
    Disposed,
}

/// Trait for receiving panel events.
pub trait PanelEventListener: Send + Sync {
    /// Called when a panel event occurs.
    fn on_event(&self, event: &PanelEvent);
}

/// The full state of a function comparison panel.
///
/// Ported from Ghidra's `FunctionComparisonPanel` Java class.
///
/// Manages multiple comparison view tabs, comparison data, scroll
/// synchronization, and state persistence.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::panel::function_comparison_panel::*;
/// use ghidra_features::codecompare::panel::*;
/// use ghidra_features::codecompare::model::ComparisonSide;
///
/// let mut panel = FunctionComparisonPanelState::new("MyPlugin");
///
/// // Register views
/// panel.register_view("Listing View", 0);
/// panel.register_view("Decompiler View", 1);
///
/// // Set active view
/// panel.set_active_view("Listing View");
/// assert_eq!(panel.active_view_name(), Some("Listing View"));
///
/// // Load comparison data
/// let prog = ProgramInfo::new(1, "/project/test", "test");
/// let left = FunctionComparisonInfo::new("main", 0x1000, 0x1000, 0x10ff, prog.clone());
/// let right = FunctionComparisonInfo::new("init", 0x2000, 0x2000, 0x20ff, prog);
/// panel.load_functions(left, right);
/// assert!(!panel.is_empty());
/// ```
pub struct FunctionComparisonPanelState {
    /// The owner (plugin) name.
    owner: String,
    /// Registered view tabs, keyed by name.
    tabs: HashMap<String, TabInfo>,
    /// Ordered tab names (for consistent tab ordering).
    tab_order: Vec<String>,
    /// The name of the currently active tab.
    active_tab: Option<String>,
    /// Whether scroll synchronization is enabled.
    scroll_sync: bool,
    /// The comparison data for the left side.
    left_data: Box<dyn ComparisonData>,
    /// The comparison data for the right side.
    right_data: Box<dyn ComparisonData>,
    /// The top-level panel save state.
    panel_state: ComparisonPanelState,
    /// Listeners for panel events.
    listeners: Vec<Box<dyn PanelEventListener>>,
}

impl std::fmt::Debug for FunctionComparisonPanelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionComparisonPanelState")
            .field("owner", &self.owner)
            .field("tabs", &self.tabs)
            .field("active_tab", &self.active_tab)
            .field("scroll_sync", &self.scroll_sync)
            .finish()
    }
}

impl FunctionComparisonPanelState {
    /// Create a new function comparison panel state.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            tabs: HashMap::new(),
            tab_order: Vec::new(),
            active_tab: None,
            scroll_sync: true,
            left_data: Box::new(EmptyComparisonData::new()),
            right_data: Box::new(EmptyComparisonData::new()),
            panel_state: ComparisonPanelState::new(),
            listeners: Vec::new(),
        }
    }

    /// Get the owner name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Register a comparison view as a tab.
    pub fn register_view(&mut self, name: impl Into<String>, sort_order: usize) {
        let name = name.into();
        if !self.tabs.contains_key(&name) {
            self.tab_order.push(name.clone());
            self.tabs.insert(name.clone(), TabInfo::new(&name, sort_order));
            // Re-sort tab order
            self.tab_order.sort_by(|a, b| {
                let order_a = self.tabs.get(a).map(|t| t.sort_order).unwrap_or(0);
                let order_b = self.tabs.get(b).map(|t| t.sort_order).unwrap_or(0);
                order_a.cmp(&order_b)
            });
        }
    }

    /// Get the number of registered tabs.
    pub fn tab_count(&self) -> usize {
        self.tabs.len()
    }

    /// Get the ordered list of tab names.
    pub fn tab_names(&self) -> &[String] {
        &self.tab_order
    }

    /// Get information about a specific tab.
    pub fn tab_info(&self, name: &str) -> Option<&TabInfo> {
        self.tabs.get(name)
    }

    /// Get a mutable reference to a specific tab's info.
    pub fn tab_info_mut(&mut self, name: &str) -> Option<&mut TabInfo> {
        self.tabs.get_mut(name)
    }

    /// Set the active view tab by name.
    ///
    /// Returns true if the tab was found and activated.
    pub fn set_active_view(&mut self, name: &str) -> bool {
        if !self.tabs.contains_key(name) {
            return false;
        }

        let old_tab = self.active_tab.clone();

        // Deselect the old tab
        if let Some(ref old) = old_tab {
            if let Some(tab) = self.tabs.get_mut(old) {
                tab.selected = false;
            }
        }

        // Select the new tab
        if let Some(tab) = self.tabs.get_mut(name) {
            tab.selected = true;
        }
        self.active_tab = Some(name.to_string());

        self.fire_event(PanelEvent::TabChanged {
            new_tab: name.to_string(),
            old_tab,
        });

        true
    }

    /// Get the name of the currently active tab.
    pub fn active_view_name(&self) -> Option<&str> {
        self.active_tab.as_deref()
    }

    /// Get the index of the currently active tab.
    pub fn active_tab_index(&self) -> Option<usize> {
        self.active_tab
            .as_ref()
            .and_then(|name| self.tab_order.iter().position(|n| n == name))
    }

    /// Load comparison data for both sides using function info.
    pub fn load_functions(
        &mut self,
        left: FunctionComparisonInfo,
        right: FunctionComparisonInfo,
    ) {
        self.left_data = Box::new(FunctionComparisonData::new(left));
        self.right_data = Box::new(FunctionComparisonData::new(right));
        self.notify_active_view_data_changed();
        self.fire_event(PanelEvent::DataLoaded {
            has_left: true,
            has_right: true,
        });
    }

    /// Load comparison data for both sides.
    pub fn load_comparisons(
        &mut self,
        left: Box<dyn ComparisonData>,
        right: Box<dyn ComparisonData>,
    ) {
        let has_left = !left.is_empty();
        let has_right = !right.is_empty();
        self.left_data = left;
        self.right_data = right;
        self.notify_active_view_data_changed();
        self.fire_event(PanelEvent::DataLoaded { has_left, has_right });
    }

    /// Clear the comparison data.
    pub fn clear(&mut self) {
        self.left_data = Box::new(EmptyComparisonData::new());
        self.right_data = Box::new(EmptyComparisonData::new());
        self.fire_event(PanelEvent::DataCleared);
    }

    /// Check if the panel has no comparison data.
    pub fn is_empty(&self) -> bool {
        self.left_data.is_empty() || self.right_data.is_empty()
    }

    /// Get the comparison data for the given side.
    pub fn get_data(&self, side: ComparisonSide) -> &dyn ComparisonData {
        match side {
            ComparisonSide::Left => self.left_data.as_ref(),
            ComparisonSide::Right => self.right_data.as_ref(),
        }
    }

    /// Get a description of the current comparison.
    pub fn description(&self) -> String {
        let left = self.left_data.get_short_description();
        let right = self.right_data.get_short_description();
        format!("{} & {}", left, right)
    }

    /// Get the scroll synchronization state.
    pub fn is_scroll_sync(&self) -> bool {
        self.scroll_sync
    }

    /// Set the scroll synchronization state.
    pub fn set_scroll_sync(&mut self, sync: bool) {
        if self.scroll_sync == sync {
            return;
        }
        self.scroll_sync = sync;
        self.fire_event(PanelEvent::ScrollSyncChanged {
            synchronized: sync,
        });
    }

    /// Toggle the scroll synchronization state.
    pub fn toggle_scroll_sync(&mut self) {
        self.set_scroll_sync(!self.scroll_sync);
    }

    /// Get the panel save state.
    pub fn panel_state(&self) -> &ComparisonPanelState {
        &self.panel_state
    }

    /// Get a mutable reference to the panel save state.
    pub fn panel_state_mut(&mut self) -> &mut ComparisonPanelState {
        &mut self.panel_state
    }

    /// Add a listener for panel events.
    pub fn add_listener(&mut self, listener: Box<dyn PanelEventListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Fire an event to all listeners.
    fn fire_event(&self, event: PanelEvent) {
        for listener in &self.listeners {
            listener.on_event(&event);
        }
    }

    /// Notify the active view that comparison data changed.
    fn notify_active_view_data_changed(&self) {
        // In the full implementation, this would call
        // activeView.loadComparisons(left, right)
        // Here we just track the state.
    }

    /// Get the title prefixes for the given side across all views.
    pub fn set_title_prefixes(
        &mut self,
        left_prefix: impl Into<String>,
        right_prefix: impl Into<String>,
    ) {
        let left = left_prefix.into();
        let right = right_prefix.into();
        self.panel_state
            .panel_state
            .set_string("left_title_prefix", &left);
        self.panel_state
            .panel_state
            .set_string("right_title_prefix", &right);
    }

    /// Check if the panel is disposed (always false in this implementation).
    pub fn is_disposed(&self) -> bool {
        false
    }

    /// Dispose of the panel.
    pub fn dispose(&mut self) {
        self.tabs.clear();
        self.tab_order.clear();
        self.active_tab = None;
        self.left_data = Box::new(EmptyComparisonData::new());
        self.right_data = Box::new(EmptyComparisonData::new());
        self.fire_event(PanelEvent::Disposed);
        self.listeners.clear();
    }

    /// Save the current state to the panel state.
    pub fn save_state(&mut self) {
        if let Some(ref active) = self.active_tab {
            self.panel_state.active_view = active.clone();
        }
        self.panel_state.scroll_sync = self.scroll_sync;

        for (name, tab) in &self.tabs {
            self.panel_state
                .orientations
                .insert(name.clone(), tab.side_by_side);
        }
    }

    /// Restore state from the panel state.
    pub fn restore_state(&mut self) {
        let active = self.panel_state.active_view.clone();
        if !active.is_empty() {
            self.set_active_view(&active);
        }
        self.scroll_sync = self.panel_state.scroll_sync;

        for (name, &side_by_side) in &self.panel_state.orientations {
            if let Some(tab) = self.tabs.get_mut(name) {
                tab.side_by_side = side_by_side;
            }
        }
    }
}

/// A simple listener that tracks panel events.
#[derive(Debug, Default)]
pub struct TrackingPanelListener {
    /// Recorded events.
    pub events: std::sync::Mutex<Vec<PanelEvent>>,
}

impl TrackingPanelListener {
    /// Create a new tracking listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of events received.
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl PanelEventListener for TrackingPanelListener {
    fn on_event(&self, event: &PanelEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

impl PanelEventListener for std::sync::Arc<TrackingPanelListener> {
    fn on_event(&self, event: &PanelEvent) {
        (**self).on_event(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_program(id: u64, path: &str, name: &str) -> ProgramInfo {
        ProgramInfo::new(id, path, name)
    }

    fn make_func_info(
        name: &str,
        entry: u64,
        prog: ProgramInfo,
    ) -> FunctionComparisonInfo {
        FunctionComparisonInfo::new(name, entry, entry, entry + 0x100, prog)
    }

    // --- TabInfo tests ---

    #[test]
    fn test_tab_info_new() {
        let tab = TabInfo::new("Listing View", 0);
        assert_eq!(tab.name, "Listing View");
        assert_eq!(tab.sort_order, 0);
        assert!(!tab.selected);
        assert!(tab.side_by_side);
    }

    // --- FunctionComparisonPanelState tests ---

    #[test]
    fn test_panel_new() {
        let panel = FunctionComparisonPanelState::new("TestPlugin");
        assert_eq!(panel.owner(), "TestPlugin");
        assert_eq!(panel.tab_count(), 0);
        assert!(panel.active_view_name().is_none());
        assert!(panel.is_scroll_sync());
        assert!(panel.is_empty());
    }

    #[test]
    fn test_panel_register_view() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        panel.register_view("Listing View", 0);
        panel.register_view("Decompiler View", 1);

        assert_eq!(panel.tab_count(), 2);
        assert_eq!(panel.tab_names().len(), 2);
    }

    #[test]
    fn test_panel_register_view_ordering() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        panel.register_view("Z View", 2);
        panel.register_view("A View", 0);
        panel.register_view("M View", 1);

        let names = panel.tab_names();
        assert_eq!(names[0], "A View");
        assert_eq!(names[1], "M View");
        assert_eq!(names[2], "Z View");
    }

    #[test]
    fn test_panel_register_view_duplicate() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        panel.register_view("Listing View", 0);
        panel.register_view("Listing View", 1); // duplicate

        assert_eq!(panel.tab_count(), 1);
    }

    #[test]
    fn test_panel_set_active_view() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        panel.register_view("Listing View", 0);
        panel.register_view("Decompiler View", 1);

        assert!(panel.set_active_view("Listing View"));
        assert_eq!(panel.active_view_name(), Some("Listing View"));
        assert_eq!(panel.active_tab_index(), Some(0));
    }

    #[test]
    fn test_panel_set_active_view_not_found() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        panel.register_view("Listing View", 0);

        assert!(!panel.set_active_view("Nonexistent View"));
        assert!(panel.active_view_name().is_none());
    }

    #[test]
    fn test_panel_set_active_view_switch() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        panel.register_view("Listing View", 0);
        panel.register_view("Decompiler View", 1);

        panel.set_active_view("Listing View");
        assert_eq!(panel.active_view_name(), Some("Listing View"));

        panel.set_active_view("Decompiler View");
        assert_eq!(panel.active_view_name(), Some("Decompiler View"));

        // Listing View should be deselected
        assert!(!panel.tab_info("Listing View").unwrap().selected);
        assert!(panel.tab_info("Decompiler View").unwrap().selected);
    }

    #[test]
    fn test_panel_load_functions() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        let prog = make_program(1, "/project/test", "test");
        let left = make_func_info("main", 0x1000, prog.clone());
        let right = make_func_info("init", 0x2000, prog);

        panel.load_functions(left, right);
        assert!(!panel.is_empty());
        assert_eq!(panel.description(), "main & init");
    }

    #[test]
    fn test_panel_load_comparisons() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        let prog = make_program(1, "/project/test", "test");
        let left = make_func_info("main", 0x1000, prog.clone());
        let right = make_func_info("init", 0x2000, prog);

        panel.load_comparisons(
            Box::new(FunctionComparisonData::new(left)),
            Box::new(FunctionComparisonData::new(right)),
        );
        assert!(!panel.is_empty());
    }

    #[test]
    fn test_panel_clear() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        let prog = make_program(1, "/project/test", "test");
        let left = make_func_info("main", 0x1000, prog.clone());
        let right = make_func_info("init", 0x2000, prog);

        panel.load_functions(left, right);
        assert!(!panel.is_empty());

        panel.clear();
        assert!(panel.is_empty());
    }

    #[test]
    fn test_panel_get_data() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        let prog = make_program(1, "/project/test", "test");
        let left = make_func_info("main", 0x1000, prog.clone());
        let right = make_func_info("init", 0x2000, prog);

        panel.load_functions(left, right);

        let left_data = panel.get_data(ComparisonSide::Left);
        assert_eq!(left_data.get_short_description(), "main");

        let right_data = panel.get_data(ComparisonSide::Right);
        assert_eq!(right_data.get_short_description(), "init");
    }

    #[test]
    fn test_panel_scroll_sync() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        assert!(panel.is_scroll_sync());

        panel.set_scroll_sync(false);
        assert!(!panel.is_scroll_sync());

        panel.toggle_scroll_sync();
        assert!(panel.is_scroll_sync());
    }

    #[test]
    fn test_panel_scroll_sync_no_change() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        panel.set_scroll_sync(true); // already true, no event
        assert!(panel.is_scroll_sync());
    }

    #[test]
    fn test_panel_tab_info() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        panel.register_view("Listing View", 0);

        let info = panel.tab_info("Listing View");
        assert!(info.is_some());
        assert_eq!(info.unwrap().name, "Listing View");

        assert!(panel.tab_info("Nonexistent").is_none());
    }

    #[test]
    fn test_panel_tab_info_mut() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        panel.register_view("Listing View", 0);

        if let Some(tab) = panel.tab_info_mut("Listing View") {
            tab.side_by_side = false;
        }

        assert!(!panel.tab_info("Listing View").unwrap().side_by_side);
    }

    #[test]
    fn test_panel_save_restore_state() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        panel.register_view("Listing View", 0);
        panel.register_view("Decompiler View", 1);

        panel.set_active_view("Decompiler View");
        panel.set_scroll_sync(false);

        panel.save_state();

        // Create a new panel and restore
        let mut panel2 = FunctionComparisonPanelState::new("Test");
        panel2.register_view("Listing View", 0);
        panel2.register_view("Decompiler View", 1);
        panel2.panel_state = panel.panel_state.clone();
        panel2.restore_state();

        assert_eq!(panel2.active_view_name(), Some("Decompiler View"));
        assert!(!panel2.is_scroll_sync());
    }

    #[test]
    fn test_panel_dispose() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        panel.register_view("Listing View", 0);
        let prog = make_program(1, "/project/test", "test");
        let left = make_func_info("main", 0x1000, prog.clone());
        let right = make_func_info("init", 0x2000, prog);
        panel.load_functions(left, right);

        panel.dispose();
        assert_eq!(panel.tab_count(), 0);
        assert!(panel.active_view_name().is_none());
        assert!(panel.is_empty());
    }

    #[test]
    fn test_panel_set_title_prefixes() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        panel.set_title_prefixes("Source:", "Target:");

        let left_prefix = panel
            .panel_state()
            .panel_state
            .get_string("left_title_prefix", "");
        assert_eq!(left_prefix, "Source:");
    }

    // --- PanelEvent tests ---

    #[test]
    fn test_panel_listener_tab_changed() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        let listener = Arc::new(TrackingPanelListener::new());
        panel.add_listener(Box::new(listener.clone()));

        panel.register_view("Listing View", 0);
        panel.register_view("Decompiler View", 1);
        panel.set_active_view("Listing View");
        panel.set_active_view("Decompiler View");

        let events = listener.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0],
            PanelEvent::TabChanged {
                new_tab: ref n,
                ..
            } if n == "Listing View"
        ));
        assert!(matches!(
            events[1],
            PanelEvent::TabChanged {
                new_tab: ref n,
                ..
            } if n == "Decompiler View"
        ));
    }

    #[test]
    fn test_panel_listener_data_loaded() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        let listener = Arc::new(TrackingPanelListener::new());
        panel.add_listener(Box::new(listener.clone()));

        let prog = make_program(1, "/project/test", "test");
        let left = make_func_info("main", 0x1000, prog.clone());
        let right = make_func_info("init", 0x2000, prog);
        panel.load_functions(left, right);

        let events = listener.events.lock().unwrap();
        assert!(events
            .iter()
            .any(|e| matches!(e, PanelEvent::DataLoaded { .. })));
    }

    #[test]
    fn test_panel_listener_data_cleared() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        let listener = Arc::new(TrackingPanelListener::new());
        panel.add_listener(Box::new(listener.clone()));

        panel.clear();

        let events = listener.events.lock().unwrap();
        assert!(events
            .iter()
            .any(|e| matches!(e, PanelEvent::DataCleared)));
    }

    #[test]
    fn test_panel_listener_scroll_sync() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        let listener = Arc::new(TrackingPanelListener::new());
        panel.add_listener(Box::new(listener.clone()));

        panel.set_scroll_sync(false);

        let events = listener.events.lock().unwrap();
        assert!(events.iter().any(|e| matches!(
            e,
            PanelEvent::ScrollSyncChanged {
                synchronized: false
            }
        )));
    }

    #[test]
    fn test_panel_listener_disposed() {
        let mut panel = FunctionComparisonPanelState::new("Test");
        let listener = Arc::new(TrackingPanelListener::new());
        panel.add_listener(Box::new(listener.clone()));

        panel.dispose();

        let events = listener.events.lock().unwrap();
        assert!(events
            .iter()
            .any(|e| matches!(e, PanelEvent::Disposed)));
    }

    // --- TrackingPanelListener tests ---

    #[test]
    fn test_tracking_listener_new() {
        let listener = TrackingPanelListener::new();
        assert_eq!(listener.event_count(), 0);
    }

    #[test]
    fn test_tracking_listener_tracks_events() {
        let listener = TrackingPanelListener::new();
        listener.on_event(&PanelEvent::DataCleared);
        listener.on_event(&PanelEvent::Disposed);
        assert_eq!(listener.event_count(), 2);
    }
}
