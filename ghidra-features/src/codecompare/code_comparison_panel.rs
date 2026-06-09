//! Code comparison panel integration layer.
//!
//! Ported from Ghidra's `CodeComparisonPanel` Java class in
//! `ghidra.features.base.codecompare.panel`.
//!
//! This module provides a top-level panel that integrates the
//! [`FunctionComparisonPanelState`] with a set of registered
//! [`CodeComparisonView`] instances. It orchestrates tab switching,
//! comparison data loading, scroll synchronization, and view lifecycle
//! management.
//!
//! While [`panel::function_comparison_panel`] manages the logical tab state,
//! this module adds the bridge logic that connects tab changes to actual
//! view activation and data propagation.
//!
//! # Key types
//!
//! - [`CodeComparisonPanel`] -- the integration layer connecting panel state to views
//! - [`ViewDescriptor`] -- metadata about a registered comparison view
//! - [`ComparisonPanelConfig`] -- configuration options for the panel

use super::panel::code_comparison_view::{CodeComparisonView, CodeComparisonViewState, ViewOrientation};
use super::panel::function_comparison_panel::{
    FunctionComparisonPanelState, PanelEvent, PanelEventListener, TabInfo, TrackingPanelListener,
};
use super::panel::{
    AddressSet, ComparisonData, ComparisonPanelState, ComparisonViewState, EmptyComparisonData,
    FunctionComparisonData, FunctionComparisonInfo, ProgramInfo,
};
use super::model::ComparisonSide;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Metadata about a registered comparison view.
///
/// Describes a view type that can be displayed as a tab in the panel.
#[derive(Debug, Clone)]
pub struct ViewDescriptor {
    /// The display name for the tab (e.g., "Listing View").
    pub name: String,
    /// The sort order (lower values appear first).
    pub sort_order: usize,
    /// A short description shown in tooltips.
    pub description: String,
    /// Whether this view supports cross-architecture comparison.
    pub supports_cross_arch: bool,
}

impl ViewDescriptor {
    /// Create a new view descriptor.
    pub fn new(
        name: impl Into<String>,
        sort_order: usize,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            sort_order,
            description: description.into(),
            supports_cross_arch: false,
        }
    }

    /// Mark this view as supporting cross-architecture comparison.
    pub fn with_cross_arch_support(mut self) -> Self {
        self.supports_cross_arch = true;
        self
    }
}

/// Configuration options for the code comparison panel.
#[derive(Debug, Clone)]
pub struct ComparisonPanelConfig {
    /// Whether to automatically synchronize scrolling when switching views.
    pub auto_scroll_sync: bool,
    /// Default orientation for new views.
    pub default_orientation: ViewOrientation,
    /// Whether to show view titles above each side.
    pub show_titles: bool,
    /// Whether to persist panel state across sessions.
    pub persist_state: bool,
    /// Maximum number of views to keep alive (cached) when not active.
    pub max_cached_views: usize,
}

impl ComparisonPanelConfig {
    /// Create a configuration with default values.
    pub fn new() -> Self {
        Self {
            auto_scroll_sync: true,
            default_orientation: ViewOrientation::SideBySide,
            show_titles: true,
            persist_state: true,
            max_cached_views: 3,
        }
    }

    /// Enable or disable automatic scroll synchronization.
    pub fn with_auto_scroll_sync(mut self, enabled: bool) -> Self {
        self.auto_scroll_sync = enabled;
        self
    }

    /// Set the default orientation.
    pub fn with_default_orientation(mut self, orientation: ViewOrientation) -> Self {
        self.default_orientation = orientation;
        self
    }

    /// Set whether to show titles.
    pub fn with_show_titles(mut self, show: bool) -> Self {
        self.show_titles = show;
        self
    }
}

impl Default for ComparisonPanelConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Events emitted by the code comparison panel.
#[derive(Debug, Clone)]
pub enum CodeComparisonPanelEvent {
    /// The active view changed.
    ViewChanged {
        /// Name of the new active view.
        new_view: String,
        /// Name of the previous active view, if any.
        old_view: Option<String>,
    },
    /// Comparison data was loaded into the panel.
    DataLoaded {
        /// Short description of the left side.
        left_desc: String,
        /// Short description of the right side.
        right_desc: String,
    },
    /// Comparison data was cleared.
    DataCleared,
    /// Scroll synchronization toggled.
    ScrollSyncToggled {
        /// Whether scrolling is now synchronized.
        enabled: bool,
    },
    /// The panel orientation changed.
    OrientationChanged {
        /// The new orientation.
        orientation: ViewOrientation,
    },
    /// The panel was disposed.
    Disposed,
}

/// Trait for receiving code comparison panel events.
pub trait CodeComparisonPanelListener: Send + Sync {
    /// Called when a panel event occurs.
    fn on_event(&self, event: &CodeComparisonPanelEvent);
}

/// The integration layer connecting panel state to comparison views.
///
/// `CodeComparisonPanel` coordinates between the logical [`FunctionComparisonPanelState`]
/// (which manages tabs and data) and registered comparison views. When the user
/// switches tabs, the panel activates the corresponding view and propagates
/// comparison data. When data changes, all views are notified.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::code_comparison_panel::*;
/// use ghidra_features::codecompare::panel::*;
///
/// let mut panel = CodeComparisonPanel::new("MyPlugin", ComparisonPanelConfig::default());
///
/// // Register views
/// panel.register_view(ViewDescriptor::new("Listing View", 0, "Disassembly listing comparison"));
/// panel.register_view(ViewDescriptor::new("Decompiler View", 1, "Decompiler output comparison"));
///
/// // Load comparison data
/// let prog = ProgramInfo::new(1, "/project/test", "test");
/// let left = FunctionComparisonInfo::new("main", 0x1000, 0x1000, 0x10ff, prog.clone());
/// let right = FunctionComparisonInfo::new("init", 0x2000, 0x2000, 0x20ff, prog);
/// panel.load_functions(left, right);
///
/// assert!(!panel.is_empty());
/// assert_eq!(panel.active_view_name(), Some("Listing View"));
/// ```
pub struct CodeComparisonPanel {
    /// Owner (plugin) identifier.
    owner: String,
    /// Configuration.
    config: ComparisonPanelConfig,
    /// The underlying panel state manager.
    panel_state: FunctionComparisonPanelState,
    /// Registered view descriptors, keyed by name.
    view_descriptors: HashMap<String, ViewDescriptor>,
    /// Listeners for panel events.
    listeners: Vec<Box<dyn CodeComparisonPanelListener>>,
}

impl std::fmt::Debug for CodeComparisonPanel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeComparisonPanel")
            .field("owner", &self.owner)
            .field("config", &self.config)
            .field("view_count", &self.view_descriptors.len())
            .field("active_view", &self.panel_state.active_view_name())
            .finish()
    }
}

impl CodeComparisonPanel {
    /// Create a new code comparison panel.
    pub fn new(owner: impl Into<String>, config: ComparisonPanelConfig) -> Self {
        let owner = owner.into();
        Self {
            panel_state: FunctionComparisonPanelState::new(&owner),
            view_descriptors: HashMap::new(),
            listeners: Vec::new(),
            owner,
            config,
        }
    }

    /// Get the owner identifier.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the configuration.
    pub fn config(&self) -> &ComparisonPanelConfig {
        &self.config
    }

    /// Get a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut ComparisonPanelConfig {
        &mut self.config
    }

    /// Register a comparison view with the panel.
    ///
    /// Creates a tab for the view. The view descriptor provides metadata
    /// about the view's capabilities.
    pub fn register_view(&mut self, descriptor: ViewDescriptor) {
        let name = descriptor.name.clone();
        let sort_order = descriptor.sort_order;
        self.panel_state.register_view(&name, sort_order);
        self.view_descriptors.insert(name, descriptor);
    }

    /// Get the number of registered views.
    pub fn view_count(&self) -> usize {
        self.view_descriptors.len()
    }

    /// Get the descriptor for a view by name.
    pub fn view_descriptor(&self, name: &str) -> Option<&ViewDescriptor> {
        self.view_descriptors.get(name)
    }

    /// Get all view names in tab order.
    pub fn view_names(&self) -> &[String] {
        self.panel_state.tab_names()
    }

    /// Set the active view by name.
    ///
    /// Returns true if the view was found and activated.
    pub fn set_active_view(&mut self, name: &str) -> bool {
        let old_view = self.panel_state.active_view_name().map(|s| s.to_string());
        if self.panel_state.set_active_view(name) {
            self.fire_event(CodeComparisonPanelEvent::ViewChanged {
                new_view: name.to_string(),
                old_view,
            });
            true
        } else {
            false
        }
    }

    /// Get the name of the currently active view.
    pub fn active_view_name(&self) -> Option<&str> {
        self.panel_state.active_view_name()
    }

    /// Load comparison data using function info objects.
    pub fn load_functions(
        &mut self,
        left: FunctionComparisonInfo,
        right: FunctionComparisonInfo,
    ) {
        let left_desc = left.display_name();
        let right_desc = right.display_name();
        self.panel_state.load_functions(left, right);
        self.fire_event(CodeComparisonPanelEvent::DataLoaded {
            left_desc,
            right_desc,
        });
    }

    /// Load comparison data using boxed comparison data objects.
    pub fn load_comparisons(
        &mut self,
        left: Box<dyn ComparisonData>,
        right: Box<dyn ComparisonData>,
    ) {
        let left_desc = left.get_short_description();
        let right_desc = right.get_short_description();
        self.panel_state.load_comparisons(left, right);
        self.fire_event(CodeComparisonPanelEvent::DataLoaded {
            left_desc,
            right_desc,
        });
    }

    /// Clear the comparison data.
    pub fn clear(&mut self) {
        self.panel_state.clear();
        self.fire_event(CodeComparisonPanelEvent::DataCleared);
    }

    /// Check if the panel has comparison data loaded.
    pub fn is_empty(&self) -> bool {
        self.panel_state.is_empty()
    }

    /// Get the comparison data for the given side.
    pub fn get_data(&self, side: ComparisonSide) -> &dyn ComparisonData {
        self.panel_state.get_data(side)
    }

    /// Check if scroll synchronization is enabled.
    pub fn is_scroll_sync(&self) -> bool {
        self.panel_state.is_scroll_sync()
    }

    /// Set the scroll synchronization state.
    pub fn set_scroll_sync(&mut self, enabled: bool) {
        self.panel_state.set_scroll_sync(enabled);
        self.fire_event(CodeComparisonPanelEvent::ScrollSyncToggled { enabled });
    }

    /// Toggle the scroll synchronization state.
    pub fn toggle_scroll_sync(&mut self) {
        let new_state = !self.panel_state.is_scroll_sync();
        self.set_scroll_sync(new_state);
    }

    /// Get the panel state for serialization.
    pub fn panel_state(&self) -> &ComparisonPanelState {
        self.panel_state.panel_state()
    }

    /// Save the current panel state for persistence.
    pub fn save_state(&mut self) {
        self.panel_state.save_state();
    }

    /// Restore the panel state from a previous save.
    pub fn restore_state(&mut self) {
        self.panel_state.restore_state();
    }

    /// Add a listener for panel events.
    pub fn add_listener(&mut self, listener: Box<dyn CodeComparisonPanelListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Dispose of the panel and all views.
    pub fn dispose(&mut self) {
        self.panel_state.dispose();
        self.fire_event(CodeComparisonPanelEvent::Disposed);
        self.listeners.clear();
    }

    /// Check if the panel is disposed.
    pub fn is_disposed(&self) -> bool {
        self.panel_state.is_disposed()
    }

    /// Get a description of the current comparison.
    pub fn description(&self) -> String {
        self.panel_state.description()
    }

    /// Fire an event to all listeners.
    fn fire_event(&self, event: CodeComparisonPanelEvent) {
        for listener in &self.listeners {
            listener.on_event(&event);
        }
    }
}

/// A simple listener that tracks panel events.
#[derive(Debug, Default)]
pub struct TrackingCodeComparisonPanelListener {
    /// Recorded events.
    pub events: std::sync::Mutex<Vec<CodeComparisonPanelEvent>>,
}

impl TrackingCodeComparisonPanelListener {
    /// Create a new tracking listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of events received.
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl CodeComparisonPanelListener for TrackingCodeComparisonPanelListener {
    fn on_event(&self, event: &CodeComparisonPanelEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

impl CodeComparisonPanelListener for Arc<TrackingCodeComparisonPanelListener> {
    fn on_event(&self, event: &CodeComparisonPanelEvent) {
        (**self).on_event(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // --- ViewDescriptor tests ---

    #[test]
    fn test_view_descriptor_new() {
        let desc = ViewDescriptor::new("Listing View", 0, "Disassembly listing");
        assert_eq!(desc.name, "Listing View");
        assert_eq!(desc.sort_order, 0);
        assert_eq!(desc.description, "Disassembly listing");
        assert!(!desc.supports_cross_arch);
    }

    #[test]
    fn test_view_descriptor_cross_arch() {
        let desc = ViewDescriptor::new("Decompiler View", 1, "Decompiler output")
            .with_cross_arch_support();
        assert!(desc.supports_cross_arch);
    }

    // --- ComparisonPanelConfig tests ---

    #[test]
    fn test_panel_config_defaults() {
        let config = ComparisonPanelConfig::new();
        assert!(config.auto_scroll_sync);
        assert_eq!(config.default_orientation, ViewOrientation::SideBySide);
        assert!(config.show_titles);
        assert!(config.persist_state);
        assert_eq!(config.max_cached_views, 3);
    }

    #[test]
    fn test_panel_config_builder() {
        let config = ComparisonPanelConfig::new()
            .with_auto_scroll_sync(false)
            .with_default_orientation(ViewOrientation::Stacked)
            .with_show_titles(false);
        assert!(!config.auto_scroll_sync);
        assert_eq!(config.default_orientation, ViewOrientation::Stacked);
        assert!(!config.show_titles);
    }

    // --- CodeComparisonPanel tests ---

    #[test]
    fn test_panel_new() {
        let panel = CodeComparisonPanel::new("TestPlugin", ComparisonPanelConfig::default());
        assert_eq!(panel.owner(), "TestPlugin");
        assert_eq!(panel.view_count(), 0);
        assert!(panel.active_view_name().is_none());
        assert!(panel.is_empty());
    }

    #[test]
    fn test_panel_register_view() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        panel.register_view(ViewDescriptor::new("Listing View", 0, "Listing comparison"));
        panel.register_view(ViewDescriptor::new("Decompiler View", 1, "Decompiler comparison"));

        assert_eq!(panel.view_count(), 2);
        assert_eq!(panel.view_names().len(), 2);
    }

    #[test]
    fn test_panel_view_descriptor() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        panel.register_view(
            ViewDescriptor::new("Listing View", 0, "Listing comparison")
                .with_cross_arch_support(),
        );

        let desc = panel.view_descriptor("Listing View").unwrap();
        assert!(desc.supports_cross_arch);

        assert!(panel.view_descriptor("Nonexistent").is_none());
    }

    #[test]
    fn test_panel_set_active_view() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        panel.register_view(ViewDescriptor::new("Listing View", 0, "desc"));
        panel.register_view(ViewDescriptor::new("Decompiler View", 1, "desc"));

        assert!(panel.set_active_view("Listing View"));
        assert_eq!(panel.active_view_name(), Some("Listing View"));

        assert!(panel.set_active_view("Decompiler View"));
        assert_eq!(panel.active_view_name(), Some("Decompiler View"));

        assert!(!panel.set_active_view("Nonexistent"));
    }

    #[test]
    fn test_panel_load_functions() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        let prog = make_program(1, "/project/test", "test");
        let left = make_func_info("main", 0x1000, prog.clone());
        let right = make_func_info("init", 0x2000, prog);

        panel.load_functions(left, right);
        assert!(!panel.is_empty());
        assert_eq!(panel.description(), "main & init");
    }

    #[test]
    fn test_panel_clear() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        let prog = make_program(1, "/project/test", "test");
        let left = make_func_info("main", 0x1000, prog.clone());
        let right = make_func_info("init", 0x2000, prog);

        panel.load_functions(left, right);
        assert!(!panel.is_empty());

        panel.clear();
        assert!(panel.is_empty());
    }

    #[test]
    fn test_panel_scroll_sync() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        assert!(panel.is_scroll_sync());

        panel.set_scroll_sync(false);
        assert!(!panel.is_scroll_sync());

        panel.toggle_scroll_sync();
        assert!(panel.is_scroll_sync());
    }

    #[test]
    fn test_panel_save_restore_state() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        panel.register_view(ViewDescriptor::new("Listing View", 0, "desc"));
        panel.register_view(ViewDescriptor::new("Decompiler View", 1, "desc"));

        panel.set_active_view("Decompiler View");
        panel.set_scroll_sync(false);
        panel.save_state();

        let mut panel2 = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        panel2.register_view(ViewDescriptor::new("Listing View", 0, "desc"));
        panel2.register_view(ViewDescriptor::new("Decompiler View", 1, "desc"));

        // Transfer state
        *panel2.panel_state.panel_state_mut() = panel.panel_state().clone();
        panel2.restore_state();

        assert_eq!(panel2.active_view_name(), Some("Decompiler View"));
        assert!(!panel2.is_scroll_sync());
    }

    #[test]
    fn test_panel_dispose() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        panel.register_view(ViewDescriptor::new("Listing View", 0, "desc"));

        let prog = make_program(1, "/project/test", "test");
        let left = make_func_info("main", 0x1000, prog.clone());
        let right = make_func_info("init", 0x2000, prog);
        panel.load_functions(left, right);

        panel.dispose();
        assert!(panel.is_empty());
    }

    // --- Listener tests ---

    #[test]
    fn test_panel_listener_view_changed() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        let listener = Arc::new(TrackingCodeComparisonPanelListener::new());
        panel.add_listener(Box::new(listener.clone()));

        panel.register_view(ViewDescriptor::new("Listing View", 0, "desc"));
        panel.register_view(ViewDescriptor::new("Decompiler View", 1, "desc"));

        panel.set_active_view("Listing View");
        panel.set_active_view("Decompiler View");

        assert_eq!(listener.event_count(), 2);
    }

    #[test]
    fn test_panel_listener_data_loaded() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        let listener = Arc::new(TrackingCodeComparisonPanelListener::new());
        panel.add_listener(Box::new(listener.clone()));

        let prog = make_program(1, "/project/test", "test");
        let left = make_func_info("main", 0x1000, prog.clone());
        let right = make_func_info("init", 0x2000, prog);
        panel.load_functions(left, right);

        assert!(listener.event_count() >= 1);
    }

    #[test]
    fn test_panel_listener_data_cleared() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        let listener = Arc::new(TrackingCodeComparisonPanelListener::new());
        panel.add_listener(Box::new(listener.clone()));

        panel.clear();
        assert!(listener.event_count() >= 1);
    }

    #[test]
    fn test_panel_listener_scroll_sync() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        let listener = Arc::new(TrackingCodeComparisonPanelListener::new());
        panel.add_listener(Box::new(listener.clone()));

        panel.set_scroll_sync(false);
        assert!(listener.event_count() >= 1);
    }

    #[test]
    fn test_panel_listener_disposed() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        let listener = Arc::new(TrackingCodeComparisonPanelListener::new());
        panel.add_listener(Box::new(listener.clone()));

        panel.dispose();
        assert!(listener.event_count() >= 1);
    }

    #[test]
    fn test_tracking_listener_new() {
        let listener = TrackingCodeComparisonPanelListener::new();
        assert_eq!(listener.event_count(), 0);
    }

    #[test]
    fn test_panel_get_data() {
        let mut panel = CodeComparisonPanel::new("Test", ComparisonPanelConfig::default());
        let prog = make_program(1, "/project/test", "test");
        let left = make_func_info("main", 0x1000, prog.clone());
        let right = make_func_info("init", 0x2000, prog);

        panel.load_functions(left, right);

        let left_data = panel.get_data(ComparisonSide::Left);
        assert_eq!(left_data.get_short_description(), "main");

        let right_data = panel.get_data(ComparisonSide::Right);
        assert_eq!(right_data.get_short_description(), "init");
    }
}
