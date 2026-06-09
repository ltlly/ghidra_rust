//! Function compare provider.
//!
//! Ported from Ghidra's `FunctionCompareProvider` Java class in
//! `ghidra.app.plugin.core.functioncompare`.
//!
//! A dockable provider that displays function comparisons. Clients
//! create and modify comparisons using the [`FunctionComparePlugin`],
//! which creates instances of this provider as needed.
//!
//! In the original Java, `FunctionCompareProvider` extends
//! `ComponentProviderAdapter` and implements `DomainObjectListener`.
//! In this Rust port we capture the logical state and behavior without
//! the Ghidra plugin framework.
//!
//! # Key types
//!
//! - [`FunctionCompareProvider`] -- the comparison provider state
//! - [`ProviderAction`] -- actions registered on the provider
//! - [`ActiveView`] -- the active view within a provider

use std::sync::{Arc, Mutex};

use super::{
    ApplyResult, ComparisonContext, FunctionComparisonAction, FunctionComparisonEntry,
    FunctionComparisonPanel, FunctionInfo, HELP_TOPIC,
};

use super::function_compare_plugin::{CompareAction, FunctionComparePlugin};

/// Popup menu groups used in the provider.
const APPLY_GROUP: &str = "A0_ApplyFunction";
const NAV_GROUP: &str = "A9 FunctionNavigate";

/// The state of the active view within a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActiveView {
    /// The listing-based code comparison view.
    Listing,
    /// The decompiler-based code comparison view.
    Decompiler,
    /// The function-graph comparison view.
    FunctionGraph,
}

impl ActiveView {
    /// A human-readable name for this view.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Listing => "Listing Code Comparison",
            Self::Decompiler => "Decompiler Code Comparison",
            Self::FunctionGraph => "Function Graph Comparison",
        }
    }
}

/// Configuration for a provider action.
#[derive(Debug, Clone)]
pub struct ProviderActionConfig {
    /// The action name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Keyboard binding, if any.
    pub key_binding: Option<String>,
    /// Popup menu path.
    pub popup_menu_path: Option<String>,
    /// Popup menu group.
    pub popup_menu_group: Option<String>,
    /// Toolbar group.
    pub toolbar_group: Option<String>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl ProviderActionConfig {
    /// Create a new action configuration.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            key_binding: None,
            popup_menu_path: None,
            popup_menu_group: None,
            toolbar_group: None,
            enabled: true,
        }
    }

    /// Set the keyboard binding.
    pub fn with_key_binding(mut self, binding: impl Into<String>) -> Self {
        self.key_binding = Some(binding.into());
        self
    }

    /// Set the popup menu path.
    pub fn with_popup_menu_path(mut self, path: impl Into<String>) -> Self {
        self.popup_menu_path = Some(path.into());
        self
    }

    /// Set the popup menu group.
    pub fn with_popup_menu_group(mut self, group: impl Into<String>) -> Self {
        self.popup_menu_group = Some(group.into());
        self
    }

    /// Set the toolbar group.
    pub fn with_toolbar_group(mut self, group: impl Into<String>) -> Self {
        self.toolbar_group = Some(group.into());
        self
    }

    /// Set whether the action is enabled.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Trait for receiving provider events.
pub trait ProviderEventListener: Send + Sync {
    /// Called when the provider is opened.
    fn on_opened(&self, provider_id: u64);

    /// Called when the provider is closed.
    fn on_closed(&self, provider_id: u64);

    /// Called when the provider is activated (gains focus).
    fn on_activated(&self, provider_id: u64);

    /// Called when the tab text changes.
    fn on_tab_text_changed(&self, provider_id: u64, new_text: &str);

    /// Called when the active view changes.
    fn on_view_changed(&self, provider_id: u64, view: ActiveView);
}

/// A function compare provider.
///
/// Manages the display of a function comparison, including navigation
/// actions, the comparison context, and the comparison panel.
///
/// Ported from Ghidra's `FunctionCompareProvider` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::functioncompare::*;
/// use ghidra_features::functioncompare::function_compare_provider::*;
///
/// let panel = FunctionComparisonPanel::new();
/// let ctx = ComparisonContext {
///     source: Some(FunctionInfo {
///         name: "main".into(),
///         namespace: "App".into(),
///         entry_address: 0x1000,
///         read_only: false,
///     }),
///     target: Some(FunctionInfo {
///         name: "init".into(),
///         namespace: "App".into(),
///         entry_address: 0x2000,
///         read_only: false,
///     }),
/// };
///
/// let provider = FunctionCompareProvider::new(
///     1,
///     "main vs init",
///     panel,
///     ctx,
/// );
///
/// assert_eq!(provider.id(), 1);
/// assert_eq!(provider.tab_text(), "main vs init");
/// assert!(!provider.is_disposed());
/// ```
pub struct FunctionCompareProvider {
    /// Unique provider ID.
    id: u64,
    /// Tab text displayed in the UI.
    tab_text: String,
    /// Title text for the provider window.
    title: String,
    /// The comparison panel.
    panel: FunctionComparisonPanel,
    /// The comparison context.
    context: ComparisonContext,
    /// The currently active view.
    active_view: ActiveView,
    /// Whether "navigate to function" is enabled.
    navigate_to_function: bool,
    /// Registered actions.
    actions: Vec<ProviderActionConfig>,
    /// Whether the provider has been disposed.
    disposed: bool,
    /// Close listener callback.
    close_listener: Option<Box<dyn Fn() + Send + Sync>>,
    /// Registered event listeners.
    listeners: Vec<Arc<dyn ProviderEventListener>>,
}

impl FunctionCompareProvider {
    /// Create a new function compare provider.
    pub fn new(
        id: u64,
        tab_text: impl Into<String>,
        panel: FunctionComparisonPanel,
        context: ComparisonContext,
    ) -> Self {
        let tab_text = tab_text.into();
        let title = tab_text.clone();

        let mut provider = Self {
            id,
            tab_text,
            title,
            panel,
            context,
            active_view: ActiveView::Decompiler,
            navigate_to_function: false,
            actions: Vec::new(),
            disposed: false,
            close_listener: None,
            listeners: Vec::new(),
        };

        provider.create_actions();
        provider
    }

    /// Get the provider ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get the tab text.
    pub fn tab_text(&self) -> &str {
        &self.tab_text
    }

    /// Get the title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Set the tab text and title.
    pub fn set_tab_text(&mut self, text: impl Into<String>) {
        let text = text.into();
        self.tab_text = text.clone();
        self.title = text.clone();
        for listener in &self.listeners {
            listener.on_tab_text_changed(self.id, &text);
        }
    }

    /// Get the currently active view.
    pub fn active_view(&self) -> ActiveView {
        self.active_view
    }

    /// Set the active view.
    pub fn set_active_view(&mut self, view: ActiveView) {
        if self.active_view != view {
            self.active_view = view;
            for listener in &self.listeners {
                listener.on_view_changed(self.id, view);
            }
        }
    }

    /// Check if "navigate to function" is enabled.
    pub fn navigate_to_function(&self) -> bool {
        self.navigate_to_function
    }

    /// Toggle "navigate to function".
    pub fn set_navigate_to_function(&mut self, enabled: bool) {
        self.navigate_to_function = enabled;
    }

    /// Get a reference to the comparison context.
    pub fn context(&self) -> &ComparisonContext {
        &self.context
    }

    /// Get a mutable reference to the comparison context.
    pub fn context_mut(&mut self) -> &mut ComparisonContext {
        &mut self.context
    }

    /// Get a reference to the comparison panel.
    pub fn panel(&self) -> &FunctionComparisonPanel {
        &self.panel
    }

    /// Get a mutable reference to the comparison panel.
    pub fn panel_mut(&mut self) -> &mut FunctionComparisonPanel {
        &mut self.panel
    }

    /// Add a listener for provider events.
    pub fn add_listener(&mut self, listener: Arc<dyn ProviderEventListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Set the close listener callback.
    pub fn set_close_listener(&mut self, listener: Box<dyn Fn() + Send + Sync>) {
        self.close_listener = Some(listener);
    }

    /// Get the registered actions.
    pub fn actions(&self) -> &[ProviderActionConfig] {
        &self.actions
    }

    /// Check whether the provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Get a description of the current comparison.
    pub fn description(&self) -> String {
        match (&self.context.source, &self.context.target) {
            (Some(s), Some(t)) => format!("{} vs {}", s.qualified_name(), t.qualified_name()),
            (Some(f), None) | (None, Some(f)) => f.qualified_name(),
            (None, None) => "Empty Comparison".to_string(),
        }
    }

    /// Update the tab and title text based on the current description.
    pub fn update_tab_and_title(&mut self) {
        let description = self.description();
        self.set_tab_text(description);
    }

    /// Check if the provider has both source and target functions.
    pub fn is_ready(&self) -> bool {
        self.context.is_valid()
    }

    /// Set the source function.
    pub fn set_source(&mut self, info: FunctionInfo) {
        self.context.source = Some(info);
        self.update_tab_and_title();
    }

    /// Set the target function.
    pub fn set_target(&mut self, info: FunctionInfo) {
        self.context.target = Some(info);
        self.update_tab_and_title();
    }

    /// Execute an apply action using the given plugin.
    ///
    /// Returns the [`ApplyResult`].
    pub fn execute_action(
        &self,
        plugin: &FunctionComparePlugin,
        action: CompareAction,
    ) -> ApplyResult {
        plugin.execute_action(action, &self.context)
    }

    /// Fire the activated event.
    pub fn on_activated(&self) {
        for listener in &self.listeners {
            listener.on_activated(self.id);
        }
    }

    /// Dispose of the provider.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.actions.clear();
        // Fire close events before clearing listeners
        for listener in &self.listeners {
            listener.on_closed(self.id);
        }
        self.listeners.clear();
        if let Some(listener) = self.close_listener.take() {
            listener();
        }
    }

    /// Create the default actions for this provider.
    fn create_actions(&mut self) {
        self.actions.push(
            ProviderActionConfig::new(
                "Apply Function Name",
                "Apply function name and namespace from source to target.",
            )
            .with_popup_menu_path("Apply Function Name")
            .with_popup_menu_group(APPLY_GROUP),
        );

        self.actions.push(
            ProviderActionConfig::new(
                "Apply Function Signature",
                "Apply function signature from source to target.",
            )
            .with_popup_menu_path("Apply Function Signature")
            .with_popup_menu_group(APPLY_GROUP),
        );

        self.actions.push(
            ProviderActionConfig::new(
                "Apply Signature with Data Types",
                "Apply function signature along with data type definitions.",
            )
            .with_popup_menu_path("Apply Signature with Data Types")
            .with_popup_menu_group(APPLY_GROUP),
        );

        self.actions.push(
            ProviderActionConfig::new(
                "Apply Calling Convention",
                "Apply calling convention from source to target.",
            )
            .with_popup_menu_path("Apply Calling Convention")
            .with_popup_menu_group(APPLY_GROUP),
        );

        self.actions.push(
            ProviderActionConfig::new(
                "Apply Function Comments",
                "Apply parameter and function comments.",
            )
            .with_popup_menu_path("Apply Function Comments")
            .with_popup_menu_group(APPLY_GROUP),
        );

        self.actions.push(
            ProviderActionConfig::new(
                "Apply All Function Data",
                "Apply all function data from source to target.",
            )
            .with_popup_menu_path("Apply All Function Data")
            .with_popup_menu_group(APPLY_GROUP),
        );
    }
}

impl Drop for FunctionCompareProvider {
    fn drop(&mut self) {
        if !self.disposed {
            self.dispose();
        }
    }
}

/// A simple listener that tracks provider events.
#[derive(Debug, Default)]
pub struct TrackingProviderListener {
    /// Recorded open events.
    pub opened: Mutex<Vec<u64>>,
    /// Recorded close events.
    pub closed: Mutex<Vec<u64>>,
    /// Recorded activate events.
    pub activated: Mutex<Vec<u64>>,
    /// Recorded tab text changes.
    pub tab_changes: Mutex<Vec<(u64, String)>>,
    /// Recorded view changes.
    pub view_changes: Mutex<Vec<(u64, ActiveView)>>,
}

impl TrackingProviderListener {
    /// Create a new tracking listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the total number of events received.
    pub fn total_events(&self) -> usize {
        self.opened.lock().unwrap().len()
            + self.closed.lock().unwrap().len()
            + self.activated.lock().unwrap().len()
            + self.tab_changes.lock().unwrap().len()
            + self.view_changes.lock().unwrap().len()
    }
}

impl ProviderEventListener for TrackingProviderListener {
    fn on_opened(&self, provider_id: u64) {
        self.opened.lock().unwrap().push(provider_id);
    }

    fn on_closed(&self, provider_id: u64) {
        self.closed.lock().unwrap().push(provider_id);
    }

    fn on_activated(&self, provider_id: u64) {
        self.activated.lock().unwrap().push(provider_id);
    }

    fn on_tab_text_changed(&self, provider_id: u64, new_text: &str) {
        self.tab_changes
            .lock()
            .unwrap()
            .push((provider_id, new_text.to_string()));
    }

    fn on_view_changed(&self, provider_id: u64, view: ActiveView) {
        self.view_changes.lock().unwrap().push((provider_id, view));
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_info(name: &str, namespace: &str, entry: u64) -> FunctionInfo {
        FunctionInfo {
            name: name.into(),
            namespace: namespace.into(),
            entry_address: entry,
            read_only: false,
        }
    }

    fn make_provider(id: u64, tab: &str) -> FunctionCompareProvider {
        let panel = FunctionComparisonPanel::new();
        let ctx = ComparisonContext {
            source: Some(make_info("src", "ns", 0x1000)),
            target: Some(make_info("tgt", "ns", 0x2000)),
        };
        FunctionCompareProvider::new(id, tab, panel, ctx)
    }

    // --- ActiveView tests ---

    #[test]
    fn test_active_view_name() {
        assert_eq!(ActiveView::Listing.name(), "Listing Code Comparison");
        assert_eq!(ActiveView::Decompiler.name(), "Decompiler Code Comparison");
        assert_eq!(ActiveView::FunctionGraph.name(), "Function Graph Comparison");
    }

    #[test]
    fn test_active_view_equality() {
        assert_eq!(ActiveView::Listing, ActiveView::Listing);
        assert_ne!(ActiveView::Listing, ActiveView::Decompiler);
    }

    // --- ProviderActionConfig tests ---

    #[test]
    fn test_action_config_basic() {
        let config = ProviderActionConfig::new("Test Action", "A test action.");
        assert_eq!(config.name, "Test Action");
        assert_eq!(config.description, "A test action.");
        assert!(config.key_binding.is_none());
        assert!(config.enabled);
    }

    #[test]
    fn test_action_config_builder() {
        let config = ProviderActionConfig::new("Nav", "Navigate.")
            .with_key_binding("ctrl+N")
            .with_popup_menu_path("Navigate")
            .with_popup_menu_group("nav_group")
            .with_toolbar_group("toolbar")
            .with_enabled(false);

        assert_eq!(config.key_binding.as_deref(), Some("ctrl+N"));
        assert_eq!(config.popup_menu_path.as_deref(), Some("Navigate"));
        assert_eq!(config.popup_menu_group.as_deref(), Some("nav_group"));
        assert_eq!(config.toolbar_group.as_deref(), Some("toolbar"));
        assert!(!config.enabled);
    }

    // --- FunctionCompareProvider tests ---

    #[test]
    fn test_provider_new() {
        let provider = make_provider(1, "test comparison");
        assert_eq!(provider.id(), 1);
        assert_eq!(provider.tab_text(), "test comparison");
        assert_eq!(provider.title(), "test comparison");
        assert!(!provider.is_disposed());
        assert_eq!(provider.active_view(), ActiveView::Decompiler);
        assert!(!provider.navigate_to_function());
        assert!(provider.is_ready());
    }

    #[test]
    fn test_provider_default_actions() {
        let provider = make_provider(1, "test");
        // Should have 6 default actions (one per apply type)
        assert_eq!(provider.actions().len(), 6);
    }

    #[test]
    fn test_provider_set_tab_text() {
        let mut provider = make_provider(1, "original");
        provider.set_tab_text("new tab text");
        assert_eq!(provider.tab_text(), "new tab text");
        assert_eq!(provider.title(), "new tab text");
    }

    #[test]
    fn test_provider_set_active_view() {
        let mut provider = make_provider(1, "test");
        provider.set_active_view(ActiveView::Listing);
        assert_eq!(provider.active_view(), ActiveView::Listing);
    }

    #[test]
    fn test_provider_navigate_to_function() {
        let mut provider = make_provider(1, "test");
        assert!(!provider.navigate_to_function());
        provider.set_navigate_to_function(true);
        assert!(provider.navigate_to_function());
    }

    #[test]
    fn test_provider_description() {
        let provider = make_provider(1, "test");
        let desc = provider.description();
        assert!(desc.contains("src"));
        assert!(desc.contains("tgt"));
    }

    #[test]
    fn test_provider_description_empty() {
        let panel = FunctionComparisonPanel::new();
        let ctx = ComparisonContext::new();
        let provider = FunctionCompareProvider::new(1, "empty", panel, ctx);
        assert_eq!(provider.description(), "Empty Comparison");
    }

    #[test]
    fn test_provider_set_source_target() {
        let panel = FunctionComparisonPanel::new();
        let ctx = ComparisonContext::new();
        let mut provider = FunctionCompareProvider::new(1, "empty", panel, ctx);
        assert!(!provider.is_ready());

        provider.set_source(make_info("main", "App", 0x1000));
        provider.set_target(make_info("init", "App", 0x2000));
        assert!(provider.is_ready());
    }

    #[test]
    fn test_provider_update_tab_and_title() {
        let mut provider = make_provider(1, "initial");
        provider.update_tab_and_title();
        let desc = provider.description();
        assert_eq!(provider.tab_text(), desc);
    }

    #[test]
    fn test_provider_context() {
        let provider = make_provider(1, "test");
        assert!(provider.context().is_valid());
        assert!(!provider.context().is_target_read_only());
    }

    #[test]
    fn test_provider_panel() {
        let mut provider = make_provider(1, "test");
        assert!(!provider.panel().is_ready());

        provider.panel_mut().set_source(FunctionComparisonEntry::new("src", "p", 0x1000));
        provider.panel_mut().set_target(FunctionComparisonEntry::new("tgt", "p", 0x2000));
        assert!(provider.panel().is_ready());
    }

    #[test]
    fn test_provider_execute_action() {
        let plugin = FunctionComparePlugin::new();
        let provider = make_provider(1, "test");

        let result = provider.execute_action(&plugin, CompareAction::ApplyName);
        assert!(result.is_success());
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = make_provider(1, "test");
        assert!(!provider.is_disposed());
        provider.dispose();
        assert!(provider.is_disposed());
        assert!(provider.actions().is_empty());
    }

    #[test]
    fn test_provider_dispose_idempotent() {
        let mut provider = make_provider(1, "test");
        provider.dispose();
        provider.dispose();
        assert!(provider.is_disposed());
    }

    #[test]
    fn test_provider_listener_notifications() {
        let listener = Arc::new(TrackingProviderListener::new());
        let mut provider = make_provider(1, "test");

        provider.add_listener(listener.clone());
        provider.set_tab_text("updated");
        provider.set_active_view(ActiveView::FunctionGraph);

        assert_eq!(listener.tab_changes.lock().unwrap().len(), 1);
        assert_eq!(listener.view_changes.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_provider_clear_listeners() {
        let listener = Arc::new(TrackingProviderListener::new());
        let mut provider = make_provider(1, "test");

        provider.add_listener(listener.clone());
        provider.clear_listeners();

        provider.set_tab_text("no listener");
        assert_eq!(listener.tab_changes.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_provider_close_listener() {
        let called = Arc::new(Mutex::new(false));
        let called_clone = called.clone();

        let mut provider = make_provider(1, "test");
        provider.set_close_listener(Box::new(move || {
            *called_clone.lock().unwrap() = true;
        }));

        provider.dispose();
        assert!(*called.lock().unwrap());
    }

    #[test]
    fn test_provider_listener_close_event() {
        let listener = Arc::new(TrackingProviderListener::new());
        let mut provider = make_provider(1, "test");
        provider.add_listener(listener.clone());

        provider.dispose();
        assert_eq!(listener.closed.lock().unwrap().len(), 1);
        assert_eq!(listener.closed.lock().unwrap()[0], 1);
    }

    // --- TrackingProviderListener tests ---

    #[test]
    fn test_tracking_provider_listener() {
        let listener = TrackingProviderListener::new();
        assert_eq!(listener.total_events(), 0);

        listener.on_opened(1);
        listener.on_activated(1);
        listener.on_tab_text_changed(1, "new text");
        listener.on_view_changed(1, ActiveView::Listing);
        listener.on_closed(1);

        assert_eq!(listener.total_events(), 5);
        assert_eq!(listener.opened.lock().unwrap().len(), 1);
        assert_eq!(listener.closed.lock().unwrap().len(), 1);
        assert_eq!(listener.activated.lock().unwrap().len(), 1);
        assert_eq!(listener.tab_changes.lock().unwrap().len(), 1);
        assert_eq!(listener.view_changes.lock().unwrap().len(), 1);
    }
}
