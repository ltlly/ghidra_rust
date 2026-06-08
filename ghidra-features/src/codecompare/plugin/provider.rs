//! Function comparison provider.
//!
//! Ported from Ghidra's `FunctionComparisonProvider` Java class in
//! `ghidra.features.codecompare.plugin`.
//!
//! A dockable provider that displays function comparisons. Clients
//! create and modify comparisons using the [`FunctionComparisonPlugin`],
//! which creates instances of this provider as needed.
//!
//! In the original Java, `FunctionComparisonProvider` extends
//! `ComponentProviderAdapter` and implements `PopupActionProvider` and
//! `FunctionComparisonModelListener`. In this Rust port we capture the
//! logical state and behavior without the Ghidra plugin framework.
//!
//! # Key types
//!
//! - [`FunctionComparisonProvider`] -- the comparison provider state
//! - [`ProviderAction`] -- actions registered on the provider
//! - [`ProviderViewState`] -- the active view within a provider

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::{ComparisonAction, PluginEvent};
use super::super::model::{
    AnyToAnyFunctionComparisonModel, ComparisonSide, FunctionComparisonModel, FunctionInfo,
};
use super::super::panel::{
    ComparisonPanelState, FunctionComparisonData, FunctionComparisonInfo, ProgramInfo,
};

/// The help topic used for all function comparison help locations.
const HELP_TOPIC: &str = "FunctionComparison";

/// Popup menu groups used in the provider.
const ADD_COMPARISON_GROUP: &str = "A9_AddToComparison";
const NAV_GROUP: &str = "A9 FunctionNavigate";
const REMOVE_FUNCTIONS_GROUP: &str = "A9_RemoveFunctions";

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

/// A function comparison provider.
///
/// Manages the display of a function comparison, including navigation
/// actions, the comparison model, and the comparison panel.
///
/// Ported from Ghidra's `FunctionComparisonProvider` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::plugin::provider::*;
/// use ghidra_features::codecompare::plugin::*;
/// use ghidra_features::codecompare::model::*;
/// use ghidra_features::codecompare::panel::*;
///
/// let f1 = FunctionInfo::new(1, "main", "/project/test", 0x1000);
/// let f2 = FunctionInfo::new(2, "init", "/project/test", 0x2000);
/// let model = Box::new(AnyToAnyFunctionComparisonModel::new(vec![f1, f2]));
/// let state = ComparisonPanelState::new();
///
/// let provider = FunctionComparisonProvider::new(
///     1,
///     "Comparison: main vs init",
///     model,
///     state,
/// );
///
/// assert_eq!(provider.id(), 1);
/// assert_eq!(provider.tab_text(), "Comparison: main vs init");
/// assert!(!provider.is_disposed());
/// ```
pub struct FunctionComparisonProvider {
    /// Unique provider ID.
    id: u64,
    /// Tab text displayed in the UI.
    tab_text: String,
    /// Title text for the provider window.
    title: String,
    /// The comparison model.
    model: Box<dyn FunctionComparisonModel>,
    /// The panel state.
    panel_state: ComparisonPanelState,
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

impl FunctionComparisonProvider {
    /// Create a new function comparison provider.
    pub fn new(
        id: u64,
        tab_text: impl Into<String>,
        model: Box<dyn FunctionComparisonModel>,
        panel_state: ComparisonPanelState,
    ) -> Self {
        let tab_text = tab_text.into();
        let title = tab_text.clone();

        let mut provider = Self {
            id,
            tab_text,
            title,
            model,
            panel_state,
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

    /// Get a reference to the comparison model.
    pub fn model(&self) -> &dyn FunctionComparisonModel {
        self.model.as_ref()
    }

    /// Get a mutable reference to the comparison model.
    pub fn model_mut(&mut self) -> &mut dyn FunctionComparisonModel {
        self.model.as_mut()
    }

    /// Get the panel state.
    pub fn panel_state(&self) -> &ComparisonPanelState {
        &self.panel_state
    }

    /// Get a mutable reference to the panel state.
    pub fn panel_state_mut(&mut self) -> &mut ComparisonPanelState {
        &mut self.panel_state
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

    /// Check if the provider supports adding functions.
    ///
    /// Returns `true` if using the `AnyToAnyFunctionComparisonModel`.
    pub fn supports_adding_functions(&self) -> bool {
        self.model.as_any().is::<AnyToAnyFunctionComparisonModel>()
    }

    /// Update the tab and title text based on the panel description.
    pub fn update_tab_and_title(&mut self) {
        let description = self.description();
        self.set_tab_text(description);
    }

    /// Get a description of the current comparison.
    pub fn description(&self) -> String {
        let left = self.model.get_active_function(ComparisonSide::Left);
        let right = self.model.get_active_function(ComparisonSide::Right);
        match (left, right) {
            (Some(l), Some(r)) => {
                format!("{} vs {}", l.display_name(), r.display_name())
            }
            (Some(f), None) | (None, Some(f)) => f.display_name(),
            (None, None) => "Empty Comparison".to_string(),
        }
    }

    /// Handle a program being closed.
    ///
    /// Removes any functions from the given program and closes if empty.
    pub fn program_closed(&mut self, program_path: &str) {
        self.model.remove_functions_by_program(program_path);
        self.update_tab_and_title();
    }

    /// Remove the active function from the comparison.
    ///
    /// Returns `true` if a function was removed.
    pub fn remove_active_function(&mut self) -> bool {
        let left = self.model.get_active_function(ComparisonSide::Left).cloned();
        let right = self.model.get_active_function(ComparisonSide::Right).cloned();

        // Try to remove the function on the side that has more functions
        let left_count = self.model.get_functions(ComparisonSide::Left).len();
        let right_count = self.model.get_functions(ComparisonSide::Right).len();

        if left_count > 1 {
            if let Some(func) = left {
                self.model.remove_function(&func);
                self.update_tab_and_title();
                return true;
            }
        } else if right_count > 1 {
            if let Some(func) = right {
                self.model.remove_function(&func);
                self.update_tab_and_title();
                return true;
            }
        }

        false
    }

    /// Check if the active function can be removed.
    pub fn can_remove_active_function(&self) -> bool {
        let left_count = self.model.get_functions(ComparisonSide::Left).len();
        let right_count = self.model.get_functions(ComparisonSide::Right).len();
        left_count > 1 || right_count > 1
    }

    /// Navigate to the next function for the side with focus.
    ///
    /// Returns `true` if navigation succeeded.
    pub fn compare_next_function(&mut self, side: ComparisonSide) -> bool {
        let functions = self.model.get_functions(side);
        if functions.is_empty() {
            return false;
        }

        let current = self.model.get_active_function(side);
        let current_idx = current.and_then(|f| {
            functions.iter().position(|&func| func.id == f.id)
        });

        let next_idx = match current_idx {
            Some(idx) => (idx + 1) % functions.len(),
            None => 0,
        };

        let next_func = functions[next_idx].clone();
        let changed = self.model.set_active_function(side, &next_func);
        if changed {
            self.update_tab_and_title();
        }
        changed
    }

    /// Navigate to the previous function for the side with focus.
    ///
    /// Returns `true` if navigation succeeded.
    pub fn compare_previous_function(&mut self, side: ComparisonSide) -> bool {
        let functions = self.model.get_functions(side);
        if functions.is_empty() {
            return false;
        }

        let current = self.model.get_active_function(side);
        let current_idx = current.and_then(|f| {
            functions.iter().position(|&func| func.id == f.id)
        });

        let prev_idx = match current_idx {
            Some(idx) => {
                if idx == 0 {
                    functions.len() - 1
                } else {
                    idx - 1
                }
            }
            None => functions.len() - 1,
        };

        let prev_func = functions[prev_idx].clone();
        let changed = self.model.set_active_function(side, &prev_func);
        if changed {
            self.update_tab_and_title();
        }
        changed
    }

    /// Check if next function navigation is possible.
    pub fn can_compare_next_function(&self) -> bool {
        let left_count = self.model.get_functions(ComparisonSide::Left).len();
        let right_count = self.model.get_functions(ComparisonSide::Right).len();
        left_count > 1 || right_count > 1
    }

    /// Check if previous function navigation is possible.
    pub fn can_compare_previous_function(&self) -> bool {
        self.can_compare_next_function()
    }

    /// Add functions to the comparison model.
    ///
    /// Only works if the model is an `AnyToAnyFunctionComparisonModel`.
    pub fn add_functions(&mut self, functions: Vec<FunctionInfo>) -> bool {
        // We need to downcast; use the as_any pattern
        if let Some(any_model) = self.model.as_any_mut().downcast_mut::<AnyToAnyFunctionComparisonModel>() {
            any_model.add_functions(functions);
            self.update_tab_and_title();
            true
        } else {
            false
        }
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
        self.listeners.clear();
        if let Some(listener) = self.close_listener.take() {
            listener();
        }
        for listener in &self.listeners {
            listener.on_closed(self.id);
        }
    }

    /// Create the default actions for this provider.
    fn create_actions(&mut self) {
        self.actions.push(
            ProviderActionConfig::new(
                "Compare Next Function",
                "Compare the next function for the side with focus.",
            )
            .with_key_binding("ctrl+shift+N")
            .with_popup_menu_path("Compare Next Function")
            .with_popup_menu_group(NAV_GROUP)
            .with_toolbar_group(NAV_GROUP),
        );

        self.actions.push(
            ProviderActionConfig::new(
                "Compare Previous Function",
                "Compare the previous function for the side with focus.",
            )
            .with_key_binding("ctrl+shift+P")
            .with_popup_menu_path("Compare Previous Function")
            .with_popup_menu_group(NAV_GROUP)
            .with_toolbar_group(NAV_GROUP),
        );

        self.actions.push(
            ProviderActionConfig::new(
                "Remove Function",
                "Removes the active function from the comparison.",
            )
            .with_key_binding("ctrl+shift+R")
            .with_popup_menu_path("Remove Function")
            .with_popup_menu_group(REMOVE_FUNCTIONS_GROUP)
            .with_toolbar_group(REMOVE_FUNCTIONS_GROUP),
        );

        self.actions.push(
            ProviderActionConfig::new(
                "Navigate to Selected Function",
                "Toggle to navigate the tool to the selected function when focus changes.",
            ),
        );

        // Add-to-comparison action only for AnyToAny models
        self.actions.push(
            ProviderActionConfig::new(
                "Add Functions To Comparison",
                "Add functions to this comparison.",
            )
            .with_popup_menu_path("Add Functions")
            .with_popup_menu_group(ADD_COMPARISON_GROUP)
            .with_toolbar_group(ADD_COMPARISON_GROUP),
        );
    }
}

impl Drop for FunctionComparisonProvider {
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
    pub opened: std::sync::Mutex<Vec<u64>>,
    /// Recorded close events.
    pub closed: std::sync::Mutex<Vec<u64>>,
    /// Recorded activate events.
    pub activated: std::sync::Mutex<Vec<u64>>,
    /// Recorded tab text changes.
    pub tab_changes: std::sync::Mutex<Vec<(u64, String)>>,
    /// Recorded view changes.
    pub view_changes: std::sync::Mutex<Vec<(u64, ActiveView)>>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_func(id: u64, name: &str, program: &str, entry: u64) -> FunctionInfo {
        FunctionInfo::new(id, name, program, entry)
    }

    fn make_model(functions: Vec<FunctionInfo>) -> Box<AnyToAnyFunctionComparisonModel> {
        Box::new(AnyToAnyFunctionComparisonModel::new(functions))
    }

    fn make_provider(functions: Vec<FunctionInfo>) -> FunctionComparisonProvider {
        let model = make_model(functions);
        let state = ComparisonPanelState::new();
        FunctionComparisonProvider::new(1, "test comparison", model, state)
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

    // --- FunctionComparisonProvider tests ---

    #[test]
    fn test_provider_new() {
        let provider = make_provider(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        assert_eq!(provider.id(), 1);
        assert_eq!(provider.tab_text(), "test comparison");
        assert_eq!(provider.title(), "test comparison");
        assert!(!provider.is_disposed());
        assert_eq!(provider.active_view(), ActiveView::Decompiler);
        assert!(!provider.navigate_to_function());
    }

    #[test]
    fn test_provider_default_actions() {
        let provider = make_provider(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        // Should have 5 default actions
        assert_eq!(provider.actions().len(), 5);
    }

    #[test]
    fn test_provider_set_tab_text() {
        let mut provider = make_provider(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        provider.set_tab_text("new tab text");
        assert_eq!(provider.tab_text(), "new tab text");
        assert_eq!(provider.title(), "new tab text");
    }

    #[test]
    fn test_provider_set_active_view() {
        let mut provider = make_provider(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        provider.set_active_view(ActiveView::Listing);
        assert_eq!(provider.active_view(), ActiveView::Listing);
    }

    #[test]
    fn test_provider_navigate_to_function() {
        let mut provider = make_provider(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        assert!(!provider.navigate_to_function());
        provider.set_navigate_to_function(true);
        assert!(provider.navigate_to_function());
    }

    #[test]
    fn test_provider_description() {
        let provider = make_provider(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        let desc = provider.description();
        // Should contain both function names
        assert!(desc.contains("init"));
        assert!(desc.contains("main"));
    }

    #[test]
    fn test_provider_compare_next() {
        let mut provider = make_provider(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
            make_func(3, "ccc", "/prog", 0x3000),
        ]);

        assert!(provider.can_compare_next_function());
        let changed = provider.compare_next_function(ComparisonSide::Right);
        assert!(changed);
    }

    #[test]
    fn test_provider_compare_previous() {
        let mut provider = make_provider(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
            make_func(3, "ccc", "/prog", 0x3000),
        ]);

        assert!(provider.can_compare_previous_function());
        let changed = provider.compare_previous_function(ComparisonSide::Right);
        assert!(changed);
    }

    #[test]
    fn test_provider_compare_next_single_function() {
        let mut provider = make_provider(vec![
            make_func(1, "main", "/prog", 0x1000),
        ]);

        assert!(!provider.can_compare_next_function());
        // Should still return false (no change possible with single function on both sides)
        let changed = provider.compare_next_function(ComparisonSide::Right);
        assert!(!changed);
    }

    #[test]
    fn test_provider_remove_active_function() {
        let mut provider = make_provider(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
            make_func(3, "ccc", "/prog", 0x3000),
        ]);

        assert!(provider.can_remove_active_function());
        assert!(provider.remove_active_function());
    }

    #[test]
    fn test_provider_remove_active_function_single() {
        let mut provider = make_provider(vec![
            make_func(1, "main", "/prog", 0x1000),
        ]);

        // With a single function on both sides, cannot remove
        assert!(!provider.can_remove_active_function());
    }

    #[test]
    fn test_provider_program_closed() {
        let mut provider = make_provider(vec![
            make_func(1, "main", "/prog1", 0x1000),
            make_func(2, "init", "/prog1", 0x2000),
            make_func(3, "foo", "/prog2", 0x3000),
        ]);

        provider.program_closed("/prog1");
        // prog1 functions removed; prog2 remains
        let left_funcs = provider.model().get_functions(ComparisonSide::Left);
        for f in left_funcs {
            assert_eq!(f.program_path, "/prog2");
        }
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = make_provider(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        assert!(!provider.is_disposed());
        provider.dispose();
        assert!(provider.is_disposed());
        assert!(provider.actions().is_empty());
    }

    #[test]
    fn test_provider_dispose_idempotent() {
        let mut provider = make_provider(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        provider.dispose();
        provider.dispose(); // second call should be no-op
        assert!(provider.is_disposed());
    }

    #[test]
    fn test_provider_add_functions() {
        let mut provider = make_provider(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
        ]);

        let added = provider.add_functions(vec![
            make_func(3, "ccc", "/prog", 0x3000),
        ]);
        assert!(added);
        assert_eq!(
            provider.model().get_functions(ComparisonSide::Left).len(),
            3
        );
    }

    #[test]
    fn test_provider_supports_adding_functions() {
        let provider = make_provider(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        assert!(provider.supports_adding_functions());
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

    #[test]
    fn test_provider_listener_notifications() {
        let listener = Arc::new(TrackingProviderListener::new());
        let mut provider = make_provider(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        provider.add_listener(listener.clone());
        provider.set_tab_text("updated");
        provider.set_active_view(ActiveView::FunctionGraph);

        assert_eq!(listener.tab_changes.lock().unwrap().len(), 1);
        assert_eq!(listener.view_changes.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_provider_clear_listeners() {
        let listener = Arc::new(TrackingProviderListener::new());
        let mut provider = make_provider(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        provider.add_listener(listener.clone());
        provider.clear_listeners();

        // After clearing, no events should be received
        provider.set_tab_text("no listener");
        assert_eq!(listener.tab_changes.lock().unwrap().len(), 0);
    }
}
