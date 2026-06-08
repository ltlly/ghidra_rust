//! Function comparison plugin.
//!
//! Ported from Ghidra's `FunctionComparisonPlugin` Java class in
//! `ghidra.features.codecompare.plugin`.
//!
//! This module provides the plugin that manages function comparison
//! providers. It handles creating comparisons, managing providers,
//! and responding to program events (open, close, restore).
//!
//! In the original Java, `FunctionComparisonPlugin` extends `ProgramPlugin`
//! and implements `FunctionComparisonService` and `DomainObjectListener`.
//! In this Rust port, we capture the logical state and behavior without
//! the Ghidra plugin framework dependency.
//!
//! # Key types
//!
//! - [`ComparisonAction`] -- actions that can be performed on comparisons
//! - [`FunctionComparisonPlugin`] -- the main plugin state

pub mod comparison_service;
pub mod multi_function_panel;
pub mod provider;
pub mod provider_listener;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use super::model::{
    AnyToAnyFunctionComparisonModel, ComparisonSide, FunctionComparisonModel, FunctionInfo,
};
use super::panel::{
    ComparisonPanelState, FunctionComparisonData, FunctionComparisonInfo, ProgramInfo,
};

/// Actions that can be performed on function comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComparisonAction {
    /// Compare selected functions (add to existing or create new).
    CompareFunctions,
    /// Compare functions in a new window.
    CompareInNewWindow,
    /// Add functions to the current comparison.
    AddToComparison,
    /// Remove the active function from the comparison.
    RemoveActiveFunction,
    /// Navigate to the next function in the comparison.
    NextFunction,
    /// Navigate to the previous function in the comparison.
    PreviousFunction,
    /// Toggle navigation to selected function.
    ToggleNavigateToFunction,
}

impl ComparisonAction {
    /// A human-readable label for this action.
    pub fn label(&self) -> &'static str {
        match self {
            Self::CompareFunctions => "Compare Function(s)",
            Self::CompareInNewWindow => "Compare in New Window",
            Self::AddToComparison => "Add Functions To Comparison",
            Self::RemoveActiveFunction => "Remove Function",
            Self::NextFunction => "Compare Next Function",
            Self::PreviousFunction => "Compare Previous Function",
            Self::ToggleNavigateToFunction => "Navigate to Selected Function",
        }
    }

    /// A description of this action.
    pub fn description(&self) -> &'static str {
        match self {
            Self::CompareFunctions => "Adds the selected function(s) to the current comparison window.",
            Self::CompareInNewWindow => "Compare the selected function(s) in a new comparison window.",
            Self::AddToComparison => "Add functions to this comparison.",
            Self::RemoveActiveFunction => "Removes the active function from the comparison.",
            Self::NextFunction => "Compare the next function for the side with focus.",
            Self::PreviousFunction => "Compare the previous function for the side with focus.",
            Self::ToggleNavigateToFunction => {
                "Toggle to navigate the tool to the selected function when focus changes."
            }
        }
    }

    /// The keyboard shortcut for this action, if any.
    pub fn key_binding(&self) -> Option<&'static str> {
        match self {
            Self::NextFunction => Some("ctrl+shift+N"),
            Self::PreviousFunction => Some("ctrl+shift+P"),
            Self::RemoveActiveFunction => Some("ctrl+shift+R"),
            _ => None,
        }
    }

    /// The popup menu group for this action.
    pub fn popup_menu_group(&self) -> &'static str {
        match self {
            Self::CompareFunctions => "Functions",
            Self::CompareInNewWindow => "Functions",
            Self::AddToComparison => "A9_AddToComparison",
            Self::RemoveActiveFunction => "A9_RemoveFunctions",
            Self::NextFunction => "A9 FunctionNavigate",
            Self::PreviousFunction => "A9 FunctionNavigate",
            Self::ToggleNavigateToFunction => "A9 FunctionNavigate",
        }
    }
}

/// Events emitted by the function comparison plugin.
#[derive(Debug, Clone)]
pub enum PluginEvent {
    /// A new comparison provider was created.
    ProviderCreated {
        /// The provider ID.
        provider_id: u64,
    },
    /// A comparison provider was closed.
    ProviderClosed {
        /// The provider ID.
        provider_id: u64,
    },
    /// A program was opened.
    ProgramOpened {
        /// The program info.
        program: ProgramInfo,
    },
    /// A program was closed.
    ProgramClosed {
        /// The program info.
        program: ProgramInfo,
    },
    /// A function was removed from a program.
    FunctionRemoved {
        /// The function info.
        function: FunctionInfo,
    },
}

/// Trait for receiving plugin events.
pub trait PluginEventListener: Send + Sync {
    /// Called when an event occurs.
    fn on_event(&self, event: &PluginEvent);
}

/// Information about a comparison provider.
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    /// Unique provider ID.
    pub id: u64,
    /// The comparison model.
    pub model_type: ModelType,
    /// Whether this provider supports adding functions.
    pub supports_adding: bool,
}

/// The type of comparison model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelType {
    /// Any-to-any model (same set of functions on both sides).
    AnyToAny,
    /// Matched model (matched source/target pairs).
    Matched,
}

/// Global provider ID counter.
static PROVIDER_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_provider_id() -> u64 {
    PROVIDER_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// The function comparison plugin state.
///
/// Manages comparison providers, handles program events, and provides
/// the comparison service API.
///
/// Ported from Ghidra's `FunctionComparisonPlugin` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::plugin::*;
/// use ghidra_features::codecompare::model::*;
/// use ghidra_features::codecompare::panel::*;
///
/// let mut plugin = FunctionComparisonPlugin::new();
///
/// // Create a comparison
/// let f1 = FunctionInfo::new(1, "main", "/project/test", 0x1000);
/// let f2 = FunctionInfo::new(2, "init", "/project/test", 0x2000);
/// let provider_id = plugin.create_comparison(vec![f1, f2]);
/// assert!(provider_id.is_some());
/// assert_eq!(plugin.provider_count(), 1);
/// ```
pub struct FunctionComparisonPlugin {
    /// Active comparison providers.
    providers: HashSet<u64>,
    /// The last active provider that supports adding functions.
    last_active_provider: Option<u64>,
    /// Shared comparison panel state.
    comparison_state: ComparisonPanelState,
    /// Listeners for plugin events.
    listeners: Vec<Arc<dyn PluginEventListener>>,
}

impl FunctionComparisonPlugin {
    /// Create a new function comparison plugin.
    pub fn new() -> Self {
        Self {
            providers: HashSet::new(),
            last_active_provider: None,
            comparison_state: ComparisonPanelState::new(),
            listeners: Vec::new(),
        }
    }

    /// Add a listener for plugin events.
    pub fn add_listener(&mut self, listener: Arc<dyn PluginEventListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Fire an event to all listeners.
    fn fire_event(&self, event: PluginEvent) {
        for listener in &self.listeners {
            listener.on_event(&event);
        }
    }

    /// Create a new comparison with the given functions.
    ///
    /// Returns the provider ID if successful.
    pub fn create_comparison(&mut self, functions: Vec<FunctionInfo>) -> Option<u64> {
        if functions.is_empty() {
            return None;
        }

        let model = AnyToAnyFunctionComparisonModel::new(functions);
        let provider_id = self.create_provider(model);
        Some(provider_id)
    }

    /// Create a comparison between two specific functions.
    ///
    /// Returns the provider ID.
    pub fn create_comparison_pair(
        &mut self,
        left: FunctionInfo,
        right: FunctionInfo,
    ) -> u64 {
        let model = AnyToAnyFunctionComparisonModel::new_pair(left, right);
        self.create_provider(model)
    }

    /// Add functions to the last active comparison, or create a new one.
    ///
    /// Returns the provider ID.
    pub fn add_to_comparison(&mut self, functions: Vec<FunctionInfo>) -> Option<u64> {
        if functions.is_empty() {
            return None;
        }

        match self.last_active_provider {
            Some(_provider_id) => {
                // In a full implementation, we would add to the existing provider's model.
                // For now, create a new provider.
                self.create_comparison(functions)
            }
            None => self.create_comparison(functions),
        }
    }

    /// Create a new provider with the given model.
    fn create_provider(&mut self, model: AnyToAnyFunctionComparisonModel) -> u64 {
        let provider_id = next_provider_id();
        self.providers.insert(provider_id);
        self.last_active_provider = Some(provider_id);
        self.fire_event(PluginEvent::ProviderCreated { provider_id });
        provider_id
    }

    /// Close a comparison provider.
    pub fn close_provider(&mut self, provider_id: u64) {
        if self.providers.remove(&provider_id) {
            if self.last_active_provider == Some(provider_id) {
                self.last_active_provider = None;
            }
            self.fire_event(PluginEvent::ProviderClosed { provider_id });
        }
    }

    /// Set a provider as the last active provider.
    pub fn provider_activated(&mut self, provider_id: u64) {
        if self.providers.contains(&provider_id) {
            self.last_active_provider = Some(provider_id);
        }
    }

    /// Handle a program being opened.
    pub fn program_opened(&mut self, program: ProgramInfo) {
        self.fire_event(PluginEvent::ProgramOpened { program });
    }

    /// Handle a program being closed.
    pub fn program_closed(&mut self, program: ProgramInfo) {
        self.fire_event(PluginEvent::ProgramClosed { program });
    }

    /// Handle a function being removed.
    pub fn function_removed(&mut self, function: FunctionInfo) {
        self.fire_event(PluginEvent::FunctionRemoved { function });
    }

    /// Get the number of active providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Check if there are any active providers.
    pub fn has_providers(&self) -> bool {
        !self.providers.is_empty()
    }

    /// Get the last active provider ID.
    pub fn last_active_provider(&self) -> Option<u64> {
        self.last_active_provider
    }

    /// Get the comparison panel state.
    pub fn comparison_state(&self) -> &ComparisonPanelState {
        &self.comparison_state
    }

    /// Get a mutable reference to the comparison panel state.
    pub fn comparison_state_mut(&mut self) -> &mut ComparisonPanelState {
        &mut self.comparison_state
    }

    /// Get all active provider IDs.
    pub fn active_providers(&self) -> Vec<u64> {
        self.providers.iter().copied().collect()
    }

    /// Dispose of the plugin.
    pub fn dispose(&mut self) {
        let provider_ids: Vec<u64> = self.providers.iter().copied().collect();
        for id in provider_ids {
            self.close_provider(id);
        }
        self.listeners.clear();
    }
}

impl Default for FunctionComparisonPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple listener that tracks plugin events.
#[derive(Debug, Default)]
pub struct TrackingPluginListener {
    /// Recorded events.
    pub events: std::sync::Mutex<Vec<PluginEvent>>,
}

impl TrackingPluginListener {
    /// Create a new tracking listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of events received.
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl PluginEventListener for TrackingPluginListener {
    fn on_event(&self, event: &PluginEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_func(id: u64, name: &str, program: &str, entry: u64) -> FunctionInfo {
        FunctionInfo::new(id, name, program, entry)
    }

    fn make_program(id: u64, path: &str, name: &str) -> ProgramInfo {
        ProgramInfo::new(id, path, name)
    }

    // --- ComparisonAction tests ---

    #[test]
    fn test_comparison_action_label() {
        assert_eq!(ComparisonAction::CompareFunctions.label(), "Compare Function(s)");
        assert_eq!(ComparisonAction::NextFunction.label(), "Compare Next Function");
    }

    #[test]
    fn test_comparison_action_description() {
        assert!(!ComparisonAction::CompareFunctions.description().is_empty());
        assert!(!ComparisonAction::RemoveActiveFunction.description().is_empty());
    }

    #[test]
    fn test_comparison_action_key_binding() {
        assert_eq!(ComparisonAction::NextFunction.key_binding(), Some("ctrl+shift+N"));
        assert_eq!(ComparisonAction::PreviousFunction.key_binding(), Some("ctrl+shift+P"));
        assert_eq!(ComparisonAction::RemoveActiveFunction.key_binding(), Some("ctrl+shift+R"));
        assert_eq!(ComparisonAction::CompareFunctions.key_binding(), None);
    }

    #[test]
    fn test_comparison_action_popup_menu_group() {
        assert_eq!(ComparisonAction::CompareFunctions.popup_menu_group(), "Functions");
        assert_eq!(
            ComparisonAction::AddToComparison.popup_menu_group(),
            "A9_AddToComparison"
        );
    }

    // --- FunctionComparisonPlugin tests ---

    #[test]
    fn test_plugin_new() {
        let plugin = FunctionComparisonPlugin::new();
        assert_eq!(plugin.provider_count(), 0);
        assert!(!plugin.has_providers());
        assert!(plugin.last_active_provider().is_none());
    }

    #[test]
    fn test_plugin_create_comparison() {
        let mut plugin = FunctionComparisonPlugin::new();
        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);

        let provider_id = plugin.create_comparison(vec![f1, f2]);
        assert!(provider_id.is_some());
        assert_eq!(plugin.provider_count(), 1);
        assert!(plugin.has_providers());
        assert_eq!(plugin.last_active_provider(), provider_id);
    }

    #[test]
    fn test_plugin_create_comparison_empty() {
        let mut plugin = FunctionComparisonPlugin::new();
        let provider_id = plugin.create_comparison(vec![]);
        assert!(provider_id.is_none());
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_plugin_create_comparison_pair() {
        let mut plugin = FunctionComparisonPlugin::new();
        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);

        let provider_id = plugin.create_comparison_pair(f1, f2);
        assert_eq!(plugin.provider_count(), 1);
        assert_eq!(plugin.last_active_provider(), Some(provider_id));
    }

    #[test]
    fn test_plugin_close_provider() {
        let mut plugin = FunctionComparisonPlugin::new();
        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);

        let provider_id = plugin.create_comparison(vec![f1, f2]).unwrap();
        assert_eq!(plugin.provider_count(), 1);

        plugin.close_provider(provider_id);
        assert_eq!(plugin.provider_count(), 0);
        assert!(!plugin.has_providers());
        assert!(plugin.last_active_provider().is_none());
    }

    #[test]
    fn test_plugin_close_nonexistent_provider() {
        let mut plugin = FunctionComparisonPlugin::new();
        plugin.close_provider(999);
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_plugin_multiple_providers() {
        let mut plugin = FunctionComparisonPlugin::new();

        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);
        let id1 = plugin.create_comparison(vec![f1, f2]).unwrap();

        let f3 = make_func(3, "foo", "/prog", 0x3000);
        let f4 = make_func(4, "bar", "/prog", 0x4000);
        let id2 = plugin.create_comparison(vec![f3, f4]).unwrap();

        assert_eq!(plugin.provider_count(), 2);
        assert_eq!(plugin.last_active_provider(), Some(id2));

        plugin.close_provider(id1);
        assert_eq!(plugin.provider_count(), 1);
        assert_eq!(plugin.last_active_provider(), Some(id2));
    }

    #[test]
    fn test_plugin_provider_activated() {
        let mut plugin = FunctionComparisonPlugin::new();

        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);
        let id1 = plugin.create_comparison(vec![f1, f2]).unwrap();

        let f3 = make_func(3, "foo", "/prog", 0x3000);
        let f4 = make_func(4, "bar", "/prog", 0x4000);
        let id2 = plugin.create_comparison(vec![f3, f4]).unwrap();

        assert_eq!(plugin.last_active_provider(), Some(id2));

        plugin.provider_activated(id1);
        assert_eq!(plugin.last_active_provider(), Some(id1));
    }

    #[test]
    fn test_plugin_add_to_comparison() {
        let mut plugin = FunctionComparisonPlugin::new();
        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);

        let provider_id = plugin.add_to_comparison(vec![f1, f2]);
        assert!(provider_id.is_some());
        assert_eq!(plugin.provider_count(), 1);
    }

    #[test]
    fn test_plugin_program_events() {
        let mut plugin = FunctionComparisonPlugin::new();
        let listener = Arc::new(TrackingPluginListener::new());
        plugin.add_listener(listener.clone());

        let prog = make_program(1, "/test", "test");
        plugin.program_opened(prog.clone());
        plugin.program_closed(prog);

        assert_eq!(listener.event_count(), 2);
    }

    #[test]
    fn test_plugin_function_removed() {
        let mut plugin = FunctionComparisonPlugin::new();
        let listener = Arc::new(TrackingPluginListener::new());
        plugin.add_listener(listener.clone());

        let func = make_func(1, "main", "/prog", 0x1000);
        plugin.function_removed(func);

        assert_eq!(listener.event_count(), 1);
    }

    #[test]
    fn test_plugin_active_providers() {
        let mut plugin = FunctionComparisonPlugin::new();

        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);
        plugin.create_comparison(vec![f1, f2]);

        let f3 = make_func(3, "foo", "/prog", 0x3000);
        let f4 = make_func(4, "bar", "/prog", 0x4000);
        plugin.create_comparison(vec![f3, f4]);

        let providers = plugin.active_providers();
        assert_eq!(providers.len(), 2);
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = FunctionComparisonPlugin::new();

        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);
        plugin.create_comparison(vec![f1, f2]);

        plugin.dispose();
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_plugin_default() {
        let plugin = FunctionComparisonPlugin::default();
        assert_eq!(plugin.provider_count(), 0);
    }

    // --- ProviderInfo tests ---

    #[test]
    fn test_model_type() {
        assert_eq!(ModelType::AnyToAny, ModelType::AnyToAny);
        assert_ne!(ModelType::AnyToAny, ModelType::Matched);
    }

    // --- TrackingPluginListener tests ---

    #[test]
    fn test_tracking_plugin_listener() {
        let listener = TrackingPluginListener::new();
        assert_eq!(listener.event_count(), 0);

        listener.on_event(&PluginEvent::ProviderCreated { provider_id: 1 });
        listener.on_event(&PluginEvent::ProviderClosed { provider_id: 1 });
        assert_eq!(listener.event_count(), 2);
    }
}
