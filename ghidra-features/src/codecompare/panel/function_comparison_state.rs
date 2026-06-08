//! Function comparison state management.
//!
//! Ported from Ghidra's `FunctionComparisonState` and `CodeComparisonViewState`
//! Java classes in `ghidra.features.base.codecompare.panel`.
//!
//! This module provides top-level state management for the function comparison
//! panel. It coordinates per-view save state, panel-level configuration
//! (active tab, scroll lock, orientation), and notifies registered callbacks
//! when the state changes externally (e.g., when the tool restores saved state).
//!
//! In the original Java, `FunctionComparisonState` holds a `SaveState` for
//! panel-level settings and a `CodeComparisonViewState` that maps each
//! `CodeComparisonView` class to its own `SaveState`. The `CodeComparisonViewState`
//! uses `ClassSearcher` to discover view classes by name. In this Rust port,
//! we use string keys instead of class references.
//!
//! # Key types
//!
//! - [`ViewTypeSaveState`] -- per-view-type save state
//! - [`CodeComparisonViewStateRegistry`] -- registry mapping view type names to save states
//! - [`FunctionComparisonState`] -- top-level comparison panel state

use std::collections::HashMap;

use super::{ComparisonPanelState, ComparisonViewState};

/// A save state for a specific type of comparison view.
///
/// In the Java original, this is a `SaveState` associated with a
/// `CodeComparisonView` class. Here we use the view type name as the key.
#[derive(Debug, Clone)]
pub struct ViewTypeSaveState {
    /// The view type name (e.g., "Listing View", "Decompiler View").
    pub view_type: String,
    /// The save state values.
    pub state: ComparisonViewState,
}

impl ViewTypeSaveState {
    /// Create a new view type save state.
    pub fn new(view_type: impl Into<String>) -> Self {
        Self {
            view_type: view_type.into(),
            state: ComparisonViewState::new(),
        }
    }

    /// Get the view type name.
    pub fn view_type(&self) -> &str {
        &self.view_type
    }

    /// Get a reference to the state.
    pub fn state(&self) -> &ComparisonViewState {
        &self.state
    }

    /// Get a mutable reference to the state.
    pub fn state_mut(&mut self) -> &mut ComparisonViewState {
        &mut self.state
    }
}

/// Registry mapping view type names to their save states.
///
/// This is the Rust equivalent of Ghidra's `CodeComparisonViewState` Java class,
/// which maps `Class<? extends CodeComparisonView>` to `SaveState`. Here we
/// use string keys (view type names) instead of class references.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::panel::function_comparison_state::*;
///
/// let mut registry = CodeComparisonViewStateRegistry::new();
///
/// // Get or create a save state for a view type
/// let state = registry.get_or_create("Listing View");
/// state.state_mut().set_bool("show_bytes", true);
///
/// // Retrieve it later
/// let state = registry.get("Listing View").unwrap();
/// assert!(state.state().get_bool("show_bytes", false));
/// ```
#[derive(Debug, Clone, Default)]
pub struct CodeComparisonViewStateRegistry {
    /// Map from view type name to save state.
    states: HashMap<String, ViewTypeSaveState>,
}

impl CodeComparisonViewStateRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the save state for a view type, or create it if it doesn't exist.
    pub fn get_or_create(&mut self, view_type: &str) -> &mut ViewTypeSaveState {
        self.states
            .entry(view_type.to_string())
            .or_insert_with(|| ViewTypeSaveState::new(view_type))
    }

    /// Get the save state for a view type, if it exists.
    pub fn get(&self, view_type: &str) -> Option<&ViewTypeSaveState> {
        self.states.get(view_type)
    }

    /// Check if a view type has a save state.
    pub fn contains(&self, view_type: &str) -> bool {
        self.states.contains_key(view_type)
    }

    /// Get all registered view type names.
    pub fn view_types(&self) -> Vec<&String> {
        self.states.keys().collect()
    }

    /// Get the number of registered view types.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Serialize all states to a simple string representation.
    pub fn to_string_repr(&self) -> String {
        let mut parts = Vec::new();
        for (name, view_state) in &self.states {
            let state_str = view_state.state().to_string_repr();
            parts.push(format!("{}:{}", name, state_str));
        }
        parts.join("|")
    }

    /// Restore states from a simple string representation.
    pub fn from_string_repr(s: &str) -> Self {
        let mut registry = Self::new();
        for part in s.split('|') {
            if let Some((name, state_str)) = part.split_once(':') {
                let view_state = ViewTypeSaveState {
                    view_type: name.to_string(),
                    state: ComparisonViewState::from_string_repr(state_str),
                };
                registry.states.insert(name.to_string(), view_state);
            }
        }
        registry
    }
}

/// Top-level state for the function comparison panel.
///
/// Manages panel-level configuration (active tab, scroll lock, orientation)
/// and per-view-type save state. Notifies registered callbacks when the
/// state changes externally.
///
/// Ported from Ghidra's `FunctionComparisonState` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::panel::function_comparison_state::*;
/// use ghidra_features::codecompare::panel::ComparisonPanelState;
///
/// let mut state = FunctionComparisonState::new();
///
/// // Panel state
/// state.panel_state_mut().active_view = "Listing".to_string();
/// state.panel_state_mut().scroll_sync = true;
///
/// // View state
/// let view_state = state.view_state_mut().get_or_create("Listing View");
/// view_state.state_mut().set_bool("show_bytes", true);
///
/// // Callbacks
/// let mut callback_called = false;
/// state.add_update_callback(Box::new(|| { /* callback logic */ }));
/// ```
pub struct FunctionComparisonState {
    /// Panel-level state (active tab, scroll lock, orientations).
    panel_state: ComparisonPanelState,
    /// Per-view-type save state registry.
    view_state: CodeComparisonViewStateRegistry,
    /// Callbacks to notify when state is restored externally.
    update_callbacks: Vec<Box<dyn Fn() + Send + Sync>>,
    /// Whether the state has been modified since last save.
    changed: bool,
}

impl std::fmt::Debug for FunctionComparisonState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionComparisonState")
            .field("panel_state", &self.panel_state)
            .field("view_state", &self.view_state)
            .field("changed", &self.changed)
            .finish()
    }
}

impl FunctionComparisonState {
    /// Create a new function comparison state with defaults.
    pub fn new() -> Self {
        Self {
            panel_state: ComparisonPanelState::new(),
            view_state: CodeComparisonViewStateRegistry::new(),
            update_callbacks: Vec::new(),
            changed: false,
        }
    }

    /// Get a reference to the panel-level state.
    pub fn panel_state(&self) -> &ComparisonPanelState {
        &self.panel_state
    }

    /// Get a mutable reference to the panel-level state.
    pub fn panel_state_mut(&mut self) -> &mut ComparisonPanelState {
        &mut self.panel_state
    }

    /// Get a reference to the view state registry.
    pub fn view_state(&self) -> &CodeComparisonViewStateRegistry {
        &self.view_state
    }

    /// Get a mutable reference to the view state registry.
    pub fn view_state_mut(&mut self) -> &mut CodeComparisonViewStateRegistry {
        &mut self.view_state
    }

    /// Signal that the state has been modified.
    pub fn set_changed(&mut self) {
        self.changed = true;
    }

    /// Check if the state has been modified since last save.
    pub fn is_changed(&self) -> bool {
        self.changed
    }

    /// Clear the changed flag (e.g., after saving).
    pub fn clear_changed(&mut self) {
        self.changed = false;
    }

    /// Add a callback to be notified when the state is restored externally.
    pub fn add_update_callback(&mut self, callback: Box<dyn Fn() + Send + Sync>) {
        self.update_callbacks.push(callback);
    }

    /// Notify all registered callbacks that the state has been restored.
    fn notify_update(&self) {
        for callback in &self.update_callbacks {
            callback();
        }
    }

    /// Serialize the entire state to a string representation.
    pub fn to_string_repr(&self) -> String {
        let panel_str = self.panel_state.to_string_repr();
        let view_str = self.view_state.to_string_repr();
        format!("PANEL:{}|VIEWS:{}", panel_str, view_str)
    }

    /// Restore state from a string representation.
    pub fn from_string_repr(s: &str) -> Self {
        let mut state = Self::new();

        for part in s.split('|') {
            if let Some(rest) = part.strip_prefix("PANEL:") {
                state.panel_state = ComparisonPanelState::from_string_repr(rest);
            } else if let Some(rest) = part.strip_prefix("VIEWS:") {
                state.view_state = CodeComparisonViewStateRegistry::from_string_repr(rest);
            }
        }

        state
    }

    /// Simulate restoring state from an external source.
    ///
    /// This is the Rust equivalent of `readConfigState` in the Java class.
    pub fn restore_state(&mut self, panel_state: ComparisonPanelState) {
        self.panel_state = panel_state;
        self.notify_update();
    }

    /// Get the active view name.
    pub fn active_view(&self) -> &str {
        &self.panel_state.active_view
    }

    /// Set the active view name.
    pub fn set_active_view(&mut self, name: impl Into<String>) {
        self.panel_state.active_view = name.into();
        self.set_changed();
    }

    /// Get the scroll sync state.
    pub fn is_scroll_sync(&self) -> bool {
        self.panel_state.scroll_sync
    }

    /// Set the scroll sync state.
    pub fn set_scroll_sync(&mut self, sync: bool) {
        self.panel_state.scroll_sync = sync;
        self.set_changed();
    }

    /// Get the orientation for a specific view.
    pub fn get_orientation(&self, view_name: &str) -> Option<bool> {
        self.panel_state.orientations.get(view_name).copied()
    }

    /// Set the orientation for a specific view.
    pub fn set_orientation(&mut self, view_name: impl Into<String>, side_by_side: bool) {
        self.panel_state
            .orientations
            .insert(view_name.into(), side_by_side);
        self.set_changed();
    }
}

impl Default for FunctionComparisonState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecompare::panel::ComparisonPanelState;

    // --- ViewTypeSaveState tests ---

    #[test]
    fn test_view_type_save_state_new() {
        let vts = ViewTypeSaveState::new("Listing View");
        assert_eq!(vts.view_type(), "Listing View");
        assert!(vts.state().is_empty());
    }

    #[test]
    fn test_view_type_save_state_access() {
        let mut vts = ViewTypeSaveState::new("Test");
        vts.state_mut().set_bool("key", true);
        assert!(vts.state().get_bool("key", false));
    }

    // --- CodeComparisonViewStateRegistry tests ---

    #[test]
    fn test_registry_new() {
        let registry = CodeComparisonViewStateRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_registry_get_or_create() {
        let mut registry = CodeComparisonViewStateRegistry::new();
        let state = registry.get_or_create("Listing View");
        state.state_mut().set_bool("show_bytes", true);

        assert_eq!(registry.len(), 1);
        assert!(registry.contains("Listing View"));
    }

    #[test]
    fn test_registry_get() {
        let mut registry = CodeComparisonViewStateRegistry::new();
        registry.get_or_create("Listing View");

        assert!(registry.get("Listing View").is_some());
        assert!(registry.get("Decompiler View").is_none());
    }

    #[test]
    fn test_registry_view_types() {
        let mut registry = CodeComparisonViewStateRegistry::new();
        registry.get_or_create("Listing View");
        registry.get_or_create("Decompiler View");

        let mut types: Vec<&String> = registry.view_types().into_iter().collect();
        types.sort();
        assert_eq!(types.len(), 2);
        assert_eq!(types[0], "Decompiler View");
        assert_eq!(types[1], "Listing View");
    }

    #[test]
    fn test_registry_serialization() {
        let mut registry = CodeComparisonViewStateRegistry::new();
        let state = registry.get_or_create("Listing View");
        state.state_mut().set_bool("show_bytes", true);
        state.state_mut().set_int("width", 80);

        let serialized = registry.to_string_repr();
        let restored = CodeComparisonViewStateRegistry::from_string_repr(&serialized);

        assert_eq!(restored.len(), 1);
        let state = restored.get("Listing View").unwrap();
        assert!(state.state().get_bool("show_bytes", false));
        assert_eq!(state.state().get_int("width", 0), 80);
    }

    // --- FunctionComparisonState tests ---

    #[test]
    fn test_function_comparison_state_new() {
        let state = FunctionComparisonState::new();
        assert_eq!(state.active_view(), "Listing");
        assert!(state.is_scroll_sync());
        assert!(!state.is_changed());
        assert!(state.view_state().is_empty());
    }

    #[test]
    fn test_function_comparison_state_active_view() {
        let mut state = FunctionComparisonState::new();
        assert_eq!(state.active_view(), "Listing");

        state.set_active_view("Decompiler");
        assert_eq!(state.active_view(), "Decompiler");
        assert!(state.is_changed());
    }

    #[test]
    fn test_function_comparison_state_scroll_sync() {
        let mut state = FunctionComparisonState::new();
        assert!(state.is_scroll_sync());

        state.set_scroll_sync(false);
        assert!(!state.is_scroll_sync());
        assert!(state.is_changed());
    }

    #[test]
    fn test_function_comparison_state_orientation() {
        let mut state = FunctionComparisonState::new();
        assert!(state.get_orientation("Listing").is_none());

        state.set_orientation("Listing", true);
        assert_eq!(state.get_orientation("Listing"), Some(true));

        state.set_orientation("Listing", false);
        assert_eq!(state.get_orientation("Listing"), Some(false));
    }

    #[test]
    fn test_function_comparison_state_changed() {
        let mut state = FunctionComparisonState::new();
        assert!(!state.is_changed());

        state.set_changed();
        assert!(state.is_changed());

        state.clear_changed();
        assert!(!state.is_changed());
    }

    #[test]
    fn test_function_comparison_state_callback() {
        let mut state = FunctionComparisonState::new();
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_clone = called.clone();

        state.add_update_callback(Box::new(move || {
            called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        let mut panel_state = ComparisonPanelState::new();
        panel_state.active_view = "Test".to_string();
        state.restore_state(panel_state);

        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_function_comparison_state_view_state() {
        let mut state = FunctionComparisonState::new();
        let view_state = state.view_state_mut().get_or_create("Listing View");
        view_state.state_mut().set_bool("show_bytes", true);

        let view_state = state.view_state().get("Listing View").unwrap();
        assert!(view_state.state().get_bool("show_bytes", false));
    }

    #[test]
    fn test_function_comparison_state_serialization() {
        let mut state = FunctionComparisonState::new();
        state.set_active_view("Decompiler");
        state.set_scroll_sync(false);
        state.set_orientation("Listing", true);

        let serialized = state.to_string_repr();
        let restored = FunctionComparisonState::from_string_repr(&serialized);

        assert_eq!(restored.active_view(), "Decompiler");
        assert!(!restored.is_scroll_sync());
        assert_eq!(restored.get_orientation("Listing"), Some(true));
    }

    #[test]
    fn test_function_comparison_state_default() {
        let state = FunctionComparisonState::default();
        assert_eq!(state.active_view(), "Listing");
        assert!(state.is_scroll_sync());
    }
}
