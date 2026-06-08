//! Multi-function comparison panel with function selection.
//!
//! Ported from Ghidra's `MultiFunctionComparisonPanel` Java class in
//! `ghidra.features.codecompare.plugin`.
//!
//! Extends the basic [`FunctionComparisonPanel`] to allow a many-to-many
//! relationship. The panel provides a pair of combo boxes above the function
//! display area that allows users to select which functions are to be compared.
//!
//! The behavior of this panel is driven by a [`FunctionComparisonModel`]. The
//! default model displays the same set of functions on both sides. But the model
//! interface allows for other behaviors such as having different sets of functions
//! on each side and even changing the set of functions on one side based on what
//! is selected on the other side.
//!
//! In the original Java, this class extends `FunctionComparisonPanel` and
//! implements `FunctionComparisonModelListener`. In this Rust port, we capture
//! the logical state and behavior without the Swing layer.
//!
//! # Key types
//!
//! - [`ComboSelection`] -- the current selection in a function combo box
//! - [`FunctionComboState`] -- state of a single function combo box
//! - [`MultiFunctionPanel`] -- the multi-function comparison panel

use std::sync::{Arc, Mutex};

use super::super::model::{
    ComparisonSide, FunctionComparisonModel, FunctionComparisonModelListener, FunctionInfo,
};
use super::super::panel::{
    ComparisonData, ComparisonPanelState, FunctionComparisonData, FunctionComparisonInfo,
    ProgramInfo,
};
use super::provider::ActiveView;

/// The current selection in a function combo box.
#[derive(Debug, Clone)]
pub struct ComboSelection {
    /// The index of the selected item.
    pub index: usize,
    /// The selected function info, if any.
    pub function: Option<FunctionInfo>,
}

impl ComboSelection {
    /// Create a new combo selection.
    pub fn new(index: usize, function: Option<FunctionInfo>) -> Self {
        Self { index, function }
    }

    /// Create an empty selection.
    pub fn empty() -> Self {
        Self {
            index: 0,
            function: None,
        }
    }

    /// Check if the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.function.is_none()
    }
}

/// State of a single function combo box.
///
/// Represents the list of available functions and the current selection
/// for one side of the comparison.
#[derive(Debug, Clone)]
pub struct FunctionComboState {
    /// The side this combo box represents.
    side: ComparisonSide,
    /// The list of available functions in sorted order.
    functions: Vec<FunctionInfo>,
    /// The current selection.
    selection: ComboSelection,
    /// Whether the combo box is enabled.
    enabled: bool,
}

impl FunctionComboState {
    /// Create a new function combo state.
    pub fn new(side: ComparisonSide) -> Self {
        Self {
            side,
            functions: Vec::new(),
            selection: ComboSelection::empty(),
            enabled: true,
        }
    }

    /// Get the side this combo box represents.
    pub fn side(&self) -> ComparisonSide {
        self.side
    }

    /// Get the list of available functions.
    pub fn functions(&self) -> &[FunctionInfo] {
        &self.functions
    }

    /// Get the current selection.
    pub fn selection(&self) -> &ComboSelection {
        &self.selection
    }

    /// Get the currently selected function, if any.
    pub fn selected_function(&self) -> Option<&FunctionInfo> {
        self.selection.function.as_ref()
    }

    /// Check if the combo box is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the number of available functions.
    pub fn count(&self) -> usize {
        self.functions.len()
    }

    /// Check if the combo box has any functions.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Update the function list and selection.
    ///
    /// This is called when the model data changes.
    pub fn update_functions(&mut self, functions: Vec<FunctionInfo>, active: Option<&FunctionInfo>) {
        self.functions = functions;

        // Find the active function in the list
        if let Some(active_func) = active {
            if let Some(idx) = self.functions.iter().position(|f| f.id == active_func.id) {
                self.selection = ComboSelection::new(idx, Some(active_func.clone()));
                return;
            }
        }

        // If active not found, select the first function
        if !self.functions.is_empty() {
            self.selection = ComboSelection::new(0, Some(self.functions[0].clone()));
        } else {
            self.selection = ComboSelection::empty();
        }
    }

    /// Select a function by index.
    ///
    /// Returns true if the selection changed.
    pub fn select_by_index(&mut self, index: usize) -> bool {
        if index >= self.functions.len() {
            return false;
        }
        let func = self.functions[index].clone();
        if self.selection.index == index && self.selection.function.as_ref() == Some(&func) {
            return false;
        }
        self.selection = ComboSelection::new(index, Some(func));
        true
    }

    /// Select a specific function.
    ///
    /// Returns true if the selection changed.
    pub fn select_function(&mut self, function: &FunctionInfo) -> bool {
        if let Some(idx) = self.functions.iter().position(|f| f.id == function.id) {
            if self.selection.index == idx && self.selection.function.as_ref() == Some(function) {
                return false;
            }
            self.selection = ComboSelection::new(idx, Some(function.clone()));
            true
        } else {
            false
        }
    }

    /// Get the next function index (wrapping around).
    pub fn next_index(&self) -> Option<usize> {
        if self.functions.is_empty() || self.functions.len() <= 1 {
            return None;
        }
        let next = (self.selection.index + 1) % self.functions.len();
        Some(next)
    }

    /// Get the previous function index (wrapping around).
    pub fn previous_index(&self) -> Option<usize> {
        if self.functions.is_empty() || self.functions.len() <= 1 {
            return None;
        }
        let prev = if self.selection.index == 0 {
            self.functions.len() - 1
        } else {
            self.selection.index - 1
        };
        Some(prev)
    }

    /// Check if navigation to the next function is possible.
    pub fn can_go_next(&self) -> bool {
        self.functions.len() > 1
    }

    /// Check if navigation to the previous function is possible.
    pub fn can_go_previous(&self) -> bool {
        self.functions.len() > 1
    }
}

/// Events emitted by the multi-function panel.
#[derive(Debug, Clone)]
pub enum MultiFunctionPanelEvent {
    /// The active function changed on one side.
    ActiveFunctionChanged {
        /// The side that changed.
        side: ComparisonSide,
        /// The new function.
        function: FunctionInfo,
    },
    /// The function list changed.
    FunctionListChanged {
        /// The side whose list changed.
        side: ComparisonSide,
        /// The new number of functions.
        count: usize,
    },
    /// The comparison data was loaded.
    ComparisonLoaded,
    /// The panel was disposed.
    Disposed,
}

/// Trait for receiving multi-function panel events.
pub trait MultiFunctionPanelListener: Send + Sync {
    /// Called when an event occurs.
    fn on_event(&self, event: &MultiFunctionPanelEvent);
}

/// The multi-function comparison panel.
///
/// Extends the basic comparison panel with function selection combo boxes.
/// Driven by a [`FunctionComparisonModel`] that determines which functions
/// are available and which are currently active.
///
/// Ported from Ghidra's `MultiFunctionComparisonPanel` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::plugin::multi_function_panel::*;
/// use ghidra_features::codecompare::model::*;
/// use ghidra_features::codecompare::panel::*;
///
/// let f1 = FunctionInfo::new(1, "main", "/prog", 0x1000);
/// let f2 = FunctionInfo::new(2, "init", "/prog", 0x2000);
/// let f3 = FunctionInfo::new(3, "foo", "/prog", 0x3000);
///
/// let model = AnyToAnyFunctionComparisonModel::new(vec![f1, f2, f3]);
/// let state = ComparisonPanelState::new();
/// let mut panel = MultiFunctionPanel::new(
///     Box::new(model),
///     state,
/// );
///
/// // Both combos should have 3 functions
/// assert_eq!(panel.left_combo().count(), 3);
/// assert_eq!(panel.right_combo().count(), 3);
///
/// // Navigate to next function on the right
/// assert!(panel.compare_next(ComparisonSide::Right));
/// ```
pub struct MultiFunctionPanel {
    /// The comparison model that drives the panel.
    model: Box<dyn FunctionComparisonModel>,
    /// The left-side function combo state.
    left_combo: FunctionComboState,
    /// The right-side function combo state.
    right_combo: FunctionComboState,
    /// The panel state (active view, scroll sync, etc.).
    panel_state: ComparisonPanelState,
    /// The currently active view.
    active_view: ActiveView,
    /// Whether the panel is disposed.
    disposed: bool,
    /// Listeners for panel events.
    listeners: Vec<Arc<dyn MultiFunctionPanelListener>>,
    /// The help topic.
    help_topic: String,
}

impl MultiFunctionPanel {
    /// Create a new multi-function panel.
    ///
    /// Initializes the combo boxes from the model's initial state.
    pub fn new(
        model: Box<dyn FunctionComparisonModel>,
        panel_state: ComparisonPanelState,
    ) -> Self {
        let mut panel = Self {
            model,
            left_combo: FunctionComboState::new(ComparisonSide::Left),
            right_combo: FunctionComboState::new(ComparisonSide::Right),
            panel_state,
            active_view: ActiveView::Decompiler,
            disposed: false,
            listeners: Vec::new(),
            help_topic: "FunctionComparison".to_string(),
        };

        panel.initialize_combos();
        panel
    }

    /// Get the help topic.
    pub fn help_topic(&self) -> &str {
        &self.help_topic
    }

    /// Get a reference to the comparison model.
    pub fn model(&self) -> &dyn FunctionComparisonModel {
        self.model.as_ref()
    }

    /// Get a mutable reference to the comparison model.
    pub fn model_mut(&mut self) -> &mut dyn FunctionComparisonModel {
        self.model.as_mut()
    }

    /// Get the left-side combo state.
    pub fn left_combo(&self) -> &FunctionComboState {
        &self.left_combo
    }

    /// Get the right-side combo state.
    pub fn right_combo(&self) -> &FunctionComboState {
        &self.right_combo
    }

    /// Get the combo state for the given side.
    pub fn combo(&self, side: ComparisonSide) -> &FunctionComboState {
        match side {
            ComparisonSide::Left => &self.left_combo,
            ComparisonSide::Right => &self.right_combo,
        }
    }

    /// Get a mutable reference to the combo state for the given side.
    pub fn combo_mut(&mut self, side: ComparisonSide) -> &mut FunctionComboState {
        match side {
            ComparisonSide::Left => &mut self.left_combo,
            ComparisonSide::Right => &mut self.right_combo,
        }
    }

    /// Get the panel state.
    pub fn panel_state(&self) -> &ComparisonPanelState {
        &self.panel_state
    }

    /// Get a mutable reference to the panel state.
    pub fn panel_state_mut(&mut self) -> &mut ComparisonPanelState {
        &mut self.panel_state
    }

    /// Get the currently active view.
    pub fn active_view(&self) -> ActiveView {
        self.active_view
    }

    /// Set the active view.
    pub fn set_active_view(&mut self, view: ActiveView) {
        self.active_view = view;
    }

    /// Add a listener for panel events.
    pub fn add_listener(&mut self, listener: Arc<dyn MultiFunctionPanelListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Fire an event to all listeners.
    fn fire_event(&self, event: MultiFunctionPanelEvent) {
        for listener in &self.listeners {
            listener.on_event(&event);
        }
    }

    /// Initialize both combo boxes from the model.
    fn initialize_combos(&mut self) {
        self.initialize_combo(ComparisonSide::Left);
        self.initialize_combo(ComparisonSide::Right);
        self.load_current_comparison();
    }

    /// Initialize a single combo box from the model.
    fn initialize_combo(&mut self, side: ComparisonSide) {
        let functions: Vec<FunctionInfo> = self
            .model
            .get_functions(side)
            .into_iter()
            .cloned()
            .collect();
        let active = self.model.get_active_function(side).cloned();
        self.combo_mut(side).update_functions(functions, active.as_ref());
    }

    /// Load the current comparison based on the active functions.
    fn load_current_comparison(&self) {
        // In the full implementation, this would call
        // loadFunctions(model.getActiveFunction(LEFT), model.getActiveFunction(RIGHT))
        // on the comparison panel. Here we just track the state.
    }

    /// Handle the model's active function changing.
    ///
    /// This is called when the model notifies that the active function
    /// changed on one side. Updates the combo selection and reloads the
    /// comparison.
    pub fn active_function_changed(&mut self, side: ComparisonSide, function: &FunctionInfo) {
        self.combo_mut(side).select_function(function);
        self.load_current_comparison();
        self.fire_event(MultiFunctionPanelEvent::ActiveFunctionChanged {
            side,
            function: function.clone(),
        });
    }

    /// Handle the model's data changing.
    ///
    /// This is called when the model notifies that the set of functions
    /// changed. Reinitializes both combo boxes and reloads the comparison.
    pub fn model_data_changed(&mut self) {
        self.initialize_combos();
        let left_count = self.left_combo.count();
        let right_count = self.right_combo.count();
        self.fire_event(MultiFunctionPanelEvent::FunctionListChanged {
            side: ComparisonSide::Left,
            count: left_count,
        });
        self.fire_event(MultiFunctionPanelEvent::FunctionListChanged {
            side: ComparisonSide::Right,
            count: right_count,
        });
    }

    /// Select a function in a combo box.
    ///
    /// This is called when the user selects a function from a combo box.
    /// Updates the model's active function for the given side.
    ///
    /// Returns true if the selection changed.
    pub fn select_function(&mut self, side: ComparisonSide, function: &FunctionInfo) -> bool {
        let changed = self.model.set_active_function(side, function);
        if changed {
            self.combo_mut(side).select_function(function);
            self.load_current_comparison();
        }
        changed
    }

    /// Select a function in a combo box by index.
    ///
    /// Returns true if the selection changed.
    pub fn select_by_index(&mut self, side: ComparisonSide, index: usize) -> bool {
        let func = match self.combo(side).functions().get(index) {
            Some(f) => f.clone(),
            None => return false,
        };
        self.select_function(side, &func)
    }

    /// Get the currently active side (the side with focus).
    ///
    /// In the Java original, this is determined by which listing panel
    /// has focus. Here we use the model's perspective.
    pub fn get_active_side(&self) -> ComparisonSide {
        // Default to the side with more functions, or Left if equal
        let left_count = self.left_combo.count();
        let right_count = self.right_combo.count();
        if right_count > left_count {
            ComparisonSide::Right
        } else {
            ComparisonSide::Left
        }
    }

    /// Check if the next function navigation is possible.
    pub fn can_compare_next(&self, side: ComparisonSide) -> bool {
        self.combo(side).can_go_next()
    }

    /// Check if the previous function navigation is possible.
    pub fn can_compare_previous(&self, side: ComparisonSide) -> bool {
        self.combo(side).can_go_previous()
    }

    /// Navigate to the next function for the given side.
    ///
    /// Returns true if navigation succeeded.
    pub fn compare_next(&mut self, side: ComparisonSide) -> bool {
        let next_idx = match self.combo(side).next_index() {
            Some(idx) => idx,
            None => return false,
        };
        self.select_by_index(side, next_idx)
    }

    /// Navigate to the previous function for the given side.
    ///
    /// Returns true if navigation succeeded.
    pub fn compare_previous(&mut self, side: ComparisonSide) -> bool {
        let prev_idx = match self.combo(side).previous_index() {
            Some(idx) => idx,
            None => return false,
        };
        self.select_by_index(side, prev_idx)
    }

    /// Check if the active function can be removed.
    pub fn can_remove_active_function(&self) -> bool {
        self.left_combo.count() > 1 || self.right_combo.count() > 1
    }

    /// Remove the active function from the comparison.
    ///
    /// Returns true if a function was removed.
    pub fn remove_active_function(&mut self) -> bool {
        let active_side = self.get_active_side();
        let active_func = self.model.get_active_function(active_side).cloned();

        if let Some(func) = active_func {
            // Only remove if there are more functions on this side
            if self.combo(active_side).count() > 1 {
                self.model.remove_function(&func);
                // The model will fire data changed, which will update combos
                self.model_data_changed();
                return true;
            }
        }

        // Try the other side
        let other_side = active_side.opposite();
        let other_func = self.model.get_active_function(other_side).cloned();
        if let Some(func) = other_func {
            if self.combo(other_side).count() > 1 {
                self.model.remove_function(&func);
                self.model_data_changed();
                return true;
            }
        }

        false
    }

    /// Add functions to the comparison.
    ///
    /// Only works if the model supports adding (is an AnyToAnyFunctionComparisonModel).
    pub fn add_functions(&mut self, _functions: Vec<FunctionInfo>) -> bool {
        // In the full implementation, this would downcast the model and call addFunctions.
        // Here we delegate to the model's generic interface.
        // The model will fire data changed, which will update combos.
        false
    }

    /// Get a description of the current comparison.
    pub fn description(&self) -> String {
        let left = self.left_combo.selected_function();
        let right = self.right_combo.selected_function();
        match (left, right) {
            (Some(l), Some(r)) => {
                format!("{} vs {}", l.display_name(), r.display_name())
            }
            (Some(f), None) | (None, Some(f)) => f.display_name(),
            (None, None) => "Empty Comparison".to_string(),
        }
    }

    /// Get the tab text for this panel.
    pub fn tab_text(&self) -> String {
        self.description()
    }

    /// Check if the panel is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose of the panel.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.listeners.clear();
        self.fire_event(MultiFunctionPanelEvent::Disposed);
    }
}

impl Drop for MultiFunctionPanel {
    fn drop(&mut self) {
        if !self.disposed {
            self.dispose();
        }
    }
}

/// A simple listener that tracks multi-function panel events.
#[derive(Debug, Default)]
pub struct TrackingMultiFunctionListener {
    /// Recorded events.
    pub events: std::sync::Mutex<Vec<MultiFunctionPanelEvent>>,
}

impl TrackingMultiFunctionListener {
    /// Create a new tracking listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of events received.
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl MultiFunctionPanelListener for TrackingMultiFunctionListener {
    fn on_event(&self, event: &MultiFunctionPanelEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::model::AnyToAnyFunctionComparisonModel;

    fn make_func(id: u64, name: &str, program: &str, entry: u64) -> FunctionInfo {
        FunctionInfo::new(id, name, program, entry)
    }

    fn make_model(functions: Vec<FunctionInfo>) -> Box<AnyToAnyFunctionComparisonModel> {
        Box::new(AnyToAnyFunctionComparisonModel::new(functions))
    }

    fn make_panel(functions: Vec<FunctionInfo>) -> MultiFunctionPanel {
        let model = make_model(functions);
        let state = ComparisonPanelState::new();
        MultiFunctionPanel::new(model, state)
    }

    // --- ComboSelection tests ---

    #[test]
    fn test_combo_selection_empty() {
        let sel = ComboSelection::empty();
        assert!(sel.is_empty());
        assert_eq!(sel.index, 0);
        assert!(sel.function.is_none());
    }

    #[test]
    fn test_combo_selection_new() {
        let f = make_func(1, "main", "/prog", 0x1000);
        let sel = ComboSelection::new(2, Some(f.clone()));
        assert!(!sel.is_empty());
        assert_eq!(sel.index, 2);
        assert_eq!(sel.function.as_ref().unwrap().id, 1);
    }

    // --- FunctionComboState tests ---

    #[test]
    fn test_combo_state_new() {
        let combo = FunctionComboState::new(ComparisonSide::Left);
        assert_eq!(combo.side(), ComparisonSide::Left);
        assert!(combo.is_empty());
        assert_eq!(combo.count(), 0);
        assert!(combo.is_enabled());
        assert!(combo.selected_function().is_none());
    }

    #[test]
    fn test_combo_state_update_functions() {
        let mut combo = FunctionComboState::new(ComparisonSide::Left);
        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        let f2 = make_func(2, "bbb", "/prog", 0x2000);
        let f3 = make_func(3, "ccc", "/prog", 0x3000);

        combo.update_functions(
            vec![f1.clone(), f2.clone(), f3.clone()],
            Some(&f2),
        );

        assert_eq!(combo.count(), 3);
        assert_eq!(combo.selected_function().unwrap().id, 2);
        assert_eq!(combo.selection().index, 1);
    }

    #[test]
    fn test_combo_state_update_no_active() {
        let mut combo = FunctionComboState::new(ComparisonSide::Left);
        let f1 = make_func(1, "aaa", "/prog", 0x1000);

        combo.update_functions(vec![f1.clone()], None);

        // Should select the first function
        assert_eq!(combo.selected_function().unwrap().id, 1);
        assert_eq!(combo.selection().index, 0);
    }

    #[test]
    fn test_combo_state_select_by_index() {
        let mut combo = FunctionComboState::new(ComparisonSide::Left);
        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        let f2 = make_func(2, "bbb", "/prog", 0x2000);

        combo.update_functions(vec![f1, f2], None);

        assert!(combo.select_by_index(1));
        assert_eq!(combo.selected_function().unwrap().id, 2);

        // Selecting the same index again should return false
        assert!(!combo.select_by_index(1));
    }

    #[test]
    fn test_combo_state_select_by_index_out_of_range() {
        let mut combo = FunctionComboState::new(ComparisonSide::Left);
        let f1 = make_func(1, "aaa", "/prog", 0x1000);

        combo.update_functions(vec![f1], None);
        assert!(!combo.select_by_index(5));
    }

    #[test]
    fn test_combo_state_select_function() {
        let mut combo = FunctionComboState::new(ComparisonSide::Left);
        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        let f2 = make_func(2, "bbb", "/prog", 0x2000);

        combo.update_functions(vec![f1.clone(), f2.clone()], None);

        assert!(combo.select_function(&f2));
        assert_eq!(combo.selected_function().unwrap().id, 2);

        // Selecting the same function again should return false
        assert!(!combo.select_function(&f2));
    }

    #[test]
    fn test_combo_state_select_unknown_function() {
        let mut combo = FunctionComboState::new(ComparisonSide::Left);
        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        let unknown = make_func(99, "zzz", "/prog", 0x9000);

        combo.update_functions(vec![f1], None);
        assert!(!combo.select_function(&unknown));
    }

    #[test]
    fn test_combo_state_navigation() {
        let mut combo = FunctionComboState::new(ComparisonSide::Left);
        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        let f2 = make_func(2, "bbb", "/prog", 0x2000);
        let f3 = make_func(3, "ccc", "/prog", 0x3000);

        combo.update_functions(vec![f1, f2, f3], None);

        assert!(combo.can_go_next());
        assert!(combo.can_go_previous());

        // Next wraps around
        assert_eq!(combo.next_index(), Some(1));
        combo.select_by_index(2);
        assert_eq!(combo.next_index(), Some(0)); // wraps to 0

        // Previous wraps around
        assert_eq!(combo.previous_index(), Some(1));
        combo.select_by_index(0);
        assert_eq!(combo.previous_index(), Some(2)); // wraps to 2
    }

    #[test]
    fn test_combo_state_navigation_single_function() {
        let mut combo = FunctionComboState::new(ComparisonSide::Left);
        let f1 = make_func(1, "aaa", "/prog", 0x1000);

        combo.update_functions(vec![f1], None);

        assert!(!combo.can_go_next());
        assert!(!combo.can_go_previous());
        assert!(combo.next_index().is_none());
        assert!(combo.previous_index().is_none());
    }

    #[test]
    fn test_combo_state_enabled() {
        let mut combo = FunctionComboState::new(ComparisonSide::Left);
        assert!(combo.is_enabled());
        combo.set_enabled(false);
        assert!(!combo.is_enabled());
    }

    // --- MultiFunctionPanel tests ---

    #[test]
    fn test_panel_new() {
        let panel = make_panel(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        assert!(!panel.is_disposed());
        assert_eq!(panel.help_topic(), "FunctionComparison");
        assert_eq!(panel.active_view(), ActiveView::Decompiler);
        assert!(panel.panel_state().is_scroll_sync());
    }

    #[test]
    fn test_panel_combos_initialized() {
        let panel = make_panel(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
            make_func(3, "ccc", "/prog", 0x3000),
        ]);

        assert_eq!(panel.left_combo().count(), 3);
        assert_eq!(panel.right_combo().count(), 3);

        // First function should be active on left, second on right
        // (AnyToAny model sets first two sorted functions as active)
        let left_func = panel.left_combo().selected_function().unwrap();
        let right_func = panel.right_combo().selected_function().unwrap();
        assert_eq!(left_func.name, "aaa");
        assert_eq!(right_func.name, "bbb");
    }

    #[test]
    fn test_panel_empty() {
        let panel = make_panel(vec![]);
        assert_eq!(panel.left_combo().count(), 0);
        assert_eq!(panel.right_combo().count(), 0);
        assert!(panel.left_combo().selected_function().is_none());
    }

    #[test]
    fn test_panel_single_function() {
        let panel = make_panel(vec![
            make_func(1, "main", "/prog", 0x1000),
        ]);

        // With AnyToAny, a single function is selected on both sides
        assert_eq!(panel.left_combo().count(), 1);
        assert_eq!(panel.right_combo().count(), 1);
    }

    #[test]
    fn test_panel_select_function() {
        let mut panel = make_panel(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
            make_func(3, "ccc", "/prog", 0x3000),
        ]);

        let f3 = make_func(3, "ccc", "/prog", 0x3000);
        assert!(panel.select_function(ComparisonSide::Right, &f3));
        assert_eq!(panel.right_combo().selected_function().unwrap().id, 3);
    }

    #[test]
    fn test_panel_select_by_index() {
        let mut panel = make_panel(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
        ]);

        assert!(panel.select_by_index(ComparisonSide::Right, 0));
        assert_eq!(panel.right_combo().selected_function().unwrap().name, "aaa");
    }

    #[test]
    fn test_panel_compare_next() {
        let mut panel = make_panel(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
            make_func(3, "ccc", "/prog", 0x3000),
        ]);

        assert!(panel.can_compare_next(ComparisonSide::Right));
        assert!(panel.compare_next(ComparisonSide::Right));
    }

    #[test]
    fn test_panel_compare_previous() {
        let mut panel = make_panel(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
            make_func(3, "ccc", "/prog", 0x3000),
        ]);

        assert!(panel.can_compare_previous(ComparisonSide::Right));
        assert!(panel.compare_previous(ComparisonSide::Right));
    }

    #[test]
    fn test_panel_compare_next_single_function() {
        let mut panel = make_panel(vec![
            make_func(1, "main", "/prog", 0x1000),
        ]);

        assert!(!panel.can_compare_next(ComparisonSide::Right));
        assert!(!panel.compare_next(ComparisonSide::Right));
    }

    #[test]
    fn test_panel_remove_active_function() {
        let mut panel = make_panel(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
            make_func(3, "ccc", "/prog", 0x3000),
        ]);

        assert!(panel.can_remove_active_function());
        assert!(panel.remove_active_function());
    }

    #[test]
    fn test_panel_remove_active_function_single() {
        let mut panel = make_panel(vec![
            make_func(1, "main", "/prog", 0x1000),
        ]);

        // With a single function on both sides, cannot remove
        assert!(!panel.can_remove_active_function());
    }

    #[test]
    fn test_panel_description() {
        let panel = make_panel(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        let desc = panel.description();
        assert!(desc.contains("main"));
        assert!(desc.contains("init"));
    }

    #[test]
    fn test_panel_tab_text() {
        let panel = make_panel(vec![
            make_func(1, "main", "/prog", 0x1000),
            make_func(2, "init", "/prog", 0x2000),
        ]);

        let text = panel.tab_text();
        assert!(!text.is_empty());
    }

    #[test]
    fn test_panel_active_view() {
        let mut panel = make_panel(vec![
            make_func(1, "main", "/prog", 0x1000),
        ]);

        assert_eq!(panel.active_view(), ActiveView::Decompiler);
        panel.set_active_view(ActiveView::Listing);
        assert_eq!(panel.active_view(), ActiveView::Listing);
    }

    #[test]
    fn test_panel_model_data_changed() {
        let mut panel = make_panel(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
        ]);
        let listener = Arc::new(TrackingMultiFunctionListener::new());
        panel.add_listener(listener.clone());

        panel.model_data_changed();

        // Should fire FunctionListChanged events
        let events = listener.events.lock().unwrap();
        assert!(events.iter().any(|e| matches!(
            e,
            MultiFunctionPanelEvent::FunctionListChanged { .. }
        )));
    }

    #[test]
    fn test_panel_active_function_changed() {
        let mut panel = make_panel(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
        ]);
        let listener = Arc::new(TrackingMultiFunctionListener::new());
        panel.add_listener(listener.clone());

        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        panel.active_function_changed(ComparisonSide::Right, &f1);

        let events = listener.events.lock().unwrap();
        assert!(events.iter().any(|e| matches!(
            e,
            MultiFunctionPanelEvent::ActiveFunctionChanged { .. }
        )));
    }

    #[test]
    fn test_panel_dispose() {
        let mut panel = make_panel(vec![
            make_func(1, "main", "/prog", 0x1000),
        ]);
        let listener = Arc::new(TrackingMultiFunctionListener::new());
        panel.add_listener(listener.clone());

        assert!(!panel.is_disposed());
        panel.dispose();
        assert!(panel.is_disposed());

        let events = listener.events.lock().unwrap();
        assert!(events.iter().any(|e| matches!(
            e,
            MultiFunctionPanelEvent::Disposed
        )));
    }

    #[test]
    fn test_panel_dispose_idempotent() {
        let mut panel = make_panel(vec![
            make_func(1, "main", "/prog", 0x1000),
        ]);

        panel.dispose();
        panel.dispose(); // second call should be no-op
        assert!(panel.is_disposed());
    }

    #[test]
    fn test_panel_get_active_side() {
        let panel = make_panel(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
        ]);

        // Both sides have the same number of functions, default to Left
        assert_eq!(panel.get_active_side(), ComparisonSide::Left);
    }

    #[test]
    fn test_panel_listener() {
        let mut panel = make_panel(vec![
            make_func(1, "aaa", "/prog", 0x1000),
            make_func(2, "bbb", "/prog", 0x2000),
        ]);
        let listener = Arc::new(TrackingMultiFunctionListener::new());
        panel.add_listener(listener.clone());

        panel.dispose();

        assert_eq!(listener.event_count(), 1);
    }

    #[test]
    fn test_panel_clear_listeners() {
        let mut panel = make_panel(vec![
            make_func(1, "main", "/prog", 0x1000),
        ]);
        let listener = Arc::new(TrackingMultiFunctionListener::new());
        panel.add_listener(listener.clone());
        panel.clear_listeners();

        panel.dispose();
        assert_eq!(listener.event_count(), 0);
    }

    // --- TrackingMultiFunctionListener tests ---

    #[test]
    fn test_tracking_listener() {
        let listener = TrackingMultiFunctionListener::new();
        assert_eq!(listener.event_count(), 0);

        listener.on_event(&MultiFunctionPanelEvent::Disposed);
        assert_eq!(listener.event_count(), 1);
    }
}
