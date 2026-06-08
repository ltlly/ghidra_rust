//! Function window provider.
//!
//! Ported from Ghidra's `FunctionWindowProvider extends ComponentProviderAdapter`.
//!
//! Manages the function table display, filter panel, navigation actions,
//! and function comparison. This is the model-level counterpart that
//! tracks UI state (selection, visibility, filter text, navigation toggles)
//! without depending on any GUI toolkit.

use super::model::FunctionTableModel;
use super::{FunctionRef, FunctionRowObject, FunctionStore};
use ghidra_core::Address;
use std::collections::HashSet;

// ===========================================================================
// FunctionWindowProvider
// ===========================================================================

/// Component provider that displays the function table.
///
/// Manages selection state, filter text, navigation toggles, and
/// provides the function comparison action. This matches Ghidra's
/// `FunctionWindowProvider` at the model level.
///
/// # Example
///
/// ```ignore
/// let mut provider = FunctionWindowProvider::new("Functions");
/// provider.show();
/// provider.select(42);
/// assert!(provider.has_selection());
/// ```
#[derive(Debug)]
pub struct FunctionWindowProvider {
    /// Provider title.
    pub title: String,
    /// Whether the provider is visible.
    pub visible: bool,
    /// Selected function IDs.
    pub selected_ids: HashSet<u64>,
    /// Navigate-on-incoming toggle state.
    pub navigate_incoming: bool,
    /// Navigate-on-outgoing toggle state.
    pub navigate_outgoing: bool,
    /// Filter text.
    pub filter_text: String,
    /// Whether the comparison action is available.
    pub compare_action_available: bool,
    /// Subtitle showing row count.
    subtitle: String,
}

impl FunctionWindowProvider {
    /// Create a new function window provider.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            visible: false,
            selected_ids: HashSet::new(),
            navigate_incoming: false,
            navigate_outgoing: false,
            filter_text: String::new(),
            compare_action_available: false,
            subtitle: String::new(),
        }
    }

    /// Show the provider.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the provider.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Toggle visibility.
    pub fn toggle(&mut self) {
        self.visible = !self.visible;
    }

    /// Select a function by ID.
    pub fn select(&mut self, id: u64) {
        self.selected_ids.clear();
        self.selected_ids.insert(id);
    }

    /// Select multiple functions by ID.
    pub fn select_multiple(&mut self, ids: &[u64]) {
        self.selected_ids.clear();
        self.selected_ids.extend(ids.iter());
    }

    /// Clear selection.
    pub fn clear_selection(&mut self) {
        self.selected_ids.clear();
    }

    /// Apply a filter to narrow the function list.
    pub fn set_filter(&mut self, text: impl Into<String>) {
        self.filter_text = text.into();
    }

    /// Clear the filter.
    pub fn clear_filter(&mut self) {
        self.filter_text.clear();
    }

    /// Whether the provider has any selection.
    pub fn has_selection(&self) -> bool {
        !self.selected_ids.is_empty()
    }

    /// Whether multiple functions are selected (for comparison).
    pub fn has_multiple_selection(&self) -> bool {
        self.selected_ids.len() > 1
    }

    /// Get the selected function IDs.
    pub fn selected_ids(&self) -> &HashSet<u64> {
        &self.selected_ids
    }

    /// Update the subtitle based on model row counts.
    ///
    /// Matches Java's `functionModel.addTableModelListener` logic:
    /// `"N items"` or `"N items (of M)"`.
    pub fn update_subtitle(&mut self, row_count: usize, unfiltered_count: usize) {
        if row_count == unfiltered_count {
            self.subtitle = format!("{} items", row_count);
        } else {
            self.subtitle = format!("{} items (of {})", row_count, unfiltered_count);
        }
    }

    /// Get the current subtitle.
    pub fn subtitle(&self) -> &str {
        &self.subtitle
    }

    /// Update the subtitle from a model (convenience method).
    pub fn update_subtitle_from_model(&mut self, model: &FunctionTableModel) {
        let row_count = model.row_count();
        let unfiltered_count = model.total_function_count();
        self.update_subtitle(row_count, unfiltered_count);
    }

    /// Get the selected function row objects from the model.
    ///
    /// Corresponds to Java's `functionModel.getRowObjects(selectedRows)`.
    pub fn get_selected_functions<'a>(
        &self,
        model: &'a FunctionTableModel,
    ) -> Vec<&'a FunctionRowObject> {
        self.selected_ids
            .iter()
            .filter_map(|id| model.get_row_by_key(*id))
            .collect()
    }

    /// Get the program location for the first selected function.
    ///
    /// Corresponds to Java's `FunctionWindowActionContext.getLocation()`.
    pub fn get_location(&self, model: &FunctionTableModel) -> Option<Address> {
        let first_id = self.selected_ids.iter().next()?;
        let row = model.get_row_by_key(*first_id)?;
        Some(row.entry_point())
    }

    /// Set up the comparison action availability.
    ///
    /// Corresponds to Java's `createCompareAction()`.
    pub fn create_compare_action(&mut self) {
        self.compare_action_available = true;
    }

    /// Remove the comparison action.
    ///
    /// Corresponds to Java's `removeCompareAction()`.
    pub fn remove_compare_action(&mut self) {
        self.compare_action_available = false;
    }

    /// Whether the compare action is enabled.
    ///
    /// The compare action requires at least 2 selected functions and
    /// the comparison service to be available.
    pub fn is_compare_enabled(&self) -> bool {
        self.compare_action_available && self.has_multiple_selection()
    }

    /// Get the IDs of functions to compare.
    ///
    /// Returns an empty vec if fewer than 2 functions are selected.
    pub fn get_comparison_function_ids(&self) -> Vec<u64> {
        if self.has_multiple_selection() {
            self.selected_ids.iter().copied().collect()
        } else {
            Vec::new()
        }
    }

    /// Read configuration state.
    pub fn read_config(&mut self, navigate_incoming: bool, navigate_outgoing: bool) {
        self.navigate_incoming = navigate_incoming;
        self.navigate_outgoing = navigate_outgoing;
    }

    /// Write configuration state.
    pub fn write_config(&self) -> (bool, bool) {
        (self.navigate_incoming, self.navigate_outgoing)
    }

    /// Handle incoming location change (for navigate-on-incoming).
    ///
    /// When navigate-on-incoming is enabled, selects the function
    /// containing the given address.
    pub fn location_changed(&mut self, addr: Option<Address>, store: Option<&FunctionStore>) {
        if !self.navigate_incoming {
            return;
        }
        let addr = match addr {
            Some(a) => a,
            None => return,
        };
        let store = match store {
            Some(s) => s,
            None => return,
        };
        if let Some(func) = store.get_function_containing(addr) {
            self.selected_ids.clear();
            self.selected_ids.insert(func.id);
        }
    }

    /// Get the related functions (function + its thunks).
    ///
    /// Corresponds to Java's `getRelatedFunctions(Function)` which
    /// gathers the function and any functions that thunk it.
    pub fn get_related_functions(
        func: &FunctionRef,
        store: &FunctionStore,
    ) -> Vec<FunctionRef> {
        let mut related = Vec::new();
        // In a full implementation, this would look up thunk addresses.
        // For now, we include the function itself and any other functions
        // whose entry point matches a thunk address.
        related.push(func.clone());

        // Look for thunk functions that point to this function
        for other in store.functions.values() {
            if other.id != func.id && other.is_thunk {
                // Check if this thunk targets our function
                // (In a full impl, we'd check thunk target addresses)
                related.push(other.clone());
            }
        }

        related
    }
}

impl Default for FunctionWindowProvider {
    fn default() -> Self {
        Self::new("Functions")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(id: u64, name: &str, offset: u64) -> FunctionRef {
        FunctionRef::new(id, name, Address::new(offset), format!("void {}()", name))
    }

    fn make_store() -> FunctionStore {
        let mut store = FunctionStore::new("test.exe");
        store.add_function(make_func(1, "main", 0x401000));
        store.add_function(make_func(2, "foo", 0x402000));
        store.add_function(make_func(3, "bar", 0x403000));
        store
    }

    #[test]
    fn test_provider_new() {
        let provider = FunctionWindowProvider::new("Functions");
        assert_eq!(provider.title, "Functions");
        assert!(!provider.visible);
        assert!(provider.selected_ids.is_empty());
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = FunctionWindowProvider::new("F");
        provider.show();
        assert!(provider.visible);
        provider.hide();
        assert!(!provider.visible);
        provider.toggle();
        assert!(provider.visible);
    }

    #[test]
    fn test_provider_selection() {
        let mut provider = FunctionWindowProvider::new("F");
        provider.select(42);
        assert!(provider.has_selection());
        assert!(provider.selected_ids.contains(&42));

        provider.select_multiple(&[1, 2, 3]);
        assert_eq!(provider.selected_ids.len(), 3);

        provider.clear_selection();
        assert!(!provider.has_selection());
    }

    #[test]
    fn test_provider_filter() {
        let mut provider = FunctionWindowProvider::new("F");
        provider.set_filter("main");
        assert_eq!(provider.filter_text, "main");
        provider.clear_filter();
        assert!(provider.filter_text.is_empty());
    }

    #[test]
    fn test_provider_config() {
        let mut provider = FunctionWindowProvider::new("F");
        provider.read_config(true, true);
        assert!(provider.navigate_incoming);
        assert!(provider.navigate_outgoing);
        let (inc, out) = provider.write_config();
        assert!(inc);
        assert!(out);
    }

    #[test]
    fn test_provider_subtitle() {
        let mut provider = FunctionWindowProvider::new("F");
        provider.update_subtitle(10, 10);
        assert_eq!(provider.subtitle(), "10 items");

        provider.update_subtitle(5, 10);
        assert_eq!(provider.subtitle(), "5 items (of 10)");
    }

    #[test]
    fn test_provider_multiple_selection() {
        let mut provider = FunctionWindowProvider::new("F");
        assert!(!provider.has_multiple_selection());

        provider.select(1);
        assert!(!provider.has_multiple_selection());

        provider.select_multiple(&[1, 2]);
        assert!(provider.has_multiple_selection());
    }

    #[test]
    fn test_provider_compare_action() {
        let mut provider = FunctionWindowProvider::new("F");
        assert!(!provider.compare_action_available);

        provider.create_compare_action();
        assert!(provider.compare_action_available);

        // Need multiple selection for compare to be enabled
        provider.select(1);
        assert!(!provider.is_compare_enabled());

        provider.select_multiple(&[1, 2]);
        assert!(provider.is_compare_enabled());

        provider.remove_compare_action();
        assert!(!provider.is_compare_enabled());
    }

    #[test]
    fn test_provider_comparison_ids() {
        let mut provider = FunctionWindowProvider::new("F");
        provider.create_compare_action();
        provider.select_multiple(&[1, 2, 3]);

        let ids = provider.get_comparison_function_ids();
        assert_eq!(ids.len(), 3);

        provider.select(1);
        let ids = provider.get_comparison_function_ids();
        assert!(ids.is_empty());
    }

    #[test]
    fn test_provider_location_changed() {
        let mut provider = FunctionWindowProvider::new("F");
        provider.navigate_incoming = true;
        let store = make_store();

        provider.location_changed(Some(Address::new(0x402000)), Some(&store));
        assert!(provider.selected_ids.contains(&2));

        provider.navigate_incoming = false;
        provider.clear_selection();
        provider.location_changed(Some(Address::new(0x402000)), Some(&store));
        assert!(!provider.has_selection());
    }

    #[test]
    fn test_provider_get_location() {
        let mut provider = FunctionWindowProvider::new("F");
        let mut model = super::super::model::FunctionTableModel::new("test");
        model.reload(Some(make_store()));

        assert!(provider.get_location(&model).is_none());

        provider.select(2);
        let loc = provider.get_location(&model);
        assert!(loc.is_some());
        assert_eq!(loc.unwrap().offset, 0x402000);
    }

    #[test]
    fn test_provider_get_selected_functions() {
        let mut provider = FunctionWindowProvider::new("F");
        let mut model = super::super::model::FunctionTableModel::new("test");
        model.reload(Some(make_store()));

        provider.select_multiple(&[1, 3]);
        let funcs = provider.get_selected_functions(&model);
        assert_eq!(funcs.len(), 2);
    }

    #[test]
    fn test_provider_update_subtitle_from_model() {
        let mut provider = FunctionWindowProvider::new("F");
        let mut model = super::super::model::FunctionTableModel::new("test");
        model.reload(Some(make_store()));

        provider.update_subtitle_from_model(&model);
        assert_eq!(provider.subtitle(), "3 items");
    }

    #[test]
    fn test_provider_default() {
        let provider = FunctionWindowProvider::default();
        assert_eq!(provider.title, "Functions");
    }

    #[test]
    fn test_provider_get_related_functions() {
        let store = make_store();
        let func = make_func(1, "main", 0x401000);
        let related = FunctionWindowProvider::get_related_functions(&func, &store);
        assert!(!related.is_empty());
        assert_eq!(related[0].id, 1);
    }
}
