//! Function tags UI panels -- ported from `ghidra.app.plugin.core.function.tags`.
//!
//! Provides the UI models for the function tags provider:
//!
//! | Rust struct                | Java class                |
//! |----------------------------|---------------------------|
//! | `EditFunctionTagsAction`   | `EditFunctionTagsAction`  |
//! | `TagListPanelModel`        | `TagListPanel`            |
//! | `SourceTagsPanelModel`     | `SourceTagsPanel`         |
//! | `TargetTagsPanelModel`     | `TargetTagsPanel`         |
//! | `AllFunctionsPanelModel`   | `AllFunctionsPanel`       |
//! | `FunctionTagButtonPanelModel` | `FunctionTagButtonPanel` |
//! | `FunctionTagProviderModel` | `FunctionTagProvider`     |
//! | `FunctionTableModel`       | `FunctionTableModel`      |

use crate::base::function::actions::{ActionContext, ListingContext, MenuData};
use crate::base::function::tags::{FunctionTag, FunctionTagManager, FunctionTagRowObject};

// ---------------------------------------------------------------------------
// EditFunctionTagsAction
// ---------------------------------------------------------------------------

/// Action to open the function tags editor for the current function.
///
/// Ported from `EditFunctionTagsAction.java`.  This action is enabled
/// when the cursor is on a function location in the listing.
#[derive(Debug, Clone)]
pub struct EditFunctionTagsAction {
    /// The display name.
    pub name: String,
    /// The menu data.
    pub menu_data: Option<MenuData>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl EditFunctionTagsAction {
    /// The menu label.
    pub const MENU_LABEL: &'static str = "Edit Tags";

    /// Creates a new edit function tags action.
    pub fn new() -> Self {
        Self {
            name: Self::MENU_LABEL.to_string(),
            menu_data: Some(MenuData::new(
                vec!["Function".into(), Self::MENU_LABEL.into()],
                "Function",
                "FunctionTag",
            )),
            enabled: true,
        }
    }

    /// Checks whether the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match ctx {
            ActionContext::Listing(listing) => {
                listing.address.is_some()
                    && !listing.has_selection
                    && listing.is_function_location
            }
            ActionContext::Symbol(_) => false,
        }
    }
}

impl Default for EditFunctionTagsAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TagListPanelModel -- abstract base for source/target tag panels
// ---------------------------------------------------------------------------

/// The mode of the tag list panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagListMode {
    /// Source panel: shows all tags NOT assigned to the current function.
    Source,
    /// Target panel: shows tags assigned to the current function.
    Target,
}

/// Model for a tag list panel.
///
/// Ported from `TagListPanel.java`.  This is the base model that both
/// `SourceTagsPanelModel` and `TargetTagsPanelModel` extend.
#[derive(Debug, Clone)]
pub struct TagListPanelModel {
    /// The panel title.
    title: String,
    /// The display mode.
    mode: TagListMode,
    /// The tags displayed in this panel.
    tags: Vec<FunctionTag>,
    /// The selected tag indices.
    selected_indices: Vec<usize>,
    /// The current function address (if any).
    function_address: Option<u64>,
    /// Whether the panel is disabled (no function selected).
    disabled: bool,
}

impl TagListPanelModel {
    /// Creates a new tag list panel model.
    pub fn new(title: impl Into<String>, mode: TagListMode) -> Self {
        Self {
            title: title.into(),
            mode,
            tags: Vec::new(),
            selected_indices: Vec::new(),
            function_address: None,
            disabled: false,
        }
    }

    /// Returns the panel title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Sets the panel title.
    pub fn set_title(&mut self, title: impl Into<String>) {
        self.title = title.into();
    }

    /// Returns the mode.
    pub fn mode(&self) -> TagListMode {
        self.mode
    }

    /// Returns the tags.
    pub fn tags(&self) -> &[FunctionTag] {
        &self.tags
    }

    /// Sets the tags.
    pub fn set_tags(&mut self, tags: Vec<FunctionTag>) {
        self.tags = tags;
        self.selected_indices.clear();
    }

    /// Adds a tag.
    pub fn add_tag(&mut self, tag: FunctionTag) {
        if !self.tags.iter().any(|t| t.id() == tag.id()) {
            self.tags.push(tag);
        }
    }

    /// Removes a tag by ID.
    pub fn remove_tag(&mut self, tag_id: u64) -> bool {
        let len = self.tags.len();
        self.tags.retain(|t| t.id() != tag_id);
        self.tags.len() < len
    }

    /// Returns the selected tags.
    pub fn selected_tags(&self) -> Vec<&FunctionTag> {
        self.selected_indices
            .iter()
            .filter_map(|&idx| self.tags.get(idx))
            .collect()
    }

    /// Returns the selected tag indices.
    pub fn selected_indices(&self) -> &[usize] {
        &self.selected_indices
    }

    /// Sets the selected tag indices.
    pub fn set_selected_indices(&mut self, indices: Vec<usize>) {
        self.selected_indices = indices;
    }

    /// Returns the current function address.
    pub fn function_address(&self) -> Option<u64> {
        self.function_address
    }

    /// Sets the current function address and refreshes tags.
    pub fn set_function_address(&mut self, addr: Option<u64>) {
        self.function_address = addr;
    }

    /// Returns whether the panel is disabled.
    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Sets the disabled state.
    pub fn set_disabled(&mut self, disabled: bool) {
        self.disabled = disabled;
    }

    /// Clears all tags.
    pub fn clear(&mut self) {
        self.tags.clear();
        self.selected_indices.clear();
        self.function_address = None;
    }

    /// Returns the tag count.
    pub fn tag_count(&self) -> usize {
        self.tags.len()
    }
}

// ---------------------------------------------------------------------------
// SourceTagsPanelModel
// ---------------------------------------------------------------------------

/// Model for the source tags panel (tags NOT yet assigned to the function).
///
/// Ported from `SourceTagsPanel.java`.
#[derive(Debug, Clone)]
pub struct SourceTagsPanelModel {
    /// The inner tag list panel model.
    pub inner: TagListPanelModel,
}

impl SourceTagsPanelModel {
    /// Creates a new source tags panel model.
    pub fn new() -> Self {
        Self {
            inner: TagListPanelModel::new("Function Tags", TagListMode::Source),
        }
    }

    /// Returns the tags that should be shown in the source panel.
    ///
    /// This is all tags in the manager minus those assigned to the
    /// current function.
    pub fn compute_source_tags(
        &self,
        manager: &FunctionTagManager,
        function_address: Option<u64>,
    ) -> Vec<FunctionTag> {
        let all_tags = manager.all_tags();
        let assigned = match function_address {
            Some(addr) => manager.tags_for_function(addr),
            None => Vec::new(),
        };
        let assigned_ids: Vec<u64> = assigned.iter().map(|t| t.id()).collect();
        all_tags
            .into_iter()
            .filter(|t| !assigned_ids.contains(&t.id()))
            .cloned()
            .collect()
    }

    /// Adds the selected tags to the current function.
    ///
    /// Returns the number of tags added.
    pub fn add_selected_tags(
        &self,
        manager: &mut FunctionTagManager,
        function_address: u64,
    ) -> usize {
        let selected = self.inner.selected_tags();
        let mut count = 0;
        for tag in selected {
            manager.add_tag_to_function(function_address, tag.id());
            count += 1;
        }
        count
    }
}

impl Default for SourceTagsPanelModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TargetTagsPanelModel
// ---------------------------------------------------------------------------

/// Model for the target tags panel (tags assigned to the function).
///
/// Ported from `TargetTagsPanel.java`.
#[derive(Debug, Clone)]
pub struct TargetTagsPanelModel {
    /// The inner tag list panel model.
    pub inner: TagListPanelModel,
}

impl TargetTagsPanelModel {
    /// Creates a new target tags panel model.
    pub fn new() -> Self {
        Self {
            inner: TagListPanelModel::new("Function Tags Assigned", TagListMode::Target),
        }
    }

    /// Refreshes the panel with the tags for the current function.
    pub fn refresh(&mut self, manager: &FunctionTagManager, function_address: Option<u64>) {
        self.inner.set_function_address(function_address);
        match function_address {
            Some(addr) => {
                let tags = manager
                    .tags_for_function(addr)
                    .into_iter()
                    .cloned()
                    .collect();
                self.inner.set_tags(tags);
                self.inner.set_disabled(false);
            }
            None => {
                self.inner.clear();
                self.inner.set_disabled(true);
            }
        }
    }

    /// Removes the selected tags from the current function.
    ///
    /// Returns the number of tags removed.
    pub fn remove_selected_tags(
        &self,
        manager: &mut FunctionTagManager,
        function_address: u64,
    ) -> usize {
        let selected = self.inner.selected_tags();
        let mut count = 0;
        for tag in selected {
            if manager.remove_tag_from_function(function_address, tag.id()) {
                count += 1;
            }
        }
        count
    }
}

impl Default for TargetTagsPanelModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FunctionTableModel (for tags panel)
// ---------------------------------------------------------------------------

/// A simple function entry for the function table in the tags provider.
#[derive(Debug, Clone)]
pub struct FunctionEntry {
    /// The function address.
    pub address: u64,
    /// The function name.
    pub name: String,
    /// The tags assigned to this function.
    pub tags: Vec<FunctionTag>,
}

impl FunctionEntry {
    /// Creates a new function entry.
    pub fn new(address: u64, name: impl Into<String>, tags: Vec<FunctionTag>) -> Self {
        Self {
            address,
            name: name.into(),
            tags,
        }
    }
}

/// Model for the functions table in the function tags provider.
///
/// Ported from `FunctionTableModel.java`.  Displays a list of functions
/// that have function tags matching a provided set.
#[derive(Debug, Clone)]
pub struct FunctionTableModelForTags {
    /// The rows.
    rows: Vec<FunctionEntry>,
    /// The tags to filter by (show functions with at least one of these).
    filter_tags: Vec<FunctionTag>,
}

impl FunctionTableModelForTags {
    /// Creates a new function table model.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            filter_tags: Vec::new(),
        }
    }

    /// Returns the rows.
    pub fn rows(&self) -> &[FunctionEntry] {
        &self.rows
    }

    /// Returns the row count.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Adds a function entry.
    pub fn add_row(&mut self, entry: FunctionEntry) {
        self.rows.push(entry);
    }

    /// Clears all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Sets the filter tags.
    pub fn set_filter_tags(&mut self, tags: Vec<FunctionTag>) {
        self.filter_tags = tags;
    }

    /// Returns the filter tags.
    pub fn filter_tags(&self) -> &[FunctionTag] {
        &self.filter_tags
    }

    /// Gets the address for a row.
    pub fn get_address(&self, row: usize) -> Option<u64> {
        self.rows.get(row).map(|r| r.address)
    }

    /// Gets a cell value by row and column.
    pub fn get_value_at(&self, row: usize, col: usize) -> Option<String> {
        let entry = self.rows.get(row)?;
        match col {
            0 => Some(entry.name.clone()),
            1 => Some(format!("0x{:x}", entry.address)),
            2 => Some(
                entry
                    .tags
                    .iter()
                    .map(|t| t.name().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            _ => None,
        }
    }
}

impl Default for FunctionTableModelForTags {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AllFunctionsPanelModel
// ---------------------------------------------------------------------------

/// Model for the "all functions" panel that shows functions with a
/// given tag.
///
/// Ported from `AllFunctionsPanel.java`.
#[derive(Debug, Clone)]
pub struct AllFunctionsPanelModel {
    /// The function table model.
    table_model: FunctionTableModelForTags,
    /// The title.
    title: String,
}

impl AllFunctionsPanelModel {
    /// Creates a new all functions panel model.
    pub fn new() -> Self {
        Self {
            table_model: FunctionTableModelForTags::new(),
            title: "Function Tags Applied Functions".to_string(),
        }
    }

    /// Returns the title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns a reference to the table model.
    pub fn table_model(&self) -> &FunctionTableModelForTags {
        &self.table_model
    }

    /// Returns a mutable reference to the table model.
    pub fn table_model_mut(&mut self) -> &mut FunctionTableModelForTags {
        &mut self.table_model
    }
}

impl Default for AllFunctionsPanelModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FunctionTagButtonPanelModel
// ---------------------------------------------------------------------------

/// Action that the button panel can trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagButtonAction {
    /// Add selected source tags to the function.
    Add,
    /// Remove selected target tags from the function.
    Remove,
    /// Delete the selected tag entirely.
    Delete,
}

/// Model for the button panel between the source and target tag lists.
///
/// Ported from `FunctionTagButtonPanel.java`.  Manages the Add, Remove,
/// and Delete buttons that move tags between the source and target panels.
#[derive(Debug, Clone)]
pub struct FunctionTagButtonPanelModel {
    /// Whether the Add button is enabled.
    add_enabled: bool,
    /// Whether the Remove button is enabled.
    remove_enabled: bool,
    /// Whether the Delete button is enabled.
    delete_enabled: bool,
}

impl FunctionTagButtonPanelModel {
    /// Creates a new button panel model.
    pub fn new() -> Self {
        Self {
            add_enabled: false,
            remove_enabled: false,
            delete_enabled: false,
        }
    }

    /// Returns whether the Add button is enabled.
    pub fn is_add_enabled(&self) -> bool {
        self.add_enabled
    }

    /// Returns whether the Remove button is enabled.
    pub fn is_remove_enabled(&self) -> bool {
        self.remove_enabled
    }

    /// Returns whether the Delete button is enabled.
    pub fn is_delete_enabled(&self) -> bool {
        self.delete_enabled
    }

    /// Updates button states based on the source and target panel
    /// selections.
    pub fn update_state(
        &mut self,
        source_selected_count: usize,
        target_selected_count: usize,
        has_function: bool,
    ) {
        self.add_enabled = has_function && source_selected_count > 0;
        self.remove_enabled = has_function && target_selected_count > 0;
        self.delete_enabled = source_selected_count > 0 || target_selected_count > 0;
    }
}

impl Default for FunctionTagButtonPanelModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FunctionTagProviderModel
// ---------------------------------------------------------------------------

/// The state of the function tag provider.
///
/// Ported from `FunctionTagProvider.java`.  This is the top-level model
/// that coordinates the source tags panel, target tags panel, button
/// panel, and all functions panel.
#[derive(Debug)]
pub struct FunctionTagProviderModel {
    /// The source tags panel model.
    pub source_panel: SourceTagsPanelModel,
    /// The target tags panel model.
    pub target_panel: TargetTagsPanelModel,
    /// The button panel model.
    pub button_panel: FunctionTagButtonPanelModel,
    /// The all functions panel model.
    pub all_functions_panel: AllFunctionsPanelModel,
    /// The current function address.
    current_function_address: Option<u64>,
    /// The new tag text from the hint text field.
    new_tag_text: String,
}

impl FunctionTagProviderModel {
    /// Creates a new function tag provider model.
    pub fn new() -> Self {
        Self {
            source_panel: SourceTagsPanelModel::new(),
            target_panel: TargetTagsPanelModel::new(),
            button_panel: FunctionTagButtonPanelModel::new(),
            all_functions_panel: AllFunctionsPanelModel::new(),
            current_function_address: None,
            new_tag_text: String::new(),
        }
    }

    /// Returns the current function address.
    pub fn current_function_address(&self) -> Option<u64> {
        self.current_function_address
    }

    /// Sets the current function and refreshes both panels.
    pub fn set_current_function(
        &mut self,
        manager: &FunctionTagManager,
        address: Option<u64>,
    ) {
        self.current_function_address = address;

        // Refresh source panel
        let source_tags = self.source_panel.compute_source_tags(manager, address);
        self.source_panel.inner.set_tags(source_tags);
        self.source_panel.inner.set_function_address(address);

        // Refresh target panel
        self.target_panel.refresh(manager, address);

        // Update button panel
        self.update_buttons();
    }

    /// Updates the button panel state.
    pub fn update_buttons(&mut self) {
        self.button_panel.update_state(
            self.source_panel.inner.selected_indices().len(),
            self.target_panel.inner.selected_indices().len(),
            self.current_function_address.is_some(),
        );
    }

    /// Creates a new tag.
    pub fn create_tag(&self, manager: &mut FunctionTagManager, name: &str) -> u64 {
        manager.create_tag(name)
    }

    /// Returns the new tag text.
    pub fn new_tag_text(&self) -> &str {
        &self.new_tag_text
    }

    /// Sets the new tag text.
    pub fn set_new_tag_text(&mut self, text: impl Into<String>) {
        self.new_tag_text = text.into();
    }
}

impl Default for FunctionTagProviderModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- EditFunctionTagsAction --

    #[test]
    fn test_edit_function_tags_action() {
        let action = EditFunctionTagsAction::new();
        assert_eq!(action.name, "Edit Tags");
    }

    #[test]
    fn test_edit_function_tags_action_enabled() {
        let action = EditFunctionTagsAction::new();
        let ctx = ActionContext::Listing(ListingContext {
            address: Some(ghidra_core::addr::Address::new(0x401000)),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_function_location: true,
            is_variable_location: false,
            is_operand_field: false,
            function_address: Some(ghidra_core::addr::Address::new(0x401000)),
        });
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_edit_function_tags_action_disabled_with_selection() {
        let action = EditFunctionTagsAction::new();
        let ctx = ActionContext::listing_selection(
            ghidra_core::addr::Address::new(0x401000),
            ghidra_core::addr::Address::new(0x402000),
        );
        assert!(!action.is_enabled_for_context(&ctx));
    }

    // -- TagListPanelModel --

    #[test]
    fn test_tag_list_panel_model() {
        let mut model = TagListPanelModel::new("Source Tags", TagListMode::Source);
        assert_eq!(model.title(), "Source Tags");
        assert_eq!(model.mode(), TagListMode::Source);
        assert!(!model.is_disabled());

        model.add_tag(FunctionTag::new(1, "tag1"));
        model.add_tag(FunctionTag::new(2, "tag2"));
        assert_eq!(model.tag_count(), 2);

        model.set_selected_indices(vec![0]);
        let selected = model.selected_tags();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name(), "tag1");
    }

    #[test]
    fn test_tag_list_panel_model_remove() {
        let mut model = TagListPanelModel::new("test", TagListMode::Target);
        model.add_tag(FunctionTag::new(1, "tag1"));
        model.add_tag(FunctionTag::new(2, "tag2"));
        assert!(model.remove_tag(1));
        assert_eq!(model.tag_count(), 1);
        assert!(!model.remove_tag(99));
    }

    #[test]
    fn test_tag_list_panel_model_dedup() {
        let mut model = TagListPanelModel::new("test", TagListMode::Source);
        model.add_tag(FunctionTag::new(1, "tag1"));
        model.add_tag(FunctionTag::new(1, "tag1"));
        assert_eq!(model.tag_count(), 1);
    }

    // -- SourceTagsPanelModel --

    #[test]
    fn test_source_tags_panel_model_compute() {
        let mut manager = FunctionTagManager::new();
        let id1 = manager.create_tag("tag1");
        let id2 = manager.create_tag("tag2");
        let id3 = manager.create_tag("tag3");
        manager.add_tag_to_function(0x401000, id1);

        let model = SourceTagsPanelModel::new();
        let source = model.compute_source_tags(&manager, Some(0x401000));
        assert_eq!(source.len(), 2);
        assert!(source.iter().all(|t| t.id() != id1));
    }

    #[test]
    fn test_source_tags_panel_model_add_selected() {
        let mut manager = FunctionTagManager::new();
        let id1 = manager.create_tag("tag1");

        let mut model = SourceTagsPanelModel::new();
        model.inner.add_tag(FunctionTag::new(id1, "tag1"));
        model.inner.set_selected_indices(vec![0]);

        let count = model.add_selected_tags(&mut manager, 0x401000);
        assert_eq!(count, 1);
        assert_eq!(manager.tags_for_function(0x401000).len(), 1);
    }

    // -- TargetTagsPanelModel --

    #[test]
    fn test_target_tags_panel_model_refresh() {
        let mut manager = FunctionTagManager::new();
        let id = manager.create_tag("tag1");
        manager.add_tag_to_function(0x401000, id);

        let mut model = TargetTagsPanelModel::new();
        model.refresh(&manager, Some(0x401000));
        assert_eq!(model.inner.tag_count(), 1);
        assert!(!model.inner.is_disabled());
    }

    #[test]
    fn test_target_tags_panel_model_no_function() {
        let manager = FunctionTagManager::new();
        let mut model = TargetTagsPanelModel::new();
        model.refresh(&manager, None);
        assert!(model.inner.is_disabled());
    }

    #[test]
    fn test_target_tags_panel_model_remove_selected() {
        let mut manager = FunctionTagManager::new();
        let id = manager.create_tag("tag1");
        manager.add_tag_to_function(0x401000, id);

        let mut model = TargetTagsPanelModel::new();
        model.refresh(&manager, Some(0x401000));
        model.inner.set_selected_indices(vec![0]);

        let count = model.remove_selected_tags(&mut manager, 0x401000);
        assert_eq!(count, 1);
        assert_eq!(manager.tags_for_function(0x401000).len(), 0);
    }

    // -- FunctionTableModelForTags --

    #[test]
    fn test_function_table_model_for_tags() {
        let mut model = FunctionTableModelForTags::new();
        model.add_row(FunctionEntry::new(
            0x401000,
            "main",
            vec![FunctionTag::new(1, "decompiled")],
        ));
        assert_eq!(model.row_count(), 1);
        assert_eq!(model.get_address(0), Some(0x401000));
    }

    #[test]
    fn test_function_table_model_values() {
        let mut model = FunctionTableModelForTags::new();
        model.add_row(FunctionEntry::new(
            0x401000,
            "main",
            vec![FunctionTag::new(1, "tag1"), FunctionTag::new(2, "tag2")],
        ));
        assert_eq!(model.get_value_at(0, 0), Some("main".into()));
        assert_eq!(model.get_value_at(0, 1), Some("0x401000".into()));
        assert_eq!(model.get_value_at(0, 2), Some("tag1, tag2".into()));
        assert_eq!(model.get_value_at(0, 3), None);
    }

    // -- AllFunctionsPanelModel --

    #[test]
    fn test_all_functions_panel_model() {
        let model = AllFunctionsPanelModel::new();
        assert_eq!(model.title(), "Function Tags Applied Functions");
        assert_eq!(model.table_model().row_count(), 0);
    }

    // -- FunctionTagButtonPanelModel --

    #[test]
    fn test_button_panel_model() {
        let mut model = FunctionTagButtonPanelModel::new();
        assert!(!model.is_add_enabled());
        assert!(!model.is_remove_enabled());
        assert!(!model.is_delete_enabled());

        // No function selected
        model.update_state(1, 0, false);
        assert!(!model.is_add_enabled());

        // Function selected with source selection
        model.update_state(1, 0, true);
        assert!(model.is_add_enabled());
        assert!(!model.is_remove_enabled());

        // Function selected with target selection
        model.update_state(0, 1, true);
        assert!(!model.is_add_enabled());
        assert!(model.is_remove_enabled());
    }

    // -- FunctionTagProviderModel --

    #[test]
    fn test_function_tag_provider_model() {
        let mut manager = FunctionTagManager::new();
        let id = manager.create_tag("tag1");
        manager.add_tag_to_function(0x401000, id);
        manager.create_tag("tag2");

        let mut provider = FunctionTagProviderModel::new();
        provider.set_current_function(&manager, Some(0x401000));

        assert_eq!(provider.current_function_address(), Some(0x401000));
        // Target panel should have tag1
        assert_eq!(provider.target_panel.inner.tag_count(), 1);
        // Source panel should have tag2
        assert_eq!(provider.source_panel.inner.tag_count(), 1);
    }

    #[test]
    fn test_function_tag_provider_create_tag() {
        let mut manager = FunctionTagManager::new();
        let provider = FunctionTagProviderModel::new();
        let id = provider.create_tag(&mut manager, "new_tag");
        assert_eq!(manager.tag_count(), 1);
        assert_eq!(manager.get_tag(id).unwrap().name(), "new_tag");
    }
}
