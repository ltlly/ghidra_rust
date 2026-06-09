//! DataTypeManager Provider -- the component provider for the Data Type Manager window.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.datamgr.DataTypeManagerProvider`.
//!
//! This module provides [`DataTypeManagerProvider`], which manages the data type
//! tree display, filtering, sorting, selection, and editing within the Data Type
//! Manager window. It is the primary UI component for browsing and managing
//! data types, categories, and archives.
//!
//! # Architecture
//!
//! ```text
//! DataTypeManagerProvider
//!   ├── name / visible / disposed
//!   ├── program connection (program_name)
//!   ├── tree state (root node, expanded set, selected node)
//!   ├── filter / search state
//!   ├── sort mode
//!   └── undo/redo support
//! ```

use std::collections::HashSet;
use std::fmt;

// ---------------------------------------------------------------------------
// NodeType -- types of nodes in the data type tree
// ---------------------------------------------------------------------------

/// The type of a node in the data type tree.
///
/// Ported from the node classification logic in `DataTypeManagerProvider`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeType {
    /// A data type category (folder).
    Category,
    /// A data type (structure, union, enum, typedef, etc.).
    DataType,
    /// A built-in data type.
    BuiltIn,
    /// A pointer type.
    Pointer,
    /// A function definition.
    FunctionDef,
    /// The root node of the tree.
    Root,
    /// An archive node (external type library).
    Archive,
}

impl NodeType {
    /// Returns `true` if this node represents a leaf (non-category) node.
    pub fn is_leaf(&self) -> bool {
        matches!(
            self,
            Self::DataType | Self::BuiltIn | Self::Pointer | Self::FunctionDef
        )
    }

    /// Returns `true` if this node can contain children.
    pub fn has_children(&self) -> bool {
        matches!(self, Self::Category | Self::Root | Self::Archive)
    }
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Category => write!(f, "Category"),
            Self::DataType => write!(f, "DataType"),
            Self::BuiltIn => write!(f, "BuiltIn"),
            Self::Pointer => write!(f, "Pointer"),
            Self::FunctionDef => write!(f, "FunctionDef"),
            Self::Root => write!(f, "Root"),
            Self::Archive => write!(f, "Archive"),
        }
    }
}

// ---------------------------------------------------------------------------
// SortMode -- sorting modes for the data type tree
// ---------------------------------------------------------------------------

/// Sorting modes for the data type tree display.
///
/// Ported from the sort logic in `DataTypeManagerProvider`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SortMode {
    /// Sort by data type name (alphabetical).
    Name,
    /// Sort by data type size.
    Size,
    /// Sort by last modification time.
    LastModified,
    /// Sort by usage/reference count.
    UsageCount,
}

impl SortMode {
    /// Returns all available sort modes.
    pub fn all() -> &'static [SortMode] {
        &[
            SortMode::Name,
            SortMode::Size,
            SortMode::LastModified,
            SortMode::UsageCount,
        ]
    }
}

impl Default for SortMode {
    fn default() -> Self {
        Self::Name
    }
}

impl fmt::Display for SortMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name => write!(f, "Name"),
            Self::Size => write!(f, "Size"),
            Self::LastModified => write!(f, "Last Modified"),
            Self::UsageCount => write!(f, "Usage Count"),
        }
    }
}

// ---------------------------------------------------------------------------
// FilterState -- filter/search state for the data type tree
// ---------------------------------------------------------------------------

/// Filter and search state for the data type tree.
///
/// Ported from the filter logic in `DataTypeManagerProvider`.
#[derive(Debug, Clone)]
pub struct FilterState {
    /// The current search text filter.
    filter_text: String,
    /// Whether to show built-in types.
    show_builtins: bool,
    /// Whether to show pointer types.
    show_pointers: bool,
    /// Whether to show function definitions.
    show_function_defs: bool,
    /// Whether to show categories.
    show_categories: bool,
    /// Whether the filter is active.
    active: bool,
}

impl FilterState {
    /// Creates a new filter state with default settings (everything visible).
    pub fn new() -> Self {
        Self {
            filter_text: String::new(),
            show_builtins: true,
            show_pointers: true,
            show_function_defs: true,
            show_categories: true,
            active: false,
        }
    }

    /// Returns the current filter text.
    pub fn filter_text(&self) -> &str {
        &self.filter_text
    }

    /// Sets the filter text and activates the filter.
    pub fn set_filter_text(&mut self, text: impl Into<String>) {
        self.filter_text = text.into();
        self.active = !self.filter_text.is_empty();
    }

    /// Clears the filter text and deactivates the filter.
    pub fn clear(&mut self) {
        self.filter_text.clear();
        self.active = false;
    }

    /// Whether the filter is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Whether to show built-in types.
    pub fn show_builtins(&self) -> bool {
        self.show_builtins
    }

    /// Set whether to show built-in types.
    pub fn set_show_builtins(&mut self, show: bool) {
        self.show_builtins = show;
    }

    /// Whether to show pointer types.
    pub fn show_pointers(&self) -> bool {
        self.show_pointers
    }

    /// Set whether to show pointer types.
    pub fn set_show_pointers(&mut self, show: bool) {
        self.show_pointers = show;
    }

    /// Whether to show function definitions.
    pub fn show_function_defs(&self) -> bool {
        self.show_function_defs
    }

    /// Set whether to show function definitions.
    pub fn set_show_function_defs(&mut self, show: bool) {
        self.show_function_defs = show;
    }

    /// Whether to show categories.
    pub fn show_categories(&self) -> bool {
        self.show_categories
    }

    /// Set whether to show categories.
    pub fn set_show_categories(&mut self, show: bool) {
        self.show_categories = show;
    }

    /// Returns `true` if the given node type passes the current filter.
    pub fn accepts(&self, node_type: NodeType) -> bool {
        match node_type {
            NodeType::Root | NodeType::Archive => true,
            NodeType::Category => self.show_categories,
            NodeType::BuiltIn => self.show_builtins,
            NodeType::Pointer => self.show_pointers,
            NodeType::FunctionDef => self.show_function_defs,
            NodeType::DataType => true,
        }
    }
}

impl Default for FilterState {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for FilterState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.active {
            write!(f, "Filter({:?})", self.filter_text)
        } else {
            write!(f, "Filter(inactive)")
        }
    }
}

// ---------------------------------------------------------------------------
// DtMgrDisplayRow -- a single display row in the data type tree
// ---------------------------------------------------------------------------

/// A single row in the data type tree display.
///
/// Ported from the display row model in `DataTypeManagerProvider`.
#[derive(Debug, Clone)]
pub struct DtMgrDisplayRow {
    /// The display name for this row.
    name: String,
    /// The node type.
    node_type: NodeType,
    /// The category path (e.g., "/Structures/MyStruct").
    category_path: String,
    /// The data type size in bytes (if applicable).
    size: Option<usize>,
    /// Whether this row is currently selected.
    selected: bool,
    /// Whether this row's node is expanded in the tree.
    expanded: bool,
    /// The depth level in the tree (0 = root).
    depth: usize,
    /// Unique identifier for this row.
    id: u64,
}

impl DtMgrDisplayRow {
    /// Creates a new display row.
    pub fn new(
        id: u64,
        name: impl Into<String>,
        node_type: NodeType,
        category_path: impl Into<String>,
        depth: usize,
    ) -> Self {
        Self {
            name: name.into(),
            node_type,
            category_path: category_path.into(),
            size: None,
            selected: false,
            expanded: false,
            depth,
            id,
        }
    }

    /// The unique identifier for this row.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Sets the display name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// The node type.
    pub fn node_type(&self) -> NodeType {
        self.node_type
    }

    /// The category path.
    pub fn category_path(&self) -> &str {
        &self.category_path
    }

    /// Sets the category path.
    pub fn set_category_path(&mut self, path: impl Into<String>) {
        self.category_path = path.into();
    }

    /// The data type size in bytes, if known.
    pub fn size(&self) -> Option<usize> {
        self.size
    }

    /// Sets the data type size.
    pub fn set_size(&mut self, size: Option<usize>) {
        self.size = size;
    }

    /// Whether this row is selected.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Sets the selection state.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Whether this row's node is expanded.
    pub fn is_expanded(&self) -> bool {
        self.expanded
    }

    /// Sets the expanded state.
    pub fn set_expanded(&mut self, expanded: bool) {
        self.expanded = expanded;
    }

    /// The depth level in the tree.
    pub fn depth(&self) -> usize {
        self.depth
    }
}

impl fmt::Display for DtMgrDisplayRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] ({})",
            self.name, self.node_type, self.category_path
        )
    }
}

// ---------------------------------------------------------------------------
// DataTypeManagerProvider -- the main component provider
// ---------------------------------------------------------------------------

/// The Data Type Manager component provider.
///
/// Manages the data type tree display, filtering, sorting, selection, and
/// editing within the Data Type Manager window. This is the primary UI
/// component for browsing and managing data types, categories, and archives.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DataTypeManagerProvider`.
#[derive(Debug)]
pub struct DataTypeManagerProvider {
    /// The provider name (typically "Data Type Manager").
    name: String,
    /// Whether the provider is currently visible.
    visible: bool,
    /// Whether the provider has been disposed.
    disposed: bool,
    /// The name of the connected program (if any).
    program_name: Option<String>,
    /// The display rows in the tree.
    rows: Vec<DtMgrDisplayRow>,
    /// The IDs of currently expanded nodes.
    expanded_ids: HashSet<u64>,
    /// The currently selected row ID.
    selected_id: Option<u64>,
    /// The current filter state.
    filter: FilterState,
    /// The current sort mode.
    sort_mode: SortMode,
    /// Next available row ID.
    next_id: u64,
    /// Whether the tree is in a "changed" state (needs refresh).
    changed: bool,
}

impl DataTypeManagerProvider {
    /// Creates a new DataTypeManager provider.
    pub fn new(name: impl Into<String>, visible: bool) -> Self {
        Self {
            name: name.into(),
            visible,
            disposed: false,
            program_name: None,
            rows: Vec::new(),
            expanded_ids: HashSet::new(),
            selected_id: None,
            filter: FilterState::new(),
            sort_mode: SortMode::default(),
            next_id: 1,
            changed: true,
        }
    }

    /// Returns the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Sets the visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Disposes the provider, clearing all state.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.rows.clear();
        self.expanded_ids.clear();
        self.selected_id = None;
        self.program_name = None;
    }

    // ---- Program connection ----

    /// Called when a program is opened; connects this provider to the program.
    pub fn program_opened(&mut self, program_name: impl Into<String>) {
        self.program_name = Some(program_name.into());
        self.changed = true;
    }

    /// Called when the program is closed; disconnects this provider.
    pub fn program_closed(&mut self) {
        self.program_name = None;
        self.rows.clear();
        self.expanded_ids.clear();
        self.selected_id = None;
        self.changed = true;
    }

    /// The name of the connected program, if any.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    // ---- Tree state ----

    /// Returns a reference to all display rows.
    pub fn rows(&self) -> &[DtMgrDisplayRow] {
        &self.rows
    }

    /// Returns a mutable reference to all display rows.
    pub fn rows_mut(&mut self) -> &mut Vec<DtMgrDisplayRow> {
        &mut self.rows
    }

    /// Adds a new row and returns its ID.
    pub fn add_row(
        &mut self,
        name: impl Into<String>,
        node_type: NodeType,
        category_path: impl Into<String>,
        depth: usize,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let row = DtMgrDisplayRow::new(id, name, node_type, category_path, depth);
        self.rows.push(row);
        self.changed = true;
        id
    }

    /// Removes a row by ID.
    pub fn remove_row(&mut self, id: u64) -> Option<DtMgrDisplayRow> {
        if let Some(pos) = self.rows.iter().position(|r| r.id() == id) {
            self.expanded_ids.remove(&id);
            if self.selected_id == Some(id) {
                self.selected_id = None;
            }
            self.changed = true;
            Some(self.rows.remove(pos))
        } else {
            None
        }
    }

    /// Finds a row by ID.
    pub fn find_row(&self, id: u64) -> Option<&DtMgrDisplayRow> {
        self.rows.iter().find(|r| r.id() == id)
    }

    /// Finds a mutable row by ID.
    pub fn find_row_mut(&mut self, id: u64) -> Option<&mut DtMgrDisplayRow> {
        self.rows.iter_mut().find(|r| r.id() == id)
    }

    /// Returns the number of display rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    // ---- Expanded state ----

    /// Expands a node by ID.
    pub fn expand(&mut self, id: u64) {
        self.expanded_ids.insert(id);
        if let Some(row) = self.find_row_mut(id) {
            row.set_expanded(true);
        }
    }

    /// Collapses a node by ID.
    pub fn collapse(&mut self, id: u64) {
        self.expanded_ids.remove(&id);
        if let Some(row) = self.find_row_mut(id) {
            row.set_expanded(false);
        }
    }

    /// Returns whether a node is expanded.
    pub fn is_expanded(&self, id: u64) -> bool {
        self.expanded_ids.contains(&id)
    }

    /// Returns the set of expanded node IDs.
    pub fn expanded_ids(&self) -> &HashSet<u64> {
        &self.expanded_ids
    }

    /// Expands all nodes.
    pub fn expand_all(&mut self) {
        for row in &self.rows {
            if row.node_type().has_children() {
                self.expanded_ids.insert(row.id());
            }
        }
        for row in &mut self.rows {
            if row.node_type().has_children() {
                row.set_expanded(true);
            }
        }
    }

    /// Collapses all nodes.
    pub fn collapse_all(&mut self) {
        self.expanded_ids.clear();
        for row in &mut self.rows {
            row.set_expanded(false);
        }
    }

    // ---- Selection ----

    /// Selects a row by ID.
    pub fn select(&mut self, id: u64) {
        // Deselect previous.
        if let Some(prev_id) = self.selected_id {
            if let Some(prev) = self.find_row_mut(prev_id) {
                prev.set_selected(false);
            }
        }
        self.selected_id = Some(id);
        if let Some(row) = self.find_row_mut(id) {
            row.set_selected(true);
        }
    }

    /// Deselects the current selection.
    pub fn deselect(&mut self) {
        if let Some(id) = self.selected_id {
            if let Some(row) = self.find_row_mut(id) {
                row.set_selected(false);
            }
        }
        self.selected_id = None;
    }

    /// Returns the ID of the currently selected row, if any.
    pub fn selected_id(&self) -> Option<u64> {
        self.selected_id
    }

    /// Returns a reference to the currently selected row, if any.
    pub fn selected_row(&self) -> Option<&DtMgrDisplayRow> {
        self.selected_id.and_then(|id| self.find_row(id))
    }

    // ---- Filter ----

    /// Returns a reference to the filter state.
    pub fn filter(&self) -> &FilterState {
        &self.filter
    }

    /// Returns a mutable reference to the filter state.
    pub fn filter_mut(&mut self) -> &mut FilterState {
        &mut self.filter
    }

    /// Applies the current filter and returns the IDs of visible rows.
    pub fn visible_row_ids(&self) -> Vec<u64> {
        self.rows
            .iter()
            .filter(|r| {
                if !self.filter.accepts(r.node_type()) {
                    return false;
                }
                if self.filter.is_active() {
                    let filter_text = self.filter.filter_text().to_lowercase();
                    r.name().to_lowercase().contains(&filter_text)
                        || r.category_path().to_lowercase().contains(&filter_text)
                } else {
                    true
                }
            })
            .map(|r| r.id())
            .collect()
    }

    // ---- Sort ----

    /// Returns the current sort mode.
    pub fn sort_mode(&self) -> SortMode {
        self.sort_mode
    }

    /// Sets the sort mode.
    pub fn set_sort_mode(&mut self, mode: SortMode) {
        self.sort_mode = mode;
        self.changed = true;
    }

    // ---- Refresh ----

    /// Whether the tree needs a refresh.
    pub fn is_changed(&self) -> bool {
        self.changed
    }

    /// Marks the tree as needing a refresh.
    pub fn mark_changed(&mut self) {
        self.changed = true;
    }

    /// Clears the changed flag (typically after a refresh).
    pub fn clear_changed(&mut self) {
        self.changed = false;
    }

    /// Clears all rows and resets the tree state.
    pub fn clear(&mut self) {
        self.rows.clear();
        self.expanded_ids.clear();
        self.selected_id = None;
        self.changed = true;
    }
}

impl Default for DataTypeManagerProvider {
    fn default() -> Self {
        Self::new("Data Type Manager", true)
    }
}

impl fmt::Display for DataTypeManagerProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DataTypeManagerProvider({}, rows={}, program={:?})",
            self.name,
            self.rows.len(),
            self.program_name
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = DataTypeManagerProvider::new("DTM", true);
        assert_eq!(provider.name(), "DTM");
        assert!(provider.is_visible());
        assert!(!provider.is_disposed());
        assert!(provider.program_name().is_none());
        assert_eq!(provider.row_count(), 0);
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        provider.add_row("test", NodeType::DataType, "/", 0);
        provider.dispose();
        assert!(provider.is_disposed());
        assert_eq!(provider.row_count(), 0);
    }

    #[test]
    fn test_provider_double_dispose() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        provider.dispose();
        provider.dispose(); // no-op
        assert!(provider.is_disposed());
    }

    #[test]
    fn test_program_connection() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        provider.program_opened("test.exe");
        assert_eq!(provider.program_name(), Some("test.exe"));
        assert!(provider.is_changed());

        provider.clear_changed();
        provider.program_closed();
        assert!(provider.program_name().is_none());
        assert!(provider.is_changed());
    }

    #[test]
    fn test_add_remove_row() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        let id = provider.add_row("MyStruct", NodeType::DataType, "/Structures", 1);
        assert_eq!(provider.row_count(), 1);
        assert_eq!(provider.find_row(id).unwrap().name(), "MyStruct");

        let removed = provider.remove_row(id);
        assert!(removed.is_some());
        assert_eq!(provider.row_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_row() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        assert!(provider.remove_row(999).is_none());
    }

    #[test]
    fn test_expand_collapse() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        let id = provider.add_row("Structures", NodeType::Category, "/", 0);

        provider.expand(id);
        assert!(provider.is_expanded(id));
        assert!(provider.find_row(id).unwrap().is_expanded());

        provider.collapse(id);
        assert!(!provider.is_expanded(id));
        assert!(!provider.find_row(id).unwrap().is_expanded());
    }

    #[test]
    fn test_expand_all_collapse_all() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        let cat1 = provider.add_row("Cat1", NodeType::Category, "/", 0);
        let cat2 = provider.add_row("Cat2", NodeType::Category, "/", 0);
        provider.add_row("Type1", NodeType::DataType, "/Cat1", 1);

        provider.expand_all();
        assert!(provider.is_expanded(cat1));
        assert!(provider.is_expanded(cat2));

        provider.collapse_all();
        assert!(!provider.is_expanded(cat1));
        assert!(!provider.is_expanded(cat2));
    }

    #[test]
    fn test_selection() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        let id1 = provider.add_row("Type1", NodeType::DataType, "/", 0);
        let id2 = provider.add_row("Type2", NodeType::DataType, "/", 0);

        provider.select(id1);
        assert_eq!(provider.selected_id(), Some(id1));
        assert!(provider.find_row(id1).unwrap().is_selected());

        provider.select(id2);
        assert_eq!(provider.selected_id(), Some(id2));
        assert!(!provider.find_row(id1).unwrap().is_selected());
        assert!(provider.find_row(id2).unwrap().is_selected());

        provider.deselect();
        assert!(provider.selected_id().is_none());
    }

    #[test]
    fn test_selected_row() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        assert!(provider.selected_row().is_none());

        let id = provider.add_row("Type1", NodeType::DataType, "/", 0);
        provider.select(id);
        assert_eq!(provider.selected_row().unwrap().name(), "Type1");
    }

    #[test]
    fn test_filter_visibility() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        provider.add_row("Struct", NodeType::DataType, "/", 0);
        provider.add_row("BuiltIn", NodeType::BuiltIn, "/", 0);
        provider.add_row("Ptr", NodeType::Pointer, "/", 0);
        provider.add_row("Cat1", NodeType::Category, "/", 0);

        // Default: all visible.
        assert_eq!(provider.visible_row_ids().len(), 4);

        // Hide builtins.
        provider.filter_mut().set_show_builtins(false);
        assert_eq!(provider.visible_row_ids().len(), 3);

        // Hide pointers too.
        provider.filter_mut().set_show_pointers(false);
        assert_eq!(provider.visible_row_ids().len(), 2);

        // Restore all, apply text filter.
        provider.filter_mut().set_show_builtins(true);
        provider.filter_mut().set_show_pointers(true);
        provider.filter_mut().set_filter_text("Struct");
        let visible = provider.visible_row_ids();
        assert_eq!(visible.len(), 1);
        assert_eq!(provider.find_row(visible[0]).unwrap().name(), "Struct");
    }

    #[test]
    fn test_filter_text_match_category_path() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        provider.add_row("MyType", NodeType::DataType, "/Structures", 0);
        provider.add_row("Other", NodeType::DataType, "/Other", 0);

        provider.filter_mut().set_filter_text("Structures");
        let visible = provider.visible_row_ids();
        assert_eq!(visible.len(), 1);
        assert_eq!(provider.find_row(visible[0]).unwrap().name(), "MyType");
    }

    #[test]
    fn test_filter_clear() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        provider.filter_mut().set_filter_text("test");
        assert!(provider.filter().is_active());
        provider.filter_mut().clear();
        assert!(!provider.filter().is_active());
    }

    #[test]
    fn test_sort_mode() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        assert_eq!(provider.sort_mode(), SortMode::Name);

        provider.set_sort_mode(SortMode::Size);
        assert_eq!(provider.sort_mode(), SortMode::Size);
        assert!(provider.is_changed());
    }

    #[test]
    fn test_refresh_state() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        assert!(provider.is_changed()); // new provider starts as changed

        provider.clear_changed();
        assert!(!provider.is_changed());

        provider.mark_changed();
        assert!(provider.is_changed());
    }

    #[test]
    fn test_clear() {
        let mut provider = DataTypeManagerProvider::new("DTM", true);
        provider.add_row("Type1", NodeType::DataType, "/", 0);
        let id = provider.add_row("Cat1", NodeType::Category, "/", 0);
        provider.expand(id);
        provider.select(id);

        provider.clear();
        assert_eq!(provider.row_count(), 0);
        assert!(provider.selected_id().is_none());
        assert!(provider.expanded_ids().is_empty());
        assert!(provider.is_changed());
    }

    #[test]
    fn test_visibility() {
        let mut provider = DataTypeManagerProvider::new("DTM", false);
        assert!(!provider.is_visible());
        provider.set_visible(true);
        assert!(provider.is_visible());
    }

    // ---- NodeType tests ----

    #[test]
    fn test_node_type_is_leaf() {
        assert!(NodeType::DataType.is_leaf());
        assert!(NodeType::BuiltIn.is_leaf());
        assert!(NodeType::Pointer.is_leaf());
        assert!(NodeType::FunctionDef.is_leaf());
        assert!(!NodeType::Category.is_leaf());
        assert!(!NodeType::Root.is_leaf());
        assert!(!NodeType::Archive.is_leaf());
    }

    #[test]
    fn test_node_type_has_children() {
        assert!(NodeType::Category.has_children());
        assert!(NodeType::Root.has_children());
        assert!(NodeType::Archive.has_children());
        assert!(!NodeType::DataType.has_children());
        assert!(!NodeType::BuiltIn.has_children());
    }

    #[test]
    fn test_node_type_display() {
        assert_eq!(format!("{}", NodeType::Category), "Category");
        assert_eq!(format!("{}", NodeType::DataType), "DataType");
        assert_eq!(format!("{}", NodeType::Root), "Root");
    }

    // ---- SortMode tests ----

    #[test]
    fn test_sort_mode_default() {
        assert_eq!(SortMode::default(), SortMode::Name);
    }

    #[test]
    fn test_sort_mode_all() {
        assert_eq!(SortMode::all().len(), 4);
    }

    #[test]
    fn test_sort_mode_display() {
        assert_eq!(format!("{}", SortMode::Name), "Name");
        assert_eq!(format!("{}", SortMode::Size), "Size");
        assert_eq!(format!("{}", SortMode::LastModified), "Last Modified");
        assert_eq!(format!("{}", SortMode::UsageCount), "Usage Count");
    }

    // ---- FilterState tests ----

    #[test]
    fn test_filter_state_default() {
        let filter = FilterState::new();
        assert!(!filter.is_active());
        assert!(filter.show_builtins());
        assert!(filter.show_pointers());
        assert!(filter.show_function_defs());
        assert!(filter.show_categories());
        assert!(filter.filter_text().is_empty());
    }

    #[test]
    fn test_filter_state_accepts() {
        let filter = FilterState::new();
        assert!(filter.accepts(NodeType::Root));
        assert!(filter.accepts(NodeType::Archive));
        assert!(filter.accepts(NodeType::Category));
        assert!(filter.accepts(NodeType::DataType));
        assert!(filter.accepts(NodeType::BuiltIn));
        assert!(filter.accepts(NodeType::Pointer));
        assert!(filter.accepts(NodeType::FunctionDef));
    }

    #[test]
    fn test_filter_state_accepts_with_restrictions() {
        let mut filter = FilterState::new();
        filter.set_show_builtins(false);
        filter.set_show_pointers(false);
        assert!(!filter.accepts(NodeType::BuiltIn));
        assert!(!filter.accepts(NodeType::Pointer));
        assert!(filter.accepts(NodeType::DataType));
        assert!(filter.accepts(NodeType::Category));
    }

    #[test]
    fn test_filter_state_display() {
        let mut filter = FilterState::new();
        assert_eq!(format!("{}", filter), "Filter(inactive)");

        filter.set_filter_text("test");
        let s = format!("{}", filter);
        assert!(s.contains("test"));
    }

    // ---- DtMgrDisplayRow tests ----

    #[test]
    fn test_display_row_creation() {
        let row = DtMgrDisplayRow::new(1, "MyStruct", NodeType::DataType, "/Structures", 1);
        assert_eq!(row.id(), 1);
        assert_eq!(row.name(), "MyStruct");
        assert_eq!(row.node_type(), NodeType::DataType);
        assert_eq!(row.category_path(), "/Structures");
        assert_eq!(row.depth(), 1);
        assert!(!row.is_selected());
        assert!(!row.is_expanded());
        assert!(row.size().is_none());
    }

    #[test]
    fn test_display_row_modification() {
        let mut row = DtMgrDisplayRow::new(1, "test", NodeType::DataType, "/", 0);
        row.set_name("renamed");
        assert_eq!(row.name(), "renamed");

        row.set_size(Some(16));
        assert_eq!(row.size(), Some(16));

        row.set_selected(true);
        assert!(row.is_selected());

        row.set_expanded(true);
        assert!(row.is_expanded());

        row.set_category_path("/NewPath");
        assert_eq!(row.category_path(), "/NewPath");
    }

    #[test]
    fn test_display_row_display() {
        let row = DtMgrDisplayRow::new(1, "MyStruct", NodeType::DataType, "/Structures", 1);
        let s = format!("{}", row);
        assert!(s.contains("MyStruct"));
        assert!(s.contains("DataType"));
        assert!(s.contains("/Structures"));
    }

    // ---- Display impls ----

    #[test]
    fn test_provider_display() {
        let provider = DataTypeManagerProvider::new("DTM", true);
        let s = format!("{}", provider);
        assert!(s.contains("DTM"));
        assert!(s.contains("rows=0"));
    }

    #[test]
    fn test_default_provider() {
        let provider = DataTypeManagerProvider::default();
        assert_eq!(provider.name(), "Data Type Manager");
    }
}
