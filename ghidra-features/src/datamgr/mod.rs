//! Data Type Manager plugin components for Ghidra Rust.
//!
//! This module is a Rust port of Ghidra's
//! `ghidra.app.plugin.core.datamgr` and `ghidra.app.plugin.core.data`
//! Java packages.  It provides:
//!
//! - **Archive management** ([`archive`]): Trait and concrete types for
//!   built-in, file-backed, program, project, and invalid archives.
//!
//! - **Synchronization** ([`sync`]): Tracking and reconciling data type
//!   differences between a program and its source archives via
//!   [`DataTypeSyncState`], [`DataTypeSyncInfo`], and [`DataTypeSynchronizer`].
//!
//! - **Handler** ([`handler`]): [`DataTypeManagerHandler`] -- the central
//!   coordinator that tracks all open archives, manages the built-in
//!   manager, and provides the lookup / lifecycle operations used by the
//!   rest of the plugin.
//!
//! - **Editor management** ([`editor`]): [`DataTypeEditorManager`] with
//!   [`EditorProvider`] for creating, opening, checking, and dismissing
//!   inline structure / union / enum editors.
//!
//! - **Tree model** ([`tree`]): A node hierarchy rooted at
//!   [`ArchiveRootNode`] with [`ArchiveNode`], [`CategoryNode`], and
//!   [`DataTypeNode`] for the data-type tree view.
//!
//! # Quick start
//!
//! ```rust
//! use ghidra_features::datamgr::handler::DataTypeManagerHandler;
//!
//! let mut handler = DataTypeManagerHandler::new("My Plugin");
//! assert_eq!(handler.all_archives().len(), 0);
//! ```

pub mod actions;
pub mod archive;
pub mod dialog;
pub mod dnd;
pub mod enum_table;
pub mod filter;
pub mod find_actions;
pub mod sync;
pub mod handler;
pub mod plugin;
pub mod property_manager;
pub mod provider;
pub mod editor;
pub mod tasks;
pub mod tree;
pub mod util;
pub mod utils;

/// Extended data type manager actions (create, delete, rename, merge, etc.).
///
/// Ported from individual action classes in
/// `ghidra.app.plugin.core.datamgr.actions`.
pub mod actions_ext;

/// Data type clipboard operations (cut/copy/paste).
///
/// Ported from cut/copy/paste actions in
/// `ghidra.app.plugin.core.datamgr.actions`.
pub mod clipboard;

/// Data type tree operations (create/rename/delete categories and types).
///
/// Ported from action and tree management classes in
/// `ghidra.app.plugin.core.datamgr.actions` and
/// `ghidra.app.plugin.core.datamgr.tree`.
pub mod tree_ops;

/// Data type association management (sync, commit, revert, update).
///
/// Ported from `ghidra.app.plugin.core.datamgr.actions.associate`.
pub mod associate;

/// Data type sync table model, derivative info, duplicate ID exceptions,
/// and archive utilities.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DataTypeSyncTableModel`,
/// `DerivativeDataTypeInfo`, `DuplicateIdException`, and `ArchiveUtils`.
pub mod sync_table;

/// Archive lifecycle operations: open, close, save, lock, unlock, merge,
/// undo/redo, and detailed sync information for individual data types.
///
/// Ported from archive action classes and DataTypeSyncInfo in
/// `ghidra.app.plugin.core.datamgr`.
pub mod archive_ops;

/// Additional tree node types (BuiltInArchiveNode, ProgramArchiveNode,
/// ProjectArchiveNode, InvalidArchiveNode, etc.).
///
/// Ported from individual tree node classes in
/// `ghidra.app.plugin.core.datamgr.tree`.
pub mod tree_nodes;

/// Archive management actions: create, delete, save-as, open, close,
/// lock, unlock, expand/collapse, merge dialogs, and undo/redo.
///
/// Ported from action classes in `ghidra.app.plugin.core.datamgr.actions`.
pub mod actions_archive;

/// Data type-specific actions: apply enums as labels, capture function
/// data types, create enums from selection, find enums by value.
///
/// Ported from action classes in `ghidra.app.plugin.core.datamgr.actions`.
pub mod actions_datatype;

/// Concrete association action implementations: commit, revert, update,
/// disassociate, sync refresh.
///
/// Ported from action classes in
/// `ghidra.app.plugin.core.datamgr.actions.associate`.
pub mod actions_associate_impl;

// Re-export the most-used public types at the datamgr level.
pub use archive::{Archive, ArchiveKind, BuiltInArchive, FileArchive, ProgramArchive,
                   ProjectArchive, InvalidFileArchive, ArchiveManagerListener};
pub use sync::{DataTypeSyncState, DataTypeSyncInfo, DataTypeSynchronizer};
pub use handler::DataTypeManagerHandler;
pub use editor::{DataTypeEditorManager, EditorProvider, EditorState, EditorListener};
pub use plugin::DataTypeManagerPlugin;
pub use property_manager::DataTypePropertyManager;
pub use provider::{DataTypesProvider, DataTypesConfig};
pub use dialog::{DataTypeSyncDialog, DataTypeSyncTableModel, SyncDialogLayout};
pub use util::{RecentArchiveTracker, DataTypeSelection, AllowedDataTypes};
pub use tree::{TreeNodeKind, ArchiveRootNode, ArchiveNode, CategoryNode, DataTypeNode};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Filter state for the data type tree
// ---------------------------------------------------------------------------

/// Filter configuration for the data type tree.
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.DtFilterState`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtFilterState {
    /// Text filter pattern.
    pub name_filter: String,
    /// Whether to show only recently used types.
    pub show_recent_only: bool,
    /// Whether to show categories.
    pub show_categories: bool,
    /// Maximum size to show (0 = unlimited).
    pub max_size: u64,
}

impl Default for DtFilterState {
    fn default() -> Self {
        Self {
            name_filter: String::new(),
            show_recent_only: false,
            show_categories: true,
            max_size: 0,
        }
    }
}

impl DtFilterState {
    /// Check if a type name passes the filter.
    pub fn matches(&self, name: &str) -> bool {
        if self.name_filter.is_empty() {
            return true;
        }
        name.to_lowercase().contains(&self.name_filter.to_lowercase())
    }
}

// ---------------------------------------------------------------------------
// NextPreviousDataTypeAction -- navigate recently used types
// ---------------------------------------------------------------------------

/// Action context for navigating through recently used data types.
///
/// Ported from `ghidra.app.plugin.core.datamgr.NextPreviousDataTypeAction`.
#[derive(Debug, Clone, Default)]
pub struct DataTypeNavigator {
    /// Recently used data type names (most recent first).
    pub recent: Vec<String>,
    /// Current position in the recent list.
    pub position: usize,
}

impl DataTypeNavigator {
    /// Create a new navigator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a data type was used.
    pub fn record_use(&mut self, type_name: &str) {
        self.recent.retain(|n| n != type_name);
        self.recent.insert(0, type_name.to_string());
        self.position = 0;
    }

    /// Go to the previous (older) recently used type.
    pub fn go_previous(&mut self) -> Option<&str> {
        if self.position + 1 < self.recent.len() {
            self.position += 1;
            self.recent.get(self.position).map(|s| s.as_str())
        } else {
            None
        }
    }

    /// Go to the next (newer) recently used type.
    pub fn go_next(&mut self) -> Option<&str> {
        if self.position > 0 {
            self.position -= 1;
            self.recent.get(self.position).map(|s| s.as_str())
        } else {
            None
        }
    }

    /// Get the current recently used type.
    pub fn current(&self) -> Option<&str> {
        self.recent.get(self.position).map(|s| s.as_str())
    }

    /// Number of recently used types.
    pub fn count(&self) -> usize {
        self.recent.len()
    }
}

// ---------------------------------------------------------------------------
// DataTypeComparePanel -- side-by-side comparison of two data types
// ---------------------------------------------------------------------------

/// Panel for comparing two data types side-by-side.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DataTypeComparePanel`.
#[derive(Debug, Clone)]
pub struct DataTypeComparePanel {
    /// The left (source) data type name.
    pub left_type_name: String,
    /// The right (destination) data type name.
    pub right_type_name: String,
    /// Differences found between the two types.
    pub differences: Vec<DataTypeDifference>,
    /// Whether to show matching fields.
    pub show_matching: bool,
}

/// A single difference between two data types.
#[derive(Debug, Clone)]
pub struct DataTypeDifference {
    /// The field name or path where the difference occurs.
    pub field_path: String,
    /// Description of the difference.
    pub description: String,
    /// The value in the left type.
    pub left_value: String,
    /// The value in the right type.
    pub right_value: String,
    /// Severity of the difference.
    pub severity: DifferenceSeverity,
}

/// Severity of a data type difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifferenceSeverity {
    /// Informational difference (e.g., comment mismatch).
    Info,
    /// Warning-level difference (e.g., size mismatch).
    Warning,
    /// Error-level difference (e.g., incompatible types).
    Error,
}

impl DataTypeComparePanel {
    /// Create a new comparison panel.
    pub fn new(left: impl Into<String>, right: impl Into<String>) -> Self {
        Self {
            left_type_name: left.into(),
            right_type_name: right.into(),
            differences: Vec::new(),
            show_matching: true,
        }
    }

    /// Add a difference to the panel.
    pub fn add_difference(&mut self, diff: DataTypeDifference) {
        self.differences.push(diff);
    }

    /// Get the number of differences.
    pub fn difference_count(&self) -> usize {
        self.differences.len()
    }

    /// Get differences filtered by severity.
    pub fn differences_by_severity(&self, severity: DifferenceSeverity) -> Vec<&DataTypeDifference> {
        self.differences.iter().filter(|d| d.severity == severity).collect()
    }

    /// Whether there are any error-level differences.
    pub fn has_errors(&self) -> bool {
        self.differences.iter().any(|d| d.severity == DifferenceSeverity::Error)
    }
}

// ---------------------------------------------------------------------------
// DefaultDataTypeArchiveService
// ---------------------------------------------------------------------------

/// Default implementation of the data type archive service.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DefaultDataTypeArchiveService`.
#[derive(Debug)]
pub struct DefaultDataTypeArchiveService {
    /// Registered archive paths.
    pub archive_paths: Vec<String>,
    /// Whether the service is initialized.
    pub initialized: bool,
}

impl DefaultDataTypeArchiveService {
    /// Create a new default archive service.
    pub fn new() -> Self {
        Self {
            archive_paths: Vec::new(),
            initialized: false,
        }
    }

    /// Initialize the service with default archive paths.
    pub fn initialize(&mut self) {
        self.archive_paths.push("builtins".to_string());
        self.initialized = true;
    }

    /// Register an archive path.
    pub fn register_archive(&mut self, path: impl Into<String>) {
        self.archive_paths.push(path.into());
    }

    /// Get the number of registered archives.
    pub fn archive_count(&self) -> usize {
        self.archive_paths.len()
    }
}

impl Default for DefaultDataTypeArchiveService {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ArchiveFileChooser
// ---------------------------------------------------------------------------

/// File chooser for selecting data type archives.
///
/// Ported from `ghidra.app.plugin.core.datamgr.ArchiveFileChooser`.
#[derive(Debug, Clone)]
pub struct ArchiveFileChooser {
    /// The selected file path.
    pub selected_path: Option<String>,
    /// Whether to show only project archives.
    pub project_only: bool,
    /// File extension filters.
    pub filters: Vec<ArchiveFileFilter>,
}

/// A file filter for archive file choosers.
#[derive(Debug, Clone)]
pub struct ArchiveFileFilter {
    /// The filter description.
    pub description: String,
    /// The file extensions this filter matches.
    pub extensions: Vec<String>,
}

impl ArchiveFileChooser {
    /// Create a new archive file chooser.
    pub fn new() -> Self {
        Self {
            selected_path: None,
            project_only: false,
            filters: vec![
                ArchiveFileFilter {
                    description: "Ghidra Archive Files".to_string(),
                    extensions: vec!["gdt".to_string()],
                },
                ArchiveFileFilter {
                    description: "All Files".to_string(),
                    extensions: vec!["*".to_string()],
                },
            ],
        }
    }

    /// Set the selected path.
    pub fn select(&mut self, path: impl Into<String>) {
        self.selected_path = Some(path.into());
    }

    /// Get the selected path.
    pub fn get_selected(&self) -> Option<&str> {
        self.selected_path.as_deref()
    }
}

impl Default for ArchiveFileChooser {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DtFilterDialog
// ---------------------------------------------------------------------------

/// Dialog for configuring data type tree filters.
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.DtFilterDialog`.
#[derive(Debug, Clone)]
pub struct DtFilterDialog {
    /// Current filter state.
    pub filter_state: DtFilterState,
    /// Whether the dialog was accepted.
    pub accepted: bool,
    /// Available filter categories.
    pub categories: Vec<String>,
}

impl DtFilterDialog {
    /// Create a new filter dialog with the given state.
    pub fn new(state: DtFilterState) -> Self {
        Self {
            filter_state: state,
            accepted: false,
            categories: Vec::new(),
        }
    }

    /// Simulate accepting the dialog.
    pub fn accept(&mut self) {
        self.accepted = true;
    }

    /// Simulate cancelling the dialog.
    pub fn cancel(&mut self) {
        self.accepted = false;
    }

    /// Add a category to filter by.
    pub fn add_category(&mut self, category: impl Into<String>) {
        self.categories.push(category.into());
    }
}

// ---------------------------------------------------------------------------
// DtFilterAction
// ---------------------------------------------------------------------------

/// Action to open the data type tree filter dialog.
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.DtFilterAction`.
#[derive(Debug, Clone)]
pub struct DtFilterAction {
    /// The action name.
    pub name: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Current filter state.
    pub filter_state: DtFilterState,
}

impl DtFilterAction {
    /// Create a new filter action.
    pub fn new() -> Self {
        Self {
            name: "Filter Data Types".to_string(),
            enabled: true,
            filter_state: DtFilterState::default(),
        }
    }

    /// Execute the action, returning the new filter state.
    pub fn execute(&self) -> DtFilterState {
        self.filter_state.clone()
    }
}

impl Default for DtFilterAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SecondaryTreeFilterProvider
// ---------------------------------------------------------------------------

/// Provider for secondary tree filtering in the data type manager.
///
/// Ported from `ghidra.app.plugin.core.datamgr.SecondaryTreeFilterProvider`.
#[derive(Debug, Clone)]
pub struct SecondaryTreeFilterProvider {
    /// The filter text.
    pub filter_text: String,
    /// Whether the filter is active.
    pub active: bool,
    /// The column index to filter on (None = all columns).
    pub filter_column: Option<usize>,
}

impl SecondaryTreeFilterProvider {
    /// Create a new secondary filter provider.
    pub fn new() -> Self {
        Self {
            filter_text: String::new(),
            active: false,
            filter_column: None,
        }
    }

    /// Set the filter text and activate the filter.
    pub fn set_filter(&mut self, text: impl Into<String>) {
        self.filter_text = text.into();
        self.active = !self.filter_text.is_empty();
    }

    /// Clear the filter.
    pub fn clear(&mut self) {
        self.filter_text.clear();
        self.active = false;
        self.filter_column = None;
    }

    /// Check if an item passes the filter.
    pub fn matches(&self, text: &str) -> bool {
        if !self.active || self.filter_text.is_empty() {
            return true;
        }
        text.to_lowercase().contains(&self.filter_text.to_lowercase())
    }
}

impl Default for SecondaryTreeFilterProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TypeGraphTask
// ---------------------------------------------------------------------------

/// Task for generating a data type dependency graph.
///
/// Ported from `ghidra.app.plugin.core.datamgr.TypeGraphTask`.
#[derive(Debug, Clone)]
pub struct TypeGraphTask {
    /// The root type name to graph from.
    pub root_type: String,
    /// Maximum depth to traverse.
    pub max_depth: usize,
    /// Discovered type dependencies.
    pub dependencies: Vec<TypeDependency>,
    /// Whether the task completed successfully.
    pub completed: bool,
}

/// A dependency edge in the type graph.
#[derive(Debug, Clone)]
pub struct TypeDependency {
    /// The source type name.
    pub from_type: String,
    /// The target type name.
    pub to_type: String,
    /// The kind of dependency.
    pub kind: DependencyKind,
}

/// The kind of type dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyKind {
    /// Type contains another type as a field.
    Contains,
    /// Type is a pointer to another type.
    PointerTo,
    /// Type is an array of another type.
    ArrayOf,
    /// Type is a typedef of another type.
    TypeDefOf,
    /// Type is a function return type.
    ReturnType,
    /// Type is a function parameter type.
    ParameterType,
}

impl TypeGraphTask {
    /// Create a new type graph task.
    pub fn new(root: impl Into<String>, max_depth: usize) -> Self {
        Self {
            root_type: root.into(),
            max_depth,
            dependencies: Vec::new(),
            completed: false,
        }
    }

    /// Add a dependency to the graph.
    pub fn add_dependency(&mut self, dep: TypeDependency) {
        self.dependencies.push(dep);
    }

    /// Mark the task as completed.
    pub fn complete(&mut self) {
        self.completed = true;
    }

    /// Get the number of discovered dependencies.
    pub fn dependency_count(&self) -> usize {
        self.dependencies.len()
    }
}

// ---------------------------------------------------------------------------
// FindReferencesToEnumFieldAction
// ---------------------------------------------------------------------------

/// Action to find references to a specific enum field.
///
/// Ported from `ghidra.app.plugin.core.datamgr.FindReferencesToEnumFieldAction`.
#[derive(Debug, Clone)]
pub struct FindReferencesToEnumFieldAction {
    /// The enum type name.
    pub enum_name: String,
    /// The field name to find references to.
    pub field_name: String,
    /// Discovered references.
    pub references: Vec<EnumFieldReference>,
}

/// A reference to an enum field.
#[derive(Debug, Clone)]
pub struct EnumFieldReference {
    /// The address of the reference.
    pub address: u64,
    /// The function containing the reference, if any.
    pub function_name: Option<String>,
    /// The operand index where the reference appears.
    pub operand_index: usize,
}

impl FindReferencesToEnumFieldAction {
    /// Create a new action.
    pub fn new(enum_name: impl Into<String>, field_name: impl Into<String>) -> Self {
        Self {
            enum_name: enum_name.into(),
            field_name: field_name.into(),
            references: Vec::new(),
        }
    }

    /// Add a reference.
    pub fn add_reference(&mut self, reference: EnumFieldReference) {
        self.references.push(reference);
    }

    /// Get the number of references found.
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }
}

// ---------------------------------------------------------------------------
// FindReferencesToFieldByNameOrOffsetAction
// ---------------------------------------------------------------------------

/// Action to find references to a structure field by name or offset.
///
/// Ported from `ghidra.app.plugin.core.datamgr.FindReferencesToFieldByNameOrOffsetAction`.
#[derive(Debug, Clone)]
pub struct FindReferencesToFieldByNameOrOffsetAction {
    /// The structure type name.
    pub structure_name: String,
    /// Search by field name (if set).
    pub field_name: Option<String>,
    /// Search by byte offset (if set).
    pub offset: Option<u64>,
    /// Discovered references.
    pub references: Vec<FieldReference>,
}

/// A reference to a structure field.
#[derive(Debug, Clone)]
pub struct FieldReference {
    /// The address of the reference.
    pub address: u64,
    /// The field name at the reference.
    pub field_name: String,
    /// The byte offset within the structure.
    pub offset: u64,
}

impl FindReferencesToFieldByNameOrOffsetAction {
    /// Create a new action searching by field name.
    pub fn by_name(structure: impl Into<String>, field: impl Into<String>) -> Self {
        Self {
            structure_name: structure.into(),
            field_name: Some(field.into()),
            offset: None,
            references: Vec::new(),
        }
    }

    /// Create a new action searching by offset.
    pub fn by_offset(structure: impl Into<String>, offset: u64) -> Self {
        Self {
            structure_name: structure.into(),
            field_name: None,
            offset: Some(offset),
            references: Vec::new(),
        }
    }

    /// Add a reference.
    pub fn add_reference(&mut self, reference: FieldReference) {
        self.references.push(reference);
    }

    /// Get the number of references found.
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dt_filter_state_default() {
        let filter = DtFilterState::default();
        assert!(filter.name_filter.is_empty());
        assert!(!filter.show_recent_only);
        assert!(filter.show_categories);
    }

    #[test]
    fn test_dt_filter_state_matches() {
        let filter = DtFilterState { name_filter: "int".to_string(), ..Default::default() };
        assert!(filter.matches("int"));
        assert!(filter.matches("Integer"));
        assert!(filter.matches("uint32"));
        assert!(!filter.matches("float"));
    }

    #[test]
    fn test_dt_filter_state_empty_filter() {
        let filter = DtFilterState::default();
        assert!(filter.matches("anything"));
        assert!(filter.matches(""));
    }

    #[test]
    fn test_data_type_navigator_record_use() {
        let mut nav = DataTypeNavigator::new();
        nav.record_use("int");
        nav.record_use("float");
        nav.record_use("char");
        assert_eq!(nav.count(), 3);
        assert_eq!(nav.current(), Some("char"));
    }

    #[test]
    fn test_data_type_navigator_dedup() {
        let mut nav = DataTypeNavigator::new();
        nav.record_use("int");
        nav.record_use("float");
        nav.record_use("int");
        assert_eq!(nav.count(), 2);
        assert_eq!(nav.current(), Some("int"));
    }

    #[test]
    fn test_data_type_navigator_navigation() {
        let mut nav = DataTypeNavigator::new();
        nav.record_use("int");
        nav.record_use("float");
        nav.record_use("char");
        // Current: "char"
        assert_eq!(nav.current(), Some("char"));
        // Previous: "float"
        assert_eq!(nav.go_previous(), Some("float"));
        // Previous: "int"
        assert_eq!(nav.go_previous(), Some("int"));
        // Can't go further back
        assert_eq!(nav.go_previous(), None);
        // Next: "float"
        assert_eq!(nav.go_next(), Some("float"));
        // Next: "char"
        assert_eq!(nav.go_next(), Some("char"));
        // Can't go further forward
        assert_eq!(nav.go_next(), None);
    }

    // -- DataTypeComparePanel tests --

    #[test]
    fn test_compare_panel_basic() {
        let panel = DataTypeComparePanel::new("StructA", "StructB");
        assert_eq!(panel.left_type_name, "StructA");
        assert_eq!(panel.right_type_name, "StructB");
        assert_eq!(panel.difference_count(), 0);
        assert!(!panel.has_errors());
    }

    #[test]
    fn test_compare_panel_add_differences() {
        let mut panel = DataTypeComparePanel::new("A", "B");
        panel.add_difference(DataTypeDifference {
            field_path: "field1".into(),
            description: "type mismatch".into(),
            left_value: "int".into(),
            right_value: "float".into(),
            severity: DifferenceSeverity::Error,
        });
        panel.add_difference(DataTypeDifference {
            field_path: "field2".into(),
            description: "size mismatch".into(),
            left_value: "4".into(),
            right_value: "8".into(),
            severity: DifferenceSeverity::Warning,
        });
        assert_eq!(panel.difference_count(), 2);
        assert!(panel.has_errors());
        assert_eq!(panel.differences_by_severity(DifferenceSeverity::Warning).len(), 1);
        assert_eq!(panel.differences_by_severity(DifferenceSeverity::Info).len(), 0);
    }

    // -- DefaultDataTypeArchiveService tests --

    #[test]
    fn test_default_archive_service() {
        let mut svc = DefaultDataTypeArchiveService::new();
        assert!(!svc.initialized);
        assert_eq!(svc.archive_count(), 0);
        svc.initialize();
        assert!(svc.initialized);
        assert_eq!(svc.archive_count(), 1);
        svc.register_archive("/path/to/archive.gdt");
        assert_eq!(svc.archive_count(), 2);
    }

    // -- ArchiveFileChooser tests --

    #[test]
    fn test_archive_file_chooser() {
        let mut chooser = ArchiveFileChooser::new();
        assert!(chooser.get_selected().is_none());
        assert_eq!(chooser.filters.len(), 2);
        chooser.select("/some/path.gdt");
        assert_eq!(chooser.get_selected(), Some("/some/path.gdt"));
    }

    // -- DtFilterDialog tests --

    #[test]
    fn test_dt_filter_dialog() {
        let state = DtFilterState { name_filter: "test".into(), ..Default::default() };
        let mut dialog = DtFilterDialog::new(state);
        assert!(!dialog.accepted);
        dialog.add_category("Structures");
        dialog.add_category("Enums");
        assert_eq!(dialog.categories.len(), 2);
        dialog.accept();
        assert!(dialog.accepted);
        dialog.cancel();
        assert!(!dialog.accepted);
    }

    // -- DtFilterAction tests --

    #[test]
    fn test_dt_filter_action() {
        let action = DtFilterAction::new();
        assert!(action.enabled);
        let state = action.execute();
        assert!(state.name_filter.is_empty());
    }

    // -- SecondaryTreeFilterProvider tests --

    #[test]
    fn test_secondary_filter_provider() {
        let mut provider = SecondaryTreeFilterProvider::new();
        assert!(!provider.active);
        assert!(provider.matches("anything"));
        provider.set_filter("int");
        assert!(provider.active);
        assert!(provider.matches("Integer"));
        assert!(!provider.matches("float"));
        provider.clear();
        assert!(!provider.active);
        assert!(provider.matches("float"));
    }

    // -- TypeGraphTask tests --

    #[test]
    fn test_type_graph_task() {
        let mut task = TypeGraphTask::new("MyStruct", 3);
        assert!(!task.completed);
        assert_eq!(task.dependency_count(), 0);
        task.add_dependency(TypeDependency {
            from_type: "MyStruct".into(),
            to_type: "int".into(),
            kind: DependencyKind::Contains,
        });
        task.add_dependency(TypeDependency {
            from_type: "MyStruct".into(),
            to_type: "char".into(),
            kind: DependencyKind::PointerTo,
        });
        assert_eq!(task.dependency_count(), 2);
        task.complete();
        assert!(task.completed);
    }

    // -- FindReferencesToEnumFieldAction tests --

    #[test]
    fn test_find_enum_field_refs() {
        let mut action = FindReferencesToEnumFieldAction::new("Color", "RED");
        assert_eq!(action.reference_count(), 0);
        action.add_reference(EnumFieldReference {
            address: 0x1000,
            function_name: Some("main".into()),
            operand_index: 0,
        });
        assert_eq!(action.reference_count(), 1);
    }

    // -- FindReferencesToFieldByNameOrOffsetAction tests --

    #[test]
    fn test_find_field_refs_by_name() {
        let mut action = FindReferencesToFieldByNameOrOffsetAction::by_name("Point", "x");
        assert!(action.field_name.is_some());
        assert!(action.offset.is_none());
        action.add_reference(FieldReference {
            address: 0x2000,
            field_name: "x".into(),
            offset: 0,
        });
        assert_eq!(action.reference_count(), 1);
    }

    #[test]
    fn test_find_field_refs_by_offset() {
        let mut action = FindReferencesToFieldByNameOrOffsetAction::by_offset("Point", 4);
        assert!(action.field_name.is_none());
        assert_eq!(action.offset, Some(4));
        action.add_reference(FieldReference {
            address: 0x3000,
            field_name: "y".into(),
            offset: 4,
        });
        assert_eq!(action.reference_count(), 1);
    }
}

