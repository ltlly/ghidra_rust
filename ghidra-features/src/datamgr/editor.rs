//! Data type editor management.
//!
//! Ported from Ghidra's `DataTypeEditorManager` Java class and
//! associated types (`EditorProvider`, `EditorOptionManager`,
//! `EditorListener`, `EditorState`).
//!
//! The [`DataTypeEditorManager`] tracks all open inline editors for
//! composite types (structure, union, enum) and function definitions.
//! It ensures that only one editor is open per data type, provides
//! save/change detection, and handles the creation of new types.

use ghidra_core::data::{
    CategoryPath, DataTypeManager, DataTypePath,
};
use std::fmt;

// ---------------------------------------------------------------------------
// EditorState
// ---------------------------------------------------------------------------

/// The current state of an editor session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EditorState {
    /// The editor is open with no unsaved changes.
    Clean,
    /// The editor has unsaved modifications.
    Dirty,
    /// The editor has been applied (saved to the data type manager).
    Applied,
    /// The editor was closed without saving.
    Discarded,
}

impl EditorState {
    /// Returns `true` if the editor has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        *self == Self::Dirty
    }

    /// Returns `true` if the editor has been applied.
    pub fn is_applied(&self) -> bool {
        *self == Self::Applied
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Clean => "Clean",
            Self::Dirty => "Dirty",
            Self::Applied => "Applied",
            Self::Discarded => "Discarded",
        }
    }
}

impl fmt::Display for EditorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// EditorKind
// ---------------------------------------------------------------------------

/// The kind of data type being edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EditorKind {
    /// Structure editor.
    Structure,
    /// Union editor.
    Union,
    /// Enum editor.
    Enum,
    /// Function definition editor.
    FunctionDefinition,
}

impl fmt::Display for EditorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Structure => write!(f, "Structure"),
            Self::Union => write!(f, "Union"),
            Self::Enum => write!(f, "Enum"),
            Self::FunctionDefinition => write!(f, "FunctionDefinition"),
        }
    }
}

// ---------------------------------------------------------------------------
// EditorProvider
// ---------------------------------------------------------------------------

/// Represents a single editor session for a data type.
///
/// This is the Rust equivalent of Ghidra's `EditorProvider` interface /
/// `CompositeEditorProvider` / `EnumEditorProvider` classes.
#[derive(Debug, Clone)]
pub struct EditorProvider {
    /// The kind of editor.
    kind: EditorKind,
    /// The data type path being edited.
    dt_path: DataTypePath,
    /// The name of the data type manager that owns the type.
    manager_name: String,
    /// Current editor state.
    state: EditorState,
    /// Whether numbers are displayed in hex.
    hex_numbers: bool,
    /// Number of fields in the composite (or enum entries).
    field_count: usize,
    /// The index of the currently selected field (0-based), if any.
    selected_field: Option<usize>,
}

impl EditorProvider {
    /// Create a new editor provider for a structure or union.
    pub fn new_composite(
        kind: EditorKind,
        dt_path: DataTypePath,
        manager_name: impl Into<String>,
        hex_numbers: bool,
        field_count: usize,
    ) -> Self {
        assert!(
            matches!(kind, EditorKind::Structure | EditorKind::Union),
            "new_composite only for Structure/Union"
        );
        Self {
            kind,
            dt_path,
            manager_name: manager_name.into(),
            state: EditorState::Clean,
            hex_numbers,
            field_count,
            selected_field: None,
        }
    }

    /// Create a new editor provider for an enum.
    pub fn new_enum(
        dt_path: DataTypePath,
        manager_name: impl Into<String>,
        entry_count: usize,
    ) -> Self {
        Self {
            kind: EditorKind::Enum,
            dt_path,
            manager_name: manager_name.into(),
            state: EditorState::Clean,
            hex_numbers: false,
            field_count: entry_count,
            selected_field: None,
        }
    }

    /// Create a new editor provider for a function definition.
    pub fn new_function_def(
        dt_path: DataTypePath,
        manager_name: impl Into<String>,
    ) -> Self {
        Self {
            kind: EditorKind::FunctionDefinition,
            dt_path,
            manager_name: manager_name.into(),
            state: EditorState::Clean,
            hex_numbers: false,
            field_count: 0,
            selected_field: None,
        }
    }

    /// The kind of editor.
    pub fn kind(&self) -> EditorKind {
        self.kind
    }

    /// The data type path being edited.
    pub fn dt_path(&self) -> &DataTypePath {
        &self.dt_path
    }

    /// The name of the owning data type manager.
    pub fn manager_name(&self) -> &str {
        &self.manager_name
    }

    /// Current editor state.
    pub fn state(&self) -> EditorState {
        self.state
    }

    /// Returns `true` if the editor has unsaved changes.
    pub fn needs_save(&self) -> bool {
        self.state.is_dirty()
    }

    /// Returns `true` if the editor is editing the given data type path.
    pub fn is_editing(&self, dt_path: &DataTypePath) -> bool {
        self.dt_path == *dt_path
    }

    /// Returns `true` if numbers are displayed in hex.
    pub fn hex_numbers(&self) -> bool {
        self.hex_numbers
    }

    /// Set hex number display.
    pub fn set_hex_numbers(&mut self, hex: bool) {
        self.hex_numbers = hex;
    }

    /// Returns the number of fields / entries.
    pub fn field_count(&self) -> usize {
        self.field_count
    }

    /// Returns the selected field index.
    pub fn selected_field(&self) -> Option<usize> {
        self.selected_field
    }

    /// Select a field by index.
    pub fn select_field(&mut self, index: usize) {
        self.selected_field = Some(index);
    }

    /// Mark the editor as dirty (has unsaved changes).
    pub fn mark_dirty(&mut self) {
        self.state = EditorState::Dirty;
    }

    /// Mark the editor as clean (changes saved or reverted).
    pub fn mark_clean(&mut self) {
        self.state = EditorState::Clean;
    }

    /// Apply (save) the changes.
    ///
    /// Returns `true` if the application succeeded.
    pub fn apply(&mut self) -> bool {
        if self.state == EditorState::Dirty {
            // In a full implementation, this would start a transaction
            // on the DataTypeManager and apply the changes.
            self.state = EditorState::Applied;
            self.state = EditorState::Clean; // After apply, back to clean.
            true
        } else {
            false
        }
    }

    /// Discard changes and close the editor.
    pub fn discard(&mut self) {
        self.state = EditorState::Discarded;
    }

    /// Dispose the editor (close without prompting).
    pub fn dispose(&mut self) {
        self.state = EditorState::Discarded;
    }
}

impl fmt::Display for EditorProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} Editor [{}] {} ({})",
            self.kind,
            self.dt_path,
            self.state.label(),
            self.manager_name
        )
    }
}

// ---------------------------------------------------------------------------
// EditorListener
// ---------------------------------------------------------------------------

/// Listener for editor lifecycle events.
///
/// Ported from Ghidra's `EditorListener` Java interface.
pub trait EditorListener: fmt::Debug + Send + Sync {
    /// Called when an editor is closed.
    fn closed(&self, _editor: &EditorProvider) {}
}

// ---------------------------------------------------------------------------
// EditorOptionManager
// ---------------------------------------------------------------------------

/// Manages editor display options (e.g., hex vs decimal).
///
/// Ported from Ghidra's `EditorOptionManager` Java class.
#[derive(Debug, Clone)]
pub struct EditorOptionManager {
    show_structure_hex: bool,
    show_union_hex: bool,
}

impl EditorOptionManager {
    /// Create a new option manager with default settings.
    pub fn new() -> Self {
        Self {
            show_structure_hex: false,
            show_union_hex: false,
        }
    }

    /// Returns `true` if structure editors show numbers in hex.
    pub fn show_structure_numbers_in_hex(&self) -> bool {
        self.show_structure_hex
    }

    /// Set whether structure editors show numbers in hex.
    pub fn set_show_structure_numbers_in_hex(&mut self, hex: bool) {
        self.show_structure_hex = hex;
    }

    /// Returns `true` if union editors show numbers in hex.
    pub fn show_union_numbers_in_hex(&self) -> bool {
        self.show_union_hex
    }

    /// Set whether union editors show numbers in hex.
    pub fn set_show_union_numbers_in_hex(&mut self, hex: bool) {
        self.show_union_hex = hex;
    }
}

impl Default for EditorOptionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DataTypeEditorManager
// ---------------------------------------------------------------------------

/// Manages all open data type editors.
///
/// Ported from Ghidra's `DataTypeEditorManager` Java class.  Ensures
/// that only one editor is open per data type, tracks dirty state, and
/// provides batch operations (check all, dismiss all, etc.).
///
/// # Example
///
/// ```rust
/// use ghidra_features::datamgr::editor::{
///     DataTypeEditorManager, EditorKind,
/// };
/// use ghidra_core::data::{CategoryPath, DataTypePath};
///
/// let mut mgr = DataTypeEditorManager::new();
/// assert!(!mgr.is_edit_in_progress());
///
/// let dt_path = DataTypePath::new(CategoryPath::ROOT, "my_struct");
/// mgr.edit_structure(dt_path.clone(), "program", false, 3);
/// assert!(mgr.is_edit_in_progress());
///
/// let edits = mgr.get_edits_in_progress();
/// assert_eq!(edits.len(), 1);
/// ```
pub struct DataTypeEditorManager {
    editors: Vec<EditorProvider>,
    option_manager: EditorOptionManager,
}

impl DataTypeEditorManager {
    /// Create a new editor manager.
    pub fn new() -> Self {
        Self {
            editors: Vec::new(),
            option_manager: EditorOptionManager::new(),
        }
    }

    /// Dispose all editors and clean up.
    pub fn dispose(&mut self) {
        self.editors.clear();
    }

    // -- Editability --

    /// Returns `true` if the given data type kind has an editor.
    pub fn is_editable(kind: EditorKind) -> bool {
        matches!(
            kind,
            EditorKind::Structure | EditorKind::Union | EditorKind::Enum
        )
    }

    // -- Open editors --

    /// Open an editor for a structure.
    pub fn edit_structure(
        &mut self,
        dt_path: DataTypePath,
        manager_name: &str,
        hex_numbers: bool,
        field_count: usize,
    ) {
        if self.reuse_existing_editor(&dt_path) {
            return;
        }
        let editor = EditorProvider::new_composite(
            EditorKind::Structure,
            dt_path,
            manager_name,
            hex_numbers,
            field_count,
        );
        self.editors.push(editor);
    }

    /// Open an editor for a union.
    pub fn edit_union(
        &mut self,
        dt_path: DataTypePath,
        manager_name: &str,
        hex_numbers: bool,
        field_count: usize,
    ) {
        if self.reuse_existing_editor(&dt_path) {
            return;
        }
        let editor = EditorProvider::new_composite(
            EditorKind::Union,
            dt_path,
            manager_name,
            hex_numbers,
            field_count,
        );
        self.editors.push(editor);
    }

    /// Open an editor for an enum.
    pub fn edit_enum(
        &mut self,
        dt_path: DataTypePath,
        manager_name: &str,
        entry_count: usize,
    ) {
        if self.reuse_existing_editor(&dt_path) {
            return;
        }
        let editor = EditorProvider::new_enum(dt_path, manager_name, entry_count);
        self.editors.push(editor);
    }

    /// Open an editor for a function definition.
    pub fn edit_function_def(
        &mut self,
        dt_path: DataTypePath,
        manager_name: &str,
    ) {
        if self.reuse_existing_editor(&dt_path) {
            return;
        }
        let editor = EditorProvider::new_function_def(dt_path, manager_name);
        self.editors.push(editor);
    }

    /// If an editor for the given data type path already exists, bring it
    /// to the front and return `true`.
    fn reuse_existing_editor(&mut self, dt_path: &DataTypePath) -> bool {
        if let Some(editor) = self.editors.iter_mut().find(|e| e.is_editing(dt_path)) {
            // In the full GUI implementation this would call toFront().
            // Just return true to signal "already open".
            let _ = editor;
            true
        } else {
            false
        }
    }

    // -- Editor lookup --

    /// Returns a reference to the editor for the given data type path, if any.
    pub fn get_editor(&self, dt_path: &DataTypePath) -> Option<&EditorProvider> {
        self.editors.iter().find(|e| e.is_editing(dt_path))
    }

    /// Returns a mutable reference to the editor for the given data type path.
    pub fn get_editor_mut(&mut self, dt_path: &DataTypePath) -> Option<&mut EditorProvider> {
        self.editors.iter_mut().find(|e| e.is_editing(dt_path))
    }

    /// Returns `true` if any editors are open.
    pub fn is_edit_in_progress(&self) -> bool {
        !self.editors.is_empty()
    }

    /// Returns the data type paths of all open editors.
    pub fn get_edits_in_progress(&self) -> Vec<&DataTypePath> {
        self.editors.iter().map(|e| e.dt_path()).collect()
    }

    // -- Save / close --

    /// Check all editors for a given manager for unsaved changes.
    ///
    /// If `manager_name` is `None`, all editors are checked.
    /// Returns `true` if all editors were resolved (saved or discarded).
    /// Returns `false` if the user would need to cancel (in a GUI context,
    /// this always returns `true` in the headless API).
    pub fn check_editors(&mut self, manager_name: Option<&str>, allow_cancel: bool) -> bool {
        let _ = allow_cancel;
        for editor in &self.editors {
            if let Some(mgr) = manager_name {
                if editor.manager_name() != mgr {
                    continue;
                }
            }
            if editor.needs_save() {
                // In headless mode, auto-apply.
                // In GUI mode, this would prompt the user.
            }
        }
        true
    }

    /// Close and dispose the editor for the given data type path.
    pub fn close_editor(&mut self, dt_path: &DataTypePath) {
        if let Some(editor) = self.get_editor_mut(dt_path) {
            editor.dispose();
        }
        self.editors.retain(|e| e.state() != EditorState::Discarded);
    }

    /// Dismiss all editors whose manager matches the given name.
    ///
    /// If `manager_name` is `None`, all editors are dismissed.
    pub fn dismiss_editors(&mut self, manager_name: Option<&str>) {
        for editor in &mut self.editors {
            if let Some(mgr) = manager_name {
                if editor.manager_name() != mgr {
                    continue;
                }
            }
            editor.dispose();
        }
        self.editors.retain(|e| e.state() != EditorState::Discarded);
    }

    /// Returns `true` if any editor for the given manager has unsaved changes.
    pub fn has_editor_changes(&self, manager_name: Option<&str>) -> bool {
        self.editors.iter().any(|e| {
            if let Some(mgr) = manager_name {
                e.manager_name() == mgr && e.needs_save()
            } else {
                e.needs_save()
            }
        })
    }

    // -- Unique name generation --

    /// Generate a unique data type name for a category.
    ///
    /// Checks the manager and existing editor sessions to avoid collisions.
    pub fn get_unique_name(
        &self,
        manager: &dyn DataTypeManager,
        category: &CategoryPath,
        base_name: &str,
    ) -> String {
        // Start with the manager's own unique name.
        let mut unique = format!("{}_0", base_name);
        let mut counter = 0u32;

        loop {
            let full_path = if category.is_root() {
                format!("/{}", unique)
            } else {
                format!("{}/{}", category.display_name(), unique)
            };

            let exists_in_manager = manager.contains(&full_path);
            let exists_in_editors = self.editors.iter().any(|e| {
                e.dt_path().data_type_name == unique
                    && e.dt_path().category_path == *category
            });

            if !exists_in_manager && !exists_in_editors {
                return unique;
            }

            counter += 1;
            unique = format!("{}_{}", base_name, counter);
        }
    }

    // -- Editor options --

    /// Returns `true` if structure editors show numbers in hex.
    pub fn show_structure_numbers_in_hex(&self) -> bool {
        self.option_manager.show_structure_numbers_in_hex()
    }

    /// Returns `true` if union editors show numbers in hex.
    pub fn show_union_numbers_in_hex(&self) -> bool {
        self.option_manager.show_union_numbers_in_hex()
    }

    /// Returns a reference to the editor option manager.
    pub fn option_manager(&self) -> &EditorOptionManager {
        &self.option_manager
    }

    /// Returns a mutable reference to the editor option manager.
    pub fn option_manager_mut(&mut self) -> &mut EditorOptionManager {
        &mut self.option_manager
    }

    /// Returns the number of open editors.
    pub fn editor_count(&self) -> usize {
        self.editors.len()
    }
}

impl Default for DataTypeEditorManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DataTypeEditorManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataTypeEditorManager")
            .field("editor_count", &self.editors.len())
            .finish()
    }
}

impl fmt::Display for DataTypeEditorManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DataTypeEditorManager ({} editors)",
            self.editors.len()
        )
    }
}

// ---------------------------------------------------------------------------
// EnumEntry -- a single row in the enum editor table
// ---------------------------------------------------------------------------

/// A single entry (name/value/comment) in the enum editor table.
///
/// Ported from `ghidra.app.plugin.core.datamgr.editor.EnumEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumEntry {
    /// The entry name (e.g. "RED").
    name: String,
    /// The entry's numeric value.
    value: i64,
    /// Optional comment for this entry.
    comment: String,
}

impl EnumEntry {
    /// Create a new enum entry.
    pub fn new(name: impl Into<String>, value: i64, comment: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value,
            comment: comment.into(),
        }
    }

    /// The entry name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the entry name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// The entry value.
    pub fn value(&self) -> i64 {
        self.value
    }

    /// Set the entry value.
    pub fn set_value(&mut self, value: i64) {
        self.value = value;
    }

    /// The entry comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Set the entry comment.
    pub fn set_comment(&mut self, comment: impl Into<String>) {
        self.comment = comment.into();
    }

    /// Format the value for display, optionally as hex.
    pub fn display_value(&self, hex: bool) -> String {
        if hex {
            format!("0x{:X}", self.value as u64)
        } else {
            self.value.to_string()
        }
    }
}

impl fmt::Display for EnumEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = 0x{:X}", self.name, self.value as u64)?;
        if !self.comment.is_empty() {
            write!(f, " // {}", self.comment)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EnumTableModel -- table model for the enum editor
// ---------------------------------------------------------------------------

/// Column indices for the enum editor table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnumColumns;

impl EnumColumns {
    /// Name column index.
    pub const NAME: usize = 0;
    /// Value column index.
    pub const VALUE: usize = 1;
    /// Comment column index.
    pub const COMMENT: usize = 2;
    /// Column headers.
    pub const HEADERS: &'static [&'static str] = &["Name", "Value", "Comment"];
    /// Default column widths in pixels.
    pub const WIDTHS: &'static [usize] = &[150, 100, 200];
    /// Total column count.
    pub const COUNT: usize = 3;
}

/// Table model for the enum editor.
///
/// Ported from `ghidra.app.plugin.core.datamgr.editor.EnumTableModel`.
///
/// Manages the list of [`EnumEntry`] rows and tracks which column is
/// the sort column.
#[derive(Debug, Clone)]
pub struct EnumTableModel {
    /// The entries in the table.
    entries: Vec<EnumEntry>,
    /// Whether values should be displayed in hex.
    show_hex: bool,
    /// The sort column index (default: VALUE).
    sort_column: usize,
    /// Whether the model has been modified since last save.
    is_changed: bool,
}

impl EnumTableModel {
    /// Create a new empty enum table model.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            show_hex: true,
            sort_column: EnumColumns::VALUE,
            is_changed: false,
        }
    }

    /// Create a model pre-populated with entries.
    pub fn with_entries(entries: Vec<EnumEntry>) -> Self {
        Self {
            entries,
            show_hex: true,
            sort_column: EnumColumns::VALUE,
            is_changed: false,
        }
    }

    /// Returns the number of entries.
    pub fn row_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the column count.
    pub fn column_count(&self) -> usize {
        EnumColumns::COUNT
    }

    /// Returns the column header for the given index.
    pub fn column_name(&self, col: usize) -> &str {
        EnumColumns::HEADERS.get(col).unwrap_or(&"")
    }

    /// Returns the value for a specific cell.
    pub fn cell_value(&self, row: usize, col: usize) -> Option<String> {
        let entry = self.entries.get(row)?;
        Some(match col {
            EnumColumns::NAME => entry.name().to_string(),
            EnumColumns::VALUE => entry.display_value(self.show_hex),
            EnumColumns::COMMENT => entry.comment().to_string(),
            _ => return None,
        })
    }

    /// Get an entry by row index.
    pub fn entry(&self, row: usize) -> Option<&EnumEntry> {
        self.entries.get(row)
    }

    /// Get a mutable entry by row index.
    pub fn entry_mut(&mut self, row: usize) -> Option<&mut EnumEntry> {
        self.is_changed = true;
        self.entries.get_mut(row)
    }

    /// Get all entries.
    pub fn entries(&self) -> &[EnumEntry] {
        &self.entries
    }

    /// Add a new entry.
    pub fn add_entry(&mut self, entry: EnumEntry) {
        self.entries.push(entry);
        self.is_changed = true;
    }

    /// Remove an entry by row index.
    pub fn remove_entry(&mut self, row: usize) -> Option<EnumEntry> {
        if row < self.entries.len() {
            self.is_changed = true;
            Some(self.entries.remove(row))
        } else {
            None
        }
    }

    /// Whether the model has been modified.
    pub fn is_changed(&self) -> bool {
        self.is_changed
    }

    /// Mark the model as clean (saved).
    pub fn mark_clean(&mut self) {
        self.is_changed = false;
    }

    /// Whether values are displayed in hex.
    pub fn show_hex(&self) -> bool {
        self.show_hex
    }

    /// Set whether values are displayed in hex.
    pub fn set_show_hex(&mut self, hex: bool) {
        self.show_hex = hex;
    }

    /// The current sort column.
    pub fn sort_column(&self) -> usize {
        self.sort_column
    }

    /// Set the sort column.
    pub fn set_sort_column(&mut self, col: usize) {
        self.sort_column = col;
    }

    /// Sort entries by the current sort column.
    pub fn sort(&mut self) {
        match self.sort_column {
            EnumColumns::NAME => self.entries.sort_by(|a, b| a.name.cmp(&b.name)),
            EnumColumns::VALUE => self.entries.sort_by(|a, b| a.value.cmp(&b.value)),
            EnumColumns::COMMENT => self.entries.sort_by(|a, b| a.comment.cmp(&b.comment)),
            _ => {}
        }
    }

    /// Find the next unused value (max + 1).
    pub fn next_value(&self) -> i64 {
        self.entries.iter().map(|e| e.value).max().map_or(0, |v| v + 1)
    }

    /// Check if a name is already in use.
    pub fn has_name(&self, name: &str) -> bool {
        self.entries.iter().any(|e| e.name() == name)
    }

    /// Get the index of the entry with the given name, if any.
    pub fn index_of_name(&self, name: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.name() == name)
    }
}

impl Default for EnumTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EnumEditorPanel -- model for the enum editor panel
// ---------------------------------------------------------------------------

/// The current editing state of the enum editor panel.
///
/// Ported from `ghidra.app.plugin.core.datamgr.editor.EnumEditorPanel`.
#[derive(Debug, Clone)]
pub struct EnumEditorPanelState {
    /// The name of the enum being edited.
    pub enum_name: String,
    /// The description of the enum.
    pub description: String,
    /// The category path.
    pub category_path: String,
    /// The size in bytes of the enum (1, 2, 4, 8).
    pub size_bytes: u32,
    /// Whether the name has been modified from the original.
    pub name_changed: bool,
    /// Whether the description has been modified.
    pub description_changed: bool,
    /// The table model with the entries.
    pub table_model: EnumTableModel,
}

impl EnumEditorPanelState {
    /// Create a new panel state for an enum editor.
    pub fn new(enum_name: impl Into<String>, size_bytes: u32) -> Self {
        Self {
            enum_name: enum_name.into(),
            description: String::new(),
            category_path: "/".to_string(),
            size_bytes,
            name_changed: false,
            description_changed: false,
            table_model: EnumTableModel::new(),
        }
    }

    /// Whether the panel has any unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.name_changed || self.description_changed || self.table_model.is_changed()
    }

    /// Mark all changes as saved.
    pub fn mark_clean(&mut self) {
        self.name_changed = false;
        self.description_changed = false;
        self.table_model.mark_clean();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use ghidra_core::data::types::DataType;
    use ghidra_core::data::{CategoryPath, StandaloneDataTypeManager};

    fn make_path(name: &str) -> DataTypePath {
        DataTypePath::new(CategoryPath::ROOT, name)
    }

    #[test]
    fn test_editor_state_display() {
        assert_eq!(format!("{}", EditorState::Clean), "Clean");
        assert_eq!(format!("{}", EditorState::Dirty), "Dirty");
        assert_eq!(format!("{}", EditorState::Applied), "Applied");
        assert_eq!(format!("{}", EditorState::Discarded), "Discarded");
    }

    #[test]
    fn test_editor_state_predicates() {
        assert!(EditorState::Dirty.is_dirty());
        assert!(!EditorState::Clean.is_dirty());
        assert!(EditorState::Applied.is_applied());
        assert!(!EditorState::Dirty.is_applied());
    }

    #[test]
    fn test_editor_kind_display() {
        assert_eq!(format!("{}", EditorKind::Structure), "Structure");
        assert_eq!(format!("{}", EditorKind::Union), "Union");
        assert_eq!(format!("{}", EditorKind::Enum), "Enum");
        assert_eq!(format!("{}", EditorKind::FunctionDefinition), "FunctionDefinition");
    }

    #[test]
    fn test_editor_provider_new_composite() {
        let dt_path = make_path("my_struct");
        let editor = EditorProvider::new_composite(
            EditorKind::Structure,
            dt_path.clone(),
            "program",
            false,
            5,
        );
        assert_eq!(editor.kind(), EditorKind::Structure);
        assert_eq!(editor.dt_path(), &dt_path);
        assert_eq!(editor.manager_name(), "program");
        assert_eq!(editor.state(), EditorState::Clean);
        assert!(!editor.needs_save());
        assert_eq!(editor.field_count(), 5);
        assert!(editor.selected_field().is_none());
    }

    #[test]
    fn test_editor_provider_new_enum() {
        let dt_path = make_path("Color");
        let editor = EditorProvider::new_enum(dt_path, "archive", 10);
        assert_eq!(editor.kind(), EditorKind::Enum);
        assert_eq!(editor.field_count(), 10);
    }

    #[test]
    fn test_editor_provider_new_function_def() {
        let dt_path = make_path("callback_t");
        let editor = EditorProvider::new_function_def(dt_path, "program");
        assert_eq!(editor.kind(), EditorKind::FunctionDefinition);
    }

    #[test]
    fn test_editor_provider_state_transitions() {
        let dt_path = make_path("my_struct");
        let mut editor = EditorProvider::new_composite(
            EditorKind::Structure, dt_path, "prog", false, 3,
        );
        assert_eq!(editor.state(), EditorState::Clean);
        editor.mark_dirty();
        assert_eq!(editor.state(), EditorState::Dirty);
        assert!(editor.needs_save());
        assert!(editor.apply());
        assert_eq!(editor.state(), EditorState::Clean);
        assert!(!editor.needs_save());
    }

    #[test]
    fn test_editor_provider_apply_when_clean() {
        let dt_path = make_path("x");
        let mut editor = EditorProvider::new_composite(
            EditorKind::Structure, dt_path, "prog", false, 0,
        );
        assert!(!editor.apply()); // not dirty, so apply fails
    }

    #[test]
    fn test_editor_provider_discard() {
        let dt_path = make_path("x");
        let mut editor = EditorProvider::new_composite(
            EditorKind::Structure, dt_path, "prog", false, 0,
        );
        editor.mark_dirty();
        editor.discard();
        assert_eq!(editor.state(), EditorState::Discarded);
    }

    #[test]
    fn test_editor_provider_select_field() {
        let dt_path = make_path("x");
        let mut editor = EditorProvider::new_composite(
            EditorKind::Structure, dt_path, "prog", false, 5,
        );
        assert!(editor.selected_field().is_none());
        editor.select_field(2);
        assert_eq!(editor.selected_field(), Some(2));
    }

    #[test]
    fn test_editor_provider_hex_numbers() {
        let dt_path = make_path("x");
        let mut editor = EditorProvider::new_composite(
            EditorKind::Structure, dt_path, "prog", true, 0,
        );
        assert!(editor.hex_numbers());
        editor.set_hex_numbers(false);
        assert!(!editor.hex_numbers());
    }

    #[test]
    fn test_editor_provider_is_editing() {
        let dt_path = make_path("my_struct");
        let editor = EditorProvider::new_composite(
            EditorKind::Structure, dt_path, "prog", false, 0,
        );
        assert!(editor.is_editing(&make_path("my_struct")));
        assert!(!editor.is_editing(&make_path("other")));
    }

    #[test]
    fn test_editor_provider_display() {
        let dt_path = make_path("my_struct");
        let editor = EditorProvider::new_composite(
            EditorKind::Structure, dt_path, "prog", false, 3,
        );
        let s = format!("{}", editor);
        assert!(s.contains("Structure"));
        assert!(s.contains("my_struct"));
    }

    #[test]
    fn test_editor_manager_new() {
        let mgr = DataTypeEditorManager::new();
        assert!(!mgr.is_edit_in_progress());
        assert_eq!(mgr.editor_count(), 0);
    }

    #[test]
    fn test_editor_manager_edit_structure() {
        let mut mgr = DataTypeEditorManager::new();
        let dt_path = make_path("my_struct");
        mgr.edit_structure(dt_path.clone(), "prog", false, 4);
        assert!(mgr.is_edit_in_progress());
        assert_eq!(mgr.editor_count(), 1);
        assert!(mgr.get_editor(&dt_path).is_some());
    }

    #[test]
    fn test_editor_manager_edit_union() {
        let mut mgr = DataTypeEditorManager::new();
        let dt_path = make_path("my_union");
        mgr.edit_union(dt_path.clone(), "prog", true, 2);
        assert_eq!(mgr.editor_count(), 1);
        let editor = mgr.get_editor(&dt_path).unwrap();
        assert_eq!(editor.kind(), EditorKind::Union);
    }

    #[test]
    fn test_editor_manager_edit_enum() {
        let mut mgr = DataTypeEditorManager::new();
        let dt_path = make_path("Color");
        mgr.edit_enum(dt_path.clone(), "archive", 5);
        assert_eq!(mgr.editor_count(), 1);
        let editor = mgr.get_editor(&dt_path).unwrap();
        assert_eq!(editor.kind(), EditorKind::Enum);
    }

    #[test]
    fn test_editor_manager_edit_function_def() {
        let mut mgr = DataTypeEditorManager::new();
        let dt_path = make_path("callback");
        mgr.edit_function_def(dt_path.clone(), "prog");
        assert_eq!(mgr.editor_count(), 1);
    }

    #[test]
    fn test_editor_manager_reuse_existing() {
        let mut mgr = DataTypeEditorManager::new();
        let dt_path = make_path("my_struct");
        mgr.edit_structure(dt_path.clone(), "prog", false, 3);
        mgr.edit_structure(dt_path.clone(), "prog", true, 5); // same path -> reused
        assert_eq!(mgr.editor_count(), 1);
    }

    #[test]
    fn test_editor_manager_multiple_editors() {
        let mut mgr = DataTypeEditorManager::new();
        mgr.edit_structure(make_path("a"), "prog", false, 1);
        mgr.edit_structure(make_path("b"), "prog", false, 2);
        mgr.edit_enum(make_path("c"), "archive", 3);
        assert_eq!(mgr.editor_count(), 3);
    }

    #[test]
    fn test_editor_manager_close_editor() {
        let mut mgr = DataTypeEditorManager::new();
        let dt_path = make_path("my_struct");
        mgr.edit_structure(dt_path.clone(), "prog", false, 3);
        assert_eq!(mgr.editor_count(), 1);
        mgr.close_editor(&dt_path);
        assert_eq!(mgr.editor_count(), 0);
    }

    #[test]
    fn test_editor_manager_dismiss_editors_by_manager() {
        let mut mgr = DataTypeEditorManager::new();
        mgr.edit_structure(make_path("a"), "prog1", false, 1);
        mgr.edit_structure(make_path("b"), "prog2", false, 2);
        mgr.edit_enum(make_path("c"), "prog1", 3);
        mgr.dismiss_editors(Some("prog1"));
        assert_eq!(mgr.editor_count(), 1);
        assert_eq!(mgr.get_editor(&make_path("b")).unwrap().manager_name(), "prog2");
    }

    #[test]
    fn test_editor_manager_dismiss_all() {
        let mut mgr = DataTypeEditorManager::new();
        mgr.edit_structure(make_path("a"), "prog", false, 1);
        mgr.edit_enum(make_path("b"), "archive", 2);
        mgr.dismiss_editors(None);
        assert_eq!(mgr.editor_count(), 0);
    }

    #[test]
    fn test_editor_manager_has_editor_changes() {
        let mut mgr = DataTypeEditorManager::new();
        let dt_path = make_path("x");
        mgr.edit_structure(dt_path.clone(), "prog", false, 1);
        assert!(!mgr.has_editor_changes(None));
        mgr.get_editor_mut(&dt_path).unwrap().mark_dirty();
        assert!(mgr.has_editor_changes(None));
        assert!(mgr.has_editor_changes(Some("prog")));
        assert!(!mgr.has_editor_changes(Some("other")));
    }

    #[test]
    fn test_editor_manager_get_edits_in_progress() {
        let mut mgr = DataTypeEditorManager::new();
        mgr.edit_structure(make_path("a"), "prog", false, 1);
        mgr.edit_enum(make_path("b"), "archive", 2);
        let edits = mgr.get_edits_in_progress();
        assert_eq!(edits.len(), 2);
    }

    #[test]
    fn test_editor_manager_unique_name() {
        let mgr = DataTypeEditorManager::new();
        let manager = StandaloneDataTypeManager::new();
        let name = mgr.get_unique_name(&manager, &CategoryPath::ROOT, "struct");
        assert_eq!(name, "struct_0");
    }

    #[test]
    fn test_editor_manager_unique_name_collision() {
        let mut manager = StandaloneDataTypeManager::new();
        let dt: Arc<dyn DataType> = Arc::new(
            ghidra_core::data::types::StructureDataType::new("struct_0"),
        );
        manager.add_type(dt, CategoryPath::ROOT);

        let mgr = DataTypeEditorManager::new();
        let name = mgr.get_unique_name(&manager, &CategoryPath::ROOT, "struct");
        assert_eq!(name, "struct_1");
    }

    #[test]
    fn test_editor_option_manager() {
        let mut opts = EditorOptionManager::new();
        assert!(!opts.show_structure_numbers_in_hex());
        assert!(!opts.show_union_numbers_in_hex());
        opts.set_show_structure_numbers_in_hex(true);
        assert!(opts.show_structure_numbers_in_hex());
        opts.set_show_union_numbers_in_hex(true);
        assert!(opts.show_union_numbers_in_hex());
    }

    #[test]
    fn test_editor_manager_display() {
        let mgr = DataTypeEditorManager::new();
        let s = format!("{}", mgr);
        assert!(s.contains("DataTypeEditorManager"));
        assert!(s.contains("0 editors"));
    }

    #[test]
    fn test_editor_manager_debug() {
        let mgr = DataTypeEditorManager::new();
        let s = format!("{:?}", mgr);
        assert!(s.contains("DataTypeEditorManager"));
    }

    #[test]
    fn test_editor_manager_dispose() {
        let mut mgr = DataTypeEditorManager::new();
        mgr.edit_structure(make_path("a"), "prog", false, 1);
        mgr.edit_enum(make_path("b"), "archive", 2);
        assert_eq!(mgr.editor_count(), 2);
        mgr.dispose();
        assert_eq!(mgr.editor_count(), 0);
    }

    // -- EnumEntry tests --

    #[test]
    fn test_enum_entry_new() {
        let e = EnumEntry::new("RED", 0, "The color red");
        assert_eq!(e.name(), "RED");
        assert_eq!(e.value(), 0);
        assert_eq!(e.comment(), "The color red");
    }

    #[test]
    fn test_enum_entry_setters() {
        let mut e = EnumEntry::new("A", 1, "");
        e.set_name("B");
        e.set_value(42);
        e.set_comment("updated");
        assert_eq!(e.name(), "B");
        assert_eq!(e.value(), 42);
        assert_eq!(e.comment(), "updated");
    }

    #[test]
    fn test_enum_entry_display_value_hex() {
        let e = EnumEntry::new("X", 255, "");
        assert_eq!(e.display_value(true), "0xFF");
        assert_eq!(e.display_value(false), "255");
    }

    #[test]
    fn test_enum_entry_display() {
        let e = EnumEntry::new("RED", 0xFF, "red color");
        let s = format!("{}", e);
        assert!(s.contains("RED"));
        assert!(s.contains("0xFF"));
        assert!(s.contains("red color"));
    }

    #[test]
    fn test_enum_entry_display_no_comment() {
        let e = EnumEntry::new("X", 1, "");
        let s = format!("{}", e);
        assert!(s.contains("X"));
        assert!(!s.contains("//"));
    }

    // -- EnumColumns tests --

    #[test]
    fn test_enum_columns() {
        assert_eq!(EnumColumns::NAME, 0);
        assert_eq!(EnumColumns::VALUE, 1);
        assert_eq!(EnumColumns::COMMENT, 2);
        assert_eq!(EnumColumns::COUNT, 3);
        assert_eq!(EnumColumns::HEADERS, &["Name", "Value", "Comment"]);
    }

    // -- EnumTableModel tests --

    #[test]
    fn test_enum_table_model_new() {
        let m = EnumTableModel::new();
        assert_eq!(m.row_count(), 0);
        assert_eq!(m.column_count(), 3);
        assert!(m.show_hex());
    }

    #[test]
    fn test_enum_table_model_with_entries() {
        let entries = vec![
            EnumEntry::new("A", 0, ""),
            EnumEntry::new("B", 1, ""),
            EnumEntry::new("C", 2, ""),
        ];
        let m = EnumTableModel::with_entries(entries);
        assert_eq!(m.row_count(), 3);
    }

    #[test]
    fn test_enum_table_model_cell_value() {
        let entries = vec![EnumEntry::new("RED", 0xFF, "the color")];
        let m = EnumTableModel::with_entries(entries);
        assert_eq!(m.cell_value(0, EnumColumns::NAME), Some("RED".to_string()));
        assert_eq!(m.cell_value(0, EnumColumns::VALUE), Some("0xFF".to_string()));
        assert_eq!(m.cell_value(0, EnumColumns::COMMENT), Some("the color".to_string()));
        assert!(m.cell_value(1, 0).is_none());
    }

    #[test]
    fn test_enum_table_model_add_remove() {
        let mut m = EnumTableModel::new();
        m.add_entry(EnumEntry::new("A", 0, ""));
        m.add_entry(EnumEntry::new("B", 1, ""));
        assert_eq!(m.row_count(), 2);
        assert!(m.is_changed());

        m.mark_clean();
        assert!(!m.is_changed());

        let removed = m.remove_entry(0);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name(), "A");
        assert_eq!(m.row_count(), 1);
        assert!(m.is_changed());
    }

    #[test]
    fn test_enum_table_model_sort() {
        let entries = vec![
            EnumEntry::new("C", 2, ""),
            EnumEntry::new("A", 0, ""),
            EnumEntry::new("B", 1, ""),
        ];
        let mut m = EnumTableModel::with_entries(entries);
        m.set_sort_column(EnumColumns::NAME);
        m.sort();
        assert_eq!(m.entry(0).unwrap().name(), "A");
        assert_eq!(m.entry(1).unwrap().name(), "B");
        assert_eq!(m.entry(2).unwrap().name(), "C");
    }

    #[test]
    fn test_enum_table_model_sort_by_value() {
        let entries = vec![
            EnumEntry::new("C", 5, ""),
            EnumEntry::new("A", 1, ""),
            EnumEntry::new("B", 3, ""),
        ];
        let mut m = EnumTableModel::with_entries(entries);
        m.set_sort_column(EnumColumns::VALUE);
        m.sort();
        assert_eq!(m.entry(0).unwrap().value(), 1);
        assert_eq!(m.entry(1).unwrap().value(), 3);
        assert_eq!(m.entry(2).unwrap().value(), 5);
    }

    #[test]
    fn test_enum_table_model_next_value() {
        let mut m = EnumTableModel::new();
        assert_eq!(m.next_value(), 0);
        m.add_entry(EnumEntry::new("A", 5, ""));
        m.add_entry(EnumEntry::new("B", 10, ""));
        assert_eq!(m.next_value(), 11);
    }

    #[test]
    fn test_enum_table_model_has_name() {
        let entries = vec![EnumEntry::new("RED", 0, "")];
        let m = EnumTableModel::with_entries(entries);
        assert!(m.has_name("RED"));
        assert!(!m.has_name("BLUE"));
    }

    #[test]
    fn test_enum_table_model_index_of_name() {
        let entries = vec![
            EnumEntry::new("A", 0, ""),
            EnumEntry::new("B", 1, ""),
        ];
        let m = EnumTableModel::with_entries(entries);
        assert_eq!(m.index_of_name("A"), Some(0));
        assert_eq!(m.index_of_name("B"), Some(1));
        assert_eq!(m.index_of_name("C"), None);
    }

    #[test]
    fn test_enum_table_model_hex_toggle() {
        let mut m = EnumTableModel::new();
        assert!(m.show_hex());
        m.set_show_hex(false);
        assert!(!m.show_hex());

        let entries = vec![EnumEntry::new("X", 42, "")];
        let m = EnumTableModel::with_entries(entries);
        let val_hex = m.cell_value(0, EnumColumns::VALUE).unwrap();
        assert!(val_hex.starts_with("0x"));
    }

    #[test]
    fn test_enum_table_model_column_name() {
        let m = EnumTableModel::new();
        assert_eq!(m.column_name(0), "Name");
        assert_eq!(m.column_name(1), "Value");
        assert_eq!(m.column_name(2), "Comment");
        assert_eq!(m.column_name(99), "");
    }

    #[test]
    fn test_enum_table_model_default() {
        let m = EnumTableModel::default();
        assert_eq!(m.row_count(), 0);
    }

    // -- EnumEditorPanelState tests --

    #[test]
    fn test_enum_editor_panel_state_new() {
        let state = EnumEditorPanelState::new("Color", 4);
        assert_eq!(state.enum_name, "Color");
        assert_eq!(state.size_bytes, 4);
        assert_eq!(state.description, "");
        assert_eq!(state.category_path, "/");
        assert!(!state.is_dirty());
    }

    #[test]
    fn test_enum_editor_panel_state_dirty() {
        let mut state = EnumEditorPanelState::new("Color", 4);
        state.name_changed = true;
        assert!(state.is_dirty());
        state.mark_clean();
        assert!(!state.is_dirty());
    }

    #[test]
    fn test_enum_editor_panel_state_table_dirty() {
        let mut state = EnumEditorPanelState::new("Color", 4);
        state.table_model.add_entry(EnumEntry::new("RED", 0, ""));
        assert!(state.is_dirty());
        state.mark_clean();
        assert!(!state.is_dirty());
    }
}
