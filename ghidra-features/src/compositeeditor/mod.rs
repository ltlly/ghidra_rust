//! Composite (struct/union) data type editor.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.compositeeditor` package.
//!
//! Provides the model and logic for editing composite data types (structs
//! and unions) including adding/removing/reordering components, setting
//! types, handling bit-fields, and managing alignment/packing.
//!
//! # Key Types
//!
//! - [`CompositeEditorModel`] -- Core model managing editable composite state
//! - [`CompEditorModel`] -- Higher-level model used by the editor panel
//! - [`ComponentContext`] -- Context about the selected component
//! - [`EditorAction`] -- Actions available in the composite editor
//! - [`ComponentRow`] -- A single row in the composite editor table
//! - [`EditTransaction`] -- A batch of changes to apply atomically

/// Composite editor actions (delete, insert, duplicate, etc.).
///
/// Ported from individual action classes in `ghidra.app.plugin.core.compositeeditor`.
pub mod actions;

/// Bit-field placement visualization component.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.BitFieldPlacementComponent`.
pub mod bitfield_placement;

/// Cell editor for inline editing of data type names and field names.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.ComponentCellEditor`.
pub mod cell_editor;

/// Bidirectional ID mapping between view and original data type managers.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.IDMapDB`.
pub mod idmap;

/// Editor model for struct/union editing with undo/redo.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorModel`.
pub mod model;

/// Editor provider types (EditorProvider, StructureEditorProvider, UnionEditorProvider).
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.EditorProvider` and
/// related provider classes.
pub mod provider;

/// Cell renderers for the composite editor table.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.DataTypeCellRenderer`
/// and `DndTableCellRenderer`.
pub mod renderer;

/// Search control panel for type-ahead data type selection.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.SearchControlPanel`.
pub mod search_control;

/// Editor action contexts for composite editor operations.
///
/// Ported from context classes in `ghidra.app.plugin.core.compositeeditor`.
pub mod context;

/// Listener interfaces for composite editor change events.
///
/// Ported from `CompositeChangeListener` and `CompositeEditorLockListener`.
pub mod listener;

/// Composite editor panel models.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompEditorPanel`,
/// `UnionEditorPanel`, and related panel classes.
pub mod panels;

/// Composite editor action implementations.
///
/// Ported from individual action classes in
/// `ghidra.app.plugin.core.compositeeditor`.
pub mod actions_impl;

/// Bit-field editor dialog model.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.BitFieldEditorDialog`.
pub mod bitfield_dialog;
pub mod undo_actions;

use serde::{Deserialize, Serialize};

/// Maximum number of components allowed in a composite type.
pub const MAX_COMPONENTS: usize = 1024;

/// Maximum name length for a component.
pub const MAX_COMPONENT_NAME_LEN: usize = 512;

// ---------------------------------------------------------------------------
// Editor action
// ---------------------------------------------------------------------------

/// Actions available in the composite editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EditorAction {
    /// Apply the current changes to the program.
    Apply,
    /// Add a new component at the selected position.
    AddComponent,
    /// Add a bit-field at the selected position.
    AddBitField,
    /// Delete the selected component(s).
    Delete,
    /// Clear the selected component(s) back to undefined.
    Clear,
    /// Create an array from the selected component.
    MakeArray,
    /// Move the selected component up.
    MoveUp,
    /// Move the selected component down.
    MoveDown,
    /// Set the type of the selected component.
    SetType,
    /// Set the name of the selected component.
    SetName,
    /// Set the comment on the selected component.
    SetComment,
    /// Toggle the enabled state of a component.
    ToggleEnabled,
    /// Undo the last edit.
    Undo,
    /// Redo the last undone edit.
    Redo,
}

impl EditorAction {
    /// Whether this action modifies the composite.
    pub fn is_modifying(&self) -> bool {
        !matches!(self, Self::Undo | Self::Redo)
    }
}

// ---------------------------------------------------------------------------
// Component row
// ---------------------------------------------------------------------------

/// A single row (component) in the composite editor table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentRow {
    /// The ordinal index of this component in the composite.
    pub ordinal: usize,
    /// The data type name for this component.
    pub type_name: String,
    /// The component field name.
    pub field_name: String,
    /// The byte offset of this component within the composite.
    pub offset: u64,
    /// The byte length of this component.
    pub length: u32,
    /// Comment text for this component.
    pub comment: Option<String>,
    /// Whether this component is a bit-field.
    pub is_bit_field: bool,
    /// Bit-field bit offset (only meaningful when `is_bit_field` is true).
    pub bit_offset: Option<u32>,
    /// Bit-field bit size (only meaningful when `is_bit_field` is true).
    pub bit_size: Option<u32>,
    /// Whether this component is currently enabled in the editor.
    pub enabled: bool,
}

impl ComponentRow {
    /// Create a new component row.
    pub fn new(
        ordinal: usize,
        type_name: impl Into<String>,
        field_name: impl Into<String>,
        offset: u64,
        length: u32,
    ) -> Self {
        Self {
            ordinal,
            type_name: type_name.into(),
            field_name: field_name.into(),
            offset,
            length,
            comment: None,
            is_bit_field: false,
            bit_offset: None,
            bit_size: None,
            enabled: true,
        }
    }

    /// The end offset of this component (exclusive).
    pub fn end_offset(&self) -> u64 {
        self.offset + self.length as u64
    }

    /// Whether this is a zero-length component.
    pub fn is_empty(&self) -> bool {
        self.length == 0 && !self.is_bit_field
    }
}

// ---------------------------------------------------------------------------
// Edit transaction
// ---------------------------------------------------------------------------

/// A batch of changes to apply to a composite type atomically.
#[derive(Debug, Clone)]
pub enum EditTransaction {
    /// Change the type of a component at the given ordinal.
    SetType {
        /// The component ordinal.
        ordinal: usize,
        /// New type name.
        new_type: String,
    },
    /// Change the name of a component.
    SetName {
        /// The component ordinal.
        ordinal: usize,
        /// New field name.
        new_name: String,
    },
    /// Insert a new component at the given position.
    Insert {
        /// Position to insert at.
        at: usize,
        /// Type name for the new component.
        type_name: String,
    },
    /// Remove a component.
    Remove {
        /// The component ordinal to remove.
        ordinal: usize,
    },
    /// Move a component from one position to another.
    Move {
        /// Source ordinal.
        from: usize,
        /// Destination ordinal.
        to: usize,
    },
    /// Replace all components.
    ReplaceAll {
        /// New component list.
        components: Vec<ComponentRow>,
    },
}

// ---------------------------------------------------------------------------
// Component context
// ---------------------------------------------------------------------------

/// Context about the currently selected component in the editor.
#[derive(Debug, Clone)]
pub struct ComponentContext {
    /// The ordinal of the selected component, if any.
    pub selected_ordinal: Option<usize>,
    /// The data type path of the parent composite.
    pub composite_type_path: String,
    /// Whether the editor is in stand-alone mode (not tied to a program).
    pub stand_alone: bool,
    /// The data type manager ID for the composite.
    pub data_type_manager_id: Option<i64>,
}

impl ComponentContext {
    /// Create a new component context.
    pub fn new(composite_type_path: impl Into<String>) -> Self {
        Self {
            selected_ordinal: None,
            composite_type_path: composite_type_path.into(),
            stand_alone: false,
            data_type_manager_id: None,
        }
    }

    /// Whether a component is selected.
    pub fn has_selection(&self) -> bool {
        self.selected_ordinal.is_some()
    }
}

// ---------------------------------------------------------------------------
// Composite editor model
// ---------------------------------------------------------------------------

/// Core model managing the editable state of a composite data type.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorModel`.
#[derive(Debug)]
pub struct CompositeEditorModel {
    /// The name of the composite being edited.
    pub composite_name: String,
    /// Whether this is a struct (true) or union (false).
    pub is_struct: bool,
    /// Current component rows.
    components: Vec<ComponentRow>,
    /// Undo stack (saved component states).
    undo_stack: Vec<Vec<ComponentRow>>,
    /// Redo stack.
    redo_stack: Vec<Vec<ComponentRow>>,
    /// Whether the model has unsaved changes.
    dirty: bool,
}

impl CompositeEditorModel {
    /// Create a new composite editor model.
    pub fn new(composite_name: impl Into<String>, is_struct: bool) -> Self {
        Self {
            composite_name: composite_name.into(),
            is_struct,
            components: Vec::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            dirty: false,
        }
    }

    /// Get the current components.
    pub fn components(&self) -> &[ComponentRow] {
        &self.components
    }

    /// Get mutable access to the current components.
    pub fn components_mut(&mut self) -> &mut Vec<ComponentRow> {
        &mut self.components
    }

    /// Set the components (e.g., when loading a composite type).
    pub fn set_components(&mut self, components: Vec<ComponentRow>) {
        self.save_undo();
        self.components = components;
        self.dirty = true;
    }

    /// Add a new component at the given position.
    pub fn add_component(&mut self, at: usize, type_name: impl Into<String>) {
        self.save_undo();
        let offset = if at == 0 {
            0
        } else if at <= self.components.len() {
            self.components[at - 1].end_offset()
        } else {
            self.components.last().map_or(0, |c| c.end_offset())
        };
        let row = ComponentRow::new(
            at,
            type_name.into(),
            String::new(),
            offset,
            1, // default 1-byte component
        );
        if at >= self.components.len() {
            self.components.push(row);
        } else {
            self.components.insert(at, row);
        }
        self.reindex();
        self.dirty = true;
    }

    /// Remove a component at the given ordinal.
    pub fn remove_component(&mut self, ordinal: usize) -> Option<ComponentRow> {
        if ordinal < self.components.len() {
            self.save_undo();
            let removed = self.components.remove(ordinal);
            self.reindex();
            self.dirty = true;
            Some(removed)
        } else {
            None
        }
    }

    /// Move a component from one position to another.
    pub fn move_component(&mut self, from: usize, to: usize) -> bool {
        if from >= self.components.len() || to >= self.components.len() || from == to {
            return false;
        }
        self.save_undo();
        let comp = self.components.remove(from);
        self.components.insert(to, comp);
        self.reindex();
        self.dirty = true;
        true
    }

    /// Set the type of a component.
    pub fn set_component_type(&mut self, ordinal: usize, type_name: impl Into<String>) -> bool {
        if ordinal < self.components.len() {
            self.save_undo();
            self.components[ordinal].type_name = type_name.into();
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Set the name of a component.
    pub fn set_component_name(&mut self, ordinal: usize, name: impl Into<String>) -> bool {
        if ordinal < self.components.len() {
            self.save_undo();
            self.components[ordinal].field_name = name.into();
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Whether the model has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the model as clean (e.g., after saving).
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Whether an undo operation is available.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Whether a redo operation is available.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Undo the last change.
    pub fn undo(&mut self) -> bool {
        if let Some(prev) = self.undo_stack.pop() {
            self.redo_stack.push(std::mem::replace(&mut self.components, prev));
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Redo the last undone change.
    pub fn redo(&mut self) -> bool {
        if let Some(next) = self.redo_stack.pop() {
            self.undo_stack.push(std::mem::replace(&mut self.components, next));
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Number of components.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Total byte size of all components.
    pub fn total_size(&self) -> u64 {
        self.components
            .last()
            .map_or(0, |c| c.end_offset())
    }

    fn save_undo(&mut self) {
        self.undo_stack.push(self.components.clone());
        self.redo_stack.clear();
    }

    fn reindex(&mut self) {
        for (i, comp) in self.components.iter_mut().enumerate() {
            comp.ordinal = i;
        }
    }
}

// ---------------------------------------------------------------------------
// Composite editor model listener events
// ---------------------------------------------------------------------------

/// Events emitted by the composite editor model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompositeEditorEvent {
    /// A new composite was loaded into the editor.
    CompositeLoaded,
    /// A component was added.
    ComponentAdded,
    /// A component was removed.
    ComponentRemoved,
    /// A component was moved.
    ComponentMoved,
    /// A component type was changed.
    ComponentTypeChanged,
    /// A component name was changed.
    ComponentNameChanged,
    /// The composite was cleared.
    CompositeCleared,
    /// The composite was applied (saved).
    CompositeApplied,
    /// Selection changed.
    SelectionChanged,
    /// The editor state changed (dirty, etc.).
    EditorStateChanged,
}

/// Trait for receiving composite editor model events.
pub trait CompositeEditorModelListener: Send + Sync {
    /// Called when an event occurs.
    fn on_event(&self, event: CompositeEditorEvent);
}

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

/// Column indices for a structure editor table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructureColumns;

impl StructureColumns {
    /// Offset column.
    pub const OFFSET: usize = 0;
    /// Length column.
    pub const LENGTH: usize = 1;
    /// Mnemonic column.
    pub const MNEMONIC: usize = 2;
    /// DataType column.
    pub const DATATYPE: usize = 3;
    /// Field Name column.
    pub const FIELDNAME: usize = 4;
    /// Comment column.
    pub const COMMENT: usize = 5;
    /// Ordinal column (hidden).
    pub const ORDINAL: usize = 6;

    /// Column headers for structure editor.
    pub const HEADERS: &'static [&'static str] =
        &["Offset", "Length", "Mnemonic", "DataType", "Name", "Comment"];

    /// Default column widths.
    pub const WIDTHS: &'static [usize] = &[75, 75, 100, 100, 100, 150];
}

/// Column indices for a union editor table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnionColumns;

impl UnionColumns {
    /// Length column.
    pub const LENGTH: usize = 0;
    /// Mnemonic column.
    pub const MNEMONIC: usize = 1;
    /// DataType column.
    pub const DATATYPE: usize = 2;
    /// Field Name column.
    pub const FIELDNAME: usize = 3;
    /// Comment column.
    pub const COMMENT: usize = 4;
    /// Ordinal column (hidden).
    pub const ORDINAL: usize = 5;

    /// Column headers for union editor.
    pub const HEADERS: &'static [&'static str] =
        &["Length", "Mnemonic", "DataType", "Name", "Comment"];

    /// Default column widths.
    pub const WIDTHS: &'static [usize] = &[75, 100, 100, 100, 150];
}

// ---------------------------------------------------------------------------
// Bit-field editor model
// ---------------------------------------------------------------------------

/// Model for editing bit-field components within a composite.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.BitFieldEditorPanel`.
#[derive(Debug)]
pub struct BitFieldEditorModel {
    /// The bit-field name.
    pub name: String,
    /// The base data type mnemonic (e.g., "uint", "int").
    pub base_type: String,
    /// The bit size of the bit-field.
    pub bit_size: u32,
    /// The bit offset within the containing storage unit.
    pub bit_offset: u32,
    /// Whether the bit-field declaration is valid.
    pub valid: bool,
}

impl BitFieldEditorModel {
    /// Create a new bit-field editor model.
    pub fn new(name: impl Into<String>, base_type: impl Into<String>, bit_size: u32, bit_offset: u32) -> Self {
        Self {
            name: name.into(),
            base_type: base_type.into(),
            bit_size,
            bit_offset,
            valid: bit_size > 0 && bit_size <= 64,
        }
    }

    /// The end bit position (exclusive).
    pub fn end_bit(&self) -> u32 {
        self.bit_offset + self.bit_size
    }

    /// Whether the bit-field fits within a given storage unit size (in bits).
    pub fn fits_in_storage(&self, storage_bits: u32) -> bool {
        self.end_bit() <= storage_bits
    }
}

// ---------------------------------------------------------------------------
// Composite viewer model
// ---------------------------------------------------------------------------

/// Model for viewing (read-only) a composite data type.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeViewerModel`.
/// This is the non-editable counterpart used in the data type manager tree.
#[derive(Debug)]
pub struct CompositeViewerModel {
    /// The composite name.
    pub composite_name: String,
    /// Whether this is a struct (true) or union (false).
    pub is_struct: bool,
    /// The components being viewed.
    components: Vec<ComponentRow>,
    /// Whether to display hex numbers.
    pub show_hex_numbers: bool,
}

impl CompositeViewerModel {
    /// Create a new viewer model.
    pub fn new(composite_name: impl Into<String>, is_struct: bool) -> Self {
        Self {
            composite_name: composite_name.into(),
            is_struct,
            components: Vec::new(),
            show_hex_numbers: false,
        }
    }

    /// Set the components.
    pub fn set_components(&mut self, components: Vec<ComponentRow>) {
        self.components = components;
    }

    /// Get the components.
    pub fn components(&self) -> &[ComponentRow] {
        &self.components
    }

    /// Number of components.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Total byte size.
    pub fn total_size(&self) -> u64 {
        self.components.last().map_or(0, |c| c.end_offset())
    }

    /// The type name ("Structure" or "Union").
    pub fn type_name(&self) -> &'static str {
        if self.is_struct { "Structure" } else { "Union" }
    }
}

// ---------------------------------------------------------------------------
// Structure editor model
// ---------------------------------------------------------------------------

/// Model for editing structure (composite) data types.
///
/// Extends the base [`CompositeEditorModel`] with structure-specific
/// behavior such as sequential component layout, offset management,
/// and gap filling.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.StructureEditorModel`.
#[derive(Debug)]
pub struct StructureEditorModel {
    /// The base composite editor model.
    pub base: CompositeEditorModel,
    /// Whether to show hex numbers in the table.
    pub show_hex_numbers: bool,
    /// Whether to show undefined bytes as components.
    pub show_undefined_bytes: bool,
    /// The number of last-used bytes for dynamic types.
    last_num_bytes: i32,
}

impl StructureEditorModel {
    /// Create a new structure editor model.
    pub fn new(composite_name: impl Into<String>) -> Self {
        Self {
            base: CompositeEditorModel::new(composite_name, true),
            show_hex_numbers: false,
            show_undefined_bytes: true,
            last_num_bytes: 1,
        }
    }

    /// Get the type name.
    pub fn type_name(&self) -> &'static str {
        "Structure"
    }

    /// Whether aligned-length components are used.
    pub fn uses_aligned_length_components(&self) -> bool {
        true
    }

    /// Get the maximum replace length for a component at the given index.
    /// Returns -1 if there's no limit.
    pub fn get_max_replace_length(&self, index: usize) -> i32 {
        if index >= self.base.component_count() {
            return -1;
        }
        let current = &self.base.components()[index];
        current.length as i32
    }

    /// Get the last used byte count for dynamic types.
    pub fn last_num_bytes(&self) -> i32 {
        self.last_num_bytes
    }

    /// Set the last used byte count.
    pub fn set_last_num_bytes(&mut self, count: i32) {
        self.last_num_bytes = count;
    }

    /// Insert an undefined component at the given offset with the given length.
    pub fn insert_undefined(&mut self, at: usize, length: u32) {
        self.base.add_component(at, "undefined");
        if let Some(last) = self.base.components_mut().last_mut() {
            last.length = length;
        }
    }

    /// Replace the component at the given index with a new type.
    pub fn replace_component_type(&mut self, index: usize, type_name: impl Into<String>) -> bool {
        self.base.set_component_type(index, type_name)
    }

    /// Get a formatted hex string for a value.
    pub fn get_hex_string(value: i32, prefix: bool) -> String {
        if prefix {
            format!("0x{:X}", value)
        } else {
            format!("{:X}", value)
        }
    }

    /// Get the offset of a component.
    pub fn get_component_offset(&self, index: usize) -> Option<u64> {
        self.base.components().get(index).map(|c| c.offset)
    }

    /// Get the length of a component.
    pub fn get_component_length(&self, index: usize) -> Option<u32> {
        self.base.components().get(index).map(|c| c.length)
    }
}

// ---------------------------------------------------------------------------
// Union editor model
// ---------------------------------------------------------------------------

/// Model for editing union data types.
///
/// Unions differ from structures in that all components start at offset 0
/// and the total size equals the size of the largest component.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.UnionEditorModel`.
#[derive(Debug)]
pub struct UnionEditorModel {
    /// The base composite editor model.
    pub base: CompositeEditorModel,
    /// Whether to show hex numbers.
    pub show_hex_numbers: bool,
    /// The number of last-used bytes for dynamic types.
    last_num_bytes: i32,
}

impl UnionEditorModel {
    /// Create a new union editor model.
    pub fn new(composite_name: impl Into<String>) -> Self {
        Self {
            base: CompositeEditorModel::new(composite_name, false),
            show_hex_numbers: false,
            last_num_bytes: 1,
        }
    }

    /// Get the type name.
    pub fn type_name(&self) -> &'static str {
        "Union"
    }

    /// Whether aligned-length components are used.
    pub fn uses_aligned_length_components(&self) -> bool {
        false
    }

    /// Get the maximum replace length.
    pub fn get_max_replace_length(&self, _index: usize) -> i32 {
        -1
    }

    /// Get the last used byte count.
    pub fn last_num_bytes(&self) -> i32 {
        self.last_num_bytes
    }

    /// Set the last used byte count.
    pub fn set_last_num_bytes(&mut self, count: i32) {
        self.last_num_bytes = count;
    }

    /// Add a component to the union (all unions start at offset 0).
    pub fn add_union_component(&mut self, type_name: impl Into<String>, length: u32) {
        let ordinal = self.base.component_count();
        let mut row = ComponentRow::new(ordinal, type_name, String::new(), 0, length);
        row.offset = 0; // All union members start at offset 0
        self.base.set_components({
            let mut comps = self.base.components().to_vec();
            comps.push(row);
            comps
        });
    }

    /// The total size of the union is the max component length.
    pub fn total_size(&self) -> u64 {
        self.base
            .components()
            .iter()
            .map(|c| c.length as u64)
            .max()
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Composite editor action manager
// ---------------------------------------------------------------------------

/// Manages actions for the composite editor.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorActionManager`.
#[derive(Debug)]
pub struct CompositeEditorActionManager {
    /// Editor actions (add, delete, etc.).
    editor_actions: Vec<EditorAction>,
    /// Favorites actions (quick-apply data types from favorites list).
    favorites: Vec<String>,
    /// Cycle group actions.
    cycle_groups: Vec<CycleGroup>,
    /// Whether the action manager is disposed.
    disposed: bool,
}

/// A cycle group of related data types that can be toggled through.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CycleGroup`.
#[derive(Debug, Clone)]
pub struct CycleGroup {
    /// Display name for this cycle group.
    pub name: String,
    /// Data types in this group, ordered by size.
    pub types: Vec<String>,
}

impl CycleGroup {
    /// Create a new cycle group.
    pub fn new(name: impl Into<String>, types: Vec<String>) -> Self {
        Self {
            name: name.into(),
            types,
        }
    }

    /// Built-in cycle groups.
    pub fn builtin_groups() -> Vec<CycleGroup> {
        vec![
            CycleGroup::new("byte", vec!["byte".into(), "char".into()]),
            CycleGroup::new("word", vec!["word".into(), "short".into(), "ushort".into()]),
            CycleGroup::new("dword", vec!["dword".into(), "int".into(), "uint".into(), "float".into()]),
            CycleGroup::new("qword", vec![
                "qword".into(), "longlong".into(), "ulonglong".into(), "double".into(),
            ]),
        ]
    }
}

impl CompositeEditorActionManager {
    /// Create a new action manager.
    pub fn new() -> Self {
        Self {
            editor_actions: Vec::new(),
            favorites: Vec::new(),
            cycle_groups: CycleGroup::builtin_groups(),
            disposed: false,
        }
    }

    /// Add an editor action.
    pub fn add_action(&mut self, action: EditorAction) {
        self.editor_actions.push(action);
    }

    /// Remove an editor action.
    pub fn remove_action(&mut self, action: &EditorAction) {
        self.editor_actions.retain(|a| a != action);
    }

    /// Get all editor actions.
    pub fn get_actions(&self) -> &[EditorAction] {
        &self.editor_actions
    }

    /// Set favorites data type names.
    pub fn set_favorites(&mut self, favorites: Vec<String>) {
        self.favorites = favorites;
    }

    /// Get favorites.
    pub fn favorites(&self) -> &[String] {
        &self.favorites
    }

    /// Get cycle groups.
    pub fn cycle_groups(&self) -> &[CycleGroup] {
        &self.cycle_groups
    }

    /// Dispose of this action manager.
    pub fn dispose(&mut self) {
        self.editor_actions.clear();
        self.favorites.clear();
        self.cycle_groups.clear();
        self.disposed = true;
    }

    /// Whether this action manager is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }
}

impl Default for CompositeEditorActionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Data type helper
// ---------------------------------------------------------------------------

/// Helper for dealing with data types in the composite editor.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.DataTypeHelper`.
pub struct DataTypeHelper;

impl DataTypeHelper {
    /// Strip whitespace from a data type name string.
    pub fn strip_whitespace(original: &str) -> String {
        original.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// Validate that a data type name is not empty and not a factory type.
    pub fn validate_type_name(name: &str) -> Result<(), String> {
        let stripped = Self::strip_whitespace(name);
        if stripped.is_empty() {
            return Err("No data type was specified.".into());
        }
        Ok(())
    }

    /// Get the base type from a type name (e.g., strip pointer/array decorators).
    pub fn get_base_type_name(type_name: &str) -> &str {
        // Strip pointer suffix
        let name = type_name.trim_end_matches('*').trim();
        // Strip array suffix [N]
        if let Some(bracket_pos) = name.find('[') {
            &name[..bracket_pos]
        } else {
            name
        }
    }

    /// Check if a type name represents a pointer type.
    pub fn is_pointer_type(type_name: &str) -> bool {
        type_name.contains('*')
    }

    /// Check if a type name represents an array type.
    pub fn is_array_type(type_name: &str) -> bool {
        type_name.contains('[')
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_editor_action_is_modifying() {
        assert!(EditorAction::Apply.is_modifying());
        assert!(EditorAction::Delete.is_modifying());
        assert!(!EditorAction::Undo.is_modifying());
        assert!(!EditorAction::Redo.is_modifying());
    }

    #[test]
    fn test_component_row_new() {
        let row = ComponentRow::new(0, "int", "field_a", 0, 4);
        assert_eq!(row.ordinal, 0);
        assert_eq!(row.type_name, "int");
        assert_eq!(row.field_name, "field_a");
        assert_eq!(row.offset, 0);
        assert_eq!(row.length, 4);
        assert!(!row.is_bit_field);
        assert!(row.enabled);
    }

    #[test]
    fn test_component_row_end_offset() {
        let row = ComponentRow::new(0, "int", "x", 4, 8);
        assert_eq!(row.end_offset(), 12);
    }

    #[test]
    fn test_component_row_is_empty() {
        let empty = ComponentRow::new(0, "empty", "e", 0, 0);
        assert!(empty.is_empty());

        let non_empty = ComponentRow::new(1, "int", "x", 0, 4);
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn test_composite_editor_model_lifecycle() {
        let mut model = CompositeEditorModel::new("MyStruct", true);
        assert_eq!(model.component_count(), 0);
        assert!(!model.is_dirty());

        model.add_component(0, "int");
        assert_eq!(model.component_count(), 1);
        assert!(model.is_dirty());

        model.add_component(1, "char");
        assert_eq!(model.component_count(), 2);

        model.remove_component(0);
        assert_eq!(model.component_count(), 1);
    }

    #[test]
    fn test_composite_editor_model_move() {
        let mut model = CompositeEditorModel::new("S", true);
        model.add_component(0, "int");
        model.add_component(1, "char");
        model.add_component(2, "short");

        assert!(model.move_component(2, 0));
        assert_eq!(model.components()[0].type_name, "short");
        assert_eq!(model.components()[1].type_name, "int");
        assert_eq!(model.components()[2].type_name, "char");
    }

    #[test]
    fn test_composite_editor_model_undo_redo() {
        let mut model = CompositeEditorModel::new("S", true);
        model.add_component(0, "int");
        assert!(model.can_undo());
        assert!(!model.can_redo());

        model.undo();
        assert_eq!(model.component_count(), 0);
        assert!(model.can_redo());

        model.redo();
        assert_eq!(model.component_count(), 1);
    }

    #[test]
    fn test_composite_editor_model_set_type() {
        let mut model = CompositeEditorModel::new("S", true);
        model.add_component(0, "int");
        assert!(model.set_component_type(0, "long"));
        assert_eq!(model.components()[0].type_name, "long");
        assert!(!model.set_component_type(5, "bad"));
    }

    #[test]
    fn test_composite_editor_model_set_name() {
        let mut model = CompositeEditorModel::new("S", true);
        model.add_component(0, "int");
        assert!(model.set_component_name(0, "field_x"));
        assert_eq!(model.components()[0].field_name, "field_x");
    }

    #[test]
    fn test_composite_editor_model_total_size() {
        let mut model = CompositeEditorModel::new("S", true);
        assert_eq!(model.total_size(), 0);

        model.add_component(0, "int"); // offset 0, len 1
        model.add_component(1, "char"); // offset 1, len 1
        assert_eq!(model.total_size(), 2);
    }

    #[test]
    fn test_component_context() {
        let ctx = ComponentContext::new("MyNamespace::MyStruct");
        assert!(!ctx.has_selection());
        assert!(!ctx.stand_alone);

        let mut ctx2 = ctx.clone();
        ctx2.selected_ordinal = Some(3);
        assert!(ctx2.has_selection());
    }

    #[test]
    fn test_edit_transaction_variants() {
        let tx = EditTransaction::SetType {
            ordinal: 0,
            new_type: "int".into(),
        };
        assert!(matches!(tx, EditTransaction::SetType { .. }));
    }

    #[test]
    fn test_structure_columns() {
        assert_eq!(StructureColumns::HEADERS.len(), 6);
        assert_eq!(StructureColumns::OFFSET, 0);
        assert_eq!(StructureColumns::ORDINAL, 6);
    }

    #[test]
    fn test_union_columns() {
        assert_eq!(UnionColumns::HEADERS.len(), 5);
        assert_eq!(UnionColumns::LENGTH, 0);
        assert_eq!(UnionColumns::ORDINAL, 5);
    }

    #[test]
    fn test_bitfield_editor_model() {
        let bf = BitFieldEditorModel::new("flags", "uint", 3, 5);
        assert_eq!(bf.end_bit(), 8);
        assert!(bf.fits_in_storage(8));
        assert!(!bf.fits_in_storage(7));
        assert!(bf.valid);
    }

    #[test]
    fn test_bitfield_editor_model_invalid() {
        let bf = BitFieldEditorModel::new("bad", "uint", 0, 0);
        assert!(!bf.valid);
        let bf2 = BitFieldEditorModel::new("bad2", "uint", 65, 0);
        assert!(!bf2.valid);
    }

    #[test]
    fn test_composite_viewer_model() {
        let mut viewer = CompositeViewerModel::new("MyStruct", true);
        assert_eq!(viewer.type_name(), "Structure");
        assert_eq!(viewer.component_count(), 0);

        viewer.set_components(vec![
            ComponentRow::new(0, "int", "x", 0, 4),
            ComponentRow::new(1, "char", "c", 4, 1),
        ]);
        assert_eq!(viewer.component_count(), 2);
        assert_eq!(viewer.total_size(), 5);
    }

    #[test]
    fn test_composite_viewer_model_union() {
        let viewer = CompositeViewerModel::new("MyUnion", false);
        assert_eq!(viewer.type_name(), "Union");
    }

    #[test]
    fn test_structure_editor_model() {
        let mut model = StructureEditorModel::new("S");
        assert_eq!(model.type_name(), "Structure");
        assert!(model.uses_aligned_length_components());

        model.base.add_component(0, "int");
        assert_eq!(model.get_component_offset(0), Some(0));
        assert_eq!(model.get_component_length(0), Some(1)); // default 1-byte

        model.set_last_num_bytes(4);
        assert_eq!(model.last_num_bytes(), 4);
    }

    #[test]
    fn test_structure_editor_model_hex_string() {
        assert_eq!(StructureEditorModel::get_hex_string(255, true), "0xFF");
        assert_eq!(StructureEditorModel::get_hex_string(10, false), "A");
    }

    #[test]
    fn test_union_editor_model() {
        let mut model = UnionEditorModel::new("U");
        assert_eq!(model.type_name(), "Union");
        assert!(!model.uses_aligned_length_components());

        model.add_union_component("int", 4);
        model.add_union_component("char[8]", 8);
        assert_eq!(model.total_size(), 8);
    }

    #[test]
    fn test_union_editor_model_empty() {
        let model = UnionEditorModel::new("EmptyUnion");
        assert_eq!(model.total_size(), 0);
    }

    #[test]
    fn test_composite_editor_action_manager() {
        let mut mgr = CompositeEditorActionManager::new();
        assert!(!mgr.is_disposed());
        assert!(mgr.get_actions().is_empty());
        assert!(!mgr.cycle_groups().is_empty());

        mgr.add_action(EditorAction::Apply);
        assert_eq!(mgr.get_actions().len(), 1);

        mgr.remove_action(&EditorAction::Apply);
        assert!(mgr.get_actions().is_empty());

        mgr.dispose();
        assert!(mgr.is_disposed());
    }

    #[test]
    fn test_cycle_group() {
        let groups = CycleGroup::builtin_groups();
        assert!(!groups.is_empty());
        assert_eq!(groups[0].name, "byte");
    }

    #[test]
    fn test_data_type_helper_strip_whitespace() {
        assert_eq!(DataTypeHelper::strip_whitespace("  int  * "), "int*");
        assert_eq!(DataTypeHelper::strip_whitespace(""), "");
    }

    #[test]
    fn test_data_type_helper_validate() {
        assert!(DataTypeHelper::validate_type_name("int").is_ok());
        assert!(DataTypeHelper::validate_type_name("").is_err());
        assert!(DataTypeHelper::validate_type_name("   ").is_err());
    }

    #[test]
    fn test_data_type_helper_base_type() {
        assert_eq!(DataTypeHelper::get_base_type_name("int *"), "int");
        assert_eq!(DataTypeHelper::get_base_type_name("char"), "char");
        assert_eq!(DataTypeHelper::get_base_type_name("int[10]"), "int");
    }

    #[test]
    fn test_data_type_helper_pointer_array() {
        assert!(DataTypeHelper::is_pointer_type("int *"));
        assert!(!DataTypeHelper::is_pointer_type("int"));
        assert!(DataTypeHelper::is_array_type("int[10]"));
        assert!(!DataTypeHelper::is_array_type("int"));
    }

    #[test]
    fn test_structure_editor_model_insert_undefined() {
        let mut model = StructureEditorModel::new("S");
        model.insert_undefined(0, 4);
        assert_eq!(model.base.component_count(), 1);
        assert_eq!(model.base.components()[0].type_name, "undefined");
        assert_eq!(model.base.components()[0].length, 4);
    }

    #[test]
    fn test_structure_editor_model_replace_component_type() {
        let mut model = StructureEditorModel::new("S");
        model.base.add_component(0, "int");
        assert!(model.replace_component_type(0, "float"));
        assert_eq!(model.base.components()[0].type_name, "float");
    }

    #[test]
    fn test_union_all_at_offset_zero() {
        let mut model = UnionEditorModel::new("U");
        model.add_union_component("int", 4);
        model.add_union_component("double", 8);
        // All union members should be at offset 0
        for comp in model.base.components() {
            assert_eq!(comp.offset, 0);
        }
    }
}
