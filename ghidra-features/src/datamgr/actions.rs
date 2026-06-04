//! Data Type Manager actions -- ported from `ghidra.app.plugin.core.datamgr.actions`.
//!
//! Each action struct models a Ghidra docking action for the data type
//! manager tree.  Actions include clipboard operations (cut/copy/paste),
//! CRUD operations on types and categories, find operations, archive
//! management, and type synchronization.
//!
//! # Actions ported
//!
//! | Rust struct                     | Java class                            |
//! |---------------------------------|---------------------------------------|
//! | `ClipboardAction`               | `CopyAction`, `CutAction`, `PasteAction` |
//! | `DeleteDataTypeAction`          | `DeleteAction`                        |
//! | `RenameDataTypeAction`          | `RenameAction`                        |
//! | `EditDataTypeAction`            | `EditAction`                          |
//! | `CreateCategoryAction`          | `CreateCategoryAction`                |
//! | `CreateDataTypeAction`          | `CreateDataTypeAction` (base)         |
//! | `CreateEnumAction`              | `CreateEnumAction`                    |
//! | `CreateStructureAction`         | `CreateStructureAction`               |
//! | `CreateUnionAction`             | `CreateUnionAction`                   |
//! | `CreatePointerAction`           | `CreatePointerAction`                 |
//! | `CreateTypeDefAction`           | `CreateTypeDefAction`                 |
//! | `CreateFunctionDefAction`       | `CreateFunctionDefinitionAction`      |
//! | `FindDataTypeAction`            | `FindDataTypesByNameAction`           |
//! | `FindDataTypeBySizeAction`      | `FindDataTypesBySizeAction`           |
//! | `FindReferencesToTypeAction`    | `FindReferencesToDataTypeAction`      |
//! | `MergeDataTypeAction`           | `MergeDataTypeAction`                 |
//! | `ReplaceDataTypeAction`         | `ReplaceDataTypeAction`               |
//! | `SetFavoriteDataTypeAction`     | `SetFavoriteDataTypeAction`           |
//! | `ExportToHeaderAction`          | `ExportToHeaderAction`                |
//! | `UndoRedoArchiveAction`         | `UndoArchiveTransactionAction`, etc.  |
//! | `ArchiveManagementAction`       | `OpenArchiveAction`, `CloseArchiveAction`, etc. |

use std::collections::HashMap;
use std::fmt;

use ghidra_core::data::{CategoryPath, DataTypePath};

// Re-export TreeNodeKind from the tree module to avoid duplication.
pub use super::tree::TreeNodeKind;

// ---------------------------------------------------------------------------
// ActionContext
// ---------------------------------------------------------------------------

/// Context for data type manager actions.
///
/// Models `DataTypesActionContext` from Ghidra.
#[derive(Debug, Clone, Default)]
pub struct DataTypesActionContext {
    /// The selected tree node paths.
    pub selected_paths: Vec<TreeNodePath>,
    /// Whether the context is in the data type manager tree.
    pub is_data_type_tree: bool,
    /// Whether the selected node is editable.
    pub is_editable: bool,
    /// Whether the selected node is modifiable.
    pub is_modifiable: bool,
    /// The archive kind of the selected node, if any.
    pub archive_kind: Option<String>,
}

impl DataTypesActionContext {
    /// Creates a new context for a single selected node.
    pub fn single_selection(path: TreeNodePath) -> Self {
        Self {
            selected_paths: vec![path],
            is_data_type_tree: true,
            ..Default::default()
        }
    }

    /// Creates a new context for multiple selected nodes.
    pub fn multi_selection(paths: Vec<TreeNodePath>) -> Self {
        Self {
            selected_paths: paths,
            is_data_type_tree: true,
            ..Default::default()
        }
    }

    /// Returns `true` if there is exactly one selected node.
    pub fn has_single_selection(&self) -> bool {
        self.selected_paths.len() == 1
    }

    /// Returns the first selected path, if any.
    pub fn first_path(&self) -> Option<&TreeNodePath> {
        self.selected_paths.first()
    }
}

// ---------------------------------------------------------------------------
// TreeNodePath
// ---------------------------------------------------------------------------

/// A path to a node in the data type tree.
///
/// Models the `TreePath` used by Ghidra's `GTree`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeNodePath {
    /// The node kind.
    pub kind: TreeNodeKind,
    /// The display name of the node.
    pub name: String,
    /// The full path (e.g., "/Category/StructName").
    pub full_path: String,
    /// Whether the node is a built-in type (non-deletable).
    pub is_built_in: bool,
    /// The archive name this node belongs to.
    pub archive_name: Option<String>,
}

impl TreeNodePath {
    /// Creates a new tree node path.
    pub fn new(kind: TreeNodeKind, name: impl Into<String>, full_path: impl Into<String>) -> Self {
        Self {
            kind,
            name: name.into(),
            full_path: full_path.into(),
            is_built_in: false,
            archive_name: None,
        }
    }

    /// Creates a category node path.
    pub fn category(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self::new(TreeNodeKind::Category, name, path)
    }

    /// Creates a data type node path.
    pub fn data_type(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self::new(TreeNodeKind::DataType, name, path)
    }

    /// Creates an archive node path.
    pub fn archive(name: impl Into<String>) -> Self {
        let n = name.into();
        Self::new(TreeNodeKind::Archive, &n, &n)
    }

    /// Returns the `CategoryPath` for this node.
    pub fn category_path(&self) -> CategoryPath {
        match self.kind {
            TreeNodeKind::Category => CategoryPath::from_path_string(&self.full_path),
            TreeNodeKind::DataType => {
                // Strip the last component to get the parent category path
                if let Some(pos) = self.full_path.rfind('/') {
                    CategoryPath::from_path_string(&self.full_path[..pos])
                } else {
                    CategoryPath::ROOT
                }
            }
            _ => CategoryPath::ROOT,
        }
    }

    /// Returns the `DataTypePath` for this node (only for data type nodes).
    pub fn data_type_path(&self) -> Option<DataTypePath> {
        if self.kind == TreeNodeKind::DataType {
            Some(DataTypePath::new(
                self.category_path(),
                self.name.clone(),
            ))
        } else {
            None
        }
    }
}

// TreeNodeKind is re-exported from `super::tree` above.

// ---------------------------------------------------------------------------
// Clipboard actions
// ---------------------------------------------------------------------------

/// The clipboard operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardOperation {
    /// Copy data types.
    Copy,
    /// Cut data types (copy + mark for deletion).
    Cut,
}

/// Action to copy or cut data types to the clipboard.
///
/// Ported from `CopyAction.java` and `CutAction.java`.
///
/// # Example
///
/// ```
/// use ghidra_features::datamgr::actions::*;
///
/// let action = ClipboardAction::copy();
/// assert_eq!(action.operation(), ClipboardOperation::Copy);
/// assert!(!action.is_enabled_for_context(&DataTypesActionContext::default()));
/// ```
#[derive(Debug, Clone)]
pub struct ClipboardAction {
    /// The operation (copy or cut).
    operation: ClipboardOperation,
    /// Whether the action is enabled.
    enabled: bool,
}

impl ClipboardAction {
    /// Creates a new copy action.
    pub fn copy() -> Self {
        Self {
            operation: ClipboardOperation::Copy,
            enabled: true,
        }
    }

    /// Creates a new cut action.
    pub fn cut() -> Self {
        Self {
            operation: ClipboardOperation::Cut,
            enabled: true,
        }
    }

    /// Returns the clipboard operation.
    pub fn operation(&self) -> ClipboardOperation {
        self.operation
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        match self.operation {
            ClipboardOperation::Copy => "Copy",
            ClipboardOperation::Cut => "Cut",
        }
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        if !self.enabled || !ctx.is_data_type_tree {
            return false;
        }
        if ctx.selected_paths.is_empty() {
            return false;
        }
        // Cannot copy/cut archive root or archive nodes
        !ctx.selected_paths.iter().any(|p| {
            p.kind == TreeNodeKind::ArchiveRoot || p.kind == TreeNodeKind::Archive
        })
    }
}

/// Action to paste data types from the clipboard.
///
/// Ported from `PasteAction.java`.
#[derive(Debug, Clone)]
pub struct PasteAction {
    /// Whether the action is enabled.
    enabled: bool,
    /// Whether there is content on the clipboard.
    has_content: bool,
}

impl PasteAction {
    /// Creates a new paste action.
    pub fn new() -> Self {
        Self {
            enabled: true,
            has_content: false,
        }
    }

    /// Sets whether there is clipboard content.
    pub fn set_has_content(&mut self, has_content: bool) {
        self.has_content = has_content;
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        "Paste"
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        self.enabled
            && self.has_content
            && ctx.is_data_type_tree
            && ctx.has_single_selection()
            && ctx.is_modifiable
    }
}

impl Default for PasteAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Delete action
// ---------------------------------------------------------------------------

/// Action to delete data types or categories.
///
/// Ported from `DeleteAction.java`.  Key binding: `Delete`.
///
/// # Example
///
/// ```
/// use ghidra_features::datamgr::actions::*;
///
/// let action = DeleteDataTypeAction::new();
/// assert_eq!(action.name(), "Delete");
/// ```
#[derive(Debug, Clone)]
pub struct DeleteDataTypeAction {
    enabled: bool,
}

impl DeleteDataTypeAction {
    /// Creates a new delete action.
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        "Delete"
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        if !self.enabled || !ctx.is_data_type_tree {
            return false;
        }
        if ctx.selected_paths.is_empty() {
            return false;
        }
        // Cannot delete the root or archive nodes, or built-in types
        !ctx.selected_paths.iter().any(|p| {
            p.kind == TreeNodeKind::ArchiveRoot
                || p.kind == TreeNodeKind::Archive
                || p.is_built_in
        })
    }

    /// Returns `true` if the action should appear in the popup menu.
    pub fn is_add_to_popup(&self, ctx: &DataTypesActionContext) -> bool {
        if !ctx.is_data_type_tree || ctx.selected_paths.is_empty() {
            return false;
        }
        // Don't show for undeletable nodes
        !ctx.selected_paths.iter().any(|p| {
            p.kind == TreeNodeKind::ArchiveRoot || p.kind == TreeNodeKind::Archive
        })
    }
}

impl Default for DeleteDataTypeAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Rename action
// ---------------------------------------------------------------------------

/// Action to rename a data type or category.
///
/// Ported from `RenameAction.java`.
#[derive(Debug, Clone)]
pub struct RenameDataTypeAction {
    enabled: bool,
}

impl RenameDataTypeAction {
    /// Creates a new rename action.
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        "Rename"
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        self.enabled
            && ctx.is_data_type_tree
            && ctx.has_single_selection()
            && ctx.is_editable
    }

    /// Returns `true` if the action should appear in the popup menu.
    pub fn is_add_to_popup(&self, ctx: &DataTypesActionContext) -> bool {
        if !ctx.is_data_type_tree || !ctx.has_single_selection() {
            return false;
        }
        if let Some(path) = ctx.first_path() {
            // Cannot rename root or archive nodes
            path.kind != TreeNodeKind::ArchiveRoot && path.kind != TreeNodeKind::Archive
        } else {
            false
        }
    }
}

impl Default for RenameDataTypeAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Edit action
// ---------------------------------------------------------------------------

/// Action to open the inline editor for a data type.
///
/// Ported from `EditAction.java`.
#[derive(Debug, Clone)]
pub struct EditDataTypeAction {
    enabled: bool,
}

impl EditDataTypeAction {
    /// Creates a new edit action.
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        "Edit"
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        self.enabled
            && ctx.is_data_type_tree
            && ctx.has_single_selection()
            && ctx.is_modifiable
    }
}

impl Default for EditDataTypeAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Create actions
// ---------------------------------------------------------------------------

/// The kind of data type to create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateTypeKind {
    /// A new enum.
    Enum,
    /// A new structure.
    Structure,
    /// A new union.
    Union,
    /// A new pointer.
    Pointer,
    /// A new type definition (typedef).
    TypeDef,
    /// A new function definition.
    FunctionDefinition,
}

impl fmt::Display for CreateTypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enum => write!(f, "Enum"),
            Self::Structure => write!(f, "Structure"),
            Self::Union => write!(f, "Union"),
            Self::Pointer => write!(f, "Pointer"),
            Self::TypeDef => write!(f, "TypeDef"),
            Self::FunctionDefinition => write!(f, "FunctionDefinition"),
        }
    }
}

/// Action to create a new data type.
///
/// Ported from `CreateDataTypeAction.java` (the abstract base) and
/// its concrete subclasses.
///
/// # Example
///
/// ```
/// use ghidra_features::datamgr::actions::*;
///
/// let action = CreateDataTypeAction::new(CreateTypeKind::Enum);
/// assert_eq!(action.name(), "New Enum...");
/// assert_eq!(action.type_kind(), CreateTypeKind::Enum);
/// ```
#[derive(Debug, Clone)]
pub struct CreateDataTypeAction {
    /// The kind of data type to create.
    type_kind: CreateTypeKind,
    /// Whether the action is enabled.
    enabled: bool,
}

impl CreateDataTypeAction {
    /// Creates a new create data type action for the given kind.
    pub fn new(type_kind: CreateTypeKind) -> Self {
        Self {
            type_kind,
            enabled: true,
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> String {
        format!("New {}...", self.type_kind)
    }

    /// Returns the data type kind.
    pub fn type_kind(&self) -> CreateTypeKind {
        self.type_kind
    }

    /// Returns `true` if the action is enabled for the given context.
    ///
    /// Creation requires a selected category node that is modifiable.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        if !self.enabled || !ctx.is_data_type_tree || !ctx.has_single_selection() {
            return false;
        }
        ctx.is_modifiable
    }

    /// Returns `true` if the action should appear in the popup menu.
    pub fn is_add_to_popup(&self, ctx: &DataTypesActionContext) -> bool {
        if !ctx.is_data_type_tree || !ctx.has_single_selection() {
            return false;
        }
        if let Some(path) = ctx.first_path() {
            // Only for category nodes, not built-in archives
            path.kind == TreeNodeKind::Category && !path.is_built_in
        } else {
            false
        }
    }
}

/// Action to create a new category (folder).
///
/// Ported from `CreateCategoryAction.java`.
#[derive(Debug, Clone)]
pub struct CreateCategoryAction {
    enabled: bool,
}

impl CreateCategoryAction {
    /// Creates a new create category action.
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        "New Folder..."
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        self.enabled
            && ctx.is_data_type_tree
            && ctx.has_single_selection()
            && ctx.is_modifiable
    }
}

impl Default for CreateCategoryAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Find actions
// ---------------------------------------------------------------------------

/// The find mode for data type search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindMode {
    /// Find by name.
    ByName,
    /// Find by size.
    BySize,
    /// Find references to a data type.
    ReferencesToType,
    /// Find references to a field.
    ReferencesToField,
    /// Find structures by offset.
    StructuresByOffset,
    /// Find structures by size.
    StructuresBySize,
    /// Find base data types.
    BaseDataType,
    /// Find enums by value.
    EnumsByValue,
}

impl fmt::Display for FindMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByName => write!(f, "ByName"),
            Self::BySize => write!(f, "BySize"),
            Self::ReferencesToType => write!(f, "ReferencesToType"),
            Self::ReferencesToField => write!(f, "ReferencesToField"),
            Self::StructuresByOffset => write!(f, "StructuresByOffset"),
            Self::StructuresBySize => write!(f, "StructuresBySize"),
            Self::BaseDataType => write!(f, "BaseDataType"),
            Self::EnumsByValue => write!(f, "EnumsByValue"),
        }
    }
}

/// Action to find data types by various criteria.
///
/// Ported from `FindDataTypesByNameAction.java`,
/// `FindDataTypesBySizeAction.java`, etc.
///
/// # Example
///
/// ```
/// use ghidra_features::datamgr::actions::*;
///
/// let action = FindDataTypeAction::new(FindMode::ByName);
/// assert_eq!(action.name(), "Find by Name...");
/// assert_eq!(action.mode(), FindMode::ByName);
/// ```
#[derive(Debug, Clone)]
pub struct FindDataTypeAction {
    /// The find mode.
    mode: FindMode,
    /// Whether the action is enabled.
    enabled: bool,
}

impl FindDataTypeAction {
    /// Creates a new find action for the given mode.
    pub fn new(mode: FindMode) -> Self {
        Self { mode, enabled: true }
    }

    /// Returns the action name.
    pub fn name(&self) -> String {
        match self.mode {
            FindMode::ByName => "Find by Name...".to_string(),
            FindMode::BySize => "Find by Size...".to_string(),
            FindMode::ReferencesToType => "Find References to Data Type".to_string(),
            FindMode::ReferencesToField => "Find References to Field...".to_string(),
            FindMode::StructuresByOffset => "Find Structures by Offset...".to_string(),
            FindMode::StructuresBySize => "Find Structures by Size...".to_string(),
            FindMode::BaseDataType => "Find Base Data Type".to_string(),
            FindMode::EnumsByValue => "Find Enums by Value...".to_string(),
        }
    }

    /// Returns the find mode.
    pub fn mode(&self) -> FindMode {
        self.mode
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        self.enabled && ctx.is_data_type_tree
    }
}

// ---------------------------------------------------------------------------
// Merge / Replace actions
// ---------------------------------------------------------------------------

/// The conflict resolution mode for merge operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Use the source version.
    UseSource,
    /// Use the destination version.
    UseDestination,
    /// Rename the source to avoid conflict.
    RenameSource,
    /// Skip conflicting types.
    Skip,
}

impl fmt::Display for ConflictResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UseSource => write!(f, "Use Source"),
            Self::UseDestination => write!(f, "Use Destination"),
            Self::RenameSource => write!(f, "Rename Source"),
            Self::Skip => write!(f, "Skip"),
        }
    }
}

/// Action to merge data types from one archive to another.
///
/// Ported from `MergeDataTypeAction.java`.
#[derive(Debug, Clone)]
pub struct MergeDataTypeAction {
    enabled: bool,
    /// The conflict resolution mode.
    conflict_resolution: ConflictResolution,
}

impl MergeDataTypeAction {
    /// Creates a new merge action.
    pub fn new() -> Self {
        Self {
            enabled: true,
            conflict_resolution: ConflictResolution::UseSource,
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        "Merge"
    }

    /// Sets the conflict resolution mode.
    pub fn set_conflict_resolution(&mut self, mode: ConflictResolution) {
        self.conflict_resolution = mode;
    }

    /// Returns the conflict resolution mode.
    pub fn conflict_resolution(&self) -> ConflictResolution {
        self.conflict_resolution
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        self.enabled
            && ctx.is_data_type_tree
            && ctx.has_single_selection()
            && ctx.is_modifiable
    }
}

impl Default for MergeDataTypeAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action to replace one data type with another.
///
/// Ported from `ReplaceDataTypeAction.java`.
#[derive(Debug, Clone)]
pub struct ReplaceDataTypeAction {
    enabled: bool,
}

impl ReplaceDataTypeAction {
    /// Creates a new replace action.
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        "Replace..."
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        self.enabled
            && ctx.is_data_type_tree
            && ctx.has_single_selection()
            && ctx.is_modifiable
    }
}

impl Default for ReplaceDataTypeAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Favorite action
// ---------------------------------------------------------------------------

/// Action to set/unset a data type as a favorite.
///
/// Ported from `SetFavoriteDataTypeAction.java`.
#[derive(Debug, Clone)]
pub struct SetFavoriteDataTypeAction {
    enabled: bool,
    /// The current favorites.
    favorites: Vec<DataTypePath>,
}

impl SetFavoriteDataTypeAction {
    /// Creates a new set favorite action.
    pub fn new() -> Self {
        Self {
            enabled: true,
            favorites: Vec::new(),
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        "Set as Favorite"
    }

    /// Adds a data type to the favorites.
    pub fn add_favorite(&mut self, path: DataTypePath) {
        if !self.favorites.contains(&path) {
            self.favorites.push(path);
        }
    }

    /// Removes a data type from the favorites.
    pub fn remove_favorite(&mut self, path: &DataTypePath) {
        self.favorites.retain(|p| p != path);
    }

    /// Returns `true` if the given data type is a favorite.
    pub fn is_favorite(&self, path: &DataTypePath) -> bool {
        self.favorites.contains(path)
    }

    /// Returns the favorites.
    pub fn favorites(&self) -> &[DataTypePath] {
        &self.favorites
    }

    /// Toggles the favorite status.
    pub fn toggle_favorite(&mut self, path: DataTypePath) {
        if self.is_favorite(&path) {
            self.remove_favorite(&path);
        } else {
            self.add_favorite(path);
        }
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        self.enabled && ctx.is_data_type_tree && ctx.has_single_selection()
    }
}

impl Default for SetFavoriteDataTypeAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Archive management actions
// ---------------------------------------------------------------------------

/// The type of archive management action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveActionKind {
    /// Open an archive file.
    Open,
    /// Close an archive.
    Close,
    /// Save the archive.
    Save,
    /// Save the archive as a new file.
    SaveAs,
    /// Lock the archive.
    Lock,
    /// Unlock the archive.
    Unlock,
    /// Delete an archive reference.
    Delete,
    /// Set the archive architecture.
    SetArchitecture,
    /// Clear the archive architecture.
    ClearArchitecture,
    /// Create a new project archive.
    CreateProjectArchive,
    /// Update source archive names.
    UpdateSourceNames,
}

impl fmt::Display for ArchiveActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "Open"),
            Self::Close => write!(f, "Close"),
            Self::Save => write!(f, "Save"),
            Self::SaveAs => write!(f, "Save As"),
            Self::Lock => write!(f, "Lock"),
            Self::Unlock => write!(f, "Unlock"),
            Self::Delete => write!(f, "Delete"),
            Self::SetArchitecture => write!(f, "Set Architecture"),
            Self::ClearArchitecture => write!(f, "Clear Architecture"),
            Self::CreateProjectArchive => write!(f, "Create Project Archive"),
            Self::UpdateSourceNames => write!(f, "Update Source Names"),
        }
    }
}

/// Action for archive management operations.
///
/// Ported from `OpenArchiveAction.java`, `CloseArchiveAction.java`,
/// `SaveArchiveAction.java`, `LockArchiveAction.java`, etc.
///
/// # Example
///
/// ```
/// use ghidra_features::datamgr::actions::*;
///
/// let action = ArchiveManagementAction::new(ArchiveActionKind::Open);
/// assert_eq!(action.name(), "Open Archive...");
/// assert_eq!(action.kind(), ArchiveActionKind::Open);
/// ```
#[derive(Debug, Clone)]
pub struct ArchiveManagementAction {
    /// The kind of archive action.
    kind: ArchiveActionKind,
    /// Whether the action is enabled.
    enabled: bool,
}

impl ArchiveManagementAction {
    /// Creates a new archive management action.
    pub fn new(kind: ArchiveActionKind) -> Self {
        Self { kind, enabled: true }
    }

    /// Returns the action name.
    pub fn name(&self) -> String {
        match self.kind {
            ArchiveActionKind::Open => "Open Archive...".to_string(),
            ArchiveActionKind::Close => "Close Archive".to_string(),
            ArchiveActionKind::Save => "Save Archive".to_string(),
            ArchiveActionKind::SaveAs => "Save Archive As...".to_string(),
            ArchiveActionKind::Lock => "Lock Archive".to_string(),
            ArchiveActionKind::Unlock => "Unlock Archive".to_string(),
            ArchiveActionKind::Delete => "Delete Archive".to_string(),
            ArchiveActionKind::SetArchitecture => "Set Architecture...".to_string(),
            ArchiveActionKind::ClearArchitecture => "Clear Architecture".to_string(),
            ArchiveActionKind::CreateProjectArchive => "Create Project Archive...".to_string(),
            ArchiveActionKind::UpdateSourceNames => "Update Source Archive Names".to_string(),
        }
    }

    /// Returns the action kind.
    pub fn kind(&self) -> ArchiveActionKind {
        self.kind
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        self.enabled && ctx.is_data_type_tree
    }
}

// ---------------------------------------------------------------------------
// Undo/Redo archive transaction actions
// ---------------------------------------------------------------------------

/// Action to undo/redo an archive transaction.
///
/// Ported from `UndoArchiveTransactionAction.java` and
/// `RedoArchiveTransactionAction.java`.
#[derive(Debug, Clone)]
pub struct UndoRedoArchiveAction {
    /// Whether this is an undo or redo action.
    is_undo: bool,
    /// Whether the action is enabled.
    enabled: bool,
}

impl UndoRedoArchiveAction {
    /// Creates a new undo action.
    pub fn undo() -> Self {
        Self {
            is_undo: true,
            enabled: true,
        }
    }

    /// Creates a new redo action.
    pub fn redo() -> Self {
        Self {
            is_undo: false,
            enabled: true,
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        if self.is_undo { "Undo" } else { "Redo" }
    }

    /// Returns `true` if this is an undo action.
    pub fn is_undo(&self) -> bool {
        self.is_undo
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        self.enabled && ctx.is_data_type_tree && ctx.is_modifiable
    }
}

// ---------------------------------------------------------------------------
// ExportToHeaderAction
// ---------------------------------------------------------------------------

/// Action to export data types as a C header file.
///
/// Ported from `ExportToHeaderAction.java`.
#[derive(Debug, Clone)]
pub struct ExportToHeaderAction {
    enabled: bool,
}

impl ExportToHeaderAction {
    /// Creates a new export to header action.
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        "Export to C Header..."
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        self.enabled && ctx.is_data_type_tree && !ctx.selected_paths.is_empty()
    }
}

impl Default for ExportToHeaderAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DisplayTypeAsGraphAction
// ---------------------------------------------------------------------------

/// Action to display a data type's structure as a graph.
///
/// Ported from `DisplayTypeAsGraphAction.java`.
#[derive(Debug, Clone)]
pub struct DisplayTypeAsGraphAction {
    enabled: bool,
}

impl DisplayTypeAsGraphAction {
    /// Creates a new display type as graph action.
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        "Show Type Graph"
    }

    /// Returns `true` if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &DataTypesActionContext) -> bool {
        self.enabled
            && ctx.is_data_type_tree
            && ctx.has_single_selection()
            && ctx
                .first_path()
                .map(|p| p.kind == TreeNodeKind::DataType)
                .unwrap_or(false)
    }
}

impl Default for DisplayTypeAsGraphAction {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- DataTypesActionContext tests --

    #[test]
    fn test_action_context_single() {
        let ctx = DataTypesActionContext::single_selection(
            TreeNodePath::data_type("int", "/int"),
        );
        assert!(ctx.has_single_selection());
        assert_eq!(ctx.first_path().unwrap().name, "int");
    }

    #[test]
    fn test_action_context_empty() {
        let ctx = DataTypesActionContext::default();
        assert!(!ctx.has_single_selection());
        assert!(ctx.first_path().is_none());
    }

    // -- TreeNodePath tests --

    #[test]
    fn test_tree_node_path_category() {
        let path = TreeNodePath::category("MyCategory", "/MyCategory");
        assert_eq!(path.kind, TreeNodeKind::Category);
        assert_eq!(path.name, "MyCategory");
        assert_eq!(path.category_path().segments.join("/"), "MyCategory");
    }

    #[test]
    fn test_tree_node_path_data_type() {
        let path = TreeNodePath::data_type("MyStruct", "/Types/MyStruct");
        assert_eq!(path.kind, TreeNodeKind::DataType);
        let dtp = path.data_type_path().unwrap();
        assert_eq!(dtp.data_type_name, "MyStruct");
    }

    #[test]
    fn test_tree_node_path_archive() {
        let path = TreeNodePath::archive("builtins");
        assert_eq!(path.kind, TreeNodeKind::Archive);
    }

    // -- ClipboardAction tests --

    #[test]
    fn test_copy_action() {
        let action = ClipboardAction::copy();
        assert_eq!(action.name(), "Copy");
        assert_eq!(action.operation(), ClipboardOperation::Copy);
    }

    #[test]
    fn test_cut_action() {
        let action = ClipboardAction::cut();
        assert_eq!(action.name(), "Cut");
        assert_eq!(action.operation(), ClipboardOperation::Cut);
    }

    #[test]
    fn test_clipboard_action_enabled() {
        let action = ClipboardAction::copy();
        let mut ctx = DataTypesActionContext::single_selection(
            TreeNodePath::data_type("int", "/int"),
        );
        ctx.is_data_type_tree = true;
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_clipboard_action_disabled_for_archive() {
        let action = ClipboardAction::copy();
        let mut ctx = DataTypesActionContext::single_selection(
            TreeNodePath::archive("builtins"),
        );
        ctx.is_data_type_tree = true;
        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_paste_action_no_content() {
        let action = PasteAction::new();
        let ctx = DataTypesActionContext::default();
        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_paste_action_with_content() {
        let mut action = PasteAction::new();
        action.set_has_content(true);
        let mut ctx = DataTypesActionContext::single_selection(
            TreeNodePath::category("Types", "/Types"),
        );
        ctx.is_data_type_tree = true;
        ctx.is_modifiable = true;
        assert!(action.is_enabled_for_context(&ctx));
    }

    // -- DeleteDataTypeAction tests --

    #[test]
    fn test_delete_action() {
        let action = DeleteDataTypeAction::new();
        assert_eq!(action.name(), "Delete");

        let mut ctx = DataTypesActionContext::single_selection(
            TreeNodePath::data_type("int", "/int"),
        );
        ctx.is_data_type_tree = true;
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_delete_action_built_in() {
        let action = DeleteDataTypeAction::new();
        let mut path = TreeNodePath::data_type("int", "/int");
        path.is_built_in = true;
        let mut ctx = DataTypesActionContext::single_selection(path);
        ctx.is_data_type_tree = true;
        assert!(!action.is_enabled_for_context(&ctx));
    }

    // -- RenameDataTypeAction tests --

    #[test]
    fn test_rename_action() {
        let action = RenameDataTypeAction::new();
        assert_eq!(action.name(), "Rename");

        let mut ctx = DataTypesActionContext::single_selection(
            TreeNodePath::data_type("int", "/int"),
        );
        ctx.is_data_type_tree = true;
        ctx.is_editable = true;
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_rename_action_not_editable() {
        let action = RenameDataTypeAction::new();
        let mut ctx = DataTypesActionContext::single_selection(
            TreeNodePath::data_type("int", "/int"),
        );
        ctx.is_data_type_tree = true;
        ctx.is_editable = false;
        assert!(!action.is_enabled_for_context(&ctx));
    }

    // -- CreateDataTypeAction tests --

    #[test]
    fn test_create_enum_action() {
        let action = CreateDataTypeAction::new(CreateTypeKind::Enum);
        assert_eq!(action.name(), "New Enum...");
        assert_eq!(action.type_kind(), CreateTypeKind::Enum);
    }

    #[test]
    fn test_create_action_enabled() {
        let action = CreateDataTypeAction::new(CreateTypeKind::Structure);
        let mut ctx = DataTypesActionContext::single_selection(
            TreeNodePath::category("Types", "/Types"),
        );
        ctx.is_data_type_tree = true;
        ctx.is_modifiable = true;
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_create_action_disabled_not_modifiable() {
        let action = CreateDataTypeAction::new(CreateTypeKind::Structure);
        let mut ctx = DataTypesActionContext::single_selection(
            TreeNodePath::category("Types", "/Types"),
        );
        ctx.is_data_type_tree = true;
        ctx.is_modifiable = false;
        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_create_category_action() {
        let action = CreateCategoryAction::new();
        assert_eq!(action.name(), "New Folder...");
    }

    // -- FindDataTypeAction tests --

    #[test]
    fn test_find_by_name() {
        let action = FindDataTypeAction::new(FindMode::ByName);
        assert_eq!(action.name(), "Find by Name...");
        assert_eq!(action.mode(), FindMode::ByName);
    }

    #[test]
    fn test_find_by_size() {
        let action = FindDataTypeAction::new(FindMode::BySize);
        assert_eq!(action.name(), "Find by Size...");
    }

    #[test]
    fn test_find_references() {
        let action = FindDataTypeAction::new(FindMode::ReferencesToType);
        assert_eq!(action.name(), "Find References to Data Type");
    }

    // -- Merge/Replace tests --

    #[test]
    fn test_merge_action() {
        let action = MergeDataTypeAction::new();
        assert_eq!(action.name(), "Merge");
        assert_eq!(
            action.conflict_resolution(),
            ConflictResolution::UseSource
        );
    }

    #[test]
    fn test_replace_action() {
        let action = ReplaceDataTypeAction::new();
        assert_eq!(action.name(), "Replace...");
    }

    // -- Favorite tests --

    #[test]
    fn test_favorite_action() {
        let mut action = SetFavoriteDataTypeAction::new();
        let path = DataTypePath::new(CategoryPath::ROOT, "int");
        assert!(!action.is_favorite(&path));

        action.add_favorite(path.clone());
        assert!(action.is_favorite(&path));
        assert_eq!(action.favorites().len(), 1);

        action.toggle_favorite(path.clone());
        assert!(!action.is_favorite(&path));
        assert_eq!(action.favorites().len(), 0);
    }

    // -- Archive management tests --

    #[test]
    fn test_archive_action_names() {
        let open = ArchiveManagementAction::new(ArchiveActionKind::Open);
        assert_eq!(open.name(), "Open Archive...");

        let close = ArchiveManagementAction::new(ArchiveActionKind::Close);
        assert_eq!(close.name(), "Close Archive");

        let save = ArchiveManagementAction::new(ArchiveActionKind::Save);
        assert_eq!(save.name(), "Save Archive");

        let lock = ArchiveManagementAction::new(ArchiveActionKind::Lock);
        assert_eq!(lock.name(), "Lock Archive");
    }

    // -- Undo/Redo tests --

    #[test]
    fn test_undo_redo_action() {
        let undo = UndoRedoArchiveAction::undo();
        assert_eq!(undo.name(), "Undo");
        assert!(undo.is_undo());

        let redo = UndoRedoArchiveAction::redo();
        assert_eq!(redo.name(), "Redo");
        assert!(!redo.is_undo());
    }

    // -- Export tests --

    #[test]
    fn test_export_to_header_action() {
        let action = ExportToHeaderAction::new();
        assert_eq!(action.name(), "Export to C Header...");
    }

    // -- DisplayTypeAsGraph tests --

    #[test]
    fn test_display_type_as_graph_action() {
        let action = DisplayTypeAsGraphAction::new();
        assert_eq!(action.name(), "Show Type Graph");

        let ctx = DataTypesActionContext::single_selection(
            TreeNodePath::data_type("int", "/int"),
        );
        assert!(action.is_enabled_for_context(&ctx));

        let ctx_cat = DataTypesActionContext::single_selection(
            TreeNodePath::category("Types", "/Types"),
        );
        assert!(!action.is_enabled_for_context(&ctx_cat));
    }

    // -- ConflictResolution tests --

    #[test]
    fn test_conflict_resolution_display() {
        assert_eq!(ConflictResolution::UseSource.to_string(), "Use Source");
        assert_eq!(
            ConflictResolution::RenameSource.to_string(),
            "Rename Source"
        );
    }

    // -- CreateTypeKind tests --

    #[test]
    fn test_create_type_kind_display() {
        assert_eq!(CreateTypeKind::Enum.to_string(), "Enum");
        assert_eq!(CreateTypeKind::Structure.to_string(), "Structure");
        assert_eq!(CreateTypeKind::FunctionDefinition.to_string(), "FunctionDefinition");
    }
}
