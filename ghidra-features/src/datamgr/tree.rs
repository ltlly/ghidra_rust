//! Data type tree node hierarchy.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.datamgr.tree` package.
//!
//! The tree models the hierarchical structure of data types across all
//! open archives.  The root is an [`ArchiveRootNode`]; its children are
//! [`ArchiveNode`]s (one per open archive), which contain
//! [`CategoryNode`]s and [`DataTypeNode`]s.

use ghidra_core::data::{
    CategoryPath, DataTypePath, UniversalID,
};
use std::fmt;

// ---------------------------------------------------------------------------
// TreeNodeKind
// ---------------------------------------------------------------------------

/// Discriminator for the different tree node types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TreeNodeKind {
    /// The root of the entire data type tree.
    ArchiveRoot,
    /// A node representing a single open archive.
    Archive,
    /// A category (folder) node within an archive.
    Category,
    /// A leaf node representing a single data type.
    DataType,
}

impl fmt::Display for TreeNodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArchiveRoot => write!(f, "ArchiveRoot"),
            Self::Archive => write!(f, "Archive"),
            Self::Category => write!(f, "Category"),
            Self::DataType => write!(f, "DataType"),
        }
    }
}

// ---------------------------------------------------------------------------
// DataTypeTreeNode trait
// ---------------------------------------------------------------------------

/// Trait for all nodes in the data type tree.
///
/// Each node has a name, a kind, optional children, and supports
/// cut/paste/edit/rename/delete semantics governed by the owning
/// archive's modifiability.
pub trait DataTypeTreeNode: fmt::Debug + Send + Sync {
    /// The kind of this node.
    fn kind(&self) -> TreeNodeKind;

    /// The display name of this node.
    fn name(&self) -> &str;

    /// The display text shown in the tree view.
    ///
    /// May include source archive annotations.
    fn display_text(&self) -> String {
        self.name().to_string()
    }

    /// Tooltip text for this node.
    fn tooltip(&self) -> Option<String> {
        None
    }

    /// Returns `true` if this node has no children (leaf node).
    fn is_leaf(&self) -> bool {
        true
    }

    /// Returns the number of direct children.
    fn child_count(&self) -> usize {
        0
    }

    /// Returns the child at the given index.
    fn child(&self, index: usize) -> Option<&dyn DataTypeTreeNode> {
        let _ = index;
        None
    }

    /// Returns all children.
    fn children(&self) -> Vec<&dyn DataTypeTreeNode> {
        Vec::new()
    }

    /// Returns `true` if this node is modifiable.
    fn is_modifiable(&self) -> bool {
        false
    }

    /// Returns `true` if this node can be deleted.
    fn can_delete(&self) -> bool {
        false
    }

    /// Returns `true` if this node can be renamed.
    fn can_rename(&self) -> bool {
        false
    }

    /// Returns `true` if this node can be cut.
    fn can_cut(&self) -> bool {
        false
    }

    /// Returns `true` if this node can be edited (has a custom editor).
    fn has_custom_editor(&self) -> bool {
        false
    }

    /// Returns the archive node that owns this node.
    fn archive_node(&self) -> Option<&dyn DataTypeTreeNode> {
        None
    }
}

// ---------------------------------------------------------------------------
// ArchiveRootNode
// ---------------------------------------------------------------------------

/// The root of the data type tree.
///
/// Contains one [`ArchiveNode`] per open archive.  Tracks a
/// modification counter that is incremented whenever any archive,
/// category, or data type changes.
#[derive(Debug)]
pub struct ArchiveRootNode {
    /// Child archive nodes, in display order.
    children: Vec<ArchiveNode>,
    /// Modification counter.
    mod_count: u64,
}

impl ArchiveRootNode {
    /// Create a new empty root node.
    pub fn new() -> Self {
        Self {
            children: Vec::new(),
            mod_count: 0,
        }
    }

    /// Add an archive node as a child.
    pub fn add_archive(&mut self, node: ArchiveNode) {
        self.children.push(node);
        self.mod_count += 1;
    }

    /// Remove the archive node at the given index.
    pub fn remove_archive(&mut self, index: usize) -> Option<ArchiveNode> {
        if index < self.children.len() {
            self.mod_count += 1;
            Some(self.children.remove(index))
        } else {
            None
        }
    }

    /// Find an archive node by its universal ID.
    pub fn find_archive(&self, id: UniversalID) -> Option<&ArchiveNode> {
        self.children.iter().find(|a| a.universal_id() == Some(id))
    }

    /// Find an archive node by its universal ID (mutable).
    pub fn find_archive_mut(&mut self, id: UniversalID) -> Option<&mut ArchiveNode> {
        self.children.iter_mut().find(|a| a.universal_id() == Some(id))
    }

    /// Returns the number of archive children.
    pub fn archive_count(&self) -> usize {
        self.children.len()
    }

    /// Returns a slice of all archive children.
    pub fn archives(&self) -> &[ArchiveNode] {
        &self.children
    }

    /// Returns the current modification count.
    pub fn modification_count(&self) -> u64 {
        self.mod_count
    }

    /// Increment the modification counter.
    pub fn increment_mod_count(&mut self) {
        self.mod_count += 1;
    }
}

impl Default for ArchiveRootNode {
    fn default() -> Self {
        Self::new()
    }
}

impl DataTypeTreeNode for ArchiveRootNode {
    fn kind(&self) -> TreeNodeKind { TreeNodeKind::ArchiveRoot }
    fn name(&self) -> &str { "Data Type Manager" }
    fn display_text(&self) -> String { "Data Type Manager".into() }
    fn is_leaf(&self) -> bool { false }
    fn child_count(&self) -> usize { self.children.len() }
    fn child(&self, index: usize) -> Option<&dyn DataTypeTreeNode> {
        self.children.get(index).map(|c| c as &dyn DataTypeTreeNode)
    }
    fn children(&self) -> Vec<&dyn DataTypeTreeNode> {
        self.children.iter().map(|c| c as &dyn DataTypeTreeNode).collect()
    }
}

impl fmt::Display for ArchiveRootNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArchiveRootNode ({} archives)", self.children.len())
    }
}

// ---------------------------------------------------------------------------
// ArchiveNode
// ---------------------------------------------------------------------------

/// A tree node representing a single open archive.
///
/// Contains [`CategoryNode`] children for the archive's root category,
/// and [`DataTypeNode`] children for types in the root category.
#[derive(Debug)]
pub struct ArchiveNode {
    /// Archive name.
    name: String,
    /// Archive kind.
    kind: super::archive::ArchiveKind,
    /// Whether this archive is modifiable.
    modifiable: bool,
    /// Universal ID of the archive.
    universal_id: Option<UniversalID>,
    /// Category children.
    categories: Vec<CategoryNode>,
    /// Data type children (types directly in root category).
    data_types: Vec<DataTypeNode>,
}

impl ArchiveNode {
    /// Create a new archive node.
    pub fn new(
        name: impl Into<String>,
        kind: super::archive::ArchiveKind,
        modifiable: bool,
        universal_id: Option<UniversalID>,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            modifiable,
            universal_id,
            categories: Vec::new(),
            data_types: Vec::new(),
        }
    }

    /// The archive kind.
    pub fn archive_kind(&self) -> super::archive::ArchiveKind {
        self.kind
    }

    /// The universal ID of this archive.
    pub fn universal_id(&self) -> Option<UniversalID> {
        self.universal_id
    }

    /// Add a category child.
    pub fn add_category(&mut self, node: CategoryNode) {
        self.categories.push(node);
    }

    /// Add a data type child.
    pub fn add_data_type(&mut self, node: DataTypeNode) {
        self.data_types.push(node);
    }

    /// Returns category children.
    pub fn categories(&self) -> &[CategoryNode] {
        &self.categories
    }

    /// Returns data type children.
    pub fn data_types(&self) -> &[DataTypeNode] {
        &self.data_types
    }

    /// Returns the total number of children (categories + data types).
    pub fn total_children(&self) -> usize {
        self.categories.len() + self.data_types.len()
    }
}

impl DataTypeTreeNode for ArchiveNode {
    fn kind(&self) -> TreeNodeKind { TreeNodeKind::Archive }
    fn name(&self) -> &str { &self.name }
    fn is_leaf(&self) -> bool { false }
    fn is_modifiable(&self) -> bool { self.modifiable }
    fn can_delete(&self) -> bool { false } // archives are closed, not deleted
    fn child_count(&self) -> usize { self.total_children() }
}

impl fmt::Display for ArchiveNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ArchiveNode '{}' [{}] ({} children)",
            self.name,
            self.kind,
            self.total_children()
        )
    }
}

// ---------------------------------------------------------------------------
// CategoryNode
// ---------------------------------------------------------------------------

/// A tree node representing a data type category (folder).
///
/// Contains sub-categories and data types.
#[derive(Debug)]
pub struct CategoryNode {
    /// Category name (leaf segment of the path).
    name: String,
    /// Full category path.
    category_path: CategoryPath,
    /// Whether this category's archive is modifiable.
    modifiable: bool,
    /// Sub-category children.
    categories: Vec<CategoryNode>,
    /// Data type children.
    data_types: Vec<DataTypeNode>,
}

impl CategoryNode {
    /// Create a new category node.
    pub fn new(
        name: impl Into<String>,
        category_path: CategoryPath,
        modifiable: bool,
    ) -> Self {
        Self {
            name: name.into(),
            category_path,
            modifiable,
            categories: Vec::new(),
            data_types: Vec::new(),
        }
    }

    /// The full category path.
    pub fn category_path(&self) -> &CategoryPath {
        &self.category_path
    }

    /// Add a sub-category.
    pub fn add_category(&mut self, node: CategoryNode) {
        self.categories.push(node);
    }

    /// Add a data type.
    pub fn add_data_type(&mut self, node: DataTypeNode) {
        self.data_types.push(node);
    }

    /// Returns sub-categories.
    pub fn categories(&self) -> &[CategoryNode] {
        &self.categories
    }

    /// Returns data types.
    pub fn data_types(&self) -> &[DataTypeNode] {
        &self.data_types
    }

    /// Returns the total number of children.
    pub fn total_children(&self) -> usize {
        self.categories.len() + self.data_types.len()
    }

    /// Find a sub-category by name.
    pub fn find_category(&self, name: &str) -> Option<&CategoryNode> {
        self.categories.iter().find(|c| c.name() == name)
    }

    /// Find a data type by name.
    pub fn find_data_type(&self, name: &str) -> Option<&DataTypeNode> {
        self.data_types.iter().find(|d| d.name() == name)
    }
}

impl DataTypeTreeNode for CategoryNode {
    fn kind(&self) -> TreeNodeKind { TreeNodeKind::Category }
    fn name(&self) -> &str { &self.name }
    fn is_leaf(&self) -> bool { false }
    fn is_modifiable(&self) -> bool { self.modifiable }
    fn can_delete(&self) -> bool { self.modifiable }
    fn can_rename(&self) -> bool { self.modifiable }
    fn child_count(&self) -> usize { self.total_children() }
}

impl fmt::Display for CategoryNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CategoryNode '{}' [{}] ({} children)",
            self.name,
            self.category_path,
            self.total_children()
        )
    }
}

// ---------------------------------------------------------------------------
// DataTypeNode
// ---------------------------------------------------------------------------

/// A leaf tree node representing a single data type.
///
/// Ported from Ghidra's `DataTypeNode` Java class.
#[derive(Debug)]
pub struct DataTypeNode {
    /// The data type name.
    name: String,
    /// The data type path.
    dt_path: DataTypePath,
    /// The category path.
    category_path: CategoryPath,
    /// Whether this node's archive is modifiable.
    modifiable: bool,
    /// Whether this type is marked as a favorite.
    is_favorite: bool,
    /// The source archive name (for display text annotation).
    source_archive_name: Option<String>,
    /// Whether this type is cut (for clipboard display).
    is_cut: bool,
    /// Whether this type is highlighted (e.g., search result).
    use_highlight: bool,
    /// The data type's kind (for icon selection in the GUI).
    data_type_kind: DataTypeNodeKind,
}

/// The kind of data type for icon/behavior selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataTypeNodeKind {
    /// A built-in primitive type.
    BuiltIn,
    /// A user-defined type (struct, union, enum, typedef, etc.).
    UserDefined,
    /// A pointer type.
    Pointer,
    /// An array type.
    Array,
    /// A function definition.
    FunctionDef,
    /// A dynamic type.
    Dynamic,
}

impl fmt::Display for DataTypeNodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuiltIn => write!(f, "BuiltIn"),
            Self::UserDefined => write!(f, "UserDefined"),
            Self::Pointer => write!(f, "Pointer"),
            Self::Array => write!(f, "Array"),
            Self::FunctionDef => write!(f, "FunctionDef"),
            Self::Dynamic => write!(f, "Dynamic"),
        }
    }
}

impl DataTypeNode {
    /// Create a new data type node.
    pub fn new(
        name: impl Into<String>,
        dt_path: DataTypePath,
        category_path: CategoryPath,
        modifiable: bool,
        data_type_kind: DataTypeNodeKind,
    ) -> Self {
        let name = name.into();
        Self {
            name,
            dt_path,
            category_path,
            modifiable,
            is_favorite: false,
            source_archive_name: None,
            is_cut: false,
            use_highlight: false,
            data_type_kind,
        }
    }

    /// The data type path.
    pub fn dt_path(&self) -> &DataTypePath {
        &self.dt_path
    }

    /// The category path.
    pub fn category_path(&self) -> &CategoryPath {
        &self.category_path
    }

    /// Returns `true` if this type is a favorite.
    pub fn is_favorite(&self) -> bool {
        self.is_favorite
    }

    /// Set or clear the favorite status.
    pub fn set_favorite(&mut self, favorite: bool) {
        self.is_favorite = favorite;
    }

    /// Set the source archive name (shown in the display text).
    pub fn set_source_archive_name(&mut self, name: Option<String>) {
        self.source_archive_name = name;
    }

    /// The source archive name, if any.
    pub fn source_archive_name(&self) -> Option<&str> {
        self.source_archive_name.as_deref()
    }

    /// Returns `true` if this node is cut (clipboard).
    pub fn is_cut(&self) -> bool {
        self.is_cut
    }

    /// Set the cut state.
    pub fn set_cut(&mut self, cut: bool) {
        self.is_cut = cut;
    }

    /// Returns `true` if this node is highlighted.
    pub fn is_highlighted(&self) -> bool {
        self.use_highlight
    }

    /// Set or clear highlighting.
    pub fn set_highlight(&mut self, highlight: bool) {
        self.use_highlight = highlight;
    }

    /// The data type kind (for icon selection).
    pub fn data_type_kind(&self) -> DataTypeNodeKind {
        self.data_type_kind
    }

    /// Returns `true` if the data type can be renamed.
    ///
    /// Built-in types, missing built-ins, arrays, and pointers cannot
    /// be renamed through the tree.
    pub fn can_rename_type(&self) -> bool {
        !matches!(
            self.data_type_kind,
            DataTypeNodeKind::BuiltIn | DataTypeNodeKind::Array | DataTypeNodeKind::Pointer
        )
    }

    /// Returns `true` if the data type has a custom editor
    /// (composite, enum, or function definition).
    pub fn has_custom_editor_for_type(&self) -> bool {
        matches!(
            self.data_type_kind,
            DataTypeNodeKind::BuiltIn | DataTypeNodeKind::UserDefined | DataTypeNodeKind::FunctionDef
        )
    }

    /// Notify this node that its data type status has changed
    /// (e.g., becomes a favorite).
    pub fn data_type_status_changed(&mut self) {
        // In a full implementation this would fire node-changed events.
    }

    /// Notify this node that its data type has been modified.
    pub fn data_type_changed(&mut self) {
        // In a full implementation this would clear tooltip cache and repaint.
    }
}

impl DataTypeTreeNode for DataTypeNode {
    fn kind(&self) -> TreeNodeKind { TreeNodeKind::DataType }
    fn name(&self) -> &str { &self.name }

    fn display_text(&self) -> String {
        if let Some(source) = &self.source_archive_name {
            format!("{}  ({})", self.name, source)
        } else {
            self.name.clone()
        }
    }

    fn is_leaf(&self) -> bool { true }
    fn is_modifiable(&self) -> bool { self.modifiable }
    fn can_delete(&self) -> bool { true }
    fn can_rename(&self) -> bool { self.can_rename_type() }
    fn can_cut(&self) -> bool { self.modifiable }
    fn has_custom_editor(&self) -> bool { self.has_custom_editor_for_type() }
}

impl fmt::Display for DataTypeNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DataTypeNode '{}'", self.display_text())
    }
}

// ---------------------------------------------------------------------------
// DtTypeFilter -- per-type filter toggle
// ---------------------------------------------------------------------------

/// A class that holds enabled state for a type and related typedefs.
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.DtTypeFilter`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DtTypeFilter {
    /// The category/type name this filter controls (e.g. "Arrays", "Enums").
    name: String,
    /// Whether the type itself is active (visible).
    is_type_active: bool,
    /// Whether typedefs of this type are active.
    is_type_def_active: bool,
}

impl DtTypeFilter {
    /// Create a new filter with both type and typedef active.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            is_type_active: true,
            is_type_def_active: true,
        }
    }

    /// Create a new filter with specified active states.
    pub fn with_state(name: impl Into<String>, type_active: bool, typedef_active: bool) -> Self {
        Self {
            name: name.into(),
            is_type_active: type_active,
            is_type_def_active: typedef_active,
        }
    }

    /// The filter name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the type itself is active.
    pub fn is_type_active(&self) -> bool {
        self.is_type_active
    }

    /// Whether typedefs of this type are active.
    pub fn is_type_def_active(&self) -> bool {
        self.is_type_def_active
    }

    /// Set whether the type itself is active.
    pub fn set_type_active(&mut self, active: bool) {
        self.is_type_active = active;
    }

    /// Set whether typedefs of this type are active.
    pub fn set_type_def_active(&mut self, active: bool) {
        self.is_type_def_active = active;
    }

    /// Create a copy of this filter.
    pub fn copy(&self) -> Self {
        Self {
            name: self.name.clone(),
            is_type_active: self.is_type_active,
            is_type_def_active: self.is_type_def_active,
        }
    }

    /// Check whether a data type passes this filter.
    ///
    /// `is_typedef` should be `true` if the data type is a TypeDef.
    pub fn passes(&self, is_typedef: bool) -> bool {
        if is_typedef {
            self.is_type_def_active
        } else {
            self.is_type_active
        }
    }
}

impl fmt::Display for DtTypeFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DtTypeFilter '{}' type={} typedef={}",
            self.name, self.is_type_active, self.is_type_def_active
        )
    }
}

// ---------------------------------------------------------------------------
// DataTypeCategory -- enum for matching data types to filter categories
// ---------------------------------------------------------------------------

/// Broad category of a data type for filter matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataTypeCategory {
    /// Array type.
    Array,
    /// Enum type.
    Enum,
    /// Function definition.
    Function,
    /// Pointer type.
    Pointer,
    /// Structure type.
    Structure,
    /// Union type.
    Union,
    /// Other (built-in, dynamic, etc.).
    Other,
}

// ---------------------------------------------------------------------------
// DtFilterState -- collection of per-type filters
// ---------------------------------------------------------------------------

/// A simple object to store various filter settings for the data type provider.
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.DtFilterState`.
///
/// Contains one [`DtTypeFilter`] per broad data-type category (arrays,
/// enums, functions, structures, pointers, unions, and other).  Arrays
/// and pointers are **off** by default, since users typically are not
/// working with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtFilterState {
    arrays_filter: DtTypeFilter,
    enums_filter: DtTypeFilter,
    functions_filter: DtTypeFilter,
    structures_filter: DtTypeFilter,
    pointers_filter: DtTypeFilter,
    unions_filter: DtTypeFilter,
    other_filter: DtTypeFilter,
}

impl DtFilterState {
    /// Create a new filter state with default settings.
    ///
    /// Arrays and pointers are off by default.
    pub fn new() -> Self {
        Self {
            arrays_filter: DtTypeFilter::with_state("Arrays", false, true),
            enums_filter: DtTypeFilter::new("Enums"),
            functions_filter: DtTypeFilter::new("Functions"),
            structures_filter: DtTypeFilter::new("Structures"),
            pointers_filter: DtTypeFilter::with_state("Pointers", false, true),
            unions_filter: DtTypeFilter::new("Unions"),
            other_filter: DtTypeFilter::new("Other"),
        }
    }

    /// Create a copy of this filter state.
    pub fn copy(&self) -> Self {
        Self {
            arrays_filter: self.arrays_filter.copy(),
            enums_filter: self.enums_filter.copy(),
            functions_filter: self.functions_filter.copy(),
            structures_filter: self.structures_filter.copy(),
            pointers_filter: self.pointers_filter.copy(),
            unions_filter: self.unions_filter.copy(),
            other_filter: self.other_filter.copy(),
        }
    }

    /// Get the filter for a specific category.
    pub fn filter_for(&self, category: DataTypeCategory) -> &DtTypeFilter {
        match category {
            DataTypeCategory::Array => &self.arrays_filter,
            DataTypeCategory::Enum => &self.enums_filter,
            DataTypeCategory::Function => &self.functions_filter,
            DataTypeCategory::Pointer => &self.pointers_filter,
            DataTypeCategory::Structure => &self.structures_filter,
            DataTypeCategory::Union => &self.unions_filter,
            DataTypeCategory::Other => &self.other_filter,
        }
    }

    /// Get a mutable filter for a specific category.
    pub fn filter_for_mut(&mut self, category: DataTypeCategory) -> &mut DtTypeFilter {
        match category {
            DataTypeCategory::Array => &mut self.arrays_filter,
            DataTypeCategory::Enum => &mut self.enums_filter,
            DataTypeCategory::Function => &mut self.functions_filter,
            DataTypeCategory::Pointer => &mut self.pointers_filter,
            DataTypeCategory::Structure => &mut self.structures_filter,
            DataTypeCategory::Union => &mut self.unions_filter,
            DataTypeCategory::Other => &mut self.other_filter,
        }
    }

    /// Check whether a data type passes the filter for its category.
    ///
    /// A bare pointer with no target passes unconditionally (mirrors
    /// the Java `DtFilterState.passesDataType` special-case for the
    /// built-in "pointer" type).
    pub fn passes_data_type(&self, category: DataTypeCategory, is_typedef: bool, is_bare_pointer: bool) -> bool {
        if is_bare_pointer {
            return true;
        }
        self.filter_for(category).passes(is_typedef)
    }

    /// Get the arrays filter.
    pub fn arrays_filter(&self) -> &DtTypeFilter { &self.arrays_filter }
    /// Get the enums filter.
    pub fn enums_filter(&self) -> &DtTypeFilter { &self.enums_filter }
    /// Get the functions filter.
    pub fn functions_filter(&self) -> &DtTypeFilter { &self.functions_filter }
    /// Get the structures filter.
    pub fn structures_filter(&self) -> &DtTypeFilter { &self.structures_filter }
    /// Get the pointers filter.
    pub fn pointers_filter(&self) -> &DtTypeFilter { &self.pointers_filter }
    /// Get the unions filter.
    pub fn unions_filter(&self) -> &DtTypeFilter { &self.unions_filter }
    /// Get the other filter.
    pub fn other_filter(&self) -> &DtTypeFilter { &self.other_filter }
}

impl Default for DtFilterState {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DtFilterState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DtFilterState [Arrays={} Enums={} Functions={} Structs={} Ptrs={} Unions={} Other={}]",
            self.arrays_filter.is_type_active(),
            self.enums_filter.is_type_active(),
            self.functions_filter.is_type_active(),
            self.structures_filter.is_type_active(),
            self.pointers_filter.is_type_active(),
            self.unions_filter.is_type_active(),
            self.other_filter.is_type_active(),
        )
    }
}

// ---------------------------------------------------------------------------
// DomainFileArchiveNode -- abstract base for file-backed archive nodes
// ---------------------------------------------------------------------------

/// State flags for a domain-file-backed archive node.
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.DomainFileArchiveNode`.
#[derive(Debug, Clone, Default)]
pub struct DomainFileState {
    /// Whether the file has unsaved changes.
    pub is_changed: bool,
    /// Whether the file is read-only.
    pub is_read_only: bool,
    /// Whether the file has been hijacked (modified outside of checkout).
    pub is_hijacked: bool,
    /// Whether the file is checked out.
    pub is_checked_out: bool,
    /// Whether the file is checked out exclusively.
    pub is_checked_out_exclusive: bool,
    /// Whether the file is under version control.
    pub is_versioned: bool,
    /// The current version number.
    pub version: i32,
    /// The latest available version number.
    pub latest_version: i32,
}

impl DomainFileState {
    /// Returns `true` if the archive is not at the latest version.
    pub fn is_not_latest(&self) -> bool {
        self.is_versioned && self.version < self.latest_version
    }

    /// Build a display string summarizing the domain file state.
    pub fn info_string(&self) -> String {
        let mut parts = Vec::new();
        if self.is_read_only { parts.push("Read-Only".to_string()); }
        if self.is_checked_out { parts.push("Checked Out".to_string()); }
        if self.is_hijacked { parts.push("Hijacked".to_string()); }
        if self.is_versioned {
            parts.push(format!("v{}/{}", self.version, self.latest_version));
        }
        if parts.is_empty() {
            "OK".to_string()
        } else {
            parts.join(", ")
        }
    }
}

// ---------------------------------------------------------------------------
// DataTypeArchiveGTree -- the top-level tree widget model
// ---------------------------------------------------------------------------

/// The top-level tree widget that displays all open data type archives.
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree`.
///
/// Manages the [`ArchiveRootNode`], handles filter state, and provides
/// search/find operations on the tree.
#[derive(Debug)]
pub struct DataTypeArchiveGTree {
    /// The root node.
    root: ArchiveRootNode,
    /// The active filter state.
    filter_state: DtFilterState,
    /// Whether the tree is loaded (children populated).
    loaded: bool,
}

impl DataTypeArchiveGTree {
    /// Create a new empty tree.
    pub fn new() -> Self {
        Self {
            root: ArchiveRootNode::new(),
            filter_state: DtFilterState::new(),
            loaded: false,
        }
    }

    /// Create a tree with a specific filter state.
    pub fn with_filter(filter_state: DtFilterState) -> Self {
        Self {
            root: ArchiveRootNode::new(),
            filter_state,
            loaded: false,
        }
    }

    /// Get a reference to the root node.
    pub fn root(&self) -> &ArchiveRootNode {
        &self.root
    }

    /// Get a mutable reference to the root node.
    pub fn root_mut(&mut self) -> &mut ArchiveRootNode {
        &mut self.root
    }

    /// Get the current filter state.
    pub fn filter_state(&self) -> &DtFilterState {
        &self.filter_state
    }

    /// Get a mutable reference to the filter state.
    pub fn filter_state_mut(&mut self) -> &mut DtFilterState {
        &mut self.filter_state
    }

    /// Set the filter state.
    pub fn set_filter_state(&mut self, state: DtFilterState) {
        self.filter_state = state;
    }

    /// Returns `true` if the tree has been loaded.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Mark the tree as loaded.
    pub fn set_loaded(&mut self, loaded: bool) {
        self.loaded = loaded;
    }

    /// Find a category node by path across all archives.
    pub fn find_category_node(&self, category_path: &str) -> Option<&CategoryNode> {
        for archive in self.root.archives() {
            if let Some(node) = find_category_recursive(archive.categories(), category_path) {
                return Some(node);
            }
        }
        None
    }

    /// Find an archive node by name.
    pub fn find_archive_by_name(&self, name: &str) -> Option<&ArchiveNode> {
        self.root.archives().iter().find(|a| a.name() == name)
    }

    /// Refresh the tree after an archive has been opened or closed.
    pub fn refresh(&mut self) {
        self.root.increment_mod_count();
    }
}

impl Default for DataTypeArchiveGTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Recursively search for a category node by path segments.
fn find_category_recursive<'a>(
    categories: &'a [CategoryNode],
    path: &str,
) -> Option<&'a CategoryNode> {
    // Strip leading '/' if present
    let path = path.strip_prefix('/').unwrap_or(path);
    let mut segments = path.splitn(2, '/');
    let first = segments.next()?;
    let rest = segments.next();

    for cat in categories {
        if cat.name() == first {
            if let Some(rest_path) = rest {
                return find_category_recursive(cat.categories(), rest_path);
            } else {
                return Some(cat);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::data::CategoryPath;

    fn make_dt_path(name: &str) -> DataTypePath {
        DataTypePath::new(CategoryPath::ROOT, name)
    }

    #[test]
    fn test_tree_node_kind_display() {
        assert_eq!(format!("{}", TreeNodeKind::ArchiveRoot), "ArchiveRoot");
        assert_eq!(format!("{}", TreeNodeKind::Archive), "Archive");
        assert_eq!(format!("{}", TreeNodeKind::Category), "Category");
        assert_eq!(format!("{}", TreeNodeKind::DataType), "DataType");
    }

    #[test]
    fn test_archive_root_node() {
        let root = ArchiveRootNode::new();
        assert_eq!(root.kind(), TreeNodeKind::ArchiveRoot);
        assert_eq!(root.name(), "Data Type Manager");
        assert!(!root.is_leaf());
        assert_eq!(root.archive_count(), 0);
        assert_eq!(root.modification_count(), 0);
    }

    #[test]
    fn test_archive_root_add_remove() {
        let mut root = ArchiveRootNode::new();
        let archive = ArchiveNode::new("BuiltIn", super::super::archive::ArchiveKind::BuiltIn, false, None);
        root.add_archive(archive);
        assert_eq!(root.archive_count(), 1);
        assert_eq!(root.modification_count(), 1);
        root.remove_archive(0);
        assert_eq!(root.archive_count(), 0);
    }

    #[test]
    fn test_archive_root_find_archive() {
        let mut root = ArchiveRootNode::new();
        let archive = ArchiveNode::new(
            "MyLib",
            super::super::archive::ArchiveKind::File,
            true,
            Some(UniversalID::new(42)),
        );
        root.add_archive(archive);
        assert!(root.find_archive(UniversalID::new(42)).is_some());
        assert!(root.find_archive(UniversalID::new(99)).is_none());
    }

    #[test]
    fn test_archive_root_display() {
        let root = ArchiveRootNode::new();
        let s = format!("{}", root);
        assert!(s.contains("ArchiveRootNode"));
    }

    #[test]
    fn test_archive_node() {
        let node = ArchiveNode::new(
            "test.gdt",
            super::super::archive::ArchiveKind::File,
            true,
            Some(UniversalID::new(10)),
        );
        assert_eq!(node.kind(), TreeNodeKind::Archive);
        assert_eq!(node.name(), "test.gdt");
        assert!(!node.is_leaf());
        assert!(node.is_modifiable());
        assert_eq!(node.universal_id(), Some(UniversalID::new(10)));
        assert_eq!(node.total_children(), 0);
    }

    #[test]
    fn test_archive_node_children() {
        let mut node = ArchiveNode::new(
            "test.gdt",
            super::super::archive::ArchiveKind::File,
            true,
            None,
        );
        node.add_category(CategoryNode::new("my_cat", CategoryPath::new("my_cat"), true));
        node.add_data_type(DataTypeNode::new(
            "int",
            make_dt_path("int"),
            CategoryPath::ROOT,
            false,
            DataTypeNodeKind::BuiltIn,
        ));
        assert_eq!(node.total_children(), 2);
        assert_eq!(node.categories().len(), 1);
        assert_eq!(node.data_types().len(), 1);
    }

    #[test]
    fn test_archive_node_display() {
        let node = ArchiveNode::new(
            "my_lib",
            super::super::archive::ArchiveKind::File,
            false,
            None,
        );
        let s = format!("{}", node);
        assert!(s.contains("my_lib"));
        assert!(s.contains("File"));
    }

    #[test]
    fn test_category_node() {
        let cat = CategoryNode::new("my_cat", CategoryPath::new("my_cat"), true);
        assert_eq!(cat.kind(), TreeNodeKind::Category);
        assert_eq!(cat.name(), "my_cat");
        assert!(!cat.is_leaf());
        assert!(cat.is_modifiable());
        assert!(cat.can_delete());
        assert!(cat.can_rename());
    }

    #[test]
    fn test_category_node_children() {
        let mut cat = CategoryNode::new("root_cat", CategoryPath::new("root_cat"), true);
        cat.add_category(CategoryNode::new("sub", CategoryPath::from_path_string("/root_cat/sub"), true));
        cat.add_data_type(DataTypeNode::new(
            "foo",
            make_dt_path("foo"),
            CategoryPath::new("root_cat"),
            true,
            DataTypeNodeKind::UserDefined,
        ));
        assert_eq!(cat.total_children(), 2);
        assert!(cat.find_category("sub").is_some());
        assert!(cat.find_category("nope").is_none());
        assert!(cat.find_data_type("foo").is_some());
        assert!(cat.find_data_type("bar").is_none());
    }

    #[test]
    fn test_category_node_readonly() {
        let cat = CategoryNode::new("ro", CategoryPath::new("ro"), false);
        assert!(!cat.is_modifiable());
        assert!(!cat.can_delete());
        assert!(!cat.can_rename());
    }

    #[test]
    fn test_category_node_display() {
        let cat = CategoryNode::new("test", CategoryPath::new("test"), true);
        let s = format!("{}", cat);
        assert!(s.contains("CategoryNode"));
        assert!(s.contains("test"));
    }

    #[test]
    fn test_data_type_node() {
        let node = DataTypeNode::new(
            "my_struct",
            make_dt_path("my_struct"),
            CategoryPath::ROOT,
            true,
            DataTypeNodeKind::UserDefined,
        );
        assert_eq!(node.kind(), TreeNodeKind::DataType);
        assert_eq!(node.name(), "my_struct");
        assert!(node.is_leaf());
        assert!(node.is_modifiable());
        assert!(node.can_delete());
        assert!(node.can_rename());
    }

    #[test]
    fn test_data_type_node_favorite() {
        let mut node = DataTypeNode::new(
            "int",
            make_dt_path("int"),
            CategoryPath::ROOT,
            false,
            DataTypeNodeKind::BuiltIn,
        );
        assert!(!node.is_favorite());
        node.set_favorite(true);
        assert!(node.is_favorite());
    }

    #[test]
    fn test_data_type_node_cut_highlight() {
        let mut node = DataTypeNode::new(
            "x",
            make_dt_path("x"),
            CategoryPath::ROOT,
            true,
            DataTypeNodeKind::UserDefined,
        );
        assert!(!node.is_cut());
        node.set_cut(true);
        assert!(node.is_cut());
        assert!(!node.is_highlighted());
        node.set_highlight(true);
        assert!(node.is_highlighted());
    }

    #[test]
    fn test_data_type_node_display_text() {
        let mut node = DataTypeNode::new(
            "my_type",
            make_dt_path("my_type"),
            CategoryPath::ROOT,
            false,
            DataTypeNodeKind::UserDefined,
        );
        assert_eq!(node.display_text(), "my_type");
        node.set_source_archive_name(Some("BuiltInTypes".into()));
        assert_eq!(node.display_text(), "my_type  (BuiltInTypes)");
    }

    #[test]
    fn test_data_type_node_cannot_rename_built_in() {
        let node = DataTypeNode::new(
            "int",
            make_dt_path("int"),
            CategoryPath::ROOT,
            false,
            DataTypeNodeKind::BuiltIn,
        );
        assert!(!node.can_rename());
    }

    #[test]
    fn test_data_type_node_cannot_rename_pointer() {
        let node = DataTypeNode::new(
            "pointer",
            make_dt_path("pointer"),
            CategoryPath::ROOT,
            false,
            DataTypeNodeKind::Pointer,
        );
        assert!(!node.can_rename());
    }

    #[test]
    fn test_data_type_node_cannot_rename_array() {
        let node = DataTypeNode::new(
            "array",
            make_dt_path("array"),
            CategoryPath::ROOT,
            false,
            DataTypeNodeKind::Array,
        );
        assert!(!node.can_rename());
    }

    #[test]
    fn test_data_type_node_has_custom_editor() {
        let user = DataTypeNode::new(
            "s", make_dt_path("s"), CategoryPath::ROOT, false,
            DataTypeNodeKind::UserDefined,
        );
        assert!(user.has_custom_editor_for_type());

        let builtin = DataTypeNode::new(
            "i", make_dt_path("i"), CategoryPath::ROOT, false,
            DataTypeNodeKind::BuiltIn,
        );
        assert!(builtin.has_custom_editor_for_type());

        let ptr = DataTypeNode::new(
            "p", make_dt_path("p"), CategoryPath::ROOT, false,
            DataTypeNodeKind::Pointer,
        );
        assert!(!ptr.has_custom_editor_for_type());
    }

    #[test]
    fn test_data_type_node_display() {
        let node = DataTypeNode::new(
            "foo",
            make_dt_path("foo"),
            CategoryPath::ROOT,
            false,
            DataTypeNodeKind::UserDefined,
        );
        let s = format!("{}", node);
        assert!(s.contains("DataTypeNode"));
        assert!(s.contains("foo"));
    }

    #[test]
    fn test_full_tree_structure() {
        let mut root = ArchiveRootNode::new();

        // Archive 1: BuiltIn
        let mut built_in = ArchiveNode::new(
            "BuiltInTypes",
            super::super::archive::ArchiveKind::BuiltIn,
            false,
            Some(UniversalID::new(1)),
        );
        built_in.add_data_type(DataTypeNode::new(
            "int",
            make_dt_path("int"),
            CategoryPath::ROOT,
            false,
            DataTypeNodeKind::BuiltIn,
        ));
        built_in.add_data_type(DataTypeNode::new(
            "void",
            make_dt_path("void"),
            CategoryPath::ROOT,
            false,
            DataTypeNodeKind::BuiltIn,
        ));
        root.add_archive(built_in);

        // Archive 2: File
        let mut file_archive = ArchiveNode::new(
            "my_types.gdt",
            super::super::archive::ArchiveKind::File,
            true,
            Some(UniversalID::new(42)),
        );
        let mut cat = CategoryNode::new("my_structs", CategoryPath::new("my_structs"), true);
        cat.add_data_type(DataTypeNode::new(
            "foo_t",
            DataTypePath::new(CategoryPath::new("my_structs"), "foo_t"),
            CategoryPath::new("my_structs"),
            true,
            DataTypeNodeKind::UserDefined,
        ));
        file_archive.add_category(cat);
        root.add_archive(file_archive);

        assert_eq!(root.archive_count(), 2);
        assert_eq!(root.child_count(), 2);

        // Verify tree traversal
        let bi = root.child(0).unwrap();
        assert_eq!(bi.name(), "BuiltInTypes");
        assert_eq!(bi.child_count(), 2);

        let fa = root.child(1).unwrap();
        assert_eq!(fa.name(), "my_types.gdt");
    }

    #[test]
    fn test_archive_root_default() {
        let root = ArchiveRootNode::default();
        assert_eq!(root.archive_count(), 0);
    }

    #[test]
    fn test_archive_root_remove_out_of_bounds() {
        let mut root = ArchiveRootNode::new();
        assert!(root.remove_archive(0).is_none());
    }

    #[test]
    fn test_data_type_node_kind_display() {
        assert_eq!(format!("{}", DataTypeNodeKind::BuiltIn), "BuiltIn");
        assert_eq!(format!("{}", DataTypeNodeKind::UserDefined), "UserDefined");
        assert_eq!(format!("{}", DataTypeNodeKind::Pointer), "Pointer");
        assert_eq!(format!("{}", DataTypeNodeKind::Array), "Array");
        assert_eq!(format!("{}", DataTypeNodeKind::FunctionDef), "FunctionDef");
        assert_eq!(format!("{}", DataTypeNodeKind::Dynamic), "Dynamic");
    }

    // -- DtTypeFilter tests --

    #[test]
    fn test_dt_type_filter_new() {
        let f = DtTypeFilter::new("Enums");
        assert_eq!(f.name(), "Enums");
        assert!(f.is_type_active());
        assert!(f.is_type_def_active());
    }

    #[test]
    fn test_dt_type_filter_with_state() {
        let f = DtTypeFilter::with_state("Arrays", false, true);
        assert!(!f.is_type_active());
        assert!(f.is_type_def_active());
    }

    #[test]
    fn test_dt_type_filter_setters() {
        let mut f = DtTypeFilter::new("Test");
        f.set_type_active(false);
        assert!(!f.is_type_active());
        f.set_type_def_active(false);
        assert!(!f.is_type_def_active());
    }

    #[test]
    fn test_dt_type_filter_copy() {
        let f = DtTypeFilter::with_state("Test", false, true);
        let c = f.copy();
        assert_eq!(f, c);
    }

    #[test]
    fn test_dt_type_filter_passes() {
        let f = DtTypeFilter::with_state("Arrays", false, true);
        assert!(!f.passes(false)); // type not active
        assert!(f.passes(true));   // typedef active
    }

    #[test]
    fn test_dt_type_filter_display() {
        let f = DtTypeFilter::new("Test");
        let s = format!("{}", f);
        assert!(s.contains("Test"));
        assert!(s.contains("type=true"));
    }

    // -- DtFilterState tests --

    #[test]
    fn test_dt_filter_state_default_arrays_off() {
        let fs = DtFilterState::new();
        assert!(!fs.arrays_filter().is_type_active());
        assert!(!fs.pointers_filter().is_type_active());
        assert!(fs.enums_filter().is_type_active());
        assert!(fs.structures_filter().is_type_active());
    }

    #[test]
    fn test_dt_filter_state_copy() {
        let fs = DtFilterState::new();
        let copy = fs.copy();
        assert_eq!(fs, copy);
    }

    #[test]
    fn test_dt_filter_state_passes_data_type() {
        let fs = DtFilterState::new();
        // Enums active, not a typedef
        assert!(fs.passes_data_type(DataTypeCategory::Enum, false, false));
        // Arrays not active by default
        assert!(!fs.passes_data_type(DataTypeCategory::Array, false, false));
        // But arrays typedef is active
        assert!(fs.passes_data_type(DataTypeCategory::Array, true, false));
        // Bare pointer always passes
        assert!(fs.passes_data_type(DataTypeCategory::Pointer, false, true));
    }

    #[test]
    fn test_dt_filter_state_filter_for() {
        let fs = DtFilterState::new();
        assert_eq!(fs.filter_for(DataTypeCategory::Enum).name(), "Enums");
        assert_eq!(fs.filter_for(DataTypeCategory::Structure).name(), "Structures");
        assert_eq!(fs.filter_for(DataTypeCategory::Union).name(), "Unions");
    }

    #[test]
    fn test_dt_filter_state_filter_for_mut() {
        let mut fs = DtFilterState::new();
        fs.filter_for_mut(DataTypeCategory::Array).set_type_active(true);
        assert!(fs.arrays_filter().is_type_active());
    }

    #[test]
    fn test_dt_filter_state_display() {
        let fs = DtFilterState::new();
        let s = format!("{}", fs);
        assert!(s.contains("DtFilterState"));
        assert!(s.contains("Arrays=false"));
    }

    // -- DtTypeFilter trait tests --

    #[test]
    fn test_data_type_category_enum() {
        let cat = DataTypeCategory::Enum;
        assert_eq!(cat, DataTypeCategory::Enum);
        assert_ne!(cat, DataTypeCategory::Structure);
    }

    // -- DomainFileState tests --

    #[test]
    fn test_domain_file_state_default() {
        let state = DomainFileState::default();
        assert!(!state.is_changed);
        assert!(!state.is_read_only);
        assert!(!state.is_checked_out);
        assert!(!state.is_not_latest());
    }

    #[test]
    fn test_domain_file_state_not_latest() {
        let state = DomainFileState {
            is_versioned: true,
            version: 3,
            latest_version: 5,
            ..Default::default()
        };
        assert!(state.is_not_latest());
    }

    #[test]
    fn test_domain_file_state_info_string() {
        let state = DomainFileState {
            is_read_only: true,
            is_versioned: true,
            version: 2,
            latest_version: 3,
            ..Default::default()
        };
        let info = state.info_string();
        assert!(info.contains("Read-Only"));
        assert!(info.contains("v2/3"));
    }

    #[test]
    fn test_domain_file_state_info_string_ok() {
        let state = DomainFileState::default();
        assert_eq!(state.info_string(), "OK");
    }

    // -- DataTypeArchiveGTree tests --

    #[test]
    fn test_gtree_new() {
        let tree = DataTypeArchiveGTree::new();
        assert!(!tree.is_loaded());
        assert_eq!(tree.root().archive_count(), 0);
    }

    #[test]
    fn test_gtree_with_filter() {
        let mut fs = DtFilterState::new();
        fs.filter_for_mut(DataTypeCategory::Array).set_type_active(true);
        let tree = DataTypeArchiveGTree::with_filter(fs);
        assert!(tree.filter_state().arrays_filter().is_type_active());
    }

    #[test]
    fn test_gtree_add_archive_and_find() {
        let mut tree = DataTypeArchiveGTree::new();
        let archive = ArchiveNode::new(
            "clib.gdt",
            super::super::archive::ArchiveKind::File,
            true,
            Some(UniversalID::new(100)),
        );
        tree.root_mut().add_archive(archive);
        assert!(tree.find_archive_by_name("clib.gdt").is_some());
        assert!(tree.find_archive_by_name("other.gdt").is_none());
    }

    #[test]
    fn test_gtree_find_category() {
        let mut tree = DataTypeArchiveGTree::new();
        let mut archive = ArchiveNode::new(
            "lib",
            super::super::archive::ArchiveKind::File,
            true,
            None,
        );
        let mut cat = CategoryNode::new("sys", CategoryPath::new("sys"), true);
        cat.add_category(CategoryNode::new("types", CategoryPath::from_path_string("/sys/types"), true));
        archive.add_category(cat);
        tree.root_mut().add_archive(archive);

        assert!(tree.find_category_node("/sys/types").is_some());
        assert!(tree.find_category_node("/sys").is_some());
        assert!(tree.find_category_node("/nonexistent").is_none());
    }

    #[test]
    fn test_gtree_refresh() {
        let mut tree = DataTypeArchiveGTree::new();
        assert_eq!(tree.root().modification_count(), 0);
        tree.refresh();
        assert_eq!(tree.root().modification_count(), 1);
    }

    #[test]
    fn test_gtree_set_loaded() {
        let mut tree = DataTypeArchiveGTree::new();
        assert!(!tree.is_loaded());
        tree.set_loaded(true);
        assert!(tree.is_loaded());
    }

    #[test]
    fn test_gtree_set_filter_state() {
        let mut tree = DataTypeArchiveGTree::new();
        let mut fs = DtFilterState::new();
        fs.filter_for_mut(DataTypeCategory::Pointer).set_type_active(true);
        tree.set_filter_state(fs);
        assert!(tree.filter_state().pointers_filter().is_type_active());
    }

    #[test]
    fn test_gtree_default() {
        let tree = DataTypeArchiveGTree::default();
        assert_eq!(tree.root().archive_count(), 0);
    }
}
