//! Data type tree node hierarchy.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.datamgr.tree` package.
//!
//! The tree models the hierarchical structure of data types across all
//! open archives.  The root is an [`ArchiveRootNode`]; its children are
//! [`ArchiveNode`]s (one per open archive), which contain
//! [`CategoryNode`]s and [`DataTypeNode`]s.

use ghidra_core::data::{
    CategoryPath, DataType, DataTypeManager, DataTypePath,
    SourceArchive, UniversalID,
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
}
