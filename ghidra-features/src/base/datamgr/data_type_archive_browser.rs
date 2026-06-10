//! Data Type Archive Browser -- browse and manage data type archives.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.datamgr.archivebrowser`
//! Java package.
//!
//! This module provides [`DataTypeArchiveBrowser`], a tree-based browser
//! for navigating open data type archives (built-in, file-backed, program,
//! and project archives).  It mirrors the archive tree displayed in the
//! left pane of the Data Type Manager window.
//!
//! # Architecture
//!
//! ```text
//! DataTypeArchiveBrowser
//!   ├── archive_nodes: Vec<ArchiveBrowserNode>
//!   ├── selected_archive: Option<usize>
//!   ├── filter: ArchiveBrowserFilter
//!   └── sort: ArchiveBrowserSort
//!
//! ArchiveBrowserNode
//!   ├── name / kind (built-in, file, program, project, invalid)
//!   ├── path (file path for file archives)
//!   ├── expanded / selected
//!   ├── categories: Vec<CategoryBrowserNode>
//!   └── type_count / dirty / modifiable
//!
//! CategoryBrowserNode
//!   ├── name / path
//!   ├── expanded / selected
//!   ├── child_categories
//!   └── child_types: Vec<TypeBrowserEntry>
//! ```

use std::fmt;

// ---------------------------------------------------------------------------
// ArchiveBrowserKind -- discriminator for archive types
// ---------------------------------------------------------------------------

/// The kind of archive displayed in the browser.
///
/// Mirrors [`ArchiveKind`] from the `datamgr::archive` module but is
/// local to the browser to avoid pulling in the full archive trait
/// hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveBrowserKind {
    /// The built-in (global) data type library.
    BuiltIn,
    /// A file-backed archive (e.g., a `.gdt` file).
    File,
    /// The data type manager embedded in a program.
    Program,
    /// A project-stored data type archive.
    Project,
    /// A placeholder for an archive that could not be opened.
    Invalid,
}

impl ArchiveBrowserKind {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::BuiltIn => "Built-In Types",
            Self::File => "File Archive",
            Self::Program => "Program",
            Self::Project => "Project",
            Self::Invalid => "Invalid",
        }
    }

    /// Whether archives of this kind can be modified.
    pub fn is_modifiable(&self) -> bool {
        matches!(self, Self::Program | Self::Project | Self::File)
    }
}

impl fmt::Display for ArchiveBrowserKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// TypeBrowserEntry -- a single data type displayed in the browser
// ---------------------------------------------------------------------------

/// A single data type entry displayed under a category in the browser.
#[derive(Debug, Clone)]
pub struct TypeBrowserEntry {
    /// The data type name.
    name: String,
    /// The data type's category path (e.g., "/Structures").
    category_path: String,
    /// The size in bytes, if known.
    size: Option<usize>,
    /// Whether this type is currently selected in the tree.
    selected: bool,
}

impl TypeBrowserEntry {
    /// Create a new type entry.
    pub fn new(name: impl Into<String>, category_path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            category_path: category_path.into(),
            size: None,
            selected: false,
        }
    }

    /// The data type name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The category path.
    pub fn category_path(&self) -> &str {
        &self.category_path
    }

    /// The size in bytes, if known.
    pub fn size(&self) -> Option<usize> {
        self.size
    }

    /// Set the size in bytes.
    pub fn set_size(&mut self, size: Option<usize>) {
        self.size = size;
    }

    /// Whether this entry is selected.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Set the selection state.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }
}

impl fmt::Display for TypeBrowserEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.category_path)
    }
}

// ---------------------------------------------------------------------------
// CategoryBrowserNode -- a category node in the browser tree
// ---------------------------------------------------------------------------

/// A category node in the archive browser tree.
#[derive(Debug, Clone)]
pub struct CategoryBrowserNode {
    /// The category name (e.g., "Structures").
    name: String,
    /// The full category path (e.g., "/Structures").
    path: String,
    /// Whether this node is expanded in the tree.
    expanded: bool,
    /// Whether this node is selected.
    selected: bool,
    /// Child categories.
    children: Vec<CategoryBrowserNode>,
    /// Data types directly under this category.
    types: Vec<TypeBrowserEntry>,
    /// Depth in the tree (0 = top-level category under archive root).
    depth: usize,
}

impl CategoryBrowserNode {
    /// Create a new category node.
    pub fn new(
        name: impl Into<String>,
        path: impl Into<String>,
        depth: usize,
    ) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            expanded: false,
            selected: false,
            children: Vec::new(),
            types: Vec::new(),
            depth,
        }
    }

    /// The category name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The full category path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether this node is expanded.
    pub fn is_expanded(&self) -> bool {
        self.expanded
    }

    /// Set the expanded state.
    pub fn set_expanded(&mut self, expanded: bool) {
        self.expanded = expanded;
    }

    /// Whether this node is selected.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Set the selection state.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// The depth in the tree.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Returns a reference to child categories.
    pub fn children(&self) -> &[CategoryBrowserNode] {
        &self.children
    }

    /// Returns a mutable reference to child categories.
    pub fn children_mut(&mut self) -> &mut Vec<CategoryBrowserNode> {
        &mut self.children
    }

    /// Add a child category.
    pub fn add_child(&mut self, child: CategoryBrowserNode) {
        self.children.push(child);
    }

    /// Returns a reference to the types under this category.
    pub fn types(&self) -> &[TypeBrowserEntry] {
        &self.types
    }

    /// Returns a mutable reference to the types under this category.
    pub fn types_mut(&mut self) -> &mut Vec<TypeBrowserEntry> {
        &mut self.types
    }

    /// Add a data type entry.
    pub fn add_type(&mut self, entry: TypeBrowserEntry) {
        self.types.push(entry);
    }

    /// The total number of types in this category and all subcategories.
    pub fn total_type_count(&self) -> usize {
        let mut count = self.types.len();
        for child in &self.children {
            count += child.total_type_count();
        }
        count
    }

    /// Expand this node and optionally all descendants.
    pub fn expand_all(&mut self) {
        self.expanded = true;
        for child in &mut self.children {
            child.expand_all();
        }
    }

    /// Collapse this node and all descendants.
    pub fn collapse_all(&mut self) {
        self.expanded = false;
        for child in &mut self.children {
            child.collapse_all();
        }
    }
}

impl fmt::Display for CategoryBrowserNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{} types, {} subcats]",
            self.name,
            self.types.len(),
            self.children.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ArchiveBrowserNode -- a top-level archive node in the browser
// ---------------------------------------------------------------------------

/// A top-level archive node in the archive browser tree.
///
/// Each open archive (built-in, file, program, project) is represented
/// as an [`ArchiveBrowserNode`] with its own category hierarchy.
#[derive(Debug, Clone)]
pub struct ArchiveBrowserNode {
    /// The display name of the archive.
    name: String,
    /// The kind of archive.
    kind: ArchiveBrowserKind,
    /// The file path (for file-backed archives).
    file_path: Option<String>,
    /// Whether this node is expanded in the tree.
    expanded: bool,
    /// Whether this node is selected.
    selected: bool,
    /// Whether the archive has unsaved changes.
    dirty: bool,
    /// Whether the archive is modifiable.
    modifiable: bool,
    /// Top-level categories under the archive root.
    categories: Vec<CategoryBrowserNode>,
    /// Total number of data types in the archive.
    type_count: usize,
    /// Unique index for this node.
    index: usize,
}

impl ArchiveBrowserNode {
    /// Create a new archive browser node.
    pub fn new(
        name: impl Into<String>,
        kind: ArchiveBrowserKind,
        index: usize,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            file_path: None,
            expanded: false,
            selected: false,
            dirty: false,
            modifiable: kind.is_modifiable(),
            categories: Vec::new(),
            type_count: 0,
            index,
        }
    }

    /// Create a file-backed archive node.
    pub fn file_archive(
        name: impl Into<String>,
        path: impl Into<String>,
        index: usize,
    ) -> Self {
        let mut node = Self::new(name, ArchiveBrowserKind::File, index);
        node.file_path = Some(path.into());
        node
    }

    /// Create the built-in types archive node.
    pub fn builtin(index: usize) -> Self {
        let mut node = Self::new("Built-In Types", ArchiveBrowserKind::BuiltIn, index);
        node.expanded = true; // Built-in is expanded by default.
        node
    }

    /// Create a program archive node.
    pub fn program(name: impl Into<String>, index: usize) -> Self {
        Self::new(name, ArchiveBrowserKind::Program, index)
    }

    /// The display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The archive kind.
    pub fn kind(&self) -> ArchiveBrowserKind {
        self.kind
    }

    /// The file path, if file-backed.
    pub fn file_path(&self) -> Option<&str> {
        self.file_path.as_deref()
    }

    /// The unique index of this node.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Whether this node is expanded.
    pub fn is_expanded(&self) -> bool {
        self.expanded
    }

    /// Set the expanded state.
    pub fn set_expanded(&mut self, expanded: bool) {
        self.expanded = expanded;
    }

    /// Whether this node is selected.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Set the selection state.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Whether the archive has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Set the dirty state.
    pub fn set_dirty(&mut self, dirty: bool) {
        self.dirty = dirty;
    }

    /// Whether the archive is modifiable.
    pub fn is_modifiable(&self) -> bool {
        self.modifiable
    }

    /// Set the modifiable state.
    pub fn set_modifiable(&mut self, modifiable: bool) {
        self.modifiable = modifiable;
    }

    /// Returns a reference to the top-level categories.
    pub fn categories(&self) -> &[CategoryBrowserNode] {
        &self.categories
    }

    /// Returns a mutable reference to the top-level categories.
    pub fn categories_mut(&mut self) -> &mut Vec<CategoryBrowserNode> {
        &mut self.categories
    }

    /// Add a top-level category.
    pub fn add_category(&mut self, category: CategoryBrowserNode) {
        self.categories.push(category);
    }

    /// The total number of data types.
    pub fn type_count(&self) -> usize {
        self.type_count
    }

    /// Set the total type count.
    pub fn set_type_count(&mut self, count: usize) {
        self.type_count = count;
    }

    /// Expand this node and all its categories.
    pub fn expand_all(&mut self) {
        self.expanded = true;
        for cat in &mut self.categories {
            cat.expand_all();
        }
    }

    /// Collapse this node and all its categories.
    pub fn collapse_all(&mut self) {
        self.expanded = false;
        for cat in &mut self.categories {
            cat.collapse_all();
        }
    }

    /// Whether the built-in archive (always modifiable=false, closeable=false).
    pub fn is_builtin(&self) -> bool {
        self.kind == ArchiveBrowserKind::BuiltIn
    }
}

impl fmt::Display for ArchiveBrowserNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] ({} types)",
            self.name,
            self.kind.label(),
            self.type_count
        )
    }
}

// ---------------------------------------------------------------------------
// ArchiveBrowserFilter -- filter for the archive browser
// ---------------------------------------------------------------------------

/// Filter state for the archive browser.
///
/// Controls which archives and data types are visible based on kind,
/// text pattern, and modification state.
#[derive(Debug, Clone)]
pub struct ArchiveBrowserFilter {
    /// Text filter pattern.
    text_filter: String,
    /// Whether to show built-in archives.
    show_builtin: bool,
    /// Whether to show file archives.
    show_file: bool,
    /// Whether to show program archives.
    show_program: bool,
    /// Whether to show project archives.
    show_project: bool,
    /// Whether to show only dirty (modified) archives.
    dirty_only: bool,
    /// Whether the filter is active.
    active: bool,
}

impl ArchiveBrowserFilter {
    /// Create a new filter with default settings (everything visible).
    pub fn new() -> Self {
        Self {
            text_filter: String::new(),
            show_builtin: true,
            show_file: true,
            show_program: true,
            show_project: true,
            dirty_only: false,
            active: false,
        }
    }

    /// The current text filter.
    pub fn text_filter(&self) -> &str {
        &self.text_filter
    }

    /// Set the text filter and activate.
    pub fn set_text_filter(&mut self, text: impl Into<String>) {
        self.text_filter = text.into();
        self.active = !self.text_filter.is_empty();
    }

    /// Clear the text filter.
    pub fn clear(&mut self) {
        self.text_filter.clear();
        self.active = false;
    }

    /// Whether the filter is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Whether to show built-in archives.
    pub fn show_builtin(&self) -> bool {
        self.show_builtin
    }

    /// Set whether to show built-in archives.
    pub fn set_show_builtin(&mut self, show: bool) {
        self.show_builtin = show;
    }

    /// Whether to show file archives.
    pub fn show_file(&self) -> bool {
        self.show_file
    }

    /// Set whether to show file archives.
    pub fn set_show_file(&mut self, show: bool) {
        self.show_file = show;
    }

    /// Whether to show program archives.
    pub fn show_program(&self) -> bool {
        self.show_program
    }

    /// Set whether to show program archives.
    pub fn set_show_program(&mut self, show: bool) {
        self.show_program = show;
    }

    /// Whether to show project archives.
    pub fn show_project(&self) -> bool {
        self.show_project
    }

    /// Set whether to show project archives.
    pub fn set_show_project(&mut self, show: bool) {
        self.show_project = show;
    }

    /// Whether to show only dirty archives.
    pub fn dirty_only(&self) -> bool {
        self.dirty_only
    }

    /// Set whether to show only dirty archives.
    pub fn set_dirty_only(&mut self, dirty_only: bool) {
        self.dirty_only = dirty_only;
    }

    /// Returns `true` if the given archive node passes this filter.
    pub fn accepts_archive(&self, node: &ArchiveBrowserNode) -> bool {
        // Kind filter.
        match node.kind() {
            ArchiveBrowserKind::BuiltIn if !self.show_builtin => return false,
            ArchiveBrowserKind::File if !self.show_file => return false,
            ArchiveBrowserKind::Program if !self.show_program => return false,
            ArchiveBrowserKind::Project if !self.show_project => return false,
            ArchiveBrowserKind::Invalid => return false,
            _ => {}
        }

        // Dirty filter.
        if self.dirty_only && !node.is_dirty() {
            return false;
        }

        // Text filter.
        if self.active {
            let lower = self.text_filter.to_lowercase();
            if !node.name().to_lowercase().contains(&lower) {
                // Also check file path.
                if let Some(path) = node.file_path() {
                    if !path.to_lowercase().contains(&lower) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }

        true
    }

    /// Returns `true` if the given type entry passes this filter.
    pub fn accepts_type(&self, entry: &TypeBrowserEntry) -> bool {
        if !self.active {
            return true;
        }
        let lower = self.text_filter.to_lowercase();
        entry.name().to_lowercase().contains(&lower)
            || entry.category_path().to_lowercase().contains(&lower)
    }
}

impl Default for ArchiveBrowserFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ArchiveBrowserFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.active {
            write!(f, "ArchiveFilter({:?})", self.text_filter)
        } else {
            write!(f, "ArchiveFilter(inactive)")
        }
    }
}

// ---------------------------------------------------------------------------
// ArchiveBrowserSort -- sort modes for the archive browser
// ---------------------------------------------------------------------------

/// Sort modes for the archive browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveBrowserSort {
    /// Sort archives by name.
    Name,
    /// Sort archives by type count.
    TypeCount,
    /// Sort archives by kind (built-in first, then file, program, project).
    Kind,
    /// Sort archives by modification state (dirty first).
    Dirty,
}

impl ArchiveBrowserSort {
    /// All available sort modes.
    pub fn all() -> &'static [ArchiveBrowserSort] {
        &[
            ArchiveBrowserSort::Name,
            ArchiveBrowserSort::TypeCount,
            ArchiveBrowserSort::Kind,
            ArchiveBrowserSort::Dirty,
        ]
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::TypeCount => "Type Count",
            Self::Kind => "Kind",
            Self::Dirty => "Dirty",
        }
    }
}

impl Default for ArchiveBrowserSort {
    fn default() -> Self {
        Self::Name
    }
}

impl fmt::Display for ArchiveBrowserSort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// DataTypeArchiveBrowser -- the main browser
// ---------------------------------------------------------------------------

/// The Data Type Archive Browser.
///
/// Manages a tree of [`ArchiveBrowserNode`] items, one per open archive,
/// each with its own category hierarchy.  Supports filtering by archive
/// kind and text pattern, sorting, and selection tracking.
///
/// Ported from `ghidra.app.plugin.core.datamgr.archivebrowser`.
#[derive(Debug)]
pub struct DataTypeArchiveBrowser {
    /// The archive nodes.
    archive_nodes: Vec<ArchiveBrowserNode>,
    /// The index of the currently selected archive, if any.
    selected_archive: Option<usize>,
    /// The filter state.
    filter: ArchiveBrowserFilter,
    /// The sort mode.
    sort_mode: ArchiveBrowserSort,
    /// Next available archive index.
    next_index: usize,
    /// Whether the browser needs a refresh.
    changed: bool,
}

impl DataTypeArchiveBrowser {
    /// Create a new archive browser.
    pub fn new() -> Self {
        Self {
            archive_nodes: Vec::new(),
            selected_archive: None,
            filter: ArchiveBrowserFilter::new(),
            sort_mode: ArchiveBrowserSort::default(),
            next_index: 0,
            changed: true,
        }
    }

    /// Add an archive node and return its index.
    pub fn add_archive(&mut self, mut node: ArchiveBrowserNode) -> usize {
        let idx = self.next_index;
        self.next_index += 1;
        node.index = idx;
        self.archive_nodes.push(node);
        self.changed = true;
        idx
    }

    /// Remove an archive node by index.
    pub fn remove_archive(&mut self, index: usize) -> Option<ArchiveBrowserNode> {
        if let Some(pos) = self.archive_nodes.iter().position(|n| n.index() == index) {
            if self.selected_archive == Some(index) {
                self.selected_archive = None;
            }
            self.changed = true;
            Some(self.archive_nodes.remove(pos))
        } else {
            None
        }
    }

    /// Returns a reference to all archive nodes.
    pub fn archives(&self) -> &[ArchiveBrowserNode] {
        &self.archive_nodes
    }

    /// Returns a mutable reference to all archive nodes.
    pub fn archives_mut(&mut self) -> &mut Vec<ArchiveBrowserNode> {
        &mut self.archive_nodes
    }

    /// Find an archive node by index.
    pub fn find_archive(&self, index: usize) -> Option<&ArchiveBrowserNode> {
        self.archive_nodes.iter().find(|n| n.index() == index)
    }

    /// Find a mutable archive node by index.
    pub fn find_archive_mut(&mut self, index: usize) -> Option<&mut ArchiveBrowserNode> {
        self.archive_nodes.iter_mut().find(|n| n.index() == index)
    }

    /// The number of archive nodes.
    pub fn archive_count(&self) -> usize {
        self.archive_nodes.len()
    }

    /// Select an archive by index.
    pub fn select_archive(&mut self, index: usize) {
        // Deselect previous.
        if let Some(prev_idx) = self.selected_archive {
            if let Some(prev) = self.find_archive_mut(prev_idx) {
                prev.set_selected(false);
            }
        }
        self.selected_archive = Some(index);
        if let Some(node) = self.find_archive_mut(index) {
            node.set_selected(true);
        }
    }

    /// Deselect the current archive.
    pub fn deselect_archive(&mut self) {
        if let Some(idx) = self.selected_archive {
            if let Some(node) = self.find_archive_mut(idx) {
                node.set_selected(false);
            }
        }
        self.selected_archive = None;
    }

    /// The index of the currently selected archive, if any.
    pub fn selected_archive_index(&self) -> Option<usize> {
        self.selected_archive
    }

    /// A reference to the currently selected archive, if any.
    pub fn selected_archive_node(&self) -> Option<&ArchiveBrowserNode> {
        self.selected_archive.and_then(|idx| self.find_archive(idx))
    }

    // ---- Filter ----

    /// Returns a reference to the filter state.
    pub fn filter(&self) -> &ArchiveBrowserFilter {
        &self.filter
    }

    /// Returns a mutable reference to the filter state.
    pub fn filter_mut(&mut self) -> &mut ArchiveBrowserFilter {
        &mut self.filter
    }

    /// Returns the indices of archives that pass the current filter.
    pub fn visible_archive_indices(&self) -> Vec<usize> {
        self.archive_nodes
            .iter()
            .filter(|n| self.filter.accepts_archive(n))
            .map(|n| n.index())
            .collect()
    }

    // ---- Sort ----

    /// Returns the current sort mode.
    pub fn sort_mode(&self) -> ArchiveBrowserSort {
        self.sort_mode
    }

    /// Sets the sort mode.
    pub fn set_sort_mode(&mut self, mode: ArchiveBrowserSort) {
        self.sort_mode = mode;
        self.changed = true;
    }

    // ---- Refresh ----

    /// Whether the browser needs a refresh.
    pub fn is_changed(&self) -> bool {
        self.changed
    }

    /// Mark the browser as needing a refresh.
    pub fn mark_changed(&mut self) {
        self.changed = true;
    }

    /// Clear the changed flag.
    pub fn clear_changed(&mut self) {
        self.changed = false;
    }

    /// Expand all archive nodes and their categories.
    pub fn expand_all(&mut self) {
        for node in &mut self.archive_nodes {
            node.expand_all();
        }
    }

    /// Collapse all archive nodes and their categories.
    pub fn collapse_all(&mut self) {
        for node in &mut self.archive_nodes {
            node.collapse_all();
        }
    }

    /// The total number of data types across all archives.
    pub fn total_type_count(&self) -> usize {
        self.archive_nodes.iter().map(|n| n.type_count()).sum()
    }

    /// Clear all archives and reset.
    pub fn clear(&mut self) {
        self.archive_nodes.clear();
        self.selected_archive = None;
        self.next_index = 0;
        self.changed = true;
    }
}

impl Default for DataTypeArchiveBrowser {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DataTypeArchiveBrowser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DataTypeArchiveBrowser({} archives, {} total types)",
            self.archive_nodes.len(),
            self.total_type_count()
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ArchiveBrowserKind tests ----

    #[test]
    fn test_archive_kind_display() {
        assert_eq!(format!("{}", ArchiveBrowserKind::BuiltIn), "Built-In Types");
        assert_eq!(format!("{}", ArchiveBrowserKind::File), "File Archive");
        assert_eq!(format!("{}", ArchiveBrowserKind::Program), "Program");
    }

    #[test]
    fn test_archive_kind_modifiable() {
        assert!(!ArchiveBrowserKind::BuiltIn.is_modifiable());
        assert!(ArchiveBrowserKind::File.is_modifiable());
        assert!(ArchiveBrowserKind::Program.is_modifiable());
        assert!(ArchiveBrowserKind::Project.is_modifiable());
        assert!(!ArchiveBrowserKind::Invalid.is_modifiable());
    }

    // ---- TypeBrowserEntry tests ----

    #[test]
    fn test_type_entry_creation() {
        let entry = TypeBrowserEntry::new("my_struct", "/Structures");
        assert_eq!(entry.name(), "my_struct");
        assert_eq!(entry.category_path(), "/Structures");
        assert!(entry.size().is_none());
        assert!(!entry.is_selected());
    }

    #[test]
    fn test_type_entry_modification() {
        let mut entry = TypeBrowserEntry::new("x", "/");
        entry.set_size(Some(16));
        assert_eq!(entry.size(), Some(16));

        entry.set_selected(true);
        assert!(entry.is_selected());
    }

    #[test]
    fn test_type_entry_display() {
        let entry = TypeBrowserEntry::new("int", "/Primitives");
        let s = format!("{}", entry);
        assert!(s.contains("int"));
        assert!(s.contains("/Primitives"));
    }

    // ---- CategoryBrowserNode tests ----

    #[test]
    fn test_category_node_creation() {
        let cat = CategoryBrowserNode::new("Structures", "/Structures", 0);
        assert_eq!(cat.name(), "Structures");
        assert_eq!(cat.path(), "/Structures");
        assert_eq!(cat.depth(), 0);
        assert!(!cat.is_expanded());
        assert!(cat.children().is_empty());
        assert!(cat.types().is_empty());
    }

    #[test]
    fn test_category_node_add_child() {
        let mut root = CategoryBrowserNode::new("root", "/", 0);
        let child = CategoryBrowserNode::new("sub", "/sub", 1);
        root.add_child(child);
        assert_eq!(root.children().len(), 1);
    }

    #[test]
    fn test_category_node_add_type() {
        let mut cat = CategoryBrowserNode::new("Structures", "/Structures", 0);
        cat.add_type(TypeBrowserEntry::new("my_struct", "/Structures"));
        assert_eq!(cat.types().len(), 1);
    }

    #[test]
    fn test_category_node_total_type_count() {
        let mut root = CategoryBrowserNode::new("root", "/", 0);
        root.add_type(TypeBrowserEntry::new("a", "/"));

        let mut child = CategoryBrowserNode::new("sub", "/sub", 1);
        child.add_type(TypeBrowserEntry::new("b", "/sub"));
        child.add_type(TypeBrowserEntry::new("c", "/sub"));
        root.add_child(child);

        assert_eq!(root.total_type_count(), 3); // 1 + 2
    }

    #[test]
    fn test_category_node_expand_collapse() {
        let mut cat = CategoryBrowserNode::new("root", "/", 0);
        cat.add_child(CategoryBrowserNode::new("sub", "/sub", 1));

        cat.expand_all();
        assert!(cat.is_expanded());
        assert!(cat.children()[0].is_expanded());

        cat.collapse_all();
        assert!(!cat.is_expanded());
        assert!(!cat.children()[0].is_expanded());
    }

    #[test]
    fn test_category_node_display() {
        let mut cat = CategoryBrowserNode::new("Structures", "/Structures", 0);
        cat.add_type(TypeBrowserEntry::new("a", "/"));
        cat.add_child(CategoryBrowserNode::new("sub", "/sub", 1));
        let s = format!("{}", cat);
        assert!(s.contains("Structures"));
        assert!(s.contains("1 types"));
        assert!(s.contains("1 subcats"));
    }

    // ---- ArchiveBrowserNode tests ----

    #[test]
    fn test_archive_node_creation() {
        let node = ArchiveBrowserNode::new("generic_C_lib", ArchiveBrowserKind::File, 0);
        assert_eq!(node.name(), "generic_C_lib");
        assert_eq!(node.kind(), ArchiveBrowserKind::File);
        assert!(node.file_path().is_none());
        assert!(!node.is_expanded());
        assert!(!node.is_dirty());
        assert!(node.is_modifiable());
    }

    #[test]
    fn test_archive_node_file_archive() {
        let node = ArchiveBrowserNode::file_archive("my_types", "/path/to/file.gdt", 1);
        assert_eq!(node.kind(), ArchiveBrowserKind::File);
        assert_eq!(node.file_path(), Some("/path/to/file.gdt"));
    }

    #[test]
    fn test_archive_node_builtin() {
        let node = ArchiveBrowserNode::builtin(0);
        assert_eq!(node.kind(), ArchiveBrowserKind::BuiltIn);
        assert!(node.is_builtin());
        assert!(node.is_expanded()); // expanded by default
    }

    #[test]
    fn test_archive_node_program() {
        let node = ArchiveBrowserNode::program("test.exe", 1);
        assert_eq!(node.kind(), ArchiveBrowserKind::Program);
        assert!(node.is_modifiable());
    }

    #[test]
    fn test_archive_node_modification() {
        let mut node = ArchiveBrowserNode::new("test", ArchiveBrowserKind::File, 0);
        node.set_dirty(true);
        assert!(node.is_dirty());

        node.set_modifiable(false);
        assert!(!node.is_modifiable());

        node.set_type_count(42);
        assert_eq!(node.type_count(), 42);
    }

    #[test]
    fn test_archive_node_categories() {
        let mut node = ArchiveBrowserNode::new("test", ArchiveBrowserKind::File, 0);
        node.add_category(CategoryBrowserNode::new("Structures", "/Structures", 0));
        assert_eq!(node.categories().len(), 1);
    }

    #[test]
    fn test_archive_node_expand_collapse() {
        let mut node = ArchiveBrowserNode::new("test", ArchiveBrowserKind::File, 0);
        node.add_category(CategoryBrowserNode::new("Cat", "/Cat", 0));

        node.expand_all();
        assert!(node.is_expanded());
        assert!(node.categories()[0].is_expanded());

        node.collapse_all();
        assert!(!node.is_expanded());
        assert!(!node.categories()[0].is_expanded());
    }

    #[test]
    fn test_archive_node_display() {
        let mut node = ArchiveBrowserNode::new("my_types", ArchiveBrowserKind::File, 0);
        node.set_type_count(10);
        let s = format!("{}", node);
        assert!(s.contains("my_types"));
        assert!(s.contains("File Archive"));
        assert!(s.contains("10 types"));
    }

    // ---- ArchiveBrowserFilter tests ----

    #[test]
    fn test_filter_default() {
        let filter = ArchiveBrowserFilter::new();
        assert!(!filter.is_active());
        assert!(filter.show_builtin());
        assert!(filter.show_file());
        assert!(filter.show_program());
        assert!(filter.show_project());
        assert!(!filter.dirty_only());
    }

    #[test]
    fn test_filter_text() {
        let mut filter = ArchiveBrowserFilter::new();
        filter.set_text_filter("test");
        assert!(filter.is_active());
        assert_eq!(filter.text_filter(), "test");

        filter.clear();
        assert!(!filter.is_active());
        assert!(filter.text_filter().is_empty());
    }

    #[test]
    fn test_filter_accepts_archive_by_kind() {
        let filter = ArchiveBrowserFilter::new();
        let builtin = ArchiveBrowserNode::builtin(0);
        let file = ArchiveBrowserNode::file_archive("x", "/x", 1);
        let program = ArchiveBrowserNode::program("prog", 2);

        assert!(filter.accepts_archive(&builtin));
        assert!(filter.accepts_archive(&file));
        assert!(filter.accepts_archive(&program));

        // Invalid is always rejected.
        let invalid = ArchiveBrowserNode::new("bad", ArchiveBrowserKind::Invalid, 3);
        assert!(!filter.accepts_archive(&invalid));
    }

    #[test]
    fn test_filter_accepts_archive_by_text() {
        let mut filter = ArchiveBrowserFilter::new();
        filter.set_text_filter("generic");

        let matching = ArchiveBrowserNode::new("generic_C_lib", ArchiveBrowserKind::BuiltIn, 0);
        let non_matching = ArchiveBrowserNode::new("windows_lib", ArchiveBrowserKind::BuiltIn, 1);

        assert!(filter.accepts_archive(&matching));
        assert!(!filter.accepts_archive(&non_matching));
    }

    #[test]
    fn test_filter_accepts_archive_by_file_path() {
        let mut filter = ArchiveBrowserFilter::new();
        filter.set_text_filter("my_types");

        let node = ArchiveBrowserNode::file_archive("lib", "/path/to/my_types.gdt", 0);
        assert!(filter.accepts_archive(&node));
    }

    #[test]
    fn test_filter_accepts_archive_dirty_only() {
        let mut filter = ArchiveBrowserFilter::new();
        filter.set_dirty_only(true);

        let mut dirty = ArchiveBrowserNode::new("dirty", ArchiveBrowserKind::File, 0);
        dirty.set_dirty(true);
        let clean = ArchiveBrowserNode::new("clean", ArchiveBrowserKind::File, 1);

        assert!(filter.accepts_archive(&dirty));
        assert!(!filter.accepts_archive(&clean));
    }

    #[test]
    fn test_filter_accepts_archive_hide_builtin() {
        let mut filter = ArchiveBrowserFilter::new();
        filter.set_show_builtin(false);

        let builtin = ArchiveBrowserNode::builtin(0);
        let file = ArchiveBrowserNode::file_archive("x", "/x", 1);

        assert!(!filter.accepts_archive(&builtin));
        assert!(filter.accepts_archive(&file));
    }

    #[test]
    fn test_filter_accepts_type() {
        let filter = ArchiveBrowserFilter::new();
        let entry = TypeBrowserEntry::new("my_struct", "/Structures");
        assert!(filter.accepts_type(&entry));
    }

    #[test]
    fn test_filter_accepts_type_with_text() {
        let mut filter = ArchiveBrowserFilter::new();
        filter.set_text_filter("struct");

        let matching = TypeBrowserEntry::new("my_struct", "/Structures");
        let non_matching = TypeBrowserEntry::new("int", "/Primitives");

        assert!(filter.accepts_type(&matching));
        assert!(!filter.accepts_type(&non_matching));
    }

    #[test]
    fn test_filter_display() {
        let mut filter = ArchiveBrowserFilter::new();
        assert_eq!(format!("{}", filter), "ArchiveFilter(inactive)");

        filter.set_text_filter("test");
        let s = format!("{}", filter);
        assert!(s.contains("test"));
    }

    // ---- ArchiveBrowserSort tests ----

    #[test]
    fn test_sort_default() {
        assert_eq!(ArchiveBrowserSort::default(), ArchiveBrowserSort::Name);
    }

    #[test]
    fn test_sort_all() {
        assert_eq!(ArchiveBrowserSort::all().len(), 4);
    }

    #[test]
    fn test_sort_display() {
        assert_eq!(format!("{}", ArchiveBrowserSort::Name), "Name");
        assert_eq!(format!("{}", ArchiveBrowserSort::TypeCount), "Type Count");
        assert_eq!(format!("{}", ArchiveBrowserSort::Kind), "Kind");
        assert_eq!(format!("{}", ArchiveBrowserSort::Dirty), "Dirty");
    }

    // ---- DataTypeArchiveBrowser tests ----

    #[test]
    fn test_browser_creation() {
        let browser = DataTypeArchiveBrowser::new();
        assert_eq!(browser.archive_count(), 0);
        assert!(browser.selected_archive_index().is_none());
        assert!(browser.is_changed());
    }

    #[test]
    fn test_browser_add_archive() {
        let mut browser = DataTypeArchiveBrowser::new();
        let idx = browser.add_archive(ArchiveBrowserNode::builtin(0));
        assert_eq!(idx, 0);
        assert_eq!(browser.archive_count(), 1);

        let idx2 = browser.add_archive(ArchiveBrowserNode::file_archive("x", "/x", 0));
        assert_eq!(idx2, 1);
        assert_eq!(browser.archive_count(), 2);
    }

    #[test]
    fn test_browser_remove_archive() {
        let mut browser = DataTypeArchiveBrowser::new();
        let idx = browser.add_archive(ArchiveBrowserNode::builtin(0));
        browser.add_archive(ArchiveBrowserNode::file_archive("x", "/x", 0));

        let removed = browser.remove_archive(idx);
        assert!(removed.is_some());
        assert_eq!(browser.archive_count(), 1);
    }

    #[test]
    fn test_browser_remove_nonexistent() {
        let mut browser = DataTypeArchiveBrowser::new();
        assert!(browser.remove_archive(999).is_none());
    }

    #[test]
    fn test_browser_find_archive() {
        let mut browser = DataTypeArchiveBrowser::new();
        let idx = browser.add_archive(ArchiveBrowserNode::builtin(0));
        assert!(browser.find_archive(idx).is_some());
        assert!(browser.find_archive(999).is_none());
    }

    #[test]
    fn test_browser_select_archive() {
        let mut browser = DataTypeArchiveBrowser::new();
        let idx1 = browser.add_archive(ArchiveBrowserNode::builtin(0));
        let idx2 = browser.add_archive(ArchiveBrowserNode::file_archive("x", "/x", 0));

        browser.select_archive(idx1);
        assert_eq!(browser.selected_archive_index(), Some(idx1));
        assert!(browser.find_archive(idx1).unwrap().is_selected());

        browser.select_archive(idx2);
        assert_eq!(browser.selected_archive_index(), Some(idx2));
        assert!(!browser.find_archive(idx1).unwrap().is_selected());
        assert!(browser.find_archive(idx2).unwrap().is_selected());
    }

    #[test]
    fn test_browser_deselect_archive() {
        let mut browser = DataTypeArchiveBrowser::new();
        let idx = browser.add_archive(ArchiveBrowserNode::builtin(0));
        browser.select_archive(idx);
        browser.deselect_archive();
        assert!(browser.selected_archive_index().is_none());
    }

    #[test]
    fn test_browser_selected_archive_node() {
        let mut browser = DataTypeArchiveBrowser::new();
        assert!(browser.selected_archive_node().is_none());

        let idx = browser.add_archive(ArchiveBrowserNode::builtin(0));
        browser.select_archive(idx);
        assert_eq!(browser.selected_archive_node().unwrap().name(), "Built-In Types");
    }

    #[test]
    fn test_browser_visible_archive_indices() {
        let mut browser = DataTypeArchiveBrowser::new();
        browser.add_archive(ArchiveBrowserNode::builtin(0));
        browser.add_archive(ArchiveBrowserNode::file_archive("x", "/x", 0));

        let visible = browser.visible_archive_indices();
        assert_eq!(visible.len(), 2);

        // Hide built-in.
        browser.filter_mut().set_show_builtin(false);
        let visible = browser.visible_archive_indices();
        assert_eq!(visible.len(), 1);
    }

    #[test]
    fn test_browser_sort_mode() {
        let mut browser = DataTypeArchiveBrowser::new();
        assert_eq!(browser.sort_mode(), ArchiveBrowserSort::Name);

        browser.set_sort_mode(ArchiveBrowserSort::TypeCount);
        assert_eq!(browser.sort_mode(), ArchiveBrowserSort::TypeCount);
        assert!(browser.is_changed());
    }

    #[test]
    fn test_browser_refresh_state() {
        let mut browser = DataTypeArchiveBrowser::new();
        assert!(browser.is_changed());

        browser.clear_changed();
        assert!(!browser.is_changed());

        browser.mark_changed();
        assert!(browser.is_changed());
    }

    #[test]
    fn test_browser_expand_collapse_all() {
        let mut browser = DataTypeArchiveBrowser::new();
        browser.add_archive(ArchiveBrowserNode::builtin(0));
        browser.add_archive(ArchiveBrowserNode::file_archive("x", "/x", 0));

        browser.expand_all();
        for node in browser.archives() {
            assert!(node.is_expanded());
        }

        browser.collapse_all();
        for node in browser.archives() {
            assert!(!node.is_expanded());
        }
    }

    #[test]
    fn test_browser_total_type_count() {
        let mut browser = DataTypeArchiveBrowser::new();
        let mut builtin = ArchiveBrowserNode::builtin(0);
        builtin.set_type_count(100);
        let mut file = ArchiveBrowserNode::file_archive("x", "/x", 0);
        file.set_type_count(50);

        browser.add_archive(builtin);
        browser.add_archive(file);
        assert_eq!(browser.total_type_count(), 150);
    }

    #[test]
    fn test_browser_clear() {
        let mut browser = DataTypeArchiveBrowser::new();
        browser.add_archive(ArchiveBrowserNode::builtin(0));
        browser.select_archive(0);

        browser.clear();
        assert_eq!(browser.archive_count(), 0);
        assert!(browser.selected_archive_index().is_none());
        assert!(browser.is_changed());
    }

    #[test]
    fn test_browser_default() {
        let browser = DataTypeArchiveBrowser::default();
        assert_eq!(browser.archive_count(), 0);
    }

    #[test]
    fn test_browser_display() {
        let mut browser = DataTypeArchiveBrowser::new();
        let mut builtin = ArchiveBrowserNode::builtin(0);
        builtin.set_type_count(100);
        browser.add_archive(builtin);

        let s = format!("{}", browser);
        assert!(s.contains("1 archives"));
        assert!(s.contains("100 total types"));
    }

    #[test]
    fn test_browser_remove_selected_archive() {
        let mut browser = DataTypeArchiveBrowser::new();
        let idx = browser.add_archive(ArchiveBrowserNode::builtin(0));
        browser.select_archive(idx);
        browser.remove_archive(idx);
        assert!(browser.selected_archive_index().is_none());
    }
}
