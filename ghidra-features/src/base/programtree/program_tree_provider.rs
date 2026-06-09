//! Program Tree Provider -- tree view provider for program trees.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.programtree.TreeViewProvider`.
//!
//! This module provides the tree view provider that manages a single
//! program tree view, including navigation, selection, and view state.
//!
//! # Architecture
//!
//! ```text
//! ProgramTreeProvider
//!   ├── Tree Panel (UI component)
//!   ├── View Address Set (current view)
//!   ├── Group Paths (selection state)
//!   └── Event Listeners (view changes)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::programtree::program_tree_provider::ProgramTreeProvider;
//!
//! let mut provider = ProgramTreeProvider::new("Program Tree");
//! assert_eq!(provider.view_name(), "Program Tree");
//! ```

use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// ViewProviderService -- trait for view provider services
// ---------------------------------------------------------------------------

/// Trait for view provider services.
///
/// Ported from Ghidra's `ViewProviderService` interface.
pub trait ViewProviderService {
    /// Returns the view name.
    fn view_name(&self) -> &str;

    /// Sets whether the view has focus.
    fn set_has_focus(&mut self, has_focus: bool);

    /// Returns the current view address set.
    fn current_view(&self) -> &[String];

    /// Adds a location to the view.
    fn add_to_view(&mut self, address: &str) -> &[String];

    /// Closes the view.
    fn view_closed(&mut self) -> bool;

    /// Deletes the view.
    fn view_deleted(&mut self) -> bool;

    /// Renames the view.
    fn view_renamed(&mut self, new_name: &str) -> bool;
}

// ---------------------------------------------------------------------------
// GroupPath -- path to a group in the tree
// ---------------------------------------------------------------------------

/// A path to a group in the program tree.
///
/// Represents the hierarchical path from root to a specific
/// module or fragment in the tree.
///
/// Ported from Ghidra's `GroupPath` Java class.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupPath {
    /// The path components (names from root to node).
    pub path: Vec<String>,
}

impl GroupPath {
    /// Creates a new group path.
    pub fn new(path: Vec<String>) -> Self {
        Self { path }
    }

    /// Creates a group path from a single name.
    pub fn from_name(name: impl Into<String>) -> Self {
        Self {
            path: vec![name.into()],
        }
    }

    /// Returns the path components.
    pub fn components(&self) -> &[String] {
        &self.path
    }

    /// Returns the depth of the path.
    pub fn depth(&self) -> usize {
        self.path.len()
    }

    /// Returns the last component (node name).
    pub fn name(&self) -> Option<&str> {
        self.path.last().map(|s| s.as_str())
    }

    /// Returns the root component.
    pub fn root(&self) -> Option<&str> {
        self.path.first().map(|s| s.as_str())
    }

    /// Returns whether this path is a prefix of another path.
    pub fn is_prefix_of(&self, other: &GroupPath) -> bool {
        if self.path.len() > other.path.len() {
            return false;
        }
        self.path.iter().zip(other.path.iter()).all(|(a, b)| a == b)
    }

    /// Returns whether this path starts with the given prefix.
    pub fn starts_with(&self, prefix: &GroupPath) -> bool {
        prefix.is_prefix_of(self)
    }

    /// Returns a sub-path from the given index.
    pub fn sub_path(&self, start: usize) -> Option<GroupPath> {
        if start >= self.path.len() {
            return None;
        }
        Some(GroupPath {
            path: self.path[start..].to_vec(),
        })
    }
}

impl fmt::Display for GroupPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.join("/"))
    }
}

// ---------------------------------------------------------------------------
// GroupView -- a view of selected groups
// ---------------------------------------------------------------------------

/// A view consisting of selected groups.
///
/// Ported from Ghidra's `GroupView` Java class.
#[derive(Debug, Clone, Default)]
pub struct GroupView {
    /// The group paths in the view.
    pub paths: Vec<GroupPath>,
}

impl GroupView {
    /// Creates a new empty group view.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a group view with the given paths.
    pub fn with_paths(paths: Vec<GroupPath>) -> Self {
        Self { paths }
    }

    /// Returns the number of groups in the view.
    pub fn count(&self) -> usize {
        self.paths.len()
    }

    /// Returns the path at the given index.
    pub fn path(&self, index: usize) -> Option<&GroupPath> {
        self.paths.get(index)
    }

    /// Adds a path to the view.
    pub fn add_path(&mut self, path: GroupPath) {
        self.paths.push(path);
    }

    /// Removes a path from the view.
    pub fn remove_path(&mut self, index: usize) -> Option<GroupPath> {
        if index < self.paths.len() {
            Some(self.paths.remove(index))
        } else {
            None
        }
    }

    /// Clears all paths.
    pub fn clear(&mut self) {
        self.paths.clear();
    }

    /// Returns whether the view is empty.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ProgramTreeProvider -- the tree view provider
// ---------------------------------------------------------------------------

/// The program tree view provider.
///
/// Manages a single program tree view, including navigation,
/// selection, and view state. Implements the `ViewProviderService`
/// trait for integration with the view manager.
///
/// Ported from Ghidra's `TreeViewProvider` Java class.
#[derive(Debug)]
pub struct ProgramTreeProvider {
    /// The tree name.
    tree_name: String,
    /// The current view address set.
    view: Vec<String>,
    /// The current program name.
    program: Option<String>,
    /// The group view (selected groups).
    group_view: GroupView,
    /// Whether the provider has focus.
    has_focus: bool,
    /// Whether the provider is disposed.
    disposed: bool,
    /// Expanded paths.
    expanded_paths: Vec<GroupPath>,
    /// Selected paths.
    selected_paths: Vec<GroupPath>,
    /// Viewed paths.
    viewed_paths: Vec<GroupPath>,
    /// Plugin options.
    options: BTreeMap<String, String>,
    /// Version tag for validity checking.
    version_tag: u64,
}

impl ProgramTreeProvider {
    /// Creates a new program tree provider.
    pub fn new(tree_name: impl Into<String>) -> Self {
        Self {
            tree_name: tree_name.into(),
            view: Vec::new(),
            program: None,
            group_view: GroupView::new(),
            has_focus: false,
            disposed: false,
            expanded_paths: Vec::new(),
            selected_paths: Vec::new(),
            viewed_paths: Vec::new(),
            options: BTreeMap::new(),
            version_tag: 0,
        }
    }

    /// Returns the tree name.
    pub fn view_name(&self) -> &str {
        &self.tree_name
    }

    /// Sets the tree name.
    pub fn set_view_name(&mut self, name: impl Into<String>) {
        self.tree_name = name.into();
    }

    /// Sets the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.program = program;
        if self.program.is_none() {
            self.view.clear();
            self.group_view.clear();
            self.expanded_paths.clear();
            self.selected_paths.clear();
            self.viewed_paths.clear();
        }
    }

    /// Returns the current program name.
    pub fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }

    /// Returns whether the provider has focus.
    pub fn has_focus(&self) -> bool {
        self.has_focus
    }

    /// Returns whether the provider is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Returns a reference to the group view.
    pub fn group_view(&self) -> &GroupView {
        &self.group_view
    }

    /// Returns a mutable reference to the group view.
    pub fn group_view_mut(&mut self) -> &mut GroupView {
        &mut self.group_view
    }

    /// Sets the group view.
    pub fn set_group_view(&mut self, view: GroupView) {
        self.group_view = view;
    }

    /// Sets the group selection.
    pub fn set_group_selection(&mut self, paths: Vec<GroupPath>) {
        self.selected_paths = paths;
    }

    /// Returns the selected paths.
    pub fn selected_paths(&self) -> &[GroupPath] {
        &self.selected_paths
    }

    /// Returns the expanded paths.
    pub fn expanded_paths(&self) -> &[GroupPath] {
        &self.expanded_paths
    }

    /// Returns the viewed paths.
    pub fn viewed_paths(&self) -> &[GroupPath] {
        &self.viewed_paths
    }

    /// Adds an expanded path.
    pub fn add_expanded_path(&mut self, path: GroupPath) {
        self.expanded_paths.push(path);
    }

    /// Adds a viewed path.
    pub fn add_viewed_path(&mut self, path: GroupPath) {
        self.viewed_paths.push(path);
    }

    /// Clears expanded paths.
    pub fn clear_expanded_paths(&mut self) {
        self.expanded_paths.clear();
    }

    /// Clears selected paths.
    pub fn clear_selected_paths(&mut self) {
        self.selected_paths.clear();
    }

    /// Clears viewed paths.
    pub fn clear_viewed_paths(&mut self) {
        self.viewed_paths.clear();
    }

    /// Replaces the view with the given node.
    pub fn replace_view(&mut self, node_name: &str) {
        self.view.clear();
        self.view.push(node_name.to_string());
    }

    /// Returns the version tag.
    pub fn version_tag(&self) -> u64 {
        self.version_tag
    }

    /// Updates the version tag.
    pub fn set_version_tag(&mut self, tag: u64) {
        self.version_tag = tag;
    }

    /// Notifies listeners of view changes.
    pub fn notify_listeners(&self) {
        // Placeholder for event notification
    }

    /// Sets a provider option.
    pub fn set_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.insert(key.into(), value.into());
    }

    /// Gets a provider option.
    pub fn get_option(&self, key: &str) -> Option<&str> {
        self.options.get(key).map(|s| s.as_str())
    }

    /// Selects paths for a given address.
    pub fn select_paths_for_location(&mut self, address: &str) {
        // Placeholder for address-based selection
        // In a real implementation, this would find all fragments
        // containing the address and select their paths
        let _ = address;
    }

    /// Returns the current view address set.
    pub fn get_view(&self) -> &[String] {
        &self.view
    }

    /// Adds an address to the view.
    pub fn add_to_view(&mut self, address: &str) {
        if !self.view.contains(&address.to_string()) {
            self.view.push(address.to_string());
        }
    }

    /// Clears the view.
    pub fn clear_view(&mut self) {
        self.view.clear();
    }

    /// Disposes the provider.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.program = None;
        self.view.clear();
        self.group_view.clear();
        self.expanded_paths.clear();
        self.selected_paths.clear();
        self.viewed_paths.clear();
    }
}

impl ViewProviderService for ProgramTreeProvider {
    fn view_name(&self) -> &str {
        &self.tree_name
    }

    fn set_has_focus(&mut self, has_focus: bool) {
        self.has_focus = has_focus;
    }

    fn current_view(&self) -> &[String] {
        &self.view
    }

    fn add_to_view(&mut self, address: &str) -> &[String] {
        self.add_to_view(address);
        &self.view
    }

    fn view_closed(&mut self) -> bool {
        if self.program.is_none() {
            return false;
        }
        self.dispose();
        true
    }

    fn view_deleted(&mut self) -> bool {
        if self.program.is_none() {
            return false;
        }
        self.dispose();
        true
    }

    fn view_renamed(&mut self, new_name: &str) -> bool {
        if self.program.is_none() {
            return false;
        }
        self.tree_name = new_name.to_string();
        true
    }
}

impl Default for ProgramTreeProvider {
    fn default() -> Self {
        Self::new("Program Tree")
    }
}

impl fmt::Display for ProgramTreeProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProgramTreeProvider({}, view_size={})",
            self.tree_name,
            self.view.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = ProgramTreeProvider::new("Test Tree");
        assert_eq!(provider.view_name(), "Test Tree");
        assert!(!provider.has_focus());
        assert!(!provider.is_disposed());
        assert!(provider.program().is_none());
    }

    #[test]
    fn test_provider_program() {
        let mut provider = ProgramTreeProvider::new("Test Tree");
        provider.set_program(Some("test.exe".to_string()));
        assert_eq!(provider.program(), Some("test.exe"));

        provider.set_program(None);
        assert!(provider.program().is_none());
    }

    #[test]
    fn test_provider_focus() {
        let mut provider = ProgramTreeProvider::new("Test Tree");
        provider.set_has_focus(true);
        assert!(provider.has_focus());

        provider.set_has_focus(false);
        assert!(!provider.has_focus());
    }

    #[test]
    fn test_group_path() {
        let path = GroupPath::new(vec![
            "root".to_string(),
            "module".to_string(),
            "fragment".to_string(),
        ]);
        assert_eq!(path.depth(), 3);
        assert_eq!(path.name(), Some("fragment"));
        assert_eq!(path.root(), Some("root"));
    }

    #[test]
    fn test_group_path_prefix() {
        let path1 = GroupPath::new(vec!["root".to_string(), "module".to_string()]);
        let path2 = GroupPath::new(vec![
            "root".to_string(),
            "module".to_string(),
            "fragment".to_string(),
        ]);

        assert!(path1.is_prefix_of(&path2));
        assert!(!path2.is_prefix_of(&path1));
        assert!(path2.starts_with(&path1));
    }

    #[test]
    fn test_group_path_sub_path() {
        let path = GroupPath::new(vec![
            "root".to_string(),
            "module".to_string(),
            "fragment".to_string(),
        ]);
        let sub = path.sub_path(1).unwrap();
        assert_eq!(sub.depth(), 2);
        assert_eq!(sub.root(), Some("module"));
    }

    #[test]
    fn test_group_view() {
        let mut view = GroupView::new();
        assert!(view.is_empty());

        view.add_path(GroupPath::from_name("path1"));
        view.add_path(GroupPath::from_name("path2"));
        assert_eq!(view.count(), 2);

        let removed = view.remove_path(0);
        assert!(removed.is_some());
        assert_eq!(view.count(), 1);
    }

    #[test]
    fn test_provider_view() {
        let mut provider = ProgramTreeProvider::new("Test Tree");
        assert!(provider.get_view().is_empty());

        provider.add_to_view("0x401000");
        provider.add_to_view("0x402000");
        assert_eq!(provider.get_view().len(), 2);

        // Adding duplicate should not increase size
        provider.add_to_view("0x401000");
        assert_eq!(provider.get_view().len(), 2);

        provider.clear_view();
        assert!(provider.get_view().is_empty());
    }

    #[test]
    fn test_provider_selection() {
        let mut provider = ProgramTreeProvider::new("Test Tree");
        assert!(provider.selected_paths().is_empty());

        let paths = vec![
            GroupPath::from_name("path1"),
            GroupPath::from_name("path2"),
        ];
        provider.set_group_selection(paths);
        assert_eq!(provider.selected_paths().len(), 2);

        provider.clear_selected_paths();
        assert!(provider.selected_paths().is_empty());
    }

    #[test]
    fn test_provider_expanded() {
        let mut provider = ProgramTreeProvider::new("Test Tree");
        provider.add_expanded_path(GroupPath::from_name("path1"));
        provider.add_expanded_path(GroupPath::from_name("path2"));
        assert_eq!(provider.expanded_paths().len(), 2);

        provider.clear_expanded_paths();
        assert!(provider.expanded_paths().is_empty());
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = ProgramTreeProvider::new("Test Tree");
        provider.set_program(Some("test.exe".to_string()));
        provider.add_to_view("0x401000");

        provider.dispose();
        assert!(provider.is_disposed());
        assert!(provider.program().is_none());
        assert!(provider.get_view().is_empty());
    }

    #[test]
    fn test_provider_rename() {
        let mut provider = ProgramTreeProvider::new("Test Tree");
        provider.set_program(Some("test.exe".to_string()));

        assert!(provider.view_renamed("New Name"));
        assert_eq!(provider.view_name(), "New Name");
    }

    #[test]
    fn test_provider_replace_view() {
        let mut provider = ProgramTreeProvider::new("Test Tree");
        provider.add_to_view("0x401000");
        provider.add_to_view("0x402000");

        provider.replace_view("0x500000");
        assert_eq!(provider.get_view().len(), 1);
        assert_eq!(provider.get_view()[0], "0x500000");
    }

    #[test]
    fn test_provider_version_tag() {
        let mut provider = ProgramTreeProvider::new("Test Tree");
        assert_eq!(provider.version_tag(), 0);

        provider.set_version_tag(42);
        assert_eq!(provider.version_tag(), 42);
    }

    #[test]
    fn test_view_provider_service_trait() {
        let mut provider = ProgramTreeProvider::new("Test Tree");
        provider.set_program(Some("test.exe".to_string()));

        let service: &mut dyn ViewProviderService = &mut provider;
        assert_eq!(service.view_name(), "Test Tree");

        service.set_has_focus(true);
        assert!(service.current_view().is_empty());

        service.add_to_view("0x401000");
        assert_eq!(service.current_view().len(), 1);
    }

    #[test]
    fn test_group_path_display() {
        let path = GroupPath::new(vec![
            "root".to_string(),
            "module".to_string(),
            "fragment".to_string(),
        ]);
        assert_eq!(format!("{}", path), "root/module/fragment");
    }

    #[test]
    fn test_provider_display() {
        let provider = ProgramTreeProvider::new("Test Tree");
        let display = format!("{}", provider);
        assert!(display.contains("Test Tree"));
        assert!(display.contains("view_size=0"));
    }
}
