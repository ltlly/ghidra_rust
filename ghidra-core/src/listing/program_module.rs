//! Program module types for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.ProgramModule`.
//!
//! A module is an internal node in the program tree. It can contain children
//! which are either other modules or fragments.

use crate::addr::{Address, AddressRange};
use crate::listing::group::Group;
use crate::listing::program_fragment::ProgramFragment;

/// A module is an internal node in the program tree.
///
/// It can contain children which are either other modules or fragments.
/// Corresponds to Ghidra's `ProgramModule` interface.
pub trait ProgramModule: Group + std::fmt::Debug {
    /// Returns true if this module directly contains the given fragment.
    fn contains_fragment(&self, name: &str) -> bool;

    /// Returns true if this module directly contains the given module.
    fn contains_module(&self, name: &str) -> bool;

    /// The number of direct children.
    fn get_num_children(&self) -> usize;

    /// Get the index of the child with the given name, or None if not found.
    fn get_index(&self, name: &str) -> Option<usize>;

    /// Create a new child module with the given name.
    fn create_module(&mut self, module_name: &str) -> Result<(), String>;

    /// Create a new child fragment with the given name.
    fn create_fragment(&mut self, fragment_name: &str) -> Result<(), String>;

    /// Remove a child by name. Returns true if removed.
    fn remove_child(&mut self, name: &str) -> Result<bool, String>;

    /// Move a child to a new index position.
    fn move_child(&mut self, name: &str, index: usize) -> Result<(), String>;

    /// Returns true if the given module is a descendant of this module.
    fn is_descendant_module(&self, name: &str) -> bool;

    /// The first address (by user ordering of children).
    fn get_first_address(&self) -> Option<Address>;

    /// The last address (by user ordering of children).
    fn get_last_address(&self) -> Option<Address>;

    /// The address set covering all descendant fragments.
    fn get_address_set(&self) -> Vec<AddressRange>;

    /// A version tag for detecting undo/redo changes.
    fn get_version_tag(&self) -> u64;

    /// The current modification number of this module tree.
    fn get_modification_number(&self) -> u64;

    /// The tree ID this module belongs to.
    fn get_tree_id(&self) -> u64;
}

/// A simple in-memory implementation of [`ProgramModule`].
#[derive(Debug, Clone)]
pub struct ProgramModuleData {
    /// The module name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional alias.
    pub alias: Option<String>,
    /// The tree name.
    pub tree_name: String,
    /// Child names in order (modules and fragments interleaved).
    child_names: Vec<String>,
    /// Child fragments by name.
    fragments: std::collections::HashMap<String, ProgramFragment>,
    /// Number of parent modules.
    pub num_parents: usize,
    /// Whether this module has been deleted.
    pub deleted: bool,
    /// Version tag.
    version_tag: u64,
    /// Modification number.
    modification_number: u64,
    /// Tree ID.
    tree_id: u64,
}

impl ProgramModuleData {
    /// Create a new empty module.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
            alias: None,
            tree_name: "Program Tree".to_string(),
            child_names: Vec::new(),
            fragments: std::collections::HashMap::new(),
            num_parents: 0,
            deleted: false,
            version_tag: 0,
            modification_number: 0,
            tree_id: 0,
        }
    }

    /// Create a new module in a specific tree.
    pub fn in_tree(name: impl Into<String>, tree_name: impl Into<String>) -> Self {
        Self {
            tree_name: tree_name.into(),
            ..Self::new(name)
        }
    }

    /// Get a child fragment by name.
    pub fn get_fragment(&self, name: &str) -> Option<&ProgramFragment> {
        self.fragments.get(name)
    }

    /// Get a mutable child fragment by name.
    pub fn get_fragment_mut(&mut self, name: &str) -> Option<&mut ProgramFragment> {
        self.fragments.get_mut(name)
    }

    /// Returns all child names in order.
    pub fn get_child_names(&self) -> &[String] {
        &self.child_names
    }
}

impl Group for ProgramModuleData {
    fn get_comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn is_deleted(&self) -> bool {
        self.deleted
    }

    fn get_min_address(&self) -> Option<Address> {
        self.fragments.values().filter_map(|f| f.get_min_address()).min()
    }

    fn get_max_address(&self) -> Option<Address> {
        self.fragments.values().filter_map(|f| f.get_max_address()).max()
    }

    fn get_num_parents(&self) -> usize {
        self.num_parents
    }

    fn get_tree_name(&self) -> &str {
        &self.tree_name
    }
}

impl ProgramModule for ProgramModuleData {
    fn contains_fragment(&self, name: &str) -> bool {
        self.fragments.contains_key(name)
    }

    fn contains_module(&self, _name: &str) -> bool {
        // In this simplified implementation, modules are not tracked separately.
        false
    }

    fn get_num_children(&self) -> usize {
        self.child_names.len()
    }

    fn get_index(&self, name: &str) -> Option<usize> {
        self.child_names.iter().position(|n| n == name)
    }

    fn create_module(&mut self, module_name: &str) -> Result<(), String> {
        if self.child_names.contains(&module_name.to_string()) {
            return Err(format!("Child '{}' already exists", module_name));
        }
        self.child_names.push(module_name.to_string());
        self.modification_number += 1;
        Ok(())
    }

    fn create_fragment(&mut self, fragment_name: &str) -> Result<(), String> {
        if self.fragments.contains_key(fragment_name) {
            return Err(format!("Fragment '{}' already exists", fragment_name));
        }
        let frag = ProgramFragment::in_tree(fragment_name, &self.tree_name);
        self.fragments.insert(fragment_name.to_string(), frag);
        self.child_names.push(fragment_name.to_string());
        self.modification_number += 1;
        Ok(())
    }

    fn remove_child(&mut self, name: &str) -> Result<bool, String> {
        let name_string = name.to_string();
        if let Some(pos) = self.child_names.iter().position(|n| n == &name_string) {
            self.child_names.remove(pos);
            self.fragments.remove(&name_string);
            self.modification_number += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn move_child(&mut self, name: &str, index: usize) -> Result<(), String> {
        let name_string = name.to_string();
        if let Some(pos) = self.child_names.iter().position(|n| n == &name_string) {
            if pos == index {
                return Ok(());
            }
            let child = self.child_names.remove(pos);
            let insert_at = if index > pos { index - 1 } else { index };
            self.child_names.insert(insert_at, child);
            self.modification_number += 1;
            Ok(())
        } else {
            Err(format!("Child '{}' not found", name))
        }
    }

    fn is_descendant_module(&self, _name: &str) -> bool {
        false // Simplified -- would need recursive check in full implementation
    }

    fn get_first_address(&self) -> Option<Address> {
        self.get_min_address()
    }

    fn get_last_address(&self) -> Option<Address> {
        self.get_max_address()
    }

    fn get_address_set(&self) -> Vec<AddressRange> {
        self.fragments
            .values()
            .filter_map(|f| {
                let min = f.get_min_address()?;
                let max = f.get_max_address()?;
                Some(AddressRange::new(min, max))
            })
            .collect()
    }

    fn get_version_tag(&self) -> u64 {
        self.version_tag
    }

    fn get_modification_number(&self) -> u64 {
        self.modification_number
    }

    fn get_tree_id(&self) -> u64 {
        self.tree_id
    }
}

/// Thrown when an action would cause the program module structure to have a cycle.
#[derive(Debug, Clone)]
pub struct CircularDependencyException(pub String);

impl std::fmt::Display for CircularDependencyException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CircularDependencyException: {}", self.0)
    }
}

impl std::error::Error for CircularDependencyException {}

impl CircularDependencyException {
    pub fn new() -> Self {
        Self("Reference is invalid.".to_string())
    }

    pub fn with_message(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl Default for CircularDependencyException {
    fn default() -> Self {
        Self::new()
    }
}

/// Thrown when a fragment or module is added to a module and it is already a child.
#[derive(Debug, Clone)]
pub struct DuplicateGroupException(pub String);

impl std::fmt::Display for DuplicateGroupException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DuplicateGroupException: {}", self.0)
    }
}

impl std::error::Error for DuplicateGroupException {}

impl DuplicateGroupException {
    pub fn new() -> Self {
        Self("The fragment or module you are adding is already there.".to_string())
    }

    pub fn with_message(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl Default for DuplicateGroupException {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_new() {
        let module = ProgramModuleData::new("root");
        assert_eq!(module.get_name(), "root");
        assert_eq!(module.get_num_children(), 0);
        assert!(!module.is_deleted());
    }

    #[test]
    fn test_module_create_fragment() {
        let mut module = ProgramModuleData::new("root");
        module.create_fragment(".text").unwrap();
        module.create_fragment(".data").unwrap();
        assert_eq!(module.get_num_children(), 2);
        assert!(module.contains_fragment(".text"));
        assert!(module.contains_fragment(".data"));
    }

    #[test]
    fn test_module_duplicate_fragment() {
        let mut module = ProgramModuleData::new("root");
        module.create_fragment(".text").unwrap();
        assert!(module.create_fragment(".text").is_err());
    }

    #[test]
    fn test_module_remove_child() {
        let mut module = ProgramModuleData::new("root");
        module.create_fragment(".text").unwrap();
        assert!(module.remove_child(".text").unwrap());
        assert_eq!(module.get_num_children(), 0);
        assert!(!module.contains_fragment(".text"));
    }

    #[test]
    fn test_module_move_child() {
        let mut module = ProgramModuleData::new("root");
        module.create_fragment(".text").unwrap();
        module.create_fragment(".data").unwrap();
        module.create_fragment(".bss").unwrap();
        // Move .bss to index 0
        module.move_child(".bss", 0).unwrap();
        assert_eq!(module.get_child_names()[0], ".bss");
    }

    #[test]
    fn test_module_get_index() {
        let mut module = ProgramModuleData::new("root");
        module.create_fragment(".text").unwrap();
        module.create_fragment(".data").unwrap();
        assert_eq!(module.get_index(".text"), Some(0));
        assert_eq!(module.get_index(".data"), Some(1));
        assert_eq!(module.get_index(".bss"), None);
    }

    #[test]
    fn test_module_address_range() {
        let mut module = ProgramModuleData::new("root");
        module.create_fragment(".text").unwrap();
        if let Some(frag) = module.get_fragment_mut(".text") {
            frag.add_address(Address::new(0x1000));
            frag.add_address(Address::new(0x1001));
        }
        assert_eq!(module.get_min_address(), Some(Address::new(0x1000)));
        assert_eq!(module.get_max_address(), Some(Address::new(0x1001)));
    }

    #[test]
    fn test_module_in_tree() {
        let module = ProgramModuleData::in_tree("root", "MyTree");
        assert_eq!(module.get_tree_name(), "MyTree");
    }

    #[test]
    fn test_circular_dependency_exception() {
        let e = CircularDependencyException::new();
        assert!(e.to_string().contains("CircularDependencyException"));
    }

    #[test]
    fn test_duplicate_group_exception() {
        let e = DuplicateGroupException::with_message("already exists");
        assert!(e.to_string().contains("already exists"));
    }
}
