//! Module/Fragment Management -- program tree modules and fragments.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.module` Java package.
//!
//! Provides logic for managing the hierarchical module/fragment organization
//! of a program's address space.

use ghidra_core::Address;

/// Action types for module operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleAction {
    /// Create a new module (subtree).
    Create,
    /// Rename a module.
    Rename,
    /// Move a module to a new parent.
    Move,
    /// Remove a module.
    Remove,
    /// Add a fragment (address range) to a module.
    AddFragment,
    /// Remove a fragment from a module.
    RemoveFragment,
}

/// A program tree module (directory node).
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Module name.
    pub name: String,
    /// Unique module ID.
    pub id: u64,
    /// Parent module ID (None for root).
    pub parent_id: Option<u64>,
    /// Whether this module is the root of the tree.
    pub is_root: bool,
}

impl ModuleInfo {
    /// Create a new module info.
    pub fn new(name: impl Into<String>, id: u64, parent_id: Option<u64>) -> Self {
        Self {
            name: name.into(),
            id,
            parent_id,
            is_root: parent_id.is_none(),
        }
    }
}

/// A program tree fragment (leaf node containing address ranges).
#[derive(Debug, Clone)]
pub struct FragmentInfo {
    /// Fragment name.
    pub name: String,
    /// The parent module ID.
    pub parent_module_id: u64,
    /// Start address of the fragment.
    pub start: Address,
    /// End address of the fragment.
    pub end: Address,
}

impl FragmentInfo {
    /// Create a new fragment info.
    pub fn new(
        name: impl Into<String>,
        parent_module_id: u64,
        start: Address,
        end: Address,
    ) -> Self {
        Self {
            name: name.into(),
            parent_module_id,
            start,
            end,
        }
    }

    /// The size of this fragment in bytes.
    pub fn size(&self) -> u64 {
        self.end.offset.saturating_sub(self.start.offset) + 1
    }
}

/// Manages the program tree structure.
#[derive(Debug, Default)]
pub struct ProgramTreeModel {
    modules: Vec<ModuleInfo>,
    fragments: Vec<FragmentInfo>,
    next_id: u64,
}

impl ProgramTreeModel {
    /// Create a new program tree model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new module.
    pub fn create_module(&mut self, name: &str, parent_id: Option<u64>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.modules.push(ModuleInfo::new(name, id, parent_id));
        id
    }

    /// Get all modules.
    pub fn get_modules(&self) -> &[ModuleInfo] {
        &self.modules
    }

    /// Add a fragment to a module.
    pub fn add_fragment(
        &mut self,
        name: &str,
        module_id: u64,
        start: Address,
        end: Address,
    ) {
        self.fragments
            .push(FragmentInfo::new(name, module_id, start, end));
    }

    /// Get all fragments.
    pub fn get_fragments(&self) -> &[FragmentInfo] {
        &self.fragments
    }

    /// Get fragments for a specific module.
    pub fn get_fragments_for_module(&self, module_id: u64) -> Vec<&FragmentInfo> {
        self.fragments
            .iter()
            .filter(|f| f.parent_module_id == module_id)
            .collect()
    }

    /// Remove a module by ID.
    pub fn remove_module(&mut self, id: u64) {
        self.modules.retain(|m| m.id != id);
        self.fragments.retain(|f| f.parent_module_id != id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_get_module() {
        let mut model = ProgramTreeModel::new();
        let id = model.create_module("root", None);
        assert_eq!(model.get_modules().len(), 1);
        assert!(model.get_modules()[0].is_root);
        let _child = model.create_module("child", Some(id));
        assert_eq!(model.get_modules().len(), 2);
    }

    #[test]
    fn test_add_fragment() {
        let mut model = ProgramTreeModel::new();
        let id = model.create_module("root", None);
        model.add_fragment(".text", id, Address::new(0x1000), Address::new(0x1FFF));
        model.add_fragment(".data", id, Address::new(0x2000), Address::new(0x2FFF));
        assert_eq!(model.get_fragments().len(), 2);
    }

    #[test]
    fn test_get_fragments_for_module() {
        let mut model = ProgramTreeModel::new();
        let id1 = model.create_module("code", None);
        let id2 = model.create_module("data", None);
        model.add_fragment(".text", id1, Address::new(0x1000), Address::new(0x1FFF));
        model.add_fragment(".data", id2, Address::new(0x2000), Address::new(0x2FFF));
        assert_eq!(model.get_fragments_for_module(id1).len(), 1);
        assert_eq!(model.get_fragments_for_module(id2).len(), 1);
    }

    #[test]
    fn test_remove_module() {
        let mut model = ProgramTreeModel::new();
        let id = model.create_module("root", None);
        model.add_fragment(".text", id, Address::new(0x1000), Address::new(0x1FFF));
        model.remove_module(id);
        assert_eq!(model.get_modules().len(), 0);
        assert_eq!(model.get_fragments().len(), 0);
    }
}
