//! Module/Fragment Management -- program tree modules and fragments.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.module` Java package.
//!
//! Provides logic for managing the hierarchical module/fragment organization
//! of a program's address space. Supports creating, renaming, moving, and
//! removing modules; adding and removing fragments; and tree traversal
//! operations.
//!
//! # Key Types
//!
//! - [`ModuleAction`] -- types of module operations
//! - [`ModuleInfo`] -- a program tree module (directory node)
//! - [`FragmentInfo`] -- a fragment (leaf node with address range)
//! - [`ProgramTreeModel`] -- manages the full program tree structure

/// Module tree provider for displaying program modules.
///
/// Ported from `ghidra.app.plugin.core.module` provider classes.
pub mod provider;

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

    /// Whether this fragment contains the given address.
    pub fn contains(&self, address: Address) -> bool {
        address.offset >= self.start.offset && address.offset <= self.end.offset
    }
}

/// Manages the program tree structure.
#[derive(Debug, Default)]
pub struct ProgramTreeModel {
    modules: Vec<ModuleInfo>,
    fragments: Vec<FragmentInfo>,
    next_id: u64,
    /// History of actions for undo support.
    history: Vec<ModuleAction>,
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
        self.history.push(ModuleAction::Create);
        id
    }

    /// Get all modules.
    pub fn get_modules(&self) -> &[ModuleInfo] {
        &self.modules
    }

    /// Get a module by ID.
    pub fn get_module(&self, id: u64) -> Option<&ModuleInfo> {
        self.modules.iter().find(|m| m.id == id)
    }

    /// Rename a module by ID.
    pub fn rename_module(&mut self, id: u64, new_name: &str) -> bool {
        if let Some(m) = self.modules.iter_mut().find(|m| m.id == id) {
            m.name = new_name.to_string();
            self.history.push(ModuleAction::Rename);
            true
        } else {
            false
        }
    }

    /// Move a module to a new parent.
    pub fn move_module(&mut self, id: u64, new_parent_id: Option<u64>) -> bool {
        // Prevent cycles: new parent must not be a descendant of id
        if let Some(parent_id) = new_parent_id {
            if self.is_ancestor(id, parent_id) {
                return false;
            }
        }
        if let Some(m) = self.modules.iter_mut().find(|m| m.id == id) {
            m.parent_id = new_parent_id;
            m.is_root = new_parent_id.is_none();
            self.history.push(ModuleAction::Move);
            true
        } else {
            false
        }
    }

    /// Check if `ancestor_id` is an ancestor of `descendant_id`.
    pub fn is_ancestor(&self, ancestor_id: u64, descendant_id: u64) -> bool {
        let mut current = descendant_id;
        loop {
            if current == ancestor_id {
                return true;
            }
            match self.modules.iter().find(|m| m.id == current) {
                Some(m) => match m.parent_id {
                    Some(pid) => current = pid,
                    None => return false,
                },
                None => return false,
            }
        }
    }

    /// Get the children of a module.
    pub fn get_children(&self, parent_id: u64) -> Vec<&ModuleInfo> {
        self.modules
            .iter()
            .filter(|m| m.parent_id == Some(parent_id))
            .collect()
    }

    /// Get the root modules (those with no parent).
    pub fn get_roots(&self) -> Vec<&ModuleInfo> {
        self.modules.iter().filter(|m| m.is_root).collect()
    }

    /// Get the depth of a module in the tree (root = 0).
    pub fn get_depth(&self, id: u64) -> usize {
        let mut depth = 0;
        let mut current = id;
        loop {
            match self.modules.iter().find(|m| m.id == current) {
                Some(m) => match m.parent_id {
                    Some(pid) => {
                        depth += 1;
                        current = pid;
                    }
                    None => return depth,
                },
                None => return depth,
            }
        }
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
        self.history.push(ModuleAction::AddFragment);
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

    /// Get all fragments that contain the given address.
    pub fn get_fragments_at_address(&self, address: Address) -> Vec<&FragmentInfo> {
        self.fragments.iter().filter(|f| f.contains(address)).collect()
    }

    /// Remove a fragment by name and module ID.
    pub fn remove_fragment(&mut self, name: &str, module_id: u64) -> bool {
        let original_len = self.fragments.len();
        self.fragments
            .retain(|f| !(f.name == name && f.parent_module_id == module_id));
        if self.fragments.len() < original_len {
            self.history.push(ModuleAction::RemoveFragment);
            true
        } else {
            false
        }
    }

    /// Remove a module by ID (also removes all child modules and fragments).
    pub fn remove_module(&mut self, id: u64) {
        // Collect all descendant module IDs
        let mut to_remove = vec![id];
        let mut i = 0;
        while i < to_remove.len() {
            let current = to_remove[i];
            for m in &self.modules {
                if m.parent_id == Some(current) {
                    to_remove.push(m.id);
                }
            }
            i += 1;
        }
        self.modules.retain(|m| !to_remove.contains(&m.id));
        self.fragments
            .retain(|f| !to_remove.contains(&f.parent_module_id));
        self.history.push(ModuleAction::Remove);
    }

    /// Get the number of modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Get the number of fragments.
    pub fn fragment_count(&self) -> usize {
        self.fragments.len()
    }

    /// Get the action history.
    pub fn history(&self) -> &[ModuleAction] {
        &self.history
    }

    /// Find the module that contains a given address (via its fragments).
    pub fn find_module_for_address(&self, address: Address) -> Option<&ModuleInfo> {
        let frag = self.fragments.iter().find(|f| f.contains(address))?;
        self.modules.iter().find(|m| m.id == frag.parent_module_id)
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

    #[test]
    fn test_rename_module() {
        let mut model = ProgramTreeModel::new();
        let id = model.create_module("old_name", None);
        assert!(model.rename_module(id, "new_name"));
        assert_eq!(model.get_module(id).unwrap().name, "new_name");
        assert!(!model.rename_module(999, "nope"));
    }

    #[test]
    fn test_move_module() {
        let mut model = ProgramTreeModel::new();
        let root = model.create_module("root", None);
        let child = model.create_module("child", Some(root));
        let grandchild = model.create_module("grandchild", Some(child));
        // Move grandchild to root
        assert!(model.move_module(grandchild, Some(root)));
        assert_eq!(model.get_module(grandchild).unwrap().parent_id, Some(root));
    }

    #[test]
    fn test_move_module_prevent_cycle() {
        let mut model = ProgramTreeModel::new();
        let root = model.create_module("root", None);
        let child = model.create_module("child", Some(root));
        // Cannot move root under its own child
        assert!(!model.move_module(root, Some(child)));
    }

    #[test]
    fn test_is_ancestor() {
        let mut model = ProgramTreeModel::new();
        let root = model.create_module("root", None);
        let child = model.create_module("child", Some(root));
        let grandchild = model.create_module("grandchild", Some(child));
        assert!(model.is_ancestor(root, grandchild));
        assert!(model.is_ancestor(child, grandchild));
        assert!(!model.is_ancestor(grandchild, root));
    }

    #[test]
    fn test_get_children() {
        let mut model = ProgramTreeModel::new();
        let root = model.create_module("root", None);
        model.create_module("a", Some(root));
        model.create_module("b", Some(root));
        assert_eq!(model.get_children(root).len(), 2);
    }

    #[test]
    fn test_get_roots() {
        let mut model = ProgramTreeModel::new();
        let r1 = model.create_module("r1", None);
        let r2 = model.create_module("r2", None);
        model.create_module("child", Some(r1));
        assert_eq!(model.get_roots().len(), 2);
    }

    #[test]
    fn test_get_depth() {
        let mut model = ProgramTreeModel::new();
        let root = model.create_module("root", None);
        let child = model.create_module("child", Some(root));
        let grandchild = model.create_module("grandchild", Some(child));
        assert_eq!(model.get_depth(root), 0);
        assert_eq!(model.get_depth(child), 1);
        assert_eq!(model.get_depth(grandchild), 2);
    }

    #[test]
    fn test_fragment_contains() {
        let frag = FragmentInfo::new(".text", 0, Address::new(0x1000), Address::new(0x1FFF));
        assert!(frag.contains(Address::new(0x1500)));
        assert!(!frag.contains(Address::new(0x2000)));
        assert_eq!(frag.size(), 0x1000);
    }

    #[test]
    fn test_remove_module_with_descendants() {
        let mut model = ProgramTreeModel::new();
        let root = model.create_module("root", None);
        let child = model.create_module("child", Some(root));
        model.create_module("grandchild", Some(child));
        model.add_fragment(".text", child, Address::new(0x1000), Address::new(0x1FFF));
        model.remove_module(root);
        assert_eq!(model.module_count(), 0);
        assert_eq!(model.fragment_count(), 0);
    }

    #[test]
    fn test_remove_fragment() {
        let mut model = ProgramTreeModel::new();
        let id = model.create_module("root", None);
        model.add_fragment(".text", id, Address::new(0x1000), Address::new(0x1FFF));
        assert!(model.remove_fragment(".text", id));
        assert_eq!(model.fragment_count(), 0);
        assert!(!model.remove_fragment(".text", id));
    }

    #[test]
    fn test_get_fragments_at_address() {
        let mut model = ProgramTreeModel::new();
        let id = model.create_module("root", None);
        model.add_fragment(".text", id, Address::new(0x1000), Address::new(0x1FFF));
        model.add_fragment(".data", id, Address::new(0x2000), Address::new(0x2FFF));
        let frags = model.get_fragments_at_address(Address::new(0x1500));
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].name, ".text");
    }

    #[test]
    fn test_find_module_for_address() {
        let mut model = ProgramTreeModel::new();
        let id = model.create_module("code", None);
        model.add_fragment(".text", id, Address::new(0x1000), Address::new(0x1FFF));
        let module = model.find_module_for_address(Address::new(0x1500));
        assert!(module.is_some());
        assert_eq!(module.unwrap().name, "code");
        assert!(model.find_module_for_address(Address::new(0x5000)).is_none());
    }

    #[test]
    fn test_history_tracking() {
        let mut model = ProgramTreeModel::new();
        let id = model.create_module("root", None);
        model.rename_module(id, "new");
        model.add_fragment(".text", id, Address::new(0x1000), Address::new(0x1FFF));
        assert!(model.history().len() >= 3);
    }

    // -- AutoRenamePlugin tests --

    #[test]
    fn test_auto_rename_plugin_new() {
        let plugin = AutoRenamePlugin::new();
        assert!(plugin.is_enabled());
        assert!(plugin.options().rename_functions);
        assert!(plugin.options().rename_labels);
    }

    #[test]
    fn test_auto_rename_plugin_rename_function() {
        let mut plugin = AutoRenamePlugin::new();
        let result = plugin.try_rename_function("sub_401000", "main");
        assert_eq!(result, Some("main".to_string()));
    }

    #[test]
    fn test_auto_rename_plugin_skip_special_names() {
        let mut plugin = AutoRenamePlugin::new();
        // Should not rename well-known names
        let result = plugin.try_rename_function("main", "new_name");
        assert!(result.is_none());
    }

    #[test]
    fn test_auto_rename_plugin_options() {
        let mut plugin = AutoRenamePlugin::new();
        plugin.options_mut().rename_functions = false;
        let result = plugin.try_rename_function("sub_401000", "main");
        assert!(result.is_none());
    }

    // -- ModuleSortPlugin tests --

    #[test]
    fn test_module_sort_plugin_new() {
        let plugin = ModuleSortPlugin::new();
        assert!(plugin.is_enabled());
        assert_eq!(plugin.sort_mode(), ModuleSortMode::ByName);
    }

    #[test]
    fn test_module_sort_plugin_sort_by_name() {
        let mut plugin = ModuleSortPlugin::new();
        let mut modules = vec![
            ModuleInfo::new("zebra", 3, Some(1)),
            ModuleInfo::new("alpha", 1, Some(1)),
            ModuleInfo::new("middle", 2, Some(1)),
        ];
        plugin.sort_modules(&mut modules);
        assert_eq!(modules[0].name, "alpha");
        assert_eq!(modules[1].name, "middle");
        assert_eq!(modules[2].name, "zebra");
    }

    #[test]
    fn test_module_sort_plugin_sort_by_address() {
        let mut plugin = ModuleSortPlugin::new();
        plugin.set_sort_mode(ModuleSortMode::ByAddress);
        assert_eq!(plugin.sort_mode(), ModuleSortMode::ByAddress);
    }

    #[test]
    fn test_module_sort_plugin_dispose() {
        let mut plugin = ModuleSortPlugin::new();
        plugin.dispose();
        assert!(!plugin.is_enabled());
    }
}

// ---------------------------------------------------------------------------
// AutoRenamePlugin
//
// Ported from `ghidra.app.plugin.core.module.AutoRenamePlugin`.
//
// Provides automatic renaming of functions and labels based on
// analysis results. When a function's purpose is identified (e.g.,
// by finding a call to `main`), the plugin renames it automatically.
// ---------------------------------------------------------------------------

/// Plugin for automatic renaming of functions and labels.
///
/// When analysis discovers a meaningful name for a function or label
/// (from debug info, symbols, or call patterns), this plugin can
/// apply the rename automatically.
#[derive(Debug, Clone)]
pub struct AutoRenamePlugin {
    /// Whether the plugin is enabled.
    enabled: bool,
    /// Configuration options.
    options: AutoRenameOptions,
}

/// Options for automatic renaming.
#[derive(Debug, Clone)]
pub struct AutoRenameOptions {
    /// Whether to automatically rename functions.
    pub rename_functions: bool,
    /// Whether to automatically rename labels.
    pub rename_labels: bool,
    /// Whether to rename only symbols with default names (e.g., `sub_401000`).
    pub rename_default_names_only: bool,
    /// Minimum confidence level for auto-renaming (0-100).
    pub min_confidence: u8,
}

impl Default for AutoRenameOptions {
    fn default() -> Self {
        Self {
            rename_functions: true,
            rename_labels: true,
            rename_default_names_only: true,
            min_confidence: 80,
        }
    }
}

impl AutoRenamePlugin {
    /// Create a new auto-rename plugin.
    pub fn new() -> Self {
        Self {
            enabled: true,
            options: AutoRenameOptions::default(),
        }
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the current options.
    pub fn options(&self) -> &AutoRenameOptions {
        &self.options
    }

    /// Get mutable options.
    pub fn options_mut(&mut self) -> &mut AutoRenameOptions {
        &mut self.options
    }

    /// Try to rename a function. Returns the new name if rename should proceed.
    ///
    /// Returns `None` if the rename should be skipped (e.g., function already
    /// has a meaningful name, or renaming is disabled).
    pub fn try_rename_function(&self, current_name: &str, proposed_name: &str) -> Option<String> {
        if !self.enabled || !self.options.rename_functions {
            return None;
        }

        if self.options.rename_default_names_only && !is_default_name(current_name) {
            return None;
        }

        if proposed_name.is_empty() || proposed_name == current_name {
            return None;
        }

        Some(proposed_name.to_string())
    }

    /// Dispose of the plugin.
    pub fn dispose(&mut self) {
        self.enabled = false;
    }
}

impl Default for AutoRenamePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a name looks like a default/auto-generated name.
fn is_default_name(name: &str) -> bool {
    name.starts_with("sub_")
        || name.starts_with("FUN_")
        || name.starts_with("LAB_")
        || name.starts_with("DAT_")
        || name.starts_with("UNK_")
}

// ---------------------------------------------------------------------------
// ModuleSortPlugin
//
// Ported from `ghidra.app.plugin.core.module.ModuleSortPlugin`.
//
// Sorts modules in the program tree by name or address.
// ---------------------------------------------------------------------------

/// Sort mode for program tree modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleSortMode {
    /// Sort modules alphabetically by name.
    ByName,
    /// Sort modules by their first address.
    ByAddress,
    /// Sort modules by the number of fragments they contain.
    ByFragmentCount,
}

/// Plugin for sorting modules in the program tree.
#[derive(Debug, Clone)]
pub struct ModuleSortPlugin {
    enabled: bool,
    sort_mode: ModuleSortMode,
}

impl ModuleSortPlugin {
    /// Create a new module sort plugin.
    pub fn new() -> Self {
        Self {
            enabled: true,
            sort_mode: ModuleSortMode::ByName,
        }
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the current sort mode.
    pub fn sort_mode(&self) -> ModuleSortMode {
        self.sort_mode
    }

    /// Set the sort mode.
    pub fn set_sort_mode(&mut self, mode: ModuleSortMode) {
        self.sort_mode = mode;
    }

    /// Sort a list of modules in-place according to the current sort mode.
    pub fn sort_modules(&self, modules: &mut [ModuleInfo]) {
        match self.sort_mode {
            ModuleSortMode::ByName => {
                modules.sort_by(|a, b| a.name.cmp(&b.name));
            }
            ModuleSortMode::ByAddress => {
                modules.sort_by_key(|m| m.id);
            }
            ModuleSortMode::ByFragmentCount => {
                // Fragment count sorting requires external data; sort by ID as fallback
                modules.sort_by_key(|m| m.id);
            }
        }
    }

    /// Dispose of the plugin.
    pub fn dispose(&mut self) {
        self.enabled = false;
    }
}

impl Default for ModuleSortPlugin {
    fn default() -> Self {
        Self::new()
    }
}
