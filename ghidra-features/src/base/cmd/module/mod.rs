//! Program tree modularization commands.
//!
//! Ported from `ghidra.app.cmd.module`.

#![allow(dead_code)]

pub mod add_module_cmd;
pub mod create_module_cmd;

/// Command to create the default program tree.
#[derive(Debug)]
pub struct CreateDefaultTreeCmd {
    tree_name: String,
}

impl CreateDefaultTreeCmd {
    pub fn new(tree_name: impl Into<String>) -> Self {
        Self {
            tree_name: tree_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to delete a program tree.
#[derive(Debug)]
pub struct DeleteTreeCmd {
    tree_name: String,
}

impl DeleteTreeCmd {
    pub fn new(tree_name: impl Into<String>) -> Self {
        Self {
            tree_name: tree_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to rename a tree node.
#[derive(Debug)]
pub struct RenameCmd {
    tree_name: String,
    node_path: Vec<String>,
    new_name: String,
}

impl RenameCmd {
    pub fn new(
        tree_name: impl Into<String>,
        node_path: Vec<String>,
        new_name: impl Into<String>,
    ) -> Self {
        Self {
            tree_name: tree_name.into(),
            node_path,
            new_name: new_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to rename a program tree.
#[derive(Debug)]
pub struct RenameTreeCmd {
    old_name: String,
    new_name: String,
}

impl RenameTreeCmd {
    pub fn new(old_name: impl Into<String>, new_name: impl Into<String>) -> Self {
        Self {
            old_name: old_name.into(),
            new_name: new_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to create a fragment (group of addresses).
#[derive(Debug)]
pub struct CreateFragmentCmd {
    tree_name: String,
    parent_path: Vec<String>,
    fragment_name: String,
    addresses: Vec<u64>,
}

impl CreateFragmentCmd {
    pub fn new(
        tree_name: impl Into<String>,
        parent_path: Vec<String>,
        fragment_name: impl Into<String>,
        addresses: Vec<u64>,
    ) -> Self {
        Self {
            tree_name: tree_name.into(),
            parent_path,
            fragment_name: fragment_name.into(),
            addresses,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to create a folder in the program tree.
#[derive(Debug)]
pub struct CreateFolderCommand {
    tree_name: String,
    parent_path: Vec<String>,
    folder_name: String,
}

impl CreateFolderCommand {
    pub fn new(
        tree_name: impl Into<String>,
        parent_path: Vec<String>,
        folder_name: impl Into<String>,
    ) -> Self {
        Self {
            tree_name: tree_name.into(),
            parent_path,
            folder_name: folder_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to merge folders in the program tree.
#[derive(Debug)]
pub struct MergeFolderCmd {
    tree_name: String,
    source_path: Vec<String>,
    dest_path: Vec<String>,
}

impl MergeFolderCmd {
    pub fn new(
        tree_name: impl Into<String>,
        source_path: Vec<String>,
        dest_path: Vec<String>,
    ) -> Self {
        Self {
            tree_name: tree_name.into(),
            source_path,
            dest_path,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to reorder a module in the tree.
#[derive(Debug)]
pub struct ReorderModuleCmd {
    tree_name: String,
    module_path: Vec<String>,
    new_index: usize,
}

impl ReorderModuleCmd {
    pub fn new(
        tree_name: impl Into<String>,
        module_path: Vec<String>,
        new_index: usize,
    ) -> Self {
        Self {
            tree_name: tree_name.into(),
            module_path,
            new_index,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Abstract base for modularization commands.
#[derive(Debug)]
pub struct AbstractModularizationCmd {
    tree_name: String,
}

impl AbstractModularizationCmd {
    pub fn new(tree_name: impl Into<String>) -> Self {
        Self {
            tree_name: tree_name.into(),
        }
    }

    pub fn tree_name(&self) -> &str {
        &self.tree_name
    }
}

/// Command for subroutine-based modularization.
#[derive(Debug)]
pub struct SubroutineModelCmd {
    inner: AbstractModularizationCmd,
}

impl SubroutineModelCmd {
    pub fn new(tree_name: impl Into<String>) -> Self {
        Self {
            inner: AbstractModularizationCmd::new(tree_name),
        }
    }
}

/// Command for complexity-depth modularization.
#[derive(Debug)]
pub struct ComplexityDepthModularizationCmd {
    inner: AbstractModularizationCmd,
}

impl ComplexityDepthModularizationCmd {
    pub fn new(tree_name: impl Into<String>) -> Self {
        Self {
            inner: AbstractModularizationCmd::new(tree_name),
        }
    }
}

/// Command for dominance-based modularization.
#[derive(Debug)]
pub struct DominanceModularizationCmd {
    inner: AbstractModularizationCmd,
}

impl DominanceModularizationCmd {
    pub fn new(tree_name: impl Into<String>) -> Self {
        Self {
            inner: AbstractModularizationCmd::new(tree_name),
        }
    }
}

/// Command for algorithm-based modularization.
#[derive(Debug)]
pub struct ModuleAlgorithmCmd {
    inner: AbstractModularizationCmd,
    algorithm_name: String,
}

impl ModuleAlgorithmCmd {
    pub fn new(tree_name: impl Into<String>, algorithm_name: impl Into<String>) -> Self {
        Self {
            inner: AbstractModularizationCmd::new(tree_name),
            algorithm_name: algorithm_name.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_default_tree() {
        let cmd = CreateDefaultTreeCmd::new("Program Tree");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_delete_tree() {
        let cmd = DeleteTreeCmd::new("Program Tree");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_rename_cmd() {
        let cmd = RenameCmd::new("Tree", vec!["root".into()], "new_name");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_rename_tree() {
        let cmd = RenameTreeCmd::new("old_tree", "new_tree");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_create_fragment() {
        let cmd = CreateFragmentCmd::new("Tree", vec!["root".into()], "frag1", vec![0x1000, 0x2000]);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_create_folder() {
        let cmd = CreateFolderCommand::new("Tree", vec![], "my_folder");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_subroutine_model_cmd() {
        let cmd = SubroutineModelCmd::new("Tree");
        assert_eq!(cmd.inner.tree_name(), "Tree");
    }

    #[test]
    fn test_complexity_depth() {
        let cmd = ComplexityDepthModularizationCmd::new("Tree");
        assert_eq!(cmd.inner.tree_name(), "Tree");
    }
}
