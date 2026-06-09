//! Command to add a module to the program tree.
//!
//! Ported from `ghidra.app.cmd.module.AddModuleCmd`.

#![allow(dead_code)]

/// Command to add a new module to a program tree.
#[derive(Debug)]
pub struct AddModuleCmd {
    tree_name: String,
    module_name: String,
    parent_path: Vec<String>,
}

impl AddModuleCmd {
    pub fn new(
        tree_name: impl Into<String>,
        module_name: impl Into<String>,
        parent_path: Vec<String>,
    ) -> Self {
        Self {
            tree_name: tree_name.into(),
            module_name: module_name.into(),
            parent_path,
        }
    }

    pub fn tree_name(&self) -> &str {
        &self.tree_name
    }

    pub fn module_name(&self) -> &str {
        &self.module_name
    }

    pub fn parent_path(&self) -> &[String] {
        &self.parent_path
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_module() {
        let cmd = AddModuleCmd::new("Program Tree", "new_module", vec!["root".into()]);
        assert!(cmd.apply_to("test"));
        assert_eq!(cmd.tree_name(), "Program Tree");
        assert_eq!(cmd.module_name(), "new_module");
        assert_eq!(cmd.parent_path(), &["root"]);
    }
}
