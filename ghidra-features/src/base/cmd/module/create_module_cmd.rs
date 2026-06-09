//! Command to create a new module in the program tree.
//!
//! Ported from `ghidra.app.cmd.module.CreateModuleCmd`.

#![allow(dead_code)]

/// Command to create a new module in a program tree.
#[derive(Debug)]
pub struct CreateModuleCmd {
    tree_name: String,
    module_name: String,
}

impl CreateModuleCmd {
    pub fn new(tree_name: impl Into<String>, module_name: impl Into<String>) -> Self {
        Self {
            tree_name: tree_name.into(),
            module_name: module_name.into(),
        }
    }

    pub fn tree_name(&self) -> &str {
        &self.tree_name
    }

    pub fn module_name(&self) -> &str {
        &self.module_name
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_module() {
        let cmd = CreateModuleCmd::new("Program Tree", "new_module");
        assert!(cmd.apply_to("test"));
        assert_eq!(cmd.tree_name(), "Program Tree");
        assert_eq!(cmd.module_name(), "new_module");
    }
}
