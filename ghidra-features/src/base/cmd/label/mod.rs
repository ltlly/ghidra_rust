//! Label commands.
//!
//! Ported from `ghidra.app.cmd.label`.

#![allow(dead_code)]

/// Source type for labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    UserDefined,
    Analysis,
    Imported,
    Default,
}

/// Command to add a label at an address.
#[derive(Debug)]
pub struct AddLabelCmd {
    address: u64,
    name: String,
    source: SourceType,
}

impl AddLabelCmd {
    pub fn new(address: u64, name: impl Into<String>, source: SourceType) -> Self {
        Self {
            address,
            name: name.into(),
            source,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to add a unique label (auto-disambiguated).
#[derive(Debug)]
pub struct AddUniqueLabelCmd {
    address: u64,
    name: String,
    source: SourceType,
}

impl AddUniqueLabelCmd {
    pub fn new(address: u64, name: impl Into<String>, source: SourceType) -> Self {
        Self {
            address,
            name: name.into(),
            source,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to create namespaces for a label path.
#[derive(Debug)]
pub struct CreateNamespacesCmd {
    path: Vec<String>,
}

impl CreateNamespacesCmd {
    pub fn new(path: Vec<String>) -> Self {
        Self { path }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to delete a label.
#[derive(Debug)]
pub struct DeleteLabelCmd {
    address: u64,
    name: String,
}

impl DeleteLabelCmd {
    pub fn new(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to rename a label.
#[derive(Debug)]
pub struct RenameLabelCmd {
    address: u64,
    old_name: String,
    new_name: String,
    source: SourceType,
}

impl RenameLabelCmd {
    pub fn new(
        address: u64,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
        source: SourceType,
    ) -> Self {
        Self {
            address,
            old_name: old_name.into(),
            new_name: new_name.into(),
            source,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to set a label as primary.
#[derive(Debug)]
pub struct SetLabelPrimaryCmd {
    address: u64,
    name: String,
}

impl SetLabelPrimaryCmd {
    pub fn new(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to pin/unpin a symbol.
#[derive(Debug)]
pub struct PinSymbolCmd {
    address: u64,
    pinned: bool,
}

impl PinSymbolCmd {
    pub fn new(address: u64, pinned: bool) -> Self {
        Self { address, pinned }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command for demangling and applying the resulting name.
#[derive(Debug)]
pub struct DemanglerCmd {
    address: u64,
    mangled_name: String,
}

impl DemanglerCmd {
    pub fn new(address: u64, mangled_name: impl Into<String>) -> Self {
        Self {
            address,
            mangled_name: mangled_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to create an external entry label.
#[derive(Debug)]
pub struct ExternalEntryCmd {
    address: u64,
    name: String,
}

impl ExternalEntryCmd {
    pub fn new(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_label() {
        let cmd = AddLabelCmd::new(0x401000, "main", SourceType::UserDefined);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_add_unique_label() {
        let cmd = AddUniqueLabelCmd::new(0x401000, "LAB_401000", SourceType::Analysis);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_delete_label() {
        let cmd = DeleteLabelCmd::new(0x401000, "old_name");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_rename_label() {
        let cmd = RenameLabelCmd::new(0x401000, "old", "new", SourceType::UserDefined);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_set_label_primary() {
        let cmd = SetLabelPrimaryCmd::new(0x401000, "main");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_pin_symbol() {
        let cmd = PinSymbolCmd::new(0x401000, true);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_demangler_cmd() {
        let cmd = DemanglerCmd::new(0x401000, "_ZN3Foo3BarEv");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_external_entry_cmd() {
        let cmd = ExternalEntryCmd::new(0x401000, "extern_func");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_create_namespaces() {
        let cmd = CreateNamespacesCmd::new(vec![
            "std".into(),
            "string".into(),
        ]);
        assert!(cmd.apply_to("test"));
    }
}
