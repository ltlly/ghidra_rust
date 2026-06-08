//! Add-label command -- standalone entry point.
//!
//! Re-exports [`AddLabelCmd`] and related types from the parent
//! `label` module for direct use as a single-file import.
//!
//! Ported from `ghidra.app.cmd.label.AddLabelCmd`.

pub use super::{
    AddLabelCmd, AddUniqueLabelCmd, CreateNamespacesCmd, DeleteLabelCmd, DemanglerCmd,
    ExternalEntryCmd, PinSymbolCmd, RenameLabelCmd, SetLabelPrimaryCmd, SourceType,
};

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
    fn test_set_primary() {
        let cmd = SetLabelPrimaryCmd::new(0x401000, "main");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_pin_symbol() {
        let cmd = PinSymbolCmd::new(0x401000, true);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_demangler() {
        let cmd = DemanglerCmd::new(0x401000, "_ZN3Foo3BarEv");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_external_entry() {
        let cmd = ExternalEntryCmd::new(0x401000, "extern_func");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_create_namespaces() {
        let cmd = CreateNamespacesCmd::new(vec!["std".into(), "string".into()]);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_label_source_types() {
        assert_ne!(SourceType::UserDefined, SourceType::Analysis);
        assert_ne!(SourceType::Imported, SourceType::Default);
    }
}
