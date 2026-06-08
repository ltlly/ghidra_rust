//! Rename command -- standalone entry point.
//!
//! Re-exports rename command types from the parent `rename` module for
//! direct use as a single-file import.
//!
//! Ported from `ghidra.app.plugin.core.rename`.

pub use super::cmd::{
    is_default_function_name, is_default_label_name, validate_symbol_name, RenameAndMoveCmd,
    RenameFunctionCmd, RenameLabelCmd, RenameNamespaceCmd, SetLabelPrimaryCmd, SetNamespaceCmd,
    MAX_SYMBOL_NAME_LENGTH,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use ghidra_core::symbol::SourceType;

    #[test]
    fn test_rename_label_cmd_standalone() {
        let cmd = RenameLabelCmd::new(Address::new(0x401000), "new_label", SourceType::UserDefined);
        assert_eq!(cmd.name(), "Rename Label");
        assert_eq!(cmd.address(), Address::new(0x401000));
        assert!(cmd.validate().is_ok());
    }

    #[test]
    fn test_rename_function_cmd_standalone() {
        let cmd = RenameFunctionCmd::new(
            Address::new(0x401000),
            "process_input",
            SourceType::UserDefined,
        );
        assert_eq!(cmd.name(), "Rename Function");
        assert!(cmd.validate().is_ok());
    }

    #[test]
    fn test_rename_and_move_standalone() {
        let cmd = RenameAndMoveCmd::rename_and_move(10, "new_name", 5, SourceType::Analysis);
        assert_eq!(cmd.new_name(), Some("new_name"));
        assert_eq!(cmd.new_namespace_id(), Some(5));
    }

    #[test]
    fn test_validate_standalone() {
        assert!(validate_symbol_name("valid_name").is_ok());
        assert!(validate_symbol_name("").is_err());
    }

    #[test]
    fn test_default_name_detection() {
        assert!(is_default_label_name("LAB_00401000"));
        assert!(!is_default_label_name("main"));
        assert!(is_default_function_name("FUN_00401000"));
        assert!(!is_default_function_name("main"));
    }
}
