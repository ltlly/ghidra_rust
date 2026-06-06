//! Rename operations for Ghidra programs.
//!
//! This module ports Ghidra's rename functionality from
//! `ghidra.app.plugin.core` to Rust. It provides commands and plugin
//! logic for renaming labels, functions, namespaces, and moving symbols
//! between namespaces.
//!
//! - [`RenameAction`] -- enum of available rename actions
//! - [`RenameActionContext`] -- context carrying address/symbol information
//! - [`RenamePlugin`] -- controller providing action enablement and command creation
//! - Commands: [`RenameLabelCmd`], [`RenameFunctionCmd`],
//!   [`RenameNamespaceCmd`], [`SetNamespaceCmd`], [`RenameAndMoveCmd`],
//!   [`SetLabelPrimaryCmd`]
//! - Validation: [`validate_symbol_name`], [`is_default_label_name`],
//!   [`is_default_function_name`]
//!
//! # Architecture
//!
//! The module separates validation and command objects ([`cmd`]) from
//! action dispatching and enablement logic ([`plugin`]). GUI dialogs
//! are not ported; the plugin provides methods that return command
//! objects suitable for execution by any frontend.

pub mod cmd;
pub mod plugin;

pub use cmd::{
    is_default_function_name, is_default_label_name, validate_symbol_name, RenameAndMoveCmd,
    RenameFunctionCmd, RenameLabelCmd, RenameNamespaceCmd, SetLabelPrimaryCmd, SetNamespaceCmd,
    MAX_SYMBOL_NAME_LENGTH,
};
pub use plugin::{RenameAction, RenameActionContext, RenamePlugin};

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use ghidra_core::symbol::SourceType;

    #[test]
    fn test_max_symbol_name_length() {
        assert!(MAX_SYMBOL_NAME_LENGTH > 0);
        assert!(MAX_SYMBOL_NAME_LENGTH <= 10_000);
    }

    #[test]
    fn test_validate_symbol_name_basic() {
        assert!(validate_symbol_name("valid_name").is_ok());
        assert!(validate_symbol_name("_underscore").is_ok());
        assert!(validate_symbol_name("a123").is_ok());
    }

    #[test]
    fn test_validate_symbol_name_empty() {
        assert!(validate_symbol_name("").is_err());
    }

    #[test]
    fn test_validate_symbol_name_too_long() {
        let long_name = "a".repeat(MAX_SYMBOL_NAME_LENGTH + 1);
        assert!(validate_symbol_name(&long_name).is_err());
    }

    #[test]
    fn test_is_default_label_name() {
        assert!(is_default_label_name("LAB_00401000"));
        assert!(is_default_label_name("DAT_00401000"));
        assert!(!is_default_label_name("main"));
        assert!(!is_default_label_name(""));
    }

    #[test]
    fn test_is_default_function_name() {
        assert!(is_default_function_name("FUN_00401000"));
        assert!(!is_default_function_name("main"));
        assert!(!is_default_function_name(""));
    }

    #[test]
    fn test_rename_action_display() {
        for action in [
            RenameAction::RenameLabel,
            RenameAction::RenameFunction,
            RenameAction::RenameNamespace,
            RenameAction::MoveToNamespace,
            RenameAction::SetLabelPrimary,
            RenameAction::RenameAndMove,
        ] {
            assert!(!action.display_name().is_empty());
        }
    }

    #[test]
    fn test_rename_action_key_binding() {
        assert_eq!(RenameAction::RenameLabel.key_binding(), Some("L"));
        assert_eq!(RenameAction::RenameFunction.key_binding(), Some("L"));
        assert_eq!(RenameAction::RenameNamespace.key_binding(), None);
        assert_eq!(RenameAction::MoveToNamespace.key_binding(), None);
        assert_eq!(RenameAction::SetLabelPrimary.key_binding(), None);
        assert_eq!(RenameAction::RenameAndMove.key_binding(), None);
    }

    #[test]
    fn test_rename_action_context_on_label() {
        let ctx = RenameActionContext::on_label(
            Address::new(0x401000),
            SourceType::UserDefined,
            false,
            false,
        );
        assert_eq!(ctx.address, Address::new(0x401000));
        assert!(ctx.on_label_field);
        assert!(!ctx.on_function);
    }

    #[test]
    fn test_rename_action_context_on_function() {
        let ctx = RenameActionContext::on_function(
            Address::new(0x401000),
            SourceType::UserDefined,
            false,
        );
        assert_eq!(ctx.address, Address::new(0x401000));
        assert!(ctx.on_function);
    }

    #[test]
    fn test_rename_label_cmd() {
        let cmd = RenameLabelCmd::new(
            Address::new(0x401000),
            "new_label",
            SourceType::UserDefined,
        );
        assert_eq!(cmd.address(), Address::new(0x401000));
        assert_eq!(cmd.new_name(), "new_label");
        assert_eq!(cmd.name(), "Rename Label");
    }

    #[test]
    fn test_rename_label_cmd_validate() {
        let cmd = RenameLabelCmd::new(
            Address::new(0x401000),
            "valid_name",
            SourceType::UserDefined,
        );
        assert!(cmd.validate().is_ok());
    }

    #[test]
    fn test_rename_label_cmd_validate_empty() {
        let cmd = RenameLabelCmd::new(
            Address::new(0x401000),
            "",
            SourceType::UserDefined,
        );
        assert!(cmd.validate().is_err());
    }

    #[test]
    fn test_rename_function_cmd() {
        let cmd = RenameFunctionCmd::new(
            Address::new(0x401000),
            "my_func",
            SourceType::UserDefined,
        );
        assert_eq!(cmd.new_name(), "my_func");
    }

    #[test]
    fn test_rename_namespace_cmd() {
        let cmd = RenameNamespaceCmd::new(
            42u64,
            "MyNS",
            SourceType::UserDefined,
        );
        assert!(!cmd.name().is_empty());
    }

    #[test]
    fn test_set_label_primary_cmd() {
        let cmd = SetLabelPrimaryCmd::new(
            Address::new(0x401000),
            "primary_label",
        );
        assert!(!cmd.name().is_empty());
    }

    #[test]
    fn test_rename_action_equality() {
        assert_eq!(RenameAction::RenameLabel, RenameAction::RenameLabel);
        assert_ne!(RenameAction::RenameLabel, RenameAction::RenameFunction);
    }

    #[test]
    fn test_rename_action_debug() {
        let action = RenameAction::RenameLabel;
        let dbg = format!("{:?}", action);
        assert!(!dbg.is_empty());
    }
}
