//! Create-function command -- standalone entry point.
//!
//! Re-exports [`CreateFunctionCmd`] and related types from the parent
//! `function` module for direct use as a single-file import.
//!
//! Ported from `ghidra.app.cmd.function.CreateFunctionCmd`.

pub use super::{
    ApplyFunctionDataTypesCmd, ApplyFunctionSignatureCmd, CaptureFunctionDataTypesCmd,
    CreateExternalFunctionCmd, CreateFunctionCmd, CreateFunctionDefinitionCmd,
    CreateMultipleFunctionsCmd, CreateThunkFunctionCmd, FunctionRenameOption, SourceType,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_function_basic() {
        let cmd = CreateFunctionCmd::new(
            Some("main".into()),
            vec![0x401000],
            vec![(0x401000, 0x401100)],
            SourceType::UserDefined,
        );
        assert_eq!(cmd.name(), Some("main"));
        assert_eq!(cmd.entries(), &[0x401000]);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_create_function_anonymous() {
        let cmd = CreateFunctionCmd::new(None, vec![0x402000], vec![], SourceType::Analysis);
        assert!(cmd.name().is_none());
    }

    #[test]
    fn test_create_function_with_options() {
        let cmd = CreateFunctionCmd::new(None, vec![0x1000], vec![], SourceType::Analysis)
            .with_find_entry_point(true)
            .with_recreate(true);
        assert!(cmd.find_entry_point);
        assert!(cmd.recreate);
    }

    #[test]
    fn test_create_external_function() {
        let cmd = CreateExternalFunctionCmd::new("libc.so", "malloc");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_create_thunk_function() {
        let cmd = CreateThunkFunctionCmd::new(0x401000, 0x402000);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_create_multiple_functions() {
        let cmd = CreateMultipleFunctionsCmd::new(vec![0x1000, 0x2000], SourceType::Analysis);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_function_rename_options() {
        assert_ne!(
            FunctionRenameOption::RenameToLabel,
            FunctionRenameOption::KeepCurrentName
        );
    }

    #[test]
    fn test_source_types() {
        assert_ne!(SourceType::UserDefined, SourceType::Analysis);
        assert_ne!(SourceType::Imported, SourceType::Default);
    }
}
