//! Create-data command -- standalone entry point.
//!
//! Re-exports [`CreateDataCmd`] and related types from the parent
//! `data` module for direct use as a single-file import.
//!
//! Ported from `ghidra.app.cmd.data.CreateDataCmd`.

pub use super::{
    AbstractCreateStructureCmd, CreateArrayCmd, CreateArrayInStructureCmd, CreateDataBackgroundCmd,
    CreateDataCmd, CreateDataInStructureBackgroundCmd, CreateDataInStructureCmd, CreateStringCmd,
    CreateStructureCmd, CreateStructureInStructureCmd, RenameDataFieldCmd, StringEncoding,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_data_basic() {
        let cmd = CreateDataCmd::new(0x401000, "dword", 4);
        assert_eq!(cmd.address(), 0x401000);
        assert_eq!(cmd.data_type_name(), "dword");
        assert_eq!(cmd.length(), 4);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_create_data_background() {
        let cmd = CreateDataBackgroundCmd::new(0x1000, "byte", 1);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_create_array() {
        let cmd = CreateArrayCmd::new(0x2000, "word", 8);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_create_string() {
        let cmd = CreateStringCmd::new(0x3000, StringEncoding::Ascii);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_string_encodings() {
        assert_ne!(StringEncoding::Ascii, StringEncoding::Utf16);
        assert_ne!(StringEncoding::Utf8, StringEncoding::Utf32);
    }

    #[test]
    fn test_create_structure() {
        let cmd = CreateStructureCmd::new(0x4000, "MyStruct");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_rename_data_field() {
        let cmd = RenameDataFieldCmd::new(0x1000, 0, "field_name");
        assert!(cmd.apply_to("test"));
    }
}
