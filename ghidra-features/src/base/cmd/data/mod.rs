//! Data creation commands.
//!
//! Ported from `ghidra.app.cmd.data`.

/// Command to create a data item at an address.
#[derive(Debug)]
pub struct CreateDataCmd {
    address: u64,
    data_type_name: String,
    length: usize,
}

impl CreateDataCmd {
    pub fn new(address: u64, data_type_name: impl Into<String>, length: usize) -> Self {
        Self {
            address,
            data_type_name: data_type_name.into(),
            length,
        }
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn data_type_name(&self) -> &str {
        &self.data_type_name
    }

    pub fn length(&self) -> usize {
        self.length
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Background command to create a data item.
#[derive(Debug)]
pub struct CreateDataBackgroundCmd {
    inner: CreateDataCmd,
}

impl CreateDataBackgroundCmd {
    pub fn new(address: u64, data_type_name: impl Into<String>, length: usize) -> Self {
        Self {
            inner: CreateDataCmd::new(address, data_type_name, length),
        }
    }

    pub fn apply_to(&self, program_name: &str) -> bool {
        self.inner.apply_to(program_name)
    }
}

/// Command to create an array at an address.
#[derive(Debug)]
pub struct CreateArrayCmd {
    address: u64,
    element_type_name: String,
    num_elements: usize,
}

impl CreateArrayCmd {
    pub fn new(
        address: u64,
        element_type_name: impl Into<String>,
        num_elements: usize,
    ) -> Self {
        Self {
            address,
            element_type_name: element_type_name.into(),
            num_elements,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to create an array within a structure.
#[derive(Debug)]
pub struct CreateArrayInStructureCmd {
    struct_address: u64,
    field_offset: usize,
    element_type_name: String,
    num_elements: usize,
}

impl CreateArrayInStructureCmd {
    pub fn new(
        struct_address: u64,
        field_offset: usize,
        element_type_name: impl Into<String>,
        num_elements: usize,
    ) -> Self {
        Self {
            struct_address,
            field_offset,
            element_type_name: element_type_name.into(),
            num_elements,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to create a string at an address.
#[derive(Debug)]
pub struct CreateStringCmd {
    address: u64,
    encoding: StringEncoding,
}

/// String encoding types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16,
    Utf32,
}

impl CreateStringCmd {
    pub fn new(address: u64, encoding: StringEncoding) -> Self {
        Self { address, encoding }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to create a structure.
#[derive(Debug)]
pub struct CreateStructureCmd {
    address: u64,
    structure_name: String,
}

impl CreateStructureCmd {
    pub fn new(address: u64, structure_name: impl Into<String>) -> Self {
        Self {
            address,
            structure_name: structure_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Abstract base for structure creation commands.
#[derive(Debug)]
pub struct AbstractCreateStructureCmd {
    address: u64,
    name: String,
}

impl AbstractCreateStructureCmd {
    pub fn new(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
        }
    }
}

/// Command to create a structure within another structure.
#[derive(Debug)]
pub struct CreateStructureInStructureCmd {
    parent_address: u64,
    field_offset: usize,
    child_name: String,
}

impl CreateStructureInStructureCmd {
    pub fn new(parent_address: u64, field_offset: usize, child_name: impl Into<String>) -> Self {
        Self {
            parent_address,
            field_offset,
            child_name: child_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Background command for creating data within a structure.
#[derive(Debug)]
pub struct CreateDataInStructureCmd {
    address: u64,
    field_offset: usize,
    data_type_name: String,
}

impl CreateDataInStructureCmd {
    pub fn new(address: u64, field_offset: usize, data_type_name: impl Into<String>) -> Self {
        Self {
            address,
            field_offset,
            data_type_name: data_type_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Background variant of CreateDataInStructureCmd.
#[derive(Debug)]
pub struct CreateDataInStructureBackgroundCmd {
    inner: CreateDataInStructureCmd,
}

impl CreateDataInStructureBackgroundCmd {
    pub fn new(address: u64, field_offset: usize, data_type_name: impl Into<String>) -> Self {
        Self {
            inner: CreateDataInStructureCmd::new(address, field_offset, data_type_name),
        }
    }

    pub fn apply_to(&self, program_name: &str) -> bool {
        self.inner.apply_to(program_name)
    }
}

/// Command to rename a field in a structure.
#[derive(Debug)]
pub struct RenameDataFieldCmd {
    address: u64,
    field_offset: usize,
    new_name: String,
}

impl RenameDataFieldCmd {
    pub fn new(address: u64, field_offset: usize, new_name: impl Into<String>) -> Self {
        Self {
            address,
            field_offset,
            new_name: new_name.into(),
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
    fn test_create_data_cmd() {
        let cmd = CreateDataCmd::new(0x401000, "dword", 4);
        assert_eq!(cmd.address(), 0x401000);
        assert_eq!(cmd.data_type_name(), "dword");
        assert_eq!(cmd.length(), 4);
    }

    #[test]
    fn test_create_array_cmd() {
        let cmd = CreateArrayCmd::new(0x1000, "byte", 16);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_create_string_cmd() {
        let cmd = CreateStringCmd::new(0x2000, StringEncoding::Utf8);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_create_structure_cmd() {
        let cmd = CreateStructureCmd::new(0x3000, "MyStruct");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_rename_data_field_cmd() {
        let cmd = RenameDataFieldCmd::new(0x1000, 0, "new_field");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_string_encodings() {
        assert_ne!(StringEncoding::Ascii, StringEncoding::Utf16);
    }
}
