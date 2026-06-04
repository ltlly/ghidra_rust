//! Data Plugin -- manage data types at addresses.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.data` Java package.
//!
//! Provides model-level logic for creating and managing data items
//! (typed data) in a program's listing, including primitive types,
//! arrays, structures, and strings.

use ghidra_core::Address;
use std::collections::BTreeMap;

/// The type of data item creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAction {
    /// Create a byte data item.
    Byte,
    /// Create a word (16-bit) data item.
    Word,
    /// Create a dword (32-bit) data item.
    DWord,
    /// Create a qword (64-bit) data item.
    QWord,
    /// Create a float data item.
    Float,
    /// Create a double data item.
    Double,
    /// Create an ASCII string.
    String,
    /// Create a Unicode string.
    Unicode,
    /// Create an array of data items.
    Array,
    /// Create a pointer.
    Pointer,
    /// Create a structure.
    Structure,
    /// Create an undefined data item.
    Undefined,
}

impl DataAction {
    /// Return the default size in bytes for this data type.
    pub fn default_size(&self) -> usize {
        match self {
            Self::Byte | Self::Undefined => 1,
            Self::Word => 2,
            Self::DWord | Self::Float => 4,
            Self::QWord | Self::Double | Self::Pointer => 8,
            Self::String => 0, // variable
            Self::Unicode => 0,
            Self::Array => 0,
            Self::Structure => 0,
        }
    }

    /// Return the display name of this data type.
    pub fn display_name(&self) -> &str {
        match self {
            Self::Byte => "byte",
            Self::Word => "word",
            Self::DWord => "dword",
            Self::QWord => "qword",
            Self::Float => "float",
            Self::Double => "double",
            Self::String => "string",
            Self::Unicode => "unicode",
            Self::Array => "array",
            Self::Pointer => "pointer",
            Self::Structure => "structure",
            Self::Undefined => "undefined",
        }
    }
}

/// A data item in the listing.
#[derive(Debug, Clone)]
pub struct DataItem {
    /// The address of this data item.
    pub address: Address,
    /// The data type.
    pub data_action: DataAction,
    /// The size in bytes.
    pub size: usize,
    /// The data type name.
    pub type_name: String,
    /// The value (as a display string).
    pub value: String,
    /// The label at this address (if any).
    pub label: Option<String>,
}

impl DataItem {
    /// Create a new data item.
    pub fn new(address: Address, data_action: DataAction, size: usize) -> Self {
        Self {
            address,
            data_action,
            size,
            type_name: data_action.display_name().to_string(),
            value: String::new(),
            label: None,
        }
    }
}

/// Model for managing data items in the listing.
#[derive(Debug, Default)]
pub struct DataPluginModel {
    items: BTreeMap<u64, DataItem>,
}

impl DataPluginModel {
    /// Create a new data plugin model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a data item at the given address.
    pub fn create_data(
        &mut self,
        address: Address,
        data_action: DataAction,
        size: usize,
    ) -> Result<(), String> {
        if self.items.contains_key(&address.offset) {
            return Err(format!(
                "Data item already exists at address {}",
                address
            ));
        }
        let item = DataItem::new(address, data_action, size);
        self.items.insert(address.offset, item);
        Ok(())
    }

    /// Remove the data item at the given address.
    pub fn remove_data(&mut self, address: Address) -> Option<DataItem> {
        self.items.remove(&address.offset)
    }

    /// Get the data item at the given address.
    pub fn get_data(&self, address: Address) -> Option<&DataItem> {
        self.items.get(&address.offset)
    }

    /// Get all data items.
    pub fn get_all_items(&self) -> Vec<&DataItem> {
        self.items.values().collect()
    }

    /// Return the number of data items.
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Clear all data items.
    pub fn clear(&mut self) {
        self.items.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_action_display() {
        assert_eq!(DataAction::Byte.display_name(), "byte");
        assert_eq!(DataAction::QWord.display_name(), "qword");
    }

    #[test]
    fn test_data_action_size() {
        assert_eq!(DataAction::Byte.default_size(), 1);
        assert_eq!(DataAction::DWord.default_size(), 4);
        assert_eq!(DataAction::QWord.default_size(), 8);
    }

    #[test]
    fn test_create_and_get_data() {
        let mut model = DataPluginModel::new();
        model
            .create_data(Address::new(0x1000), DataAction::DWord, 4)
            .unwrap();
        let item = model.get_data(Address::new(0x1000)).unwrap();
        assert_eq!(item.type_name, "dword");
        assert_eq!(item.size, 4);
    }

    #[test]
    fn test_duplicate_data_rejected() {
        let mut model = DataPluginModel::new();
        model
            .create_data(Address::new(0x1000), DataAction::Byte, 1)
            .unwrap();
        let result = model.create_data(Address::new(0x1000), DataAction::Word, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_data() {
        let mut model = DataPluginModel::new();
        model
            .create_data(Address::new(0x1000), DataAction::Byte, 1)
            .unwrap();
        let removed = model.remove_data(Address::new(0x1000));
        assert!(removed.is_some());
        assert_eq!(model.item_count(), 0);
    }

    #[test]
    fn test_get_all_items() {
        let mut model = DataPluginModel::new();
        model
            .create_data(Address::new(0x1000), DataAction::Byte, 1)
            .unwrap();
        model
            .create_data(Address::new(0x2000), DataAction::Word, 2)
            .unwrap();
        assert_eq!(model.get_all_items().len(), 2);
    }
}
