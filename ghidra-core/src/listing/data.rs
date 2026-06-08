//! Data code unit types for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.Data`.
//!
//! A data item is a typed value applied at an address. Supports structures,
//! unions, arrays, pointers, typedefs, and component hierarchies.

use crate::addr::Address;
use crate::data::DataType;
use std::sync::Arc;

/// A data item within the listing -- a typed value applied at an address.
///
/// Corresponds to Ghidra's `Data` interface. Supports structures, unions,
/// arrays, pointers, typedefs, and component hierarchies.
#[derive(Debug, Clone)]
pub struct Data {
    /// The address of this data item.
    pub address: Address,
    /// The size of this data item in bytes.
    pub size: usize,
    /// The data type applied at this location.
    pub data_type: Option<Arc<dyn DataType>>,
    /// The name of the data type (for display).
    pub data_type_name: String,
    /// An optional interpreted value string (e.g., "42", "\"hello\"").
    pub value: Option<String>,
    /// Whether this data type has been defined (not an undefined placeholder).
    pub is_defined: bool,
    /// Whether this data is a pointer.
    pub is_pointer: bool,
    /// Whether this data is a union.
    pub is_union: bool,
    /// Whether this data is a structure.
    pub is_structure: bool,
    /// Whether this data is an array.
    pub is_array: bool,
    /// Whether this data is dynamic (size determined at runtime).
    pub is_dynamic: bool,
    /// Whether this data is constant (not writable).
    pub is_constant: bool,
    /// The field name if this is a component of a composite type.
    pub field_name: Option<String>,
    /// The component path (indices into parent composites).
    pub component_path: Vec<usize>,
    /// Sub-components (for composite types).
    pub components: Vec<Data>,
    /// The parent data item, if this is a component.
    pub parent: Option<Box<Data>>,
    /// Offset from the parent data item start.
    pub parent_offset: usize,
    /// Offset from the root data item start.
    pub root_offset: usize,
    /// Optional label at this address.
    pub label: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
}

impl Data {
    /// Create a new data item.
    pub fn new(
        address: Address,
        size: usize,
        data_type: Option<Arc<dyn DataType>>,
    ) -> Self {
        let name = data_type
            .as_ref()
            .map(|dt| dt.name().to_string())
            .unwrap_or_else(|| "undefined".to_string());
        let is_defined = data_type.as_ref().map(|dt| dt.is_defined()).unwrap_or(false);
        let is_pointer = data_type.as_ref().map(|dt| dt.is_pointer()).unwrap_or(false);
        Self {
            address,
            size,
            data_type,
            data_type_name: name,
            value: None,
            is_defined,
            is_pointer,
            is_union: false,
            is_structure: false,
            is_array: false,
            is_dynamic: false,
            is_constant: false,
            field_name: None,
            component_path: Vec::new(),
            components: Vec::new(),
            parent: None,
            parent_offset: 0,
            root_offset: 0,
            label: None,
            comment: None,
        }
    }

    /// Builder: set a display value.
    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Builder: set a label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Builder: set a comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Builder: set as structure.
    pub fn with_structure(mut self) -> Self {
        self.is_structure = true;
        self
    }

    /// Builder: set as union.
    pub fn with_union(mut self) -> Self {
        self.is_union = true;
        self
    }

    /// Builder: set as array.
    pub fn with_array(mut self) -> Self {
        self.is_array = true;
        self
    }

    /// Get a component by index.
    pub fn get_component(&self, index: usize) -> Option<&Data> {
        self.components.get(index)
    }

    /// Get a component by its component path.
    pub fn get_component_by_path(&self, path: &[usize]) -> Option<&Data> {
        let mut current = self;
        for &idx in path {
            current = current.components.get(idx)?;
        }
        Some(current)
    }

    /// Number of immediate child components.
    pub fn get_num_components(&self) -> usize {
        self.components.len()
    }

    /// The component level (0 = top-level, 1 = direct child, etc.).
    pub fn get_component_level(&self) -> usize {
        self.component_path.len()
    }

    /// Returns true if this data item has any child components.
    pub fn has_components(&self) -> bool {
        !self.components.is_empty()
    }

    /// Returns true if this data item is the top-level/root data object.
    pub fn is_root(&self) -> bool {
        self.parent.is_none() && self.component_path.is_empty()
    }

    /// Returns true if this has a string value (the data type produces a String).
    pub fn has_string_value(&self) -> bool {
        self.data_type_name.contains("string")
            || self.data_type_name.contains("String")
    }

    /// The default value representation string.
    pub fn get_default_value_representation(&self) -> String {
        self.value.clone().unwrap_or_else(|| "??".to_string())
    }

    /// The full path name (dot notation) for this field.
    pub fn get_path_name(&self) -> String {
        if let Some(ref field) = self.field_name {
            if let Some(ref parent) = self.parent {
                format!("{}.{}", parent.get_path_name(), field)
            } else {
                field.clone()
            }
        } else {
            self.data_type_name.clone()
        }
    }

    /// The component path name (dot notation) for this field.
    pub fn get_component_path_name(&self) -> String {
        self.get_path_name()
    }

    /// Get the root data item (top-level parent).
    pub fn get_root(&self) -> &Data {
        let mut current = self;
        while let Some(ref parent) = current.parent {
            current = parent;
        }
        current
    }

    /// Returns true if this address is within this data item's range.
    pub fn contains(&self, addr: &Address) -> bool {
        addr.offset >= self.address.offset
            && addr.offset < self.address.offset + self.size as u64
    }

    /// The address immediately following this data item.
    pub fn next_address(&self) -> Address {
        self.address.add(self.size as u64)
    }
}

impl PartialEq for Data {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
            && self.size == other.size
            && self.data_type_name == other.data_type_name
    }
}

impl Eq for Data {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::types::{BuiltInDataType, BuiltInDataTypeWrapper, PointerDataType};

    fn make_int_type() -> Arc<dyn DataType> {
        Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int))
    }

    fn make_char_type() -> Arc<dyn DataType> {
        Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Char))
    }

    #[test]
    fn test_data_new() {
        let dt = make_int_type();
        let data = Data::new(Address::new(0x2000), 4, Some(dt))
            .with_value("42")
            .with_label("my_int");
        assert_eq!(data.address, Address::new(0x2000));
        assert_eq!(data.value, Some("42".to_string()));
        assert_eq!(data.label, Some("my_int".to_string()));
        assert_eq!(data.size, 4);
        assert!(data.is_defined);
        assert!(!data.is_pointer);
    }

    #[test]
    fn test_data_pointer_check() {
        let void_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(
            BuiltInDataType::Void,
        ));
        let ptr_type: Arc<dyn DataType> = Arc::new(PointerDataType::new(void_type));
        let data = Data::new(Address::new(0x3000), 8, Some(ptr_type));
        assert!(data.is_pointer);
    }

    #[test]
    fn test_data_undefined() {
        let data = Data::new(Address::new(0x4000), 1, None);
        assert!(!data.is_defined);
        assert_eq!(data.data_type_name, "undefined");
    }

    #[test]
    fn test_data_components() {
        let child = Data::new(Address::new(0x1001), 1, Some(make_char_type()));
        let mut root = Data::new(Address::new(0x1000), 2, Some(make_int_type()));
        root.components.push(child);

        assert!(root.has_components());
        assert!(root.is_root());
        assert_eq!(root.get_num_components(), 1);
        assert!(!root.get_component(0).unwrap().has_components());
    }

    #[test]
    fn test_data_contains() {
        let data = Data::new(Address::new(0x1000), 4, Some(make_int_type()));
        assert!(data.contains(&Address::new(0x1000)));
        assert!(data.contains(&Address::new(0x1003)));
        assert!(!data.contains(&Address::new(0x1004)));
    }

    #[test]
    fn test_data_builder_chain() {
        let data = Data::new(Address::new(0x5000), 16, Some(make_int_type()))
            .with_structure()
            .with_comment("test struct")
            .with_label("my_struct");
        assert!(data.is_structure);
        assert_eq!(data.comment, Some("test struct".to_string()));
        assert_eq!(data.label, Some("my_struct".to_string()));
    }
}
