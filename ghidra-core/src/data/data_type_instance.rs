//! Data type instance: a context-specific instantiation of a data type.
//!
//! Port of Ghidra's `DataTypeInstance.java`.
//!
//! Most data types are not context sensitive. Dynamic data types and factory
//! data types need to produce an instance with a concrete length based on
//! the memory context.

use std::fmt;
use std::sync::Arc;

use super::types::DataType;

// ============================================================================
// DataTypeInstance
// ============================================================================

/// An instance of a `DataType` that is applicable for a given context.
///
/// Port of Ghidra's `DataTypeInstance.java`. Most data types are not context
/// sensitive and are suitable for use anywhere. Dynamic structures and similar
/// types need to create an instance that wraps the data type with a concrete
/// length.
///
/// This is useful for situations where a data type must have a fixed length.
#[derive(Debug, Clone)]
pub struct DataTypeInstance {
    /// The data type.
    data_type: Arc<dyn DataType>,
    /// The fixed length in bytes.
    length: usize,
}

impl DataTypeInstance {
    /// Create a new data type instance with the given length.
    ///
    /// If `length` is 0, falls back to the data type's own length or 1.
    pub fn new(data_type: Arc<dyn DataType>, length: usize) -> Self {
        let actual_length = if length == 0 {
            let dt_len = data_type.get_size();
            if dt_len > 0 {
                dt_len
            } else {
                1
            }
        } else {
            length
        };
        Self {
            data_type,
            length: actual_length,
        }
    }

    /// Create a data type instance using the data type's natural length.
    pub fn from_type(data_type: Arc<dyn DataType>) -> Self {
        let length = data_type.get_size().max(1);
        Self { data_type, length }
    }

    /// Get the data type.
    pub fn data_type(&self) -> &Arc<dyn DataType> {
        &self.data_type
    }

    /// Get the fixed length of this data type instance.
    pub fn length(&self) -> usize {
        self.length
    }

    /// Set the length of this data type instance.
    pub fn set_length(&mut self, length: usize) {
        self.length = length;
    }

    /// Generate a data type instance for the given data type.
    ///
    /// For fixed-length types, uses the aligned length. For dynamic types,
    /// uses the specified length. Returns `None` if the data type is a
    /// factory type or if the length cannot be determined.
    pub fn get_data_type_instance(
        data_type: &Arc<dyn DataType>,
        length: Option<usize>,
        use_aligned_length: bool,
    ) -> Option<Self> {
        // Factory data types cannot be instantiated without context.
        // (In Rust, we check if the type is defined and has a size.)
        if data_type.get_size() == 0 && !data_type.is_undefined() {
            return None;
        }

        let dt_length = if let Some(len) = length {
            if len > 0 {
                len
            } else {
                if use_aligned_length {
                    data_type.get_alignment().max(data_type.get_size())
                } else {
                    data_type.get_size()
                }
            }
        } else if use_aligned_length {
            data_type.get_alignment().max(data_type.get_size())
        } else {
            data_type.get_size()
        };

        if dt_length == 0 {
            return None;
        }

        Some(Self::new(data_type.clone(), dt_length))
    }
}

impl fmt::Display for DataTypeInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({} bytes)",
            self.data_type.name(),
            self.length
        )
    }
}

impl PartialEq for DataTypeInstance {
    fn eq(&self, other: &Self) -> bool {
        self.length == other.length && self.data_type.is_equivalent(other.data_type.as_ref())
    }
}

impl Eq for DataTypeInstance {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::types::{StructureDataType, UndefinedDataType};
    use crate::data::builtin_types::VoidDataType;

    #[test]
    fn test_instance_new() {
        let dt = Arc::new(StructureDataType::new("test"));
        let inst = DataTypeInstance::new(dt, 4);
        assert_eq!(inst.length(), 4);
        assert_eq!(inst.data_type().name(), "test");
    }

    #[test]
    fn test_instance_zero_length_fallback() {
        let dt = Arc::new(StructureDataType::new("empty"));
        // Size 0, should fall back to 1
        let inst = DataTypeInstance::new(dt, 0);
        assert_eq!(inst.length(), 1);
    }

    #[test]
    fn test_instance_from_type() {
        let dt = Arc::new(VoidDataType::new());
        let inst = DataTypeInstance::from_type(dt);
        // Void has size 0, fallback to 1
        assert_eq!(inst.length(), 1);
    }

    #[test]
    fn test_instance_set_length() {
        let dt = Arc::new(StructureDataType::new("test"));
        let mut inst = DataTypeInstance::new(dt, 4);
        inst.set_length(8);
        assert_eq!(inst.length(), 8);
    }

    #[test]
    fn test_instance_display() {
        let dt = Arc::new(StructureDataType::new("my_struct"));
        let inst = DataTypeInstance::new(dt, 16);
        assert_eq!(format!("{}", inst), "my_struct (16 bytes)");
    }

    #[test]
    fn test_instance_equality() {
        let dt1 = Arc::new(StructureDataType::new("test"));
        let dt2 = Arc::new(StructureDataType::new("test"));
        let inst1 = DataTypeInstance::new(dt1, 4);
        let inst2 = DataTypeInstance::new(dt2, 4);
        assert_eq!(inst1, inst2);
    }

    #[test]
    fn test_get_data_type_instance_fixed() {
        // Use a type with a known size
        let dt: Arc<dyn DataType> = Arc::new(UndefinedDataType::new(8));
        let inst = DataTypeInstance::get_data_type_instance(&dt, Some(8), false);
        assert!(inst.is_some());
        assert_eq!(inst.unwrap().length(), 8);
    }

    #[test]
    fn test_get_data_type_instance_default() {
        let dt: Arc<dyn DataType> = Arc::new(UndefinedDataType::new(4));
        let inst = DataTypeInstance::get_data_type_instance(&dt, None, false);
        assert!(inst.is_some());
        assert_eq!(inst.unwrap().length(), 4);
    }
}
