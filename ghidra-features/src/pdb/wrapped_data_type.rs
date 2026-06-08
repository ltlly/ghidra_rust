//! Wrapped Data Type -- a DataType with additional PDB-specific metadata.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb.WrappedDataType`.

use std::fmt;

/// A data type wrapper that carries additional PDB-specific metadata.
///
/// PDB types sometimes need extra context beyond what a plain data type provides.
/// This wrapper tracks:
/// - Whether the type represents a zero-length array (flex array marker)
/// - Whether the type is a "NoType" placeholder (forced to 1-byte size in PDB)
///
/// A `BitFieldData` variant may be used to convey bitfield-related information.
#[derive(Debug, Clone)]
pub struct WrappedDataType {
    /// The underlying data type representation.
    pub data_type: PdbDataType,
    /// True if this represents a zero-length array that cannot be directly
    /// represented as an Array type. Zero-length arrays are only supported
    /// as trailing flex-arrays within a structure.
    pub is_zero_length_array: bool,
    /// True if this corresponds to NoType as used by PDB, forced to 1-byte size.
    pub is_no_type: bool,
}

/// Simplified data type representation for PDB parsing.
///
/// In a full implementation this would reference the program's DataTypeManager,
/// but for PDB parsing purposes we track the essential type information.
#[derive(Debug, Clone)]
pub enum PdbDataType {
    /// A primitive type (void, char, int, float, etc.).
    Primitive {
        /// Type name (e.g., "int", "float").
        name: String,
        /// Size in bytes.
        size: u32,
    },
    /// A pointer to another type.
    Pointer {
        /// Size of the pointer in bytes (4 or 8).
        size: u32,
        /// Whether this is a reference (&) rather than a pointer (*).
        is_reference: bool,
    },
    /// A named type reference (class, struct, union, enum, typedef).
    Named {
        /// The type name.
        name: String,
        /// The type index in TPI/IPI.
        type_index: u32,
    },
    /// An array type.
    Array {
        /// Element type index.
        element_type_index: u32,
        /// Number of elements.
        element_count: u32,
    },
    /// A bitfield type.
    BitField {
        /// Base type index.
        base_type_index: u32,
        /// Bit size of the bitfield.
        bit_size: u8,
        /// Bit offset within the base type.
        bit_offset: u8,
    },
    /// A procedure/function type.
    Procedure {
        /// Return type index.
        return_type_index: u32,
        /// Parameter type indices.
        param_type_indices: Vec<u32>,
    },
    /// A modifier (const, volatile, etc.).
    Modifier {
        /// Underlying type index.
        underlying_type_index: u32,
        /// Is const.
        is_const: bool,
        /// Is volatile.
        is_volatile: bool,
    },
    /// A type that could not be resolved.
    Unresolved {
        /// The type index that could not be resolved.
        type_index: u32,
    },
}

impl PdbDataType {
    /// Get the display name of this data type.
    pub fn name(&self) -> &str {
        match self {
            PdbDataType::Primitive { name, .. } => name,
            PdbDataType::Pointer { .. } => "pointer",
            PdbDataType::Named { name, .. } => name,
            PdbDataType::Array { .. } => "array",
            PdbDataType::BitField { .. } => "bitfield",
            PdbDataType::Procedure { .. } => "procedure",
            PdbDataType::Modifier { .. } => "modifier",
            PdbDataType::Unresolved { .. } => "unresolved",
        }
    }

    /// Get the size in bytes of this data type, if known.
    pub fn size(&self) -> Option<u32> {
        match self {
            PdbDataType::Primitive { size, .. } => Some(*size),
            PdbDataType::Pointer { size, .. } => Some(*size),
            PdbDataType::Array { element_type_index: _, element_count } => {
                // Would need element size to compute; return None for now
                if *element_count == 0 { Some(0) } else { None }
            }
            PdbDataType::BitField { .. } => None, // Bitfields don't have a standalone size
            _ => None,
        }
    }

    /// Check if this is a primitive type.
    pub fn is_primitive(&self) -> bool {
        matches!(self, PdbDataType::Primitive { .. })
    }

    /// Check if this is a pointer type.
    pub fn is_pointer(&self) -> bool {
        matches!(self, PdbDataType::Pointer { .. })
    }

    /// Check if this is a named type reference.
    pub fn is_named(&self) -> bool {
        matches!(self, PdbDataType::Named { .. })
    }
}

impl WrappedDataType {
    /// Create a new WrappedDataType.
    pub fn new(
        data_type: PdbDataType,
        is_zero_length_array: bool,
        is_no_type: bool,
    ) -> Self {
        Self {
            data_type,
            is_zero_length_array,
            is_no_type,
        }
    }

    /// Create a simple wrapped type with no special flags.
    pub fn simple(data_type: PdbDataType) -> Self {
        Self {
            data_type,
            is_zero_length_array: false,
            is_no_type: false,
        }
    }

    /// Create a zero-length array wrapper.
    pub fn zero_length_array(data_type: PdbDataType) -> Self {
        Self {
            data_type,
            is_zero_length_array: true,
            is_no_type: false,
        }
    }

    /// Create a NoType wrapper.
    pub fn no_type() -> Self {
        Self {
            data_type: PdbDataType::Primitive {
                name: "NoType".to_string(),
                size: 1,
            },
            is_zero_length_array: false,
            is_no_type: true,
        }
    }
}

impl fmt::Display for WrappedDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.data_type.name())?;
        if self.is_zero_length_array {
            write!(f, " [zero-length]")?;
        }
        if self.is_no_type {
            write!(f, " [no-type]")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapped_simple() {
        let dt = PdbDataType::Primitive {
            name: "int".to_string(),
            size: 4,
        };
        let wrapped = WrappedDataType::simple(dt);
        assert!(!wrapped.is_zero_length_array);
        assert!(!wrapped.is_no_type);
        assert_eq!(wrapped.data_type.name(), "int");
    }

    #[test]
    fn test_wrapped_zero_length_array() {
        let dt = PdbDataType::Named {
            name: "char".to_string(),
            type_index: 0x0070,
        };
        let wrapped = WrappedDataType::zero_length_array(dt);
        assert!(wrapped.is_zero_length_array);
        assert!(!wrapped.is_no_type);
    }

    #[test]
    fn test_wrapped_no_type() {
        let wrapped = WrappedDataType::no_type();
        assert!(!wrapped.is_zero_length_array);
        assert!(wrapped.is_no_type);
        assert_eq!(wrapped.data_type.name(), "NoType");
    }

    #[test]
    fn test_pdb_datatype_primitive() {
        let dt = PdbDataType::Primitive {
            name: "float".to_string(),
            size: 4,
        };
        assert!(dt.is_primitive());
        assert!(!dt.is_pointer());
        assert_eq!(dt.size(), Some(4));
    }

    #[test]
    fn test_pdb_datatype_pointer() {
        let dt = PdbDataType::Pointer {
            size: 8,
            is_reference: false,
        };
        assert!(dt.is_pointer());
        assert_eq!(dt.size(), Some(8));
    }

    #[test]
    fn test_pdb_datatype_named() {
        let dt = PdbDataType::Named {
            name: "MyStruct".to_string(),
            type_index: 0x1000,
        };
        assert!(dt.is_named());
        assert_eq!(dt.name(), "MyStruct");
    }

    #[test]
    fn test_display_simple() {
        let dt = PdbDataType::Primitive {
            name: "int".to_string(),
            size: 4,
        };
        let wrapped = WrappedDataType::simple(dt);
        assert_eq!(format!("{}", wrapped), "int");
    }

    #[test]
    fn test_display_with_flags() {
        let dt = PdbDataType::Primitive {
            name: "char".to_string(),
            size: 1,
        };
        let wrapped = WrappedDataType::new(dt, true, false);
        assert_eq!(format!("{}", wrapped), "char [zero-length]");
    }

    #[test]
    fn test_pdb_datatype_unresolved() {
        let dt = PdbDataType::Unresolved { type_index: 0xFFFF };
        assert_eq!(dt.name(), "unresolved");
        assert_eq!(dt.size(), None);
    }
}
