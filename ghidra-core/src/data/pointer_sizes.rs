//! Fixed-size pointer data types ported from Ghidra.
//!
//! Covers:
//! - `Pointer8DataType` - 8-bit (1 byte) pointer
//! - `Pointer16DataType` - 16-bit (2 byte) pointer
//! - `Pointer24DataType` - 24-bit (3 byte) pointer
//! - `Pointer32DataType` - 32-bit (4 byte) pointer
//! - `Pointer40DataType` - 40-bit (5 byte) pointer
//! - `Pointer48DataType` - 48-bit (6 byte) pointer
//! - `Pointer56DataType` - 56-bit (7 byte) pointer
//! - `Pointer64DataType` - 64-bit (8 byte) pointer
//! - `PointerTypedef` - pointer typedef wrapper
//! - `PointerTypedefBuilder` - builder for pointer typedefs

use std::fmt;
use std::sync::Arc;

use super::types::{DataType, PointerDataType};
use super::CategoryPath;

// ============================================================================
// Macro for fixed-size pointer types
// ============================================================================

macro_rules! define_pointer_size {
    ($name:ident, $bits:expr, $bytes:expr, $desc:expr) => {
        /// Pointer type with fixed size of $bits bits ($bytes bytes).
        #[derive(Debug, Clone)]
        pub struct $name {
            pub pointed_to: Arc<dyn DataType>,
            pub category_path: CategoryPath,
        }

        impl $name {
            pub fn new(pointed_to: Arc<dyn DataType>) -> Self {
                Self { pointed_to, category_path: CategoryPath::ROOT }
            }
            pub fn with_category_path(mut self, path: CategoryPath) -> Self {
                self.category_path = path; self
            }
            pub fn pointer_size() -> usize { $bytes }
            pub fn pointer_bits() -> usize { $bits }
        }

        impl DataType for $name {
            fn as_any(&self) -> &dyn std::any::Any { self }
            fn name(&self) -> &str { concat!("pointer", $bits) }
            fn description(&self) -> &str { $desc }
            fn get_size(&self) -> usize { $bytes }
            fn is_pointer(&self) -> bool { true }
            fn get_alignment(&self) -> usize { $bytes }
            fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }

            fn is_equivalent(&self, other: &dyn DataType) -> bool {
                self.name() == other.name() && self.get_size() == other.get_size()
            }

            fn get_category_path(&self) -> &CategoryPath { &self.category_path }
            fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{} * ({}-bit)", self.pointed_to.name(), $bits)
            }
        }
    };
}

define_pointer_size!(Pointer8DataType, 8, 1, "8-bit (1 byte) pointer");
define_pointer_size!(Pointer16DataType, 16, 2, "16-bit (2 byte) pointer");
define_pointer_size!(Pointer24DataType, 24, 3, "24-bit (3 byte) pointer");
define_pointer_size!(Pointer32DataType, 32, 4, "32-bit (4 byte) pointer");
define_pointer_size!(Pointer40DataType, 40, 5, "40-bit (5 byte) pointer");
define_pointer_size!(Pointer48DataType, 48, 6, "48-bit (6 byte) pointer");
define_pointer_size!(Pointer56DataType, 56, 7, "56-bit (7 byte) pointer");
define_pointer_size!(Pointer64DataType, 64, 8, "64-bit (8 byte) pointer");

// ============================================================================
// PointerTypedef
// ============================================================================

/// Pointer typedef wrapper. Port of Ghidra's `PointerTypedef` interface and `PointerTypedefBuilder`.
///
/// Wraps a pointer data type with additional typedef-level settings such as
/// pointer type classification, address space override, offset mask/shift, etc.
#[derive(Debug, Clone)]
pub struct PointerTypedef {
    pub pointer: PointerDataType,
    pub pointer_type_name: String,
    pub address_space_name: Option<String>,
    pub offset_mask: u64,
    pub offset_shift: i32,
    pub category_path: CategoryPath,
}

impl PointerTypedef {
    pub fn new(pointer: PointerDataType) -> Self {
        Self {
            pointer,
            pointer_type_name: "default".into(),
            address_space_name: None,
            offset_mask: 0,
            offset_shift: 0,
            category_path: CategoryPath::ROOT,
        }
    }

    pub fn with_pointer_type(mut self, name: impl Into<String>) -> Self {
        self.pointer_type_name = name.into(); self
    }

    pub fn with_address_space(mut self, space: impl Into<String>) -> Self {
        self.address_space_name = Some(space.into()); self
    }

    pub fn with_offset_mask(mut self, mask: u64) -> Self {
        self.offset_mask = mask; self
    }

    pub fn with_offset_shift(mut self, shift: i32) -> Self {
        self.offset_shift = shift; self
    }

    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
}

impl DataType for PointerTypedef {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "pointer" }
    fn description(&self) -> &str { "Pointer typedef" }
    fn get_size(&self) -> usize { self.pointer.get_size() }
    fn is_pointer(&self) -> bool { true }
    fn get_alignment(&self) -> usize { self.pointer.get_alignment() }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.pointer.is_equivalent(other)
    }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for PointerTypedef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pointer_typedef ({})", self.pointer_type_name)
    }
}

// ============================================================================
// PointerTypedefBuilder
// ============================================================================

/// Builder for creating pointer typedefs. Port of Ghidra's `PointerTypedefBuilder`.
#[derive(Debug, Clone)]
pub struct PointerTypedefBuilder {
    pub pointed_to: Arc<dyn DataType>,
    pub pointer_size: usize,
    pub pointer_type_name: String,
    pub address_space_name: Option<String>,
    pub offset_mask: u64,
    pub offset_shift: i32,
    pub category_path: CategoryPath,
}

impl PointerTypedefBuilder {
    pub fn new(pointed_to: Arc<dyn DataType>, pointer_size: usize) -> Self {
        Self {
            pointed_to, pointer_size,
            pointer_type_name: "default".into(),
            address_space_name: None,
            offset_mask: 0,
            offset_shift: 0,
            category_path: CategoryPath::ROOT,
        }
    }

    pub fn pointer_type(mut self, name: impl Into<String>) -> Self {
        self.pointer_type_name = name.into(); self
    }

    pub fn address_space(mut self, space: impl Into<String>) -> Self {
        self.address_space_name = Some(space.into()); self
    }

    pub fn offset_mask(mut self, mask: u64) -> Self {
        self.offset_mask = mask; self
    }

    pub fn offset_shift(mut self, shift: i32) -> Self {
        self.offset_shift = shift; self
    }

    pub fn category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }

    /// Build the PointerTypedef.
    pub fn build(self) -> PointerTypedef {
        let ptr = PointerDataType::with_size(self.pointed_to, self.pointer_size);
        PointerTypedef {
            pointer: ptr,
            pointer_type_name: self.pointer_type_name,
            address_space_name: self.address_space_name,
            offset_mask: self.offset_mask,
            offset_shift: self.offset_shift,
            category_path: self.category_path,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::BuiltInDataTypeWrapper;

    #[test]
    fn test_pointer8() {
        let void: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(super::super::types::BuiltInDataType::Void));
        let p = Pointer8DataType::new(void);
        assert_eq!(p.get_size(), 1);
        assert!(p.is_pointer());
        assert_eq!(Pointer8DataType::pointer_bits(), 8);
    }

    #[test]
    fn test_pointer16() {
        let void: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(super::super::types::BuiltInDataType::Void));
        let p = Pointer16DataType::new(void);
        assert_eq!(p.get_size(), 2);
        assert!(p.is_pointer());
    }

    #[test]
    fn test_pointer32() {
        let void: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(super::super::types::BuiltInDataType::Void));
        let p = Pointer32DataType::new(void);
        assert_eq!(p.get_size(), 4);
        assert!(p.is_pointer());
    }

    #[test]
    fn test_pointer64() {
        let void: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(super::super::types::BuiltInDataType::Void));
        let p = Pointer64DataType::new(void);
        assert_eq!(p.get_size(), 8);
        assert!(p.is_pointer());
        assert_eq!(Pointer64DataType::pointer_bits(), 64);
    }

    #[test]
    fn test_all_pointer_sizes() {
        assert_eq!(Pointer8DataType::pointer_size(), 1);
        assert_eq!(Pointer16DataType::pointer_size(), 2);
        assert_eq!(Pointer24DataType::pointer_size(), 3);
        assert_eq!(Pointer32DataType::pointer_size(), 4);
        assert_eq!(Pointer40DataType::pointer_size(), 5);
        assert_eq!(Pointer48DataType::pointer_size(), 6);
        assert_eq!(Pointer56DataType::pointer_size(), 7);
        assert_eq!(Pointer64DataType::pointer_size(), 8);
    }

    #[test]
    fn test_pointer_typedef() {
        let int: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(super::super::types::BuiltInDataType::Int));
        let ptr = PointerDataType::new(int);
        let typedef = PointerTypedef::new(ptr)
            .with_pointer_type("near")
            .with_offset_mask(0xFFFF);
        assert_eq!(typedef.pointer_type_name, "near");
        assert_eq!(typedef.offset_mask, 0xFFFF);
        assert!(typedef.is_pointer());
    }

    #[test]
    fn test_pointer_typedef_builder() {
        let int: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(super::super::types::BuiltInDataType::Int));
        let typedef = PointerTypedefBuilder::new(int, 4)
            .pointer_type("far")
            .address_space("ram")
            .offset_shift(2)
            .build();
        assert_eq!(typedef.pointer_type_name, "far");
        assert_eq!(typedef.address_space_name, Some("ram".to_string()));
        assert_eq!(typedef.offset_shift, 2);
        assert_eq!(typedef.get_size(), 4);
    }

    #[test]
    fn test_pointer_display() {
        let int: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(super::super::types::BuiltInDataType::Int));
        let p = Pointer32DataType::new(int);
        let display = format!("{}", p);
        assert!(display.contains("int"));
        assert!(display.contains("32-bit"));
    }
}
