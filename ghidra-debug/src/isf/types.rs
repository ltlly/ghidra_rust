//! ISF data type object model.
//!
//! Ported from Ghidra's `ghidra.program.model.data.ISF` package.
//!
//! Provides Rust equivalents of the ISF type hierarchy: builtins,
//! composites, enums, pointers, typedefs, functions, etc.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::server::{IsfComponent, IsfTypeDef, IsfTypeKind};

// ---------------------------------------------------------------------------
// IsfObject (trait)
// ---------------------------------------------------------------------------

/// Trait for all ISF objects.
pub trait IsfObject {
    /// Convert to an ISF type definition.
    fn to_type_def(&self) -> IsfTypeDef;
}

// ---------------------------------------------------------------------------
// IsfBuiltIn
// ---------------------------------------------------------------------------

/// A built-in type (void, int, float, bool, char, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfBuiltIn {
    /// The type ID.
    pub type_id: u64,
    /// The type name (e.g., "int", "unsigned long").
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// Whether the type is signed.
    pub is_signed: bool,
    /// Whether this is a floating-point type.
    pub is_float: bool,
}

impl IsfBuiltIn {
    /// Create a new built-in type.
    pub fn new(type_id: u64, name: impl Into<String>, size: u64) -> Self {
        Self {
            type_id,
            name: name.into(),
            size,
            is_signed: true,
            is_float: false,
        }
    }
}

impl IsfObject for IsfBuiltIn {
    fn to_type_def(&self) -> IsfTypeDef {
        IsfTypeDef {
            type_id: self.type_id,
            name: self.name.clone(),
            kind: IsfTypeKind::BuiltIn,
            size: self.size,
            alignment: self.size,
            components: vec![],
            properties: {
                let mut p = BTreeMap::new();
                p.insert("signed".into(), serde_json::json!(self.is_signed));
                p.insert("float".into(), serde_json::json!(self.is_float));
                p
            },
        }
    }
}

// ---------------------------------------------------------------------------
// IsfComposite
// ---------------------------------------------------------------------------

/// A structure or class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfComposite {
    /// The type ID.
    pub type_id: u64,
    /// The type name.
    pub name: String,
    /// Total size in bytes.
    pub size: u64,
    /// Alignment in bytes.
    pub alignment: u64,
    /// Whether this is a union (vs. struct).
    pub is_union: bool,
    /// Fields.
    pub fields: Vec<IsfComponent>,
}

impl IsfComposite {
    /// Create a new composite type.
    pub fn new(type_id: u64, name: impl Into<String>, size: u64) -> Self {
        Self {
            type_id,
            name: name.into(),
            size,
            alignment: 1,
            is_union: false,
            fields: Vec::new(),
        }
    }

    /// Add a field.
    pub fn add_field(&mut self, field: IsfComponent) {
        self.fields.push(field);
    }
}

impl IsfObject for IsfComposite {
    fn to_type_def(&self) -> IsfTypeDef {
        IsfTypeDef {
            type_id: self.type_id,
            name: self.name.clone(),
            kind: IsfTypeKind::Composite,
            size: self.size,
            alignment: self.alignment,
            components: self.fields.clone(),
            properties: {
                let mut p = BTreeMap::new();
                p.insert("union".into(), serde_json::json!(self.is_union));
                p
            },
        }
    }
}

// ---------------------------------------------------------------------------
// IsfEnum
// ---------------------------------------------------------------------------

/// An enumeration type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfEnum {
    /// The type ID.
    pub type_id: u64,
    /// The type name.
    pub name: String,
    /// The underlying size in bytes.
    pub size: u64,
    /// Enum values: name -> integer value.
    pub values: BTreeMap<String, i64>,
}

impl IsfEnum {
    /// Create a new enum.
    pub fn new(type_id: u64, name: impl Into<String>, size: u64) -> Self {
        Self {
            type_id,
            name: name.into(),
            size,
            values: BTreeMap::new(),
        }
    }

    /// Add a value.
    pub fn add_value(&mut self, name: impl Into<String>, value: i64) {
        self.values.insert(name.into(), value);
    }
}

impl IsfObject for IsfEnum {
    fn to_type_def(&self) -> IsfTypeDef {
        let mut props = BTreeMap::new();
        for (k, v) in &self.values {
            props.insert(format!("enum.{}", k), serde_json::json!(v));
        }
        IsfTypeDef {
            type_id: self.type_id,
            name: self.name.clone(),
            kind: IsfTypeKind::Enum,
            size: self.size,
            alignment: self.size,
            components: vec![],
            properties: props,
        }
    }
}

// ---------------------------------------------------------------------------
// IsfPointer
// ---------------------------------------------------------------------------

/// A pointer type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfPointer {
    /// The type ID.
    pub type_id: u64,
    /// The type name.
    pub name: String,
    /// Size in bytes (typically 4 or 8).
    pub size: u64,
    /// The type ID of the pointed-to type.
    pub pointee_type_id: u64,
}

impl IsfPointer {
    /// Create a new pointer.
    pub fn new(type_id: u64, name: impl Into<String>, size: u64, pointee_type_id: u64) -> Self {
        Self {
            type_id,
            name: name.into(),
            size,
            pointee_type_id,
        }
    }
}

impl IsfObject for IsfPointer {
    fn to_type_def(&self) -> IsfTypeDef {
        IsfTypeDef {
            type_id: self.type_id,
            name: self.name.clone(),
            kind: IsfTypeKind::Pointer,
            size: self.size,
            alignment: self.size,
            components: vec![],
            properties: {
                let mut p = BTreeMap::new();
                p.insert("pointee".into(), serde_json::json!(self.pointee_type_id));
                p
            },
        }
    }
}

// ---------------------------------------------------------------------------
// IsfTypedef
// ---------------------------------------------------------------------------

/// A typedef / alias.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfTypedef {
    /// The type ID.
    pub type_id: u64,
    /// The alias name.
    pub name: String,
    /// The underlying type ID.
    pub base_type_id: u64,
    /// Size (same as base type).
    pub size: u64,
}

impl IsfTypedef {
    /// Create a new typedef.
    pub fn new(type_id: u64, name: impl Into<String>, base_type_id: u64, size: u64) -> Self {
        Self {
            type_id,
            name: name.into(),
            base_type_id,
            size,
        }
    }
}

impl IsfObject for IsfTypedef {
    fn to_type_def(&self) -> IsfTypeDef {
        IsfTypeDef {
            type_id: self.type_id,
            name: self.name.clone(),
            kind: IsfTypeKind::Typedef,
            size: self.size,
            alignment: 1,
            components: vec![],
            properties: {
                let mut p = BTreeMap::new();
                p.insert("base".into(), serde_json::json!(self.base_type_id));
                p
            },
        }
    }
}

// ---------------------------------------------------------------------------
// IsfFunction
// ---------------------------------------------------------------------------

/// A function signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfFunction {
    /// The type ID.
    pub type_id: u64,
    /// The function name.
    pub name: String,
    /// Return type ID.
    pub return_type_id: u64,
    /// Parameters.
    pub parameters: Vec<IsfComponent>,
    /// Whether this is a variadic function.
    pub is_variadic: bool,
    /// Calling convention name.
    pub calling_convention: String,
}

impl IsfFunction {
    /// Create a new function.
    pub fn new(type_id: u64, name: impl Into<String>, return_type_id: u64) -> Self {
        Self {
            type_id,
            name: name.into(),
            return_type_id,
            parameters: Vec::new(),
            is_variadic: false,
            calling_convention: "default".into(),
        }
    }

    /// Add a parameter.
    pub fn add_parameter(&mut self, param: IsfComponent) {
        self.parameters.push(param);
    }
}

impl IsfObject for IsfFunction {
    fn to_type_def(&self) -> IsfTypeDef {
        IsfTypeDef {
            type_id: self.type_id,
            name: self.name.clone(),
            kind: IsfTypeKind::Function,
            size: 0,
            alignment: 0,
            components: self.parameters.clone(),
            properties: {
                let mut p = BTreeMap::new();
                p.insert("return_type".into(), serde_json::json!(self.return_type_id));
                p.insert("variadic".into(), serde_json::json!(self.is_variadic));
                p.insert(
                    "calling_convention".into(),
                    serde_json::json!(self.calling_convention),
                );
                p
            },
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isf_built_in() {
        let bt = IsfBuiltIn::new(1, "int", 4);
        let td = bt.to_type_def();
        assert_eq!(td.kind, IsfTypeKind::BuiltIn);
        assert_eq!(td.size, 4);
        assert_eq!(td.name, "int");
    }

    #[test]
    fn test_isf_built_in_unsigned() {
        let mut bt = IsfBuiltIn::new(2, "unsigned int", 4);
        bt.is_signed = false;
        let td = bt.to_type_def();
        assert_eq!(td.properties["signed"], serde_json::json!(false));
    }

    #[test]
    fn test_isf_composite() {
        let mut comp = IsfComposite::new(10, "point_t", 8);
        comp.add_field(IsfComponent {
            name: "x".into(),
            offset: 0,
            type_id: 1,
            size: 4,
        });
        comp.add_field(IsfComponent {
            name: "y".into(),
            offset: 4,
            type_id: 1,
            size: 4,
        });
        let td = comp.to_type_def();
        assert_eq!(td.kind, IsfTypeKind::Composite);
        assert_eq!(td.components.len(), 2);
        assert_eq!(td.properties["union"], serde_json::json!(false));
    }

    #[test]
    fn test_isf_enum() {
        let mut e = IsfEnum::new(20, "color_t", 4);
        e.add_value("RED", 0);
        e.add_value("GREEN", 1);
        e.add_value("BLUE", 2);
        let td = e.to_type_def();
        assert_eq!(td.kind, IsfTypeKind::Enum);
        assert_eq!(td.properties["enum.RED"], serde_json::json!(0));
    }

    #[test]
    fn test_isf_pointer() {
        let p = IsfPointer::new(30, "int *", 8, 1);
        let td = p.to_type_def();
        assert_eq!(td.kind, IsfTypeKind::Pointer);
        assert_eq!(td.properties["pointee"], serde_json::json!(1));
    }

    #[test]
    fn test_isf_typedef() {
        let t = IsfTypedef::new(40, "pid_t", 1, 4);
        let td = t.to_type_def();
        assert_eq!(td.kind, IsfTypeKind::Typedef);
        assert_eq!(td.properties["base"], serde_json::json!(1));
    }

    #[test]
    fn test_isf_function() {
        let mut f = IsfFunction::new(50, "main", 1);
        f.add_parameter(IsfComponent {
            name: "argc".into(),
            offset: 0,
            type_id: 1,
            size: 4,
        });
        f.add_parameter(IsfComponent {
            name: "argv".into(),
            offset: 8,
            type_id: 6,
            size: 8,
        });
        let td = f.to_type_def();
        assert_eq!(td.kind, IsfTypeKind::Function);
        assert_eq!(td.components.len(), 2);
        assert_eq!(td.properties["return_type"], serde_json::json!(1));
        assert_eq!(td.properties["variadic"], serde_json::json!(false));
    }

    #[test]
    fn test_isf_function_variadic() {
        let mut f = IsfFunction::new(51, "printf", 1);
        f.is_variadic = true;
        f.calling_convention = "cdecl".into();
        let td = f.to_type_def();
        assert_eq!(td.properties["variadic"], serde_json::json!(true));
        assert_eq!(td.properties["calling_convention"], serde_json::json!("cdecl"));
    }

    #[test]
    fn test_isf_objects_serde() {
        let bt = IsfBuiltIn::new(1, "int", 4);
        let json = serde_json::to_string(&bt).unwrap();
        let back: IsfBuiltIn = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "int");

        let comp = IsfComposite::new(10, "s", 8);
        let json = serde_json::to_string(&comp).unwrap();
        let _: IsfComposite = serde_json::from_str(&json).unwrap();
    }
}
