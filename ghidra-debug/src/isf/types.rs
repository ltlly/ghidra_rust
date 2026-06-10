//! ISF data type object model.
//!
//! Ported from Ghidra's `ghidra.program.model.data.ISF` package.
//!
//! Provides Rust equivalents of the ISF type hierarchy: builtins,
//! composites, enums, pointers, typedefs, functions, arrays, bit fields,
//! function pointers, dynamic components, typed objects, settings, and
//! the ISF utilities for type classification.

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
///
/// Ported from Ghidra's `IsfBuiltIn`.
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
    /// The endianness ("big" or "little").
    pub endian: String,
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
            endian: "little".into(),
        }
    }

    /// Set the endianness.
    pub fn with_endian(mut self, endian: impl Into<String>) -> Self {
        self.endian = endian.into();
        self
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
                p.insert("endian".into(), serde_json::json!(self.endian));
                p
            },
        }
    }
}

// ---------------------------------------------------------------------------
// IsfComposite
// ---------------------------------------------------------------------------

/// A structure or class.
///
/// Ported from Ghidra's `IsfComposite`.
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
///
/// Ported from Ghidra's `IsfEnum`.
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
///
/// Ported from Ghidra's `IsfPointer`.
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
    /// The endianness ("big" or "little").
    pub endian: String,
}

impl IsfPointer {
    /// Create a new pointer.
    pub fn new(type_id: u64, name: impl Into<String>, size: u64, pointee_type_id: u64) -> Self {
        Self {
            type_id,
            name: name.into(),
            size,
            pointee_type_id,
            endian: "little".into(),
        }
    }

    /// Set the endianness.
    pub fn with_endian(mut self, endian: impl Into<String>) -> Self {
        self.endian = endian.into();
        self
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
                p.insert("endian".into(), serde_json::json!(self.endian));
                p
            },
        }
    }
}

// ---------------------------------------------------------------------------
// IsfTypedef
// ---------------------------------------------------------------------------

/// A typedef / alias.
///
/// Ported from Ghidra's `IsfTypedefBase` / `IsfTypedefUser`.
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
    /// The kind of base: "integral", "user", or "pointer".
    pub typedef_kind: String,
}

impl IsfTypedef {
    /// Create a new typedef.
    pub fn new(type_id: u64, name: impl Into<String>, base_type_id: u64, size: u64) -> Self {
        Self {
            type_id,
            name: name.into(),
            base_type_id,
            size,
            typedef_kind: "user".into(),
        }
    }

    /// Create an integral typedef (e.g., `typedef unsigned int size_t`).
    pub fn new_integral(type_id: u64, name: impl Into<String>, base_type_id: u64, size: u64) -> Self {
        Self {
            type_id,
            name: name.into(),
            base_type_id,
            size,
            typedef_kind: "integral".into(),
        }
    }

    /// Create a pointer typedef (e.g., `typedef struct foo *foo_t`).
    pub fn new_pointer(type_id: u64, name: impl Into<String>, base_type_id: u64, size: u64) -> Self {
        Self {
            type_id,
            name: name.into(),
            base_type_id,
            size,
            typedef_kind: "pointer".into(),
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
                p.insert("typedef_kind".into(), serde_json::json!(self.typedef_kind));
                p
            },
        }
    }
}

// ---------------------------------------------------------------------------
// IsfFunction
// ---------------------------------------------------------------------------

/// A function signature.
///
/// Ported from Ghidra's `IsfFunction`.
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

// ---------------------------------------------------------------------------
// IsfFunctionPointer
// ---------------------------------------------------------------------------

/// A function pointer type.
///
/// Ported from Ghidra's `IsfFunctionPointer`. Represents a pointer to a
/// function definition, wrapping the function signature as a subtype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfFunctionPointer {
    /// The type ID.
    pub type_id: u64,
    /// The type name.
    pub name: String,
    /// Always "pointer".
    pub kind: String,
    /// The function signature this pointer points to.
    pub subtype: IsfFunction,
}

impl IsfFunctionPointer {
    /// Create a new function pointer.
    pub fn new(type_id: u64, name: impl Into<String>, subtype: IsfFunction) -> Self {
        Self {
            type_id,
            name: name.into(),
            kind: "pointer".into(),
            subtype,
        }
    }
}

impl IsfObject for IsfFunctionPointer {
    fn to_type_def(&self) -> IsfTypeDef {
        let mut props = BTreeMap::new();
        props.insert("kind".into(), serde_json::json!("pointer"));
        props.insert(
            "subtype".into(),
            serde_json::to_value(self.subtype.to_type_def()).unwrap_or_default(),
        );
        IsfTypeDef {
            type_id: self.type_id,
            name: self.name.clone(),
            kind: IsfTypeKind::Pointer,
            size: 0,
            alignment: 0,
            components: vec![],
            properties: props,
        }
    }
}

// ---------------------------------------------------------------------------
// IsfDataTypeArray
// ---------------------------------------------------------------------------

/// An array data type.
///
/// Ported from Ghidra's `IsfDataTypeArray`. Represents an array of a
/// given element type with a known element count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfDataTypeArray {
    /// The type ID.
    pub type_id: u64,
    /// The type name.
    pub name: String,
    /// Always "array".
    pub kind: String,
    /// Number of elements.
    pub count: u64,
    /// The element type (as an ISF type definition).
    pub subtype: Box<IsfTypeDef>,
}

impl IsfDataTypeArray {
    /// Create a new array type.
    pub fn new(
        type_id: u64,
        name: impl Into<String>,
        count: u64,
        subtype: IsfTypeDef,
    ) -> Self {
        Self {
            type_id,
            name: name.into(),
            kind: "array".into(),
            count,
            subtype: Box::new(subtype),
        }
    }
}

impl IsfObject for IsfDataTypeArray {
    fn to_type_def(&self) -> IsfTypeDef {
        let mut props = BTreeMap::new();
        props.insert("kind".into(), serde_json::json!("array"));
        props.insert("count".into(), serde_json::json!(self.count));
        props.insert(
            "subtype".into(),
            serde_json::to_value(&*self.subtype).unwrap_or_default(),
        );
        IsfTypeDef {
            type_id: self.type_id,
            name: self.name.clone(),
            kind: IsfTypeKind::Array,
            size: self.subtype.size * self.count,
            alignment: self.subtype.alignment,
            components: vec![],
            properties: props,
        }
    }
}

// ---------------------------------------------------------------------------
// IsfDataTypeBitField
// ---------------------------------------------------------------------------

/// A bit field data type.
///
/// Ported from Ghidra's `IsfDataTypeBitField`. Represents a bit field
/// within a storage type, specifying bit position and length.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfDataTypeBitField {
    /// The type ID.
    pub type_id: u64,
    /// The type name.
    pub name: String,
    /// Always "bitfield".
    pub kind: String,
    /// The bit length of the field.
    pub bit_length: u32,
    /// The bit position within the storage unit.
    pub bit_position: u32,
    /// The base storage type.
    pub storage_type: Box<IsfTypeDef>,
    /// The storage size in bytes.
    pub storage_size: u64,
}

impl IsfDataTypeBitField {
    /// Create a new bit field type.
    pub fn new(
        type_id: u64,
        name: impl Into<String>,
        bit_length: u32,
        bit_position: u32,
        storage_type: IsfTypeDef,
        storage_size: u64,
    ) -> Self {
        Self {
            type_id,
            name: name.into(),
            kind: "bitfield".into(),
            bit_length,
            bit_position,
            storage_type: Box::new(storage_type),
            storage_size,
        }
    }
}

impl IsfObject for IsfDataTypeBitField {
    fn to_type_def(&self) -> IsfTypeDef {
        let mut props = BTreeMap::new();
        props.insert("kind".into(), serde_json::json!("bitfield"));
        props.insert("bit_length".into(), serde_json::json!(self.bit_length));
        props.insert("bit_position".into(), serde_json::json!(self.bit_position));
        props.insert("storage_size".into(), serde_json::json!(self.storage_size));
        props.insert(
            "storage_type".into(),
            serde_json::to_value(&*self.storage_type).unwrap_or_default(),
        );
        IsfTypeDef {
            type_id: self.type_id,
            name: self.name.clone(),
            kind: IsfTypeKind::BitField,
            size: self.storage_size,
            alignment: 1,
            components: vec![],
            properties: props,
        }
    }
}

// ---------------------------------------------------------------------------
// IsfDynamicComponent
// ---------------------------------------------------------------------------

/// A dynamic-length component (e.g., flexible array member).
///
/// Ported from Ghidra's `IsfDynamicComponent`. Represents a dynamic
/// array within a composite type whose element count is determined at
/// runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfDynamicComponent {
    /// The type ID.
    pub type_id: u64,
    /// The type name.
    pub name: String,
    /// Always "array".
    pub kind: String,
    /// Number of elements.
    pub count: u64,
    /// The element type.
    pub subtype: Box<IsfTypeDef>,
}

impl IsfDynamicComponent {
    /// Create a new dynamic component.
    pub fn new(
        type_id: u64,
        name: impl Into<String>,
        count: u64,
        subtype: IsfTypeDef,
    ) -> Self {
        Self {
            type_id,
            name: name.into(),
            kind: "array".into(),
            count,
            subtype: Box::new(subtype),
        }
    }
}

impl IsfObject for IsfDynamicComponent {
    fn to_type_def(&self) -> IsfTypeDef {
        let mut props = BTreeMap::new();
        props.insert("kind".into(), serde_json::json!("array"));
        props.insert("count".into(), serde_json::json!(self.count));
        props.insert("dynamic".into(), serde_json::json!(true));
        props.insert(
            "subtype".into(),
            serde_json::to_value(&*self.subtype).unwrap_or_default(),
        );
        IsfTypeDef {
            type_id: self.type_id,
            name: self.name.clone(),
            kind: IsfTypeKind::Array,
            size: self.subtype.size.saturating_mul(self.count),
            alignment: self.subtype.alignment,
            components: vec![],
            properties: props,
        }
    }
}

// ---------------------------------------------------------------------------
// IsfTypedObject
// ---------------------------------------------------------------------------

/// A typed object (pointer/array wrapping a base type).
///
/// Ported from Ghidra's `IsfTypedObject`. Used when the ISF representation
/// needs to express a type reference (pointer to or array of) a base type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfTypedObject {
    /// The type ID.
    pub type_id: u64,
    /// The type name.
    pub name: String,
    /// The kind of the wrapped type (e.g., "struct", "base", "pointer").
    pub kind: String,
    /// Size in bytes (-1 for language-dependent sizes).
    pub size: i64,
    /// The wrapped type definition.
    #[serde(rename = "type")]
    pub type_ref: Box<IsfTypeDef>,
}

impl IsfTypedObject {
    /// Create a new typed object.
    pub fn new(
        type_id: u64,
        name: impl Into<String>,
        kind: impl Into<String>,
        size: i64,
        type_ref: IsfTypeDef,
    ) -> Self {
        Self {
            type_id,
            name: name.into(),
            kind: kind.into(),
            size,
            type_ref: Box::new(type_ref),
        }
    }
}

impl IsfObject for IsfTypedObject {
    fn to_type_def(&self) -> IsfTypeDef {
        let mut props = BTreeMap::new();
        props.insert("kind".into(), serde_json::json!(self.kind));
        props.insert("size".into(), serde_json::json!(self.size));
        props.insert(
            "type_ref".into(),
            serde_json::to_value(&*self.type_ref).unwrap_or_default(),
        );
        IsfTypeDef {
            type_id: self.type_id,
            name: self.name.clone(),
            kind: IsfTypeKind::Pointer, // Best approximation
            size: self.size.max(0) as u64,
            alignment: 1,
            components: vec![],
            properties: props,
        }
    }
}

// ---------------------------------------------------------------------------
// IsfSetting
// ---------------------------------------------------------------------------

/// A named setting value.
///
/// Ported from Ghidra's `IsfSetting`. Used to represent metadata
/// key-value pairs in ISF exports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfSetting {
    /// The setting name.
    pub name: String,
    /// The setting kind: "string" or "long".
    pub kind: String,
    /// The setting value as a string.
    pub value: String,
}

impl IsfSetting {
    /// Create a string setting.
    pub fn string(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: "string".into(),
            value: value.into(),
        }
    }

    /// Create a numeric setting.
    pub fn long(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            kind: "long".into(),
            value: value.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// IsfProducer
// ---------------------------------------------------------------------------

/// Producer metadata for an ISF export.
///
/// Ported from Ghidra's `IsfProducer`. Describes the tool that
/// produced the ISF data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfProducer {
    /// The creation datetime.
    pub datetime: String,
    /// The producer name.
    pub name: String,
    /// The producer version.
    pub version: String,
}

impl IsfProducer {
    /// Create a new producer.
    pub fn new(
        datetime: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            datetime: datetime.into(),
            name: name.into(),
            version: version.into(),
        }
    }

    /// Create a Ghidra producer with the given version.
    pub fn ghidra(version: impl Into<String>) -> Self {
        Self::new(
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
            "Ghidra",
            version,
        )
    }
}

// ---------------------------------------------------------------------------
// IsfUtilities
// ---------------------------------------------------------------------------

/// Utility functions for ISF type classification.
///
/// Ported from Ghidra's `IsfUtilities`.
pub struct IsfUtilities;

impl IsfUtilities {
    /// Get the kind string for an ISF type kind.
    pub fn kind_string(kind: &IsfTypeKind) -> &'static str {
        match kind {
            IsfTypeKind::BuiltIn => "base",
            IsfTypeKind::Composite => "struct",
            IsfTypeKind::Enum => "enum",
            IsfTypeKind::Pointer => "pointer",
            IsfTypeKind::Typedef => "typedef",
            IsfTypeKind::Function => "function",
            IsfTypeKind::Array => "array",
            IsfTypeKind::BitField => "bitfield",
        }
    }

    /// Whether a type kind is a "base" type (built-in, pointer, void).
    pub fn is_base_type(kind: &IsfTypeKind) -> bool {
        matches!(kind, IsfTypeKind::BuiltIn | IsfTypeKind::Pointer)
    }

    /// Whether a type kind is a user-defined type (composite, typedef, etc.).
    pub fn is_user_type(kind: &IsfTypeKind) -> bool {
        matches!(
            kind,
            IsfTypeKind::Composite
                | IsfTypeKind::Typedef
                | IsfTypeKind::Function
                | IsfTypeKind::Array
                | IsfTypeKind::BitField
        )
    }

    /// Categorize an ISF type definition into one of three ISF JSON sections:
    /// "base_types", "user_types", or "enums".
    pub fn categorize(td: &IsfTypeDef) -> &'static str {
        match td.kind {
            IsfTypeKind::BuiltIn | IsfTypeKind::Pointer => "base_types",
            IsfTypeKind::Enum => "enums",
            _ => "user_types",
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
    fn test_isf_built_in_endian() {
        let bt = IsfBuiltIn::new(1, "int", 4).with_endian("big");
        let td = bt.to_type_def();
        assert_eq!(td.properties["endian"], serde_json::json!("big"));
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
    fn test_isf_pointer_endian() {
        let p = IsfPointer::new(30, "int *", 8, 1).with_endian("big");
        let td = p.to_type_def();
        assert_eq!(td.properties["endian"], serde_json::json!("big"));
    }

    #[test]
    fn test_isf_typedef() {
        let t = IsfTypedef::new(40, "pid_t", 1, 4);
        let td = t.to_type_def();
        assert_eq!(td.kind, IsfTypeKind::Typedef);
        assert_eq!(td.properties["base"], serde_json::json!(1));
        assert_eq!(td.properties["typedef_kind"], serde_json::json!("user"));
    }

    #[test]
    fn test_isf_typedef_integral() {
        let t = IsfTypedef::new_integral(41, "size_t", 2, 8);
        let td = t.to_type_def();
        assert_eq!(td.properties["typedef_kind"], serde_json::json!("integral"));
    }

    #[test]
    fn test_isf_typedef_pointer() {
        let t = IsfTypedef::new_pointer(42, "foo_t", 3, 8);
        let td = t.to_type_def();
        assert_eq!(td.properties["typedef_kind"], serde_json::json!("pointer"));
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
    fn test_isf_function_pointer() {
        let func = IsfFunction::new(52, "callback", 1);
        let fp = IsfFunctionPointer::new(53, "callback_t", func);
        let td = fp.to_type_def();
        assert_eq!(td.kind, IsfTypeKind::Pointer);
        assert_eq!(td.properties["kind"], serde_json::json!("pointer"));
    }

    #[test]
    fn test_isf_data_type_array() {
        let elem = IsfTypeDef {
            type_id: 1,
            name: "int".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 4,
            alignment: 4,
            components: vec![],
            properties: BTreeMap::new(),
        };
        let arr = IsfDataTypeArray::new(60, "int_arr", 10, elem);
        let td = arr.to_type_def();
        assert_eq!(td.kind, IsfTypeKind::Array);
        assert_eq!(td.size, 40);
        assert_eq!(td.properties["count"], serde_json::json!(10));
        assert_eq!(td.properties["kind"], serde_json::json!("array"));
    }

    #[test]
    fn test_isf_bitfield() {
        let base = IsfTypeDef {
            type_id: 1,
            name: "unsigned int".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 4,
            alignment: 4,
            components: vec![],
            properties: BTreeMap::new(),
        };
        let bf = IsfDataTypeBitField::new(70, "flags_bf", 3, 8, base, 4);
        let td = bf.to_type_def();
        assert_eq!(td.kind, IsfTypeKind::BitField);
        assert_eq!(td.properties["bit_length"], serde_json::json!(3));
        assert_eq!(td.properties["bit_position"], serde_json::json!(8));
    }

    #[test]
    fn test_isf_dynamic_component() {
        let elem = IsfTypeDef {
            type_id: 1,
            name: "char".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 1,
            alignment: 1,
            components: vec![],
            properties: BTreeMap::new(),
        };
        let dc = IsfDynamicComponent::new(80, "flexible_arr", 0, elem);
        let td = dc.to_type_def();
        assert_eq!(td.kind, IsfTypeKind::Array);
        assert_eq!(td.properties["dynamic"], serde_json::json!(true));
    }

    #[test]
    fn test_isf_typed_object() {
        let inner = IsfTypeDef {
            type_id: 1,
            name: "int".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 4,
            alignment: 4,
            components: vec![],
            properties: BTreeMap::new(),
        };
        let to = IsfTypedObject::new(90, "int*", "pointer", 8, inner);
        let td = to.to_type_def();
        assert_eq!(td.properties["kind"], serde_json::json!("pointer"));
    }

    #[test]
    fn test_isf_setting() {
        let s = IsfSetting::string("format", "6.2.0");
        assert_eq!(s.kind, "string");
        assert_eq!(s.value, "6.2.0");

        let s = IsfSetting::long("count", 42);
        assert_eq!(s.kind, "long");
        assert_eq!(s.value, "42");
    }

    #[test]
    fn test_isf_producer() {
        let p = IsfProducer::new("2024-01-01 12:00:00.000000", "Ghidra", "11.0");
        assert_eq!(p.name, "Ghidra");
        assert_eq!(p.version, "11.0");
        assert_eq!(p.datetime, "2024-01-01 12:00:00.000000");
    }

    #[test]
    fn test_isf_producer_ghidra() {
        let p = IsfProducer::ghidra("11.2");
        assert_eq!(p.name, "Ghidra");
        assert_eq!(p.version, "11.2");
        assert!(!p.datetime.is_empty());
    }

    #[test]
    fn test_isf_utilities() {
        assert_eq!(IsfUtilities::kind_string(&IsfTypeKind::BuiltIn), "base");
        assert_eq!(IsfUtilities::kind_string(&IsfTypeKind::Composite), "struct");
        assert_eq!(IsfUtilities::kind_string(&IsfTypeKind::Enum), "enum");
        assert_eq!(IsfUtilities::kind_string(&IsfTypeKind::Array), "array");

        assert!(IsfUtilities::is_base_type(&IsfTypeKind::BuiltIn));
        assert!(IsfUtilities::is_base_type(&IsfTypeKind::Pointer));
        assert!(!IsfUtilities::is_base_type(&IsfTypeKind::Composite));

        assert!(IsfUtilities::is_user_type(&IsfTypeKind::Composite));
        assert!(IsfUtilities::is_user_type(&IsfTypeKind::Array));
        assert!(!IsfUtilities::is_user_type(&IsfTypeKind::BuiltIn));

        assert_eq!(
            IsfUtilities::categorize(&IsfTypeDef {
                type_id: 0, name: "".into(), kind: IsfTypeKind::BuiltIn,
                size: 0, alignment: 0, components: vec![], properties: BTreeMap::new()
            }),
            "base_types"
        );
        assert_eq!(
            IsfUtilities::categorize(&IsfTypeDef {
                type_id: 0, name: "".into(), kind: IsfTypeKind::Enum,
                size: 0, alignment: 0, components: vec![], properties: BTreeMap::new()
            }),
            "enums"
        );
        assert_eq!(
            IsfUtilities::categorize(&IsfTypeDef {
                type_id: 0, name: "".into(), kind: IsfTypeKind::Composite,
                size: 0, alignment: 0, components: vec![], properties: BTreeMap::new()
            }),
            "user_types"
        );
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

        let func = IsfFunction::new(50, "main", 1);
        let json = serde_json::to_string(&func).unwrap();
        let _: IsfFunction = serde_json::from_str(&json).unwrap();

        let fp = IsfFunctionPointer::new(53, "cb", IsfFunction::new(52, "f", 1));
        let json = serde_json::to_string(&fp).unwrap();
        let _: IsfFunctionPointer = serde_json::from_str(&json).unwrap();

        let s = IsfSetting::string("key", "val");
        let json = serde_json::to_string(&s).unwrap();
        let _: IsfSetting = serde_json::from_str(&json).unwrap();

        let p = IsfProducer::ghidra("1.0");
        let json = serde_json::to_string(&p).unwrap();
        let _: IsfProducer = serde_json::from_str(&json).unwrap();
    }
}
