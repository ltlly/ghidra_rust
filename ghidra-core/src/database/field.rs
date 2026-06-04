//! Ghidra Field type system ported from Java's `db` package.
//!
//! The Java framework uses an abstract `Field` class with polymorphic subclasses
//! (LongField, IntField, StringField, etc.). In Rust we use an enum
//! ([`GhidraField`]) with typed variants for static dispatch, while still
//! preserving the full API surface of every Java Field class.
//!
//! ## Field Type Codes
//!
//! The 8-bit field type encoding from the Java source is preserved:
//!
//! | Code | Type              |
//! |------|-------------------|
//! | 0    | ByteField         |
//! | 1    | ShortField        |
//! | 2    | IntField          |
//! | 3    | LongField         |
//! | 4    | StringField       |
//! | 5    | BinaryField       |
//! | 6    | BooleanField      |
//! | 7    | FixedField10      |
//! | 8    | LegacyIndexField  |

use crate::database::error::IllegalFieldAccessException;
use std::cmp::Ordering;
use std::fmt;

// ============================================================================
// Field type constants (ported from Java Field)
// ============================================================================

/// 1-byte signed integer field type code.
pub const BYTE_TYPE: u8 = 0;
/// 2-byte signed integer field type code.
pub const SHORT_TYPE: u8 = 1;
/// 4-byte signed integer field type code.
pub const INT_TYPE: u8 = 2;
/// 8-byte signed integer field type code.
pub const LONG_TYPE: u8 = 3;
/// Variable-length UTF-8 string field type code.
pub const STRING_TYPE: u8 = 4;
/// Variable-length binary blob field type code.
pub const BINARY_OBJ_TYPE: u8 = 5;
/// 1-byte boolean field type code.
pub const BOOLEAN_TYPE: u8 = 6;
/// 10-byte fixed-length binary field type code.
pub const FIXED_10_TYPE: u8 = 7;
/// Legacy long-key index field type code.
pub const LEGACY_INDEX_LONG_TYPE: u8 = 8;

/// Field type mask (lower nibble).
pub const FIELD_TYPE_MASK: u8 = 0x0F;
/// Index primary key type mask (upper nibble).
pub const INDEX_PRIMARY_KEY_TYPE_MASK: u8 = !FIELD_TYPE_MASK;
/// Index field type shift.
pub const INDEX_FIELD_TYPE_SHIFT: u32 = 4;
/// Reserved field encoding value.
pub const FIELD_EXTENSION_INDICATOR: u8 = 0xff;

// ============================================================================
// GhidraField — the unified field enum (port of Java Field hierarchy)
// ============================================================================

/// A typed field value used in Ghidra database records.
///
/// This is the Rust equivalent of Java's abstract `Field` class and all its
/// subclasses: `LongField`, `IntField`, `ShortField`, `ByteField`,
/// `BooleanField`, `StringField`, `BinaryField`, `FixedField10`,
/// `BinaryCodedField`, `IndexField`, `LegacyIndexField`.
///
/// Fields can be in a null state (distinct from zero for primitive types)
/// when used as sparse columns within a `SparseRecord`.
#[derive(Debug, Clone)]
pub enum GhidraField {
    /// 8-byte signed long (port of `LongField`).
    Long {
        value: i64,
        is_null: bool,
    },
    /// 4-byte signed integer (port of `IntField`).
    Int {
        value: i32,
        is_null: bool,
    },
    /// 2-byte signed short (port of `ShortField`).
    Short {
        value: i16,
        is_null: bool,
    },
    /// 1-byte signed byte (port of `ByteField`).
    Byte {
        value: i8,
        is_null: bool,
    },
    /// 1-byte boolean (port of `BooleanField`).
    Boolean {
        value: bool,
        is_null: bool,
    },
    /// Variable-length UTF-8 string (port of `StringField`).
    String {
        value: Option<String>,
    },
    /// Variable-length binary data (port of `BinaryField`).
    Binary {
        value: Option<Vec<u8>>,
    },
    /// 10-byte fixed-length binary (port of `FixedField10`).
    Fixed10 {
        value: [u8; 10],
        is_null: bool,
    },
    /// Binary-coded composite field (port of `BinaryCodedField`).
    BinaryCoded {
        fields: Vec<GhidraField>,
    },
    /// Index field with a specific key type (port of `IndexField`).
    Index {
        key_field: Box<GhidraField>,
        field_type_code: u8,
    },
    /// Legacy index field with long key (port of `LegacyIndexField`).
    LegacyIndex {
        key_value: i64,
    },
}

impl GhidraField {
    // ---- Constructors (mirrors Java's INSTANCE / newField() pattern) ----

    /// Create a new LongField with value 0.
    pub fn new_long() -> Self {
        GhidraField::Long {
            value: 0,
            is_null: false,
        }
    }

    /// Create a LongField with the given value.
    pub fn long(v: i64) -> Self {
        GhidraField::Long {
            value: v,
            is_null: false,
        }
    }

    /// Create a new IntField with value 0.
    pub fn new_int() -> Self {
        GhidraField::Int {
            value: 0,
            is_null: false,
        }
    }

    /// Create an IntField with the given value.
    pub fn int(v: i32) -> Self {
        GhidraField::Int {
            value: v,
            is_null: false,
        }
    }

    /// Create a new ShortField with value 0.
    pub fn new_short() -> Self {
        GhidraField::Short {
            value: 0,
            is_null: false,
        }
    }

    /// Create a ShortField with the given value.
    pub fn short(v: i16) -> Self {
        GhidraField::Short {
            value: v,
            is_null: false,
        }
    }

    /// Create a new ByteField with value 0.
    pub fn new_byte() -> Self {
        GhidraField::Byte {
            value: 0,
            is_null: false,
        }
    }

    /// Create a ByteField with the given value.
    pub fn byte(v: i8) -> Self {
        GhidraField::Byte {
            value: v,
            is_null: false,
        }
    }

    /// Create a new BooleanField with value false.
    pub fn new_boolean() -> Self {
        GhidraField::Boolean {
            value: false,
            is_null: false,
        }
    }

    /// Create a BooleanField with the given value.
    pub fn boolean(v: bool) -> Self {
        GhidraField::Boolean {
            value: v,
            is_null: false,
        }
    }

    /// Create a new StringField with null value.
    pub fn new_string() -> Self {
        GhidraField::String { value: None }
    }

    /// Create a StringField with the given value.
    pub fn string(v: impl Into<String>) -> Self {
        GhidraField::String {
            value: Some(v.into()),
        }
    }

    /// Create a new BinaryField with null value.
    pub fn new_binary() -> Self {
        GhidraField::Binary { value: None }
    }

    /// Create a BinaryField with the given data.
    pub fn binary(v: Vec<u8>) -> Self {
        GhidraField::Binary {
            value: Some(v),
        }
    }

    /// Create a new FixedField10 with zero value.
    pub fn new_fixed10() -> Self {
        GhidraField::Fixed10 {
            value: [0u8; 10],
            is_null: false,
        }
    }

    /// Create a FixedField10 with the given bytes.
    pub fn fixed10(v: [u8; 10]) -> Self {
        GhidraField::Fixed10 {
            value: v,
            is_null: false,
        }
    }

    /// Create an IndexField wrapping the given key field and type code.
    pub fn index(key: GhidraField, type_code: u8) -> Self {
        GhidraField::Index {
            key_field: Box::new(key),
            field_type_code: type_code,
        }
    }

    /// Create a LegacyIndexField with the given long key.
    pub fn legacy_index(key: i64) -> Self {
        GhidraField::LegacyIndex { key_value: key }
    }

    // ---- INSTANCE constants (mirrors Java INSTANCE static fields) ----

    /// LongField INSTANCE (zero value, immutable).
    pub fn long_instance() -> Self {
        GhidraField::long(0)
    }

    /// IntField INSTANCE (zero value, immutable).
    pub fn int_instance() -> Self {
        GhidraField::int(0)
    }

    /// ShortField INSTANCE (zero value, immutable).
    pub fn short_instance() -> Self {
        GhidraField::short(0)
    }

    /// ByteField INSTANCE (zero value, immutable).
    pub fn byte_instance() -> Self {
        GhidraField::byte(0)
    }

    /// BooleanField INSTANCE (false, immutable).
    pub fn boolean_instance() -> Self {
        GhidraField::boolean(false)
    }

    /// StringField INSTANCE (null value, immutable).
    pub fn string_instance() -> Self {
        GhidraField::new_string()
    }

    /// BinaryField INSTANCE (null value, immutable).
    pub fn binary_instance() -> Self {
        GhidraField::new_binary()
    }

    /// FixedField10 INSTANCE (zero, immutable).
    pub fn fixed10_instance() -> Self {
        GhidraField::new_fixed10()
    }

    // ---- MIN_VALUE / MAX_VALUE constants ----

    /// Minimum value for LongField.
    pub fn long_min_value() -> Self {
        GhidraField::long(i64::MIN)
    }

    /// Maximum value for LongField.
    pub fn long_max_value() -> Self {
        GhidraField::long(i64::MAX)
    }

    /// Minimum value for IntField.
    pub fn int_min_value() -> Self {
        GhidraField::int(i32::MIN)
    }

    /// Maximum value for IntField.
    pub fn int_max_value() -> Self {
        GhidraField::int(i32::MAX)
    }

    /// Minimum value for ShortField.
    pub fn short_min_value() -> Self {
        GhidraField::short(i16::MIN)
    }

    /// Maximum value for ShortField.
    pub fn short_max_value() -> Self {
        GhidraField::short(i16::MAX)
    }

    /// Minimum value for ByteField.
    pub fn byte_min_value() -> Self {
        GhidraField::byte(i8::MIN)
    }

    /// Maximum value for ByteField.
    pub fn byte_max_value() -> Self {
        GhidraField::byte(i8::MAX)
    }

    /// Minimum value for BooleanField (false).
    pub fn boolean_min_value() -> Self {
        GhidraField::boolean(false)
    }

    /// Maximum value for BooleanField (true).
    pub fn boolean_max_value() -> Self {
        GhidraField::boolean(true)
    }

    // ---- Factory method (port of Java Field.getField(byte)) ----

    /// Get a field instance for the given field type code.
    ///
    /// Port of Java `Field.getField(byte fieldType)`.
    pub fn get_field(field_type: u8) -> Result<Self, crate::database::error::UnsupportedFieldException> {
        if field_type == 0x88 {
            return Err(crate::database::error::UnsupportedFieldException::new(field_type));
        }
        if (field_type & INDEX_PRIMARY_KEY_TYPE_MASK) == 0 {
            match field_type & FIELD_TYPE_MASK {
                LONG_TYPE => Ok(GhidraField::long_instance()),
                INT_TYPE => Ok(GhidraField::int_instance()),
                STRING_TYPE => Ok(GhidraField::string_instance()),
                SHORT_TYPE => Ok(GhidraField::short_instance()),
                BYTE_TYPE => Ok(GhidraField::byte_instance()),
                BOOLEAN_TYPE => Ok(GhidraField::boolean_instance()),
                BINARY_OBJ_TYPE => Ok(GhidraField::binary_instance()),
                FIXED_10_TYPE => Ok(GhidraField::fixed10_instance()),
                _ => Err(crate::database::error::UnsupportedFieldException::new(field_type)),
            }
        } else {
            // Index field — the upper nibble encodes the primary key type
            Self::get_index_field(field_type)
        }
    }

    /// Get an IndexField for the given encoded field type.
    ///
    /// Port of Java `IndexField.getIndexField(byte)`.
    fn get_index_field(field_type: u8) -> Result<Self, crate::database::error::UnsupportedFieldException> {
        let key_type = (field_type >> INDEX_FIELD_TYPE_SHIFT) & 0x0F;
        let inner = GhidraField::get_field(key_type)?;
        Ok(GhidraField::index(inner, field_type))
    }

    /// Get a fixed-length field of the specified size.
    ///
    /// Port of Java `Field.getFixedField(int size)`.
    pub fn get_fixed_field(size: usize) -> Result<Self, String> {
        match size {
            1 => Ok(GhidraField::new_byte()),
            4 => Ok(GhidraField::new_int()),
            8 => Ok(GhidraField::new_long()),
            10 => Ok(GhidraField::new_fixed10()),
            _ => Err(format!("Unsupported fixed-field length: {}", size)),
        }
    }

    /// Get the fixed-field type byte for the given fixed length.
    ///
    /// Port of Java `Field.getFixedType(int fixedLength)`.
    pub fn get_fixed_type(fixed_length: usize) -> Result<u8, String> {
        match fixed_length {
            10 => Ok(FIXED_10_TYPE),
            _ => Err(format!("Unsupported fixed-length binary type size: {}", fixed_length)),
        }
    }

    /// Determine if a field instance may be indexed.
    ///
    /// Port of Java `Field.canIndex(Field)`.
    pub fn can_index(&self) -> bool {
        match self {
            GhidraField::Index { .. } => false,
            GhidraField::Boolean { .. } => false,
            GhidraField::Byte { .. } => false,
            _ => true,
        }
    }

    // ---- Typed value accessors ----

    /// Get as `i64` (port of `getLongValue`).
    pub fn get_long_value(&self) -> Result<i64, IllegalFieldAccessException> {
        match self {
            GhidraField::Long { value, .. } => Ok(*value),
            GhidraField::Int { value, .. } => Ok(*value as i64),
            GhidraField::Short { value, .. } => Ok(*value as i64),
            GhidraField::Byte { value, .. } => Ok(*value as i64),
            GhidraField::Boolean { value, .. } => Ok(if *value { 1 } else { 0 }),
            _ => Err(IllegalFieldAccessException::with_message(
                "getLongValue not supported for this field type",
            )),
        }
    }

    /// Set from `i64` (port of `setLongValue`).
    pub fn set_long_value(&mut self, v: i64) -> Result<(), IllegalFieldAccessException> {
        match self {
            GhidraField::Long { value, is_null } => {
                *value = v;
                *is_null = false;
                Ok(())
            }
            GhidraField::Int { value, is_null } => {
                *value = v as i32;
                *is_null = false;
                Ok(())
            }
            GhidraField::Short { value, is_null } => {
                *value = v as i16;
                *is_null = false;
                Ok(())
            }
            GhidraField::Byte { value, is_null } => {
                *value = v as i8;
                *is_null = false;
                Ok(())
            }
            GhidraField::Boolean { value, is_null } => {
                *value = v != 0;
                *is_null = false;
                Ok(())
            }
            _ => Err(IllegalFieldAccessException::with_message(
                "setLongValue not supported for this field type",
            )),
        }
    }

    /// Get as `i32` (port of `getIntValue`).
    pub fn get_int_value(&self) -> Result<i32, IllegalFieldAccessException> {
        match self {
            GhidraField::Int { value, .. } => Ok(*value),
            GhidraField::Long { value, .. } => Ok(*value as i32),
            GhidraField::Short { value, .. } => Ok(*value as i32),
            GhidraField::Byte { value, .. } => Ok(*value as i32),
            _ => Err(IllegalFieldAccessException::with_message(
                "getIntValue not supported for this field type",
            )),
        }
    }

    /// Set from `i32` (port of `setIntValue`).
    pub fn set_int_value(&mut self, v: i32) -> Result<(), IllegalFieldAccessException> {
        match self {
            GhidraField::Int { value, is_null } => {
                *value = v;
                *is_null = false;
                Ok(())
            }
            _ => Err(IllegalFieldAccessException::with_message(
                "setIntValue not supported for this field type",
            )),
        }
    }

    /// Get as `i16` (port of `getShortValue`).
    pub fn get_short_value(&self) -> Result<i16, IllegalFieldAccessException> {
        match self {
            GhidraField::Short { value, .. } => Ok(*value),
            _ => Err(IllegalFieldAccessException::with_message(
                "getShortValue not supported for this field type",
            )),
        }
    }

    /// Set from `i16` (port of `setShortValue`).
    pub fn set_short_value(&mut self, v: i16) -> Result<(), IllegalFieldAccessException> {
        match self {
            GhidraField::Short { value, is_null } => {
                *value = v;
                *is_null = false;
                Ok(())
            }
            _ => Err(IllegalFieldAccessException::with_message(
                "setShortValue not supported for this field type",
            )),
        }
    }

    /// Get as `i8` (port of `getByteValue`).
    pub fn get_byte_value(&self) -> Result<i8, IllegalFieldAccessException> {
        match self {
            GhidraField::Byte { value, .. } => Ok(*value),
            _ => Err(IllegalFieldAccessException::with_message(
                "getByteValue not supported for this field type",
            )),
        }
    }

    /// Set from `i8` (port of `setByteValue`).
    pub fn set_byte_value(&mut self, v: i8) -> Result<(), IllegalFieldAccessException> {
        match self {
            GhidraField::Byte { value, is_null } => {
                *value = v;
                *is_null = false;
                Ok(())
            }
            _ => Err(IllegalFieldAccessException::with_message(
                "setByteValue not supported for this field type",
            )),
        }
    }

    /// Get as `bool` (port of `getBooleanValue`).
    pub fn get_boolean_value(&self) -> Result<bool, IllegalFieldAccessException> {
        match self {
            GhidraField::Boolean { value, .. } => Ok(*value),
            _ => Err(IllegalFieldAccessException::with_message(
                "getBooleanValue not supported for this field type",
            )),
        }
    }

    /// Set from `bool` (port of `setBooleanValue`).
    pub fn set_boolean_value(&mut self, v: bool) -> Result<(), IllegalFieldAccessException> {
        match self {
            GhidraField::Boolean { value, is_null } => {
                *value = v;
                *is_null = false;
                Ok(())
            }
            _ => Err(IllegalFieldAccessException::with_message(
                "setBooleanValue not supported for this field type",
            )),
        }
    }

    /// Get as string (port of `getString`).
    pub fn get_string(&self) -> Result<Option<&str>, IllegalFieldAccessException> {
        match self {
            GhidraField::String { value } => Ok(value.as_deref()),
            _ => Err(IllegalFieldAccessException::with_message(
                "getString not supported for this field type",
            )),
        }
    }

    /// Set from string (port of `setString`).
    pub fn set_string(&mut self, s: Option<String>) -> Result<(), IllegalFieldAccessException> {
        match self {
            GhidraField::String { value } => {
                *value = s;
                Ok(())
            }
            _ => Err(IllegalFieldAccessException::with_message(
                "setString not supported for this field type",
            )),
        }
    }

    /// Get binary data (port of `getBinaryData`).
    pub fn get_binary_data(&self) -> Option<&[u8]> {
        match self {
            GhidraField::Binary { value } => value.as_deref(),
            GhidraField::String { value } => value.as_ref().map(|s| s.as_bytes()),
            GhidraField::Fixed10 { value, is_null } => {
                if *is_null {
                    None
                } else {
                    Some(value.as_slice())
                }
            }
            _ => None,
        }
    }

    /// Set binary data (port of `setBinaryData`).
    pub fn set_binary_data(&mut self, data: Option<Vec<u8>>) {
        match self {
            GhidraField::Binary { value } => {
                *value = data;
            }
            GhidraField::Fixed10 { value, is_null } => {
                if let Some(bytes) = data {
                    let len = bytes.len().min(10);
                    value[..len].copy_from_slice(&bytes[..len]);
                    *is_null = false;
                } else {
                    *value = [0u8; 10];
                    *is_null = true;
                }
            }
            _ => {}
        }
    }

    // ---- State queries ----

    /// True if the field is in a null state.
    ///
    /// Port of Java `Field.isNull()`.
    pub fn is_null(&self) -> bool {
        match self {
            GhidraField::Long { is_null, .. } => *is_null,
            GhidraField::Int { is_null, .. } => *is_null,
            GhidraField::Short { is_null, .. } => *is_null,
            GhidraField::Byte { is_null, .. } => *is_null,
            GhidraField::Boolean { is_null, .. } => *is_null,
            GhidraField::String { value } => value.is_none(),
            GhidraField::Binary { value } => value.is_none(),
            GhidraField::Fixed10 { is_null, .. } => *is_null,
            GhidraField::BinaryCoded { fields } => fields.iter().all(|f| f.is_null()),
            GhidraField::Index { key_field, .. } => key_field.is_null(),
            GhidraField::LegacyIndex { .. } => false,
        }
    }

    /// Set the field to its null state.
    ///
    /// Port of Java `Field.setNull()`.
    pub fn set_null(&mut self) {
        match self {
            GhidraField::Long { value, is_null } => {
                *value = 0;
                *is_null = true;
            }
            GhidraField::Int { value, is_null } => {
                *value = 0;
                *is_null = true;
            }
            GhidraField::Short { value, is_null } => {
                *value = 0;
                *is_null = true;
            }
            GhidraField::Byte { value, is_null } => {
                *value = 0;
                *is_null = true;
            }
            GhidraField::Boolean { value, is_null } => {
                *value = false;
                *is_null = true;
            }
            GhidraField::String { value } => {
                *value = None;
            }
            GhidraField::Binary { value } => {
                *value = None;
            }
            GhidraField::Fixed10 { value, is_null } => {
                *value = [0u8; 10];
                *is_null = true;
            }
            GhidraField::BinaryCoded { fields } => {
                for f in fields.iter_mut() {
                    f.set_null();
                }
            }
            GhidraField::Index { key_field, .. } => key_field.set_null(),
            GhidraField::LegacyIndex { .. } => {}
        }
    }

    /// True if this is a variable-length field.
    ///
    /// Port of Java `Field.isVariableLength()`.
    pub fn is_variable_length(&self) -> bool {
        matches!(
            self,
            GhidraField::String { .. }
                | GhidraField::Binary { .. }
                | GhidraField::BinaryCoded { .. }
        )
    }

    /// True if this field is the same type as another.
    ///
    /// Port of Java `Field.isSameType(Field)`.
    pub fn is_same_type(&self, other: &GhidraField) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }

    /// Get the encoded field type byte.
    ///
    /// Port of Java `Field.getFieldType()`.
    pub fn get_field_type(&self) -> u8 {
        match self {
            GhidraField::Long { .. } => LONG_TYPE,
            GhidraField::Int { .. } => INT_TYPE,
            GhidraField::Short { .. } => SHORT_TYPE,
            GhidraField::Byte { .. } => BYTE_TYPE,
            GhidraField::Boolean { .. } => BOOLEAN_TYPE,
            GhidraField::String { .. } => STRING_TYPE,
            GhidraField::Binary { .. } => BINARY_OBJ_TYPE,
            GhidraField::Fixed10 { .. } => FIXED_10_TYPE,
            GhidraField::BinaryCoded { .. } => BINARY_OBJ_TYPE,
            GhidraField::Index { field_type_code, .. } => *field_type_code,
            GhidraField::LegacyIndex { .. } => LEGACY_INDEX_LONG_TYPE,
        }
    }

    /// Get the storage length in bytes for this field.
    ///
    /// Port of Java `Field.length()`.
    pub fn length(&self) -> usize {
        match self {
            GhidraField::Long { .. } => 8,
            GhidraField::Int { .. } => 4,
            GhidraField::Short { .. } => 2,
            GhidraField::Byte { .. } => 1,
            GhidraField::Boolean { .. } => 1,
            GhidraField::String { value } => {
                match value {
                    Some(s) => s.len() + 4, // 4-byte length prefix
                    None => 4,
                }
            }
            GhidraField::Binary { value } => {
                match value {
                    Some(v) => v.len() + 4,
                    None => 4,
                }
            }
            GhidraField::Fixed10 { .. } => 10,
            GhidraField::BinaryCoded { fields } => fields.iter().map(|f| f.length()).sum(),
            GhidraField::Index { key_field, .. } => key_field.length(),
            GhidraField::LegacyIndex { .. } => 8,
        }
    }

    /// Get the field value as a formatted string.
    ///
    /// Port of Java `Field.getValueAsString()`.
    pub fn get_value_as_string(&self) -> String {
        match self {
            GhidraField::Long { value, .. } => format!("0x{:x}", value),
            GhidraField::Int { value, .. } => format!("0x{:x}", value),
            GhidraField::Short { value, .. } => format!("0x{:x}", (*value as u32) & 0xffff),
            GhidraField::Byte { value, .. } => format!("0x{:x}", (*value as u32) & 0xff),
            GhidraField::Boolean { value, .. } => value.to_string(),
            GhidraField::String { value } => {
                match value {
                    Some(s) => format!("\"{}\"", s),
                    None => "null".to_string(),
                }
            }
            GhidraField::Binary { value } => {
                match value {
                    Some(v) => {
                        let hex: Vec<String> = v.iter().take(24).map(|b| format!("{:02x}", b)).collect();
                        let mut s = hex.join(" ");
                        if v.len() > 24 {
                            s.push_str("...");
                        }
                        format!("{{{}}}", s)
                    }
                    None => "null".to_string(),
                }
            }
            GhidraField::Fixed10 { value, .. } => {
                let hex: Vec<String> = value.iter().map(|b| format!("{:02x}", b)).collect();
                format!("{{{}}}", hex.join(" "))
            }
            GhidraField::BinaryCoded { fields } => {
                let inner: Vec<String> = fields.iter().map(|f| f.get_value_as_string()).collect();
                format!("BCD({})", inner.join(", "))
            }
            GhidraField::Index { key_field, .. } => {
                format!("IDX({})", key_field.get_value_as_string())
            }
            GhidraField::LegacyIndex { key_value } => {
                format!("LEGACY_IDX(0x{:x})", key_value)
            }
        }
    }

    /// Create a new empty field of the same type.
    ///
    /// Port of Java `Field.newField()`.
    pub fn new_field(&self) -> Self {
        match self {
            GhidraField::Long { .. } => GhidraField::new_long(),
            GhidraField::Int { .. } => GhidraField::new_int(),
            GhidraField::Short { .. } => GhidraField::new_short(),
            GhidraField::Byte { .. } => GhidraField::new_byte(),
            GhidraField::Boolean { .. } => GhidraField::new_boolean(),
            GhidraField::String { .. } => GhidraField::new_string(),
            GhidraField::Binary { .. } => GhidraField::new_binary(),
            GhidraField::Fixed10 { .. } => GhidraField::new_fixed10(),
            GhidraField::BinaryCoded { fields } => {
                GhidraField::BinaryCoded {
                    fields: fields.iter().map(|f| f.new_field()).collect(),
                }
            }
            GhidraField::Index { key_field, field_type_code } => {
                GhidraField::Index {
                    key_field: Box::new(key_field.new_field()),
                    field_type_code: *field_type_code,
                }
            }
            GhidraField::LegacyIndex { .. } => GhidraField::LegacyIndex { key_value: 0 },
        }
    }

    /// Create a copy of this field with the same value.
    ///
    /// Port of Java `Field.copyField()`.
    pub fn copy_field(&self) -> Self {
        self.clone()
    }

    /// Serialize this field to a byte vector.
    ///
    /// Port of Java `Field.getBinaryData()` (the canonical serialization).
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            GhidraField::Long { value, .. } => value.to_be_bytes().to_vec(),
            GhidraField::Int { value, .. } => value.to_be_bytes().to_vec(),
            GhidraField::Short { value, .. } => value.to_be_bytes().to_vec(),
            GhidraField::Byte { value, .. } => (*value as u8).to_be_bytes().to_vec(),
            GhidraField::Boolean { value, .. } => vec![if *value { 1u8 } else { 0u8 }],
            GhidraField::String { value } => {
                match value {
                    Some(s) => {
                        let bytes = s.as_bytes();
                        let mut result = (bytes.len() as i32).to_be_bytes().to_vec();
                        result.extend_from_slice(bytes);
                        result
                    }
                    None => (-1i32).to_be_bytes().to_vec(),
                }
            }
            GhidraField::Binary { value } => {
                match value {
                    Some(v) => {
                        let mut result = (v.len() as i32).to_be_bytes().to_vec();
                        result.extend_from_slice(v);
                        result
                    }
                    None => (-1i32).to_be_bytes().to_vec(),
                }
            }
            GhidraField::Fixed10 { value, .. } => value.to_vec(),
            GhidraField::BinaryCoded { fields } => {
                let mut result = Vec::new();
                for f in fields {
                    result.extend_from_slice(&f.to_bytes());
                }
                result
            }
            GhidraField::Index { key_field, .. } => key_field.to_bytes(),
            GhidraField::LegacyIndex { key_value } => key_value.to_be_bytes().to_vec(),
        }
    }

    /// Truncate a variable-length field to the specified length.
    ///
    /// Port of Java `Field.truncate(int)`.
    pub fn truncate(&mut self, max_len: usize) {
        match self {
            GhidraField::String { value } => {
                if let Some(s) = value {
                    let max_chars = max_len.saturating_sub(4);
                    if s.len() > max_chars {
                        *value = Some(s[..max_chars].to_string());
                    }
                }
            }
            GhidraField::Binary { value } => {
                if let Some(v) = value {
                    let max_data = max_len.saturating_sub(4);
                    if v.len() > max_data {
                        v.truncate(max_data);
                    }
                }
            }
            _ => {}
        }
    }

    /// Get minimum value for this field type (fixed-length only).
    ///
    /// Port of Java `Field.getMinValue()`.
    pub fn get_min_value(&self) -> Result<Self, String> {
        match self {
            GhidraField::Long { .. } => Ok(GhidraField::long_min_value()),
            GhidraField::Int { .. } => Ok(GhidraField::int_min_value()),
            GhidraField::Short { .. } => Ok(GhidraField::short_min_value()),
            GhidraField::Byte { .. } => Ok(GhidraField::byte_min_value()),
            GhidraField::Boolean { .. } => Ok(GhidraField::boolean_min_value()),
            _ => Err("getMinValue not supported for variable-length fields".to_string()),
        }
    }

    /// Get maximum value for this field type (fixed-length only).
    ///
    /// Port of Java `Field.getMaxValue()`.
    pub fn get_max_value(&self) -> Result<Self, String> {
        match self {
            GhidraField::Long { .. } => Ok(GhidraField::long_max_value()),
            GhidraField::Int { .. } => Ok(GhidraField::int_max_value()),
            GhidraField::Short { .. } => Ok(GhidraField::short_max_value()),
            GhidraField::Byte { .. } => Ok(GhidraField::byte_max_value()),
            GhidraField::Boolean { .. } => Ok(GhidraField::boolean_max_value()),
            _ => Err("getMaxValue not supported for variable-length fields".to_string()),
        }
    }
}

// ---- Comparison (port of Java Field.compareTo) ----

impl PartialEq for GhidraField {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (GhidraField::Long { value: a, .. }, GhidraField::Long { value: b, .. }) => a == b,
            (GhidraField::Int { value: a, .. }, GhidraField::Int { value: b, .. }) => a == b,
            (GhidraField::Short { value: a, .. }, GhidraField::Short { value: b, .. }) => a == b,
            (GhidraField::Byte { value: a, .. }, GhidraField::Byte { value: b, .. }) => a == b,
            (GhidraField::Boolean { value: a, .. }, GhidraField::Boolean { value: b, .. }) => a == b,
            (GhidraField::String { value: a }, GhidraField::String { value: b }) => a == b,
            (GhidraField::Binary { value: a }, GhidraField::Binary { value: b }) => a == b,
            (GhidraField::Fixed10 { value: a, .. }, GhidraField::Fixed10 { value: b, .. }) => a == b,
            (GhidraField::LegacyIndex { key_value: a }, GhidraField::LegacyIndex { key_value: b }) => a == b,
            _ => false,
        }
    }
}

impl Eq for GhidraField {}

impl PartialOrd for GhidraField {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GhidraField {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (GhidraField::Long { value: a, .. }, GhidraField::Long { value: b, .. }) => a.cmp(b),
            (GhidraField::Int { value: a, .. }, GhidraField::Int { value: b, .. }) => a.cmp(b),
            (GhidraField::Short { value: a, .. }, GhidraField::Short { value: b, .. }) => a.cmp(b),
            (GhidraField::Byte { value: a, .. }, GhidraField::Byte { value: b, .. }) => a.cmp(b),
            (GhidraField::Boolean { value: a, .. }, GhidraField::Boolean { value: b, .. }) => a.cmp(b),
            (GhidraField::String { value: a }, GhidraField::String { value: b }) => a.cmp(b),
            (GhidraField::Binary { value: a }, GhidraField::Binary { value: b }) => a.cmp(b),
            (GhidraField::Fixed10 { value: a, .. }, GhidraField::Fixed10 { value: b, .. }) => a.cmp(b),
            (GhidraField::LegacyIndex { key_value: a }, GhidraField::LegacyIndex { key_value: b }) => a.cmp(b),
            // Different types: compare by discriminant ordering
            _ => {
                let da = std::mem::discriminant(self);
                let db = std::mem::discriminant(other);
                // This is a simplified ordering; Java throws ClassCastException
                format!("{:?}", da).cmp(&format!("{:?}", db))
            }
        }
    }
}

impl fmt::Display for GhidraField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_value_as_string())
    }
}

// ============================================================================
// BinaryCodedField helper (port of Java BinaryCodedField)
// ============================================================================

/// A composite field that packs multiple fields into a single binary blob.
///
/// Port of Java `db.BinaryCodedField`.
impl GhidraField {
    /// Create a BinaryCodedField from a list of sub-fields.
    pub fn binary_coded(fields: Vec<GhidraField>) -> Self {
        GhidraField::BinaryCoded { fields }
    }

    /// Get the sub-fields of a BinaryCodedField.
    pub fn get_fields(&self) -> Option<&[GhidraField]> {
        match self {
            GhidraField::BinaryCoded { fields } => Some(fields),
            _ => None,
        }
    }

    /// Get the sub-fields of a BinaryCodedField (mutable).
    pub fn get_fields_mut(&mut self) -> Option<&mut Vec<GhidraField>> {
        match self {
            GhidraField::BinaryCoded { fields } => Some(fields),
            _ => None,
        }
    }

    /// Encode a BinaryCodedField into bytes (port of BinaryCodedField.getBinaryData).
    pub fn encode_binary_coded(fields: &[GhidraField]) -> Vec<u8> {
        let mut result = Vec::new();
        for field in fields {
            // Write field type byte
            result.push(field.get_field_type());
            // Write field data
            let data = field.to_bytes();
            result.extend_from_slice(&data);
        }
        result
    }

    /// Decode bytes into a list of GhidraField (port of BinaryCodedField constructor).
    pub fn decode_binary_coded(data: &[u8]) -> Result<Vec<GhidraField>, String> {
        let mut fields = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let field_type = data[offset];
            offset += 1;
            let mut field = GhidraField::get_field(field_type)
                .map_err(|e| e.to_string())?;
            let field_len = match field_type & FIELD_TYPE_MASK {
                LONG_TYPE => { 8 }
                INT_TYPE => { 4 }
                SHORT_TYPE => { 2 }
                BYTE_TYPE | BOOLEAN_TYPE => { 1 }
                FIXED_10_TYPE => { 10 }
                STRING_TYPE | BINARY_OBJ_TYPE => {
                    if offset + 4 > data.len() {
                        return Err("Incomplete field data".to_string());
                    }
                    let len = i32::from_be_bytes([
                        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                    ]);
                    if len < 0 {
                        4
                    } else {
                        4 + len as usize
                    }
                }
                _ => return Err(format!("Unknown field type: 0x{:02x}", field_type)),
            };
            if offset + field_len > data.len() {
                return Err("Incomplete field data".to_string());
            }
            // Set value from raw bytes
            match &mut field {
                GhidraField::Long { value, is_null } => {
                    *value = i64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
                    *is_null = false;
                }
                GhidraField::Int { value, is_null } => {
                    *value = i32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
                    *is_null = false;
                }
                GhidraField::Short { value, is_null } => {
                    *value = i16::from_be_bytes(data[offset..offset + 2].try_into().unwrap());
                    *is_null = false;
                }
                GhidraField::Byte { value, is_null } => {
                    *value = data[offset] as i8;
                    *is_null = false;
                }
                GhidraField::Boolean { value, is_null } => {
                    *value = data[offset] != 0;
                    *is_null = false;
                }
                GhidraField::String { value } => {
                    let len = i32::from_be_bytes([
                        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                    ]);
                    if len >= 0 {
                        let s = String::from_utf8_lossy(
                            &data[offset + 4..offset + 4 + len as usize],
                        ).to_string();
                        *value = Some(s);
                    }
                }
                GhidraField::Binary { value } => {
                    let len = i32::from_be_bytes([
                        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                    ]);
                    if len >= 0 {
                        *value = Some(data[offset + 4..offset + 4 + len as usize].to_vec());
                    }
                }
                GhidraField::Fixed10 { value, is_null } => {
                    value.copy_from_slice(&data[offset..offset + 10]);
                    *is_null = false;
                }
                _ => {}
            }
            offset += field_len;
            fields.push(field);
        }
        Ok(fields)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_long_field_basics() {
        let mut f = GhidraField::long(42);
        assert_eq!(f.get_long_value().unwrap(), 42);
        assert_eq!(f.length(), 8);
        assert_eq!(f.get_field_type(), LONG_TYPE);
        assert!(!f.is_null());
        assert!(!f.is_variable_length());

        f.set_long_value(100).unwrap();
        assert_eq!(f.get_long_value().unwrap(), 100);
    }

    #[test]
    fn test_int_field_basics() {
        let f = GhidraField::int(99);
        assert_eq!(f.get_int_value().unwrap(), 99);
        assert_eq!(f.get_long_value().unwrap(), 99);
        assert_eq!(f.length(), 4);
    }

    #[test]
    fn test_short_field_basics() {
        let f = GhidraField::short(1234);
        assert_eq!(f.get_short_value().unwrap(), 1234);
        assert_eq!(f.length(), 2);
    }

    #[test]
    fn test_byte_field_basics() {
        let f = GhidraField::byte(42);
        assert_eq!(f.get_byte_value().unwrap(), 42);
        assert_eq!(f.length(), 1);
    }

    #[test]
    fn test_boolean_field() {
        let f = GhidraField::boolean(true);
        assert!(f.get_boolean_value().unwrap());
        assert_eq!(f.length(), 1);
    }

    #[test]
    fn test_string_field() {
        let mut f = GhidraField::string("hello");
        assert_eq!(f.get_string().unwrap(), Some("hello"));
        assert!(f.is_variable_length());
        assert_eq!(f.length(), 9); // 5 bytes + 4 byte prefix

        f.set_null();
        assert!(f.is_null());
        assert_eq!(f.length(), 4); // null string: 4-byte -1 prefix
    }

    #[test]
    fn test_binary_field() {
        let f = GhidraField::binary(vec![0x01, 0x02, 0x03]);
        assert_eq!(f.get_binary_data(), Some(&[0x01, 0x02, 0x03][..]));
        assert!(f.is_variable_length());
    }

    #[test]
    fn test_fixed10_field() {
        let f = GhidraField::fixed10([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(f.length(), 10);
        assert_eq!(f.get_binary_data(), Some(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9][..]));
    }

    #[test]
    fn test_field_type_codes() {
        assert_eq!(GhidraField::long(0).get_field_type(), LONG_TYPE);
        assert_eq!(GhidraField::int(0).get_field_type(), INT_TYPE);
        assert_eq!(GhidraField::short(0).get_field_type(), SHORT_TYPE);
        assert_eq!(GhidraField::byte(0).get_field_type(), BYTE_TYPE);
        assert_eq!(GhidraField::boolean(false).get_field_type(), BOOLEAN_TYPE);
        assert_eq!(GhidraField::new_string().get_field_type(), STRING_TYPE);
        assert_eq!(GhidraField::new_binary().get_field_type(), BINARY_OBJ_TYPE);
        assert_eq!(GhidraField::new_fixed10().get_field_type(), FIXED_10_TYPE);
    }

    #[test]
    fn test_field_get_field_factory() {
        let f = GhidraField::get_field(LONG_TYPE).unwrap();
        assert!(matches!(f, GhidraField::Long { .. }));

        let f = GhidraField::get_field(INT_TYPE).unwrap();
        assert!(matches!(f, GhidraField::Int { .. }));

        let f = GhidraField::get_field(STRING_TYPE).unwrap();
        assert!(matches!(f, GhidraField::String { .. }));
    }

    #[test]
    fn test_field_comparison() {
        let a = GhidraField::long(10);
        let b = GhidraField::long(20);
        assert!(a < b);
        assert!(b > a);

        let a = GhidraField::string("abc");
        let b = GhidraField::string("def");
        assert!(a < b);
    }

    #[test]
    fn test_field_null_state() {
        let mut f = GhidraField::long(42);
        assert!(!f.is_null());
        f.set_null();
        assert!(f.is_null());
        assert_eq!(f.get_long_value().unwrap(), 0);
    }

    #[test]
    fn test_field_copy() {
        let f = GhidraField::long(42);
        let copy = f.copy_field();
        assert_eq!(f, copy);
    }

    #[test]
    fn test_field_new_field() {
        let f = GhidraField::long(42);
        let new = f.new_field();
        assert!(matches!(new, GhidraField::Long { .. }));
        assert_eq!(new.get_long_value().unwrap(), 0);
    }

    #[test]
    fn test_field_get_fixed_field() {
        let f = GhidraField::get_fixed_field(1).unwrap();
        assert!(matches!(f, GhidraField::Byte { .. }));

        let f = GhidraField::get_fixed_field(4).unwrap();
        assert!(matches!(f, GhidraField::Int { .. }));

        let f = GhidraField::get_fixed_field(8).unwrap();
        assert!(matches!(f, GhidraField::Long { .. }));

        assert!(GhidraField::get_fixed_field(3).is_err());
    }

    #[test]
    fn test_field_to_bytes() {
        let f = GhidraField::long(0x0102030405060708);
        let bytes = f.to_bytes();
        assert_eq!(bytes, vec![1, 2, 3, 4, 5, 6, 7, 8]);

        let f = GhidraField::int(0x01020304);
        let bytes = f.to_bytes();
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_field_value_as_string() {
        assert_eq!(GhidraField::long(255).get_value_as_string(), "0xff");
        assert_eq!(GhidraField::int(16).get_value_as_string(), "0x10");
        assert_eq!(GhidraField::boolean(true).get_value_as_string(), "true");
        assert_eq!(
            GhidraField::string("test").get_value_as_string(),
            "\"test\""
        );
    }

    #[test]
    fn test_field_is_same_type() {
        let a = GhidraField::long(1);
        let b = GhidraField::long(2);
        let c = GhidraField::int(1);
        assert!(a.is_same_type(&b));
        assert!(!a.is_same_type(&c));
    }

    #[test]
    fn test_can_index() {
        assert!(GhidraField::long(0).can_index());
        assert!(GhidraField::string("a").can_index());
        assert!(!GhidraField::boolean(false).can_index());
        assert!(!GhidraField::byte(0).can_index());
    }

    #[test]
    fn test_binary_coded_field() {
        let fields = vec![
            GhidraField::long(42),
            GhidraField::string("hello"),
        ];
        let bcd = GhidraField::binary_coded(fields);
        assert!(bcd.get_fields().is_some());
        assert_eq!(bcd.get_fields().unwrap().len(), 2);
    }

    #[test]
    fn test_legacy_index_field() {
        let f = GhidraField::legacy_index(12345);
        assert_eq!(f.get_field_type(), LEGACY_INDEX_LONG_TYPE);
        assert_eq!(f.length(), 8);
        assert!(!f.is_null());
    }

    #[test]
    fn test_min_max_values() {
        let f = GhidraField::long(0);
        let min = f.get_min_value().unwrap();
        let max = f.get_max_value().unwrap();
        assert_eq!(min.get_long_value().unwrap(), i64::MIN);
        assert_eq!(max.get_long_value().unwrap(), i64::MAX);
    }

    #[test]
    fn test_truncate_string() {
        let mut f = GhidraField::string("hello world");
        f.truncate(7); // 4-byte prefix + 3 chars
        assert_eq!(f.get_string().unwrap(), Some("hel"));
    }

    #[test]
    fn test_field_ordering() {
        let mut fields = vec![
            GhidraField::long(3),
            GhidraField::long(1),
            GhidraField::long(2),
        ];
        fields.sort();
        assert_eq!(fields[0].get_long_value().unwrap(), 1);
        assert_eq!(fields[1].get_long_value().unwrap(), 2);
        assert_eq!(fields[2].get_long_value().unwrap(), 3);
    }
}
