//! Trace data operation types.
//!
//! Ported from Ghidra's Framework-TraceModeling data operations,
//! including `TraceBasedDataTypeManager`, `TraceDataType`, and data settings.

use std::collections::BTreeMap;

/// Data type conflict resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataTypeConflictHandler {
    /// Replace the existing data type.
    Replace,
    /// Keep the existing data type.
    Keep,
    /// Rename the new data type.
    RenameNew,
    /// Rename the existing data type.
    RenameExisting,
}

/// A data type entry in a trace-based data type manager.
#[derive(Debug, Clone)]
pub struct TraceDataTypeEntry {
    /// Unique ID for this data type.
    pub id: i64,
    /// Name of the data type.
    pub name: String,
    /// Category path (e.g., "/structs/MyStruct").
    pub category_path: String,
    /// Size in bytes (0 for variable-length types).
    pub size: usize,
    /// Whether this is a built-in type.
    pub builtin: bool,
}

/// Settings for a data element in the trace.
#[derive(Debug, Clone, Default)]
pub struct TraceDataSettings {
    /// The data type ID.
    pub data_type_id: Option<i64>,
    /// Whether the data has associated comments.
    pub has_comment: bool,
    /// The primary reference (if any).
    pub primary_ref: Option<ReferenceInfo>,
    /// Memory reference(s).
    pub memory_refs: Vec<ReferenceInfo>,
    /// Whether this is an equate.
    pub is_equate: bool,
    /// The equate value, if applicable.
    pub equate_value: Option<String>,
    /// User-defined properties.
    pub properties: BTreeMap<String, String>,
}

/// Information about a reference from one address to another.
#[derive(Debug, Clone)]
pub struct ReferenceInfo {
    /// The source address.
    pub from_address: u64,
    /// The destination address.
    pub to_address: u64,
    /// The reference type.
    pub ref_type: ReferenceType,
    /// The operand index (-1 for the mnemonic).
    pub operand_index: i32,
}

/// The type of a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReferenceType {
    /// Data (pointer) reference.
    Data,
    /// Flow (jump/call) reference.
    Flow,
    /// Read reference.
    Read,
    /// Write reference.
    Write,
    /// Read-write reference.
    ReadWrite,
    /// Indirect reference.
    Indirect,
}

/// Operations on trace data settings.
pub trait TraceDataSettingsOperations {
    /// Get the data type ID at the given address.
    fn get_data_type_id(&self, address: u64) -> Option<i64>;

    /// Set the data type ID at the given address.
    fn set_data_type_id(&mut self, address: u64, data_type_id: i64) -> Result<(), String>;

    /// Clear the data type at the given address.
    fn clear_data_type(&mut self, address: u64) -> Result<(), String>;

    /// Get the comment at the given address.
    fn get_comment(&self, address: u64, comment_type: CommentType) -> Option<String>;

    /// Set the comment at the given address.
    fn set_comment(&mut self, address: u64, comment_type: CommentType, comment: &str) -> Result<(), String>;

    /// Get the primary reference from the given address.
    fn get_primary_reference(&self, address: u64) -> Option<ReferenceInfo>;

    /// Set the primary reference from the given address.
    fn set_primary_reference(&mut self, address: u64, ref_info: ReferenceInfo) -> Result<(), String>;

    /// Get the equate at the given address.
    fn get_equate(&self, address: u64) -> Option<String>;

    /// Set an equate at the given address.
    fn set_equate(&mut self, address: u64, equate: &str) -> Result<(), String>;

    /// Remove an equate at the given address.
    fn remove_equate(&mut self, address: u64) -> Result<(), String>;
}

/// The type of a code unit comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    /// Pre-comment (appears before the code unit).
    Pre,
    /// End-of-line comment.
    Eol,
    /// Post-comment (appears after the code unit).
    Post,
    /// Plate comment (appears above with a separator line).
    Plate,
    /// Repeatable comment (shown at all references).
    Repeatable,
}

/// Settings value - a wrapper for typed settings.
#[derive(Debug, Clone)]
pub enum SettingsValue {
    /// Boolean value.
    Bool(bool),
    /// Integer value.
    Int(i64),
    /// Long value.
    Long(i64),
    /// String value.
    String(String),
    /// Float value.
    Float(f64),
    /// Double value.
    Double(f64),
}

impl SettingsValue {
    /// Get as bool.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            SettingsValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as i64.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            SettingsValue::Int(v) | SettingsValue::Long(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            SettingsValue::String(v) => Some(v),
            _ => None,
        }
    }

    /// Get as f64.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            SettingsValue::Float(v) | SettingsValue::Double(v) => Some(*v),
            _ => None,
        }
    }
}

/// Data settings adapter for bridging trace data to program data settings.
pub trait DataSettingsAdapter: Send + Sync {
    /// Get a setting value for the given address and key.
    fn get_setting(&self, address: u64, key: &str) -> Option<SettingsValue>;

    /// Set a setting value for the given address and key.
    fn set_setting(&mut self, address: u64, key: &str, value: SettingsValue) -> Result<(), String>;

    /// Clear a setting for the given address and key.
    fn clear_setting(&mut self, address: u64, key: &str) -> Result<(), String>;

    /// Get all settings for the given address.
    fn get_all_settings(&self, address: u64) -> BTreeMap<String, SettingsValue>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_conflict_handler() {
        assert_ne!(
            DataTypeConflictHandler::Replace,
            DataTypeConflictHandler::Keep
        );
        assert_eq!(
            DataTypeConflictHandler::RenameNew,
            DataTypeConflictHandler::RenameNew
        );
    }

    #[test]
    fn test_data_type_entry() {
        let entry = TraceDataTypeEntry {
            id: 1,
            name: "uint32_t".into(),
            category_path: "/".into(),
            size: 4,
            builtin: true,
        };
        assert_eq!(entry.size, 4);
        assert!(entry.builtin);
    }

    #[test]
    fn test_reference_type_variants() {
        assert_ne!(ReferenceType::Data, ReferenceType::Flow);
        assert_eq!(ReferenceType::Read, ReferenceType::Read);
    }

    #[test]
    fn test_comment_type_variants() {
        let types = [
            CommentType::Pre,
            CommentType::Eol,
            CommentType::Post,
            CommentType::Plate,
            CommentType::Repeatable,
        ];
        assert_eq!(types.len(), 5);
    }

    #[test]
    fn test_settings_value_bool() {
        let val = SettingsValue::Bool(true);
        assert_eq!(val.as_bool(), Some(true));
        assert!(val.as_i64().is_none());
        assert!(val.as_str().is_none());
    }

    #[test]
    fn test_settings_value_int() {
        let val = SettingsValue::Int(42);
        assert_eq!(val.as_i64(), Some(42));
        assert!(val.as_bool().is_none());
    }

    #[test]
    fn test_settings_value_string() {
        let val = SettingsValue::String("hello".into());
        assert_eq!(val.as_str(), Some("hello"));
    }

    #[test]
    fn test_settings_value_float() {
        let val = SettingsValue::Float(3.14);
        assert!((val.as_f64().unwrap() - 3.14).abs() < f64::EPSILON);
    }

    #[test]
    fn test_settings_value_long() {
        let val = SettingsValue::Long(i64::MAX);
        assert_eq!(val.as_i64(), Some(i64::MAX));
    }

    #[test]
    fn test_settings_value_double() {
        let val = SettingsValue::Double(2.718281828);
        assert!((val.as_f64().unwrap() - 2.718281828).abs() < f64::EPSILON);
    }

    #[test]
    fn test_trace_data_settings_default() {
        let settings = TraceDataSettings::default();
        assert!(settings.data_type_id.is_none());
        assert!(!settings.has_comment);
        assert!(settings.primary_ref.is_none());
        assert!(settings.memory_refs.is_empty());
        assert!(!settings.is_equate);
    }

    #[test]
    fn test_reference_info() {
        let ri = ReferenceInfo {
            from_address: 0x400000,
            to_address: 0x400100,
            ref_type: ReferenceType::Flow,
            operand_index: -1,
        };
        assert_eq!(ri.ref_type, ReferenceType::Flow);
        assert_eq!(ri.operand_index, -1);
    }
}
