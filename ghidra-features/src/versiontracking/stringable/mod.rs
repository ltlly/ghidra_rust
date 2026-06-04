//! Stringable types for serializing and deserializing markup values.
//!
//! Each stringable type corresponds to a Java Stringable class in
//! `ghidra.feature.vt.api.stringable`.

pub use crate::versiontracking::markup::Stringable;

/// Storage prefix constants matching the Java implementations.
pub const FUNCTION_NAME_PREFIX: &str = "FN";
pub const FUNCTION_SIGNATURE_PREFIX: &str = "FS";
pub const DATA_TYPE_PREFIX: &str = "DT";
pub const LABEL_PREFIX: &str = "LB";
pub const COMMENT_PREFIX: &str = "CM";
pub const PARAMETER_PREFIX: &str = "PM";
pub const MULTIPLE_SYMBOLS_PREFIX: &str = "MS";
pub const GENERIC_PREFIX: &str = "GS";

// ---------------------------------------------------------------------------
// Individual stringable type implementations
// ---------------------------------------------------------------------------

/// Function name stringable.
///
/// Corresponds to `FunctionNameStringable` Java class.
pub struct FunctionNameStringable;

impl FunctionNameStringable {
    /// Create a storage string from a function name.
    pub fn to_storage_string(name: &str) -> String {
        Stringable::FunctionName(name.to_string()).to_storage_string()
    }

    /// Parse a function name from a storage string.
    pub fn from_storage_string(s: &str) -> Option<String> {
        match Stringable::from_storage_string(s)? {
            Stringable::FunctionName(name) => Some(name),
            _ => None,
        }
    }
}

/// Function signature stringable.
///
/// Corresponds to `FunctionSignatureStringable` Java class.
pub struct FunctionSignatureStringable;

impl FunctionSignatureStringable {
    /// Create a storage string from a function signature.
    pub fn to_storage_string(signature: &str) -> String {
        Stringable::FunctionSignature(signature.to_string()).to_storage_string()
    }

    /// Parse a function signature from a storage string.
    pub fn from_storage_string(s: &str) -> Option<String> {
        match Stringable::from_storage_string(s)? {
            Stringable::FunctionSignature(sig) => Some(sig),
            _ => None,
        }
    }
}

/// Data type stringable.
///
/// Corresponds to `DataTypeStringable` Java class.
pub struct DataTypeStringable;

impl DataTypeStringable {
    /// Create a storage string from data type info.
    pub fn to_storage_string(name: &str, type_id: i64, manager_id: i64, size: i32) -> String {
        Stringable::DataType {
            name: name.to_string(),
            type_id,
            manager_id,
            size,
        }
        .to_storage_string()
    }

    /// Parse data type info from a storage string.
    pub fn from_storage_string(s: &str) -> Option<(String, i64, i64, i32)> {
        match Stringable::from_storage_string(s)? {
            Stringable::DataType {
                name,
                type_id,
                manager_id,
                size,
            } => Some((name, type_id, manager_id, size)),
            _ => None,
        }
    }
}

/// Label stringable.
///
/// Corresponds to `StringStringable` and label-related Java classes.
pub struct LabelStringable;

impl LabelStringable {
    /// Create a storage string from a label.
    pub fn to_storage_string(label: &str) -> String {
        Stringable::Label(label.to_string()).to_storage_string()
    }

    /// Parse a label from a storage string.
    pub fn from_storage_string(s: &str) -> Option<String> {
        match Stringable::from_storage_string(s)? {
            Stringable::Label(label) => Some(label),
            _ => None,
        }
    }
}

/// Symbol stringable.
///
/// Corresponds to `SymbolStringable` Java class.
pub struct SymbolStringable;

impl SymbolStringable {
    /// Create a storage string from a symbol name.
    pub fn to_storage_string(symbol_name: &str) -> String {
        // Symbols are stored as generic strings with a label prefix
        Stringable::Label(symbol_name.to_string()).to_storage_string()
    }

    /// Parse a symbol name from a storage string.
    pub fn from_storage_string(s: &str) -> Option<String> {
        match Stringable::from_storage_string(s)? {
            Stringable::Label(name) => Some(name),
            _ => None,
        }
    }
}

/// Multiple symbol stringable.
///
/// Corresponds to `MultipleSymbolStringable` Java class.
pub struct MultipleSymbolStringable;

impl MultipleSymbolStringable {
    /// Create a storage string from multiple symbol names.
    pub fn to_storage_string(names: &[&str]) -> String {
        Stringable::MultipleSymbols(names.iter().map(|s| s.to_string()).collect()).to_storage_string()
    }

    /// Parse multiple symbol names from a storage string.
    pub fn from_storage_string(s: &str) -> Option<Vec<String>> {
        match Stringable::from_storage_string(s)? {
            Stringable::MultipleSymbols(names) => Some(names),
            _ => None,
        }
    }
}

/// Generic stringable.
///
/// Used for values that don't have a more specific type.
pub struct GenericStringable;

impl GenericStringable {
    /// Create a storage string from a generic value.
    pub fn to_storage_string(value: &str) -> String {
        Stringable::Generic(value.to_string()).to_storage_string()
    }

    /// Parse a generic value from a storage string.
    pub fn from_storage_string(s: &str) -> Option<String> {
        match Stringable::from_storage_string(s)? {
            Stringable::Generic(val) => Some(val),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Parameter info types (for deprecated parameter stringable)
// ---------------------------------------------------------------------------

/// Information about a function parameter.
///
/// Corresponds to `ParameterInfo` in the deprecated stringable package.
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterInfo {
    /// Parameter name
    pub name: String,
    /// Data type name
    pub data_type: String,
    /// Parameter ordinal (0-based)
    pub ordinal: i32,
}

impl ParameterInfo {
    /// Create a new parameter info.
    pub fn new(name: impl Into<String>, data_type: impl Into<String>, ordinal: i32) -> Self {
        Self {
            name: name.into(),
            data_type: data_type.into(),
            ordinal,
        }
    }

    /// Serialize to a storage string.
    pub fn to_storage_string(&self) -> String {
        Stringable::Parameter {
            name: self.name.clone(),
            data_type: self.data_type.clone(),
            ordinal: self.ordinal,
        }
        .to_storage_string()
    }

    /// Deserialize from a storage string.
    pub fn from_storage_string(s: &str) -> Option<Self> {
        match Stringable::from_storage_string(s)? {
            Stringable::Parameter {
                name,
                data_type,
                ordinal,
            } => Some(Self {
                name,
                data_type,
                ordinal,
            }),
            _ => None,
        }
    }
}

/// Local variable info for deprecated parameter stringable support.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalVariableInfo {
    /// Variable name
    pub name: String,
    /// Data type name
    pub data_type: String,
    /// Stack offset
    pub stack_offset: i32,
}

impl LocalVariableInfo {
    /// Create a new local variable info.
    pub fn new(name: impl Into<String>, data_type: impl Into<String>, stack_offset: i32) -> Self {
        Self {
            name: name.into(),
            data_type: data_type.into(),
            stack_offset,
        }
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Parse any storage string into a Stringable.
///
/// This is a convenience function that combines `Stringable::from_storage_string`.
pub fn parse_stringable(s: &str) -> Option<Stringable> {
    Stringable::from_storage_string(s)
}

/// Create a storage string from a Stringable.
pub fn to_storage_string(s: &Stringable) -> String {
    s.to_storage_string()
}

/// Returns the prefix for a given storage string.
pub fn extract_prefix(s: &str) -> Option<&str> {
    s.split_once(':').map(|(prefix, _)| prefix)
}

/// Returns whether a storage string has the given prefix.
pub fn has_prefix(s: &str, prefix: &str) -> bool {
    extract_prefix(s) == Some(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_name_stringable() {
        let storage = FunctionNameStringable::to_storage_string("main");
        assert!(storage.starts_with("FN:"));
        let name = FunctionNameStringable::from_storage_string(&storage).unwrap();
        assert_eq!(name, "main");
    }

    #[test]
    fn test_function_signature_stringable() {
        let storage = FunctionSignatureStringable::to_storage_string("void main(int argc)");
        let sig = FunctionSignatureStringable::from_storage_string(&storage).unwrap();
        assert_eq!(sig, "void main(int argc)");
    }

    #[test]
    fn test_data_type_stringable() {
        let storage = DataTypeStringable::to_storage_string("uint32", 42, 1, 4);
        let (name, type_id, manager_id, size) = DataTypeStringable::from_storage_string(&storage).unwrap();
        assert_eq!(name, "uint32");
        assert_eq!(type_id, 42);
        assert_eq!(manager_id, 1);
        assert_eq!(size, 4);
    }

    #[test]
    fn test_label_stringable() {
        let storage = LabelStringable::to_storage_string("global_var");
        let label = LabelStringable::from_storage_string(&storage).unwrap();
        assert_eq!(label, "global_var");
    }

    #[test]
    fn test_multiple_symbol_stringable() {
        let storage = MultipleSymbolStringable::to_storage_string(&["sym1", "sym2", "sym3"]);
        let names = MultipleSymbolStringable::from_storage_string(&storage).unwrap();
        assert_eq!(names, vec!["sym1", "sym2", "sym3"]);
    }

    #[test]
    fn test_generic_stringable() {
        let storage = GenericStringable::to_storage_string("hello world");
        let val = GenericStringable::from_storage_string(&storage).unwrap();
        assert_eq!(val, "hello world");
    }

    #[test]
    fn test_parameter_info() {
        let info = ParameterInfo::new("argc", "int", 0);
        let storage = info.to_storage_string();
        let restored = ParameterInfo::from_storage_string(&storage).unwrap();
        assert_eq!(restored, info);
    }

    #[test]
    fn test_parse_stringable() {
        let s = parse_stringable("FN:main").unwrap();
        assert_eq!(s, Stringable::FunctionName("main".to_string()));
        assert!(parse_stringable("XX:bad").is_none());
    }

    #[test]
    fn test_extract_prefix() {
        assert_eq!(extract_prefix("FN:main"), Some("FN"));
        assert_eq!(extract_prefix("DT:1/2/type/4"), Some("DT"));
        assert_eq!(extract_prefix("nocolon"), None);
    }

    #[test]
    fn test_has_prefix() {
        assert!(has_prefix("FN:main", "FN"));
        assert!(!has_prefix("FN:main", "DT"));
    }

    #[test]
    fn test_local_variable_info() {
        let info = LocalVariableInfo::new("x", "int", -4);
        assert_eq!(info.name, "x");
        assert_eq!(info.data_type, "int");
        assert_eq!(info.stack_offset, -4);
    }

    #[test]
    fn test_prefix_constants() {
        assert_eq!(FUNCTION_NAME_PREFIX, "FN");
        assert_eq!(FUNCTION_SIGNATURE_PREFIX, "FS");
        assert_eq!(DATA_TYPE_PREFIX, "DT");
        assert_eq!(LABEL_PREFIX, "LB");
        assert_eq!(COMMENT_PREFIX, "CM");
        assert_eq!(PARAMETER_PREFIX, "PM");
        assert_eq!(MULTIPLE_SYMBOLS_PREFIX, "MS");
        assert_eq!(GENERIC_PREFIX, "GS");
    }
}
