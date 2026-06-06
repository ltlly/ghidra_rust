//! Data type helper utilities for the composite editor.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.DataTypeHelper`.
//!
//! Provides static helper methods for dealing with data types in the
//! composite data type editor (Structure or Union Editor).

/// Strip whitespace from a string, removing blanks and control characters.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.DataTypeHelper.stripWhiteSpace`.
pub fn strip_whitespace(original: &str) -> String {
    original
        .chars()
        .filter(|&c| c > ' ')
        .collect()
}

/// Get the base data type of a type, unwrapping TypeDef, Array, and Pointer.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.DataTypeHelper.getBaseType`.
#[derive(Debug, Clone)]
pub enum DataTypeDesc {
    /// A basic/primitive data type.
    Primitive(String),
    /// A typedef wrapping another type.
    TypeDef {
        /// The typedef name.
        name: String,
        /// The underlying data type.
        base: Box<DataTypeDesc>,
    },
    /// An array of another type.
    Array {
        /// The element data type.
        element: Box<DataTypeDesc>,
        /// The number of elements.
        length: usize,
    },
    /// A pointer to another type.
    Pointer {
        /// The target data type.
        target: Box<DataTypeDesc>,
        /// The pointer size in bytes.
        size: usize,
    },
    /// A composite (struct/union) type.
    Composite {
        /// The composite name.
        name: String,
        /// Whether this is a union (vs struct).
        is_union: bool,
    },
    /// A function definition.
    FunctionDef {
        /// The function name.
        name: String,
    },
}

impl DataTypeDesc {
    /// Get the base type, unwrapping typedefs, arrays, and pointers.
    pub fn get_base_type(&self) -> &DataTypeDesc {
        match self {
            Self::TypeDef { base, .. } => base.get_base_type(),
            Self::Array { element, .. } => element.get_base_type(),
            Self::Pointer { target, .. } => {
                // If target is null-like, return self
                target.get_base_type()
            }
            other => other,
        }
    }

    /// Get the display name.
    pub fn display_name(&self) -> &str {
        match self {
            Self::Primitive(name) => name,
            Self::TypeDef { name, .. } => name,
            Self::Array { element, length } => {
                // Simplified: in reality this would format as "type[length]"
                element.display_name()
            }
            Self::Pointer { target, .. } => {
                target.display_name()
            }
            Self::Composite { name, .. } => name,
            Self::FunctionDef { name } => name,
        }
    }

    /// Whether this is a function definition (or a typedef wrapping one).
    pub fn is_function_def(&self) -> bool {
        match self {
            Self::FunctionDef { .. } => true,
            Self::TypeDef { base, .. } => base.is_function_def(),
            _ => false,
        }
    }

    /// Whether this is a factory data type (placeholder for fixed-size types).
    pub fn is_factory_type(&self) -> bool {
        match self {
            Self::Primitive(name) => name.starts_with("undefined") || name.starts_with("factory"),
            _ => false,
        }
    }
}

/// The result of parsing a data type from user input.
///
/// Ported from `DataTypeParser` usage in `DataTypeHelper.parseDataType`.
#[derive(Debug, Clone)]
pub struct DataTypeParseResult {
    /// The parsed data type description.
    pub data_type: DataTypeDesc,
    /// The resolved size in bytes (may differ from data_type's inherent size).
    pub resolved_size: i32,
    /// Whether the user needs to be prompted for a size.
    pub needs_size_prompt: bool,
    /// Error message if parsing failed.
    pub error: Option<String>,
}

impl DataTypeParseResult {
    /// Create a successful parse result.
    pub fn success(data_type: DataTypeDesc, size: i32) -> Self {
        Self {
            data_type,
            resolved_size: size,
            needs_size_prompt: false,
            error: None,
        }
    }

    /// Create a result that needs a size prompt.
    pub fn needs_size(data_type: DataTypeDesc, default_size: i32) -> Self {
        Self {
            data_type,
            resolved_size: default_size,
            needs_size_prompt: true,
            error: None,
        }
    }

    /// Create a failed parse result.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            data_type: DataTypeDesc::Primitive("error".into()),
            resolved_size: 0,
            needs_size_prompt: false,
            error: Some(message.into()),
        }
    }

    /// Whether the parse was successful (no error).
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

/// Validate that a data type is allowable in a composite editor.
///
/// Returns `Err` with a message if the data type is not allowed.
pub fn check_allowable_data_type(dt: &DataTypeDesc) -> Result<(), String> {
    if dt.is_factory_type() {
        return Err("Factory data types are not allowed.".to_string());
    }
    Ok(())
}

/// Compute the fixed-length size for a data type.
///
/// Returns `None` if the size is indeterminate (e.g., dynamic) and
/// the user needs to be prompted.
pub fn get_fixed_length(dt: &DataTypeDesc, aligned_length: bool) -> Option<usize> {
    match dt {
        DataTypeDesc::Primitive(_) => Some(4), // simplified: assume 4-byte default
        DataTypeDesc::TypeDef { base, .. } => get_fixed_length(base, aligned_length),
        DataTypeDesc::Array { element, length } => {
            get_fixed_length(element, aligned_length).map(|es| es * length)
        }
        DataTypeDesc::Pointer { size, .. } => Some(*size),
        DataTypeDesc::Composite { .. } => Some(0), // would need to look up actual size
        DataTypeDesc::FunctionDef { .. } => None,   // function defs need pointer wrapping
    }
}

/// Compute the maximum replace length for a composite at a given index.
///
/// Returns -1 if unlimited.
pub fn get_max_replace_length(
    total_size: usize,
    current_offset: usize,
    _is_union: bool,
) -> i32 {
    if _is_union {
        return total_size as i32;
    }
    let remaining = total_size.saturating_sub(current_offset);
    remaining as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_whitespace() {
        assert_eq!(strip_whitespace("hello world"), "helloworld");
        assert_eq!(strip_whitespace("  a b c  "), "abc");
        assert_eq!(strip_whitespace(""), "");
        assert_eq!(strip_whitespace("no_whitespace"), "no_whitespace");
        assert_eq!(strip_whitespace("\t\n\r"), "");
    }

    #[test]
    fn test_data_type_desc_base_type() {
        let dt = DataTypeDesc::TypeDef {
            name: "MyInt".into(),
            base: Box::new(DataTypeDesc::Primitive("int".into())),
        };
        let base = dt.get_base_type();
        assert_eq!(base.display_name(), "int");
    }

    #[test]
    fn test_data_type_desc_pointer_base() {
        let dt = DataTypeDesc::Pointer {
            target: Box::new(DataTypeDesc::Primitive("char".into())),
            size: 8,
        };
        let base = dt.get_base_type();
        assert_eq!(base.display_name(), "char");
    }

    #[test]
    fn test_data_type_desc_function_def() {
        let dt = DataTypeDesc::FunctionDef {
            name: "callback".into(),
        };
        assert!(dt.is_function_def());

        let wrapped = DataTypeDesc::TypeDef {
            name: "Callback".into(),
            base: Box::new(dt),
        };
        assert!(wrapped.is_function_def());
    }

    #[test]
    fn test_data_type_parse_result() {
        let result = DataTypeParseResult::success(
            DataTypeDesc::Primitive("int".into()),
            4,
        );
        assert!(result.is_ok());
        assert_eq!(result.resolved_size, 4);

        let result = DataTypeParseResult::error("Invalid type");
        assert!(!result.is_ok());
        assert!(result.error.is_some());
    }

    #[test]
    fn test_check_allowable_data_type() {
        let dt = DataTypeDesc::Primitive("int".into());
        assert!(check_allowable_data_type(&dt).is_ok());

        let dt = DataTypeDesc::Primitive("undefined4".into());
        assert!(check_allowable_data_type(&dt).is_err());
    }

    #[test]
    fn test_get_fixed_length() {
        assert_eq!(get_fixed_length(&DataTypeDesc::Primitive("int".into()), false), Some(4));
        assert_eq!(
            get_fixed_length(
                &DataTypeDesc::Pointer {
                    target: Box::new(DataTypeDesc::Primitive("void".into())),
                    size: 8,
                },
                false,
            ),
            Some(8),
        );
    }

    #[test]
    fn test_get_fixed_length_array() {
        let dt = DataTypeDesc::Array {
            element: Box::new(DataTypeDesc::Primitive("int".into())),
            length: 10,
        };
        assert_eq!(get_fixed_length(&dt, false), Some(40));
    }

    #[test]
    fn test_get_fixed_length_function_def() {
        let dt = DataTypeDesc::FunctionDef {
            name: "callback".into(),
        };
        assert_eq!(get_fixed_length(&dt, false), None);
    }

    #[test]
    fn test_max_replace_length() {
        assert_eq!(get_max_replace_length(100, 0, false), 100);
        assert_eq!(get_max_replace_length(100, 60, false), 40);
        assert_eq!(get_max_replace_length(100, 100, false), 0);
        assert_eq!(get_max_replace_length(100, 120, false), 0);
    }

    #[test]
    fn test_max_replace_length_union() {
        // For unions, the max replace length is always the total size
        assert_eq!(get_max_replace_length(100, 0, true), 100);
        assert_eq!(get_max_replace_length(100, 50, true), 100);
    }
}
