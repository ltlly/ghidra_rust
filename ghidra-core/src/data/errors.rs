//! Error types for data type operations, ported from Ghidra.
//!
//! Covers:
//! - `DataTypeEncodeException` - encoding errors
//! - `InvalidDataTypeException` - invalid data type errors
//! - `DataTypeDependencyException` - dependency errors
//! - `InvalidNameException` / `IllegalRenameException` - naming errors

use std::fmt;

/// Error when encoding a value for a data type fails.
/// Port of Ghidra's `DataTypeEncodeException`.
#[derive(Debug, Clone)]
pub struct DataTypeEncodeError {
    pub message: String,
    pub value_description: String,
    pub type_name: String,
}

impl DataTypeEncodeError {
    pub fn new(
        message: impl Into<String>,
        value_description: impl Into<String>,
        type_name: impl Into<String>,
    ) -> Self {
        Self {
            message: message.into(),
            value_description: value_description.into(),
            type_name: type_name.into(),
        }
    }
}

impl fmt::Display for DataTypeEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, "Cannot encode '{}' as {}: {}",
            self.value_description, self.type_name, self.message
        )
    }
}

impl std::error::Error for DataTypeEncodeError {}

/// Error when a data type is invalid.
/// Port of Ghidra's `InvalidDataTypeException`.
#[derive(Debug, Clone)]
pub struct InvalidDataTypeError {
    pub message: String,
}

impl InvalidDataTypeError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for InvalidDataTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid data type: {}", self.message)
    }
}

impl std::error::Error for InvalidDataTypeError {}

/// Error when a data type dependency is violated.
/// Port of Ghidra's `DataTypeDependencyException`.
#[derive(Debug, Clone)]
pub struct DataTypeDependencyError {
    pub message: String,
}

impl DataTypeDependencyError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for DataTypeDependencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Data type dependency error: {}", self.message)
    }
}

impl std::error::Error for DataTypeDependencyError {}

/// Error when a name is invalid for a data type or category.
/// Port of Ghidra's `InvalidNameException` / `IllegalRenameException`.
#[derive(Debug, Clone)]
pub struct InvalidNameError {
    pub name: String,
    pub reason: String,
}

impl InvalidNameError {
    pub fn new(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { name: name.into(), reason: reason.into() }
    }

    /// Name is null or empty.
    pub fn empty_name() -> Self {
        Self::new("", "Name cannot be null or empty")
    }

    /// Name contains invalid characters.
    pub fn invalid_chars(name: &str) -> Self {
        Self::new(name, "Name contains invalid characters")
    }

    /// Duplicate name within the same category.
    pub fn duplicate(name: &str) -> Self {
        Self::new(name, "A data type with this name already exists in the category")
    }
}

impl fmt::Display for InvalidNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid name '{}': {}", self.name, self.reason)
    }
}

impl std::error::Error for InvalidNameError {}

/// Error when renaming is illegal.
/// Port of Ghidra's `IllegalRenameException`.
#[derive(Debug, Clone)]
pub struct IllegalRenameError {
    pub old_name: String,
    pub new_name: String,
    pub reason: String,
}

impl IllegalRenameError {
    pub fn new(
        old_name: impl Into<String>,
        new_name: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            old_name: old_name.into(),
            new_name: new_name.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for IllegalRenameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, "Cannot rename '{}' to '{}': {}",
            self.old_name, self.new_name, self.reason
        )
    }
}

impl std::error::Error for IllegalRenameError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_error() {
        let err = DataTypeEncodeError::new("out of range", "999", "byte");
        assert!(format!("{}", err).contains("999"));
        assert!(format!("{}", err).contains("byte"));
    }

    #[test]
    fn test_invalid_type_error() {
        let err = InvalidDataTypeError::new("size is zero");
        assert!(format!("{}", err).contains("size is zero"));
    }

    #[test]
    fn test_dependency_error() {
        let err = DataTypeDependencyError::new("circular dependency");
        assert!(format!("{}", err).contains("circular"));
    }

    #[test]
    fn test_invalid_name_error() {
        let err = InvalidNameError::empty_name();
        assert!(format!("{}", err).contains("null or empty"));

        let err2 = InvalidNameError::duplicate("int");
        assert!(format!("{}", err2).contains("already exists"));
    }

    #[test]
    fn test_rename_error() {
        let err = IllegalRenameError::new("old", "new", "read-only");
        assert!(format!("{}", err).contains("old"));
        assert!(format!("{}", err).contains("new"));
    }
}
