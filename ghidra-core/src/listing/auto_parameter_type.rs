//! Auto-parameter types for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.AutoParameterType`.
//!
//! Defines the various types of auto-parameters that can be implicitly
//! added to a function's parameter list by the calling convention.

use serde::{Deserialize, Serialize};

/// Types of auto-parameters.
///
/// Corresponds to `ghidra.program.model.listing.AutoParameterType`.
///
/// Auto-parameters are hidden parameters that are implicitly added to a
/// function's parameter list based on the calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AutoParameterType {
    /// The `this` pointer associated with a `__thiscall` calling convention,
    /// passed as a hidden parameter.
    This,
    /// A caller-allocated return storage pointer passed as a hidden parameter.
    ReturnStoragePtr,
}

impl AutoParameterType {
    /// Returns the display name for this auto-parameter type.
    pub fn get_display_name(self) -> &'static str {
        match self {
            AutoParameterType::This => "this",
            AutoParameterType::ReturnStoragePtr => "__return_storage_ptr__",
        }
    }

    /// Returns the ordinal value for storage.
    pub fn ordinal(self) -> u8 {
        match self {
            AutoParameterType::This => 0,
            AutoParameterType::ReturnStoragePtr => 1,
        }
    }

    /// Creates an `AutoParameterType` from an ordinal.
    pub fn from_ordinal(ordinal: u8) -> Option<Self> {
        match ordinal {
            0 => Some(AutoParameterType::This),
            1 => Some(AutoParameterType::ReturnStoragePtr),
            _ => None,
        }
    }

    /// All auto-parameter types.
    pub fn all() -> &'static [AutoParameterType] {
        &[AutoParameterType::This, AutoParameterType::ReturnStoragePtr]
    }
}

impl std::fmt::Display for AutoParameterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_parameter_type_display() {
        assert_eq!(format!("{}", AutoParameterType::This), "this");
        assert_eq!(
            format!("{}", AutoParameterType::ReturnStoragePtr),
            "__return_storage_ptr__"
        );
    }

    #[test]
    fn test_auto_parameter_type_ordinal() {
        assert_eq!(AutoParameterType::This.ordinal(), 0);
        assert_eq!(AutoParameterType::ReturnStoragePtr.ordinal(), 1);
    }

    #[test]
    fn test_auto_parameter_type_from_ordinal() {
        assert_eq!(
            AutoParameterType::from_ordinal(0),
            Some(AutoParameterType::This)
        );
        assert_eq!(
            AutoParameterType::from_ordinal(1),
            Some(AutoParameterType::ReturnStoragePtr)
        );
        assert_eq!(AutoParameterType::from_ordinal(2), None);
    }

    #[test]
    fn test_auto_parameter_type_all() {
        assert_eq!(AutoParameterType::all().len(), 2);
    }
}
