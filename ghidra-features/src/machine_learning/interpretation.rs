//! Address interpretation enum.
//!
//! Ported from `Interpretation.java` in the MachineLearning extension.
//!
//! Represents possible interpretations of addresses in a binary program
//! (e.g., data, undefined, function start, function interior, etc.).

use std::fmt;

/// An enum representing possible interpretations of addresses in a program.
///
/// Used during function start detection to classify what each address
/// represents in the current disassembly state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Interpretation {
    /// The address is in undefined (uninitialized/unexplored) memory.
    Undefined,
    /// The address contains defined data.
    Data,
    /// The address is an offcut reference (middle of an instruction).
    Offcut,
    /// The address is the start of a basic block.
    BlockStart,
    /// The address is within a basic block (not at the start).
    WithinBlock,
    /// The address is the entry point of a function.
    FunctionStart,
    /// The address is inside a function body (not the entry point).
    FunctionInterior,
}

impl Interpretation {
    /// Get the human-readable display name for this interpretation.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Undefined => "Undefined",
            Self::Data => "Data",
            Self::Offcut => "Offcut",
            Self::BlockStart => "Block Start",
            Self::WithinBlock => "Within Block",
            Self::FunctionStart => "Function Start",
            Self::FunctionInterior => "Function Interior",
        }
    }

    /// Returns `true` if this interpretation indicates the address is within
    /// recognized code (a function start or interior).
    pub fn is_code(&self) -> bool {
        matches!(self, Self::FunctionStart | Self::FunctionInterior)
    }

    /// Returns `true` if this interpretation indicates the address is at a
    /// function entry point.
    pub fn is_function_entry(&self) -> bool {
        matches!(self, Self::FunctionStart)
    }

    /// Returns `true` if the address is in undefined or data memory.
    pub fn is_undefined_or_data(&self) -> bool {
        matches!(self, Self::Undefined | Self::Data)
    }
}

impl fmt::Display for Interpretation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_names() {
        assert_eq!(Interpretation::Undefined.to_string(), "Undefined");
        assert_eq!(Interpretation::Data.to_string(), "Data");
        assert_eq!(Interpretation::Offcut.to_string(), "Offcut");
        assert_eq!(Interpretation::BlockStart.to_string(), "Block Start");
        assert_eq!(Interpretation::WithinBlock.to_string(), "Within Block");
        assert_eq!(
            Interpretation::FunctionStart.to_string(),
            "Function Start"
        );
        assert_eq!(
            Interpretation::FunctionInterior.to_string(),
            "Function Interior"
        );
    }

    #[test]
    fn test_is_code() {
        assert!(Interpretation::FunctionStart.is_code());
        assert!(Interpretation::FunctionInterior.is_code());
        assert!(!Interpretation::Data.is_code());
        assert!(!Interpretation::Undefined.is_code());
        assert!(!Interpretation::BlockStart.is_code());
    }

    #[test]
    fn test_is_function_entry() {
        assert!(Interpretation::FunctionStart.is_function_entry());
        assert!(!Interpretation::FunctionInterior.is_function_entry());
        assert!(!Interpretation::Undefined.is_function_entry());
    }

    #[test]
    fn test_is_undefined_or_data() {
        assert!(Interpretation::Undefined.is_undefined_or_data());
        assert!(Interpretation::Data.is_undefined_or_data());
        assert!(!Interpretation::Offcut.is_undefined_or_data());
        assert!(!Interpretation::FunctionStart.is_undefined_or_data());
    }

    #[test]
    fn test_all_variants_unique() {
        let variants = [
            Interpretation::Undefined,
            Interpretation::Data,
            Interpretation::Offcut,
            Interpretation::BlockStart,
            Interpretation::WithinBlock,
            Interpretation::FunctionStart,
            Interpretation::FunctionInterior,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }
}
