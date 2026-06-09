//! Bind -- precedence enum for PDB type emit formatting.
//!
//! Ports Ghidra's inner enum `AbstractMsType.Bind`.

use std::fmt;

/// Precedence level used when emitting PDB type expressions.
///
/// When serializing complex type expressions (e.g., pointer-to-function,
/// array-of-pointers), parentheses must be inserted to preserve the correct
/// reading order. The `Bind` enum encodes which syntactic category the
/// current type occupies, so that the emitter can decide whether surrounding
/// parentheses are needed.
///
/// The variants are ordered by increasing syntactic tightness:
/// `PTR` binds most loosely, `NONE` is the default / no-binding case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Bind {
    /// Pointer type context (e.g., `int *`).
    PTR = 0,
    /// Array type context (e.g., `int[10]`).
    ARRAY = 1,
    /// Procedure / function type context (e.g., `int(int, int)`).
    PROC = 2,
    /// No specific binding context -- the default.
    NONE = 3,
}

impl Default for Bind {
    fn default() -> Self {
        Bind::NONE
    }
}

impl Bind {
    /// Return the label name of this bind level.
    pub fn label(&self) -> &'static str {
        match self {
            Bind::PTR => "PTR",
            Bind::ARRAY => "ARRAY",
            Bind::PROC => "PROC",
            Bind::NONE => "NONE",
        }
    }

    /// Parse a bind level from its ordinal value.
    pub fn from_ordinal(v: u8) -> Self {
        match v {
            0 => Bind::PTR,
            1 => Bind::ARRAY,
            2 => Bind::PROC,
            _ => Bind::NONE,
        }
    }
}

impl fmt::Display for Bind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordering() {
        assert!(Bind::PTR < Bind::ARRAY);
        assert!(Bind::ARRAY < Bind::PROC);
        assert!(Bind::PROC < Bind::NONE);
    }

    #[test]
    fn test_label() {
        assert_eq!(Bind::PTR.label(), "PTR");
        assert_eq!(Bind::ARRAY.label(), "ARRAY");
        assert_eq!(Bind::PROC.label(), "PROC");
        assert_eq!(Bind::NONE.label(), "NONE");
    }

    #[test]
    fn test_from_ordinal() {
        assert_eq!(Bind::from_ordinal(0), Bind::PTR);
        assert_eq!(Bind::from_ordinal(1), Bind::ARRAY);
        assert_eq!(Bind::from_ordinal(2), Bind::PROC);
        assert_eq!(Bind::from_ordinal(3), Bind::NONE);
        assert_eq!(Bind::from_ordinal(99), Bind::NONE);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Bind::PTR), "PTR");
        assert_eq!(format!("{}", Bind::NONE), "NONE");
    }

    #[test]
    fn test_default() {
        assert_eq!(Bind::default(), Bind::NONE);
    }
}
