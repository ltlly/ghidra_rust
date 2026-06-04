//! TraceBreakpointKind - the kinds of breakpoints in a trace.
//!
//! Ported from Ghidra's `TraceBreakpointKind` enum.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// The kind of a breakpoint, identifying what access traps execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TraceBreakpointKind {
    /// Read access breakpoint.
    Read,
    /// Write access breakpoint.
    Write,
    /// Hardware execute breakpoint.
    HwExecute,
    /// Software execute breakpoint.
    SwExecute,
}

impl TraceBreakpointKind {
    /// The character used to encode this kind in the database.
    pub fn encoding_char(&self) -> char {
        match self {
            Self::Read => 'R',
            Self::Write => 'W',
            Self::HwExecute => 'X',
            Self::SwExecute => 'x',
        }
    }

    /// Decode a kind from its database character.
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'R' => Some(Self::Read),
            'W' => Some(Self::Write),
            'X' => Some(Self::HwExecute),
            'x' => Some(Self::SwExecute),
            _ => None,
        }
    }

    /// Bit mask for database encoding.
    pub fn bit(&self) -> u8 {
        match self {
            Self::Read => 1,
            Self::Write => 2,
            Self::HwExecute => 4,
            Self::SwExecute => 8,
        }
    }

    /// Decode a set of kinds from a bit field.
    pub fn from_bits(bits: u8) -> BTreeSet<Self> {
        let mut set = BTreeSet::new();
        if bits & 1 != 0 {
            set.insert(Self::Read);
        }
        if bits & 2 != 0 {
            set.insert(Self::Write);
        }
        if bits & 4 != 0 {
            set.insert(Self::HwExecute);
        }
        if bits & 8 != 0 {
            set.insert(Self::SwExecute);
        }
        set
    }

    /// Encode a set of kinds to a bit field.
    pub fn to_bits(kinds: &BTreeSet<Self>) -> u8 {
        kinds.iter().fold(0u8, |acc, k| acc | k.bit())
    }

    /// Parse a set of kinds from a flags string (e.g. "RWX").
    pub fn from_flags(s: &str) -> BTreeSet<Self> {
        s.chars()
            .filter_map(Self::from_char)
            .collect()
    }
}

impl fmt::Display for TraceBreakpointKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encoding_char())
    }
}

/// A set of breakpoint kinds.
pub type BreakpointKindSet = BTreeSet<TraceBreakpointKind>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoding_char_roundtrip() {
        for kind in [
            TraceBreakpointKind::Read,
            TraceBreakpointKind::Write,
            TraceBreakpointKind::HwExecute,
            TraceBreakpointKind::SwExecute,
        ] {
            assert_eq!(TraceBreakpointKind::from_char(kind.encoding_char()), Some(kind));
        }
    }

    #[test]
    fn test_bits_roundtrip() {
        let kinds: BTreeSet<_> = [
            TraceBreakpointKind::Read,
            TraceBreakpointKind::HwExecute,
        ]
        .into_iter()
        .collect();
        let bits = TraceBreakpointKind::to_bits(&kinds);
        let back = TraceBreakpointKind::from_bits(bits);
        assert_eq!(kinds, back);
    }

    #[test]
    fn test_from_flags() {
        let kinds = TraceBreakpointKind::from_flags("RWX");
        assert!(kinds.contains(&TraceBreakpointKind::Read));
        assert!(kinds.contains(&TraceBreakpointKind::Write));
        assert!(kinds.contains(&TraceBreakpointKind::HwExecute));
        assert!(!kinds.contains(&TraceBreakpointKind::SwExecute));
    }

    #[test]
    fn test_display() {
        assert_eq!(TraceBreakpointKind::Read.to_string(), "R");
        assert_eq!(TraceBreakpointKind::HwExecute.to_string(), "X");
    }
}
