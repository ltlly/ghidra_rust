//! Enumeration types for data type system.
//!
//! Ports of:
//! - `AlignmentType.java`
//! - `PackingType.java`
//! - `GenericCallingConvention.java`
//! - `ArchiveType.java`

use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// AlignmentType
// ============================================================================

/// Specifies the type of alignment which applies to a composite data type.
///
/// Port of Ghidra's `AlignmentType.java`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlignmentType {
    /// Alignment is computed based upon the current pack setting and data organization rules.
    /// If packing is disabled the computed alignment will be 1.
    Default,
    /// Alignment will be a multiple of the machine alignment specified by the data organization.
    Machine,
    /// Alignment will be a multiple of the explicit alignment value specified for the datatype.
    Explicit,
}

impl AlignmentType {
    /// Returns `true` if this is the DEFAULT alignment type.
    pub fn is_default(&self) -> bool {
        *self == Self::Default
    }

    /// Returns `true` if this is the MACHINE alignment type.
    pub fn is_machine(&self) -> bool {
        *self == Self::Machine
    }

    /// Returns `true` if this is the EXPLICIT alignment type.
    pub fn is_explicit(&self) -> bool {
        *self == Self::Explicit
    }
}

impl Default for AlignmentType {
    fn default() -> Self {
        Self::Default
    }
}

impl fmt::Display for AlignmentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "DEFAULT"),
            Self::Machine => write!(f, "MACHINE"),
            Self::Explicit => write!(f, "EXPLICIT"),
        }
    }
}

// ============================================================================
// PackingType
// ============================================================================

/// Specifies the pack setting which applies to a composite data type.
///
/// Port of Ghidra's `PackingType.java`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackingType {
    /// Automatic component placement should not be performed. Components are placed
    /// at specified offsets and undefined components are used to reflect padding/unused bytes.
    /// Commonly used during reverse-engineering.
    Disabled,
    /// Components should be placed automatically based upon their alignment.
    /// Reflects default compiler behavior when a complete composite definition is known.
    Default,
    /// An explicit pack value has been specified. Components should be placed automatically
    /// based upon their alignment, not to exceed the pack value.
    Explicit,
}

impl PackingType {
    /// Returns `true` if packing is disabled (manual placement).
    pub fn is_disabled(&self) -> bool {
        *self == Self::Disabled
    }

    /// Returns `true` if default packing rules apply.
    pub fn is_default(&self) -> bool {
        *self == Self::Default
    }

    /// Returns `true` if an explicit pack value is used.
    pub fn is_explicit(&self) -> bool {
        *self == Self::Explicit
    }
}

impl Default for PackingType {
    fn default() -> Self {
        Self::Disabled
    }
}

impl fmt::Display for PackingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "DISABLED"),
            Self::Default => write!(f, "DEFAULT"),
            Self::Explicit => write!(f, "EXPLICIT"),
        }
    }
}

// ============================================================================
// GenericCallingConvention
// ============================================================================

/// Identifies the generic calling convention associated with a function definition.
///
/// Port of Ghidra's `GenericCallingConvention.java`. Use of this enum is deprecated
/// in favor of arbitrary calling convention name strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GenericCallingConvention {
    /// The calling convention has not been identified.
    Unknown,
    /// MS Windows calling convention where the called-function purges the stack.
    Stdcall,
    /// Standard/default C calling convention using the stack for parameters.
    Cdecl,
    /// Standard/default convention using only registers for parameters.
    Fastcall,
    /// C++ instance method calling convention.
    Thiscall,
    /// Extended vector registers calling convention (similar to fastcall).
    Vectorcall,
}

impl GenericCallingConvention {
    /// The declaration name string (e.g., `"__stdcall"`).
    pub fn declaration_name(&self) -> &'static str {
        match self {
            Self::Unknown => "",
            Self::Stdcall => "__stdcall",
            Self::Cdecl => "__cdecl",
            Self::Fastcall => "__fastcall",
            Self::Thiscall => "__thiscall",
            Self::Vectorcall => "__vectorcall",
        }
    }

    /// Look up a convention by its declaration name (case-insensitive).
    /// Falls back to `Unknown` if not found.
    pub fn from_declaration_name(name: &str) -> Self {
        let lower = name.to_lowercase();
        for variant in Self::all() {
            if variant.declaration_name().to_lowercase() == lower
                || format!("{:?}", variant).to_lowercase() == lower
            {
                return *variant;
            }
        }
        Self::Unknown
    }

    /// Look up a convention by ordinal.
    pub fn from_ordinal(ordinal: usize) -> Self {
        let all = Self::all();
        if ordinal < all.len() {
            all[ordinal]
        } else {
            Self::Unknown
        }
    }

    /// All conventions in canonical order.
    pub fn all() -> &'static [GenericCallingConvention] {
        &[
            Self::Unknown,
            Self::Stdcall,
            Self::Cdecl,
            Self::Fastcall,
            Self::Thiscall,
            Self::Vectorcall,
        ]
    }

    /// The ordinal (index) of this convention.
    pub fn ordinal(&self) -> usize {
        Self::all()
            .iter()
            .position(|v| *v == *self)
            .unwrap_or(0)
    }
}

impl Default for GenericCallingConvention {
    fn default() -> Self {
        Self::Unknown
    }
}

impl fmt::Display for GenericCallingConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.declaration_name())
    }
}

// ============================================================================
// ArchiveType
// ============================================================================

/// The type of a data type archive.
///
/// Port of Ghidra's `ArchiveType.java`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArchiveType {
    /// A program archive.
    Program,
    /// A project archive.
    Project,
    /// A file archive (e.g., .gdt file).
    File,
    /// Built-in types archive.
    BuiltIn,
}

impl ArchiveType {
    /// Returns `true` if this is a program archive.
    pub fn is_program(&self) -> bool {
        *self == Self::Program
    }

    /// Returns `true` if this is a file archive.
    pub fn is_file(&self) -> bool {
        *self == Self::File
    }

    /// Returns `true` if this is the built-in types archive.
    pub fn is_builtin(&self) -> bool {
        *self == Self::BuiltIn
    }
}

impl Default for ArchiveType {
    fn default() -> Self {
        Self::File
    }
}

impl fmt::Display for ArchiveType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Program => write!(f, "Program"),
            Self::Project => write!(f, "Project"),
            Self::File => write!(f, "File"),
            Self::BuiltIn => write!(f, "BuiltIn"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alignment_type() {
        assert!(AlignmentType::Default.is_default());
        assert!(AlignmentType::Machine.is_machine());
        assert!(AlignmentType::Explicit.is_explicit());
        assert_eq!(format!("{}", AlignmentType::Machine), "MACHINE");
    }

    #[test]
    fn test_packing_type() {
        assert!(PackingType::Disabled.is_disabled());
        assert!(PackingType::Default.is_default());
        assert!(PackingType::Explicit.is_explicit());
        assert_eq!(format!("{}", PackingType::Disabled), "DISABLED");
    }

    #[test]
    fn test_generic_calling_convention_from_name() {
        assert_eq!(
            GenericCallingConvention::from_declaration_name("__stdcall"),
            GenericCallingConvention::Stdcall
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("__cdecl"),
            GenericCallingConvention::Cdecl
        );
        assert_eq!(
            GenericCallingConvention::from_declaration_name("unknown"),
            GenericCallingConvention::Unknown
        );
    }

    #[test]
    fn test_generic_calling_convention_ordinal() {
        assert_eq!(GenericCallingConvention::Unknown.ordinal(), 0);
        assert_eq!(GenericCallingConvention::Stdcall.ordinal(), 1);
        assert_eq!(GenericCallingConvention::Cdecl.ordinal(), 2);
        assert_eq!(GenericCallingConvention::from_ordinal(3), GenericCallingConvention::Fastcall);
    }

    #[test]
    fn test_generic_calling_convention_display() {
        assert_eq!(format!("{}", GenericCallingConvention::Thiscall), "__thiscall");
        assert_eq!(format!("{}", GenericCallingConvention::Vectorcall), "__vectorcall");
    }

    #[test]
    fn test_archive_type() {
        assert!(ArchiveType::File.is_file());
        assert!(ArchiveType::BuiltIn.is_builtin());
        assert_eq!(format!("{}", ArchiveType::Program), "Program");
    }
}
