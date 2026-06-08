//! PDB Kind -- classification of PDB composite members.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb.PdbKind`.

use std::fmt;

/// Classification of PDB composite members.
///
/// Each variant represents a specific kind of member within a PDB composite
/// (structure, union, or class).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PdbKind {
    /// A structure container.
    Structure,
    /// A union container.
    Union,
    /// A regular member field.
    Member,
    /// A static local variable.
    StaticLocal,
    /// A static member variable.
    StaticMember,
    /// An object pointer (this pointer).
    ObjectPointer,
    /// A function parameter.
    Parameter,
    /// A local variable.
    Local,
    /// Unknown or unsupported kind.
    Unknown,
}

impl PdbKind {
    /// Get the camelCase name of this kind.
    ///
    /// For example, `ObjectPointer` returns `"ObjectPointer"`,
    /// `StaticLocal` returns `"StaticLocal"`.
    pub fn camel_name(&self) -> &'static str {
        match self {
            PdbKind::Structure => "Structure",
            PdbKind::Union => "Union",
            PdbKind::Member => "Member",
            PdbKind::StaticLocal => "StaticLocal",
            PdbKind::StaticMember => "StaticMember",
            PdbKind::ObjectPointer => "ObjectPointer",
            PdbKind::Parameter => "Parameter",
            PdbKind::Local => "Local",
            PdbKind::Unknown => "Unknown",
        }
    }

    /// Parse a case-insensitive kind string and return the corresponding PdbKind.
    ///
    /// Kind strings are expected in camel notation (e.g., "ObjectPointer").
    /// If not identified, `Unknown` is returned.
    pub fn parse(kind: &str) -> Self {
        let lower = kind.to_lowercase();
        match lower.as_str() {
            "structure" => PdbKind::Structure,
            "union" => PdbKind::Union,
            "member" => PdbKind::Member,
            "staticlocal" => PdbKind::StaticLocal,
            "staticmember" => PdbKind::StaticMember,
            "objectpointer" => PdbKind::ObjectPointer,
            "parameter" => PdbKind::Parameter,
            "local" => PdbKind::Local,
            _ => PdbKind::Unknown,
        }
    }

    /// Convert an UPPER_CASE name to CamelCase.
    ///
    /// For example, `"OBJECT_POINTER"` becomes `"ObjectPointer"`.
    pub fn to_camel(name: &str) -> String {
        let mut result = String::with_capacity(name.len());
        let mut make_upper = true;
        for c in name.chars() {
            if c == '_' {
                make_upper = true;
                continue;
            }
            if make_upper {
                result.push(c.to_ascii_uppercase());
                make_upper = false;
            } else {
                result.push(c.to_ascii_lowercase());
            }
        }
        result
    }
}

impl fmt::Display for PdbKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.camel_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_camel_name() {
        assert_eq!(PdbKind::Structure.camel_name(), "Structure");
        assert_eq!(PdbKind::ObjectPointer.camel_name(), "ObjectPointer");
        assert_eq!(PdbKind::StaticLocal.camel_name(), "StaticLocal");
        assert_eq!(PdbKind::Unknown.camel_name(), "Unknown");
    }

    #[test]
    fn test_parse_case_insensitive() {
        assert_eq!(PdbKind::parse("Structure"), PdbKind::Structure);
        assert_eq!(PdbKind::parse("STRUCTURE"), PdbKind::Structure);
        assert_eq!(PdbKind::parse("structure"), PdbKind::Structure);
        assert_eq!(PdbKind::parse("ObjectPointer"), PdbKind::ObjectPointer);
        assert_eq!(PdbKind::parse("objectpointer"), PdbKind::ObjectPointer);
    }

    #[test]
    fn test_parse_unknown() {
        assert_eq!(PdbKind::parse("NotAKind"), PdbKind::Unknown);
        assert_eq!(PdbKind::parse(""), PdbKind::Unknown);
    }

    #[test]
    fn test_to_camel() {
        assert_eq!(PdbKind::to_camel("OBJECT_POINTER"), "ObjectPointer");
        assert_eq!(PdbKind::to_camel("STATIC_LOCAL"), "StaticLocal");
        assert_eq!(PdbKind::to_camel("MEMBER"), "Member");
        assert_eq!(PdbKind::to_camel("STRUCTURE"), "Structure");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", PdbKind::Member), "Member");
        assert_eq!(format!("{}", PdbKind::ObjectPointer), "ObjectPointer");
    }

    #[test]
    fn test_all_variants_have_camel_name() {
        let kinds = [
            PdbKind::Structure,
            PdbKind::Union,
            PdbKind::Member,
            PdbKind::StaticLocal,
            PdbKind::StaticMember,
            PdbKind::ObjectPointer,
            PdbKind::Parameter,
            PdbKind::Local,
            PdbKind::Unknown,
        ];
        for kind in &kinds {
            let name = kind.camel_name();
            assert!(!name.is_empty());
            // Verify round-trip through parse
            assert_eq!(PdbKind::parse(name), *kind);
        }
    }
}
