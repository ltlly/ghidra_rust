//! PDB Member -- data model for composite structure/union members.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb.PdbMember` and
//! `ghidra.app.util.bin.format.pdb.DefaultPdbMember`.

use std::fmt;

use super::pdb_kind::PdbKind;
use super::wrapped_data_type::WrappedDataType;

/// Errors that can occur during PDB member operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdbMemberError {
    /// Failed to resolve the member's data type.
    DataTypeResolutionFailed(String),
    /// Invalid bitfield specification.
    InvalidBitfield(String),
    /// Missing bitfield offset.
    MissingBitfieldOffset,
}

impl fmt::Display for PdbMemberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PdbMemberError::DataTypeResolutionFailed(name) => {
                write!(f, "Failed to resolve datatype: {}", name)
            }
            PdbMemberError::InvalidBitfield(spec) => {
                write!(f, "Invalid PDB bitfield specification: {}", spec)
            }
            PdbMemberError::MissingBitfieldOffset => {
                write!(f, "Missing bitfield offset in PDB member")
            }
        }
    }
}

impl std::error::Error for PdbMemberError {}

/// A PDB member within a composite type (structure, union, or class).
///
/// Conveys PDB member information used for datatype reconstruction.
/// The `data_type_name` is expected to include namespace prefixes when relevant.
///
/// When representing bitfields, the `name` field conveys bit-size and bit-offset
/// information (e.g., `fieldname:SSSS:XXXX` where SSSS is the bit-size and
/// XXXX is the bit-offset).
#[derive(Debug, Clone)]
pub struct PdbMember {
    /// Member field name. For bitfields, this is the clean name without the
    /// bitfield size/offset suffix.
    pub name: String,
    /// Member data type name (may be namespace-qualified).
    pub data_type_name: String,
    /// Byte offset of this member within the root composite.
    pub offset: i32,
    /// Optional member comment.
    pub comment: Option<String>,
    /// Kind of member record.
    pub kind: PdbKind,
    /// Whether this member is a bitfield.
    pub is_bitfield: bool,
    /// Bitfield size in bits (only valid if `is_bitfield` is true).
    pub bitfield_size: i32,
    /// Bitfield offset within the base type (only valid if `is_bitfield` is true).
    /// A value of -1 indicates unknown.
    pub bitfield_offset: i32,
}

impl PdbMember {
    /// Create a new PDB member.
    ///
    /// Parses the name to extract bitfield information if present.
    pub fn new(
        name: &str,
        data_type_name: &str,
        offset: i32,
        kind: PdbKind,
    ) -> Self {
        let (clean_name, is_bitfield, bitfield_size, bitfield_offset) =
            Self::parse_member(name, kind);

        Self {
            name: clean_name,
            data_type_name: data_type_name.to_string(),
            offset,
            comment: None,
            kind,
            is_bitfield,
            bitfield_size,
            bitfield_offset,
        }
    }

    /// Create a new PDB member with a comment.
    pub fn with_comment(
        name: &str,
        data_type_name: &str,
        offset: i32,
        kind: PdbKind,
        comment: &str,
    ) -> Self {
        let mut member = Self::new(name, data_type_name, offset, kind);
        member.comment = Some(comment.to_string());
        member
    }

    /// Parse the member name to extract the clean name and bitfield information.
    ///
    /// The name format for bitfields is: `name:BIT_SIZE_HEX:BIT_OFFSET_HEX`
    /// where the hex values have "0x" prefixes.
    fn parse_member(name: &str, kind: PdbKind) -> (String, bool, i32, i32) {
        if name.is_empty() {
            return (name.to_string(), false, -1, -1);
        }

        // For non-Member kinds, strip namespace prefix
        if kind != PdbKind::Member {
            return (extract_last_name(name), false, -1, -1);
        }

        if let Some(bf_index) = get_bitfield_index(name) {
            let clean_name = name[..bf_index].to_string();
            let bit_spec = &name[bf_index + 1..];

            // Parse BIT_SIZE:BIT_OFFSET
            let (bitfield_size, bitfield_offset) = if let Some(colon_pos) = bit_spec.find(':') {
                let size_str = &bit_spec[..colon_pos];
                let offset_str = &bit_spec[colon_pos + 1..];
                let size = parse_hex_or_dec(size_str).unwrap_or(0);
                let offset = parse_hex_or_dec(offset_str).unwrap_or(-1);
                (size, offset)
            } else {
                // Missing offset
                let size = parse_hex_or_dec(bit_spec).unwrap_or(0);
                (size, -1)
            };

            (clean_name, true, bitfield_size, bitfield_offset)
        } else {
            // For Member kind, keep the name as-is (including namespace prefix)
            (name.to_string(), false, -1, -1)
        }
    }

    /// Get the display string for this member.
    pub fn display_string(&self) -> String {
        let mut s = format!(
            "name={}, type={}, offset={}",
            self.name, self.data_type_name, self.offset
        );
        if self.is_bitfield {
            s.push_str(&format!(
                ", bitSize={}, bitOffset={}",
                self.bitfield_size, self.bitfield_offset
            ));
        }
        s
    }

    /// Check if this member is a regular field member (not a container or special kind).
    pub fn is_field_member(&self) -> bool {
        self.kind == PdbKind::Member
    }
}

impl fmt::Display for PdbMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "name={}, type={}, offset={}",
            self.name, self.data_type_name, self.offset
        )
    }
}

/// Find the index of the bitfield component in a mixed name field.
///
/// Assumes format: `nameWithNamespace[:bfBitLen:bfBitOff]`
/// The bfBitLen and bfBitOff fields are represented as hex with "0x" prefixes.
///
/// Returns the index of the first singleton colon, or -1 if there is no bitfield component.
fn get_bitfield_index(name: &str) -> Option<usize> {
    let last_colon = name.rfind(':')?;
    // Minimum location of last singleton ':' is 1 (e.g., "a:0x1")
    if last_colon < 1 {
        return None;
    }
    // Check if we found "::" (namespace delimiter)
    if last_colon > 0 && name.as_bytes().get(last_colon - 1) == Some(&b':') {
        return None;
    }
    // Find the previous colon (for "name:SIZE:OFFSET" format)
    if let Some(prev_colon) = name[..last_colon].rfind(':') {
        // Verify it's a singleton colon (not "::")
        if prev_colon > 0 && name.as_bytes().get(prev_colon - 1) == Some(&b':') {
            return None;
        }
        Some(prev_colon)
    } else {
        // Single colon format: "name:SIZE" (no offset)
        Some(last_colon)
    }
}

/// Extract the last component of a namespace-qualified name.
///
/// For example, `"std::vector::iterator"` returns `"iterator"`.
fn extract_last_name(name: &str) -> String {
    // Split on "::" and take the last component
    if let Some(pos) = name.rfind("::") {
        name[pos + 2..].to_string()
    } else {
        name.to_string()
    }
}

/// Parse a hex string (with optional "0x" prefix) or decimal string.
fn parse_hex_or_dec(s: &str) -> Option<i32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<i32>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_member() {
        let m = PdbMember::new("field1", "int", 0, PdbKind::Member);
        assert_eq!(m.name, "field1");
        assert_eq!(m.data_type_name, "int");
        assert_eq!(m.offset, 0);
        assert!(!m.is_bitfield);
    }

    #[test]
    fn test_member_with_namespace() {
        let m = PdbMember::new("MyClass::member", "float", 4, PdbKind::Member);
        // For Member kind with no bitfield spec, the name is kept as-is from parse_member
        // but extract_last_name is not called for Member kind
        assert_eq!(m.name, "MyClass::member");
    }

    #[test]
    fn test_non_member_strips_namespace() {
        let m = PdbMember::new("MyClass::base_member", "int", 0, PdbKind::StaticMember);
        assert_eq!(m.name, "base_member");
    }

    #[test]
    fn test_bitfield_member() {
        let m = PdbMember::new("flags:0x4:0x0", "unsigned int", 0, PdbKind::Member);
        assert_eq!(m.name, "flags");
        assert!(m.is_bitfield);
        assert_eq!(m.bitfield_size, 4);
        assert_eq!(m.bitfield_offset, 0);
    }

    #[test]
    fn test_bitfield_member_with_namespace_in_name() {
        // Bitfield parsing should work even with namespace-like names
        let m = PdbMember::new("myfield:0x8:0x10", "int", 8, PdbKind::Member);
        assert_eq!(m.name, "myfield");
        assert!(m.is_bitfield);
        assert_eq!(m.bitfield_size, 8);
        assert_eq!(m.bitfield_offset, 16);
    }

    #[test]
    fn test_bitfield_missing_offset() {
        let m = PdbMember::new("bits:0x4", "int", 0, PdbKind::Member);
        assert_eq!(m.name, "bits");
        assert!(m.is_bitfield);
        assert_eq!(m.bitfield_size, 4);
        assert_eq!(m.bitfield_offset, -1); // missing
    }

    #[test]
    fn test_empty_name() {
        let m = PdbMember::new("", "int", 0, PdbKind::Member);
        assert_eq!(m.name, "");
        assert!(!m.is_bitfield);
    }

    #[test]
    fn test_with_comment() {
        let m = PdbMember::with_comment("x", "int", 0, PdbKind::Member, "test comment");
        assert_eq!(m.comment, Some("test comment".to_string()));
    }

    #[test]
    fn test_display() {
        let m = PdbMember::new("value", "int", 4, PdbKind::Member);
        assert_eq!(format!("{}", m), "name=value, type=int, offset=4");
    }

    #[test]
    fn test_display_string_bitfield() {
        let m = PdbMember::new("flags:0x8:0x0", "unsigned int", 0, PdbKind::Member);
        let s = m.display_string();
        assert!(s.contains("bitSize=8"));
        assert!(s.contains("bitOffset=0"));
    }

    #[test]
    fn test_is_field_member() {
        let m = PdbMember::new("x", "int", 0, PdbKind::Member);
        assert!(m.is_field_member());

        let m = PdbMember::new("base", "int", 0, PdbKind::StaticMember);
        assert!(!m.is_field_member());
    }

    #[test]
    fn test_get_bitfield_index() {
        assert_eq!(get_bitfield_index("a:0x1:0x0"), Some(1));
        assert_eq!(get_bitfield_index("name:0x4:0x8"), Some(4));
        assert_eq!(get_bitfield_index("ns::name"), None); // "::" is namespace
        assert_eq!(get_bitfield_index("simple"), None);
        assert_eq!(get_bitfield_index("a"), None); // too short
    }

    #[test]
    fn test_extract_last_name() {
        assert_eq!(extract_last_name("std::vector"), "vector");
        assert_eq!(extract_last_name("a::b::c"), "c");
        assert_eq!(extract_last_name("simple"), "simple");
    }

    #[test]
    fn test_parse_hex_or_dec() {
        assert_eq!(parse_hex_or_dec("0x10"), Some(16));
        assert_eq!(parse_hex_or_dec("0xFF"), Some(255));
        assert_eq!(parse_hex_or_dec("42"), Some(42));
        assert_eq!(parse_hex_or_dec("invalid"), None);
    }
}
