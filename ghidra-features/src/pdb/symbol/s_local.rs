//! S_LOCAL_V2 / S_LOCAL_2005 -- Local variable symbol (v2 format).
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.LocalMsSymbol` and
//! `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.LocalVariableFlags`.
//!
//! # Binary Format
//!
//! ```text
//! type_index : u32       (type index into TPI stream)
//! flags      : u16       (LocalVariableFlags bitfield)
//! name       : NT string (null-terminated UTF-8)
//! ```
//!
//! After the name, the stream is 4-byte aligned (the `align4` step in Java).
//!
//! # Flag Bits
//!
//! The 16-bit `flags` field is decoded as a bitfield following the Java
//! `LocalVariableFlags.processFlags()` layout (bits 0-10).

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// Local variable flag bits.
///
/// These flags are encoded in the 16-bit `flags` field of the `S_LOCAL_V2`
/// record. They describe the storage class and properties of the local
/// variable.
///
/// The bit layout matches Ghidra's `LocalVariableFlags.processFlags()`:
///
/// | Bit | Field |
/// |-----|-------|
/// | 0   | is_parameter |
/// | 1   | is_address_taken |
/// | 2   | is_compiler_generated |
/// | 3   | is_aggregate (isAggregateWhole) |
/// | 4   | is_aggregate_member (isAggregatedPart) |
/// | 5   | is_aliased |
/// | 6   | is_alias (isAggregateContainingAggregate) |
/// | 7   | is_function_return_value |
/// | 8   | is_optimized_out |
/// | 9   | is_enregistered_global |
/// | 10  | is_enregistered_static |
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalFlags {
    /// Variable is a parameter (not a local).
    pub is_parameter: bool,
    /// Variable address is taken somewhere in the program.
    pub is_address_taken: bool,
    /// Variable is compiler-generated (not present in source).
    pub is_compiler_generated: bool,
    /// Variable is an aggregate (struct/union) that has been decomposed.
    pub is_aggregate: bool,
    /// Variable is part of an aggregate (a member that was split out).
    pub is_aggregate_member: bool,
    /// Variable is aliased (shared storage with another variable).
    pub is_aliased: bool,
    /// Variable is aliased through an aggregate member.
    pub is_alias: bool,
    /// Variable is a function return value.
    pub is_function_return_value: bool,
    /// Variable has been optimized out by the compiler.
    pub is_optimized_out: bool,
    /// Variable is an enregistered global.
    pub is_enregistered_global: bool,
    /// Variable is an enregistered static local.
    pub is_enregistered_static: bool,
}

impl LocalFlags {
    /// Decode flags from a raw 16-bit value.
    pub fn from_u16(raw: u16) -> Self {
        Self {
            is_parameter: (raw & 0x0001) != 0,
            is_address_taken: (raw & 0x0002) != 0,
            is_compiler_generated: (raw & 0x0004) != 0,
            is_aggregate: (raw & 0x0008) != 0,
            is_aggregate_member: (raw & 0x0010) != 0,
            is_aliased: (raw & 0x0020) != 0,
            is_alias: (raw & 0x0040) != 0,
            is_function_return_value: (raw & 0x0080) != 0,
            is_optimized_out: (raw & 0x0100) != 0,
            is_enregistered_global: (raw & 0x0200) != 0,
            is_enregistered_static: (raw & 0x0400) != 0,
        }
    }

    /// Encode flags back to a raw 16-bit value.
    pub fn to_u16(&self) -> u16 {
        let mut val: u16 = 0;
        if self.is_parameter { val |= 0x0001; }
        if self.is_address_taken { val |= 0x0002; }
        if self.is_compiler_generated { val |= 0x0004; }
        if self.is_aggregate { val |= 0x0008; }
        if self.is_aggregate_member { val |= 0x0010; }
        if self.is_aliased { val |= 0x0020; }
        if self.is_alias { val |= 0x0040; }
        if self.is_function_return_value { val |= 0x0080; }
        if self.is_optimized_out { val |= 0x0100; }
        if self.is_enregistered_global { val |= 0x0200; }
        if self.is_enregistered_static { val |= 0x0400; }
        val
    }

    /// Return a human-readable description of the active flags.
    ///
    /// This matches the Java `LocalVariableFlags.emit()` output format.
    pub fn emit_description(&self) -> String {
        let mut parts = Vec::new();
        if self.is_address_taken {
            parts.push("Address Taken");
        }
        if self.is_compiler_generated {
            parts.push("Compiler Generated");
        }
        if self.is_aggregate {
            parts.push("aggregate");
        }
        if self.is_aggregate_member {
            parts.push("aggregated");
        }
        if self.is_aliased {
            parts.push("aliased");
        }
        if self.is_alias {
            parts.push("alias");
        }
        if self.is_function_return_value {
            parts.push("return value");
        }
        if self.is_optimized_out {
            parts.push("optimized away");
        }
        if self.is_enregistered_global {
            if self.is_enregistered_static {
                parts.push("file static");
            } else {
                parts.push("global");
            }
        } else if self.is_enregistered_static {
            parts.push("static local");
        }
        parts.join(", ")
    }
}

/// A local variable symbol (`S_LOCAL_V2` / `S_LOCAL_2005`).
///
/// This symbol describes a local variable or parameter within a procedure.
/// It identifies the variable's type, name, and properties. The actual
/// storage location is specified by a subsequent `S_DEFRANGE_*` record that
/// follows this symbol in the symbol stream.
///
/// # PDB Binary Layout
///
/// ```text
/// type_index : u32
/// flags      : u16
/// name       : NT string
/// ```
///
/// This corresponds to `S_LOCAL_V2` (0x1035) and `S_LOCAL_2005` (0x1026)
/// in the CodeView symbol set. Both variants share the same layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLocal {
    /// The type record number describing this variable's type.
    pub type_record_number: RecordNumber,

    /// Raw flags value.
    pub raw_flags: u16,

    /// Parsed flag values from the `flags` bitfield.
    pub local_flags: LocalFlags,

    /// The variable name.
    pub name: String,
}

impl SLocal {
    /// Create a new local variable symbol.
    pub fn new(
        type_record_number: RecordNumber,
        raw_flags: u16,
        name: String,
    ) -> Self {
        Self {
            type_record_number,
            raw_flags,
            local_flags: LocalFlags::from_u16(raw_flags),
            name,
        }
    }

    /// Parse an S_LOCAL_V2 symbol from a byte slice.
    ///
    /// Expects the layout: `type_index(u32) + flags(u16) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let raw_flags = u16::from_le_bytes([data[4], data[5]]);
        let name = parse_nt_string(&data[6..]);
        Some(Self {
            type_record_number: trn,
            raw_flags,
            local_flags: LocalFlags::from_u16(raw_flags),
            name,
        })
    }

    /// Return `true` if this local is a parameter rather than a true local.
    pub fn is_parameter(&self) -> bool {
        self.local_flags.is_parameter
    }

    /// Return `true` if the variable's address is taken.
    pub fn is_address_taken(&self) -> bool {
        self.local_flags.is_address_taken
    }

    /// Return `true` if this is a compiler-generated variable.
    pub fn is_compiler_generated(&self) -> bool {
        self.local_flags.is_compiler_generated
    }

    /// Return `true` if this variable is a function return value.
    pub fn is_function_return_value(&self) -> bool {
        self.local_flags.is_function_return_value
    }

    /// Return `true` if this variable has been optimized out.
    pub fn is_optimized_out(&self) -> bool {
        self.local_flags.is_optimized_out
    }

    /// Return `true` if this variable is an enregistered global.
    pub fn is_enregistered_global(&self) -> bool {
        self.local_flags.is_enregistered_global
    }

    /// Return `true` if this variable is an enregistered static local.
    pub fn is_enregistered_static(&self) -> bool {
        self.local_flags.is_enregistered_static
    }

    /// Return a human-readable description of the flag state.
    ///
    /// Matches the Java `LocalVariableFlags.emit()` format.
    pub fn flags_description(&self) -> String {
        let prefix = if self.is_parameter() { "Param" } else { "Local" };
        let detail = self.local_flags.emit_description();
        if detail.is_empty() {
            prefix.to_string()
        } else {
            format!("{}, {}", prefix, detail)
        }
    }
}

impl AbstractMsSymbol for SLocal {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_LOCAL_V2
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_LOCAL_V2"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags_desc = self.local_flags.emit_description();
        if flags_desc.is_empty() {
            write!(
                f,
                "LOCAL: {:#010X} {}, {}",
                self.type_record_number.number(),
                if self.is_parameter() { "Param" } else { "Local" },
                self.name,
            )
        } else {
            write!(
                f,
                "LOCAL: {:#010X} {}, {}, {}",
                self.type_record_number.number(),
                if self.is_parameter() { "Param" } else { "Local" },
                flags_desc,
                self.name,
            )
        }
    }
}

impl NameMsSymbol for SLocal {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SLocal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

/// Parse a null-terminated UTF-8 string from a byte slice.
fn parse_nt_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::RecordNumber;

    fn make_local_bytes(type_index: u32, flags: u16, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_index.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_local_bytes(0x1020, 0, b"my_var");
        let sym = SLocal::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.raw_flags, 0);
        assert_eq!(sym.name, "my_var");
        assert!(!sym.is_parameter());
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SLocal::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_name() {
        let data = make_local_bytes(0x1000, 0, b"");
        let sym = SLocal::parse(&data).unwrap();
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_parameter_flag() {
        let data = make_local_bytes(0x1020, 0x0001, b"param_a");
        let sym = SLocal::parse(&data).unwrap();
        assert!(sym.is_parameter());
        assert!(!sym.is_address_taken());
    }

    #[test]
    fn test_parse_address_taken_flag() {
        let data = make_local_bytes(0x1020, 0x0002, b"buf");
        let sym = SLocal::parse(&data).unwrap();
        assert!(!sym.is_parameter());
        assert!(sym.is_address_taken());
    }

    #[test]
    fn test_parse_compiler_generated_flag() {
        let data = make_local_bytes(0x1020, 0x0004, b"$T0");
        let sym = SLocal::parse(&data).unwrap();
        assert!(sym.is_compiler_generated());
    }

    #[test]
    fn test_parse_multiple_flags() {
        // parameter + address_taken = 0x0001 | 0x0002 = 0x0003
        let data = make_local_bytes(0x1020, 0x0003, b"arg");
        let sym = SLocal::parse(&data).unwrap();
        assert!(sym.is_parameter());
        assert!(sym.is_address_taken());
    }

    #[test]
    fn test_parse_function_return_value_flag() {
        let data = make_local_bytes(0x1020, 0x0080, b"$ret");
        let sym = SLocal::parse(&data).unwrap();
        assert!(sym.is_function_return_value());
        assert!(!sym.is_parameter());
    }

    #[test]
    fn test_parse_optimized_out_flag() {
        let data = make_local_bytes(0x1020, 0x0100, b"$opt");
        let sym = SLocal::parse(&data).unwrap();
        assert!(sym.is_optimized_out());
    }

    #[test]
    fn test_parse_enregistered_global_flag() {
        let data = make_local_bytes(0x1020, 0x0200, b"g_var");
        let sym = SLocal::parse(&data).unwrap();
        assert!(sym.is_enregistered_global());
        assert!(!sym.is_enregistered_static());
    }

    #[test]
    fn test_parse_enregistered_static_flag() {
        let data = make_local_bytes(0x1020, 0x0400, b"s_var");
        let sym = SLocal::parse(&data).unwrap();
        assert!(sym.is_enregistered_static());
        assert!(!sym.is_enregistered_global());
    }

    #[test]
    fn test_parse_enregistered_file_static() {
        // global + static = 0x0200 | 0x0400 = 0x0600
        let data = make_local_bytes(0x1020, 0x0600, b"fs_var");
        let sym = SLocal::parse(&data).unwrap();
        assert!(sym.is_enregistered_global());
        assert!(sym.is_enregistered_static());
    }

    #[test]
    fn test_parse_alias_flag() {
        let data = make_local_bytes(0x1020, 0x0040, b"alias_var");
        let sym = SLocal::parse(&data).unwrap();
        assert!(sym.local_flags.is_alias);
    }

    #[test]
    fn test_flags_description_parameter() {
        let sym = SLocal::new(
            RecordNumber::type_record_number(0x1020),
            0x0001,
            "p".to_string(),
        );
        assert_eq!(sym.flags_description(), "Param");
    }

    #[test]
    fn test_flags_description_with_details() {
        let sym = SLocal::new(
            RecordNumber::type_record_number(0x1020),
            0x0001 | 0x0002, // parameter + address_taken
            "p".to_string(),
        );
        assert_eq!(sym.flags_description(), "Param, Address Taken");
    }

    #[test]
    fn test_flags_description_optimized_out() {
        let sym = SLocal::new(
            RecordNumber::type_record_number(0x1020),
            0x0100,
            "x".to_string(),
        );
        assert_eq!(sym.flags_description(), "Local, optimized away");
    }

    #[test]
    fn test_trait_impls() {
        let sym = SLocal::new(
            RecordNumber::type_record_number(0x1020),
            0,
            "local_x".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x1035);
        assert_eq!(sym.symbol_type_name(), "S_LOCAL_V2");
        assert_eq!(sym.name(), "local_x");
    }

    #[test]
    fn test_display() {
        let sym = SLocal::new(
            RecordNumber::type_record_number(0x1000),
            0x0001,
            "my_param".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("LOCAL"));
        assert!(s.contains("Param"));
        assert!(s.contains("my_param"));
    }

    #[test]
    fn test_name_trait() {
        let sym = SLocal::new(
            RecordNumber::type_record_number(0x1000),
            0,
            "foo".to_string(),
        );
        assert_eq!(sym.name(), "foo");
    }

    #[test]
    fn test_clone_eq() {
        let a = SLocal::new(
            RecordNumber::type_record_number(0x1020),
            0,
            "x".to_string(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_flags_roundtrip() {
        // Test that from_u16 -> to_u16 produces the same value
        for raw in [0u16, 0x0001, 0x0003, 0x007F, 0x07FF, 0xFFFF] {
            let flags = LocalFlags::from_u16(raw);
            // Only bits 0-10 are defined, so mask to those
            assert_eq!(flags.to_u16(), raw & 0x07FF);
        }
    }

    #[test]
    fn test_flags_to_u16_individual() {
        let flags = LocalFlags::from_u16(0x0001);
        assert_eq!(flags.to_u16(), 0x0001);

        let flags = LocalFlags::from_u16(0x0400);
        assert_eq!(flags.to_u16(), 0x0400);
    }
}
