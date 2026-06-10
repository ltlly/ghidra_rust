//! S_REGISTER -- Register variable symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.RegisterMsSymbol`
//! (0x1106), `RegisterStMsSymbol` (0x1001), and `Register16MsSymbol` (0x0002).
//!
//! The 16-bit variant (`Register16MsSymbol`) encodes two register indices in a
//! single u16: the high byte is the primary register, the low byte is the
//! secondary register.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};
use crate::pdb::registers;

/// Which variant of the register symbol was parsed.
///
/// The three variants share the same struct but differ in how the register
/// field is encoded and which PDB kind they correspond to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterVariant {
    /// `S_REGISTER` (0x1106) -- 32-bit type index, single u16 register, NT string.
    Register,
    /// `S_REGISTER_ST` (0x1001) -- 32-bit type index, single u16 register, ST string.
    RegisterSt,
    /// `S_REGISTER_16` (0x0002) -- 16-bit type index, dual-register (high:low byte), ST string.
    Register16,
}

/// A register variable symbol (`S_REGISTER`).
///
/// This symbol describes a variable whose value is held in a CPU register
/// rather than in memory. It records the type, the register index, and the
/// variable name.
///
/// # PDB Binary Layout (S_REGISTER, 32-bit type index, NT string)
///
/// ```text
/// type_record : u32
/// register    : u16
/// name        : NT string
/// ```
///
/// # PDB Binary Layout (S_REGISTER_ST, 32-bit type index, ST string)
///
/// ```text
/// type_record : u32
/// register    : u16
/// name        : ST string (16-bit length prefix)
/// ```
///
/// # PDB Binary Layout (S_REGISTER_16, 16-bit type index, dual register)
///
/// ```text
/// type_record : u16
/// register    : u16  (high byte = primary, low byte = secondary)
/// name        : ST string (16-bit length prefix)
/// ```
///
/// This corresponds to `S_REGISTER` (0x1106), `S_REGISTER_ST` (0x1001), and
/// `S_REGISTER_16` (0x0002) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SRegister {
    /// The type record number describing this variable's type.
    pub type_record_number: RecordNumber,

    /// The register index (architecture-specific register number).
    /// For the 16-bit dual-register variant, this is the primary (high byte).
    pub register_index: u16,

    /// The secondary register index, only used by the 16-bit dual-register
    /// variant (`Register16MsSymbol`). Zero for all other variants.
    pub register_index2: u16,

    /// The variable name.
    pub name: String,

    /// Which variant was parsed.
    variant: RegisterVariant,
}

impl SRegister {
    /// Create a new register variable symbol (S_REGISTER variant).
    pub fn new(type_record_number: RecordNumber, register_index: u16, name: String) -> Self {
        Self {
            type_record_number,
            register_index,
            register_index2: 0,
            name,
            variant: RegisterVariant::Register,
        }
    }

    /// Create a new ST-format register variable symbol (S_REGISTER_ST variant).
    pub fn new_st(type_record_number: RecordNumber, register_index: u16, name: String) -> Self {
        Self {
            type_record_number,
            register_index,
            register_index2: 0,
            name,
            variant: RegisterVariant::RegisterSt,
        }
    }

    /// Create a new 16-bit dual-register variable symbol (S_REGISTER_16 variant).
    ///
    /// `register_val` is the raw 16-bit value where the high byte is the
    /// primary register and the low byte is the secondary register.
    pub fn new_register16(
        type_record_number: RecordNumber,
        register_val: u16,
        name: String,
    ) -> Self {
        Self {
            type_record_number,
            register_index: register_val >> 8,
            register_index2: register_val & 0xFF,
            name,
            variant: RegisterVariant::Register16,
        }
    }

    /// Parse an S_REGISTER symbol from a byte slice (32-bit type index, NT string).
    ///
    /// Expects the layout: `type_record(u32) + register(u16) + name(NT)`.
    ///
    /// This handles `S_REGISTER` (0x1106).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let register_index = u16::from_le_bytes([data[4], data[5]]);
        let name = parse_nt_string(&data[6..]);
        Some(Self {
            type_record_number: trn,
            register_index,
            register_index2: 0,
            name,
            variant: RegisterVariant::Register,
        })
    }

    /// Parse an S_REGISTER_ST symbol from a byte slice (32-bit type index, ST string).
    ///
    /// Expects the layout: `type_record(u32) + register(u16) + name(ST)`.
    ///
    /// The Java `RegisterStMsSymbol` uses `recordNumberSize=32` and
    /// `StringParseType.StringUtf8St` (16-bit length-prefixed UTF-8 string).
    ///
    /// This handles `S_REGISTER_ST` (0x1001).
    pub fn parse_st(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 32);
        let register_index = u16::from_le_bytes([data[4], data[5]]);
        let name = parse_st_string(&data[6..]);
        Some(Self {
            type_record_number: trn,
            register_index,
            register_index2: 0,
            name,
            variant: RegisterVariant::RegisterSt,
        })
    }

    /// Parse an S_REGISTER_16 symbol from a byte slice (16-bit type index,
    /// dual-register, ST string).
    ///
    /// Expects the layout: `type_record(u16) + register(u16) + name(ST)`.
    ///
    /// The Java `Register16MsSymbol` uses `recordNumberSize=16` and
    /// `StringParseType.StringUtf8St`. The 16-bit register value is split:
    /// high byte = primary register, low byte = secondary register.
    ///
    /// This handles `S_REGISTER_16` (0x0002).
    pub fn parse_register16(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let (trn, _) = RecordNumber::parse(data, 0, RecordCategory::Type, 16);
        let register_val = u16::from_le_bytes([data[2], data[3]]);
        let name = parse_st_string(&data[4..]);
        Some(Self {
            type_record_number: trn,
            register_index: register_val >> 8,
            register_index2: register_val & 0xFF,
            name,
            variant: RegisterVariant::Register16,
        })
    }

    /// Return the variant of this register symbol.
    pub fn variant(&self) -> RegisterVariant {
        self.variant
    }

    /// Return the human-readable register name for this symbol's register
    /// index, using the standard CV register mapping.
    ///
    /// Returns a static string such as `"EAX"`, `"RBP"`, `"XMM0"`, etc.
    /// If the register index is not recognized, returns `"???"`.
    pub fn register_name(&self) -> &'static str {
        registers::register_name(self.register_index as u32)
    }

    /// Return the human-readable name for the secondary register (16-bit
    /// variant only).
    ///
    /// Returns `"???"` if the secondary register is zero or unrecognized.
    pub fn register_name2(&self) -> &'static str {
        registers::register_name(self.register_index2 as u32)
    }

    /// Whether this is the dual-register 16-bit variant.
    pub fn is_dual_register(&self) -> bool {
        self.variant == RegisterVariant::Register16
    }

    /// Whether this was parsed from the ST string format.
    pub fn is_st_format(&self) -> bool {
        self.variant == RegisterVariant::RegisterSt
    }

    /// Parse an S_REGISTER symbol and return it along with the total bytes
    /// consumed (including 4-byte alignment padding after the name).
    ///
    /// This matches the Java `reader.align4()` call in
    /// `RegisterMsSymbol`.
    pub fn parse_aligned(data: &[u8]) -> Option<(Self, usize)> {
        let sym = Self::parse(data)?;
        // type_record(4) + register(2) + name_len + null, aligned to 4
        let name_data = &data[6..];
        let end = name_data.iter().position(|&b| b == 0).unwrap_or(name_data.len());
        let name_len = end + 1;
        let total = 6 + name_len;
        let aligned = (total + 3) & !3;
        Some((sym, aligned))
    }

    /// Parse an S_REGISTER_ST symbol and return it along with the total bytes
    /// consumed (including 4-byte alignment padding after the name).
    pub fn parse_st_aligned(data: &[u8]) -> Option<(Self, usize)> {
        let sym = Self::parse_st(data)?;
        // type_record(4) + register(2) + st_len_prefix(2) + name_bytes, aligned to 4
        if data.len() < 8 {
            return Some((sym, data.len()));
        }
        let st_len = u16::from_le_bytes([data[6], data[7]]) as usize;
        let total = 8 + st_len;
        let aligned = (total + 3) & !3;
        Some((sym, aligned))
    }

    /// Parse an S_REGISTER_16 symbol and return it along with the total bytes
    /// consumed (including 4-byte alignment padding after the name).
    pub fn parse_register16_aligned(data: &[u8]) -> Option<(Self, usize)> {
        let sym = Self::parse_register16(data)?;
        // type_record(2) + register(2) + st_len_prefix(2) + name_bytes, aligned to 4
        if data.len() < 6 {
            return Some((sym, data.len()));
        }
        let st_len = u16::from_le_bytes([data[4], data[5]]) as usize;
        let total = 6 + st_len;
        let aligned = (total + 3) & !3;
        Some((sym, aligned))
    }

    /// Return the human-readable register names for all registers in this
    /// symbol (both primary and secondary for the 16-bit variant).
    pub fn register_names(&self) -> Vec<&'static str> {
        let mut names = vec![self.register_name()];
        if self.is_dual_register() && self.register_index2 != 0 {
            names.push(self.register_name2());
        }
        names
    }
}

impl AbstractMsSymbol for SRegister {
    fn pdb_id(&self) -> u16 {
        match self.variant {
            RegisterVariant::Register => super::super::symbol_kind::S_REGISTER,
            RegisterVariant::RegisterSt => super::super::symbol_kind::S_REGISTER_ST,
            RegisterVariant::Register16 => 0x0002, // S_REGISTER_16
        }
    }

    fn symbol_type_name(&self) -> &'static str {
        match self.variant {
            RegisterVariant::Register => "S_REGISTER",
            RegisterVariant::RegisterSt => "S_REGISTER_ST",
            RegisterVariant::Register16 => "S_REGISTER_16",
        }
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.variant == RegisterVariant::Register16 {
            // Dual-register format: emit both register names
            write!(
                f,
                "Register16: {} ({:#X}):{} ({:#X}), Type: {}, {}",
                self.register_name(),
                self.register_index,
                self.register_name2(),
                self.register_index2,
                self.type_record_number,
                self.name
            )
        } else {
            write!(
                f,
                "Register: {} ({:#X}), Type: {}, {}",
                self.register_name(),
                self.register_index,
                self.type_record_number,
                self.name
            )
        }
    }
}

impl NameMsSymbol for SRegister {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

/// Parse a null-terminated UTF-8 string from a byte slice.
fn parse_nt_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

/// Parse an ST-format UTF-8 string (16-bit length prefix followed by that
/// many bytes of UTF-8 data).
fn parse_st_string(data: &[u8]) -> String {
    if data.len() < 2 {
        return String::new();
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let end = 2 + len;
    if end > data.len() {
        return String::from_utf8_lossy(&data[2..]).to_string();
    }
    String::from_utf8_lossy(&data[2..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::RecordNumber;

    fn make_register_bytes(type_index: u32, register: u16, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_index.to_le_bytes());
        data.extend_from_slice(&register.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    fn make_register_st_bytes(type_index: u32, register: u16, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_index.to_le_bytes());
        data.extend_from_slice(&register.to_le_bytes());
        // ST string: 16-bit length prefix + raw bytes
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);
        data
    }

    fn make_register16_bytes(type_index: u16, register_val: u16, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&type_index.to_le_bytes());
        data.extend_from_slice(&register_val.to_le_bytes());
        // ST string: 16-bit length prefix + raw bytes
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_register_bytes(0x1020, 20, b"eax_var");
        let sym = SRegister::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.register_index, 20);
        assert_eq!(sym.name, "eax_var");
        assert_eq!(sym.variant, RegisterVariant::Register);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SRegister::parse(&data).is_none());
    }

    #[test]
    fn test_parse_empty_name() {
        let data = make_register_bytes(0x1000, 6, b"");
        let sym = SRegister::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1000);
        assert_eq!(sym.register_index, 6);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_minimal() {
        // type_record(u32) + register(u16) + null byte = 7 bytes
        let data = [0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00];
        let sym = SRegister::parse(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 1);
        assert_eq!(sym.register_index, 3);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_st_basic() {
        let data = make_register_st_bytes(0x1020, 17, b"eax_st_var");
        let sym = SRegister::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1020);
        assert_eq!(sym.register_index, 17);
        assert_eq!(sym.name, "eax_st_var");
        assert_eq!(sym.variant, RegisterVariant::RegisterSt);
    }

    #[test]
    fn test_parse_st_truncated() {
        let data = [0x00, 0x01]; // too short (need 6 bytes min: 4 type + 2 register)
        assert!(SRegister::parse_st(&data).is_none());
    }

    #[test]
    fn test_parse_st_empty_name() {
        let data = make_register_st_bytes(0x1000, 6, b"");
        let sym = SRegister::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x1000);
        assert_eq!(sym.register_index, 6);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_register16_basic() {
        // register_val = 0x1112 => primary=0x11 (EAX), secondary=0x12 (ECX)
        let data = make_register16_bytes(0x0100, 0x1112, b"dual_reg");
        let sym = SRegister::parse_register16(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x0100);
        assert_eq!(sym.register_index, 0x11);
        assert_eq!(sym.register_index2, 0x12);
        assert_eq!(sym.name, "dual_reg");
        assert_eq!(sym.variant, RegisterVariant::Register16);
        assert!(sym.is_dual_register());
    }

    #[test]
    fn test_parse_register16_truncated() {
        let data = [0x00, 0x01]; // too short for 16-bit type + register
        assert!(SRegister::parse_register16(&data).is_none());
    }

    #[test]
    fn test_parse_register16_empty_name() {
        let data = make_register16_bytes(0x0050, 0x1100, b"");
        let sym = SRegister::parse_register16(&data).unwrap();
        assert_eq!(sym.register_index, 0x11);
        assert_eq!(sym.register_index2, 0x00);
        assert_eq!(sym.name, "");
    }

    #[test]
    fn test_parse_register16_high_byte_primary() {
        // 0x1314 => primary=0x13 (EBX), secondary=0x14 (ESP)
        let data = make_register16_bytes(0x0200, 0x1314, b"pair");
        let sym = SRegister::parse_register16(&data).unwrap();
        assert_eq!(sym.register_index, 0x13);
        assert_eq!(sym.register_index2, 0x14);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SRegister::new(
            RecordNumber::type_record_number(0x1020),
            20,
            "local_var".to_string(),
        );
        assert_eq!(sym.pdb_id(), 0x0002);
        assert_eq!(sym.symbol_type_name(), "S_REGISTER");
        assert_eq!(sym.name(), "local_var");
        assert_eq!(sym.register_index, 20);
        assert!(!sym.is_dual_register());
    }

    #[test]
    fn test_trait_impls_st() {
        let sym = SRegister::parse_st(&make_register_st_bytes(0x1000, 17, b"eax")).unwrap();
        assert_eq!(sym.pdb_id(), 0x1001);
        assert_eq!(sym.symbol_type_name(), "S_REGISTER_ST");
    }

    #[test]
    fn test_trait_impls_register16() {
        let sym = SRegister::parse_register16(&make_register16_bytes(0x0100, 0x1112, b"d")).unwrap();
        assert_eq!(sym.pdb_id(), 0x0002);
        assert_eq!(sym.symbol_type_name(), "S_REGISTER_16");
    }

    #[test]
    fn test_display() {
        let sym = SRegister::new(
            RecordNumber::type_record_number(0x1000),
            20,
            "bp_var".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("Register"));
        assert!(s.contains("bp_var"));
        assert!(s.contains("EBX")); // register index 20 = EBX
    }

    #[test]
    fn test_display_register16() {
        let sym = SRegister::new_register16(
            RecordNumber::type_record_number(0x0100),
            0x1112,
            "dual".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("Register16"));
        assert!(s.contains("EAX"));
        assert!(s.contains("ECX"));
        assert!(s.contains("dual"));
    }

    #[test]
    fn test_register_name_eax() {
        let sym = SRegister::new(
            RecordNumber::type_record_number(0x1000),
            0x0011,
            "ret_val".to_string(),
        );
        assert_eq!(sym.register_name(), "EAX");
    }

    #[test]
    fn test_register_name_rbp() {
        let sym = SRegister::new(
            RecordNumber::type_record_number(0x1000),
            0x0095,
            "frame_var".to_string(),
        );
        assert_eq!(sym.register_name(), "RBP");
    }

    #[test]
    fn test_register_name_unknown() {
        let sym = SRegister::new(
            RecordNumber::type_record_number(0x1000),
            0xFFFF,
            "mystery".to_string(),
        );
        // The registers module returns "Unknown" for unrecognized indices
        let name = sym.register_name();
        assert!(name == "???" || name == "Unknown",
            "unexpected register name: {}", name);
    }

    #[test]
    fn test_x86_register_indices() {
        // Common x86-64 register indices: EAX=17, ECX=18, EDX=19, EBX=20
        let data = make_register_bytes(0x1000, 17, b"ret_val");
        let sym = SRegister::parse(&data).unwrap();
        assert_eq!(sym.register_index, 17);
        assert_eq!(sym.register_name(), "EAX");

        let data = make_register_bytes(0x1000, 20, b"saved_bx");
        let sym = SRegister::parse(&data).unwrap();
        assert_eq!(sym.register_index, 20);
        assert_eq!(sym.register_name(), "EBX");
    }

    #[test]
    fn test_display_contains_register_name() {
        let sym = SRegister::new(
            RecordNumber::type_record_number(0x1000),
            0x0011, // EAX
            "my_eax".to_string(),
        );
        let s = format!("{}", sym);
        assert!(s.contains("EAX"));
        assert!(s.contains("0x11"));
        assert!(s.contains("my_eax"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SRegister::new(
            RecordNumber::type_record_number(0x1020),
            20,
            "test".to_string(),
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_st_format_roundtrip() {
        let data = make_register_st_bytes(0x0100, 0x0016, b"bp_local");
        let sym = SRegister::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x0100);
        assert_eq!(sym.register_index, 0x0016);
        assert_eq!(sym.register_name(), "EBP");
        assert_eq!(sym.name, "bp_local");
    }

    #[test]
    fn test_parse_st_32bit_type_index() {
        // ST variants use 32-bit type index, not 16-bit
        let data = make_register_st_bytes(0x12345678, 0x0011, b"eax_st");
        let sym = SRegister::parse_st(&data).unwrap();
        assert_eq!(sym.type_record_number.number(), 0x12345678);
        assert_eq!(sym.register_index, 0x0011);
        assert_eq!(sym.register_name(), "EAX");
        assert_eq!(sym.name, "eax_st");
    }

    #[test]
    fn test_register16_secondary_register_name() {
        let sym = SRegister::new_register16(
            RecordNumber::type_record_number(0x0100),
            0x1112, // primary=EAX, secondary=ECX
            "split".to_string(),
        );
        assert_eq!(sym.register_name(), "EAX");
        assert_eq!(sym.register_name2(), "ECX");
    }

    #[test]
    fn test_new_st_constructor() {
        let sym = SRegister::new_st(
            RecordNumber::type_record_number(0x1020),
            17,
            "st_var".to_string(),
        );
        assert_eq!(sym.variant(), RegisterVariant::RegisterSt);
        assert_eq!(sym.register_index, 17);
        assert_eq!(sym.name, "st_var");
        assert_eq!(sym.pdb_id(), 0x1001);
        assert!(sym.is_st_format());
    }

    #[test]
    fn test_register_names_single() {
        let sym = SRegister::new(
            RecordNumber::type_record_number(0x1000),
            0x0011,
            "v".to_string(),
        );
        let names = sym.register_names();
        assert_eq!(names, vec!["EAX"]);
    }

    #[test]
    fn test_register_names_dual() {
        let sym = SRegister::new_register16(
            RecordNumber::type_record_number(0x0100),
            0x1112,
            "v".to_string(),
        );
        let names = sym.register_names();
        assert_eq!(names, vec!["EAX", "ECX"]);
    }

    #[test]
    fn test_register_names_dual_no_secondary() {
        let sym = SRegister::new_register16(
            RecordNumber::type_record_number(0x0100),
            0x1100, // secondary=0
            "v".to_string(),
        );
        let names = sym.register_names();
        assert_eq!(names, vec!["EAX"]);
    }

    #[test]
    fn test_parse_register16_aligned_basic() {
        // type_record(2) + register(2) + st_len(2) + "abc"(3) = 9, aligned to 12
        let data = make_register16_bytes(0x0100, 0x1112, b"abc");
        let (sym, consumed) = SRegister::parse_register16_aligned(&data).unwrap();
        assert_eq!(sym.register_index, 0x11);
        assert_eq!(sym.register_index2, 0x12);
        assert_eq!(sym.name, "abc");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_register16_aligned_empty() {
        // type_record(2) + register(2) + st_len(2) + ""(0) = 6, aligned to 8
        let data = make_register16_bytes(0x0100, 0x1100, b"");
        let (sym, consumed) = SRegister::parse_register16_aligned(&data).unwrap();
        assert_eq!(sym.name, "");
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_variant_consistency() {
        let sym = SRegister::new(
            RecordNumber::type_record_number(0x1000),
            0x0011,
            "v".to_string(),
        );
        assert_eq!(sym.variant(), RegisterVariant::Register);

        let data = make_register_st_bytes(0x1000, 0x0011, b"v");
        let sym = SRegister::parse_st(&data).unwrap();
        assert_eq!(sym.variant(), RegisterVariant::RegisterSt);

        let data = make_register16_bytes(0x0100, 0x1112, b"v");
        let sym = SRegister::parse_register16(&data).unwrap();
        assert_eq!(sym.variant(), RegisterVariant::Register16);
    }

    #[test]
    fn test_is_st_format() {
        let sym = SRegister::new(
            RecordNumber::type_record_number(0x1000),
            0x0011,
            "v".to_string(),
        );
        assert!(!sym.is_st_format());

        let data = make_register_st_bytes(0x1000, 0x0011, b"v");
        let sym = SRegister::parse_st(&data).unwrap();
        assert!(sym.is_st_format());
    }

    #[test]
    fn test_parse_aligned_basic() {
        // type_record(4) + register(2) + "abc\0"(4) = 10, aligned to 12
        let data = make_register_bytes(0x1000, 17, b"abc");
        let (sym, consumed) = SRegister::parse_aligned(&data).unwrap();
        assert_eq!(sym.register_index, 17);
        assert_eq!(sym.name, "abc");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_aligned_already_aligned() {
        // type_record(4) + register(2) + "ab\0"(3) = 9, aligned to 12
        let data = make_register_bytes(0x1000, 17, b"ab");
        let (sym, consumed) = SRegister::parse_aligned(&data).unwrap();
        assert_eq!(sym.name, "ab");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_st_aligned_basic() {
        // type_record(4) + register(2) + st_len(2) + "abc"(3) = 11, aligned to 12
        let data = make_register_st_bytes(0x1000, 17, b"abc");
        let (sym, consumed) = SRegister::parse_st_aligned(&data).unwrap();
        assert_eq!(sym.register_index, 17);
        assert_eq!(sym.name, "abc");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_parse_st_aligned_empty_name() {
        // type_record(4) + register(2) + st_len(2) + ""(0) = 8, aligned to 8
        let data = make_register_st_bytes(0x1000, 17, b"");
        let (sym, consumed) = SRegister::parse_st_aligned(&data).unwrap();
        assert_eq!(sym.name, "");
        assert_eq!(consumed, 8);
    }
}
