//! Miscellaneous Plugin Utilities.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.misc` Java package.
//!
//! Provides shared utility types used by multiple plugins.

/// Miscellaneous actions (memory map, program info, etc.).
///
/// Ported from `ghidra.app.plugin.core.misc` action classes.
pub mod actions;

/// The import type for binary files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportType {
    /// Auto-detect the file format.
    Auto,
    /// Raw binary.
    Raw,
    /// ELF binary.
    Elf,
    /// PE (Windows) binary.
    Pe,
    /// Mach-O binary.
    Macho,
    /// COFF object file.
    Coff,
    /// Intel HEX format.
    IntelHex,
    /// Motorola S-Record format.
    MotorolaSRecord,
    /// Java Class file.
    JavaClass,
    /// Dalvik DEX file.
    Dalvik,
    /// WebAssembly.
    Wasm,
}

impl ImportType {
    /// Get the display name of the import type.
    pub fn display_name(&self) -> &str {
        match self {
            Self::Auto => "Auto-detect",
            Self::Raw => "Raw Binary",
            Self::Elf => "ELF",
            Self::Pe => "PE",
            Self::Macho => "Mach-O",
            Self::Coff => "COFF",
            Self::IntelHex => "Intel HEX",
            Self::MotorolaSRecord => "Motorola S-Record",
            Self::JavaClass => "Java Class",
            Self::Dalvik => "Dalvik DEX",
            Self::Wasm => "WebAssembly",
        }
    }

    /// Whether this format is auto-detected.
    pub fn is_auto(&self) -> bool { matches!(self, Self::Auto) }

    /// File extension commonly associated with this format.
    pub fn file_extension(&self) -> Option<&str> {
        match self {
            Self::Elf => Some("elf"), Self::Pe => Some("exe"),
            Self::Macho => Some("macho"), Self::Coff => Some("o"),
            Self::IntelHex => Some("hex"), Self::MotorolaSRecord => Some("srec"),
            Self::JavaClass => Some("class"), Self::Dalvik => Some("dex"),
            Self::Wasm => Some("wasm"), _ => None,
        }
    }
}

impl std::fmt::Display for ImportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.display_name()) }
}

/// A display format option for addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressDisplayFormat {
    /// Hexadecimal (default).
    Hex,
    /// Decimal.
    Decimal,
    /// Octal.
    Octal,
    /// Binary.
    Binary,
}

impl AddressDisplayFormat {
    /// Format an address value according to this format.
    pub fn format(&self, value: u64) -> String {
        match self {
            Self::Hex => format!("0x{:X}", value),
            Self::Decimal => format!("{}", value),
            Self::Octal => format!("0o{:o}", value),
            Self::Binary => format!("0b{:b}", value),
        }
    }

    /// Format with a fixed width (zero-padded).
    pub fn format_padded(&self, value: u64, width: usize) -> String {
        match self {
            Self::Hex => format!("0x{:0width$X}", value, width = width),
            Self::Decimal => format!("{:0width$}", value, width = width),
            Self::Octal => format!("0o{:0width$o}", value, width = width),
            Self::Binary => format!("0b{:0width$b}", value, width = width),
        }
    }
}

impl Default for AddressDisplayFormat {
    fn default() -> Self { Self::Hex }
}

/// Byte order for multi-byte values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    /// Big-endian (most significant byte first).
    Big,
    /// Little-endian (least significant byte first).
    Little,
}

impl Endianness {
    /// Whether this is big-endian.
    pub fn is_big_endian(&self) -> bool { matches!(self, Self::Big) }
    /// Whether this is little-endian.
    pub fn is_little_endian(&self) -> bool { matches!(self, Self::Little) }
    /// Read a `u16` from a 2-byte slice.
    pub fn read_u16(&self, data: &[u8]) -> u16 {
        match self {
            Self::Big => u16::from_be_bytes([data[0], data[1]]),
            Self::Little => u16::from_le_bytes([data[0], data[1]]),
        }
    }
    /// Read a `u32` from a 4-byte slice.
    pub fn read_u32(&self, data: &[u8]) -> u32 {
        match self {
            Self::Big => u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            Self::Little => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        }
    }
}

impl std::fmt::Display for Endianness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Big => write!(f, "Big Endian"), Self::Little => write!(f, "Little Endian") }
    }
}

/// Formatting options for register values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterValueFormat {
    Hex, SignedDecimal, UnsignedDecimal, Octal, Binary,
}

impl RegisterValueFormat {
    /// Format a register value.
    pub fn format_value(&self, value: u64, size_bytes: usize) -> String {
        match self {
            Self::Hex => format!("0x{:0width$X}", value, width = size_bytes * 2),
            Self::SignedDecimal => {
                let signed = match size_bytes { 1 => value as i8 as i64, 2 => value as i16 as i64, 4 => value as i32 as i64, _ => value as i64 };
                format!("{}", signed)
            }
            Self::UnsignedDecimal => format!("{}", value),
            Self::Octal => format!("0o{:o}", value),
            Self::Binary => format!("0b{:b}", value),
        }
    }
}

impl Default for RegisterValueFormat {
    fn default() -> Self { Self::Hex }
}

/// Standard plugin categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginCategory { Common, Analysis, Processor, Debugger, Script, Data, Search }

impl PluginCategory {
    /// Display name.
    pub fn display_name(&self) -> &str {
        match self { Self::Common => "Common", Self::Analysis => "Analysis", Self::Processor => "Processor", Self::Debugger => "Debugger", Self::Script => "Script", Self::Data => "Data", Self::Search => "Search" }
    }
}

impl std::fmt::Display for PluginCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.display_name()) }
}

/// Plugin status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus { Released, Beta, Development, Deprecated, Hidden }

impl PluginStatus {
    /// Whether the plugin is usable.
    pub fn is_usable(&self) -> bool { !matches!(self, Self::Deprecated | Self::Hidden) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_type_display() {
        assert_eq!(ImportType::Elf.display_name(), "ELF");
        assert_eq!(ImportType::Pe.display_name(), "PE");
        assert_eq!(ImportType::JavaClass.display_name(), "Java Class");
        assert_eq!(ImportType::Wasm.display_name(), "WebAssembly");
    }

    #[test]
    fn test_import_type_properties() {
        assert!(ImportType::Auto.is_auto());
        assert!(!ImportType::Elf.is_auto());
        assert_eq!(ImportType::Elf.file_extension(), Some("elf"));
        assert_eq!(ImportType::Auto.file_extension(), None);
    }

    #[test]
    fn test_import_type_display_trait() { assert_eq!(ImportType::Elf.to_string(), "ELF"); }

    #[test]
    fn test_address_display_format() {
        assert_eq!(AddressDisplayFormat::Hex.format(255), "0xFF");
        assert_eq!(AddressDisplayFormat::Decimal.format(255), "255");
        assert_eq!(AddressDisplayFormat::Octal.format(255), "0o377");
        assert_eq!(AddressDisplayFormat::Binary.format(8), "0b1000");
    }

    #[test]
    fn test_address_display_format_padded() {
        assert_eq!(AddressDisplayFormat::Hex.format_padded(0xFF, 4), "0x00FF");
    }

    #[test]
    fn test_address_display_format_default() {
        assert_eq!(AddressDisplayFormat::default(), AddressDisplayFormat::Hex);
    }

    #[test]
    fn test_endianness() {
        assert!(Endianness::Big.is_big_endian());
        assert!(!Endianness::Big.is_little_endian());
    }

    #[test]
    fn test_endianness_read_u16() {
        let data = [0x01, 0x02];
        assert_eq!(Endianness::Big.read_u16(&data), 0x0102);
        assert_eq!(Endianness::Little.read_u16(&data), 0x0201);
    }

    #[test]
    fn test_endianness_read_u32() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(Endianness::Big.read_u32(&data), 0x01020304);
        assert_eq!(Endianness::Little.read_u32(&data), 0x04030201);
    }

    #[test]
    fn test_endianness_display() {
        assert_eq!(Endianness::Big.to_string(), "Big Endian");
    }

    #[test]
    fn test_register_value_format() {
        let fmt = RegisterValueFormat::Hex;
        assert_eq!(fmt.format_value(255, 1), "0xFF");
        let fmt = RegisterValueFormat::SignedDecimal;
        assert_eq!(fmt.format_value(0xFF, 1), "-1");
    }

    #[test]
    fn test_plugin_category() {
        assert_eq!(PluginCategory::Common.display_name(), "Common");
        assert_eq!(PluginCategory::Analysis.to_string(), "Analysis");
    }

    #[test]
    fn test_plugin_status() {
        assert!(PluginStatus::Released.is_usable());
        assert!(!PluginStatus::Deprecated.is_usable());
    }
}
