//! Miscellaneous Plugin Utilities.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.misc` Java package.
//!
//! Provides shared utility types used by multiple plugins.

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
        }
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_type_display() {
        assert_eq!(ImportType::Elf.display_name(), "ELF");
        assert_eq!(ImportType::Pe.display_name(), "PE");
    }

    #[test]
    fn test_address_display_format() {
        assert_eq!(AddressDisplayFormat::Hex.format(255), "0xFF");
        assert_eq!(AddressDisplayFormat::Decimal.format(255), "255");
        assert_eq!(AddressDisplayFormat::Octal.format(255), "0o377");
        assert_eq!(AddressDisplayFormat::Binary.format(8), "0b1000");
    }
}
