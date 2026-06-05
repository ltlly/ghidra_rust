//! DWARF Exception Handling Data Types
//!
//! Ported from `ghidra.app.plugin.exceptionhandlers.gcc.datatype`.
//!
//! Provides Ghidra data type representations for DWARF encoding modes
//! and PC-relative addresses used in exception handling tables.

/// DWARF Encoding Mode data type.
///
/// Represents a DWARF exception handling encoding byte in the listing.
/// The encoding byte contains both the data format (low nibble) and
/// the application mode (high nibble).
#[derive(Debug, Clone)]
pub struct DwarfEncodingModeDataType {
    /// The raw encoding byte value.
    pub encoding: u8,
}

impl DwarfEncodingModeDataType {
    /// Create a new encoding mode data type.
    pub fn new(encoding: u8) -> Self {
        Self { encoding }
    }

    /// Get the display name for this encoding.
    pub fn display_name(&self) -> String {
        let format = super::DwarfEhDataDecodeFormat::from_code(self.encoding & 0x0f);
        let mode = super::DwarfEhDataApplicationMode::from_code(self.encoding & 0xf0);

        let format_str = match format {
            Some(super::DwarfEhDataDecodeFormat::Absptr) => "absptr",
            Some(super::DwarfEhDataDecodeFormat::Uleb128) => "uleb128",
            Some(super::DwarfEhDataDecodeFormat::Udata2) => "udata2",
            Some(super::DwarfEhDataDecodeFormat::Udata4) => "udata4",
            Some(super::DwarfEhDataDecodeFormat::Udata8) => "udata8",
            Some(super::DwarfEhDataDecodeFormat::Signed) => "signed",
            Some(super::DwarfEhDataDecodeFormat::Sleb128) => "sleb128",
            Some(super::DwarfEhDataDecodeFormat::Sdata2) => "sdata2",
            Some(super::DwarfEhDataDecodeFormat::Sdata4) => "sdata4",
            Some(super::DwarfEhDataDecodeFormat::Sdata8) => "sdata8",
            Some(super::DwarfEhDataDecodeFormat::Omit) => "omit",
            None => "unknown",
        };

        let mode_str = match mode {
            Some(super::DwarfEhDataApplicationMode::Absptr) => "absptr",
            Some(super::DwarfEhDataApplicationMode::Pcrel) => "pcrel",
            Some(super::DwarfEhDataApplicationMode::Textrel) => "textrel",
            Some(super::DwarfEhDataApplicationMode::Datarel) => "datarel",
            Some(super::DwarfEhDataApplicationMode::Funcrel) => "funcrel",
            Some(super::DwarfEhDataApplicationMode::Aligned) => "aligned",
            Some(super::DwarfEhDataApplicationMode::Indirect) => "indirect",
            Some(super::DwarfEhDataApplicationMode::Omit) => "omit",
            None => "unknown",
        };

        format!("DW_EH_PE_{} | DW_EH_PE_{}", format_str, mode_str)
    }

    /// Get the byte size of this encoding mode (1 byte).
    pub fn length(&self) -> usize {
        1
    }
}

/// PC-relative 31-bit address data type.
///
/// Used in some ARM exception handling tables where the address is stored
/// as a signed 31-bit offset relative to the encoding location.
#[derive(Debug, Clone)]
pub struct PcRelative31AddressDataType {
    /// The raw signed offset value.
    pub offset: i32,
}

impl PcRelative31AddressDataType {
    /// Create a new PC-relative address.
    pub fn new(offset: i32) -> Self {
        Self { offset }
    }

    /// Resolve the absolute address given a base address.
    pub fn resolve(&self, base: u64) -> u64 {
        (base as i64 + self.offset as i64) as u64
    }

    /// Get the byte size of this data type (4 bytes).
    pub fn length(&self) -> usize {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoding_mode_display() {
        // DW_EH_PE_udata4 | DW_EH_PE_pcrel = 0x13
        let dt = DwarfEncodingModeDataType::new(0x13);
        assert_eq!(dt.display_name(), "DW_EH_PE_udata4 | DW_EH_PE_pcrel");
    }

    #[test]
    fn test_encoding_mode_absptr() {
        let dt = DwarfEncodingModeDataType::new(0x00);
        assert_eq!(dt.display_name(), "DW_EH_PE_absptr | DW_EH_PE_absptr");
    }

    #[test]
    fn test_encoding_mode_sdata4_datarel() {
        // DW_EH_PE_sdata4 | DW_EH_PE_datarel = 0x3b
        let dt = DwarfEncodingModeDataType::new(0x3b);
        assert_eq!(dt.display_name(), "DW_EH_PE_sdata4 | DW_EH_PE_datarel");
    }

    #[test]
    fn test_pc_relative_resolve() {
        let pc = PcRelative31AddressDataType::new(0x100);
        assert_eq!(pc.resolve(0x1000), 0x1100);

        let neg = PcRelative31AddressDataType::new(-0x100);
        assert_eq!(neg.resolve(0x1000), 0x0f00);
    }

    #[test]
    fn test_encoding_mode_length() {
        let dt = DwarfEncodingModeDataType::new(0x00);
        assert_eq!(dt.length(), 1);
    }

    #[test]
    fn test_pc_relative_length() {
        let dt = PcRelative31AddressDataType::new(0);
        assert_eq!(dt.length(), 4);
    }
}
