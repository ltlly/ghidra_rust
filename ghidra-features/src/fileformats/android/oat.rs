//! Android OAT format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.oat` package.
//!
//! OAT files are Android's ahead-of-time compiled DEX files.

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// OAT magic: `"oat\n"`.
pub const OAT_MAGIC: &[u8; 4] = b"oat\n";

/// OAT file types.
pub const OAT_EXECUTABLE: &str = "exec";
pub const OAT_RELOCATABLE: &str = "reloc";

// Instruction set types.
pub const OAT_ISA_NONE: u32 = 0;
pub const OAT_ISA_ARM: u32 = 1;
pub const OAT_ISA_ARM_64: u32 = 2;
pub const OAT_ISA_THUMB2: u32 = 3;
pub const OAT_ISA_X86: u32 = 4;
pub const OAT_ISA_X86_64: u32 = 5;
pub const OAT_ISA_MIPS: u32 = 6;
pub const OAT_ISA_MIPS_64: u32 = 7;

// ═══════════════════════════════════════════════════════════════════════════════════
// OAT Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parsed OAT header.
#[derive(Debug, Clone)]
pub struct OatHeader {
    /// Magic: `"oat\n"`.
    pub magic: [u8; 4],
    /// Version string (e.g., `"131\0"`).
    pub version: [u8; 4],
}

impl OatHeader {
    /// Parse an OAT header.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 8 {
            return Err("Data too short for OAT header".to_string());
        }
        let magic: [u8; 4] = data[0..4].try_into().unwrap();
        if magic != *OAT_MAGIC {
            return Err(format!("Invalid OAT magic: {:?}", magic));
        }
        let version: [u8; 4] = data[4..8].try_into().unwrap();

        Ok(OatHeader { magic, version })
    }

    pub fn is_valid(&self) -> bool {
        self.magic == *OAT_MAGIC
    }

    pub fn version_string(&self) -> String {
        String::from_utf8_lossy(&self.version)
            .trim_matches('\0')
            .to_string()
    }
}

/// Check if data starts with OAT magic.
pub fn is_oat(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == OAT_MAGIC
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_oat() {
        assert!(is_oat(b"oat\n"));
        assert!(!is_oat(b"nope"));
    }

    #[test]
    fn test_header_parse() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(b"oat\n");
        data[4..8].copy_from_slice(b"131\0");

        let hdr = OatHeader::parse(&data).unwrap();
        assert!(hdr.is_valid());
        assert_eq!(hdr.version_string(), "131");
    }

    #[test]
    fn test_header_invalid() {
        assert!(OatHeader::parse(b"bad\nxxxx").is_err());
    }

    #[test]
    fn test_isa_types() {
        assert_eq!(OAT_ISA_ARM, 1);
        assert_eq!(OAT_ISA_X86_64, 5);
    }
}
