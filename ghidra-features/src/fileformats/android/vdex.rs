//! Android VDEX format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.vdex` package.
//!
//! VDEX (Verified DEX) files contain verified DEX files used by Android runtime.

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// VDEX magic: `"vdex"`.
pub const VDEX_MAGIC: &[u8; 4] = b"vdex";

// ═══════════════════════════════════════════════════════════════════════════════════
// VDEX Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parsed VDEX header.
#[derive(Debug, Clone)]
pub struct VdexHeader {
    /// Magic: `"vdex"`.
    pub magic: [u8; 4],
    /// Version string.
    pub version: [u8; 4],
}

impl VdexHeader {
    /// Parse a VDEX header.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 8 {
            return Err("Data too short for VDEX header".to_string());
        }
        let magic: [u8; 4] = data[0..4].try_into().unwrap();
        if magic != *VDEX_MAGIC {
            return Err(format!("Invalid VDEX magic: {:?}", magic));
        }
        let version: [u8; 4] = data[4..8].try_into().unwrap();
        Ok(VdexHeader { magic, version })
    }

    pub fn is_valid(&self) -> bool {
        self.magic == *VDEX_MAGIC
    }

    pub fn version_string(&self) -> String {
        String::from_utf8_lossy(&self.version)
            .trim_matches('\0')
            .to_string()
    }
}

/// Check if data starts with VDEX magic.
pub fn is_vdex(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == VDEX_MAGIC
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_vdex() {
        assert!(is_vdex(b"vdex"));
        assert!(!is_vdex(b"novd"));
    }

    #[test]
    fn test_header_parse() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(b"vdex");
        data[4..8].copy_from_slice(b"027\0");

        let hdr = VdexHeader::parse(&data).unwrap();
        assert!(hdr.is_valid());
        assert_eq!(hdr.version_string(), "027");
    }

    #[test]
    fn test_header_invalid() {
        assert!(VdexHeader::parse(b"bad!xxxx").is_err());
    }
}
