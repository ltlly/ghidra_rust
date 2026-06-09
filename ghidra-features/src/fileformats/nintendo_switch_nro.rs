//! Nintendo Switch NRO (Nintendo Relocatable Object) format extensions.
//!
//! This module provides higher-level NRO analysis helpers that complement
//! the core NRO parser in [`crate::fileformats::nintendo::nso`].
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.nso` package.
//!
//! # NRO-specific extensions
//!
//! Beyond the standard NSO/NRO header, NRO files may contain:
//! - **Asset header** ("ASET") with icon and NACP data offsets
//! - **Module name** stored after the asset header
//! - **API info** (SDK add-ons, flags)
//!
//! References:
//! - [Switchbrew: NRO](https://switchbrew.org/wiki/NRO)
//! - Ghidra's `ghidra.app.util.bin.format.nso` package

use crate::fileformats::nintendo::nso::{
    NsoError, NsoResult, NRO_MAGIC, NSO_HEADER_SIZE,
};

// ═══════════════════════════════════════════════════════════════════════════════════
// NRO Asset Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parsed NRO asset header ("ASET").
///
/// NRO files may embed assets (icon, NACP) at the end of the file.
/// The asset header precedes these embedded resources and describes
/// their offsets and sizes.
#[derive(Debug, Clone)]
pub struct NroAssetHeader {
    /// Magic bytes ("ASET").
    pub magic: [u8; 4],
    /// Version of the asset header format.
    pub version: u32,
    /// Offset to the embedded icon data (relative to NRO start).
    pub icon_offset: u32,
    /// Size of the icon data in bytes.
    pub icon_size: u32,
    /// Offset to the embedded NACP data (relative to NRO start).
    pub nacp_offset: u32,
    /// Size of the NACP data in bytes.
    pub nacp_size: u32,
}

impl NroAssetHeader {
    /// Size of the asset header (0x30 bytes).
    pub const SIZE: usize = 0x30;

    /// Parse an asset header from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for NroAssetHeader".to_string());
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);
        if &magic != b"ASET" {
            return Err(format!("Invalid NRO asset header magic: {:?}", magic));
        }

        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let icon_offset = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let icon_size = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let nacp_offset = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let nacp_size = u32::from_le_bytes(data[20..24].try_into().unwrap());

        Ok(NroAssetHeader {
            magic,
            version,
            icon_offset,
            icon_size,
            nacp_offset,
            nacp_size,
        })
    }

    /// Returns true if the icon data is present.
    pub fn has_icon(&self) -> bool {
        self.icon_offset != 0 && self.icon_size != 0
    }

    /// Returns true if the NACP data is present.
    pub fn has_nacp(&self) -> bool {
        self.nacp_offset != 0 && self.nacp_size != 0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// NRO Module Info
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parsed NRO module name descriptor.
///
/// NRO files may embed a module name at the end of the file.  The name
/// is preceded by a small header that gives the relative offset and
/// length of the name string.
#[derive(Debug, Clone)]
pub struct NroModuleName {
    /// The module name (ASCII, NUL-terminated).
    pub name: String,
    /// File offset where the module name header starts.
    pub file_offset: u32,
}

impl NroModuleName {
    /// Size of the module name header (8 bytes).
    pub const HEADER_SIZE: usize = 8;

    /// Parse a module name from an NRO file.
    ///
    /// `nro_size` is the total size of the NRO file (from the NRO header).
    /// `data` is the entire NRO file contents.
    pub fn parse(data: &[u8], nro_size: u32) -> Result<Self, String> {
        // Module name header is at nro_size - 0x20
        let header_offset = nro_size.saturating_sub(0x20) as usize;
        if header_offset + Self::HEADER_SIZE > data.len() {
            return Err("NRO module name header out of bounds".to_string());
        }

        let hdr = &data[header_offset..];
        let name_rel_offset = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let name_size = u32::from_le_bytes(hdr[4..8].try_into().unwrap());

        let name_abs_offset = header_offset + name_rel_offset as usize;
        if name_abs_offset + name_size as usize > data.len() {
            return Err("NRO module name string out of bounds".to_string());
        }

        let name_bytes = &data[name_abs_offset..name_abs_offset + name_size as usize];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\0')
            .to_string();

        Ok(NroModuleName {
            name,
            file_offset: header_offset as u32,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// NRO API Info
// ═══════════════════════════════════════════════════════════════════════════════════

/// NRO SDK add-on information.
///
/// NRO files may contain an "INAPI" section describing the SDK
/// version and add-on features used to build the binary.
#[derive(Debug, Clone)]
pub struct NroApiInfo {
    /// Magic bytes ("INAPI").
    pub magic: [u8; 5],
    /// SDK add-on version.
    pub sdk_addon_version: u32,
    /// Flags describing the API features.
    pub flags: u32,
}

impl NroApiInfo {
    /// Size of the API info header (16 bytes: 5 magic + 3 pad + 4 version + 4 flags).
    pub const SIZE: usize = 16;

    /// Parse API info from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for NroApiInfo".to_string());
        }

        let mut magic = [0u8; 5];
        magic.copy_from_slice(&data[0..5]);
        if &magic != b"INAPI" {
            return Err(format!("Invalid NRO API info magic: {:?}", magic));
        }

        let sdk_addon_version = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let flags = u32::from_le_bytes(data[12..16].try_into().unwrap());

        Ok(NroApiInfo {
            magic,
            sdk_addon_version,
            flags,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// NRO Detection
// ═══════════════════════════════════════════════════════════════════════════════════

/// Quick check: does this byte slice look like an NRO file?
pub fn is_nro(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"NRO0"
}

/// Quick check: does this byte slice look like an NRO asset header?
pub fn is_aset(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"ASET"
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_nro_detection() {
        assert!(is_nro(b"NRO0"));
        assert!(!is_nro(b"NSO0"));
        assert!(!is_nro(&[]));
    }

    #[test]
    fn test_is_aset_detection() {
        assert!(is_aset(b"ASET"));
        assert!(!is_aset(b"XXXX"));
    }

    #[test]
    fn test_asset_header_parse() {
        let mut data = vec![0u8; NroAssetHeader::SIZE];
        data[0..4].copy_from_slice(b"ASET");
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // version
        data[8..12].copy_from_slice(&0x2000u32.to_le_bytes()); // icon_offset
        data[12..16].copy_from_slice(&0x1000u32.to_le_bytes()); // icon_size
        data[16..20].copy_from_slice(&0x4000u32.to_le_bytes()); // nacp_offset
        data[20..24].copy_from_slice(&0x2000u32.to_le_bytes()); // nacp_size

        let header = NroAssetHeader::parse(&data).unwrap();
        assert_eq!(header.magic, *b"ASET");
        assert!(header.has_icon());
        assert!(header.has_nacp());
        assert_eq!(header.icon_size, 0x1000);
    }

    #[test]
    fn test_asset_header_invalid_magic() {
        let mut data = vec![0u8; NroAssetHeader::SIZE];
        data[0..4].copy_from_slice(b"XXXX");
        assert!(NroAssetHeader::parse(&data).is_err());
    }

    #[test]
    fn test_module_name_parse() {
        let nro_size: u32 = 0x2000;
        let mut data = vec![0u8; nro_size as usize];

        // Module name header at nro_size - 0x20 = 0x1FE0
        let hdr_offset = (nro_size - 0x20) as usize;
        // Name string starts at hdr_offset + 8 = 0x1FE8
        let name_rel_off: u32 = 8;
        let name_bytes = b"my_module\0";
        data[hdr_offset..hdr_offset + 4].copy_from_slice(&name_rel_off.to_le_bytes());
        data[hdr_offset + 4..hdr_offset + 8]
            .copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        data[hdr_offset + 8..hdr_offset + 8 + name_bytes.len()].copy_from_slice(name_bytes);

        let module = NroModuleName::parse(&data, nro_size).unwrap();
        assert_eq!(module.name, "my_module");
    }

    #[test]
    fn test_api_info_parse() {
        let mut data = vec![0u8; NroApiInfo::SIZE];
        data[0..5].copy_from_slice(b"INAPI");
        data[8..12].copy_from_slice(&3u32.to_le_bytes()); // sdk_addon_version
        data[12..16].copy_from_slice(&1u32.to_le_bytes()); // flags

        let info = NroApiInfo::parse(&data).unwrap();
        assert_eq!(info.sdk_addon_version, 3);
    }
}
