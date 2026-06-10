//! Android VDEX file header parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.vdex.VdexHeader`
//! and per-version `headers/VdexHeader_*.java`.
//!
//! VDEX (Verified DEX) files contain verified DEX files used by the
//! Android Runtime.  Each Android release version changes the header
//! layout; this module covers versions 006 through 027.
//!
//! References:
//! - <https://android.googlesource.com/platform/art/+/refs/heads/master/runtime/vdex_file.h>

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// VDEX magic: `"vdex"`.
pub const VDEX_MAGIC: &[u8; 4] = b"vdex";

/// Length of the version string (4 bytes, ASCII).
pub const VERSION_LENGTH: usize = 4;

// Supported version strings.
/// Nougat MR1 (Android 7.1).
pub const VDEX_VERSION_006: &str = "006";
/// Oreo (Android 8.0).
pub const VDEX_VERSION_010: &str = "010";
/// Oreo MR1 (Android 8.1).
pub const VDEX_VERSION_012: &str = "012";
/// Pie (Android 9).
pub const VDEX_VERSION_015: &str = "015";
/// Q (Android 10).
pub const VDEX_VERSION_019: &str = "019";
/// R (Android 11).
pub const VDEX_VERSION_021: &str = "021";
/// S (Android 12).
pub const VDEX_VERSION_023: &str = "023";
/// Android 12L / 13.
pub const VDEX_VERSION_027: &str = "027";

/// All supported VDEX version strings.
pub const SUPPORTED_VERSIONS: &[&str] = &[
    VDEX_VERSION_006,
    VDEX_VERSION_010,
    VDEX_VERSION_012,
    VDEX_VERSION_015,
    VDEX_VERSION_019,
    VDEX_VERSION_021,
    VDEX_VERSION_023,
    VDEX_VERSION_027,
];

// ═══════════════════════════════════════════════════════════════════════════════════
// VdexHeaderVersion enum
// ═══════════════════════════════════════════════════════════════════════════════════

/// Discriminated VDEX header, covering all supported versions.
///
/// The Java source uses an abstract `VdexHeader` base class with
/// per-version subclasses.  In Rust we use an enum whose variants
/// carry the version-specific fields.
#[derive(Debug, Clone)]
pub enum VdexHeaderVersion {
    /// Nougat MR1 (version 006).
    V006(VdexHeaderV006),
    /// Oreo (version 010).
    V010(VdexHeaderV010),
    /// Oreo MR1 (version 012).
    V012(VdexHeaderV012),
    /// Pie (version 015).
    V015(VdexHeaderV015),
    /// Q (version 019).
    V019(VdexHeaderV019),
    /// R (version 021).
    V021(VdexHeaderV021),
    /// S (version 023).
    V023(VdexHeaderV023),
    /// Android 12L / 13 (version 027).
    V027(VdexHeaderV027),
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Per-version header structs
// ═══════════════════════════════════════════════════════════════════════════════════

/// Nougat MR1 VDEX header (version 006).
///
/// Layout: magic(4) + version(4) + num_dex_files(4) + verifier_deps_size(4)
///       + quickening_info_size(4) + dex_sections_size(4) = 24 bytes.
#[derive(Debug, Clone)]
pub struct VdexHeaderV006 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub num_dex_files: u32,
    pub verifier_deps_size: u32,
    pub quickening_info_size: u32,
    pub dex_sections_size: u32,
}

/// Oreo VDEX header (version 010).
///
/// Same layout as v006 but with different semantics for some fields.
#[derive(Debug, Clone)]
pub struct VdexHeaderV010 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub num_dex_files: u32,
    pub verifier_deps_size: u32,
    pub quickening_info_size: u32,
    pub dex_sections_size: u32,
}

/// Oreo MR1 VDEX header (version 012).
///
/// Same layout as v010.
#[derive(Debug, Clone)]
pub struct VdexHeaderV012 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub num_dex_files: u32,
    pub verifier_deps_size: u32,
    pub quickening_info_size: u32,
    pub dex_sections_size: u32,
}

/// Pie VDEX header (version 015).
///
/// Same layout as v012.
#[derive(Debug, Clone)]
pub struct VdexHeaderV015 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub num_dex_files: u32,
    pub verifier_deps_size: u32,
    pub quickening_info_size: u32,
    pub dex_sections_size: u32,
}

/// Q VDEX header (version 019).
///
/// Layout is the same as v015 but quickening_info_size is always 0
/// (quickening was removed in Q).
#[derive(Debug, Clone)]
pub struct VdexHeaderV019 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub num_dex_files: u32,
    pub verifier_deps_size: u32,
    pub quickening_info_size: u32,
    pub dex_sections_size: u32,
}

/// R VDEX header (version 021).
///
/// Same layout as v019.
#[derive(Debug, Clone)]
pub struct VdexHeaderV021 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub num_dex_files: u32,
    pub verifier_deps_size: u32,
    pub quickening_info_size: u32,
    pub dex_sections_size: u32,
}

/// S VDEX header (version 023).
///
/// Same layout as v021.
#[derive(Debug, Clone)]
pub struct VdexHeaderV023 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub num_dex_files: u32,
    pub verifier_deps_size: u32,
    pub quickening_info_size: u32,
    pub dex_sections_size: u32,
}

/// Android 12L / 13 VDEX header (version 027).
///
/// Same layout as v023.
#[derive(Debug, Clone)]
pub struct VdexHeaderV027 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub num_dex_files: u32,
    pub verifier_deps_size: u32,
    pub quickening_info_size: u32,
    pub dex_sections_size: u32,
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Simple VdexHeader (kept for backward compatibility)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parsed VDEX header (minimal, backward-compatible form).
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

// ═══════════════════════════════════════════════════════════════════════════════════
// Parsing helpers
// ═══════════════════════════════════════════════════════════════════════════════════

/// Read a little-endian u32 from `data` at `offset`.
fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > data.len() {
        return Err(format!(
            "VDEX header: read_u32 at {} beyond data length {}",
            offset,
            data.len()
        ));
    }
    Ok(u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()))
}

/// Fixed header size for all VDEX versions: magic(4) + version(4) + 4 x u32 = 24 bytes.
const FIXED_HEADER_SIZE: usize = 24;

// ═══════════════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════════════

/// Check if data starts with VDEX magic.
pub fn is_vdex(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == VDEX_MAGIC
}

/// Check if a version string is supported.
pub fn is_supported_version(version: &str) -> bool {
    SUPPORTED_VERSIONS.contains(&version)
}

/// Parse a VDEX header from raw bytes.
///
/// Returns the version-specific header variant.  The parser reads the
/// magic and version, then dispatches to the correct layout.
pub fn parse_vdex_header(data: &[u8]) -> Result<VdexHeaderVersion, String> {
    if data.len() < FIXED_HEADER_SIZE {
        return Err("Data too short for VDEX header (need at least 24 bytes)".to_string());
    }

    let magic: [u8; 4] = data[0..4].try_into().unwrap();
    if magic != *VDEX_MAGIC {
        return Err(format!("Invalid VDEX magic: {:?}", magic));
    }

    let version: [u8; 4] = data[4..8].try_into().unwrap();
    let version_str = std::str::from_utf8(&version)
        .map_err(|_| "VDEX version is not valid UTF-8")?
        .trim_matches('\0');

    let num_dex_files = read_u32(data, 8)?;
    let verifier_deps_size = read_u32(data, 12)?;
    let quickening_info_size = read_u32(data, 16)?;
    let dex_sections_size = read_u32(data, 20)?;

    macro_rules! make_header {
        ($t:ident, $variant:ident) => {
            Ok(VdexHeaderVersion::$variant($t {
                magic,
                version,
                num_dex_files,
                verifier_deps_size,
                quickening_info_size,
                dex_sections_size,
            }))
        };
    }

    match version_str {
        VDEX_VERSION_006 => make_header!(VdexHeaderV006, V006),
        VDEX_VERSION_010 => make_header!(VdexHeaderV010, V010),
        VDEX_VERSION_012 => make_header!(VdexHeaderV012, V012),
        VDEX_VERSION_015 => make_header!(VdexHeaderV015, V015),
        VDEX_VERSION_019 => make_header!(VdexHeaderV019, V019),
        VDEX_VERSION_021 => make_header!(VdexHeaderV021, V021),
        VDEX_VERSION_023 => make_header!(VdexHeaderV023, V023),
        VDEX_VERSION_027 => make_header!(VdexHeaderV027, V027),
        _ => Err(format!("Unsupported VDEX version: {:?}", version_str)),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Accessor helpers on VdexHeaderVersion
// ═══════════════════════════════════════════════════════════════════════════════════

impl VdexHeaderVersion {
    /// Returns the version string (e.g. "027").
    pub fn version_string(&self) -> String {
        let v = match self {
            Self::V006(h) => &h.version,
            Self::V010(h) => &h.version,
            Self::V012(h) => &h.version,
            Self::V015(h) => &h.version,
            Self::V019(h) => &h.version,
            Self::V021(h) => &h.version,
            Self::V023(h) => &h.version,
            Self::V027(h) => &h.version,
        };
        String::from_utf8_lossy(v).trim_matches('\0').to_string()
    }

    /// Returns the number of DEX files in this VDEX.
    pub fn num_dex_files(&self) -> u32 {
        match self {
            Self::V006(h) => h.num_dex_files,
            Self::V010(h) => h.num_dex_files,
            Self::V012(h) => h.num_dex_files,
            Self::V015(h) => h.num_dex_files,
            Self::V019(h) => h.num_dex_files,
            Self::V021(h) => h.num_dex_files,
            Self::V023(h) => h.num_dex_files,
            Self::V027(h) => h.num_dex_files,
        }
    }

    /// Returns the verifier dependencies section size.
    pub fn verifier_deps_size(&self) -> u32 {
        match self {
            Self::V006(h) => h.verifier_deps_size,
            Self::V010(h) => h.verifier_deps_size,
            Self::V012(h) => h.verifier_deps_size,
            Self::V015(h) => h.verifier_deps_size,
            Self::V019(h) => h.verifier_deps_size,
            Self::V021(h) => h.verifier_deps_size,
            Self::V023(h) => h.verifier_deps_size,
            Self::V027(h) => h.verifier_deps_size,
        }
    }

    /// Returns the quickening info section size.
    ///
    /// Note: for Q (version 019) and later, this is always 0 because
    /// quickening was removed.
    pub fn quickening_info_size(&self) -> u32 {
        match self {
            Self::V006(h) => h.quickening_info_size,
            Self::V010(h) => h.quickening_info_size,
            Self::V012(h) => h.quickening_info_size,
            Self::V015(h) => h.quickening_info_size,
            Self::V019(h) => h.quickening_info_size,
            Self::V021(h) => h.quickening_info_size,
            Self::V023(h) => h.quickening_info_size,
            Self::V027(h) => h.quickening_info_size,
        }
    }

    /// Returns the DEX sections size.
    pub fn dex_sections_size(&self) -> u32 {
        match self {
            Self::V006(h) => h.dex_sections_size,
            Self::V010(h) => h.dex_sections_size,
            Self::V012(h) => h.dex_sections_size,
            Self::V015(h) => h.dex_sections_size,
            Self::V019(h) => h.dex_sections_size,
            Self::V021(h) => h.dex_sections_size,
            Self::V023(h) => h.dex_sections_size,
            Self::V027(h) => h.dex_sections_size,
        }
    }

    /// Returns the offset where DEX file data begins (after the fixed header).
    pub fn dex_data_offset(&self) -> u32 {
        FIXED_HEADER_SIZE as u32
    }

    /// Returns true if this version uses quickening (pre-Q).
    pub fn has_quickening(&self) -> bool {
        matches!(self, Self::V006(_) | Self::V010(_) | Self::V012(_) | Self::V015(_))
    }
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
        assert!(!is_vdex(&[0u8; 3]));
    }

    #[test]
    fn test_is_supported_version() {
        assert!(is_supported_version("006"));
        assert!(is_supported_version("027"));
        assert!(!is_supported_version("999"));
    }

    fn build_vdex_data(version: &[u8; 4], num_dex: u32, deps_size: u32, qinfo_size: u32, dex_size: u32) -> Vec<u8> {
        let mut data = vec![0u8; FIXED_HEADER_SIZE];
        data[0..4].copy_from_slice(b"vdex");
        data[4..8].copy_from_slice(version);
        data[8..12].copy_from_slice(&num_dex.to_le_bytes());
        data[12..16].copy_from_slice(&deps_size.to_le_bytes());
        data[16..20].copy_from_slice(&qinfo_size.to_le_bytes());
        data[20..24].copy_from_slice(&dex_size.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_vdex_header_v027() {
        let data = build_vdex_data(b"027\0", 3, 0x100, 0, 0x2000);
        let header = parse_vdex_header(&data).unwrap();
        assert_eq!(header.version_string(), "027");
        assert_eq!(header.num_dex_files(), 3);
        assert_eq!(header.verifier_deps_size(), 0x100);
        assert_eq!(header.quickening_info_size(), 0);
        assert_eq!(header.dex_sections_size(), 0x2000);
        assert!(!header.has_quickening());
    }

    #[test]
    fn test_parse_vdex_header_v006() {
        let data = build_vdex_data(b"006\0", 1, 0x80, 0x40, 0x1000);
        let header = parse_vdex_header(&data).unwrap();
        assert_eq!(header.version_string(), "006");
        assert_eq!(header.num_dex_files(), 1);
        assert_eq!(header.quickening_info_size(), 0x40);
        assert!(header.has_quickening());
    }

    #[test]
    fn test_parse_vdex_header_v019() {
        let data = build_vdex_data(b"019\0", 2, 0x200, 0, 0x4000);
        let header = parse_vdex_header(&data).unwrap();
        assert_eq!(header.version_string(), "019");
        assert_eq!(header.num_dex_files(), 2);
        assert!(!header.has_quickening());
    }

    #[test]
    fn test_parse_vdex_header_invalid_magic() {
        let data = build_vdex_data(b"027\0", 1, 0, 0, 0);
        let mut bad_data = data;
        bad_data[0..4].copy_from_slice(b"bad!");
        assert!(parse_vdex_header(&bad_data).is_err());
    }

    #[test]
    fn test_parse_vdex_header_unsupported_version() {
        let data = build_vdex_data(b"999\0", 1, 0, 0, 0);
        assert!(parse_vdex_header(&data).is_err());
    }

    #[test]
    fn test_parse_vdex_header_too_short() {
        assert!(parse_vdex_header(&[0u8; 4]).is_err());
    }

    #[test]
    fn test_dex_data_offset() {
        let data = build_vdex_data(b"027\0", 1, 0, 0, 0);
        let header = parse_vdex_header(&data).unwrap();
        assert_eq!(header.dex_data_offset(), FIXED_HEADER_SIZE as u32);
    }

    // ── Backward-compatible VdexHeader tests ──────────────────────────────

    #[test]
    fn test_vdex_header_parse() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(b"vdex");
        data[4..8].copy_from_slice(b"027\0");

        let hdr = VdexHeader::parse(&data).unwrap();
        assert!(hdr.is_valid());
        assert_eq!(hdr.version_string(), "027");
    }

    #[test]
    fn test_vdex_header_invalid() {
        assert!(VdexHeader::parse(b"bad!xxxx").is_err());
    }
}
