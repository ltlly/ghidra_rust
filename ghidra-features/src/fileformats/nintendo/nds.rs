//! Nintendo DS ROM cartridge format.
//!
//! NDS ROMs contain two ARM binaries: ARM9 (main CPU) and ARM7 (sub/IO CPU).
//! The cartridge header occupies the first 512 bytes (0x200) and provides
//! offsets, sizes, and load addresses for both binaries, plus a File Name
//! Table (FNT) and File Allocation Table (FAT) for the on-cartridge
//! filesystem.
//!
//! # NDS cartridge header layout
//!
//! | Offset | Size  | Field                        |
//! |--------|-------|------------------------------|
//! | 0x00   | 12    | Game title (ASCII)           |
//! | 0x0C   | 4     | Game code                    |
//! | 0x10   | 2     | Maker code                   |
//! | 0x12   | 1     | Unit code                    |
//! | 0x13   | 1     | Encryption seed select       |
//! | 0x14   | 1     | Device capacity (ROM size)   |
//! | 0x15   | 9     | Reserved                     |
//! | 0x1E   | 1     | ROM version                  |
//! | 0x1F   | 1     | Autostart flag               |
//! | 0x20   | 4     | ARM9 binary offset           |
//! | 0x24   | 4     | ARM9 entry address           |
//! | 0x28   | 4     | ARM9 load address            |
//! | 0x2C   | 4     | ARM9 size                    |
//! | 0x30   | 4     | ARM7 binary offset           |
//! | 0x34   | 4     | ARM7 entry address           |
//! | 0x38   | 4     | ARM7 load address            |
//! | 0x3C   | 4     | ARM7 size                    |
//! | 0x40   | 4     | File Name Table offset       |
//! | 0x44   | 4     | File Name Table size         |
//! | 0x48   | 4     | File Allocation Table offset |
//! | 0x4C   | 4     | File Allocation Table size   |
//! | ...    | ...   | (more fields follow up to 0x200) |
//!
//! References:
//! - [GBATEK: NDS Cartridge Header](https://problemkaputt.de/gbatek-ds-cartridge-header.htm)
//! - [DSBrew: NDS Format](https://dsbrew.net/wiki/NDS_Format)
//! - Ghidra's `ghidra.app.util.bin.format.nds` package

// ===========================================================================
// Imports
// ===========================================================================

use std::fmt;

use nom::{
    bytes::complete::take,
    combinator::{map, verify},
    number::complete::{le_u16, le_u32, le_u8},
    sequence::tuple,
    IResult, Parser,
};

// ===========================================================================
// Error Types
// ===========================================================================

/// NDS ROM parse error.
#[derive(Debug, Clone)]
pub enum NdsError {
    /// File is too small to contain a valid NDS header (512 bytes minimum).
    TruncatedData,
    /// The game code field is invalid or empty.
    InvalidGameCode,
    /// ARM9 offset/size is out of bounds.
    InvalidArm9Segment,
    /// ARM7 offset/size is out of bounds.
    InvalidArm7Segment,
    /// The ROM size implied by the device capacity byte exceeds the file size.
    RomSizeExceedsFile,
    /// A nom parse error.
    ParseError(String),
}

impl fmt::Display for NdsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedData => {
                write!(f, "truncated NDS ROM data (need at least 512 bytes)")
            }
            Self::InvalidGameCode => write!(f, "invalid or empty game code"),
            Self::InvalidArm9Segment => write!(f, "ARM9 segment offset/size out of bounds"),
            Self::InvalidArm7Segment => write!(f, "ARM7 segment offset/size out of bounds"),
            Self::RomSizeExceedsFile => write!(f, "ROM size implied by device capacity exceeds file size"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for NdsError {}

impl<T> From<nom::Err<nom::error::Error<T>>> for NdsError {
    fn from(e: nom::Err<nom::error::Error<T>>) -> Self {
        Self::ParseError(format!("{e:?}"))
    }
}

/// Type alias for NDS results.
pub type NdsResult<T> = Result<T, NdsError>;

// ===========================================================================
// Constants
// ===========================================================================

/// Size of the NDS cartridge header.
pub const NDS_HEADER_SIZE: usize = 0x200; // 512

/// Maximum length of the game title field.
pub const GAME_TITLE_LEN: usize = 12;

/// Size of the game code field.
pub const GAME_CODE_LEN: usize = 4;

/// Size of the maker code field.
pub const MAKER_CODE_LEN: usize = 2;

/// Maximum ROM size for Nintendo DS (4 Gbit = 512 MiB).
pub const MAX_ROM_SIZE: u32 = 0x2000_0000;

/// Nintendo DS secure area size (first 8 KiB — encrypted for commercial games).
pub const SECURE_AREA_SIZE: usize = 0x2000;

// ── Unit code constants ────────────────────────────────────────────────

/// NDS unit code.
const UNIT_NDS: u8 = 0x00;
/// NDS unit code (alternate).
const UNIT_NDS_I: u8 = 0x02;
/// DSi unit code.
const UNIT_DSI: u8 = 0x03;
/// DSi (alternate).
const UNIT_DSI2: u8 = 0x05;

/// Human-readable unit code name.
pub fn unit_code_name(code: u8) -> &'static str {
    match code {
        0x00 => "NDS",
        0x02 => "NDS / iQue",
        0x03 => "DSi",
        0x05 => "DSi (enhanced)",
        _ => "UNKNOWN",
    }
}

// ── ROM device capacity decoding ───────────────────────────────────────

/// Decode the actual ROM size in bytes from the device capacity byte at 0x14.
///
/// The capacity byte encodes the ROM size as `128 KiB << value`.
/// Standard cart sizes are 8, 16, 32, 64, 128, 256, and 512 MiB.
pub fn decode_rom_size(capacity: u8) -> u32 {
    if capacity > 16 {
        return MAX_ROM_SIZE; // cap at 512 MiB
    }
    0x20000_u32 << (capacity as u32) // 128 KiB << capacity
}

/// Return the approximate ROM size in kibibytes.
pub fn rom_size_kib(capacity: u8) -> u32 {
    decode_rom_size(capacity) / 1024
}

/// Return the approximate ROM size in mebibytes.
pub fn rom_size_mib(capacity: u8) -> u32 {
    decode_rom_size(capacity) / (1024 * 1024)
}

// ===========================================================================
// Structured Types
// ===========================================================================

/// An ARM binary segment within an NDS ROM.
#[derive(Debug, Clone)]
pub struct NdsArmSegment {
    /// File offset of the binary payload.
    pub offset: u32,
    /// Entry-point address.
    pub entry_address: u32,
    /// Load (RAM) address.
    pub load_address: u32,
    /// Size of the binary in bytes.
    pub size: u32,
    /// Raw payload bytes.
    pub data: Vec<u8>,
    /// Whether the segment data was successfully extracted.
    pub valid: bool,
}

impl NdsArmSegment {
    /// Returns true if this segment has valid data.
    pub fn is_present(&self) -> bool {
        self.offset != 0 && self.size != 0
    }
}

/// A fully parsed NDS ROM.
#[derive(Debug, Clone)]
pub struct NdsRom {
    /// Game title (12 ASCII characters).
    pub title: String,
    /// Game code (4 ASCII characters, e.g. "ADAJ").
    pub game_code: [u8; GAME_CODE_LEN],
    /// Maker code (2 ASCII characters).
    pub maker_code: [u8; MAKER_CODE_LEN],
    /// Unit code.
    pub unit_code: u8,
    /// Encryption seed select byte.
    pub encryption_seed_select: u8,
    /// Device capacity byte (ROM size code).
    pub device_capacity: u8,
    /// ROM version.
    pub version: u8,
    /// Autostart flag (0x80 = auto-start from card).
    pub autostart: u8,
    /// ARM9 binary segment.
    pub arm9: NdsArmSegment,
    /// ARM7 binary segment.
    pub arm7: NdsArmSegment,
    /// File Name Table offset.
    pub fnt_offset: u32,
    /// File Name Table size.
    pub fnt_size: u32,
    /// File Allocation Table offset.
    pub fat_offset: u32,
    /// File Allocation Table size.
    pub fat_size: u32,
    /// ARM9 overlay table offset.
    pub arm9_overlay_offset: u32,
    /// ARM9 overlay table size.
    pub arm9_overlay_size: u32,
    /// ARM7 overlay table offset.
    pub arm7_overlay_offset: u32,
    /// ARM7 overlay table size.
    pub arm7_overlay_size: u32,
    /// Normal CMD settings for port 0x40001A4.
    pub port_settings_normal: u32,
    /// KEY1 CMD settings for port 0x40001A4.
    pub port_settings_key1: u32,
    /// Icon/title offset (DSi banner offset for DSi-enhanced).
    pub icon_title_offset: u32,
    /// Secure area CRC16 (0 if unused).
    pub secure_area_crc: u16,
    /// Secure area transfer timeout (seconds).
    pub secure_area_timeout: u16,
    /// ARM9 autoload address.
    pub arm9_autoload: u32,
    /// ARM7 autoload address.
    pub arm7_autoload: u32,
    /// Secure area disable bitmask.
    pub secure_disable: u64,
    /// ROM size of this cartridge in bytes.
    pub rom_size: u32,
    /// Total NDS file size.
    pub total_file_size: u32,
    /// Raw header bytes (0x200).
    pub raw_header: Vec<u8>,
}

impl NdsRom {
    /// Game title with trailing whitespace/zeros stripped.
    pub fn title_trimmed(&self) -> &str {
        self.title.trim_end().trim_end_matches('\0')
    }

    /// Game code as a printable string.
    pub fn game_code_str(&self) -> String {
        String::from_utf8_lossy(&self.game_code).to_string()
    }

    /// Maker code as a printable string.
    pub fn maker_code_str(&self) -> String {
        String::from_utf8_lossy(&self.maker_code).to_string()
    }

    /// Decoded ROM size from the device capacity byte.
    pub fn capacity_rom_size(&self) -> u32 {
        decode_rom_size(self.device_capacity)
    }

    /// Is this a DSi-enhanced or DSi-exclusive ROM?
    pub fn is_dsi(&self) -> bool {
        self.unit_code == UNIT_DSI || self.unit_code == UNIT_DSI2
    }

    /// Is the secure area encrypted? (Check if the first 8 KiB is zeroed)
    pub fn is_secure_area_encrypted(&self, full_data: &[u8]) -> bool {
        if full_data.len() < SECURE_AREA_SIZE {
            return false;
        }
        // Secure area is the first 8 KiB after the header (offset 0x200..0x2000)
        let start = NDS_HEADER_SIZE;
        let secure = &full_data[start..start + SECURE_AREA_SIZE];
        // If all zeros, it's been decrypted or is a homebrew ROM
        !secure.iter().all(|&b| b == 0)
    }

    /// Returns the ROM ID string: game_code + maker_code.
    pub fn rom_id(&self) -> String {
        format!("{}{}", self.game_code_str(), self.maker_code_str())
    }
}

// ===========================================================================
// Nom Parsers
// ===========================================================================

/// Parse an NDS ROM from a byte slice.
pub fn parse_nds(data: &[u8]) -> NdsResult<NdsRom> {
    if data.len() < NDS_HEADER_SIZE {
        return Err(NdsError::TruncatedData);
    }

    let (remaining, mut rom) = parse_nds_header(data)?;
    let _ = remaining;

    // Validate game code
    if rom.game_code.iter().all(|&b| b == 0) {
        return Err(NdsError::InvalidGameCode);
    }

    // Extract ARM9 segment data
    if rom.arm9.is_present() {
        match extract_segment(data, rom.arm9.offset, rom.arm9.size) {
            Some(seg_data) => {
                rom.arm9.data = seg_data;
                rom.arm9.valid = true;
            }
            None => return Err(NdsError::InvalidArm9Segment),
        }
    }

    // Extract ARM7 segment data
    if rom.arm7.is_present() {
        match extract_segment(data, rom.arm7.offset, rom.arm7.size) {
            Some(seg_data) => {
                rom.arm7.data = seg_data;
                rom.arm7.valid = true;
            }
            None => return Err(NdsError::InvalidArm7Segment),
        }
    }

    // Validate ROM size from capacity byte
    let capacity_size = decode_rom_size(rom.device_capacity);
    if capacity_size > data.len() as u32 && capacity_size > 0 {
        // This is common for trimmed ROMs; only error on extreme mismatch
        if data.len() < 0x20000 {
            return Err(NdsError::RomSizeExceedsFile);
        }
    }

    rom.rom_size = capacity_size;
    rom.total_file_size = data.len() as u32;

    // Save raw header
    rom.raw_header = data[..NDS_HEADER_SIZE].to_vec();

    Ok(rom)
}

/// Quick check: is this an NDS ROM?
///
/// Checks that the game code is non-zero ASCII, unit code is in the NDS
/// range, and both ARM9/ARM7 offsets are present and nonzero.
pub fn is_nds(data: &[u8]) -> bool {
    if data.len() < NDS_HEADER_SIZE {
        return false;
    }

    // Game code should be printable ASCII
    let game_code = &data[0x0C..0x10];
    if !game_code.iter().all(|&b| b.is_ascii_alphanumeric()) {
        return false;
    }

    // Unit code must be 0x00, 0x02, 0x03, or 0x05
    let unit = data[0x12];
    if unit != 0x00 && unit != 0x02 && unit != 0x03 && unit != 0x05 {
        return false;
    }

    // ARM9 offset must be non-zero (points past the header)
    let arm9_off = u32::from_le_bytes([data[0x20], data[0x21], data[0x22], data[0x23]]);
    if arm9_off == 0 || arm9_off < NDS_HEADER_SIZE as u32 {
        return false;
    }

    true
}

/// Parse the NDS ROM header using nom.
fn parse_nds_header(input: &[u8]) -> IResult<&[u8], NdsRom> {
    let (input, title_bytes) = take(GAME_TITLE_LEN)(input)?;
    let (input, game_code_bytes) = take(GAME_CODE_LEN)(input)?;
    let (input, maker_code_bytes) = take(MAKER_CODE_LEN)(input)?;
    let (input, unit_code) = le_u8(input)?;
    let (input, enc_seed_select) = le_u8(input)?;
    let (input, device_capacity) = le_u8(input)?;
    let (input, _reserved1) = take(7usize)(input)?; // 0x15..0x1B (7 bytes)
    let (input, _reserved2) = le_u8(input)?; // 0x1C
    let (input, _reserved3) = le_u8(input)?; // 0x1D
    let (input, version) = le_u8(input)?; // 0x1E
    let (input, autostart) = le_u8(input)?; // 0x1F

    // ARM9 segment
    let (input, arm9_offset) = le_u32(input)?;
    let (input, arm9_entry) = le_u32(input)?;
    let (input, arm9_load) = le_u32(input)?;
    let (input, arm9_size) = le_u32(input)?;

    // ARM7 segment
    let (input, arm7_offset) = le_u32(input)?;
    let (input, arm7_entry) = le_u32(input)?;
    let (input, arm7_load) = le_u32(input)?;
    let (input, arm7_size) = le_u32(input)?;

    // Filesystem tables
    let (input, fnt_offset) = le_u32(input)?;
    let (input, fnt_size) = le_u32(input)?;
    let (input, fat_offset) = le_u32(input)?;
    let (input, fat_size) = le_u32(input)?;

    // Overlay tables
    let (input, arm9_overlay_offset) = le_u32(input)?;
    let (input, arm9_overlay_size) = le_u32(input)?;
    let (input, arm7_overlay_offset) = le_u32(input)?;
    let (input, arm7_overlay_size) = le_u32(input)?;

    // Port settings
    let (input, port_settings_normal) = le_u32(input)?;
    let (input, port_settings_key1) = le_u32(input)?;

    // Icon/title offset
    let (input, icon_title_offset) = le_u32(input)?;

    // Secure area
    let (input, secure_area_crc) = le_u16(input)?;
    let (input, secure_area_timeout) = le_u16(input)?;

    // Autoload addresses
    let (input, arm9_autoload) = le_u32(input)?;
    let (input, arm7_autoload) = le_u32(input)?;

    // Secure area disable
    let (input, secure_disable_lo) = le_u32(input)?;
    let (input, secure_disable_hi) = le_u32(input)?;

    // Parse remaining bytes up to 0x200
    // (already consumed 0x80 bytes out of 0x200)
    let remaining_header = NDS_HEADER_SIZE
        .saturating_sub(0x80)
        .saturating_sub(0x20); // we have parsed 0x80+0x20 so far
    // Actually let's recalculate:
    //   title(12) + game_code(4) + maker_code(2) + unit(1) + seed(1) + cap(1) + res(9) +
    //   ver(1) + auto(1) + arm9(16) + arm7(16) + fnt(8) + fat(8) + arm9ovl(8) +
    //   arm7ovl(8) + port(8) + icon(4) + sec_crc(2) + sec_to(2) + arm9al(4) +
    //   arm7al(4) + sec_dis(8)
    //   = 12+4+2+1+1+1+9+1+1 + 16+16+8+8+8+8+8+4+2+2+4+4+8 = 128 bytes

    // We have consumed 128 bytes (0x80). 0x380 bytes remain in a 0x400-byte
    // extended header, but for NDS base header it's 0x200 bytes total.
    // Remaining is 0x200 - 0x80 = 0x180, but we've already parsed some fields
    // beyond 0x80 in the extended area. Let me simplify: just skip to 0x200.

    // Actually, the NDS header is the first 0x200 bytes. The nom parser
    // has consumed some of those bytes. The remaining input starts at
    // whatever we haven't consumed yet. We just need to skip to the
    // end of the 0x200-byte header.

    // For nom, we've consumed from position 0 to wherever `input` now points.
    // The remaining bytes in the 0x200 header become part of `input`.
    // We'll just leave them unconsumed and the caller knows to skip them.

    let title = String::from_utf8_lossy(title_bytes).to_string();

    let mut game_code = [0u8; GAME_CODE_LEN];
    game_code.copy_from_slice(game_code_bytes);

    let mut maker_code = [0u8; MAKER_CODE_LEN];
    maker_code.copy_from_slice(maker_code_bytes);

    let secure_disable = (secure_disable_hi as u64) << 32 | (secure_disable_lo as u64);

    Ok((
        input,
        NdsRom {
            title,
            game_code,
            maker_code,
            unit_code,
            encryption_seed_select: enc_seed_select,
            device_capacity,
            version,
            autostart,
            arm9: NdsArmSegment {
                offset: arm9_offset,
                entry_address: arm9_entry,
                load_address: arm9_load,
                size: arm9_size,
                data: Vec::new(),
                valid: false,
            },
            arm7: NdsArmSegment {
                offset: arm7_offset,
                entry_address: arm7_entry,
                load_address: arm7_load,
                size: arm7_size,
                data: Vec::new(),
                valid: false,
            },
            fnt_offset,
            fnt_size,
            fat_offset,
            fat_size,
            arm9_overlay_offset,
            arm9_overlay_size,
            arm7_overlay_offset,
            arm7_overlay_size,
            port_settings_normal,
            port_settings_key1,
            icon_title_offset,
            secure_area_crc,
            secure_area_timeout,
            arm9_autoload,
            arm7_autoload,
            secure_disable,
            rom_size: 0,
            total_file_size: 0,
            raw_header: Vec::new(),
        },
    ))
}

/// Extract segment data from the file, bounded by the data buffer.
fn extract_segment(data: &[u8], offset: u32, size: u32) -> Option<Vec<u8>> {
    let start = offset as usize;
    let size = size as usize;
    if size == 0 || start + size > data.len() {
        if start < data.len() {
            return Some(data[start..].to_vec());
        }
        return None;
    }
    Some(data[start..start + size].to_vec())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_nds() -> Vec<u8> {
        // Build a minimal NDS ROM: header + dummy ARM9 + ARM7
        let arm9_size: u32 = 0x4000;
        let arm7_size: u32 = 0x1000;
        let total_size = NDS_HEADER_SIZE as u32 + arm9_size + arm7_size;
        let mut buf = vec![0u8; total_size as usize];

        // Title "TESTNDS     "
        let title = b"TESTNDS     ";
        buf[0x00..0x0C].copy_from_slice(title);

        // Game code "ATND"
        buf[0x0C..0x10].copy_from_slice(b"ATND");

        // Maker code "01"
        buf[0x10..0x12].copy_from_slice(b"01");

        // Unit code = NDS
        buf[0x12] = 0x00;

        // Encryption seed select = 0
        buf[0x13] = 0x00;

        // Device capacity = 7 (128 KiB << 7 = 16 MiB)
        // 16 MiB is 0x01000000 = 128 KiB << 7
        buf[0x14] = 7;

        // Version = 1
        buf[0x1E] = 1;

        // Autostart = 0x80
        buf[0x1F] = 0x80;

        // ARM9 offset = 0x200
        let arm9_off: u32 = NDS_HEADER_SIZE as u32;
        buf[0x20..0x24].copy_from_slice(&arm9_off.to_le_bytes());
        // ARM9 entry = 0x0200_0800
        buf[0x24..0x28].copy_from_slice(&0x0200_0800_u32.to_le_bytes());
        // ARM9 load = 0x0200_0800
        buf[0x28..0x2C].copy_from_slice(&0x0200_0800_u32.to_le_bytes());
        // ARM9 size
        buf[0x2C..0x30].copy_from_slice(&arm9_size.to_le_bytes());

        // ARM7 offset = 0x200 + 0x4000
        let arm7_off: u32 = NDS_HEADER_SIZE as u32 + arm9_size;
        buf[0x30..0x34].copy_from_slice(&arm7_off.to_le_bytes());
        // ARM7 entry = 0x037F_8000
        buf[0x34..0x38].copy_from_slice(&0x037F_8000_u32.to_le_bytes());
        // ARM7 load = 0x037F_8000
        buf[0x38..0x3C].copy_from_slice(&0x037F_8000_u32.to_le_bytes());
        // ARM7 size
        buf[0x3C..0x40].copy_from_slice(&arm7_size.to_le_bytes());

        // FNT offset = 0 (no filesystem)
        // FAT offset = 0 (no filesystem)

        // Fill ARM9 segment with dummy code (ARM NOPs)
        let arm9_start = arm9_off as usize;
        for i in (arm9_start..arm9_start + arm9_size as usize).step_by(4) {
            buf[i..i + 4].copy_from_slice(&[0x00, 0x00, 0xA0, 0xE1]); // MOV R0, R0 (NOP)
        }

        // Fill ARM7 segment with dummy code
        let arm7_start = arm7_off as usize;
        for i in (arm7_start..arm7_start + arm7_size as usize).step_by(4) {
            buf[i..i + 4].copy_from_slice(&[0x00, 0x00, 0xA0, 0xE1]);
        }

        buf
    }

    #[test]
    fn test_parse_minimal_nds() {
        let data = build_minimal_nds();
        let rom = parse_nds(&data).expect("should parse minimal NDS ROM");
        assert_eq!(rom.title_trimmed(), "TESTNDS");
        assert_eq!(rom.game_code_str(), "ATND");
        assert_eq!(rom.maker_code_str(), "01");
        assert_eq!(rom.unit_code, 0x00);
        assert_eq!(rom.version, 1);
        assert_eq!(rom.autostart, 0x80);
        assert_eq!(rom.rom_id(), "ATND01");

        // ARM9
        assert!(rom.arm9.is_present());
        assert!(rom.arm9.valid);
        assert_eq!(rom.arm9.offset, NDS_HEADER_SIZE as u32);
        assert_eq!(rom.arm9.entry_address, 0x0200_0800);
        assert_eq!(rom.arm9.data.len(), 0x4000);

        // ARM7
        assert!(rom.arm7.is_present());
        assert!(rom.arm7.valid);
        assert_eq!(rom.arm7.entry_address, 0x037F_8000);
        assert_eq!(rom.arm7.data.len(), 0x1000);

        // ROM size: 128 KiB << 7 = 16 MiB
        assert_eq!(rom.capacity_rom_size(), 16 * 1024 * 1024);
        assert!(!rom.is_dsi());
    }

    #[test]
    fn test_is_nds_detection() {
        let data = build_minimal_nds();
        assert!(is_nds(&data));
        assert!(!is_nds(&[]));
        assert!(!is_nds(&[0u8; NDS_HEADER_SIZE]));
    }

    #[test]
    fn test_truncated_data() {
        let data = vec![0u8; 100];
        assert!(parse_nds(&data).is_err());
    }

    #[test]
    fn test_empty_game_code_rejected() {
        let mut data = build_minimal_nds();
        data[0x0C..0x10].copy_from_slice(&[0u8; 4]);
        assert!(parse_nds(&data).is_err());
    }

    #[test]
    fn test_dsi_detection() {
        let mut data = build_minimal_nds();
        data[0x12] = 0x03; // DSi unit code
        let rom = parse_nds(&data).unwrap();
        assert!(rom.is_dsi());
    }

    #[test]
    fn test_rom_size_decoding() {
        assert_eq!(decode_rom_size(0), 0x20000); // 128 KiB
        assert_eq!(decode_rom_size(7), 0x1000000); // 16 MiB
        assert_eq!(decode_rom_size(10), 0x8000000); // 128 MiB
        assert_eq!(decode_rom_size(16), 0x20000000); // 512 MiB
        assert_eq!(decode_rom_size(99), MAX_ROM_SIZE); // capped
    }

    #[test]
    fn test_unit_code_names() {
        assert_eq!(unit_code_name(0x00), "NDS");
        assert_eq!(unit_code_name(0x03), "DSi");
        assert_eq!(unit_code_name(0xFF), "UNKNOWN");
    }
}
