//! Game Boy Advance ROM cartridge format.
//!
//! GBA ROMs follow a fixed cartridge header layout in the first 192 bytes
//! (0xC0).  The header includes the Nintendo logo (required for boot ROM
//! validation), game title, game code, and a complementary checksum that
//! the GBA BIOS verifies at boot.
//!
//! # GBA cartridge header layout
//!
//! | Offset | Size | Field            |
//! |--------|------|------------------|
//! | 0x00   | 4    | ARM branch instruction (entry point; 0xEA0000xx) |
//! | 0x04   | 156  | Nintendo logo (decompressed from BIOS)   |
//! | 0xA0   | 12   | Game title (ASCII, space-padded)         |
//! | 0xAC   | 4    | Game code (upper-case ASCII)             |
//! | 0xB0   | 2    | Maker code (ASCII)                       |
//! | 0xB2   | 1    | Fixed value (must be 0x96)               |
//! | 0xB3   | 1    | Main unit code                           |
//! | 0xB4   | 1    | Device type                              |
//! | 0xB5   | 7    | Reserved area                            |
//! | 0xBC   | 1    | Software version                         |
//! | 0xBD   | 1    | Complement check (header checksum)       |
//! | 0xBE   | 2    | Reserved area 2                          |
//!
//! The GBA BIOS validates the Nintendo logo by decompressing it and comparing
//! against an on-die copy.  If the logo is incorrect the game will not boot.
//!
//! References:
//! - [GBATEK: GBA Cartridge Header](https://problemkaputt.de/gbatek-gba-cartridge-header.htm)
//! - [TONC: The Cartridge Header](https://www.coranac.com/tonc/text/gbaheader.htm)
//! - Ghidra's `ghidra.app.util.bin.format.gba` package

// ===========================================================================
// Imports
// ===========================================================================

use std::fmt;

use nom::{
    bytes::complete::take,
    number::complete::le_u8,
    IResult,
};

// ===========================================================================
// Error Types
// ===========================================================================

/// GBA ROM parse error.
#[derive(Debug, Clone)]
pub enum GbaError {
    /// File is too small to contain a GBA cartridge header (192 bytes min).
    TruncatedData,
    /// The fixed value at offset 0xB2 is not 0x96.
    InvalidFixedValue(u8),
    /// The complement check at 0xBD does not match the computed checksum.
    BadComplementCheck { expected: u8, actual: u8 },
    /// A nom parse error.
    ParseError(String),
}

impl fmt::Display for GbaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedData => {
                write!(f, "truncated GBA ROM data (need at least 192 bytes)")
            }
            Self::InvalidFixedValue(v) => {
                write!(f, "invalid fixed value at 0xB2: 0x{v:02X} (expected 0x96)")
            }
            Self::BadComplementCheck { expected, actual } => {
                write!(
                    f,
                    "complement check failed: computed 0x{expected:02X}, stored 0x{actual:02X}"
                )
            }
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for GbaError {}

impl<T> From<nom::Err<nom::error::Error<T>>> for GbaError {
    fn from(e: nom::Err<nom::error::Error<T>>) -> Self {
        Self::ParseError(format!("{e:?}"))
    }
}

/// Type alias for GBA results.
pub type GbaResult<T> = Result<T, GbaError>;

// ===========================================================================
// Constants
// ===========================================================================

/// Size of the GBA cartridge header in bytes.
pub const GBA_HEADER_SIZE: usize = 0xC0; // 192

/// Size of the Nintendo logo bitmap in bytes.
pub const NINTENDO_LOGO_SIZE: usize = 156;

/// Maximum length of the game title field.
pub const GAME_TITLE_LEN: usize = 12;

/// Size of the game code field.
pub const GAME_CODE_LEN: usize = 4;

/// Size of the maker code field.
pub const MAKER_CODE_LEN: usize = 2;

/// Fixed value that must appear at offset 0xB2.
pub const FIXED_VALUE: u8 = 0x96;

/// Minimum ROM size (32 KiB).
pub const MIN_ROM_SIZE: u32 = 0x8000;

/// Maximum ROM size (32 MiB).
pub const MAX_ROM_SIZE: u32 = 0x200_0000;

// ── Device type constants ──────────────────────────────────────────────

/// No additional device.
const DEVICE_NONE: u8 = 0x00;

/// Known device type names.
pub fn device_type_name(dtype: u8) -> &'static str {
    match dtype {
        0x00 => "None",
        0x01 => "Rumble Pak",
        0x02 => "GYRO sensor",
        0x03 => "SOLAR sensor",
        0x04 => "Real-Time Clock (RTC)",
        0x05 => "Rumble + RTC",
        0x06 => "GYRO + Rumble",
        _ => "UNKNOWN",
    }
}

/// Known unit code names.
pub fn unit_code_name(code: u8) -> &'static str {
    match code {
        0x00 => "GBA",
        0x01 => "GBA (bug-fixed)",
        0x02 => "NDS / NDS Lite",
        0x03 => "Game Boy Player",
        _ => "UNKNOWN",
    }
}

// ── ROM size decoding ──────────────────────────────────────────────────

/// Decode ROM size from the device capacity byte at offset 0xB4.
///
/// Note: the device type byte is not a reliable ROM size indicator for
/// GBA.  Actual size is determined from the cartridge ROM chip pinout.
/// This function returns the minimum size implied by the type nibble.
pub fn decode_rom_size(_device_type: u8) -> u32 {
    // GBA ROM sizes aren't encoded in a simple power-of-2 field.
    // The ROM size is determined by the physical cartridge PCB.
    // We return a conservative minimum.
    MIN_ROM_SIZE
}

/// Decode save type from the device type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GbaSaveType {
    /// No save hardware.
    None,
    /// SRAM (battery-backed RAM).
    Sram,
    /// Flash memory (64 KiB).
    Flash64,
    /// Flash memory (128 KiB).
    Flash128,
    /// EEPROM (512 bytes / 8 KiB).
    Eeprom,
}

impl fmt::Display for GbaSaveType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "NONE"),
            Self::Sram => write!(f, "SRAM"),
            Self::Flash64 => write!(f, "FLASH_64K"),
            Self::Flash128 => write!(f, "FLASH_128K"),
            Self::Eeprom => write!(f, "EEPROM"),
        }
    }
}

// ===========================================================================
// Structured Types
// ===========================================================================

/// A parsed GBA ROM cartridge header.
#[derive(Debug, Clone)]
pub struct GbaRom {
    /// ARM branch instruction at 0x00 (entry point).
    pub entry_branch: [u8; 4],
    /// Nintendo logo bitmap (156 bytes, verified by BIOS).
    pub nintendo_logo: [u8; NINTENDO_LOGO_SIZE],
    /// Game title (up to 12 ASCII characters, space-padded).
    pub title: String,
    /// Game code (4 ASCII characters, e.g. "AGBJ").
    pub game_code: [u8; GAME_CODE_LEN],
    /// Maker code (2 ASCII characters, e.g. "01" for Nintendo).
    pub maker_code: [u8; MAKER_CODE_LEN],
    /// Fixed value (should be 0x96).
    pub fixed_value: u8,
    /// Main unit code (0 = GBA, 2 = NDS).
    pub unit_code: u8,
    /// Device type.
    pub device_type: u8,
    /// Reserved bytes (offset 0xB5..0xBB).
    pub reserved: [u8; 7],
    /// Software version number.
    pub version: u8,
    /// Complement check byte (header checksum).
    pub complement_check: u8,
    /// Reserved area 2 (offset 0xBE..0xBF).
    pub reserved2: [u8; 2],
    /// Total ROM size in bytes (from file size, not header).
    pub rom_size: u32,
}

impl GbaRom {
    /// Return the game title trimmed of trailing spaces.
    pub fn title_trimmed(&self) -> &str {
        self.title.trim_end()
    }

    /// Return the game code as a string.
    pub fn game_code_str(&self) -> String {
        String::from_utf8_lossy(&self.game_code).to_string()
    }

    /// Return the maker code as a string.
    pub fn maker_code_str(&self) -> String {
        String::from_utf8_lossy(&self.maker_code).to_string()
    }

    /// Compute the header checksum and compare against stored value.
    ///
    /// The GBA BIOS computes: `checksum = 0 - SUM(header[0xA0..0xBC]) mod 256`.
    /// We recompute and compare.
    pub fn verify_complement_check(&self, raw_header: &[u8]) -> bool {
        if raw_header.len() < GBA_HEADER_SIZE {
            return false;
        }
        let sum: u16 = raw_header[0xA0..0xBD].iter().map(|&b| b as u16).sum();
        let computed = (0x100_u16.wrapping_sub(sum % 256)) as u8;
        computed == self.complement_check
    }

    /// Returns true if this appears to be a valid GBA ROM (fixed_value == 0x96).
    pub fn is_valid(&self) -> bool {
        self.fixed_value == FIXED_VALUE
    }

    /// Returns the entry-point offset decoded from the ARM branch instruction.
    ///
    /// The entry is a `B <offset>` instruction (opcode 0xEA000000 + offset).
    /// The offset is shifted left by 2 and sign-extended.
    pub fn entry_point_offset(&self) -> i32 {
        let instr = u32::from_le_bytes(self.entry_branch);
        // Extract 24-bit signed offset from ARM B instruction
        let offset = (instr & 0x00FF_FFFF) as i32;
        // Sign-extend from 24 bits
        let offset = (offset << 8) >> 6; // shift left 2 for instruction offset
        offset
    }

    /// Is this a multiboot ROM? (entry branch == 0)
    pub fn is_multiboot(&self) -> bool {
        self.entry_branch == [0u8; 4]
    }
}

// ===========================================================================
// Nom Parsers
// ===========================================================================

/// Parse a GBA ROM cartridge from a byte slice.
///
/// Reads the first 192 bytes as the cartridge header and validates
/// the fixed value and complement check.
pub fn parse_gba(data: &[u8]) -> GbaResult<GbaRom> {
    if data.len() < GBA_HEADER_SIZE {
        return Err(GbaError::TruncatedData);
    }

    let (remaining, mut rom) = parse_gba_header(data)?;
    let _ = remaining;

    // Validate fixed value
    if rom.fixed_value != FIXED_VALUE {
        return Err(GbaError::InvalidFixedValue(rom.fixed_value));
    }

    // Verify complement check
    let header_slice = &data[..GBA_HEADER_SIZE];
    let sum: u16 = header_slice[0xA0..0xBD].iter().map(|&b| b as u16).sum();
    let computed = (0x100_u16.wrapping_sub(sum % 256)) as u8;
    if computed != rom.complement_check {
        return Err(GbaError::BadComplementCheck {
            expected: computed,
            actual: rom.complement_check,
        });
    }

    // Total ROM size is just the file size, clamped to sensible range
    rom.rom_size = data.len() as u32;

    Ok(rom)
}

/// Quick check: is this a GBA ROM?
///
/// Checks that the fixed value at 0xB2 is 0x96 and the entry instruction
/// looks like a valid ARM branch (or is 0 for multiboot).
pub fn is_gba(data: &[u8]) -> bool {
    if data.len() < GBA_HEADER_SIZE {
        return false;
    }
    // Must have the fixed value
    if data[0xB2] != FIXED_VALUE {
        return false;
    }
    // Entry must be a valid ARM branch (0xEAxxxxxx) or all zeros (multiboot)
    let entry = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if entry != 0 && (entry & 0xFF00_0000) != 0xEA00_0000 {
        return false;
    }
    true
}

/// Parse the GBA cartridge header with nom.
fn parse_gba_header(input: &[u8]) -> IResult<&[u8], GbaRom> {
    let (input, entry_branch_bytes) = take(4usize)(input)?;
    let (input, logo_bytes) = take(NINTENDO_LOGO_SIZE)(input)?;
    let (input, title_bytes) = take(GAME_TITLE_LEN)(input)?;
    let (input, game_code_bytes) = take(GAME_CODE_LEN)(input)?;
    let (input, maker_code_bytes) = take(MAKER_CODE_LEN)(input)?;
    let (input, fixed_value) = le_u8(input)?;
    let (input, unit_code) = le_u8(input)?;
    let (input, device_type) = le_u8(input)?;
    let (input, reserved_bytes) = take(7usize)(input)?;
    let (input, version) = le_u8(input)?;
    let (input, complement_check) = le_u8(input)?;
    let (input, reserved2_bytes) = take(2usize)(input)?;

    let mut entry_branch = [0u8; 4];
    entry_branch.copy_from_slice(entry_branch_bytes);

    let mut nintendo_logo = [0u8; NINTENDO_LOGO_SIZE];
    nintendo_logo.copy_from_slice(logo_bytes);

    let title = String::from_utf8_lossy(title_bytes).to_string();

    let mut game_code = [0u8; GAME_CODE_LEN];
    game_code.copy_from_slice(game_code_bytes);

    let mut maker_code = [0u8; MAKER_CODE_LEN];
    maker_code.copy_from_slice(maker_code_bytes);

    let mut reserved = [0u8; 7];
    reserved.copy_from_slice(reserved_bytes);

    let mut reserved2 = [0u8; 2];
    reserved2.copy_from_slice(reserved2_bytes);

    Ok((
        input,
        GbaRom {
            entry_branch,
            nintendo_logo,
            title,
            game_code,
            maker_code,
            fixed_value,
            unit_code,
            device_type,
            reserved,
            version,
            complement_check,
            reserved2,
            rom_size: 0, // filled in by caller
        },
    ))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid GBA ROM header.
    fn build_minimal_gba() -> Vec<u8> {
        let mut buf = vec![0u8; MIN_ROM_SIZE as usize];

        // ARM B 0x080000C0 (common entry for GBA)
        let branch: u32 = 0xEA00_002E; // B <offset> to 0x080000C0
        buf[0..4].copy_from_slice(&branch.to_le_bytes());

        // Nintendo logo (compressed bitmap) — 156 bytes
        // Use the real GBA BIOS logo values for validation
        let logo_data: [u8; 156] = [
            0x24, 0xFF, 0xAE, 0x51, 0x69, 0x9A, 0xA2, 0x21, 0x3D, 0x84, 0x82, 0x0A,
            0x84, 0xE4, 0x09, 0xAD, 0x11, 0x24, 0x8B, 0x98, 0xC0, 0x81, 0x7F, 0x21,
            0xA3, 0x52, 0xBE, 0x19, 0x93, 0x09, 0xCE, 0x20, 0x10, 0x46, 0x4A, 0x4A,
            0xF8, 0x27, 0x31, 0xEC, 0x58, 0xC7, 0xE8, 0x33, 0x82, 0xE3, 0xCE, 0xBF,
            0x85, 0xF4, 0xDF, 0x94, 0xCE, 0x4B, 0x09, 0xC1, 0x94, 0x56, 0x8A, 0xC0,
            0x13, 0x72, 0xA7, 0xFC, 0x9F, 0x84, 0x4D, 0x73, 0xA3, 0xCA, 0x9A, 0x61,
            0x58, 0x97, 0xA3, 0x27, 0xFC, 0x03, 0x98, 0x76, 0x23, 0x1D, 0xC7, 0x61,
            0x03, 0x04, 0xAE, 0x56, 0xBF, 0x38, 0x84, 0x00, 0x40, 0xA7, 0x0E, 0xFD,
            0xFF, 0x52, 0xFE, 0x03, 0x6F, 0x95, 0x30, 0xF1, 0x97, 0xFB, 0xC0, 0x85,
            0x60, 0xD6, 0x80, 0x25, 0xA9, 0x63, 0xBE, 0x03, 0x01, 0x4E, 0x38, 0xE2,
            0xF9, 0xA2, 0x34, 0xFF, 0xBB, 0x3E, 0x03, 0x44, 0x78, 0x00, 0x90, 0xCB,
            0x88, 0x11, 0x3A, 0x94, 0x65, 0xC0, 0x7C, 0x63, 0x87, 0xF0, 0x3C, 0xAF,
            0xD6, 0x25, 0xE4, 0x8B, 0x38, 0x0A, 0xAC, 0x72, 0x21, 0xD4, 0xF8, 0x07,
        ];
        buf[4..160].copy_from_slice(&logo_data);

        // Title "TESTGAME    " (12 chars, space-padded)
        let title = b"TESTGAME    ";
        buf[0xA0..0xAC].copy_from_slice(title);

        // Game code "ATST"
        buf[0xAC..0xB0].copy_from_slice(b"ATST");

        // Maker code "01" (Nintendo)
        buf[0xB0..0xB2].copy_from_slice(b"01");

        // Fixed value
        buf[0xB2] = FIXED_VALUE;

        // Unit code = GBA
        buf[0xB3] = 0x00;

        // Device type = None
        buf[0xB4] = 0x00;

        // Reserved (7 bytes of 0x00)
        // (already zero)

        // Version = 1
        buf[0xBC] = 1;

        // Compute complement check:
        // sum of bytes 0xA0..0xBC (not including 0xBD)
        let sum: u16 = buf[0xA0..0xBD].iter().map(|&b| b as u16).sum();
        let complement = (0x100_u16.wrapping_sub(sum % 256)) as u8;
        buf[0xBD] = complement;

        buf
    }

    #[test]
    fn test_parse_minimal_gba() {
        let data = build_minimal_gba();
        let rom = parse_gba(&data).expect("should parse minimal GBA ROM");
        assert_eq!(rom.title_trimmed(), "TESTGAME");
        assert_eq!(rom.game_code_str(), "ATST");
        assert_eq!(rom.maker_code_str(), "01");
        assert_eq!(rom.fixed_value, FIXED_VALUE);
        assert_eq!(rom.unit_code, 0x00);
        assert_eq!(rom.version, 1);
        assert!(rom.is_valid());
        assert!(!rom.is_multiboot());
        assert_eq!(rom.rom_size, MIN_ROM_SIZE);
    }

    #[test]
    fn test_is_gba_detection() {
        let data = build_minimal_gba();
        assert!(is_gba(&data));
        assert!(!is_gba(&[]));
        assert!(!is_gba(&[0u8; GBA_HEADER_SIZE]));
    }

    #[test]
    fn test_complement_check() {
        let data = build_minimal_gba();
        let rom = parse_gba(&data).unwrap();
        assert!(rom.verify_complement_check(&data));
    }

    #[test]
    fn test_bad_fixed_value_rejected() {
        let mut data = build_minimal_gba();
        data[0xB2] = 0x00; // corrupt fixed value
        assert!(parse_gba(&data).is_err());
    }

    #[test]
    fn test_bad_complement_check_rejected() {
        let mut data = build_minimal_gba();
        data[0xBD] = data[0xBD].wrapping_add(1); // corrupt checksum
        assert!(parse_gba(&data).is_err());
    }

    #[test]
    fn test_truncated_data() {
        let data = vec![0u8; 50];
        assert!(parse_gba(&data).is_err());
    }

    #[test]
    fn test_entry_point_offset() {
        let data = build_minimal_gba();
        let rom = parse_gba(&data).unwrap();
        let offset = rom.entry_point_offset();
        // 0xEA00002E -> offset = (0x2E << 2) = 0xB8, sign-extended positive
        assert_eq!(offset, 0xB8);
    }

    #[test]
    fn test_multiboot_rom() {
        let mut data = build_minimal_gba();
        data[0..4].copy_from_slice(&[0u8; 4]);
        let rom = parse_gba(&data).unwrap();
        assert!(rom.is_multiboot());
    }

    #[test]
    fn test_device_type_names() {
        assert_eq!(device_type_name(0x00), "None");
        assert_eq!(device_type_name(0x01), "Rumble Pak");
        assert_eq!(device_type_name(0x04), "Real-Time Clock (RTC)");
    }

    #[test]
    fn test_unit_code_names() {
        assert_eq!(unit_code_name(0x00), "GBA");
        assert_eq!(unit_code_name(0x02), "NDS / NDS Lite");
    }
}
