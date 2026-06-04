//! CPIO archive format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.cpio` package.
//! Supports both old-style (bin/odc) and new ASCII (newc) CPIO formats.
//!
//! References:
//! - POSIX.1-2001 cpio interchange format
//! - <https://man7.org/linux/man-pages/man5/cpio.5.html>

use nom::{
    bytes::complete::{tag, take},
    combinator::map_res,
    IResult,
};
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// Magic for "newc" (new ASCII) format: `"070701"`.
pub const CPIO_NEWC_MAGIC: &[u8] = b"070701";

/// Magic for "newc" CRC format: `"070702"`.
pub const CPIO_CRC_MAGIC: &[u8] = b"070702";

/// Magic for old binary (odc) format: `"\xC7\x71"`.
pub const CPIO_ODC_MAGIC: [u8; 2] = [0xC7, 0x71];

/// The trailer entry name that signals end-of-archive.
pub const CPIO_TRAILER: &str = "TRAILER!!!";

/// CPIO entry type flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpioFormat {
    /// New ASCII (SVR4) format.
    Newc,
    /// New ASCII with CRC.
    Crc,
    /// Old binary (POSIX.1) format.
    Odc,
}

/// A single CPIO entry header.
#[derive(Debug, Clone)]
pub struct CpioEntry {
    /// Device number.
    pub dev: u32,
    /// Inode number.
    pub ino: u32,
    /// File mode (permissions and type).
    pub mode: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Number of links.
    pub nlink: u32,
    /// Modification time.
    pub mtime: u32,
    /// File size in bytes.
    pub file_size: u32,
    /// Major device number (of device file).
    pub dev_major: u32,
    /// Minor device number (of device file).
    pub dev_minor: u32,
    /// Remote device major.
    pub rdev_major: u32,
    /// Remote device minor.
    pub rdev_minor: u32,
    /// File name (path).
    pub name: String,
    /// Name length including NUL.
    pub namesize: u32,
    /// The CPIO format variant.
    pub format: CpioFormat,
    /// Checksum (CRC format only).
    pub checksum: u32,
    /// Absolute offset of this entry's header in the archive.
    pub header_offset: u64,
    /// Absolute offset of this entry's data in the archive.
    pub data_offset: u64,
}

impl CpioEntry {
    /// Whether this entry is a directory.
    pub fn is_directory(&self) -> bool {
        (self.mode & 0o170000) == 0o040000
    }

    /// Whether this entry is a regular file.
    pub fn is_regular(&self) -> bool {
        (self.mode & 0o170000) == 0o100000
    }

    /// Whether this entry is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        (self.mode & 0o170000) == 0o120000
    }

    /// Whether this is the trailer entry.
    pub fn is_trailer(&self) -> bool {
        self.name == CPIO_TRAILER
    }

    /// The Unix permission bits.
    pub fn permissions(&self) -> u32 {
        self.mode & 0o7777
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Parsing
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parse a hexadecimal ASCII string of `len` bytes to u32.
fn parse_hex_u32(input: &[u8], len: usize) -> IResult<&[u8], u32> {
    let (i, raw) = take(len)(input)?;
    let s = std::str::from_utf8(raw)
        .map_err(|_| nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Char)))?;
    let val = u32::from_str_radix(s.trim(), 16)
        .map_err(|_| nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Digit)))?;
    Ok((i, val))
}

/// Align the offset to 4 bytes for newc format.
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Parse a newc/crc format entry header.
fn parse_newc_entry(input: &[u8], offset: u64) -> IResult<&[u8], CpioEntry> {
    let start = input;
    let (i, magic) = take(6usize)(input)?;

    let format = if magic == CPIO_NEWC_MAGIC {
        CpioFormat::Newc
    } else {
        CpioFormat::Crc
    };

    let (i, ino) = parse_hex_u32(i, 8)?;
    let (i, mode) = parse_hex_u32(i, 8)?;
    let (i, uid) = parse_hex_u32(i, 8)?;
    let (i, gid) = parse_hex_u32(i, 8)?;
    let (i, nlink) = parse_hex_u32(i, 8)?;
    let (i, mtime) = parse_hex_u32(i, 8)?;
    let (i, file_size) = parse_hex_u32(i, 8)?;
    let (i, dev_major) = parse_hex_u32(i, 8)?;
    let (i, dev_minor) = parse_hex_u32(i, 8)?;
    let (i, rdev_major) = parse_hex_u32(i, 8)?;
    let (i, rdev_minor) = parse_hex_u32(i, 8)?;
    let (i, namesize) = parse_hex_u32(i, 8)?;
    let (i, checksum) = parse_hex_u32(i, 8)?;

    // Read name (namesize bytes including NUL)
    let (i, name_raw) = take(namesize as usize)(i)?;
    let name = if namesize > 0 {
        let end = name_raw.iter().position(|&b| b == 0).unwrap_or(namesize as usize);
        String::from_utf8_lossy(&name_raw[..end]).to_string()
    } else {
        String::new()
    };

    // Calculate header size (from start to after name) and align to 4 bytes
    // Note: i is already positioned after name (take(namesize) above consumed it)
    let consumed = input.len() - i.len();
    let header_size = align4(consumed);
    let skip = header_size - consumed;
    let (i, _) = take(skip)(i)?;

    // Data follows, aligned to 4 bytes
    let data_offset_abs = offset + header_size as u64;

    Ok((
        i,
        CpioEntry {
            dev: 0,
            ino,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            file_size,
            dev_major,
            dev_minor,
            rdev_major,
            rdev_minor,
            name,
            namesize,
            format,
            checksum,
            header_offset: offset,
            data_offset: data_offset_abs,
        },
    ))
}

// ═══════════════════════════════════════════════════════════════════════════════════
// CPIO Archive
// ═══════════════════════════════════════════════════════════════════════════════════

/// A parsed CPIO archive.
#[derive(Debug, Clone)]
pub struct CpioArchive {
    /// All entries found in the archive (excluding trailer).
    pub entries: Vec<CpioEntry>,
    /// The detected CPIO format.
    pub format: CpioFormat,
}

impl CpioArchive {
    /// Detect the CPIO format and parse the archive.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 6 {
            return Err("Data too short for CPIO".to_string());
        }

        // Check for newc/crc
        if &data[..6] == CPIO_NEWC_MAGIC || &data[..6] == CPIO_CRC_MAGIC {
            return Self::parse_newc(data);
        }

        // Check for odc
        if data.len() >= 2 && data[0] == CPIO_ODC_MAGIC[0] && data[1] == CPIO_ODC_MAGIC[1] {
            return Err("ODC format not yet supported".to_string());
        }

        Err("Unknown CPIO format".to_string())
    }

    fn parse_newc(data: &[u8]) -> Result<Self, String> {
        let mut entries = Vec::new();
        let mut remaining = data;
        let mut offset: u64 = 0;

        loop {
            if remaining.len() < 114 {
                // Minimum newc header size
                break;
            }

            match parse_newc_entry(remaining, offset) {
                Ok((i, entry)) => {
                    // Check for trailer BEFORE adding to entries
                    if entry.is_trailer() {
                        break;
                    }

                    // Advance past data
                    let data_padded = align4(entry.file_size as usize);
                    let consumed = remaining.len() - i.len();
                    let advance = consumed + data_padded;
                    if advance > remaining.len() {
                        break;
                    }
                    offset += advance as u64;
                    remaining = &remaining[advance..];
                    entries.push(entry);
                }
                Err(_) => break,
            }
        }

        let format = if data.len() >= 6 && &data[..6] == CPIO_CRC_MAGIC {
            CpioFormat::Crc
        } else {
            CpioFormat::Newc
        };

        Ok(CpioArchive { entries, format })
    }

    /// Returns only regular file entries.
    pub fn files(&self) -> Vec<&CpioEntry> {
        self.entries.iter().filter(|e| e.is_regular()).collect()
    }

    /// Returns only directory entries.
    pub fn directories(&self) -> Vec<&CpioEntry> {
        self.entries.iter().filter(|e| e.is_directory()).collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_u32() {
        let data = b"000001ed";
        let (_, val) = parse_hex_u32(data, 8).unwrap();
        assert_eq!(val, 0x1ed); // 493
    }

    #[test]
    fn test_align4() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(3), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
    }

    fn make_newc_entry(name: &str, file_size: u32, mode: u32) -> Vec<u8> {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(b"070701"); // magic
        hdr.extend_from_slice(format!("{:08x}", 12345u32).as_bytes()); // ino
        hdr.extend_from_slice(format!("{:08x}", mode).as_bytes()); // mode
        hdr.extend_from_slice(format!("{:08x}", 1000u32).as_bytes()); // uid
        hdr.extend_from_slice(format!("{:08x}", 1000u32).as_bytes()); // gid
        hdr.extend_from_slice(format!("{:08x}", 1u32).as_bytes()); // nlink
        hdr.extend_from_slice(format!("{:08x}", 0x5F5E100u32).as_bytes()); // mtime
        hdr.extend_from_slice(format!("{:08x}", file_size).as_bytes()); // filesize
        hdr.extend_from_slice(format!("{:08x}", 0u32).as_bytes()); // devmajor
        hdr.extend_from_slice(format!("{:08x}", 0u32).as_bytes()); // devminor
        hdr.extend_from_slice(format!("{:08x}", 0u32).as_bytes()); // rdevmajor
        hdr.extend_from_slice(format!("{:08x}", 0u32).as_bytes()); // rdevminor
        let name_with_nul = format!("{}\0", name);
        hdr.extend_from_slice(format!("{:08x}", name_with_nul.len()).as_bytes()); // namesize
        hdr.extend_from_slice(b"00000000"); // checksum
        hdr.extend_from_slice(name_with_nul.as_bytes());
        // Pad to 4-byte alignment
        while hdr.len() % 4 != 0 {
            hdr.push(0);
        }
        hdr
    }

    #[test]
    fn test_parse_newc_single_entry() {
        let mut data = Vec::new();
        let hdr = make_newc_entry("test.txt", 0, 0o100644);
        data.extend_from_slice(&hdr);
        // Trailer
        let trailer = make_newc_entry("TRAILER!!!", 0, 0);
        data.extend_from_slice(&trailer);

        let archive = CpioArchive::parse(&data).unwrap();
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, "test.txt");
        assert!(archive.entries[0].is_regular());
        assert_eq!(archive.entries[0].mode, 0o100644u32);
        assert_eq!(archive.format, CpioFormat::Newc);
    }

    #[test]
    fn test_parse_newc_directory() {
        let mut data = Vec::new();
        let hdr = make_newc_entry("mydir/", 0, 0o040755);
        data.extend_from_slice(&hdr);
        let trailer = make_newc_entry("TRAILER!!!", 0, 0);
        data.extend_from_slice(&trailer);

        let archive = CpioArchive::parse(&data).unwrap();
        assert_eq!(archive.entries.len(), 1);
        assert!(archive.entries[0].is_directory());
    }

    #[test]
    fn test_entry_permissions() {
        let entry = CpioEntry {
            dev: 0,
            ino: 1,
            mode: 0o100755,
            uid: 0,
            gid: 0,
            nlink: 1,
            mtime: 0,
            file_size: 0,
            dev_major: 0,
            dev_minor: 0,
            rdev_major: 0,
            rdev_minor: 0,
            name: "test".to_string(),
            namesize: 5,
            format: CpioFormat::Newc,
            checksum: 0,
            header_offset: 0,
            data_offset: 0,
        };
        assert!(entry.is_regular());
        assert!(!entry.is_directory());
        assert_eq!(entry.permissions(), 0o755);
    }

    #[test]
    fn test_detect_format_invalid() {
        assert!(CpioArchive::parse(b"nope").is_err());
    }
}
