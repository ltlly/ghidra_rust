//! TAR archive format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.tar` package.
//! Supports POSIX (ustar), GNU, and PAX extended headers.
//!
//! References:
//! - POSIX.1-2001 (ustar) format
//! - GNU tar format
//! - <https://www.gnu.org/software/tar/manual/html_node/Standard.html>

use nom::{
    bytes::complete::{tag, take},
    combinator::{map, map_res, opt},
    number::complete::{le_u8, be_u64},
    sequence::tuple,
    IResult,
};
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// Size of a TAR header block.
pub const TAR_BLOCK_SIZE: usize = 512;

/// USTAR magic: `"ustar\0"`.
pub const USTAR_MAGIC: &[u8] = b"ustar\0";

/// USTAR version: `"00"`.
pub const USTAR_VERSION: &[u8] = b"00";

/// GNU magic: `"ustar "`.
pub const GNU_MAGIC: &[u8] = b"ustar ";

/// GNU version: `" \0"`.
pub const GNU_VERSION: &[u8] = b" \0";

/// TAR entry type flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarTypeFlag {
    /// Regular file (or '\0').
    Regular,
    /// Hard link.
    HardLink,
    /// Symbolic link.
    SymLink,
    /// Character device.
    CharDevice,
    /// Block device.
    BlockDevice,
    /// Directory.
    Directory,
    /// FIFO (named pipe).
    Fifo,
    /// Contiguous file.
    Contiguous,
    /// Global extended header (PAX).
    GlobalExtendedHeader,
    /// Local extended header (PAX).
    LocalExtendedHeader,
    /// Unknown/other type flag.
    Unknown(u8),
}

impl TarTypeFlag {
    pub fn from_byte(b: u8) -> Self {
        match b {
            b'0' | 0 => TarTypeFlag::Regular,
            b'1' => TarTypeFlag::HardLink,
            b'2' => TarTypeFlag::SymLink,
            b'3' => TarTypeFlag::CharDevice,
            b'4' => TarTypeFlag::BlockDevice,
            b'5' => TarTypeFlag::Directory,
            b'6' => TarTypeFlag::Fifo,
            b'7' => TarTypeFlag::Contiguous,
            b'g' => TarTypeFlag::GlobalExtendedHeader,
            b'x' => TarTypeFlag::LocalExtendedHeader,
            other => TarTypeFlag::Unknown(other),
        }
    }
}

impl fmt::Display for TarTypeFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TarTypeFlag::Regular => write!(f, "Regular File"),
            TarTypeFlag::HardLink => write!(f, "Hard Link"),
            TarTypeFlag::SymLink => write!(f, "Symbolic Link"),
            TarTypeFlag::CharDevice => write!(f, "Character Device"),
            TarTypeFlag::BlockDevice => write!(f, "Block Device"),
            TarTypeFlag::Directory => write!(f, "Directory"),
            TarTypeFlag::Fifo => write!(f, "FIFO"),
            TarTypeFlag::Contiguous => write!(f, "Contiguous File"),
            TarTypeFlag::GlobalExtendedHeader => write!(f, "PAX Global Extended Header"),
            TarTypeFlag::LocalExtendedHeader => write!(f, "PAX Local Extended Header"),
            TarTypeFlag::Unknown(b) => write!(f, "Unknown({})", b),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// TAR Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// A single entry in a TAR archive.
#[derive(Debug, Clone)]
pub struct TarEntry {
    /// File name (may include path prefix from ustar).
    pub name: String,
    /// File mode (permissions).
    pub mode: u64,
    /// Owner user ID.
    pub uid: u64,
    /// Owner group ID.
    pub gid: u64,
    /// File size in bytes.
    pub size: u64,
    /// Modification time (seconds since epoch).
    pub mtime: u64,
    /// Checksum.
    pub checksum: u32,
    /// Type flag.
    pub type_flag: TarTypeFlag,
    /// Name of linked file (for hard/symbolic links).
    pub link_name: String,
    /// USTAR owner name.
    pub uname: String,
    /// USTAR group name.
    pub gname: String,
    /// USTAR device major number.
    pub dev_major: u32,
    /// USTAR device minor number.
    pub dev_minor: u32,
    /// Offset of the entry header in the archive.
    pub header_offset: u64,
    /// Offset of the entry data in the archive.
    pub data_offset: u64,
}

impl TarEntry {
    /// Whether this entry is a directory.
    pub fn is_directory(&self) -> bool {
        self.type_flag == TarTypeFlag::Directory
    }

    /// Whether this entry is a regular file.
    pub fn is_file(&self) -> bool {
        self.type_flag == TarTypeFlag::Regular
    }

    /// Whether this entry is a symlink.
    pub fn is_symlink(&self) -> bool {
        self.type_flag == TarTypeFlag::SymLink
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Parser Helpers
// ═══════════════════════════════════════════════════════════════════════════════════

/// Read an octal string field of `len` bytes and parse to u64.
fn parse_octal(input: &[u8], len: usize) -> IResult<&[u8], u64> {
    let (i, raw) = take(len)(input)?;
    let s = std::str::from_utf8(raw)
        .map_err(|_| nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Char)))?;
    let s = s.trim_matches('\0').trim();
    if s.is_empty() {
        return Ok((i, 0));
    }
    // Handle base-256 encoding (binary format for large values)
    if (raw[0] & 0x80) != 0 {
        let mut val: u64 = 0;
        for &b in &raw[1..] {
            val = (val << 8) | (b as u64);
        }
        return Ok((i, val));
    }
    let val = u64::from_str_radix(s, 8)
        .map_err(|_| nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Digit)))?;
    Ok((i, val))
}

/// Read a NUL-terminated string field of `len` bytes.
fn parse_string(input: &[u8], len: usize) -> IResult<&[u8], String> {
    let (i, raw) = take(len)(input)?;
    let end = raw.iter().position(|&b| b == 0).unwrap_or(len);
    let s = String::from_utf8_lossy(&raw[..end]).to_string();
    Ok((i, s))
}

/// Parse a 512-byte TAR header block into a `TarEntry`.
fn parse_header<'a>(input: &'a [u8], offset: u64) -> IResult<&'a [u8], TarEntry> {
    let (i, name_bytes) = take(100usize)(input)?;
    let name_raw = std::str::from_utf8(name_bytes)
        .unwrap_or("")
        .trim_matches('\0');

    let (i, mode) = parse_octal(i, 8)?;
    let (i, uid) = parse_octal(i, 8)?;
    let (i, gid) = parse_octal(i, 8)?;
    let (i, size) = parse_octal(i, 12)?;
    let (i, mtime) = parse_octal(i, 12)?;

    // Checksum: 8 bytes, last byte is NUL or space
    let (i, chk_raw) = take(8usize)(i)?;
    let chk_str = std::str::from_utf8(chk_raw)
        .unwrap_or("")
        .trim_matches('\0')
        .trim();
    let checksum = chk_str.parse::<u32>().unwrap_or(0);

    let (i, type_byte) = le_u8(i)?;
    let type_flag = TarTypeFlag::from_byte(type_byte);

    let (i, link_name) = parse_string(i, 100)?;

    // USTAR extension fields
    let (i, _magic) = take(6usize)(i)?;
    let (i, _version) = take(2usize)(i)?;
    let (i, uname) = parse_string(i, 32)?;
    let (i, gname) = parse_string(i, 32)?;
    let (i, dev_major_raw) = parse_octal(i, 8)?;
    let (i, dev_minor_raw) = parse_octal(i, 8)?;
    let (i, prefix) = parse_string(i, 155)?;
    let (i, _padding) = take(12usize)(i)?;

    // Combine prefix and name for long paths
    let full_name = if !prefix.is_empty() {
        format!("{}/{}", prefix, name_raw)
    } else {
        name_raw.to_string()
    };

    Ok((
        i,
        TarEntry {
            name: full_name,
            mode,
            uid,
            gid,
            size,
            mtime,
            checksum,
            type_flag,
            link_name,
            uname,
            gname,
            dev_major: dev_major_raw as u32,
            dev_minor: dev_minor_raw as u32,
            header_offset: offset,
            data_offset: offset + TAR_BLOCK_SIZE as u64,
        },
    ))
}

// ═══════════════════════════════════════════════════════════════════════════════════
// TAR Archive
// ═══════════════════════════════════════════════════════════════════════════════════

/// A parsed TAR archive containing all entry headers.
#[derive(Debug, Clone)]
pub struct TarArchive {
    /// All entries found in the archive.
    pub entries: Vec<TarEntry>,
}

impl TarArchive {
    /// Parse a complete TAR archive from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let mut entries = Vec::new();
        let mut offset: usize = 0;

        while offset + TAR_BLOCK_SIZE <= data.len() {
            // Check for end-of-archive marker (two consecutive zero blocks)
            let block = &data[offset..offset + TAR_BLOCK_SIZE];
            if block.iter().all(|&b| b == 0) {
                break;
            }

            match parse_header(block, offset as u64) {
                Ok((_, entry)) => {
                    let data_size = entry.size as usize;
                    let padded_size = (data_size + TAR_BLOCK_SIZE - 1) & !(TAR_BLOCK_SIZE - 1);
                    offset += TAR_BLOCK_SIZE + padded_size;
                    entries.push(entry);
                }
                Err(_) => break,
            }
        }

        Ok(TarArchive { entries })
    }

    /// Returns only regular file entries.
    pub fn files(&self) -> Vec<&TarEntry> {
        self.entries.iter().filter(|e| e.is_file()).collect()
    }

    /// Returns only directory entries.
    pub fn directories(&self) -> Vec<&TarEntry> {
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
    fn test_type_flag_from_byte() {
        assert_eq!(TarTypeFlag::from_byte(b'0'), TarTypeFlag::Regular);
        assert_eq!(TarTypeFlag::from_byte(0), TarTypeFlag::Regular);
        assert_eq!(TarTypeFlag::from_byte(b'5'), TarTypeFlag::Directory);
        assert_eq!(TarTypeFlag::from_byte(b'2'), TarTypeFlag::SymLink);
        assert_eq!(TarTypeFlag::from_byte(b'x'), TarTypeFlag::LocalExtendedHeader);
        assert_eq!(TarTypeFlag::from_byte(b'g'), TarTypeFlag::GlobalExtendedHeader);
    }

    #[test]
    fn test_parse_empty_archive() {
        let data = vec![0u8; 1024]; // Two zero blocks = end of archive
        let archive = TarArchive::parse(&data).unwrap();
        assert!(archive.entries.is_empty());
    }

    fn make_tar_header(name: &[u8], size: u64, type_flag: u8) -> Vec<u8> {
        let mut block = vec![0u8; TAR_BLOCK_SIZE];
        // name: 100 bytes
        block[..name.len()].copy_from_slice(name);
        block[name.len()] = 0;
        // mode
        let mode_s = format!("{:07o}\0", 0o644u32);
        block[100..108].copy_from_slice(mode_s.as_bytes());
        // uid
        let uid_s = format!("{:07o}\0", 1000u32);
        block[108..116].copy_from_slice(uid_s.as_bytes());
        // gid
        let gid_s = format!("{:07o}\0", 1000u32);
        block[116..124].copy_from_slice(gid_s.as_bytes());
        // size
        let size_s = format!("{:011o}\0", size);
        block[124..136].copy_from_slice(size_s.as_bytes());
        // mtime
        let mtime_s = format!("{:011o}\0", 1234567890u64);
        block[136..148].copy_from_slice(mtime_s.as_bytes());
        // checksum placeholder
        block[148..156].copy_from_slice(b"        ");
        // type flag
        block[156] = type_flag;
        // magic
        block[257..263].copy_from_slice(b"ustar\0");
        // version
        block[263..265].copy_from_slice(b"00");

        // Compute checksum
        let chk: u32 = block.iter().map(|&b| b as u32).sum();
        let chk_s = format!("{:06o}\0 ", chk);
        block[148..156].copy_from_slice(chk_s.as_bytes());

        block
    }

    #[test]
    fn test_parse_single_file_entry() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_tar_header(b"test.txt", 10, b'0'));
        // Add padded data block
        data.extend_from_slice(&[0x41u8; 512]);
        // End-of-archive marker
        data.extend_from_slice(&[0u8; 1024]);

        let archive = TarArchive::parse(&data).unwrap();
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, "test.txt");
        assert_eq!(archive.entries[0].size, 10);
        assert_eq!(archive.entries[0].type_flag, TarTypeFlag::Regular);
        assert!(archive.entries[0].is_file());
        assert!(!archive.entries[0].is_directory());
    }

    #[test]
    fn test_parse_directory_entry() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_tar_header(b"mydir/", 0, b'5'));
        data.extend_from_slice(&[0u8; 1024]);

        let archive = TarArchive::parse(&data).unwrap();
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, "mydir/");
        assert!(archive.entries[0].is_directory());
        assert_eq!(archive.directories().len(), 1);
    }

    #[test]
    fn test_parse_multiple_entries() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_tar_header(b"file1.txt", 5, b'0'));
        data.extend_from_slice(&[0x41u8; 512]); // padded data
        data.extend_from_slice(&make_tar_header(b"file2.txt", 0, b'0'));
        data.extend_from_slice(&[0u8; 1024]);

        let archive = TarArchive::parse(&data).unwrap();
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(archive.files().len(), 2);
    }
}
