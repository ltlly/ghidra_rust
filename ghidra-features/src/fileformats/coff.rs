//! COFF Archive format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.coff` package.
//! Parses COFF archive (`.a`) files containing object files.
//!
//! Note: COFF file headers are already parsed in the PE module.
//!
//! References:
//! - Microsoft PE/COFF specification
//! - <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#archive-file-format>

use nom::{bytes::complete::take, IResult};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// COFF Archive magic: `"!<arch>\n"`.
pub const COFF_ARCHIVE_MAGIC: &[u8; 8] = b"!<arch>\n";

/// COFF Archive member header size (60 bytes).
pub const COFF_ARCHIVE_MEMBER_HEADER_SIZE: usize = 60;

/// Special member name for the first linker member.
pub const COFF_LINKER_MEMBER_NAME: &str = "/               ";

/// Special member name for the second linker member (longnames).
pub const COFF_LONGNAMES_MEMBER_NAME: &str = "//              ";

// ═══════════════════════════════════════════════════════════════════════════════════
// Archive Member Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// COFF Archive member header.
#[derive(Debug, Clone)]
pub struct CoffArchiveMember {
    /// Member name (16 bytes, space-padded).
    pub name: String,
    /// Modification timestamp (12 bytes).
    pub date: String,
    /// Owner ID (6 bytes).
    pub user_id: String,
    /// Group ID (6 bytes).
    pub group_id: String,
    /// File mode (8 bytes, octal).
    pub mode: String,
    /// Size of the member data (10 bytes).
    pub size: u64,
    /// End-of-header marker (should be "`\n"`).
    pub end_marker: [u8; 2],
    /// Offset of this member's data in the archive.
    pub data_offset: u64,
    /// The raw member data.
    pub data: Vec<u8>,
}

impl CoffArchiveMember {
    /// Parse an archive member header from ASCII bytes.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, name_bytes) = take(16usize)(data)?;
        let (i, date_bytes) = take(12usize)(i)?;
        let (i, user_id_bytes) = take(6usize)(i)?;
        let (i, group_id_bytes) = take(6usize)(i)?;
        let (i, mode_bytes) = take(8usize)(i)?;
        let (i, size_bytes) = take(10usize)(i)?;
        let (i, end_marker) = take(2usize)(i)?;

        let name = String::from_utf8_lossy(name_bytes).trim().to_string();
        let date = String::from_utf8_lossy(date_bytes).trim().to_string();
        let user_id = String::from_utf8_lossy(user_id_bytes).trim().to_string();
        let group_id = String::from_utf8_lossy(group_id_bytes).trim().to_string();
        let mode = String::from_utf8_lossy(mode_bytes).trim().to_string();
        let size_str = String::from_utf8_lossy(size_bytes).trim().to_string();
        let size = size_str.parse::<u64>().unwrap_or(0);

        Ok((
            i,
            CoffArchiveMember {
                name,
                date,
                user_id,
                group_id,
                mode,
                size,
                end_marker: [end_marker[0], end_marker[1]],
                data_offset: 0,
                data: Vec::new(),
            },
        ))
    }

    /// Whether this is the first linker member (symbol table).
    pub fn is_linker_member(&self) -> bool {
        self.name.starts_with('/')
            && self.name.len() == 1
    }

    /// Whether this is the longnames member.
    pub fn is_longnames_member(&self) -> bool {
        self.name.starts_with("//") && self.name.len() == 2
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// COFF Archive
// ═══════════════════════════════════════════════════════════════════════════════════

/// A parsed COFF archive.
#[derive(Debug, Clone)]
pub struct CoffArchive {
    /// All members found in the archive.
    pub members: Vec<CoffArchiveMember>,
}

impl CoffArchive {
    /// Parse a COFF archive from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 8 || &data[..8] != COFF_ARCHIVE_MAGIC {
            return Err("Not a valid COFF archive (bad magic)".to_string());
        }

        let mut members = Vec::new();
        let mut offset = 8usize; // Skip magic

        while offset + COFF_ARCHIVE_MEMBER_HEADER_SIZE <= data.len() {
            match CoffArchiveMember::parse(&data[offset..]) {
                Ok((_, mut member)) => {
                    let data_start = offset + COFF_ARCHIVE_MEMBER_HEADER_SIZE;
                    let data_end = data_start + member.size as usize;

                    if data_end > data.len() {
                        break;
                    }

                    member.data_offset = data_start as u64;
                    member.data = data[data_start..data_end].to_vec();

                    // Align to 2-byte boundary
                    offset = (data_end + 1) & !1;

                    members.push(member);
                }
                Err(_) => break,
            }
        }

        Ok(CoffArchive { members })
    }
}

/// Check if a byte slice starts with the COFF archive magic.
pub fn is_coff_archive(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..8] == COFF_ARCHIVE_MAGIC
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_coff_archive() {
        assert!(is_coff_archive(b"!<arch>\n"));
        assert!(!is_coff_archive(b"not an a"));
    }

    #[test]
    fn test_magic_constant() {
        assert_eq!(COFF_ARCHIVE_MAGIC, b"!<arch>\n");
    }

    #[test]
    fn test_parse_empty_archive() {
        let data = b"!<arch>\n";
        let archive = CoffArchive::parse(data).unwrap();
        assert!(archive.members.is_empty());
    }

    fn make_member_header(name: &[u8; 16], size: u64) -> Vec<u8> {
        let mut hdr = vec![0u8; COFF_ARCHIVE_MEMBER_HEADER_SIZE];
        hdr[..16].copy_from_slice(name);
        let date_s = format!("{:<12}", 0);
        hdr[16..28].copy_from_slice(date_s.as_bytes());
        let uid_s = format!("{:<6}", 0);
        hdr[28..34].copy_from_slice(uid_s.as_bytes());
        let gid_s = format!("{:<6}", 0);
        hdr[34..40].copy_from_slice(gid_s.as_bytes());
        let mode_s = format!("{:<8}", "0");
        hdr[40..48].copy_from_slice(mode_s.as_bytes());
        let size_s = format!("{:<10}", size);
        hdr[48..58].copy_from_slice(size_s.as_bytes());
        hdr[58] = b'`';
        hdr[59] = b'\n';
        hdr
    }

    #[test]
    fn test_parse_single_member() {
        let mut data = Vec::new();
        data.extend_from_slice(b"!<arch>\n");

        let mut name = [b' '; 16];
        name[..5].copy_from_slice(b"test/");
        let hdr = make_member_header(&name, 4);
        data.extend_from_slice(&hdr);
        data.extend_from_slice(b"test"); // 4 bytes of data

        let archive = CoffArchive::parse(&data).unwrap();
        assert_eq!(archive.members.len(), 1);
        // In COFF archive format, member name ends with '/' which is included
        assert_eq!(archive.members[0].name, "test/");
        assert_eq!(archive.members[0].size, 4);
        assert_eq!(archive.members[0].data, b"test");
    }
}
