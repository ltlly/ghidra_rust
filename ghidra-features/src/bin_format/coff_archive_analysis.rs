//! COFF Archive binary analysis command ported from Ghidra's
//! `ghidra.app.cmd.formats.CoffArchiveBinaryAnalysisCommand`.
//!
//! Provides [`CoffArchiveAnalysisCommand`] which analyzes a COFF archive (.lib/.ar)
//! and produces [`ProgramMarkup`] entries for:
//! - Archive header ("!<arch>\n" magic)
//! - Archive member headers
//! - First linker member (symbol offsets)
//! - Second linker member (symbol offsets + indices)
//! - Long names member (extended filename table)
//! - COFF member payloads
//!
//! This implementation works on raw binary data and generates markup descriptors
//! rather than directly mutating a Ghidra Program.

use super::analysis_command::{
    BinaryAnalysisCommand, CommentType, FragmentEntry, LabelEntry, MarkupEntry, MessageLog,
    ProgramMarkup, SourceType,
};
use super::binary_reader::BinaryReader;
use super::types::DataTypeDescription;

// ---------------------------------------------------------------------------
// COFF Archive Constants
// ---------------------------------------------------------------------------

/// Archive magic string.
const ARCHIVE_MAGIC: &[u8; 8] = b"!<arch>\n";

/// Archive magic string length.
const ARCHIVE_MAGIC_LEN: usize = 8;

/// Archive member header size (60 bytes).
const ARCHIVE_MEMBER_HEADER_SIZE: u64 = 60;

/// Size of the name field in a member header.
const MEMBER_NAME_SIZE: usize = 16;

/// Size of the date field in a member header.
const MEMBER_DATE_SIZE: usize = 12;

/// Size of the userID field in a member header.
const MEMBER_USERID_SIZE: usize = 6;

/// Size of the groupID field in a member header.
const MEMBER_GROUPID_SIZE: usize = 6;

/// Size of the mode field in a member header.
const MEMBER_MODE_SIZE: usize = 8;

/// Size of the size field in a member header.
const MEMBER_SIZE_SIZE: usize = 10;

/// Special name for the first/second linker member.
const SLASH: &[u8] = b"/";

/// Special name for the long names member.
const SLASH_SLASH: &[u8] = b"//";

// ---------------------------------------------------------------------------
// Parsed structures
// ---------------------------------------------------------------------------

/// Parsed archive member header.
#[derive(Debug, Clone)]
struct ArchiveMemberHeader {
    name: String,
    date: String,
    user_id: String,
    group_id: String,
    mode: String,
    size: u64,
    file_offset: u64,
    payload_offset: u64,
}

/// Parsed first linker member.
#[derive(Debug, Clone)]
struct FirstLinkerMember {
    symbol_count: u32,
    offsets: Vec<u32>,
    string_table_size: u32,
    strings: Vec<String>,
    file_offset: u64,
}

/// Parsed second linker member.
#[derive(Debug, Clone)]
struct SecondLinkerMember {
    member_count: u32,
    offsets: Vec<u32>,
    symbol_count: u32,
    indices: Vec<u16>,
    string_table_size: u32,
    strings: Vec<String>,
    file_offset: u64,
}

/// Parsed long names member.
#[derive(Debug, Clone)]
struct LongNamesMember {
    names: Vec<String>,
    file_offset: u64,
    total_size: u64,
}

/// Parsed archive header and contents.
#[derive(Debug)]
struct ArchiveInfo {
    member_headers: Vec<ArchiveMemberHeader>,
    first_linker: Option<FirstLinkerMember>,
    second_linker: Option<SecondLinkerMember>,
    long_names: Option<LongNamesMember>,
}

// ---------------------------------------------------------------------------
// CoffArchiveAnalysisCommand
// ---------------------------------------------------------------------------

/// COFF Archive binary analysis command.
///
/// Ported from `ghidra.app.cmd.formats.CoffArchiveBinaryAnalysisCommand`. Parses
/// the archive header, member headers, linker members, and long names member,
/// and produces a [`ProgramMarkup`].
pub struct CoffArchiveAnalysisCommand {
    messages: MessageLog,
}

impl CoffArchiveAnalysisCommand {
    /// Create a new COFF Archive analysis command.
    pub fn new() -> Self {
        Self {
            messages: MessageLog::new(),
        }
    }

    /// Parse the archive and its members.
    fn parse_archive(&self, data: &[u8]) -> Result<ArchiveInfo, String> {
        if data.len() < ARCHIVE_MAGIC_LEN {
            return Err("Data too short for archive magic".into());
        }

        // Verify magic
        if &data[..ARCHIVE_MAGIC_LEN] != ARCHIVE_MAGIC {
            return Err("Not a COFF archive: invalid magic".into());
        }

        let mut cursor = ARCHIVE_MAGIC_LEN;
        let mut member_headers = Vec::new();
        let mut first_linker: Option<FirstLinkerMember> = None;
        let mut second_linker: Option<SecondLinkerMember> = None;
        let mut long_names: Option<LongNamesMember> = None;
        let mut member_num: usize = 0;

        while cursor + ARCHIVE_MEMBER_HEADER_SIZE as usize <= data.len() {
            // Check for end-of-header marker
            if data[cursor + 58] != b'`' || data[cursor + 59] != b'\n' {
                // Not a valid member header, try to continue
                break;
            }

            let header = self.parse_member_header(data, cursor)?;
            let name = header.name.clone();
            let payload_offset = header.payload_offset;
            let size = header.size;

            if name == "/" {
                // Linker member
                match member_num {
                    0 => {
                        first_linker = Some(self.parse_first_linker_member(data, payload_offset as usize, size, cursor as u64)?);
                    }
                    1 => {
                        second_linker = Some(self.parse_second_linker_member(data, payload_offset as usize, size, cursor as u64)?);
                    }
                    _ => {
                        return Err("Invalid COFF archive: multiple linker members".into());
                    }
                }
            } else if name == "//" {
                // Long names member
                if long_names.is_some() {
                    return Err("Invalid COFF archive: multiple long names members".into());
                }
                long_names = Some(self.parse_long_names_member(data, payload_offset as usize, size, cursor as u64)?);
            }

            member_headers.push(header);
            cursor = payload_offset as usize + size as usize;
            // Align to even byte boundary (ar archives are 2-byte aligned)
            if cursor % 2 != 0 {
                cursor += 1;
            }
            member_num += 1;
        }

        Ok(ArchiveInfo {
            member_headers,
            first_linker,
            second_linker,
            long_names,
        })
    }

    /// Parse a single archive member header.
    fn parse_member_header(&self, data: &[u8], offset: usize) -> Result<ArchiveMemberHeader, String> {
        if offset + ARCHIVE_MEMBER_HEADER_SIZE as usize > data.len() {
            return Err("Member header extends beyond data".into());
        }

        // Name: 16 bytes, space-padded
        let name_bytes = &data[offset..offset + MEMBER_NAME_SIZE];
        let name_end = name_bytes.iter().position(|&b| b == b' ' || b == b'\n').unwrap_or(MEMBER_NAME_SIZE);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

        // Date: 12 bytes
        let date_bytes = &data[offset + 16..offset + 16 + MEMBER_DATE_SIZE];
        let date_end = date_bytes.iter().position(|&b| b == b' ' || b == b'\n').unwrap_or(MEMBER_DATE_SIZE);
        let date = String::from_utf8_lossy(&date_bytes[..date_end]).to_string();

        // User ID: 6 bytes
        let uid_bytes = &data[offset + 28..offset + 28 + MEMBER_USERID_SIZE];
        let uid_end = uid_bytes.iter().position(|&b| b == b' ' || b == b'\n').unwrap_or(MEMBER_USERID_SIZE);
        let user_id = String::from_utf8_lossy(&uid_bytes[..uid_end]).to_string();

        // Group ID: 6 bytes
        let gid_bytes = &data[offset + 34..offset + 34 + MEMBER_GROUPID_SIZE];
        let gid_end = gid_bytes.iter().position(|&b| b == b' ' || b == b'\n').unwrap_or(MEMBER_GROUPID_SIZE);
        let group_id = String::from_utf8_lossy(&gid_bytes[..gid_end]).to_string();

        // Mode: 8 bytes
        let mode_bytes = &data[offset + 40..offset + 40 + MEMBER_MODE_SIZE];
        let mode_end = mode_bytes.iter().position(|&b| b == b' ' || b == b'\n').unwrap_or(MEMBER_MODE_SIZE);
        let mode = String::from_utf8_lossy(&mode_bytes[..mode_end]).to_string();

        // Size: 10 bytes, decimal ASCII
        let size_bytes = &data[offset + 48..offset + 48 + MEMBER_SIZE_SIZE];
        let size_end = size_bytes.iter().position(|&b| b == b' ' || b == b'\n').unwrap_or(MEMBER_SIZE_SIZE);
        let size_str = String::from_utf8_lossy(&size_bytes[..size_end]).to_string();
        let size: u64 = size_str.parse().unwrap_or(0);

        let file_offset = offset as u64;
        let payload_offset = offset as u64 + ARCHIVE_MEMBER_HEADER_SIZE;

        Ok(ArchiveMemberHeader {
            name,
            date,
            user_id,
            group_id,
            mode,
            size,
            file_offset,
            payload_offset,
        })
    }

    /// Parse the first linker member.
    fn parse_first_linker_member(
        &self,
        data: &[u8],
        offset: usize,
        size: u64,
        header_offset: u64,
    ) -> Result<FirstLinkerMember, String> {
        if offset + 4 > data.len() {
            return Err("First linker member extends beyond data".into());
        }

        let reader = BinaryReader::from_bytes(&data[offset..], true); // little-endian
        let symbol_count = reader.read_u32_at(0).map_err(|e| format!("symbol_count: {}", e))?;

        let mut pos = 4;
        let mut offsets = Vec::new();
        for i in 0..symbol_count {
            if offset + pos + 4 > data.len() {
                return Err(format!("First linker offset {} extends beyond data", i));
            }
            let off = reader.read_u32_at(pos).map_err(|e| format!("offset[{}]: {}", i, e))?;
            offsets.push(off);
            pos += 4;
        }

        // String table follows
        let mut strings = Vec::new();
        let string_start = pos;
        let mut s = String::new();
        let end = std::cmp::min(offset + size as usize, data.len());
        for &byte in &data[offset + pos..end] {
            if byte == 0 {
                if !s.is_empty() {
                    strings.push(s);
                    s = String::new();
                }
            } else {
                s.push(byte as char);
            }
        }
        if !s.is_empty() {
            strings.push(s);
        }

        let string_table_size = (size as u32).saturating_sub(string_start as u32);

        Ok(FirstLinkerMember {
            symbol_count,
            offsets,
            string_table_size,
            strings,
            file_offset: header_offset,
        })
    }

    /// Parse the second linker member.
    fn parse_second_linker_member(
        &self,
        data: &[u8],
        offset: usize,
        size: u64,
        header_offset: u64,
    ) -> Result<SecondLinkerMember, String> {
        if offset + 4 > data.len() {
            return Err("Second linker member extends beyond data".into());
        }

        let reader = BinaryReader::from_bytes(&data[offset..], true); // little-endian
        let member_count = reader.read_u32_at(0).map_err(|e| format!("member_count: {}", e))?;

        let mut pos = 4;
        let mut offsets = Vec::new();
        for i in 0..member_count {
            if offset + pos + 4 > data.len() {
                return Err(format!("Second linker offset {} extends beyond data", i));
            }
            let off = reader.read_u32_at(pos).map_err(|e| format!("offset[{}]: {}", i, e))?;
            offsets.push(off);
            pos += 4;
        }

        // Symbol count
        if offset + pos + 4 > data.len() {
            return Err("Second linker symbol count extends beyond data".into());
        }
        let symbol_count = reader.read_u32_at(pos).map_err(|e| format!("symbol_count: {}", e))?;
        pos += 4;

        // Indices (1-based member indices)
        let mut indices = Vec::new();
        for i in 0..symbol_count {
            if offset + pos + 2 > data.len() {
                return Err(format!("Second linker index {} extends beyond data", i));
            }
            let idx = reader.read_u16_at(pos).map_err(|e| format!("index[{}]: {}", i, e))?;
            indices.push(idx);
            pos += 2;
        }

        // String table follows
        let mut strings = Vec::new();
        let string_start = pos;
        let mut s = String::new();
        let end = std::cmp::min(offset + size as usize, data.len());
        for &byte in &data[offset + pos..end] {
            if byte == 0 {
                if !s.is_empty() {
                    strings.push(s);
                    s = String::new();
                }
            } else {
                s.push(byte as char);
            }
        }
        if !s.is_empty() {
            strings.push(s);
        }

        let string_table_size = (size as u32).saturating_sub(string_start as u32);

        Ok(SecondLinkerMember {
            member_count,
            offsets,
            symbol_count,
            indices,
            string_table_size,
            strings,
            file_offset: header_offset,
        })
    }

    /// Parse the long names member.
    fn parse_long_names_member(
        &self,
        data: &[u8],
        offset: usize,
        size: u64,
        header_offset: u64,
    ) -> Result<LongNamesMember, String> {
        let mut names = Vec::new();
        let end = std::cmp::min(offset + size as usize, data.len());
        let mut s = String::new();

        for &byte in &data[offset..end] {
            if byte == 0 || byte == b'\n' {
                if !s.is_empty() {
                    // Remove trailing '/' if present
                    if s.ends_with('/') {
                        s.pop();
                    }
                    names.push(s);
                    s = String::new();
                }
            } else {
                s.push(byte as char);
            }
        }
        if !s.is_empty() {
            if s.ends_with('/') {
                s.pop();
            }
            names.push(s);
        }

        Ok(LongNamesMember {
            names,
            file_offset: header_offset,
            total_size: size,
        })
    }

    /// Resolve a member name, handling long name references (e.g., "/15").
    fn resolve_name(
        &self,
        name: &str,
        long_names: Option<&LongNamesMember>,
    ) -> String {
        if let Some(stripped) = name.strip_prefix('/') {
            if let Ok(idx) = stripped.parse::<usize>() {
                if let Some(ln) = long_names {
                    if idx < ln.names.len() {
                        return ln.names[idx].clone();
                    }
                }
            }
        }
        // Replace invalid characters with underscore
        name.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' { c } else { '_' })
            .collect()
    }

    /// Process archive header markup.
    fn process_archive_header(&self, markup: &mut ProgramMarkup) {
        markup.add_markup(
            MarkupEntry::new(0, DataTypeDescription::Struct {
                name: "ArchiveHeader".into(),
                size: ARCHIVE_MAGIC_LEN as u32,
            })
            .with_name("ArchiveHeader")
            .with_comment("COFF Archive (!<arch>\\n)", CommentType::Plate),
        );
        markup.add_fragment(FragmentEntry::new("ArchiveHeader", 0, ARCHIVE_MAGIC_LEN as u64));
    }

    /// Process archive member header markup.
    fn process_member_headers(
        &self,
        markup: &mut ProgramMarkup,
        headers: &[ArchiveMemberHeader],
        long_names: Option<&LongNamesMember>,
    ) {
        for header in headers {
            let comment = format!(
                "Name: {}\nDate: {}\nUser ID: {}\nGroup ID: {}\nMode: {}\nSize: {}",
                header.name,
                header.date,
                header.user_id,
                header.group_id,
                header.mode,
                header.size,
            );

            markup.add_markup(
                MarkupEntry::new(header.file_offset, DataTypeDescription::Struct {
                    name: "ArchiveMemberHeader".into(),
                    size: ARCHIVE_MEMBER_HEADER_SIZE as u32,
                })
                .with_comment(comment, CommentType::Plate),
            );
            markup.add_fragment(FragmentEntry::new(
                "ArchiveMemberHeader",
                header.file_offset,
                ARCHIVE_MEMBER_HEADER_SIZE,
            ));

            // Create fragment for member payload if it has data
            if header.size > 0 && header.name != "/" && header.name != "//" {
                let resolved_name = self.resolve_name(&header.name, long_names);
                markup.add_fragment(FragmentEntry::new(
                    &resolved_name,
                    header.payload_offset,
                    header.size,
                ));
                markup.add_label(
                    LabelEntry::new(header.payload_offset, &resolved_name)
                        .with_source(SourceType::Imported),
                );
            }
        }
    }

    /// Process first linker member markup.
    fn process_first_linker(
        &self,
        markup: &mut ProgramMarkup,
        linker: &FirstLinkerMember,
    ) {
        let comment = format!(
            "First Linker Member\nSymbol Count: {}\nString Table Size: {}",
            linker.symbol_count,
            linker.string_table_size,
        );

        let total_size = 4 + (linker.symbol_count as u64) * 4 + linker.string_table_size as u64;

        markup.add_markup(
            MarkupEntry::new(linker.file_offset + ARCHIVE_MEMBER_HEADER_SIZE, DataTypeDescription::Struct {
                name: "FirstLinkerMember".into(),
                size: total_size as u32,
            })
            .with_comment(comment, CommentType::Plate),
        );
        markup.add_fragment(FragmentEntry::new(
            "FirstLinkerMember",
            linker.file_offset + ARCHIVE_MEMBER_HEADER_SIZE,
            total_size,
        ));
    }

    /// Process second linker member markup.
    fn process_second_linker(
        &self,
        markup: &mut ProgramMarkup,
        linker: &SecondLinkerMember,
    ) {
        let comment = format!(
            "Second Linker Member\nMember Count: {}\nSymbol Count: {}\nString Table Size: {}",
            linker.member_count,
            linker.symbol_count,
            linker.string_table_size,
        );

        let total_size = 4
            + (linker.member_count as u64) * 4
            + 4
            + (linker.symbol_count as u64) * 2
            + linker.string_table_size as u64;

        markup.add_markup(
            MarkupEntry::new(linker.file_offset + ARCHIVE_MEMBER_HEADER_SIZE, DataTypeDescription::Struct {
                name: "SecondLinkerMember".into(),
                size: total_size as u32,
            })
            .with_comment(comment, CommentType::Plate),
        );
        markup.add_fragment(FragmentEntry::new(
            "SecondLinkerMember",
            linker.file_offset + ARCHIVE_MEMBER_HEADER_SIZE,
            total_size,
        ));
    }

    /// Process long names member markup.
    fn process_long_names(
        &self,
        markup: &mut ProgramMarkup,
        long_names: &LongNamesMember,
    ) {
        let comment = format!(
            "Long Names Member\nNames: {}",
            long_names.names.len(),
        );

        markup.add_markup(
            MarkupEntry::new(long_names.file_offset + ARCHIVE_MEMBER_HEADER_SIZE, DataTypeDescription::Struct {
                name: "LongNamesMember".into(),
                size: long_names.total_size as u32,
            })
            .with_comment(comment, CommentType::Plate),
        );
        markup.add_fragment(FragmentEntry::new(
            "LongNamesMember",
            long_names.file_offset + ARCHIVE_MEMBER_HEADER_SIZE,
            long_names.total_size,
        ));
    }
}

impl Default for CoffArchiveAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryAnalysisCommand for CoffArchiveAnalysisCommand {
    fn name(&self) -> &str {
        "COFF Archive Header Annotation"
    }

    fn can_apply(&self, data: &[u8]) -> bool {
        if data.len() < ARCHIVE_MAGIC_LEN {
            return false;
        }
        &data[..ARCHIVE_MAGIC_LEN] == ARCHIVE_MAGIC
    }

    fn apply(&self, data: &[u8], _is_little_endian: bool) -> Result<ProgramMarkup, String> {
        let mut markup = ProgramMarkup::new();

        // 1. Process archive magic header
        self.process_archive_header(&mut markup);

        // 2. Parse the archive
        let archive = self.parse_archive(data)?;

        // 3. Process member headers
        self.process_member_headers(&mut markup, &archive.member_headers, archive.long_names.as_ref());

        // 4. Process first linker member
        if let Some(ref linker) = archive.first_linker {
            self.process_first_linker(&mut markup, linker);
        }

        // 5. Process second linker member
        if let Some(ref linker) = archive.second_linker {
            self.process_second_linker(&mut markup, linker);
        }

        // 6. Process long names member
        if let Some(ref long_names) = archive.long_names {
            self.process_long_names(&mut markup, long_names);
        }

        let is_ms = archive.first_linker.is_some()
            && archive.second_linker.is_some()
            && archive.long_names.is_some();

        self.messages.append_msg(format!(
            "COFF Archive analysis complete: {} members, MS format={}",
            archive.member_headers.len(),
            is_ms,
        ));

        Ok(markup)
    }

    fn messages(&self) -> &MessageLog {
        &self.messages
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal COFF archive with just the magic and one empty member.
    fn make_minimal_archive() -> Vec<u8> {
        let mut data = Vec::new();

        // Magic
        data.extend_from_slice(b"!<arch>\n");

        // A dummy member: name="dummy.o", size=0
        let member = b"dummy.o/        0           0     0     0       0         `\n";
        data.extend_from_slice(member);

        data
    }

    /// Build a COFF archive with first linker member and long names.
    fn make_archive_with_linkers() -> Vec<u8> {
        let mut data = Vec::new();

        // Magic
        data.extend_from_slice(b"!<arch>\n");

        // First linker member "/" with 1 symbol, 4 bytes offset table + string
        // "/               0           0     0     0       12        `\n"
        data.extend_from_slice(b"/               0           0     0     0       12        `\n");
        // symbol count = 1 (LE u32)
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        // offset to member = 0 (LE u32)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // string: "_main\0"
        data.extend_from_slice(b"_main\0");

        // Pad to even boundary
        if data.len() % 2 != 0 {
            data.push(b'\n');
        }

        // Long names member "//" with 1 name
        data.extend_from_slice(b"//              0           0     0     0       9         `\n");
        // Long name: "long.o/\n"  (8 bytes + null)
        data.extend_from_slice(b"long.o/\n\0");

        // Pad to even boundary
        if data.len() % 2 != 0 {
            data.push(b'\n');
        }

        // A real member using long name reference "/0"
        data.extend_from_slice(b"/0              0           0     0     0       4         `\n");
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // 4 bytes payload

        data
    }

    #[test]
    fn test_coff_archive_can_apply() {
        let cmd = CoffArchiveAnalysisCommand::new();
        let data = make_minimal_archive();
        assert!(cmd.can_apply(&data));
    }

    #[test]
    fn test_coff_archive_cannot_apply_elf() {
        let cmd = CoffArchiveAnalysisCommand::new();
        let data = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        assert!(!cmd.can_apply(&data));
    }

    #[test]
    fn test_coff_archive_cannot_apply_short() {
        let cmd = CoffArchiveAnalysisCommand::new();
        let data = b"!<ar";
        assert!(!cmd.can_apply(data));
    }

    #[test]
    fn test_coff_archive_parse_member_header() {
        let cmd = CoffArchiveAnalysisCommand::new();
        let data = make_minimal_archive();
        let header = cmd.parse_member_header(&data, ARCHIVE_MAGIC_LEN).unwrap();
        assert_eq!(header.name, "dummy.o");
        assert_eq!(header.size, 0);
    }

    #[test]
    fn test_coff_archive_apply_minimal() {
        let cmd = CoffArchiveAnalysisCommand::new();
        let data = make_minimal_archive();
        let result = cmd.apply(&data, true);
        assert!(result.is_ok(), "apply failed: {:?}", result.err());

        let markup = result.unwrap();
        assert!(!markup.is_empty());
        // Should have archive header + member header
        assert!(markup.data_markups.len() >= 2);
        assert!(markup.fragments.len() >= 2);
    }

    #[test]
    fn test_coff_archive_apply_with_linkers() {
        let cmd = CoffArchiveAnalysisCommand::new();
        let data = make_archive_with_linkers();
        let result = cmd.apply(&data, true);
        assert!(result.is_ok(), "apply failed: {:?}", result.err());

        let markup = result.unwrap();
        assert!(!markup.is_empty());
        // Should have archive header, first linker, long names, member headers
        assert!(markup.data_markups.len() >= 3);
        assert!(markup.fragments.len() >= 3);
    }

    #[test]
    fn test_coff_archive_resolve_long_name() {
        let cmd = CoffArchiveAnalysisCommand::new();
        let long_names = LongNamesMember {
            names: vec!["very_long_name.o".to_string()],
            file_offset: 0,
            total_size: 0,
        };
        assert_eq!(cmd.resolve_name("/0", Some(&long_names)), "very_long_name.o");
        assert_eq!(cmd.resolve_name("/1", Some(&long_names)), "/1");
        assert_eq!(cmd.resolve_name("short.o", Some(&long_names)), "short.o");
    }

    #[test]
    fn test_coff_archive_resolve_name_invalid_chars() {
        let cmd = CoffArchiveAnalysisCommand::new();
        assert_eq!(cmd.resolve_name("a b/c.o", None), "a_b_c.o");
    }
}
