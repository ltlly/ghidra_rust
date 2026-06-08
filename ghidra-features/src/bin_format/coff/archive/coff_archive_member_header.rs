//! COFF archive member header ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.archive.CoffArchiveMemberHeader`.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;

use super::coff_archive_constants as constants;
use super::long_names_member::LongNamesMember;

/// A COFF archive member header.
///
/// Ported from `ghidra.app.util.bin.format.coff.archive.CoffArchiveMemberHeader`.
/// Each member in a COFF archive (.lib / .ar) starts with this 60-byte header.
#[derive(Debug, Clone)]
pub struct CoffArchiveMemberHeader {
    /// The resolved name of this member.
    name: String,
    /// Date (milliseconds since Unix epoch), or 0 if not present.
    date: i64,
    /// User ID string.
    user_id: String,
    /// Group ID string.
    group_id: String,
    /// File mode string.
    mode: String,
    /// Size of the member payload in bytes.
    size: u64,
    /// File offset of the payload data.
    payload_offset: u64,
    /// File offset of this member header.
    member_offset: u64,
}

impl CoffArchiveMemberHeader {
    /// Read a COFF archive member header from the reader.
    ///
    /// The reader should be positioned just past any previous member's data.
    /// The optional `long_names` parameter provides the long names string table
    /// for resolving names that use the `/offset` scheme.
    pub fn read(
        reader: &mut BinaryReader,
        long_names: Option<&LongNamesMember>,
    ) -> io::Result<Self> {
        // Align to even boundary
        if reader.cursor() % 2 != 0 {
            reader.advance(1);
        }

        let header_offset = reader.cursor();

        // Read the raw name field (16 bytes)
        let raw_name = reader.read_next_fixed_string(constants::CAMH_NAME_LEN)?;
        let date_str = reader.read_next_fixed_string(constants::CAMH_DATE_LEN)?;
        let user_id = reader.read_next_fixed_string(constants::CAMH_USERID_LEN)?;
        let group_id = reader.read_next_fixed_string(constants::CAMH_GROUPID_LEN)?;
        let mode = reader.read_next_fixed_string(constants::CAMH_MODE_LEN)?;
        let size_str = reader.read_next_fixed_string(constants::CAMH_SIZE_LEN)?;

        // Verify end-of-header magic
        let eoh = reader.read_next_bytes(constants::CAMH_EOH_LEN)?;
        if eoh != *constants::CAMH_EOH_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Bad EOH magic string: {:?} (expected {:?})",
                    eoh, constants::CAMH_EOH_MAGIC
                ),
            ));
        }

        let mut payload_offset = header_offset + constants::CAMH_PAYLOAD_OFF;

        // Parse the size
        let mut size = size_str.trim().parse::<u64>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Bad size value: {}", size_str),
            )
        })?;

        // Decode the name field (trim whitespace first)
        let raw_name_trimmed = raw_name.trim();
        let name = if raw_name_trimmed.starts_with("#1/") {
            // Name is stored at the beginning of the payload
            let name_len_str = &raw_name_trimmed[3..];
            let name_len = name_len_str.trim().parse::<usize>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Bad name len value: {}", raw_name),
                )
            })?;
            let name = reader.read_fixed_string_at(payload_offset, name_len)?;
            size = size.saturating_sub(name_len as u64);
            payload_offset += name_len as u64;
            name
        } else if raw_name_trimmed.starts_with('/') && raw_name_trimmed.len() > 1 {
            // Long name lookup: /offset
            if let Some(lnm) = long_names {
                let offset = raw_name_trimmed[1..].trim().parse::<u64>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Bad long name offset: {}", raw_name),
                    )
                })?;
                let mut name = lnm.get_string_at_offset(reader.provider(), offset)?;
                if name.ends_with('/') {
                    name.pop();
                }
                name
            } else {
                raw_name_trimmed.to_string()
            }
        } else if raw_name_trimmed == "/" || raw_name_trimmed == "//" {
            // Linker member or long names member - keep as-is
            raw_name_trimmed.to_string()
        } else if raw_name_trimmed.ends_with('/') {
            // Regular name with trailing slash
            raw_name_trimmed[..raw_name_trimmed.len() - 1].to_string()
        } else {
            raw_name_trimmed.to_string()
        };

        // Parse the date
        let date = if date_str.trim().is_empty() {
            0
        } else {
            match date_str.trim().parse::<i64>() {
                Ok(secs) => secs * 1000, // seconds to milliseconds
                Err(_) => 0,
            }
        };

        reader.set_cursor(payload_offset);

        Ok(Self {
            name,
            date,
            user_id,
            group_id,
            mode,
            size,
            payload_offset,
            member_offset: header_offset,
        })
    }

    /// Returns the resolved name of this member.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the date in milliseconds since Unix epoch.
    pub fn date(&self) -> i64 {
        self.date
    }

    /// Returns the user ID string.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Returns the user ID as an integer, or 0 if not parseable.
    pub fn user_id_int(&self) -> i32 {
        self.user_id.parse().unwrap_or(0)
    }

    /// Returns the group ID string.
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    /// Returns the group ID as an integer, or 0 if not parseable.
    pub fn group_id_int(&self) -> i32 {
        self.group_id.parse().unwrap_or(0)
    }

    /// Returns the file mode string.
    pub fn mode(&self) -> &str {
        &self.mode
    }

    /// Returns the payload size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the file offset of the payload data.
    pub fn payload_offset(&self) -> u64 {
        self.payload_offset
    }

    /// Returns the file offset of this member header.
    pub fn member_offset(&self) -> u64 {
        self.member_offset
    }

    /// Returns true if this header contains a COFF file (not a linker or long names member).
    pub fn is_coff(&self) -> bool {
        self.name != constants::SLASH && self.name != constants::SLASH_SLASH
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bin_format::byte_provider::ByteArrayProvider;

    fn build_member_header(name: &[u8; 16], size_str: &[u8; 10], payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(name);
        data.extend_from_slice(b"0           "); // date
        data.extend_from_slice(b"0     "); // user id
        data.extend_from_slice(b"0     "); // group id
        data.extend_from_slice(b"0       "); // mode
        data.extend_from_slice(size_str);
        data.extend_from_slice(b"`\n");
        data.extend_from_slice(payload);
        data
    }

    #[test]
    fn test_read_simple_member() {
        let mut name = [b' '; 16];
        name[..6].copy_from_slice(b"test.c");
        name[6] = b'/';

        let payload = b"hello world";
        let size_str = b"11       \n";
        let data = build_member_header(&name, size_str, payload);

        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = CoffArchiveMemberHeader::read(&mut reader, None).unwrap();

        assert_eq!(header.name(), "test.c");
        assert_eq!(header.size(), 11);
        assert!(header.is_coff());
    }

    #[test]
    fn test_read_linker_member() {
        let mut name = [b' '; 16];
        name[0] = b'/';

        let payload = b"\x00\x00\x00\x00";
        let size_str = b"4         ";
        let data = build_member_header(&name, size_str, payload);

        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = CoffArchiveMemberHeader::read(&mut reader, None).unwrap();

        assert_eq!(header.name(), "/");
        assert!(!header.is_coff());
    }
}
