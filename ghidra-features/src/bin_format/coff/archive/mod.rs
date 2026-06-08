//! COFF archive format ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.archive` package.
//!
//! Provides types for parsing COFF archive files (.lib / .ar):
//! - [`CoffArchiveHeader`] -- top-level archive parser
//! - [`CoffArchiveMemberHeader`] -- per-member header
//! - [`FirstLinkerMember`] -- first "/" special member (Microsoft)
//! - [`SecondLinkerMember`] -- second "/" special member (Microsoft)
//! - [`LongNamesMember`] -- "//" special member with long filenames
//! - Constants for archive field offsets and sizes

pub mod coff_archive_constants;
pub mod coff_archive_member_header;
pub mod first_linker_member;
pub mod long_names_member;
pub mod second_linker_member;

pub use coff_archive_constants::*;
pub use coff_archive_member_header::CoffArchiveMemberHeader;
pub use first_linker_member::FirstLinkerMember;
pub use long_names_member::LongNamesMember;
pub use second_linker_member::SecondLinkerMember;

use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::byte_provider::ByteProvider;

use crate::bin_format::coff::coff_exception::CoffException;

/// A COFF archive file (Microsoft .lib or Unix .ar).
///
/// Ported from `ghidra.app.util.bin.format.coff.archive.CoffArchiveHeader`.
/// Parses the archive and its member headers, linker members, and long names member.
#[derive(Debug)]
pub struct CoffArchiveHeader {
    first_linker_member: Option<FirstLinkerMember>,
    second_linker_member: Option<SecondLinkerMember>,
    long_name_member: Option<LongNamesMember>,
    member_headers: Vec<CoffArchiveMemberHeader>,
    is_ms: bool,
}

impl CoffArchiveHeader {
    /// Returns true if the given provider starts with a COFF archive magic.
    pub fn is_match(provider: &dyn ByteProvider) -> bool {
        if provider.length() < coff_archive_constants::MAGIC_LEN as u64 {
            return false;
        }
        match provider.read_slice(0, coff_archive_constants::MAGIC_LEN) {
            Ok(bytes) => bytes == *coff_archive_constants::MAGIC_BYTES,
            Err(_) => false,
        }
    }

    /// Read and parse a COFF archive from the given provider.
    ///
    /// Returns `Ok(None)` if the provider does not contain a COFF archive.
    pub fn read(provider: Box<dyn ByteProvider>) -> Result<Option<Self>, CoffException> {
        if !Self::is_match(provider.as_ref()) {
            return Ok(None);
        }

        let mut reader = BinaryReader::new(provider, false); // endianness doesn't matter for ASCII headers
        reader.set_cursor(coff_archive_constants::MAGIC_LEN as u64);

        let mut cah = CoffArchiveHeader {
            first_linker_member: None,
            second_linker_member: None,
            long_name_member: None,
            member_headers: Vec::new(),
            is_ms: false,
        };

        let mut member_num: usize = 0;

        while reader.remaining() >= coff_archive_constants::CAMH_MIN_SIZE {
            let camh = match CoffArchiveMemberHeader::read(
                &mut reader,
                cah.long_name_member.as_ref(),
            ) {
                Ok(h) => h,
                Err(e) => {
                    // If we've parsed at least 3 members, return partial success
                    if member_num > 3 {
                        break;
                    }
                    return Err(CoffException::from(e));
                }
            };

            let name = camh.name().to_string();

            if name == "/" {
                match member_num {
                    0 => {
                        let flm = FirstLinkerMember::parse(
                            &mut reader,
                            camh.size(),
                            true,
                        )?;
                        cah.first_linker_member = Some(flm);
                    }
                    1 => {
                        let slm = SecondLinkerMember::parse(
                            &mut reader,
                            camh.size(),
                            true,
                        )?;
                        cah.second_linker_member = Some(slm);
                    }
                    _ => {
                        return Err(CoffException::new(
                            "Invalid COFF: multiple 1st and 2nd linker members detected.",
                        ));
                    }
                }
            } else if name == "//" {
                if cah.long_name_member.is_none() {
                    let lnm = LongNamesMember::parse(&mut reader, camh.size())?;
                    cah.long_name_member = Some(lnm);
                } else {
                    return Err(CoffException::new(
                        "Invalid COFF: multiple long name members detected.",
                    ));
                }
            } else {
                // Advance reader past the payload
                reader.set_cursor(camh.payload_offset() + camh.size());
            }

            cah.member_headers.push(camh);
            member_num += 1;
        }

        cah.is_ms = cah.first_linker_member.is_some()
            && cah.second_linker_member.is_some()
            && cah.long_name_member.is_some();

        Ok(Some(cah))
    }

    /// Returns the list of all archive member headers.
    pub fn member_headers(&self) -> &[CoffArchiveMemberHeader] {
        &self.member_headers
    }

    /// Returns the first linker member, if present.
    pub fn first_linker_member(&self) -> Option<&FirstLinkerMember> {
        self.first_linker_member.as_ref()
    }

    /// Returns the second linker member, if present.
    pub fn second_linker_member(&self) -> Option<&SecondLinkerMember> {
        self.second_linker_member.as_ref()
    }

    /// Returns the long names member, if present.
    pub fn long_name_member(&self) -> Option<&LongNamesMember> {
        self.long_name_member.as_ref()
    }

    /// Returns true if this archive appears to be in Microsoft format.
    ///
    /// Microsoft archives have both linker members and a long names member.
    pub fn is_ms_format(&self) -> bool {
        self.is_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bin_format::byte_provider::ByteArrayProvider;

    fn build_minimal_archive() -> Vec<u8> {
        let mut data = Vec::new();
        // Magic
        data.extend_from_slice(b"!<arch>\n");

        // "/" member (first linker) - just a dummy with size 0
        data.extend_from_slice(b"/               0           0     0     0       4         `\n");
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // 4 bytes payload

        // "//" member (long names) - empty
        data.extend_from_slice(b"//              0           0     0     0       1         `\n");
        data.extend_from_slice(b"\0"); // 1 byte payload

        data
    }

    #[test]
    fn test_is_match() {
        let data = b"!<arch>\nrest of data here";
        let provider = ByteArrayProvider::new(None, data.to_vec());
        assert!(CoffArchiveHeader::is_match(&provider));
    }

    #[test]
    fn test_is_not_match() {
        let data = b"PE\x00\x00some PE file";
        let provider = ByteArrayProvider::new(None, data.to_vec());
        assert!(!CoffArchiveHeader::is_match(&provider));
    }

    #[test]
    fn test_is_not_match_too_short() {
        let data = b"!<ar";
        let provider = ByteArrayProvider::new(None, data.to_vec());
        assert!(!CoffArchiveHeader::is_match(&provider));
    }

    #[test]
    fn test_read_none_when_not_archive() {
        let data = b"PE\x00\x00";
        let provider: Box<dyn ByteProvider> = Box::new(ByteArrayProvider::new(None, data.to_vec()));
        let result = CoffArchiveHeader::read(provider).unwrap();
        assert!(result.is_none());
    }
}
