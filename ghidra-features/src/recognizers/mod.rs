//! File format recognizers.
//!
//! Ported from Ghidra's `ghidra.app.util.recognizer` Java package.
//!
//! Each recognizer inspects the first few bytes of a file (magic bytes)
//! and returns a human-readable description if the format is identified.
//! Recognizers are ordered by priority so that more-specific checks
//! (e.g. EmptyPkzip, which looks at ZIP's end-of-central-directory)
//! can override generic ones.

mod types;
pub use types::*;

// ---- individual recognizers ------------------------------------------------

mod ace;
mod arj;
mod bzip2;
mod cabarc;
mod chm;
mod compressia;
mod cpio;
mod cramfs;
mod deb;
mod dmg;
mod empty_pkzip;
mod freeze;
mod gzip;
mod imp;
mod iso9660;
mod jar;
mod lha;
mod macromedia_flash;
mod mswim;
mod pak_arc;
mod pkzip;
mod ppmd;
mod rar;
mod rpm;
mod sbc;
mod seven_zip;
mod spanned_pkzip;
mod sqlite;
mod stuffit;
mod tar;
mod uharc;
mod unix_compress;
mod unix_pack;
mod vhd;
mod xar;
mod xz;
mod zlib;
mod zoo;

pub use ace::AceRecognizer;
pub use arj::ArjRecognizer;
pub use bzip2::Bzip2Recognizer;
pub use cabarc::CabarcRecognizer;
pub use chm::CHMRecognizer;
pub use compressia::CompressiaRecognizer;
pub use cpio::CpioRecognizer;
pub use cramfs::CramFSRecognizer;
pub use deb::DebRecognizer;
pub use dmg::DmgRecognizer;
pub use empty_pkzip::EmptyPkzipRecognizer;
pub use freeze::FreezeRecognizer;
pub use gzip::GzipRecognizer;
pub use imp::ImpRecognizer;
pub use iso9660::ISO9660Recognizer;
pub use jar::JarRecognizer;
pub use lha::LhaRecognizer;
pub use macromedia_flash::MacromediaFlashRecognizer;
pub use mswim::MSWIMRecognizer;
pub use pak_arc::PakArcRecognizer;
pub use pkzip::PkzipRecognizer;
pub use ppmd::PpmdRecognizer;
pub use rar::RarRecognizer;
pub use rpm::RpmRecognizer;
pub use sbc::SbcRecognizer;
pub use seven_zip::SevenZipRecognizer;
pub use spanned_pkzip::SpannedPkzipRecognizer;
pub use sqlite::SqliteRecognizer;
pub use stuffit::StuffitRecognizer;
pub use tar::TarRecognizer;
pub use uharc::UharcRecognizer;
pub use unix_compress::UnixCompressRecognizer;
pub use unix_pack::UnixPackRecognizer;
pub use vhd::VHDRecognizer;
pub use xar::XarRecognizer;
pub use xz::XzRecognizer;
pub use zlib::ZlibRecognizer;
pub use zoo::ZooRecognizer;

/// Create a `Vec` containing all built-in recognizers, sorted by priority
/// (higher priority first).
///
/// This is the recommended way to obtain a default set of recognizers
/// for use in a binary loader pipeline.
pub fn all_recognizers() -> Vec<Box<dyn Recognizer>> {
    let mut recognizers: Vec<Box<dyn Recognizer>> = vec![
        Box::new(AceRecognizer),
        Box::new(ArjRecognizer),
        Box::new(Bzip2Recognizer),
        Box::new(CabarcRecognizer),
        Box::new(CHMRecognizer),
        Box::new(CompressiaRecognizer),
        Box::new(CpioRecognizer),
        Box::new(CramFSRecognizer),
        Box::new(DebRecognizer),
        Box::new(DmgRecognizer),
        Box::new(EmptyPkzipRecognizer),
        Box::new(FreezeRecognizer),
        Box::new(GzipRecognizer),
        Box::new(ImpRecognizer),
        Box::new(ISO9660Recognizer),
        Box::new(JarRecognizer),
        Box::new(LhaRecognizer),
        Box::new(MacromediaFlashRecognizer),
        Box::new(MSWIMRecognizer),
        Box::new(PakArcRecognizer),
        Box::new(PkzipRecognizer),
        Box::new(PpmdRecognizer),
        Box::new(RarRecognizer),
        Box::new(RpmRecognizer),
        Box::new(SbcRecognizer),
        Box::new(SevenZipRecognizer),
        Box::new(SpannedPkzipRecognizer),
        Box::new(SqliteRecognizer),
        Box::new(StuffitRecognizer),
        Box::new(TarRecognizer),
        Box::new(UharcRecognizer),
        Box::new(UnixCompressRecognizer),
        Box::new(UnixPackRecognizer),
        Box::new(VHDRecognizer),
        Box::new(XarRecognizer),
        Box::new(XzRecognizer),
        Box::new(ZlibRecognizer),
        Box::new(ZooRecognizer),
    ];
    recognizers.sort_by(|a, b| b.priority().cmp(&a.priority()));
    recognizers
}

/// Run all recognizers against the given bytes and return the first match.
///
/// Recognizers are tried in priority order (highest first).
pub fn recognize(data: &[u8]) -> Option<String> {
    let recognizers = all_recognizers();
    for rec in &recognizers {
        if let Some(desc) = rec.recognize(data) {
            return Some(desc);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize_gzip() {
        let data = [0x1f, 0x8b, 0x08, 0x00];
        let result = recognize(&data);
        assert!(result.is_some());
        assert!(result.unwrap().contains("GZIP"));
    }

    #[test]
    fn test_recognize_pkzip() {
        let data = [0x50, 0x4b, 0x03, 0x04, 0x00];
        let result = recognize(&data);
        assert!(result.is_some());
        assert!(result.unwrap().contains("PKZIP"));
    }

    #[test]
    fn test_recognize_bzip2() {
        let data = [0x42, 0x5a, 0x68, 0x00];
        let result = recognize(&data);
        assert!(result.is_some());
        assert!(result.unwrap().contains("BZIP2"));
    }

    #[test]
    fn test_recognize_unknown() {
        let data = [0x00, 0x00, 0x00, 0x00];
        let result = recognize(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_recognize_too_short() {
        let data = [0x1f];
        let result = recognize(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_all_recognizers_returns_sorted() {
        let recs = all_recognizers();
        assert!(!recs.is_empty());
        for window in recs.windows(2) {
            assert!(window[0].priority() >= window[1].priority());
        }
    }

    #[test]
    fn test_recognize_sqlite() {
        let mut data = vec![0u8; 100];
        data[..16].copy_from_slice(b"SQLite format 3\0");
        let result = recognize(&data);
        assert!(result.is_some());
        assert!(result.unwrap().contains("SQLite"));
    }

    #[test]
    fn test_recognize_tar() {
        let mut data = vec![0u8; 263];
        data[257..262].copy_from_slice(b"ustar");
        let result = recognize(&data);
        assert!(result.is_some());
        assert!(result.unwrap().contains("TAR"));
    }
}
