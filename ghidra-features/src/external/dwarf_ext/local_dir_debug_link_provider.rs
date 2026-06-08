//! LocalDirDebugLinkProvider -- recursive directory search for debug-link files.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.LocalDirDebugLinkProvider`.
//!
//! Searches for DWARF external debug files specified via a debug-link
//! filename and CRC in a directory tree.  Unlike
//! [`SameDirDebugInfoProvider`](super::SameDirDebugInfoProvider), this
//! provider recursively searches subdirectories.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::debug_info_provider::{DebugFileProvider, DebugInfoProvider, DebugProviderResult};
use super::debug_info_provider_status::DebugInfoProviderStatus;
use super::external_debug_info::ExternalDebugInfo;

/// The URI scheme prefix for this provider type.
pub const DEBUGLINK_NAME_PREFIX: &str = "debuglink://";

/// A [`DebugFileProvider`](super::DebugFileProvider) that searches for
/// DWARF external debug files specified via a debug-link filename / CRC
/// in a directory tree.
///
/// Unlike [`SameDirDebugInfoProvider`](super::SameDirDebugInfoProvider),
/// this provider recursively searches subdirectories for the target file.
///
/// # Name format
///
/// Serialized as `"debuglink:///path/to/dir"`.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::dwarf_ext::{
///     LocalDirDebugLinkProvider, DebugInfoProvider,
///     DebugInfoProviderStatus,
/// };
/// use std::path::PathBuf;
///
/// let provider = LocalDirDebugLinkProvider::new(PathBuf::from("/usr/lib/debug"));
/// assert!(provider.name().starts_with("debuglink://"));
/// ```
#[derive(Debug)]
pub struct LocalDirDebugLinkProvider {
    /// The root directory to search.
    search_dir: PathBuf,
    /// Cached serialized name.
    name: String,
    /// Cached descriptive name.
    descriptive_name: String,
}

impl LocalDirDebugLinkProvider {
    /// Creates a new `LocalDirDebugLinkProvider` at the specified directory.
    pub fn new(search_dir: PathBuf) -> Self {
        let name = format!("{}{}", DEBUGLINK_NAME_PREFIX, search_dir.display());
        let descriptive_name = format!("{} (debug-link dir)", search_dir.display());
        Self {
            search_dir,
            name,
            descriptive_name,
        }
    }

    /// Returns `true` if the given name string specifies a
    /// `LocalDirDebugLinkProvider`.
    pub fn matches(name: &str) -> bool {
        name.starts_with(DEBUGLINK_NAME_PREFIX)
    }

    /// Returns a reference to the search directory.
    pub fn search_dir(&self) -> &Path {
        &self.search_dir
    }

    /// Ensures the filename does not escape the search directory.
    fn ensure_safe_filename(&self, filename: &str) -> io::Result<()> {
        let test_file = self.search_dir.join(filename);
        if test_file.parent() != Some(self.search_dir.as_path()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported path specified in debug file: {}", filename),
            ));
        }
        Ok(())
    }

    /// Recursively searches `dir` for a file matching the debug-link
    /// criteria.
    fn find_file(&self, dir: &Path, debug_info: &ExternalDebugInfo) -> DebugProviderResult<Option<PathBuf>> {
        if !debug_info.has_debug_link() {
            return Ok(None);
        }

        let filename = debug_info.filename().unwrap();
        let file = dir.join(filename);
        if file.is_file() {
            let file_crc = calc_crc(&file)?;
            if file_crc == debug_info.crc() {
                return Ok(Some(file));
            }
            eprintln!(
                "DWARF external debug file found with mismatching crc, ignored: {:?} ({:08x})",
                file, file_crc
            );
        }

        // Recurse into subdirectories
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // TODO: prevent recursing into symlinks?
                    if let Some(result) = self.find_file(&path, debug_info)? {
                        return Ok(Some(result));
                    }
                }
            }
        }

        Ok(None)
    }
}

impl DebugInfoProvider for LocalDirDebugLinkProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptive_name(&self) -> &str {
        &self.descriptive_name
    }

    fn status(&self) -> DebugInfoProviderStatus {
        if self.search_dir.is_dir() {
            DebugInfoProviderStatus::Valid
        } else {
            DebugInfoProviderStatus::Invalid
        }
    }
}

impl DebugFileProvider for LocalDirDebugLinkProvider {
    fn get_file(&self, debug_info: &ExternalDebugInfo) -> DebugProviderResult<Option<PathBuf>> {
        if !debug_info.has_debug_link() || !self.search_dir.is_dir() {
            return Ok(None);
        }
        self.ensure_safe_filename(debug_info.filename().unwrap())?;
        self.find_file(&self.search_dir, debug_info)
    }
}

/// Calculates the CRC32 for the specified file.
///
/// Reads the entire file and computes the CRC32 checksum.
pub fn calc_crc(path: &Path) -> io::Result<u32> {
    let data = fs::read(path)?;
    Ok(crate::base::checksums::crc32(&data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_matches() {
        assert!(LocalDirDebugLinkProvider::matches("debuglink:///usr/lib/debug"));
        assert!(!LocalDirDebugLinkProvider::matches("build-id:///usr/lib/debug"));
        assert!(!LocalDirDebugLinkProvider::matches("."));
    }

    #[test]
    fn test_name_format() {
        let provider = LocalDirDebugLinkProvider::new(PathBuf::from("/usr/lib/debug"));
        assert_eq!(provider.name(), "debuglink:///usr/lib/debug");
        assert_eq!(provider.descriptive_name(), "/usr/lib/debug (debug-link dir)");
    }

    #[test]
    fn test_status_valid() {
        let provider = LocalDirDebugLinkProvider::new(PathBuf::from("/tmp"));
        assert_eq!(provider.status(), DebugInfoProviderStatus::Valid);
    }

    #[test]
    fn test_status_invalid() {
        let provider = LocalDirDebugLinkProvider::new(PathBuf::from("/nonexistent"));
        assert_eq!(provider.status(), DebugInfoProviderStatus::Invalid);
    }

    #[test]
    fn test_ensure_safe_filename_rejects_traversal() {
        let provider = LocalDirDebugLinkProvider::new(PathBuf::from("/usr/lib/debug"));
        assert!(provider.ensure_safe_filename("../etc/passwd").is_err());
    }

    #[test]
    fn test_get_file_no_debuglink() {
        let provider = LocalDirDebugLinkProvider::new(PathBuf::from("/tmp"));
        let info = ExternalDebugInfo::for_build_id("abc");
        let result = provider.get_file(&info).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_calc_crc_nonexistent() {
        let result = calc_crc(Path::new("/nonexistent/file"));
        assert!(result.is_err());
    }
}
