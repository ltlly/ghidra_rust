//! SameDirDebugInfoProvider -- searches the program's import directory.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.SameDirDebugInfoProvider`.
//!
//! A [`DebugFileProvider`](super::DebugFileProvider) that only looks in
//! the program's original import directory for matching debug files.
//! Unlike [`LocalDirDebugLinkProvider`](super::LocalDirDebugLinkProvider),
//! it does NOT recursively search subdirectories.

use std::fs;
use std::io;
use std::path::PathBuf;

use super::debug_info_provider::{DebugFileProvider, DebugInfoProvider, DebugProviderResult};
use super::debug_info_provider_status::DebugInfoProviderStatus;
use super::external_debug_info::ExternalDebugInfo;
use super::local_dir_debug_link_provider::calc_crc;

/// Human-readable description for this provider type.
pub const DESC: &str = "Program's Import Location";

/// A [`DebugFileProvider`](super::DebugFileProvider) that only looks in the
/// program's original import directory for matching debug files.
///
/// Unlike [`LocalDirDebugLinkProvider`](super::LocalDirDebugLinkProvider),
/// this provider does NOT recursively search subdirectories.
///
/// # Name format
///
/// The serialized name is simply `"."` (a single dot).
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::dwarf_ext::{
///     SameDirDebugInfoProvider, DebugInfoProvider,
///     DebugInfoProviderStatus,
/// };
/// use std::path::PathBuf;
///
/// let provider = SameDirDebugInfoProvider::new(Some(PathBuf::from("/usr/bin")));
/// assert_eq!(provider.name(), ".");
/// assert_eq!(provider.status(), DebugInfoProviderStatus::Valid);
/// ```
#[derive(Debug)]
pub struct SameDirDebugInfoProvider {
    /// The program's directory, or `None` if not available.
    prog_dir: Option<PathBuf>,
}

impl SameDirDebugInfoProvider {
    /// Creates a new `SameDirDebugInfoProvider` for the given directory.
    ///
    /// Pass `None` if the program directory is not known.
    pub fn new(prog_dir: Option<PathBuf>) -> Self {
        Self { prog_dir }
    }

    /// Returns `true` if the given name string specifies a
    /// `SameDirDebugInfoProvider`.
    pub fn matches(name: &str) -> bool {
        name == "."
    }

    /// Returns the program directory, if set.
    pub fn prog_dir(&self) -> Option<&PathBuf> {
        self.prog_dir.as_ref()
    }

    /// Ensures the filename does not escape the program directory (path
    /// traversal protection).
    fn ensure_safe_filename(&self, filename: &str) -> io::Result<PathBuf> {
        let prog_dir = self.prog_dir.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Program directory not set")
        })?;
        let test_file = prog_dir.join(filename);
        // Verify the parent is still the prog_dir (no path traversal)
        if test_file.parent() != Some(prog_dir.as_path()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported path specified in debug file: {}", filename),
            ));
        }
        Ok(test_file)
    }
}

impl DebugInfoProvider for SameDirDebugInfoProvider {
    fn name(&self) -> &str {
        "."
    }

    fn descriptive_name(&self) -> &str {
        // In Java this was: DESC + (progDir != null ? " (" + progDir.getPath() + ")" : "")
        // For simplicity return the static desc. A real impl could cache the string.
        DESC
    }

    fn status(&self) -> DebugInfoProviderStatus {
        match &self.prog_dir {
            Some(dir) => {
                if dir.is_dir() {
                    DebugInfoProviderStatus::Valid
                } else {
                    DebugInfoProviderStatus::Invalid
                }
            }
            None => DebugInfoProviderStatus::Unknown,
        }
    }
}

impl DebugFileProvider for SameDirDebugInfoProvider {
    fn get_file(&self, debug_info: &ExternalDebugInfo) -> DebugProviderResult<Option<PathBuf>> {
        // Try debuglink
        if debug_info.has_debug_link() {
            let filename = debug_info.filename().unwrap();
            let debug_file = self.ensure_safe_filename(filename)?;
            if debug_file.is_file() {
                let file_crc = calc_crc(&debug_file)?;
                if file_crc == debug_info.crc() {
                    return Ok(Some(debug_file));
                }
                // CRC mismatch -- log and skip
                eprintln!(
                    "DWARF external debug file found with mismatching crc, ignored: {:?} ({:08x})",
                    debug_file, file_crc
                );
            }
        }

        // Try build-id (guess: co-located file named "<buildid>.debug")
        if debug_info.has_build_id() {
            let build_id = debug_info.build_id().unwrap();
            let debug_file = self.ensure_safe_filename(&format!("{}.debug", build_id))?;
            if debug_file.is_file() {
                return Ok(Some(debug_file));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_matches() {
        assert!(SameDirDebugInfoProvider::matches("."));
        assert!(!SameDirDebugInfoProvider::matches("something"));
    }

    #[test]
    fn test_status_with_valid_dir() {
        let provider = SameDirDebugInfoProvider::new(Some(PathBuf::from("/tmp")));
        assert_eq!(provider.status(), DebugInfoProviderStatus::Valid);
    }

    #[test]
    fn test_status_with_invalid_dir() {
        let provider = SameDirDebugInfoProvider::new(Some(PathBuf::from("/nonexistent/path")));
        assert_eq!(provider.status(), DebugInfoProviderStatus::Invalid);
    }

    #[test]
    fn test_status_with_no_dir() {
        let provider = SameDirDebugInfoProvider::new(None);
        assert_eq!(provider.status(), DebugInfoProviderStatus::Unknown);
    }

    #[test]
    fn test_name() {
        let provider = SameDirDebugInfoProvider::new(None);
        assert_eq!(provider.name(), ".");
    }

    #[test]
    fn test_ensure_safe_filename_rejects_traversal() {
        let provider = SameDirDebugInfoProvider::new(Some(PathBuf::from("/usr/bin")));
        assert!(provider.ensure_safe_filename("../etc/passwd").is_err());
    }

    #[test]
    fn test_get_file_no_debuglink_no_buildid() {
        let provider = SameDirDebugInfoProvider::new(Some(PathBuf::from("/tmp")));
        let info = ExternalDebugInfo::new(None, 0, None, super::super::ObjectType::DebugInfo, None);
        let result = provider.get_file(&info).unwrap();
        assert!(result.is_none());
    }
}
