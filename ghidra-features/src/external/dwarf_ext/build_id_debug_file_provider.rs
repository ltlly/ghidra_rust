//! BuildIdDebugFileProvider -- bucketed build-id directory lookup.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.BuildIdDebugFileProvider`.
//!
//! A [`DebugFileProvider`](super::DebugFileProvider) that expects external
//! debug files to be named using the hexadecimal value of the build-id
//! hash, arranged in a bucketed directory hierarchy using the first 2 hex
//! digits of the hash.
//!
//! For example, a debug file with hash
//! `6addc39dc19c1b45f9ba70baf7fd81ea6508ea7f` would be stored as
//! `<root>/6a/ddc39dc19c1b45f9ba70baf7fd81ea6508ea7f.debug`.

use std::path::PathBuf;

use super::debug_info_provider::{DebugFileProvider, DebugInfoProvider, DebugProviderResult};
use super::debug_info_provider_status::DebugInfoProviderStatus;
use super::external_debug_info::ExternalDebugInfo;

/// The URI scheme prefix for this provider type.
pub const BUILDID_NAME_PREFIX: &str = "build-id://";

/// A [`DebugFileProvider`](super::DebugFileProvider) that expects external
/// debug files to be named using the hexadecimal value of the build-id
/// hash, arranged in a bucketed directory hierarchy using the first 2 hex
/// digits of the hash.
///
/// For example, the debug file with hash
/// `6addc39dc19c1b45f9ba70baf7fd81ea6508ea7f` would be stored as
/// `6a/ddc39dc19c1b45f9ba70baf7fd81ea6508ea7f.debug` under the root
/// directory.
///
/// # Name format
///
/// Serialized as `"build-id:///path/to/build-id"`.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::dwarf_ext::{
///     BuildIdDebugFileProvider, DebugInfoProvider,
/// };
/// use std::path::PathBuf;
///
/// let provider = BuildIdDebugFileProvider::new(PathBuf::from("/usr/lib/debug/.build-id"));
/// assert!(provider.name().starts_with("build-id://"));
/// ```
#[derive(Debug)]
pub struct BuildIdDebugFileProvider {
    /// Root directory of the build-id hierarchy (typically ends with
    /// `.build-id`).
    root_dir: PathBuf,
    /// Cached serialized name.
    name: String,
    /// Cached descriptive name.
    descriptive_name: String,
}

impl BuildIdDebugFileProvider {
    /// Creates a new `BuildIdDebugFileProvider` at the specified directory.
    pub fn new(root_dir: PathBuf) -> Self {
        let name = format!("{}{}", BUILDID_NAME_PREFIX, root_dir.display());
        let descriptive_name = format!("{} (.build-id dir)", root_dir.display());
        Self {
            root_dir,
            name,
            descriptive_name,
        }
    }

    /// Returns `true` if the given name string specifies a
    /// `BuildIdDebugFileProvider`.
    pub fn matches(name: &str) -> bool {
        name.starts_with(BUILDID_NAME_PREFIX)
    }

    /// Returns a reference to the root directory.
    pub fn root_dir(&self) -> &std::path::Path {
        &self.root_dir
    }
}

impl DebugInfoProvider for BuildIdDebugFileProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptive_name(&self) -> &str {
        &self.descriptive_name
    }

    fn status(&self) -> DebugInfoProviderStatus {
        if self.root_dir.is_dir() {
            DebugInfoProviderStatus::Valid
        } else {
            DebugInfoProviderStatus::Invalid
        }
    }
}

impl DebugFileProvider for BuildIdDebugFileProvider {
    fn get_file(&self, debug_info: &ExternalDebugInfo) -> DebugProviderResult<Option<PathBuf>> {
        let build_id = match debug_info.build_id() {
            Some(id) if id.len() >= 4 => id, // 2 bytes = 4 hex digits minimum
            _ => return Ok(None),
        };

        let bucket_dir = self.root_dir.join(&build_id[..2]);
        let file = bucket_dir.join(format!("{}.debug", &build_id[2..]));

        // Path traversal protection: verify bucket_dir is under root_dir
        if bucket_dir.parent() != Some(self.root_dir.as_path()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Bad buildid: {}", build_id),
            )
            .into());
        }
        if file.parent() != Some(bucket_dir.as_path()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Bad buildid: {}", build_id),
            )
            .into());
        }

        if file.is_file() {
            Ok(Some(file))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_matches() {
        assert!(BuildIdDebugFileProvider::matches(
            "build-id:///usr/lib/debug/.build-id"
        ));
        assert!(!BuildIdDebugFileProvider::matches(
            "debuglink:///usr/lib/debug"
        ));
        assert!(!BuildIdDebugFileProvider::matches("."));
    }

    #[test]
    fn test_name_format() {
        let provider = BuildIdDebugFileProvider::new(PathBuf::from("/usr/lib/debug/.build-id"));
        assert_eq!(
            provider.name(),
            "build-id:///usr/lib/debug/.build-id"
        );
        assert_eq!(
            provider.descriptive_name(),
            "/usr/lib/debug/.build-id (.build-id dir)"
        );
    }

    #[test]
    fn test_status_valid() {
        let provider = BuildIdDebugFileProvider::new(PathBuf::from("/tmp"));
        assert_eq!(provider.status(), DebugInfoProviderStatus::Valid);
    }

    #[test]
    fn test_status_invalid() {
        let provider = BuildIdDebugFileProvider::new(PathBuf::from("/nonexistent"));
        assert_eq!(provider.status(), DebugInfoProviderStatus::Invalid);
    }

    #[test]
    fn test_get_file_no_build_id() {
        let provider = BuildIdDebugFileProvider::new(PathBuf::from("/tmp"));
        let info = ExternalDebugInfo::for_debug_link("test.debug", 42);
        let result = provider.get_file(&info).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_file_short_build_id() {
        let provider = BuildIdDebugFileProvider::new(PathBuf::from("/tmp"));
        let info = ExternalDebugInfo::for_build_id("ab"); // too short
        let result = provider.get_file(&info).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_file_not_found() {
        let provider = BuildIdDebugFileProvider::new(PathBuf::from("/tmp"));
        let info = ExternalDebugInfo::for_build_id("6addc39dc19c1b45f9ba70baf7fd81ea6508ea7f");
        let result = provider.get_file(&info).unwrap();
        assert!(result.is_none());
    }
}
