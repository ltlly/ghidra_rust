//! LocalDirDebugInfoDProvider -- debuginfod-compatible local directory cache.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.LocalDirDebugInfoDProvider`.
//!
//! Provides debug files found in a debuginfod-client compatible directory
//! structure (i.e. `<root>/<build-id-hex>/<object-type>`).  Also provides
//! the ability to store streamed debug data (implements [`DebugFileStorage`]).
//!
//! This provider does NOT try to follow debuginfod's file age-off logic
//! or config values; it implements its own simple maintenance cycle.

use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::debug_info_provider::{
    DebugFileProvider, DebugFileStorage, DebugInfoProvider, DebugProviderError,
    DebugProviderResult, DebugStreamProvider, StreamInfo,
};
use super::debug_info_provider_status::DebugInfoProviderStatus;
use super::external_debug_info::ExternalDebugInfo;
use super::ObjectType;

/// URI scheme prefix for this provider type.
pub const DEBUGINFOD_NAME_PREFIX: &str = "debuginfod-dir://";

/// Special name for the Ghidra-managed cache directory.
pub const GHIDRACACHE_NAME: &str = "$DEFAULT";

/// Special name for the user's debuginfod-client cache directory.
pub const USERHOMECACHE_NAME: &str = "$DEBUGINFOD_CLIENT_CACHE";

/// How often maintenance should run (1 day).
const MAINT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum age of cached debug files (7 days).
pub const MAX_FILE_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// A [`DebugFileStorage`] that stores and retrieves debug files using a
/// debuginfod-client compatible directory hierarchy:
///
/// ```text
/// <root_dir>/<build-id-hex>/debuginfo
/// <root_dir>/<build-id-hex>/executable
/// <root_dir>/<build-id-hex>/source-<escaped-path>
/// ```
///
/// # Name format
///
/// Serialized as `"debuginfod-dir:///path/to/dir"` or with special
/// sentinel values `$DEFAULT` / `$DEBUGINFOD_CLIENT_CACHE`.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::dwarf_ext::{
///     LocalDirDebugInfoDProvider, DebugInfoProvider,
///     DebugInfoProviderStatus,
/// };
/// use std::path::PathBuf;
///
/// let provider = LocalDirDebugInfoDProvider::new(PathBuf::from("/tmp/cache"));
/// assert!(provider.name().starts_with("debuginfod-dir://"));
/// ```
#[derive(Debug)]
pub struct LocalDirDebugInfoDProvider {
    /// Root directory for cached debug files.
    root_dir: PathBuf,
    /// Serialized name (may include special sentinel values).
    name: String,
    /// Human-readable description.
    descriptive_name: String,
    /// Whether an initial maintenance check is pending.
    needs_init_maint_check: bool,
}

impl LocalDirDebugInfoDProvider {
    /// Creates a new provider at the specified root directory.
    pub fn new(root_dir: PathBuf) -> Self {
        let name = format!("{}{}", DEBUGINFOD_NAME_PREFIX, root_dir.display());
        let descriptive_name = format!("{} (debuginfod dir)", root_dir.display());
        Self {
            root_dir,
            name,
            descriptive_name,
            needs_init_maint_check: false,
        }
    }

    /// Creates a new provider with explicit name and description.
    pub fn with_names(
        root_dir: PathBuf,
        name: String,
        descriptive_name: String,
    ) -> Self {
        Self {
            root_dir,
            name,
            descriptive_name,
            needs_init_maint_check: false,
        }
    }

    /// Returns `true` if the given name string specifies a
    /// `LocalDirDebugInfoDProvider`.
    pub fn matches(name: &str) -> bool {
        name.starts_with(DEBUGINFOD_NAME_PREFIX)
    }

    /// Creates a new provider from a serialized name string.
    ///
    /// Recognizes the special names `$DEFAULT` (Ghidra cache) and
    /// `$DEBUGINFOD_CLIENT_CACHE` (user home debuginfod cache).
    pub fn from_name(name: &str) -> Option<Self> {
        if !Self::matches(name) {
            return None;
        }
        let inner = &name[DEBUGINFOD_NAME_PREFIX.len()..];
        if inner == USERHOMECACHE_NAME {
            return Some(Self::user_home_cache_instance());
        }
        if inner == GHIDRACACHE_NAME {
            return Some(Self::ghidra_cache_instance());
        }
        Some(Self::new(PathBuf::from(inner)))
    }

    /// Returns a provider pointing at the user's debuginfod-client cache
    /// directory (`$XDG_CACHE_HOME/debuginfod_client` or
    /// `~/.cache/debuginfod_client`).
    pub fn user_home_cache_instance() -> Self {
        let cache_dir = get_cache_home_location().join("debuginfod_client");
        let name = format!("{}{}", DEBUGINFOD_NAME_PREFIX, USERHOMECACHE_NAME);
        let descriptive_name = format!("DebugInfoD Cache Dir <{}>", cache_dir.display());
        Self::with_names(cache_dir, name, descriptive_name)
    }

    /// Returns a provider pointing at a Ghidra-specific cache directory.
    ///
    /// The directory is `<user-cache>/debuginfo-cache` and will be created
    /// if it does not exist.
    pub fn ghidra_cache_instance() -> Self {
        let cache_dir = get_ghidra_user_cache_dir().join("debuginfo-cache");
        let _ = fs::create_dir_all(&cache_dir);
        let name = format!("{}{}", DEBUGINFOD_NAME_PREFIX, GHIDRACACHE_NAME);
        let descriptive_name = format!("Ghidra Cache Dir <{}>", cache_dir.display());
        let mut provider = Self::with_names(cache_dir, name, descriptive_name);
        provider.needs_init_maint_check = true;
        provider
    }

    /// Returns a reference to the root directory.
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Sets whether an initial maintenance check is needed.
    pub fn set_needs_maint_check(&mut self, needs: bool) {
        self.needs_init_maint_check = needs;
    }

    /// Returns the path to the build-id subdirectory.
    fn buildid_dir(&self, build_id: &str) -> io::Result<PathBuf> {
        let dir = self.root_dir.join(build_id);
        // Path traversal protection: verify parent is root_dir
        if dir.parent() != Some(self.root_dir.as_path()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Bad buildid value: {}", build_id),
            ));
        }
        Ok(dir)
    }

    /// Returns the cache path for the given debug info identifier.
    fn cache_path(&self, id: &ExternalDebugInfo) -> io::Result<PathBuf> {
        let build_id = id.build_id().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Missing build-id")
        })?;
        let mut suffix = String::new();
        if id.object_type() == ObjectType::Source {
            let extra = id.extra().unwrap_or("");
            suffix = format!("-{}", escape_path(extra));
        }
        let dir = self.buildid_dir(build_id)?;
        Ok(dir.join(format!("{}{}", id.object_type().path_string(), suffix)))
    }

    /// Performs the initial maintenance check if flagged.
    fn perform_init_maint_if_needed(&mut self) {
        if self.needs_init_maint_check {
            self.perform_cache_maint_if_needed();
            self.needs_init_maint_check = false;
        }
    }

    /// Checks whether maintenance is due and performs age-off.
    pub fn perform_cache_maint_if_needed(&self) {
        if !self.root_dir.is_dir() {
            return;
        }
        // Safety: refuse to clean "/"
        if self.root_dir.parent().is_none() {
            eprintln!("Refusing to clean up files in {}", self.root_dir.display());
            return;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let last_maint_file = self.root_dir.join(".lastmaint");
        let last_maint_ts = last_maint_file
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        if last_maint_ts + MAINT_INTERVAL.as_millis() as u64 > now {
            return;
        }

        self.cache_maint(MAX_FILE_AGE);

        // Write timestamp
        if let Ok(mut f) = File::create(&last_maint_file) {
            let _ = write!(f, "Last maint run at {:?}", SystemTime::now());
        }
    }

    /// Ages off debug files older than `max_age`.
    pub fn cache_maint(&self, max_age: Duration) {
        let max_age_ms = max_age.as_millis() as u64;
        let cutoff_ms = u64::MAX - max_age_ms; // effectively: now - max_age
        // We actually want now() - max_age
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cutoff = if max_age_ms <= now {
            now - max_age_ms
        } else {
            0
        };

        let mut deleted_count: u64 = 0;
        let mut deleted_bytes: u64 = 0;

        let entries = match fs::read_dir(&self.root_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || !is_buildid_subdir_name(&path) {
                continue;
            }

            let sub_entries = match fs::read_dir(&path) {
                Ok(e) => e,
                Err(_) => continue,
            };

            let mut sub_dir_file_count = 0u64;
            let mut deleted_sub_dir_file_count = 0u64;

            for sub_entry in sub_entries.flatten() {
                sub_dir_file_count += 1;
                let sub_path = sub_entry.path();
                if sub_path.is_file() {
                    let modified_ms = sub_path
                        .metadata()
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    if modified_ms != 0 && modified_ms < cutoff {
                        let size = sub_path.metadata().map(|m| m.len()).unwrap_or(0);
                        if fs::remove_file(&sub_path).is_ok() {
                            deleted_count += 1;
                            deleted_bytes += size;
                            deleted_sub_dir_file_count += 1;
                        }
                    }
                }
            }

            if sub_dir_file_count == deleted_sub_dir_file_count {
                let _ = fs::remove_dir(&path);
            }
        }

        eprintln!(
            "Finished cache cleanup of debug files in {}, deleted {} files, {} total bytes",
            self.root_dir.display(),
            deleted_count,
            deleted_bytes
        );
    }

    /// Removes all cached files.
    pub fn purge_all(&self) {
        self.cache_maint(Duration::ZERO);
        let _ = fs::remove_file(self.root_dir.join(".lastmaint"));
    }
}

impl DebugInfoProvider for LocalDirDebugInfoDProvider {
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

impl DebugFileProvider for LocalDirDebugInfoDProvider {
    fn get_file(&self, debug_info: &ExternalDebugInfo) -> DebugProviderResult<Option<PathBuf>> {
        if !self.root_dir.is_dir() || !debug_info.has_build_id() {
            return Ok(None);
        }

        let f = self.cache_path(debug_info)?;
        if f.is_file() {
            // Touch the file to update its modification time by opening for append
            let _ = fs::OpenOptions::new().append(true).open(&f);
            return Ok(Some(f));
        }
        Ok(None)
    }
}

impl DebugStreamProvider for LocalDirDebugInfoDProvider {
    fn get_stream(
        &self,
        _debug_info: &ExternalDebugInfo,
    ) -> DebugProviderResult<Option<StreamInfo>> {
        // This provider does not fetch from a remote source.
        Ok(None)
    }
}

impl DebugFileStorage for LocalDirDebugInfoDProvider {
    fn put_stream(
        &self,
        id: &ExternalDebugInfo,
        mut stream: StreamInfo,
    ) -> DebugProviderResult<PathBuf> {
        if !self.root_dir.is_dir() {
            return Err(DebugProviderError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Invalid debuginfo directory: {}", self.root_dir.display()),
            )));
        }
        if !id.has_build_id() {
            return Err(DebugProviderError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Can't store debug file without BuildId value: {:?}", id),
            )));
        }

        let f = self.cache_path(id)?;
        let tmp_name = format!(".tmp_{}", f.file_name().unwrap_or_default().to_string_lossy());
        let tmp_f = f.parent().unwrap_or(&self.root_dir).join(&tmp_name);

        // Ensure parent directory exists
        if let Some(parent) = f.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write stream to temp file
        {
            let mut out_file = File::create(&tmp_f)?;
            let mut reader = stream.into_reader();
            io::copy(&mut reader, &mut out_file)?;
        }

        // Atomically rename temp to final
        if f.is_file() {
            fs::remove_file(&f).map_err(|e| {
                DebugProviderError::Io(io::Error::new(
                    e.kind(),
                    format!("Could not delete {}", f.display()),
                ))
            })?;
        }
        fs::rename(&tmp_f, &f).map_err(|e| {
            let _ = fs::remove_file(&tmp_f);
            DebugProviderError::Io(io::Error::new(
                e.kind(),
                format!(
                    "Could not rename temp file {} to {}",
                    tmp_f.display(),
                    f.display()
                ),
            ))
        })?;

        Ok(f)
    }
}

// ---------------------------------------------------------------------------
// Path escaping (compatible with debuginfod-client.c logic)
// ---------------------------------------------------------------------------

/// Converts a path string into a filename-safe string compatible with
/// the debuginfod-client cache format.
///
/// The result is `<8-hex-digits>-<escaped-path>` where non-alphanumeric
/// characters (except `.`, `_`, `-`) are replaced with `#`.
fn escape_path(s: &str) -> String {
    let max_path = 255 / 2; // from debuginfod-client.c:path_escape()
    let hash = djb_x33a_hash(s);
    let truncated = if s.len() > max_path {
        &s[s.len() - max_path..]
    } else {
        s
    };
    let escaped: String = truncated
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '#'
            }
        })
        .collect();
    format!("{:08x}-{}", hash, escaped)
}

/// DJB X33A hash, compatible with debuginfod-client.c.
fn djb_x33a_hash(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    for b in s.bytes() {
        hash = hash.wrapping_shl(5).wrapping_add(hash).wrapping_add(b as u64);
    }
    hash
}

/// Checks whether a directory name looks like a build-id hash
/// subdirectory (hex-encoded, at least 20 bytes / 40 hex chars).
fn is_buildid_subdir_name(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    if name.len() < 40 {
        return false;
    }
    name.chars().all(|c| c.is_ascii_hexdigit())
}

/// Returns the XDG_CACHE_HOME directory (or `~/.cache` fallback).
fn get_cache_home_location() -> PathBuf {
    if let Ok(val) = env::var("XDG_CACHE_HOME") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if p.is_absolute() {
                return p;
            }
        }
    }
    // Fallback to ~/.cache
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".cache")
}

/// Returns a Ghidra-specific user cache directory.
fn get_ghidra_user_cache_dir() -> PathBuf {
    // Prefer XDG_CACHE_HOME/ghidra, fall back to ~/.cache/ghidra
    get_cache_home_location().join("ghidra")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_matches() {
        assert!(LocalDirDebugInfoDProvider::matches(
            "debuginfod-dir:///tmp/cache"
        ));
        assert!(LocalDirDebugInfoDProvider::matches(
            "debuginfod-dir://$DEFAULT"
        ));
        assert!(!LocalDirDebugInfoDProvider::matches("build-id:///tmp"));
        assert!(!LocalDirDebugInfoDProvider::matches("."));
    }

    #[test]
    fn test_from_name_special_default() {
        let provider = LocalDirDebugInfoDProvider::from_name("debuginfod-dir://$DEFAULT");
        assert!(provider.is_some());
        let p = provider.unwrap();
        assert_eq!(p.name(), "debuginfod-dir://$DEFAULT");
    }

    #[test]
    fn test_from_name_special_user_home() {
        let provider =
            LocalDirDebugInfoDProvider::from_name("debuginfod-dir://$DEBUGINFOD_CLIENT_CACHE");
        assert!(provider.is_some());
        let p = provider.unwrap();
        assert_eq!(
            p.name(),
            "debuginfod-dir://$DEBUGINFOD_CLIENT_CACHE"
        );
    }

    #[test]
    fn test_from_name_custom_path() {
        let provider = LocalDirDebugInfoDProvider::from_name("debuginfod-dir:///tmp/mycache");
        assert!(provider.is_some());
        let p = provider.unwrap();
        assert_eq!(p.root_dir(), Path::new("/tmp/mycache"));
    }

    #[test]
    fn test_from_name_none() {
        assert!(LocalDirDebugInfoDProvider::from_name("something-else").is_none());
    }

    #[test]
    fn test_new_name_format() {
        let provider = LocalDirDebugInfoDProvider::new(PathBuf::from("/tmp/cache"));
        assert_eq!(provider.name(), "debuginfod-dir:///tmp/cache");
        assert_eq!(
            provider.descriptive_name(),
            "/tmp/cache (debuginfod dir)"
        );
    }

    #[test]
    fn test_status_valid() {
        let provider = LocalDirDebugInfoDProvider::new(PathBuf::from("/tmp"));
        assert_eq!(provider.status(), DebugInfoProviderStatus::Valid);
    }

    #[test]
    fn test_status_invalid() {
        let provider = LocalDirDebugInfoDProvider::new(PathBuf::from("/nonexistent/path"));
        assert_eq!(provider.status(), DebugInfoProviderStatus::Invalid);
    }

    #[test]
    fn test_get_file_no_build_id() {
        let provider = LocalDirDebugInfoDProvider::new(PathBuf::from("/tmp"));
        let info = ExternalDebugInfo::for_debug_link("test.debug", 42);
        let result = provider.get_file(&info).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_escape_path() {
        let escaped = escape_path("/usr/include/stdio.h");
        // Format is {hex-hash}-{escaped-path}
        assert!(escaped.contains('-'));
        assert!(!escaped.contains('/'));
        // Verify it starts with hex digits before the dash
        let dash_pos = escaped.find('-').unwrap();
        assert!(dash_pos >= 8);
        let hex_part = &escaped[..dash_pos];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
        // Verify the path part has slashes replaced with #
        let path_part = &escaped[dash_pos + 1..];
        assert!(path_part.contains('#'));
    }

    #[test]
    fn test_djb_x33a_hash() {
        // Known test vector
        let hash = djb_x33a_hash("test");
        assert_ne!(hash, 0);
        // Same input -> same output
        assert_eq!(djb_x33a_hash("test"), djb_x33a_hash("test"));
        // Different input -> different output (with high probability)
        assert_ne!(djb_x33a_hash("test"), djb_x33a_hash("other"));
    }

    #[test]
    fn test_is_buildid_subdir_name() {
        assert!(is_buildid_subdir_name(Path::new(
            "6addc39dc19c1b45f9ba70baf7fd81ea6508ea7f"
        )));
        assert!(!is_buildid_subdir_name(Path::new("ab"))); // too short
        assert!(!is_buildid_subdir_name(Path::new("not_hex")));
    }

    #[test]
    fn test_cache_path_source() {
        let provider = LocalDirDebugInfoDProvider::new(PathBuf::from("/tmp/cache"));
        let info = ExternalDebugInfo::for_build_id("abc123").with_type(
            ObjectType::Source,
            Some("stdio.h".into()),
        );
        let path = provider.cache_path(&info).unwrap();
        let fname = path.file_name().unwrap().to_string_lossy();
        assert!(fname.starts_with("source-"));
        assert_eq!(path.parent().unwrap(), Path::new("/tmp/cache/abc123"));
    }

    #[test]
    fn test_cache_path_debuginfo() {
        let provider = LocalDirDebugInfoDProvider::new(PathBuf::from("/tmp/cache"));
        let info = ExternalDebugInfo::for_build_id("abc123");
        let path = provider.cache_path(&info).unwrap();
        assert_eq!(path.file_name().unwrap(), "debuginfo");
        assert_eq!(path.parent().unwrap(), Path::new("/tmp/cache/abc123"));
    }

    #[test]
    fn test_ghidra_cache_instance() {
        let provider = LocalDirDebugInfoDProvider::ghidra_cache_instance();
        assert_eq!(provider.name(), "debuginfod-dir://$DEFAULT");
        assert!(provider.descriptive_name().contains("Ghidra Cache Dir"));
    }

    #[test]
    fn test_user_home_cache_instance() {
        let provider = LocalDirDebugInfoDProvider::user_home_cache_instance();
        assert_eq!(
            provider.name(),
            "debuginfod-dir://$DEBUGINFOD_CLIENT_CACHE"
        );
        assert!(provider.descriptive_name().contains("DebugInfoD Cache Dir"));
    }
}
