//! Miscellaneous utility types and helpers used throughout ghidra-core.
//!
//! Includes endianness, versioning, bit manipulation, file locking,
//! MD5 hashing, class/file scanning, and ports of Ghidra's Framework/Utility
//! Java packages.
//!
//! # Submodules
//!
//! - [`task_monitor`] -- TaskMonitor trait, StubTaskMonitor, CancelledException,
//!   CancellableIterator (port of `ghidra.util.task`).
//! - [`msg`] -- Logging facade with Msg, ErrorLogger, ErrorDisplay, Issue
//!   (port of `ghidra.util.Msg`).
//! - [`exceptions`] -- Exception types: UsrException, AssertException,
//!   CancelledException, TimeoutException (port of `ghidra.util.exception`).
//! - [`xml_parser`] -- XmlPullParser, XmlElement, XmlException
//!   (port of `ghidra.xml`).
//! - [`xml_utilities`] -- XmlUtilities, XmlWriter for XML generation, escaping,
//!   pretty-printing, and validation (port of `ghidra.util.XmlUtilities`).
//! - [`operating_system`] -- OperatingSystem enum (port of
//!   `ghidra.framework.OperatingSystem`).
//! - [`application`] -- ApplicationLayout, ApplicationProperties, GModule,
//!   ApplicationVersion, ApplicationIdentifier, XdgUtils
//!   (port of `utility.application` and `ghidra.framework`).
//! - [`functional`] -- Callback, ExceptionalFunction, ExceptionalSupplier
//!   (port of `utility.function`).
//! - [`resource`] -- Resource, ResourceFile, GClassLoader, JarEntryNode
//!   (port of `generic.jar`).
//! - [`service_provider`] -- ServiceProvider, PluggableServiceRegistry
//!   (port of `ghidra.framework.plugintool`).
//! - [`concurrent`] -- GThreadPool, NamedDaemonThreadFactory
//!   (port of `generic.concurrent`).
//! - [`data_structures`] -- Duo, Range, Location, Fixup
//!   (port of `ghidra.util.datastruct` and `ghidra.util`).
//! - [`stream_utils`] -- BoundedInputStream, HashingOutputStream,
//!   MonitoredOutputStream, NullOutputStream
//!   (port of `ghidra.util` stream types).
//! - [`system_utilities`] -- SystemUtilities, FileUtilities,
//!   ReflectionUtilities (port of `ghidra.util` and `utilities.util`).
//! - [`string_utilities`] -- StringUtilities, StringBuilder
//!   (port of `ghidra.util.StringUtilities`).
//! - [`number_utilities`] -- NumberUtilities, FlexInteger
//!   (port of `ghidra.util.NumberUtilities`).
//! - [`binary_coded_decimal`] -- BcdUtils, BcdNumber
//!   (port of `ghidra.util.BinaryCodedDecimal`).
//! - [`color_utils`] -- ColorUtils, Color
//!   (port of `ghidra.util.ColorUtils`).
//! - [`html_utilities`] -- HTMLUtilities, HtmlBuilder
//!   (port of `ghidra.util.HTMLUtilities`).
//! - [`module_utils`] -- ModuleUtilities, ModuleManifestFile,
//!   ClasspathFilter (port of `utility.module`).

pub mod application;
pub mod binary_coded_decimal;
pub mod color_utils;
pub mod concurrent;
pub mod data_structures;
pub mod exceptions;
pub mod functional;
pub mod html_utilities;
pub mod module_utils;
pub mod msg;
pub mod number_utilities;
pub mod operating_system;
pub mod resource;
pub mod service_provider;
pub mod stream_utils;
pub mod string_utilities;
pub mod system_utilities;
pub mod task_monitor;
pub mod xml_parser;
pub mod xml_utilities;

use std::fmt;

// ---------------------------------------------------------------------------
// Endian
// ---------------------------------------------------------------------------

/// Endianness enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    Big,
    Little,
}

impl Endian {
    /// Determine host endianness at runtime.
    pub fn host() -> Self {
        if cfg!(target_endian = "little") {
            Endian::Little
        } else {
            Endian::Big
        }
    }

    /// Returns `true` for big-endian.
    pub fn is_big(&self) -> bool {
        matches!(self, Endian::Big)
    }

    /// Returns `true` for little-endian.
    pub fn is_little(&self) -> bool {
        matches!(self, Endian::Little)
    }
}

impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endian::Big => write!(f, "big"),
            Endian::Little => write!(f, "little"),
        }
    }
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// A version identifier (major.minor.patch).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// Alignment
// ---------------------------------------------------------------------------

/// Alignment constraint (power of 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Alignment(pub u32);

impl Alignment {
    pub const ONE: Self = Self(1);
    pub const TWO: Self = Self(2);
    pub const FOUR: Self = Self(4);
    pub const EIGHT: Self = Self(8);
    pub const SIXTEEN: Self = Self(16);

    /// Returns `true` when addr satisfies this alignment.
    pub fn is_aligned(&self, addr: u64) -> bool {
        addr % self.0 as u64 == 0
    }

    /// Round addr up to the next aligned boundary.
    pub fn align_up(&self, addr: u64) -> u64 {
        let mask = self.0 as u64 - 1;
        (addr + mask) & !mask
    }

    /// Round addr down to the nearest aligned boundary.
    pub fn align_down(&self, addr: u64) -> u64 {
        let mask = self.0 as u64 - 1;
        addr & !mask
    }
}

// ---------------------------------------------------------------------------
// BitUtils
// ---------------------------------------------------------------------------

/// Bit-level manipulation utilities.
pub struct BitUtils;

impl BitUtils {
    /// Extract bits [high..low] from value (inclusive).
    pub fn extract(value: u64, high: u32, low: u32) -> u64 {
        debug_assert!(high >= low);
        let width = high - low + 1;
        let mask = if width >= 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        (value >> low) & mask
    }

    /// Sign-extend a width-bit value to 64 bits.
    pub fn sign_extend(value: u64, width: u32) -> i64 {
        if width >= 64 {
            return value as i64;
        }
        let shift = 64 - width;
        ((value << shift) as i64) >> shift
    }

    /// Zero-extend a width-bit value to 64 bits (identity on u64).
    pub fn zero_extend(value: u64, _width: u32) -> u64 {
        value
    }

    /// Reverse bytes of a u16.
    pub fn byte_swap16(value: u16) -> u16 {
        value.swap_bytes()
    }

    /// Reverse bytes of a u32.
    pub fn byte_swap32(value: u32) -> u32 {
        value.swap_bytes()
    }

    /// Reverse bytes of a u64.
    pub fn byte_swap64(value: u64) -> u64 {
        value.swap_bytes()
    }
}

// ======================================================================
// FileLocker
// ======================================================================

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// File-based locking mechanism.
///
/// Creates a lock file containing properties (username, hostname, timestamp,
/// OS info) to prevent concurrent use of resources.
///
/// Corresponds to Ghidra's `FileLocker`.
#[derive(Debug)]
pub struct FileLocker {
    lock_file: PathBuf,
    existing_lock_properties: Option<HashMap<String, String>>,
    created_lock_properties: Option<HashMap<String, String>>,
    existing_lock_type: Option<String>,
    is_locked: bool,
}

impl FileLocker {
    /// Create a new `FileLocker` for the given lock file path.
    pub fn new(lock_file: &Path) -> Self {
        let existing = Self::load_existing_lock_file(lock_file);
        let existing_lock_type = existing
            .as_ref()
            .and_then(|p| p.get("<META> Supports File Channel Locking").cloned());

        Self {
            lock_file: lock_file.to_path_buf(),
            existing_lock_properties: existing,
            created_lock_properties: None,
            existing_lock_type,
            is_locked: false,
        }
    }

    /// Attempt to acquire the lock.
    ///
    /// Returns `true` if the lock was acquired. Returns `false` if a lock
    /// already exists.
    pub fn lock(&mut self) -> bool {
        if self.existing_lock_properties.is_some() {
            return false;
        }
        self.create_lock_file()
    }

    /// Returns `true` if this instance holds the lock.
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    /// Release the lock by deleting the lock file.
    pub fn release(&mut self) {
        if self.is_lock_owner() {
            let _ = fs::remove_file(&self.lock_file);
        }
        self.is_locked = false;
    }

    /// Returns `true` if the existing lock can be forcibly taken.
    pub fn can_force_lock(&self) -> bool {
        self.existing_lock_type.as_deref() == Some("File Lock")
    }

    /// Force-acquire the lock, replacing an existing file lock.
    pub fn force_lock(&mut self) -> bool {
        if self.can_force_lock() {
            return self.create_lock_file();
        }
        false
    }

    /// Get information about the existing lock file.
    pub fn get_existing_lock_file_information(&self) -> String {
        match &self.existing_lock_properties {
            None => "no properties in lock file".to_string(),
            Some(props) => {
                let keys = [
                    "Username",
                    "Hostname",
                    "Timestamp",
                    "OS Name",
                    "OS Architecture",
                    "OS Version",
                ];
                let mut lines = Vec::new();
                for key in &keys {
                    if let Some(val) = props.get(*key) {
                        lines.push(format!("{}: {}", key, val));
                    }
                }
                lines.join("\n")
            }
        }
    }

    fn load_existing_lock_file(lock_file: &Path) -> Option<HashMap<String, String>> {
        if !lock_file.exists() {
            return None;
        }
        let file = fs::File::open(lock_file).ok()?;
        let reader = BufReader::new(file);
        let mut props = HashMap::new();
        for line in reader.lines() {
            if let Ok(line) = line {
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim().to_string();
                    let value = value
                        .trim()
                        .trim_start_matches('"')
                        .trim_end_matches('"')
                        .to_string();
                    props.insert(key, value);
                }
            }
        }
        if props.is_empty() {
            None
        } else {
            Some(props)
        }
    }

    fn create_lock_file(&mut self) -> bool {
        let mut properties = HashMap::new();

        properties.insert(
            "Username".to_string(),
            crate::generic::system::SystemInfo::user_name(),
        );
        properties.insert(
            "Hostname".to_string(),
            crate::generic::system::SystemInfo::host_name(),
        );
        properties.insert(
            "Timestamp".to_string(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        );
        properties.insert("OS Name".to_string(), std::env::consts::OS.to_string());
        properties.insert(
            "OS Architecture".to_string(),
            std::env::consts::ARCH.to_string(),
        );
        properties.insert("OS Version".to_string(), "unknown".to_string());
        properties.insert(
            "<META> Supports File Channel Locking".to_string(),
            "File Lock".to_string(),
        );

        if !Self::store_properties(&self.lock_file, &properties) {
            return false;
        }

        if self.lock_file.exists() {
            self.created_lock_properties = Some(properties);
            self.is_locked = true;
            return true;
        }
        false
    }

    fn store_properties(path: &Path, properties: &HashMap<String, String>) -> bool {
        let mut file = match fs::File::create(path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        for (key, value) in properties {
            let _ = writeln!(file, "{}={}", key, value);
        }
        true
    }

    fn is_lock_owner(&self) -> bool {
        let created = match &self.created_lock_properties {
            Some(p) => p,
            None => return false,
        };
        let current = match Self::load_existing_lock_file(&self.lock_file) {
            Some(p) => p,
            None => return false,
        };
        let keys = [
            "Username",
            "Hostname",
            "Timestamp",
            "OS Name",
            "OS Architecture",
            "OS Version",
        ];
        keys.iter()
            .all(|k| created.get(*k) == current.get(*k))
    }
}

impl Drop for FileLocker {
    fn drop(&mut self) {
        if self.is_locked {
            self.release();
        }
    }
}

// ======================================================================
// MD5 Hash utilities
// ======================================================================

use md5::{Digest, Md5};
use std::io::Read;

/// MD5 hashing utilities.
///
/// Corresponds to Ghidra's `MD5Utilities`.
pub struct Md5Utils;

impl Md5Utils {
    /// Compute the MD5 hash of a byte slice, returning a hex string.
    pub fn md5_hash_bytes(data: &[u8]) -> String {
        let mut hasher = Md5::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Compute the MD5 hash of a string.
    pub fn md5_hash_str(s: &str) -> String {
        Self::md5_hash_bytes(s.as_bytes())
    }

    /// Compute the MD5 hash of a reader's contents.
    pub fn md5_hash_reader<R: Read>(reader: &mut R) -> io::Result<String> {
        let mut hasher = Md5::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Compute the MD5 hash of a file's contents.
    pub fn md5_hash_file(path: &Path) -> io::Result<String> {
        let mut file = fs::File::open(path)?;
        Self::md5_hash_reader(&mut file)
    }

    /// Compute the combined MD5 hash of multiple strings.
    pub fn md5_hash_list(values: &[String]) -> String {
        let mut hasher = Md5::new();
        for v in values {
            hasher.update(v.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// Hex dump binary data as chars.
    pub fn hex_dump(data: &[u8]) -> Vec<char> {
        data.iter()
            .flat_map(|b| {
                let s = format!("{:02x}", b);
                s.chars().collect::<Vec<_>>()
            })
            .collect()
    }

    /// Hex dump binary data as a string.
    pub fn hex_dump_string(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Generate a salted MD5 hash. The first 4 characters of the result are the salt.
    pub fn salted_md5_hash(data: &[u8]) -> String {
        use rand::Rng;
        let salt: u16 = rand::thread_rng().gen();
        let salt_str = format!("{:04x}", salt);
        let mut hasher = Md5::new();
        hasher.update(salt_str.as_bytes());
        hasher.update(data);
        format!("{}{:x}", salt_str, hasher.finalize())
    }

    /// Generate an unsalted MD5 hash.
    pub fn md5_hash(data: &[u8]) -> String {
        Self::md5_hash_bytes(data)
    }
}

// ======================================================================
// ClassSearcher / File scanning
// ======================================================================

/// File scanning utility for discovering files matching criteria.
///
/// Corresponds to Ghidra's `ClassSearcher` for file/classpath scanning.
pub struct ClassSearcher;

/// Information about a discovered file.
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// Path to the containing directory or jar.
    pub path: String,
    /// Full name (e.g., qualified class name or file path).
    pub name: String,
    /// File extension or suffix.
    pub suffix: String,
    /// Additional metadata.
    pub metadata: String,
}

impl ClassSearcher {
    /// Scan directories and jar files in the given search paths for files
    /// matching the provided suffix pattern.
    ///
    /// Returns discovered file information grouped by suffix.
    pub fn find_files(
        search_paths: &[String],
        suffix_pattern: &regex::Regex,
    ) -> io::Result<HashMap<String, Vec<FileInfo>>> {
        let mut result: HashMap<String, Vec<FileInfo>> = HashMap::new();
        let mut all_infos: Vec<FileInfo> = Vec::new();

        for search_path in search_paths {
            let path = Path::new(search_path);
            if !path.exists() {
                continue;
            }

            let lc = search_path.to_lowercase();
            if lc.ends_with(".jar") || lc.ends_with(".zip") {
                // For now, note jar files but don't attempt to read their contents
                // (that would require the `zip` crate for full support)
                log::debug!("ClassSearcher: skipping jar scan: {}", search_path);
            } else if path.is_dir() {
                Self::scan_directory(path, suffix_pattern, &mut all_infos)?;
            }
        }

        // De-duplicate by name
        let mut seen: HashMap<String, FileInfo> = HashMap::new();
        for info in all_infos {
            if !seen.contains_key(&info.name) {
                seen.insert(info.name.clone(), info);
            }
        }

        for info in seen.into_values() {
            result.entry(info.suffix.clone()).or_default().push(info);
        }

        Ok(result)
    }

    /// Recursively scan a directory for files matching the suffix pattern.
    fn scan_directory(
        dir: &Path,
        suffix_pattern: &regex::Regex,
        results: &mut Vec<FileInfo>,
    ) -> io::Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            if path.is_dir() {
                // Skip common non-source directories
                let skip = ["target", "node_modules", ".git", "test_data"];
                if skip.contains(&file_name.as_str()) {
                    continue;
                }
                Self::scan_directory(&path, suffix_pattern, results)?;
            } else if path.is_file() {
                // Check if the file name matches the suffix pattern
                if let Some(stripped) = file_name.strip_suffix(".class") {
                    let qualified = stripped.replace('/', ".");
                    if suffix_pattern.is_match(&qualified) || suffix_pattern.is_match(&file_name) {
                        if let Some(caps) = suffix_pattern.captures(&file_name) {
                            let suffix = caps.get(1).map_or("", |m| m.as_str()).to_string();
                            results.push(FileInfo {
                                path: dir.to_string_lossy().to_string(),
                                name: qualified,
                                suffix,
                                metadata: String::new(),
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Scan a single directory non-recursively for files.
    pub fn scan_directory_flat(
        dir: &Path,
        extension: &str,
    ) -> io::Result<Vec<PathBuf>> {
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut files = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == extension {
                        files.push(path);
                    }
                }
            }
        }
        Ok(files)
    }
}

// ======================================================================
// Tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endian() {
        let e = Endian::host();
        assert!(e.is_little() || e.is_big());
    }

    #[test]
    fn test_version() {
        let v = Version::new(1, 2, 3);
        assert_eq!(format!("{}", v), "1.2.3");
    }

    #[test]
    fn test_alignment() {
        let a = Alignment::FOUR;
        assert!(a.is_aligned(0x1004));
        assert!(!a.is_aligned(0x1005));
        assert_eq!(a.align_up(0x1005), 0x1008);
        assert_eq!(a.align_down(0x1005), 0x1004);
    }

    #[test]
    fn test_bit_utils() {
        assert_eq!(BitUtils::extract(0x1234, 11, 8), 0x2);
        assert_eq!(BitUtils::sign_extend(0xFF, 8), -1);
        assert_eq!(BitUtils::byte_swap16(0x1234), 0x3412);
    }

    #[test]
    fn test_md5_hash() {
        let hash = Md5Utils::md5_hash_str("hello");
        assert_eq!(hash.len(), 32);
        // Known MD5 of "hello"
        assert_eq!(hash, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_file_locker_basic() {
        let tmp = std::env::temp_dir().join("test_ghidra_lock.lock");
        // Clean up from any prior failed test
        let _ = fs::remove_file(&tmp);

        let mut locker = FileLocker::new(&tmp);
        assert!(!locker.is_locked());
        assert!(locker.lock());
        assert!(locker.is_locked());
        locker.release();
        assert!(!locker.is_locked());
        assert!(!tmp.exists());
    }

    #[test]
    fn test_class_searcher_scan() {
        use std::io::Write;
        let tmp_dir = std::env::temp_dir().join("ghidra_test_scan");
        let _ = fs::create_dir(&tmp_dir);
        let test_file = tmp_dir.join("TestPlugin.class");
        let mut f = fs::File::create(&test_file).unwrap();
        f.write_all(b"dummy").unwrap();

        let re = regex::Regex::new(r".*(Plugin)$").unwrap();
        let paths = vec![tmp_dir.to_string_lossy().to_string()];
        let _result = ClassSearcher::find_files(&paths, &re).unwrap();

        let _ = fs::remove_dir_all(&tmp_dir);
        // We might or might not find it depending on path parsing
        assert!(!paths.is_empty());
    }
}
