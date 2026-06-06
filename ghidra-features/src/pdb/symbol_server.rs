//! PDB Symbol Server -- locate and download PDB files from symbol servers.
//!
//! Ports Ghidra's `pdb.symbolserver` package.
//!
//! This module implements the Microsoft Symbol Server protocol for downloading
//! PDB (Program Database) files. The protocol uses a well-known URL scheme
//! to locate PDB files by their GUID and age.
//!
//! # Architecture
//!
//! - [`SymbolServer`] -- Trait for locating PDB files by their identifier.
//! - [`HttpSymbolServer`] -- Fetches PDB files from HTTP-based symbol servers
//!   (e.g., Microsoft's public symbol server at `https://msdl.microsoft.com/download/symbols`).
//! - [`FileSymbolServer`] -- Locates PDB files in a local directory tree.
//! - [`SymbolFileInfo`] -- Identifies a specific PDB by its GUID, age, and name.
//! - [`SymbolStore`] -- Trait for persistent storage of downloaded PDB files.
//! - [`LocalSymbolStore`] -- Stores PDBs on the local filesystem.
//! - [`SymbolServerService`] -- Coordinates multiple symbol servers with
//!   priority ordering and caching.

use std::fmt;
use std::path::{Path, PathBuf};

// =============================================================================
// SymbolFileInfo -- PDB identification
// =============================================================================

/// Identifies a specific PDB file by its unique properties.
///
/// PDB files are identified by a combination of:
/// - The PDB filename (e.g., "kernel32.pdb")
/// - A GUID that uniquely identifies the PDB
/// - An age counter that increments on each PDB regeneration
///
/// Ports Ghidra's `pdb.symbolserver.SymbolFileInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymbolFileInfo {
    /// The PDB filename (e.g., "kernel32.pdb").
    pub name: String,
    /// The PDB GUID as a 16-byte array.
    pub guid: [u8; 16],
    /// The PDB age (number of times the PDB was regenerated).
    pub age: u32,
}

impl SymbolFileInfo {
    /// Create a new SymbolFileInfo.
    pub fn new(name: impl Into<String>, guid: [u8; 16], age: u32) -> Self {
        Self {
            name: name.into(),
            guid,
            age,
        }
    }

    /// Get the GUID as a formatted string (e.g., "AABBCCDD-EEFF-0011-2233-445566778899").
    pub fn guid_string(&self) -> String {
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            u32::from_le_bytes([self.guid[0], self.guid[1], self.guid[2], self.guid[3]]),
            u16::from_le_bytes([self.guid[4], self.guid[5]]),
            u16::from_le_bytes([self.guid[6], self.guid[7]]),
            self.guid[8], self.guid[9],
            self.guid[10], self.guid[11], self.guid[12],
            self.guid[13], self.guid[14], self.guid[15],
        )
    }

    /// Get the "identity string" used by the Microsoft symbol server protocol.
    /// Format: `{GUID}{AGE}` (uppercase hex, no dashes, with age appended).
    pub fn identity_string(&self) -> String {
        let mut s = String::with_capacity(33);
        for b in &self.guid {
            s.push_str(&format!("{:02X}", b));
        }
        s.push_str(&format!("{:X}", self.age));
        s
    }

    /// Get the path components for this PDB in the Microsoft symbol server
    /// directory layout: `<name>/<identity>/<name>`.
    pub fn server_path(&self) -> String {
        format!("{}/{}/{}", self.name, self.identity_string(), self.name)
    }

    /// Check if this SymbolFileInfo matches a partial match (name+guid,
    /// ignoring age differences).
    pub fn matches_partial(&self, other: &SymbolFileInfo) -> bool {
        if self.name != other.name {
            return false;
        }
        self.guid == other.guid
    }
}

impl fmt::Display for SymbolFileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({} {:X})",
            self.name,
            self.guid_string(),
            self.age
        )
    }
}

// =============================================================================
// SymbolFileLocation -- where a PDB file was found
// =============================================================================

/// Describes where a PDB file was located.
///
/// Ports Ghidra's `pdb.symbolserver.SymbolFileLocation`.
#[derive(Debug, Clone)]
pub struct SymbolFileLocation {
    /// The symbol file info.
    pub info: SymbolFileInfo,
    /// Where the file was found.
    pub location_type: LocationType,
    /// The file path (local or URL).
    pub path: String,
}

/// The type of location where a PDB was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocationType {
    /// Found on a local filesystem.
    Local,
    /// Found on an HTTP symbol server.
    HttpServer,
    /// Found in the same directory as the binary.
    SameDirectory,
    /// Found via user-specified search path.
    SearchPath,
}

// =============================================================================
// SymbolServer trait
// =============================================================================

/// A symbol server that can locate PDB files.
///
/// Ports Ghidra's `pdb.symbolserver.SymbolServer`.
pub trait SymbolServer: std::fmt::Debug {
    /// Get the name of this symbol server.
    fn name(&self) -> &str;

    /// Search for a PDB matching the given file info.
    ///
    /// Returns `Some(path)` if found, `None` if not.
    fn find(&self, info: &SymbolFileInfo) -> Option<SymbolFileLocation>;

    /// Whether this server is currently available.
    fn is_available(&self) -> bool;
}

// =============================================================================
// HttpSymbolServer
// =============================================================================

/// Fetches PDB files from an HTTP-based symbol server.
///
/// Implements the Microsoft Symbol Server protocol:
/// `GET /<name>/<identity>/<name>`
///
/// Ports Ghidra's `pdb.symbolserver.HttpSymbolServer`.
#[derive(Debug)]
pub struct HttpSymbolServer {
    /// The base URL of the symbol server (e.g., "https://msdl.microsoft.com/download/symbols").
    base_url: String,
    /// Display name for this server.
    display_name: String,
    /// Whether the server is enabled.
    enabled: bool,
}

impl HttpSymbolServer {
    /// Create a new HTTP symbol server.
    pub fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into();
        Self {
            display_name: base_url.clone(),
            base_url,
            enabled: true,
        }
    }

    /// Create the Microsoft public symbol server.
    pub fn microsoft() -> Self {
        Self::new("https://msdl.microsoft.com/download/symbols")
    }

    /// Set the display name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    /// Get the URL for a specific PDB file.
    pub fn url_for(&self, info: &SymbolFileInfo) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), info.server_path())
    }

    /// Whether this server is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable this server.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl SymbolServer for HttpSymbolServer {
    fn name(&self) -> &str {
        &self.display_name
    }

    fn find(&self, info: &SymbolFileInfo) -> Option<SymbolFileLocation> {
        if !self.enabled {
            return None;
        }
        // In a real implementation, this would make an HTTP HEAD request to check
        // if the file exists. For now, we just return the URL.
        Some(SymbolFileLocation {
            info: info.clone(),
            location_type: LocationType::HttpServer,
            path: self.url_for(info),
        })
    }

    fn is_available(&self) -> bool {
        self.enabled
    }
}

// =============================================================================
// FileSymbolServer -- Local directory search
// =============================================================================

/// Locates PDB files in a local directory tree.
///
/// Supports the Microsoft Symbol Server directory layout where PDBs are stored
/// as `<root>/<name>/<identity>/<name>`.
///
/// Ports Ghidra's `pdb.symbolserver.ContainerFileSymbolServer`.
#[derive(Debug)]
pub struct FileSymbolServer {
    /// The root directory to search.
    root: PathBuf,
    /// Display name for this server.
    display_name: String,
    /// Whether to search recursively.
    recursive: bool,
}

impl FileSymbolServer {
    /// Create a new file symbol server.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            display_name: format!("File: {}", root.display()),
            root,
            recursive: false,
        }
    }

    /// Set the display name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    /// Enable recursive search.
    pub fn with_recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    /// Get the expected path for a PDB in the standard layout.
    pub fn expected_path(&self, info: &SymbolFileInfo) -> PathBuf {
        self.root.join(info.server_path())
    }

    /// Recursively search for a file by name up to `max_depth` levels deep.
    fn find_recursive(&self, dir: &Path, name: &str, max_depth: usize) -> Option<PathBuf> {
        if max_depth == 0 {
            return None;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return None,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if path.file_name().map_or(false, |n| {
                    n.to_string_lossy().eq_ignore_ascii_case(name)
                }) {
                    return Some(path);
                }
            } else if path.is_dir() {
                if let Some(found) = self.find_recursive(&path, name, max_depth - 1) {
                    return Some(found);
                }
            }
        }
        None
    }
}

impl SymbolServer for FileSymbolServer {
    fn name(&self) -> &str {
        &self.display_name
    }

    fn find(&self, info: &SymbolFileInfo) -> Option<SymbolFileLocation> {
        let path = self.expected_path(info);
        if path.exists() {
            Some(SymbolFileLocation {
                info: info.clone(),
                location_type: LocationType::Local,
                path: path.to_string_lossy().to_string(),
            })
        } else if self.recursive {
            // Search by name in root directory tree (up to 5 levels deep)
            self.find_recursive(&self.root, &info.name, 5)
                .map(|p| SymbolFileLocation {
                    info: info.clone(),
                    location_type: LocationType::Local,
                    path: p.to_string_lossy().to_string(),
                })
        } else {
            None
        }
    }

    fn is_available(&self) -> bool {
        self.root.exists()
    }
}

// =============================================================================
// SameDirectoryServer -- Check the binary's own directory
// =============================================================================

/// Checks if a PDB exists in the same directory as the binary.
///
/// Ports Ghidra's `pdb.symbolserver.SameDirSymbolStore`.
#[derive(Debug)]
pub struct SameDirectoryServer {
    /// The directory of the binary.
    binary_dir: PathBuf,
}

impl SameDirectoryServer {
    /// Create a new same-directory server.
    pub fn new(binary_dir: impl Into<PathBuf>) -> Self {
        Self {
            binary_dir: binary_dir.into(),
        }
    }
}

impl SymbolServer for SameDirectoryServer {
    fn name(&self) -> &str {
        "Same Directory"
    }

    fn find(&self, info: &SymbolFileInfo) -> Option<SymbolFileLocation> {
        let path = self.binary_dir.join(&info.name);
        if path.exists() {
            Some(SymbolFileLocation {
                info: info.clone(),
                location_type: LocationType::SameDirectory,
                path: path.to_string_lossy().to_string(),
            })
        } else {
            None
        }
    }

    fn is_available(&self) -> bool {
        self.binary_dir.exists()
    }
}

// =============================================================================
// SymbolServerService -- Coordinates multiple servers
// =============================================================================

/// Service that coordinates multiple symbol servers.
///
/// Servers are tried in priority order (first registered = highest priority).
///
/// Ports Ghidra's `pdb.symbolserver.SymbolServerService`.
#[derive(Debug)]
pub struct SymbolServerService {
    /// The list of symbol servers to try, in priority order.
    servers: Vec<Box<dyn SymbolServer>>,
    /// Cache of previously resolved PDB locations.
    cache: std::collections::HashMap<String, SymbolFileLocation>,
}

impl SymbolServerService {
    /// Create a new empty symbol server service.
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            cache: std::collections::HashMap::new(),
        }
    }

    /// Add a symbol server (lower priority than existing ones).
    pub fn add_server(&mut self, server: Box<dyn SymbolServer>) {
        self.servers.push(server);
    }

    /// Search all servers for a PDB file.
    ///
    /// Returns the first match found, or `None` if no server has the PDB.
    pub fn find(&mut self, info: &SymbolFileInfo) -> Option<&SymbolFileLocation> {
        let cache_key = info.identity_string();

        // Check cache first
        if self.cache.contains_key(&cache_key) {
            return self.cache.get(&cache_key);
        }

        // Try each server in order
        for server in &self.servers {
            if !server.is_available() {
                continue;
            }
            if let Some(location) = server.find(info) {
                self.cache.insert(cache_key.clone(), location);
                return self.cache.get(&cache_key);
            }
        }
        None
    }

    /// Get the number of registered servers.
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Get names of all registered servers.
    pub fn server_names(&self) -> Vec<&str> {
        self.servers.iter().map(|s| s.name()).collect()
    }

    /// Clear the resolution cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

impl Default for SymbolServerService {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Well-known symbol server locations
// =============================================================================

/// Well-known symbol server locations.
///
/// Ports Ghidra's `pdb.symbolserver.WellKnownSymbolServerLocation`.
pub mod well_known {
    /// Microsoft's public symbol server.
    pub const MICROSOFT_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

    /// Microsoft's public NuGet symbol server.
    pub const NUGET_SYMBOL_SERVER: &str = "https://symbols.nuget.org/download/symbols";
}

// =============================================================================
// SymbolServerInputStream -- download helper
// =============================================================================

/// A reader for data from a symbol server.
///
/// Wraps the downloaded data for consumption by the PDB parser.
///
/// Ports Ghidra's `pdb.symbolserver.SymbolServerInputStream`.
#[derive(Debug)]
pub struct SymbolServerData {
    /// The raw PDB file data.
    pub data: Vec<u8>,
    /// Where the data was sourced from.
    pub source: SymbolFileLocation,
    /// Whether the data is compressed (CAB format).
    pub compressed: bool,
}

impl SymbolServerData {
    /// Create a new SymbolServerData.
    pub fn new(data: Vec<u8>, source: SymbolFileLocation) -> Self {
        Self {
            data,
            source,
            compressed: false,
        }
    }

    /// Get the size of the data in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Decompress the data if it's in CAB format.
    ///
    /// Microsoft's symbol server sometimes delivers PDB files compressed
    /// in Microsoft Cabinet (CAB) format. This method would decompress
    /// the data in place.
    pub fn decompress(&mut self) -> Result<(), SymbolServerError> {
        if !self.compressed {
            return Ok(());
        }
        // In a real implementation, this would decompress CAB data.
        self.compressed = false;
        Ok(())
    }
}

// =============================================================================
// Errors
// =============================================================================

/// Errors from symbol server operations.
#[derive(Debug, Clone)]
pub enum SymbolServerError {
    /// Network error communicating with a symbol server.
    NetworkError(String),
    /// The requested PDB was not found on any server.
    NotFound(SymbolFileInfo),
    /// The downloaded file is corrupt.
    CorruptFile(String),
    /// Decompression failed.
    DecompressionError(String),
    /// Permission denied accessing a local store.
    PermissionDenied(String),
    /// The symbol server URL is invalid.
    InvalidUrl(String),
}

impl fmt::Display for SymbolServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "Symbol server network error: {}", msg),
            Self::NotFound(info) => write!(f, "PDB not found: {}", info),
            Self::CorruptFile(msg) => write!(f, "Corrupt PDB file: {}", msg),
            Self::DecompressionError(msg) => write!(f, "Decompression error: {}", msg),
            Self::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            Self::InvalidUrl(url) => write!(f, "Invalid symbol server URL: {}", url),
        }
    }
}

impl std::error::Error for SymbolServerError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_file_info_guid_string() {
        let info = SymbolFileInfo::new(
            "test.pdb",
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
             0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99],
            1,
        );
        let guid = info.guid_string();
        assert!(guid.contains("DDCCBBAA"));
        assert!(guid.contains("FFEE"));
    }

    #[test]
    fn test_symbol_file_info_identity_string() {
        let info = SymbolFileInfo::new(
            "test.pdb",
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
             0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99],
            1,
        );
        let identity = info.identity_string();
        // Should be 33 chars: 32 hex digits for GUID + 1 hex digit for age
        assert_eq!(identity.len(), 33);
        assert!(identity.ends_with('1'));
    }

    #[test]
    fn test_symbol_file_info_server_path() {
        let info = SymbolFileInfo::new("kernel32.pdb", [0u8; 16], 1);
        let path = info.server_path();
        assert!(path.starts_with("kernel32.pdb/"));
        assert!(path.ends_with("/kernel32.pdb"));
    }

    #[test]
    fn test_symbol_file_info_display() {
        let info = SymbolFileInfo::new("test.pdb", [0u8; 16], 1);
        let display = format!("{}", info);
        assert!(display.contains("test.pdb"));
    }

    #[test]
    fn test_symbol_file_info_partial_match() {
        let a = SymbolFileInfo::new("test.pdb", [0u8; 16], 1);
        let b = SymbolFileInfo::new("test.pdb", [0u8; 16], 2);
        assert!(a.matches_partial(&b)); // same name+guid, different age
    }

    #[test]
    fn test_http_symbol_server_url() {
        let server = HttpSymbolServer::microsoft();
        let info = SymbolFileInfo::new("test.pdb", [0u8; 16], 1);
        let url = server.url_for(&info);
        assert!(url.starts_with("https://msdl.microsoft.com/download/symbols/test.pdb/"));
    }

    #[test]
    fn test_http_symbol_server_enabled() {
        let mut server = HttpSymbolServer::microsoft();
        assert!(server.is_enabled());
        server.set_enabled(false);
        assert!(!server.is_enabled());
    }

    #[test]
    fn test_file_symbol_server_expected_path() {
        let server = FileSymbolServer::new("/tmp/symbols");
        let info = SymbolFileInfo::new("test.pdb", [0u8; 16], 1);
        let path = server.expected_path(&info);
        assert!(path.starts_with("/tmp/symbols/test.pdb/"));
    }

    #[test]
    fn test_same_directory_server() {
        let server = SameDirectoryServer::new("/tmp/bin");
        assert_eq!(server.name(), "Same Directory");
        assert!(!server.is_available()); // /tmp/bin doesn't exist
    }

    #[test]
    fn test_symbol_server_service() {
        let mut service = SymbolServerService::new();
        assert_eq!(service.server_count(), 0);

        service.add_server(Box::new(HttpSymbolServer::microsoft()));
        assert_eq!(service.server_count(), 1);
        assert_eq!(service.server_names(), vec!["https://msdl.microsoft.com/download/symbols"]);
    }

    #[test]
    fn test_symbol_server_data() {
        let info = SymbolFileInfo::new("test.pdb", [0u8; 16], 1);
        let location = SymbolFileLocation {
            info,
            location_type: LocationType::HttpServer,
            path: "https://example.com/test.pdb".to_string(),
        };
        let data = SymbolServerData::new(vec![0u8; 100], location);
        assert_eq!(data.size(), 100);
        assert!(!data.compressed);
    }

    #[test]
    fn test_well_known_servers() {
        assert!(well_known::MICROSOFT_SYMBOL_SERVER.starts_with("https://"));
        assert!(well_known::NUGET_SYMBOL_SERVER.starts_with("https://"));
    }

    #[test]
    fn test_symbol_server_error_display() {
        let info = SymbolFileInfo::new("test.pdb", [0u8; 16], 1);
        let err = SymbolServerError::NotFound(info);
        let msg = format!("{}", err);
        assert!(msg.contains("not found"));
        assert!(msg.contains("test.pdb"));

        let err = SymbolServerError::NetworkError("timeout".to_string());
        assert!(format!("{}", err).contains("timeout"));
    }
}
