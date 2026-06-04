//! Skeleton plugin templates for Ghidra extensions.
//!
//! Port of Ghidra's `skeleton` package.
//!
//! These types model the extension points (Plugin, Analyzer, Loader, Exporter, FileSystem)
//! that a Ghidra extension can implement. They serve as templates and documentation
//! for building real extensions in Rust.

use std::collections::HashMap;
use std::io;

// ---------------------------------------------------------------------------
// Plugin skeleton
// ---------------------------------------------------------------------------

/// Status of a plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus {
    Stable,
    Release,
    StableAdded,
    ReleaseAdded,
    StableModified,
    ReleaseModified,
    Deprecated,
    ProofOfConcept,
}

/// Information about a Ghidra plugin.
#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub status: PluginStatus,
    pub package_name: String,
    pub category: String,
    pub short_description: String,
    pub description: String,
}

impl Default for PluginInfo {
    fn default() -> Self {
        Self {
            status: PluginStatus::Stable,
            package_name: "Examples".to_string(),
            category: "Examples".to_string(),
            short_description: "Plugin short description goes here.".to_string(),
            description: "Plugin long description goes here.".to_string(),
        }
    }
}

/// A skeleton Ghidra plugin.
///
/// In the Java source this extends `ProgramPlugin`. In the Rust port we model
/// the metadata and lifecycle hooks rather than the full Swing UI integration.
#[derive(Debug, Clone)]
pub struct SkeletonPlugin {
    info: PluginInfo,
    name: String,
}

impl SkeletonPlugin {
    /// Create a new skeleton plugin.
    pub fn new(name: &str) -> Self {
        Self {
            info: PluginInfo::default(),
            name: name.to_string(),
        }
    }

    /// Create with specific plugin info.
    pub fn with_info(name: &str, info: PluginInfo) -> Self {
        Self {
            info,
            name: name.to_string(),
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the plugin info.
    pub fn info(&self) -> &PluginInfo {
        &self.info
    }

    /// Called when the plugin is initialized.
    pub fn init(&self) {
        // Override in real implementation
    }
}

// ---------------------------------------------------------------------------
// Analyzer skeleton
// ---------------------------------------------------------------------------

/// Type of analyzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalyzerType {
    ByteAnalyzer,
    DataAnalyzer,
    FunctionAnalyzer,
    InstructionAnalyzer,
    OneShotAnalyzer,
}

/// Options for an analyzer.
#[derive(Debug, Clone)]
pub struct Options {
    entries: HashMap<String, OptionValue>,
}

/// Value for an analyzer option.
#[derive(Debug, Clone)]
pub enum OptionValue {
    Bool(bool),
    Int(i64),
    String(String),
}

impl Default for Options {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl Options {
    /// Register an option.
    pub fn register_option(&mut self, name: &str, default: OptionValue, description: &str) {
        self.entries.insert(name.to_string(), default);
        let _ = description; // stored for docs only
    }

    /// Get a boolean option value.
    pub fn get_bool(&self, name: &str) -> Option<bool> {
        match self.entries.get(name)? {
            OptionValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Get a string option value.
    pub fn get_string(&self, name: &str) -> Option<&str> {
        match self.entries.get(name)? {
            OptionValue::String(v) => Some(v),
            _ => None,
        }
    }
}

/// A skeleton analyzer.
#[derive(Debug, Clone)]
pub struct SkeletonAnalyzer {
    name: String,
    description: String,
    #[allow(dead_code)]
    analyzer_type: AnalyzerType,
}

impl SkeletonAnalyzer {
    /// Create a new skeleton analyzer.
    pub fn new() -> Self {
        Self {
            name: "My Analyzer".to_string(),
            description: "Analyzer description goes here".to_string(),
            analyzer_type: AnalyzerType::ByteAnalyzer,
        }
    }

    /// Returns the analyzer name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the analyzer description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the default enablement (true by default).
    pub fn default_enablement(&self) -> bool {
        true
    }

    /// Check if this analyzer can analyze the given program.
    pub fn can_analyze(&self) -> bool {
        true
    }

    /// Register custom options.
    pub fn register_options(&self, options: &mut Options) {
        options.register_option(
            "Option name goes here",
            OptionValue::Bool(false),
            "Option description goes here",
        );
    }
}

impl Default for SkeletonAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Loader skeleton
// ---------------------------------------------------------------------------

/// Represents a load specification for a loader.
#[derive(Debug, Clone)]
pub struct LoadSpec {
    pub name: String,
    pub language_id: String,
    pub compiler_id: String,
}

/// A skeleton loader.
#[derive(Debug, Clone)]
pub struct SkeletonLoader {
    name: String,
}

impl SkeletonLoader {
    /// Create a new skeleton loader.
    pub fn new() -> Self {
        Self {
            name: "My loader".to_string(),
        }
    }

    /// Returns the loader name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Examines provider bytes and returns supported load specs.
    pub fn find_supported_load_specs(&self, _data: &[u8]) -> Vec<LoadSpec> {
        // Examine bytes and return load specs in real implementation
        Vec::new()
    }

    /// Returns the default options for this loader.
    pub fn default_options(&self) -> Vec<(String, String)> {
        vec![(
            "Option name goes here".to_string(),
            "Default option value goes here".to_string(),
        )]
    }
}

impl Default for SkeletonLoader {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Exporter skeleton
// ---------------------------------------------------------------------------

/// A skeleton exporter.
#[derive(Debug, Clone)]
pub struct SkeletonExporter {
    name: String,
    extension: String,
}

impl SkeletonExporter {
    /// Create a new skeleton exporter.
    pub fn new() -> Self {
        Self {
            name: "My Exporter".to_string(),
            extension: "exp".to_string(),
        }
    }

    /// Returns the exporter name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the file extension.
    pub fn extension(&self) -> &str {
        &self.extension
    }

    /// Whether address-restricted export is supported.
    pub fn supports_address_restricted_export(&self) -> bool {
        false
    }

    /// Returns the default options for this exporter.
    pub fn options(&self) -> Vec<(String, String)> {
        vec![(
            "Option name goes here".to_string(),
            "Default option value goes here".to_string(),
        )]
    }
}

impl Default for SkeletonExporter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FileSystem skeleton
// ---------------------------------------------------------------------------

/// Metadata for a file in a custom file system.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub offset: u64,
    pub size: u64,
}

/// A skeleton file system.
#[derive(Debug, Clone)]
pub struct SkeletonFileSystem {
    fs_type: String,
    description: String,
    name: String,
    entries: Vec<FileEntry>,
    closed: bool,
}

impl SkeletonFileSystem {
    /// Create a new skeleton file system.
    pub fn new(name: &str) -> Self {
        Self {
            fs_type: "fstypegoeshere".to_string(),
            description: "File system description goes here".to_string(),
            name: name.to_string(),
            entries: Vec::new(),
            closed: false,
        }
    }

    /// Returns the file system type.
    pub fn fs_type(&self) -> &str {
        &self.fs_type
    }

    /// Returns the file system description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the file system name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the file system is closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Returns the number of files.
    pub fn file_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns a reference to the file entries.
    pub fn entries(&self) -> &[FileEntry] {
        &self.entries
    }

    /// Add a file entry.
    pub fn add_entry(&mut self, entry: FileEntry) {
        self.entries.push(entry);
    }

    /// Mount the file system (parse entries from provider data).
    pub fn mount(&mut self, _data: &[u8]) {
        // Parse data and populate entries in real implementation
    }

    /// Close the file system.
    pub fn close(&mut self) {
        self.closed = true;
        self.entries.clear();
    }

    /// Look up a file by path.
    pub fn lookup(&self, path: &str) -> Option<&FileEntry> {
        self.entries.iter().find(|e| e.path == path)
    }

    /// Get the byte range for a file entry.
    pub fn get_bytes<'a>(&self, data: &'a [u8], entry: &FileEntry) -> io::Result<&'a [u8]> {
        let start = entry.offset as usize;
        let end = start + entry.size as usize;
        if end <= data.len() {
            Ok(&data[start..end])
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "File entry extends beyond data",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skeleton_plugin() {
        let plugin = SkeletonPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert_eq!(plugin.info().status, PluginStatus::Stable);
        assert_eq!(plugin.info().category, "Examples");
    }

    #[test]
    fn test_skeleton_analyzer() {
        let analyzer = SkeletonAnalyzer::new();
        assert_eq!(analyzer.name(), "My Analyzer");
        assert!(analyzer.default_enablement());
        assert!(analyzer.can_analyze());
    }

    #[test]
    fn test_analyzer_options() {
        let analyzer = SkeletonAnalyzer::new();
        let mut options = Options::default();
        analyzer.register_options(&mut options);
        assert_eq!(options.get_bool("Option name goes here"), Some(false));
    }

    #[test]
    fn test_skeleton_loader() {
        let loader = SkeletonLoader::new();
        assert_eq!(loader.name(), "My loader");
        assert!(loader.find_supported_load_specs(&[]).is_empty());
    }

    #[test]
    fn test_skeleton_exporter() {
        let exporter = SkeletonExporter::new();
        assert_eq!(exporter.name(), "My Exporter");
        assert_eq!(exporter.extension(), "exp");
        assert!(!exporter.supports_address_restricted_export());
    }

    #[test]
    fn test_skeleton_filesystem() {
        let mut fs = SkeletonFileSystem::new("test.img");
        assert_eq!(fs.name(), "test.img");
        assert!(!fs.is_closed());
        assert_eq!(fs.file_count(), 0);

        fs.add_entry(FileEntry {
            name: "file.txt".to_string(),
            path: "/file.txt".to_string(),
            offset: 0,
            size: 10,
        });
        assert_eq!(fs.file_count(), 1);
        assert!(fs.lookup("/file.txt").is_some());
        assert!(fs.lookup("/missing.txt").is_none());

        let data = b"0123456789extra";
        let entry = fs.lookup("/file.txt").unwrap();
        let bytes = fs.get_bytes(data, entry).unwrap();
        assert_eq!(bytes, b"0123456789");

        fs.close();
        assert!(fs.is_closed());
        assert_eq!(fs.file_count(), 0);
    }
}
