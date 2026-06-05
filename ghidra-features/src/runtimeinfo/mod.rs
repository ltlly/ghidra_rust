//! Runtime Information Plugin
//!
//! Ported from `ghidra.app.plugin.runtimeinfo`.
//!
//! Provides runtime information display including version details,
//! memory usage, installed processors, application layout, and
//! system properties / environment variables.

use std::collections::BTreeMap;

/// The Runtime Information plugin.
///
/// Provides dialog-based display of Ghidra runtime information:
/// version, memory usage, application layout, system properties,
/// environment, installed processors, and extension points.
#[derive(Debug, Clone)]
pub struct RuntimeInfoPlugin {
    /// The plugin name.
    pub name: String,
}

impl RuntimeInfoPlugin {
    /// Plugin name.
    pub const NAME: &'static str = "Runtime Information";

    /// Create a new runtime info plugin.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
        }
    }

    /// Get the supported action names.
    pub fn actions(&self) -> Vec<&str> {
        vec!["Installed Processors", "Runtime Information"]
    }
}

impl Default for RuntimeInfoPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Version information useful for bug reports.
#[derive(Debug, Clone)]
pub struct VersionInfo {
    /// Ghidra version string.
    pub ghidra_version: String,
    /// Ghidra release name.
    pub ghidra_release: String,
    /// Ghidra build date.
    pub ghidra_build_date: String,
    /// Ghidra source revision.
    pub ghidra_revision: String,
    /// Whether running in development mode.
    pub is_development_mode: bool,
    /// Operating system name.
    pub os_name: String,
    /// Operating system architecture.
    pub os_arch: String,
    /// Operating system version.
    pub os_version: String,
    /// OS pretty name (Linux-specific).
    pub os_pretty_name: Option<String>,
    /// Rust version used to build.
    pub rust_version: String,
}

impl VersionInfo {
    /// Gather current version information.
    pub fn gather() -> Self {
        Self {
            ghidra_version: env!("CARGO_PKG_VERSION").to_string(),
            ghidra_release: "Rust Port".to_string(),
            ghidra_build_date: "N/A".to_string(),
            ghidra_revision: "N/A".to_string(),
            is_development_mode: cfg!(debug_assertions),
            os_name: std::env::consts::OS.to_string(),
            os_arch: std::env::consts::ARCH.to_string(),
            os_version: get_os_version(),
            os_pretty_name: get_os_pretty_name(),
            rust_version: get_rust_version(),
        }
    }

    /// Format the version info as a human-readable string.
    pub fn format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Ghidra Version: {}", self.ghidra_version));
        lines.push(format!("Ghidra Release: {}", self.ghidra_release));
        lines.push(format!("Ghidra Build Date: {}", self.ghidra_build_date));
        lines.push(format!("Ghidra Revision: {}", self.ghidra_revision));
        lines.push(format!("Ghidra Development Mode: {}", self.is_development_mode));
        lines.push(format!("OS Name: {}", self.os_name));
        lines.push(format!("OS Arch: {}", self.os_arch));
        lines.push(format!("OS Version: {}", self.os_version));
        if let Some(ref pretty) = self.os_pretty_name {
            lines.push(format!("OS Pretty Name: {}", pretty));
        }
        lines.push(format!("Rust Version: {}", self.rust_version));
        lines.join("\n")
    }
}

/// Memory usage information.
#[derive(Debug, Clone)]
pub struct MemoryUsage {
    /// Maximum memory available (bytes).
    pub max_memory: u64,
    /// Total memory allocated (bytes).
    pub total_memory: u64,
    /// Free memory available (bytes).
    pub free_memory: u64,
}

impl MemoryUsage {
    /// The currently used memory in bytes.
    pub fn used_memory(&self) -> u64 {
        self.total_memory.saturating_sub(self.free_memory)
    }

    /// The maximum memory in MB.
    pub fn max_memory_mb(&self) -> u64 {
        self.max_memory >> 20
    }

    /// The total memory in MB.
    pub fn total_memory_mb(&self) -> u64 {
        self.total_memory >> 20
    }

    /// The free memory in MB.
    pub fn free_memory_mb(&self) -> u64 {
        self.free_memory >> 20
    }

    /// The used memory in MB.
    pub fn used_memory_mb(&self) -> u64 {
        self.used_memory() >> 20
    }

    /// Format memory value as a human-readable string (MB).
    pub fn format_mb(bytes: u64) -> String {
        format!("{}MB", bytes >> 20)
    }
}

/// Application layout information.
#[derive(Debug, Clone)]
pub struct ApplicationLayout {
    /// Process ID.
    pub pid: u64,
    /// Installation directory path.
    pub installation_dir: String,
    /// Settings directory path.
    pub settings_dir: String,
    /// Cache directory path.
    pub cache_dir: String,
    /// Temp directory path.
    pub temp_dir: String,
}

impl ApplicationLayout {
    /// Gather current application layout information.
    pub fn gather() -> Self {
        Self {
            pid: std::process::id() as u64,
            installation_dir: get_env_or_default("GHIDRA_INSTALL_DIR", "N/A"),
            settings_dir: get_env_or_default("GHIDRA_SETTINGS_DIR", "N/A"),
            cache_dir: get_env_or_default("GHIDRA_CACHE_DIR", "N/A"),
            temp_dir: std::env::temp_dir().to_string_lossy().to_string(),
        }
    }

    /// Convert to a key-value map for display.
    pub fn to_map(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert("PID".into(), self.pid.to_string());
        map.insert("Installation Directory".into(), self.installation_dir.clone());
        map.insert("Settings Directory".into(), self.settings_dir.clone());
        map.insert("Cache Directory".into(), self.cache_dir.clone());
        map.insert("Temp Directory".into(), self.temp_dir.clone());
        map
    }
}

/// Installed processor information.
#[derive(Debug, Clone)]
pub struct InstalledProcessors {
    /// Map of processor name to number of variants.
    pub processors: BTreeMap<String, usize>,
}

impl InstalledProcessors {
    /// Create an empty processors map.
    pub fn new() -> Self {
        Self {
            processors: BTreeMap::new(),
        }
    }

    /// Add a processor variant.
    pub fn add_processor(&mut self, name: &str) {
        *self.processors.entry(name.to_string()).or_insert(0) += 1;
    }

    /// Get the total number of processors.
    pub fn total_count(&self) -> usize {
        self.processors.values().sum()
    }
}

impl Default for InstalledProcessors {
    fn default() -> Self {
        Self::new()
    }
}

/// A generic 2-column table model for displaying key-value pairs.
#[derive(Debug, Clone)]
pub struct MapTablePanel<K: Ord, V> {
    /// Panel name.
    pub name: String,
    /// Key column name.
    pub key_column: String,
    /// Value column name.
    pub value_column: String,
    /// The data entries.
    pub entries: Vec<(K, V)>,
}

impl<K: Ord, V> MapTablePanel<K, V> {
    /// Create a new map table panel from a BTreeMap.
    pub fn from_map(name: &str, map: &BTreeMap<K, V>, key_col: &str, val_col: &str) -> Self
    where
        K: Clone,
        V: Clone,
    {
        Self {
            name: name.to_string(),
            key_column: key_col.to_string(),
            value_column: val_col.to_string(),
            entries: map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        }
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// Helper functions
fn get_os_version() -> String {
    std::env::consts::OS.to_string()
}

fn get_os_pretty_name() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
                    let name = value.trim_matches('"');
                    return Some(name.to_string());
                }
            }
        }
        if let Ok(content) = std::fs::read_to_string("/usr/lib/os-release") {
            for line in content.lines() {
                if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
                    let name = value.trim_matches('"');
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

fn get_rust_version() -> String {
    option_env!("RUSTC_VERSION").unwrap_or("unknown").to_string()
}

fn get_env_or_default(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = RuntimeInfoPlugin::new();
        assert_eq!(plugin.name, "Runtime Information");
        assert_eq!(plugin.actions().len(), 2);
    }

    #[test]
    fn test_version_info() {
        let info = VersionInfo::gather();
        assert!(!info.os_name.is_empty());
        assert!(!info.os_arch.is_empty());
        let formatted = info.format();
        assert!(formatted.contains("OS Name:"));
        assert!(formatted.contains("Rust Version:"));
    }

    #[test]
    fn test_memory_usage() {
        let usage = MemoryUsage {
            max_memory: 1024 * 1024 * 1024,   // 1GB
            total_memory: 512 * 1024 * 1024,   // 512MB
            free_memory: 256 * 1024 * 1024,    // 256MB
        };
        assert_eq!(usage.used_memory(), 256 * 1024 * 1024);
        assert_eq!(usage.max_memory_mb(), 1024);
        assert_eq!(usage.total_memory_mb(), 512);
        assert_eq!(usage.free_memory_mb(), 256);
        assert_eq!(usage.used_memory_mb(), 256);
    }

    #[test]
    fn test_memory_format() {
        assert_eq!(MemoryUsage::format_mb(1024 * 1024 * 100), "100MB");
        assert_eq!(MemoryUsage::format_mb(1024 * 1024), "1MB");
    }

    #[test]
    fn test_application_layout() {
        let layout = ApplicationLayout::gather();
        assert!(layout.pid > 0);
        let map = layout.to_map();
        assert!(map.contains_key("PID"));
        assert!(map.contains_key("Temp Directory"));
    }

    #[test]
    fn test_installed_processors() {
        let mut procs = InstalledProcessors::new();
        procs.add_processor("x86");
        procs.add_processor("x86");
        procs.add_processor("ARM");
        assert_eq!(procs.processors["x86"], 2);
        assert_eq!(procs.processors["ARM"], 1);
        assert_eq!(procs.total_count(), 3);
    }

    #[test]
    fn test_map_table_panel() {
        let mut map = BTreeMap::new();
        map.insert("key1".to_string(), "val1".to_string());
        map.insert("key2".to_string(), "val2".to_string());
        let panel = MapTablePanel::from_map("Test", &map, "Key", "Value");
        assert_eq!(panel.len(), 2);
        assert!(!panel.is_empty());
        assert_eq!(panel.name, "Test");
    }

    #[test]
    fn test_empty_map_table_panel() {
        let map: BTreeMap<String, String> = BTreeMap::new();
        let panel = MapTablePanel::from_map("Empty", &map, "K", "V");
        assert!(panel.is_empty());
    }
}
