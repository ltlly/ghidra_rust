//! Database-backed guest platform management.
//!
//! Ported from Ghidra's `ghidra.trace.database.guest` package in
//! Framework-TraceModeling. Provides types for managing guest platform
//! registrations and address range mappings within a trace database.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::guest::TraceGuestPlatformMappedRange;

/// A guest language entry in the trace database.
///
/// Ported from Ghidra's `DBTraceGuestLanguage`. Stores a registered
/// language definition with version information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceGuestLanguage {
    /// Unique key for this language entry.
    pub key: i64,
    /// Language ID (e.g., "x86:LE:64:default").
    pub language_id: String,
    /// Language version.
    pub version: i32,
    /// Language minor version.
    pub minor_version: i32,
}

impl DbTraceGuestLanguage {
    /// Create a new guest language entry.
    pub fn new(key: i64, language_id: impl Into<String>, version: i32, minor_version: i32) -> Self {
        Self {
            key,
            language_id: language_id.into(),
            version,
            minor_version,
        }
    }

    /// Whether this language entry matches the given language ID.
    pub fn matches(&self, language_id: &str) -> bool {
        self.language_id == language_id
    }
}

/// A guest platform entry in the trace database.
///
/// Ported from Ghidra's `DBTraceGuestPlatform`. Represents a registered
/// guest architecture/platform with its compiler specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceGuestPlatform {
    /// Unique key for this platform entry.
    pub key: i64,
    /// Key into the language table.
    pub language_key: i64,
    /// Compiler spec ID (e.g., "default", "gcc").
    pub compiler_spec_id: String,
    /// Language ID for quick access.
    pub language_id: String,
    /// Host-to-guest address mappings.
    pub mapped_ranges: Vec<TraceGuestPlatformMappedRange>,
}

impl DbTraceGuestPlatform {
    /// Create a new guest platform entry.
    pub fn new(
        key: i64,
        language_key: i64,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            key,
            language_key,
            compiler_spec_id: compiler_spec_id.into(),
            language_id: language_id.into(),
            mapped_ranges: Vec::new(),
        }
    }

    /// Whether this platform is a guest (not the host).
    pub fn is_guest(&self) -> bool {
        true
    }

    /// Add a mapped range from host to guest addresses.
    pub fn add_mapped_range(&mut self, range: TraceGuestPlatformMappedRange) {
        self.mapped_ranges.push(range);
    }

    /// Map a guest address to a host address.
    pub fn map_guest_to_host(&self, guest_addr: u64) -> Option<u64> {
        self.mapped_ranges
            .iter()
            .find_map(|r| r.guest_to_host(guest_addr))
    }

    /// Map a host address to a guest address.
    pub fn map_host_to_guest(&self, host_addr: u64) -> Option<u64> {
        self.mapped_ranges
            .iter()
            .find_map(|r| r.host_to_guest(host_addr))
    }

    /// Remove a mapped range that contains the given guest address.
    pub fn remove_mapped_range_at_guest(&mut self, guest_addr: u64) -> bool {
        let before = self.mapped_ranges.len();
        self.mapped_ranges
            .retain(|r| !(guest_addr >= r.guest_min && guest_addr <= r.guest_max));
        self.mapped_ranges.len() < before
    }

    /// Get all mapped ranges for this platform.
    pub fn mapped_ranges(&self) -> &[TraceGuestPlatformMappedRange] {
        &self.mapped_ranges
    }
}

/// The host platform representation in the database.
///
/// Ported from Ghidra's `DBTraceHostPlatform`. The host platform is the
/// native trace platform, which maps identity (host = guest).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceHostPlatform {
    /// Language ID of the host.
    pub language_id: String,
    /// Compiler spec ID of the host.
    pub compiler_spec_id: String,
}

impl DbTraceHostPlatform {
    /// Create a new host platform.
    pub fn new(
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
        }
    }

    /// Whether this is a guest platform (always false for host).
    pub fn is_guest(&self) -> bool {
        false
    }

    /// Map host to guest (identity for host platform).
    pub fn map_host_to_guest(&self, addr: u64) -> u64 {
        addr
    }

    /// Map guest to host (identity for host platform).
    pub fn map_guest_to_host(&self, addr: u64) -> u64 {
        addr
    }
}

/// The database-backed platform manager.
///
/// Manages all guest platforms, their language entries, and address range
/// mappings. Ported from Ghidra's `DBTracePlatformManager`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTracePlatformManager {
    next_key: i64,
    /// The host platform.
    pub host_platform: DbTraceHostPlatform,
    /// Registered languages, keyed by language key.
    languages: BTreeMap<i64, DbTraceGuestLanguage>,
    /// Registered guest platforms, keyed by platform key.
    platforms: BTreeMap<i64, DbTraceGuestPlatform>,
    /// Map from compiler spec ID to platform key.
    compiler_to_platform: BTreeMap<String, i64>,
    /// Map from language ID to language key.
    language_id_to_key: BTreeMap<String, i64>,
}

impl DbTracePlatformManager {
    /// Create a new platform manager.
    pub fn new(
        host_language_id: impl Into<String>,
        host_compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            next_key: 0,
            host_platform: DbTraceHostPlatform::new(host_language_id, host_compiler_spec_id),
            languages: BTreeMap::new(),
            platforms: BTreeMap::new(),
            compiler_to_platform: BTreeMap::new(),
            language_id_to_key: BTreeMap::new(),
        }
    }

    fn allocate_key(&mut self) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        key
    }

    /// Get or create a language entry for the given language ID.
    pub fn get_or_create_language(
        &mut self,
        language_id: impl Into<String>,
        version: i32,
        minor_version: i32,
    ) -> i64 {
        let lang_id = language_id.into();
        if let Some(&key) = self.language_id_to_key.get(&lang_id) {
            return key;
        }
        let key = self.allocate_key();
        let lang = DbTraceGuestLanguage::new(key, lang_id.clone(), version, minor_version);
        self.language_id_to_key.insert(lang_id, key);
        self.languages.insert(key, lang);
        key
    }

    /// Add a guest platform.
    pub fn add_guest_platform(
        &mut self,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> i64 {
        let lang_id = language_id.into();
        let cspec_id = compiler_spec_id.into();

        // Check for duplicate
        if self.compiler_to_platform.contains_key(&cspec_id) {
            panic!("Guest platform already exists for compiler spec: {}", cspec_id);
        }

        let lang_key = self.get_or_create_language(&lang_id, 0, 0);
        let key = self.allocate_key();
        let platform = DbTraceGuestPlatform::new(key, lang_key, lang_id, cspec_id.clone());

        self.compiler_to_platform.insert(cspec_id, key);
        self.platforms.insert(key, platform);
        key
    }

    /// Get a guest platform by key.
    pub fn get_platform(&self, key: i64) -> Option<&DbTraceGuestPlatform> {
        self.platforms.get(&key)
    }

    /// Get a mutable reference to a guest platform by key.
    pub fn get_platform_mut(&mut self, key: i64) -> Option<&mut DbTraceGuestPlatform> {
        self.platforms.get_mut(&key)
    }

    /// Get a guest platform by compiler spec ID.
    pub fn platform_by_compiler_spec(&self, cspec_id: &str) -> Option<&DbTraceGuestPlatform> {
        self.compiler_to_platform
            .get(cspec_id)
            .and_then(|&key| self.platforms.get(&key))
    }

    /// Get all guest platforms.
    pub fn guest_platforms(&self) -> impl Iterator<Item = &DbTraceGuestPlatform> {
        self.platforms.values()
    }

    /// Delete a guest platform by key.
    pub fn delete_platform(&mut self, key: i64) -> bool {
        if let Some(platform) = self.platforms.remove(&key) {
            self.compiler_to_platform.remove(&platform.compiler_spec_id);
            true
        } else {
            false
        }
    }

    /// Get a language entry by key.
    pub fn get_language(&self, key: i64) -> Option<&DbTraceGuestLanguage> {
        self.languages.get(&key)
    }

    /// The number of registered guest platforms.
    pub fn platform_count(&self) -> usize {
        self.platforms.len()
    }

    /// The number of registered languages.
    pub fn language_count(&self) -> usize {
        self.languages.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Lifespan;

    #[test]
    fn test_guest_language_creation() {
        let lang = DbTraceGuestLanguage::new(1, "ARM:LE:32:v8", 1, 0);
        assert_eq!(lang.key, 1);
        assert!(lang.matches("ARM:LE:32:v8"));
        assert!(!lang.matches("x86:LE:64:default"));
    }

    #[test]
    fn test_guest_platform_creation() {
        let platform = DbTraceGuestPlatform::new(
            1,
            0,
            "ARM:LE:32:v8",
            "default",
        );
        assert!(platform.is_guest());
        assert_eq!(platform.language_id, "ARM:LE:32:v8");
        assert_eq!(platform.mapped_ranges().len(), 0);
    }

    #[test]
    fn test_guest_platform_mapping() {
        let mut platform = DbTraceGuestPlatform::new(1, 0, "ARM:LE:32:v8", "default");
        platform.add_mapped_range(TraceGuestPlatformMappedRange::new(
            1, 0x1000, 0x1fff, 0xf000_0000, Lifespan::ALL,
        ));

        assert_eq!(platform.map_guest_to_host(0x1500), Some(0xf000_0500));
        assert_eq!(platform.map_host_to_guest(0xf000_0500), Some(0x1500));
        assert_eq!(platform.map_guest_to_host(0x2000), None);
    }

    #[test]
    fn test_host_platform_identity() {
        let host = DbTraceHostPlatform::new("x86:LE:64:default", "default");
        assert!(!host.is_guest());
        assert_eq!(host.map_host_to_guest(0x400000), 0x400000);
        assert_eq!(host.map_guest_to_host(0x400000), 0x400000);
    }

    #[test]
    fn test_platform_manager_add_guest() {
        let mut mgr = DbTracePlatformManager::new("x86:LE:64:default", "default");
        let key = mgr.add_guest_platform("ARM:LE:32:v8", "default");

        assert_eq!(mgr.platform_count(), 1);
        assert_eq!(mgr.language_count(), 1);

        let platform = mgr.get_platform(key).unwrap();
        assert_eq!(platform.language_id, "ARM:LE:32:v8");
    }

    #[test]
    fn test_platform_manager_by_compiler_spec() {
        let mut mgr = DbTracePlatformManager::new("x86:LE:64:default", "default");
        mgr.add_guest_platform("ARM:LE:32:v8", "arm-eabi");

        let platform = mgr.platform_by_compiler_spec("arm-eabi");
        assert!(platform.is_some());
        assert_eq!(platform.unwrap().language_id, "ARM:LE:32:v8");

        assert!(mgr.platform_by_compiler_spec("nonexistent").is_none());
    }

    #[test]
    fn test_platform_manager_delete() {
        let mut mgr = DbTracePlatformManager::new("x86:LE:64:default", "default");
        let key = mgr.add_guest_platform("ARM:LE:32:v8", "arm-eabi");
        assert_eq!(mgr.platform_count(), 1);

        assert!(mgr.delete_platform(key));
        assert_eq!(mgr.platform_count(), 0);
        assert!(mgr.platform_by_compiler_spec("arm-eabi").is_none());
    }

    #[test]
    fn test_platform_manager_language_dedup() {
        let mut mgr = DbTracePlatformManager::new("x86:LE:64:default", "default");
        mgr.get_or_create_language("ARM:LE:32:v8", 1, 0);
        mgr.get_or_create_language("ARM:LE:32:v8", 1, 0);
        assert_eq!(mgr.language_count(), 1);
    }

    #[test]
    fn test_guest_platform_remove_range() {
        let mut platform = DbTraceGuestPlatform::new(1, 0, "ARM:LE:32:v8", "default");
        platform.add_mapped_range(TraceGuestPlatformMappedRange::new(
            1, 0x1000, 0x1fff, 0xf000_0000, Lifespan::ALL,
        ));
        assert_eq!(platform.mapped_ranges().len(), 1);

        assert!(platform.remove_mapped_range_at_guest(0x1500));
        assert_eq!(platform.mapped_ranges().len(), 0);
    }
}
