//! TracePlatform and guest platform management.
//!
//! Ported from Ghidra's `ghidra.trace.model.guest` package.
//! Manages platform information for traces, including guest platform mappings.

use serde::{Deserialize, Serialize};

use super::Lifespan;

/// A platform in the trace (architecture + compiler specification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePlatform {
    /// Language ID (e.g., "x86:LE:64:default").
    pub language_id: String,
    /// Compiler spec ID (e.g., "default", "gcc").
    pub compiler_spec_id: String,
    /// The unique key for this platform.
    pub key: i64,
}

impl TracePlatform {
    /// Create a new platform.
    pub fn new(
        key: i64,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            key,
        }
    }

    /// Whether this is a 64-bit platform.
    pub fn is_64_bit(&self) -> bool {
        self.language_id.contains(":64:")
    }

    /// Whether this is a big-endian platform.
    pub fn is_big_endian(&self) -> bool {
        self.language_id.contains(":BE:")
    }

    /// The processor name extracted from the language ID.
    pub fn processor(&self) -> &str {
        self.language_id.split(':').next().unwrap_or("")
    }
}

/// A guest platform mapping: maps a guest platform's address range into the
/// trace's native address range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceGuestPlatformMappedRange {
    /// The guest platform key.
    pub guest_platform_key: i64,
    /// Start offset in the guest space.
    pub guest_min: u64,
    /// End offset in the guest space.
    pub guest_max: u64,
    /// Start offset in the host/trace space.
    pub host_min: u64,
    /// The lifespan of this mapping.
    pub lifespan: Lifespan,
}

impl TraceGuestPlatformMappedRange {
    /// Create a new guest platform mapped range.
    pub fn new(
        guest_platform_key: i64,
        guest_min: u64,
        guest_max: u64,
        host_min: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            guest_platform_key,
            guest_min,
            guest_max,
            host_min,
            lifespan,
        }
    }

    /// Translate a guest address to a host address.
    pub fn guest_to_host(&self, guest_addr: u64) -> Option<u64> {
        if guest_addr >= self.guest_min && guest_addr <= self.guest_max {
            Some(self.host_min + (guest_addr - self.guest_min))
        } else {
            None
        }
    }

    /// Translate a host address to a guest address.
    pub fn host_to_guest(&self, host_addr: u64) -> Option<u64> {
        let range_size = self.guest_max - self.guest_min;
        let host_max = self.host_min + range_size;
        if host_addr >= self.host_min && host_addr <= host_max {
            Some(self.guest_min + (host_addr - self.host_min))
        } else {
            None
        }
    }

    /// The size of the mapped range.
    pub fn size(&self) -> u64 {
        self.guest_max - self.guest_min + 1
    }
}

/// Manages platforms and guest platform mappings for a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracePlatformManager {
    next_key: i64,
    platforms: Vec<TracePlatform>,
    guest_ranges: Vec<TraceGuestPlatformMappedRange>,
    /// The native (host) platform key.
    native_platform_key: Option<i64>,
}

impl TracePlatformManager {
    /// Create a new platform manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a platform.
    pub fn add_platform(
        &mut self,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        self.platforms.push(TracePlatform::new(key, language_id, compiler_spec_id));
        key
    }

    /// Get a platform by key.
    pub fn get_platform(&self, key: i64) -> Option<&TracePlatform> {
        self.platforms.iter().find(|p| p.key == key)
    }

    /// Get all platforms.
    pub fn platforms(&self) -> &[TracePlatform] {
        &self.platforms
    }

    /// Set the native platform.
    pub fn set_native_platform(&mut self, key: i64) {
        self.native_platform_key = Some(key);
    }

    /// Get the native platform.
    pub fn native_platform(&self) -> Option<&TracePlatform> {
        self.native_platform_key
            .and_then(|k| self.get_platform(k))
    }

    /// Add a guest platform mapped range.
    pub fn add_guest_range(&mut self, range: TraceGuestPlatformMappedRange) {
        self.guest_ranges.push(range);
    }

    /// Get guest ranges for a given platform at a given snap.
    pub fn guest_ranges_at(&self, platform_key: i64, snap: i64) -> Vec<&TraceGuestPlatformMappedRange> {
        self.guest_ranges
            .iter()
            .filter(|r| r.guest_platform_key == platform_key && r.lifespan.contains(snap))
            .collect()
    }

    /// Translate a guest address to a host address.
    pub fn guest_to_host(&self, platform_key: i64, guest_addr: u64, snap: i64) -> Option<u64> {
        self.guest_ranges_at(platform_key, snap)
            .iter()
            .find_map(|r| r.guest_to_host(guest_addr))
    }

    /// Translate a host address to a guest address.
    pub fn host_to_guest(&self, platform_key: i64, host_addr: u64, snap: i64) -> Option<u64> {
        self.guest_ranges_at(platform_key, snap)
            .iter()
            .find_map(|r| r.host_to_guest(host_addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_properties() {
        let p = TracePlatform::new(1, "x86:LE:64:default", "default");
        assert!(p.is_64_bit());
        assert!(!p.is_big_endian());
        assert_eq!(p.processor(), "x86");

        let p32 = TracePlatform::new(2, "ARM:LE:32:v8", "default");
        assert!(!p32.is_64_bit());
        assert_eq!(p32.processor(), "ARM");

        let pbe = TracePlatform::new(3, "PowerPC:BE:64:default", "default");
        assert!(pbe.is_big_endian());
    }

    #[test]
    fn test_guest_range_translation() {
        let range = TraceGuestPlatformMappedRange::new(
            2,
            0x1000, 0x1fff,
            0x7f0000,
            Lifespan::ALL,
        );
        assert_eq!(range.guest_to_host(0x1500), Some(0x7f0500));
        assert_eq!(range.guest_to_host(0x2000), None);
        assert_eq!(range.host_to_guest(0x7f0500), Some(0x1500));
        assert_eq!(range.size(), 0x1000);
    }

    #[test]
    fn test_platform_manager() {
        let mut mgr = TracePlatformManager::new();
        let key = mgr.add_platform("x86:LE:64:default", "default");
        mgr.set_native_platform(key);

        assert!(mgr.get_platform(key).is_some());
        assert_eq!(mgr.platforms().len(), 1);
        assert_eq!(mgr.native_platform().unwrap().language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_platform_manager_guest_translation() {
        let mut mgr = TracePlatformManager::new();
        let guest_key = mgr.add_platform("ARM:LE:32:v8", "default");
        mgr.add_guest_range(TraceGuestPlatformMappedRange::new(
            guest_key,
            0x1000, 0x1fff,
            0x7f0000,
            Lifespan::ALL,
        ));

        assert_eq!(mgr.guest_to_host(guest_key, 0x1500, 0), Some(0x7f0500));
        assert_eq!(mgr.host_to_guest(guest_key, 0x7f0500, 0), Some(0x1500));
    }

    #[test]
    fn test_platform_serde() {
        let p = TracePlatform::new(1, "x86:LE:64:default", "default");
        let json = serde_json::to_string(&p).unwrap();
        let back: TracePlatform = serde_json::from_str(&json).unwrap();
        assert_eq!(back.language_id, "x86:LE:64:default");
    }
}
