//! Utility functions for the trace database.
//!
//! Ported from Ghidra's `DBTraceUtils`. Provides helper functions
//! for common trace database operations.

use serde::{Deserialize, Serialize};

/// An (offset, snap) tuple used to index/locate blocks in the trace's byte stores.
///
/// Ported from Ghidra's `DBTraceUtils.OffsetSnap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OffsetSnap {
    /// The byte offset within the block.
    pub offset: u64,
    /// The snapshot key (snap) at which this entry is valid.
    pub snap: i64,
}

impl OffsetSnap {
    /// Create a new OffsetSnap.
    pub fn new(offset: u64, snap: i64) -> Self {
        Self { offset, snap }
    }

    /// Check if this entry is in scratch space.
    pub fn is_scratch(&self) -> bool {
        crate::model::lifespan::is_scratch(self.snap)
    }

    /// Encode to bytes (16 bytes: 8 for offset, 8 for snap).
    pub fn encode(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&self.offset.to_le_bytes());
        buf[8..].copy_from_slice(&self.snap.to_le_bytes());
        buf
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let offset = u64::from_le_bytes(data[..8].try_into().ok()?);
        let snap = i64::from_le_bytes(data[8..16].try_into().ok()?);
        Some(Self { offset, snap })
    }
}

impl std::fmt::Display for OffsetSnap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},{:08x}", self.snap, self.offset)
    }
}

/// A key encoding an (offset, snap) tuple for database ordering.
///
/// Orders by offset first, then by snap. Ported from Ghidra's
/// `OffsetThenSnapDBFieldCodec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OffsetThenSnapKey {
    /// The byte offset.
    pub offset: u64,
    /// The snapshot key.
    pub snap: i64,
}

impl OffsetThenSnapKey {
    /// Create a new key.
    pub fn new(offset: u64, snap: i64) -> Self {
        Self { offset, snap }
    }

    /// Encode for database storage (offset first, then snap).
    pub fn encode(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&self.offset.to_be_bytes());
        buf[8..].copy_from_slice(&self.snap.to_be_bytes());
        buf
    }

    /// Decode from database storage.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let offset = u64::from_be_bytes(data[..8].try_into().ok()?);
        let snap = i64::from_be_bytes(data[8..16].try_into().ok()?);
        Some(Self { offset, snap })
    }
}

impl PartialOrd for OffsetThenSnapKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OffsetThenSnapKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.offset
            .cmp(&other.offset)
            .then(self.snap.cmp(&other.snap))
    }
}

/// A key encoding a (snap, offset) tuple for database ordering.
///
/// Orders by snap first, then by offset. Ported from Ghidra's
/// `SnapThenOffsetDBFieldCodec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapThenOffsetKey {
    /// The snapshot key.
    pub snap: i64,
    /// The byte offset.
    pub offset: u64,
}

impl SnapThenOffsetKey {
    /// Create a new key.
    pub fn new(snap: i64, offset: u64) -> Self {
        Self { snap, offset }
    }

    /// Encode for database storage (snap first, then offset).
    pub fn encode(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&self.snap.to_be_bytes());
        buf[8..].copy_from_slice(&self.offset.to_be_bytes());
        buf
    }

    /// Decode from database storage.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let snap = i64::from_be_bytes(data[..8].try_into().ok()?);
        let offset = u64::from_be_bytes(data[8..16].try_into().ok()?);
        Some(Self { snap, offset })
    }
}

impl PartialOrd for SnapThenOffsetKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SnapThenOffsetKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.snap
            .cmp(&other.snap)
            .then(self.offset.cmp(&other.offset))
    }
}

/// Table name generation utilities.
///
/// Ported from Ghidra's `DBTraceUtils.tableName()`.
pub fn table_name(base: &str, space_name: &str) -> String {
    format!("{}_{}", base, space_name)
}

/// Encode a string to bytes for database storage.
pub fn encode_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(4 + bytes.len());
    result.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    result.extend_from_slice(bytes);
    result
}

/// Decode a string from database bytes.
pub fn decode_string(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(data[..4].try_into().ok()?) as usize;
    if data.len() < 4 + len {
        return None;
    }
    String::from_utf8(data[4..4 + len].to_vec()).ok()
}

/// Compute the set of address ranges where two byte arrays differ.
///
/// Ported from Ghidra's `ByteArrayUtils.computeDiffsAddressSet`.
pub fn compute_diffs_ranges(a: &[u8], b: &[u8]) -> Vec<(usize, usize)> {
    if a.len() != b.len() {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    let mut diff_start: Option<usize> = None;
    for i in 0..a.len() {
        if a[i] == b[i] {
            if let Some(start) = diff_start {
                ranges.push((start, i - 1));
                diff_start = None;
            }
        } else if diff_start.is_none() {
            diff_start = Some(i);
        }
    }
    if let Some(start) = diff_start {
        ranges.push((start, a.len() - 1));
    }
    ranges
}

/// Compute a simple hash of a byte range.
pub fn hash_bytes(data: &[u8]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

/// Ref type encoding for database storage of references.
///
/// Ported from Ghidra's `RefType` field codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedRefType {
    /// The numeric ref type ID.
    pub type_id: u32,
}

impl EncodedRefType {
    /// Create from a type ID.
    pub fn new(type_id: u32) -> Self {
        Self { type_id }
    }

    /// Encode to bytes.
    pub fn encode(&self) -> [u8; 4] {
        self.type_id.to_le_bytes()
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        Some(Self {
            type_id: u32::from_le_bytes(data[..4].try_into().ok()?),
        })
    }
}

/// Encode a URL to a string for database storage.
///
/// Ported from Ghidra's `DBTraceUtils.URLDBFieldCodec`.
pub fn encode_url(url: &str) -> String {
    url.to_string()
}

/// Encode a language ID to a string for database storage.
///
/// Ported from Ghidra's `DBTraceUtils.LanguageIDDBFieldCodec`.
pub fn encode_language_id(lang_id: &str) -> String {
    lang_id.to_string()
}

/// Encode a compiler spec ID to a string for database storage.
///
/// Ported from Ghidra's `DBTraceUtils.CompilerSpecIDDBFieldCodec`.
pub fn encode_compiler_spec_id(comp_id: &str) -> String {
    comp_id.to_string()
}

/// Information about a trace database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDatabaseInfo {
    /// The trace name.
    pub name: String,
    /// When the trace was created.
    pub date_created: String,
    /// The base language ID (e.g., "x86:LE:64:default").
    pub base_language_id: String,
    /// The base compiler spec ID.
    pub base_compiler_spec_id: String,
    /// The platform name.
    pub platform: Option<String>,
    /// The executable path.
    pub executable_path: Option<String>,
    /// The emulator cache version.
    pub emulator_cache_version: i64,
}

impl TraceDatabaseInfo {
    /// Create new database info.
    pub fn new(
        name: impl Into<String>,
        base_language_id: impl Into<String>,
        base_compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            date_created: chrono::Utc::now().to_rfc3339(),
            base_language_id: base_language_id.into(),
            base_compiler_spec_id: base_compiler_spec_id.into(),
            platform: None,
            executable_path: None,
            emulator_cache_version: 0,
        }
    }

    /// Set the platform.
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Set the executable path.
    pub fn with_executable_path(mut self, path: impl Into<String>) -> Self {
        self.executable_path = Some(path.into());
        self
    }
}

/// The trace chunk size constant used by the database.
pub const CHUNK_SIZE: usize = 4096;

/// Database timing constants.
pub mod timing {
    /// The interval (ms) between database flushes.
    pub const DB_TIME_INTERVAL: u64 = 500;
    /// The buffer size for pending writes.
    pub const DB_BUFFER_SIZE: usize = 1000;
}

/// Utility functions for trace address and space operations.
pub struct TraceDbUtils;

impl TraceDbUtils {
    /// Normalize an address space name (lowercase, strip prefixes).
    pub fn normalize_space_name(name: &str) -> String {
        name.to_lowercase().replace("space_", "")
    }

    /// Check if a space name represents a register space.
    pub fn is_register_space(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower == "register" || lower == "registers" || lower.starts_with("reg")
    }

    /// Check if a space name represents a memory space.
    pub fn is_memory_space(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower == "ram" || lower == "memory" || lower == "mem" || lower.starts_with("ram")
    }

    /// Check if a space name represents a stack space.
    pub fn is_stack_space(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower == "stack" || lower.starts_with("stack")
    }

    /// Format a snap value for display.
    pub fn format_snap(snap: i64) -> String {
        if snap < 0 {
            "scratch".to_string()
        } else {
            format!("snap:{}", snap)
        }
    }

    /// Parse a snap value from a display string.
    pub fn parse_snap(s: &str) -> Option<i64> {
        if s == "scratch" {
            Some(-1)
        } else if let Some(rest) = s.strip_prefix("snap:") {
            rest.parse().ok()
        } else {
            s.parse().ok()
        }
    }

    /// Format a trace key (unique identifier) for display.
    pub fn format_trace_key(key: i64) -> String {
        format!("trace:{}", key)
    }

    /// Compute the overlap between two address ranges.
    /// Returns (overlap_start, overlap_end) or None if no overlap.
    pub fn range_overlap(min1: u64, max1: u64, min2: u64, max2: u64) -> Option<(u64, u64)> {
        let start = min1.max(min2);
        let end = max1.min(max2);
        if start <= end {
            Some((start, end))
        } else {
            None
        }
    }

    /// Align an address down to a given alignment.
    pub fn align_down(addr: u64, alignment: u64) -> u64 {
        if alignment == 0 {
            return addr;
        }
        addr & !(alignment - 1)
    }

    /// Align an address up to a given alignment.
    pub fn align_up(addr: u64, alignment: u64) -> u64 {
        if alignment == 0 {
            return addr;
        }
        (addr + alignment - 1) & !(alignment - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_database_info() {
        let info = TraceDatabaseInfo::new(
            "test_trace",
            "x86:LE:64:default",
            "default",
        )
        .with_platform("Windows")
        .with_executable_path("/usr/bin/test");
        assert_eq!(info.name, "test_trace");
        assert_eq!(info.platform, Some("Windows".into()));
        assert_eq!(info.executable_path, Some("/usr/bin/test".into()));
    }

    #[test]
    fn test_constants() {
        assert_eq!(CHUNK_SIZE, 4096);
        assert_eq!(timing::DB_TIME_INTERVAL, 500);
        assert_eq!(timing::DB_BUFFER_SIZE, 1000);
    }

    #[test]
    fn test_space_name_checks() {
        assert!(TraceDbUtils::is_register_space("register"));
        assert!(TraceDbUtils::is_register_space("REGISTER"));
        assert!(TraceDbUtils::is_register_space("registers"));
        assert!(!TraceDbUtils::is_register_space("ram"));

        assert!(TraceDbUtils::is_memory_space("ram"));
        assert!(TraceDbUtils::is_memory_space("RAM"));
        assert!(TraceDbUtils::is_memory_space("memory"));
        assert!(!TraceDbUtils::is_memory_space("register"));

        assert!(TraceDbUtils::is_stack_space("stack"));
        assert!(TraceDbUtils::is_stack_space("STACK"));
    }

    #[test]
    fn test_normalize_space_name() {
        assert_eq!(TraceDbUtils::normalize_space_name("RAM"), "ram");
        assert_eq!(TraceDbUtils::normalize_space_name("space_register"), "register");
    }

    #[test]
    fn test_format_snap() {
        assert_eq!(TraceDbUtils::format_snap(5), "snap:5");
        assert_eq!(TraceDbUtils::format_snap(-1), "scratch");
        assert_eq!(TraceDbUtils::format_snap(0), "snap:0");
    }

    #[test]
    fn test_parse_snap() {
        assert_eq!(TraceDbUtils::parse_snap("snap:5"), Some(5));
        assert_eq!(TraceDbUtils::parse_snap("scratch"), Some(-1));
        assert_eq!(TraceDbUtils::parse_snap("42"), Some(42));
        assert_eq!(TraceDbUtils::parse_snap("invalid"), None);
    }

    #[test]
    fn test_range_overlap() {
        assert_eq!(
            TraceDbUtils::range_overlap(0, 100, 50, 150),
            Some((50, 100))
        );
        assert_eq!(
            TraceDbUtils::range_overlap(0, 100, 200, 300),
            None
        );
        assert_eq!(
            TraceDbUtils::range_overlap(0, 100, 100, 200),
            Some((100, 100))
        );
    }

    #[test]
    fn test_align_down() {
        assert_eq!(TraceDbUtils::align_down(0x1234, 0x1000), 0x1000);
        assert_eq!(TraceDbUtils::align_down(0x1000, 0x1000), 0x1000);
        assert_eq!(TraceDbUtils::align_down(0x1fff, 0x1000), 0x1000);
        assert_eq!(TraceDbUtils::align_down(0x1234, 0), 0x1234);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(TraceDbUtils::align_up(0x1234, 0x1000), 0x2000);
        assert_eq!(TraceDbUtils::align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(TraceDbUtils::align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(TraceDbUtils::align_up(0x1234, 0), 0x1234);
    }

    #[test]
    fn test_trace_key_format() {
        assert_eq!(TraceDbUtils::format_trace_key(42), "trace:42");
    }

    #[test]
    fn test_database_info_serde() {
        let info = TraceDatabaseInfo::new("t", "x86:LE:64:default", "default");
        let json = serde_json::to_string(&info).unwrap();
        let back: TraceDatabaseInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "t");
    }

    #[test]
    fn test_offset_snap_roundtrip() {
        let os = OffsetSnap::new(0xDEAD, 42);
        assert!(!os.is_scratch());
        let encoded = os.encode();
        let decoded = OffsetSnap::decode(&encoded).unwrap();
        assert_eq!(os, decoded);
    }

    #[test]
    fn test_offset_snap_scratch() {
        let os = OffsetSnap::new(0, -1);
        assert!(os.is_scratch());
    }

    #[test]
    fn test_offset_snap_display() {
        let os = OffsetSnap::new(0x1234, 5);
        assert_eq!(format!("{}", os), "5,00001234");
    }

    #[test]
    fn test_offset_snap_decode_short() {
        assert!(OffsetSnap::decode(&[1, 2, 3]).is_none());
    }

    #[test]
    fn test_offset_then_snap_key_ordering() {
        let a = OffsetThenSnapKey::new(10, 1);
        let b = OffsetThenSnapKey::new(10, 2);
        let c = OffsetThenSnapKey::new(20, 1);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn test_offset_then_snap_key_roundtrip() {
        let key = OffsetThenSnapKey::new(0x1234, 42);
        let encoded = key.encode();
        let decoded = OffsetThenSnapKey::decode(&encoded).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_snap_then_offset_key_ordering() {
        let a = SnapThenOffsetKey::new(1, 10);
        let b = SnapThenOffsetKey::new(1, 20);
        let c = SnapThenOffsetKey::new(2, 10);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn test_snap_then_offset_key_roundtrip() {
        let key = SnapThenOffsetKey::new(42, 0xABCD);
        let encoded = key.encode();
        let decoded = SnapThenOffsetKey::decode(&encoded).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_table_name() {
        assert_eq!(table_name("MemoryBlocks", "ram"), "MemoryBlocks_ram");
        assert_eq!(table_name("Regs", "register"), "Regs_register");
    }

    #[test]
    fn test_string_encode_decode_roundtrip() {
        let original = "hello world";
        let encoded = encode_string(original);
        let decoded = decode_string(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_string_decode_empty() {
        assert!(decode_string(&[1, 2]).is_none());
    }

    #[test]
    fn test_string_decode_short_payload() {
        let mut data = vec![5, 0, 0, 0]; // len=5
        data.extend_from_slice(b"hi"); // only 2 bytes
        assert!(decode_string(&data).is_none());
    }

    #[test]
    fn test_compute_diffs_ranges() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 9, 3, 8, 5];
        let diffs = compute_diffs_ranges(&a, &b);
        assert_eq!(diffs, vec![(1, 1), (3, 3)]);
    }

    #[test]
    fn test_compute_diffs_ranges_all_same() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3];
        let diffs = compute_diffs_ranges(&a, &b);
        assert!(diffs.is_empty());
    }

    #[test]
    fn test_compute_diffs_ranges_all_different() {
        let a = [1u8, 2, 3];
        let b = [4u8, 5, 6];
        let diffs = compute_diffs_ranges(&a, &b);
        assert_eq!(diffs, vec![(0, 2)]);
    }

    #[test]
    fn test_compute_diffs_ranges_different_lengths() {
        let a = [1u8, 2];
        let b = [1u8, 2, 3];
        let diffs = compute_diffs_ranges(&a, &b);
        assert!(diffs.is_empty());
    }

    #[test]
    fn test_hash_bytes() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"hello");
        let h3 = hash_bytes(b"world");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_encoded_ref_type_roundtrip() {
        let rt = EncodedRefType::new(42);
        let encoded = rt.encode();
        let decoded = EncodedRefType::decode(&encoded).unwrap();
        assert_eq!(rt, decoded);
    }

    #[test]
    fn test_encode_helpers() {
        assert_eq!(encode_url("http://example.com"), "http://example.com");
        assert_eq!(encode_language_id("x86:LE:64:default"), "x86:LE:64:default");
        assert_eq!(encode_compiler_spec_id("default"), "default");
    }
}
