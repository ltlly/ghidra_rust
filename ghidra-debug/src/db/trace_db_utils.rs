//! Utility functions for the trace database.
//!
//! Ported from Ghidra's `DBTraceUtils`. Provides helper functions
//! for common trace database operations.

use serde::{Deserialize, Serialize};

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
}
