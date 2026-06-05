//! Utilities for static mapping management.
//!
//! Ported from Ghidra's `DebuggerStaticMappingUtils`.
//!
//! Provides helper functions for adding, querying, and displaying
//! static mappings between trace addresses and program addresses.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// Compute the short name of a module from its path.
///
/// Ported from `DebuggerStaticMappingUtils.computeModuleShortName()`.
///
/// Extracts the filename portion from a full path, handling both
/// Windows (`\`) and Unix (`/`) path separators.
pub fn compute_module_short_name(path: &str) -> &str {
    if let Some(pos) = path.rfind('\\') {
        &path[pos + 1..]
    } else if let Some(pos) = path.rfind('/') {
        &path[pos + 1..]
    } else {
        path
    }
}

/// Compute a display string for the mapped images covering an address range.
///
/// Ported from `DebuggerStaticMappingUtils.computeMappedFiles()`.
///
/// Returns:
/// - Empty string if no mappings cover the range
/// - The image name if a single mapping fully covers the range
/// - The image name with "*" suffix if it only partially covers
/// - Comma-separated list if multiple images cover the range
pub fn compute_mapped_files(mappings: &[MappingInfo], snap: i64, min_addr: u64, max_addr: u64) -> String {
    let overlapping: Vec<&MappingInfo> = mappings
        .iter()
        .filter(|m| m.overlaps(min_addr, max_addr, snap))
        .collect();

    if overlapping.is_empty() {
        return String::new();
    }

    if overlapping.len() == 1 {
        let single = overlapping[0];
        if single.from_min <= min_addr && single.from_max >= max_addr {
            return get_image_name(&single.program_url);
        }
        return format!("{}*", get_image_name(&single.program_url));
    }

    let mut names: Vec<String> = overlapping
        .iter()
        .map(|m| get_image_name(&m.program_url))
        .collect();
    names.sort();
    names.dedup();

    if names.len() == 1 {
        format!("{}*", names[0])
    } else {
        names.join(",")
    }
}

/// Get the image name (last path component) from a URL.
///
/// Ported from `DebuggerStaticMappingUtils.getImageName()`.
pub fn get_image_name(url: &str) -> String {
    url.rsplit('/')
        .next()
        .unwrap_or(url)
        .to_string()
}

/// Information about a static mapping entry for utility computations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingInfo {
    /// The trace address range start.
    pub from_min: u64,
    /// The trace address range end (inclusive).
    pub from_max: u64,
    /// The lifespan during which this mapping is valid.
    pub lifespan: Lifespan,
    /// The program URL.
    pub program_url: String,
    /// The static (program) address as a string.
    pub static_address: String,
    /// The length of the mapping.
    pub length: u64,
}

impl MappingInfo {
    /// Create a new mapping info.
    pub fn new(
        from_min: u64,
        from_max: u64,
        lifespan: Lifespan,
        program_url: impl Into<String>,
        static_address: impl Into<String>,
        length: u64,
    ) -> Self {
        Self {
            from_min,
            from_max,
            lifespan,
            program_url: program_url.into(),
            static_address: static_address.into(),
            length,
        }
    }

    /// Whether this mapping overlaps the given trace address range at the given snap.
    pub fn overlaps(&self, min_addr: u64, max_addr: u64, snap: i64) -> bool {
        if !self.lifespan.contains(snap) {
            return false;
        }
        self.from_min <= max_addr && min_addr <= self.from_max
    }

    /// Whether this mapping contains the given trace address at the given snap.
    pub fn contains(&self, addr: u64, snap: i64) -> bool {
        addr >= self.from_min && addr <= self.from_max && self.lifespan.contains(snap)
    }

    /// Translate a trace address to a program address offset.
    pub fn trace_to_program_offset(&self, trace_addr: u64) -> Option<u64> {
        if trace_addr >= self.from_min && trace_addr <= self.from_max {
            Some(trace_addr - self.from_min)
        } else {
            None
        }
    }
}

/// An extremum tracker for computing min/max of address ranges.
///
/// Ported from `DebuggerStaticMappingUtils.Extrema`.
#[derive(Debug, Clone, Default)]
pub struct Extrema {
    /// The minimum address seen.
    pub min: Option<u64>,
    /// The maximum address seen.
    pub max: Option<u64>,
}

impl Extrema {
    /// Create a new extremum tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Consider a range.
    pub fn consider_range(&mut self, min: u64, max: u64) {
        self.min = Some(match self.min {
            Some(m) => m.min(min),
            None => min,
        });
        self.max = Some(match self.max {
            Some(m) => m.max(max),
            None => max,
        });
    }

    /// Consider a single address.
    pub fn consider(&mut self, addr: u64) {
        self.consider_range(addr, addr);
    }

    /// Get the length (max - min + 1), or 0 if empty.
    pub fn length(&self) -> u64 {
        match (self.min, self.max) {
            (Some(min), Some(max)) => max - min + 1,
            _ => 0,
        }
    }

    /// Get the range as (min, max).
    pub fn range(&self) -> Option<(u64, u64)> {
        match (self.min, self.max) {
            (Some(min), Some(max)) => Some((min, max)),
            _ => None,
        }
    }
}

/// Check whether a memory block is "real" (loaded, not overlay, not external).
///
/// Ported from `DebuggerStaticMappingUtils.isReal()`.
pub fn is_real_block(is_loaded: bool, is_overlay: bool, is_external: bool) -> bool {
    is_loaded && !is_overlay && !is_external
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_module_short_name_unix() {
        assert_eq!(compute_module_short_name("/usr/lib/libc.so"), "libc.so");
        assert_eq!(compute_module_short_name("libc.so"), "libc.so");
    }

    #[test]
    fn test_compute_module_short_name_windows() {
        assert_eq!(compute_module_short_name("C:\\Windows\\kernel32.dll"), "kernel32.dll");
    }

    #[test]
    fn test_get_image_name() {
        assert_eq!(get_image_name("file:///usr/lib/libc.so"), "libc.so");
        assert_eq!(get_image_name("http://server/path/prog.exe"), "prog.exe");
        assert_eq!(get_image_name("no_slash"), "no_slash");
    }

    #[test]
    fn test_compute_mapped_files_empty() {
        let result = compute_mapped_files(&[], 0, 0x1000, 0x2000);
        assert!(result.is_empty());
    }

    #[test]
    fn test_compute_mapped_files_single_full() {
        let mappings = vec![MappingInfo::new(
            0x1000, 0x3000, Lifespan::at(0), "file:///prog.exe", "0x400000", 0x2001,
        )];
        let result = compute_mapped_files(&mappings, 0, 0x1000, 0x3000);
        assert_eq!(result, "prog.exe");
    }

    #[test]
    fn test_compute_mapped_files_single_partial() {
        let mappings = vec![MappingInfo::new(
            0x1000, 0x2000, Lifespan::at(0), "file:///prog.exe", "0x400000", 0x1001,
        )];
        let result = compute_mapped_files(&mappings, 0, 0x1000, 0x3000);
        assert_eq!(result, "prog.exe*");
    }

    #[test]
    fn test_compute_mapped_files_multiple() {
        let mappings = vec![
            MappingInfo::new(0x1000, 0x2000, Lifespan::at(0), "file:///a.exe", "0x400000", 0x1001),
            MappingInfo::new(0x2001, 0x3000, Lifespan::at(0), "file:///b.dll", "0x500000", 0x1000),
        ];
        let result = compute_mapped_files(&mappings, 0, 0x1000, 0x3000);
        assert!(result.contains("a.exe"));
        assert!(result.contains("b.dll"));
    }

    #[test]
    fn test_mapping_info_contains() {
        let m = MappingInfo::new(0x1000, 0x2000, Lifespan::at(5), "file:///p", "0x0", 0x1001);
        assert!(m.contains(0x1500, 5));
        assert!(!m.contains(0x1500, 10)); // wrong snap
        assert!(!m.contains(0x3000, 5)); // wrong addr
    }

    #[test]
    fn test_mapping_info_overlaps() {
        let m = MappingInfo::new(0x1000, 0x2000, Lifespan::at(0), "file:///p", "0x0", 0x1001);
        assert!(m.overlaps(0x1800, 0x2800, 0));
        assert!(!m.overlaps(0x3000, 0x4000, 0));
    }

    #[test]
    fn test_mapping_info_trace_to_program_offset() {
        let m = MappingInfo::new(0x400000, 0x400fff, Lifespan::at(0), "file:///p", "0x0", 0x1000);
        assert_eq!(m.trace_to_program_offset(0x400000), Some(0));
        assert_eq!(m.trace_to_program_offset(0x400100), Some(0x100));
        assert_eq!(m.trace_to_program_offset(0x500000), None);
    }

    #[test]
    fn test_extrema() {
        let mut e = Extrema::new();
        assert!(e.range().is_none());

        e.consider(0x400000);
        e.consider_range(0x300000, 0x500000);
        e.consider(0x200000);

        assert_eq!(e.min, Some(0x200000));
        assert_eq!(e.max, Some(0x500000));
        assert_eq!(e.length(), 0x300001);
    }

    #[test]
    fn test_extrema_single() {
        let mut e = Extrema::new();
        e.consider(0x1000);
        assert_eq!(e.length(), 1);
    }

    #[test]
    fn test_is_real_block() {
        assert!(is_real_block(true, false, false));
        assert!(!is_real_block(false, false, false));
        assert!(!is_real_block(true, true, false));
        assert!(!is_real_block(true, false, true));
    }

    #[test]
    fn test_mapping_info_serde() {
        let m = MappingInfo::new(0x1000, 0x2000, Lifespan::at(0), "file:///p", "0x0", 0x1001);
        let json = serde_json::to_string(&m).unwrap();
        let back: MappingInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.from_min, 0x1000);
    }
}
