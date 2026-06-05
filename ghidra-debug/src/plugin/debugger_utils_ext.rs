//! Extended debugger utility types ported from Java.
//!
//! Ported from the Debugger module's `utils` package. Provides
//! miscellaneous utilities for the debugger plugin framework.

use std::collections::HashMap;

/// Compute the alignment-adjusted address for a given alignment.
///
/// Rounds `address` up to the next multiple of `alignment`.
/// If `alignment` is 0 or 1, returns `address` unchanged.
pub fn align_address(address: u64, alignment: u64) -> u64 {
    if alignment <= 1 {
        return address;
    }
    (address + alignment - 1) & !(alignment - 1)
}

/// Compute the number of bytes needed to reach the next alignment boundary.
pub fn alignment_padding(address: u64, alignment: u64) -> u64 {
    if alignment <= 1 {
        return 0;
    }
    let aligned = align_address(address, alignment);
    aligned - address
}

/// Check if an address is properly aligned.
pub fn is_aligned(address: u64, alignment: u64) -> bool {
    alignment <= 1 || address % alignment == 0
}

/// Memory range utility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRange {
    /// Start address (inclusive).
    pub min_address: u64,
    /// End address (inclusive).
    pub max_address: u64,
}

impl MemoryRange {
    /// Create a new memory range.
    pub fn new(min_address: u64, max_address: u64) -> Self {
        Self {
            min_address,
            max_address: max_address.max(min_address),
        }
    }

    /// Get the size of the range in bytes.
    pub fn size(&self) -> u64 {
        self.max_address - self.min_address + 1
    }

    /// Check if this range contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.min_address && address <= self.max_address
    }

    /// Check if this range overlaps with another.
    pub fn overlaps(&self, other: &MemoryRange) -> bool {
        self.min_address <= other.max_address && other.min_address <= self.max_address
    }

    /// Compute the intersection of two ranges.
    pub fn intersect(&self, other: &MemoryRange) -> Option<MemoryRange> {
        let min = self.min_address.max(other.min_address);
        let max = self.max_address.min(other.max_address);
        if min <= max {
            Some(MemoryRange::new(min, max))
        } else {
            None
        }
    }

    /// Compute the union of two overlapping/adjacent ranges.
    pub fn union(&self, other: &MemoryRange) -> MemoryRange {
        MemoryRange::new(
            self.min_address.min(other.min_address),
            self.max_address.max(other.max_address),
        )
    }
}

/// A register value in the debugger.
#[derive(Debug, Clone)]
pub struct DebuggerRegisterValue {
    /// Register name.
    pub name: String,
    /// Register value bytes (little-endian).
    pub value: Vec<u8>,
    /// Whether this value has been modified from the default.
    pub is_modified: bool,
}

impl DebuggerRegisterValue {
    /// Create a new register value.
    pub fn new(name: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            value,
            is_modified: false,
        }
    }

    /// Interpret the value as a u64 (little-endian).
    pub fn as_u64(&self) -> Option<u64> {
        if self.value.len() >= 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&self.value[..8]);
            Some(u64::from_le_bytes(bytes))
        } else if self.value.len() >= 4 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&self.value[..4]);
            Some(u32::from_le_bytes(bytes) as u64)
        } else {
            None
        }
    }

    /// Get the size of this register in bytes.
    pub fn size(&self) -> usize {
        self.value.len()
    }
}

/// Program location utilities for the debugger.
#[derive(Debug, Clone)]
pub struct ProgramLocationUtils;

impl ProgramLocationUtils {
    /// Normalize an address to be within the given address space range.
    pub fn normalize_address(address: u64, space_size: u64) -> u64 {
        if space_size == 0 {
            address
        } else {
            address % space_size
        }
    }

    /// Check if an address is in the "valid" range for a program.
    pub fn is_valid_address(address: u64, min_address: u64, max_address: u64) -> bool {
        address >= min_address && address <= max_address
    }

    /// Format an address as a hexadecimal string.
    pub fn format_address(address: u64) -> String {
        format!("0x{:x}", address)
    }

    /// Parse a hexadecimal address string.
    pub fn parse_address(s: &str) -> Option<u64> {
        let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(s, 16).ok()
    }
}

/// Program URL utilities for the debugger.
#[derive(Debug, Clone)]
pub struct ProgramUrlUtils;

impl ProgramUrlUtils {
    /// Extract the program name from a URL.
    pub fn extract_program_name(url: &str) -> &str {
        url.rsplit('/').next().unwrap_or(url)
    }

    /// Check if a URL looks like a program URL.
    pub fn is_program_url(url: &str) -> bool {
        url.ends_with(".gzf")
            || url.ends_with(".xml.gz")
            || url.ends_with(".bxml")
            || url.contains("/programs/")
    }
}

/// Transaction coalescer that batches multiple small changes
/// into a single transaction.
///
/// Ported from `DefaultTransactionCoalescer`.
#[derive(Debug)]
pub struct TransactionCoalescer {
    /// Whether coalescing is active.
    active: bool,
    /// Pending operations to coalesce.
    pending_ops: Vec<String>,
    /// Delay before committing (milliseconds).
    delay_ms: u64,
}

impl TransactionCoalescer {
    /// Create a new coalescer with the given delay.
    pub fn new(delay_ms: u64) -> Self {
        Self {
            active: false,
            pending_ops: Vec::new(),
            delay_ms,
        }
    }

    /// Start a coalescing session.
    pub fn start(&mut self) {
        self.active = true;
        self.pending_ops.clear();
    }

    /// Add an operation to the current coalescing session.
    pub fn add_operation(&mut self, op: impl Into<String>) {
        if self.active {
            self.pending_ops.push(op.into());
        }
    }

    /// Check if coalescing is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// End the coalescing session and return the pending operations.
    pub fn end(&mut self) -> Vec<String> {
        self.active = false;
        std::mem::take(&mut self.pending_ops)
    }

    /// Get the number of pending operations.
    pub fn pending_count(&self) -> usize {
        self.pending_ops.len()
    }

    /// Get the configured delay in milliseconds.
    pub fn delay_ms(&self) -> u64 {
        self.delay_ms
    }
}

/// Miscellaneous utilities for the debugger.
pub struct MiscellaneousUtils;

impl MiscellaneousUtils {
    /// Compute a hash of bytes for change detection.
    pub fn hash_bytes(bytes: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    }

    /// Check if two byte slices differ, returning the offset of first difference.
    pub fn first_diff_offset(a: &[u8], b: &[u8]) -> Option<usize> {
        let min_len = a.len().min(b.len());
        for i in 0..min_len {
            if a[i] != b[i] {
                return Some(i);
            }
        }
        if a.len() != b.len() {
            return Some(min_len);
        }
        None
    }

    /// Compute the ranges of differences between two byte slices.
    pub fn diff_ranges(old: &[u8], new: &[u8]) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        let min_len = old.len().min(new.len());
        let mut start = None;

        for i in 0..min_len {
            if old[i] != new[i] {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start {
                ranges.push((s, i));
                start = None;
            }
        }

        if let Some(s) = start {
            ranges.push((s, min_len));
        }

        // Handle length differences
        if old.len() != new.len() {
            let extra_start = min_len;
            let extra_end = old.len().max(new.len());
            ranges.push((extra_start, extra_end));
        }

        ranges
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alignment() {
        assert_eq!(align_address(0x1000, 0x10), 0x1000);
        assert_eq!(align_address(0x1001, 0x10), 0x1010);
        assert_eq!(align_address(0x100f, 0x10), 0x1010);
        assert_eq!(align_address(0x1000, 1), 0x1000);

        assert!(is_aligned(0x1000, 0x10));
        assert!(!is_aligned(0x1001, 0x10));
        assert_eq!(alignment_padding(0x1001, 0x10), 15);
    }

    #[test]
    fn test_memory_range() {
        let r1 = MemoryRange::new(0x1000, 0x2000);
        let r2 = MemoryRange::new(0x1500, 0x2500);

        assert_eq!(r1.size(), 0x1001);
        assert!(r1.contains(0x1500));
        assert!(!r1.contains(0x3000));
        assert!(r1.overlaps(&r2));

        let intersection = r1.intersect(&r2).unwrap();
        assert_eq!(intersection.min_address, 0x1500);
        assert_eq!(intersection.max_address, 0x2000);

        let union = r1.union(&r2);
        assert_eq!(union.min_address, 0x1000);
        assert_eq!(union.max_address, 0x2500);

        let r3 = MemoryRange::new(0x3000, 0x4000);
        assert!(r1.intersect(&r3).is_none());
    }

    #[test]
    fn test_register_value() {
        let rv = DebuggerRegisterValue::new("RAX", vec![0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
        assert_eq!(rv.as_u64(), Some(0x12345678));
        assert_eq!(rv.size(), 8);
    }

    #[test]
    fn test_program_location_utils() {
        assert_eq!(ProgramLocationUtils::format_address(0x400000), "0x400000");
        assert_eq!(ProgramLocationUtils::parse_address("0x400000"), Some(0x400000));
        assert_eq!(ProgramLocationUtils::parse_address("400000"), Some(0x400000));
        assert_eq!(ProgramLocationUtils::parse_address("invalid"), None);
    }

    #[test]
    fn test_transaction_coalescer() {
        let mut coalescer = TransactionCoalescer::new(100);
        assert!(!coalescer.is_active());

        coalescer.start();
        assert!(coalescer.is_active());
        coalescer.add_operation("op1");
        coalescer.add_operation("op2");
        assert_eq!(coalescer.pending_count(), 2);

        let ops = coalescer.end();
        assert_eq!(ops.len(), 2);
        assert!(!coalescer.is_active());
    }

    #[test]
    fn test_misc_utils() {
        let a = vec![1, 2, 3, 4, 5];
        let b = vec![1, 2, 9, 4, 5];
        assert_eq!(MiscellaneousUtils::first_diff_offset(&a, &b), Some(2));

        let ranges = MiscellaneousUtils::diff_ranges(&a, &b);
        assert_eq!(ranges, vec![(2, 3)]);
    }

    #[test]
    fn test_diff_ranges_length_change() {
        let a = vec![1, 2, 3];
        let b = vec![1, 2, 3, 4, 5];
        let ranges = MiscellaneousUtils::diff_ranges(&a, &b);
        assert_eq!(ranges, vec![(3, 5)]);
    }
}
