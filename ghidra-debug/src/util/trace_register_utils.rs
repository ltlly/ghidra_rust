//! Register utility functions for trace debugging.
//!
//! Ported from Ghidra's `ghidra.trace.util.TraceRegisterUtils`.
//! Provides utility functions for working with registers in the context
//! of a debug trace, including register range computation, overlay space
//! handling, byte padding/truncation, register value encoding/decoding,
//! and register container lookup.

use std::collections::HashMap;

/// Compute the byte range for a register.
///
/// Given a register's address (offset) and size in bytes, return (start, end) inclusive.
/// Corresponds to Ghidra's `TraceRegisterUtils.rangeForRegister()`.
pub fn range_for_register(address: u64, num_bytes: u32) -> (u64, u64) {
    (address, address + num_bytes as u64 - 1)
}

/// Check whether a register's range intersects with a given address range.
///
/// Both ranges are (min, max) inclusive.
pub fn register_range_intersects(
    reg_min: u64,
    reg_max: u64,
    range_min: u64,
    range_max: u64,
) -> bool {
    reg_min <= range_max && range_min <= reg_max
}

/// Compute the intersection of two address ranges.
///
/// Returns `Some((start, end))` if the ranges intersect, `None` otherwise.
pub fn range_intersection(
    a_min: u64,
    a_max: u64,
    b_min: u64,
    b_max: u64,
) -> Option<(u64, u64)> {
    let start = a_min.max(b_min);
    let end = a_max.min(b_max);
    if start <= end {
        Some((start, end))
    } else {
        None
    }
}

/// Pad or truncate a byte array to a given length.
///
/// If the array is shorter, it is right-aligned (zero-padded on the left).
/// If the array is longer, the rightmost `length` bytes are returned.
/// Corresponds to Ghidra's `TraceRegisterUtils.padOrTruncate()`.
pub fn pad_or_truncate(arr: &[u8], length: usize) -> Vec<u8> {
    if arr.len() == length {
        return arr.to_vec();
    }
    if arr.len() < length {
        let mut result = vec![0u8; length];
        result[length - arr.len()..].copy_from_slice(arr);
        result
    } else {
        arr[arr.len() - length..].to_vec()
    }
}

/// Compute the mask offset for a sub-register within its base register.
///
/// This is the byte offset of the sub-register relative to the start of
/// its base register's mask.
/// Corresponds to Ghidra's `TraceRegisterUtils.computeMaskOffset()`.
pub fn compute_mask_offset(register_offset: u32, base_register_offset: u32) -> u32 {
    register_offset - base_register_offset
}

/// Check if a register is byte-aligned (LSB on byte boundary, bit length is whole bytes).
///
/// Corresponds to Ghidra's `TraceRegisterUtils.isByteBound()`.
pub fn is_byte_bound(lsb: u32, bit_length: u32) -> bool {
    lsb % 8 == 0 && bit_length % 8 == 0
}

/// Require that a register is byte-aligned, or return an error.
pub fn require_byte_bound(lsb: u32, bit_length: u32) -> Result<(), String> {
    if is_byte_bound(lsb, bit_length) {
        Ok(())
    } else {
        Err("Cannot work with sub-byte registers. Consider a parent instead.".to_string())
    }
}

/// Reverse a portion of a byte array in-place.
///
/// Corresponds to Apache Commons `ArrayUtils.reverse(bytes, from, to)`.
pub fn reverse_bytes(bytes: &mut [u8], from: usize, to: usize) {
    let mut i = from;
    let mut j = to.saturating_sub(1);
    while i < j {
        bytes.swap(i, j);
        i += 1;
        j = j.saturating_sub(1);
    }
}

/// Encode a register value from bytes, handling endianness.
///
/// For a little-endian register that is not a processor context register,
/// the value bytes are reversed. Returns the resulting byte buffer.
pub fn encode_register_value(
    raw_bytes: &[u8],
    is_big_endian: bool,
    is_processor_context: bool,
    byte_length: usize,
) -> Vec<u8> {
    let mut bytes = raw_bytes.to_vec();
    let start = bytes.len() / 2;
    let end = bytes.len();

    // Context registers are always big-endian
    if !is_big_endian && !is_processor_context {
        reverse_bytes(&mut bytes, start, end);
    }

    // Extract the relevant portion
    if start + byte_length <= bytes.len() {
        bytes[start..start + byte_length].to_vec()
    } else {
        pad_or_truncate(&bytes[start..], byte_length)
    }
}

/// Prepare a byte buffer for reading a register value.
///
/// Creates a buffer of the correct size (mask.length * 2) with the mask
/// placed at the beginning. Returns the buffer and the start position
/// for the value.
pub fn prepare_register_buffer(mask: &[u8], _mask_offset: usize) -> Vec<u8> {
    let total_size = mask.len() * 2;
    let mut buf = vec![0u8; total_size];
    buf[..mask.len()].copy_from_slice(mask);
    buf
}

/// Decode a register value from a buffer, handling endianness.
///
/// Takes the raw buffer (mask + value) and extracts the register value,
/// reversing bytes for little-endian registers if needed.
pub fn decode_register_value(
    buf: &[u8],
    mask_length: usize,
    is_big_endian: bool,
    is_processor_context: bool,
) -> Vec<u8> {
    let mut result = buf.to_vec();
    let len = result.len();
    if !is_big_endian && !is_processor_context && mask_length < len {
        reverse_bytes(&mut result, mask_length, len);
    }
    result
}

/// A register index for fast lookup by address range.
///
/// Corresponds to Ghidra's inner `TraceRegisterUtils.RegisterIndex`.
#[derive(Debug, Clone, Default)]
pub struct RegisterIndex {
    /// Maps base address -> (size, set of register names at that address)
    entries: HashMap<u64, (u32, Vec<String>)>,
}

impl RegisterIndex {
    /// Create a new empty register index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a register to the index.
    pub fn add_register(&mut self, name: impl Into<String>, address: u64, size: u32) {
        let entry = self.entries.entry(address).or_insert((size, Vec::new()));
        entry.1.push(name.into());
    }

    /// Find all registers whose ranges intersect the given range.
    pub fn find_intersecting(&self, range_min: u64, range_max: u64) -> Vec<&str> {
        let mut result = Vec::new();
        for (&addr, &(size, ref names)) in &self.entries {
            let (reg_min, reg_max) = range_for_register(addr, size);
            if register_range_intersects(reg_min, reg_max, range_min, range_max) {
                for name in names {
                    result.push(name.as_str());
                }
            }
        }
        result
    }

    /// Get the number of registered base addresses.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Utility to compute overlay address mappings.
///
/// When working with overlay address spaces, this function converts an
/// address range from an overlay space to the corresponding range in
/// the physical space.
///
/// Returns the converted (min, max) in the physical space.
pub fn get_physical_range(
    range_min: u64,
    range_max: u64,
    _overlay_base: u64,
    _physical_base: u64,
) -> (u64, u64) {
    // In Ghidra's model, the overlay range maps to the same offset in the physical space.
    // The overlay_base and physical_base are the same offset; the overlay is just a name alias.
    (range_min, range_max)
}

/// Convert an address set (as min/max ranges) from overlay space to physical space.
pub fn get_physical_ranges(
    ranges: &[(u64, u64)],
    overlay_base: u64,
    physical_base: u64,
) -> Vec<(u64, u64)> {
    ranges
        .iter()
        .map(|&(min, max)| get_physical_range(min, max, overlay_base, physical_base))
        .collect()
}

/// Seek through a composite data structure to find the component at a given range.
///
/// Takes a flat list of components (offset, size) and finds which component
/// contains the requested range. Returns the component index if found.
///
/// Corresponds to Ghidra's `TraceRegisterUtils.seekComponent()`.
pub fn seek_component(
    components: &[(u64, u32)], // (offset_from_base, size)
    target_offset: u64,
    target_size: u32,
) -> Option<usize> {
    let target_end = target_offset + target_size as u64 - 1;
    for (i, &(comp_offset, comp_size)) in components.iter().enumerate() {
        let comp_end = comp_offset + comp_size as u64 - 1;
        if comp_offset <= target_offset && target_end <= comp_end {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_for_register() {
        let (min, max) = range_for_register(0x1000, 4);
        assert_eq!(min, 0x1000);
        assert_eq!(max, 0x1003);
    }

    #[test]
    fn test_register_range_intersects() {
        assert!(register_range_intersects(0, 10, 5, 15));
        assert!(register_range_intersects(5, 15, 0, 10));
        assert!(!register_range_intersects(0, 4, 5, 10));
        assert!(register_range_intersects(0, 5, 5, 10)); // edge: exactly touching
    }

    #[test]
    fn test_range_intersection() {
        assert_eq!(range_intersection(0, 10, 5, 15), Some((5, 10)));
        assert_eq!(range_intersection(0, 4, 5, 10), None);
        assert_eq!(range_intersection(5, 10, 0, 4), None);
        assert_eq!(range_intersection(0, 0, 0, 0), Some((0, 0)));
    }

    #[test]
    fn test_pad_or_truncate_same() {
        let arr = [1, 2, 3];
        assert_eq!(pad_or_truncate(&arr, 3), vec![1, 2, 3]);
    }

    #[test]
    fn test_pad_or_truncate_shorter() {
        let arr = [1, 2];
        let result = pad_or_truncate(&arr, 4);
        assert_eq!(result, vec![0, 0, 1, 2]); // right-aligned
    }

    #[test]
    fn test_pad_or_truncate_longer() {
        let arr = [1, 2, 3, 4, 5];
        let result = pad_or_truncate(&arr, 3);
        assert_eq!(result, vec![3, 4, 5]); // rightmost 3 bytes
    }

    #[test]
    fn test_compute_mask_offset() {
        assert_eq!(compute_mask_offset(4, 0), 4);
        assert_eq!(compute_mask_offset(0, 0), 0);
        assert_eq!(compute_mask_offset(8, 4), 4);
    }

    #[test]
    fn test_is_byte_bound() {
        assert!(is_byte_bound(0, 32));
        assert!(is_byte_bound(0, 8));
        assert!(is_byte_bound(8, 16));
        assert!(!is_byte_bound(1, 8));
        assert!(!is_byte_bound(0, 5));
    }

    #[test]
    fn test_require_byte_bound() {
        assert!(require_byte_bound(0, 32).is_ok());
        assert!(require_byte_bound(1, 8).is_err());
    }

    #[test]
    fn test_reverse_bytes() {
        let mut arr = [1, 2, 3, 4, 5];
        reverse_bytes(&mut arr, 1, 4);
        assert_eq!(arr, [1, 4, 3, 2, 5]);
    }

    #[test]
    fn test_encode_register_value() {
        let raw = [0, 0, 0x12, 0x34]; // mask | value
        let result = encode_register_value(&raw, true, false, 2);
        assert_eq!(result, vec![0x12, 0x34]);
    }

    #[test]
    fn test_encode_register_value_little_endian() {
        let raw = [0, 0, 0x34, 0x12]; // mask | value (LE)
        let result = encode_register_value(&raw, false, false, 2);
        // LE: bytes are reversed, so [0x12, 0x34]
        assert_eq!(result, vec![0x12, 0x34]);
    }

    #[test]
    fn test_register_index() {
        let mut idx = RegisterIndex::new();
        idx.add_register("RAX", 0, 8);
        idx.add_register("EAX", 0, 4);
        idx.add_register("RBX", 8, 8);

        let results = idx.find_intersecting(0, 3);
        assert_eq!(results.len(), 2);
        assert!(results.contains(&"RAX"));
        assert!(results.contains(&"EAX"));

        let results = idx.find_intersecting(8, 15);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "RBX");
    }

    #[test]
    fn test_seek_component() {
        // struct { int a; long b; char c; }
        let components = vec![
            (0, 4),  // a: offset 0, size 4
            (4, 8),  // b: offset 4, size 8
            (12, 1), // c: offset 12, size 1
        ];

        assert_eq!(seek_component(&components, 0, 4), Some(0));
        assert_eq!(seek_component(&components, 4, 8), Some(1));
        assert_eq!(seek_component(&components, 12, 1), Some(2));
        assert_eq!(seek_component(&components, 0, 8), None); // spans a and b
    }

    #[test]
    fn test_get_physical_ranges() {
        let ranges = vec![(0x1000, 0x1FFF), (0x2000, 0x2FFF)];
        let physical = get_physical_ranges(&ranges, 0, 0);
        assert_eq!(physical, ranges);
    }
}
