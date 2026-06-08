//! Address range splitter.
//!
//! Direct translation of `ghidra.program.model.address.AddressRangeSplitter`.
//!
//! Provides [`AddressRangeSplitter`] which takes a single address range and
//! breaks it into smaller sub-ranges of a specified maximum size. This is
//! useful for processing large address ranges in manageable chunks (e.g.,
//! reading memory into reasonably sized buffers).

use crate::addr::{Address, AddressRange};

/// Breaks a single address range into sub-ranges of a maximum size.
///
/// Corresponds to `ghidra.program.model.address.AddressRangeSplitter`.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::Address;
/// use ghidra_core::addr::range_splitter::AddressRangeSplitter;
///
/// let range = Address::new(0x1000)..=Address::new(0x10FF);
/// let splitter = AddressRangeSplitter::new(Address::new(0x1000), Address::new(0x10FF), 0x40, true);
///
/// let chunks: Vec<_> = splitter.collect();
/// assert_eq!(chunks.len(), 4);
/// assert_eq!(chunks[0].start.offset, 0x1000);
/// assert_eq!(chunks[0].end.offset, 0x103F);
/// ```
#[derive(Debug, Clone)]
pub struct AddressRangeSplitter {
    remaining: Option<(Address, Address)>,
    split_size: u64,
    forward: bool,
}

impl AddressRangeSplitter {
    /// Create a new range splitter.
    ///
    /// # Arguments
    /// * `min_addr` - the minimum address of the range
    /// * `max_addr` - the maximum address of the range
    /// * `split_size` - the maximum number of addresses per sub-range
    /// * `forward` - if true, produce ranges from low to high; otherwise high to low
    pub fn new(min_addr: Address, max_addr: Address, split_size: u64, forward: bool) -> Self {
        let remaining = if min_addr.offset <= max_addr && split_size > 0 {
            Some((min_addr, max_addr))
        } else {
            None
        };
        Self {
            remaining,
            split_size,
            forward,
        }
    }

    /// Create from an `AddressRange`.
    pub fn from_range(range: &AddressRange, split_size: u64, forward: bool) -> Self {
        Self::new(range.start, range.end, split_size, forward)
    }

    fn extract_chunk_from_start(&mut self) -> AddressRange {
        let (start, end) = self.remaining.unwrap();
        let chunk_end_offset = (start.offset + self.split_size - 1).min(end.offset);
        let chunk_end = Address::new(chunk_end_offset);

        if chunk_end.offset >= end.offset {
            self.remaining = None;
        } else {
            self.remaining = Some((chunk_end.next(), end));
        }

        AddressRange::new(start, chunk_end)
    }

    fn extract_chunk_from_end(&mut self) -> AddressRange {
        let (start, end) = self.remaining.unwrap();
        let chunk_start_offset = if end.offset >= self.split_size - 1 {
            end.offset - self.split_size + 1
        } else {
            0
        };
        let chunk_start = Address::new(chunk_start_offset.max(start.offset));

        if chunk_start.offset <= start.offset {
            self.remaining = None;
        } else {
            self.remaining = Some((start, chunk_start.prev()));
        }

        AddressRange::new(chunk_start, end)
    }
}

impl Iterator for AddressRangeSplitter {
    type Item = AddressRange;

    fn next(&mut self) -> Option<AddressRange> {
        let (start, end) = self.remaining?;

        // If the remaining range is small enough, return it as a single chunk
        let remaining_size = end.offset - start.offset + 1;
        if remaining_size <= self.split_size {
            self.remaining = None;
            return Some(AddressRange::new(start, end));
        }

        Some(if self.forward {
            self.extract_chunk_from_start()
        } else {
            self.extract_chunk_from_end()
        })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_splitting() {
        let splitter =
            AddressRangeSplitter::new(Address::new(0x1000), Address::new(0x10FF), 0x40, true);
        let chunks: Vec<AddressRange> = splitter.collect();

        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].start.offset, 0x1000);
        assert_eq!(chunks[0].end.offset, 0x103F);
        assert_eq!(chunks[1].start.offset, 0x1040);
        assert_eq!(chunks[1].end.offset, 0x107F);
        assert_eq!(chunks[2].start.offset, 0x1080);
        assert_eq!(chunks[2].end.offset, 0x10BF);
        assert_eq!(chunks[3].start.offset, 0x10C0);
        assert_eq!(chunks[3].end.offset, 0x10FF);
    }

    #[test]
    fn test_reverse_splitting() {
        let splitter =
            AddressRangeSplitter::new(Address::new(0x1000), Address::new(0x10FF), 0x40, false);
        let chunks: Vec<AddressRange> = splitter.collect();

        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].start.offset, 0x10C0);
        assert_eq!(chunks[0].end.offset, 0x10FF);
        assert_eq!(chunks[3].start.offset, 0x1000);
        assert_eq!(chunks[3].end.offset, 0x103F);
    }

    #[test]
    fn test_single_chunk() {
        let splitter =
            AddressRangeSplitter::new(Address::new(0x1000), Address::new(0x103F), 0x100, true);
        let chunks: Vec<AddressRange> = splitter.collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].start.offset, 0x1000);
        assert_eq!(chunks[0].end.offset, 0x103F);
    }

    #[test]
    fn test_exact_division() {
        let splitter =
            AddressRangeSplitter::new(Address::new(0), Address::new(99), 10, true);
        let chunks: Vec<AddressRange> = splitter.collect();
        assert_eq!(chunks.len(), 10);
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.start.offset, (i * 10) as u64);
            assert_eq!(chunk.end.offset, (i * 10 + 9) as u64);
        }
    }

    #[test]
    fn test_singleton_range() {
        let splitter =
            AddressRangeSplitter::new(Address::new(0x42), Address::new(0x42), 100, true);
        let chunks: Vec<AddressRange> = splitter.collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].start.offset, 0x42);
        assert_eq!(chunks[0].end.offset, 0x42);
    }

    #[test]
    fn test_no_gaps() {
        let splitter =
            AddressRangeSplitter::new(Address::new(0x1000), Address::new(0x1063), 30, true);
        let chunks: Vec<AddressRange> = splitter.collect();

        // Verify no gaps
        for i in 0..chunks.len() - 1 {
            assert_eq!(chunks[i].end.next(), chunks[i + 1].start);
        }
        // Verify boundaries
        assert_eq!(chunks.first().unwrap().start.offset, 0x1000);
        assert_eq!(chunks.last().unwrap().end.offset, 0x1063);
    }

    #[test]
    fn test_split_size_larger_than_range() {
        let splitter =
            AddressRangeSplitter::new(Address::new(0x100), Address::new(0x109), 1000, true);
        let chunks: Vec<AddressRange> = splitter.collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].start.offset, 0x100);
        assert_eq!(chunks[0].end.offset, 0x109);
    }

    #[test]
    fn test_from_range() {
        let range = AddressRange::new(Address::new(0x1000), Address::new(0x10FF));
        let splitter = AddressRangeSplitter::from_range(&range, 0x80, true);
        let chunks: Vec<AddressRange> = splitter.collect();
        assert_eq!(chunks.len(), 2);
    }
}
