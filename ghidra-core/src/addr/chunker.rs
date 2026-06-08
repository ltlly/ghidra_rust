//! Address range chunking utilities for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.address.AddressRangeChunker`.
//!
//! Provides [`AddressRangeChunker`] for breaking a range of addresses into
//! fixed-size chunks. This is useful for processing large address ranges in
//! background threads, allowing periodic UI updates.

use crate::addr::{Address, AddressRange};
use std::fmt;

/// A class to break a range of addresses into chunks of a given size.
///
/// Corresponds to `ghidra.program.model.address.AddressRangeChunker`.
///
/// This is useful for breaking up processing of large swaths of addresses,
/// such as when performing work in a background thread. Doing this allows
/// the client to iterate over the range, pausing enough to allow the UI
/// to update.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::{Address, AddressRange};
/// use ghidra_core::addr::chunker::AddressRangeChunker;
///
/// let start = Address::new(0x1000);
/// let end = Address::new(0x10FF);
/// let chunker = AddressRangeChunker::new(start, end, 0x40).unwrap();
///
/// let chunks: Vec<AddressRange> = chunker.collect();
/// assert_eq!(chunks.len(), 4);
/// assert_eq!(chunks[0].start.offset, 0x1000);
/// assert_eq!(chunks[0].end.offset, 0x103F);
/// assert_eq!(chunks[3].start.offset, 0x10C0);
/// assert_eq!(chunks[3].end.offset, 0x10FF);
/// ```
#[derive(Debug, Clone)]
pub struct AddressRangeChunker {
    /// The end address (inclusive) of the full range.
    end: Address,
    /// The start address of the next chunk to produce.
    next_start: Option<Address>,
    /// The size of each chunk (unsigned).
    chunk_size: u64,
}

impl AddressRangeChunker {
    /// Create a new chunker from an address range and chunk size.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `chunk_size` is 0
    /// - `start` is after `end`
    pub fn from_range(range: AddressRange, chunk_size: u64) -> Result<Self, ChunkerError> {
        Self::new(range.start, range.end, chunk_size)
    }

    /// Create a new chunker from start/end addresses and chunk size.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `chunk_size` is 0
    /// - `start` is after `end`
    pub fn new(start: Address, end: Address, chunk_size: u64) -> Result<Self, ChunkerError> {
        if chunk_size == 0 {
            return Err(ChunkerError::ZeroChunkSize);
        }
        if start.offset > end.offset {
            return Err(ChunkerError::StartAfterEnd {
                start: start.offset,
                end: end.offset,
            });
        }
        Ok(Self {
            end,
            next_start: Some(start),
            chunk_size,
        })
    }

    /// Returns the total number of chunks that will be produced.
    ///
    /// This is a best-effort calculation; the actual number may differ
    /// if the range size is not evenly divisible by the chunk size.
    pub fn num_chunks(&self) -> u64 {
        let total = self.end.offset - self.next_start.map(|a| a.offset).unwrap_or(self.end.offset) + 1;
        (total + self.chunk_size - 1) / self.chunk_size
    }

    /// Returns the chunk size.
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }
}

impl Iterator for AddressRangeChunker {
    type Item = AddressRange;

    fn next(&mut self) -> Option<AddressRange> {
        let start = self.next_start?;

        let available_less1 = self.end.offset.wrapping_sub(start.offset);
        let size_less1 = self.chunk_size.wrapping_sub(1).min(available_less1);

        let chunk_end = start.add(size_less1);

        // Advance next_start
        if chunk_end.offset == self.end.offset {
            self.next_start = None; // no more
        } else {
            self.next_start = Some(chunk_end.next());
        }

        Some(AddressRange::new(start, chunk_end))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if let Some(start) = self.next_start {
            let total = self.end.offset - start.offset + 1;
            let n = ((total + self.chunk_size - 1) / self.chunk_size) as usize;
            (n, Some(n))
        } else {
            (0, Some(0))
        }
    }
}

impl ExactSizeIterator for AddressRangeChunker {}

/// Error type for [`AddressRangeChunker`] construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkerError {
    /// Chunk size was zero.
    ZeroChunkSize,
    /// Start address is after end address.
    StartAfterEnd { start: u64, end: u64 },
}

impl fmt::Display for ChunkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChunkerError::ZeroChunkSize => write!(f, "Chunk size must be greater than 0"),
            ChunkerError::StartAfterEnd { start, end } => {
                write!(f, "Start address 0x{:x} is after end address 0x{:x}", start, end)
            }
        }
    }
}

impl std::error::Error for ChunkerError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_chunking() {
        let start = Address::new(0x1000);
        let end = Address::new(0x10FF);
        let chunker = AddressRangeChunker::new(start, end, 0x40).unwrap();

        let chunks: Vec<AddressRange> = chunker.collect();
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
    fn test_exact_division() {
        let start = Address::new(0);
        let end = Address::new(99);
        let chunker = AddressRangeChunker::new(start, end, 10).unwrap();

        let chunks: Vec<AddressRange> = chunker.collect();
        assert_eq!(chunks.len(), 10);
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.start.offset, (i * 10) as u64);
            assert_eq!(chunk.end.offset, (i * 10 + 9) as u64);
        }
    }

    #[test]
    fn test_single_chunk() {
        let start = Address::new(0x100);
        let end = Address::new(0x109);
        let chunker = AddressRangeChunker::new(start, end, 100).unwrap();

        let chunks: Vec<AddressRange> = chunker.collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].start.offset, 0x100);
        assert_eq!(chunks[0].end.offset, 0x109);
    }

    #[test]
    fn test_singleton_range() {
        let addr = Address::new(0x42);
        let chunker = AddressRangeChunker::new(addr, addr, 1).unwrap();

        let chunks: Vec<AddressRange> = chunker.collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].start.offset, 0x42);
        assert_eq!(chunks[0].end.offset, 0x42);
    }

    #[test]
    fn test_size_hint() {
        let start = Address::new(0);
        let end = Address::new(99);
        let chunker = AddressRangeChunker::new(start, end, 10).unwrap();

        assert_eq!(chunker.size_hint(), (10, Some(10)));
    }

    #[test]
    fn test_exact_size_iterator() {
        let start = Address::new(0);
        let end = Address::new(99);
        let chunker = AddressRangeChunker::new(start, end, 10).unwrap();

        assert_eq!(chunker.len(), 10);
    }

    #[test]
    fn test_num_chunks() {
        let start = Address::new(0);
        let end = Address::new(99);
        let chunker = AddressRangeChunker::new(start, end, 10).unwrap();
        assert_eq!(chunker.num_chunks(), 10);

        let chunker = AddressRangeChunker::new(start, end, 7).unwrap();
        assert_eq!(chunker.num_chunks(), 15); // ceil(100/7)
    }

    #[test]
    fn test_chunk_size() {
        let chunker = AddressRangeChunker::new(Address::new(0), Address::new(99), 42).unwrap();
        assert_eq!(chunker.chunk_size(), 42);
    }

    #[test]
    fn test_error_zero_chunk_size() {
        let result = AddressRangeChunker::new(Address::new(0), Address::new(99), 0);
        assert_eq!(result.unwrap_err(), ChunkerError::ZeroChunkSize);
    }

    #[test]
    fn test_error_start_after_end() {
        let result = AddressRangeChunker::new(Address::new(100), Address::new(50), 10);
        assert_eq!(
            result.unwrap_err(),
            ChunkerError::StartAfterEnd {
                start: 100,
                end: 50
            }
        );
    }

    #[test]
    fn test_from_range() {
        let range = AddressRange::new(Address::new(0), Address::new(99));
        let chunker = AddressRangeChunker::from_range(range, 10).unwrap();
        assert_eq!(chunker.len(), 10);
    }

    #[test]
    fn test_all_addresses_covered() {
        let start = Address::new(0x1000);
        let end = Address::new(0x1063); // 100 addresses
        let chunker = AddressRangeChunker::new(start, end, 30).unwrap();

        let chunks: Vec<AddressRange> = chunker.collect();
        // Verify no gaps
        for i in 0..chunks.len() - 1 {
            assert_eq!(chunks[i].end.next(), chunks[i + 1].start);
        }
        // Verify boundaries
        assert_eq!(chunks.first().unwrap().start, start);
        assert_eq!(chunks.last().unwrap().end, end);
    }

    #[test]
    fn test_display_error() {
        let err = ChunkerError::ZeroChunkSize;
        assert!(format!("{}", err).contains("greater than 0"));

        let err = ChunkerError::StartAfterEnd {
            start: 0x100,
            end: 0x50,
        };
        assert!(format!("{}", err).contains("0x100"));
        assert!(format!("{}", err).contains("0x50"));
    }
}
