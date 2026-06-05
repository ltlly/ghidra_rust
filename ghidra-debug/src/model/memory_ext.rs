//! Extended memory types for traces.
//!
//! Ported from Ghidra's `ghidra.trace.model.memory` package:
//! - TraceMemorySpaceInputStream: an InputStream over a trace memory space
//! - TraceOverlappedRegionException: thrown when regions overlap
//! - TraceRegisterContainer (re-export from register.rs)
//!
//! Also provides memory-related utility functions.

use std::io::{self, Read};

use thiserror::Error;

use super::memory::TraceMemoryRegion;

/// An error indicating that memory regions overlap.
///
/// Thrown when attempting to create a memory region that overlaps
/// with one or more existing regions.
#[derive(Debug, Error)]
#[error("overlaps other regions: {conflict_count} conflict(s)")]
pub struct TraceOverlappedRegionException {
    /// The conflicting regions.
    pub conflicts: Vec<TraceMemoryRegion>,
    /// The number of conflicts.
    pub conflict_count: usize,
}

impl TraceOverlappedRegionException {
    /// Create a new overlap exception.
    pub fn new(conflicts: Vec<TraceMemoryRegion>) -> Self {
        let conflict_count = conflicts.len();
        Self {
            conflicts,
            conflict_count,
        }
    }

    /// Get the conflicting regions.
    pub fn get_conflicts(&self) -> &[TraceMemoryRegion] {
        &self.conflicts
    }
}

/// An `io::Read` implementation that reads from a trace memory space.
///
/// Equivalent to Ghidra's `TraceMemorySpaceInputStream`. Reads bytes
/// from a region of memory in a trace at a given snapshot.
pub struct TraceMemorySpaceInputStream {
    /// The bytes to read from (pre-fetched from the trace).
    data: Vec<u8>,
    /// Current read position.
    pos: usize,
    /// Mark position for mark/reset support.
    mark: Option<usize>,
}

impl TraceMemorySpaceInputStream {
    /// Create a new memory input stream from a byte buffer.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            pos: 0,
            mark: None,
        }
    }

    /// Create a new memory input stream from a slice of bytes.
    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }

    /// Get the number of bytes still available for reading.
    pub fn available(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Get the total size of the underlying data.
    pub fn total_size(&self) -> usize {
        self.data.len()
    }

    /// Get the current read position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Mark the current position (for later reset).
    pub fn mark(&mut self) {
        self.mark = Some(self.pos);
    }

    /// Reset to the last marked position.
    pub fn reset(&mut self) -> io::Result<()> {
        match self.mark {
            Some(m) => {
                self.pos = m;
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::Other,
                "mark not set",
            )),
        }
    }

    /// Whether mark/reset is supported (always true for this type).
    pub fn mark_supported(&self) -> bool {
        true
    }

    /// Skip the specified number of bytes.
    pub fn skip(&mut self, n: usize) -> usize {
        let skipped = std::cmp::min(self.available(), n);
        self.pos += skipped;
        skipped
    }
}

impl Read for TraceMemorySpaceInputStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.available();
        if available == 0 {
            return Ok(0);
        }
        let to_read = std::cmp::min(buf.len(), available);
        buf[..to_read].copy_from_slice(&self.data[self.pos..self.pos + to_read]);
        self.pos += to_read;
        Ok(to_read)
    }
}

/// A builder for constructing memory region maps with overlap detection.
#[derive(Debug, Clone, Default)]
pub struct MemoryRegionBuilder {
    regions: Vec<TraceMemoryRegion>,
}

impl MemoryRegionBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a region, checking for overlaps.
    pub fn add_region(
        &mut self,
        region: TraceMemoryRegion,
    ) -> Result<(), TraceOverlappedRegionException> {
        let conflicts: Vec<TraceMemoryRegion> = self
            .regions
            .iter()
            .filter(|r| {
                r.min_offset <= region.max_offset && region.min_offset <= r.max_offset
            })
            .cloned()
            .collect();

        if !conflicts.is_empty() {
            return Err(TraceOverlappedRegionException::new(conflicts));
        }

        self.regions.push(region);
        Ok(())
    }

    /// Get all registered regions.
    pub fn regions(&self) -> &[TraceMemoryRegion] {
        &self.regions
    }

    /// Find the region containing the given offset.
    pub fn find_region(&self, offset: u64) -> Option<&TraceMemoryRegion> {
        self.regions
            .iter()
            .find(|r| offset >= r.min_offset && offset <= r.max_offset)
    }

    /// Get the number of regions.
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Whether the builder has no regions.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::memory::TraceMemoryState;

    #[test]
    fn test_overlapped_region_exception() {
        let conflicts = vec![
            TraceMemoryRegion::new(0x100, 0x200, TraceMemoryState::Known),
            TraceMemoryRegion::new(0x180, 0x300, TraceMemoryState::Known),
        ];
        let e = TraceOverlappedRegionException::new(conflicts);
        assert_eq!(e.conflict_count, 2);
        let err_str = format!("{}", e);
        assert!(err_str.contains("2 conflict"));
    }

    #[test]
    fn test_memory_input_stream_basic() {
        let data = vec![0x90, 0xcc, 0xc3, 0x48, 0x89];
        let mut stream = TraceMemorySpaceInputStream::new(data);
        assert_eq!(stream.available(), 5);
        assert_eq!(stream.total_size(), 5);
        assert_eq!(stream.position(), 0);

        let mut buf = [0u8; 3];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf, [0x90, 0xcc, 0xc3]);
        assert_eq!(stream.position(), 3);
        assert_eq!(stream.available(), 2);
    }

    #[test]
    fn test_memory_input_stream_eof() {
        let data = vec![0x42];
        let mut stream = TraceMemorySpaceInputStream::new(data);

        let mut buf = [0u8; 10];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x42);

        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_memory_input_stream_mark_reset() {
        let data = vec![1, 2, 3, 4, 5];
        let mut stream = TraceMemorySpaceInputStream::new(data);

        let mut buf = [0u8; 2];
        stream.read(&mut buf).unwrap();
        assert_eq!(buf, [1, 2]);

        stream.mark();
        stream.read(&mut buf).unwrap();
        assert_eq!(buf, [3, 4]);

        stream.reset().unwrap();
        assert_eq!(stream.position(), 2);

        stream.read(&mut buf).unwrap();
        assert_eq!(buf, [3, 4]);
    }

    #[test]
    fn test_memory_input_stream_skip() {
        let data = vec![1, 2, 3, 4, 5];
        let mut stream = TraceMemorySpaceInputStream::new(data);

        let skipped = stream.skip(3);
        assert_eq!(skipped, 3);
        assert_eq!(stream.position(), 3);

        let mut buf = [0u8; 1];
        stream.read(&mut buf).unwrap();
        assert_eq!(buf[0], 4);
    }

    #[test]
    fn test_memory_input_stream_skip_past_end() {
        let data = vec![1, 2, 3];
        let mut stream = TraceMemorySpaceInputStream::new(data);

        let skipped = stream.skip(100);
        assert_eq!(skipped, 3);
        assert_eq!(stream.available(), 0);
    }

    #[test]
    fn test_memory_input_stream_reset_without_mark() {
        let data = vec![1, 2];
        let mut stream = TraceMemorySpaceInputStream::new(data);
        assert!(stream.reset().is_err());
    }

    #[test]
    fn test_memory_input_stream_from_slice() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let mut stream = TraceMemorySpaceInputStream::from_slice(&data);
        let mut buf = [0u8; 4];
        stream.read(&mut buf).unwrap();
        assert_eq!(buf, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_region_builder_no_overlap() {
        let mut builder = MemoryRegionBuilder::new();
        builder
            .add_region(TraceMemoryRegion::new(
                0x100,
                0x200,
                TraceMemoryState::Known,
            ))
            .unwrap();
        builder
            .add_region(TraceMemoryRegion::new(
                0x300,
                0x400,
                TraceMemoryState::Known,
            ))
            .unwrap();
        assert_eq!(builder.len(), 2);
    }

    #[test]
    fn test_region_builder_overlap() {
        let mut builder = MemoryRegionBuilder::new();
        builder
            .add_region(TraceMemoryRegion::new(
                0x100,
                0x200,
                TraceMemoryState::Known,
            ))
            .unwrap();
        let result = builder.add_region(TraceMemoryRegion::new(
            0x180,
            0x300,
            TraceMemoryState::Known,
        ));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.conflict_count, 1);
    }

    #[test]
    fn test_region_builder_find() {
        let mut builder = MemoryRegionBuilder::new();
        builder
            .add_region(TraceMemoryRegion::new(
                0x100,
                0x200,
                TraceMemoryState::Known,
            ))
            .unwrap();
        assert!(builder.find_region(0x150).is_some());
        assert!(builder.find_region(0x250).is_none());
    }
}
