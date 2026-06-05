//! Deep trace memory space interfaces.
//!
//! Ported from Ghidra's Framework-TraceModeling model interfaces for
//! `TraceMemorySpace`, `TraceMemoryOperations`, and memory buffer types.
//! These provide the higher-level memory access abstractions used by
//! the debugger framework.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::memory::TraceMemoryState;
use super::memory_flag::TraceMemoryFlag;
use super::lifespan::Lifespan;

/// A result from querying memory state in a space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryStateQuery {
    /// The state is known.
    Known(Vec<u8>),
    /// The state is unknown (never written).
    Unknown,
    /// The state is error (read failed).
    Error(String),
}

impl MemoryStateQuery {
    /// Whether the query returned known data.
    pub fn is_known(&self) -> bool {
        matches!(self, MemoryStateQuery::Known(_))
    }

    /// Get the data if known.
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            MemoryStateQuery::Known(d) => Some(d),
            _ => None,
        }
    }
}

/// A block of memory in a trace space.
///
/// Ported from Ghidra's trace memory block concept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMemoryBlock {
    /// The start address of the block.
    pub start: u64,
    /// The length of the block in bytes.
    pub length: u64,
    /// The permissions/flags for this block.
    pub flags: BTreeSet<TraceMemoryFlag>,
    /// Whether this block is initialized.
    pub initialized: bool,
    /// The name of the block.
    pub name: String,
}

impl TraceMemoryBlock {
    /// Create a new memory block.
    pub fn new(
        name: impl Into<String>,
        start: u64,
        length: u64,
    ) -> Self {
        Self {
            start,
            length,
            flags: BTreeSet::new(),
            initialized: true,
            name: name.into(),
        }
    }

    /// Get the end address (exclusive).
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.length)
    }

    /// Whether this block contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }

    /// Whether this block overlaps with a range.
    pub fn overlaps(&self, min: u64, max: u64) -> bool {
        self.start <= max && min < self.end()
    }

    /// Set a flag.
    pub fn set_flag(&mut self, flag: TraceMemoryFlag) {
        self.flags.insert(flag);
    }

    /// Check if a flag is set.
    pub fn has_flag(&self, flag: &TraceMemoryFlag) -> bool {
        self.flags.contains(flag)
    }

    /// Whether this block is readable.
    pub fn is_readable(&self) -> bool {
        self.has_flag(&TraceMemoryFlag::Read)
    }

    /// Whether this block is writable.
    pub fn is_writable(&self) -> bool {
        self.has_flag(&TraceMemoryFlag::Write)
    }

    /// Whether this block is executable.
    pub fn is_executable(&self) -> bool {
        self.has_flag(&TraceMemoryFlag::Execute)
    }
}

/// A compressed representation of memory bytes in a block.
///
/// Ported from Ghidra's concept of compressed memory storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedMemoryBlock {
    /// The base address offset.
    pub base_offset: u64,
    /// RLE-encoded data: (byte_value, count) pairs.
    pub rle_data: Vec<(u8, u32)>,
    /// Total uncompressed length.
    pub uncompressed_length: u64,
}

impl CompressedMemoryBlock {
    /// Create from raw bytes using simple RLE.
    pub fn from_bytes(base_offset: u64, data: &[u8]) -> Self {
        let mut rle = Vec::new();
        if !data.is_empty() {
            let mut current = data[0];
            let mut count: u32 = 1;
            for &b in &data[1..] {
                if b == current && count < u32::MAX {
                    count += 1;
                } else {
                    rle.push((current, count));
                    current = b;
                    count = 1;
                }
            }
            rle.push((current, count));
        }
        Self {
            base_offset,
            rle_data: rle,
            uncompressed_length: data.len() as u64,
        }
    }

    /// Decompress to raw bytes.
    pub fn decompress(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.uncompressed_length as usize);
        for &(byte, count) in &self.rle_data {
            for _ in 0..count {
                result.push(byte);
            }
        }
        result
    }

    /// Get the compression ratio.
    pub fn compression_ratio(&self) -> f64 {
        if self.uncompressed_length == 0 {
            return 0.0;
        }
        (self.rle_data.len() * 5) as f64 / self.uncompressed_length as f64
    }
}

/// A memory buffer interface for reading from a trace at a given snap.
///
/// Ported from Ghidra's `TraceMemorySpace` read operations.
#[derive(Debug, Clone)]
pub struct TraceMemoryBuffer {
    /// The snap at which this buffer reads.
    pub snap: i64,
    /// Cached data by address.
    pub data: BTreeMap<u64, Vec<u8>>,
    /// Known memory regions.
    pub blocks: Vec<TraceMemoryBlock>,
}

impl TraceMemoryBuffer {
    /// Create a new empty buffer.
    pub fn new(snap: i64) -> Self {
        Self {
            snap,
            data: BTreeMap::new(),
            blocks: Vec::new(),
        }
    }

    /// Add a block of data.
    pub fn put_bytes(&mut self, addr: u64, bytes: &[u8]) {
        self.data.insert(addr, bytes.to_vec());
    }

    /// Read bytes from the buffer.
    pub fn get_bytes(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        // Find the data entry that contains this address
        for (&base, data) in self.data.iter().rev() {
            if addr >= base && addr < base + data.len() as u64 {
                let offset = (addr - base) as usize;
                let available = data.len() - offset;
                let to_read = len.min(available);
                return Some(data[offset..offset + to_read].to_vec());
            }
        }
        None
    }

    /// Query memory state at an address.
    pub fn query_state(&self, addr: u64, len: usize) -> MemoryStateQuery {
        match self.get_bytes(addr, len) {
            Some(data) => MemoryStateQuery::Known(data),
            None => MemoryStateQuery::Unknown,
        }
    }

    /// Add a memory block.
    pub fn add_block(&mut self, block: TraceMemoryBlock) {
        self.blocks.push(block);
    }

    /// Check if an address is in a known block.
    pub fn is_in_block(&self, addr: u64) -> bool {
        self.blocks.iter().any(|b| b.contains(addr))
    }

    /// Get the block containing an address.
    pub fn get_block(&self, addr: u64) -> Option<&TraceMemoryBlock> {
        self.blocks.iter().find(|b| b.contains(addr))
    }
}

/// Represents a write to trace memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMemoryWrite {
    /// The snap at which the write occurred.
    pub snap: i64,
    /// The start address.
    pub address: u64,
    /// The bytes written.
    pub data: Vec<u8>,
    /// The thread that performed the write, if known.
    pub thread_id: Option<u64>,
}

impl TraceMemoryWrite {
    /// Create a new memory write.
    pub fn new(snap: i64, address: u64, data: Vec<u8>) -> Self {
        Self {
            snap,
            address,
            data,
            thread_id: None,
        }
    }

    /// Set the thread ID.
    pub fn with_thread(mut self, thread_id: u64) -> Self {
        self.thread_id = Some(thread_id);
        self
    }

    /// Get the end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.address + self.data.len() as u64
    }

    /// Length of the write in bytes.
    pub fn length(&self) -> usize {
        self.data.len()
    }
}

/// The memory state for a region in a trace.
///
/// Ported from Ghidra's `TraceMemoryState`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionMemoryState {
    /// Memory is fully known in this region.
    Known,
    /// Memory is partially known.
    Partial,
    /// Memory state is unknown.
    Unknown,
    /// Memory is inaccessible.
    Inaccessible,
}

impl RegionMemoryState {
    /// Whether the state represents readable memory.
    pub fn is_readable(&self) -> bool {
        matches!(self, RegionMemoryState::Known | RegionMemoryState::Partial)
    }
}

/// Information about a memory region in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMemoryRegionInfo {
    /// The region name.
    pub name: String,
    /// Start address.
    pub min_address: u64,
    /// End address (inclusive).
    pub max_address: u64,
    /// The lifespan of this region.
    pub lifespan: Lifespan,
    /// Region flags.
    pub flags: BTreeSet<TraceMemoryFlag>,
    /// The memory state.
    pub state: RegionMemoryState,
}

impl TraceMemoryRegionInfo {
    /// Create new region info.
    pub fn new(
        name: impl Into<String>,
        min_address: u64,
        max_address: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            name: name.into(),
            min_address,
            max_address,
            lifespan,
            flags: BTreeSet::new(),
            state: RegionMemoryState::Known,
        }
    }

    /// Length of the region in bytes.
    pub fn length(&self) -> u64 {
        self.max_address - self.min_address + 1
    }

    /// Whether an address falls within this region.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.min_address && addr <= self.max_address
    }

    /// Whether this region is valid at a given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_block() {
        let mut block = TraceMemoryBlock::new(".text", 0x400000, 0x1000);
        assert_eq!(block.end(), 0x401000);
        assert!(block.contains(0x400500));
        assert!(!block.contains(0x300000));
        assert!(!block.contains(0x401000)); // exclusive end

        block.set_flag(TraceMemoryFlag::Read);
        block.set_flag(TraceMemoryFlag::Execute);
        assert!(block.is_readable());
        assert!(!block.is_writable());
        assert!(block.is_executable());
    }

    #[test]
    fn test_memory_block_overlaps() {
        let block = TraceMemoryBlock::new("test", 100, 50);
        assert!(block.overlaps(90, 110));
        assert!(block.overlaps(140, 160));
        assert!(!block.overlaps(150, 200));
    }

    #[test]
    fn test_compressed_memory_block() {
        let data = vec![0u8; 100];
        let compressed = CompressedMemoryBlock::from_bytes(0, &data);
        assert_eq!(compressed.rle_data.len(), 1);
        assert_eq!(compressed.rle_data[0], (0, 100));
        assert_eq!(compressed.uncompressed_length, 100);

        let decompressed = compressed.decompress();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compressed_memory_mixed() {
        let data = vec![1, 1, 1, 2, 3, 3, 3, 3];
        let compressed = CompressedMemoryBlock::from_bytes(0, &data);
        assert_eq!(compressed.rle_data.len(), 3);
        assert_eq!(compressed.rle_data, vec![(1, 3), (2, 1), (3, 4)]);

        let decompressed = compressed.decompress();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_memory_buffer() {
        let mut buf = TraceMemoryBuffer::new(10);
        buf.put_bytes(0x1000, &[0x90, 0x90, 0xCC]);

        let bytes = buf.get_bytes(0x1000, 3).unwrap();
        assert_eq!(bytes, vec![0x90, 0x90, 0xCC]);

        let bytes = buf.get_bytes(0x1001, 2).unwrap();
        assert_eq!(bytes, vec![0x90, 0xCC]);

        assert!(buf.get_bytes(0x2000, 1).is_none());
    }

    #[test]
    fn test_memory_buffer_state_query() {
        let mut buf = TraceMemoryBuffer::new(0);
        buf.put_bytes(0, &[1, 2, 3]);

        let q = buf.query_state(0, 3);
        assert!(q.is_known());
        assert_eq!(q.data(), Some([1u8, 2, 3].as_slice()));

        let q = buf.query_state(100, 1);
        assert!(!q.is_known());
    }

    #[test]
    fn test_memory_buffer_blocks() {
        let mut buf = TraceMemoryBuffer::new(0);
        let block = TraceMemoryBlock::new(".data", 0x2000, 0x100);
        buf.add_block(block);

        assert!(buf.is_in_block(0x2050));
        assert!(!buf.is_in_block(0x3000));

        let b = buf.get_block(0x2050).unwrap();
        assert_eq!(b.name, ".data");
    }

    #[test]
    fn test_memory_write() {
        let write = TraceMemoryWrite::new(5, 0x1000, vec![0x90, 0x90])
            .with_thread(1);
        assert_eq!(write.end_address(), 0x1002);
        assert_eq!(write.length(), 2);
        assert_eq!(write.thread_id, Some(1));
    }

    #[test]
    fn test_region_memory_state() {
        assert!(RegionMemoryState::Known.is_readable());
        assert!(RegionMemoryState::Partial.is_readable());
        assert!(!RegionMemoryState::Unknown.is_readable());
        assert!(!RegionMemoryState::Inaccessible.is_readable());
    }

    #[test]
    fn test_memory_region_info() {
        let region = TraceMemoryRegionInfo::new("stack", 0x7FFE0000, 0x7FFFFFFF, Lifespan::span(0, 100));
        assert_eq!(region.length(), 0x20000);
        assert!(region.contains(0x7FFF0000));
        assert!(region.is_valid_at(50));
        assert!(!region.is_valid_at(200));
    }
}
