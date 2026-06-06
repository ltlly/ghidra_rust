//! `ProgramByteSource` -- byte source backed by a program's memory.
//!
//! Ported from `ghidra.features.base.memsearch.bytesource.ProgramByteSource`.

use crate::memsearch::bytesource::addressable::AddressableByteSource;
use crate::memsearch::bytesource::search_region::{ProgramSearchRegion, SearchRegion};

/// Byte source implementation that reads from a Ghidra program's memory.
///
/// Provides access to loaded and initialized memory blocks.
pub struct ProgramByteSource {
    /// Base address of the program image.
    image_base: u64,
    /// Name of the program for display purposes.
    program_name: String,
    /// Raw memory data indexed by address range.
    memory_blocks: Vec<(u64, u64, Vec<u8>)>, // (start, end, data)
}

impl ProgramByteSource {
    /// Create a new program byte source.
    pub fn new(program_name: &str, image_base: u64) -> Self {
        Self {
            image_base,
            program_name: program_name.to_string(),
            memory_blocks: Vec::new(),
        }
    }

    /// Add a memory block to this byte source.
    pub fn add_memory_block(&mut self, start: u64, data: Vec<u8>) {
        let end = start + data.len() as u64;
        self.memory_blocks.push((start, end, data));
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Get the image base address.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Get the total number of bytes across all memory blocks.
    pub fn total_bytes(&self) -> u64 {
        self.memory_blocks.iter().map(|(_, _, d)| d.len() as u64).sum()
    }
}

impl AddressableByteSource for ProgramByteSource {
    fn get_bytes(&self, address: u64, buffer: &mut [u8], length: usize) -> usize {
        for (start, end, data) in &self.memory_blocks {
            if address >= *start && address < *end {
                let offset = (address - *start) as usize;
                let available = data.len() - offset;
                let count = length.min(available).min(buffer.len());
                buffer[..count].copy_from_slice(&data[offset..offset + count]);
                return count;
            }
        }
        0
    }

    fn get_searchable_regions(&self) -> Vec<Box<dyn SearchRegion>> {
        vec![
            Box::new(ProgramSearchRegion::Loaded),
            Box::new(ProgramSearchRegion::Other),
        ]
    }

    fn invalidate(&self) {
        // nothing to do for the static case
    }

    fn get_canonical_offset(&self, address: u64) -> u64 {
        address
    }

    fn rebase_from_canonical(&self, canonical_offset: u64) -> u64 {
        let offset = canonical_offset.wrapping_sub(self.image_base);
        self.image_base.wrapping_add(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_byte_source_basic() {
        let mut source = ProgramByteSource::new("test.exe", 0x400000);
        source.add_memory_block(0x401000, vec![0x55, 0x89, 0xE5, 0x83]);

        let mut buf = [0u8; 4];
        let n = source.get_bytes(0x401000, &mut buf, 4);
        assert_eq!(n, 4);
        assert_eq!(buf, [0x55, 0x89, 0xE5, 0x83]);
    }

    #[test]
    fn test_program_byte_source_partial() {
        let mut source = ProgramByteSource::new("test.exe", 0x400000);
        source.add_memory_block(0x401000, vec![0x55, 0x89]);

        let mut buf = [0u8; 4];
        let n = source.get_bytes(0x401000, &mut buf, 4);
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], &[0x55, 0x89]);
    }

    #[test]
    fn test_program_byte_source_out_of_range() {
        let mut source = ProgramByteSource::new("test.exe", 0x400000);
        source.add_memory_block(0x401000, vec![0x55, 0x89]);

        let mut buf = [0u8; 4];
        let n = source.get_bytes(0x500000, &mut buf, 4);
        assert_eq!(n, 0);
    }

    #[test]
    fn test_searchable_regions() {
        let source = ProgramByteSource::new("test.exe", 0x400000);
        let regions = source.get_searchable_regions();
        assert_eq!(regions.len(), 2);
    }

    #[test]
    fn test_rebase() {
        let source = ProgramByteSource::new("test.exe", 0x400000);
        let addr = source.rebase_from_canonical(0x401000);
        assert_eq!(addr, 0x401000);
    }

    #[test]
    fn test_total_bytes() {
        let mut source = ProgramByteSource::new("test.exe", 0x400000);
        source.add_memory_block(0x401000, vec![0u8; 256]);
        source.add_memory_block(0x402000, vec![0u8; 512]);
        assert_eq!(source.total_bytes(), 768);
    }
}
