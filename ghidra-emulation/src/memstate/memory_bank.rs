//! Memory bank for page-based memory storage.
//!
//! Ported from Java: `ghidra.pcode.memstate.MemoryBank`.
//!
//! A MemoryBank is associated with a specific address space and provides
//! page-based storage for emulation.

use super::memory_fault_handler::{DefaultMemoryFaultHandler, MemoryFaultHandler};
use super::memory_page::MemoryPage;
use std::collections::HashMap;

/// A memory bank provides page-based storage for a specific address space.
///
/// Memory is divided into fixed-size pages. Each page tracks which bytes
/// have been initialized.
pub struct MemoryBank {
    /// Number of bytes in an aligned page.
    page_size: usize,
    /// Name of the address space.
    space_name: String,
    /// Whether this bank uses big-endian byte order.
    is_big_endian: bool,
    /// Number of bytes required for the uninitialized mask per page.
    initialized_mask_size: usize,
    /// The pages in this bank, keyed by aligned page address.
    pages: HashMap<u64, MemoryPage>,
    /// Fault handler for uninitialized reads.
    fault_handler: Box<dyn MemoryFaultHandler>,
}

impl std::fmt::Debug for MemoryBank {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryBank")
            .field("page_size", &self.page_size)
            .field("space_name", &self.space_name)
            .field("is_big_endian", &self.is_big_endian)
            .field("num_pages", &self.pages.len())
            .finish()
    }
}

impl MemoryBank {
    /// Create a new memory bank.
    ///
    /// # Arguments
    /// * `space_name` - name of the address space
    /// * `is_big_endian` - whether to use big-endian byte order
    /// * `page_size` - number of bytes in a page (must be a power of 2)
    pub fn new(space_name: impl Into<String>, is_big_endian: bool, page_size: usize) -> Self {
        Self {
            page_size,
            space_name: space_name.into(),
            is_big_endian,
            initialized_mask_size: (page_size + 7) / 8,
            pages: HashMap::new(),
            fault_handler: Box::new(DefaultMemoryFaultHandler),
        }
    }

    /// Create a new memory bank with a custom fault handler.
    pub fn with_fault_handler(
        space_name: impl Into<String>,
        is_big_endian: bool,
        page_size: usize,
        fault_handler: Box<dyn MemoryFaultHandler>,
    ) -> Self {
        Self {
            page_size,
            space_name: space_name.into(),
            is_big_endian,
            initialized_mask_size: (page_size + 7) / 8,
            pages: HashMap::new(),
            fault_handler,
        }
    }

    /// Get the page size.
    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// Get the address space name.
    pub fn space_name(&self) -> &str {
        &self.space_name
    }

    /// Check if this bank uses big-endian byte order.
    pub fn is_big_endian(&self) -> bool {
        self.is_big_endian
    }

    /// Get the initialized mask size in bytes.
    pub fn initialized_mask_size(&self) -> usize {
        self.initialized_mask_size
    }

    /// Get or create a page at the given aligned address.
    fn get_or_create_page(&mut self, aligned_addr: u64) -> &mut MemoryPage {
        self.pages
            .entry(aligned_addr)
            .or_insert_with(|| MemoryPage::new(self.page_size))
    }

    /// Get a page at the given aligned address, if it exists.
    pub fn get_page(&self, aligned_addr: u64) -> Option<&MemoryPage> {
        self.pages.get(&aligned_addr)
    }

    /// Get a mutable page at the given aligned address, if it exists.
    pub fn get_page_mut(&mut self, aligned_addr: u64) -> Option<&mut MemoryPage> {
        self.pages.get_mut(&aligned_addr)
    }

    /// Get the fault handler reference.
    pub fn fault_handler(&self) -> &dyn MemoryFaultHandler {
        self.fault_handler.as_ref()
    }

    /// Write a chunk of bytes to the memory bank.
    ///
    /// # Arguments
    /// * `offset` - start address
    /// * `data` - bytes to write
    pub fn set_chunk(&mut self, mut offset: u64, data: &[u8]) {
        let pagemask = (self.page_size as u64) - 1;
        let mut buf_offset = 0;
        let mut remaining = data.len();

        while remaining > 0 {
            let offalign = offset & !pagemask;
            let skip = (offset - offalign) as usize;
            let mut cursize = self.page_size - skip;
            if remaining < cursize {
                cursize = remaining;
            }

            let page = self.get_or_create_page(offalign);
            page.data[skip..skip + cursize]
                .copy_from_slice(&data[buf_offset..buf_offset + cursize]);
            page.set_initialized(skip, cursize, true);

            remaining -= cursize;
            offset += cursize as u64;
            buf_offset += cursize;
        }
    }

    /// Read a chunk of bytes from the memory bank.
    ///
    /// # Arguments
    /// * `offset` - start address
    /// * `size` - number of bytes to read
    /// * `stop_on_uninitialized` - if true, stop reading when uninitialized data is encountered
    ///
    /// # Returns
    /// Number of bytes actually read.
    pub fn get_chunk(
        &mut self,
        mut offset: u64,
        size: usize,
        result: &mut [u8],
        stop_on_uninitialized: bool,
    ) -> usize {
        let pagemask = (self.page_size as u64) - 1;
        let mut count = 0;
        let mut buf_offset = 0;

        while count < size {
            let offalign = offset & !pagemask;
            let skip = (offset - offalign) as usize;
            let mut cursize = self.page_size - skip;
            if size - count < cursize {
                cursize = size - count;
            }

            let page = self.get_or_create_page(offalign);
            let initialized_count = page.get_initialized_byte_count(skip, cursize);

            // Copy initialized data
            result[buf_offset..buf_offset + initialized_count]
                .copy_from_slice(&page.data[skip..skip + initialized_count]);
            count += initialized_count;
            offset += initialized_count as u64;
            buf_offset += initialized_count;
            cursize -= initialized_count;

            if cursize > 0 {
                // Handle uninitialized read - split borrows by accessing fields directly
                let page_size = self.page_size;
                let address = ghidra_core::addr::Address::new(offset);
                let fault = self.fault_handler.as_ref();
                let page = self.pages
                    .entry(offalign)
                    .or_insert_with(|| MemoryPage::new(page_size));
                if fault
                    .uninitialized_read(address, cursize, &mut page.data, skip + initialized_count)
                {
                    page.set_initialized(skip + initialized_count, cursize, true);
                } else if stop_on_uninitialized {
                    return count;
                }

                let page = self.pages
                    .entry(offalign)
                    .or_insert_with(|| MemoryPage::new(page_size));
                result[buf_offset..buf_offset + cursize]
                    .copy_from_slice(&page.data[skip + initialized_count..skip + initialized_count + cursize]);
                count += cursize;
                offset += cursize as u64;
                buf_offset += cursize;
            }
        }

        count
    }

    /// Set the initialization state of a range of bytes.
    pub fn set_initialized(&mut self, mut offset: u64, size: usize, initialized: bool) {
        let pagemask = (self.page_size as u64) - 1;
        let mut remaining = size;

        while remaining > 0 {
            let offalign = offset & !pagemask;
            let skip = (offset - offalign) as usize;
            let mut cursize = self.page_size - skip;
            if remaining < cursize {
                cursize = remaining;
            }

            let page = self.get_or_create_page(offalign);
            page.set_initialized(skip, cursize, initialized);

            remaining -= cursize;
            offset += cursize as u64;
        }
    }

    /// Decode a value from a byte sequence.
    pub fn construct_value(data: &[u8], offset: usize, size: usize, big_endian: bool) -> u64 {
        let mut result: u64 = 0;
        if big_endian {
            for i in 0..size {
                result <<= 8;
                result |= (data[offset + i] as u64) & 0xFF;
            }
        } else {
            for i in (0..size).rev() {
                result <<= 8;
                result |= (data[offset + i] as u64) & 0xFF;
            }
        }
        result
    }

    /// Encode a value into a byte sequence.
    pub fn deconstruct_value(
        data: &mut [u8],
        offset: usize,
        val: u64,
        size: usize,
        big_endian: bool,
    ) {
        let mut val = val;
        if big_endian {
            for i in (0..size).rev() {
                data[offset + i] = (val & 0xFF) as u8;
                val >>= 8;
            }
        } else {
            for i in 0..size {
                data[offset + i] = (val & 0xFF) as u8;
                val >>= 8;
            }
        }
    }

    /// Clear all pages.
    pub fn clear(&mut self) {
        self.pages.clear();
    }

    /// Get the number of pages.
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_bank_creation() {
        let bank = MemoryBank::new("RAM", false, 256);
        assert_eq!(bank.page_size(), 256);
        assert_eq!(bank.space_name(), "RAM");
        assert!(!bank.is_big_endian());
    }

    #[test]
    fn test_write_read_chunk() {
        let mut bank = MemoryBank::new("RAM", false, 256);
        let data = vec![1, 2, 3, 4, 5];
        bank.set_chunk(0x100, &data);

        let mut result = vec![0u8; 5];
        let read = bank.get_chunk(0x100, 5, &mut result, false);
        assert_eq!(read, 5);
        assert_eq!(result, data);
    }

    #[test]
    fn test_cross_page_read_write() {
        let mut bank = MemoryBank::new("RAM", false, 4);
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        bank.set_chunk(0x02, &data); // Crosses page boundary at 0x04

        let mut result = vec![0u8; 6];
        let read = bank.get_chunk(0x02, 6, &mut result, false);
        assert_eq!(read, 6);
        assert_eq!(result, data);
    }

    #[test]
    fn test_construct_value_le() {
        let data = vec![0x78, 0x56, 0x34, 0x12];
        let val = MemoryBank::construct_value(&data, 0, 4, false);
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_construct_value_be() {
        let data = vec![0x12, 0x34, 0x56, 0x78];
        let val = MemoryBank::construct_value(&data, 0, 4, true);
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_deconstruct_value_le() {
        let mut data = vec![0u8; 4];
        MemoryBank::deconstruct_value(&mut data, 0, 0x12345678, 4, false);
        assert_eq!(data, vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_deconstruct_value_be() {
        let mut data = vec![0u8; 4];
        MemoryBank::deconstruct_value(&mut data, 0, 0x12345678, 4, true);
        assert_eq!(data, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_set_initialized() {
        let mut bank = MemoryBank::new("RAM", false, 256);
        bank.set_chunk(0x100, &[1, 2, 3]);
        bank.set_initialized(0x100, 3, false);

        // Now reading should trigger fault handler which initializes to 0
        let mut result = vec![0xFF; 3];
        let read = bank.get_chunk(0x100, 3, &mut result, false);
        assert_eq!(read, 3);
        assert_eq!(result, vec![0, 0, 0]);
    }

    #[test]
    fn test_clear() {
        let mut bank = MemoryBank::new("RAM", false, 256);
        bank.set_chunk(0x100, &[1, 2, 3]);
        assert_eq!(bank.page_count(), 1);

        bank.clear();
        assert_eq!(bank.page_count(), 0);
    }
}
