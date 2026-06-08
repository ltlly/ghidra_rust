//! Memory page for page-based memory storage.
//!
//! Ported from Java: `ghidra.pcode.memstate.MemoryPage`.

/// A single page of memory in a memory bank.
///
/// Each page has a fixed size and tracks which bytes are initialized.
#[derive(Debug, Clone)]
pub struct MemoryPage {
    /// The data bytes in this page.
    pub data: Vec<u8>,
    /// Tracks which bytes are initialized (1 bit per byte).
    initialized: Vec<u8>,
    /// Size of the page in bytes.
    page_size: usize,
}

impl MemoryPage {
    /// Create a new memory page with the given size.
    pub fn new(page_size: usize) -> Self {
        let mask_size = (page_size + 7) / 8;
        Self {
            data: vec![0; page_size],
            initialized: vec![0; mask_size],
            page_size,
        }
    }

    /// Get the number of initialized bytes starting at `skip` for `size` bytes.
    pub fn get_initialized_byte_count(&self, skip: usize, size: usize) -> usize {
        let mut count = 0;
        for i in skip..skip + size {
            if i >= self.page_size {
                break;
            }
            if self.is_initialized(i) {
                count += 1;
            } else {
                break;
            }
        }
        count
    }

    /// Check if a byte at the given offset is initialized.
    pub fn is_initialized(&self, offset: usize) -> bool {
        let byte_idx = offset / 8;
        let bit_idx = offset % 8;
        if byte_idx >= self.initialized.len() {
            return false;
        }
        (self.initialized[byte_idx] >> bit_idx) & 1 != 0
    }

    /// Set the initialization state of bytes starting at `skip` for `size` bytes.
    pub fn set_initialized(&mut self, skip: usize, size: usize, initialized: bool) {
        for i in skip..skip + size {
            if i >= self.page_size {
                break;
            }
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            if byte_idx < self.initialized.len() {
                if initialized {
                    self.initialized[byte_idx] |= 1 << bit_idx;
                } else {
                    self.initialized[byte_idx] &= !(1 << bit_idx);
                }
            }
        }
    }

    /// Get the page size.
    pub fn page_size(&self) -> usize {
        self.page_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_creation() {
        let page = MemoryPage::new(256);
        assert_eq!(page.page_size(), 256);
        assert_eq!(page.data.len(), 256);
    }

    #[test]
    fn test_initialization_tracking() {
        let mut page = MemoryPage::new(16);
        assert!(!page.is_initialized(0));
        assert!(!page.is_initialized(5));

        page.set_initialized(0, 8, true);
        assert!(page.is_initialized(0));
        assert!(page.is_initialized(7));
        assert!(!page.is_initialized(8));
    }

    #[test]
    fn test_get_initialized_byte_count() {
        let mut page = MemoryPage::new(16);
        page.set_initialized(2, 5, true);

        // Starting at 2, 5 bytes are initialized
        assert_eq!(page.get_initialized_byte_count(2, 10), 5);

        // Starting at 0, 0 bytes are initialized (first uninitialized)
        assert_eq!(page.get_initialized_byte_count(0, 10), 0);
    }

    #[test]
    fn test_unset_initialization() {
        let mut page = MemoryPage::new(16);
        page.set_initialized(0, 8, true);
        assert!(page.is_initialized(5));

        page.set_initialized(5, 2, false);
        assert!(page.is_initialized(4));
        assert!(!page.is_initialized(5));
        assert!(!page.is_initialized(6));
        assert!(page.is_initialized(7));
    }
}
