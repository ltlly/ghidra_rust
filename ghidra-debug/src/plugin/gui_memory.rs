//! Memory GUI data model types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.memory`
//! package in the Debugger module. Provides memory region panel data types
//! for viewing and managing memory regions.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A memory region row for the regions panel.
///
/// Ported from Ghidra's region panel data model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionRow {
    /// Region name (e.g., ".text", ".data").
    pub name: String,
    /// Start address.
    pub min_address: u64,
    /// End address.
    pub max_address: u64,
    /// The address space name.
    pub space_name: String,
    /// Whether the region is readable.
    pub readable: bool,
    /// Whether the region is writable.
    pub writable: bool,
    /// Whether the region is executable.
    pub executable: bool,
    /// Whether the region is volatile.
    pub volatile: bool,
    /// The lifespan of this region.
    pub lifespan: Lifespan,
    /// Thread key this region belongs to (0 for global).
    pub thread_key: i64,
}

impl MemoryRegionRow {
    /// Create a new memory region row.
    pub fn new(
        name: impl Into<String>,
        min_address: u64,
        max_address: u64,
    ) -> Self {
        Self {
            name: name.into(),
            min_address,
            max_address,
            space_name: String::from("ram"),
            readable: true,
            writable: true,
            executable: false,
            volatile: false,
            lifespan: Lifespan::ALL,
            thread_key: 0,
        }
    }

    /// The size of the region in bytes.
    pub fn size(&self) -> u64 {
        if self.max_address >= self.min_address {
            self.max_address - self.min_address + 1
        } else {
            0
        }
    }

    /// Whether the given address is within this region.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.min_address && address <= self.max_address
    }

    /// Permission flags as a display string (e.g., "RWX").
    pub fn permissions_string(&self) -> String {
        let mut s = String::new();
        s.push(if self.readable { 'R' } else { '-' });
        s.push(if self.writable { 'W' } else { '-' });
        s.push(if self.executable { 'X' } else { '-' });
        s
    }
}

/// Cached byte page for the memory bytes viewer.
///
/// Ported from Ghidra's `CachedBytePage`. Represents a page of memory
/// bytes fetched from the trace for display in the hex viewer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedBytePage {
    /// Base address of this page.
    pub base_address: u64,
    /// Size of this page in bytes.
    pub page_size: usize,
    /// The bytes in this page.
    pub bytes: Vec<u8>,
    /// Per-byte state: true = known, false = unknown.
    pub known: Vec<bool>,
    /// Whether this page has been fetched.
    pub loaded: bool,
}

impl CachedBytePage {
    /// Page size constant (4 KiB).
    pub const PAGE_SIZE: usize = 4096;

    /// Create a new empty page at the given base address.
    pub fn new(base_address: u64) -> Self {
        Self {
            base_address,
            page_size: Self::PAGE_SIZE,
            bytes: vec![0u8; Self::PAGE_SIZE],
            known: vec![false; Self::PAGE_SIZE],
            loaded: false,
        }
    }

    /// Get the byte at the given offset within this page.
    pub fn get_byte(&self, offset: usize) -> Option<(u8, bool)> {
        if offset < self.page_size {
            Some((self.bytes[offset], self.known[offset]))
        } else {
            None
        }
    }

    /// Set a byte at the given offset.
    pub fn set_byte(&mut self, offset: usize, value: u8, known: bool) {
        if offset < self.page_size {
            self.bytes[offset] = value;
            self.known[offset] = known;
        }
    }

    /// Set a range of bytes.
    pub fn set_bytes(&mut self, offset: usize, data: &[u8], known: bool) {
        let end = (offset + data.len()).min(self.page_size);
        let len = end - offset;
        self.bytes[offset..end].copy_from_slice(&data[..len]);
        for i in offset..end {
            self.known[i] = known;
        }
    }

    /// The end address of this page (exclusive).
    pub fn end_address(&self) -> u64 {
        self.base_address + self.page_size as u64
    }

    /// Whether the given address falls within this page.
    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.base_address && address < self.end_address()
    }

    /// Mark the page as loaded.
    pub fn mark_loaded(&mut self) {
        self.loaded = true;
    }
}

/// Model for the memory regions display panel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryRegionTableModel {
    regions: Vec<MemoryRegionRow>,
}

impl MemoryRegionTableModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of regions.
    pub fn row_count(&self) -> usize {
        self.regions.len()
    }

    /// Get all regions.
    pub fn regions(&self) -> &[MemoryRegionRow] {
        &self.regions
    }

    /// Add a region.
    pub fn add_region(&mut self, region: MemoryRegionRow) {
        self.regions.push(region);
        self.regions.sort_by_key(|r| r.min_address);
    }

    /// Remove a region by name.
    pub fn remove_region(&mut self, name: &str) -> bool {
        let before = self.regions.len();
        self.regions.retain(|r| r.name != name);
        self.regions.len() < before
    }

    /// Find the region containing the given address.
    pub fn region_at(&self, address: u64) -> Option<&MemoryRegionRow> {
        self.regions.iter().find(|r| r.contains(address))
    }

    /// Get regions that intersect the given range.
    pub fn regions_intersecting(&self, min: u64, max: u64) -> Vec<&MemoryRegionRow> {
        self.regions
            .iter()
            .filter(|r| r.min_address <= max && r.max_address >= min)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_region_row() {
        let row = MemoryRegionRow::new(".text", 0x400000, 0x400fff);
        assert_eq!(row.size(), 0x1000);
        assert!(row.contains(0x400500));
        assert!(!row.contains(0x500000));
        assert_eq!(row.permissions_string(), "RW-");
    }

    #[test]
    fn test_memory_region_permissions() {
        let mut row = MemoryRegionRow::new(".text", 0x400000, 0x400fff);
        row.executable = true;
        row.writable = false;
        assert_eq!(row.permissions_string(), "R-X");
    }

    #[test]
    fn test_cached_byte_page() {
        let mut page = CachedBytePage::new(0x400000);
        assert!(!page.loaded);
        assert!(!page.contains_address(0x3fffff));
        assert!(page.contains_address(0x400000));
        assert!(page.contains_address(0x400fff));
        assert!(!page.contains_address(0x401000));

        page.set_byte(0, 0x42, true);
        let (val, known) = page.get_byte(0).unwrap();
        assert_eq!(val, 0x42);
        assert!(known);

        let (val2, known2) = page.get_byte(1).unwrap();
        assert_eq!(val2, 0);
        assert!(!known2);
    }

    #[test]
    fn test_cached_byte_page_bulk_set() {
        let mut page = CachedBytePage::new(0x1000);
        page.set_bytes(10, &[1, 2, 3, 4, 5], true);
        for i in 0..5 {
            let (val, known) = page.get_byte(10 + i).unwrap();
            assert_eq!(val, (i + 1) as u8);
            assert!(known);
        }
    }

    #[test]
    fn test_memory_region_table_model() {
        let mut model = MemoryRegionTableModel::new();
        model.add_region(MemoryRegionRow::new(".data", 0x600000, 0x600fff));
        model.add_region(MemoryRegionRow::new(".text", 0x400000, 0x400fff));

        assert_eq!(model.row_count(), 2);
        // Should be sorted by address
        assert_eq!(model.regions()[0].name, ".text");
        assert_eq!(model.regions()[1].name, ".data");

        assert!(model.region_at(0x400500).is_some());
        assert_eq!(model.region_at(0x400500).unwrap().name, ".text");
    }

    #[test]
    fn test_memory_region_table_model_intersecting() {
        let mut model = MemoryRegionTableModel::new();
        model.add_region(MemoryRegionRow::new(".text", 0x400000, 0x400fff));
        model.add_region(MemoryRegionRow::new(".data", 0x600000, 0x600fff));

        let intersecting = model.regions_intersecting(0x300000, 0x500000);
        assert_eq!(intersecting.len(), 1);
        assert_eq!(intersecting[0].name, ".text");
    }

    #[test]
    fn test_memory_region_table_model_remove() {
        let mut model = MemoryRegionTableModel::new();
        model.add_region(MemoryRegionRow::new(".text", 0x400000, 0x400fff));
        assert!(model.remove_region(".text"));
        assert_eq!(model.row_count(), 0);
    }
}
