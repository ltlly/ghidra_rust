//! Memory view types for visualizing memory state.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.memview` package.
//! Provides a grid-based visualization of memory state (known, unknown,
//! written, etc.) across address ranges and snapshots.

use serde::{Deserialize, Serialize};

/// The type of a memory box (cell) in the memory view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemviewBoxType {
    /// Memory state is unknown/uninitialized.
    Unknown,
    /// Memory state is known (read from the target).
    Known,
    /// Memory was written by the user or emulator.
    Written,
    /// Memory was read by the emulator.
    Read,
    /// Memory is in an error state.
    Error,
}

/// A single cell in the memory view grid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBox {
    /// The address of this cell.
    pub address: u64,
    /// The snap this state is observed at.
    pub snap: i64,
    /// The state of this memory region.
    pub box_type: MemviewBoxType,
    /// The size of the region this cell represents (in bytes).
    pub size: u32,
}

impl MemoryBox {
    /// Create a new memory box.
    pub fn new(address: u64, snap: i64, box_type: MemviewBoxType, size: u32) -> Self {
        Self {
            address,
            snap,
            box_type,
            size,
        }
    }

    /// Whether this box represents known memory.
    pub fn is_known(&self) -> bool {
        self.box_type == MemviewBoxType::Known || self.box_type == MemviewBoxType::Written
    }

    /// Whether this box represents unknown memory.
    pub fn is_unknown(&self) -> bool {
        self.box_type == MemviewBoxType::Unknown
    }
}

/// A map of memory state for visualization.
///
/// Ported from Ghidra's `MemviewMap`. Contains a grid of `MemoryBox`
/// entries indexed by (address, snap).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemviewMap {
    /// The address step per cell.
    pub address_step: u64,
    /// The snap step per cell.
    pub snap_step: i64,
    /// The minimum address.
    pub min_address: u64,
    /// The maximum address.
    pub max_address: u64,
    /// The minimum snap.
    pub min_snap: i64,
    /// The maximum snap.
    pub max_snap: i64,
    /// The cells in the map.
    pub cells: Vec<MemoryBox>,
}

impl MemviewMap {
    /// Create a new empty memory view map.
    pub fn new(address_step: u64, snap_step: i64) -> Self {
        Self {
            address_step,
            snap_step,
            min_address: u64::MAX,
            max_address: 0,
            min_snap: i64::MAX,
            max_snap: i64::MIN,
            cells: Vec::new(),
        }
    }

    /// Add a cell to the map.
    pub fn add_cell(&mut self, cell: MemoryBox) {
        if cell.address < self.min_address {
            self.min_address = cell.address;
        }
        if cell.address > self.max_address {
            self.max_address = cell.address;
        }
        if cell.snap < self.min_snap {
            self.min_snap = cell.snap;
        }
        if cell.snap > self.max_snap {
            self.max_snap = cell.snap;
        }
        self.cells.push(cell);
    }

    /// Get the cell at a specific address and snap.
    pub fn get_cell(&self, address: u64, snap: i64) -> Option<&MemoryBox> {
        self.cells
            .iter()
            .find(|c| c.address == address && c.snap == snap)
    }

    /// Get all cells for a given snap.
    pub fn cells_at_snap(&self, snap: i64) -> Vec<&MemoryBox> {
        self.cells.iter().filter(|c| c.snap == snap).collect()
    }

    /// Get all cells for a given address.
    pub fn cells_at_address(&self, address: u64) -> Vec<&MemoryBox> {
        self.cells.iter().filter(|c| c.address == address).collect()
    }

    /// The number of cells.
    pub fn len(&self) -> usize {
        self.cells.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// The number of columns (addresses).
    pub fn columns(&self) -> u64 {
        if self.min_address > self.max_address {
            0
        } else {
            (self.max_address - self.min_address) / self.address_step + 1
        }
    }

    /// The number of rows (snaps).
    pub fn rows(&self) -> i64 {
        if self.min_snap > self.max_snap {
            0
        } else {
            (self.max_snap - self.min_snap) / self.snap_step + 1
        }
    }
}

/// The model for the memory view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemviewModel {
    /// The map data.
    pub map: MemviewMap,
    /// The memory region name.
    pub region_name: String,
    /// The language ID for register/size info.
    pub language_id: String,
}

impl MemviewModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the region being displayed.
    pub fn with_region(mut self, name: impl Into<String>) -> Self {
        self.region_name = name.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_box() {
        let box1 = MemoryBox::new(0x400000, 0, MemviewBoxType::Known, 4);
        assert!(box1.is_known());
        assert!(!box1.is_unknown());

        let box2 = MemoryBox::new(0x400004, 0, MemviewBoxType::Unknown, 4);
        assert!(!box2.is_known());
        assert!(box2.is_unknown());
    }

    #[test]
    fn test_memview_map() {
        let mut map = MemviewMap::new(4, 1);
        map.add_cell(MemoryBox::new(0x400000, 0, MemviewBoxType::Known, 4));
        map.add_cell(MemoryBox::new(0x400004, 0, MemviewBoxType::Unknown, 4));
        map.add_cell(MemoryBox::new(0x400000, 1, MemviewBoxType::Written, 4));

        assert_eq!(map.len(), 3);
        assert_eq!(map.columns(), 2);
        assert_eq!(map.rows(), 2);

        let cell = map.get_cell(0x400000, 0).unwrap();
        assert!(cell.is_known());

        assert!(map.get_cell(0x500000, 0).is_none());
    }

    #[test]
    fn test_memview_map_at_snap() {
        let mut map = MemviewMap::new(4, 1);
        map.add_cell(MemoryBox::new(0x100, 0, MemviewBoxType::Known, 4));
        map.add_cell(MemoryBox::new(0x200, 0, MemviewBoxType::Known, 4));
        map.add_cell(MemoryBox::new(0x100, 1, MemviewBoxType::Unknown, 4));

        let at_snap_0 = map.cells_at_snap(0);
        assert_eq!(at_snap_0.len(), 2);

        let at_addr_0x100 = map.cells_at_address(0x100);
        assert_eq!(at_addr_0x100.len(), 2);
    }

    #[test]
    fn test_empty_map() {
        let map = MemviewMap::new(4, 1);
        assert!(map.is_empty());
        assert_eq!(map.columns(), 0);
        assert_eq!(map.rows(), 0);
    }

    #[test]
    fn test_memview_model() {
        let model = MemviewModel::new()
            .with_region("ram");
        assert_eq!(model.region_name, "ram");
    }

    #[test]
    fn test_memview_serde() {
        let mut map = MemviewMap::new(4, 1);
        map.add_cell(MemoryBox::new(0x100, 0, MemviewBoxType::Known, 4));
        let json = serde_json::to_string(&map).unwrap();
        let back: MemviewMap = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }
}
