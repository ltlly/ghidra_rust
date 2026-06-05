//! Memory view types for visualizing memory state.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.memview` package.
//! Provides a grid-based visualization of memory state (known, unknown,
//! written, etc.) across address ranges and snapshots.

use serde::{Deserialize, Serialize};

/// The type of a memory box (cell) in the memory view.
///
/// Ported from Ghidra's `MemviewBoxType` enum in
/// `ghidra.app.plugin.core.debug.gui.memview`.
/// Each variant represents a distinct type of memory event or state,
/// and carries a default color for the visualization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemviewBoxType {
    /// Unknown/uninitialized memory.
    Unknown,
    /// Memory state is known (read from the target).
    Known,
    /// Memory was written by the user or emulator.
    Written,
    /// Memory was read by the emulator.
    Read,
    /// Memory is in an error state.
    Error,
    /// Executable instructions present.
    Instructions,
    /// Process-level memory event.
    Process,
    /// Thread-level memory event.
    Thread,
    /// Module-level memory event.
    Module,
    /// Memory region event.
    Region,
    /// Image mapping event.
    Image,
    /// Virtual allocation event.
    VirtualAlloc,
    /// Heap creation event.
    HeapCreate,
    /// Heap allocation event.
    HeapAlloc,
    /// Pool allocation event.
    Pool,
    /// Stack memory event.
    Stack,
    /// Performance info event.
    PerfInfo,
    /// Memory read event from target.
    ReadMemory,
    /// Memory write event from target.
    WriteMemory,
    /// Breakpoint memory event.
    Breakpoint,
}

impl MemviewBoxType {
    /// Get the default color for this box type as ARGB.
    ///
    /// Colors match the Ghidra GColor defaults.
    pub fn default_color(&self) -> u32 {
        match self {
            Self::Unknown => 0xff_888888,
            Self::Known => 0xff_4488cc,
            Self::Written => 0xff_88cc44,
            Self::Read => 0xff_cccc44,
            Self::Error => 0xff_cc4444,
            Self::Instructions => 0xff_ffcc00,
            Self::Process => 0xff_00ccff,
            Self::Thread => 0xff_cc99ff,
            Self::Module => 0xff_66cccc,
            Self::Region => 0xff_339966,
            Self::Image => 0xff_669933,
            Self::VirtualAlloc => 0xff_9966cc,
            Self::HeapCreate => 0xff_cc6699,
            Self::HeapAlloc => 0xff_ff9966,
            Self::Pool => 0xff_6699ff,
            Self::Stack => 0xff_99ccff,
            Self::PerfInfo => 0xff_cccccc,
            Self::ReadMemory => 0xff_ffff99,
            Self::WriteMemory => 0xff_ff9999,
            Self::Breakpoint => 0xff_ff3333,
        }
    }

    /// Get all variants.
    pub fn all_variants() -> &'static [MemviewBoxType] {
        &[
            Self::Unknown, Self::Known, Self::Written, Self::Read, Self::Error,
            Self::Instructions, Self::Process, Self::Thread, Self::Module,
            Self::Region, Self::Image, Self::VirtualAlloc, Self::HeapCreate,
            Self::HeapAlloc, Self::Pool, Self::Stack, Self::PerfInfo,
            Self::ReadMemory, Self::WriteMemory, Self::Breakpoint,
        ]
    }
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

/// A zoom action for the memview (address or time axis).
///
/// Ported from Ghidra's zoom actions (ZoomInAAction, ZoomOutAAction,
/// ZoomInTAction, ZoomOutTAction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemviewZoomAction {
    /// Zoom in on the address axis.
    ZoomInAddress,
    /// Zoom out on the address axis.
    ZoomOutAddress,
    /// Zoom in on the time axis.
    ZoomInTime,
    /// Zoom out on the time axis.
    ZoomOutTime,
}

impl MemviewZoomAction {
    /// Get the zoom factor for this action (1 = zoom in, -1 = zoom out).
    pub fn direction(&self) -> i32 {
        match self {
            Self::ZoomInAddress | Self::ZoomInTime => 1,
            Self::ZoomOutAddress | Self::ZoomOutTime => -1,
        }
    }

    /// Whether this is an address-axis zoom.
    pub fn is_address_axis(&self) -> bool {
        matches!(self, Self::ZoomInAddress | Self::ZoomOutAddress)
    }

    /// Whether this is a time-axis zoom.
    pub fn is_time_axis(&self) -> bool {
        matches!(self, Self::ZoomInTime | Self::ZoomOutTime)
    }
}

/// The service interface for the memory view.
///
/// Ported from Ghidra's `MemviewService` interface in
/// `ghidra.app.plugin.core.debug.gui.memview`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemviewServiceImpl {
    /// The box list.
    boxes: Vec<MemoryBox>,
    /// The current program name.
    pub program_name: String,
    /// Current zoom level on the address axis.
    pub address_zoom: f64,
    /// Current zoom level on the time axis.
    pub time_zoom: f64,
}

impl MemviewServiceImpl {
    /// Create a new service implementation.
    pub fn new() -> Self {
        Self {
            boxes: Vec::new(),
            program_name: String::new(),
            address_zoom: 1.0,
            time_zoom: 1.0,
        }
    }

    /// Set the box list.
    pub fn set_boxes(&mut self, box_list: Vec<MemoryBox>) {
        self.boxes = box_list;
    }

    /// Get the box list.
    pub fn boxes(&self) -> &[MemoryBox] {
        &self.boxes
    }

    /// Initialize views.
    pub fn init_views(&mut self) {
        // Reset zoom levels
        self.address_zoom = 1.0;
        self.time_zoom = 1.0;
    }

    /// Set the current program.
    pub fn set_program(&mut self, name: impl Into<String>) {
        self.program_name = name.into();
    }

    /// Apply a zoom action.
    pub fn apply_zoom(&mut self, action: MemviewZoomAction) {
        let factor = 2.0_f64.powi(action.direction());
        if action.is_address_axis() {
            self.address_zoom = (self.address_zoom * factor).clamp(0.01, 100.0);
        } else {
            self.time_zoom = (self.time_zoom * factor).clamp(0.01, 100.0);
        }
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
    fn test_memview_box_type_default_colors() {
        // Verify all variants have non-zero colors
        for &v in MemviewBoxType::all_variants() {
            assert_ne!(v.default_color(), 0, "Color for {:?} should be non-zero", v);
        }
    }

    #[test]
    fn test_memview_box_type_all_variants() {
        let variants = MemviewBoxType::all_variants();
        assert_eq!(variants.len(), 20);
        assert!(variants.contains(&MemviewBoxType::Instructions));
        assert!(variants.contains(&MemviewBoxType::Process));
        assert!(variants.contains(&MemviewBoxType::Thread));
        assert!(variants.contains(&MemviewBoxType::Module));
        assert!(variants.contains(&MemviewBoxType::Breakpoint));
    }

    #[test]
    fn test_memview_box_type_is_known() {
        assert!(MemoryBox::new(0, 0, MemviewBoxType::Known, 1).is_known());
        assert!(MemoryBox::new(0, 0, MemviewBoxType::Written, 1).is_known());
        assert!(!MemoryBox::new(0, 0, MemviewBoxType::Instructions, 1).is_known());
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
    fn test_memview_zoom_action() {
        assert_eq!(MemviewZoomAction::ZoomInAddress.direction(), 1);
        assert_eq!(MemviewZoomAction::ZoomOutAddress.direction(), -1);
        assert!(MemviewZoomAction::ZoomInAddress.is_address_axis());
        assert!(!MemviewZoomAction::ZoomInAddress.is_time_axis());
        assert!(MemviewZoomAction::ZoomInTime.is_time_axis());
        assert!(!MemviewZoomAction::ZoomInTime.is_address_axis());
    }

    #[test]
    fn test_memview_service() {
        let mut svc = MemviewServiceImpl::new();
        svc.set_program("test.exe");
        assert_eq!(svc.program_name, "test.exe");
        svc.set_boxes(vec![
            MemoryBox::new(0x100, 0, MemviewBoxType::Known, 4),
        ]);
        assert_eq!(svc.boxes().len(), 1);
    }

    #[test]
    fn test_memview_service_zoom() {
        let mut svc = MemviewServiceImpl::new();
        assert_eq!(svc.address_zoom, 1.0);
        svc.apply_zoom(MemviewZoomAction::ZoomInAddress);
        assert!(svc.address_zoom > 1.0);
        svc.apply_zoom(MemviewZoomAction::ZoomOutAddress);
        assert!((svc.address_zoom - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_memview_service_init_views() {
        let mut svc = MemviewServiceImpl::new();
        svc.address_zoom = 5.0;
        svc.time_zoom = 3.0;
        svc.init_views();
        assert_eq!(svc.address_zoom, 1.0);
        assert_eq!(svc.time_zoom, 1.0);
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
