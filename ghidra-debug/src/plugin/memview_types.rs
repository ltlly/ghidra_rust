//! Memory view panel data model types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.memview` package.
//! Provides the data model for the memory view panel, which displays a
//! visualization of memory access patterns from a debug trace.


use serde::{Deserialize, Serialize};

/// The type of a memory box in the memory view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemviewBoxType {
    /// A regular memory region.
    Region,
    /// A mapped memory section.
    Section,
    /// A stack frame area.
    Stack,
    /// A heap allocation.
    Heap,
    /// An unmapped/guard page.
    Guard,
    /// Free/unused memory.
    Free,
}

impl MemviewBoxType {
    /// Display name for this box type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Region => "Region",
            Self::Section => "Section",
            Self::Stack => "Stack",
            Self::Heap => "Heap",
            Self::Guard => "Guard",
            Self::Free => "Free",
        }
    }
}

/// A box in the memory view representing a contiguous memory range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBox {
    /// The start address.
    pub start_address: u64,
    /// The size in bytes.
    pub size: u64,
    /// The type of this box.
    pub box_type: MemviewBoxType,
    /// Display label.
    pub label: Option<String>,
    /// Access count (number of reads/writes observed).
    pub access_count: u64,
    /// Read count.
    pub read_count: u64,
    /// Write count.
    pub write_count: u64,
    /// Execute count.
    pub execute_count: u64,
    /// Color index for visualization.
    pub color_index: u32,
    /// The address space name.
    pub space_name: String,
    /// Whether this box is currently selected.
    pub selected: bool,
}

impl MemoryBox {
    /// Create a new memory box.
    pub fn new(
        start_address: u64,
        size: u64,
        box_type: MemviewBoxType,
        space_name: impl Into<String>,
    ) -> Self {
        Self {
            start_address,
            size,
            box_type,
            label: None,
            access_count: 0,
            read_count: 0,
            write_count: 0,
            execute_count: 0,
            color_index: 0,
            space_name: space_name.into(),
            selected: false,
        }
    }

    /// The end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.start_address.saturating_add(self.size)
    }

    /// Whether the given address falls within this box.
    pub fn contains_address(&self, addr: u64) -> bool {
        addr >= self.start_address && addr < self.end_address()
    }

    /// The total access density (accesses per byte).
    pub fn access_density(&self) -> f64 {
        if self.size == 0 {
            0.0
        } else {
            self.access_count as f64 / self.size as f64
        }
    }

    /// Set the label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set the color index.
    pub fn with_color(mut self, index: u32) -> Self {
        self.color_index = index;
        self
    }

    /// Record a read access at the given address.
    pub fn record_read(&mut self, _addr: u64) {
        self.read_count += 1;
        self.access_count += 1;
    }

    /// Record a write access at the given address.
    pub fn record_write(&mut self, _addr: u64) {
        self.write_count += 1;
        self.access_count += 1;
    }

    /// Record an execute access at the given address.
    pub fn record_execute(&mut self, _addr: u64) {
        self.execute_count += 1;
        self.access_count += 1;
    }

    /// Whether this box has any accesses.
    pub fn has_accesses(&self) -> bool {
        self.access_count > 0
    }

    /// Whether this is a read-heavy region.
    pub fn is_read_heavy(&self) -> bool {
        self.read_count > self.write_count && self.read_count > self.execute_count
    }

    /// Whether this is a write-heavy region.
    pub fn is_write_heavy(&self) -> bool {
        self.write_count > self.read_count && self.write_count > self.execute_count
    }

    /// Whether this is an execute-heavy region.
    pub fn is_execute_heavy(&self) -> bool {
        self.execute_count > self.read_count && self.execute_count > self.write_count
    }
}

/// The map model for the memory view.
///
/// Holds all memory boxes and provides query methods for the visualization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemviewMap {
    /// All memory boxes, keyed by start address.
    boxes: Vec<MemoryBox>,
    /// Total bytes tracked.
    total_bytes: u64,
    /// Maximum address seen.
    max_address: u64,
    /// Zoom level (1.0 = default).
    pub zoom_level: f64,
    /// Whether to show access heat map overlay.
    pub show_heatmap: bool,
    /// Whether to show region labels.
    pub show_labels: bool,
}

impl MemviewMap {
    /// Create a new empty memory view map.
    pub fn new() -> Self {
        Self {
            boxes: Vec::new(),
            total_bytes: 0,
            max_address: 0,
            zoom_level: 1.0,
            show_heatmap: true,
            show_labels: true,
        }
    }

    /// Add a memory box to the map.
    pub fn add_box(&mut self, memory_box: MemoryBox) {
        self.total_bytes += memory_box.size;
        let end = memory_box.end_address();
        if end > self.max_address {
            self.max_address = end;
        }
        self.boxes.push(memory_box);
    }

    /// Get all memory boxes.
    pub fn boxes(&self) -> &[MemoryBox] {
        &self.boxes
    }

    /// Get a mutable reference to all memory boxes.
    pub fn boxes_mut(&mut self) -> &mut [MemoryBox] {
        &mut self.boxes
    }

    /// Find the box containing the given address.
    pub fn box_at_address(&self, addr: u64) -> Option<&MemoryBox> {
        self.boxes.iter().find(|b| b.contains_address(addr))
    }

    /// Find the box containing the given address (mutable).
    pub fn box_at_address_mut(&mut self, addr: u64) -> Option<&mut MemoryBox> {
        self.boxes.iter_mut().find(|b| b.contains_address(addr))
    }

    /// Get the total number of boxes.
    pub fn box_count(&self) -> usize {
        self.boxes.len()
    }

    /// Get the total bytes tracked.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Get the maximum address.
    pub fn max_address(&self) -> u64 {
        self.max_address
    }

    /// Record a read access at the given address.
    pub fn record_read(&mut self, addr: u64) {
        if let Some(b) = self.box_at_address_mut(addr) {
            b.record_read(addr);
        }
    }

    /// Record a write access at the given address.
    pub fn record_write(&mut self, addr: u64) {
        if let Some(b) = self.box_at_address_mut(addr) {
            b.record_write(addr);
        }
    }

    /// Record an execute access at the given address.
    pub fn record_execute(&mut self, addr: u64) {
        if let Some(b) = self.box_at_address_mut(addr) {
            b.record_execute(addr);
        }
    }

    /// Get all boxes of a specific type.
    pub fn boxes_of_type(&self, box_type: MemviewBoxType) -> Vec<&MemoryBox> {
        self.boxes.iter().filter(|b| b.box_type == box_type).collect()
    }

    /// Zoom in.
    pub fn zoom_in(&mut self) {
        self.zoom_level = (self.zoom_level * 1.25).min(16.0);
    }

    /// Zoom out.
    pub fn zoom_out(&mut self) {
        self.zoom_level = (self.zoom_level / 1.25).max(0.1);
    }

    /// Reset zoom to default.
    pub fn reset_zoom(&mut self) {
        self.zoom_level = 1.0;
    }

    /// Clear all boxes.
    pub fn clear(&mut self) {
        self.boxes.clear();
        self.total_bytes = 0;
        self.max_address = 0;
    }
}

impl Default for MemviewMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MemviewModel -- the full model for the memory view panel
// ---------------------------------------------------------------------------

/// The full model for the memory view panel.
///
/// Combines the map data with visualization settings and trace listener state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemviewModel {
    /// The memory map.
    pub map: MemviewMap,
    /// The current snap being viewed.
    pub current_snap: i64,
    /// The trace key.
    pub trace_key: Option<i64>,
    /// Whether the view is currently loading data.
    pub loading: bool,
    /// Address format for display.
    pub address_format: MemviewAddressFormat,
    /// Color scheme for the visualization.
    pub color_scheme: MemviewColorScheme,
}

/// Address format for the memory view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemviewAddressFormat {
    /// Display addresses in hexadecimal.
    Hex,
    /// Display addresses in decimal.
    Decimal,
}

/// Color scheme for the memory view visualization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemviewColorScheme {
    /// Color by access type (read=blue, write=red, execute=green).
    AccessType,
    /// Color by access density (heat map).
    Density,
    /// Color by region type.
    RegionType,
    /// Single color with intensity based on access.
    Monochrome,
}

impl MemviewModel {
    /// Create a new memview model.
    pub fn new(snap: i64) -> Self {
        Self {
            map: MemviewMap::new(),
            current_snap: snap,
            trace_key: None,
            loading: false,
            address_format: MemviewAddressFormat::Hex,
            color_scheme: MemviewColorScheme::AccessType,
        }
    }
}

/// Zoom action for the memory view (panel-level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemviewPanelZoomAction {
    /// Zoom in (increase scale).
    ZoomIn,
    /// Zoom out (decrease scale).
    ZoomOut,
    /// Reset zoom to default.
    ResetZoom,
    /// Zoom to fit all memory.
    ZoomToFit,
    /// Zoom to a specific address range.
    ZoomToRange,
}

/// Service interface for memory view operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemviewServiceImpl {
    /// Current model state.
    pub model: MemviewModel,
    /// Registered listeners count.
    pub listener_count: usize,
}

impl MemviewServiceImpl {
    /// Create a new memview service.
    pub fn new(snap: i64) -> Self {
        Self {
            model: MemviewModel::new(snap),
            listener_count: 0,
        }
    }

    /// Record an access event.
    pub fn record_access(&mut self, addr: u64, is_read: bool, is_write: bool, is_execute: bool) {
        if is_read {
            self.model.map.record_read(addr);
        }
        if is_write {
            self.model.map.record_write(addr);
        }
        if is_execute {
            self.model.map.record_execute(addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memview_box_type_display() {
        assert_eq!(MemviewBoxType::Region.display_name(), "Region");
        assert_eq!(MemviewBoxType::Stack.display_name(), "Stack");
        assert_eq!(MemviewBoxType::Heap.display_name(), "Heap");
    }

    #[test]
    fn test_memory_box_basics() {
        let b = MemoryBox::new(0x1000, 0x100, MemviewBoxType::Region, "ram")
            .with_label("code")
            .with_color(1);

        assert_eq!(b.start_address, 0x1000);
        assert_eq!(b.end_address(), 0x1100);
        assert!(b.contains_address(0x1050));
        assert!(!b.contains_address(0x1100));
        assert!(!b.contains_address(0x0FFF));
        assert_eq!(b.label.as_deref(), Some("code"));
        assert_eq!(b.color_index, 1);
    }

    #[test]
    fn test_memory_box_accesses() {
        let mut b = MemoryBox::new(0x1000, 0x100, MemviewBoxType::Heap, "ram");
        assert!(!b.has_accesses());

        b.record_read(0x1000);
        b.record_read(0x1004);
        b.record_write(0x1008);
        b.record_execute(0x1010);

        assert_eq!(b.access_count, 4);
        assert_eq!(b.read_count, 2);
        assert_eq!(b.write_count, 1);
        assert_eq!(b.execute_count, 1);
        assert!(b.has_accesses());
    }

    #[test]
    fn test_memory_box_access_patterns() {
        let mut b = MemoryBox::new(0x1000, 0x100, MemviewBoxType::Region, "ram");
        b.record_read(0x1000);
        b.record_read(0x1004);
        b.record_write(0x1008);
        assert!(b.is_read_heavy());

        let mut b = MemoryBox::new(0x2000, 0x100, MemviewBoxType::Region, "ram");
        b.record_write(0x2000);
        b.record_write(0x2004);
        b.record_read(0x2008);
        assert!(b.is_write_heavy());

        let mut b = MemoryBox::new(0x3000, 0x100, MemviewBoxType::Region, "ram");
        b.record_execute(0x3000);
        b.record_execute(0x3004);
        assert!(b.is_execute_heavy());
    }

    #[test]
    fn test_memory_box_density() {
        let mut b = MemoryBox::new(0x1000, 0x100, MemviewBoxType::Region, "ram");
        assert!((b.access_density() - 0.0).abs() < f64::EPSILON);

        for i in 0..0x10 {
            b.record_read(0x1000 + i);
        }
        // 16 accesses / 256 bytes = 0.0625
        assert!((b.access_density() - 0.0625).abs() < 0.001);
    }

    #[test]
    fn test_memory_box_empty_size() {
        let b = MemoryBox::new(0x1000, 0, MemviewBoxType::Region, "ram");
        assert!((b.access_density() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_memview_map_basics() {
        let mut map = MemviewMap::new();
        assert_eq!(map.box_count(), 0);
        assert_eq!(map.total_bytes(), 0);

        map.add_box(MemoryBox::new(0x1000, 0x100, MemviewBoxType::Region, "ram"));
        map.add_box(MemoryBox::new(0x2000, 0x200, MemviewBoxType::Stack, "ram"));

        assert_eq!(map.box_count(), 2);
        assert_eq!(map.total_bytes(), 0x300);
        assert_eq!(map.max_address(), 0x2200);
    }

    #[test]
    fn test_memview_map_box_at_address() {
        let mut map = MemviewMap::new();
        map.add_box(MemoryBox::new(0x1000, 0x100, MemviewBoxType::Region, "ram"));
        map.add_box(MemoryBox::new(0x2000, 0x100, MemviewBoxType::Stack, "ram"));

        let b = map.box_at_address(0x1050).unwrap();
        assert_eq!(b.start_address, 0x1000);

        assert!(map.box_at_address(0x1500).is_none());
    }

    #[test]
    fn test_memview_map_record_access() {
        let mut map = MemviewMap::new();
        map.add_box(MemoryBox::new(0x1000, 0x100, MemviewBoxType::Region, "ram"));

        map.record_read(0x1000);
        map.record_write(0x1010);
        map.record_execute(0x1020);

        let b = map.box_at_address(0x1000).unwrap();
        assert_eq!(b.access_count, 3);
        assert_eq!(b.read_count, 1);
        assert_eq!(b.write_count, 1);
        assert_eq!(b.execute_count, 1);
    }

    #[test]
    fn test_memview_map_boxes_of_type() {
        let mut map = MemviewMap::new();
        map.add_box(MemoryBox::new(0x1000, 0x100, MemviewBoxType::Region, "ram"));
        map.add_box(MemoryBox::new(0x2000, 0x100, MemviewBoxType::Stack, "ram"));
        map.add_box(MemoryBox::new(0x3000, 0x100, MemviewBoxType::Region, "ram"));

        assert_eq!(map.boxes_of_type(MemviewBoxType::Region).len(), 2);
        assert_eq!(map.boxes_of_type(MemviewBoxType::Stack).len(), 1);
        assert_eq!(map.boxes_of_type(MemviewBoxType::Heap).len(), 0);
    }

    #[test]
    fn test_memview_map_zoom() {
        let mut map = MemviewMap::new();
        assert!((map.zoom_level - 1.0).abs() < f64::EPSILON);

        map.zoom_in();
        assert!(map.zoom_level > 1.0);

        map.zoom_out();
        map.zoom_out();
        assert!(map.zoom_level < 1.0);

        map.reset_zoom();
        assert!((map.zoom_level - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_memview_map_zoom_clamped() {
        let mut map = MemviewMap::new();
        for _ in 0..100 {
            map.zoom_in();
        }
        assert!(map.zoom_level <= 16.0);

        for _ in 0..200 {
            map.zoom_out();
        }
        assert!(map.zoom_level >= 0.1);
    }

    #[test]
    fn test_memview_map_clear() {
        let mut map = MemviewMap::new();
        map.add_box(MemoryBox::new(0x1000, 0x100, MemviewBoxType::Region, "ram"));
        assert_eq!(map.box_count(), 1);

        map.clear();
        assert_eq!(map.box_count(), 0);
        assert_eq!(map.total_bytes(), 0);
        assert_eq!(map.max_address(), 0);
    }

    #[test]
    fn test_memview_model() {
        let model = MemviewModel::new(5);
        assert_eq!(model.current_snap, 5);
        assert!(model.trace_key.is_none());
        assert!(!model.loading);
        assert_eq!(model.address_format, MemviewAddressFormat::Hex);
        assert_eq!(model.color_scheme, MemviewColorScheme::AccessType);
    }

    #[test]
    fn test_memview_zoom_action_variants() {
        assert_ne!(MemviewPanelZoomAction::ZoomIn, MemviewPanelZoomAction::ZoomOut);
        assert_ne!(MemviewPanelZoomAction::ResetZoom, MemviewPanelZoomAction::ZoomToFit);
    }

    #[test]
    fn test_memview_service() {
        let mut svc = MemviewServiceImpl::new(5);
        svc.record_access(0x1000, true, false, false);
        svc.record_access(0x1004, false, true, false);
        svc.record_access(0x1008, false, false, true);

        // Nothing recorded yet because no boxes added
        assert_eq!(svc.model.map.total_bytes(), 0);

        svc.model
            .map
            .add_box(MemoryBox::new(0x1000, 0x100, MemviewBoxType::Region, "ram"));

        svc.record_access(0x1000, true, false, false);
        let b = svc.model.map.box_at_address(0x1000).unwrap();
        assert_eq!(b.read_count, 1);
    }

    #[test]
    fn test_memview_map_default() {
        let map = MemviewMap::default();
        assert!(map.boxes().is_empty());
        assert!(map.show_heatmap);
        assert!(map.show_labels);
    }
}
