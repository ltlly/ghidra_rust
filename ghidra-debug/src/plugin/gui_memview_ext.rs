//! Extended memory viewer GUI types for the debugger.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.memview` package.
//! Provides the memory viewer plugin data model for visualizing memory as
//! a grid of cells.

use std::collections::BTreeMap;

/// Type of cell in the memory view.
///
/// Corresponds to Java's `MemviewBoxType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemviewBoxType {
    /// A memory cell showing a byte value.
    Byte,
    /// A memory cell showing an ASCII character.
    Ascii,
    /// A memory cell showing an instruction.
    Instruction,
    /// A memory cell showing a data value.
    Data,
    /// An unmapped or unknown cell.
    Unknown,
}

impl MemviewBoxType {
    /// Get the width of this box type in display units.
    pub fn display_width(&self) -> usize {
        match self {
            MemviewBoxType::Byte => 2,
            MemviewBoxType::Ascii => 1,
            MemviewBoxType::Instruction => 16,
            MemviewBoxType::Data => 8,
            MemviewBoxType::Unknown => 2,
        }
    }
}

/// A single memory box (cell) in the memory viewer.
///
/// Corresponds to Java's `MemoryBox`.
#[derive(Debug, Clone)]
pub struct MemoryBox {
    /// Address offset of this box.
    pub offset: u64,
    /// The box type.
    pub box_type: MemviewBoxType,
    /// The value (byte value or encoded representation).
    pub value: u8,
    /// Whether this box is part of the current selection.
    pub selected: bool,
    /// Whether this box is highlighted (e.g., changed value).
    pub highlighted: bool,
}

impl MemoryBox {
    /// Create a new memory box.
    pub fn new(offset: u64, box_type: MemviewBoxType, value: u8) -> Self {
        Self {
            offset,
            box_type,
            value,
            selected: false,
            highlighted: false,
        }
    }

    /// Get the hex representation of this box's value.
    pub fn hex_string(&self) -> String {
        format!("{:02X}", self.value)
    }

    /// Get the ASCII representation of this box's value.
    pub fn ascii_char(&self) -> char {
        if self.value >= 0x20 && self.value < 0x7F {
            self.value as char
        } else {
            '.'
        }
    }
}

/// A model for the memory view map, mapping addresses to boxes.
///
/// Corresponds to Java's `MemviewMapModel` and `MemviewMap`.
#[derive(Debug)]
pub struct MemviewModel {
    /// Memory boxes indexed by offset.
    boxes: BTreeMap<u64, MemoryBox>,
    /// Number of columns in the grid.
    pub columns: usize,
    /// Starting offset of the view.
    pub start_offset: u64,
    /// The snap being viewed.
    pub current_snap: i64,
    /// Zoom level (1.0 = normal).
    pub zoom: f64,
}

impl MemviewModel {
    /// Create a new memory view model.
    pub fn new(columns: usize, start_offset: u64) -> Self {
        Self {
            boxes: BTreeMap::new(),
            columns,
            start_offset,
            current_snap: 0,
            zoom: 1.0,
        }
    }

    /// Set a box at an offset.
    pub fn set_box(&mut self, memory_box: MemoryBox) {
        self.boxes.insert(memory_box.offset, memory_box);
    }

    /// Get a box at an offset.
    pub fn get_box(&self, offset: u64) -> Option<&MemoryBox> {
        self.boxes.get(&offset)
    }

    /// Get a mutable reference to a box at an offset.
    pub fn get_box_mut(&mut self, offset: u64) -> Option<&mut MemoryBox> {
        self.boxes.get_mut(&offset)
    }

    /// Load memory bytes into the model.
    pub fn load_bytes(&mut self, start: u64, data: &[u8], box_type: MemviewBoxType) {
        for (i, &byte) in data.iter().enumerate() {
            let offset = start + i as u64;
            self.set_box(MemoryBox::new(offset, box_type, byte));
        }
    }

    /// Get the total number of boxes.
    pub fn box_count(&self) -> usize {
        self.boxes.len()
    }

    /// Get all boxes in order.
    pub fn all_boxes(&self) -> Vec<&MemoryBox> {
        self.boxes.values().collect()
    }

    /// Select a range of boxes.
    pub fn select_range(&mut self, start: u64, end: u64) {
        for (_, b) in self.boxes.range_mut(start..=end) {
            b.selected = true;
        }
    }

    /// Clear all selections.
    pub fn clear_selection(&mut self) {
        for b in self.boxes.values_mut() {
            b.selected = false;
        }
    }

    /// Highlight changed bytes.
    pub fn highlight_changes(&mut self, offsets: &[u64]) {
        for &offset in offsets {
            if let Some(b) = self.boxes.get_mut(&offset) {
                b.highlighted = true;
            }
        }
    }

    /// Clear all highlights.
    pub fn clear_highlights(&mut self) {
        for b in self.boxes.values_mut() {
            b.highlighted = false;
        }
    }

    /// Zoom in.
    pub fn zoom_in(&mut self) {
        self.zoom = (self.zoom * 1.25).min(4.0);
    }

    /// Zoom out.
    pub fn zoom_out(&mut self) {
        self.zoom = (self.zoom / 1.25).max(0.25);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memview_box_type_display_width() {
        assert_eq!(MemviewBoxType::Byte.display_width(), 2);
        assert_eq!(MemviewBoxType::Ascii.display_width(), 1);
        assert_eq!(MemviewBoxType::Instruction.display_width(), 16);
    }

    #[test]
    fn test_memory_box() {
        let box1 = MemoryBox::new(0x1000, MemviewBoxType::Byte, 0xFF);
        assert_eq!(box1.hex_string(), "FF");
        assert_eq!(box1.ascii_char(), '.');

        let box2 = MemoryBox::new(0x1001, MemviewBoxType::Ascii, b'A');
        assert_eq!(box2.ascii_char(), 'A');
        assert_eq!(box2.hex_string(), "41");
    }

    #[test]
    fn test_memview_model_basic() {
        let mut model = MemviewModel::new(16, 0x1000);
        model.load_bytes(0x1000, &[0x48, 0x65, 0x6C, 0x6C, 0x6F], MemviewBoxType::Byte);
        assert_eq!(model.box_count(), 5);
        assert_eq!(model.get_box(0x1000).unwrap().value, 0x48);
        assert_eq!(model.get_box(0x1004).unwrap().value, 0x6F);
    }

    #[test]
    fn test_memview_model_selection() {
        let mut model = MemviewModel::new(16, 0x1000);
        model.load_bytes(0x1000, &[0; 10], MemviewBoxType::Byte);
        model.select_range(0x1002, 0x1005);

        assert!(!model.get_box(0x1001).unwrap().selected);
        assert!(model.get_box(0x1002).unwrap().selected);
        assert!(model.get_box(0x1005).unwrap().selected);
        assert!(!model.get_box(0x1006).unwrap().selected);

        model.clear_selection();
        assert!(!model.get_box(0x1003).unwrap().selected);
    }

    #[test]
    fn test_memview_model_highlight() {
        let mut model = MemviewModel::new(16, 0x1000);
        model.load_bytes(0x1000, &[0; 5], MemviewBoxType::Byte);
        model.highlight_changes(&[0x1001, 0x1003]);

        assert!(!model.get_box(0x1000).unwrap().highlighted);
        assert!(model.get_box(0x1001).unwrap().highlighted);
        assert!(model.get_box(0x1003).unwrap().highlighted);

        model.clear_highlights();
        assert!(!model.get_box(0x1001).unwrap().highlighted);
    }

    #[test]
    fn test_memview_model_zoom() {
        let mut model = MemviewModel::new(16, 0x1000);
        assert_eq!(model.zoom, 1.0);

        model.zoom_in();
        assert!((model.zoom - 1.25).abs() < 0.01);

        model.zoom_out();
        model.zoom_out();
        assert!(model.zoom < 1.0);
    }

    #[test]
    fn test_memview_model_zoom_limits() {
        let mut model = MemviewModel::new(16, 0x1000);
        for _ in 0..100 {
            model.zoom_in();
        }
        assert!((model.zoom - 4.0).abs() < 0.01);

        model.zoom = 1.0;
        for _ in 0..100 {
            model.zoom_out();
        }
        assert!((model.zoom - 0.25).abs() < 0.01);
    }
}
