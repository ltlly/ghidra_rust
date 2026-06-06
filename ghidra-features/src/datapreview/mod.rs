//! Data type preview plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.datapreview` package.
//!
//! Provides a preview of bytes at an address based on user-selected
//! data types. Displays how memory bytes would be interpreted as
//! various data types (int, float, string, etc.).
//!
//! # Key Types
//!
//! - [`DataTypePreviewPlugin`] -- Plugin providing the data type preview panel
//! - [`DataTypePreview`] -- Preview of bytes as a specific data type
//! - [`DataTypeComponentPreview`] -- Preview of a composite component
//! - [`Preview`] -- Trait for preview implementations
//! - [`PreviewModel`] -- Table model for preview rows

/// Data preview model for interpreting bytes at an address.
///
/// Ported from `ghidra.app.plugin.core.datapreview` preview classes.
pub mod preview_model;

/// Data type preview plugin and component preview.
///
/// Ported from `ghidra.app.plugin.core.datapreview.DataTypePreviewPlugin`,
/// `DataTypePreview`, `DataTypeComponentPreview`, and `Preview`.
pub mod plugin;

use std::cmp::Ordering;

/// Maximum preview string length.
pub const MAX_PREVIEW_LENGTH: usize = 128;

/// Column header for the preview name column.
pub const NAME_COLUMN: &str = "Data Type";

/// Column header for the preview value column.
pub const PREVIEW_COLUMN: &str = "Preview";

// ---------------------------------------------------------------------------
// Preview trait
// ---------------------------------------------------------------------------

/// Trait for data type preview implementations.
///
/// Ported from `ghidra.app.plugin.core.datapreview.Preview`.
pub trait Preview: Send + Sync + std::fmt::Debug {
    /// Display name for this preview.
    fn name(&self) -> &str;

    /// Generate a preview string for bytes at the given address.
    ///
    /// Returns `None` if the preview cannot be generated (e.g., out of
    /// bounds, invalid encoding).
    fn get_preview(&self, memory: &[u8], offset: usize) -> Option<String>;

    /// The data type name being previewed.
    fn data_type_name(&self) -> &str;

    /// The expected byte length for this preview type, if fixed.
    fn expected_length(&self) -> Option<usize>;
}

// ---------------------------------------------------------------------------
// Data type preview
// ---------------------------------------------------------------------------

/// Preview of bytes interpreted as a simple data type.
///
/// Ported from `ghidra.app.plugin.core.datapreview.DataTypePreview`.
#[derive(Debug, Clone)]
pub struct DataTypePreview {
    /// The data type name (e.g., "int", "float", "string").
    type_name: String,
    /// Display name for the preview.
    display_name: String,
    /// Expected byte length (None for variable-length types).
    byte_length: Option<usize>,
}

impl DataTypePreview {
    /// Create a new data type preview.
    pub fn new(
        type_name: impl Into<String>,
        display_name: impl Into<String>,
        byte_length: Option<usize>,
    ) -> Self {
        Self {
            type_name: type_name.into(),
            display_name: display_name.into(),
            byte_length,
        }
    }

    /// Create a preview for a 1-byte type.
    pub fn byte_type(name: impl Into<String>) -> Self {
        let n = name.into();
        Self::new(&n, &n, Some(1))
    }

    /// Create a preview for a 2-byte type.
    pub fn word_type(name: impl Into<String>) -> Self {
        let n = name.into();
        Self::new(&n, &n, Some(2))
    }

    /// Create a preview for a 4-byte type.
    pub fn dword_type(name: impl Into<String>) -> Self {
        let n = name.into();
        Self::new(&n, &n, Some(4))
    }

    /// Create a preview for an 8-byte type.
    pub fn qword_type(name: impl Into<String>) -> Self {
        let n = name.into();
        Self::new(&n, &n, Some(8))
    }
}

impl Preview for DataTypePreview {
    fn name(&self) -> &str {
        &self.display_name
    }

    fn get_preview(&self, memory: &[u8], offset: usize) -> Option<String> {
        if offset >= memory.len() {
            return None;
        }

        // Handle variable-length types (string, char[]) first
        match self.type_name.as_str() {
            "string" | "char[]" => {
                let bytes = &memory[offset..];
                let s: String = bytes
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| {
                        if b.is_ascii_graphic() || b == b' ' {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .take(MAX_PREVIEW_LENGTH)
                    .collect();
                return Some(format!("\"{}\"", s));
            }
            _ => {}
        }

        let len = self.byte_length?;
        if offset + len > memory.len() {
            return None;
        }
        let bytes = &memory[offset..offset + len];

        match self.type_name.as_str() {
            "byte" | "uchar" => Some(format!("0x{:02X}", bytes[0])),
            "sbyte" | "char" => Some(format!("{}", bytes[0] as i8)),
            "word" | "ushort" => {
                let val = u16::from_le_bytes([bytes[0], bytes[1]]);
                Some(format!("0x{:04X}", val))
            }
            "sword" | "short" => {
                let val = i16::from_le_bytes([bytes[0], bytes[1]]);
                Some(format!("{}", val))
            }
            "dword" | "uint" => {
                let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Some(format!("0x{:08X}", val))
            }
            "sdword" | "int" => {
                let val = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Some(format!("{}", val))
            }
            "qword" | "ulong" | "pointer" => {
                let mut buf = [0u8; 8];
                buf[..len.min(8)].copy_from_slice(&bytes[..len.min(8)]);
                Some(format!("0x{:016X}", u64::from_le_bytes(buf)))
            }
            "float" => {
                let val = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Some(format!("{}", val))
            }
            "double" => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(bytes);
                Some(format!("{}", f64::from_le_bytes(buf)))
            }
            _ => {
                // Fallback: hex dump
                let hex: String = bytes.iter().map(|b| format!("{:02X} ", b)).collect();
                Some(hex.trim().to_string())
            }
        }
    }

    fn data_type_name(&self) -> &str {
        &self.type_name
    }

    fn expected_length(&self) -> Option<usize> {
        self.byte_length
    }
}

impl PartialEq for DataTypePreview {
    fn eq(&self, other: &Self) -> bool {
        self.display_name == other.display_name
    }
}

impl Eq for DataTypePreview {}

impl PartialOrd for DataTypePreview {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DataTypePreview {
    fn cmp(&self, other: &Self) -> Ordering {
        self.display_name.cmp(&other.display_name)
    }
}

// ---------------------------------------------------------------------------
// Data type component preview
// ---------------------------------------------------------------------------

/// Preview of bytes as a component within a composite type.
///
/// Ported from `ghidra.app.plugin.core.datapreview.DataTypeComponentPreview`.
#[derive(Debug, Clone)]
pub struct DataTypeComponentPreview {
    /// The parent composite type name.
    pub parent_name: String,
    /// The component's field name.
    pub field_name: String,
    /// The component's type name.
    pub type_name: String,
    /// Byte offset of the component within the composite.
    pub offset: usize,
    /// Byte length of the component.
    pub length: usize,
}

impl DataTypeComponentPreview {
    /// Create a new component preview.
    pub fn new(
        parent_name: impl Into<String>,
        field_name: impl Into<String>,
        type_name: impl Into<String>,
        offset: usize,
        length: usize,
    ) -> Self {
        Self {
            parent_name: parent_name.into(),
            field_name: field_name.into(),
            type_name: type_name.into(),
            offset,
            length,
        }
    }
}

impl Preview for DataTypeComponentPreview {
    fn name(&self) -> &str {
        &self.field_name
    }

    fn get_preview(&self, memory: &[u8], base_offset: usize) -> Option<String> {
        let abs_offset = base_offset + self.offset;
        if abs_offset + self.length > memory.len() || self.length == 0 {
            return None;
        }
        let bytes = &memory[abs_offset..abs_offset + self.length];
        let hex: String = bytes.iter().map(|b| format!("{:02X} ", b)).collect();
        Some(hex.trim().to_string())
    }

    fn data_type_name(&self) -> &str {
        &self.type_name
    }

    fn expected_length(&self) -> Option<usize> {
        Some(self.length)
    }
}

impl PartialEq for DataTypeComponentPreview {
    fn eq(&self, other: &Self) -> bool {
        self.parent_name == other.parent_name && self.field_name == other.field_name
    }
}

impl Eq for DataTypeComponentPreview {}

impl PartialOrd for DataTypeComponentPreview {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DataTypeComponentPreview {
    fn cmp(&self, other: &Self) -> Ordering {
        self.parent_name
            .cmp(&other.parent_name)
            .then_with(|| self.field_name.cmp(&other.field_name))
    }
}

// ---------------------------------------------------------------------------
// Preview model
// ---------------------------------------------------------------------------

/// Table model holding a collection of data type previews.
///
/// Ported from the `DTPPTableModel` inside the `DataTypePreviewPlugin`.
pub struct PreviewModel {
    /// The preview rows in the model.
    previews: Vec<Box<dyn Preview>>,
    /// Memory bytes currently being previewed.
    memory: Vec<u8>,
    /// Base address offset for previews.
    base_offset: usize,
}

impl PreviewModel {
    /// Create a new empty preview model.
    pub fn new() -> Self {
        Self {
            previews: Vec::new(),
            memory: Vec::new(),
            base_offset: 0,
        }
    }

    /// Set the memory to preview.
    pub fn set_memory(&mut self, memory: Vec<u8>, base_offset: usize) {
        self.memory = memory;
        self.base_offset = base_offset;
    }

    /// Add a preview to the model.
    pub fn add_preview(&mut self, preview: Box<dyn Preview>) {
        self.previews.push(preview);
    }

    /// Remove a preview at the given index.
    pub fn remove_preview(&mut self, index: usize) -> Option<Box<dyn Preview>> {
        if index < self.previews.len() {
            Some(self.previews.remove(index))
        } else {
            None
        }
    }

    /// Get the number of previews.
    pub fn len(&self) -> usize {
        self.previews.len()
    }

    /// Whether the model is empty.
    pub fn is_empty(&self) -> bool {
        self.previews.is_empty()
    }

    /// Get the name for a preview at the given index.
    pub fn name_at(&self, index: usize) -> Option<&str> {
        self.previews.get(index).map(|p| p.name())
    }

    /// Get the preview string for a row at the current address.
    pub fn preview_at(&self, index: usize) -> Option<String> {
        self.previews
            .get(index)
            .and_then(|p| p.get_preview(&self.memory, self.base_offset))
    }

    /// Remove all previews.
    pub fn clear(&mut self) {
        self.previews.clear();
    }

    /// Get the data type paths for all previews that have a known data type.
    pub fn data_type_names(&self) -> Vec<&str> {
        self.previews.iter().map(|p| p.data_type_name()).collect()
    }
}

impl Default for PreviewModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Data type preview plugin
// ---------------------------------------------------------------------------

/// Plugin providing the data type preview panel.
///
/// Ported from `ghidra.app.plugin.core.datapreview.DataTypePreviewPlugin`.
pub struct DataTypePreviewPlugin {
    /// The preview model.
    model: PreviewModel,
    /// Whether the preview panel is visible.
    visible: bool,
    /// Current address being previewed.
    current_offset: Option<usize>,
}

impl DataTypePreviewPlugin {
    /// Create a new data type preview plugin with default types.
    pub fn new() -> Self {
        let mut model = PreviewModel::new();
        model.add_preview(Box::new(DataTypePreview::byte_type("byte")));
        model.add_preview(Box::new(DataTypePreview::word_type("word")));
        model.add_preview(Box::new(DataTypePreview::dword_type("dword")));
        model.add_preview(Box::new(DataTypePreview::qword_type("qword")));
        model.add_preview(Box::new(DataTypePreview::new("float", "float", Some(4))));
        model.add_preview(Box::new(DataTypePreview::new("double", "double", Some(8))));
        model.add_preview(Box::new(DataTypePreview::new("string", "string", None)));
        model.add_preview(Box::new(DataTypePreview::new("pointer", "pointer", Some(8))));

        Self {
            model,
            visible: false,
            current_offset: None,
        }
    }

    /// Get a reference to the preview model.
    pub fn model(&self) -> &PreviewModel {
        &self.model
    }

    /// Get a mutable reference to the preview model.
    pub fn model_mut(&mut self) -> &mut PreviewModel {
        &mut self.model
    }

    /// Set the memory and offset to preview.
    pub fn set_memory(&mut self, memory: Vec<u8>, offset: usize) {
        self.model.set_memory(memory, offset);
        self.current_offset = Some(offset);
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the preview is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Current offset being previewed.
    pub fn current_offset(&self) -> Option<usize> {
        self.current_offset
    }
}

impl Default for DataTypePreviewPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_preview() {
        let preview = DataTypePreview::byte_type("byte");
        let memory = vec![0xFF, 0x42];
        assert_eq!(preview.get_preview(&memory, 0), Some("0xFF".to_string()));
        assert_eq!(preview.get_preview(&memory, 1), Some("0x42".to_string()));
        assert!(preview.get_preview(&memory, 2).is_none());
    }

    #[test]
    fn test_word_preview() {
        let preview = DataTypePreview::word_type("word");
        let memory = vec![0x34, 0x12];
        assert_eq!(
            preview.get_preview(&memory, 0),
            Some("0x1234".to_string())
        );
    }

    #[test]
    fn test_dword_preview() {
        let preview = DataTypePreview::dword_type("dword");
        let memory = vec![0x78, 0x56, 0x34, 0x12];
        assert_eq!(
            preview.get_preview(&memory, 0),
            Some("0x12345678".to_string())
        );
    }

    #[test]
    fn test_int_preview() {
        let preview = DataTypePreview::new("int", "int", Some(4));
        let memory = vec![0xFF, 0xFF, 0xFF, 0xFF]; // -1 in little-endian
        assert_eq!(preview.get_preview(&memory, 0), Some("-1".to_string()));
    }

    #[test]
    fn test_float_preview() {
        let preview = DataTypePreview::new("float", "float", Some(4));
        let bytes = 1.0f32.to_le_bytes();
        let result = preview.get_preview(&bytes, 0).unwrap();
        assert_eq!(result, "1");
    }

    #[test]
    fn test_string_preview() {
        let preview = DataTypePreview::new("string", "string", None);
        let memory = b"Hello\x00";
        let result = preview.get_preview(memory, 0).unwrap();
        assert_eq!(result, "\"Hello\"");
    }

    #[test]
    fn test_string_preview_with_unprintable() {
        let preview = DataTypePreview::new("string", "string", None);
        let memory = vec![b'A', 0x01, b'B', 0x00];
        let result = preview.get_preview(&memory, 0).unwrap();
        assert_eq!(result, "\"A.B\"");
    }

    #[test]
    fn test_component_preview() {
        let preview = DataTypeComponentPreview::new("MyStruct", "field_a", "int", 4, 4);
        let memory = vec![0, 0, 0, 0, 0x78, 0x56, 0x34, 0x12];
        let result = preview.get_preview(&memory, 0).unwrap();
        assert_eq!(result, "78 56 34 12");
    }

    #[test]
    fn test_preview_model_lifecycle() {
        let mut model = PreviewModel::new();
        assert!(model.is_empty());

        model.add_preview(Box::new(DataTypePreview::byte_type("byte")));
        model.add_preview(Box::new(DataTypePreview::word_type("word")));
        assert_eq!(model.len(), 2);
        assert_eq!(model.name_at(0), Some("byte"));
        assert_eq!(model.name_at(1), Some("word"));

        model.set_memory(vec![0xAB, 0xCD], 0);
        assert_eq!(model.preview_at(0), Some("0xAB".to_string()));
        assert_eq!(model.preview_at(1), Some("0xCDAB".to_string()));

        model.remove_preview(0);
        assert_eq!(model.len(), 1);

        model.clear();
        assert!(model.is_empty());
    }

    #[test]
    fn test_preview_model_data_type_names() {
        let mut model = PreviewModel::new();
        model.add_preview(Box::new(DataTypePreview::byte_type("byte")));
        model.add_preview(Box::new(DataTypePreview::dword_type("dword")));
        let names = model.data_type_names();
        assert_eq!(names, vec!["byte", "dword"]);
    }

    #[test]
    fn test_preview_ordering() {
        let p1 = DataTypePreview::byte_type("aaa");
        let p2 = DataTypePreview::byte_type("bbb");
        assert!(p1 < p2);
    }

    #[test]
    fn test_preview_plugin() {
        let plugin = DataTypePreviewPlugin::new();
        assert!(!plugin.is_visible());
        assert!(plugin.current_offset().is_none());
        assert_eq!(plugin.model().len(), 8); // default previews
    }

    #[test]
    fn test_preview_plugin_memory() {
        let mut plugin = DataTypePreviewPlugin::new();
        plugin.set_visible(true);
        plugin.set_memory(vec![0x42, 0x43], 0);
        assert_eq!(plugin.current_offset(), Some(0));
        assert!(plugin.is_visible());
    }
}
