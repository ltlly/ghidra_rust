//! Data type preview plugin and component preview.
//!
//! Ported from `ghidra.app.plugin.core.datapreview.DataTypePreviewPlugin`,
//! `DataTypePreview`, `DataTypeComponentPreview`, and `Preview`.

use ghidra_core::Address;

// ---------------------------------------------------------------------------
// DataTypePreviewPlugin
// ---------------------------------------------------------------------------

/// Plugin providing data type preview in the listing.
///
/// Ported from `ghidra.app.plugin.core.datapreview.DataTypePreviewPlugin`.
#[derive(Debug)]
pub struct DataTypePreviewPlugin {
    /// Whether preview is enabled.
    enabled: bool,
    /// The current preview.
    preview: Option<DataTypePreview>,
}

impl DataTypePreviewPlugin {
    /// Create a new data type preview plugin.
    pub fn new() -> Self {
        Self {
            enabled: true,
            preview: None,
        }
    }

    /// Whether preview is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable preview.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Set the current preview.
    pub fn set_preview(&mut self, preview: DataTypePreview) {
        self.preview = Some(preview);
    }

    /// Get the current preview.
    pub fn preview(&self) -> Option<&DataTypePreview> {
        self.preview.as_ref()
    }

    /// Clear the preview.
    pub fn clear_preview(&mut self) {
        self.preview = None;
    }
}

impl Default for DataTypePreviewPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DataTypePreview
// ---------------------------------------------------------------------------

/// Preview of a data type at an address.
///
/// Ported from `ghidra.app.plugin.core.datapreview.DataTypePreview`.
#[derive(Debug, Clone)]
pub struct DataTypePreview {
    /// The address being previewed.
    pub address: Address,
    /// The data type name.
    pub type_name: String,
    /// The size in bytes.
    pub size: usize,
    /// The formatted value string.
    pub formatted_value: String,
    /// Component previews (for composite types).
    pub components: Vec<DataTypeComponentPreview>,
    /// Raw bytes at the address.
    pub raw_bytes: Vec<u8>,
}

impl DataTypePreview {
    /// Create a new data type preview.
    pub fn new(
        address: Address,
        type_name: impl Into<String>,
        size: usize,
        formatted_value: impl Into<String>,
        raw_bytes: Vec<u8>,
    ) -> Self {
        Self {
            address,
            type_name: type_name.into(),
            size,
            formatted_value: formatted_value.into(),
            components: Vec::new(),
            raw_bytes,
        }
    }

    /// Add a component preview.
    pub fn add_component(&mut self, component: DataTypeComponentPreview) {
        self.components.push(component);
    }

    /// Get the number of components.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Whether this is a composite type (has components).
    pub fn is_composite(&self) -> bool {
        !self.components.is_empty()
    }

    /// Format the preview as a display string.
    pub fn display_string(&self) -> String {
        if self.is_composite() {
            let mut s = format!("{} {{", self.type_name);
            for comp in &self.components {
                s.push_str(&format!(
                    "\n  {}: {}",
                    comp.field_name, comp.formatted_value
                ));
            }
            s.push_str("\n}");
            s
        } else {
            format!("{}: {}", self.type_name, self.formatted_value)
        }
    }
}

// ---------------------------------------------------------------------------
// DataTypeComponentPreview
// ---------------------------------------------------------------------------

/// Preview of a single component within a composite data type.
///
/// Ported from `ghidra.app.plugin.core.datapreview.DataTypeComponentPreview`.
#[derive(Debug, Clone)]
pub struct DataTypeComponentPreview {
    /// The field/offset name.
    pub field_name: String,
    /// The offset within the parent type.
    pub offset: usize,
    /// The size of this component.
    pub size: usize,
    /// The component data type name.
    pub type_name: String,
    /// The formatted value.
    pub formatted_value: String,
    /// The raw bytes for this component.
    pub raw_bytes: Vec<u8>,
}

impl DataTypeComponentPreview {
    /// Create a new component preview.
    pub fn new(
        field_name: impl Into<String>,
        offset: usize,
        size: usize,
        type_name: impl Into<String>,
        formatted_value: impl Into<String>,
        raw_bytes: Vec<u8>,
    ) -> Self {
        Self {
            field_name: field_name.into(),
            offset,
            size,
            type_name: type_name.into(),
            formatted_value: formatted_value.into(),
            raw_bytes,
        }
    }
}

// ---------------------------------------------------------------------------
// Preview trait
// ---------------------------------------------------------------------------

/// Trait for objects that can provide a preview.
pub trait Preview {
    /// Get the preview text.
    fn preview_text(&self) -> String;

    /// Get the address being previewed.
    fn preview_address(&self) -> Address;
}

impl Preview for DataTypePreview {
    fn preview_text(&self) -> String {
        self.display_string()
    }

    fn preview_address(&self) -> Address {
        self.address
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datatype_preview_plugin() {
        let mut plugin = DataTypePreviewPlugin::new();
        assert!(plugin.is_enabled());
        assert!(plugin.preview().is_none());

        plugin.set_preview(DataTypePreview::new(
            Address::new(0x1000),
            "int",
            4,
            "42",
            vec![0x2A, 0x00, 0x00, 0x00],
        ));
        assert!(plugin.preview().is_some());

        plugin.clear_preview();
        assert!(plugin.preview().is_none());
    }

    #[test]
    fn test_datatype_preview_simple() {
        let preview = DataTypePreview::new(
            Address::new(0x1000),
            "uint32_t",
            4,
            "0xDEADBEEF",
            vec![0xEF, 0xBE, 0xAD, 0xDE],
        );
        assert_eq!(preview.type_name, "uint32_t");
        assert_eq!(preview.size, 4);
        assert!(!preview.is_composite());
        assert_eq!(preview.component_count(), 0);

        let display = preview.display_string();
        assert!(display.contains("uint32_t"));
        assert!(display.contains("0xDEADBEEF"));
    }

    #[test]
    fn test_datatype_preview_composite() {
        let mut preview = DataTypePreview::new(
            Address::new(0x1000),
            "Point",
            8,
            "",
            vec![0x0A, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00],
        );
        preview.add_component(DataTypeComponentPreview::new(
            "x",
            0,
            4,
            "int32_t",
            "10",
            vec![0x0A, 0x00, 0x00, 0x00],
        ));
        preview.add_component(DataTypeComponentPreview::new(
            "y",
            4,
            4,
            "int32_t",
            "20",
            vec![0x14, 0x00, 0x00, 0x00],
        ));

        assert!(preview.is_composite());
        assert_eq!(preview.component_count(), 2);

        let display = preview.display_string();
        assert!(display.contains("Point {"));
        assert!(display.contains("x: 10"));
        assert!(display.contains("y: 20"));
    }

    #[test]
    fn test_datatype_component_preview() {
        let comp = DataTypeComponentPreview::new(
            "field_a",
            0,
            4,
            "uint32_t",
            "0x12345678",
            vec![0x78, 0x56, 0x34, 0x12],
        );
        assert_eq!(comp.field_name, "field_a");
        assert_eq!(comp.offset, 0);
        assert_eq!(comp.size, 4);
    }

    #[test]
    fn test_preview_trait() {
        let preview = DataTypePreview::new(
            Address::new(0x400000),
            "short",
            2,
            "256",
            vec![0x00, 0x01],
        );
        assert_eq!(preview.preview_address().offset, 0x400000);
        assert!(!preview.preview_text().is_empty());
    }

    #[test]
    fn test_plugin_disabled() {
        let mut plugin = DataTypePreviewPlugin::new();
        plugin.set_enabled(false);
        assert!(!plugin.is_enabled());
    }
}
