//! Data preview model.
//!
//! Ported from `ghidra.app.plugin.core.datapreview` classes.
//!
//! Provides a preview of how bytes at the current address would be
//! interpreted as various data types (integer, float, pointer, etc.).

/// Preview of a data interpretation.
#[derive(Debug, Clone)]
pub struct DataPreview {
    /// The data type name.
    pub type_name: String,
    /// The interpreted value as a string.
    pub value: String,
    /// The size of this interpretation in bytes.
    pub size: usize,
    /// Whether this interpretation is applicable at the current address.
    pub is_valid: bool,
    /// A hint about the interpretation (e.g., "IEEE 754 float").
    pub hint: String,
}

/// Model for data preview.
#[derive(Debug)]
pub struct DataPreviewModel {
    /// The raw bytes being previewed.
    bytes: Vec<u8>,
    /// The current address.
    address: u64,
    /// Preview interpretations.
    previews: Vec<DataPreview>,
    /// Selected preview index.
    selected: Option<usize>,
}

impl DataPreviewModel {
    pub fn new() -> Self {
        Self {
            bytes: Vec::new(),
            address: 0,
            previews: Vec::new(),
            selected: None,
        }
    }

    /// Set the bytes to preview at the given address.
    pub fn set_data(&mut self, address: u64, bytes: Vec<u8>) {
        self.address = address;
        self.bytes = bytes;
        self.previews.clear();
        self.generate_previews();
        self.selected = None;
    }

    /// Get the previews.
    pub fn previews(&self) -> &[DataPreview] {
        &self.previews
    }

    /// Get the selected preview.
    pub fn selected_preview(&self) -> Option<&DataPreview> {
        self.selected.and_then(|i| self.previews.get(i))
    }

    /// Select a preview.
    pub fn select(&mut self, index: Option<usize>) {
        self.selected = index;
    }

    /// Get the current address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Get the raw bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn generate_previews(&mut self) {
        if self.bytes.is_empty() {
            return;
        }

        // Byte interpretation
        if self.bytes.len() >= 1 {
            self.previews.push(DataPreview {
                type_name: "byte".to_string(),
                value: format!("0x{:02X}", self.bytes[0]),
                size: 1,
                is_valid: true,
                hint: "Unsigned 8-bit integer".to_string(),
            });
        }

        // Word interpretation
        if self.bytes.len() >= 2 {
            let val = u16::from_le_bytes([self.bytes[0], self.bytes[1]]);
            self.previews.push(DataPreview {
                type_name: "word".to_string(),
                value: format!("0x{:04X}", val),
                size: 2,
                is_valid: true,
                hint: "Unsigned 16-bit integer (LE)".to_string(),
            });
        }

        // Dword interpretation
        if self.bytes.len() >= 4 {
            let val = u32::from_le_bytes([
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
            ]);
            self.previews.push(DataPreview {
                type_name: "dword".to_string(),
                value: format!("0x{:08X}", val),
                size: 4,
                is_valid: true,
                hint: "Unsigned 32-bit integer (LE)".to_string(),
            });
            // Float
            let fval = f32::from_bits(val);
            self.previews.push(DataPreview {
                type_name: "float".to_string(),
                value: format!("{}", fval),
                size: 4,
                is_valid: true,
                hint: "IEEE 754 single-precision float".to_string(),
            });
        }

        // Qword interpretation
        if self.bytes.len() >= 8 {
            let val = u64::from_le_bytes([
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
                self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7],
            ]);
            self.previews.push(DataPreview {
                type_name: "qword".to_string(),
                value: format!("0x{:016X}", val),
                size: 8,
                is_valid: true,
                hint: "Unsigned 64-bit integer (LE)".to_string(),
            });
            // Double
            let dval = f64::from_bits(val);
            self.previews.push(DataPreview {
                type_name: "double".to_string(),
                value: format!("{}", dval),
                size: 8,
                is_valid: true,
                hint: "IEEE 754 double-precision float".to_string(),
            });
        }

        // ASCII/pointer hint
        if self.bytes.len() >= 4 {
            let printable = self.bytes.iter().all(|&b| b >= 0x20 && b < 0x7F);
            if printable {
                self.previews.push(DataPreview {
                    type_name: "string".to_string(),
                    value: String::from_utf8_lossy(&self.bytes).to_string(),
                    size: self.bytes.len(),
                    is_valid: true,
                    hint: "Printable ASCII string".to_string(),
                });
            }
        }
    }
}

impl Default for DataPreviewModel {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preview_model_empty() {
        let model = DataPreviewModel::new();
        assert!(model.previews().is_empty());
        assert!(model.selected_preview().is_none());
    }

    #[test]
    fn test_preview_byte() {
        let mut model = DataPreviewModel::new();
        model.set_data(0x1000, vec![0x41]);
        assert!(!model.previews().is_empty());
        assert_eq!(model.previews()[0].type_name, "byte");
        assert_eq!(model.previews()[0].value, "0x41");
    }

    #[test]
    fn test_preview_word() {
        let mut model = DataPreviewModel::new();
        model.set_data(0x1000, vec![0x34, 0x12]);
        let word = model.previews().iter().find(|p| p.type_name == "word").unwrap();
        assert_eq!(word.value, "0x1234");
    }

    #[test]
    fn test_preview_dword_float() {
        let mut model = DataPreviewModel::new();
        let f: f32 = 3.14;
        let bytes = f.to_le_bytes().to_vec();
        model.set_data(0x1000, bytes);
        let float_preview = model.previews().iter().find(|p| p.type_name == "float").unwrap();
        assert!(float_preview.value.starts_with("3.14"));
    }

    #[test]
    fn test_preview_string() {
        let mut model = DataPreviewModel::new();
        model.set_data(0x1000, b"Hello".to_vec());
        let str_preview = model.previews().iter().find(|p| p.type_name == "string");
        assert!(str_preview.is_some());
        assert_eq!(str_preview.unwrap().value, "Hello");
    }

    #[test]
    fn test_preview_select() {
        let mut model = DataPreviewModel::new();
        model.set_data(0x1000, vec![0x41, 0x42, 0x43, 0x44]);
        model.select(Some(1));
        assert!(model.selected_preview().is_some());
    }
}
