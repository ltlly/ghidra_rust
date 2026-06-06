//! `MaskValue` -- stores mask and value bytes for instruction patterns.
//!
//! Ported from `ghidra.features.base.memsearch.mnemonic.MaskValue`.

/// Stores information about an instruction mask and value.
///
/// The mask specifies which bits of the instruction are significant for
/// matching (set bits are checked, cleared bits are wildcards).
///
/// Ported from `MaskValue.java`.
#[derive(Debug, Clone)]
pub struct MaskValue {
    /// The mask bytes.
    mask: Vec<u8>,
    /// The value bytes.
    value: Vec<u8>,
    /// Optional text representation.
    text_representation: Option<String>,
}

impl MaskValue {
    /// Create a new mask/value pair.
    pub fn new(mask: Vec<u8>, value: Vec<u8>) -> Self {
        Self {
            mask,
            value,
            text_representation: None,
        }
    }

    /// Create a new mask/value pair with a text representation.
    pub fn with_text(mask: Vec<u8>, value: Vec<u8>, text: &str) -> Self {
        Self {
            mask,
            value,
            text_representation: Some(text.to_string()),
        }
    }

    /// Get the mask bytes.
    pub fn mask(&self) -> &[u8] {
        &self.mask
    }

    /// Get the value bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Get the text representation.
    pub fn text_representation(&self) -> Option<&str> {
        self.text_representation.as_deref()
    }

    /// Perform a bitwise OR on the mask bytes.
    pub fn or_mask(&mut self, other: &[u8]) {
        if self.mask.is_empty() {
            return;
        }
        let len = self.mask.len().min(other.len());
        for i in 0..len {
            self.mask[i] |= other[i];
        }
    }

    /// Perform a bitwise OR on the value bytes.
    pub fn or_value(&mut self, other: &[u8]) {
        if self.value.is_empty() {
            return;
        }
        let len = self.value.len().min(other.len());
        for i in 0..len {
            self.value[i] |= other[i];
        }
    }

    /// Perform a bitwise AND on the mask bytes.
    pub fn and_mask(&mut self, other: &[u8]) {
        if self.mask.is_empty() {
            return;
        }
        let len = self.mask.len().min(other.len());
        for i in 0..len {
            self.mask[i] &= other[i];
        }
    }

    /// Combine this mask/value with another by OR-ing both masks and values.
    pub fn combine_with(&mut self, other: &MaskValue) {
        self.or_mask(&other.mask);
        self.or_value(&other.value);
    }

    /// Get the byte length.
    pub fn length(&self) -> usize {
        self.value.len()
    }
}

impl std::fmt::Display for MaskValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rep = self.text_representation.as_deref().unwrap_or("");
        write!(
            f,
            "MaskValue - {} [mask={}, value={}]",
            rep,
            format_bytes(&self.mask),
            format_bytes(&self.value)
        )
    }
}

fn format_bytes(bytes: &[u8]) -> String {
    format!(
        "[{}]",
        bytes
            .iter()
            .map(|b| format!("{}", b))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_value_basic() {
        let mv = MaskValue::new(vec![0xFF, 0xFF], vec![0x55, 0x89]);
        assert_eq!(mv.mask(), &[0xFF, 0xFF]);
        assert_eq!(mv.value(), &[0x55, 0x89]);
        assert_eq!(mv.length(), 2);
    }

    #[test]
    fn test_or_mask() {
        let mut mv = MaskValue::new(vec![0xF0, 0x0F], vec![0x55, 0x89]);
        mv.or_mask(&[0x0F, 0xF0]);
        assert_eq!(mv.mask(), &[0xFF, 0xFF]);
    }

    #[test]
    fn test_and_mask() {
        let mut mv = MaskValue::new(vec![0xFF, 0xFF], vec![0x55, 0x89]);
        mv.and_mask(&[0xF0, 0x0F]);
        assert_eq!(mv.mask(), &[0xF0, 0x0F]);
    }

    #[test]
    fn test_combine_with() {
        let mut mv1 = MaskValue::new(vec![0xF0, 0x00], vec![0x50, 0x00]);
        let mv2 = MaskValue::new(vec![0x0F, 0xF0], vec![0x05, 0x80]);
        mv1.combine_with(&mv2);
        assert_eq!(mv1.mask(), &[0xFF, 0xF0]);
        assert_eq!(mv1.value(), &[0x55, 0x80]);
    }

    #[test]
    fn test_with_text() {
        let mv = MaskValue::with_text(vec![0xFF], vec![0x55], "PUSH EBP");
        assert_eq!(mv.text_representation(), Some("PUSH EBP"));
    }
}
