//! Hover Plugin -- show tooltip information on hover.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.hover` Java package.
//!
//! Provides model-level logic for computing what information to display
//! when the user hovers over elements in the listing.

use ghidra_core::Address;

/// The type of element being hovered over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoverElementType {
    /// Hovering over a label.
    Label,
    /// Hovering over a register.
    Register,
    /// Hovering over a data type.
    DataType,
    /// Hovering over an address reference.
    AddressReference,
    /// Hovering over a function.
    Function,
    /// Hovering over a variable.
    Variable,
    /// Hovering over a comment.
    Comment,
}

/// A hover info entry.
#[derive(Debug, Clone)]
pub struct HoverInfo {
    /// The element type being hovered.
    pub element_type: HoverElementType,
    /// The address associated with the hover.
    pub address: Address,
    /// The text to display in the tooltip.
    pub display_text: String,
    /// Whether this hover info should be shown.
    pub enabled: bool,
}

impl HoverInfo {
    /// Create a new hover info entry.
    pub fn new(
        element_type: HoverElementType,
        address: Address,
        display_text: impl Into<String>,
    ) -> Self {
        Self {
            element_type,
            address,
            display_text: display_text.into(),
            enabled: true,
        }
    }
}

/// Model for computing hover information.
#[derive(Debug, Default)]
pub struct HoverModel {
    entries: Vec<HoverInfo>,
}

impl HoverModel {
    /// Create a new hover model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a hover info entry.
    pub fn add_entry(&mut self, entry: HoverInfo) {
        self.entries.push(entry);
    }

    /// Get hover info for an address.
    pub fn get_hover_at(&self, address: Address) -> Vec<&HoverInfo> {
        self.entries
            .iter()
            .filter(|e| e.address == address && e.enabled)
            .collect()
    }

    /// Get all entries.
    pub fn get_all_entries(&self) -> &[HoverInfo] {
        &self.entries
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return the number of entries.
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hover_info() {
        let mut model = HoverModel::new();
        model.add_entry(HoverInfo::new(
            HoverElementType::Label,
            Address::new(0x1000),
            "main: Function entry point",
        ));
        let entries = model.get_hover_at(Address::new(0x1000));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].display_text, "main: Function entry point");
    }

    #[test]
    fn test_hover_disabled() {
        let mut model = HoverModel::new();
        let mut info = HoverInfo::new(
            HoverElementType::Register,
            Address::new(0x1000),
            "RAX = 0",
        );
        info.enabled = false;
        model.add_entry(info);
        let entries = model.get_hover_at(Address::new(0x1000));
        assert_eq!(entries.len(), 0);
    }
}
