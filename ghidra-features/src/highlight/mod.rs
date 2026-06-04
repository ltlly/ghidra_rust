//! Highlight Plugin -- highlight matching text and patterns.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.highlight` Java package.

use ghidra_core::Address;
use std::collections::HashMap;

/// A highlight color specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighlightColor {
    /// Red component (0-255).
    pub r: u8,
    /// Green component (0-255).
    pub g: u8,
    /// Blue component (0-255).
    pub b: u8,
    /// Alpha (transparency) component (0-255).
    pub a: u8,
}

impl HighlightColor {
    /// Create a new highlight color.
    pub fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Yellow highlight.
    pub fn yellow() -> Self {
        Self::new(255, 255, 0, 128)
    }

    /// Green highlight.
    pub fn green() -> Self {
        Self::new(0, 255, 0, 128)
    }

    /// Red highlight.
    pub fn red() -> Self {
        Self::new(255, 0, 0, 128)
    }

    /// Cyan highlight.
    pub fn cyan() -> Self {
        Self::new(0, 255, 255, 128)
    }
}

/// A highlight entry at a specific address.
#[derive(Debug, Clone)]
pub struct HighlightEntry {
    /// The address to highlight.
    pub address: Address,
    /// The highlight color.
    pub color: HighlightColor,
    /// The highlighted text (optional).
    pub text: Option<String>,
}

/// Manages highlights in the listing.
#[derive(Debug, Default)]
pub struct HighlightManager {
    entries: HashMap<u64, HighlightEntry>,
}

impl HighlightManager {
    /// Create a new highlight manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a highlight at an address.
    pub fn set_highlight(&mut self, address: Address, color: HighlightColor) {
        self.entries.insert(
            address.offset,
            HighlightEntry {
                address,
                color,
                text: None,
            },
        );
    }

    /// Remove a highlight at an address.
    pub fn remove_highlight(&mut self, address: Address) {
        self.entries.remove(&address.offset);
    }

    /// Get the highlight at an address.
    pub fn get_highlight(&self, address: Address) -> Option<&HighlightEntry> {
        self.entries.get(&address.offset)
    }

    /// Check if an address is highlighted.
    pub fn is_highlighted(&self, address: Address) -> bool {
        self.entries.contains_key(&address.offset)
    }

    /// Clear all highlights.
    pub fn clear_all(&mut self) {
        self.entries.clear();
    }

    /// Return the number of highlighted addresses.
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get_highlight() {
        let mut mgr = HighlightManager::new();
        mgr.set_highlight(Address::new(0x1000), HighlightColor::yellow());
        assert!(mgr.is_highlighted(Address::new(0x1000)));
        let entry = mgr.get_highlight(Address::new(0x1000)).unwrap();
        assert_eq!(entry.color, HighlightColor::yellow());
    }

    #[test]
    fn test_remove_highlight() {
        let mut mgr = HighlightManager::new();
        mgr.set_highlight(Address::new(0x1000), HighlightColor::red());
        mgr.remove_highlight(Address::new(0x1000));
        assert!(!mgr.is_highlighted(Address::new(0x1000)));
    }

    #[test]
    fn test_clear_all() {
        let mut mgr = HighlightManager::new();
        mgr.set_highlight(Address::new(0x1000), HighlightColor::green());
        mgr.set_highlight(Address::new(0x2000), HighlightColor::cyan());
        mgr.clear_all();
        assert_eq!(mgr.count(), 0);
    }
}
