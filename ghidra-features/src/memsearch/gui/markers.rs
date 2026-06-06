//! `SearchMarkers` -- manages marker sets for search results.
//!
//! Ported from `ghidra.features.base.memsearch.gui.SearchMarkers`.

use std::collections::BTreeMap;

use crate::memsearch::searcher::MemoryMatch;

/// Manages markers for search results displayed in the listing.
///
/// Ported from `SearchMarkers.java`.
#[derive(Debug, Clone)]
pub struct SearchMarkers {
    /// Marker title (usually the search text).
    title: String,
    /// Markers keyed by address.
    markers: BTreeMap<u64, String>,
    /// Background highlight color (as RGB).
    highlight_color: (u8, u8, u8),
}

impl SearchMarkers {
    /// Create a new set of search markers.
    pub fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            markers: BTreeMap::new(),
            highlight_color: (0xFF, 0xFF, 0x00), // default yellow
        }
    }

    /// Set the highlight color.
    pub fn with_color(mut self, r: u8, g: u8, b: u8) -> Self {
        self.highlight_color = (r, g, b);
        self
    }

    /// Update markers from a set of matches.
    pub fn set_markers(&mut self, matches: &[MemoryMatch]) {
        self.markers.clear();
        for m in matches {
            self.markers.insert(
                m.address(),
                format_bytes(m.current_bytes()),
            );
        }
    }

    /// Add a single marker.
    pub fn add_marker(&mut self, address: u64, tooltip: &str) {
        self.markers.insert(address, tooltip.to_string());
    }

    /// Remove a marker.
    pub fn remove_marker(&mut self, address: u64) {
        self.markers.remove(&address);
    }

    /// Get the number of markers.
    pub fn len(&self) -> usize {
        self.markers.len()
    }

    /// Returns true if there are no markers.
    pub fn is_empty(&self) -> bool {
        self.markers.is_empty()
    }

    /// Check if a marker exists at the given address.
    pub fn has_marker_at(&self, address: u64) -> bool {
        self.markers.contains_key(&address)
    }

    /// Get all marker addresses.
    pub fn addresses(&self) -> Vec<u64> {
        self.markers.keys().copied().collect()
    }

    /// Get the tooltip for a marker at the given address.
    pub fn tooltip_at(&self, address: u64) -> Option<&str> {
        self.markers.get(&address).map(|s| s.as_str())
    }

    /// Get the title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Get the highlight color as (R, G, B).
    pub fn highlight_color(&self) -> (u8, u8, u8) {
        self.highlight_color
    }

    /// Clear all markers.
    pub fn clear(&mut self) {
        self.markers.clear();
    }
}

fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markers_basic() {
        let mut markers = SearchMarkers::new("test search");
        assert_eq!(markers.title(), "test search");
        assert!(markers.is_empty());
    }

    #[test]
    fn test_markers_from_matches() {
        let mut markers = SearchMarkers::new("test");
        let matches = vec![
            MemoryMatch::new(0x1000, vec![0x55, 0x89]),
            MemoryMatch::new(0x2000, vec![0xE5, 0xC3]),
        ];
        markers.set_markers(&matches);
        assert_eq!(markers.len(), 2);
        assert!(markers.has_marker_at(0x1000));
        assert!(markers.has_marker_at(0x2000));
    }

    #[test]
    fn test_markers_add_remove() {
        let mut markers = SearchMarkers::new("test");
        markers.add_marker(0x1000, "push ebp");
        assert!(markers.has_marker_at(0x1000));

        markers.remove_marker(0x1000);
        assert!(!markers.has_marker_at(0x1000));
    }

    #[test]
    fn test_markers_color() {
        let markers = SearchMarkers::new("test").with_color(0xFF, 0x00, 0x00);
        assert_eq!(markers.highlight_color(), (0xFF, 0x00, 0x00));
    }

    #[test]
    fn test_markers_tooltip() {
        let mut markers = SearchMarkers::new("test");
        markers.add_marker(0x1000, "55 89");
        assert_eq!(markers.tooltip_at(0x1000), Some("55 89"));
        assert_eq!(markers.tooltip_at(0x2000), None);
    }

    #[test]
    fn test_markers_addresses() {
        let mut markers = SearchMarkers::new("test");
        markers.add_marker(0x2000, "b");
        markers.add_marker(0x1000, "a");
        let addrs = markers.addresses();
        assert_eq!(addrs, vec![0x1000, 0x2000]); // BTreeMap is sorted
    }
}
