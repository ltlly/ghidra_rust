//! Address-based background color highlighting.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.colorizer` package.
//!
//! Provides a service for setting and querying background colors at specific
//! addresses in the listing view. Color data is stored per-address and can
//! be used for visual annotation of interesting code regions.
//!
//! # Usage
//!
//! ```rust
//! use ghidra_features::base::colorizer::{ColorizingService, ColorizingServiceImpl};
//!
//! let mut svc = ColorizingServiceImpl::new();
//! svc.set_background_color(0x400000, 0x4000FF, 0xFF0000); // Red highlight
//! assert_eq!(svc.get_background_color(0x400050), Some(0xFF0000));
//! svc.clear_background_color(0x400000, 0x4000FF);
//! assert_eq!(svc.get_background_color(0x400050), None);
//! ```

use std::collections::BTreeMap;

/// Represents an RGB color as a 24-bit integer (0xRRGGBB).
pub type Color = u32;

/// Create a color from red, green, blue components (0..255).
pub fn rgb(r: u8, g: u8, b: u8) -> Color {
    ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
}

/// Extract the red component from a color.
pub fn red(c: Color) -> u8 {
    ((c >> 16) & 0xFF) as u8
}

/// Extract the green component from a color.
pub fn green(c: Color) -> u8 {
    ((c >> 8) & 0xFF) as u8
}

/// Extract the blue component from a color.
pub fn blue(c: Color) -> u8 {
    (c & 0xFF) as u8
}

/// Compute a "fill" color by blending the given color toward white (200/255ths).
///
/// Ported from `MarkerSetImpl.getFillColor()`.
pub fn fill_color(c: Color) -> Color {
    const TARGET: u32 = 200;
    let r = (red(c) as u32 + 3 * TARGET) / 4;
    let g = (green(c) as u32 + 3 * TARGET) / 4;
    let b = (blue(c) as u32 + 3 * TARGET) / 4;
    rgb(r as u8, g as u8, b as u8)
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Trait for colorizing service implementations.
///
/// Ported from `ghidra.app.plugin.core.colorizer.ColorizingService`.
pub trait ColorizingService: Send + Sync {
    /// Set the background color for a range of addresses (inclusive).
    fn set_background_color(&mut self, min_addr: u64, max_addr: u64, color: Color);

    /// Get the background color at a specific address.
    fn get_background_color(&self, addr: u64) -> Option<Color>;

    /// Get all addresses that have a background color set.
    fn all_colored_addresses(&self) -> Vec<(u64, u64)>;

    /// Get all addresses that have a specific color.
    fn addresses_with_color(&self, color: Color) -> Vec<(u64, u64)>;

    /// Clear background colors over a range (inclusive).
    fn clear_background_color(&mut self, min_addr: u64, max_addr: u64);

    /// Clear all background colors.
    fn clear_all_background_colors(&mut self);
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/// In-memory implementation of the colorizing service.
///
/// Stores address-to-color mappings in a `BTreeMap` for efficient
/// range queries. Each entry maps a single address to a color value.
///
/// This corresponds to the non-GUI portions of Ghidra's `ColorizingPlugin`
/// and its backing store.
#[derive(Debug)]
pub struct ColorizingServiceImpl {
    /// Address -> Color mapping.
    colors: BTreeMap<u64, Color>,
    /// Recently used colors (most recent first).
    recent_colors: Vec<Color>,
    /// Maximum number of recent colors to track.
    max_recent: usize,
}

impl ColorizingServiceImpl {
    /// Create a new empty colorizing service.
    pub fn new() -> Self {
        Self {
            colors: BTreeMap::new(),
            recent_colors: Vec::new(),
            max_recent: 16,
        }
    }

    /// Get the most recently used color.
    pub fn most_recent_color(&self) -> Option<Color> {
        self.recent_colors.first().copied()
    }

    /// Get the list of recently used colors.
    pub fn recent_colors(&self) -> &[Color] {
        &self.recent_colors
    }

    /// Record a color as recently used.
    fn record_recent_color(&mut self, color: Color) {
        self.recent_colors.retain(|&c| c != color);
        self.recent_colors.insert(0, color);
        if self.recent_colors.len() > self.max_recent {
            self.recent_colors.truncate(self.max_recent);
        }
    }

    /// Count the total number of colored addresses.
    pub fn colored_address_count(&self) -> usize {
        self.colors.len()
    }

    /// Check if any colors are set.
    pub fn has_colors(&self) -> bool {
        !self.colors.is_empty()
    }
}

impl Default for ColorizingServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl ColorizingService for ColorizingServiceImpl {
    fn set_background_color(&mut self, min_addr: u64, max_addr: u64, color: Color) {
        self.record_recent_color(color);
        for addr in min_addr..=max_addr {
            self.colors.insert(addr, color);
        }
    }

    fn get_background_color(&self, addr: u64) -> Option<Color> {
        self.colors.get(&addr).copied()
    }

    fn all_colored_addresses(&self) -> Vec<(u64, u64)> {
        merge_ranges(&self.colors)
    }

    fn addresses_with_color(&self, color: Color) -> Vec<(u64, u64)> {
        let filtered: BTreeMap<u64, Color> = self
            .colors
            .iter()
            .filter(|(_, &c)| c == color)
            .map(|(&k, &v)| (k, v))
            .collect();
        merge_ranges(&filtered)
    }

    fn clear_background_color(&mut self, min_addr: u64, max_addr: u64) {
        // Collect keys to remove to avoid borrowing issues.
        let keys: Vec<u64> = self
            .colors
            .range(min_addr..=max_addr)
            .map(|(&k, _)| k)
            .collect();
        for key in keys {
            self.colors.remove(&key);
        }
    }

    fn clear_all_background_colors(&mut self) {
        self.colors.clear();
    }
}

/// Merge contiguous addresses into (min, max) range pairs.
fn merge_ranges(colors: &BTreeMap<u64, Color>) -> Vec<(u64, u64)> {
    if colors.is_empty() {
        return Vec::new();
    }

    let mut ranges = Vec::new();
    let mut iter = colors.iter();
    let (&first_addr, _) = iter.next().unwrap();
    let mut range_start = first_addr;
    let mut range_end = first_addr;

    for (&addr, _) in iter {
        if addr == range_end + 1 {
            range_end = addr;
        } else {
            ranges.push((range_start, range_end));
            range_start = addr;
            range_end = addr;
        }
    }
    ranges.push((range_start, range_end));
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rgb_construction() {
        let c = rgb(0xFF, 0x00, 0x00);
        assert_eq!(c, 0xFF0000);
        assert_eq!(red(c), 0xFF);
        assert_eq!(green(c), 0x00);
        assert_eq!(blue(c), 0x00);
    }

    #[test]
    fn test_rgb_mixed() {
        let c = rgb(0x12, 0x34, 0x56);
        assert_eq!(red(c), 0x12);
        assert_eq!(green(c), 0x34);
        assert_eq!(blue(c), 0x56);
    }

    #[test]
    fn test_fill_color() {
        let red_color = rgb(255, 0, 0);
        let filled = fill_color(red_color);
        // Should be blended toward white (200).
        assert!(red(filled) < 255);
        assert!(green(filled) > 0);
        assert!(blue(filled) > 0);
    }

    #[test]
    fn test_service_set_and_get() {
        let mut svc = ColorizingServiceImpl::new();
        svc.set_background_color(100, 200, 0xFF0000);
        assert_eq!(svc.get_background_color(100), Some(0xFF0000));
        assert_eq!(svc.get_background_color(150), Some(0xFF0000));
        assert_eq!(svc.get_background_color(200), Some(0xFF0000));
        assert_eq!(svc.get_background_color(201), None);
        assert_eq!(svc.get_background_color(99), None);
    }

    #[test]
    fn test_service_clear_range() {
        let mut svc = ColorizingServiceImpl::new();
        svc.set_background_color(100, 200, 0xFF0000);
        svc.clear_background_color(150, 160);
        assert_eq!(svc.get_background_color(149), Some(0xFF0000));
        assert_eq!(svc.get_background_color(150), None);
        assert_eq!(svc.get_background_color(160), None);
        assert_eq!(svc.get_background_color(161), Some(0xFF0000));
    }

    #[test]
    fn test_service_clear_all() {
        let mut svc = ColorizingServiceImpl::new();
        svc.set_background_color(100, 200, 0xFF0000);
        svc.clear_all_background_colors();
        assert!(svc.all_colored_addresses().is_empty());
    }

    #[test]
    fn test_service_overlapping_colors() {
        let mut svc = ColorizingServiceImpl::new();
        svc.set_background_color(100, 200, 0xFF0000);
        svc.set_background_color(150, 250, 0x00FF00);
        assert_eq!(svc.get_background_color(100), Some(0xFF0000));
        assert_eq!(svc.get_background_color(150), Some(0x00FF00)); // Overwritten
        assert_eq!(svc.get_background_color(250), Some(0x00FF00));
    }

    #[test]
    fn test_service_all_colored_ranges() {
        let mut svc = ColorizingServiceImpl::new();
        svc.set_background_color(10, 20, 0xFF0000);
        svc.set_background_color(30, 40, 0x00FF00);
        let ranges = svc.all_colored_addresses();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], (10, 20));
        assert_eq!(ranges[1], (30, 40));
    }

    #[test]
    fn test_service_addresses_with_color() {
        let mut svc = ColorizingServiceImpl::new();
        svc.set_background_color(10, 20, 0xFF0000);
        svc.set_background_color(30, 40, 0x00FF00);
        let red_ranges = svc.addresses_with_color(0xFF0000);
        assert_eq!(red_ranges.len(), 1);
        assert_eq!(red_ranges[0], (10, 20));
    }

    #[test]
    fn test_service_recent_colors() {
        let mut svc = ColorizingServiceImpl::new();
        svc.set_background_color(10, 10, 0xFF0000);
        svc.set_background_color(20, 20, 0x00FF00);
        assert_eq!(svc.most_recent_color(), Some(0x00FF00));
        assert_eq!(svc.recent_colors().len(), 2);
        assert_eq!(svc.recent_colors()[0], 0x00FF00);
        assert_eq!(svc.recent_colors()[1], 0xFF0000);
    }

    #[test]
    fn test_service_recent_colors_dedup() {
        let mut svc = ColorizingServiceImpl::new();
        svc.set_background_color(10, 10, 0xFF0000);
        svc.set_background_color(20, 20, 0x00FF00);
        svc.set_background_color(30, 30, 0xFF0000); // Same red again
        assert_eq!(svc.most_recent_color(), Some(0xFF0000));
        assert_eq!(svc.recent_colors().len(), 2); // Deduped
    }

    #[test]
    fn test_service_count() {
        let mut svc = ColorizingServiceImpl::new();
        assert_eq!(svc.colored_address_count(), 0);
        assert!(!svc.has_colors());

        svc.set_background_color(10, 14, 0xFF0000);
        assert_eq!(svc.colored_address_count(), 5);
        assert!(svc.has_colors());
    }

    #[test]
    fn test_merge_ranges_contiguous() {
        let mut colors = BTreeMap::new();
        colors.insert(10, 0xFF0000);
        colors.insert(11, 0xFF0000);
        colors.insert(12, 0xFF0000);
        colors.insert(14, 0xFF0000);
        let ranges = merge_ranges(&colors);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], (10, 12));
        assert_eq!(ranges[1], (14, 14));
    }

    #[test]
    fn test_default_service() {
        let svc = ColorizingServiceImpl::default();
        assert!(svc.all_colored_addresses().is_empty());
    }
}
