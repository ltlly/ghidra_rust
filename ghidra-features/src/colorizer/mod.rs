//! Colorizer Plugin -- colorize code units in the listing.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.colorizer` Java package.
//!
//! Provides model-level logic for applying color schemes to addresses
//! in the listing view, including heat-map coloring based on analysis
//! properties, color range navigation, recent color tracking, and a
//! colorizing service interface.
//!
//! # Key Types
//!
//! - [`ColorEntry`] -- an RGB color with foreground/background flag
//! - [`ColorizerMode`] -- the active colorization scheme
//! - [`ColorRange`] -- a contiguous range of addresses sharing a color
//! - [`ColorizingService`] -- trait for programmatic color management
//! - [`ColorizerModel`] -- the default in-memory colorizing service

use ghidra_core::Address;
use std::collections::HashMap;

/// Maximum number of recently used colors to track.
const MAX_RECENT_COLORS: usize = 16;

// ---------------------------------------------------------------------------
// ColorizerMode
// ---------------------------------------------------------------------------

/// The colorizer mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorizerMode {
    /// No colorization.
    #[default]
    None,
    /// Color by function.
    ByFunction,
    /// Color by instruction type.
    ByInstructionType,
    /// Color by register usage.
    ByRegister,
    /// Color by entropy/byte values.
    ByEntropy,
}

// ---------------------------------------------------------------------------
// ColorEntry
// ---------------------------------------------------------------------------

/// A color entry for an address.
///
/// Ported from `java.awt.Color` usage in `ColorizingService`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColorEntry {
    /// The color as RGB.
    pub r: u8,
    pub g: u8,
    pub b: u8,
    /// Whether this is foreground (text) or background color.
    pub is_foreground: bool,
}

impl ColorEntry {
    /// Create a new background color entry.
    pub fn new(r: u8, g: u8, b: u8) -> Self {
        Self {
            r,
            g,
            b,
            is_foreground: false,
        }
    }

    /// Create a new foreground color entry.
    pub fn foreground(r: u8, g: u8, b: u8) -> Self {
        Self {
            r,
            g,
            b,
            is_foreground: true,
        }
    }

    /// Common color: yellow.
    pub fn yellow() -> Self {
        Self::new(255, 255, 0)
    }

    /// Common color: red.
    pub fn red() -> Self {
        Self::new(255, 0, 0)
    }

    /// Common color: green.
    pub fn green() -> Self {
        Self::new(0, 200, 0)
    }

    /// Common color: blue.
    pub fn blue() -> Self {
        Self::new(0, 0, 255)
    }

    /// Common color: cyan.
    pub fn cyan() -> Self {
        Self::new(0, 255, 255)
    }

    /// Whether two colors are the same RGB value.
    pub fn rgb_equals(&self, other: &ColorEntry) -> bool {
        self.r == other.r && self.g == other.g && self.b == other.b
    }
}

// ---------------------------------------------------------------------------
// ColorRange -- contiguous colored region
// ---------------------------------------------------------------------------

/// A contiguous range of addresses that share the same color.
///
/// Ported from the color range navigation concept in `ColorizingPlugin`.
#[derive(Debug, Clone)]
pub struct ColorRange {
    /// Start address (inclusive).
    pub start: Address,
    /// End address (inclusive).
    pub end: Address,
    /// The color applied to this range.
    pub color: ColorEntry,
}

impl ColorRange {
    /// Create a new color range.
    pub fn new(start: Address, end: Address, color: ColorEntry) -> Self {
        Self { start, end, color }
    }

    /// The number of addresses in this range.
    pub fn size(&self) -> u64 {
        self.end.offset.saturating_sub(self.start.offset) + 1
    }

    /// Check whether this range contains the given address.
    pub fn contains(&self, address: Address) -> bool {
        address.offset >= self.start.offset && address.offset <= self.end.offset
    }
}

// ---------------------------------------------------------------------------
// ColorizingService -- trait for programmatic color management
// ---------------------------------------------------------------------------

/// Trait for colorizing service implementations.
///
/// Ported from `ghidra.app.plugin.core.colorizer.ColorizingService`.
pub trait ColorizingService {
    /// Set the background color for a single address.
    fn set_background_color(&mut self, address: Address, color: ColorEntry);

    /// Get the background color at a given address.
    fn get_background_color(&self, address: Address) -> Option<&ColorEntry>;

    /// Clear the background color at a given address.
    fn clear_background_color(&mut self, address: Address) -> bool;

    /// Clear all background colors.
    fn clear_all_colors(&mut self);

    /// Get the most recently used color.
    fn get_most_recent_color(&self) -> Option<&ColorEntry>;

    /// Get the list of recently used colors.
    fn get_recent_colors(&self) -> &[ColorEntry];

    /// Find the next color range starting at or after the given address.
    fn find_next_color_range(&self, from: Address) -> Option<ColorRange>;

    /// Find the previous color range starting at or before the given address.
    fn find_previous_color_range(&self, from: Address) -> Option<ColorRange>;

    /// Get the total number of colored addresses.
    fn colored_address_count(&self) -> usize;
}

// ---------------------------------------------------------------------------
// ColorizerModel -- in-memory colorizing service
// ---------------------------------------------------------------------------

/// Manages color assignments for the listing.
///
/// This is the default in-memory implementation of [`ColorizingService`].
#[derive(Debug, Default)]
pub struct ColorizerModel {
    mode: ColorizerMode,
    colors: HashMap<u64, ColorEntry>,
    recent_colors: Vec<ColorEntry>,
}

impl ColorizerModel {
    /// Create a new colorizer model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the colorizer mode.
    pub fn set_mode(&mut self, mode: ColorizerMode) {
        self.mode = mode;
    }

    /// Get the current mode.
    pub fn mode(&self) -> ColorizerMode {
        self.mode
    }

    /// Set the color for an address and track it as recently used.
    pub fn set_color(&mut self, address: Address, color: ColorEntry) {
        self.add_recent_color(color.clone());
        self.colors.insert(address.offset, color);
    }

    /// Get the color for an address.
    pub fn get_color(&self, address: Address) -> Option<&ColorEntry> {
        self.colors.get(&address.offset)
    }

    /// Remove the color for a specific address.
    pub fn remove_color(&mut self, address: Address) -> Option<ColorEntry> {
        self.colors.remove(&address.offset)
    }

    /// Clear all colors.
    pub fn clear(&mut self) {
        self.colors.clear();
    }

    /// Return the number of colored addresses.
    pub fn count(&self) -> usize {
        self.colors.len()
    }

    /// Get all colored addresses, sorted.
    pub fn colored_addresses(&self) -> Vec<Address> {
        let mut addrs: Vec<u64> = self.colors.keys().copied().collect();
        addrs.sort();
        addrs.into_iter().map(Address::new).collect()
    }

    /// Compute color ranges by merging adjacent addresses with the same color.
    pub fn compute_color_ranges(&self) -> Vec<ColorRange> {
        let mut sorted: Vec<(u64, &ColorEntry)> =
            self.colors.iter().map(|(&k, v)| (k, v)).collect();
        sorted.sort_by_key(|(k, _)| *k);

        let mut ranges = Vec::new();
        let mut iter = sorted.into_iter();
        if let Some((start_offset, first_color)) = iter.next() {
            let mut current_start = start_offset;
            let mut current_end = start_offset;
            let mut current_color = first_color;

            for (offset, color) in iter {
                if offset == current_end + 1 && color.rgb_equals(current_color) {
                    current_end = offset;
                } else {
                    ranges.push(ColorRange::new(
                        Address::new(current_start),
                        Address::new(current_end),
                        current_color.clone(),
                    ));
                    current_start = offset;
                    current_end = offset;
                    current_color = color;
                }
            }
            ranges.push(ColorRange::new(
                Address::new(current_start),
                Address::new(current_end),
                current_color.clone(),
            ));
        }
        ranges
    }

    fn add_recent_color(&mut self, color: ColorEntry) {
        self.recent_colors.retain(|c| !c.rgb_equals(&color));
        self.recent_colors.insert(0, color);
        if self.recent_colors.len() > MAX_RECENT_COLORS {
            self.recent_colors.truncate(MAX_RECENT_COLORS);
        }
    }
}

impl ColorizingService for ColorizerModel {
    fn set_background_color(&mut self, address: Address, color: ColorEntry) {
        self.set_color(address, color);
    }

    fn get_background_color(&self, address: Address) -> Option<&ColorEntry> {
        self.get_color(address)
    }

    fn clear_background_color(&mut self, address: Address) -> bool {
        self.remove_color(address).is_some()
    }

    fn clear_all_colors(&mut self) {
        self.clear();
    }

    fn get_most_recent_color(&self) -> Option<&ColorEntry> {
        self.recent_colors.first()
    }

    fn get_recent_colors(&self) -> &[ColorEntry] {
        &self.recent_colors
    }

    fn find_next_color_range(&self, from: Address) -> Option<ColorRange> {
        let ranges = self.compute_color_ranges();
        ranges
            .into_iter()
            .find(|r| r.end.offset >= from.offset)
            .filter(|r| r.start.offset >= from.offset || r.contains(from))
    }

    fn find_previous_color_range(&self, from: Address) -> Option<ColorRange> {
        let ranges = self.compute_color_ranges();
        ranges
            .into_iter()
            .rfind(|r| r.start.offset <= from.offset)
            .filter(|r| r.start.offset <= from.offset || r.contains(from))
    }

    fn colored_address_count(&self) -> usize {
        self.count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_colorizer_mode() {
        let mut model = ColorizerModel::new();
        assert_eq!(model.mode(), ColorizerMode::None);
        model.set_mode(ColorizerMode::ByFunction);
        assert_eq!(model.mode(), ColorizerMode::ByFunction);
    }

    #[test]
    fn test_set_and_get_color() {
        let mut model = ColorizerModel::new();
        model.set_color(Address::new(0x1000), ColorEntry::new(255, 0, 0));
        let color = model.get_color(Address::new(0x1000)).unwrap();
        assert_eq!(color.r, 255);
    }

    #[test]
    fn test_color_entry_presets() {
        let y = ColorEntry::yellow();
        assert_eq!(y.r, 255);
        assert_eq!(y.g, 255);
        assert_eq!(y.b, 0);
        assert!(!y.is_foreground);

        let fg = ColorEntry::foreground(128, 128, 128);
        assert!(fg.is_foreground);
    }

    #[test]
    fn test_rgb_equals() {
        let a = ColorEntry::new(10, 20, 30);
        let b = ColorEntry::new(10, 20, 30);
        let c = ColorEntry::new(10, 20, 31);
        assert!(a.rgb_equals(&b));
        assert!(!a.rgb_equals(&c));
    }

    #[test]
    fn test_remove_color() {
        let mut model = ColorizerModel::new();
        model.set_color(Address::new(0x1000), ColorEntry::red());
        assert!(model.remove_color(Address::new(0x1000)).is_some());
        assert!(model.get_color(Address::new(0x1000)).is_none());
    }

    #[test]
    fn test_colored_addresses_sorted() {
        let mut model = ColorizerModel::new();
        model.set_color(Address::new(0x3000), ColorEntry::red());
        model.set_color(Address::new(0x1000), ColorEntry::blue());
        model.set_color(Address::new(0x2000), ColorEntry::green());
        let addrs = model.colored_addresses();
        assert_eq!(addrs, vec![Address::new(0x1000), Address::new(0x2000), Address::new(0x3000)]);
    }

    #[test]
    fn test_compute_color_ranges_merge() {
        let mut model = ColorizerModel::new();
        let red = ColorEntry::red();
        model.set_color(Address::new(0x1000), red.clone());
        model.set_color(Address::new(0x1001), red.clone());
        model.set_color(Address::new(0x1002), red.clone());
        model.set_color(Address::new(0x2000), ColorEntry::blue());
        let ranges = model.compute_color_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start.offset, 0x1000);
        assert_eq!(ranges[0].end.offset, 0x1002);
        assert_eq!(ranges[0].size(), 3);
        assert_eq!(ranges[1].start.offset, 0x2000);
    }

    #[test]
    fn test_compute_color_ranges_no_merge_different_color() {
        let mut model = ColorizerModel::new();
        model.set_color(Address::new(0x1000), ColorEntry::red());
        model.set_color(Address::new(0x1001), ColorEntry::blue());
        let ranges = model.compute_color_ranges();
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn test_color_range_contains() {
        let range = ColorRange::new(Address::new(0x1000), Address::new(0x100F), ColorEntry::red());
        assert!(range.contains(Address::new(0x1005)));
        assert!(!range.contains(Address::new(0x2000)));
        assert_eq!(range.size(), 16);
    }

    #[test]
    fn test_recent_colors() {
        let mut model = ColorizerModel::new();
        model.set_color(Address::new(0x1000), ColorEntry::red());
        model.set_color(Address::new(0x2000), ColorEntry::blue());
        model.set_color(Address::new(0x3000), ColorEntry::red());
        assert_eq!(model.get_most_recent_color().unwrap().r, 255);
        assert_eq!(model.get_most_recent_color().unwrap().b, 0);
        assert_eq!(model.get_recent_colors().len(), 2);
    }

    #[test]
    fn test_find_next_color_range() {
        let mut model = ColorizerModel::new();
        model.set_color(Address::new(0x1000), ColorEntry::red());
        model.set_color(Address::new(0x1001), ColorEntry::red());
        model.set_color(Address::new(0x2000), ColorEntry::blue());
        let next = model.find_next_color_range(Address::new(0x1000)).unwrap();
        assert_eq!(next.start.offset, 0x1000);
    }

    #[test]
    fn test_find_previous_color_range() {
        let mut model = ColorizerModel::new();
        model.set_color(Address::new(0x1000), ColorEntry::red());
        model.set_color(Address::new(0x2000), ColorEntry::blue());
        let prev = model.find_previous_color_range(Address::new(0x2000)).unwrap();
        assert_eq!(prev.start.offset, 0x2000);
    }

    #[test]
    fn test_service_trait() {
        let mut model = ColorizerModel::new();
        ColorizingService::set_background_color(&mut model, Address::new(0x1000), ColorEntry::green());
        assert!(ColorizingService::get_background_color(&model, Address::new(0x1000)).is_some());
        assert!(ColorizingService::clear_background_color(&mut model, Address::new(0x1000)));
        assert!(ColorizingService::get_background_color(&model, Address::new(0x1000)).is_none());
    }
}
