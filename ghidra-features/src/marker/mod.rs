//! Marker management -- marker sets, manager, and rendering support.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.marker` Java package.
//!
//! Markers are visual annotations shown in the listing margin and overview
//! bar. They indicate the location of bookmarks, search results, analysis
//! warnings, and other important addresses in a program.
//!
//! # Architecture
//!
//! - [`MarkerSet`] -- a single named, prioritized set of markers.
//! - [`AreaMarkerSet`] -- marks contiguous address ranges.
//! - [`PointMarkerSet`] -- marks individual addresses.
//! - [`MarkerManager`] -- manages all marker sets for a program.
//! - [`MarkerPanel`] -- model for rendering markers in the UI.

/// Marker plugin, overview provider, margin provider, and navigation.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.marker` Java package.
pub mod plugin;

/// Marker Manager Plugin -- the main plugin orchestrating marker services.
///
/// Ported from `ghidra.app.plugin.core.marker.MarkerManagerPlugin`.
pub mod marker_plugin;

/// Marker providers -- margin and overview rendering.
///
/// Ported from `ghidra.app.plugin.core.marker.MarkerMarginProvider` and
/// `ghidra.app.plugin.core.marker.MarkerOverviewProvider`.
pub mod marker_provider;

use std::collections::{BTreeMap, BTreeSet, HashMap};

// ============================================================================
// MarkerType -- distinguishes area vs. point markers
// ============================================================================

/// Whether a marker set covers areas or individual points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerType {
    /// Marks contiguous address ranges.
    Area,
    /// Marks individual addresses.
    Point,
}

// ============================================================================
// RgbColor -- simple color representation
// ============================================================================

/// An RGBA color, used for marker display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RgbColor {
    /// Red channel (0-255).
    pub r: u8,
    /// Green channel (0-255).
    pub g: u8,
    /// Blue channel (0-255).
    pub b: u8,
    /// Alpha channel (0-255).
    pub a: u8,
}

impl RgbColor {
    /// Create a new RGBA color.
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Create a fully opaque color.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// Standard red.
    pub const RED: Self = Self::rgb(255, 0, 0);
    /// Standard green.
    pub const GREEN: Self = Self::rgb(0, 255, 0);
    /// Standard blue.
    pub const BLUE: Self = Self::rgb(0, 0, 255);
    /// Standard yellow.
    pub const YELLOW: Self = Self::rgb(255, 255, 0);
    /// Standard orange.
    pub const ORANGE: Self = Self::rgb(255, 165, 0);
    /// Standard magenta.
    pub const MAGENTA: Self = Self::rgb(255, 0, 255);
    /// Standard cyan.
    pub const CYAN: Self = Self::rgb(0, 255, 255);

    /// Blend two colors (simple 50/50 average).
    pub fn blend(a: &RgbColor, b: &RgbColor) -> Self {
        Self {
            r: ((a.r as u16 + b.r as u16) / 2) as u8,
            g: ((a.g as u16 + b.g as u16) / 2) as u8,
            b: ((a.b as u16 + b.b as u16) / 2) as u8,
            a: ((a.a as u16 + b.a as u16) / 2) as u8,
        }
    }
}

impl std::fmt::Display for RgbColor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{:02X}{:02X}{:02X}", self.r, self.g, self.b)
    }
}

// ============================================================================
// MarkerSet -- a single named set of markers
// ============================================================================

/// Trait representing a set of markers with a common name and priority.
///
/// Mirrors Ghidra's `MarkerSet` / `MarkerSetImpl` classes.
pub trait MarkerSet: Send + Sync + std::fmt::Debug {
    /// The name of this marker set.
    fn name(&self) -> &str;

    /// Description of this marker set.
    fn description(&self) -> &str;

    /// Priority (higher numbers render on top).
    fn priority(&self) -> i32;

    /// Whether markers should be shown in the margin.
    fn show_markers(&self) -> bool;

    /// Whether markers should be shown in the overview bar.
    fn show_navigation(&self) -> bool;

    /// Whether to color the background of marked addresses.
    fn color_background(&self) -> bool;

    /// The marker color.
    fn marker_color(&self) -> RgbColor;

    /// Whether this marker set is active (visible).
    fn is_active(&self) -> bool;

    /// Set the active state.
    fn set_active(&mut self, active: bool);

    /// Whether this marker set has the preferred display flag.
    fn is_preferred(&self) -> bool;

    /// Check whether a given address is contained.
    fn contains(&self, address: u64) -> bool;

    /// Return all addresses in this set.
    fn addresses(&self) -> Vec<u64>;

    /// The number of markers.
    fn count(&self) -> usize;

    /// Whether this set is empty.
    fn is_empty(&self) -> bool {
        self.count() == 0
    }
}

// ============================================================================
// AreaMarkerSetImpl -- contiguous address ranges
// ============================================================================

/// An area marker set covering address ranges.
#[derive(Debug, Clone)]
pub struct AreaMarkerSetImpl {
    name: String,
    description: String,
    priority: i32,
    show_markers: bool,
    show_navigation: bool,
    color_background: bool,
    color: RgbColor,
    active: bool,
    preferred: bool,
    /// Sorted set of (start, end) ranges.
    ranges: BTreeMap<u64, u64>,
}

impl AreaMarkerSetImpl {
    /// Create a new area marker set.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        priority: i32,
        color: RgbColor,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            priority,
            show_markers: true,
            show_navigation: true,
            color_background: false,
            color,
            active: true,
            preferred: true,
            ranges: BTreeMap::new(),
        }
    }

    /// Set whether markers are shown.
    pub fn with_show_markers(mut self, show: bool) -> Self {
        self.show_markers = show;
        self
    }

    /// Set whether navigation bar markers are shown.
    pub fn with_show_navigation(mut self, show: bool) -> Self {
        self.show_navigation = show;
        self
    }

    /// Set whether to color the background.
    pub fn with_color_background(mut self, color_bg: bool) -> Self {
        self.color_background = color_bg;
        self
    }

    /// Set preferred flag.
    pub fn with_preferred(mut self, preferred: bool) -> Self {
        self.preferred = preferred;
        self
    }

    /// Add an address range to this marker set.
    pub fn add_range(&mut self, start: u64, end: u64) {
        if start > end {
            return;
        }
        // Merge overlapping ranges
        let mut new_start = start;
        let mut new_end = end;
        let mut to_remove = Vec::new();

        for (&r_start, &r_end) in &self.ranges {
            if r_start <= new_end + 1 && r_end + 1 >= new_start {
                new_start = new_start.min(r_start);
                new_end = new_end.max(r_end);
                to_remove.push(r_start);
            }
        }
        for k in to_remove {
            self.ranges.remove(&k);
        }
        self.ranges.insert(new_start, new_end);
    }

    /// Remove an address range from this marker set.
    pub fn remove_range(&mut self, start: u64, end: u64) {
        let mut to_insert = Vec::new();
        let mut to_remove = Vec::new();

        for (&r_start, &r_end) in &self.ranges {
            if r_start > end || r_end < start {
                continue;
            }
            to_remove.push(r_start);
            if r_start < start {
                to_insert.push((r_start, start - 1));
            }
            if r_end > end {
                to_insert.push((end + 1, r_end));
            }
        }
        for k in to_remove {
            self.ranges.remove(&k);
        }
        for (s, e) in to_insert {
            self.ranges.insert(s, e);
        }
    }

    /// Get all ranges as (start, end) pairs.
    pub fn get_ranges(&self) -> Vec<(u64, u64)> {
        self.ranges.iter().map(|(&s, &e)| (s, e)).collect()
    }
}

impl MarkerSet for AreaMarkerSetImpl {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn priority(&self) -> i32 {
        self.priority
    }

    fn show_markers(&self) -> bool {
        self.show_markers
    }

    fn show_navigation(&self) -> bool {
        self.show_navigation
    }

    fn color_background(&self) -> bool {
        self.color_background
    }

    fn marker_color(&self) -> RgbColor {
        self.color
    }

    fn is_active(&self) -> bool {
        self.active
    }

    fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    fn is_preferred(&self) -> bool {
        self.preferred
    }

    fn contains(&self, address: u64) -> bool {
        self.ranges
            .range(..=address)
            .next_back()
            .map_or(false, |(_, &end)| address <= end)
    }

    fn addresses(&self) -> Vec<u64> {
        let mut addrs = Vec::new();
        for (&start, &end) in &self.ranges {
            addrs.extend(start..=end);
        }
        addrs
    }

    fn count(&self) -> usize {
        self.ranges.iter().map(|(&s, &e)| (e - s + 1) as usize).sum()
    }
}

// ============================================================================
// PointMarkerSetImpl -- individual address markers
// ============================================================================

/// A point marker set for individual addresses.
#[derive(Debug, Clone)]
pub struct PointMarkerSetImpl {
    name: String,
    description: String,
    priority: i32,
    show_markers: bool,
    show_navigation: bool,
    color_background: bool,
    color: RgbColor,
    active: bool,
    preferred: bool,
    addresses: BTreeSet<u64>,
}

impl PointMarkerSetImpl {
    /// Create a new point marker set.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        priority: i32,
        color: RgbColor,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            priority,
            show_markers: true,
            show_navigation: true,
            color_background: false,
            color,
            active: true,
            preferred: true,
            addresses: BTreeSet::new(),
        }
    }

    /// Set whether markers are shown.
    pub fn with_show_markers(mut self, show: bool) -> Self {
        self.show_markers = show;
        self
    }

    /// Set whether navigation bar markers are shown.
    pub fn with_show_navigation(mut self, show: bool) -> Self {
        self.show_navigation = show;
        self
    }

    /// Set whether to color the background.
    pub fn with_color_background(mut self, color_bg: bool) -> Self {
        self.color_background = color_bg;
        self
    }

    /// Set preferred flag.
    pub fn with_preferred(mut self, preferred: bool) -> Self {
        self.preferred = preferred;
        self
    }

    /// Add an address to this marker set.
    pub fn add(&mut self, address: u64) {
        self.addresses.insert(address);
    }

    /// Remove an address from this marker set.
    pub fn remove(&mut self, address: u64) {
        self.addresses.remove(&address);
    }

    /// Add multiple addresses.
    pub fn add_all(&mut self, addresses: impl IntoIterator<Item = u64>) {
        for addr in addresses {
            self.addresses.insert(addr);
        }
    }

    /// Get addresses in a given range.
    pub fn addresses_in_range(&self, start: u64, end: u64) -> Vec<u64> {
        self.addresses
            .range(start..=end)
            .copied()
            .collect()
    }
}

impl MarkerSet for PointMarkerSetImpl {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn priority(&self) -> i32 {
        self.priority
    }

    fn show_markers(&self) -> bool {
        self.show_markers
    }

    fn show_navigation(&self) -> bool {
        self.show_navigation
    }

    fn color_background(&self) -> bool {
        self.color_background
    }

    fn marker_color(&self) -> RgbColor {
        self.color
    }

    fn is_active(&self) -> bool {
        self.active
    }

    fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    fn is_preferred(&self) -> bool {
        self.preferred
    }

    fn contains(&self, address: u64) -> bool {
        self.addresses.contains(&address)
    }

    fn addresses(&self) -> Vec<u64> {
        self.addresses.iter().copied().collect()
    }

    fn count(&self) -> usize {
        self.addresses.len()
    }
}

// ============================================================================
// MarkerManager -- manages all marker sets for a program
// ============================================================================

/// Manages all marker sets for a single program.
///
/// Marker sets are organized by name for retrieval and by group for
/// display-layer management.
#[derive(Debug, Default)]
pub struct MarkerManager {
    /// Marker sets indexed by name.
    sets: HashMap<String, Vec<Box<dyn MarkerSet>>>,
    /// Group assignments: group_name -> set_name.
    groups: HashMap<String, String>,
    /// Marker change listeners (notified when sets change).
    dirty: bool,
}

impl MarkerManager {
    /// Create a new empty marker manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a marker set.
    pub fn add_marker_set(&mut self, set: Box<dyn MarkerSet>) {
        let name = set.name().to_string();
        self.sets.entry(name).or_default().push(set);
        self.dirty = true;
    }

    /// Get all marker sets with the given name.
    pub fn get_marker_sets(&self, name: &str) -> Vec<&dyn MarkerSet> {
        self.sets
            .get(name)
            .map(|v| v.iter().map(|b| b.as_ref()).collect())
            .unwrap_or_default()
    }

    /// Remove all marker sets with the given name.
    pub fn remove_marker_sets(&mut self, name: &str) {
        self.sets.remove(name);
        self.dirty = true;
    }

    /// Remove a specific marker set by index within its name group.
    pub fn remove_marker_set(&mut self, name: &str, index: usize) -> bool {
        if let Some(sets) = self.sets.get_mut(name) {
            if index < sets.len() {
                sets.remove(index);
                if sets.is_empty() {
                    self.sets.remove(name);
                }
                self.dirty = true;
                return true;
            }
        }
        false
    }

    /// Assign a marker set to a named group (e.g. "Errors", "Bookmarks").
    /// Only one marker set per group can be active at a time.
    pub fn set_marker_for_group(&mut self, group_name: &str, set_name: &str) {
        self.groups
            .insert(group_name.to_string(), set_name.to_string());
        self.dirty = true;
    }

    /// Get the active marker set name for a group.
    pub fn get_marker_for_group(&self, group_name: &str) -> Option<&str> {
        self.groups.get(group_name).map(|s| s.as_str())
    }

    /// Remove a group assignment.
    pub fn remove_marker_for_group(&mut self, group_name: &str) {
        self.groups.remove(group_name);
        self.dirty = true;
    }

    /// Get the blended background color at a given address, considering
    /// all active marker sets that color backgrounds.
    pub fn get_background_color(&self, address: u64) -> Option<RgbColor> {
        let mut color: Option<RgbColor> = None;
        for sets in self.sets.values() {
            for set in sets {
                if set.is_active() && set.color_background() && set.contains(address) {
                    color = match color {
                        None => Some(set.marker_color()),
                        Some(existing) => Some(RgbColor::blend(&existing, &set.marker_color())),
                    };
                }
            }
        }
        color
    }

    /// Get the highest-priority active marker set at the given address.
    pub fn get_marker_at(&self, address: u64) -> Option<&dyn MarkerSet> {
        let mut best: Option<&dyn MarkerSet> = None;
        for sets in self.sets.values() {
            for set in sets {
                if set.is_active() && set.contains(address) {
                    if best.is_none() || set.priority() > best.unwrap().priority() {
                        best = Some(set.as_ref());
                    }
                }
            }
        }
        best
    }

    /// Get all marker sets as a flat list.
    pub fn all_marker_sets(&self) -> Vec<&dyn MarkerSet> {
        self.sets
            .values()
            .flat_map(|v| v.iter().map(|b| b.as_ref()))
            .collect()
    }

    /// The total number of registered marker sets.
    pub fn marker_set_count(&self) -> usize {
        self.sets.values().map(|v| v.len()).sum()
    }

    /// Clear all marker sets.
    pub fn clear(&mut self) {
        self.sets.clear();
        self.groups.clear();
        self.dirty = true;
    }

    /// Whether the marker manager has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark changes as acknowledged.
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// Get all tooltip lines for markers at the given address.
    pub fn get_tooltip_lines(&self, address: u64) -> Vec<String> {
        let mut lines = Vec::new();
        for sets in self.sets.values() {
            for set in sets {
                if set.is_active() && set.contains(address) {
                    lines.push(format!("{}: {}", set.name(), set.description()));
                }
            }
        }
        lines
    }
}

// ============================================================================
// MarkerPanel -- rendering model for a marker margin/overview
// ============================================================================

/// Configuration for rendering markers in a panel (margin or overview).
#[derive(Debug, Clone)]
pub struct MarkerPanel {
    /// Width of the panel in pixels.
    pub width: u32,
    /// Height of the panel in pixels.
    pub height: u32,
    /// The rendered pixel data (RGBA).
    pixels: Vec<u8>,
}

impl MarkerPanel {
    /// Create a new marker panel with the given dimensions.
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            pixels: vec![0; (width * height * 4) as usize],
        }
    }

    /// Clear the panel to the given background color.
    pub fn clear(&mut self, color: RgbColor) {
        for chunk in self.pixels.chunks_exact_mut(4) {
            chunk[0] = color.r;
            chunk[1] = color.g;
            chunk[2] = color.b;
            chunk[3] = color.a;
        }
    }

    /// Draw a filled rectangle.
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: RgbColor) {
        for row in y..(y + h).min(self.height) {
            for col in x..(x + w).min(self.width) {
                let idx = ((row * self.width + col) * 4) as usize;
                if idx + 3 < self.pixels.len() {
                    self.pixels[idx] = color.r;
                    self.pixels[idx + 1] = color.g;
                    self.pixels[idx + 2] = color.b;
                    self.pixels[idx + 3] = color.a;
                }
            }
        }
    }

    /// Get the raw pixel data.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    /// Get mutable pixel data.
    pub fn pixels_mut(&mut self) -> &mut [u8] {
        &mut self.pixels
    }

    /// Total pixel count.
    pub fn pixel_count(&self) -> usize {
        (self.width * self.height) as usize
    }
}

// ============================================================================
// MarkerSetCache -- per-program cache of marker sets
// ============================================================================

/// A cache of marker sets organized by priority.
#[derive(Debug, Default)]
pub struct MarkerSetCache {
    entries: Vec<Box<dyn MarkerSet>>,
}

impl MarkerSetCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a marker set, maintaining priority order.
    pub fn insert(&mut self, set: Box<dyn MarkerSet>) {
        let priority = set.priority();
        let pos = self
            .entries
            .binary_search_by_key(&priority, |s| s.priority())
            .unwrap_or_else(|p| p);
        self.entries.insert(pos, set);
    }

    /// Find a marker set by name.
    pub fn get_by_name(&self, name: &str) -> Option<&dyn MarkerSet> {
        self.entries
            .iter()
            .find(|s| s.name() == name)
            .map(|b| b.as_ref())
    }

    /// Remove a marker set by name.
    pub fn remove_by_name(&mut self, name: &str) -> bool {
        if let Some(pos) = self.entries.iter().position(|s| s.name() == name) {
            self.entries.remove(pos);
            return true;
        }
        false
    }

    /// Get the background color at a given address from all active
    /// marker sets that color backgrounds.
    pub fn get_background_color(&self, address: u64) -> Option<RgbColor> {
        let mut color: Option<RgbColor> = None;
        for set in &self.entries {
            if set.is_active() && set.color_background() && set.contains(address) {
                color = match color {
                    None => Some(set.marker_color()),
                    Some(existing) => Some(RgbColor::blend(&existing, &set.marker_color())),
                };
            }
        }
        color
    }

    /// Get tooltip lines at a given address.
    pub fn get_tooltip_lines(&self, address: u64) -> Vec<String> {
        let mut lines = Vec::new();
        for set in self.entries.iter().rev() {
            if set.is_active() && set.contains(address) {
                lines.push(format!("{}: {}", set.name(), set.description()));
                if lines.len() >= 10 {
                    lines.push("...".to_string());
                    break;
                }
            }
        }
        lines
    }

    /// The number of marker sets in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get the highest-priority marker set containing the given address.
    pub fn get_marker_set_at(&self, address: u64) -> Option<&dyn MarkerSet> {
        self.entries
            .iter()
            .rev()
            .find(|s| s.is_active() && s.contains(address))
            .map(|b| b.as_ref())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rgb_color() {
        let c = RgbColor::rgb(255, 128, 0);
        assert_eq!(c.r, 255);
        assert_eq!(c.g, 128);
        assert_eq!(c.b, 0);
        assert_eq!(c.a, 255);
        assert_eq!(c.to_string(), "#FF8000");
    }

    #[test]
    fn test_rgb_color_blend() {
        let c = RgbColor::blend(&RgbColor::RED, &RgbColor::BLUE);
        assert_eq!(c.r, 127);
        assert_eq!(c.g, 0);
        assert_eq!(c.b, 127);
    }

    #[test]
    fn test_area_marker_set() {
        let mut set = AreaMarkerSetImpl::new("Test", "Test area markers", 5, RgbColor::RED);
        set.add_range(0x1000, 0x10FF);
        assert!(set.contains(0x1000));
        assert!(set.contains(0x1080));
        assert!(set.contains(0x10FF));
        assert!(!set.contains(0x1100));
        assert!(!set.contains(0x0FFF));
        assert_eq!(set.count(), 0x100);
    }

    #[test]
    fn test_area_marker_merge() {
        let mut set = AreaMarkerSetImpl::new("Test", "", 1, RgbColor::RED);
        set.add_range(0x1000, 0x1010);
        set.add_range(0x1008, 0x1020); // Overlapping
        assert_eq!(set.get_ranges().len(), 1);
        assert_eq!(set.get_ranges()[0], (0x1000, 0x1020));
    }

    #[test]
    fn test_area_marker_merge_adjacent() {
        let mut set = AreaMarkerSetImpl::new("Test", "", 1, RgbColor::RED);
        set.add_range(0x1000, 0x1010);
        set.add_range(0x1011, 0x1020); // Adjacent
        assert_eq!(set.get_ranges().len(), 1);
        assert_eq!(set.get_ranges()[0], (0x1000, 0x1020));
    }

    #[test]
    fn test_area_marker_remove_range() {
        let mut set = AreaMarkerSetImpl::new("Test", "", 1, RgbColor::RED);
        set.add_range(0x1000, 0x10FF);
        set.remove_range(0x1080, 0x108F);
        let ranges = set.get_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], (0x1000, 0x107F));
        assert_eq!(ranges[1], (0x1090, 0x10FF));
        assert!(!set.contains(0x1085));
        assert!(set.contains(0x107F));
        assert!(set.contains(0x1090));
    }

    #[test]
    fn test_point_marker_set() {
        let mut set = PointMarkerSetImpl::new("Test", "Point markers", 5, RgbColor::GREEN);
        set.add(0x1000);
        set.add(0x2000);
        set.add(0x3000);
        assert!(set.contains(0x1000));
        assert!(!set.contains(0x1500));
        assert_eq!(set.count(), 3);

        set.remove(0x2000);
        assert!(!set.contains(0x2000));
        assert_eq!(set.count(), 2);
    }

    #[test]
    fn test_point_marker_range() {
        let mut set = PointMarkerSetImpl::new("Test", "", 1, RgbColor::BLUE);
        set.add_all(vec![0x100, 0x200, 0x300, 0x400, 0x500]);
        let in_range = set.addresses_in_range(0x150, 0x350);
        assert_eq!(in_range, vec![0x200, 0x300]);
    }

    #[test]
    fn test_marker_manager() {
        let mut mgr = MarkerManager::new();
        assert_eq!(mgr.marker_set_count(), 0);

        let area = AreaMarkerSetImpl::new("Errors", "Error markers", 10, RgbColor::RED);
        mgr.add_marker_set(Box::new(area));

        let point = PointMarkerSetImpl::new("Bookmarks", "User bookmarks", 5, RgbColor::GREEN);
        mgr.add_marker_set(Box::new(point));

        assert_eq!(mgr.marker_set_count(), 2);
        assert!(mgr.get_marker_sets("Errors").len() == 1);
        assert!(mgr.get_marker_sets("Bookmarks").len() == 1);
    }

    #[test]
    fn test_marker_manager_background_color() {
        let mut mgr = MarkerManager::new();
        let mut area = AreaMarkerSetImpl::new("Warnings", "", 5, RgbColor::YELLOW);
        area = area.with_color_background(true);
        area.add_range(0x1000, 0x10FF);

        // Need to add_range via mutation after construction
        let mut area2 = AreaMarkerSetImpl::new("Warnings2", "", 5, RgbColor::YELLOW)
            .with_color_background(true);
        area2.add_range(0x1000, 0x10FF);
        mgr.add_marker_set(Box::new(area2));

        let color = mgr.get_background_color(0x1050);
        assert!(color.is_some());

        let no_color = mgr.get_background_color(0x2000);
        assert!(no_color.is_none());
    }

    #[test]
    fn test_marker_manager_groups() {
        let mut mgr = MarkerManager::new();
        mgr.set_marker_for_group("Errors", "ErrorMarkers");
        assert_eq!(mgr.get_marker_for_group("Errors"), Some("ErrorMarkers"));
        mgr.remove_marker_for_group("Errors");
        assert!(mgr.get_marker_for_group("Errors").is_none());
    }

    #[test]
    fn test_marker_manager_tooltip() {
        let mut mgr = MarkerManager::new();
        let area = AreaMarkerSetImpl::new("Search Results", "Found 3 matches", 5, RgbColor::CYAN);
        mgr.add_marker_set(Box::new(area));
        // We can't directly call add_range on the boxed set, but we can test tooltip structure
        let tips = mgr.get_tooltip_lines(0x1000);
        // Empty because the default area set has no ranges
        assert!(tips.is_empty());
    }

    #[test]
    fn test_marker_set_cache() {
        let mut cache = MarkerSetCache::new();
        assert!(cache.is_empty());

        let area = AreaMarkerSetImpl::new("Errors", "Error set", 10, RgbColor::RED);
        cache.insert(Box::new(area));

        let point = PointMarkerSetImpl::new("Bookmarks", "Bookmarks", 5, RgbColor::GREEN);
        cache.insert(Box::new(point));

        assert_eq!(cache.len(), 2);
        assert!(cache.get_by_name("Errors").is_some());
        assert!(cache.get_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_marker_panel() {
        let mut panel = MarkerPanel::new(100, 50);
        assert_eq!(panel.pixel_count(), 5000);
        panel.clear(RgbColor::rgb(32, 32, 32));
        let px = panel.pixels();
        assert_eq!(px[0], 32);
        assert_eq!(px[1], 32);
        assert_eq!(px[2], 32);
    }

    #[test]
    fn test_marker_panel_fill_rect() {
        let mut panel = MarkerPanel::new(10, 10);
        panel.clear(RgbColor::rgb(0, 0, 0));
        panel.fill_rect(2, 2, 3, 3, RgbColor::RED);
        // Check pixel at (2, 2)
        let idx = (2 * 10 + 2) * 4;
        assert_eq!(panel.pixels()[idx], 255);
        assert_eq!(panel.pixels()[idx + 1], 0);
        // Check pixel at (1, 1) is still black
        let idx2 = (1 * 10 + 1) * 4;
        assert_eq!(panel.pixels()[idx2], 0);
    }

    #[test]
    fn test_area_marker_set_builder() {
        let set = AreaMarkerSetImpl::new("Test", "desc", 1, RgbColor::RED)
            .with_show_markers(false)
            .with_show_navigation(true)
            .with_color_background(true)
            .with_preferred(false);
        assert!(!set.show_markers());
        assert!(set.show_navigation());
        assert!(set.color_background());
        assert!(!set.is_preferred());
    }

    #[test]
    fn test_point_marker_set_builder() {
        let set = PointMarkerSetImpl::new("Test", "desc", 1, RgbColor::BLUE)
            .with_show_markers(false)
            .with_color_background(true)
            .with_preferred(false);
        assert!(!set.show_markers());
        assert!(set.color_background());
        assert!(!set.is_preferred());
    }

    #[test]
    fn test_marker_type_enum() {
        assert_ne!(MarkerType::Area, MarkerType::Point);
    }

    #[test]
    fn test_marker_set_active_toggle() {
        let mut set = PointMarkerSetImpl::new("Test", "", 1, RgbColor::RED);
        assert!(set.is_active());
        set.set_active(false);
        assert!(!set.is_active());
        set.set_active(true);
        assert!(set.is_active());
    }

    #[test]
    fn test_marker_manager_remove() {
        let mut mgr = MarkerManager::new();
        let area = AreaMarkerSetImpl::new("Test", "", 1, RgbColor::RED);
        mgr.add_marker_set(Box::new(area));
        assert_eq!(mgr.marker_set_count(), 1);
        mgr.remove_marker_sets("Test");
        assert_eq!(mgr.marker_set_count(), 0);
    }

    #[test]
    fn test_marker_manager_clear() {
        let mut mgr = MarkerManager::new();
        mgr.add_marker_set(Box::new(AreaMarkerSetImpl::new("A", "", 1, RgbColor::RED)));
        mgr.add_marker_set(Box::new(PointMarkerSetImpl::new("B", "", 2, RgbColor::GREEN)));
        mgr.set_marker_for_group("G", "A");
        assert_eq!(mgr.marker_set_count(), 2);
        mgr.clear();
        assert_eq!(mgr.marker_set_count(), 0);
    }

    #[test]
    fn test_modifiable_address_set_collection() {
        let mut coll = ModifiableAddressSetCollection::new();
        coll.add_range(0x1000, 0x10FF);
        coll.add_range(0x2000, 0x20FF);
        assert_eq!(coll.range_count(), 2);
        assert!(coll.contains(0x1050));
        assert!(coll.contains(0x2050));
        assert!(!coll.contains(0x3000));
    }

    #[test]
    fn test_modifiable_address_set_collection_remove() {
        let mut coll = ModifiableAddressSetCollection::new();
        coll.add_range(0x1000, 0x10FF);
        coll.remove_range(0x1050, 0x10AF);
        assert!(coll.contains(0x1040));
        assert!(!coll.contains(0x1070));
        assert!(coll.contains(0x10B0));
    }

    #[test]
    fn test_modifiable_address_set_collection_intersect() {
        let mut coll = ModifiableAddressSetCollection::new();
        coll.add_range(0x1000, 0x10FF);
        let intersected = coll.intersects_range(0x1050, 0x10AF);
        assert!(intersected);

        let not_intersected = coll.intersects_range(0x2000, 0x20FF);
        assert!(!not_intersected);
    }

    #[test]
    fn test_modifiable_address_set_collection_clear() {
        let mut coll = ModifiableAddressSetCollection::new();
        coll.add_range(0x1000, 0x10FF);
        coll.add_range(0x2000, 0x20FF);
        coll.clear();
        assert_eq!(coll.range_count(), 0);
        assert!(!coll.contains(0x1050));
    }

    #[test]
    fn test_modifiable_address_set_collection_num_addresses() {
        let mut coll = ModifiableAddressSetCollection::new();
        coll.add_range(0x1000, 0x100F);
        assert_eq!(coll.num_addresses(), 16);
    }

    #[test]
    fn test_marker_manager_get_marker_sets() {
        let mut mgr = MarkerManager::new();
        mgr.add_marker_set(Box::new(AreaMarkerSetImpl::new("Bookmarks", "", 5, RgbColor::BLUE)));
        mgr.add_marker_set(Box::new(AreaMarkerSetImpl::new("Errors", "", 10, RgbColor::RED)));
        let bookmarks = mgr.get_marker_sets("Bookmarks");
        assert_eq!(bookmarks.len(), 1);
    }

    #[test]
    fn test_marker_manager_priority_ordering() {
        let mut mgr = MarkerManager::new();
        let mut low = AreaMarkerSetImpl::new("Low", "", 1, RgbColor::GREEN);
        low.add_range(0x1000, 0x1000);
        let mut high = AreaMarkerSetImpl::new("High", "", 10, RgbColor::RED);
        high.add_range(0x1000, 0x1000);
        mgr.add_marker_set(Box::new(low));
        mgr.add_marker_set(Box::new(high));
        let marker = mgr.get_marker_at(0x1000);
        assert!(marker.is_some());
        assert_eq!(marker.unwrap().name(), "High");
    }
}

// ---------------------------------------------------------------------------
// ModifiableAddressSetCollection -- ported from ModifiableAddressSetCollection.java
// ---------------------------------------------------------------------------

/// A collection of address ranges that can be modified.
///
/// Ported from Ghidra's `ModifiableAddressSetCollection.java`.
/// Used by marker sets to track which addresses contain markers.
#[derive(Debug, Clone, Default)]
pub struct ModifiableAddressSetCollection {
    /// Sorted address ranges (start, end) inclusive.
    ranges: Vec<(u64, u64)>,
}

impl ModifiableAddressSetCollection {
    /// Create a new empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an address range [start, end] inclusive.
    pub fn add_range(&mut self, start: u64, end: u64) {
        if start > end {
            return;
        }
        self.ranges.push((start, end));
        self.normalize();
    }

    /// Remove an address range [start, end] inclusive.
    pub fn remove_range(&mut self, start: u64, end: u64) {
        if start > end {
            return;
        }
        let mut new_ranges = Vec::new();
        for &(rs, re) in &self.ranges {
            if re < start || rs > end {
                // No overlap
                new_ranges.push((rs, re));
            } else {
                // Overlap -- split if needed
                if rs < start {
                    new_ranges.push((rs, start - 1));
                }
                if re > end {
                    new_ranges.push((end + 1, re));
                }
            }
        }
        self.ranges = new_ranges;
    }

    /// Check if a given address is contained in any range.
    pub fn contains(&self, address: u64) -> bool {
        self.ranges.iter().any(|&(s, e)| address >= s && address <= e)
    }

    /// Check if a given range intersects with any stored range.
    pub fn intersects_range(&self, start: u64, end: u64) -> bool {
        self.ranges.iter().any(|&(rs, re)| rs <= end && re >= start)
    }

    /// The number of contiguous ranges.
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// The total number of addresses across all ranges.
    pub fn num_addresses(&self) -> u64 {
        self.ranges.iter().map(|&(s, e)| e - s + 1).sum()
    }

    /// Whether the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Clear all ranges.
    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    /// Get the minimum address.
    pub fn min_address(&self) -> Option<u64> {
        self.ranges.first().map(|&(s, _)| s)
    }

    /// Get the maximum address.
    pub fn max_address(&self) -> Option<u64> {
        self.ranges.last().map(|(_, e)| *e)
    }

    /// Get all ranges as a slice.
    pub fn ranges(&self) -> &[(u64, u64)] {
        &self.ranges
    }

    /// Merge overlapping and adjacent ranges.
    fn normalize(&mut self) {
        if self.ranges.is_empty() {
            return;
        }
        self.ranges.sort_by_key(|&(s, _)| s);
        let mut merged = Vec::new();
        let (mut cur_start, mut cur_end) = self.ranges[0];
        for &(s, e) in &self.ranges[1..] {
            if s <= cur_end + 1 {
                cur_end = cur_end.max(e);
            } else {
                merged.push((cur_start, cur_end));
                cur_start = s;
                cur_end = e;
            }
        }
        merged.push((cur_start, cur_end));
        self.ranges = merged;
    }
}
