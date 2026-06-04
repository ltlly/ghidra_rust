//! Marker set system for navigation and overview display.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.marker` package.
//!
//! Provides the marker set abstraction used to annotate addresses in the
//! listing margin and navigation bar. Markers represent warnings, errors,
//! bookmarks, breakpoints, and other annotations at specific addresses.
//!
//! # Architecture
//!
//! - [`MarkerSet`] -- Trait for marker set implementations.
//! - [`PointMarker`] -- A marker at a single address.
//! - [`AreaMarker`] -- A marker over a contiguous address range.
//! - [`MarkerManager`] -- Manages all marker sets for a program.
//! - [`MarkerDescriptor`] -- Describes how to display a marker (color, icon, tooltip).
//!
//! # Usage
//!
//! ```rust
//! use ghidra_features::base::marker::*;
//!
//! let mut mgr = MarkerManager::new();
//! let set_id = mgr.create_point_marker_set(
//!     "Bookmarks",
//!     "User bookmarks",
//!     10,        // priority
//!     0x00FF00,  // green
//! );
//! mgr.add_point_marker(set_id, 0x400000);
//! mgr.add_point_marker(set_id, 0x400100);
//! assert!(mgr.marker_sets()[&set_id].contains(0x400000));
//! ```

use std::collections::BTreeMap;
use std::collections::HashMap;

/// Unique identifier for a marker set.
pub type MarkerSetId = u64;

/// Represents an RGB color as 0xRRGGBB.
pub type Color = u32;

/// Marker types indicating the nature of an annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MarkerType {
    /// Generic bookmark.
    Bookmark,
    /// Error marker (red).
    Error,
    /// Warning marker (yellow).
    Warning,
    /// Information marker (blue).
    Info,
    /// Breakpoint marker.
    Breakpoint,
    /// Probe (debugger watchpoint).
    Probe,
    /// Function start/end marker.
    Function,
    /// Code flow marker.
    Flow,
    /// User-defined marker type.
    Custom(u16),
}

impl MarkerType {
    /// Default color for this marker type.
    pub fn default_color(&self) -> Color {
        match self {
            Self::Error => 0xFF0000,      // Red
            Self::Warning => 0xFFFF00,    // Yellow
            Self::Info => 0x0000FF,       // Blue
            Self::Bookmark => 0x00FF00,   // Green
            Self::Breakpoint => 0xFF00FF, // Magenta
            Self::Probe => 0x00FFFF,      // Cyan
            Self::Function => 0x808080,   // Gray
            Self::Flow => 0xFFA500,       // Orange
            Self::Custom(_) => 0xC0C0C0,  // Light gray
        }
    }
}

/// Descriptor that defines how a marker is displayed.
///
/// Ported from `ghidra.app.services.MarkerDescriptor`.
#[derive(Debug, Clone)]
pub struct MarkerDescriptor {
    /// Tooltip format string. Occurrences of `{addr}` are replaced with
    /// the marker's address when generating tooltip text.
    pub tooltip_template: Option<String>,
    /// Icon name (resource key) for this marker.
    pub icon_name: Option<String>,
    /// Whether this marker should be highlighted.
    pub highlight: bool,
}

impl MarkerDescriptor {
    /// Create a basic descriptor with a tooltip template.
    pub fn with_tooltip(template: impl Into<String>) -> Self {
        Self {
            tooltip_template: Some(template.into()),
            icon_name: None,
            highlight: false,
        }
    }

    /// Create a descriptor with an icon.
    pub fn with_icon(icon_name: impl Into<String>) -> Self {
        Self {
            tooltip_template: None,
            icon_name: Some(icon_name.into()),
            highlight: false,
        }
    }

    /// Generate a tooltip for a specific address.
    pub fn get_tooltip(&self, addr: u64) -> Option<String> {
        self.tooltip_template.as_ref().map(|tmpl| {
            tmpl.replace("{addr}", &format!("0x{:X}", addr))
        })
    }
}

impl Default for MarkerDescriptor {
    fn default() -> Self {
        Self {
            tooltip_template: None,
            icon_name: None,
            highlight: false,
        }
    }
}

// ---------------------------------------------------------------------------
// MarkerSet trait
// ---------------------------------------------------------------------------

/// Trait for marker set implementations.
///
/// A marker set is a named, prioritized collection of addresses (or address
/// ranges) that should be highlighted in the listing view's margin and
/// navigation bar.
///
/// Ported from `ghidra.app.services.MarkerSet`.
pub trait MarkerSet: Send + Sync {
    /// Name of this marker set.
    fn name(&self) -> &str;

    /// Description of this marker set.
    fn description(&self) -> &str;

    /// Priority of this marker set (lower = higher priority).
    fn priority(&self) -> i32;

    /// Whether this is a preferred marker set (displayed with special treatment).
    fn is_preferred(&self) -> bool;

    /// The marker color.
    fn color(&self) -> Color;

    /// Whether this marker set is currently active.
    fn is_active(&self) -> bool;

    /// Whether to show markers in the listing margin.
    fn display_in_marker_bar(&self) -> bool;

    /// Whether to show markers in the navigation bar.
    fn is_displayed_in_navigation_bar(&self) -> bool;

    /// Whether this marker set colors the background of the listing.
    fn is_coloring_background(&self) -> bool;

    /// Check if the given address has a marker.
    fn contains(&self, addr: u64) -> bool;

    /// Get all marker addresses.
    fn addresses(&self) -> Vec<(u64, u64)>;

    /// Whether the marker set is empty.
    fn is_empty(&self) -> bool;

    /// Add a point marker at the given address.
    fn add_address(&mut self, addr: u64);

    /// Add a marker range (inclusive).
    fn add_range(&mut self, min_addr: u64, max_addr: u64);

    /// Clear markers in the given range.
    fn clear_range(&mut self, min_addr: u64, max_addr: u64);

    /// Clear all markers.
    fn clear_all_markers(&mut self);

    /// Set active state.
    fn set_active(&mut self, active: bool);

    /// Set marker color.
    fn set_color(&mut self, color: Color);
}

// ---------------------------------------------------------------------------
// Point marker set
// ---------------------------------------------------------------------------

/// A marker set that marks individual addresses.
///
/// Ported from `ghidra.app.plugin.core.marker.PointMarkerSet`.
#[derive(Debug, Clone)]
pub struct PointMarkerSetData {
    name: String,
    description: String,
    priority: i32,
    is_preferred: bool,
    color: Color,
    active: bool,
    show_markers: bool,
    show_navigation: bool,
    color_background: bool,
    /// Sorted map of addresses.
    addresses: BTreeMap<u64, ()>,
    descriptor: Option<MarkerDescriptor>,
}

impl PointMarkerSetData {
    /// Create a new point marker set.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        priority: i32,
        color: Color,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            priority,
            is_preferred: false,
            color,
            active: true,
            show_markers: true,
            show_navigation: true,
            color_background: false,
            addresses: BTreeMap::new(),
            descriptor: None,
        }
    }

    /// Add a marker at the given address.
    pub fn add(&mut self, addr: u64) {
        self.addresses.insert(addr, ());
    }

    /// Remove the marker at the given address.
    pub fn remove(&mut self, addr: u64) {
        self.addresses.remove(&addr);
    }

    /// Clear all markers.
    pub fn clear_all(&mut self) {
        self.addresses.clear();
    }

    /// Set the marker descriptor.
    pub fn set_descriptor(&mut self, descriptor: MarkerDescriptor) {
        self.descriptor = Some(descriptor);
    }

    /// Get the marker descriptor.
    pub fn descriptor(&self) -> Option<&MarkerDescriptor> {
        self.descriptor.as_ref()
    }

    /// Set whether this is a preferred marker set.
    pub fn set_preferred(&mut self, preferred: bool) {
        self.is_preferred = preferred;
    }

    /// Set active state.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    /// Set marker color.
    pub fn set_color(&mut self, color: Color) {
        self.color = color;
    }
}

impl MarkerSet for PointMarkerSetData {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn priority(&self) -> i32 {
        self.priority
    }

    fn is_preferred(&self) -> bool {
        self.is_preferred
    }

    fn color(&self) -> Color {
        self.color
    }

    fn is_active(&self) -> bool {
        self.active
    }

    fn display_in_marker_bar(&self) -> bool {
        self.show_markers
    }

    fn is_displayed_in_navigation_bar(&self) -> bool {
        self.show_navigation
    }

    fn is_coloring_background(&self) -> bool {
        self.color_background
    }

    fn contains(&self, addr: u64) -> bool {
        self.addresses.contains_key(&addr)
    }

    fn addresses(&self) -> Vec<(u64, u64)> {
        self.addresses.keys().map(|&a| (a, a)).collect()
    }

    fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    fn add_address(&mut self, addr: u64) {
        self.addresses.insert(addr, ());
    }

    fn add_range(&mut self, min_addr: u64, max_addr: u64) {
        for addr in min_addr..=max_addr {
            self.addresses.insert(addr, ());
        }
    }

    fn clear_range(&mut self, min_addr: u64, max_addr: u64) {
        let keys: Vec<u64> = self
            .addresses
            .range(min_addr..=max_addr)
            .map(|(&k, _)| k)
            .collect();
        for key in keys {
            self.addresses.remove(&key);
        }
    }

    fn clear_all_markers(&mut self) {
        self.addresses.clear();
    }

    fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    fn set_color(&mut self, color: Color) {
        self.color = color;
    }
}

// ---------------------------------------------------------------------------
// Area marker set
// ---------------------------------------------------------------------------

/// A marker set that marks contiguous address ranges.
///
/// Ported from `ghidra.app.plugin.core.marker.AreaMarkerSet`.
#[derive(Debug, Clone)]
pub struct AreaMarkerSetData {
    name: String,
    description: String,
    priority: i32,
    is_preferred: bool,
    color: Color,
    active: bool,
    show_markers: bool,
    show_navigation: bool,
    color_background: bool,
    /// Sorted map: start_addr -> end_addr (inclusive).
    ranges: BTreeMap<u64, u64>,
    descriptor: Option<MarkerDescriptor>,
}

impl AreaMarkerSetData {
    /// Create a new area marker set.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        priority: i32,
        color: Color,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            priority,
            is_preferred: false,
            color,
            active: true,
            show_markers: true,
            show_navigation: true,
            color_background: false,
            ranges: BTreeMap::new(),
            descriptor: None,
        }
    }

    /// Add a marker range (inclusive).
    pub fn add_range(&mut self, min_addr: u64, max_addr: u64) {
        // Simple insertion; callers should avoid overlapping ranges.
        self.ranges.insert(min_addr, max_addr);
    }

    /// Remove markers in the given range.
    pub fn clear_range(&mut self, min_addr: u64, max_addr: u64) {
        // Remove any range that overlaps [min_addr, max_addr].
        let keys: Vec<u64> = self
            .ranges
            .range(..=max_addr)
            .filter(|(_, &end)| end >= min_addr)
            .map(|(&k, _)| k)
            .collect();
        for key in keys {
            self.ranges.remove(&key);
        }
    }

    /// Clear all markers.
    pub fn clear_all(&mut self) {
        self.ranges.clear();
    }

    /// Set the marker descriptor.
    pub fn set_descriptor(&mut self, descriptor: MarkerDescriptor) {
        self.descriptor = Some(descriptor);
    }

    /// Set whether this is a preferred marker set.
    pub fn set_preferred(&mut self, preferred: bool) {
        self.is_preferred = preferred;
    }

    /// Set active state.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    /// Set marker color.
    pub fn set_color(&mut self, color: Color) {
        self.color = color;
    }
}

impl MarkerSet for AreaMarkerSetData {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn priority(&self) -> i32 {
        self.priority
    }

    fn is_preferred(&self) -> bool {
        self.is_preferred
    }

    fn color(&self) -> Color {
        self.color
    }

    fn is_active(&self) -> bool {
        self.active
    }

    fn display_in_marker_bar(&self) -> bool {
        self.show_markers
    }

    fn is_displayed_in_navigation_bar(&self) -> bool {
        self.show_navigation
    }

    fn is_coloring_background(&self) -> bool {
        self.color_background
    }

    fn contains(&self, addr: u64) -> bool {
        self.ranges
            .range(..=addr)
            .next_back()
            .map(|(_, &end)| addr <= end)
            .unwrap_or(false)
    }

    fn addresses(&self) -> Vec<(u64, u64)> {
        self.ranges.iter().map(|(&start, &end)| (start, end)).collect()
    }

    fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    fn add_address(&mut self, addr: u64) {
        self.ranges.insert(addr, addr);
    }

    fn add_range(&mut self, min_addr: u64, max_addr: u64) {
        self.ranges.insert(min_addr, max_addr);
    }

    fn clear_range(&mut self, min_addr: u64, max_addr: u64) {
        let keys: Vec<u64> = self
            .ranges
            .range(..=max_addr)
            .filter(|(_, &end)| end >= min_addr)
            .map(|(&k, _)| k)
            .collect();
        for key in keys {
            self.ranges.remove(&key);
        }
    }

    fn clear_all_markers(&mut self) {
        self.ranges.clear();
    }

    fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    fn set_color(&mut self, color: Color) {
        self.color = color;
    }
}

// ---------------------------------------------------------------------------
// MarkerManager
// ---------------------------------------------------------------------------

/// Manages all marker sets for a program.
///
/// Provides a central registry for creating, querying, and managing
/// marker sets. Corresponds to Ghidra's `MarkerManager`.
pub struct MarkerManager {
    /// All marker sets, keyed by ID.
    sets: HashMap<MarkerSetId, Box<dyn MarkerSet>>,
    /// Next available marker set ID.
    next_id: MarkerSetId,
}

impl std::fmt::Debug for MarkerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarkerManager")
            .field("num_sets", &self.sets.len())
            .field("next_id", &self.next_id)
            .finish()
    }
}

impl MarkerManager {
    /// Create a new empty marker manager.
    pub fn new() -> Self {
        Self {
            sets: HashMap::new(),
            next_id: 1,
        }
    }

    /// Create a point marker set and return its ID.
    pub fn create_point_marker_set(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        priority: i32,
        color: Color,
    ) -> MarkerSetId {
        let id = self.next_id;
        self.next_id += 1;
        let set = Box::new(PointMarkerSetData::new(name, description, priority, color));
        self.sets.insert(id, set);
        id
    }

    /// Create an area marker set and return its ID.
    pub fn create_area_marker_set(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        priority: i32,
        color: Color,
    ) -> MarkerSetId {
        let id = self.next_id;
        self.next_id += 1;
        let set = Box::new(AreaMarkerSetData::new(name, description, priority, color));
        self.sets.insert(id, set);
        id
    }

    /// Add a point marker to the specified marker set.
    pub fn add_point_marker(&mut self, set_id: MarkerSetId, addr: u64) {
        if let Some(set) = self.sets.get_mut(&set_id) {
            set.add_address(addr);
        }
    }

    /// Add a range marker to the specified marker set.
    pub fn add_range_marker(&mut self, set_id: MarkerSetId, min_addr: u64, max_addr: u64) {
        if let Some(set) = self.sets.get_mut(&set_id) {
            set.add_range(min_addr, max_addr);
        }
    }

    /// Clear markers in a range from the specified marker set.
    pub fn clear_markers(&mut self, set_id: MarkerSetId, min_addr: u64, max_addr: u64) {
        if let Some(set) = self.sets.get_mut(&set_id) {
            set.clear_range(min_addr, max_addr);
        }
    }

    /// Clear all markers from the specified marker set.
    pub fn clear_all_markers(&mut self, set_id: MarkerSetId) {
        if let Some(set) = self.sets.get_mut(&set_id) {
            set.clear_all_markers();
        }
    }

    /// Get a reference to a marker set by ID.
    pub fn get(&self, id: MarkerSetId) -> Option<&dyn MarkerSet> {
        self.sets.get(&id).map(|s| s.as_ref())
    }

    /// Remove a marker set.
    pub fn remove(&mut self, id: MarkerSetId) {
        self.sets.remove(&id);
    }

    /// Get all marker set IDs.
    pub fn marker_set_ids(&self) -> Vec<MarkerSetId> {
        self.sets.keys().copied().collect()
    }

    /// Get all marker sets.
    pub fn marker_sets(&self) -> &HashMap<MarkerSetId, Box<dyn MarkerSet>> {
        &self.sets
    }

    /// Get all active marker sets, sorted by priority.
    pub fn active_marker_sets(&self) -> Vec<(MarkerSetId, &dyn MarkerSet)> {
        let mut sets: Vec<_> = self
            .sets
            .iter()
            .filter(|(_, s)| s.is_active())
            .map(|(&id, s)| (id, s.as_ref()))
            .collect();
        sets.sort_by_key(|(_, s)| s.priority());
        sets
    }

    /// Check if any marker set contains the given address.
    pub fn has_marker_at(&self, addr: u64) -> bool {
        self.sets.values().any(|s| s.is_active() && s.contains(addr))
    }

    /// Get all marker sets that contain the given address.
    pub fn marker_sets_at(&self, addr: u64) -> Vec<MarkerSetId> {
        self.sets
            .iter()
            .filter(|(_, s)| s.is_active() && s.contains(addr))
            .map(|(&id, _)| id)
            .collect()
    }

    /// Get the total number of markers across all active sets.
    pub fn total_marker_count(&self) -> usize {
        self.sets
            .values()
            .filter(|s| s.is_active())
            .map(|s| s.addresses().len())
            .sum()
    }
}

impl Default for MarkerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point_marker_set_new() {
        let set = PointMarkerSetData::new("Test", "Description", 10, 0xFF0000);
        assert_eq!(set.name(), "Test");
        assert_eq!(set.description(), "Description");
        assert_eq!(set.priority(), 10);
        assert_eq!(set.color(), 0xFF0000);
        assert!(set.is_active());
        assert!(set.is_empty());
    }

    #[test]
    fn test_point_marker_set_add_contains() {
        let mut set = PointMarkerSetData::new("Bookmarks", "", 10, 0x00FF00);
        set.add(0x400000);
        set.add(0x400100);
        assert!(set.contains(0x400000));
        assert!(set.contains(0x400100));
        assert!(!set.contains(0x400050));
        assert!(!set.is_empty());
    }

    #[test]
    fn test_point_marker_set_remove() {
        let mut set = PointMarkerSetData::new("Test", "", 10, 0xFF0000);
        set.add(100);
        set.add(200);
        set.remove(100);
        assert!(!set.contains(100));
        assert!(set.contains(200));
    }

    #[test]
    fn test_point_marker_set_clear_all() {
        let mut set = PointMarkerSetData::new("Test", "", 10, 0xFF0000);
        set.add(100);
        set.add(200);
        set.clear_all();
        assert!(set.is_empty());
    }

    #[test]
    fn test_point_marker_set_addresses() {
        let mut set = PointMarkerSetData::new("Test", "", 10, 0xFF0000);
        set.add(300);
        set.add(100);
        set.add(200);
        let addrs = set.addresses();
        assert_eq!(addrs.len(), 3);
        // Should be sorted.
        assert_eq!(addrs[0].0, 100);
        assert_eq!(addrs[1].0, 200);
        assert_eq!(addrs[2].0, 300);
    }

    #[test]
    fn test_area_marker_set() {
        let mut set = AreaMarkerSetData::new("Functions", "", 5, 0x0000FF);
        set.add_range(0x400000, 0x400100);
        set.add_range(0x500000, 0x500200);
        assert!(set.contains(0x400050));
        assert!(set.contains(0x400100));
        assert!(!set.contains(0x400101));
        assert!(set.contains(0x500100));
    }

    #[test]
    fn test_area_marker_set_clear_range() {
        let mut set = AreaMarkerSetData::new("Test", "", 5, 0xFF0000);
        set.add_range(100, 200);
        set.add_range(300, 400);
        set.clear_range(150, 350);
        // First range overlaps, should be removed.
        assert!(!set.contains(100));
        // Second range overlaps, should be removed.
        assert!(!set.contains(300));
        assert!(set.is_empty());
    }

    #[test]
    fn test_marker_descriptor_tooltip() {
        let desc = MarkerDescriptor::with_tooltip("Bookmark at {addr}");
        let tooltip = desc.get_tooltip(0x400000);
        assert_eq!(tooltip, Some("Bookmark at 0x400000".to_string()));
    }

    #[test]
    fn test_marker_type_default_colors() {
        assert_eq!(MarkerType::Error.default_color(), 0xFF0000);
        assert_eq!(MarkerType::Warning.default_color(), 0xFFFF00);
        assert_eq!(MarkerType::Bookmark.default_color(), 0x00FF00);
    }

    #[test]
    fn test_marker_manager_new() {
        let mgr = MarkerManager::new();
        assert!(mgr.marker_sets().is_empty());
    }

    #[test]
    fn test_marker_manager_create_point() {
        let mut mgr = MarkerManager::new();
        let id = mgr.create_point_marker_set("Bookmarks", "User bookmarks", 10, 0x00FF00);
        assert!(mgr.get(id).is_some());
        assert_eq!(mgr.get(id).unwrap().name(), "Bookmarks");
    }

    #[test]
    fn test_marker_manager_create_area() {
        let mut mgr = MarkerManager::new();
        let id = mgr.create_area_marker_set("Functions", "Function ranges", 5, 0x0000FF);
        assert!(mgr.get(id).is_some());
    }

    #[test]
    fn test_marker_manager_remove() {
        let mut mgr = MarkerManager::new();
        let id = mgr.create_point_marker_set("Test", "", 10, 0xFF0000);
        mgr.remove(id);
        assert!(mgr.get(id).is_none());
    }

    #[test]
    fn test_marker_manager_has_marker_at() {
        let mut mgr = MarkerManager::new();
        let _id = mgr.create_point_marker_set("Test", "", 10, 0xFF0000);
        // Empty set has no markers.
        assert!(!mgr.has_marker_at(0x400000));
    }

    #[test]
    fn test_marker_manager_active_sets() {
        let mut mgr = MarkerManager::new();
        let _id1 = mgr.create_point_marker_set("High", "", 1, 0xFF0000);
        let _id2 = mgr.create_point_marker_set("Low", "", 100, 0x00FF00);
        let active = mgr.active_marker_sets();
        assert_eq!(active.len(), 2);
        // Sorted by priority (lower = higher priority).
        assert_eq!(active[0].1.name(), "High");
        assert_eq!(active[1].1.name(), "Low");
    }

    #[test]
    fn test_point_marker_set_preferred() {
        let mut set = PointMarkerSetData::new("Preferred", "", 1, 0xFF0000);
        assert!(!set.is_preferred());
        set.set_preferred(true);
        assert!(set.is_preferred());
    }

    #[test]
    fn test_point_marker_set_active_state() {
        let mut set = PointMarkerSetData::new("Test", "", 10, 0xFF0000);
        assert!(set.is_active());
        set.set_active(false);
        assert!(!set.is_active());
    }

    #[test]
    fn test_point_marker_descriptor() {
        let mut set = PointMarkerSetData::new("Test", "", 10, 0xFF0000);
        assert!(set.descriptor().is_none());
        set.set_descriptor(MarkerDescriptor::with_tooltip("At {addr}"));
        assert!(set.descriptor().is_some());
    }
}
