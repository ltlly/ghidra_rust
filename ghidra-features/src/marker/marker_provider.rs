//! Marker Providers -- margin and overview rendering.
//!
//! Ported from Ghidra's:
//! - `ghidra.app.plugin.core.marker.MarkerMarginProvider`
//! - `ghidra.app.plugin.core.marker.MarkerOverviewProvider`
//! - `ghidra.app.plugin.core.marker.NavigationPanel`
//! - `ghidra.app.plugin.core.marker.MarkerPanel` (rendering)
//!
//! The margin provider renders markers to the left of the listing panel.
//! The overview provider renders a scaled-down view of markers outside the
//! scrollbar to the right of listing field panels.

use super::{MarkerManager, MarkerPanel, MarkerSet, RgbColor};
use std::collections::HashMap;

// ============================================================================
// ListingMarginProvider -- trait for margin rendering
// ============================================================================

/// Trait for objects that provide a marker margin in the listing.
///
/// Ported from Ghidra's `ListingMarginProvider` interface.
pub trait ListingMarginProvider: Send + Sync + std::fmt::Debug {
    /// Set the owner ID for this provider (to distinguish providers from
    /// different tool instances).
    fn set_owner_id(&mut self, owner_id: u64);

    /// Set the current program location.
    fn set_location(&mut self, address: Option<u64>);

    /// Dispose of this provider.
    fn dispose(&mut self);

    /// Whether this provider is resizable.
    fn is_resizable(&self) -> bool;

    /// Notify the provider that the screen data has changed.
    fn screen_data_changed(
        &mut self,
        start_address: u64,
        end_address: u64,
        visible_height: u32,
    );

    /// Get the marker location at the given pixel coordinates.
    fn get_marker_location(&self, x: i32, y: i32) -> Option<MarkerLocation>;
}

// ============================================================================
// ListingOverviewProvider -- trait for overview rendering
// ============================================================================

/// Trait for objects that provide an overview bar in the listing.
///
/// Ported from Ghidra's `ListingOverviewProvider` interface.
pub trait ListingOverviewProvider: Send + Sync + std::fmt::Debug {
    /// Dispose of this provider.
    fn dispose(&mut self);

    /// Notify the provider that the screen data has changed.
    fn screen_data_changed(
        &mut self,
        start_address: u64,
        end_address: u64,
        visible_height: u32,
    );

    /// Set the navigatable for navigation actions.
    fn set_navigatable(&mut self, navigatable_id: Option<u64>);
}

// ============================================================================
// MarkerLocation -- a location in the marker system
// ============================================================================

/// Represents a marker location in the listing, combining a program address
/// with marker set information and pixel coordinates.
///
/// Ported from Ghidra's `MarkerLocation`.
#[derive(Debug, Clone)]
pub struct MarkerLocation {
    /// The marker set at this location (if any).
    pub marker_set_name: Option<String>,
    /// The address in the program.
    pub address: u64,
    /// The x pixel coordinate.
    pub x: i32,
    /// The y pixel coordinate.
    pub y: i32,
}

impl MarkerLocation {
    /// Create a new marker location.
    pub fn new(address: u64, x: i32, y: i32) -> Self {
        Self {
            marker_set_name: None,
            address,
            x,
            y,
        }
    }

    /// Create a marker location with an associated marker set name.
    pub fn with_marker_set(mut self, name: impl Into<String>) -> Self {
        self.marker_set_name = Some(name.into());
        self
    }
}

// ============================================================================
// VerticalPixelAddressMap -- maps pixel rows to addresses
// ============================================================================

/// Maps vertical pixel positions to program addresses.
///
/// Ported from Ghidra's `VerticalPixelAddressMap` (used by `MarkerPanel`).
#[derive(Debug, Clone)]
pub struct VerticalPixelAddressMap {
    /// Maps pixel y-coordinate to an address.
    entries: Vec<PixelAddressEntry>,
}

/// A single entry in the pixel-to-address mapping.
#[derive(Debug, Clone)]
struct PixelAddressEntry {
    /// The y pixel coordinate.
    y: u32,
    /// The address at this pixel.
    address: u64,
}

impl VerticalPixelAddressMap {
    /// Create a new empty map.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Add a mapping from a pixel row to an address.
    pub fn insert(&mut self, y: u32, address: u64) {
        self.entries.push(PixelAddressEntry { y, address });
        self.entries.sort_by_key(|e| e.y);
    }

    /// Get the address at the given y pixel coordinate.
    /// Returns the address of the nearest entry at or before `y`.
    pub fn get_address(&self, y: u32) -> Option<u64> {
        match self.entries.binary_search_by_key(&y, |e| e.y) {
            Ok(idx) => self.entries.get(idx).map(|e| e.address),
            Err(idx) => {
                if idx > 0 {
                    self.entries.get(idx - 1).map(|e| e.address)
                } else {
                    None
                }
            }
        }
    }

    /// Get the number of entries in the map.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get the address range represented by this map.
    pub fn address_range(&self) -> Option<(u64, u64)> {
        if self.entries.is_empty() {
            return None;
        }
        let first = self.entries.first().unwrap().address;
        let last = self.entries.last().unwrap().address;
        Some((first.min(last), first.max(last)))
    }
}

impl Default for VerticalPixelAddressMap {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MarkerMarginProvider -- renders markers in the left margin
// ============================================================================

/// The margin provider renders markers to the left of listing field panels.
///
/// Ported from `ghidra.app.plugin.core.marker.MarkerMarginProvider`.
///
/// These are managed by a `MarkerManager`. Obtain one via
/// `MarkerService.createMarginProvider()`.
#[derive(Debug, Clone)]
pub struct MarkerMarginProvider {
    /// Unique ID for this provider instance.
    id: usize,
    /// The owner ID (tool-level identifier).
    owner_id: Option<u64>,
    /// The marker panel used for rendering.
    panel: MarkerPanel,
    /// The current program address range being displayed.
    start_address: u64,
    /// The end of the displayed address range.
    end_address: u64,
    /// Whether this provider has been disposed.
    disposed: bool,
    /// The pixel-to-address map for hit testing.
    pixel_map: VerticalPixelAddressMap,
    /// Double-click handler callback ID (if registered).
    double_click_handler: Option<u64>,
}

impl MarkerMarginProvider {
    /// Create a new margin provider.
    ///
    /// `id` is a unique identifier for this provider instance.
    pub fn new(id: usize) -> Self {
        Self {
            id,
            owner_id: None,
            panel: MarkerPanel::new(16, 400), // default margin width and height
            start_address: 0,
            end_address: 0,
            disposed: false,
            pixel_map: VerticalPixelAddressMap::new(),
            double_click_handler: None,
        }
    }

    /// Get the unique ID of this provider.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Whether this provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Get the marker panel's current dimensions.
    pub fn panel_dimensions(&self) -> (u32, u32) {
        (self.panel.width, self.panel.height)
    }

    /// Resize the marker panel.
    pub fn resize(&mut self, width: u32, height: u32) {
        self.panel = MarkerPanel::new(width, height);
    }

    /// Clear the marker panel to the given background color.
    pub fn clear_panel(&mut self, color: RgbColor) {
        self.panel.clear(color);
    }

    /// Paint a marker at the given address with the specified color.
    ///
    /// This maps the address to a y-coordinate using the pixel map and
    /// draws a filled rectangle in the margin.
    pub fn paint_marker(&mut self, address: u64, color: RgbColor, marker_width: u32) {
        if let Some(y) = self.address_to_pixel(address) {
            self.panel
                .fill_rect(0, y, marker_width, 1, color);
        }
    }

    /// Paint an area marker spanning from `start` to `end` addresses.
    pub fn paint_area_marker(
        &mut self,
        start: u64,
        end: u64,
        color: RgbColor,
        marker_width: u32,
    ) {
        let start_y = self.address_to_pixel(start).unwrap_or(0);
        let end_y = self.address_to_pixel(end).unwrap_or(start_y);
        let height = if end_y >= start_y {
            end_y - start_y + 1
        } else {
            1
        };
        self.panel.fill_rect(0, start_y, marker_width, height, color);
    }

    /// Get the marker location at the given pixel coordinates.
    ///
    /// Used for hit-testing on mouse clicks.
    pub fn get_marker_location_at(&self, x: i32, y: i32) -> Option<MarkerLocation> {
        let address = self.pixel_map.get_address(y as u32)?;
        Some(MarkerLocation::new(address, x, y))
    }

    /// Map an address to a pixel y-coordinate.
    ///
    /// Returns `None` if the address is outside the visible range.
    fn address_to_pixel(&self, address: u64) -> Option<u32> {
        if self.pixel_map.is_empty() {
            return None;
        }
        // Search for the entry whose address matches or is closest
        for entry in &self.pixel_map.entries {
            if entry.address >= address {
                return Some(entry.y);
            }
        }
        None
    }

    /// Generate a tooltip string for the given pixel coordinates.
    ///
    /// Returns a formatted tooltip if there are markers at this location.
    pub fn generate_tooltip(
        &self,
        x: i32,
        y: i32,
        marker_manager: &MarkerManager,
    ) -> Option<String> {
        let address = self.pixel_map.get_address(y as u32)?;
        let lines = marker_manager.get_tooltip_lines(address);
        if lines.is_empty() {
            return None;
        }
        Some(lines.join("\n"))
    }
}

impl ListingMarginProvider for MarkerMarginProvider {
    fn set_owner_id(&mut self, owner_id: u64) {
        self.owner_id = Some(owner_id);
    }

    fn set_location(&mut self, address: Option<u64>) {
        // Margin providers typically don't track the current cursor location
    }

    fn dispose(&mut self) {
        self.disposed = true;
        self.pixel_map.clear();
    }

    fn is_resizable(&self) -> bool {
        false
    }

    fn screen_data_changed(
        &mut self,
        start_address: u64,
        end_address: u64,
        visible_height: u32,
    ) {
        self.start_address = start_address;
        self.end_address = end_address;
        // Resize the panel to match the visible area
        if visible_height != self.panel.height {
            self.panel = MarkerPanel::new(self.panel.width, visible_height);
        }
    }

    fn get_marker_location(&self, x: i32, y: i32) -> Option<MarkerLocation> {
        self.get_marker_location_at(x, y)
    }
}

// ============================================================================
// MarkerOverviewProvider -- renders markers in the overview bar
// ============================================================================

/// The overview provider renders a scaled-down view of markers, usually
/// placed outside the scrollbar to the right of listing field panels.
///
/// Ported from `ghidra.app.plugin.core.marker.MarkerOverviewProvider`.
///
/// These are managed by a `MarkerManager`. Obtain one via
/// `MarkerService.createOverviewProvider()`.
#[derive(Debug, Clone)]
pub struct MarkerOverviewProvider {
    /// Unique ID for this provider instance.
    id: usize,
    /// The name of the owner plugin.
    owner: String,
    /// The marker panel for rendering the overview.
    panel: MarkerPanel,
    /// The current address range being displayed.
    start_address: u64,
    /// End of the displayed range.
    end_address: u64,
    /// The navigatable ID for navigation actions.
    navigatable_id: Option<u64>,
    /// Whether this provider has been disposed.
    disposed: bool,
    /// The total address space size (for scaling).
    total_address_space: u64,
    /// Marker set visibility toggles (set name -> visible).
    marker_visibility: HashMap<String, bool>,
}

impl MarkerOverviewProvider {
    /// Create a new overview provider.
    ///
    /// `id` is a unique identifier for this provider instance.
    /// `owner` is the name of the owning plugin.
    pub fn new(id: usize, owner: &str) -> Self {
        Self {
            id,
            owner: owner.to_string(),
            panel: MarkerPanel::new(16, 400),
            start_address: 0,
            end_address: 0,
            navigatable_id: None,
            disposed: false,
            total_address_space: 0xFFFF_FFFF, // default 32-bit space
            marker_visibility: HashMap::new(),
        }
    }

    /// Get the unique ID of this provider.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Get the owner plugin name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Whether this provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Get the panel dimensions.
    pub fn panel_dimensions(&self) -> (u32, u32) {
        (self.panel.width, self.panel.height)
    }

    /// Resize the overview panel.
    pub fn resize(&mut self, width: u32, height: u32) {
        self.panel = MarkerPanel::new(width, height);
    }

    /// Set the total address space for scaling calculations.
    pub fn set_total_address_space(&mut self, size: u64) {
        self.total_address_space = size;
    }

    /// Set whether a marker set is visible in the overview.
    pub fn set_marker_visible(&mut self, name: &str, visible: bool) {
        self.marker_visibility.insert(name.to_string(), visible);
    }

    /// Check if a marker set is visible in the overview.
    pub fn is_marker_visible(&self, name: &str) -> bool {
        self.marker_visibility.get(name).copied().unwrap_or(true)
    }

    /// Paint a marker at the given address in the overview.
    ///
    /// The address is scaled to a y-coordinate based on the total address space
    /// and the panel height.
    pub fn paint_marker(&mut self, address: u64, color: RgbColor) {
        let y = self.address_to_overview_y(address);
        if y < self.panel.height {
            self.panel.fill_rect(0, y, self.panel.width, 1, color);
        }
    }

    /// Paint an area marker in the overview.
    pub fn paint_area_marker(&mut self, start: u64, end: u64, color: RgbColor) {
        let start_y = self.address_to_overview_y(start);
        let end_y = self.address_to_overview_y(end);
        let height = if end_y >= start_y {
            end_y - start_y + 1
        } else {
            1
        };
        if start_y < self.panel.height {
            self.panel
                .fill_rect(0, start_y, self.panel.width, height, color);
        }
    }

    /// Clear the overview panel.
    pub fn clear_panel(&mut self, color: RgbColor) {
        self.panel.clear(color);
    }

    /// Get the raw pixel data of the overview panel.
    pub fn pixels(&self) -> &[u8] {
        self.panel.pixels()
    }

    /// Translate an overview panel y-coordinate back to a program address.
    ///
    /// Used for click-to-navigate in the overview bar.
    pub fn overview_y_to_address(&self, y: u32) -> u64 {
        if self.panel.height == 0 || self.total_address_space == 0 {
            return 0;
        }
        let fraction = y as f64 / self.panel.height as f64;
        (fraction * self.total_address_space as f64) as u64
    }

    /// Scale an address to a y-coordinate in the overview panel.
    fn address_to_overview_y(&self, address: u64) -> u32 {
        if self.total_address_space == 0 || self.panel.height == 0 {
            return 0;
        }
        let fraction = address as f64 / self.total_address_space as f64;
        (fraction * self.panel.height as f64) as u32
    }
}

impl ListingOverviewProvider for MarkerOverviewProvider {
    fn dispose(&mut self) {
        self.disposed = true;
        self.marker_visibility.clear();
    }

    fn screen_data_changed(
        &mut self,
        start_address: u64,
        end_address: u64,
        visible_height: u32,
    ) {
        self.start_address = start_address;
        self.end_address = end_address;
        if visible_height != self.panel.height {
            self.panel = MarkerPanel::new(self.panel.width, visible_height);
        }
    }

    fn set_navigatable(&mut self, navigatable_id: Option<u64>) {
        self.navigatable_id = navigatable_id;
    }
}

// ============================================================================
// MarkerClickedListener -- callback for marker click events
// ============================================================================

/// Trait for handling marker click events.
///
/// Ported from Ghidra's `MarkerClickedListener`.
pub trait MarkerClickedListener: Send + Sync + std::fmt::Debug {
    /// Called when a marker is double-clicked.
    fn marker_double_clicked(&self, location: MarkerLocation);

    /// Called when a marker is single-clicked.
    fn marker_clicked(&self, location: MarkerLocation);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- MarkerLocation tests --

    #[test]
    fn test_marker_location() {
        let loc = MarkerLocation::new(0x1000, 10, 20);
        assert_eq!(loc.address, 0x1000);
        assert_eq!(loc.x, 10);
        assert_eq!(loc.y, 20);
        assert!(loc.marker_set_name.is_none());
    }

    #[test]
    fn test_marker_location_with_set() {
        let loc = MarkerLocation::new(0x2000, 5, 15).with_marker_set("Errors");
        assert_eq!(loc.marker_set_name, Some("Errors".to_string()));
    }

    // -- VerticalPixelAddressMap tests --

    #[test]
    fn test_pixel_address_map() {
        let mut map = VerticalPixelAddressMap::new();
        assert!(map.is_empty());

        map.insert(0, 0x1000);
        map.insert(100, 0x2000);
        map.insert(200, 0x3000);

        assert_eq!(map.len(), 3);
        assert_eq!(map.get_address(0), Some(0x1000));
        assert_eq!(map.get_address(50), Some(0x1000)); // nearest at or before
        assert_eq!(map.get_address(100), Some(0x2000));
        assert_eq!(map.get_address(150), Some(0x2000));
        assert_eq!(map.get_address(200), Some(0x3000));
        assert_eq!(map.get_address(250), Some(0x3000));
    }

    #[test]
    fn test_pixel_address_map_empty() {
        let map = VerticalPixelAddressMap::new();
        assert!(map.get_address(0).is_none());
        assert!(map.address_range().is_none());
    }

    #[test]
    fn test_pixel_address_map_range() {
        let mut map = VerticalPixelAddressMap::new();
        map.insert(0, 0x1000);
        map.insert(200, 0x5000);
        let range = map.address_range().unwrap();
        assert_eq!(range, (0x1000, 0x5000));
    }

    // -- MarkerMarginProvider tests --

    #[test]
    fn test_margin_provider_creation() {
        let provider = MarkerMarginProvider::new(0);
        assert_eq!(provider.id(), 0);
        assert!(!provider.is_disposed());
        assert!(!provider.is_resizable());
    }

    #[test]
    fn test_margin_provider_resize() {
        let mut provider = MarkerMarginProvider::new(0);
        provider.resize(32, 800);
        assert_eq!(provider.panel_dimensions(), (32, 800));
    }

    #[test]
    fn test_margin_provider_dispose() {
        let mut provider = MarkerMarginProvider::new(0);
        assert!(!provider.is_disposed());
        provider.dispose();
        assert!(provider.is_disposed());
    }

    #[test]
    fn test_margin_provider_screen_data() {
        let mut provider = MarkerMarginProvider::new(0);
        provider.screen_data_changed(0x1000, 0x2000, 500);
        assert_eq!(provider.start_address, 0x1000);
        assert_eq!(provider.end_address, 0x2000);
        assert_eq!(provider.panel_dimensions().1, 500);
    }

    #[test]
    fn test_margin_provider_owner_id() {
        let mut provider = MarkerMarginProvider::new(0);
        provider.set_owner_id(42);
        assert_eq!(provider.owner_id, Some(42));
    }

    #[test]
    fn test_margin_provider_marker_location() {
        let mut provider = MarkerMarginProvider::new(0);
        // No pixel map entries, so no marker location
        let loc = provider.get_marker_location_at(5, 50);
        assert!(loc.is_none());
    }

    #[test]
    fn test_margin_provider_paint() {
        let mut provider = MarkerMarginProvider::new(0);
        // Paint should not panic even without pixel map entries
        provider.paint_marker(0x1000, RgbColor::RED, 16);
        provider.paint_area_marker(0x1000, 0x2000, RgbColor::BLUE, 16);
    }

    // -- MarkerOverviewProvider tests --

    #[test]
    fn test_overview_provider_creation() {
        let provider = MarkerOverviewProvider::new(0, "TestPlugin");
        assert_eq!(provider.id(), 0);
        assert_eq!(provider.owner(), "TestPlugin");
        assert!(!provider.is_disposed());
    }

    #[test]
    fn test_overview_provider_resize() {
        let mut provider = MarkerOverviewProvider::new(0, "Test");
        provider.resize(32, 600);
        assert_eq!(provider.panel_dimensions(), (32, 600));
    }

    #[test]
    fn test_overview_provider_dispose() {
        let mut provider = MarkerOverviewProvider::new(0, "Test");
        provider.dispose();
        assert!(provider.is_disposed());
    }

    #[test]
    fn test_overview_provider_navigatable() {
        let mut provider = MarkerOverviewProvider::new(0, "Test");
        assert!(provider.navigatable_id.is_none());
        provider.set_navigatable(Some(99));
        assert_eq!(provider.navigatable_id, Some(99));
        provider.set_navigatable(None);
        assert!(provider.navigatable_id.is_none());
    }

    #[test]
    fn test_overview_provider_visibility() {
        let mut provider = MarkerOverviewProvider::new(0, "Test");
        assert!(provider.is_marker_visible("anything")); // default true

        provider.set_marker_visible("Errors", false);
        assert!(!provider.is_marker_visible("Errors"));
        assert!(provider.is_marker_visible("Warnings")); // others unaffected
    }

    #[test]
    fn test_overview_provider_address_scaling() {
        let mut provider = MarkerOverviewProvider::new(0, "Test");
        provider.set_total_address_space(0x10000);
        provider.resize(16, 256);

        // Address 0x8000 should map to y=128 (halfway)
        assert_eq!(provider.address_to_overview_y(0x8000), 128);

        // Reverse: y=128 should map to approximately 0x8000
        let addr = provider.overview_y_to_address(128);
        assert_eq!(addr, 0x8000);
    }

    #[test]
    fn test_overview_provider_paint() {
        let mut provider = MarkerOverviewProvider::new(0, "Test");
        provider.set_total_address_space(0x10000);
        provider.resize(16, 256);

        // Should not panic
        provider.paint_marker(0x8000, RgbColor::RED);
        provider.paint_area_marker(0x1000, 0x2000, RgbColor::BLUE);
        provider.clear_panel(RgbColor::rgb(0, 0, 0));
    }

    #[test]
    fn test_overview_provider_screen_data() {
        let mut provider = MarkerOverviewProvider::new(0, "Test");
        provider.screen_data_changed(0x1000, 0x5000, 300);
        assert_eq!(provider.start_address, 0x1000);
        assert_eq!(provider.end_address, 0x5000);
        assert_eq!(provider.panel_dimensions().1, 300);
    }

    #[test]
    fn test_overview_provider_total_address_space() {
        let mut provider = MarkerOverviewProvider::new(0, "Test");
        provider.set_total_address_space(0);
        // Division by zero protection: should return 0
        assert_eq!(provider.address_to_overview_y(0x8000), 0);
    }

    #[test]
    fn test_overview_provider_zero_height() {
        let mut provider = MarkerOverviewProvider::new(0, "Test");
        provider.set_total_address_space(0x10000);
        provider.panel = MarkerPanel::new(16, 0);
        assert_eq!(provider.address_to_overview_y(0x8000), 0);
        assert_eq!(provider.overview_y_to_address(50), 0);
    }
}
