//! Overview color plugin -- maps program addresses to colors for the
//! Listing's right-margin bar.
//!
//! Ports `ghidra.app.plugin.core.overview`:
//! - [`OverviewColorService`] trait (the core service interface)
//! - [`OverviewColorComponent`] (the bar renderer)
//! - [`OverviewColorPlugin`] (the plugin that manages services)

use std::collections::HashMap;

use ghidra_core::addr::Address;
use ghidra_core::program::program::Program;

// ---------------------------------------------------------------------------
// OverviewColorService -- trait
// ---------------------------------------------------------------------------

/// Associates colours with any address in a program.
///
/// Implementations are discovered at runtime and presented as toggles
/// in the Listing's margin area (e.g. "Address Type", "Entropy").
pub trait OverviewColorService: Send + Sync {
    /// Human-readable name of this colour service.
    fn name(&self) -> &str;

    /// Return the colour for the given program address.
    ///
    /// The returned value is an RGBA tuple `(r, g, b, a)` with each
    /// component in `0..=255`.
    fn color_for_address(&self, address: &Address) -> (u8, u8, u8, u8);

    /// Set the program this service should analyse.
    fn set_program(&mut self, program: Option<&Program>);

    /// Return the current program (if any).
    fn program(&self) -> Option<&Program>;

    /// Tooltip text when the user hovers over the given address.
    fn tooltip_text(&self, address: &Address) -> String;

    /// Optional help topic key.
    fn help_topic(&self) -> &str {
        "OverviewPlugin"
    }
}

// ---------------------------------------------------------------------------
// OverviewColorComponent -- renders the colour bar
// ---------------------------------------------------------------------------

/// Width of the overview bar in pixels.
pub const OVERVIEW_WIDTH: u16 = 16;

/// Default background colour when no data is available.
pub const DEFAULT_COLOR: (u8, u8, u8, u8) = (0x40, 0x40, 0x40, 0xFF);

/// The overview bar component that paints address-to-colour mapping.
///
/// Each pixel row in the bar corresponds to a range of program
/// addresses.  The component lazily refreshes its colour cache.
pub struct OverviewColorComponent {
    /// Per-pixel colour cache.  `None` entries need recomputation.
    colors: Vec<Option<(u8, u8, u8, u8)>>,
    /// Height in pixels (= number of address buckets).
    height: u32,
    /// Total number of address indices in the current view.
    index_count: u64,
    /// Flag indicating a refresh is pending.
    dirty: bool,
}

impl OverviewColorComponent {
    /// Create a new overview component with the given height.
    pub fn new(height: u32) -> Self {
        Self {
            colors: vec![None; height as usize],
            height,
            index_count: 0,
            dirty: true,
        }
    }

    /// Notify the component that the visible address range changed.
    ///
    /// `index_count` is the total number of addressable units in the
    /// current view.
    pub fn screen_data_changed(&mut self, index_count: u64) {
        self.index_count = index_count;
        self.colors = vec![None; self.height as usize];
        self.dirty = true;
    }

    /// Mark every pixel as needing recomputation.
    pub fn refresh_all(&mut self) {
        self.colors = vec![None; self.height as usize];
        self.dirty = true;
    }

    /// Invalidate colour pixels that cover the given address-index range.
    pub fn refresh_range(&mut self, start_index: u64, end_index: u64) {
        if self.index_count == 0 {
            return;
        }
        let pixel_start = self.index_to_pixel(start_index);
        let pixel_end = self.index_to_pixel(end_index);
        for i in pixel_start..=pixel_end.min(self.height.saturating_sub(1) as usize) {
            if i < self.colors.len() {
                self.colors[i] = None;
            }
        }
        self.dirty = true;
    }

    /// Lazily compute colours using the provided service.
    ///
    /// Returns `true` if any pixels were recomputed.
    pub fn tick(&mut self, service: &dyn OverviewColorService) -> bool {
        if !self.dirty || self.index_count == 0 {
            return false;
        }
        let big_height = self.height as u64;
        for i in 0..self.height as usize {
            if self.colors[i].is_none() {
                let idx = (self.index_count as u128 * i as u128 / big_height as u128) as u64;
                let addr = Address::new(idx);
                self.colors[i] = Some(service.color_for_address(&addr));
            }
        }
        self.dirty = false;
        true
    }

    /// Get the precomputed colour for a pixel row (for painting).
    pub fn get_color(&self, pixel_index: u32) -> (u8, u8, u8, u8) {
        let idx = pixel_index as usize;
        if idx < self.colors.len() {
            self.colors[idx].unwrap_or(DEFAULT_COLOR)
        } else {
            DEFAULT_COLOR
        }
    }

    /// Map a pixel Y-coordinate to a program address index.
    pub fn pixel_to_index(&self, pixel_y: u32) -> u64 {
        if self.height == 0 || self.index_count == 0 {
            return 0;
        }
        (self.index_count as u128 * pixel_y as u128 / self.height as u128) as u64
    }

    /// Map a program address index to a pixel Y-coordinate.
    pub fn index_to_pixel(&self, index: u64) -> usize {
        if self.index_count == 0 {
            return 0;
        }
        ((index as u128 * self.height as u128) / self.index_count as u128) as usize
    }

    /// Current height.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Resize the component (e.g. when the window resizes).
    pub fn set_height(&mut self, new_height: u32) {
        if new_height != self.height {
            self.height = new_height;
            self.colors = vec![None; new_height as usize];
            self.dirty = true;
        }
    }
}

// ---------------------------------------------------------------------------
// OverviewColorPlugin -- manages overview services
// ---------------------------------------------------------------------------

/// Tracks which [`OverviewColorService`] instances are currently visible
/// in the overview margin.
pub struct OverviewColorPlugin {
    /// All known services (by name).
    services: HashMap<String, Box<dyn OverviewColorService>>,
    /// Names of currently active (visible) services.
    active: Vec<String>,
}

impl OverviewColorPlugin {
    /// Create a new empty plugin.
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            active: Vec::new(),
        }
    }

    /// Register a colour service.
    pub fn register_service(&mut self, service: Box<dyn OverviewColorService>) {
        let name = service.name().to_owned();
        self.services.insert(name, service);
    }

    /// Activate a service by name.  Returns `true` if the service exists.
    pub fn activate(&mut self, name: &str) -> bool {
        if self.services.contains_key(name) && !self.active.contains(&name.to_owned()) {
            self.active.push(name.to_owned());
            true
        } else {
            false
        }
    }

    /// Deactivate a service by name.
    pub fn deactivate(&mut self, name: &str) {
        self.active.retain(|n| n != name);
    }

    /// Returns `true` if the named service is currently active.
    pub fn is_active(&self, name: &str) -> bool {
        self.active.iter().any(|n| n == name)
    }

    /// Get a reference to a registered service.
    pub fn service(&self, name: &str) -> Option<&dyn OverviewColorService> {
        self.services.get(name).map(|s| s.as_ref())
    }

    /// List all registered service names.
    pub fn service_names(&self) -> Vec<&str> {
        self.services.keys().map(|s| s.as_str()).collect()
    }

    /// List currently active service names.
    pub fn active_service_names(&self) -> &[String] {
        &self.active
    }

    /// Notify all active services of a program change.
    pub fn set_program(&mut self, program: Option<&Program>) {
        for name in &self.active {
            if let Some(svc) = self.services.get_mut(name) {
                svc.set_program(program);
            }
        }
    }

    /// Serialize active service names for persistence.
    pub fn save_state(&self) -> Vec<String> {
        self.active.clone()
    }

    /// Restore active services from a saved state.
    pub fn load_state(&mut self, names: &[String]) {
        for name in names {
            self.activate(name);
        }
    }
}

impl Default for OverviewColorPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct MockService {
        name: String,
        color: (u8, u8, u8, u8),
    }

    impl MockService {
        fn new(name: &str, color: (u8, u8, u8, u8)) -> Self {
            Self {
                name: name.to_owned(),
                color,
            }
        }
    }

    impl OverviewColorService for MockService {
        fn name(&self) -> &str {
            &self.name
        }
        fn color_for_address(&self, _addr: &Address) -> (u8, u8, u8, u8) {
            self.color
        }
        fn set_program(&mut self, _program: Option<&Program>) {}
        fn program(&self) -> Option<&Program> {
            None
        }
        fn tooltip_text(&self, addr: &Address) -> String {
            format!("addr={:?}", addr)
        }
    }

    #[test]
    fn component_creation() {
        let comp = OverviewColorComponent::new(100);
        assert_eq!(comp.height(), 100);
    }

    #[test]
    fn component_screen_data_changed() {
        let mut comp = OverviewColorComponent::new(50);
        comp.screen_data_changed(1000);
        assert!(comp.dirty);
        assert_eq!(comp.index_count, 1000);
    }

    #[test]
    fn component_pixel_to_index_roundtrip() {
        let mut comp = OverviewColorComponent::new(100);
        comp.screen_data_changed(1000);
        // First pixel maps to index 0
        assert_eq!(comp.pixel_to_index(0), 0);
        // Pixel 50 maps to index 500
        assert_eq!(comp.pixel_to_index(50), 500);
        // Pixel 100 would be out-of-range but maps to index_count
        assert_eq!(comp.pixel_to_index(100), 1000);
    }

    #[test]
    fn component_index_to_pixel() {
        let mut comp = OverviewColorComponent::new(100);
        comp.screen_data_changed(1000);
        assert_eq!(comp.index_to_pixel(0), 0);
        assert_eq!(comp.index_to_pixel(500), 50);
        assert_eq!(comp.index_to_pixel(1000), 100);
    }

    #[test]
    fn component_tick_populates_colors() {
        let mut comp = OverviewColorComponent::new(10);
        comp.screen_data_changed(100);
        let svc = MockService::new("test", (255, 0, 0, 255));
        assert!(comp.tick(&svc));
        assert!(!comp.dirty);
        // All colors should now be red
        for i in 0..10 {
            assert_eq!(comp.get_color(i), (255, 0, 0, 255));
        }
    }

    #[test]
    fn component_tick_noop_when_clean() {
        let mut comp = OverviewColorComponent::new(10);
        comp.screen_data_changed(100);
        let svc = MockService::new("test", (255, 0, 0, 255));
        assert!(comp.tick(&svc)); // first tick
        assert!(!comp.tick(&svc)); // second tick is no-op
    }

    #[test]
    fn component_refresh_range() {
        let mut comp = OverviewColorComponent::new(100);
        comp.screen_data_changed(1000);
        let svc = MockService::new("test", (0, 255, 0, 255));
        comp.tick(&svc);
        // Refresh middle range
        comp.refresh_range(200, 400);
        assert!(comp.dirty);
        // Pixels 20-40 should be None after refresh
        assert!(comp.colors[20].is_none());
        assert!(comp.colors[30].is_none());
        // Pixels outside range should still be set
        assert!(comp.colors[5].is_some());
    }

    #[test]
    fn component_set_height() {
        let mut comp = OverviewColorComponent::new(50);
        comp.set_height(100);
        assert_eq!(comp.height(), 100);
    }

    #[test]
    fn plugin_register_and_list() {
        let mut plugin = OverviewColorPlugin::new();
        plugin.register_service(Box::new(MockService::new("Entropy", (0, 0, 0, 255))));
        plugin.register_service(Box::new(MockService::new("AddrType", (255, 255, 255, 255))));
        assert_eq!(plugin.service_names().len(), 2);
    }

    #[test]
    fn plugin_activate_deactivate() {
        let mut plugin = OverviewColorPlugin::new();
        plugin.register_service(Box::new(MockService::new("S1", (0, 0, 0, 255))));
        assert!(!plugin.is_active("S1"));
        assert!(plugin.activate("S1"));
        assert!(plugin.is_active("S1"));
        plugin.deactivate("S1");
        assert!(!plugin.is_active("S1"));
    }

    #[test]
    fn plugin_activate_nonexistent_returns_false() {
        let mut plugin = OverviewColorPlugin::new();
        assert!(!plugin.activate("nope"));
    }

    #[test]
    fn plugin_save_load_state() {
        let mut plugin = OverviewColorPlugin::new();
        plugin.register_service(Box::new(MockService::new("A", (0, 0, 0, 255))));
        plugin.register_service(Box::new(MockService::new("B", (0, 0, 0, 255))));
        plugin.activate("A");
        plugin.activate("B");
        let saved = plugin.save_state();
        let mut plugin2 = OverviewColorPlugin::new();
        plugin2.register_service(Box::new(MockService::new("A", (0, 0, 0, 255))));
        plugin2.register_service(Box::new(MockService::new("B", (0, 0, 0, 255))));
        plugin2.load_state(&saved);
        assert!(plugin2.is_active("A"));
        assert!(plugin2.is_active("B"));
    }

    #[test]
    fn plugin_service_lookup() {
        let mut plugin = OverviewColorPlugin::new();
        plugin.register_service(Box::new(MockService::new("X", (1, 2, 3, 4))));
        let svc = plugin.service("X").unwrap();
        assert_eq!(svc.color_for_address(&Address::new(0)), (1, 2, 3, 4));
    }
}
