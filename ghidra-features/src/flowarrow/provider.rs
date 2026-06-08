//! Flow Arrow margin provider and plugin.
//!
//! Ported from `ghidra.app.plugin.core.flowarrow.FlowArrowMarginProvider`
//! (755 lines) and `FlowArrowPlugin` (99 lines).
//!
//! The [`FlowArrowMarginProvider`] manages the lifecycle of flow arrows
//! in a listing view: tracking screen position, building arrows from
//! program references, assigning columns, and managing active/selected state.
//!
//! The [`FlowArrowPlugin`] is the top-level plugin that creates providers
//! and manages tool-level options.

use super::{
    FlowArrow, FlowArrowLayout, FlowArrowModel, FlowArrowType,
    LEFT_OFFSET, MAX_DEPTH, MAX_REFS_TO_SHOW,
};
use ghidra_core::Address;
use std::collections::{HashMap, HashSet};

// ============================================================================
// FlowArrowMarginProvider (ported from FlowArrowMarginProvider.java)
// ============================================================================

/// Provider that supplies flow arrow data for the listing margin.
///
/// Ported from `FlowArrowMarginProvider.java`. This is the central
/// coordinator that:
///
/// - Tracks the visible screen range (`screen_top` .. `screen_bottom`)
/// - Maps addresses to pixel positions for arrow rendering
/// - Builds arrows from instruction references (jumps, calls, fallthroughs)
/// - Groups arrows by shared endpoints and assigns column lanes
/// - Manages active arrows (at current cursor) and selected arrows
/// - Caches offscreen arrows to reduce clutter
#[derive(Debug)]
pub struct FlowArrowMarginProvider {
    /// The flow arrow model holding all current arrows.
    model: FlowArrowModel,
    /// Whether the provider is enabled.
    enabled: bool,
    /// Maximum number of columns to display.
    max_columns: usize,
    /// Current cursor address.
    current_addr: Option<Address>,
    /// The top address visible on screen.
    screen_top: Option<Address>,
    /// The bottom address visible on screen.
    screen_bottom: Option<Address>,
    /// Map from address to the start y-pixel of its layout row.
    start_address_to_pixel: HashMap<u64, f64>,
    /// Map from address to the end y-pixel of its layout row.
    end_address_to_pixel: HashMap<u64, f64>,
    /// Arrows manually selected by the user (persists across screen changes).
    selected_arrows: HashSet<ArrowKey>,
    /// Arrows at the current cursor address.
    active_arrows: HashSet<ArrowKey>,
    /// The maximum column assigned in the current view.
    max_column: i32,
    /// Valid state flag (true when program and layout data are available).
    valid_state: bool,
    /// Offscreen arrow cache for reducing clutter.
    offscreen_cache: OffscreenArrowsFlow,
}

/// A key for identifying arrows in sets (start + end + type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ArrowKey {
    start: u64,
    end: u64,
    arrow_type: FlowArrowType,
}

impl ArrowKey {
    fn from_arrow(arrow: &FlowArrow) -> Self {
        Self {
            start: arrow.start.offset,
            end: arrow.end.offset,
            arrow_type: arrow.arrow_type,
        }
    }
}

impl FlowArrowMarginProvider {
    /// Create a new margin provider.
    pub fn new() -> Self {
        Self {
            model: FlowArrowModel::new(),
            enabled: true,
            max_columns: 8,
            current_addr: None,
            screen_top: None,
            screen_bottom: None,
            start_address_to_pixel: HashMap::new(),
            end_address_to_pixel: HashMap::new(),
            selected_arrows: HashSet::new(),
            active_arrows: HashSet::new(),
            max_column: 0,
            valid_state: false,
            offscreen_cache: OffscreenArrowsFlow::new(),
        }
    }

    /// Whether the provider is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the provider.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the maximum number of columns.
    pub fn max_columns(&self) -> usize {
        self.max_columns
    }

    /// Set the maximum number of columns.
    pub fn set_max_columns(&mut self, max: usize) {
        self.max_columns = max;
    }

    /// Get the current cursor address.
    pub fn current_address(&self) -> Option<Address> {
        self.current_addr
    }

    /// Get the top address of the visible screen.
    pub fn screen_top(&self) -> Option<Address> {
        self.screen_top
    }

    /// Get the bottom address of the visible screen.
    pub fn screen_bottom(&self) -> Option<Address> {
        self.screen_bottom
    }

    /// Get the maximum column depth.
    pub fn max_column(&self) -> i32 {
        self.max_column
    }

    /// Add a flow arrow.
    pub fn add_arrow(&mut self, arrow: FlowArrow) {
        self.model.add_arrow(arrow);
    }

    /// Clear all arrows.
    pub fn clear(&mut self) {
        self.model.clear();
        self.active_arrows.clear();
        self.selected_arrows.clear();
        self.max_column = 0;
    }

    /// Get the number of arrows.
    pub fn arrow_count(&self) -> usize {
        self.model.count()
    }

    /// Get all arrows with columns assigned.
    pub fn get_arrows_with_columns(&self) -> Vec<FlowArrow> {
        let mut arrows: Vec<FlowArrow> = self.model.get_arrows().to_vec();
        FlowArrowLayout::assign_columns(&mut arrows);
        arrows.retain(|a| a.column < self.max_columns as i32);
        arrows
    }

    /// Whether an address is on the visible screen.
    ///
    /// Ported from `FlowArrowMarginProvider.isOnScreen(Address)`.
    pub fn is_on_screen(&self, address: Address) -> bool {
        match (self.screen_top, self.screen_bottom) {
            (Some(top), Some(bottom)) => address >= top && address <= bottom,
            _ => true,
        }
    }

    /// Whether an arrow is completely off screen.
    ///
    /// Ported from `FlowArrowMarginProvider.isOffscreen(FlowArrow)`.
    pub fn is_offscreen(&self, arrow: &FlowArrow) -> bool {
        match (self.screen_top, self.screen_bottom) {
            (Some(top), Some(bottom)) => {
                (arrow.start < top && arrow.end < top)
                    || (arrow.start > bottom && arrow.end > bottom)
            }
            _ => true,
        }
    }

    /// Whether an address is below the visible screen.
    ///
    /// Ported from `FlowArrowMarginProvider.isBelowScreen(Address)`.
    pub fn is_below_screen(&self, address: Address) -> bool {
        match self.screen_bottom {
            Some(bottom) => address > bottom,
            _ => true,
        }
    }

    /// Get the start y-pixel for an address.
    ///
    /// Ported from `FlowArrowMarginProvider.getStartPos(Address)`.
    pub fn get_start_pos(&self, addr: Address) -> Option<f64> {
        self.start_address_to_pixel.get(&addr.offset).copied()
    }

    /// Get the end y-pixel for an address.
    ///
    /// Ported from `FlowArrowMarginProvider.getEndPos(Address)`.
    pub fn get_end_pos(&self, addr: Address) -> Option<f64> {
        self.end_address_to_pixel.get(&addr.offset).copied()
    }

    /// Set an arrow as selected or deselected.
    ///
    /// Ported from `FlowArrowMarginProvider.setArrowSelected()`.
    pub fn set_arrow_selected(&mut self, arrow: &FlowArrow, selected: bool) {
        let key = ArrowKey::from_arrow(arrow);
        if selected {
            self.selected_arrows.insert(key);
        } else {
            self.selected_arrows.remove(&key);
        }
    }

    /// Get the flow arrow model.
    pub fn model(&self) -> &FlowArrowModel {
        &self.model
    }

    /// Get mutable access to the flow arrow model.
    pub fn model_mut(&mut self) -> &mut FlowArrowModel {
        &mut self.model
    }

    /// Update the cursor location and refresh active arrows.
    ///
    /// Ported from `FlowArrowMarginProvider.setLocation(ProgramLocation)`.
    pub fn set_location(&mut self, address: Address) {
        self.current_addr = Some(address);
        self.clear_active_arrows();
        self.assign_active_arrows();
    }

    /// Update screen data from the listing panel.
    ///
    /// Ported from `FlowArrowMarginProvider.screenDataChanged()`.
    /// Call this when the listing scrolls or resizes.
    pub fn screen_data_changed(
        &mut self,
        screen_top: Address,
        screen_bottom: Address,
        layout_count: usize,
    ) {
        self.screen_top = Some(screen_top);
        self.screen_bottom = Some(screen_bottom);
        self.valid_state = layout_count > 0;
    }

    /// Set address-to-pixel mappings for the current screen.
    pub fn set_address_pixel_map(
        &mut self,
        start_map: HashMap<u64, f64>,
        end_map: HashMap<u64, f64>,
    ) {
        self.start_address_to_pixel = start_map;
        self.end_address_to_pixel = end_map;
    }

    /// Rebuild arrows from instruction flow analysis.
    ///
    /// This simulates the analysis pass that examines instructions to
    /// determine their control flow targets, as done in
    /// `FlowArrowMarginProvider.getFlowArrowsForScreenInstructions()`.
    pub fn rebuild_from_flow(
        &mut self,
        branches: &[(Address, Address, bool)],
        calls: &[(Address, Address)],
        fallthroughs: &[(Address, Address)],
    ) {
        self.model.clear();
        self.max_column = 0;

        for &(from, to, is_conditional) in branches {
            let arrow_type = if is_conditional {
                FlowArrowType::classify(from, to, true, false)
            } else {
                FlowArrowType::classify(from, to, false, false)
            };
            self.model.add_arrow(FlowArrow::new(from, to, arrow_type));
        }

        for &(from, to) in calls {
            self.model.add_arrow(FlowArrow::new(from, to, FlowArrowType::Call));
        }

        for &(from, to) in fallthroughs {
            self.model.add_arrow(FlowArrow::new(from, to, FlowArrowType::FallThrough));
        }
    }

    /// Full update: rebuild arrows, assign columns, assign active arrows.
    ///
    /// Ported from `FlowArrowMarginProvider.update()`.
    pub fn update(&mut self) {
        if !self.enabled || !self.valid_state {
            return;
        }

        // Reset selected arrows' shapes
        for arrow in self.model.get_arrows_mut() {
            let key = ArrowKey::from_arrow(arrow);
            if self.selected_arrows.contains(&key) {
                arrow.selected = true;
            }
            arrow.reset_shape();
        }

        // Assign columns
        let arrows = self.model.get_arrows_mut();
        FlowArrowLayout::assign_columns_grouped(arrows);

        // Track max column
        self.max_column = arrows.iter().map(|a| a.column).max().unwrap_or(0);

        // Assign active arrows
        self.assign_active_arrows();
    }

    /// Update and signal a repaint needed.
    ///
    /// Ported from `FlowArrowMarginProvider.updateAndRepaint()`.
    pub fn update_and_repaint(&mut self) {
        self.update();
    }

    /// Validate the provider state.
    ///
    /// Ported from `FlowArrowMarginProvider.validateState()`.
    fn validate_state(&mut self) {
        self.valid_state = self.screen_top.is_some()
            && self.screen_bottom.is_some()
            && !self.start_address_to_pixel.is_empty();
    }

    /// Clear active arrows.
    ///
    /// Ported from `FlowArrowMarginProvider.clearActiveArrows()`.
    fn clear_active_arrows(&mut self) {
        for arrow in self.model.get_arrows_mut() {
            if arrow.active {
                arrow.active = false;
                arrow.reset_shape();
            }
        }
        self.active_arrows.clear();
    }

    /// Assign arrows at the current address as active.
    ///
    /// Ported from `FlowArrowMarginProvider.assignActiveArrows()`.
    fn assign_active_arrows(&mut self) {
        if !self.active_arrows.is_empty() {
            // Just reset shapes for existing active arrows
            for arrow in self.model.get_arrows_mut() {
                if arrow.active {
                    arrow.reset_shape();
                }
            }
            return;
        }

        let current = match self.current_addr {
            Some(addr) => addr,
            None => return,
        };

        for arrow in self.model.get_arrows_mut() {
            if arrow.start == current {
                arrow.active = true;
                let key = ArrowKey::from_arrow(arrow);
                self.active_arrows.insert(key);
            }
        }
    }

    /// Get the last address on screen in the given direction.
    ///
    /// Ported from `FlowArrowMarginProvider.getLastAddressOnScreen()`.
    pub fn get_last_address_on_screen(&self, _end: Address, up: bool) -> Option<Address> {
        if up {
            self.screen_top
        } else {
            self.screen_bottom
        }
    }

    /// Dispose of this provider.
    ///
    /// Ported from `FlowArrowMarginProvider.dispose()`.
    pub fn dispose(&mut self) {
        self.model.clear();
        self.selected_arrows.clear();
        self.active_arrows.clear();
        self.start_address_to_pixel.clear();
        self.end_address_to_pixel.clear();
        self.current_addr = None;
        self.screen_top = None;
        self.screen_bottom = None;
    }
}

impl Default for FlowArrowMarginProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// OffscreenArrowsFlow (ported from FlowArrowMarginProvider inner class)
// ============================================================================

/// Cache of offscreen arrows to reduce clutter.
///
/// Ported from `FlowArrowMarginProvider.OffscreenArrowsFlow`. Tracks
/// arrow usage from each start address to limit offscreen arrows.
/// Allows one offscreen arrow above and below for each of the three
/// flow types (conditional, fallthrough, other).
#[derive(Debug, Default)]
struct OffscreenArrowsFlow {
    /// Flows going above the screen, keyed by start address.
    flows_above: HashMap<u64, OffScreenFlow>,
    /// Flows going below the screen, keyed by start address.
    flows_below: HashMap<u64, OffScreenFlow>,
}

impl OffscreenArrowsFlow {
    fn new() -> Self {
        Self::default()
    }

    /// Check if we already have a representative arrow for this start
    /// address going in this direction with this flow type.
    ///
    /// Returns `true` if a duplicate offscreen arrow was found.
    fn exists(
        &mut self,
        start: Address,
        end: Address,
        screen_top: Address,
        screen_bottom: Address,
        arrow_type: FlowArrowType,
    ) -> bool {
        let is_above = end < screen_top;
        let is_below = end > screen_bottom;

        if !(is_above || is_below) {
            return false; // on-screen
        }

        let flows = if is_above {
            &mut self.flows_above
        } else {
            &mut self.flows_below
        };

        let flow = flows.entry(start.offset).or_insert_with(OffScreenFlow::new);
        flow.set_flow(arrow_type)
    }

    fn clear(&mut self) {
        self.flows_above.clear();
        self.flows_below.clear();
    }
}

/// Tracks which flow types have been seen for a given start address.
#[derive(Debug, Default)]
struct OffScreenFlow {
    conditional: bool,
    fallthrough: bool,
    other: bool,
}

impl OffScreenFlow {
    fn new() -> Self {
        Self::default()
    }

    /// Record a flow type and return whether it was already set.
    fn set_flow(&mut self, arrow_type: FlowArrowType) -> bool {
        if arrow_type.is_conditional() {
            let was_set = self.conditional;
            self.conditional = true;
            was_set
        } else if arrow_type.is_fallthrough() {
            let was_set = self.fallthrough;
            self.fallthrough = true;
            was_set
        } else {
            let was_set = self.other;
            self.other = true;
            was_set
        }
    }
}

// ============================================================================
// FlowArrowPlugin (ported from FlowArrowPlugin.java)
// ============================================================================

/// Plugin managing flow arrow display in the code browser.
///
/// Ported from `FlowArrowPlugin.java`. This is the top-level entry
/// point that creates margin providers and manages tool-level options
/// such as arrow colors.
///
/// In the Java version, this plugin:
/// - Provides the `ListingMarginProviderService` to create margin providers
/// - Registers theme color bindings for arrow colors
/// - Handles program lifecycle events
#[derive(Debug)]
pub struct FlowArrowPlugin {
    /// Plugin name.
    name: String,
    /// The margin providers created by this plugin.
    providers: Vec<usize>,
    /// Whether the plugin is active.
    active: bool,
    /// Current program name.
    current_program: Option<String>,
    /// Non-active arrow color (R, G, B).
    pub color_non_active: (u8, u8, u8),
    /// Active arrow color (R, G, B).
    pub color_active: (u8, u8, u8),
    /// Selected arrow color (R, G, B).
    pub color_selected: (u8, u8, u8),
}

impl FlowArrowPlugin {
    /// Create a new flow arrow plugin.
    ///
    /// Ported from `FlowArrowPlugin(PluginTool)`.
    pub fn new() -> Self {
        Self {
            name: "FlowArrowPlugin".to_string(),
            providers: Vec::new(),
            active: false,
            current_program: None,
            color_non_active: (128, 128, 128),  // gray
            color_active: (0, 128, 255),         // blue
            color_selected: (255, 128, 0),       // orange
        }
    }

    /// Plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Activate the plugin.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivate the plugin.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Whether the plugin is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Set the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.current_program = program;
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Register a provider with this plugin.
    ///
    /// Ported from `FlowArrowPlugin.createMarginProvider()`.
    pub fn create_margin_provider(&mut self) -> usize {
        let id = self.providers.len();
        self.providers.push(id);
        id
    }

    /// Remove a provider from this plugin.
    ///
    /// Ported from `FlowArrowPlugin.remove(FlowArrowMarginProvider)`.
    pub fn remove_provider(&mut self, id: usize) {
        self.providers.retain(|&p| p != id);
    }

    /// Get the number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Dispose of this plugin.
    ///
    /// Ported from `FlowArrowPlugin.dispose()`.
    pub fn dispose(&mut self) {
        self.providers.clear();
        self.active = false;
        self.current_program = None;
    }
}

impl Default for FlowArrowPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------------
    // FlowArrowMarginProvider tests
    // ----------------------------------------------------------------

    #[test]
    fn test_provider_basic() {
        let provider = FlowArrowMarginProvider::new();
        assert!(provider.is_enabled());
        assert_eq!(provider.max_columns(), 8);
        assert_eq!(provider.arrow_count(), 0);
        assert!(provider.current_address().is_none());
    }

    #[test]
    fn test_provider_arrows() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward,
        ));
        provider.add_arrow(FlowArrow::new(
            Address::new(0x3000), Address::new(0x1000), FlowArrowType::JumpBackward,
        ));
        assert_eq!(provider.arrow_count(), 2);
    }

    #[test]
    fn test_provider_screen_tracking() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.screen_data_changed(
            Address::new(0x1000),
            Address::new(0x5000),
            100,
        );
        assert!(provider.is_on_screen(Address::new(0x2000)));
        assert!(!provider.is_on_screen(Address::new(0x6000)));
        assert!(!provider.is_on_screen(Address::new(0x0500)));
    }

    #[test]
    fn test_provider_offscreen() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.screen_data_changed(
            Address::new(0x1000),
            Address::new(0x5000),
            100,
        );

        let on_screen = FlowArrow::new(
            Address::new(0x2000), Address::new(0x3000), FlowArrowType::JumpForward,
        );
        assert!(!provider.is_offscreen(&on_screen));

        let off_above = FlowArrow::new(
            Address::new(0x0500), Address::new(0x0600), FlowArrowType::JumpForward,
        );
        assert!(provider.is_offscreen(&off_above));

        let off_below = FlowArrow::new(
            Address::new(0x6000), Address::new(0x7000), FlowArrowType::JumpForward,
        );
        assert!(provider.is_offscreen(&off_below));
    }

    #[test]
    fn test_provider_below_screen() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.screen_data_changed(
            Address::new(0x1000),
            Address::new(0x5000),
            100,
        );
        assert!(provider.is_below_screen(Address::new(0x6000)));
        assert!(!provider.is_below_screen(Address::new(0x3000)));
    }

    #[test]
    fn test_provider_location() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward,
        ));
        provider.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x3000), FlowArrowType::ConditionalForward,
        ));
        provider.set_location(Address::new(0x1000));

        let arrows = provider.model().get_arrows();
        let active_count = arrows.iter().filter(|a| a.active).count();
        assert_eq!(active_count, 2);
    }

    #[test]
    fn test_provider_location_change() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward,
        ));
        provider.set_location(Address::new(0x1000));
        assert!(provider.model().get_arrows()[0].active);

        // Move to different address -- arrow should become inactive
        provider.set_location(Address::new(0x3000));
        assert!(!provider.model().get_arrows()[0].active);
    }

    #[test]
    fn test_provider_selected_arrows() {
        let mut provider = FlowArrowMarginProvider::new();
        let arrow = FlowArrow::new(
            Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward,
        );
        provider.add_arrow(arrow.clone());
        provider.set_arrow_selected(&arrow, true);

        // Selection is tracked by key
        let key = ArrowKey::from_arrow(&arrow);
        assert!(provider.selected_arrows.contains(&key));
    }

    #[test]
    fn test_provider_rebuild_from_flow() {
        let mut provider = FlowArrowMarginProvider::new();
        let branches = vec![
            (Address::new(0x1000), Address::new(0x2000), true),
            (Address::new(0x3000), Address::new(0x1000), false),
        ];
        let calls = vec![(Address::new(0x4000), Address::new(0x5000))];
        let fallthroughs = vec![(Address::new(0x1000), Address::new(0x1004))];

        provider.rebuild_from_flow(&branches, &calls, &fallthroughs);
        assert_eq!(provider.arrow_count(), 4);
    }

    #[test]
    fn test_provider_update() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.screen_data_changed(
            Address::new(0x1000),
            Address::new(0x5000),
            100,
        );
        provider.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward,
        ));
        provider.set_location(Address::new(0x1000));
        provider.update();

        // After update, arrow should be active and have a column assigned
        let arrow = &provider.model().get_arrows()[0];
        assert!(arrow.active);
        assert!(arrow.column >= 0);
    }

    #[test]
    fn test_provider_clear() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward,
        ));
        assert_eq!(provider.arrow_count(), 1);
        provider.clear();
        assert_eq!(provider.arrow_count(), 0);
    }

    #[test]
    fn test_provider_enabled() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.set_enabled(false);
        assert!(!provider.is_enabled());
        provider.set_enabled(true);
        assert!(provider.is_enabled());
    }

    #[test]
    fn test_provider_pixel_map() {
        let mut provider = FlowArrowMarginProvider::new();
        let mut start_map = HashMap::new();
        start_map.insert(0x1000_u64, 10.0_f64);
        start_map.insert(0x2000_u64, 50.0_f64);
        let mut end_map = HashMap::new();
        end_map.insert(0x1000_u64, 20.0_f64);
        end_map.insert(0x2000_u64, 60.0_f64);

        provider.set_address_pixel_map(start_map, end_map);
        assert_eq!(provider.get_start_pos(Address::new(0x1000)), Some(10.0));
        assert_eq!(provider.get_end_pos(Address::new(0x2000)), Some(60.0));
        assert_eq!(provider.get_start_pos(Address::new(0x9999)), None);
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.add_arrow(FlowArrow::new(
            Address::new(0x1000), Address::new(0x2000), FlowArrowType::JumpForward,
        ));
        provider.screen_data_changed(
            Address::new(0x1000), Address::new(0x5000), 100,
        );
        provider.dispose();
        assert_eq!(provider.arrow_count(), 0);
        assert!(provider.screen_top().is_none());
    }

    #[test]
    fn test_provider_last_address() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.screen_data_changed(
            Address::new(0x1000), Address::new(0x5000), 100,
        );
        assert_eq!(
            provider.get_last_address_on_screen(Address::new(0x3000), true),
            Some(Address::new(0x1000)),
        );
        assert_eq!(
            provider.get_last_address_on_screen(Address::new(0x3000), false),
            Some(Address::new(0x5000)),
        );
    }

    // ----------------------------------------------------------------
    // OffscreenArrowsFlow tests
    // ----------------------------------------------------------------

    #[test]
    fn test_offscreen_arrows_flow() {
        let mut cache = OffscreenArrowsFlow::new();
        let top = Address::new(0x1000);
        let bottom = Address::new(0x5000);

        // First offscreen arrow should not be a duplicate
        let dup = cache.exists(
            Address::new(0x2000), Address::new(0x0500),
            top, bottom, FlowArrowType::JumpForward,
        );
        assert!(!dup);

        // Same direction/type from same start => duplicate
        let dup = cache.exists(
            Address::new(0x2000), Address::new(0x0600),
            top, bottom, FlowArrowType::JumpForward,
        );
        assert!(dup);

        // Different type from same start => not duplicate
        let dup = cache.exists(
            Address::new(0x2000), Address::new(0x0700),
            top, bottom, FlowArrowType::ConditionalForward,
        );
        assert!(!dup);
    }

    #[test]
    fn test_offscreen_arrows_flow_on_screen() {
        let mut cache = OffscreenArrowsFlow::new();
        let top = Address::new(0x1000);
        let bottom = Address::new(0x5000);

        // On-screen arrow should never be a duplicate
        let dup = cache.exists(
            Address::new(0x2000), Address::new(0x3000),
            top, bottom, FlowArrowType::JumpForward,
        );
        assert!(!dup);
    }

    #[test]
    fn test_offscreen_flow_clear() {
        let mut cache = OffscreenArrowsFlow::new();
        let top = Address::new(0x1000);
        let bottom = Address::new(0x5000);

        cache.exists(
            Address::new(0x2000), Address::new(0x0500),
            top, bottom, FlowArrowType::JumpForward,
        );
        cache.clear();

        // After clear, same arrow should not be a duplicate
        let dup = cache.exists(
            Address::new(0x2000), Address::new(0x0500),
            top, bottom, FlowArrowType::JumpForward,
        );
        assert!(!dup);
    }

    // ----------------------------------------------------------------
    // FlowArrowPlugin tests
    // ----------------------------------------------------------------

    #[test]
    fn test_plugin_lifecycle() {
        let mut plugin = FlowArrowPlugin::new();
        assert_eq!(plugin.name(), "FlowArrowPlugin");
        assert!(!plugin.is_active());
        assert!(plugin.current_program().is_none());

        plugin.set_program(Some("test.exe".into()));
        assert_eq!(plugin.current_program(), Some("test.exe"));

        plugin.activate();
        assert!(plugin.is_active());

        plugin.deactivate();
        assert!(!plugin.is_active());
    }

    #[test]
    fn test_plugin_providers() {
        let mut plugin = FlowArrowPlugin::new();
        let id1 = plugin.create_margin_provider();
        let id2 = plugin.create_margin_provider();
        assert_eq!(plugin.provider_count(), 2);

        plugin.remove_provider(id1);
        assert_eq!(plugin.provider_count(), 1);
    }

    #[test]
    fn test_plugin_colors() {
        let plugin = FlowArrowPlugin::new();
        assert_eq!(plugin.color_non_active, (128, 128, 128));
        assert_eq!(plugin.color_active, (0, 128, 255));
        assert_eq!(plugin.color_selected, (255, 128, 0));
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = FlowArrowPlugin::new();
        plugin.create_margin_provider();
        plugin.create_margin_provider();
        plugin.set_program(Some("test.exe".into()));
        plugin.activate();

        plugin.dispose();
        assert_eq!(plugin.provider_count(), 0);
        assert!(plugin.current_program().is_none());
        assert!(!plugin.is_active());
    }
}
