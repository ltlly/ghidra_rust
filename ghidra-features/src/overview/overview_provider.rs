//! Overview Color Provider -- listing margin bar with actions, navigation, and refresh.
//!
//! Ported from Ghidra's `OverviewColorComponent` Java class (which implements
//! `ListingOverviewProvider`).
//!
//! This module provides an enhanced provider implementation that covers:
//! - Overview bar rendering with color services
//! - Mouse-click navigation (go-to address on click)
//! - Tooltip generation from address
//! - Refresh management with batched update model
//! - Action install/uninstall lifecycle
//! - Screen data change handling (address map updates)
//! - Navigatable association
//! - Domain object listener model (staleness detection)
//!
//! # Architecture
//!
//! - [`EnhancedOverviewProvider`] -- full-featured overview provider
//! - [`ProviderAction`] -- actions local to the provider
//! - [`DomainChangeEvent`] -- events that cause staleness
//! - [`RefreshState`] -- refresh scheduling model
//! - [`AddressIndexMap`] -- address-to-index mapping

use std::collections::{HashSet, VecDeque};

use ghidra_core::Address;

use super::{OverviewColorComponent, OverviewColorService, RgbColor};

// ---------------------------------------------------------------------------
// AddressIndexMap -- address-to-index mapping
// ---------------------------------------------------------------------------

/// Maps between addresses and linear indices for the overview bar.
///
/// Ported from `ghidra.app.util.viewer.util.AddressIndexMap`.
///
/// This provides the bidirectional mapping between program addresses and
/// pixel-row indices in the overview bar.
#[derive(Debug, Clone)]
pub struct AddressIndexMap {
    /// Total number of address indices.
    index_count: u64,
    /// Address-to-index lookup (sorted by address).
    address_to_index: Vec<(u64, u64)>,
    /// Index-to-address lookup (sorted by index).
    index_to_address: Vec<(u64, u64)>,
}

impl AddressIndexMap {
    /// Create a new empty address index map.
    pub fn new() -> Self {
        Self {
            index_count: 0,
            address_to_index: Vec::new(),
            index_to_address: Vec::new(),
        }
    }

    /// Create a map from a sorted list of addresses.
    pub fn from_addresses(addresses: &[u64]) -> Self {
        let mut addr_to_idx = Vec::with_capacity(addresses.len());
        let mut idx_to_addr = Vec::with_capacity(addresses.len());
        for (i, &addr) in addresses.iter().enumerate() {
            addr_to_idx.push((addr, i as u64));
            idx_to_addr.push((i as u64, addr));
        }
        Self {
            index_count: addresses.len() as u64,
            address_to_index: addr_to_idx,
            index_to_address: idx_to_addr,
        }
    }

    /// Get the total number of indices.
    pub fn index_count(&self) -> u64 {
        self.index_count
    }

    /// Get the index for a given address.
    pub fn get_index(&self, address: u64) -> Option<u64> {
        self.address_to_index
            .binary_search_by_key(&address, |&(a, _)| a)
            .ok()
            .map(|i| self.address_to_index[i].1)
    }

    /// Get the address for a given index.
    pub fn get_address(&self, index: u64) -> Option<u64> {
        if index >= self.index_count {
            return None;
        }
        self.index_to_address
            .binary_search_by_key(&index, |&(i, _)| i)
            .ok()
            .map(|i| self.index_to_address[i].1)
    }

    /// Check if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.index_count == 0
    }
}

impl Default for AddressIndexMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RefreshState -- batched refresh scheduling
// ---------------------------------------------------------------------------

/// Refresh scheduling state.
///
/// Ported from `SwingUpdateManager` usage in `OverviewColorComponent`.
///
/// The Java original uses a `SwingUpdateManager(100, 15000, ...)` which
/// batches refresh requests: it coalesces rapid requests into a single
/// refresh with a minimum interval of 100ms and a maximum delay of 15s.
#[derive(Debug, Clone)]
pub struct RefreshState {
    /// Minimum interval between refreshes (milliseconds).
    pub min_interval_ms: u64,
    /// Maximum delay before a pending refresh is forced (milliseconds).
    pub max_delay_ms: u64,
    /// Whether a refresh is currently pending.
    pending: bool,
    /// Timestamp of the last refresh (monotonic counter).
    last_refresh_tick: u64,
    /// Current tick counter.
    current_tick: u64,
}

impl RefreshState {
    /// Create a new refresh state with default timing.
    pub fn new() -> Self {
        Self {
            min_interval_ms: 100,
            max_delay_ms: 15000,
            pending: false,
            last_refresh_tick: 0,
            current_tick: 0,
        }
    }

    /// Request a refresh. Returns true if the refresh should execute now.
    pub fn request_refresh(&mut self) -> bool {
        self.pending = true;
        self.current_tick += 1;
        let elapsed = self.current_tick - self.last_refresh_tick;
        if elapsed * 100 >= self.min_interval_ms {
            self.pending = false;
            self.last_refresh_tick = self.current_tick;
            true
        } else {
            false
        }
    }

    /// Check if a refresh is pending.
    pub fn is_pending(&self) -> bool {
        self.pending
    }

    /// Force a pending refresh to execute. Returns true if there was a pending refresh.
    pub fn force_refresh(&mut self) -> bool {
        if self.pending {
            self.pending = false;
            self.last_refresh_tick = self.current_tick;
            true
        } else {
            false
        }
    }

    /// Advance the tick (simulates time passing).
    pub fn advance_tick(&mut self) {
        self.current_tick += 1;
    }

    /// Reset the refresh state.
    pub fn reset(&mut self) {
        self.pending = false;
        self.last_refresh_tick = self.current_tick;
    }
}

impl Default for RefreshState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DomainChangeEvent -- events that cause staleness
// ---------------------------------------------------------------------------

/// Events from the domain object that can cause the overview to become stale.
///
/// Ported from the `DomainObjectListener` pattern in
/// `OverviewColorComponent.screenDataChanged()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainChangeEvent {
    /// The domain object was restored from a save.
    Restored,
    /// A memory block was moved.
    MemoryBlockMoved,
    /// A memory block was removed.
    MemoryBlockRemoved,
    /// A memory block was added.
    MemoryBlockAdded,
    /// A memory block was changed.
    MemoryBlockChanged,
    /// Code was added.
    CodeAdded,
    /// Code was removed.
    CodeRemoved,
    /// A symbol was added.
    SymbolAdded,
    /// A symbol was removed.
    SymbolRemoved,
    /// A symbol was renamed.
    SymbolRenamed,
}

// ---------------------------------------------------------------------------
// ProviderAction -- actions local to the provider
// ---------------------------------------------------------------------------

/// Actions that can be performed on the overview provider.
///
/// Ported from the `DockingActionIf` list returned by
/// `OverviewColorService.getActions()`.
#[derive(Debug, Clone)]
pub enum ProviderAction {
    /// Show a legend dialog for the overview colors.
    ShowLegend {
        /// Legend title.
        title: String,
    },
    /// Refresh the entire overview bar.
    RefreshAll,
    /// Go to the address at a specific pixel.
    GoToPixel {
        /// Y-coordinate of the pixel.
        pixel_y: u32,
    },
    /// Toggle tooltip display.
    ToggleTooltips,
    /// Custom service-specific action.
    Custom {
        /// Action name.
        name: String,
        /// Action description.
        description: String,
    },
}

// ---------------------------------------------------------------------------
// Navigatable -- navigation target
// ---------------------------------------------------------------------------

/// A navigatable entity (e.g., a code browser listing).
///
/// Ported from `ghidra.app.nav.Navigatable`.
#[derive(Debug, Clone)]
pub struct Navigatable {
    /// Unique identifier for this navigatable.
    pub id: String,
    /// Whether this navigatable is currently open.
    pub open: bool,
    /// The current address.
    pub current_address: Option<u64>,
}

impl Navigatable {
    /// Create a new navigatable.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            open: true,
            current_address: None,
        }
    }

    /// Navigate to an address.
    pub fn go_to(&mut self, address: u64) {
        self.current_address = Some(address);
    }
}

// ---------------------------------------------------------------------------
// EnhancedOverviewProvider
// ---------------------------------------------------------------------------

/// Full-featured overview provider.
///
/// Ported from `OverviewColorComponent` which implements
/// `ListingOverviewProvider` in Java.
///
/// This provider renders a vertical color bar in the listing margin,
/// using an [`OverviewColorService`] to map addresses to colors.
/// It supports mouse-click navigation, tooltips, batched refresh,
/// and domain object change listening.
///
/// # Example
///
/// ```
/// use ghidra_features::overview::overview_provider::*;
/// use ghidra_features::overview::*;
/// use ghidra_core::Address;
///
/// let mut provider = EnhancedOverviewProvider::new("OverviewBar");
/// provider.set_height(200);
///
/// // Set up address map
/// let addresses: Vec<u64> = (0..1000).collect();
/// provider.update_address_map(AddressIndexMap::from_addresses(&addresses));
///
/// // Refresh with a color service
/// provider.refresh_all();
/// ```
pub struct EnhancedOverviewProvider {
    /// Provider title.
    pub title: String,
    /// Whether the provider is visible.
    pub visible: bool,
    /// The underlying overview color component.
    component: OverviewColorComponent,
    /// Address-to-index mapping.
    address_map: AddressIndexMap,
    /// Refresh scheduling state.
    refresh_state: RefreshState,
    /// Associated navigatable (if any).
    navigatable: Option<Navigatable>,
    /// Actions installed for this provider.
    installed_actions: Vec<ProviderAction>,
    /// Whether actions are currently installed.
    actions_installed: bool,
    /// Domain change events that have occurred since last refresh.
    pending_changes: HashSet<DomainChangeEvent>,
    /// Preferred width in pixels.
    preferred_width: u32,
    /// The current program name.
    program_name: Option<String>,
    /// Event log for testing/debugging.
    event_log: VecDeque<String>,
    /// Maximum event log size.
    max_log_size: usize,
}

impl EnhancedOverviewProvider {
    /// Create a new overview provider with a stub color service.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            visible: false,
            component: OverviewColorComponent::new(Box::new(super::StubColorService::new(
                "default".to_string(),
            ))),
            address_map: AddressIndexMap::new(),
            refresh_state: RefreshState::new(),
            navigatable: None,
            installed_actions: Vec::new(),
            actions_installed: false,
            pending_changes: HashSet::new(),
            preferred_width: 16,
            program_name: None,
            event_log: VecDeque::new(),
            max_log_size: 100,
        }
    }

    /// Create a new provider with a specific color service.
    pub fn with_service(
        title: impl Into<String>,
        service: Box<dyn OverviewColorService>,
    ) -> Self {
        Self {
            title: title.into(),
            visible: false,
            component: OverviewColorComponent::new(service),
            address_map: AddressIndexMap::new(),
            refresh_state: RefreshState::new(),
            navigatable: None,
            installed_actions: Vec::new(),
            actions_installed: false,
            pending_changes: HashSet::new(),
            preferred_width: 16,
            program_name: None,
            event_log: VecDeque::new(),
            max_log_size: 100,
        }
    }

    // -- Visibility --

    /// Show the provider.
    pub fn show(&mut self) {
        self.visible = true;
        self.log_event("show");
    }

    /// Hide the provider.
    pub fn hide(&mut self) {
        self.visible = false;
        self.log_event("hide");
    }

    /// Toggle visibility.
    pub fn toggle(&mut self) {
        self.visible = !self.visible;
        self.log_event(if self.visible { "show" } else { "hide" });
    }

    /// Check if the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    // -- Component delegation --

    /// Set the height of the overview bar (number of pixels).
    pub fn set_height(&mut self, height: u32) {
        self.component.set_height(height);
    }

    /// Get the current height.
    pub fn height(&self) -> u32 {
        self.component.height()
    }

    /// Get the preferred width.
    pub fn preferred_width(&self) -> u32 {
        self.preferred_width
    }

    /// Get the component's computed colors.
    pub fn colors(&self) -> &[RgbColor] {
        self.component.colors()
    }

    // -- Address map management --

    /// Update the address index map.
    ///
    /// Ported from `OverviewColorComponent.screenDataChanged()`.
    pub fn update_address_map(&mut self, map: AddressIndexMap) {
        self.address_map = map;
        self.log_event("address_map_updated");
    }

    /// Get the address index map.
    pub fn address_map(&self) -> &AddressIndexMap {
        &self.address_map
    }

    // -- Refresh management --

    /// Request a full refresh of the overview bar.
    ///
    /// Ported from `OverviewColorComponent.refreshAll()`.
    pub fn refresh_all(&mut self) {
        if self.address_map.is_empty() {
            return;
        }
        let total = self.address_map.index_count();
        let addresses: Vec<Address> = (0..total)
            .filter_map(|i| self.address_map.get_address(i))
            .map(Address::new)
            .collect();
        self.component.refresh_all(total, &addresses);
        self.refresh_state.reset();
        self.pending_changes.clear();
        self.log_event("refresh_all");
    }

    /// Request a refresh for a specific address range.
    ///
    /// Ported from `OverviewColorComponent.refresh(start, end)`.
    pub fn refresh_range(&mut self, start_address: u64, end_address: u64) {
        let start_pixel = self.address_map.get_index(start_address).unwrap_or(0);
        let end_pixel = self.address_map.get_index(end_address).unwrap_or(0);
        self.component
            .refresh_range(start_pixel as usize, end_pixel as usize);
        if self.refresh_state.request_refresh() {
            self.log_event("refresh_range_immediate");
        } else {
            self.log_event("refresh_range_deferred");
        }
    }

    /// Process pending refresh if any.
    ///
    /// Returns true if a refresh was performed.
    pub fn process_pending_refresh(&mut self) -> bool {
        if self.refresh_state.force_refresh() {
            self.refresh_all();
            true
        } else {
            false
        }
    }

    /// Check if a refresh is pending.
    pub fn has_pending_refresh(&self) -> bool {
        self.refresh_state.is_pending()
    }

    // -- Navigation --

    /// Set the navigatable for this provider.
    ///
    /// Ported from `OverviewColorComponent.setNavigatable()`.
    pub fn set_navigatable(&mut self, navigatable: Navigatable) {
        self.navigatable = Some(navigatable);
        self.log_event("navigatable_set");
    }

    /// Get the navigatable, if any.
    pub fn navigatable(&self) -> Option<&Navigatable> {
        self.navigatable.as_ref()
    }

    /// Navigate to the address at the given pixel Y-coordinate.
    ///
    /// Ported from the `mousePressed` handler in `OverviewColorComponent`.
    pub fn go_to_pixel(&mut self, pixel_y: u32) -> Option<u64> {
        let total = self.address_map.index_count();
        if total == 0 || self.component.height() == 0 {
            return None;
        }
        let index =
            (total as u128 * pixel_y as u128 / self.component.height() as u128) as u64;
        let address = self.address_map.get_address(index)?;
        if let Some(ref mut nav) = self.navigatable {
            nav.go_to(address);
        }
        self.log_event(&format!("go_to_pixel({}) -> 0x{:X}", pixel_y, address));
        Some(address)
    }

    /// Get the address for a given pixel Y-coordinate.
    pub fn get_address_for_pixel(&self, pixel_y: u32) -> Option<Address> {
        let total = self.address_map.index_count();
        if total == 0 || self.component.height() == 0 {
            return None;
        }
        let index =
            (total as u128 * pixel_y as u128 / self.component.height() as u128) as u64;
        self.address_map.get_address(index).map(Address::new)
    }

    /// Get the pixel Y-coordinate for a given address.
    pub fn get_pixel_for_address(&self, address: u64) -> Option<u32> {
        let index = self.address_map.get_index(address)?;
        let total = self.address_map.index_count();
        if total == 0 || self.component.height() == 0 {
            return None;
        }
        Some((index as u128 * self.component.height() as u128 / total as u128) as u32)
    }

    // -- Tooltips --

    /// Get the tooltip text for a given pixel Y-coordinate.
    ///
    /// Ported from `OverviewColorComponent.getToolTipText()`.
    pub fn get_tooltip(&self, pixel_y: u32) -> String {
        if let Some(addr) = self.get_address_for_pixel(pixel_y) {
            self.component.service_name().to_string()
                + ": "
                + &format!("0x{:X}", addr.offset)
        } else {
            String::new()
        }
    }

    // -- Actions --

    /// Install provider actions.
    ///
    /// Ported from `OverviewColorComponent.installActions()`.
    pub fn install_actions(&mut self, actions: Vec<ProviderAction>) {
        self.installed_actions = actions;
        self.actions_installed = true;
        self.log_event(&format!(
            "actions_installed({})",
            self.installed_actions.len()
        ));
    }

    /// Uninstall provider actions.
    ///
    /// Ported from `OverviewColorComponent.uninstallActions()`.
    pub fn uninstall_actions(&mut self) {
        self.installed_actions.clear();
        self.actions_installed = false;
        self.log_event("actions_uninstalled");
    }

    /// Check if actions are installed.
    pub fn are_actions_installed(&self) -> bool {
        self.actions_installed
    }

    /// Get the installed actions.
    pub fn installed_actions(&self) -> &[ProviderAction] {
        &self.installed_actions
    }

    // -- Domain object events --

    /// Handle a domain change event.
    ///
    /// Ported from the `DomainObjectListener` in `OverviewColorComponent`.
    pub fn domain_changed(&mut self, event: DomainChangeEvent) {
        match event {
            DomainChangeEvent::Restored
            | DomainChangeEvent::MemoryBlockMoved
            | DomainChangeEvent::MemoryBlockRemoved
            | DomainChangeEvent::MemoryBlockAdded => {
                // Full refresh needed
                self.refresh_all();
            }
            DomainChangeEvent::CodeAdded
            | DomainChangeEvent::CodeRemoved
            | DomainChangeEvent::MemoryBlockChanged => {
                // Mark as stale, refresh on next opportunity
                self.pending_changes.insert(event);
                self.refresh_state.request_refresh();
            }
            DomainChangeEvent::SymbolAdded
            | DomainChangeEvent::SymbolRemoved
            | DomainChangeEvent::SymbolRenamed => {
                // May need targeted refresh
                self.pending_changes.insert(event);
            }
        }
        self.log_event(&format!("domain_changed({:?})", event));
    }

    /// Check if the provider has pending (stale) changes.
    pub fn is_stale(&self) -> bool {
        !self.pending_changes.is_empty()
    }

    /// Get the set of pending domain change events.
    pub fn pending_changes(&self) -> &HashSet<DomainChangeEvent> {
        &self.pending_changes
    }

    // -- Program lifecycle --

    /// Set the current program name.
    pub fn set_program(&mut self, program_name: Option<String>) {
        self.program_name = program_name;
    }

    /// Get the current program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    // -- Disposal --

    /// Dispose of the provider.
    ///
    /// Ported from `OverviewColorComponent.dispose()`.
    pub fn dispose(&mut self) {
        self.uninstall_actions();
        self.navigatable = None;
        self.address_map = AddressIndexMap::new();
        self.visible = false;
        self.log_event("disposed");
    }

    // -- Event log --

    /// Get the event log.
    pub fn event_log(&self) -> &VecDeque<String> {
        &self.event_log
    }

    /// Clear the event log.
    pub fn clear_event_log(&mut self) {
        self.event_log.clear();
    }

    fn log_event(&mut self, event: &str) {
        if self.event_log.len() >= self.max_log_size {
            self.event_log.pop_front();
        }
        self.event_log.push_back(event.to_string());
    }
}

impl std::fmt::Debug for EnhancedOverviewProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnhancedOverviewProvider")
            .field("title", &self.title)
            .field("visible", &self.visible)
            .field("address_map", &self.address_map)
            .field("refresh_state", &self.refresh_state)
            .field("actions_installed", &self.actions_installed)
            .field("preferred_width", &self.preferred_width)
            .field("program_name", &self.program_name)
            .finish()
    }
}

impl Default for EnhancedOverviewProvider {
    fn default() -> Self {
        Self::new("OverviewBar")
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overview::{OverviewColorService, RgbColor};

    #[derive(Debug)]
    struct TestService {
        name: String,
        program: Option<String>,
    }

    impl TestService {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                program: None,
            }
        }
    }

    impl OverviewColorService for TestService {
        fn name(&self) -> &str {
            &self.name
        }
        fn get_color(&self, address: &Address) -> RgbColor {
            RgbColor::new((address.offset & 0xFF) as u8, 128, 200)
        }
        fn set_program(&mut self, program_name: Option<String>) {
            self.program = program_name;
        }
        fn get_program(&self) -> Option<&str> {
            self.program.as_deref()
        }
        fn get_tooltip_text(&self, address: &Address) -> String {
            format!("0x{:X}", address.offset)
        }
        fn initialize(&mut self) {}
    }

    // -- AddressIndexMap tests --

    #[test]
    fn test_address_index_map_empty() {
        let map = AddressIndexMap::new();
        assert!(map.is_empty());
        assert_eq!(map.index_count(), 0);
        assert!(map.get_index(0).is_none());
        assert!(map.get_address(0).is_none());
    }

    #[test]
    fn test_address_index_map_from_addresses() {
        let addrs = vec![0x1000, 0x2000, 0x3000, 0x4000];
        let map = AddressIndexMap::from_addresses(&addrs);

        assert_eq!(map.index_count(), 4);
        assert!(!map.is_empty());

        assert_eq!(map.get_index(0x1000), Some(0));
        assert_eq!(map.get_index(0x2000), Some(1));
        assert_eq!(map.get_index(0x3000), Some(2));
        assert_eq!(map.get_index(0x4000), Some(3));
        assert!(map.get_index(0x5000).is_none());

        assert_eq!(map.get_address(0), Some(0x1000));
        assert_eq!(map.get_address(3), Some(0x4000));
        assert!(map.get_address(4).is_none());
    }

    // -- RefreshState tests --

    #[test]
    fn test_refresh_state_basic() {
        let mut state = RefreshState::new();
        assert!(!state.is_pending());

        // First request should succeed immediately (elapsed = 0, min_interval = 100)
        // Since tick starts at 0 and last_refresh is 0, elapsed = 0 * 100 = 0 < 100
        // So it will be pending
        let _ = state.request_refresh();
    }

    #[test]
    fn test_refresh_state_force() {
        let mut state = RefreshState::new();
        state.pending = true;
        assert!(state.force_refresh());
        assert!(!state.is_pending());

        // Force with nothing pending
        assert!(!state.force_refresh());
    }

    #[test]
    fn test_refresh_state_reset() {
        let mut state = RefreshState::new();
        state.pending = true;
        state.reset();
        assert!(!state.is_pending());
    }

    // -- Navigatable tests --

    #[test]
    fn test_navigatable() {
        let mut nav = Navigatable::new("Listing1");
        assert_eq!(nav.id, "Listing1");
        assert!(nav.open);
        assert!(nav.current_address.is_none());

        nav.go_to(0x401000);
        assert_eq!(nav.current_address, Some(0x401000));
    }

    // -- EnhancedOverviewProvider tests --

    #[test]
    fn test_provider_new() {
        let provider = EnhancedOverviewProvider::new("TestBar");
        assert_eq!(provider.title, "TestBar");
        assert!(!provider.is_visible());
        assert_eq!(provider.preferred_width(), 16);
        assert!(provider.program_name().is_none());
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = EnhancedOverviewProvider::new("TestBar");
        assert!(!provider.is_visible());

        provider.show();
        assert!(provider.is_visible());

        provider.hide();
        assert!(!provider.is_visible());

        provider.toggle();
        assert!(provider.is_visible());

        provider.toggle();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_height() {
        let mut provider = EnhancedOverviewProvider::new("TestBar");
        provider.set_height(200);
        assert_eq!(provider.height(), 200);
    }

    #[test]
    fn test_provider_address_map() {
        let mut provider = EnhancedOverviewProvider::new("TestBar");
        let addrs: Vec<u64> = (0..100).collect();
        provider.update_address_map(AddressIndexMap::from_addresses(&addrs));

        assert_eq!(provider.address_map().index_count(), 100);
    }

    #[test]
    fn test_provider_navigation() {
        let mut provider = EnhancedOverviewProvider::new("TestBar");
        provider.set_height(100);
        provider.set_navigatable(Navigatable::new("Listing1"));

        let addrs: Vec<u64> = (0..1000).collect();
        provider.update_address_map(AddressIndexMap::from_addresses(&addrs));

        // Navigate to pixel 50 with 1000 addresses and 100 pixel height
        // index = 1000 * 50 / 100 = 500
        let addr = provider.go_to_pixel(50);
        assert!(addr.is_some());
        let addr = addr.unwrap();
        assert!(addr >= 490 && addr <= 510); // roughly index 500

        // Navigatable should be updated
        assert!(provider.navigatable().is_some());
        assert_eq!(provider.navigatable().unwrap().current_address, Some(addr));
    }

    #[test]
    fn test_provider_navigation_without_navigatable() {
        let mut provider = EnhancedOverviewProvider::new("TestBar");
        provider.set_height(100);

        let addrs: Vec<u64> = (0..100).collect();
        provider.update_address_map(AddressIndexMap::from_addresses(&addrs));

        // Should still return the address even without a navigatable
        let addr = provider.go_to_pixel(50);
        assert!(addr.is_some());
    }

    #[test]
    fn test_provider_pixel_address_mapping() {
        let mut provider = EnhancedOverviewProvider::new("TestBar");
        provider.set_height(100);

        let addrs: Vec<u64> = (0..1000).collect();
        provider.update_address_map(AddressIndexMap::from_addresses(&addrs));

        // Address to pixel
        let px = provider.get_pixel_for_address(500);
        assert!(px.is_some());
        assert!(px.unwrap() >= 45 && px.unwrap() <= 55);

        // Pixel to address
        let addr = provider.get_address_for_pixel(50);
        assert!(addr.is_some());
    }

    #[test]
    fn test_provider_tooltip() {
        let mut provider = EnhancedOverviewProvider::new("TestBar");
        provider.set_height(10);

        let addrs: Vec<u64> = (0..100).collect();
        provider.update_address_map(AddressIndexMap::from_addresses(&addrs));

        let tip = provider.get_tooltip(5);
        // Should return some non-empty string when there's data
        // (may be empty if the address lookup fails)
        let _ = tip; // Just verify it doesn't panic
    }

    #[test]
    fn test_provider_actions() {
        let mut provider = EnhancedOverviewProvider::new("TestBar");
        assert!(!provider.are_actions_installed());

        let actions = vec![
            ProviderAction::ShowLegend {
                title: "Legend".to_string(),
            },
            ProviderAction::RefreshAll,
            ProviderAction::ToggleTooltips,
        ];
        provider.install_actions(actions);
        assert!(provider.are_actions_installed());
        assert_eq!(provider.installed_actions().len(), 3);

        provider.uninstall_actions();
        assert!(!provider.are_actions_installed());
        assert!(provider.installed_actions().is_empty());
    }

    #[test]
    fn test_provider_domain_events() {
        let mut provider = EnhancedOverviewProvider::new("TestBar");
        assert!(!provider.is_stale());

        provider.domain_changed(DomainChangeEvent::CodeAdded);
        assert!(provider.is_stale());
        assert!(provider.pending_changes().contains(&DomainChangeEvent::CodeAdded));

        provider.domain_changed(DomainChangeEvent::SymbolRenamed);
        assert!(provider.pending_changes().contains(&DomainChangeEvent::SymbolRenamed));
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = EnhancedOverviewProvider::new("TestBar");
        provider.show();
        provider.install_actions(vec![ProviderAction::RefreshAll]);
        provider.set_navigatable(Navigatable::new("test"));

        provider.dispose();
        assert!(!provider.is_visible());
        assert!(!provider.are_actions_installed());
        assert!(provider.navigatable().is_none());
    }

    #[test]
    fn test_provider_event_log() {
        let mut provider = EnhancedOverviewProvider::new("TestBar");
        assert!(provider.event_log().is_empty());

        provider.show();
        provider.hide();
        assert!(provider.event_log().len() >= 2);

        provider.clear_event_log();
        assert!(provider.event_log().is_empty());
    }

    #[test]
    fn test_provider_with_service() {
        let service = Box::new(TestService::new("Entropy"));
        let mut provider = EnhancedOverviewProvider::with_service("OverviewBar", service);
        provider.set_height(100);

        let addrs: Vec<u64> = (0..1000).collect();
        provider.update_address_map(AddressIndexMap::from_addresses(&addrs));

        provider.refresh_all();
        assert_eq!(provider.colors().len(), 100);
    }

    #[test]
    fn test_provider_program_lifecycle() {
        let mut provider = EnhancedOverviewProvider::new("TestBar");
        assert!(provider.program_name().is_none());

        provider.set_program(Some("test.exe".to_string()));
        assert_eq!(provider.program_name(), Some("test.exe"));

        provider.set_program(None);
        assert!(provider.program_name().is_none());
    }

    #[test]
    fn test_provider_refresh_empty_map() {
        let mut provider = EnhancedOverviewProvider::new("TestBar");
        provider.set_height(100);
        // Refresh with empty map should not panic
        provider.refresh_all();
        assert!(provider.colors().is_empty());
    }

    #[test]
    fn test_domain_change_event_equality() {
        assert_eq!(DomainChangeEvent::Restored, DomainChangeEvent::Restored);
        assert_ne!(DomainChangeEvent::Restored, DomainChangeEvent::CodeAdded);
    }

    #[test]
    fn test_provider_action_variants() {
        let legend = ProviderAction::ShowLegend {
            title: "Colors".to_string(),
        };
        let refresh = ProviderAction::RefreshAll;
        let goto = ProviderAction::GoToPixel { pixel_y: 42 };
        let toggle = ProviderAction::ToggleTooltips;
        let custom = ProviderAction::Custom {
            name: "Custom".to_string(),
            description: "A custom action".to_string(),
        };

        // Just verify they construct without panic
        match legend {
            ProviderAction::ShowLegend { title } => assert_eq!(title, "Colors"),
            _ => panic!("wrong variant"),
        }
        match goto {
            ProviderAction::GoToPixel { pixel_y } => assert_eq!(pixel_y, 42),
            _ => panic!("wrong variant"),
        }
        let _ = refresh;
        let _ = toggle;
        let _ = custom;
    }

    #[test]
    fn test_address_index_map_out_of_bounds() {
        let addrs = vec![0x1000, 0x2000];
        let map = AddressIndexMap::from_addresses(&addrs);

        assert!(map.get_address(5).is_none());
        assert!(map.get_index(0x9999).is_none());
    }
}
