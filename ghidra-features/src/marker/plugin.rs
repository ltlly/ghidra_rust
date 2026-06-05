//! Marker plugin, overview provider, and margin provider.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.marker` Java package:
//! `MarkerManagerPlugin`, `MarkerOverviewProvider`, `MarkerMarginProvider`,
//! `MarkerPanel`, `NavigationPanel`, `MarginProviderSupplier`,
//! `ModifiableAddressSetCollection`.

use super::{MarkerManager, RgbColor};
use std::collections::BTreeSet;

// ============================================================================
// MarginProviderSupplier -- provides a margin provider
// ============================================================================

/// Trait for objects that supply a margin provider.
///
/// Ported from `ghidra.app.plugin.core.marker.MarginProviderSupplier`.
pub trait MarginProviderSupplier: Send + Sync {
    /// Get the margin provider.
    fn get_margin_provider(&self) -> Option<&dyn MarginProvider>;
}

/// Trait for rendering markers in the listing margin.
///
/// Ported from `ghidra.app.plugin.core.marker.MarkerMarginProvider`.
pub trait MarginProvider: Send + Sync {
    /// Get the name of this margin provider.
    fn name(&self) -> &str;

    /// Get the priority (lower values are rendered first).
    fn priority(&self) -> i32;

    /// Whether this provider is enabled.
    fn is_enabled(&self) -> bool;

    /// Set whether this provider is enabled.
    fn set_enabled(&mut self, enabled: bool);
}

// ============================================================================
// MarkerOverviewProvider -- provides an overview bar model
// ============================================================================

/// The overview provider renders a scaled-down view of markers.
///
/// Ported from `ghidra.app.plugin.core.marker.MarkerOverviewProvider`.
#[derive(Debug)]
pub struct MarkerOverviewProvider {
    /// The name of this overview provider.
    pub name: String,
    /// The priority.
    pub priority: i32,
    /// Whether enabled.
    enabled: bool,
    /// The color for overview markers.
    pub color: RgbColor,
    /// The marker set ID this provider displays.
    pub marker_set_id: Option<u64>,
}

impl MarkerOverviewProvider {
    /// Create a new overview provider.
    pub fn new(name: impl Into<String>, color: RgbColor) -> Self {
        Self {
            name: name.into(),
            priority: 0,
            enabled: true,
            color,
            marker_set_id: None,
        }
    }

    /// Bind to a marker set.
    pub fn bind_marker_set(&mut self, set_id: u64) {
        self.marker_set_id = Some(set_id);
    }

    /// Unbind from the marker set.
    pub fn unbind(&mut self) {
        self.marker_set_id = None;
    }

    /// Whether this provider is bound to a marker set.
    pub fn is_bound(&self) -> bool {
        self.marker_set_id.is_some()
    }
}

impl MarginProvider for MarkerOverviewProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn priority(&self) -> i32 {
        self.priority
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

// ============================================================================
// NavigationPanel -- navigation between markers
// ============================================================================

/// Navigation between markers in a marker set.
///
/// Ported from `ghidra.app.plugin.core.marker.NavigationPanel`.
#[derive(Debug)]
pub struct MarkerNavigation {
    /// The addresses with markers, sorted.
    addresses: Vec<u64>,
    /// The current index.
    current_index: Option<usize>,
}

impl MarkerNavigation {
    /// Create a new navigation from a sorted list of addresses.
    pub fn new(addresses: Vec<u64>) -> Self {
        let mut sorted = addresses;
        sorted.sort();
        sorted.dedup();
        Self {
            addresses: sorted,
            current_index: None,
        }
    }

    /// Navigate to the next marker after `address`.
    pub fn go_next(&mut self, address: u64) -> Option<u64> {
        let pos = self.addresses.iter().position(|&a| a > address);
        if let Some(idx) = pos {
            self.current_index = Some(idx);
            Some(self.addresses[idx])
        } else {
            None
        }
    }

    /// Navigate to the previous marker before `address`.
    pub fn go_previous(&mut self, address: u64) -> Option<u64> {
        let pos = self
            .addresses
            .iter()
            .rposition(|&a| a < address);
        if let Some(idx) = pos {
            self.current_index = Some(idx);
            Some(self.addresses[idx])
        } else {
            None
        }
    }

    /// Navigate to the first marker.
    pub fn go_first(&mut self) -> Option<u64> {
        if self.addresses.is_empty() {
            return None;
        }
        self.current_index = Some(0);
        Some(self.addresses[0])
    }

    /// Navigate to the last marker.
    pub fn go_last(&mut self) -> Option<u64> {
        if self.addresses.is_empty() {
            return None;
        }
        let idx = self.addresses.len() - 1;
        self.current_index = Some(idx);
        Some(self.addresses[idx])
    }

    /// The total number of markers.
    pub fn count(&self) -> usize {
        self.addresses.len()
    }

    /// The current address (if navigated).
    pub fn current(&self) -> Option<u64> {
        self.current_index.map(|i| self.addresses[i])
    }
}

// ============================================================================
// ModifiableAddressSetCollection -- a modifiable set of addresses
// ============================================================================

/// A modifiable set of addresses, used for marker area management.
///
/// Ported from `ghidra.app.plugin.core.marker.ModifiableAddressSetCollection`.
#[derive(Debug, Clone, Default)]
pub struct ModifiableAddressSet {
    /// The addresses in the set.
    addresses: BTreeSet<u64>,
}

impl ModifiableAddressSet {
    /// Create a new empty address set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an address to the set.
    pub fn add(&mut self, address: u64) {
        self.addresses.insert(address);
    }

    /// Remove an address from the set.
    pub fn remove(&mut self, address: u64) {
        self.addresses.remove(&address);
    }

    /// Check whether the set contains an address.
    pub fn contains(&self, address: u64) -> bool {
        self.addresses.contains(&address)
    }

    /// Add a range of addresses.
    pub fn add_range(&mut self, start: u64, end: u64) {
        for addr in start..=end {
            self.addresses.insert(addr);
        }
    }

    /// Remove a range of addresses.
    pub fn remove_range(&mut self, start: u64, end: u64) {
        for addr in start..=end {
            self.addresses.remove(&addr);
        }
    }

    /// The number of addresses in the set.
    pub fn size(&self) -> usize {
        self.addresses.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Get the minimum address.
    pub fn min(&self) -> Option<u64> {
        self.addresses.iter().next().copied()
    }

    /// Get the maximum address.
    pub fn max(&self) -> Option<u64> {
        self.addresses.iter().next_back().copied()
    }

    /// Get all addresses as a sorted Vec.
    pub fn to_vec(&self) -> Vec<u64> {
        self.addresses.iter().copied().collect()
    }

    /// Union with another set.
    pub fn union(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for &addr in &other.addresses {
            result.addresses.insert(addr);
        }
        result
    }

    /// Intersect with another set.
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            addresses: self.addresses.intersection(&other.addresses).copied().collect(),
        }
    }

    /// Difference (self - other).
    pub fn difference(&self, other: &Self) -> Self {
        Self {
            addresses: self.addresses.difference(&other.addresses).copied().collect(),
        }
    }
}

// ============================================================================
// MarkerManagerPlugin -- plugin orchestrating marker sets
// ============================================================================

/// The marker manager plugin.
///
/// Ported from `ghidra.app.plugin.core.marker.MarkerManagerPlugin`.
#[derive(Debug)]
pub struct MarkerManagerPlugin {
    /// The marker manager.
    pub manager: MarkerManager,
    /// Registered overview providers.
    overview_providers: Vec<MarkerOverviewProvider>,
    /// Whether the plugin is disposed.
    disposed: bool,
}

impl MarkerManagerPlugin {
    /// Create a new marker manager plugin.
    pub fn new() -> Self {
        Self {
            manager: MarkerManager::new(),
            overview_providers: Vec::new(),
            disposed: false,
        }
    }

    /// Add an overview provider.
    pub fn add_overview_provider(&mut self, provider: MarkerOverviewProvider) {
        self.overview_providers.push(provider);
    }

    /// Remove an overview provider by name.
    pub fn remove_overview_provider(&mut self, name: &str) {
        self.overview_providers.retain(|p| p.name() != name);
    }

    /// Get all overview providers.
    pub fn overview_providers(&self) -> &[MarkerOverviewProvider] {
        &self.overview_providers
    }

    /// Get a mutable overview provider by name.
    pub fn overview_provider_mut(&mut self, name: &str) -> Option<&mut MarkerOverviewProvider> {
        self.overview_providers.iter_mut().find(|p| p.name() == name)
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.overview_providers.clear();
    }

    /// Whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }
}

impl Default for MarkerManagerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overview_provider() {
        let mut provider = MarkerOverviewProvider::new("Test", RgbColor::RED);
        assert_eq!(provider.name(), "Test");
        assert!(provider.is_enabled());
        assert!(!provider.is_bound());

        provider.bind_marker_set(42);
        assert!(provider.is_bound());
        provider.unbind();
        assert!(!provider.is_bound());

        provider.set_enabled(false);
        assert!(!provider.is_enabled());
    }

    #[test]
    fn test_marker_navigation() {
        let nav = MarkerNavigation::new(vec![0x3000, 0x1000, 0x2000, 0x1000]);
        assert_eq!(nav.count(), 3); // deduped

        let mut nav = nav;
        assert_eq!(nav.go_first(), Some(0x1000));
        assert_eq!(nav.go_last(), Some(0x3000));
        assert_eq!(nav.current(), Some(0x3000));

        assert_eq!(nav.go_next(0x1000), Some(0x2000));
        assert_eq!(nav.go_next(0x3000), None);
        assert_eq!(nav.go_previous(0x3000), Some(0x2000));
        assert_eq!(nav.go_previous(0x1000), None);
    }

    #[test]
    fn test_marker_navigation_empty() {
        let mut nav = MarkerNavigation::new(vec![]);
        assert_eq!(nav.count(), 0);
        assert_eq!(nav.go_first(), None);
        assert_eq!(nav.go_last(), None);
        assert_eq!(nav.go_next(0), None);
        assert_eq!(nav.go_previous(0), None);
        assert_eq!(nav.current(), None);
    }

    #[test]
    fn test_modifiable_address_set() {
        let mut set = ModifiableAddressSet::new();
        assert!(set.is_empty());

        set.add(0x1000);
        set.add(0x2000);
        set.add(0x3000);
        assert_eq!(set.size(), 3);
        assert!(set.contains(0x1000));
        assert!(!set.contains(0x4000));
        assert_eq!(set.min(), Some(0x1000));
        assert_eq!(set.max(), Some(0x3000));

        set.remove(0x2000);
        assert_eq!(set.size(), 2);
        assert!(!set.contains(0x2000));
    }

    #[test]
    fn test_address_set_range() {
        let mut set = ModifiableAddressSet::new();
        set.add_range(0x1000, 0x1005);
        assert_eq!(set.size(), 6);
        assert!(set.contains(0x1003));

        set.remove_range(0x1002, 0x1004);
        assert_eq!(set.size(), 3);
        assert!(!set.contains(0x1003));
    }

    #[test]
    fn test_address_set_union() {
        let mut a = ModifiableAddressSet::new();
        a.add(0x1000);
        a.add(0x2000);

        let mut b = ModifiableAddressSet::new();
        b.add(0x2000);
        b.add(0x3000);

        let union = a.union(&b);
        assert_eq!(union.size(), 3);
        assert!(union.contains(0x1000));
        assert!(union.contains(0x2000));
        assert!(union.contains(0x3000));
    }

    #[test]
    fn test_address_set_intersect() {
        let mut a = ModifiableAddressSet::new();
        a.add(0x1000);
        a.add(0x2000);

        let mut b = ModifiableAddressSet::new();
        b.add(0x2000);
        b.add(0x3000);

        let inter = a.intersect(&b);
        assert_eq!(inter.size(), 1);
        assert!(inter.contains(0x2000));
    }

    #[test]
    fn test_address_set_difference() {
        let mut a = ModifiableAddressSet::new();
        a.add(0x1000);
        a.add(0x2000);

        let mut b = ModifiableAddressSet::new();
        b.add(0x2000);

        let diff = a.difference(&b);
        assert_eq!(diff.size(), 1);
        assert!(diff.contains(0x1000));
        assert!(!diff.contains(0x2000));
    }

    #[test]
    fn test_address_set_to_vec() {
        let mut set = ModifiableAddressSet::new();
        set.add(0x3000);
        set.add(0x1000);
        set.add(0x2000);
        assert_eq!(set.to_vec(), vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn test_marker_manager_plugin() {
        let mut plugin = MarkerManagerPlugin::new();
        assert!(!plugin.is_disposed());

        let provider = MarkerOverviewProvider::new("Warnings", RgbColor::ORANGE);
        plugin.add_overview_provider(provider);
        assert_eq!(plugin.overview_providers().len(), 1);

        plugin.remove_overview_provider("Warnings");
        assert_eq!(plugin.overview_providers().len(), 0);

        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_marker_manager_plugin_overview_mut() {
        let mut plugin = MarkerManagerPlugin::new();
        plugin.add_overview_provider(MarkerOverviewProvider::new("A", RgbColor::RED));

        let p = plugin.overview_provider_mut("A").unwrap();
        p.priority = 10;
        assert_eq!(plugin.overview_providers()[0].priority(), 10);
    }

    #[test]
    fn test_marker_manager_plugin_overview_not_found() {
        let mut plugin = MarkerManagerPlugin::new();
        assert!(plugin.overview_provider_mut("missing").is_none());
    }
}
