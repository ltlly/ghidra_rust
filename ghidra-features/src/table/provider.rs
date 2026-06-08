//! Table component provider.
//!
//! This module provides the Rust analogue of
//! `ghidra.app.plugin.core.table.TableComponentProvider<T>`, which
//! wraps a table model with navigation, marker, and filter support.

use std::collections::HashSet;

use ghidra_core::addr::Address;


// ---------------------------------------------------------------------------
// MarkerSet
// ---------------------------------------------------------------------------

/// A set of addresses displayed as markers in the margin.
///
/// This is the Rust equivalent of Ghidra's `MarkerSet`.
#[derive(Debug, Clone, Default)]
pub struct MarkerSet {
    /// Name of this marker set.
    name: String,
    /// Addresses in this set.
    addresses: HashSet<Address>,
    /// RGBA color for the markers.
    color: (u8, u8, u8, u8),
    /// Whether markers in this set are active.
    active: bool,
}

impl MarkerSet {
    /// Creates a new marker set with the given name and color.
    pub fn new(name: impl Into<String>, color: (u8, u8, u8, u8)) -> Self {
        Self {
            name: name.into(),
            addresses: HashSet::new(),
            color,
            active: true,
        }
    }

    /// Adds an address to the marker set.
    pub fn add(&mut self, addr: Address) {
        self.addresses.insert(addr);
    }

    /// Removes an address from the marker set.
    pub fn remove(&mut self, addr: &Address) {
        self.addresses.remove(addr);
    }

    /// Clears all addresses from the marker set.
    pub fn clear_all(&mut self) {
        self.addresses.clear();
    }

    /// Returns the number of addresses in the set.
    pub fn count(&self) -> usize {
        self.addresses.len()
    }

    /// Returns the name of this marker set.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the marker color.
    pub fn color(&self) -> (u8, u8, u8, u8) {
        self.color
    }

    /// Returns whether this marker set is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Sets whether this marker set is active.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    /// Returns an iterator over the addresses in this set.
    pub fn addresses(&self) -> impl Iterator<Item = &Address> {
        self.addresses.iter()
    }
}

// ---------------------------------------------------------------------------
// ComponentProviderState
// ---------------------------------------------------------------------------

/// Lifecycle state of a component provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentProviderState {
    /// The provider is being constructed.
    Initializing,
    /// The provider is visible.
    Visible,
    /// The provider is hidden (program deactivated, etc.).
    Hidden,
    /// The provider has been closed.
    Closed,
}

// ---------------------------------------------------------------------------
// TableComponentProvider
// ---------------------------------------------------------------------------

/// Component provider that displays a table view with navigation and
/// markers.
///
/// This is the Rust equivalent of
/// `ghidra.app.plugin.core.table.TableComponentProvider<T>`.  It
/// wraps a table model and manages:
///
/// - Navigation (go-to on row selection)
/// - Marker sets in the listing margin
/// - Filtering via a filter panel
/// - Lifecycle and cleanup
pub struct TableComponentProvider {
    /// Unique identifier for this provider.
    id: String,
    /// Display title.
    title: String,
    /// Name of the provider type (e.g., "Search Results").
    name: String,
    /// Sub-menu name in the window menu.
    window_sub_menu: Option<String>,
    /// Current lifecycle state.
    state: ComponentProviderState,
    /// Marker set for highlighting addresses in the listing.
    marker_set: Option<MarkerSet>,
    /// Whether this provider is transient (closed on program close).
    transient: bool,
    /// Subtitle showing row count and program name.
    subtitle: String,
    /// Program name for subtitle display.
    program_name: String,
    /// Current row count.
    row_count: usize,
    /// Filtered row count (if filtering is active).
    filtered_count: Option<usize>,
    /// Callback invoked when the provider is closed.
    closed_callback: Option<Box<dyn Fn() + Send + Sync>>,
    /// Help location topic.
    help_topic: String,
    /// Help location anchor.
    help_anchor: String,
}

impl TableComponentProvider {
    /// Creates a new `TableComponentProvider`.
    ///
    /// # Parameters
    ///
    /// * `id` -- unique identifier for this provider.
    /// * `title` -- display title (e.g., "Search Text \"foo\"").
    /// * `name` -- provider type name (e.g., "Search Results").
    /// * `program_name` -- the program name for subtitle display.
    /// * `window_sub_menu` -- optional sub-menu in the window menu.
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        name: impl Into<String>,
        program_name: impl Into<String>,
        window_sub_menu: Option<String>,
    ) -> Self {
        let title = title.into();
        let program_name = program_name.into();
        let subtitle = Self::generate_subtitle(&program_name, 0, None);

        Self {
            id: id.into(),
            title,
            name: name.into(),
            window_sub_menu,
            state: ComponentProviderState::Initializing,
            marker_set: None,
            transient: true,
            subtitle,
            program_name,
            row_count: 0,
            filtered_count: None,
            closed_callback: None,
            help_topic: "Search".into(),
            help_anchor: "Query_Results".into(),
        }
    }

    /// Returns the provider ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the display title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Sets the display title.
    pub fn set_title(&mut self, title: impl Into<String>) {
        self.title = title.into();
    }

    /// Returns the provider type name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the window sub-menu name.
    pub fn window_sub_menu(&self) -> Option<&str> {
        self.window_sub_menu.as_deref()
    }

    /// Returns the current lifecycle state.
    pub fn state(&self) -> ComponentProviderState {
        self.state
    }

    /// Makes the provider visible.
    pub fn set_visible(&mut self, visible: bool) {
        if visible {
            self.state = ComponentProviderState::Visible;
        } else {
            self.state = ComponentProviderState::Hidden;
        }
    }

    /// Marks this provider as transient.
    pub fn set_transient(&mut self) {
        self.transient = true;
    }

    /// Returns whether this provider is transient.
    pub fn is_transient(&self) -> bool {
        self.transient
    }

    /// Sets the help location.
    pub fn set_help_location(&mut self, topic: impl Into<String>, anchor: impl Into<String>) {
        self.help_topic = topic.into();
        self.help_anchor = anchor.into();
    }

    /// Returns the help topic.
    pub fn help_topic(&self) -> &str {
        &self.help_topic
    }

    /// Returns the help anchor.
    pub fn help_anchor(&self) -> &str {
        &self.help_anchor
    }

    /// Creates a marker set for this provider.
    pub fn create_marker_set(
        &mut self,
        name: impl Into<String>,
        color: (u8, u8, u8, u8),
    ) {
        self.marker_set = Some(MarkerSet::new(name, color));
    }

    /// Returns a reference to the marker set, if any.
    pub fn marker_set(&self) -> Option<&MarkerSet> {
        self.marker_set.as_ref()
    }

    /// Returns a mutable reference to the marker set, if any.
    pub fn marker_set_mut(&mut self) -> Option<&mut MarkerSet> {
        self.marker_set.as_mut()
    }

    /// Loads markers from a list of addresses.
    pub fn load_markers(&mut self, addresses: &[Address]) {
        if let Some(ms) = &mut self.marker_set {
            ms.clear_all();
            for addr in addresses {
                ms.add(*addr);
            }
        }
    }

    /// Reloads markers (clears and re-loads from the given addresses).
    pub fn reload_markers(&mut self, addresses: &[Address]) {
        self.load_markers(addresses);
    }

    /// Closes the component provider.
    pub fn close_component(&mut self) {
        self.state = ComponentProviderState::Closed;
        if let Some(ms) = &mut self.marker_set {
            ms.clear_all();
        }
        if let Some(cb) = &self.closed_callback {
            cb();
        }
    }

    /// Sets the callback to be invoked when the provider is closed.
    pub fn set_closed_callback(&mut self, cb: impl Fn() + Send + Sync + 'static) {
        self.closed_callback = Some(Box::new(cb));
    }

    /// Refreshes the table (updates row count and subtitle).
    pub fn refresh(&mut self, row_count: usize) {
        self.row_count = row_count;
        self.update_title();
    }

    /// Updates the subtitle based on current row counts.
    fn update_title(&mut self) {
        self.subtitle = Self::generate_subtitle(&self.program_name, self.row_count, self.filtered_count);
    }

    /// Returns the current subtitle.
    pub fn subtitle(&self) -> &str {
        &self.subtitle
    }

    /// Sets the filtered row count.
    pub fn set_filtered_count(&mut self, count: Option<usize>) {
        self.filtered_count = count;
        self.update_title();
    }

    /// Returns the current row count.
    pub fn row_count(&self) -> usize {
        self.row_count
    }

    /// Generates a subtitle string from program name and row counts.
    fn generate_subtitle(program_name: &str, row_count: usize, filtered_count: Option<usize>) -> String {
        let filtered_text = match filtered_count {
            Some(total) => format!(" of {}", total),
            None => String::new(),
        };

        match row_count {
            0 => format!("({}) ", program_name),
            1 => format!("({})     (1 entry{})", program_name, filtered_text),
            n => format!("({})     ({} entries{})", program_name, n, filtered_text),
        }
    }

    /// Called when the provider is activated (brought to foreground).
    pub fn component_activated(&mut self) {
        if let Some(ms) = &mut self.marker_set {
            ms.set_active(true);
        }
    }

    /// Called when the provider is deactivated (loses focus).
    pub fn component_deactivated(&mut self) {
        // No-op in the Rust model (no Swing EDT).
    }

    /// Called when the provider is hidden.
    pub fn component_hidden(&mut self) {
        self.state = ComponentProviderState::Hidden;
    }
}

// ---------------------------------------------------------------------------
// ActivationListener
// ---------------------------------------------------------------------------

/// Trait for receiving activation/deactivation notifications.
///
/// This is the Rust equivalent of
/// `ghidra.framework.plugintool.ComponentProviderActivationListener`.
pub trait ComponentProviderActivationListener: Send + Sync {
    /// Called when the component provider is activated.
    fn component_provider_activated(&self, provider_id: &str);

    /// Called when the component provider is deactivated.
    fn component_provider_deactivated(&self, provider_id: &str);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_lifecycle() {
        let mut provider = TableComponentProvider::new(
            "id1",
            "Search Text \"foo\"",
            "Search Results",
            "test.exe",
            None,
        );
        assert_eq!(provider.state(), ComponentProviderState::Initializing);

        provider.set_visible(true);
        assert_eq!(provider.state(), ComponentProviderState::Visible);

        provider.close_component();
        assert_eq!(provider.state(), ComponentProviderState::Closed);
    }

    #[test]
    fn test_provider_subtitle() {
        let mut provider = TableComponentProvider::new(
            "id1",
            "Test",
            "Results",
            "test.exe",
            None,
        );

        // No rows.
        assert!(provider.subtitle().contains("test.exe"));

        // 1 row.
        provider.refresh(1);
        assert!(provider.subtitle().contains("1 entry"));
        assert!(!provider.subtitle().contains("entries"));

        // Multiple rows.
        provider.refresh(5);
        assert!(provider.subtitle().contains("5 entries"));

        // With filtered count.
        provider.set_filtered_count(Some(100));
        assert!(provider.subtitle().contains("of 100"));
    }

    #[test]
    fn test_provider_markers() {
        let mut provider = TableComponentProvider::new(
            "id1",
            "Test",
            "Results",
            "test.exe",
            None,
        );

        provider.create_marker_set("Highlights", (255, 0, 0, 255));
        assert!(provider.marker_set().is_some());

        let addrs = vec![Address::new(0x1000), Address::new(0x2000)];
        provider.load_markers(&addrs);
        assert_eq!(provider.marker_set().unwrap().count(), 2);

        provider.close_component();
        assert_eq!(provider.marker_set().unwrap().count(), 0);
    }

    #[test]
    fn test_provider_transient() {
        let mut provider = TableComponentProvider::new(
            "id1", "T", "R", "test.exe", None,
        );
        provider.set_transient();
        assert!(provider.is_transient());
    }

    #[test]
    fn test_marker_set() {
        let mut ms = MarkerSet::new("Test", (0, 255, 0, 255));
        assert_eq!(ms.name(), "Test");
        assert_eq!(ms.color(), (0, 255, 0, 255));
        assert!(ms.is_active());

        ms.add(Address::new(0x1000));
        ms.add(Address::new(0x2000));
        assert_eq!(ms.count(), 2);

        ms.remove(&Address::new(0x1000));
        assert_eq!(ms.count(), 1);

        ms.clear_all();
        assert_eq!(ms.count(), 0);

        ms.set_active(false);
        assert!(!ms.is_active());
    }
}
