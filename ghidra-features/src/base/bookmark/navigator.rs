//! Bookmark navigator and marker management.
//!
//! Handles the display and navigation of bookmarks in browser marker margins.
//!
//! Ported from Ghidra's `BookmarkNavigator`, this module manages:
//! - Creating and configuring marker sets for bookmark types
//! - Adding/clearing bookmark markers at addresses
//! - Building tooltip text for bookmark locations
//! - Defining built-in bookmark types with their display properties

use std::collections::BTreeMap;
use std::fmt;

use ghidra_core::addr::Address;

use super::model::BookmarkManager;
use super::types::BookmarkType;

// ---------------------------------------------------------------------------
// MarkerDescriptor
// ---------------------------------------------------------------------------

/// A trait for providing tooltip text at a marker location.
///
/// Corresponds to Ghidra's `MarkerDescriptor.getTooltip()`.
pub trait MarkerDescriptor: fmt::Debug {
    /// Returns tooltip text for the given address.
    fn get_tooltip(&self, addr: &Address) -> Option<String>;
}

// ---------------------------------------------------------------------------
// BookmarkMarkerSet
// ---------------------------------------------------------------------------

/// Tracks which addresses have bookmark markers for a specific bookmark type.
///
/// This is the Rust analogue of Ghidra's `MarkerSet` used by
/// `BookmarkNavigator` to manage bookmark markers in the listing.
#[derive(Debug, Clone)]
pub struct BookmarkMarkerSet {
    /// The bookmark type string this marker set represents.
    type_string: String,
    /// The set of addresses that have bookmarks of this type.
    addresses: BTreeMap<u64, ()>,
    /// Marker display priority.
    priority: i32,
    /// Optional marker color (RGB hex string).
    color: Option<String>,
    /// Optional icon identifier.
    icon_id: Option<String>,
}

impl BookmarkMarkerSet {
    /// Creates a new marker set for the given bookmark type.
    pub fn new(
        type_string: impl Into<String>,
        priority: i32,
        color: Option<String>,
        icon_id: Option<String>,
    ) -> Self {
        Self {
            type_string: type_string.into(),
            addresses: BTreeMap::new(),
            priority,
            color,
            icon_id,
        }
    }

    /// Returns the type string.
    pub fn type_string(&self) -> &str {
        &self.type_string
    }

    /// Returns the marker priority.
    pub fn priority(&self) -> i32 {
        self.priority
    }

    /// Returns the marker color, or None.
    pub fn color(&self) -> Option<&str> {
        self.color.as_deref()
    }

    /// Returns the icon identifier, or None.
    pub fn icon_id(&self) -> Option<&str> {
        self.icon_id.as_deref()
    }

    /// Adds a marker at the given address.
    pub fn add(&mut self, addr: &Address) {
        self.addresses.insert(addr.offset, ());
    }

    /// Clears the marker at the given address.
    pub fn clear(&mut self, addr: &Address) {
        self.addresses.remove(&addr.offset);
    }

    /// Returns true if there is a marker at the given address.
    pub fn contains(&self, addr: &Address) -> bool {
        self.addresses.contains_key(&addr.offset)
    }

    /// Returns true if any markers exist within the given address range (inclusive).
    pub fn intersects(&self, start: &Address, end: &Address) -> bool {
        self.addresses
            .range(start.offset..=end.offset)
            .next()
            .is_some()
    }

    /// Replaces the entire set of marker addresses.
    pub fn set_addresses(&mut self, addresses: impl IntoIterator<Item = Address>) {
        self.addresses.clear();
        for addr in addresses {
            self.addresses.insert(addr.offset, ());
        }
    }

    /// Returns the number of markers.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Returns true if there are no markers.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Returns all addresses with markers.
    pub fn addresses(&self) -> Vec<Address> {
        self.addresses.keys().map(|&offset| Address::new(offset)).collect()
    }
}

// ---------------------------------------------------------------------------
// BookmarkNavigator
// ---------------------------------------------------------------------------

/// Manages navigation and display of bookmarks in browser marker margins.
///
/// Corresponds to Ghidra's `BookmarkNavigator` which:
/// - Creates marker sets for each bookmark type
/// - Provides tooltip text for bookmark locations
/// - Syncs marker sets when bookmarks are added/removed
/// - Defines built-in bookmark types on the BookmarkManager
pub struct BookmarkNavigator {
    /// The bookmark type string this navigator manages.
    type_string: String,
    /// The marker set for this bookmark type.
    marker_set: BookmarkMarkerSet,
    /// Reference to the bookmark manager (used for tooltip queries).
    bookmark_manager: BookmarkManager,
}

impl BookmarkNavigator {
    /// Creates a new BookmarkNavigator for the given bookmark type.
    ///
    /// The marker set is configured with the type's priority, color, and icon.
    pub fn new(bookmark_manager: BookmarkManager, bmt: &BookmarkType) -> Self {
        let priority = if bmt.marker_priority() < 0 {
            BookmarkType::default_priority()
        } else {
            bmt.marker_priority()
        };

        let marker_set = BookmarkMarkerSet::new(
            bmt.type_string(),
            priority,
            bmt.marker_color().map(|s| s.to_string()),
            bmt.icon_id().map(|s| s.to_string()),
        );

        Self {
            type_string: bmt.type_string().to_string(),
            marker_set,
            bookmark_manager,
        }
    }

    /// Returns the bookmark type string.
    pub fn type_string(&self) -> &str {
        &self.type_string
    }

    /// Returns a reference to the marker set.
    pub fn marker_set(&self) -> &BookmarkMarkerSet {
        &self.marker_set
    }

    /// Returns a mutable reference to the marker set.
    pub fn marker_set_mut(&mut self) -> &mut BookmarkMarkerSet {
        &mut self.marker_set
    }

    /// Adds a bookmark marker at the given address.
    pub fn add(&mut self, addr: &Address) {
        self.marker_set.add(addr);
    }

    /// Clears the bookmark marker at the given address.
    pub fn clear(&mut self, addr: &Address) {
        self.marker_set.clear(addr);
    }

    /// Returns true if any markers exist within the given range.
    pub fn intersects(&self, start: &Address, end: &Address) -> bool {
        self.marker_set.intersects(start, end)
    }

    /// Rebuilds the marker set from the bookmark manager.
    pub fn update_markers(&mut self) {
        let addrs: Vec<Address> = self
            .bookmark_manager
            .get_bookmarks_iterator(&self.type_string)
            .map(|bm| *bm.address())
            .collect();
        self.marker_set.set_addresses(addrs);
    }

    /// Builds tooltip text for the bookmarks at the given address.
    ///
    /// The tooltip format is:
    /// ```text
    /// Note [Category]: Comment
    /// Note [Category2]: Comment2
    /// ```
    pub fn get_tooltip(&self, addr: &Address) -> Option<String> {
        let bookmarks = self.bookmark_manager.get_bookmarks_by_type(addr, &self.type_string);
        if bookmarks.is_empty() {
            return Some(self.type_string.clone());
        }

        let parts: Vec<String> = bookmarks
            .iter()
            .map(|bm| {
                let cat = bm.category();
                let mut text = self.type_string.clone();
                if !cat.is_empty() {
                    text.push_str(" [");
                    text.push_str(cat);
                    text.push(']');
                }
                text.push_str(": ");
                text.push_str(bm.comment());
                text
            })
            .collect();

        Some(parts.join("\n"))
    }

    /// Defines built-in bookmark types on the given BookmarkManager.
    ///
    /// This is typically called once when a program is activated.
    pub fn define_bookmark_types(mgr: &mut BookmarkManager) {
        for bt in BookmarkType::builtin_types() {
            mgr.define_type(
                bt.type_string(),
                bt.icon_id().map(|s| s.to_string()),
                bt.marker_color().map(|s| s.to_string()),
                bt.marker_priority(),
            );
        }
    }
}

impl fmt::Debug for BookmarkNavigator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BookmarkNavigator")
            .field("type_string", &self.type_string)
            .field("marker_set", &self.marker_set)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_navigator() -> BookmarkNavigator {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "Cat1", "First");
        mgr.set_bookmark(&addr(0x2000), "Note", "Cat2", "Second");
        mgr.set_bookmark(&addr(0x3000), "Warning", "", "Warn");

        let bmt = mgr.get_bookmark_type("Note").unwrap().clone();
        let mut nav = BookmarkNavigator::new(mgr, &bmt);
        nav.update_markers();
        nav
    }

    #[test]
    fn test_navigator_type_string() {
        let nav = make_navigator();
        assert_eq!(nav.type_string(), "Note");
    }

    #[test]
    fn test_navigator_marker_count() {
        let nav = make_navigator();
        assert_eq!(nav.marker_set().len(), 2);
    }

    #[test]
    fn test_navigator_add_and_clear() {
        let mut nav = make_navigator();
        assert!(!nav.marker_set().contains(&addr(0x5000)));
        nav.add(&addr(0x5000));
        assert!(nav.marker_set().contains(&addr(0x5000)));
        nav.clear(&addr(0x5000));
        assert!(!nav.marker_set().contains(&addr(0x5000)));
    }

    #[test]
    fn test_navigator_intersects() {
        let nav = make_navigator();
        assert!(nav.intersects(&addr(0x0F00), &addr(0x1100)));
        assert!(nav.intersects(&addr(0x1000), &addr(0x2000)));
        assert!(!nav.intersects(&addr(0x4000), &addr(0x5000)));
    }

    #[test]
    fn test_navigator_tooltip_single() {
        let nav = make_navigator();
        let tooltip = nav.get_tooltip(&addr(0x1000)).unwrap();
        assert!(tooltip.contains("Note"));
        assert!(tooltip.contains("[Cat1]"));
        assert!(tooltip.contains("First"));
    }

    #[test]
    fn test_navigator_tooltip_nonexistent() {
        let nav = make_navigator();
        let tooltip = nav.get_tooltip(&addr(0x9999)).unwrap();
        assert_eq!(tooltip, "Note");
    }

    #[test]
    fn test_navigator_update_markers() {
        let mut nav = make_navigator();
        // Add a new bookmark and refresh.
        nav.bookmark_manager
            .set_bookmark(&addr(0x5000), "Note", "", "New");
        nav.update_markers();
        assert_eq!(nav.marker_set().len(), 3);
        assert!(nav.marker_set().contains(&addr(0x5000)));
    }

    #[test]
    fn test_define_bookmark_types() {
        let mut mgr = BookmarkManager::new();
        // Clear all types first
        mgr.clear();
        BookmarkNavigator::define_bookmark_types(&mut mgr);
        assert!(mgr.get_bookmark_type("Note").is_some());
        assert!(mgr.get_bookmark_type("Warning").is_some());
    }

    // -- BookmarkMarkerSet tests --

    #[test]
    fn test_marker_set_addresses() {
        let mut ms = BookmarkMarkerSet::new("Test", 1, None, None);
        ms.add(&addr(0x1000));
        ms.add(&addr(0x2000));
        let addrs = ms.addresses();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].offset, 0x1000);
        assert_eq!(addrs[1].offset, 0x2000);
    }

    #[test]
    fn test_marker_set_set_addresses() {
        let mut ms = BookmarkMarkerSet::new("Test", 1, None, None);
        ms.add(&addr(0x1000));
        ms.set_addresses(vec![addr(0x5000), addr(0x6000)]);
        assert_eq!(ms.len(), 2);
        assert!(ms.contains(&addr(0x5000)));
        assert!(!ms.contains(&addr(0x1000)));
    }
}
