//! Bookmark edit and delete commands.
//!
//! Commands encapsulate bookmark mutations for undo/redo support.
//! Each command implements the [`BookmarkCommand`] trait which provides
//! `apply()` and `name()` methods.
//!
//! Ported from Ghidra's:
//! - `BookmarkEditCmd` -- add or modify a bookmark
//! - `BookmarkDeleteCmd` -- remove bookmarks by various criteria

use ghidra_core::addr::Address;

use super::model::BookmarkManager;

// ---------------------------------------------------------------------------
// AddressSet (simplified for command support)
// ---------------------------------------------------------------------------

/// A simplified address set used by bookmark commands.
///
/// In Ghidra this would be `AddressSetView`; here we provide a minimal
/// implementation that supports the bookmark command use cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressSet {
    ranges: Vec<(Address, Address)>,
}

impl AddressSet {
    /// Creates a new empty address set.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Creates an address set containing a single address.
    pub fn single(addr: Address) -> Self {
        Self {
            ranges: vec![(addr, addr)],
        }
    }

    /// Creates an address set from a range (inclusive).
    pub fn range(start: Address, end: Address) -> Self {
        Self {
            ranges: vec![(start, end)],
        }
    }

    /// Adds a range (inclusive) to this set.
    pub fn add_range(&mut self, start: Address, end: Address) {
        self.ranges.push((start, end));
    }

    /// Returns true if this set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Returns the number of ranges.
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Returns an iterator over (start, end) range pairs.
    pub fn ranges(&self) -> &[(Address, Address)] {
        &self.ranges
    }

    /// Returns the minimum address in the first range, if any.
    pub fn min_address(&self) -> Option<Address> {
        self.ranges.first().map(|(start, _)| *start)
    }
}

impl Default for AddressSet {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BookmarkCommand trait
// ---------------------------------------------------------------------------

/// Trait for bookmark commands that can be applied to a BookmarkManager.
///
/// This mirrors Ghidra's `Command<Program>` pattern where commands
/// encapsulate a single undo-able operation.
pub trait BookmarkCommand {
    /// Apply this command to the given BookmarkManager.
    /// Returns `true` on success.
    fn apply(&self, mgr: &mut BookmarkManager) -> bool;

    /// A human-readable name for this command (for undo display).
    fn name(&self) -> &str;

    /// An optional status message after execution.
    fn status_msg(&self) -> Option<&str> {
        None
    }
}

// ---------------------------------------------------------------------------
// BookmarkEditCmd -- add or modify bookmarks
// ---------------------------------------------------------------------------

/// Command to create or update bookmarks at one or more addresses.
///
/// This corresponds to Ghidra's `BookmarkEditCmd` which can:
/// 1. Add a bookmark at a single address
/// 2. Add bookmarks at the first address of each range in an address set
/// 3. Edit an existing bookmark's category and comment
#[derive(Debug, Clone)]
pub struct BookmarkEditCmd {
    /// If editing an existing bookmark, its ID.
    existing_id: Option<u64>,
    /// The target address (for single-address mode).
    addr: Option<Address>,
    /// The target address set (for multi-address mode).
    addr_set: Option<AddressSet>,
    /// Bookmark type.
    type_string: String,
    /// Bookmark category.
    category: String,
    /// Bookmark comment.
    comment: String,
    /// Display name for this command.
    presentation_name: String,
}

impl BookmarkEditCmd {
    /// Creates a command to add a bookmark at a single address.
    ///
    /// Corresponds to `BookmarkEditCmd(Address, String, String, String)`.
    pub fn at_address(
        addr: Address,
        type_string: impl Into<String>,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        let ts = type_string.into();
        let presentation_name = format!("Add {} Bookmark", ts);
        Self {
            existing_id: None,
            addr: Some(addr),
            addr_set: None,
            type_string: ts,
            category: category.into(),
            comment: comment.into(),
            presentation_name,
        }
    }

    /// Creates a command to add bookmarks at the first address of each range.
    ///
    /// Corresponds to `BookmarkEditCmd(AddressSetView, String, String, String)`.
    pub fn at_addresses(
        addr_set: AddressSet,
        type_string: impl Into<String>,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        let ts = type_string.into();
        let presentation_name = format!("Add {} Bookmark(s)", ts);
        Self {
            existing_id: None,
            addr: None,
            addr_set: Some(addr_set),
            type_string: ts,
            category: category.into(),
            comment: comment.into(),
            presentation_name,
        }
    }

    /// Creates a command to edit an existing bookmark.
    ///
    /// Corresponds to `BookmarkEditCmd(Bookmark, String, String)`.
    pub fn edit(
        bookmark_id: u64,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            existing_id: Some(bookmark_id),
            addr: None,
            addr_set: None,
            type_string: String::new(),
            category: category.into(),
            comment: comment.into(),
            presentation_name: "Edit Bookmark".into(),
        }
    }
}

impl BookmarkCommand for BookmarkEditCmd {
    fn apply(&self, mgr: &mut BookmarkManager) -> bool {
        if let Some(id) = self.existing_id {
            // Edit existing bookmark.
            if let Some(bm) = mgr.get_bookmark_mut(id) {
                bm.set(&self.category, &self.comment);
                return true;
            }
            return false;
        }

        if let Some(addr) = self.addr {
            // Single address.
            mgr.set_bookmark(&addr, &self.type_string, &self.category, &self.comment);
            return true;
        }

        if let Some(ref set) = self.addr_set {
            // Multiple ranges -- set bookmark at first address of each range.
            for &(start, end) in set.ranges() {
                let min_addr = if start <= end { start } else { end };
                mgr.set_bookmark(&min_addr, &self.type_string, &self.category, &self.comment);
            }
            return true;
        }

        false
    }

    fn name(&self) -> &str {
        &self.presentation_name
    }
}

// ---------------------------------------------------------------------------
// BookmarkDeleteCmd -- remove bookmarks
// ---------------------------------------------------------------------------

/// Command to delete bookmarks matching various criteria.
///
/// This corresponds to Ghidra's `BookmarkDeleteCmd` which can delete:
/// - A list of bookmarks by ID
/// - All bookmarks at a given address
/// - All bookmarks of a given type
/// - All bookmarks in an address set
/// - Various combinations of the above
#[derive(Debug, Clone)]
pub struct BookmarkDeleteCmd {
    /// Which deletion mode to use.
    mode: DeleteMode,
    /// Display name for this command.
    presentation_name: String,
}

/// Internal enum for the various deletion modes.
#[derive(Debug, Clone)]
enum DeleteMode {
    /// Delete bookmarks by ID.
    ByIds(Vec<u64>),
    /// Delete all bookmarks at a given address.
    AtAddress(Address),
    /// Delete bookmarks at an address filtered by type.
    AtAddressByType(Address, String),
    /// Delete bookmarks at an address filtered by type and category.
    AtAddressByTypeAndCategory(Address, String, String),
    /// Delete all bookmarks in an address set.
    AtAddressSet(AddressSet),
    /// Delete bookmarks in an address set filtered by type.
    AtAddressSetByType(AddressSet, String),
    /// Delete bookmarks in an address set filtered by type and category.
    AtAddressSetByTypeAndCategory(AddressSet, String, String),
    /// Delete all bookmarks of a given type.
    ByType(String),
    /// Delete all bookmarks of a given type and category.
    ByTypeAndCategory(String, String),
}

impl BookmarkDeleteCmd {
    /// Delete a single bookmark by ID.
    pub fn by_id(id: u64) -> Self {
        Self {
            mode: DeleteMode::ByIds(vec![id]),
            presentation_name: "Delete Bookmark".into(),
        }
    }

    /// Delete bookmarks by ID.
    pub fn by_ids(ids: Vec<u64>) -> Self {
        Self {
            mode: DeleteMode::ByIds(ids),
            presentation_name: "Delete Bookmark(s)".into(),
        }
    }

    /// Delete all bookmarks at the given address.
    pub fn at_address(addr: Address) -> Self {
        Self {
            mode: DeleteMode::AtAddress(addr),
            presentation_name: format!("Delete Bookmarks at {}", addr.offset),
        }
    }

    /// Delete bookmarks at the given address with the given type.
    pub fn at_address_by_type(addr: Address, type_string: impl Into<String>) -> Self {
        let ts = type_string.into();
        Self {
            mode: DeleteMode::AtAddressByType(addr, ts.clone()),
            presentation_name: format!("Delete {} Bookmarks at {}", ts, addr.offset),
        }
    }

    /// Delete bookmarks at the given address with the given type and category.
    pub fn at_address_by_type_and_category(
        addr: Address,
        type_string: impl Into<String>,
        category: impl Into<String>,
    ) -> Self {
        let ts = type_string.into();
        let cat = category.into();
        Self {
            mode: DeleteMode::AtAddressByTypeAndCategory(addr, ts.clone(), cat.clone()),
            presentation_name: format!("Delete {}, {} Bookmark at {}", ts, cat, addr.offset),
        }
    }

    /// Delete all bookmarks in the given address set.
    pub fn at_address_set(set: AddressSet) -> Self {
        Self {
            mode: DeleteMode::AtAddressSet(set),
            presentation_name: "Delete Bookmarks over address range".into(),
        }
    }

    /// Delete bookmarks in the address set filtered by type.
    pub fn at_address_set_by_type(set: AddressSet, type_string: impl Into<String>) -> Self {
        let ts = type_string.into();
        Self {
            mode: DeleteMode::AtAddressSetByType(set, ts.clone()),
            presentation_name: format!("Delete {} Bookmarks over address range", ts),
        }
    }

    /// Delete bookmarks in the address set filtered by type and category.
    pub fn at_address_set_by_type_and_category(
        set: AddressSet,
        type_string: impl Into<String>,
        category: impl Into<String>,
    ) -> Self {
        let ts = type_string.into();
        let cat = category.into();
        Self {
            mode: DeleteMode::AtAddressSetByTypeAndCategory(set, ts.clone(), cat.clone()),
            presentation_name: format!(
                "Delete {}, {} Bookmarks over address range",
                ts, cat
            ),
        }
    }

    /// Delete all bookmarks of the given type.
    pub fn by_type(type_string: impl Into<String>) -> Self {
        let ts = type_string.into();
        Self {
            mode: DeleteMode::ByType(ts.clone()),
            presentation_name: format!("Delete all {} Bookmarks", ts),
        }
    }

    /// Delete all bookmarks of the given type and category.
    pub fn by_type_and_category(
        type_string: impl Into<String>,
        category: impl Into<String>,
    ) -> Self {
        let ts = type_string.into();
        let cat = category.into();
        Self {
            mode: DeleteMode::ByTypeAndCategory(ts.clone(), cat.clone()),
            presentation_name: format!("Delete all Bookmarks of type {} and category {}", ts, cat),
        }
    }
}

impl BookmarkCommand for BookmarkDeleteCmd {
    fn apply(&self, mgr: &mut BookmarkManager) -> bool {
        match &self.mode {
            DeleteMode::ByIds(ids) => {
                for id in ids {
                    mgr.remove_bookmark_by_id(*id);
                }
            }
            DeleteMode::AtAddress(addr) => {
                mgr.remove_bookmarks_at_addresses(&[*addr]);
            }
            DeleteMode::AtAddressByType(addr, type_string) => {
                mgr.remove_bookmarks_at_addresses_by_type(&[*addr], type_string);
            }
            DeleteMode::AtAddressByTypeAndCategory(addr, type_string, category) => {
                let ids_to_remove: Vec<u64> = mgr
                    .get_bookmarks(addr)
                    .iter()
                    .filter(|bm| bm.type_string() == type_string && bm.category() == category)
                    .map(|bm| bm.id())
                    .collect();
                for id in ids_to_remove {
                    mgr.remove_bookmark_by_id(id);
                }
            }
            DeleteMode::AtAddressSet(set) => {
                let addrs: Vec<Address> = set
                    .ranges()
                    .iter()
                    .map(|&(s, e)| if s <= e { s } else { e })
                    .collect();
                mgr.remove_bookmarks_at_addresses(&addrs);
            }
            DeleteMode::AtAddressSetByType(set, type_string) => {
                let addrs: Vec<Address> = set
                    .ranges()
                    .iter()
                    .map(|&(s, e)| if s <= e { s } else { e })
                    .collect();
                mgr.remove_bookmarks_at_addresses_by_type(&addrs, type_string);
            }
            DeleteMode::AtAddressSetByTypeAndCategory(set, type_string, category) => {
                for &(start, end) in set.ranges() {
                    let min_addr = if start <= end { start } else { end };
                    let ids: Vec<u64> = mgr
                        .get_bookmarks(&min_addr)
                        .iter()
                        .filter(|bm| {
                            bm.type_string() == type_string && bm.category() == category
                        })
                        .map(|bm| bm.id())
                        .collect();
                    for id in ids {
                        mgr.remove_bookmark_by_id(id);
                    }
                }
            }
            DeleteMode::ByType(type_string) => {
                mgr.remove_bookmarks_by_type(type_string);
            }
            DeleteMode::ByTypeAndCategory(type_string, category) => {
                mgr.remove_bookmarks_by_type_and_category(type_string, category);
            }
        }
        true
    }

    fn name(&self) -> &str {
        &self.presentation_name
    }
}

// ---------------------------------------------------------------------------
// BookmarkDeleteBackgroundCmd -- bulk delete with progress
// ---------------------------------------------------------------------------

/// Command to delete an array of bookmarks with progress reporting.
///
/// This corresponds to Ghidra's `BookmarkDeleteBackgroundCmd` which
/// iterates over an array of bookmarks, removing each one.
#[derive(Debug, Clone)]
pub struct BookmarkDeleteBackgroundCmd {
    /// The bookmark IDs to delete.
    bookmark_ids: Vec<u64>,
}

impl BookmarkDeleteBackgroundCmd {
    /// Creates a new background delete command for the given bookmark IDs.
    pub fn new(bookmark_ids: Vec<u64>) -> Self {
        Self { bookmark_ids }
    }

    /// Returns the number of bookmarks to delete.
    pub fn count(&self) -> usize {
        self.bookmark_ids.len()
    }

    /// Applies the deletion to the given BookmarkManager.
    /// Returns the number of bookmarks actually removed.
    pub fn apply(&self, mgr: &mut BookmarkManager) -> usize {
        let mut removed = 0;
        for &id in &self.bookmark_ids {
            if mgr.remove_bookmark_by_id(id).is_some() {
                removed += 1;
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn setup_mgr() -> BookmarkManager {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "Todo", "Fix this");
        mgr.set_bookmark(&addr(0x1000), "Warning", "", "Potential issue");
        mgr.set_bookmark(&addr(0x2000), "Note", "Todo", "Also fix");
        mgr.set_bookmark(&addr(0x3000), "Error", "Bug", "Crash here");
        mgr
    }

    // -- BookmarkEditCmd tests --

    #[test]
    fn test_edit_cmd_at_address() {
        let mut mgr = BookmarkManager::new();
        let cmd = BookmarkEditCmd::at_address(addr(0x1000), "Note", "Cat", "Comment");
        assert!(cmd.apply(&mut mgr));
        assert_eq!(mgr.get_bookmark_count(), 1);
        assert_eq!(cmd.name(), "Add Note Bookmark");
    }

    #[test]
    fn test_edit_cmd_at_addresses() {
        let mut mgr = BookmarkManager::new();
        let mut set = AddressSet::new();
        set.add_range(addr(0x1000), addr(0x1500));
        set.add_range(addr(0x2000), addr(0x2500));
        let cmd = BookmarkEditCmd::at_addresses(set, "Note", "Cat", "Comment");
        assert!(cmd.apply(&mut mgr));
        assert_eq!(mgr.get_bookmark_count(), 2);
    }

    #[test]
    fn test_edit_cmd_edit_existing() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "Old", "Old comment");
        let cmd = BookmarkEditCmd::edit(1, "New", "New comment");
        assert!(cmd.apply(&mut mgr));
        let bm = mgr.get_bookmark(1).unwrap();
        assert_eq!(bm.category(), "New");
        assert_eq!(bm.comment(), "New comment");
    }

    // -- BookmarkDeleteCmd tests --

    #[test]
    fn test_delete_cmd_by_id() {
        let mut mgr = setup_mgr();
        let cmd = BookmarkDeleteCmd::by_id(1);
        assert!(cmd.apply(&mut mgr));
        assert!(mgr.get_bookmark(1).is_none());
        assert_eq!(mgr.get_bookmark_count(), 3);
    }

    #[test]
    fn test_delete_cmd_at_address() {
        let mut mgr = setup_mgr();
        let cmd = BookmarkDeleteCmd::at_address(addr(0x1000));
        assert!(cmd.apply(&mut mgr));
        assert_eq!(mgr.get_bookmarks(&addr(0x1000)).len(), 0);
        assert_eq!(mgr.get_bookmark_count(), 2);
    }

    #[test]
    fn test_delete_cmd_at_address_by_type() {
        let mut mgr = setup_mgr();
        let cmd = BookmarkDeleteCmd::at_address_by_type(addr(0x1000), "Note");
        assert!(cmd.apply(&mut mgr));
        // Should still have the Warning at 0x1000.
        assert_eq!(mgr.get_bookmarks(&addr(0x1000)).len(), 1);
    }

    #[test]
    fn test_delete_cmd_by_type() {
        let mut mgr = setup_mgr();
        let cmd = BookmarkDeleteCmd::by_type("Note");
        assert!(cmd.apply(&mut mgr));
        assert_eq!(mgr.get_bookmark_count_by_type("Note"), 0);
        assert_eq!(mgr.get_bookmark_count_by_type("Warning"), 1);
        assert_eq!(mgr.get_bookmark_count_by_type("Error"), 1);
    }

    #[test]
    fn test_delete_cmd_by_type_and_category() {
        let mut mgr = setup_mgr();
        let cmd = BookmarkDeleteCmd::by_type_and_category("Note", "Todo");
        assert!(cmd.apply(&mut mgr));
        assert_eq!(mgr.get_bookmark_count_by_type("Note"), 0);
    }

    #[test]
    fn test_delete_cmd_at_address_set() {
        let mut mgr = setup_mgr();
        let set = AddressSet::single(addr(0x1000));
        let cmd = BookmarkDeleteCmd::at_address_set(set);
        assert!(cmd.apply(&mut mgr));
        assert_eq!(mgr.get_bookmarks(&addr(0x1000)).len(), 0);
    }

    #[test]
    fn test_delete_cmd_at_address_set_by_type() {
        let mut mgr = setup_mgr();
        let set = AddressSet::single(addr(0x1000));
        let cmd = BookmarkDeleteCmd::at_address_set_by_type(set, "Note");
        assert!(cmd.apply(&mut mgr));
        assert_eq!(mgr.get_bookmarks(&addr(0x1000)).len(), 1);
    }

    // -- BookmarkDeleteBackgroundCmd tests --

    #[test]
    fn test_background_delete() {
        let mut mgr = setup_mgr();
        let cmd = BookmarkDeleteBackgroundCmd::new(vec![1, 2]);
        let removed = cmd.apply(&mut mgr);
        assert_eq!(removed, 2);
        assert_eq!(mgr.get_bookmark_count(), 2);
    }

    #[test]
    fn test_background_delete_nonexistent() {
        let mut mgr = setup_mgr();
        let cmd = BookmarkDeleteBackgroundCmd::new(vec![999]);
        let removed = cmd.apply(&mut mgr);
        assert_eq!(removed, 0);
    }

    // -- AddressSet tests --

    #[test]
    fn test_address_set_single() {
        let set = AddressSet::single(addr(0x1000));
        assert!(!set.is_empty());
        assert_eq!(set.num_ranges(), 1);
        assert_eq!(set.min_address().unwrap().offset, 0x1000);
    }

    #[test]
    fn test_address_set_range() {
        let set = AddressSet::range(addr(0x1000), addr(0x2000));
        assert_eq!(set.num_ranges(), 1);
        let (s, e) = set.ranges()[0];
        assert_eq!(s.offset, 0x1000);
        assert_eq!(e.offset, 0x2000);
    }

    #[test]
    fn test_address_set_add_range() {
        let mut set = AddressSet::new();
        set.add_range(addr(0x1000), addr(0x2000));
        set.add_range(addr(0x3000), addr(0x4000));
        assert_eq!(set.num_ranges(), 2);
    }

    #[test]
    fn test_address_set_empty() {
        let set = AddressSet::new();
        assert!(set.is_empty());
        assert!(set.min_address().is_none());
    }
}
