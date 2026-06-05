//! Bookmark table row mappers.
//!
//! Ported from Ghidra's:
//! - `BookmarkRowObjectToAddressTableRowMapper` -- maps bookmark rows to addresses
//! - `BookmarkRowObjectToProgramLocationTableRowMapper` -- maps bookmark rows to
//!   program locations
//!
//! These mappers allow the bookmark table to participate in Ghidra's
//! cross-table navigation system (clicking a row navigates to the address).

use ghidra_core::addr::Address;

use super::model::{Bookmark, BookmarkManager, BookmarkRowObject};

// ---------------------------------------------------------------------------
// BookmarkRowObjectToAddressTableRowMapper
// ---------------------------------------------------------------------------

/// Maps a bookmark row object to an address for table row cross-linking.
///
/// Ported from Ghidra's `BookmarkRowObjectToAddressTableRowMapper`. When
/// a bookmark table row is selected, this mapper produces the address
/// that should be navigated to in the listing.
///
/// # Example
///
/// ```
/// use ghidra_features::base::bookmark::*;
/// use ghidra_core::addr::Address;
///
/// let mapper = BookmarkRowObjectToAddressTableRowMapper;
/// let bookmark = Bookmark::new(1, Address::new(0x401000), "Note", "Cat", "Msg");
/// let addr = mapper.bookmark_to_address(&bookmark);
/// assert_eq!(addr.offset, 0x401000);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct BookmarkRowObjectToAddressTableRowMapper;

impl BookmarkRowObjectToAddressTableRowMapper {
    /// Maps a Bookmark to its address.
    pub fn bookmark_to_address(&self, bookmark: &Bookmark) -> Address {
        *bookmark.address()
    }

    /// Maps a Bookmark (by reference) to its address.
    pub fn get_address(&self, bookmark: &Bookmark) -> Address {
        *bookmark.address()
    }
}

// ---------------------------------------------------------------------------
// BookmarkRowObjectToProgramLocationTableRowMapper
// ---------------------------------------------------------------------------

/// Maps a bookmark row object to a program location for table navigation.
///
/// Ported from Ghidra's `BookmarkRowObjectToProgramLocationTableRowMapper`.
/// This mapper extends the address mapping with additional location context
/// such as the program name and the specific code unit.
///
/// # Example
///
/// ```
/// use ghidra_features::base::bookmark::*;
/// use ghidra_core::addr::Address;
///
/// let mapper = BookmarkRowObjectToProgramLocationTableRowMapper;
/// let bookmark = Bookmark::new(5, Address::new(0x401000), "Note", "Cat", "Msg");
/// let loc = mapper.bookmark_to_program_location(&bookmark);
/// assert_eq!(loc.address().offset, 0x401000);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct BookmarkRowObjectToProgramLocationTableRowMapper;

impl BookmarkRowObjectToProgramLocationTableRowMapper {
    /// Returns a program location for a Bookmark.
    pub fn bookmark_to_program_location(&self, bookmark: &Bookmark) -> ProgramLocation {
        ProgramLocation {
            address: *bookmark.address(),
            program_name: String::new(),
            row_object_key: bookmark.id(),
        }
    }
}

/// A program location for table navigation.
///
/// This is a simplified version of Ghidra's ProgramLocation, containing
/// just the address and identifying information needed for cross-table
/// navigation.
#[derive(Debug, Clone)]
pub struct ProgramLocation {
    /// The address to navigate to.
    address: Address,
    /// The program name.
    program_name: String,
    /// The row object key (bookmark ID).
    row_object_key: u64,
}

impl ProgramLocation {
    /// Creates a new program location.
    pub fn new(address: Address, program_name: impl Into<String>, row_object_key: u64) -> Self {
        Self {
            address,
            program_name: program_name.into(),
            row_object_key,
        }
    }

    /// Returns the address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Returns the row object key.
    pub fn row_object_key(&self) -> u64 {
        self.row_object_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_address_mapper_with_bookmark() {
        let mapper = BookmarkRowObjectToAddressTableRowMapper;
        let bookmark = Bookmark::new(1, addr(0x2000), "Warning", "Test", "Test msg");
        let a = mapper.bookmark_to_address(&bookmark);
        assert_eq!(a.offset, 0x2000);
    }

    #[test]
    fn test_address_mapper_get_address() {
        let mapper = BookmarkRowObjectToAddressTableRowMapper;
        let bookmark = Bookmark::new(1, addr(0x401000), "Note", "Cat", "Msg");
        let a = mapper.get_address(&bookmark);
        assert_eq!(a.offset, 0x401000);
    }

    #[test]
    fn test_location_mapper_with_bookmark() {
        let mapper = BookmarkRowObjectToProgramLocationTableRowMapper;
        let bookmark = Bookmark::new(10, addr(0x5000), "Note", "Cat", "Msg");
        let loc = mapper.bookmark_to_program_location(&bookmark);
        assert_eq!(loc.address().offset, 0x5000);
        assert_eq!(loc.row_object_key(), 10);
    }

    #[test]
    fn test_program_location() {
        let loc = ProgramLocation::new(addr(0x1000), "test_program", 42);
        assert_eq!(loc.address().offset, 0x1000);
        assert_eq!(loc.program_name(), "test_program");
        assert_eq!(loc.row_object_key(), 42);
    }

    #[test]
    fn test_mapper_with_manager() {
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "Cat1", "Msg1");
        mgr.set_bookmark(&addr(0x2000), "Warning", "Cat2", "Msg2");

        assert_eq!(mgr.get_bookmark_count(), 2);

        let addr_mapper = BookmarkRowObjectToAddressTableRowMapper;
        let loc_mapper = BookmarkRowObjectToProgramLocationTableRowMapper;

        for id in mgr.bookmark_ids() {
            let bm = mgr.get_bookmark(id).unwrap();
            let a = addr_mapper.bookmark_to_address(bm);
            let loc = loc_mapper.bookmark_to_program_location(bm);
            assert_eq!(a, loc.address());
            assert_eq!(bm.id(), loc.row_object_key());
        }
    }

    #[test]
    fn test_program_location_display() {
        let loc = ProgramLocation::new(addr(0x1000), "prog", 1);
        assert_eq!(loc.program_name(), "prog");
        assert_eq!(loc.row_object_key(), 1);
    }
}
