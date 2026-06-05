//! Comment row object -- row representation for the comment window table.
//!
//! Ported from `ghidra.app.plugin.core.commentwindow.CommentRowObject` and
//! associated table mappers.

use super::{CommentEntry, CommentType};
use ghidra_core::Address;

/// A row in the comment window table.
///
/// Ported from `ghidra.app.plugin.core.commentwindow.CommentRowObject`.
///
/// Wraps a [`CommentEntry`] with additional display metadata
/// needed for the table view.
#[derive(Debug, Clone)]
pub struct CommentRowObject {
    /// The underlying comment entry.
    pub entry: CommentEntry,
    /// The display address string.
    pub display_address: String,
    /// The row index in the table.
    pub row_index: usize,
}

impl CommentRowObject {
    /// Create a new row object from a comment entry.
    pub fn new(entry: CommentEntry, row_index: usize) -> Self {
        let display_address = format!("0x{:x}", entry.address.offset);
        Self {
            entry,
            display_address,
            row_index,
        }
    }

    /// The address of this comment.
    pub fn address(&self) -> Address {
        self.entry.address
    }

    /// The comment type.
    pub fn comment_type(&self) -> CommentType {
        self.entry.comment_type
    }

    /// The comment text.
    pub fn text(&self) -> &str {
        &self.entry.text
    }

    /// The display address.
    pub fn address_display(&self) -> &str {
        &self.display_address
    }
}

impl PartialEq for CommentRowObject {
    fn eq(&self, other: &Self) -> bool {
        self.entry.address == other.entry.address
            && self.entry.comment_type == other.entry.comment_type
    }
}

impl Eq for CommentRowObject {}

impl PartialOrd for CommentRowObject {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CommentRowObject {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.entry
            .address
            .offset
            .cmp(&other.entry.address.offset)
            .then_with(|| self.entry.comment_type.cmp(&other.entry.comment_type))
    }
}

/// Mapper that converts a `CommentRowObject` to an address for navigation.
///
/// Ported from `ghidra.app.plugin.core.commentwindow.CommentRowObjectToAddressTableRowMapper`.
#[derive(Debug)]
pub struct CommentRowToAddressMapper;

impl CommentRowToAddressMapper {
    /// Map a row object to its address.
    pub fn get_address(row: &CommentRowObject) -> u64 {
        row.entry.address.offset
    }
}

/// Mapper that converts a `CommentRowObject` to a program location for navigation.
///
/// Ported from `ghidra.app.plugin.core.commentwindow.CommentRowObjectToProgramLocationTableRowMapper`.
#[derive(Debug)]
pub struct CommentRowToLocationMapper;

impl CommentRowToLocationMapper {
    /// Map a row object to a program location (address + field info).
    pub fn get_location(row: &CommentRowObject) -> (u64, CommentType) {
        (row.entry.address.offset, row.entry.comment_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comment_row_object() {
        let entry = CommentEntry::new(Address::new(0x1000), CommentType::Eol, "test");
        let row = CommentRowObject::new(entry, 0);
        assert_eq!(row.address().offset, 0x1000);
        assert_eq!(row.comment_type(), CommentType::Eol);
        assert_eq!(row.text(), "test");
        assert_eq!(row.address_display(), "0x1000");
    }

    #[test]
    fn test_comment_row_ordering() {
        let e1 = CommentEntry::new(Address::new(0x2000), CommentType::Eol, "b");
        let e2 = CommentEntry::new(Address::new(0x1000), CommentType::Pre, "a");
        let r1 = CommentRowObject::new(e1, 1);
        let r2 = CommentRowObject::new(e2, 0);
        assert!(r2 < r1); // r2 has lower address
    }

    #[test]
    fn test_comment_row_same_address_different_type() {
        let e1 = CommentEntry::new(Address::new(0x1000), CommentType::Eol, "eol");
        let e2 = CommentEntry::new(Address::new(0x1000), CommentType::Pre, "pre");
        let r1 = CommentRowObject::new(e1, 0);
        let r2 = CommentRowObject::new(e2, 1);
        assert_ne!(r1, r2);
        assert!(r1 < r2); // Eol < Pre
    }

    #[test]
    fn test_comment_row_equality() {
        let e1 = CommentEntry::new(Address::new(0x1000), CommentType::Eol, "a");
        let e2 = CommentEntry::new(Address::new(0x1000), CommentType::Eol, "b");
        let r1 = CommentRowObject::new(e1, 0);
        let r2 = CommentRowObject::new(e2, 1);
        // Same address and type => equal (text doesn't matter)
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_address_mapper() {
        let entry = CommentEntry::new(Address::new(0x400000), CommentType::Plate, "banner");
        let row = CommentRowObject::new(entry, 0);
        assert_eq!(CommentRowToAddressMapper::get_address(&row), 0x400000);
    }

    #[test]
    fn test_location_mapper() {
        let entry = CommentEntry::new(Address::new(0x400000), CommentType::Post, "post");
        let row = CommentRowObject::new(entry, 0);
        let (addr, ct) = CommentRowToLocationMapper::get_location(&row);
        assert_eq!(addr, 0x400000);
        assert_eq!(ct, CommentType::Post);
    }
}
