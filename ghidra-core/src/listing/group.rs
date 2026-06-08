//! Group (fragment/module) interface for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.Group`.
//!
//! Defines the [`Group`] trait for groupings of code units that may have
//! attributes such as names and comments. Groups are the building blocks
//! of the program tree (fragments and modules).

use crate::addr::Address;

/// The interface for groupings of code units.
///
/// Corresponds to `ghidra.program.model.listing.Group`. A group is either
/// a [`ProgramFragment`] (contiguous range of code units) or a
/// [`ProgramModule`] (hierarchical container of fragments and modules).
pub trait Group {
    /// Returns the comment associated with this group, or `None`.
    fn get_comment(&self) -> Option<&str>;

    /// Returns the name of this group.
    fn get_name(&self) -> &str;

    /// Returns `true` if this group has been deleted from the program.
    fn is_deleted(&self) -> bool;

    /// Returns the minimum address of this group.
    fn get_min_address(&self) -> Option<Address>;

    /// Returns the maximum address of this group.
    fn get_max_address(&self) -> Option<Address>;

    /// Returns the number of parents this group has.
    fn get_num_parents(&self) -> usize;

    /// Returns the name of the tree this group belongs to.
    fn get_tree_name(&self) -> &str;

    /// Returns `true` if the given address is within this group's address range.
    fn contains_address(&self, addr: &Address) -> bool {
        match (self.get_min_address(), self.get_max_address()) {
            (Some(min), Some(max)) => addr.offset >= min.offset && addr.offset <= max.offset,
            _ => false,
        }
    }
}

/// Concrete group data for serialization and storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupData {
    /// The group name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// The tree name this group belongs to.
    pub tree_name: String,
    /// Minimum address.
    pub min_address: Option<Address>,
    /// Maximum address.
    pub max_address: Option<Address>,
    /// Number of parent groups.
    pub num_parents: usize,
    /// Whether this group has been deleted.
    pub deleted: bool,
}

impl GroupData {
    /// Creates a new group data.
    pub fn new(name: impl Into<String>, tree_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
            tree_name: tree_name.into(),
            min_address: None,
            max_address: None,
            num_parents: 0,
            deleted: false,
        }
    }

    /// Sets the address range for this group.
    pub fn with_address_range(mut self, min: Address, max: Address) -> Self {
        self.min_address = Some(min);
        self.max_address = Some(max);
        self
    }

    /// Sets the comment for this group.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

impl Group for GroupData {
    fn get_comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn is_deleted(&self) -> bool {
        self.deleted
    }

    fn get_min_address(&self) -> Option<Address> {
        self.min_address
    }

    fn get_max_address(&self) -> Option<Address> {
        self.max_address
    }

    fn get_num_parents(&self) -> usize {
        self.num_parents
    }

    fn get_tree_name(&self) -> &str {
        &self.tree_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_data_basic() {
        let group = GroupData::new("my_fragment", "Tree1");
        assert_eq!(group.get_name(), "my_fragment");
        assert_eq!(group.get_tree_name(), "Tree1");
        assert!(!group.is_deleted());
        assert!(group.get_comment().is_none());
    }

    #[test]
    fn test_group_data_with_range() {
        let group = GroupData::new("f1", "Tree1")
            .with_address_range(Address::new(0x1000), Address::new(0x2000));
        assert_eq!(group.get_min_address().unwrap().offset, 0x1000);
        assert_eq!(group.get_max_address().unwrap().offset, 0x2000);
        assert!(group.contains_address(&Address::new(0x1500)));
        assert!(!group.contains_address(&Address::new(0x3000)));
    }

    #[test]
    fn test_group_data_with_comment() {
        let group = GroupData::new("f1", "Tree1").with_comment("my comment");
        assert_eq!(group.get_comment(), Some("my comment"));
    }
}
