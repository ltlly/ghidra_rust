//! Listing trait and in-memory implementation for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.Listing`.
//!
//! A [`Listing`] provides query and modification methods for code units,
//! instructions, data items, comments, and the program tree.

use crate::addr::{Address, AddressRange};
use crate::listing::code_unit::CodeUnitData;
use crate::listing::comment_type::CommentType;
use crate::listing::data::Data;
use crate::listing::instruction::Instruction;
use std::collections::{BTreeMap, HashMap};

/// All comments at a given address.
#[derive(Debug, Clone, Default)]
pub struct CodeUnitComments {
    /// The address these comments apply to.
    pub address: Address,
    /// End-of-line comment.
    pub eol_comment: Option<String>,
    /// Pre-comment (before the code unit).
    pub pre_comment: Option<String>,
    /// Post-comment (after the code unit).
    pub post_comment: Option<String>,
    /// Plate comment (multi-line banner).
    pub plate_comment: Option<String>,
    /// Repeatable comment.
    pub repeatable_comment: Option<String>,
}

impl CodeUnitComments {
    /// Create a new empty comment set for an address.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            ..Default::default()
        }
    }

    /// Get the comment for a specific type.
    pub fn get_comment(&self, comment_type: CommentType) -> Option<&str> {
        match comment_type {
            CommentType::Eol => self.eol_comment.as_deref(),
            CommentType::Pre => self.pre_comment.as_deref(),
            CommentType::Post => self.post_comment.as_deref(),
            CommentType::Plate => self.plate_comment.as_deref(),
            CommentType::Repeatable => self.repeatable_comment.as_deref(),
        }
    }

    /// Set the comment for a specific type.
    pub fn set_comment(&mut self, comment_type: CommentType, comment: Option<String>) {
        match comment_type {
            CommentType::Eol => self.eol_comment = comment,
            CommentType::Pre => self.pre_comment = comment,
            CommentType::Post => self.post_comment = comment,
            CommentType::Plate => self.plate_comment = comment,
            CommentType::Repeatable => self.repeatable_comment = comment,
        }
    }

    /// Returns true if all comment fields are `None`.
    pub fn is_empty(&self) -> bool {
        self.eol_comment.is_none()
            && self.pre_comment.is_none()
            && self.post_comment.is_none()
            && self.plate_comment.is_none()
            && self.repeatable_comment.is_none()
    }
}

/// The abstract interface for interacting with the program listing.
///
/// A [`Listing`] provides query and modification methods for code units,
/// instructions, data items, comments, and functions. This trait corresponds
/// to Ghidra's `Listing` Java interface.
pub trait Listing: Send + Sync {
    /// Returns the default tree name.
    fn default_tree_name(&self) -> &str {
        "Program Tree"
    }

    // ---- Code Unit queries ----

    /// Get the code unit that starts at the given address.
    fn get_code_unit_at(&self, addr: &Address) -> Option<&CodeUnitData>;

    /// Get the code unit that contains the given address.
    fn get_code_unit_containing(&self, addr: &Address) -> Option<&CodeUnitData>;

    /// Get the next code unit after the given address.
    fn get_code_unit_after(&self, addr: &Address) -> Option<&CodeUnitData>;

    /// Get the code unit before the given address.
    fn get_code_unit_before(&self, addr: &Address) -> Option<&CodeUnitData>;

    // ---- Instruction queries ----

    /// Get the instruction at the given address.
    fn get_instruction_at(&self, addr: &Address) -> Option<&Instruction>;

    /// Get the instruction containing the given address.
    fn get_instruction_containing(&self, addr: &Address) -> Option<&Instruction>;

    // ---- Data queries ----

    /// Get the data item (defined or undefined) at the given address.
    fn get_data_at(&self, addr: &Address) -> Option<&Data>;

    /// Get the data item containing the given address.
    fn get_data_containing(&self, addr: &Address) -> Option<&Data>;

    /// Get the defined data item at the given address.
    fn get_defined_data_at(&self, addr: &Address) -> Option<&Data>;

    // ---- Comments ----

    /// Get a comment of a specific type at an address.
    fn get_comment(&self, comment_type: CommentType, address: &Address) -> Option<String>;

    /// Get all comments at an address.
    fn get_all_comments(&self, address: &Address) -> CodeUnitComments;

    /// Set a comment of a specific type at an address.
    fn set_comment(
        &mut self,
        address: Address,
        comment_type: CommentType,
        comment: Option<String>,
    );

    // ---- Iteration ----

    /// Get code units in the given range (forward).
    fn get_code_units(&self, range: &AddressRange) -> Vec<&CodeUnitData>;

    /// Get instructions in the given range.
    fn get_instructions(&self, range: &AddressRange) -> Vec<&Instruction>;

    /// Get data items in the given range.
    fn get_data(&self, range: &AddressRange) -> Vec<&Data>;

    // ---- Modification ----

    /// Create a code unit at the given address.
    fn create_code_unit(
        &mut self,
        addr: Address,
        length: usize,
        bytes: Vec<u8>,
    ) -> Result<(), String>;

    /// Remove a code unit at the given address.
    fn remove_code_unit(&mut self, addr: &Address) -> Result<(), String>;

    /// Clear all code units in the given range.
    fn clear_code_units(&mut self, range: &AddressRange) -> Result<(), String>;

    /// Clear comments in the given range.
    fn clear_comments(&mut self, start_addr: Address, end_addr: Address);

    /// Returns true if the given range is entirely undefined.
    fn is_undefined(&self, start: Address, end: Address) -> bool;

    // ---- Statistics ----

    /// Total number of code units.
    fn get_num_code_units(&self) -> usize;

    /// Total number of defined data items.
    fn get_num_defined_data(&self) -> usize;

    /// Total number of instructions.
    fn get_num_instructions(&self) -> usize;

    // ---- Bounds ----

    /// Minimum address that has a code unit.
    fn get_min_address(&self) -> Option<Address>;

    /// Maximum address that has a code unit.
    fn get_max_address(&self) -> Option<Address>;

    /// Raw bytes at an address.
    fn get_bytes(&self, addr: Address, length: usize) -> Vec<u8>;
}

/// A simple in-memory implementation of [`Listing`] backed by `BTreeMap`s.
#[derive(Debug, Clone, Default)]
pub struct InMemoryListing {
    /// Code units indexed by address.
    code_units: BTreeMap<Address, CodeUnitData>,
    /// Instructions indexed by address.
    instructions: BTreeMap<Address, Instruction>,
    /// Data items indexed by address.
    data_items: BTreeMap<Address, Data>,
    /// Comments indexed by address.
    comments: HashMap<Address, CodeUnitComments>,
    /// Raw bytes storage.
    raw_bytes: HashMap<Address, Vec<u8>>,
}

impl InMemoryListing {
    /// Create a new empty listing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored code units.
    pub fn code_unit_count(&self) -> usize {
        self.code_units.len()
    }

    /// Number of stored instructions.
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Number of stored data items.
    pub fn data_count(&self) -> usize {
        self.data_items.len()
    }

    /// Returns true if a code unit starts at the given address.
    pub fn has_code_unit_at(&self, addr: &Address) -> bool {
        self.code_units.contains_key(addr)
    }

    /// Returns true if an instruction starts at the given address.
    pub fn has_instruction_at(&self, addr: &Address) -> bool {
        self.instructions.contains_key(addr)
    }

    /// Returns true if a data item starts at the given address.
    pub fn has_data_at(&self, addr: &Address) -> bool {
        self.data_items.contains_key(addr)
    }

    /// Number of addresses with at least one stored comment.
    pub fn comment_address_count(&self) -> usize {
        self.comments.len()
    }

    /// Insert an instruction.
    pub fn insert_instruction(&mut self, instruction: Instruction) {
        let addr = instruction.address;
        self.instructions.insert(addr, instruction);
    }

    /// Insert a data item.
    pub fn insert_data(&mut self, data: Data) {
        let addr = data.address;
        self.data_items.insert(addr, data);
    }
}

impl Listing for InMemoryListing {
    fn get_code_unit_at(&self, addr: &Address) -> Option<&CodeUnitData> {
        self.code_units.get(addr)
    }

    fn get_code_unit_containing(&self, addr: &Address) -> Option<&CodeUnitData> {
        self.code_units.values().find(|cu| {
            let len = cu.bytes.len() as u64;
            if len == 0 {
                return false;
            }
            let max_offset = cu.address.offset + len - 1;
            addr.offset >= cu.address.offset && addr.offset <= max_offset
        })
    }

    fn get_code_unit_after(&self, addr: &Address) -> Option<&CodeUnitData> {
        self.code_units
            .range((std::ops::Bound::Excluded(addr), std::ops::Bound::Unbounded))
            .next()
            .map(|(_, cu)| cu)
    }

    fn get_code_unit_before(&self, addr: &Address) -> Option<&CodeUnitData> {
        self.code_units
            .range((std::ops::Bound::Unbounded, std::ops::Bound::Excluded(addr)))
            .next_back()
            .map(|(_, cu)| cu)
    }

    fn get_instruction_at(&self, addr: &Address) -> Option<&Instruction> {
        self.instructions.get(addr)
    }

    fn get_instruction_containing(&self, addr: &Address) -> Option<&Instruction> {
        self.instructions.values().find(|ins| ins.contains(addr))
    }

    fn get_data_at(&self, addr: &Address) -> Option<&Data> {
        self.data_items.get(addr)
    }

    fn get_data_containing(&self, addr: &Address) -> Option<&Data> {
        self.data_items.values().find(|d| d.contains(addr))
    }

    fn get_defined_data_at(&self, addr: &Address) -> Option<&Data> {
        self.data_items.get(addr).filter(|d| d.is_defined)
    }

    fn get_comment(&self, comment_type: CommentType, address: &Address) -> Option<String> {
        self.comments
            .get(address)
            .and_then(|c| c.get_comment(comment_type))
            .map(|s| s.to_string())
    }

    fn get_all_comments(&self, address: &Address) -> CodeUnitComments {
        self.comments
            .get(address)
            .cloned()
            .unwrap_or_else(|| CodeUnitComments::new(*address))
    }

    fn set_comment(
        &mut self,
        address: Address,
        comment_type: CommentType,
        comment: Option<String>,
    ) {
        self.comments
            .entry(address)
            .or_insert_with(|| CodeUnitComments::new(address))
            .set_comment(comment_type, comment);
    }

    fn get_code_units(&self, range: &AddressRange) -> Vec<&CodeUnitData> {
        self.code_units
            .range(range.start..=range.end)
            .map(|(_, cu)| cu)
            .collect()
    }

    fn get_instructions(&self, range: &AddressRange) -> Vec<&Instruction> {
        self.instructions
            .range(range.start..=range.end)
            .map(|(_, ins)| ins)
            .collect()
    }

    fn get_data(&self, range: &AddressRange) -> Vec<&Data> {
        self.data_items
            .range(range.start..=range.end)
            .map(|(_, d)| d)
            .collect()
    }

    fn create_code_unit(
        &mut self,
        addr: Address,
        _length: usize,
        bytes: Vec<u8>,
    ) -> Result<(), String> {
        let cu = CodeUnitData::new(addr, bytes.clone(), "db", false);
        self.code_units.insert(addr, cu);
        self.raw_bytes.insert(addr, bytes);
        Ok(())
    }

    fn remove_code_unit(&mut self, addr: &Address) -> Result<(), String> {
        self.code_units.remove(addr);
        self.instructions.remove(addr);
        self.data_items.remove(addr);
        self.raw_bytes.remove(addr);
        Ok(())
    }

    fn clear_code_units(&mut self, range: &AddressRange) -> Result<(), String> {
        let addrs: Vec<Address> = self
            .code_units
            .range(range.start..=range.end)
            .map(|(a, _)| *a)
            .collect();
        for addr in addrs {
            self.code_units.remove(&addr);
            self.instructions.remove(&addr);
            self.data_items.remove(&addr);
            self.raw_bytes.remove(&addr);
            self.comments.remove(&addr);
        }
        Ok(())
    }

    fn clear_comments(&mut self, start_addr: Address, end_addr: Address) {
        let to_remove: Vec<Address> = self
            .comments
            .keys()
            .filter(|a| a.offset >= start_addr.offset && a.offset <= end_addr.offset)
            .copied()
            .collect();
        for addr in to_remove {
            self.comments.remove(&addr);
        }
    }

    fn is_undefined(&self, start: Address, end: Address) -> bool {
        for offset in start.offset..=end.offset {
            let addr = Address::new(offset);
            if self.code_units.contains_key(&addr)
                || self.instructions.contains_key(&addr)
                || self.data_items.contains_key(&addr)
            {
                return false;
            }
        }
        true
    }

    fn get_num_code_units(&self) -> usize {
        self.code_units.len()
    }

    fn get_num_defined_data(&self) -> usize {
        self.data_items.values().filter(|d| d.is_defined).count()
    }

    fn get_num_instructions(&self) -> usize {
        self.instructions.len()
    }

    fn get_min_address(&self) -> Option<Address> {
        self.code_units.keys().next().copied()
    }

    fn get_max_address(&self) -> Option<Address> {
        self.code_units.keys().next_back().copied()
    }

    fn get_bytes(&self, addr: Address, length: usize) -> Vec<u8> {
        if let Some(data) = self.raw_bytes.get(&addr) {
            let take = length.min(data.len());
            data[..take].to_vec()
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_listing_create_and_query() {
        let mut listing = InMemoryListing::new();
        let addr = Address::new(0x1000);
        listing.create_code_unit(addr, 1, vec![0x90]).unwrap();
        assert!(listing.has_code_unit_at(&addr));
        assert_eq!(listing.get_num_code_units(), 1);
    }

    #[test]
    fn test_listing_comments() {
        let mut listing = InMemoryListing::new();
        let addr = Address::new(0x1000);
        listing.create_code_unit(addr, 1, vec![0x90]).unwrap();
        listing.set_comment(addr, CommentType::Eol, Some("note".to_string()));
        assert_eq!(
            listing.get_comment(CommentType::Eol, &addr),
            Some("note".to_string())
        );
        assert_eq!(listing.comment_address_count(), 1);
    }

    #[test]
    fn test_listing_remove() {
        let mut listing = InMemoryListing::new();
        let addr = Address::new(0x1000);
        listing.create_code_unit(addr, 1, vec![0x90]).unwrap();
        listing.remove_code_unit(&addr).unwrap();
        assert!(!listing.has_code_unit_at(&addr));
    }

    #[test]
    fn test_listing_is_undefined() {
        let mut listing = InMemoryListing::new();
        listing.create_code_unit(Address::new(0x1000), 1, vec![0x90]).unwrap();
        assert!(listing.is_undefined(Address::new(0x2000), Address::new(0x2010)));
        assert!(!listing.is_undefined(Address::new(0x1000), Address::new(0x1000)));
    }

    #[test]
    fn test_code_unit_comments() {
        let mut comments = CodeUnitComments::new(Address::new(0x1000));
        assert!(comments.is_empty());
        comments.set_comment(CommentType::Eol, Some("end of line".to_string()));
        assert_eq!(
            comments.get_comment(CommentType::Eol),
            Some("end of line")
        );
        assert!(!comments.is_empty());
    }

    #[test]
    fn test_listing_insert_instruction() {
        let mut listing = InMemoryListing::new();
        let ins = Instruction::new(Address::new(0x1000), 3, vec![0x48, 0x89, 0xe5], "mov");
        listing.insert_instruction(ins);
        assert!(listing.has_instruction_at(&Address::new(0x1000)));
        assert_eq!(listing.get_num_instructions(), 1);
    }

    #[test]
    fn test_listing_insert_data() {
        let mut listing = InMemoryListing::new();
        let data = Data::new(Address::new(0x2000), 4, None);
        listing.insert_data(data);
        assert!(listing.has_data_at(&Address::new(0x2000)));
        assert_eq!(listing.get_num_defined_data(), 0); // undefined data
    }
}
