//! Varnode -- raw variable node in pcode.
//!
//! Ported from `ghidra.program.model.pcode.Varnode` and
//! `ghidra.program.model.pcode.VarnodeAST`.

use crate::addr::Address;
use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// Varnode -- raw variable location
// ============================================================================

/// A raw variable node: a location (address + size) in a program.
///
/// Corresponds to Ghidra's `Varnode`. This is the simplest form -- just a
/// variable location and size, not part of a syntax tree. A raw varnode is
/// said to be "free"; it is not attached to any variable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Varnode {
    /// The address of this varnode.
    pub address: Address,
    /// The size of this varnode in bytes.
    pub size: u32,
    /// The address space ID (used for encoding/decoding).
    pub space_id: u32,
    /// The offset within the address space.
    pub offset: u64,
}

/// The set of Varnode pieces referred to by a single Varnode in join space.
///
/// A join varnode represents a logical value split across multiple physical
/// storage locations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Join {
    /// The list of individual Varnodes being joined.
    pub pieces: Vec<Varnode>,
    /// The size (in bytes) of the logical whole.
    pub logical_size: u32,
}

/// Constants matching Java Varnode class.
impl Varnode {
    /// The maximum number of bytes in a varnode (16 bytes / 128 bits).
    pub const MAX_VARNODE_SIZE: u32 = 16;

    /// Create a new varnode at the given address and size.
    pub fn new(address: Address, size: u32) -> Self {
        Self {
            address,
            size,
            space_id: 0,
            offset: address.offset,
        }
    }

    /// Create a varnode with explicit space ID and offset.
    pub fn with_space(address: Address, size: u32, space_id: u32, offset: u64) -> Self {
        Self {
            address,
            size,
            space_id,
            offset,
        }
    }

    /// Create a varnode for the constant address space.
    pub fn constant(offset: u64, size: u32) -> Self {
        Self {
            address: Address::new(offset),
            size,
            space_id: 0, // const space
            offset,
        }
    }

    /// Create a varnode for the register address space.
    pub fn register(offset: u64, size: u32) -> Self {
        Self {
            address: Address::new(offset),
            size,
            space_id: 1, // register space
            offset,
        }
    }

    /// Create a varnode representing a stack variable.
    pub fn stack(offset: u64, size: u32) -> Self {
        Self {
            address: Address::new(offset),
            size,
            space_id: 2, // stack space
            offset,
        }
    }

    /// Create a varnode for the unique (temporary) address space.
    pub fn unique(offset: u64, size: u32) -> Self {
        Self {
            address: Address::new(offset),
            size,
            space_id: 3, // unique space
            offset,
        }
    }

    /// Returns the address of this varnode.
    pub fn get_address(&self) -> Address {
        self.address
    }

    /// Returns the offset within the address space.
    pub fn get_offset(&self) -> u64 {
        self.offset
    }

    /// Returns the size in bytes.
    pub fn get_size(&self) -> u32 {
        self.size
    }

    /// Returns the address space ID.
    pub fn get_space_id(&self) -> u32 {
        self.space_id
    }

    /// Returns `true` if this is in the constant address space.
    pub fn is_constant(&self) -> bool {
        self.space_id == 0
    }

    /// Returns `true` if this is in the register address space.
    pub fn is_register(&self) -> bool {
        self.space_id == 1
    }

    /// Returns `true` if this is in the stack address space.
    pub fn is_stack(&self) -> bool {
        self.space_id == 2
    }

    /// Returns `true` if this is in the unique (temporary) address space.
    pub fn is_unique(&self) -> bool {
        self.space_id == 3
    }

    /// Returns `true` if this is a memory (RAM) varnode.
    pub fn is_memory(&self) -> bool {
        self.space_id >= 100 // convention: RAM space IDs are >= 100
    }

    /// Returns `true` if this varnode represents a register.
    pub fn is_register_address(&self) -> bool {
        self.is_register()
    }

    /// Returns a bitmask of the appropriate width for this varnode's size.
    pub fn get_mask(&self) -> u64 {
        match self.size {
            0 => 0,
            n if n >= 8 => u64::MAX,
            n => (1u64 << (n * 8)) - 1,
        }
    }

    /// Returns `true` if the address is the join space (representing a
    /// multi-location variable).
    pub fn is_join(&self) -> bool {
        self.space_id == 4 // join space convention
    }

    /// Returns `true` if two varnodes overlap.
    pub fn overlaps(&self, other: &Varnode) -> bool {
        if self.space_id != other.space_id {
            return false;
        }
        let self_end = self.offset + self.size as u64;
        let other_end = other.offset + other.size as u64;
        self.offset < other_end && other.offset < self_end
    }

    /// Returns `true` if this varnode contains the given varnode.
    pub fn contains(&self, other: &Varnode) -> bool {
        if self.space_id != other.space_id {
            return false;
        }
        let self_end = self.offset + self.size as u64;
        let other_end = other.offset + other.size as u64;
        self.offset <= other.offset && self_end >= other_end
    }

    /// Returns `true` if this varnode is adjacent to (immediately follows)
    /// `other`.
    pub fn is_adjacent(&self, other: &Varnode) -> bool {
        if self.space_id != other.space_id {
            return false;
        }
        self.offset + self.size as u64 == other.offset
            || other.offset + other.size as u64 == self.offset
    }

    /// Returns `true` if this varnode is "free" (not linked into a syntax tree).
    /// In the raw form, all varnodes are free.
    pub fn is_free(&self) -> bool {
        true
    }

    /// Returns `true` if this varnode is an input to the function (not defined
    /// by any pcode op).
    pub fn is_input(&self) -> bool {
        false // overridden in VarnodeAST
    }

    /// Returns `true` if this varnode is persistent across calls.
    pub fn is_persistent(&self) -> bool {
        false // overridden in VarnodeAST
    }

    /// Returns `true` if this varnode is tied to an address (not movable).
    pub fn is_addr_tied(&self) -> bool {
        false // overridden in VarnodeAST
    }

    /// Returns `true` if this varnode is unaffected (preserved) across calls.
    pub fn is_unaffected(&self) -> bool {
        false // overridden in VarnodeAST
    }

    /// Returns a bitmask array for sizes 0..=8.
    pub const SIZE_MASKS: [u64; 9] = [
        0,
        0xFF,
        0xFFFF,
        0xFF_FFFF,
        0xFFFF_FFFF,
        0xFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF,
        0xFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
}

impl fmt::Display for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}:{:x}, {})", self.space_id, self.offset, self.size)
    }
}

// ============================================================================
// VarnodeAST -- syntax tree varnode with graph edges
// ============================================================================

/// A varnode that participates in the Abstract Syntax Tree.
///
/// Corresponds to Ghidra's `VarnodeAST`. Extends [`Varnode`] with:
/// - A defining [`PcodeOpAST`] (in-edge).
/// - A list of descendant PcodeOps that use this varnode (out-edges).
/// - A reference to the [`HighVariable`] it is an instance of.
/// - Flags for input, address-tied, persistent, unaffected, and free state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarnodeAST {
    /// The underlying raw varnode data.
    pub vn: Varnode,
    /// Whether this is a function input varnode.
    pub is_input: bool,
    /// Whether this varnode's value is tied to its address.
    pub is_addr_tied: bool,
    /// Whether this varnode is persistent across calls.
    pub is_persistent: bool,
    /// Whether this varnode is unaffected (callee-saved) across calls.
    pub is_unaffected: bool,
    /// Whether this varnode is free (not linked to any HighVariable).
    pub is_free: bool,
    /// Unique id for distinguishing otherwise identical varnodes.
    pub unique_id: u32,
    /// Forced merge group within this varnode's high-level variable.
    pub merge_group: i16,
    /// Index of the HighVariable this varnode is an instance of (u32::MAX if none).
    pub high_variable_index: u32,
    /// Index of the PcodeOpAST that defines this varnode (in-edge, u32::MAX if none).
    pub def_index: u32,
    /// Indices of PcodeOps that use this varnode (out-edges).
    pub descendants: Vec<u32>,
}

impl VarnodeAST {
    /// Create a new AST varnode.
    pub fn new(address: Address, size: u32, unique_id: u32) -> Self {
        Self {
            vn: Varnode::new(address, size),
            is_input: false,
            is_addr_tied: false,
            is_persistent: false,
            is_unaffected: false,
            is_free: true,
            unique_id,
            merge_group: 0,
            high_variable_index: u32::MAX,
            def_index: u32::MAX,
            descendants: Vec::new(),
        }
    }

    /// Create from an existing raw varnode.
    pub fn from_varnode(vn: Varnode, unique_id: u32) -> Self {
        Self {
            vn,
            is_input: false,
            is_addr_tied: false,
            is_persistent: false,
            is_unaffected: false,
            is_free: true,
            unique_id,
            merge_group: 0,
            high_variable_index: u32::MAX,
            def_index: u32::MAX,
            descendants: Vec::new(),
        }
    }

    /// Returns the address.
    pub fn get_address(&self) -> Address {
        self.vn.address
    }

    /// Returns the size in bytes.
    pub fn get_size(&self) -> u32 {
        self.vn.size
    }

    /// Returns the unique id.
    pub fn get_unique_id(&self) -> u32 {
        self.unique_id
    }

    /// Returns `true` if this is a function input.
    pub fn is_input(&self) -> bool {
        self.is_input
    }

    /// Returns `true` if this is a free varnode (not linked to a HighVariable).
    pub fn is_free(&self) -> bool {
        self.is_free
    }

    /// Returns `true` if this is persistent across calls.
    pub fn is_persistent(&self) -> bool {
        self.is_persistent
    }

    /// Returns `true` if this is address-tied.
    pub fn is_addr_tied(&self) -> bool {
        self.is_addr_tied
    }

    /// Returns `true` if this is unaffected (callee-saved) across calls.
    pub fn is_unaffected(&self) -> bool {
        self.is_unaffected
    }

    /// Returns the merge group.
    pub fn get_merge_group(&self) -> i16 {
        self.merge_group
    }

    /// Set the defining PcodeOp index.
    pub fn set_def(&mut self, def_index: u32) {
        self.def_index = def_index;
    }

    /// Returns the defining PcodeOp index, or `None` if not defined.
    pub fn get_def_index(&self) -> Option<u32> {
        if self.def_index == u32::MAX {
            None
        } else {
            Some(self.def_index)
        }
    }

    /// Add a descendant (user) PcodeOp index.
    pub fn add_descendant(&mut self, op_index: u32) {
        self.descendants.push(op_index);
    }

    /// Remove a descendant PcodeOp index.
    pub fn remove_descendant(&mut self, op_index: u32) {
        self.descendants.retain(|&x| x != op_index);
    }

    /// Returns the number of descendant (user) PcodeOps.
    pub fn num_descendants(&self) -> usize {
        self.descendants.len()
    }

    /// Returns the HighVariable index, or `None`.
    pub fn get_high_variable_index(&self) -> Option<u32> {
        if self.high_variable_index == u32::MAX {
            None
        } else {
            Some(self.high_variable_index)
        }
    }

    /// Set the HighVariable index.
    pub fn set_high(&mut self, hv_index: u32) {
        self.high_variable_index = hv_index;
        self.is_free = false;
    }

    /// Mark this varnode as a function input.
    pub fn set_input(&mut self, input: bool) {
        self.is_input = input;
    }

    /// Mark this varnode as address-tied.
    pub fn set_addr_tied(&mut self, tied: bool) {
        self.is_addr_tied = tied;
    }

    /// Mark this varnode as persistent.
    pub fn set_persistent(&mut self, persistent: bool) {
        self.is_persistent = persistent;
    }

    /// Mark this varnode as unaffected (callee-saved).
    pub fn set_unaffected(&mut self, unaffected: bool) {
        self.is_unaffected = unaffected;
    }

    /// Mark this varnode as free (not linked to a HighVariable).
    pub fn set_free(&mut self, free: bool) {
        self.is_free = free;
    }
}

impl fmt::Display for VarnodeAST {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} (def: {:?}, uses: {})",
            self.unique_id,
            self.vn,
            self.get_def_index(),
            self.descendants.len()
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varnode_creation() {
        let vn = Varnode::new(Address::new(0x1000), 4);
        assert_eq!(vn.get_address(), Address::new(0x1000));
        assert_eq!(vn.get_size(), 4);
        assert_eq!(vn.get_offset(), 0x1000);
    }

    #[test]
    fn test_varnode_constant() {
        let vn = Varnode::constant(0x42, 8);
        assert!(vn.is_constant());
        assert!(!vn.is_register());
    }

    #[test]
    fn test_varnode_register() {
        let vn = Varnode::register(0x10, 4);
        assert!(vn.is_register());
    }

    #[test]
    fn test_varnode_stack() {
        let vn = Varnode::stack(0xFFFF_FFFF_FFFF_FFF0u64, 8);
        assert!(vn.is_stack());
    }

    #[test]
    fn test_varnode_unique() {
        let vn = Varnode::unique(0x100, 4);
        assert!(vn.is_unique());
    }

    #[test]
    fn test_varnode_mask() {
        assert_eq!(Varnode::new(Address::new(0), 0).get_mask(), 0);
        assert_eq!(Varnode::new(Address::new(0), 1).get_mask(), 0xFF);
        assert_eq!(Varnode::new(Address::new(0), 2).get_mask(), 0xFFFF);
        assert_eq!(Varnode::new(Address::new(0), 4).get_mask(), 0xFFFF_FFFF);
        assert_eq!(Varnode::new(Address::new(0), 8).get_mask(), u64::MAX);
    }

    #[test]
    fn test_varnode_overlaps() {
        let a = Varnode::new(Address::new(0x100), 4);
        let b = Varnode::new(Address::new(0x102), 4);
        let c = Varnode::new(Address::new(0x200), 4);
        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_varnode_contains() {
        let a = Varnode::new(Address::new(0x100), 16);
        let b = Varnode::new(Address::new(0x104), 4);
        assert!(a.contains(&b));
        assert!(!b.contains(&a));
    }

    #[test]
    fn test_varnode_adjacent() {
        let a = Varnode::new(Address::new(0x100), 4);
        let b = Varnode::new(Address::new(0x104), 4);
        assert!(a.is_adjacent(&b));
        assert!(b.is_adjacent(&a));
        let c = Varnode::new(Address::new(0x200), 4);
        assert!(!a.is_adjacent(&c));
    }

    #[test]
    fn test_varnode_display() {
        let vn = Varnode::new(Address::new(0x401000), 4);
        let s = format!("{}", vn);
        assert!(s.contains("401000"));
        assert!(s.contains("4"));
    }

    #[test]
    fn test_join() {
        let pieces = vec![
            Varnode::register(0, 4),
            Varnode::register(4, 4),
        ];
        let join = Join {
            pieces,
            logical_size: 8,
        };
        assert_eq!(join.logical_size, 8);
        assert_eq!(join.pieces.len(), 2);
    }

    #[test]
    fn test_varnode_ast_creation() {
        let vn = VarnodeAST::new(Address::new(0x1000), 4, 7);
        assert_eq!(vn.get_unique_id(), 7);
        assert!(vn.is_free());
        assert!(!vn.is_input());
        assert_eq!(vn.get_def_index(), None);
        assert_eq!(vn.num_descendants(), 0);
    }

    #[test]
    fn test_varnode_ast_def_use() {
        let mut vn = VarnodeAST::new(Address::new(0x1000), 4, 0);
        vn.set_def(5);
        assert_eq!(vn.get_def_index(), Some(5));
        vn.add_descendant(10);
        vn.add_descendant(11);
        assert_eq!(vn.num_descendants(), 2);
        vn.remove_descendant(10);
        assert_eq!(vn.num_descendants(), 1);
    }

    #[test]
    fn test_varnode_ast_high_variable() {
        let mut vn = VarnodeAST::new(Address::new(0x1000), 4, 0);
        assert!(vn.get_high_variable_index().is_none());
        assert!(vn.is_free());
        vn.set_high(42);
        assert_eq!(vn.get_high_variable_index(), Some(42));
        assert!(!vn.is_free());
    }

    #[test]
    fn test_varnode_ast_flags() {
        let mut vn = VarnodeAST::new(Address::new(0x1000), 4, 0);
        vn.set_input(true);
        vn.set_addr_tied(true);
        vn.set_persistent(true);
        vn.set_unaffected(true);
        assert!(vn.is_input());
        assert!(vn.is_addr_tied());
        assert!(vn.is_persistent());
        assert!(vn.is_unaffected());
    }

    #[test]
    fn test_varnode_ast_display() {
        let vn = VarnodeAST::new(Address::new(0x401000), 4, 99);
        let s = format!("{}", vn);
        assert!(s.contains("99"));
        assert!(s.contains("401000"));
    }

    #[test]
    fn test_varnode_size_masks() {
        assert_eq!(Varnode::SIZE_MASKS[0], 0);
        assert_eq!(Varnode::SIZE_MASKS[1], 0xFF);
        assert_eq!(Varnode::SIZE_MASKS[4], 0xFFFF_FFFF);
        assert_eq!(Varnode::SIZE_MASKS[8], u64::MAX);
    }
}
