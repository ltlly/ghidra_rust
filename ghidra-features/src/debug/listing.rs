//! Listing (code unit) model for the Debug framework.
//!
//! Ported from `ghidra.trace.model.listing` — includes [`TraceCodeUnit`],
//! [`TraceInstruction`], [`TraceData`], [`TraceCodeManager`],
//! and supporting types.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use super::core_types::Lifespan;

// ---------------------------------------------------------------------------
// CodeUnitType
// ---------------------------------------------------------------------------

/// The type of a code unit.
///
/// Ported from `ghidra.program.model.listing.CodeUnit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeUnitType {
    /// An instruction.
    Instruction,
    /// Defined data.
    DefinedData,
    /// Undefined data.
    UndefinedData,
}

impl fmt::Display for CodeUnitType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeUnitType::Instruction => write!(f, "Instruction"),
            CodeUnitType::DefinedData => write!(f, "DefinedData"),
            CodeUnitType::UndefinedData => write!(f, "UndefinedData"),
        }
    }
}

// ---------------------------------------------------------------------------
// TraceCodeUnit (unified)
// ---------------------------------------------------------------------------

/// A code unit in a trace listing.
///
/// Ported from `ghidra.trace.model.listing.TraceCodeUnit`. This is a unified
/// representation covering instructions, defined data, and undefined data.
#[derive(Debug, Clone)]
pub struct TraceCodeUnit {
    /// Unique key.
    key: u64,
    /// The code unit type.
    unit_type: CodeUnitType,
    /// The address space name.
    space_name: String,
    /// The start address.
    pub address: u64,
    /// The length in bytes.
    length: usize,
    /// The mnemonic (for instructions) or data type name (for data).
    mnemonic: String,
    /// The operand representations (for instructions).
    operands: Vec<String>,
    /// Raw bytes of the code unit.
    bytes: Vec<u8>,
    /// The lifespan of this code unit.
    pub lifespan: Lifespan,
    /// Whether deleted.
    deleted: bool,
}

impl TraceCodeUnit {
    /// Create an instruction code unit.
    pub fn new_instruction(
        key: u64,
        space_name: impl Into<String>,
        address: u64,
        mnemonic: impl Into<String>,
        operands: Vec<String>,
        bytes: Vec<u8>,
        lifespan: Lifespan,
    ) -> Self {
        let length = bytes.len();
        Self {
            key,
            unit_type: CodeUnitType::Instruction,
            space_name: space_name.into(),
            address,
            length,
            mnemonic: mnemonic.into(),
            operands,
            bytes,
            lifespan,
            deleted: false,
        }
    }

    /// Create a defined data code unit.
    pub fn new_data(
        key: u64,
        space_name: impl Into<String>,
        address: u64,
        data_type_name: impl Into<String>,
        length: usize,
        bytes: Vec<u8>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            unit_type: CodeUnitType::DefinedData,
            space_name: space_name.into(),
            address,
            length,
            mnemonic: data_type_name.into(),
            operands: Vec::new(),
            bytes,
            lifespan,
            deleted: false,
        }
    }

    /// Create an undefined data code unit.
    pub fn new_undefined(
        key: u64,
        space_name: impl Into<String>,
        address: u64,
        length: usize,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            unit_type: CodeUnitType::UndefinedData,
            space_name: space_name.into(),
            address,
            length,
            mnemonic: "undefined".to_string(),
            operands: Vec::new(),
            bytes: vec![0; length],
            lifespan,
            deleted: false,
        }
    }

    /// Returns the unique key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Returns the code unit type.
    pub fn unit_type(&self) -> CodeUnitType {
        self.unit_type
    }

    /// Returns the address space name.
    pub fn space_name(&self) -> &str {
        &self.space_name
    }

    /// Returns the length in bytes.
    pub fn length(&self) -> usize {
        self.length
    }

    /// Returns the end address (inclusive).
    pub fn max_address(&self) -> u64 {
        self.address + self.length as u64 - 1
    }

    /// Returns the mnemonic or data type name.
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Returns the operand representations.
    pub fn operands(&self) -> &[String] {
        &self.operands
    }

    /// Returns the raw bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns `true` if this is an instruction.
    pub fn is_instruction(&self) -> bool {
        self.unit_type == CodeUnitType::Instruction
    }

    /// Returns `true` if this is defined data.
    pub fn is_data(&self) -> bool {
        self.unit_type == CodeUnitType::DefinedData
    }

    /// Returns a formatted representation (mnemonic + operands).
    pub fn representation(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.operands.join(", "))
        }
    }

    /// Check if this code unit contains the given address.
    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.address && address <= self.max_address()
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }

    /// Delete this code unit.
    pub fn delete(&mut self) {
        self.deleted = true;
    }
}

impl fmt::Display for TraceCodeUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{:x}: {} ({}, {} bytes)",
            self.address,
            self.representation(),
            self.unit_type,
            self.length
        )
    }
}

// ---------------------------------------------------------------------------
// CommentType
// ---------------------------------------------------------------------------

/// The type of a comment at a code unit.
///
/// Ported from `ghidra.program.model.listing.CodeUnit` comment types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CommentType {
    /// Pre-comment (above).
    Pre,
    /// End-of-line comment.
    Eol,
    /// Post-comment (below).
    Post,
    /// Plate comment (block header).
    Plate,
    /// Repeatable comment.
    Repeatable,
}

impl fmt::Display for CommentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommentType::Pre => write!(f, "Pre"),
            CommentType::Eol => write!(f, "EOL"),
            CommentType::Post => write!(f, "Post"),
            CommentType::Plate => write!(f, "Plate"),
            CommentType::Repeatable => write!(f, "Repeatable"),
        }
    }
}

// ---------------------------------------------------------------------------
// TraceComment
// ---------------------------------------------------------------------------

/// A comment at an address in the trace.
#[derive(Debug, Clone)]
pub struct TraceComment {
    /// The address space name.
    pub space_name: String,
    /// The address offset.
    pub address: u64,
    /// The comment type.
    pub comment_type: CommentType,
    /// The comment text.
    text: String,
    /// The lifespan of this comment.
    pub lifespan: Lifespan,
}

impl TraceComment {
    /// Create a new comment.
    pub fn new(
        space_name: impl Into<String>,
        address: u64,
        comment_type: CommentType,
        text: impl Into<String>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            space_name: space_name.into(),
            address,
            comment_type,
            text: text.into(),
            lifespan,
        }
    }

    /// Returns the comment text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Set the comment text.
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = text.into();
    }
}

// ---------------------------------------------------------------------------
// TraceCodeSpace
// ---------------------------------------------------------------------------

/// A code space (an address space with code units).
///
/// Ported from `ghidra.trace.model.listing.TraceCodeSpace`.
#[derive(Debug)]
pub struct TraceCodeSpace {
    /// The address space name.
    pub space_name: String,
    /// Code units in this space, indexed by (address, key).
    units: BTreeMap<(u64, u64), TraceCodeUnit>,
    /// Comments in this space.
    comments: Vec<TraceComment>,
}

impl TraceCodeSpace {
    /// Create a new code space.
    pub fn new(space_name: impl Into<String>) -> Self {
        Self {
            space_name: space_name.into(),
            units: BTreeMap::new(),
            comments: Vec::new(),
        }
    }

    /// Add a code unit.
    pub fn add_unit(&mut self, unit: TraceCodeUnit) {
        self.units.insert((unit.address, unit.key), unit);
    }

    /// Get the code unit at the given address and snapshot.
    pub fn get_unit_at(&self, address: u64, snap: i64) -> Option<&TraceCodeUnit> {
        self.units
            .values()
            .find(|u| u.contains_address(address) && u.is_valid(snap))
    }

    /// Get all code units valid at the given snapshot.
    pub fn get_units_at_snap(&self, snap: i64) -> Vec<&TraceCodeUnit> {
        self.units
            .values()
            .filter(|u| u.is_valid(snap))
            .collect()
    }

    /// Get all instructions valid at the given snapshot.
    pub fn get_instructions(&self, snap: i64) -> Vec<&TraceCodeUnit> {
        self.units
            .values()
            .filter(|u| u.is_instruction() && u.is_valid(snap))
            .collect()
    }

    /// Get all defined data valid at the given snapshot.
    pub fn get_defined_data(&self, snap: i64) -> Vec<&TraceCodeUnit> {
        self.units
            .values()
            .filter(|u| u.is_data() && u.is_valid(snap))
            .collect()
    }

    /// Add a comment.
    pub fn add_comment(&mut self, comment: TraceComment) {
        self.comments.push(comment);
    }

    /// Get comments at a given address and snapshot.
    pub fn get_comments_at(&self, address: u64, snap: i64) -> Vec<&TraceComment> {
        self.comments
            .iter()
            .filter(|c| c.address == address && c.lifespan.contains(snap))
            .collect()
    }

    /// Iterate over all units.
    pub fn units(&self) -> impl Iterator<Item = &TraceCodeUnit> {
        self.units.values()
    }
}

// ---------------------------------------------------------------------------
// TraceCodeManager
// ---------------------------------------------------------------------------

/// Manages code spaces (listings) within a trace.
///
/// Ported from `ghidra.trace.model.listing.TraceCodeManager`.
#[derive(Debug)]
pub struct TraceCodeManager {
    spaces: BTreeMap<String, TraceCodeSpace>,
    next_key: AtomicU64,
}

impl TraceCodeManager {
    /// Create a new code manager.
    pub fn new() -> Self {
        Self {
            spaces: BTreeMap::new(),
            next_key: AtomicU64::new(1),
        }
    }

    fn alloc_key(&self) -> u64 {
        self.next_key.fetch_add(1, Ordering::Relaxed)
    }

    /// Get or create a code space.
    pub fn get_or_create_space(&mut self, space_name: &str) -> &mut TraceCodeSpace {
        self.spaces
            .entry(space_name.to_string())
            .or_insert_with(|| TraceCodeSpace::new(space_name))
    }

    /// Get a code space by name.
    pub fn get_space(&self, space_name: &str) -> Option<&TraceCodeSpace> {
        self.spaces.get(space_name)
    }

    /// Create an instruction in the given space.
    pub fn create_instruction(
        &mut self,
        space_name: &str,
        address: u64,
        mnemonic: impl Into<String>,
        operands: Vec<String>,
        bytes: Vec<u8>,
        lifespan: Lifespan,
    ) -> u64 {
        let key = self.alloc_key();
        let unit = TraceCodeUnit::new_instruction(
            key,
            space_name,
            address,
            mnemonic,
            operands,
            bytes,
            lifespan,
        );
        self.spaces
            .entry(space_name.to_string())
            .or_insert_with(|| TraceCodeSpace::new(space_name))
            .add_unit(unit);
        key
    }

    /// Create a data unit in the given space.
    pub fn create_data(
        &mut self,
        space_name: &str,
        address: u64,
        data_type_name: impl Into<String>,
        length: usize,
        bytes: Vec<u8>,
        lifespan: Lifespan,
    ) -> u64 {
        let key = self.alloc_key();
        let unit = TraceCodeUnit::new_data(
            key,
            space_name,
            address,
            data_type_name,
            length,
            bytes,
            lifespan,
        );
        self.spaces
            .entry(space_name.to_string())
            .or_insert_with(|| TraceCodeSpace::new(space_name))
            .add_unit(unit);
        key
    }

    /// Get the code unit at a given address.
    pub fn get_code_unit_at(
        &self,
        space_name: &str,
        address: u64,
        snap: i64,
    ) -> Option<&TraceCodeUnit> {
        self.spaces
            .get(space_name)
            .and_then(|s| s.get_unit_at(address, snap))
    }

    /// Iterate over all spaces.
    pub fn spaces(&self) -> impl Iterator<Item = &TraceCodeSpace> {
        self.spaces.values()
    }

    /// Count all code units across all spaces at the given snap.
    pub fn count_units(&self, snap: i64) -> usize {
        self.spaces.values().map(|s| s.get_units_at_snap(snap).len()).sum()
    }
}

impl Default for TraceCodeManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_unit_instruction() {
        let unit = TraceCodeUnit::new_instruction(
            1,
            "ram",
            0x400000,
            "MOV",
            vec!["EAX".to_string(), "0x1".to_string()],
            vec![0xB8, 0x01, 0x00, 0x00, 0x00],
            Lifespan::now_on(0),
        );
        assert_eq!(unit.key(), 1);
        assert!(unit.is_instruction());
        assert!(!unit.is_data());
        assert_eq!(unit.mnemonic(), "MOV");
        assert_eq!(unit.length(), 5);
        assert_eq!(unit.max_address(), 0x400004);
        assert!(unit.contains_address(0x400002));
        assert!(!unit.contains_address(0x400005));
        assert_eq!(unit.representation(), "MOV EAX, 0x1");
    }

    #[test]
    fn test_code_unit_data() {
        let unit = TraceCodeUnit::new_data(
            2,
            "ram",
            0x600000,
            "dword",
            4,
            vec![0x78, 0x56, 0x34, 0x12],
            Lifespan::now_on(0),
        );
        assert!(unit.is_data());
        assert!(!unit.is_instruction());
        assert_eq!(unit.mnemonic(), "dword");
        assert_eq!(unit.length(), 4);
    }

    #[test]
    fn test_code_unit_undefined() {
        let unit = TraceCodeUnit::new_undefined(3, "ram", 0x700000, 8, Lifespan::now_on(0));
        assert_eq!(unit.unit_type(), CodeUnitType::UndefinedData);
        assert_eq!(unit.length(), 8);
        assert_eq!(unit.bytes().len(), 8);
    }

    #[test]
    fn test_code_unit_display() {
        let unit = TraceCodeUnit::new_instruction(
            1,
            "ram",
            0x400000,
            "NOP",
            vec![],
            vec![0x90],
            Lifespan::now_on(0),
        );
        assert_eq!(format!("{unit}"), "0x400000: NOP (Instruction, 1 bytes)");
    }

    #[test]
    fn test_code_space() {
        let mut space = TraceCodeSpace::new("ram");
        space.add_unit(TraceCodeUnit::new_instruction(
            1,
            "ram",
            0x400000,
            "NOP",
            vec![],
            vec![0x90],
            Lifespan::now_on(0),
        ));
        space.add_unit(TraceCodeUnit::new_data(
            2,
            "ram",
            0x400010,
            "dword",
            4,
            vec![0, 0, 0, 0],
            Lifespan::now_on(0),
        ));

        assert_eq!(space.get_units_at_snap(0).len(), 2);
        assert_eq!(space.get_instructions(0).len(), 1);
        assert_eq!(space.get_defined_data(0).len(), 1);

        let unit_at = space.get_unit_at(0x400000, 0).unwrap();
        assert_eq!(unit_at.mnemonic(), "NOP");
    }

    #[test]
    fn test_code_space_comments() {
        let mut space = TraceCodeSpace::new("ram");
        space.add_comment(TraceComment::new(
            "ram",
            0x400000,
            CommentType::Plate,
            "Main function entry point",
            Lifespan::now_on(0),
        ));

        let comments = space.get_comments_at(0x400000, 0);
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].text(), "Main function entry point");
    }

    #[test]
    fn test_code_manager() {
        let mut mgr = TraceCodeManager::new();
        let key1 = mgr.create_instruction(
            "ram",
            0x400000,
            "MOV",
            vec!["EAX".to_string(), "0x1".to_string()],
            vec![0xB8, 0x01, 0x00, 0x00, 0x00],
            Lifespan::now_on(0),
        );
        let key2 = mgr.create_data(
            "ram",
            0x600000,
            "dword",
            4,
            vec![0x78, 0x56, 0x34, 0x12],
            Lifespan::now_on(0),
        );

        assert_eq!(mgr.count_units(0), 2);

        let unit = mgr.get_code_unit_at("ram", 0x400000, 0).unwrap();
        assert!(unit.is_instruction());

        let data = mgr.get_code_unit_at("ram", 0x600000, 0).unwrap();
        assert!(data.is_data());
    }

    #[test]
    fn test_code_manager_spaces() {
        let mut mgr = TraceCodeManager::new();
        mgr.create_instruction(
            "ram",
            0x400000,
            "NOP",
            vec![],
            vec![0x90],
            Lifespan::now_on(0),
        );
        mgr.create_instruction(
            "register",
            0x0,
            "MOV",
            vec!["RAX".to_string()],
            vec![],
            Lifespan::now_on(0),
        );

        assert_eq!(mgr.spaces().count(), 2);
    }
}
