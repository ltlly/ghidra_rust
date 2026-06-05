//! Abstract view types for database-backed listing, program, and symbol views.
//!
//! Ported from Ghidra's `AbstractBaseDBTraceCodeUnitsView`,
//! `AbstractDBTraceProgramViewMemoryBlock`, `AbstractDBTraceSymbol`,
//! and related abstract base classes in Framework-TraceModeling.
//!
//! These types provide the structural foundation that concrete database-backed
//! view implementations extend. In Rust, they are expressed as traits and
//! concrete base structs that hold common state.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Code unit adapter trait
// ---------------------------------------------------------------------------

/// Adapter for accessing code unit properties.
///
/// Ported from `DBTraceCodeUnitAdapter` / `InternalBaseCodeUnitsView`.
pub trait CodeUnitAdapter: fmt::Debug {
    /// Get the minimum address of this code unit.
    fn min_address(&self) -> u64;

    /// Get the maximum address of this code unit.
    fn max_address(&self) -> u64;

    /// Get the length of this code unit.
    fn length(&self) -> u64 {
        self.max_address() - self.min_address() + 1
    }

    /// Get the snap at which this code unit is valid.
    fn snap(&self) -> i64;

    /// Get the address space name.
    fn space_name(&self) -> &str;

    /// Whether this is a data unit (vs instruction).
    fn is_data(&self) -> bool;

    /// Whether this is an instruction.
    fn is_instruction(&self) -> bool {
        !self.is_data()
    }

    /// Whether this code unit contains the given address.
    fn contains(&self, address: u64) -> bool {
        address >= self.min_address() && address <= self.max_address()
    }
}

// ---------------------------------------------------------------------------
// Abstract base code units view
// ---------------------------------------------------------------------------

/// Abstract base for code units views over a specific address space.
///
/// Ported from `AbstractBaseDBTraceCodeUnitsView`. Provides common
/// operations for looking up code units by address and snap.
#[derive(Debug)]
pub struct AbstractCodeUnitsView<T: CodeUnitAdapter> {
    /// The address space name this view covers.
    pub space_name: String,
    /// Entries indexed by (snap, min_address).
    entries: BTreeMap<(i64, u64), T>,
}

impl<T: CodeUnitAdapter> AbstractCodeUnitsView<T> {
    /// Create a new empty code units view.
    pub fn new(space_name: impl Into<String>) -> Self {
        Self {
            space_name: space_name.into(),
            entries: BTreeMap::new(),
        }
    }

    /// Insert a code unit into this view.
    pub fn insert(&mut self, unit: T) {
        let key = (unit.snap(), unit.min_address());
        self.entries.insert(key, unit);
    }

    /// Get the number of code units in this view.
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// Get the code unit at the exact given snap and address.
    pub fn get_at(&self, snap: i64, address: u64) -> Option<&T> {
        // Search for any unit at this address that spans the given snap
        self.entries
            .range(..=(snap, u64::MAX))
            .rev()
            .find(|((s, a), unit)| *a == address && *s <= snap && unit.contains(address))
            .map(|(_, unit)| unit)
    }

    /// Get the code unit containing the given address at the given snap.
    pub fn get_containing(&self, snap: i64, address: u64) -> Option<&T> {
        self.entries
            .range(..=(snap, u64::MAX))
            .rev()
            .find(|((s, _), unit)| *s <= snap && unit.contains(address))
            .map(|(_, unit)| unit)
    }

    /// Get the code unit at or before the given address.
    pub fn get_floor(&self, snap: i64, address: u64) -> Option<&T> {
        self.entries
            .range(..=(snap, address))
            .rev()
            .find(|((s, _), _)| *s <= snap)
            .map(|(_, unit)| unit)
    }

    /// Get the code unit at or after the given address.
    pub fn get_ceiling(&self, snap: i64, address: u64) -> Option<&T> {
        self.entries
            .range((snap, address)..)
            .find(|((s, _), _)| *s == snap)
            .map(|(_, unit)| unit)
    }

    /// Get the code unit before the given address.
    pub fn get_before(&self, snap: i64, address: u64) -> Option<&T> {
        if address == 0 {
            return None;
        }
        self.get_floor(snap, address - 1)
    }

    /// Get all code units in a range at the given snap.
    pub fn get_in_range(&self, snap: i64, start: u64, end: u64) -> Vec<&T> {
        self.entries
            .range((snap, start)..=(snap, end))
            .filter(|((s, _), _)| *s == snap)
            .map(|(_, unit)| unit)
            .collect()
    }

    /// Get all code units for a given snap.
    pub fn get_for_snap(&self, snap: i64) -> Vec<&T> {
        self.entries
            .range(..=(snap, u64::MAX))
            .rev()
            .filter(|((s, _), _)| *s == snap)
            .map(|(_, unit)| unit)
            .collect()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&(i64, u64), &T)> {
        self.entries.iter()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ---------------------------------------------------------------------------
// Abstract program view memory block
// ---------------------------------------------------------------------------

/// Permissions for a memory block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemoryBlockPermissions {
    /// Read permission.
    pub read: bool,
    /// Write permission.
    pub write: bool,
    /// Execute permission.
    pub execute: bool,
}

impl MemoryBlockPermissions {
    /// Create permissions with all access.
    pub fn all() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
        }
    }

    /// Create read-only permissions.
    pub fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
        }
    }

    /// Create read-execute permissions.
    pub fn read_execute() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
        }
    }

    /// Create no permissions.
    pub fn none() -> Self {
        Self {
            read: false,
            write: false,
            execute: false,
        }
    }
}

impl Default for MemoryBlockPermissions {
    fn default() -> Self {
        Self::all()
    }
}

/// A memory block in a program view.
///
/// Ported from `AbstractDBTraceProgramViewMemoryBlock`. Represents a
/// contiguous region of memory in a trace program view, backed by
/// a trace memory space.
#[derive(Debug, Clone)]
pub struct ProgramViewMemoryBlock {
    /// The name of this block.
    pub name: String,
    /// Start address.
    pub start: u64,
    /// End address.
    pub end: u64,
    /// The address space name.
    pub space_name: String,
    /// Block permissions.
    pub permissions: MemoryBlockPermissions,
    /// Whether this block is initialized.
    pub initialized: bool,
    /// Whether this block is volatile.
    pub volatile: bool,
    /// The source name (e.g., "program", "overlay").
    pub source_name: String,
}

impl ProgramViewMemoryBlock {
    /// Create a new memory block.
    pub fn new(
        name: impl Into<String>,
        start: u64,
        end: u64,
        space_name: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            start,
            end,
            space_name: space_name.into(),
            permissions: MemoryBlockPermissions::all(),
            initialized: true,
            volatile: false,
            source_name: "trace".to_string(),
        }
    }

    /// Get the size of this block.
    pub fn size(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Check if this block contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address <= self.end
    }

    /// Get the source info description.
    pub fn info_description(&self) -> String {
        format!(
            "{}: {} [0x{:X} - 0x{:X}]",
            self.source_name, self.name, self.start, self.end
        )
    }
}

// ---------------------------------------------------------------------------
// Abstract trace symbol
// ---------------------------------------------------------------------------

/// Source type for a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolSourceType {
    /// User-defined symbol.
    UserDefined,
    /// Imported symbol.
    Imported,
    /// Analysis-derived symbol.
    Analysis,
    /// Default (unnamed) symbol.
    Default,
}

impl Default for SymbolSourceType {
    fn default() -> Self {
        Self::UserDefined
    }
}

/// Flags for a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolFlags {
    /// Source type (lower 4 bits).
    pub source: SymbolSourceType,
    /// Whether this is a primary symbol.
    pub primary: bool,
    /// Whether this is external.
    pub external: bool,
    /// Whether this is a dynamic symbol.
    pub dynamic: bool,
}

impl SymbolFlags {
    /// Create default flags.
    pub fn new(source: SymbolSourceType) -> Self {
        Self {
            source,
            primary: false,
            external: false,
            dynamic: false,
        }
    }

    /// Encode flags into a byte.
    pub fn encode(&self) -> u8 {
        let mut flags: u8 = match self.source {
            SymbolSourceType::UserDefined => 0,
            SymbolSourceType::Imported => 1,
            SymbolSourceType::Analysis => 2,
            SymbolSourceType::Default => 3,
        };
        if self.primary {
            flags |= 0x10;
        }
        if self.external {
            flags |= 0x20;
        }
        if self.dynamic {
            flags |= 0x40;
        }
        flags
    }

    /// Decode flags from a byte.
    pub fn decode(flags: u8) -> Self {
        let source = match flags & 0x0F {
            1 => SymbolSourceType::Imported,
            2 => SymbolSourceType::Analysis,
            3 => SymbolSourceType::Default,
            _ => SymbolSourceType::UserDefined,
        };
        Self {
            source,
            primary: flags & 0x10 != 0,
            external: flags & 0x20 != 0,
            dynamic: flags & 0x40 != 0,
        }
    }
}

/// An abstract database-backed symbol.
///
/// Ported from `AbstractDBTraceSymbol`. Holds common fields for all
/// symbol types: name, parent, flags, address, and lifespan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractDbSymbol {
    /// Symbol ID.
    pub id: i64,
    /// Symbol name.
    pub name: String,
    /// Parent namespace symbol ID.
    pub parent_id: i64,
    /// Symbol flags.
    pub flags: SymbolFlags,
    /// Address offset (0 if not address-based).
    pub address: u64,
    /// Address space name.
    pub space_name: String,
    /// Minimum snap for which this symbol is valid.
    pub min_snap: i64,
    /// Maximum snap for which this symbol is valid.
    pub max_snap: i64,
}

impl AbstractDbSymbol {
    /// Create a new abstract symbol.
    pub fn new(
        id: i64,
        name: impl Into<String>,
        parent_id: i64,
        source: SymbolSourceType,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            parent_id,
            flags: SymbolFlags::new(source),
            address: 0,
            space_name: String::new(),
            min_snap: 0,
            max_snap: i64::MAX,
        }
    }

    /// Check if this symbol is valid at the given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        snap >= self.min_snap && snap <= self.max_snap
    }

    /// Whether this is a primary symbol.
    pub fn is_primary(&self) -> bool {
        self.flags.primary
    }

    /// Whether this is external.
    pub fn is_external(&self) -> bool {
        self.flags.external
    }

    /// Encode flags to byte.
    pub fn encode_flags(&self) -> u8 {
        self.flags.encode()
    }

    /// Decode flags from byte.
    pub fn set_flags_from_byte(&mut self, byte: u8) {
        self.flags = SymbolFlags::decode(byte);
    }
}

impl fmt::Display for AbstractDbSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} @ 0x{:X} [{}]", self.name, self.address, self.space_name)
    }
}

// ---------------------------------------------------------------------------
// Code unit view entry (for program view listing)
// ---------------------------------------------------------------------------

/// An entry in a code unit view, used for program view listing.
///
/// This represents a row in the listing panel showing a code unit
/// at a particular address in a trace program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeUnitViewEntry {
    /// The address offset.
    pub address: u64,
    /// The address space name.
    pub space: String,
    /// The snap.
    pub snap: i64,
    /// Whether this is an instruction.
    pub is_instruction: bool,
    /// The mnemonic or data type name.
    pub label: String,
    /// The length in bytes.
    pub length: u32,
    /// Comment text, if any.
    pub comment: Option<String>,
}

impl CodeUnitViewEntry {
    /// Create a new code unit view entry.
    pub fn new(address: u64, space: impl Into<String>, snap: i64) -> Self {
        Self {
            address,
            space: space.into(),
            snap,
            is_instruction: false,
            label: String::new(),
            length: 0,
            comment: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone)]
    struct MockCodeUnit {
        min_addr: u64,
        max_addr: u64,
        snap_val: i64,
        space_val: String,
        is_data: bool,
    }

    impl MockCodeUnit {
        fn new(min: u64, max: u64, snap: i64) -> Self {
            Self {
                min_addr: min,
                max_addr: max,
                snap_val: snap,
                space_val: "ram".to_string(),
                is_data: false,
            }
        }

        fn data(min: u64, max: u64, snap: i64) -> Self {
            Self {
                is_data: true,
                ..Self::new(min, max, snap)
            }
        }
    }

    impl CodeUnitAdapter for MockCodeUnit {
        fn min_address(&self) -> u64 {
            self.min_addr
        }
        fn max_address(&self) -> u64 {
            self.max_addr
        }
        fn snap(&self) -> i64 {
            self.snap_val
        }
        fn space_name(&self) -> &str {
            &self.space_val
        }
        fn is_data(&self) -> bool {
            self.is_data
        }
    }

    #[test]
    fn test_code_units_view_insert_and_get() {
        let mut view = AbstractCodeUnitsView::<MockCodeUnit>::new("ram");
        view.insert(MockCodeUnit::new(0x1000, 0x1004, 0));
        view.insert(MockCodeUnit::new(0x1005, 0x1009, 0));

        assert_eq!(view.size(), 2);
        assert!(view.get_at(0, 0x1000).is_some());
        assert!(view.get_at(0, 0x1005).is_some());
        assert!(view.get_at(0, 0x2000).is_none());
    }

    #[test]
    fn test_code_units_view_containing() {
        let mut view = AbstractCodeUnitsView::<MockCodeUnit>::new("ram");
        view.insert(MockCodeUnit::new(0x1000, 0x1004, 0));

        assert!(view.get_containing(0, 0x1002).is_some());
        assert!(view.get_containing(0, 0x1000).is_some());
        assert!(view.get_containing(0, 0x1004).is_some());
        assert!(view.get_containing(0, 0x1005).is_none());
    }

    #[test]
    fn test_code_units_view_floor_ceiling() {
        let mut view = AbstractCodeUnitsView::<MockCodeUnit>::new("ram");
        view.insert(MockCodeUnit::new(0x1000, 0x1004, 0));
        view.insert(MockCodeUnit::new(0x2000, 0x2004, 0));

        assert!(view.get_floor(0, 0x1500).is_some());
        assert_eq!(view.get_floor(0, 0x1500).unwrap().min_address(), 0x1000);

        assert!(view.get_ceiling(0, 0x1500).is_some());
        assert_eq!(view.get_ceiling(0, 0x1500).unwrap().min_address(), 0x2000);
    }

    #[test]
    fn test_code_units_view_before() {
        let mut view = AbstractCodeUnitsView::<MockCodeUnit>::new("ram");
        view.insert(MockCodeUnit::new(0x1000, 0x1004, 0));

        assert!(view.get_before(0, 0x1000).is_none());
        assert!(view.get_before(0, 0x1001).is_some());
    }

    #[test]
    fn test_memory_block() {
        let block = ProgramViewMemoryBlock::new(".text", 0x400000, 0x400FFF, "ram");
        assert_eq!(block.name, ".text");
        assert_eq!(block.size(), 0x1000);
        assert!(block.contains(0x400500));
        assert!(!block.contains(0x500000));
    }

    #[test]
    fn test_memory_block_permissions() {
        let perms = MemoryBlockPermissions::read_execute();
        assert!(perms.read);
        assert!(!perms.write);
        assert!(perms.execute);
    }

    #[test]
    fn test_symbol_flags_encode_decode() {
        let flags = SymbolFlags {
            source: SymbolSourceType::Analysis,
            primary: true,
            external: false,
            dynamic: true,
        };
        let encoded = flags.encode();
        let decoded = SymbolFlags::decode(encoded);
        assert_eq!(decoded.source, SymbolSourceType::Analysis);
        assert!(decoded.primary);
        assert!(!decoded.external);
        assert!(decoded.dynamic);
    }

    #[test]
    fn test_abstract_db_symbol() {
        let mut sym = AbstractDbSymbol::new(1, "main", 0, SymbolSourceType::UserDefined);
        sym.address = 0x400000;
        sym.space_name = "ram".to_string();
        sym.min_snap = 0;
        sym.max_snap = 100;

        assert!(sym.is_valid_at(50));
        assert!(!sym.is_valid_at(200));
        assert_eq!(format!("{}", sym), "main @ 0x400000 [ram]");
    }

    #[test]
    fn test_abstract_db_symbol_flags() {
        let mut sym = AbstractDbSymbol::new(1, "func", 0, SymbolSourceType::UserDefined);
        sym.flags.primary = true;
        let encoded = sym.encode_flags();
        sym.set_flags_from_byte(encoded);
        assert!(sym.flags.primary);
    }

    #[test]
    fn test_code_unit_view_entry() {
        let entry = CodeUnitViewEntry::new(0x400000, "ram", 5);
        assert_eq!(entry.address, 0x400000);
        assert_eq!(entry.snap, 5);
        assert!(!entry.is_instruction);
    }

    #[test]
    fn test_code_unit_adapter() {
        let unit = MockCodeUnit::new(0x1000, 0x1004, 0);
        assert_eq!(unit.length(), 5);
        assert!(unit.contains(0x1002));
        assert!(!unit.is_data());
        assert!(unit.is_instruction());
    }

    #[test]
    fn test_code_units_view_in_range() {
        let mut view = AbstractCodeUnitsView::<MockCodeUnit>::new("ram");
        view.insert(MockCodeUnit::new(0x1000, 0x1004, 0));
        view.insert(MockCodeUnit::new(0x2000, 0x2004, 0));
        view.insert(MockCodeUnit::new(0x3000, 0x3004, 0));

        let in_range = view.get_in_range(0, 0x1000, 0x2004);
        assert_eq!(in_range.len(), 2);
    }
}
