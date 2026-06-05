//! Program view memory implementation for the trace database.
//!
//! Ported from Ghidra's `DBTraceProgramViewMemory` and related classes
//! in `ghidra.trace.database.program`. Provides the Memory interface
//! over a trace at a specific snap.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A memory block visible through a program view.
///
/// Ported from Ghidra's `DBTraceProgramViewMemoryRegionBlock` and
/// `DBTraceProgramViewMemorySpaceBlock`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewMemoryBlock {
    /// Block name.
    pub name: String,
    /// The address space.
    pub address_space: String,
    /// Start offset.
    pub start_offset: u64,
    /// End offset.
    pub end_offset: u64,
    /// Whether readable.
    pub readable: bool,
    /// Whether writable.
    pub writable: bool,
    /// Whether executable.
    pub executable: bool,
    /// Whether this is a volatile block.
    pub volatile: bool,
    /// Whether this is an initialized block (has backing bytes).
    pub initialized: bool,
    /// Whether this block is from a memory region (vs. an address space).
    pub from_region: bool,
}

impl ProgramViewMemoryBlock {
    /// Create a new memory block.
    pub fn new(
        name: impl Into<String>,
        address_space: impl Into<String>,
        start_offset: u64,
        end_offset: u64,
    ) -> Self {
        Self {
            name: name.into(),
            address_space: address_space.into(),
            start_offset,
            end_offset,
            readable: true,
            writable: false,
            executable: false,
            volatile: false,
            initialized: true,
            from_region: false,
        }
    }

    /// Whether this block contains the given address offset.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.start_offset && offset <= self.end_offset
    }

    /// The size of this block.
    pub fn size(&self) -> u64 {
        self.end_offset - self.start_offset + 1
    }
}

/// A program view memory manager.
///
/// Ported from Ghidra's `DBTraceProgramViewMemory`. Provides memory
/// access through the program view interface at a specific snap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceProgramViewMemory {
    /// The view ID.
    pub view_id: i64,
    /// The snap this memory view is filtered to.
    pub snap: i64,
    /// Memory blocks visible at this snap.
    blocks: Vec<ProgramViewMemoryBlock>,
}

impl DbTraceProgramViewMemory {
    /// Create a new program view memory.
    pub fn new(view_id: i64, snap: i64) -> Self {
        Self {
            view_id,
            snap,
            blocks: Vec::new(),
        }
    }

    /// Set the snap for this memory view.
    pub fn set_snap(&mut self, snap: i64) {
        self.snap = snap;
    }

    /// Add a memory block.
    pub fn add_block(&mut self, block: ProgramViewMemoryBlock) {
        self.blocks.push(block);
    }

    /// Get all blocks.
    pub fn blocks(&self) -> &[ProgramViewMemoryBlock] {
        &self.blocks
    }

    /// Get the block containing the given address.
    pub fn get_block_at(&self, space: &str, offset: u64) -> Option<&ProgramViewMemoryBlock> {
        self.blocks
            .iter()
            .find(|b| b.address_space == space && b.contains(offset))
    }

    /// Get all blocks in a given address space.
    pub fn get_blocks_in_space(&self, space: &str) -> Vec<&ProgramViewMemoryBlock> {
        self.blocks
            .iter()
            .filter(|b| b.address_space == space)
            .collect()
    }

    /// Whether the given address is valid (covered by any block).
    pub fn is_valid_address(&self, space: &str, offset: u64) -> bool {
        self.blocks
            .iter()
            .any(|b| b.address_space == space && b.contains(offset))
    }

    /// Get the number of blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Clear all blocks.
    pub fn invalidate_cache(&mut self) {
        self.blocks.clear();
    }
}

/// A program view program context (register context).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewProgramContext {
    /// The view ID.
    pub view_id: i64,
    /// Register values indexed by register name.
    register_values: Vec<ProgramViewRegisterValue>,
}

/// A register value in a program view context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewRegisterValue {
    /// The register name.
    pub register_name: String,
    /// The register value as bytes.
    pub value: Vec<u8>,
    /// The address range where this value applies.
    pub min_address_offset: u64,
    pub max_address_offset: u64,
    /// The snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

impl ProgramViewProgramContext {
    /// Create a new program context.
    pub fn new(view_id: i64) -> Self {
        Self {
            view_id,
            register_values: Vec::new(),
        }
    }

    /// Set a register value.
    pub fn set_register(
        &mut self,
        name: impl Into<String>,
        value: Vec<u8>,
        min_addr: u64,
        max_addr: u64,
        min_snap: i64,
        max_snap: i64,
    ) {
        self.register_values.push(ProgramViewRegisterValue {
            register_name: name.into(),
            value,
            min_address_offset: min_addr,
            max_address_offset: max_addr,
            min_snap,
            max_snap,
        });
    }

    /// Get a register value at the given address and snap.
    pub fn get_register(&self, name: &str, offset: u64, snap: i64) -> Option<&ProgramViewRegisterValue> {
        self.register_values.iter().find(|rv| {
            rv.register_name == name
                && offset >= rv.min_address_offset
                && offset <= rv.max_address_offset
                && snap >= rv.min_snap
                && snap <= rv.max_snap
        })
    }
}

/// A program view reference manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewReferenceManager {
    /// The view ID.
    pub view_id: i64,
    /// References visible at this view's snap.
    references: Vec<ProgramViewReference>,
}

/// A reference visible through a program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewReference {
    /// From address offset.
    pub from_offset: u64,
    /// From address space.
    pub from_space: String,
    /// To address offset.
    pub to_offset: u64,
    /// To address space.
    pub to_space: String,
    /// Whether this is the primary reference.
    pub is_primary: bool,
    /// The operand index.
    pub operand_index: i32,
    /// The reference kind.
    pub kind: String,
    /// The snap.
    pub snap: i64,
}

impl ProgramViewReferenceManager {
    /// Create a new reference manager.
    pub fn new(view_id: i64) -> Self {
        Self {
            view_id,
            references: Vec::new(),
        }
    }

    /// Add a reference.
    pub fn add_reference(&mut self, reference: ProgramViewReference) {
        self.references.push(reference);
    }

    /// Get references from a given address.
    pub fn get_from(&self, space: &str, offset: u64, snap: i64) -> Vec<&ProgramViewReference> {
        self.references
            .iter()
            .filter(|r| r.from_space == space && r.from_offset == offset && r.snap == snap)
            .collect()
    }

    /// Get references to a given address.
    pub fn get_to(&self, space: &str, offset: u64, snap: i64) -> Vec<&ProgramViewReference> {
        self.references
            .iter()
            .filter(|r| r.to_space == space && r.to_offset == offset && r.snap == snap)
            .collect()
    }
}

/// A program view symbol table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewSymbolTable {
    /// The view ID.
    pub view_id: i64,
    /// Symbols visible at this view's snap.
    symbols: Vec<ProgramViewSymbol>,
}

/// A symbol visible through a program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewSymbol {
    /// Symbol name.
    pub name: String,
    /// Symbol address space.
    pub address_space: String,
    /// Symbol address offset.
    pub address_offset: u64,
    /// Symbol type.
    pub symbol_type: String,
    /// Whether primary.
    pub is_primary: bool,
    /// The snap.
    pub snap: i64,
}

impl ProgramViewSymbolTable {
    /// Create a new symbol table.
    pub fn new(view_id: i64) -> Self {
        Self {
            view_id,
            symbols: Vec::new(),
        }
    }

    /// Add a symbol.
    pub fn add_symbol(&mut self, symbol: ProgramViewSymbol) {
        self.symbols.push(symbol);
    }

    /// Get symbols at the given address.
    pub fn get_at(&self, space: &str, offset: u64, snap: i64) -> Vec<&ProgramViewSymbol> {
        self.symbols
            .iter()
            .filter(|s| {
                s.address_space == space && s.address_offset == offset && s.snap == snap
            })
            .collect()
    }

    /// Get symbols by name.
    pub fn get_by_name(&self, name: &str, snap: i64) -> Vec<&ProgramViewSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.name == name && s.snap == snap)
            .collect()
    }
}

/// A program view bookmark manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewBookmarkManager {
    /// The view ID.
    pub view_id: i64,
    /// Bookmarks visible at this view's snap.
    bookmarks: Vec<ProgramViewBookmarkEntry>,
}

/// A bookmark visible through a program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewBookmarkEntry {
    /// Bookmark type.
    pub category: String,
    /// Address space.
    pub address_space: String,
    /// Address offset.
    pub address_offset: u64,
    /// Comment.
    pub comment: String,
    /// The snap.
    pub snap: i64,
}

impl ProgramViewBookmarkManager {
    /// Create a new bookmark manager.
    pub fn new(view_id: i64) -> Self {
        Self {
            view_id,
            bookmarks: Vec::new(),
        }
    }

    /// Add a bookmark.
    pub fn add_bookmark(&mut self, bookmark: ProgramViewBookmarkEntry) {
        self.bookmarks.push(bookmark);
    }

    /// Get bookmarks at the given address.
    pub fn get_at(&self, space: &str, offset: u64, snap: i64) -> Vec<&ProgramViewBookmarkEntry> {
        self.bookmarks
            .iter()
            .filter(|b| {
                b.address_space == space && b.address_offset == offset && b.snap == snap
            })
            .collect()
    }

    /// Get all bookmarks of a given category.
    pub fn get_by_category(&self, category: &str, snap: i64) -> Vec<&ProgramViewBookmarkEntry> {
        self.bookmarks
            .iter()
            .filter(|b| b.category == category && b.snap == snap)
            .collect()
    }
}

/// A program view property map manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewPropertyMapManager {
    /// The view ID.
    pub view_id: i64,
    /// Property maps.
    property_maps: Vec<ProgramViewPropertyMap>,
}

/// A property map entry in a program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewPropertyMap {
    /// Property name.
    pub name: String,
    /// Property entries (address, value).
    pub entries: Vec<(u64, String)>,
}

impl ProgramViewPropertyMapManager {
    /// Create a new property map manager.
    pub fn new(view_id: i64) -> Self {
        Self {
            view_id,
            property_maps: Vec::new(),
        }
    }

    /// Add a property map.
    pub fn add_property_map(&mut self, map: ProgramViewPropertyMap) {
        self.property_maps.push(map);
    }

    /// Get a property value.
    pub fn get(&self, map_name: &str, address: u64) -> Option<&str> {
        self.property_maps
            .iter()
            .find(|m| m.name == map_name)
            .and_then(|m| {
                m.entries
                    .iter()
                    .find(|(addr, _)| *addr == address)
                    .map(|(_, val)| val.as_str())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_block() {
        let block = ProgramViewMemoryBlock::new("ram", "ram", 0x0, 0xFFFF);
        assert!(block.contains(0x1000));
        assert!(!block.contains(0x10000));
        assert_eq!(block.size(), 0x10000);
    }

    #[test]
    fn test_program_view_memory() {
        let mut mem = DbTraceProgramViewMemory::new(1, 0);
        mem.add_block(ProgramViewMemoryBlock::new("text", "ram", 0x1000, 0x2000));
        mem.add_block(ProgramViewMemoryBlock::new("data", "ram", 0x3000, 0x4000));
        assert_eq!(mem.block_count(), 2);
        assert!(mem.is_valid_address("ram", 0x1500));
        assert!(!mem.is_valid_address("ram", 0x5000));
        let block = mem.get_block_at("ram", 0x3500);
        assert!(block.is_some());
        assert_eq!(block.unwrap().name, "data");
    }

    #[test]
    fn test_program_context() {
        let mut ctx = ProgramViewProgramContext::new(1);
        ctx.set_register("RAX", vec![0x42; 8], 0, 0xFFFF, 0, 100);
        let val = ctx.get_register("RAX", 0x1000, 50);
        assert!(val.is_some());
        assert_eq!(val.unwrap().value, vec![0x42; 8]);
    }

    #[test]
    fn test_reference_manager() {
        let mut rm = ProgramViewReferenceManager::new(1);
        rm.add_reference(ProgramViewReference {
            from_offset: 0x1000,
            from_space: "ram".to_string(),
            to_offset: 0x2000,
            to_space: "ram".to_string(),
            is_primary: true,
            operand_index: -1,
            kind: "flow".to_string(),
            snap: 0,
        });
        let from = rm.get_from("ram", 0x1000, 0);
        assert_eq!(from.len(), 1);
        let to = rm.get_to("ram", 0x2000, 0);
        assert_eq!(to.len(), 1);
    }

    #[test]
    fn test_symbol_table() {
        let mut table = ProgramViewSymbolTable::new(1);
        table.add_symbol(ProgramViewSymbol {
            name: "main".to_string(),
            address_space: "ram".to_string(),
            address_offset: 0x1000,
            symbol_type: "label".to_string(),
            is_primary: true,
            snap: 0,
        });
        let syms = table.get_at("ram", 0x1000, 0);
        assert_eq!(syms.len(), 1);
        let by_name = table.get_by_name("main", 0);
        assert_eq!(by_name.len(), 1);
    }

    #[test]
    fn test_bookmark_manager() {
        let mut bm = ProgramViewBookmarkManager::new(1);
        bm.add_bookmark(ProgramViewBookmarkEntry {
            category: "Info".to_string(),
            address_space: "ram".to_string(),
            address_offset: 0x1000,
            comment: "important".to_string(),
            snap: 0,
        });
        let at = bm.get_at("ram", 0x1000, 0);
        assert_eq!(at.len(), 1);
    }

    #[test]
    fn test_property_map_manager() {
        let mut pm = ProgramViewPropertyMapManager::new(1);
        pm.add_property_map(ProgramViewPropertyMap {
            name: "my_prop".to_string(),
            entries: vec![(0x1000, "val1".to_string()), (0x2000, "val2".to_string())],
        });
        assert_eq!(pm.get("my_prop", 0x1000), Some("val1"));
        assert_eq!(pm.get("my_prop", 0x2000), Some("val2"));
        assert_eq!(pm.get("my_prop", 0x3000), None);
    }
}
