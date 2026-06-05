//! Full symbol manager for the trace database.
//!
//! Ported from Ghidra's `DBTraceSymbolManager` in
//! `ghidra.trace.database.symbol`. Manages all symbol types (labels,
//! namespaces, classes, functions) and equates within a trace.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A packed symbol ID encoding type and key.
///
/// Ghidra packs symbol type into the upper 8 bits and the key into
/// the lower 56 bits of a 64-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymbolId {
    /// The raw packed ID.
    pub raw: u64,
}

impl SymbolId {
    const TYPE_MASK: u64 = 0xFF;
    const TYPE_SHIFT: u32 = 64 - 8;
    const KEY_MASK: u64 = 0x00FF_FFFF_FFFF_FFFF;
    const KEY_SHIFT: u32 = 0;

    /// Pack a symbol type ID and key into a single ID.
    pub fn pack(symbol_type_id: u8, key: i64) -> Self {
        let raw = ((symbol_type_id as u64) << Self::TYPE_SHIFT)
            | ((key as u64) & Self::KEY_MASK);
        Self { raw }
    }

    /// Extract the symbol type ID.
    pub fn symbol_type_id(&self) -> u8 {
        ((self.raw >> Self::TYPE_SHIFT) & Self::TYPE_MASK) as u8
    }

    /// Extract the key.
    pub fn key(&self) -> i64 {
        ((self.raw >> Self::KEY_SHIFT) & Self::KEY_MASK) as i64
    }
}

/// Symbol type IDs matching Ghidra's SymbolType ordinal values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SymbolType {
    /// Label (user-defined name at an address).
    Label = 1,
    /// Namespace (container for other symbols).
    Namespace = 2,
    /// Class symbol.
    Class = 3,
    /// Function symbol.
    Function = 4,
    /// Library symbol.
    Library = 5,
    /// Global namespace (special root).
    Global = 6,
}

impl SymbolType {
    /// Get the numeric ID for this symbol type.
    pub fn id(&self) -> u8 {
        *self as u8
    }

    /// Parse a symbol type from its numeric ID.
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(SymbolType::Label),
            2 => Some(SymbolType::Namespace),
            3 => Some(SymbolType::Class),
            4 => Some(SymbolType::Function),
            5 => Some(SymbolType::Library),
            6 => Some(SymbolType::Global),
            _ => None,
        }
    }
}

/// Source of a symbol definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SourceType {
    /// User-defined.
    UserDefined = 0,
    /// Analysis-derived.
    Analysis = 1,
    /// Imported from an external library.
    Imported = 2,
    /// Default (placeholder).
    Default = 3,
}

impl SourceType {
    const SOURCE_MASK: u8 = 0x03;
    const SOURCE_SHIFT: u32 = 0;

    /// Encode source type into flags byte.
    pub fn encode(self) -> u8 {
        (self as u8) & Self::SOURCE_MASK
    }

    /// Decode source type from flags byte.
    pub fn decode(flags: u8) -> Self {
        match (flags >> Self::SOURCE_SHIFT) & Self::SOURCE_MASK {
            0 => SourceType::UserDefined,
            1 => SourceType::Analysis,
            2 => SourceType::Imported,
            _ => SourceType::Default,
        }
    }
}

/// A symbol entry in the trace database.
///
/// Ported from Ghidra's `AbstractDBTraceSymbol` and its subclasses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSymbolEntry {
    /// Database row ID.
    pub id: i64,
    /// The symbol name.
    pub name: String,
    /// Parent namespace symbol ID (-1 for global).
    pub parent_id: i64,
    /// Symbol type flags.
    pub flags: u8,
    /// The symbol type.
    pub symbol_type: SymbolType,
    /// The address (packed as space_id + offset).
    pub address_space: String,
    pub address_offset: u64,
    /// The source type.
    pub source: SourceType,
}

impl TraceSymbolEntry {
    /// Create a new label symbol entry.
    pub fn new_label(
        id: i64,
        name: impl Into<String>,
        parent_id: i64,
        address_space: impl Into<String>,
        address_offset: u64,
        source: SourceType,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            parent_id,
            flags: source.encode(),
            symbol_type: SymbolType::Label,
            address_space: address_space.into(),
            address_offset,
            source,
        }
    }

    /// Create a new namespace symbol entry.
    pub fn new_namespace(
        id: i64,
        name: impl Into<String>,
        parent_id: i64,
        source: SourceType,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            parent_id,
            flags: source.encode(),
            symbol_type: SymbolType::Namespace,
            address_space: String::new(),
            address_offset: 0,
            source,
        }
    }

    /// Create a new class symbol entry.
    pub fn new_class(
        id: i64,
        name: impl Into<String>,
        parent_id: i64,
        source: SourceType,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            parent_id,
            flags: source.encode(),
            symbol_type: SymbolType::Class,
            address_space: String::new(),
            address_offset: 0,
            source,
        }
    }

    /// Whether this is a global namespace symbol.
    pub fn is_global(&self) -> bool {
        self.symbol_type == SymbolType::Global || self.parent_id == -1
    }

    /// Whether this is a namespace-type symbol.
    pub fn is_namespace(&self) -> bool {
        matches!(
            self.symbol_type,
            SymbolType::Namespace | SymbolType::Class | SymbolType::Global
        )
    }

    /// Get the packed symbol ID.
    pub fn symbol_id(&self) -> SymbolId {
        SymbolId::pack(self.symbol_type.id(), self.id)
    }

    /// Get the source type from flags.
    pub fn get_source(&self) -> SourceType {
        SourceType::decode(self.flags)
    }
}

/// A symbol ID map entry for indexing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolIdEntry {
    /// The symbol ID.
    pub symbol_id: i64,
    /// The address range min.
    pub range_min: u64,
    /// The address range max.
    pub range_max: u64,
    /// The address space.
    pub space: String,
    /// The snap range min.
    pub min_snap: i64,
    /// The snap range max.
    pub max_snap: i64,
}

/// The trace symbol manager.
///
/// Ported from Ghidra's `DBTraceSymbolManager`. Manages symbols across
/// all address spaces and time snaps within a trace.
#[derive(Debug)]
pub struct TraceDbSymbolManager {
    /// All symbols indexed by ID.
    symbols: HashMap<i64, TraceSymbolEntry>,
    /// Symbol index by name.
    name_index: HashMap<String, Vec<i64>>,
    /// Symbol index by address (space, offset).
    address_index: HashMap<(String, u64), Vec<i64>>,
    /// Symbol ID map entries for range queries.
    id_map: Vec<SymbolIdEntry>,
    /// Next available symbol ID.
    next_id: i64,
    /// The global namespace symbol.
    global_namespace_id: i64,
}

impl TraceDbSymbolManager {
    /// Create a new symbol manager.
    pub fn new() -> Self {
        let mut mgr = Self {
            symbols: HashMap::new(),
            name_index: HashMap::new(),
            address_index: HashMap::new(),
            id_map: Vec::new(),
            next_id: 1,
            global_namespace_id: 0,
        };
        // Create the global namespace
        let global = TraceSymbolEntry::new_namespace(0, "Global", -1, SourceType::Default);
        mgr.symbols.insert(0, global);
        mgr
    }

    /// Add a label symbol at an address.
    pub fn add_label(
        &mut self,
        name: impl Into<String>,
        parent_id: i64,
        space: impl Into<String>,
        offset: u64,
        source: SourceType,
        min_snap: i64,
        max_snap: i64,
    ) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        let name_str = name.into();
        let space_str = space.into();

        let entry = TraceSymbolEntry::new_label(
            id,
            &name_str,
            parent_id,
            &space_str,
            offset,
            source,
        );
        self.symbols.insert(id, entry);

        // Update indices
        self.name_index
            .entry(name_str.clone())
            .or_default()
            .push(id);
        self.address_index
            .entry((space_str.clone(), offset))
            .or_default()
            .push(id);

        // Add to ID map
        self.id_map.push(SymbolIdEntry {
            symbol_id: id,
            range_min: offset,
            range_max: offset,
            space: space_str,
            min_snap,
            max_snap,
        });

        id
    }

    /// Add a namespace symbol.
    pub fn add_namespace(
        &mut self,
        name: impl Into<String>,
        parent_id: i64,
        source: SourceType,
    ) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        let entry = TraceSymbolEntry::new_namespace(id, name, parent_id, source);
        self.symbols.insert(id, entry);
        id
    }

    /// Add a class symbol.
    pub fn add_class(
        &mut self,
        name: impl Into<String>,
        parent_id: i64,
        source: SourceType,
    ) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        let entry = TraceSymbolEntry::new_class(id, name, parent_id, source);
        self.symbols.insert(id, entry);
        id
    }

    /// Get a symbol by ID.
    pub fn get_symbol_by_id(&self, id: i64) -> Option<&TraceSymbolEntry> {
        self.symbols.get(&id)
    }

    /// Get symbols by name at a given snap.
    pub fn get_symbols_by_name(&self, name: &str, _snap: i64) -> Vec<&TraceSymbolEntry> {
        self.name_index
            .get(name)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.symbols.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get symbols at an address.
    pub fn get_symbols_at(
        &self,
        space: &str,
        offset: u64,
        _snap: i64,
    ) -> Vec<&TraceSymbolEntry> {
        self.address_index
            .get(&(space.to_string(), offset))
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.symbols.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Delete a symbol by ID.
    pub fn delete_symbol(&mut self, id: i64) -> bool {
        if let Some(entry) = self.symbols.remove(&id) {
            // Remove from name index
            if let Some(ids) = self.name_index.get_mut(&entry.name) {
                ids.retain(|&x| x != id);
                if ids.is_empty() {
                    self.name_index.remove(&entry.name);
                }
            }
            // Remove from address index
            let key = (entry.address_space.clone(), entry.address_offset);
            if let Some(ids) = self.address_index.get_mut(&key) {
                ids.retain(|&x| x != id);
                if ids.is_empty() {
                    self.address_index.remove(&key);
                }
            }
            // Remove from ID map
            self.id_map.retain(|e| e.symbol_id != id);
            true
        } else {
            false
        }
    }

    /// Rename a symbol.
    pub fn rename_symbol(&mut self, id: i64, new_name: impl Into<String>) -> bool {
        let new_name = new_name.into();
        if let Some(entry) = self.symbols.get_mut(&id) {
            let old_name = entry.name.clone();
            entry.name = new_name.clone();

            // Update name index
            if let Some(ids) = self.name_index.get_mut(&old_name) {
                ids.retain(|&x| x != id);
                if ids.is_empty() {
                    self.name_index.remove(&old_name);
                }
            }
            self.name_index
                .entry(new_name)
                .or_default()
                .push(id);
            true
        } else {
            false
        }
    }

    /// Get the total number of symbols.
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Get the global namespace ID.
    pub fn global_namespace_id(&self) -> i64 {
        self.global_namespace_id
    }

    /// Get all symbols of a given type.
    pub fn get_symbols_by_type(&self, symbol_type: SymbolType) -> Vec<&TraceSymbolEntry> {
        self.symbols
            .values()
            .filter(|s| s.symbol_type == symbol_type)
            .collect()
    }

    /// Get all symbols under a parent namespace.
    pub fn get_children(&self, parent_id: i64) -> Vec<&TraceSymbolEntry> {
        self.symbols
            .values()
            .filter(|s| s.parent_id == parent_id)
            .collect()
    }

    /// Get the path of a symbol (sequence of namespace names from root).
    pub fn get_symbol_path(&self, id: i64) -> Vec<String> {
        let mut path = Vec::new();
        let mut current_id = id;
        loop {
            match self.symbols.get(&current_id) {
                Some(entry) => {
                    path.push(entry.name.clone());
                    if entry.is_global() {
                        break;
                    }
                    current_id = entry.parent_id;
                }
                None => break,
            }
        }
        path.reverse();
        path
    }

    /// Clear all symbols.
    pub fn clear(&mut self) {
        self.symbols.clear();
        self.name_index.clear();
        self.address_index.clear();
        self.id_map.clear();
        self.next_id = 1;
        // Re-create global namespace
        let global = TraceSymbolEntry::new_namespace(0, "Global", -1, SourceType::Default);
        self.symbols.insert(0, global);
    }
}

impl Default for TraceDbSymbolManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_id_pack_unpack() {
        let id = SymbolId::pack(SymbolType::Label as u8, 42);
        assert_eq!(id.symbol_type_id(), SymbolType::Label as u8);
        assert_eq!(id.key(), 42);
    }

    #[test]
    fn test_symbol_type_from_id() {
        assert_eq!(SymbolType::from_id(1), Some(SymbolType::Label));
        assert_eq!(SymbolType::from_id(2), Some(SymbolType::Namespace));
        assert_eq!(SymbolType::from_id(99), None);
    }

    #[test]
    fn test_source_type_encode_decode() {
        let src = SourceType::Analysis;
        let encoded = src.encode();
        assert_eq!(SourceType::decode(encoded), SourceType::Analysis);
    }

    #[test]
    fn test_symbol_manager_add_label() {
        let mut mgr = TraceDbSymbolManager::new();
        let id = mgr.add_label("main", 0, "ram", 0x1000, SourceType::UserDefined, 0, 100);
        assert!(id > 0);
        let sym = mgr.get_symbol_by_id(id).unwrap();
        assert_eq!(sym.name, "main");
        assert_eq!(sym.symbol_type, SymbolType::Label);
    }

    #[test]
    fn test_symbol_manager_get_by_name() {
        let mut mgr = TraceDbSymbolManager::new();
        mgr.add_label("test", 0, "ram", 0x1000, SourceType::UserDefined, 0, 100);
        let syms = mgr.get_symbols_by_name("test", 50);
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "test");
    }

    #[test]
    fn test_symbol_manager_get_by_address() {
        let mut mgr = TraceDbSymbolManager::new();
        mgr.add_label("func", 0, "ram", 0x2000, SourceType::UserDefined, 0, 100);
        let syms = mgr.get_symbols_at("ram", 0x2000, 50);
        assert_eq!(syms.len(), 1);
    }

    #[test]
    fn test_symbol_manager_delete() {
        let mut mgr = TraceDbSymbolManager::new();
        let id = mgr.add_label("temp", 0, "ram", 0, SourceType::UserDefined, 0, 100);
        assert_eq!(mgr.symbol_count(), 2); // global + temp
        assert!(mgr.delete_symbol(id));
        assert_eq!(mgr.symbol_count(), 1);
        assert!(mgr.get_symbol_by_id(id).is_none());
    }

    #[test]
    fn test_symbol_manager_rename() {
        let mut mgr = TraceDbSymbolManager::new();
        let id = mgr.add_label("old", 0, "ram", 0, SourceType::UserDefined, 0, 100);
        assert!(mgr.rename_symbol(id, "new"));
        let sym = mgr.get_symbols_by_name("new", 0);
        assert_eq!(sym.len(), 1);
        assert_eq!(sym[0].name, "new");
        let old = mgr.get_symbols_by_name("old", 0);
        assert!(old.is_empty());
    }

    #[test]
    fn test_symbol_manager_namespace() {
        let mut mgr = TraceDbSymbolManager::new();
        let ns_id = mgr.add_namespace("mylib", 0, SourceType::UserDefined);
        let sym_id = mgr.add_label("func", ns_id, "ram", 0x100, SourceType::UserDefined, 0, 100);
        let children = mgr.get_children(ns_id);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name, "func");
        let path = mgr.get_symbol_path(sym_id);
        assert_eq!(path, vec!["Global", "mylib", "func"]);
    }

    #[test]
    fn test_symbol_manager_class() {
        let mut mgr = TraceDbSymbolManager::new();
        let class_id = mgr.add_class("MyClass", 0, SourceType::UserDefined);
        let sym = mgr.get_symbol_by_id(class_id).unwrap();
        assert_eq!(sym.symbol_type, SymbolType::Class);
        assert!(sym.is_namespace());
    }

    #[test]
    fn test_symbol_manager_get_by_type() {
        let mut mgr = TraceDbSymbolManager::new();
        mgr.add_label("a", 0, "ram", 0, SourceType::UserDefined, 0, 100);
        mgr.add_label("b", 0, "ram", 4, SourceType::UserDefined, 0, 100);
        mgr.add_namespace("ns", 0, SourceType::UserDefined);
        let labels = mgr.get_symbols_by_type(SymbolType::Label);
        assert_eq!(labels.len(), 2);
        // global namespace (id=0) + "ns"
        let namespaces = mgr.get_symbols_by_type(SymbolType::Namespace);
        assert_eq!(namespaces.len(), 2);
    }

    #[test]
    fn test_symbol_manager_global_namespace() {
        let mgr = TraceDbSymbolManager::new();
        assert_eq!(mgr.global_namespace_id(), 0);
        let global = mgr.get_symbol_by_id(0).unwrap();
        assert!(global.is_global());
        assert_eq!(global.name, "Global");
    }

    #[test]
    fn test_symbol_entry_is_namespace() {
        let label = TraceSymbolEntry::new_label(1, "x", 0, "ram", 0, SourceType::UserDefined);
        assert!(!label.is_namespace());
        let ns = TraceSymbolEntry::new_namespace(2, "ns", 0, SourceType::UserDefined);
        assert!(ns.is_namespace());
        let class = TraceSymbolEntry::new_class(3, "cls", 0, SourceType::UserDefined);
        assert!(class.is_namespace());
    }

    #[test]
    fn test_symbol_manager_clear() {
        let mut mgr = TraceDbSymbolManager::new();
        mgr.add_label("a", 0, "ram", 0, SourceType::UserDefined, 0, 100);
        mgr.add_label("b", 0, "ram", 4, SourceType::UserDefined, 0, 100);
        assert!(mgr.symbol_count() > 1);
        mgr.clear();
        assert_eq!(mgr.symbol_count(), 1); // only global namespace remains
        assert!(mgr.get_symbol_by_id(0).is_some());
    }
}
