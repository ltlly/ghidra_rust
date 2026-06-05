//! Symbol table view for trace program views.
//!
//! Ported from Ghidra's `DBTraceProgramViewSymbolTable` in
//! `ghidra.trace.database.program`. Provides the Ghidra SymbolTable
//! interface for a single snapshot of a trace.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Symbol types for the program view symbol table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramViewSymbolType {
    /// A label (function name, variable name, etc.).
    Label,
    /// A function symbol.
    Function,
    /// A class/namespace symbol.
    Class,
    /// A library symbol.
    Library,
    /// An external reference.
    External,
    /// A parameter symbol.
    Parameter,
    /// A local variable.
    LocalVariable,
}

/// A symbol entry in the program view symbol table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewSymbolEntry {
    /// Unique key.
    pub key: i64,
    /// The symbol name.
    pub name: String,
    /// The address (offset).
    pub address: u64,
    /// The address space.
    pub space: String,
    /// The symbol type.
    pub symbol_type: ProgramViewSymbolType,
    /// The namespace ID.
    pub namespace_id: i64,
    /// Whether this is the primary symbol at its address.
    pub is_primary: bool,
    /// Source type (user-defined vs. analysis).
    pub is_user_defined: bool,
}

impl ProgramViewSymbolEntry {
    /// Create a new symbol entry.
    pub fn new(
        key: i64,
        name: impl Into<String>,
        address: u64,
        space: impl Into<String>,
        symbol_type: ProgramViewSymbolType,
    ) -> Self {
        Self {
            key,
            name: name.into(),
            address,
            space: space.into(),
            symbol_type,
            namespace_id: 0,
            is_primary: false,
            is_user_defined: false,
        }
    }
}

/// Symbol table for a trace program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewSymbolTable {
    /// Symbols indexed by key.
    symbols: BTreeMap<i64, ProgramViewSymbolEntry>,
    /// Name index: (namespace_id, name) -> key.
    name_index: BTreeMap<(i64, String), i64>,
    /// Address index: address -> keys.
    address_index: BTreeMap<u64, Vec<i64>>,
    /// Next key.
    next_key: i64,
    /// The snap.
    snap: i64,
}

impl ProgramViewSymbolTable {
    /// Create a new symbol table.
    pub fn new(snap: i64) -> Self {
        Self {
            symbols: BTreeMap::new(),
            name_index: BTreeMap::new(),
            address_index: BTreeMap::new(),
            next_key: 1,
            snap,
        }
    }

    /// Add a symbol.
    pub fn add_symbol(&mut self, mut sym: ProgramViewSymbolEntry) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        sym.key = key;
        self.name_index
            .insert((sym.namespace_id, sym.name.clone()), key);
        self.address_index
            .entry(sym.address)
            .or_default()
            .push(key);
        self.symbols.insert(key, sym);
        key
    }

    /// Get a symbol by key.
    pub fn get_symbol(&self, key: i64) -> Option<&ProgramViewSymbolEntry> {
        self.symbols.get(&key)
    }

    /// Get symbols at a given address.
    pub fn get_symbols_at(&self, address: u64) -> Vec<&ProgramViewSymbolEntry> {
        self.address_index
            .get(&address)
            .map(|keys| keys.iter().filter_map(|&k| self.symbols.get(&k)).collect())
            .unwrap_or_default()
    }

    /// Get a symbol by name and namespace.
    pub fn get_symbol_by_name(&self, namespace_id: i64, name: &str) -> Option<&ProgramViewSymbolEntry> {
        self.name_index
            .get(&(namespace_id, name.to_string()))
            .and_then(|&key| self.symbols.get(&key))
    }

    /// Get all symbols.
    pub fn all_symbols(&self) -> Vec<&ProgramViewSymbolEntry> {
        self.symbols.values().collect()
    }

    /// Get symbols matching a prefix.
    pub fn get_symbols_with_prefix(&self, prefix: &str) -> Vec<&ProgramViewSymbolEntry> {
        self.symbols
            .values()
            .filter(|s| s.name.starts_with(prefix))
            .collect()
    }

    /// Remove a symbol by key.
    pub fn remove_symbol(&mut self, key: i64) -> bool {
        if let Some(sym) = self.symbols.remove(&key) {
            self.name_index.remove(&(sym.namespace_id, sym.name));
            if let Some(keys) = self.address_index.get_mut(&sym.address) {
                keys.retain(|&k| k != key);
            }
            true
        } else {
            false
        }
    }

    /// Get symbol count.
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_table_add_and_get() {
        let mut table = ProgramViewSymbolTable::new(0);
        let key = table.add_symbol(ProgramViewSymbolEntry::new(0, "main", 0x1000, "ram", ProgramViewSymbolType::Function));
        let sym = table.get_symbol(key).unwrap();
        assert_eq!(sym.name, "main");
        assert_eq!(sym.symbol_type, ProgramViewSymbolType::Function);
    }

    #[test]
    fn test_symbol_table_by_name() {
        let mut table = ProgramViewSymbolTable::new(0);
        table.add_symbol(ProgramViewSymbolEntry::new(0, "printf", 0, "external", ProgramViewSymbolType::External));
        let sym = table.get_symbol_by_name(0, "printf");
        assert!(sym.is_some());
    }

    #[test]
    fn test_symbol_table_at_address() {
        let mut table = ProgramViewSymbolTable::new(0);
        table.add_symbol(ProgramViewSymbolEntry::new(0, "foo", 0x1000, "ram", ProgramViewSymbolType::Label));
        table.add_symbol(ProgramViewSymbolEntry::new(0, "bar", 0x1000, "ram", ProgramViewSymbolType::Label));
        assert_eq!(table.get_symbols_at(0x1000).len(), 2);
        assert_eq!(table.get_symbols_at(0x2000).len(), 0);
    }

    #[test]
    fn test_symbol_table_remove() {
        let mut table = ProgramViewSymbolTable::new(0);
        let key = table.add_symbol(ProgramViewSymbolEntry::new(0, "x", 0x100, "ram", ProgramViewSymbolType::Label));
        assert!(table.remove_symbol(key));
        assert_eq!(table.symbol_count(), 0);
    }

    #[test]
    fn test_symbol_table_prefix() {
        let mut table = ProgramViewSymbolTable::new(0);
        table.add_symbol(ProgramViewSymbolEntry::new(0, "func_a", 0x100, "ram", ProgramViewSymbolType::Function));
        table.add_symbol(ProgramViewSymbolEntry::new(0, "func_b", 0x200, "ram", ProgramViewSymbolType::Function));
        table.add_symbol(ProgramViewSymbolEntry::new(0, "data_x", 0x300, "ram", ProgramViewSymbolType::Label));
        let funcs = table.get_symbols_with_prefix("func_");
        assert_eq!(funcs.len(), 2);
    }
}
