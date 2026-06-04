//! TraceSymbol - symbols, labels, equates, and references in a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol` package.
//! Provides the trace-equivalent of Ghidra's Symbol Table.

use serde::{Deserialize, Serialize};

use super::Lifespan;

/// The kind of a trace symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TraceSymbolKind {
    /// A label (function entry point, data label, etc.).
    Label,
    /// A namespace (container for other symbols).
    Namespace,
    /// A class symbol.
    Class,
    /// A function symbol.
    Function,
}

/// A symbol in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSymbol {
    /// Unique key.
    pub key: i64,
    /// The symbol name.
    pub name: String,
    /// The address of this symbol.
    pub address: Option<u64>,
    /// The address space.
    pub space: Option<String>,
    /// The kind of symbol.
    pub kind: TraceSymbolKind,
    /// The parent namespace key (None for global).
    pub parent_key: Option<i64>,
    /// The lifespan of this symbol.
    pub lifespan: Lifespan,
}

impl TraceSymbol {
    /// Create a label symbol.
    pub fn label(
        key: i64,
        name: impl Into<String>,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            name: name.into(),
            address: Some(address),
            space: Some(space.into()),
            kind: TraceSymbolKind::Label,
            parent_key: None,
            lifespan,
        }
    }

    /// Create a namespace symbol.
    pub fn namespace(
        key: i64,
        name: impl Into<String>,
        parent_key: Option<i64>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            name: name.into(),
            address: None,
            space: None,
            kind: TraceSymbolKind::Namespace,
            parent_key,
            lifespan,
        }
    }

    /// Create a function symbol.
    pub fn function(
        key: i64,
        name: impl Into<String>,
        address: u64,
        space: impl Into<String>,
        parent_key: Option<i64>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            name: name.into(),
            address: Some(address),
            space: Some(space.into()),
            kind: TraceSymbolKind::Function,
            parent_key,
            lifespan,
        }
    }

    /// Set the parent namespace key.
    pub fn with_parent(mut self, parent_key: i64) -> Self {
        self.parent_key = Some(parent_key);
        self
    }

    /// Whether this symbol is valid at the given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }
}

/// The kind of a reference in the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceReferenceKind {
    /// A memory-to-memory reference (e.g., call, jump).
    Memory,
    /// An offset reference.
    Offset,
    /// A shifted reference.
    Shifted,
    /// A stack reference.
    Stack,
}

/// A reference in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceReference {
    /// Unique key.
    pub key: i64,
    /// The source address.
    pub from_address: u64,
    /// The destination address.
    pub to_address: u64,
    /// The reference kind.
    pub kind: TraceReferenceKind,
    /// The lifespan of this reference.
    pub lifespan: Lifespan,
    /// Whether this is a primary reference.
    pub is_primary: bool,
}

impl TraceReference {
    /// Create a memory reference.
    pub fn memory(key: i64, from: u64, to: u64, lifespan: Lifespan) -> Self {
        Self {
            key,
            from_address: from,
            to_address: to,
            kind: TraceReferenceKind::Memory,
            lifespan,
            is_primary: false,
        }
    }

    /// Create a stack reference.
    pub fn stack(key: i64, from: u64, to: u64, lifespan: Lifespan) -> Self {
        Self {
            key,
            from_address: from,
            to_address: to,
            kind: TraceReferenceKind::Stack,
            lifespan,
            is_primary: false,
        }
    }

    /// Mark as primary.
    pub fn with_primary(mut self, primary: bool) -> Self {
        self.is_primary = primary;
        self
    }
}

/// An equate (named constant) in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEquate {
    /// Unique key.
    pub key: i64,
    /// The equate name.
    pub name: String,
    /// The numeric value.
    pub value: i64,
    /// The lifespan of this equate.
    pub lifespan: Lifespan,
}

impl TraceEquate {
    /// Create a new equate.
    pub fn new(key: i64, name: impl Into<String>, value: i64, lifespan: Lifespan) -> Self {
        Self {
            key,
            name: name.into(),
            value,
            lifespan,
        }
    }
}

/// An equate reference (application of an equate at a specific location).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEquateReference {
    /// The equate key.
    pub equate_key: i64,
    /// The address where the equate is applied.
    pub address: u64,
    /// The operand index.
    pub operand_index: i32,
    /// The lifespan of this reference.
    pub lifespan: Lifespan,
}

/// Manages symbols for a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceSymbolManager {
    next_key: i64,
    symbols: Vec<TraceSymbol>,
    references: Vec<TraceReference>,
    equates: Vec<TraceEquate>,
    equate_references: Vec<TraceEquateReference>,
}

impl TraceSymbolManager {
    /// Create a new symbol manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a symbol.
    pub fn add_symbol(&mut self, mut sym: TraceSymbol) -> i64 {
        if sym.key == 0 {
            sym.key = self.next_key;
        }
        if sym.key >= self.next_key {
            self.next_key = sym.key + 1;
        }
        let key = sym.key;
        self.symbols.push(sym);
        key
    }

    /// Create and add a label.
    pub fn create_label(
        &mut self,
        name: impl Into<String>,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
    ) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        self.symbols.push(TraceSymbol::label(key, name, address, space, lifespan));
        key
    }

    /// Create and add a function.
    pub fn create_function(
        &mut self,
        name: impl Into<String>,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
    ) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        self.symbols.push(TraceSymbol::function(key, name, address, space, None, lifespan));
        key
    }

    /// Create and add a namespace.
    pub fn create_namespace(
        &mut self,
        name: impl Into<String>,
        parent_key: Option<i64>,
        lifespan: Lifespan,
    ) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        self.symbols.push(TraceSymbol::namespace(key, name, parent_key, lifespan));
        key
    }

    /// Delete a symbol by key.
    pub fn delete_symbol(&mut self, key: i64) -> bool {
        let before = self.symbols.len();
        self.symbols.retain(|s| s.key != key);
        self.symbols.len() < before
    }

    /// Get a symbol by key.
    pub fn get_symbol(&self, key: i64) -> Option<&TraceSymbol> {
        self.symbols.iter().find(|s| s.key == key)
    }

    /// Find symbols by name at a given snap.
    pub fn get_symbols_by_name(&self, name: &str, snap: i64) -> Vec<&TraceSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.name == name && s.lifespan.contains(snap))
            .collect()
    }

    /// Find symbols at a given address.
    pub fn get_symbols_at(&self, address: u64, space: &str, snap: i64) -> Vec<&TraceSymbol> {
        self.symbols
            .iter()
            .filter(|s| {
                s.address == Some(address)
                    && s.space.as_deref() == Some(space)
                    && s.lifespan.contains(snap)
            })
            .collect()
    }

    /// Get all symbols at a given snap.
    pub fn all_symbols_at(&self, snap: i64) -> Vec<&TraceSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.lifespan.contains(snap))
            .collect()
    }

    /// Get all function symbols at a given snap.
    pub fn functions_at(&self, snap: i64) -> Vec<&TraceSymbol> {
        self.symbols
            .iter()
            .filter(|s| s.kind == TraceSymbolKind::Function && s.lifespan.contains(snap))
            .collect()
    }

    /// Add a reference.
    pub fn add_reference(&mut self, mut r#ref: TraceReference) -> i64 {
        if r#ref.key == 0 {
            r#ref.key = self.next_key;
        }
        if r#ref.key >= self.next_key {
            self.next_key = r#ref.key + 1;
        }
        let key = r#ref.key;
        self.references.push(r#ref);
        key
    }

    /// Get references from a given address.
    pub fn references_from(&self, address: u64, snap: i64) -> Vec<&TraceReference> {
        self.references
            .iter()
            .filter(|r| r.from_address == address && r.lifespan.contains(snap))
            .collect()
    }

    /// Get references to a given address.
    pub fn references_to(&self, address: u64, snap: i64) -> Vec<&TraceReference> {
        self.references
            .iter()
            .filter(|r| r.to_address == address && r.lifespan.contains(snap))
            .collect()
    }

    /// Add an equate.
    pub fn add_equate(&mut self, equate: TraceEquate) {
        self.equates.push(equate);
    }

    /// Get equates at a given address.
    pub fn equates_at(&self, address: u64, snap: i64) -> Vec<&TraceEquate> {
        self.equate_references
            .iter()
            .filter(|er| er.address == address && er.lifespan.contains(snap))
            .filter_map(|er| self.equates.iter().find(|e| e.key == er.equate_key))
            .collect()
    }

    /// Number of symbols.
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Number of references.
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_symbol() {
        let sym = TraceSymbol::label(1, "main", 0x400000, "ram", Lifespan::now_on(0));
        assert_eq!(sym.name, "main");
        assert_eq!(sym.address, Some(0x400000));
        assert_eq!(sym.kind, TraceSymbolKind::Label);
        assert!(sym.is_valid_at(5));
    }

    #[test]
    fn test_function_symbol() {
        let sym = TraceSymbol::function(1, "printf", 0x400100, "ram", None, Lifespan::now_on(0));
        assert_eq!(sym.kind, TraceSymbolKind::Function);
    }

    #[test]
    fn test_namespace_symbol() {
        let sym = TraceSymbol::namespace(1, "libc", None, Lifespan::ALL);
        assert_eq!(sym.kind, TraceSymbolKind::Namespace);
        assert!(sym.address.is_none());
    }

    #[test]
    fn test_symbol_manager_create_and_query() {
        let mut mgr = TraceSymbolManager::new();
        mgr.create_label("main", 0x400000, "ram", Lifespan::now_on(0));
        mgr.create_label("printf", 0x400100, "ram", Lifespan::now_on(0));
        mgr.create_function("main_func", 0x400000, "ram", Lifespan::now_on(0));

        assert_eq!(mgr.symbol_count(), 3);

        let at_main = mgr.get_symbols_at(0x400000, "ram", 5);
        assert_eq!(at_main.len(), 2); // label + function

        let funcs = mgr.functions_at(5);
        assert_eq!(funcs.len(), 1);
    }

    #[test]
    fn test_symbol_manager_references() {
        let mut mgr = TraceSymbolManager::new();
        let r = TraceReference::memory(0, 0x400000, 0x400100, Lifespan::now_on(0))
            .with_primary(true);
        mgr.add_reference(r);

        let from = mgr.references_from(0x400000, 5);
        assert_eq!(from.len(), 1);
        assert!(from[0].is_primary);

        let to = mgr.references_to(0x400100, 5);
        assert_eq!(to.len(), 1);
    }

    #[test]
    fn test_symbol_manager_delete() {
        let mut mgr = TraceSymbolManager::new();
        let key = mgr.create_label("test", 0x100, "ram", Lifespan::ALL);
        assert_eq!(mgr.symbol_count(), 1);
        assert!(mgr.delete_symbol(key));
        assert_eq!(mgr.symbol_count(), 0);
    }

    #[test]
    fn test_symbol_manager_by_name() {
        let mut mgr = TraceSymbolManager::new();
        mgr.create_label("shared_name", 0x100, "ram", Lifespan::now_on(0));
        mgr.create_label("shared_name", 0x200, "ram", Lifespan::now_on(0));

        let found = mgr.get_symbols_by_name("shared_name", 5);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_reference_kinds() {
        let mem_ref = TraceReference::memory(0, 0x100, 0x200, Lifespan::ALL);
        assert_eq!(mem_ref.kind, TraceReferenceKind::Memory);

        let stack_ref = TraceReference::stack(0, 0x100, 0x200, Lifespan::ALL);
        assert_eq!(stack_ref.kind, TraceReferenceKind::Stack);
    }

    #[test]
    fn test_equate() {
        let e = TraceEquate::new(1, "MY_CONST", 42, Lifespan::ALL);
        assert_eq!(e.name, "MY_CONST");
        assert_eq!(e.value, 42);
    }

    #[test]
    fn test_symbol_serde() {
        let sym = TraceSymbol::label(1, "main", 0x400000, "ram", Lifespan::now_on(0));
        let json = serde_json::to_string(&sym).unwrap();
        let back: TraceSymbol = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "main");
    }
}
