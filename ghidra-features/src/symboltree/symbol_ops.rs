//! Symbol tree operations for managing symbols.
//!
//! Ported from action classes in `ghidra.app.plugin.core.symboltree.actions`.
//!
//! Provides operations for creating namespaces, classes, libraries,
//! external locations, and performing CRUD operations on symbols
//! in the symbol tree.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::SymbolType;

// ---------------------------------------------------------------------------
// SymbolOperation
// ---------------------------------------------------------------------------

/// An operation that can be performed on the symbol tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolOperation {
    /// Create a new namespace.
    CreateNamespace {
        /// Parent namespace path.
        parent: String,
        /// Name of the new namespace.
        name: String,
    },
    /// Create a new class.
    CreateClass {
        /// Parent namespace path.
        parent: String,
        /// Name of the new class.
        name: String,
    },
    /// Create a new library.
    CreateLibrary {
        /// Name of the new library.
        name: String,
    },
    /// Create an external location.
    CreateExternalLocation {
        /// Library name.
        library: String,
        /// Symbol name.
        name: String,
        /// Original data type (optional).
        original_data_type: Option<String>,
    },
    /// Rename a symbol.
    RenameSymbol {
        /// The address of the symbol.
        address: u64,
        /// The new name.
        new_name: String,
    },
    /// Delete a symbol.
    DeleteSymbol {
        /// The address of the symbol.
        address: u64,
    },
    /// Move a symbol to a new namespace.
    MoveSymbol {
        /// The address of the symbol.
        address: u64,
        /// The target namespace path.
        target_namespace: String,
    },
    /// Set the primary symbol at an address.
    SetPrimarySymbol {
        /// The address.
        address: u64,
        /// The symbol name to make primary.
        name: String,
    },
    /// Pin an external symbol.
    PinSymbol {
        /// The symbol address.
        address: u64,
    },
    /// Unpin an external symbol.
    UnpinSymbol {
        /// The symbol address.
        address: u64,
    },
}

// ---------------------------------------------------------------------------
// SymbolOperationResult
// ---------------------------------------------------------------------------

/// Result of a symbol tree operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolOperationResult {
    /// Whether the operation succeeded.
    pub success: bool,
    /// A human-readable message.
    pub message: String,
    /// The address of the affected symbol (if applicable).
    pub affected_address: Option<u64>,
    /// Any warnings.
    pub warnings: Vec<String>,
}

impl SymbolOperationResult {
    /// Create a success result.
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            affected_address: None,
            warnings: Vec::new(),
        }
    }

    /// Create a failure result.
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            affected_address: None,
            warnings: Vec::new(),
        }
    }

    /// Set the affected address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.affected_address = Some(addr);
        self
    }
}

// ---------------------------------------------------------------------------
// SymbolTableManager
// ---------------------------------------------------------------------------

/// Manages the symbol table for the symbol tree.
///
/// Provides CRUD operations on symbols, namespace management, and
/// external location tracking.
///
/// # Example
///
/// ```
/// use ghidra_features::symboltree::symbol_ops::*;
///
/// let mut mgr = SymbolTableManager::new();
/// mgr.add_symbol(SymbolEntry::function("main", 0x400000));
/// mgr.create_namespace("", "MyLib");
/// assert_eq!(mgr.symbol_count(), 1);
/// ```
#[derive(Debug, Clone)]
pub struct SymbolTableManager {
    /// Symbols indexed by address.
    symbols: HashMap<u64, SymbolEntry>,
    /// Namespace hierarchy: path -> (parent, children, display_name).
    namespaces: HashMap<String, NamespaceData>,
    /// External libraries.
    libraries: HashMap<String, LibraryData>,
    /// Event log.
    events: Vec<String>,
    /// Next unique ID for symbols.
    next_id: u64,
}

/// Metadata for a single symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolEntry {
    /// Unique symbol ID.
    pub id: u64,
    /// Symbol name.
    pub name: String,
    /// Symbol type.
    pub symbol_type: SymbolType,
    /// Address.
    pub address: u64,
    /// Namespace path.
    pub namespace: String,
    /// Whether this is the primary symbol at its address.
    pub is_primary: bool,
    /// Whether this is an external symbol.
    pub is_external: bool,
    /// Whether this symbol is pinned.
    pub is_pinned: bool,
    /// Source (user-defined, default, import, etc.).
    pub source: SymbolSource,
}

/// The source of a symbol definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolSource {
    /// User-defined.
    UserDefined,
    /// Default (auto-generated).
    Default,
    /// Imported from a binary.
    Import,
    /// Analysis-derived.
    Analysis,
    /// External library.
    External,
}

impl SymbolEntry {
    /// Create a function symbol.
    pub fn function(name: impl Into<String>, address: u64) -> Self {
        Self {
            id: 0,
            name: name.into(),
            symbol_type: SymbolType::Function,
            address,
            namespace: String::new(),
            is_primary: true,
            is_external: false,
            is_pinned: false,
            source: SymbolSource::UserDefined,
        }
    }

    /// Create a label symbol.
    pub fn label(name: impl Into<String>, address: u64) -> Self {
        Self {
            id: 0,
            name: name.into(),
            symbol_type: SymbolType::Label,
            address,
            namespace: String::new(),
            is_primary: true,
            is_external: false,
            is_pinned: false,
            source: SymbolSource::UserDefined,
        }
    }

    /// Create an external symbol.
    pub fn external(
        name: impl Into<String>,
        address: u64,
        library: impl Into<String>,
    ) -> Self {
        Self {
            id: 0,
            name: name.into(),
            symbol_type: SymbolType::ExternalLocation,
            address,
            namespace: library.into(),
            is_primary: true,
            is_external: true,
            is_pinned: false,
            source: SymbolSource::External,
        }
    }

    /// The fully qualified name (namespace::name).
    pub fn qualified_name(&self) -> String {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            format!("{}::{}", self.namespace, self.name)
        }
    }
}

/// Data for a namespace.
#[derive(Debug, Clone)]
struct NamespaceData {
    /// Display name.
    name: String,
    /// Parent path.
    parent: String,
    /// Child namespace paths.
    children: Vec<String>,
    /// Whether this is a class namespace.
    is_class: bool,
}

/// Data for an external library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryData {
    /// Library name.
    pub name: String,
    /// External symbols in this library.
    pub symbols: Vec<String>,
    /// Path to the library file (if known).
    pub path: Option<String>,
}

impl SymbolTableManager {
    /// Create a new empty symbol table manager.
    pub fn new() -> Self {
        let mut namespaces = HashMap::new();
        namespaces.insert(
            String::new(),
            NamespaceData {
                name: String::new(),
                parent: String::new(),
                children: Vec::new(),
                is_class: false,
            },
        );

        Self {
            symbols: HashMap::new(),
            namespaces,
            libraries: HashMap::new(),
            events: Vec::new(),
            next_id: 1,
        }
    }

    /// Add a symbol to the table.
    pub fn add_symbol(&mut self, mut entry: SymbolEntry) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        entry.id = id;
        let addr = entry.address;
        self.symbols.insert(addr, entry);
        self.events.push(format!("Added symbol at 0x{:x}", addr));
        id
    }

    /// Get a symbol by address.
    pub fn get_symbol(&self, address: u64) -> Option<&SymbolEntry> {
        self.symbols.get(&address)
    }

    /// Get a mutable reference to a symbol.
    pub fn get_symbol_mut(&mut self, address: u64) -> Option<&mut SymbolEntry> {
        self.symbols.get_mut(&address)
    }

    /// Delete a symbol by address.
    pub fn delete_symbol(&mut self, address: u64) -> bool {
        if self.symbols.remove(&address).is_some() {
            self.events
                .push(format!("Deleted symbol at 0x{:x}", address));
            true
        } else {
            false
        }
    }

    /// Rename a symbol.
    pub fn rename_symbol(
        &mut self,
        address: u64,
        new_name: &str,
    ) -> SymbolOperationResult {
        let entry = match self.symbols.get_mut(&address) {
            Some(e) => e,
            None => {
                return SymbolOperationResult::failure(format!(
                    "No symbol at address 0x{:x}",
                    address
                ))
            }
        };
        let old_name = entry.name.clone();
        entry.name = new_name.to_string();

        self.events.push(format!(
            "Renamed symbol at 0x{:x} from '{}' to '{}'",
            address, old_name, new_name
        ));

        SymbolOperationResult::success(format!("Renamed to '{}'", new_name))
            .with_address(address)
    }

    /// Move a symbol to a new namespace.
    pub fn move_symbol(
        &mut self,
        address: u64,
        target_namespace: &str,
    ) -> SymbolOperationResult {
        if !self.namespaces.contains_key(target_namespace) {
            return SymbolOperationResult::failure(format!(
                "Namespace '{}' does not exist",
                target_namespace
            ));
        }

        let entry = match self.symbols.get_mut(&address) {
            Some(e) => e,
            None => {
                return SymbolOperationResult::failure(format!(
                    "No symbol at address 0x{:x}",
                    address
                ))
            }
        };

        entry.namespace = target_namespace.to_string();

        self.events.push(format!(
            "Moved symbol at 0x{:x} to namespace '{}'",
            address, target_namespace
        ));

        SymbolOperationResult::success(format!("Moved to '{}'", target_namespace))
            .with_address(address)
    }

    /// Create a namespace.
    pub fn create_namespace(
        &mut self,
        parent: &str,
        name: &str,
    ) -> SymbolOperationResult {
        if name.is_empty() {
            return SymbolOperationResult::failure("Namespace name cannot be empty");
        }
        if !self.namespaces.contains_key(parent) {
            return SymbolOperationResult::failure(format!(
                "Parent namespace '{}' does not exist",
                parent
            ));
        }

        let path = if parent.is_empty() {
            name.to_string()
        } else {
            format!("{}::{}", parent, name)
        };

        if self.namespaces.contains_key(&path) {
            return SymbolOperationResult::failure(format!(
                "Namespace '{}' already exists",
                path
            ));
        }

        let ns = NamespaceData {
            name: name.to_string(),
            parent: parent.to_string(),
            children: Vec::new(),
            is_class: false,
        };
        self.namespaces.insert(path.clone(), ns);

        if let Some(p) = self.namespaces.get_mut(parent) {
            p.children.push(path.clone());
        }

        self.events
            .push(format!("Created namespace '{}'", path));
        SymbolOperationResult::success(format!("Created namespace '{}'", name))
    }

    /// Create a class namespace.
    pub fn create_class(
        &mut self,
        parent: &str,
        name: &str,
    ) -> SymbolOperationResult {
        if name.is_empty() {
            return SymbolOperationResult::failure("Class name cannot be empty");
        }
        if !self.namespaces.contains_key(parent) {
            return SymbolOperationResult::failure(format!(
                "Parent namespace '{}' does not exist",
                parent
            ));
        }

        let path = if parent.is_empty() {
            name.to_string()
        } else {
            format!("{}::{}", parent, name)
        };

        if self.namespaces.contains_key(&path) {
            return SymbolOperationResult::failure(format!(
                "Class '{}' already exists",
                path
            ));
        }

        let ns = NamespaceData {
            name: name.to_string(),
            parent: parent.to_string(),
            children: Vec::new(),
            is_class: true,
        };
        self.namespaces.insert(path.clone(), ns);

        if let Some(p) = self.namespaces.get_mut(parent) {
            p.children.push(path.clone());
        }

        self.events.push(format!("Created class '{}'", path));
        SymbolOperationResult::success(format!("Created class '{}'", name))
    }

    /// Create an external library.
    pub fn create_library(&mut self, name: &str) -> SymbolOperationResult {
        if name.is_empty() {
            return SymbolOperationResult::failure("Library name cannot be empty");
        }
        if self.libraries.contains_key(name) {
            return SymbolOperationResult::failure(format!(
                "Library '{}' already exists",
                name
            ));
        }

        self.libraries.insert(
            name.to_string(),
            LibraryData {
                name: name.to_string(),
                symbols: Vec::new(),
                path: None,
            },
        );

        self.events.push(format!("Created library '{}'", name));
        SymbolOperationResult::success(format!("Created library '{}'", name))
    }

    /// Set the primary symbol at an address.
    pub fn set_primary(&mut self, address: u64, name: &str) -> SymbolOperationResult {
        // Clear primary flag on all symbols at this address
        for entry in self.symbols.values_mut() {
            if entry.address == address {
                entry.is_primary = entry.name == name;
            }
        }

        self.events.push(format!(
            "Set primary at 0x{:x} to '{}'",
            address, name
        ));
        SymbolOperationResult::success(format!("Set primary to '{}'", name))
            .with_address(address)
    }

    /// Get the total number of symbols.
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Get the number of namespaces (excluding root).
    pub fn namespace_count(&self) -> usize {
        self.namespaces.len().saturating_sub(1)
    }

    /// Get the number of external libraries.
    pub fn library_count(&self) -> usize {
        self.libraries.len()
    }

    /// Get symbols in a namespace.
    pub fn symbols_in_namespace(&self, namespace: &str) -> Vec<&SymbolEntry> {
        self.symbols
            .values()
            .filter(|s| s.namespace == namespace)
            .collect()
    }

    /// Get symbols by type.
    pub fn symbols_by_type(&self, symbol_type: SymbolType) -> Vec<&SymbolEntry> {
        self.symbols
            .values()
            .filter(|s| s.symbol_type == symbol_type)
            .collect()
    }

    /// Search symbols by name pattern (case-insensitive substring match).
    pub fn search_symbols(&self, pattern: &str) -> Vec<&SymbolEntry> {
        let lower = pattern.to_lowercase();
        self.symbols
            .values()
            .filter(|s| s.name.to_lowercase().contains(&lower))
            .collect()
    }

    /// Get all child namespaces of a namespace.
    pub fn child_namespaces(&self, parent: &str) -> Vec<&str> {
        self.namespaces
            .get(parent)
            .map(|ns| ns.children.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Check if a namespace is a class.
    pub fn is_class(&self, path: &str) -> bool {
        self.namespaces
            .get(path)
            .map_or(false, |ns| ns.is_class)
    }

    /// Check if a namespace exists.
    pub fn has_namespace(&self, path: &str) -> bool {
        self.namespaces.contains_key(path)
    }

    /// Get the event log.
    pub fn events(&self) -> &[String] {
        &self.events
    }

    /// Get all symbols.
    pub fn all_symbols(&self) -> Vec<&SymbolEntry> {
        self.symbols.values().collect()
    }

    /// Get all symbol addresses.
    pub fn all_addresses(&self) -> Vec<u64> {
        self.symbols.keys().copied().collect()
    }
}

impl Default for SymbolTableManager {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_symbol() {
        let mut mgr = SymbolTableManager::new();
        let id = mgr.add_symbol(SymbolEntry::function("main", 0x400000));
        assert_eq!(id, 1);
        assert_eq!(mgr.symbol_count(), 1);
    }

    #[test]
    fn test_get_symbol() {
        let mut mgr = SymbolTableManager::new();
        mgr.add_symbol(SymbolEntry::function("main", 0x400000));
        let sym = mgr.get_symbol(0x400000).unwrap();
        assert_eq!(sym.name, "main");
        assert_eq!(sym.symbol_type, SymbolType::Function);
    }

    #[test]
    fn test_delete_symbol() {
        let mut mgr = SymbolTableManager::new();
        mgr.add_symbol(SymbolEntry::function("main", 0x400000));
        assert!(mgr.delete_symbol(0x400000));
        assert_eq!(mgr.symbol_count(), 0);
        assert!(!mgr.delete_symbol(0x400000));
    }

    #[test]
    fn test_rename_symbol() {
        let mut mgr = SymbolTableManager::new();
        mgr.add_symbol(SymbolEntry::function("old_name", 0x400000));
        let result = mgr.rename_symbol(0x400000, "new_name");
        assert!(result.success);
        assert_eq!(mgr.get_symbol(0x400000).unwrap().name, "new_name");
    }

    #[test]
    fn test_rename_nonexistent() {
        let mut mgr = SymbolTableManager::new();
        let result = mgr.rename_symbol(0x400000, "new_name");
        assert!(!result.success);
    }

    #[test]
    fn test_create_namespace() {
        let mut mgr = SymbolTableManager::new();
        let result = mgr.create_namespace("", "MyLib");
        assert!(result.success);
        assert!(mgr.has_namespace("MyLib"));
    }

    #[test]
    fn test_create_nested_namespace() {
        let mut mgr = SymbolTableManager::new();
        mgr.create_namespace("", "A");
        let result = mgr.create_namespace("A", "B");
        assert!(result.success);
        assert!(mgr.has_namespace("A::B"));
    }

    #[test]
    fn test_create_class() {
        let mut mgr = SymbolTableManager::new();
        let result = mgr.create_class("", "MyClass");
        assert!(result.success);
        assert!(mgr.is_class("MyClass"));
        assert!(!mgr.is_class(""));
    }

    #[test]
    fn test_create_library() {
        let mut mgr = SymbolTableManager::new();
        let result = mgr.create_library("libc.so");
        assert!(result.success);
        assert_eq!(mgr.library_count(), 1);
    }

    #[test]
    fn test_create_library_duplicate() {
        let mut mgr = SymbolTableManager::new();
        mgr.create_library("libc.so");
        let result = mgr.create_library("libc.so");
        assert!(!result.success);
    }

    #[test]
    fn test_move_symbol() {
        let mut mgr = SymbolTableManager::new();
        mgr.add_symbol(SymbolEntry::function("main", 0x400000));
        mgr.create_namespace("", "MyLib");
        let result = mgr.move_symbol(0x400000, "MyLib");
        assert!(result.success);
        assert_eq!(mgr.get_symbol(0x400000).unwrap().namespace, "MyLib");
    }

    #[test]
    fn test_move_to_nonexistent() {
        let mut mgr = SymbolTableManager::new();
        mgr.add_symbol(SymbolEntry::function("main", 0x400000));
        let result = mgr.move_symbol(0x400000, "NonExistent");
        assert!(!result.success);
    }

    #[test]
    fn test_set_primary() {
        let mut mgr = SymbolTableManager::new();
        mgr.add_symbol(SymbolEntry::function("main", 0x400000));
        let result = mgr.set_primary(0x400000, "main");
        assert!(result.success);
    }

    #[test]
    fn test_symbols_in_namespace() {
        let mut mgr = SymbolTableManager::new();
        let mut s1 = SymbolEntry::function("main", 0x400000);
        s1.namespace = "MyLib".to_string();
        mgr.add_symbol(s1);
        let mut s2 = SymbolEntry::label("data", 0x500000);
        s2.namespace = "MyLib".to_string();
        mgr.add_symbol(s2);

        let symbols = mgr.symbols_in_namespace("MyLib");
        assert_eq!(symbols.len(), 2);
    }

    #[test]
    fn test_symbols_by_type() {
        let mut mgr = SymbolTableManager::new();
        mgr.add_symbol(SymbolEntry::function("main", 0x400000));
        mgr.add_symbol(SymbolEntry::label("data", 0x500000));

        let funcs = mgr.symbols_by_type(SymbolType::Function);
        assert_eq!(funcs.len(), 1);
        let labels = mgr.symbols_by_type(SymbolType::Label);
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn test_search_symbols() {
        let mut mgr = SymbolTableManager::new();
        mgr.add_symbol(SymbolEntry::function("main", 0x400000));
        mgr.add_symbol(SymbolEntry::function("main_loop", 0x400100));
        mgr.add_symbol(SymbolEntry::function("init", 0x400200));

        let found = mgr.search_symbols("main");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_search_case_insensitive() {
        let mut mgr = SymbolTableManager::new();
        mgr.add_symbol(SymbolEntry::function("MyFunc", 0x400000));
        let found = mgr.search_symbols("myfunc");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_namespace_hierarchy() {
        let mut mgr = SymbolTableManager::new();
        mgr.create_namespace("", "A");
        mgr.create_namespace("A", "B");
        let children = mgr.child_namespaces("");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0], "A");
    }

    #[test]
    fn test_symbol_entry_qualified_name() {
        let mut entry = SymbolEntry::function("main", 0x400000);
        assert_eq!(entry.qualified_name(), "main");
        entry.namespace = "MyLib".to_string();
        assert_eq!(entry.qualified_name(), "MyLib::main");
    }

    #[test]
    fn test_external_symbol() {
        let entry = SymbolEntry::external("printf", 0, "libc.so");
        assert!(entry.is_external);
        assert_eq!(entry.symbol_type, SymbolType::ExternalLocation);
    }

    #[test]
    fn test_symbol_ids_increment() {
        let mut mgr = SymbolTableManager::new();
        let id1 = mgr.add_symbol(SymbolEntry::function("a", 0x100));
        let id2 = mgr.add_symbol(SymbolEntry::function("b", 0x200));
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn test_empty_name_rejected() {
        let mut mgr = SymbolTableManager::new();
        assert!(!mgr.create_namespace("", "").success);
        assert!(!mgr.create_class("", "").success);
        assert!(!mgr.create_library("").success);
    }

    #[test]
    fn test_all_symbols() {
        let mut mgr = SymbolTableManager::new();
        mgr.add_symbol(SymbolEntry::function("a", 0x100));
        mgr.add_symbol(SymbolEntry::label("b", 0x200));
        assert_eq!(mgr.all_symbols().len(), 2);
        assert_eq!(mgr.all_addresses().len(), 2);
    }

    #[test]
    fn test_symbol_operation_serialization() {
        let op = SymbolOperation::CreateNamespace {
            parent: String::new(),
            name: "Test".to_string(),
        };
        let json = serde_json::to_string(&op).unwrap();
        let _: SymbolOperation = serde_json::from_str(&json).unwrap();
    }
}
