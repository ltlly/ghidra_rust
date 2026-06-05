//! Symbol row objects -- row representation for the symbol table.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.symtable` package:
//!
//! - [`SymbolRowObject`] -- a single row in the symbol table
//! - [`DeletedSymbolRowObject`] -- placeholder for deleted symbols
//! - [`NewSymbolFilter`] -- extended filter with namespace/scope support

// Ported from ghidra.app.plugin.core.symtable

/// A row in the symbol table.
///
/// Ported from `ghidra.app.plugin.core.symtable.SymbolRowObject`.
#[derive(Debug, Clone)]
pub struct SymbolRowObject {
    /// Symbol ID.
    pub id: u64,
    /// Symbol name.
    pub name: String,
    /// Symbol address.
    pub address: u64,
    /// Symbol namespace (e.g., "Global", function name).
    pub namespace: String,
    /// Symbol type name (e.g., "Label", "Function", "Class").
    pub symbol_type: String,
    /// Whether this is a primary symbol.
    pub is_primary: bool,
    /// Source of the symbol (e.g., "User", "Imported", "Analysis").
    pub source: String,
    /// External library name (if external symbol).
    pub external_library: Option<String>,
}

impl SymbolRowObject {
    /// Create a new symbol row object.
    pub fn new(
        id: u64,
        name: impl Into<String>,
        address: u64,
        namespace: impl Into<String>,
        symbol_type: impl Into<String>,
        is_primary: bool,
        source: impl Into<String>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            address,
            namespace: namespace.into(),
            symbol_type: symbol_type.into(),
            is_primary,
            source: source.into(),
            external_library: None,
        }
    }

    /// Set the external library name.
    pub fn with_external_library(mut self, library: impl Into<String>) -> Self {
        self.external_library = Some(library.into());
        self
    }

    /// The full qualified name (namespace::name).
    pub fn qualified_name(&self) -> String {
        if self.namespace == "Global" {
            self.name.clone()
        } else {
            format!("{}::{}", self.namespace, self.name)
        }
    }

    /// Whether this is an external symbol.
    pub fn is_external(&self) -> bool {
        self.external_library.is_some()
    }
}

impl PartialEq for SymbolRowObject {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for SymbolRowObject {}

impl PartialOrd for SymbolRowObject {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SymbolRowObject {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
            .then_with(|| self.name.cmp(&other.name))
    }
}

/// Placeholder for a deleted symbol row.
///
/// Ported from `ghidra.app.plugin.core.symtable.DeletedSymbolRowObject`.
#[derive(Debug, Clone)]
pub struct DeletedSymbolRowObject {
    /// The ID of the deleted symbol.
    pub id: u64,
    /// The name of the deleted symbol.
    pub name: String,
    /// The address of the deleted symbol.
    pub address: u64,
}

impl DeletedSymbolRowObject {
    /// Create a new deleted symbol row object.
    pub fn new(id: u64, name: impl Into<String>, address: u64) -> Self {
        Self {
            id,
            name: name.into(),
            address,
        }
    }
}

/// Extended filter for the symbol table with namespace and scope support.
///
/// Ported from `ghidra.app.plugin.core.symtable.NewSymbolFilter`.
///
/// Extends the basic `SymbolFilter` with additional filtering criteria:
/// - Include/exclude external symbols
/// - Include/exclude dynamic symbols
/// - Filter by specific symbol types
/// - Filter by namespace/scope
#[derive(Debug, Clone)]
pub struct NewSymbolFilter {
    /// Name pattern (substring match, case-insensitive).
    name_pattern: Option<String>,
    /// Whether to include only primary symbols.
    primary_only: bool,
    /// Whether to include external symbols.
    include_external: bool,
    /// Whether to include dynamic symbols.
    include_dynamic: bool,
    /// Minimum address for filter.
    min_address: Option<u64>,
    /// Maximum address for filter.
    max_address: Option<u64>,
    /// Allowed symbol type names (empty = all).
    type_filter: Vec<String>,
    /// Allowed namespace names (empty = all).
    namespace_filter: Vec<String>,
    /// Whether any filtering criteria are set.
    has_criteria: bool,
}

impl NewSymbolFilter {
    /// Create a new filter with all symbols visible.
    pub fn new() -> Self {
        Self {
            name_pattern: None,
            primary_only: false,
            include_external: true,
            include_dynamic: true,
            min_address: None,
            max_address: None,
            type_filter: Vec::new(),
            namespace_filter: Vec::new(),
            has_criteria: false,
        }
    }

    /// Set the name pattern filter.
    pub fn set_name_pattern(&mut self, pattern: Option<String>) {
        self.name_pattern = pattern;
        self.update_criteria();
    }

    /// Set whether to show only primary symbols.
    pub fn set_primary_only(&mut self, primary_only: bool) {
        self.primary_only = primary_only;
        self.update_criteria();
    }

    /// Set whether to include external symbols.
    pub fn set_include_external(&mut self, include: bool) {
        self.include_external = include;
        self.update_criteria();
    }

    /// Set whether to include dynamic symbols.
    pub fn set_include_dynamic(&mut self, include: bool) {
        self.include_dynamic = include;
        self.update_criteria();
    }

    /// Set the address range filter.
    pub fn set_address_range(&mut self, min: Option<u64>, max: Option<u64>) {
        self.min_address = min;
        self.max_address = max;
        self.update_criteria();
    }

    /// Set the type filter.
    pub fn set_type_filter(&mut self, types: Vec<String>) {
        self.type_filter = types;
        self.update_criteria();
    }

    /// Set the namespace filter.
    pub fn set_namespace_filter(&mut self, namespaces: Vec<String>) {
        self.namespace_filter = namespaces;
        self.update_criteria();
    }

    /// Whether any filtering criteria are set.
    pub fn has_criteria(&self) -> bool {
        self.has_criteria
    }

    /// Check if a symbol row object matches this filter.
    pub fn matches(&self, row: &SymbolRowObject) -> bool {
        // Name pattern
        if let Some(ref pattern) = self.name_pattern {
            let lower = pattern.to_lowercase();
            if !row.name.to_lowercase().contains(&lower) {
                return false;
            }
        }

        // Primary only
        if self.primary_only && !row.is_primary {
            return false;
        }

        // External symbols
        if !self.include_external && row.is_external() {
            return false;
        }

        // Address range
        if let Some(min) = self.min_address {
            if row.address < min {
                return false;
            }
        }
        if let Some(max) = self.max_address {
            if row.address > max {
                return false;
            }
        }

        // Type filter
        if !self.type_filter.is_empty() && !self.type_filter.contains(&row.symbol_type) {
            return false;
        }

        // Namespace filter
        if !self.namespace_filter.is_empty() && !self.namespace_filter.contains(&row.namespace) {
            return false;
        }

        true
    }

    fn update_criteria(&mut self) {
        self.has_criteria = self.name_pattern.is_some()
            || self.primary_only
            || !self.include_external
            || !self.include_dynamic
            || self.min_address.is_some()
            || self.max_address.is_some()
            || !self.type_filter.is_empty()
            || !self.namespace_filter.is_empty();
    }

    /// Reset the filter to show all symbols.
    pub fn clear(&mut self) {
        self.name_pattern = None;
        self.primary_only = false;
        self.include_external = true;
        self.include_dynamic = true;
        self.min_address = None;
        self.max_address = None;
        self.type_filter.clear();
        self.namespace_filter.clear();
        self.has_criteria = false;
    }
}

impl Default for NewSymbolFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_row(name: &str, addr: u64) -> SymbolRowObject {
        SymbolRowObject::new(1, name, addr, "Global", "Label", true, "User")
    }

    #[test]
    fn test_symbol_row_object_basic() {
        let row = SymbolRowObject::new(1, "main", 0x400000, "Global", "Function", true, "User");
        assert_eq!(row.id, 1);
        assert_eq!(row.name, "main");
        assert_eq!(row.address, 0x400000);
        assert!(row.is_primary);
        assert!(!row.is_external());
        assert_eq!(row.qualified_name(), "main");
    }

    #[test]
    fn test_symbol_row_object_namespaced() {
        let row = SymbolRowObject::new(2, "helper", 0x401000, "MyClass", "Method", false, "Analysis");
        assert_eq!(row.qualified_name(), "MyClass::helper");
        assert!(!row.is_primary);
    }

    #[test]
    fn test_symbol_row_object_external() {
        let row = SymbolRowObject::new(3, "printf", 0x0, "Global", "Label", true, "Imported")
            .with_external_library("libc.so");
        assert!(row.is_external());
        assert_eq!(row.external_library.as_deref(), Some("libc.so"));
    }

    #[test]
    fn test_symbol_row_object_ordering() {
        let r1 = make_row("alpha", 0x1000);
        let r2 = make_row("beta", 0x2000);
        assert!(r1 < r2);
    }

    #[test]
    fn test_deleted_symbol_row_object() {
        let row = DeletedSymbolRowObject::new(42, "deleted_func", 0x400000);
        assert_eq!(row.id, 42);
        assert_eq!(row.name, "deleted_func");
        assert_eq!(row.address, 0x400000);
    }

    #[test]
    fn test_new_symbol_filter_no_criteria() {
        let filter = NewSymbolFilter::new();
        assert!(!filter.has_criteria());
        assert!(filter.matches(&make_row("anything", 0x1000)));
    }

    #[test]
    fn test_new_symbol_filter_name() {
        let mut filter = NewSymbolFilter::new();
        filter.set_name_pattern(Some("main".into()));
        assert!(filter.has_criteria());
        assert!(filter.matches(&make_row("main", 0x1000)));
        assert!(filter.matches(&make_row("my_main_func", 0x1000)));
        assert!(!filter.matches(&make_row("init", 0x1000)));
    }

    #[test]
    fn test_new_symbol_filter_primary_only() {
        let mut filter = NewSymbolFilter::new();
        filter.set_primary_only(true);
        assert!(filter.has_criteria());

        let primary = SymbolRowObject::new(1, "a", 0x1000, "Global", "Label", true, "User");
        let secondary = SymbolRowObject::new(2, "b", 0x2000, "Global", "Label", false, "User");
        assert!(filter.matches(&primary));
        assert!(!filter.matches(&secondary));
    }

    #[test]
    fn test_new_symbol_filter_external() {
        let mut filter = NewSymbolFilter::new();
        filter.set_include_external(false);
        assert!(filter.has_criteria());

        let local = make_row("local_func", 0x1000);
        let ext = SymbolRowObject::new(2, "printf", 0, "Global", "Label", true, "Imported")
            .with_external_library("libc.so");
        assert!(filter.matches(&local));
        assert!(!filter.matches(&ext));
    }

    #[test]
    fn test_new_symbol_filter_address_range() {
        let mut filter = NewSymbolFilter::new();
        filter.set_address_range(Some(0x400000), Some(0x500000));
        assert!(filter.has_criteria());
        assert!(filter.matches(&make_row("a", 0x400000)));
        assert!(filter.matches(&make_row("b", 0x450000)));
        assert!(filter.matches(&make_row("c", 0x500000)));
        assert!(!filter.matches(&make_row("d", 0x300000)));
        assert!(!filter.matches(&make_row("e", 0x600000)));
    }

    #[test]
    fn test_new_symbol_filter_type() {
        let mut filter = NewSymbolFilter::new();
        filter.set_type_filter(vec!["Function".into(), "Class".into()]);

        let func = SymbolRowObject::new(1, "a", 0x1000, "Global", "Function", true, "User");
        let label = SymbolRowObject::new(2, "b", 0x2000, "Global", "Label", true, "User");
        assert!(filter.matches(&func));
        assert!(!filter.matches(&label));
    }

    #[test]
    fn test_new_symbol_filter_namespace() {
        let mut filter = NewSymbolFilter::new();
        filter.set_namespace_filter(vec!["MyClass".into()]);

        let in_class = SymbolRowObject::new(1, "a", 0x1000, "MyClass", "Method", true, "User");
        let in_global = SymbolRowObject::new(2, "b", 0x2000, "Global", "Label", true, "User");
        assert!(filter.matches(&in_class));
        assert!(!filter.matches(&in_global));
    }

    #[test]
    fn test_new_symbol_filter_clear() {
        let mut filter = NewSymbolFilter::new();
        filter.set_name_pattern(Some("test".into()));
        filter.set_primary_only(true);
        filter.set_address_range(Some(0), Some(0xFF));
        assert!(filter.has_criteria());

        filter.clear();
        assert!(!filter.has_criteria());
        assert!(filter.matches(&make_row("anything", 0x1000)));
    }

    #[test]
    fn test_new_symbol_filter_combined() {
        let mut filter = NewSymbolFilter::new();
        filter.set_name_pattern(Some("func".into()));
        filter.set_primary_only(true);
        filter.set_address_range(Some(0x400000), Some(0x500000));

        let good = SymbolRowObject::new(1, "my_func", 0x450000, "Global", "Function", true, "User");
        let bad_name = SymbolRowObject::new(2, "data", 0x450000, "Global", "Label", true, "User");
        let bad_addr = SymbolRowObject::new(3, "func2", 0x600000, "Global", "Function", true, "User");
        let bad_primary = SymbolRowObject::new(4, "func3", 0x450000, "Global", "Function", false, "User");

        assert!(filter.matches(&good));
        assert!(!filter.matches(&bad_name));
        assert!(!filter.matches(&bad_addr));
        assert!(!filter.matches(&bad_primary));
    }
}
