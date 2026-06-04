//! High-level decompiler types.
//!
//! Ported from `ghidra.program.model.pcode.High*` classes. These types model
//! the decompiler's view of variables, symbols, and function prototypes.

use crate::addr::Address;
use crate::pcode::varnode::Varnode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ============================================================================
// PcodeDataTypeManager -- minimal data-type manager for pcode types
// ============================================================================

/// A minimal data type manager used by pcode high-level types.
///
/// This is a simplified port of Ghidra's `PcodeDataTypeManager`. It stores
/// a mapping from type IDs to type names. In Ghidra this references the
/// full `DataTypeManager`; here we keep just enough for the pcode model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeDataTypeManager {
    /// Map from type ID to type name.
    types: HashMap<u64, String>,
    /// Name of this data type archive.
    pub name: String,
}

impl PcodeDataTypeManager {
    /// Create a new empty data type manager.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            types: HashMap::new(),
            name: name.into(),
        }
    }

    /// Register a type name with an ID.
    pub fn add_type(&mut self, id: u64, name: impl Into<String>) {
        self.types.insert(id, name.into());
    }

    /// Look up a type name by ID.
    pub fn get_type_name(&self, id: u64) -> Option<&str> {
        self.types.get(&id).map(|s| s.as_str())
    }

    /// Returns the number of registered types.
    pub fn num_types(&self) -> usize {
        self.types.len()
    }
}

impl Default for PcodeDataTypeManager {
    fn default() -> Self {
        Self::new("default")
    }
}

// ============================================================================
// FunctionPrototype -- decompiler's view of a function prototype
// ============================================================================

/// A function prototype as seen by the decompiler.
///
/// Corresponds to Ghidra's `FunctionPrototype`. Contains the return type,
/// parameter types, calling convention, and other attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionPrototype {
    /// Whether the function has a "void" return type.
    pub has_no_return: bool,
    /// Whether the function returns a value.
    pub has_return: bool,
    /// Whether the function's parameters are fully known (not variadic).
    pub is_variadic: bool,
    /// Whether the function inline.
    pub is_inline: bool,
    /// Whether this is a constructor.
    pub is_constructor: bool,
    /// Whether this is a destructor.
    pub is_destructor: bool,
    /// The calling convention name (e.g., "__cdecl", "__stdcall").
    pub calling_convention: String,
    /// Index of the parameter marking the "this" pointer (for methods), or -1.
    pub this_param_index: i32,
    /// Return storage location index (into the symbol map), or -1 if none.
    pub return_storage_index: i32,
}

impl FunctionPrototype {
    /// Create a new function prototype with defaults.
    pub fn new() -> Self {
        Self {
            has_no_return: false,
            has_return: true,
            is_variadic: false,
            is_inline: false,
            is_constructor: false,
            is_destructor: false,
            calling_convention: String::new(),
            this_param_index: -1,
            return_storage_index: -1,
        }
    }

    /// Returns `true` if this is a method (has a `this` pointer).
    pub fn has_this(&self) -> bool {
        self.this_param_index >= 0
    }

    /// Returns `true` if this function returns void.
    pub fn is_void_return(&self) -> bool {
        self.has_no_return || !self.has_return
    }
}

impl Default for FunctionPrototype {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SymbolEntry -- a storage mapping for a HighSymbol
// ============================================================================

/// A mapping from a [`HighSymbol`] to a specific storage location.
///
/// Corresponds to Ghidra's `SymbolEntry`. A symbol may have multiple entries
/// if it is stored in different locations at different points.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolEntry {
    /// The address of this storage location.
    pub address: Address,
    /// Size of the storage in bytes.
    pub size: u32,
    /// The first use offset (relative to the start of the function), or -1.
    pub first_use_offset: i32,
    /// The varnode index representing this storage location.
    pub varnode_index: u32,
}

impl SymbolEntry {
    /// Create a new symbol entry.
    pub fn new(address: Address, size: u32) -> Self {
        Self {
            address,
            size,
            first_use_offset: -1,
            varnode_index: u32::MAX,
        }
    }

    /// Create a symbol entry with a varnode index.
    pub fn with_varnode(address: Address, size: u32, varnode_index: u32) -> Self {
        Self {
            address,
            size,
            first_use_offset: -1,
            varnode_index,
        }
    }

    /// Returns `true` if this entry has a valid varnode.
    pub fn has_varnode(&self) -> bool {
        self.varnode_index != u32::MAX
    }
}

// ============================================================================
// HighSymbol -- a symbol in the decompiler's model
// ============================================================================

/// A symbol within the decompiler's model of a function.
///
/// Corresponds to Ghidra's `HighSymbol`. The symbol has a name and data-type,
/// along with storage mappings via [`SymbolEntry`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighSymbol {
    /// Unique ID of this symbol.
    pub id: u64,
    /// Symbol name.
    pub name: String,
    /// Type ID (into the PcodeDataTypeManager).
    pub type_id: u64,
    /// Category: -1=none, 0=parameter, 1=equate.
    pub category: i32,
    /// Numbering within the category.
    pub category_index: i32,
    /// Whether the name is locked (cannot be renamed).
    pub name_locked: bool,
    /// Whether the type is locked (cannot be changed).
    pub type_locked: bool,
    /// Whether this is the "this" pointer symbol.
    pub is_this: bool,
    /// Whether this is a hidden symbol (e.g., hidden pointer for return values).
    pub is_hidden: bool,
    /// Storage mappings for this symbol.
    pub entries: Vec<SymbolEntry>,
    /// Index of the associated HighVariable (u32::MAX if none).
    pub high_variable_index: u32,
}

impl HighSymbol {
    /// Base ID for dynamic symbols.
    pub const ID_BASE: u64 = 0x4000_0000_0000_0000;

    /// Create a new high symbol.
    pub fn new(id: u64, name: impl Into<String>, type_id: u64) -> Self {
        Self {
            id,
            name: name.into(),
            type_id,
            category: -1,
            category_index: -1,
            name_locked: false,
            type_locked: false,
            is_this: false,
            is_hidden: false,
            entries: Vec::new(),
            high_variable_index: u32::MAX,
        }
    }

    /// Add a storage entry to this symbol.
    pub fn add_entry(&mut self, entry: SymbolEntry) {
        self.entries.push(entry);
    }

    /// Returns the number of storage entries.
    pub fn num_entries(&self) -> usize {
        self.entries.len()
    }

    /// Returns the first entry's address, if any.
    pub fn get_first_address(&self) -> Option<Address> {
        self.entries.first().map(|e| e.address)
    }
}

impl fmt::Display for HighSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HighSymbol({}: \"{}\")", self.id, self.name)
    }
}

// ============================================================================
// HighFunctionSymbol -- symbol representing a function
// ============================================================================

/// A symbol that represents a function in the decompiler's model.
///
/// Corresponds to Ghidra's `HighFunctionSymbol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighFunctionSymbol {
    /// The underlying symbol data.
    pub symbol: HighSymbol,
    /// The function's namespace ID.
    pub namespace_id: u64,
    /// The function's entry point address.
    pub entry_point: Address,
}

impl HighFunctionSymbol {
    pub fn new(id: u64, name: impl Into<String>, type_id: u64, entry_point: Address) -> Self {
        Self {
            symbol: HighSymbol::new(id, name, type_id),
            namespace_id: 0,
            entry_point,
        }
    }
}

/// A label symbol in the decompiler's model.
///
/// Corresponds to Ghidra's `HighLabelSymbol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighLabelSymbol {
    pub symbol: HighSymbol,
    /// The label's address.
    pub label_address: Address,
}

impl HighLabelSymbol {
    pub fn new(id: u64, name: impl Into<String>, label_address: Address) -> Self {
        Self {
            symbol: HighSymbol::new(id, name, 0),
            label_address,
        }
    }
}

/// A code symbol (backed by a Data object) in the decompiler's model.
///
/// Corresponds to Ghidra's `HighCodeSymbol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighCodeSymbol {
    pub symbol: HighSymbol,
    /// The size of the data item.
    pub data_size: u32,
}

impl HighCodeSymbol {
    pub fn new(id: u64, name: impl Into<String>, type_id: u64, data_size: u32) -> Self {
        Self {
            symbol: HighSymbol::new(id, name, type_id),
            data_size,
        }
    }
}

/// An external reference symbol in the decompiler's model.
///
/// Corresponds to Ghidra's `HighExternalSymbol`. The symbol address is the
/// code location that CALL instructions refer to, while the resolve address
/// is where the decompiler expects to retrieve the Function object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighExternalSymbol {
    pub symbol: HighSymbol,
    /// The address of the function object (for thunk resolution).
    pub resolve_address: Address,
}

impl HighExternalSymbol {
    pub fn new(
        id: u64,
        name: impl Into<String>,
        addr: Address,
        resolve_address: Address,
    ) -> Self {
        let mut sym = HighSymbol::new(id, name, 0);
        sym.add_entry(SymbolEntry::new(addr, 1));
        Self {
            symbol: sym,
            resolve_address,
        }
    }
}

/// A "function shell" symbol -- a minimal function representation used
/// during decompiler analysis.
///
/// Corresponds to Ghidra's `HighFunctionShellSymbol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighFunctionShellSymbol {
    pub symbol: HighSymbol,
    /// Whether this is an external function.
    pub is_external: bool,
}

impl HighFunctionShellSymbol {
    pub fn new(id: u64, name: impl Into<String>, type_id: u64) -> Self {
        Self {
            symbol: HighSymbol::new(id, name, type_id),
            is_external: false,
        }
    }
}

// ============================================================================
// HighVariable -- abstract high-level variable
// ============================================================================

/// The class of a [`HighVariable`].
///
/// This enum replaces the Java class hierarchy of `HighVariable` subclasses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HighVariableClass {
    /// A local variable.
    Local,
    /// A function parameter.
    Param,
    /// A global or register variable.
    Global,
    /// Any other variable (catch-all).
    Other,
    /// A compile-time constant.
    Constant,
}

impl HighVariableClass {
    /// Returns the single-character class string used in the XML encoding.
    pub fn class_char(self) -> char {
        match self {
            HighVariableClass::Local => 'l',
            HighVariableClass::Param => 'p',
            HighVariableClass::Global => 'g',
            HighVariableClass::Other => 'o',
            HighVariableClass::Constant => 'c',
        }
    }

    /// Returns the class for a single-character class string.
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'l' => Some(HighVariableClass::Local),
            'p' => Some(HighVariableClass::Param),
            'g' => Some(HighVariableClass::Global),
            'o' => Some(HighVariableClass::Other),
            'c' => Some(HighVariableClass::Constant),
            _ => None,
        }
    }
}

/// A high-level variable (as in a high-level language like C/C++).
///
/// Corresponds to Ghidra's abstract `HighVariable` class. Built out of
/// one or more [`Varnode`]s (low-level variable locations).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighVariable {
    /// The class of this variable.
    pub class: HighVariableClass,
    /// Variable name.
    pub name: String,
    /// Data type ID (into the PcodeDataTypeManager).
    pub type_id: u64,
    /// Index of the representative VarnodeAST.
    pub represent_index: u32,
    /// Indices of all VarnodeAST instances of this variable.
    pub instance_indices: Vec<u32>,
    /// Offset (in bytes) into containing symbol (-1 = whole match).
    pub offset: i32,
    /// Index of the associated HighSymbol (u32::MAX if none).
    pub symbol_index: u32,
    /// Index of the associated HighFunction.
    pub function_index: u32,
}

impl HighVariable {
    /// Create a new high variable.
    pub fn new(
        class: HighVariableClass,
        name: impl Into<String>,
        type_id: u64,
        represent_index: u32,
    ) -> Self {
        Self {
            class,
            name: name.into(),
            type_id,
            represent_index,
            instance_indices: Vec::new(),
            offset: -1,
            symbol_index: u32::MAX,
            function_index: u32::MAX,
        }
    }

    /// Add a VarnodeAST instance to this variable.
    pub fn add_instance(&mut self, vn_index: u32) {
        self.instance_indices.push(vn_index);
    }

    /// Returns the number of instances.
    pub fn num_instances(&self) -> usize {
        self.instance_indices.len()
    }

    /// Returns `true` if this variable has an associated symbol.
    pub fn has_symbol(&self) -> bool {
        self.symbol_index != u32::MAX
    }

    /// Returns `true` if the offset indicates a partial match.
    pub fn is_partial_match(&self) -> bool {
        self.offset >= 0
    }
}

impl fmt::Display for HighVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HighVar({}, \"{}\")", self.class.class_char(), self.name)
    }
}

// ============================================================================
// Concrete HighVariable subclasses (as wrapper types)
// ============================================================================

/// A local variable in the decompiler's model.
///
/// Corresponds to Ghidra's `HighLocal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighLocal {
    pub var: HighVariable,
}

impl HighLocal {
    pub fn new(name: impl Into<String>, type_id: u64, represent_index: u32) -> Self {
        Self {
            var: HighVariable::new(HighVariableClass::Local, name, type_id, represent_index),
        }
    }
}

/// A function parameter in the decompiler's model.
///
/// Corresponds to Ghidra's `HighParam`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighParam {
    pub var: HighVariable,
    /// The parameter ordinal (0-based).
    pub ordinal: u32,
}

impl HighParam {
    pub fn new(
        name: impl Into<String>,
        type_id: u64,
        represent_index: u32,
        ordinal: u32,
    ) -> Self {
        Self {
            var: HighVariable::new(HighVariableClass::Param, name, type_id, represent_index),
            ordinal,
        }
    }
}

/// A global variable in the decompiler's model.
///
/// Corresponds to Ghidra's `HighGlobal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighGlobal {
    pub var: HighVariable,
    /// The global variable's address.
    pub address: Address,
}

impl HighGlobal {
    pub fn new(
        name: impl Into<String>,
        type_id: u64,
        represent_index: u32,
        address: Address,
    ) -> Self {
        Self {
            var: HighVariable::new(HighVariableClass::Global, name, type_id, represent_index),
            address,
        }
    }
}

/// An "other" variable (catch-all for variables that don't fit other categories).
///
/// Corresponds to Ghidra's `HighOther`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighOther {
    pub var: HighVariable,
}

impl HighOther {
    pub fn new(name: impl Into<String>, type_id: u64, represent_index: u32) -> Self {
        Self {
            var: HighVariable::new(HighVariableClass::Other, name, type_id, represent_index),
        }
    }
}

/// A compile-time constant in the decompiler's model.
///
/// Corresponds to Ghidra's `HighConstant`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighConstant {
    pub var: HighVariable,
    /// The constant value.
    pub value: u64,
}

impl HighConstant {
    pub fn new(type_id: u64, represent_index: u32, value: u64) -> Self {
        Self {
            var: HighVariable::new(HighVariableClass::Constant, "", type_id, represent_index),
            value,
        }
    }
}

// ============================================================================
// DataTypeSymbol -- a symbol with an associated data type
// ============================================================================

/// A named data type symbol used during prototype resolution.
///
/// Corresponds to Ghidra's `DataTypeSymbol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeSymbol {
    /// Symbol name.
    pub name: String,
    /// Data type ID.
    pub type_id: u64,
    /// Symbol ID.
    pub id: u64,
    /// Whether this is a typedef.
    pub is_typedef: bool,
}

impl DataTypeSymbol {
    pub fn new(name: impl Into<String>, type_id: u64, id: u64) -> Self {
        Self {
            name: name.into(),
            type_id,
            id,
            is_typedef: false,
        }
    }
}

// ============================================================================
// EquateSymbol -- an equate (named constant) in pcode
// ============================================================================

/// An equate symbol (named constant substitution).
///
/// Corresponds to Ghidra's `EquateSymbol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquateSymbol {
    /// The equate name.
    pub name: String,
    /// The numeric value.
    pub value: i64,
    /// The format string for display (e.g., "0x%x").
    pub format: String,
}

impl EquateSymbol {
    pub fn new(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            value,
            format: String::new(),
        }
    }
}

// ============================================================================
// LocalSymbolMap -- mapping of local symbols within a function
// ============================================================================

/// A map of local symbols within a decompiler function model.
///
/// Corresponds to Ghidra's `LocalSymbolMap`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSymbolMap {
    /// Symbols indexed by their unique ID.
    pub symbols: HashMap<u64, HighSymbol>,
    /// The next unique symbol ID to allocate.
    pub next_id: u64,
}

impl LocalSymbolMap {
    /// Create a new empty local symbol map.
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
            next_id: 1,
        }
    }

    /// Add a symbol to the map.
    pub fn add_symbol(&mut self, mut symbol: HighSymbol) -> u64 {
        if symbol.id == 0 {
            symbol.id = self.next_id;
            self.next_id += 1;
        }
        let id = symbol.id;
        self.symbols.insert(id, symbol);
        id
    }

    /// Look up a symbol by ID.
    pub fn get_symbol(&self, id: u64) -> Option<&HighSymbol> {
        self.symbols.get(&id)
    }

    /// Look up a symbol by ID (mutable).
    pub fn get_symbol_mut(&mut self, id: u64) -> Option<&mut HighSymbol> {
        self.symbols.get_mut(&id)
    }

    /// Returns the number of symbols.
    pub fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    /// Iterate over all symbols.
    pub fn iter(&self) -> impl Iterator<Item = &HighSymbol> {
        self.symbols.values()
    }
}

impl Default for LocalSymbolMap {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GlobalSymbolMap -- mapping of global symbols for a function
// ============================================================================

/// A map of global symbols referenced by a decompiler function model.
///
/// Corresponds to Ghidra's `GlobalSymbolMap`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSymbolMap {
    /// Global symbols indexed by their unique ID.
    pub symbols: HashMap<u64, HighSymbol>,
    /// External symbols indexed by their unique ID.
    pub external_symbols: HashMap<u64, HighExternalSymbol>,
    /// Global variable references.
    pub globals: HashMap<u64, HighGlobal>,
}

impl GlobalSymbolMap {
    /// Create a new empty global symbol map.
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
            external_symbols: HashMap::new(),
            globals: HashMap::new(),
        }
    }

    /// Add a global symbol.
    pub fn add_symbol(&mut self, symbol: HighSymbol) {
        self.symbols.insert(symbol.id, symbol);
    }

    /// Add an external symbol.
    pub fn add_external(&mut self, ext: HighExternalSymbol) {
        self.external_symbols.insert(ext.symbol.id, ext);
    }

    /// Look up a global symbol by ID.
    pub fn get_symbol(&self, id: u64) -> Option<&HighSymbol> {
        self.symbols.get(&id)
    }

    /// Look up an external symbol by ID.
    pub fn get_external(&self, id: u64) -> Option<&HighExternalSymbol> {
        self.external_symbols.get(&id)
    }
}

impl Default for GlobalSymbolMap {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// HighFunction -- decompiler model of a function
// ============================================================================

/// High-level abstraction associated with a low-level function.
///
/// Corresponds to Ghidra's `HighFunction`. Contains the decompiler's
/// view of a function: its prototype, local/global symbols, jump tables,
/// and the pcode syntax tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighFunction {
    /// The function's entry point address.
    pub entry_point: Address,
    /// The function's prototype.
    pub prototype: FunctionPrototype,
    /// Local symbols within this function.
    pub local_symbols: LocalSymbolMap,
    /// Global symbols referenced by this function.
    pub global_symbols: GlobalSymbolMap,
    /// Jump tables discovered during decompilation.
    pub jump_tables: Vec<JumpTable>,
    /// Prototype override entries.
    pub proto_overrides: Vec<DataTypeSymbol>,
    /// Index of the PcodeSyntaxTree associated with this function (u32::MAX if none).
    pub syntax_tree_index: u32,
    /// Language ID string.
    pub language_id: String,
    /// Compiler spec ID string.
    pub compiler_spec_id: String,
}

/// A jump table discovered during decompilation.
///
/// Corresponds to Ghidra's `JumpTable`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpTable {
    /// The address of the indirect branch.
    pub branch_address: Address,
    /// The target addresses.
    pub targets: Vec<Address>,
}

impl JumpTable {
    pub fn new(branch_address: Address) -> Self {
        Self {
            branch_address,
            targets: Vec::new(),
        }
    }

    pub fn add_target(&mut self, target: Address) {
        self.targets.push(target);
    }
}

impl HighFunction {
    /// Tag name used to store decompiler annotations in program metadata.
    pub const DECOMPILER_TAG_MAP: &'static str = "decompiler_tags";

    /// Name of the override namespace.
    pub const OVERRIDE_NAMESPACE_NAME: &'static str = "override";

    /// Create a new high function at the given entry point.
    pub fn new(entry_point: Address) -> Self {
        Self {
            entry_point,
            prototype: FunctionPrototype::new(),
            local_symbols: LocalSymbolMap::new(),
            global_symbols: GlobalSymbolMap::new(),
            jump_tables: Vec::new(),
            proto_overrides: Vec::new(),
            syntax_tree_index: u32::MAX,
            language_id: String::new(),
            compiler_spec_id: String::new(),
        }
    }

    /// Returns the function entry point.
    pub fn get_entry_point(&self) -> Address {
        self.entry_point
    }

    /// Returns the function prototype.
    pub fn get_prototype(&self) -> &FunctionPrototype {
        &self.prototype
    }

    /// Returns the local symbol map.
    pub fn get_local_symbols(&self) -> &LocalSymbolMap {
        &self.local_symbols
    }

    /// Returns the global symbol map.
    pub fn get_global_symbols(&self) -> &GlobalSymbolMap {
        &self.global_symbols
    }

    /// Returns the jump tables.
    pub fn get_jump_tables(&self) -> &[JumpTable] {
        &self.jump_tables
    }

    /// Returns the number of local symbols.
    pub fn num_local_symbols(&self) -> usize {
        self.local_symbols.num_symbols()
    }

    /// Returns `true` if this function has a syntax tree.
    pub fn has_syntax_tree(&self) -> bool {
        self.syntax_tree_index != u32::MAX
    }

    /// Returns `true` if this function has a prototype.
    pub fn has_prototype(&self) -> bool {
        self.prototype.has_return || self.prototype.has_no_return
    }

    /// Returns the language ID.
    pub fn get_language_id(&self) -> &str {
        &self.language_id
    }

    /// Returns the compiler spec ID.
    pub fn get_compiler_spec_id(&self) -> &str {
        &self.compiler_spec_id
    }
}

impl fmt::Display for HighFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HighFunction({}, {} local symbols, {} jump tables)",
            self.entry_point,
            self.local_symbols.num_symbols(),
            self.jump_tables.len()
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
    fn test_pcode_data_type_manager() {
        let mut dtm = PcodeDataTypeManager::new("test");
        dtm.add_type(1, "int");
        dtm.add_type(2, "char*");
        assert_eq!(dtm.num_types(), 2);
        assert_eq!(dtm.get_type_name(1), Some("int"));
        assert_eq!(dtm.get_type_name(2), Some("char*"));
        assert_eq!(dtm.get_type_name(99), None);
    }

    #[test]
    fn test_function_prototype() {
        let mut proto = FunctionPrototype::new();
        assert!(!proto.has_this());
        assert!(!proto.is_void_return());
        proto.has_no_return = true;
        assert!(proto.is_void_return());
        proto.this_param_index = 0;
        assert!(proto.has_this());
    }

    #[test]
    fn test_symbol_entry() {
        let e = SymbolEntry::new(Address::new(0x1000), 4);
        assert!(!e.has_varnode());
        let e2 = SymbolEntry::with_varnode(Address::new(0x1000), 4, 10);
        assert!(e2.has_varnode());
    }

    #[test]
    fn test_high_symbol() {
        let mut sym = HighSymbol::new(1, "myVar", 42);
        assert_eq!(sym.name, "myVar");
        assert_eq!(sym.category, -1);
        assert!(!sym.name_locked);
        assert!(sym.entries.is_empty());
        sym.add_entry(SymbolEntry::new(Address::new(0x1000), 4));
        assert_eq!(sym.num_entries(), 1);
        assert_eq!(sym.get_first_address(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_high_symbol_display() {
        let sym = HighSymbol::new(1, "test", 0);
        let s = format!("{}", sym);
        assert!(s.contains("test"));
    }

    #[test]
    fn test_high_symbol_id_base() {
        assert_eq!(HighSymbol::ID_BASE, 0x4000_0000_0000_0000);
    }

    #[test]
    fn test_high_function_symbol() {
        let fs = HighFunctionSymbol::new(1, "main", 10, Address::new(0x401000));
        assert_eq!(fs.entry_point, Address::new(0x401000));
        assert_eq!(fs.symbol.name, "main");
    }

    #[test]
    fn test_high_label_symbol() {
        let ls = HighLabelSymbol::new(1, "LAB_00401000", Address::new(0x401000));
        assert_eq!(ls.label_address, Address::new(0x401000));
    }

    #[test]
    fn test_high_code_symbol() {
        let cs = HighCodeSymbol::new(1, "globalData", 5, 8);
        assert_eq!(cs.data_size, 8);
    }

    #[test]
    fn test_high_external_symbol() {
        let ext = HighExternalSymbol::new(1, "printf", Address::new(0), Address::new(0x401000));
        assert_eq!(ext.resolve_address, Address::new(0x401000));
        assert_eq!(ext.symbol.num_entries(), 1);
    }

    #[test]
    fn test_high_variable_class() {
        assert_eq!(HighVariableClass::Local.class_char(), 'l');
        assert_eq!(HighVariableClass::from_char('p'), Some(HighVariableClass::Param));
        assert!(HighVariableClass::from_char('x').is_none());
    }

    #[test]
    fn test_high_variable() {
        let mut hv = HighVariable::new(HighVariableClass::Local, "x", 1, 10);
        assert_eq!(hv.class, HighVariableClass::Local);
        assert!(!hv.has_symbol());
        assert!(!hv.is_partial_match());
        hv.add_instance(11);
        hv.add_instance(12);
        assert_eq!(hv.num_instances(), 2);
        hv.offset = 4;
        assert!(hv.is_partial_match());
    }

    #[test]
    fn test_high_variable_display() {
        let hv = HighVariable::new(HighVariableClass::Param, "argc", 1, 0);
        let s = format!("{}", hv);
        assert!(s.contains("p"));
        assert!(s.contains("argc"));
    }

    #[test]
    fn test_high_local() {
        let hl = HighLocal::new("tmp", 1, 5);
        assert_eq!(hl.var.class, HighVariableClass::Local);
        assert_eq!(hl.var.name, "tmp");
    }

    #[test]
    fn test_high_param() {
        let hp = HighParam::new("arg0", 1, 5, 0);
        assert_eq!(hp.var.class, HighVariableClass::Param);
        assert_eq!(hp.ordinal, 0);
    }

    #[test]
    fn test_high_global() {
        let hg = HighGlobal::new("g_count", 1, 5, Address::new(0x600000));
        assert_eq!(hg.address, Address::new(0x600000));
    }

    #[test]
    fn test_high_other() {
        let ho = HighOther::new("unspec", 1, 5);
        assert_eq!(ho.var.class, HighVariableClass::Other);
    }

    #[test]
    fn test_high_constant() {
        let hc = HighConstant::new(1, 5, 42);
        assert_eq!(hc.value, 42);
        assert_eq!(hc.var.class, HighVariableClass::Constant);
    }

    #[test]
    fn test_data_type_symbol() {
        let dts = DataTypeSymbol::new("mytype", 10, 5);
        assert_eq!(dts.name, "mytype");
        assert!(!dts.is_typedef);
    }

    #[test]
    fn test_equate_symbol() {
        let es = EquateSymbol::new("MY_CONST", 0x42);
        assert_eq!(es.value, 0x42);
    }

    #[test]
    fn test_local_symbol_map() {
        let mut lsm = LocalSymbolMap::new();
        let sym = HighSymbol::new(0, "auto_var", 1);
        let id = lsm.add_symbol(sym);
        assert!(id > 0);
        assert_eq!(lsm.num_symbols(), 1);
        assert!(lsm.get_symbol(id).is_some());
        assert_eq!(lsm.get_symbol(id).unwrap().name, "auto_var");
    }

    #[test]
    fn test_global_symbol_map() {
        let mut gsm = GlobalSymbolMap::new();
        gsm.add_symbol(HighSymbol::new(1, "global_x", 1));
        gsm.add_external(HighExternalSymbol::new(
            2,
            "malloc",
            Address::new(0),
            Address::new(0x1000),
        ));
        assert!(gsm.get_symbol(1).is_some());
        assert!(gsm.get_external(2).is_some());
        assert!(gsm.get_symbol(99).is_none());
    }

    #[test]
    fn test_high_function() {
        let mut hf = HighFunction::new(Address::new(0x401000));
        assert_eq!(hf.get_entry_point(), Address::new(0x401000));
        assert!(!hf.has_syntax_tree());
        assert!(hf.jump_tables.is_empty());

        hf.local_symbols
            .add_symbol(HighSymbol::new(0, "local_var", 1));
        assert_eq!(hf.num_local_symbols(), 1);

        let jt = JumpTable::new(Address::new(0x401100));
        hf.jump_tables.push(jt);
        assert_eq!(hf.jump_tables.len(), 1);
    }

    #[test]
    fn test_high_function_constants() {
        assert_eq!(HighFunction::DECOMPILER_TAG_MAP, "decompiler_tags");
        assert_eq!(HighFunction::OVERRIDE_NAMESPACE_NAME, "override");
    }

    #[test]
    fn test_high_function_display() {
        let hf = HighFunction::new(Address::new(0x401000));
        let s = format!("{}", hf);
        assert!(s.contains("401000"));
    }

    #[test]
    fn test_jump_table() {
        let mut jt = JumpTable::new(Address::new(0x401100));
        jt.add_target(Address::new(0x401200));
        jt.add_target(Address::new(0x401300));
        assert_eq!(jt.targets.len(), 2);
    }

    #[test]
    fn test_high_function_shell_symbol() {
        let hfs = HighFunctionShellSymbol::new(1, "thunk_func", 5);
        assert!(!hfs.is_external);
        assert_eq!(hfs.symbol.name, "thunk_func");
    }
}
