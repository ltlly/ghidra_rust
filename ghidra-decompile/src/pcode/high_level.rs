//! High-level variable and symbol types for the decompiler's function model.
//!
//! Ports Ghidra's `HighVariable`, `HighSymbol`, `HighLocal`, `HighParam`,
//! `HighConstant`, `HighGlobal`, `HighOther`, `HighFunction`,
//! `FunctionPrototype`, `LocalSymbolMap`, `GlobalSymbolMap`, and related types.
//!
//! These types represent the decompiler's high-level abstraction of variables,
//! symbols, and function prototypes that are built during decompilation and
//! used to produce the final C output.

use super::operation::Varnode;
use super::opcodes::OpCode;
use super::sequence::SequenceNumber;
use ghidra_core::addr::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// HighVariable - base class for high-level variables
// ============================================================================

/// A high-level variable (as in a high-level language like C/C++)
/// built out of Varnodes (low-level variables).
///
/// This is the Rust equivalent of Ghidra's `HighVariable` abstract class.
/// Subclasses are modeled via the [`HighVariableKind`] enum.
#[derive(Debug, Clone)]
pub struct HighVariable {
    /// The name of the variable.
    pub name: Option<String>,
    /// The data type of the variable (as a string representation).
    pub data_type: Option<String>,
    /// A representative varnode for this variable.
    pub representative: Option<Varnode>,
    /// All instances (varnodes) that this variable occupies at various points.
    pub instances: Vec<Varnode>,
    /// Offset (in bytes) into containing symbol. -1 indicates whole match.
    pub offset: i32,
    /// The kind of high-level variable (local, param, constant, global, other).
    pub kind: HighVariableKind,
    /// Optional symbol reference id.
    pub symbol_id: Option<u64>,
    /// The PC address where this variable comes into scope.
    pub pc_address: Option<Address>,
    /// The parameter slot (for HighParam only).
    pub slot: Option<usize>,
}

/// Discriminator for the different kinds of high-level variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HighVariableKind {
    /// A local variable within the function.
    Local,
    /// A function parameter.
    Param,
    /// A typed constant.
    Constant,
    /// A reference to a global variable.
    Global,
    /// Other (compiler infrastructure like stack pointer, saved registers).
    Other,
}

impl HighVariable {
    /// Create a new HighVariable with the given kind.
    pub fn new(kind: HighVariableKind) -> Self {
        Self {
            name: None,
            data_type: None,
            representative: None,
            instances: Vec::new(),
            offset: -1,
            kind,
            symbol_id: None,
            pc_address: None,
            slot: None,
        }
    }

    /// Create a HighVariable with full attributes.
    pub fn with_attributes(
        kind: HighVariableKind,
        name: Option<String>,
        data_type: Option<String>,
        representative: Varnode,
        instances: Vec<Varnode>,
        offset: i32,
    ) -> Self {
        Self {
            name,
            data_type,
            representative: Some(representative),
            instances,
            offset,
            kind,
            symbol_id: None,
            pc_address: None,
            slot: None,
        }
    }

    /// Get the name of the variable.
    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the size of the variable (from the representative varnode).
    pub fn get_size(&self) -> u32 {
        self.representative.as_ref().map_or(0, |v| v.size)
    }

    /// Get the data type string.
    pub fn get_data_type(&self) -> Option<&str> {
        self.data_type.as_deref()
    }

    /// Get the representative varnode.
    pub fn get_representative(&self) -> Option<&Varnode> {
        self.representative.as_ref()
    }

    /// Get all instances of this variable.
    pub fn get_instances(&self) -> &[Varnode] {
        &self.instances
    }

    /// Get the offset into the containing symbol.
    pub fn get_offset(&self) -> i32 {
        self.offset
    }

    /// Attach instances and a representative to this variable.
    pub fn attach_instances(&mut self, instances: Vec<Varnode>, rep: Varnode) {
        self.representative = Some(rep);
        if instances.is_empty() {
            if let Some(ref r) = self.representative {
                self.instances = vec![r.clone()];
            }
        } else {
            self.instances = instances;
        }
    }

    /// Returns true if this variable requires dynamic storage (e.g., unique space).
    pub fn requires_dynamic_storage(&self) -> bool {
        if let Some(ref rep) = self.representative {
            if rep.is_unique() {
                return true;
            }
        }
        false
    }

    /// Get the associated symbol id, if any.
    pub fn get_symbol_id(&self) -> Option<u64> {
        self.symbol_id
    }

    /// Get the PC address where this variable comes into scope.
    pub fn get_pc_address(&self) -> Option<Address> {
        self.pc_address
    }

    /// Get the parameter slot (only valid for HighParam).
    pub fn get_slot(&self) -> Option<usize> {
        self.slot
    }

    /// Returns true if this is a local variable.
    pub fn is_local(&self) -> bool {
        self.kind == HighVariableKind::Local
    }

    /// Returns true if this is a parameter.
    pub fn is_param(&self) -> bool {
        self.kind == HighVariableKind::Param
    }

    /// Returns true if this is a constant.
    pub fn is_constant(&self) -> bool {
        self.kind == HighVariableKind::Constant
    }

    /// Returns true if this is a global reference.
    pub fn is_global(&self) -> bool {
        self.kind == HighVariableKind::Global
    }

    /// Returns true if this is an "other" type (compiler infrastructure).
    pub fn is_other(&self) -> bool {
        self.kind == HighVariableKind::Other
    }
}

// ============================================================================
// HighSymbol
// ============================================================================

/// A symbol within the decompiler's model of a function.
///
/// Has a name, data type, and optional storage mappings.
#[derive(Debug, Clone)]
pub struct HighSymbol {
    /// Unique id of this symbol.
    pub id: u64,
    /// The name of the symbol.
    pub name: String,
    /// The data type (as string representation).
    pub data_type: Option<String>,
    /// Whether the name is locked (cannot be changed by the decompiler).
    pub name_locked: bool,
    /// Whether the type is locked.
    pub type_locked: bool,
    /// Whether this is a "this" pointer for a method call.
    pub is_this_pointer: bool,
    /// Whether this is a hidden return storage pointer.
    pub is_hidden_return: bool,
    /// Category: -1=none, 0=parameter, 1=equate.
    pub category: i32,
    /// Numbering within the category (slot for parameters).
    pub category_index: i32,
    /// Symbol entry mappings (storage locations).
    pub entries: Vec<SymbolEntry>,
    /// Associated high variable, if any.
    pub high_variable: Option<Box<HighVariable>>,
}

impl HighSymbol {
    /// ID base for dynamically created symbols.
    pub const ID_BASE: u64 = 0x4000_0000_0000_0000;

    /// Create a new HighSymbol.
    pub fn new(id: u64, name: String, data_type: Option<String>) -> Self {
        Self {
            id,
            name,
            data_type,
            name_locked: false,
            type_locked: false,
            is_this_pointer: false,
            is_hidden_return: false,
            category: -1,
            category_index: -1,
            entries: Vec::new(),
            high_variable: None,
        }
    }

    /// Get the symbol id.
    pub fn get_id(&self) -> u64 {
        self.id
    }

    /// Get the symbol name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the data type.
    pub fn get_data_type(&self) -> Option<&str> {
        self.data_type.as_deref()
    }

    /// Set the category and category index.
    pub fn set_category(&mut self, cat: i32, index: i32) {
        self.category = cat;
        self.category_index = index;
    }

    /// Add a symbol entry mapping.
    pub fn add_entry(&mut self, entry: SymbolEntry) {
        self.entries.push(entry);
    }

    /// Get the first (primary) entry, if any.
    pub fn get_first_entry(&self) -> Option<&SymbolEntry> {
        self.entries.first()
    }

    /// Set the name lock.
    pub fn set_name_lock(&mut self, locked: bool) {
        self.name_locked = locked;
    }

    /// Set the type lock.
    pub fn set_type_lock(&mut self, locked: bool) {
        self.type_locked = locked;
    }

    /// Returns true if the name is locked.
    pub fn is_name_locked(&self) -> bool {
        self.name_locked
    }

    /// Returns true if the type is locked.
    pub fn is_type_locked(&self) -> bool {
        self.type_locked
    }

    /// Returns true if this symbol is a parameter (category == 0).
    pub fn is_parameter(&self) -> bool {
        self.category == 0
    }

    /// Get the category index (slot for parameters).
    pub fn get_category_index(&self) -> i32 {
        self.category_index
    }

    /// Get the size from the first entry.
    pub fn get_size(&self) -> u32 {
        self.entries.first().map_or(0, |e| e.size)
    }

    /// Get the PC address from the first entry.
    pub fn get_pc_address(&self) -> Option<Address> {
        self.entries.first().and_then(|e| e.pc_address)
    }

    /// Associate a high variable with this symbol.
    pub fn set_high_variable(&mut self, high: HighVariable) {
        if let Some(ref existing) = self.high_variable {
            if existing.get_size() >= high.get_size() {
                return;
            }
        }
        self.high_variable = Some(Box::new(high));
    }

    /// Get the associated high variable.
    pub fn get_high_variable(&self) -> Option<&HighVariable> {
        self.high_variable.as_deref()
    }

    /// Returns true if this is the "this" pointer.
    pub fn is_this_pointer(&self) -> bool {
        self.is_this_pointer
    }

    /// Returns true if this is a hidden return parameter.
    pub fn is_hidden_return(&self) -> bool {
        self.is_hidden_return
    }

    /// Returns true if this symbol is isolated (cannot be merged).
    pub fn is_isolated(&self) -> bool {
        self.type_locked
    }

    /// Returns true if this symbol is in the global scope.
    pub fn is_global(&self) -> bool {
        false // Default: not global; override in subclasses
    }
}

// ============================================================================
// EquateSymbol
// ============================================================================

/// Display format constants for equate symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EquateFormat {
    /// Default format.
    Default = 0,
    /// Hexadecimal.
    Hex = 1,
    /// Decimal.
    Dec = 2,
    /// Octal.
    Oct = 3,
    /// Binary.
    Bin = 4,
    /// Character.
    Char = 5,
    /// Float.
    Float = 6,
    /// Double.
    Double = 7,
}

impl EquateFormat {
    /// Get the format string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            EquateFormat::Default => "",
            EquateFormat::Hex => "hex",
            EquateFormat::Dec => "dec",
            EquateFormat::Oct => "oct",
            EquateFormat::Bin => "bin",
            EquateFormat::Char => "char",
            EquateFormat::Float => "float",
            EquateFormat::Double => "double",
        }
    }

    /// Parse a format string.
    pub fn from_str(s: &str) -> Self {
        match s {
            "hex" => EquateFormat::Hex,
            "dec" => EquateFormat::Dec,
            "oct" => EquateFormat::Oct,
            "bin" => EquateFormat::Bin,
            "char" => EquateFormat::Char,
            "float" => EquateFormat::Float,
            "double" => EquateFormat::Double,
            _ => EquateFormat::Default,
        }
    }

    /// Determine the format from an equate name and value.
    pub fn detect_from_name(name: &str) -> Self {
        let chars: Vec<char> = name.chars().collect();
        if chars.is_empty() {
            return EquateFormat::Default;
        }

        let mut pos = 0;
        let first = if chars[0] == '-' {
            if chars.len() <= 1 {
                return EquateFormat::Default;
            }
            pos = 1;
            chars[1]
        } else {
            chars[0]
        };

        match first {
            '\'' | '"' => return EquateFormat::Char,
            '0' => {
                if chars.len() > pos + 1 && chars[pos + 1] == 'x' {
                    return EquateFormat::Hex;
                }
            }
            'A' | 'B' | 'C' | 'D' | 'E' | 'F' => {
                if chars.len() >= 3 && chars[2] == 'h' {
                    return EquateFormat::Char;
                }
                return EquateFormat::Default;
            }
            _ => {}
        }

        if !first.is_ascii_digit() {
            return EquateFormat::Default;
        }

        match chars.last() {
            Some('b') => EquateFormat::Bin,
            Some('o') => EquateFormat::Oct,
            Some('\'') | Some('"') | Some('h') => EquateFormat::Char,
            _ => EquateFormat::Dec,
        }
    }
}

/// An equate symbol: a named constant within the decompiler's model.
#[derive(Debug, Clone)]
pub struct EquateSymbol {
    /// The base symbol data.
    pub base: HighSymbol,
    /// The value of the equate.
    pub value: u64,
    /// The format conversion type.
    pub convert: EquateFormat,
}

impl EquateSymbol {
    /// Create a new equate symbol.
    pub fn new(id: u64, name: String, value: u64, convert: EquateFormat) -> Self {
        let mut base = HighSymbol::new(id, name, None);
        base.category = 1;
        Self {
            base,
            value,
            convert,
        }
    }

    /// Get the value.
    pub fn get_value(&self) -> u64 {
        self.value
    }

    /// Get the format.
    pub fn get_convert(&self) -> EquateFormat {
        self.convert
    }
}

// ============================================================================
// SymbolEntry - storage mapping for a HighSymbol
// ============================================================================

/// A mapping from a HighSymbol to the storage that holds the symbol's value.
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// The address of the first varnode in the storage.
    pub address: Address,
    /// Size in bytes.
    pub size: u32,
    /// The PC address where this entry applies (None = entire function).
    pub pc_address: Option<Address>,
    /// The storage kind.
    pub kind: SymbolEntryKind,
    /// Dynamic hash value (for hash-based entries).
    pub hash: Option<u64>,
    /// Mutability: 0=normal, 1=volatile, 2=constant.
    pub mutability: u8,
}

/// Kind of symbol entry mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolEntryKind {
    /// Mapped to a fixed address/register.
    Mapped,
    /// Dynamically hashed storage.
    Dynamic,
    /// Mapped data entry (for code symbols).
    MappedData,
}

impl SymbolEntry {
    /// Create a mapped entry.
    pub fn mapped(address: Address, size: u32, pc_address: Option<Address>) -> Self {
        Self {
            address,
            size,
            pc_address,
            kind: SymbolEntryKind::Mapped,
            hash: None,
            mutability: 0,
        }
    }

    /// Create a dynamic entry.
    pub fn dynamic(address: Address, pc_address: Option<Address>, hash: u64) -> Self {
        Self {
            address,
            size: 0,
            pc_address,
            kind: SymbolEntryKind::Dynamic,
            hash: Some(hash),
            mutability: 0,
        }
    }

    /// Get the storage address.
    pub fn get_address(&self) -> Address {
        self.address
    }

    /// Get the storage size.
    pub fn get_size(&self) -> u32 {
        self.size
    }

    /// Get the PC address where this mapping applies.
    pub fn get_pc_address(&self) -> Option<Address> {
        self.pc_address
    }

    /// Get the hash value (for dynamic entries).
    pub fn get_hash(&self) -> Option<u64> {
        self.hash
    }

    /// Get the mutability.
    pub fn get_mutability(&self) -> u8 {
        self.mutability
    }

    /// Returns true if this is a hash-based entry.
    pub fn is_hash_storage(&self) -> bool {
        self.kind == SymbolEntryKind::Dynamic
    }
}

// ============================================================================
// LocalSymbolMap
// ============================================================================

/// A container for local symbols within a function.
///
/// Contains HighSymbol objects for any symbol within the scope of the
/// function, including parameters.
#[derive(Debug, Clone)]
pub struct LocalSymbolMap {
    /// Address space name for local variables (usually "stack").
    pub local_space: Option<String>,
    /// All symbols mapped by id.
    pub symbol_map: HashMap<u64, HighSymbol>,
    /// Parameter symbols, ordered by slot.
    pub param_symbols: Vec<u64>,
    /// Next available symbol id.
    pub next_symbol_id: u64,
}

impl LocalSymbolMap {
    /// Create a new empty local symbol map.
    pub fn new(local_space: Option<String>) -> Self {
        Self {
            local_space,
            symbol_map: HashMap::new(),
            param_symbols: Vec::new(),
            next_symbol_id: 0,
        }
    }

    /// Assign the next unique symbol id.
    pub fn next_id(&mut self) -> u64 {
        let id = HighSymbol::ID_BASE + self.next_symbol_id;
        self.next_symbol_id += 1;
        id
    }

    /// Insert a symbol into the map.
    pub fn insert_symbol(&mut self, sym: HighSymbol) {
        let id = sym.get_id();
        if (id >> 56) == (HighSymbol::ID_BASE >> 56) {
            let val = id & 0x7FFF_FFFF;
            if val > self.next_symbol_id {
                self.next_symbol_id = val;
            }
        }
        if sym.is_parameter() {
            self.param_symbols.push(id);
        }
        self.symbol_map.insert(id, sym);
    }

    /// Get a symbol by id.
    pub fn get_symbol(&self, id: u64) -> Option<&HighSymbol> {
        self.symbol_map.get(&id)
    }

    /// Get a mutable symbol by id.
    pub fn get_symbol_mut(&mut self, id: u64) -> Option<&mut HighSymbol> {
        self.symbol_map.get_mut(&id)
    }

    /// Get all symbols.
    pub fn get_symbols(&self) -> impl Iterator<Item = &HighSymbol> {
        self.symbol_map.values()
    }

    /// Get the number of parameter symbols.
    pub fn get_num_params(&self) -> usize {
        self.param_symbols.len()
    }

    /// Get the i-th parameter symbol.
    pub fn get_param_symbol(&self, i: usize) -> Option<&HighSymbol> {
        self.param_symbols
            .get(i)
            .and_then(|id| self.symbol_map.get(id))
    }

    /// Create a new mapped symbol and insert it.
    pub fn new_mapped_symbol(
        &mut self,
        id: u64,
        name: String,
        data_type: Option<String>,
        address: Address,
        size: u32,
        pc_address: Option<Address>,
        slot: Option<i32>,
    ) -> HighSymbol {
        let real_id = if id == 0 { self.next_id() } else { id };
        let mut sym = HighSymbol::new(real_id, name, data_type);
        if let Some(s) = slot {
            if s >= 0 {
                sym.set_category(0, s);
            }
        }
        let entry = SymbolEntry::mapped(address, size, pc_address);
        sym.add_entry(entry);
        let result = sym.clone();
        self.insert_symbol(sym);
        result
    }

    /// Build a name-to-symbol map.
    pub fn get_name_to_symbol_map(&self) -> HashMap<String, &HighSymbol> {
        let mut map = HashMap::new();
        for sym in self.symbol_map.values() {
            map.insert(sym.get_name().to_string(), sym);
        }
        map
    }

    /// Clear all symbols.
    pub fn clear(&mut self) {
        self.symbol_map.clear();
        self.param_symbols.clear();
    }
}

// ============================================================================
// GlobalSymbolMap
// ============================================================================

/// A container for global symbols accessed by a function.
#[derive(Debug, Clone)]
pub struct GlobalSymbolMap {
    /// Symbols mapped by address.
    pub addr_mapped: HashMap<u64, HighSymbol>,
    /// Symbols mapped by id.
    pub symbol_map: HashMap<u64, HighSymbol>,
    /// Next available symbol id.
    pub next_symbol_id: u64,
}

impl GlobalSymbolMap {
    /// Create a new empty global symbol map.
    pub fn new() -> Self {
        Self {
            addr_mapped: HashMap::new(),
            symbol_map: HashMap::new(),
            next_symbol_id: 0,
        }
    }

    /// Insert a symbol into the map.
    pub fn insert_symbol(&mut self, sym: HighSymbol, addr: Address) {
        let id = sym.get_id();
        if (id >> 56) == (HighSymbol::ID_BASE >> 56) {
            let val = id & 0x7FFF_FFFF;
            if val > self.next_symbol_id {
                self.next_symbol_id = val;
            }
        }
        self.addr_mapped.insert(addr.offset, sym.clone());
        self.symbol_map.insert(id, sym);
    }

    /// Get a symbol by id.
    pub fn get_symbol(&self, id: u64) -> Option<&HighSymbol> {
        self.symbol_map.get(&id)
    }

    /// Get a symbol by address.
    pub fn get_symbol_by_addr(&self, addr: Address) -> Option<&HighSymbol> {
        self.addr_mapped.get(&addr.offset)
    }

    /// Create a new symbol and insert it.
    pub fn new_symbol(
        &mut self,
        id: u64,
        addr: Address,
        name: String,
        data_type: Option<String>,
        size: u32,
    ) -> HighSymbol {
        let sym = HighSymbol::new(id, name, data_type);
        let result = sym.clone();
        self.insert_symbol(sym, addr);
        result
    }

    /// Get all symbols.
    pub fn get_symbols(&self) -> impl Iterator<Item = &HighSymbol> {
        self.symbol_map.values()
    }
}

impl Default for GlobalSymbolMap {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FunctionPrototype
// ============================================================================

/// High-level prototype of a function, describing inputs and outputs.
#[derive(Debug, Clone)]
pub struct FunctionPrototype {
    /// Name of the calling convention model.
    pub model_name: Option<String>,
    /// Name of pcode inject associated with this prototype.
    pub inject_name: Option<String>,
    /// Return type (as string).
    pub return_type: Option<String>,
    /// Return storage address.
    pub return_storage: Option<Address>,
    /// Parameter definitions.
    pub params: Vec<ParameterDef>,
    /// Is the prototype model locked.
    pub model_locked: bool,
    /// Is the input prototype locked (void input).
    pub void_input_locked: bool,
    /// Is the return type locked.
    pub output_locked: bool,
    /// Does this function accept variable arguments.
    pub is_vararg: bool,
    /// Extra bytes popped off by this function's return.
    pub extra_pop: i32,
    /// Function should be inlined.
    pub is_inline: bool,
    /// Calls to this function do not return.
    pub no_return: bool,
    /// Uses custom storage for parameters.
    pub custom: bool,
    /// Has a "this" pointer.
    pub has_this: bool,
    /// Is an object constructor.
    pub is_constructor: bool,
    /// Is an object destructor.
    pub is_destructor: bool,
}

/// A parameter definition within a function prototype.
#[derive(Debug, Clone)]
pub struct ParameterDef {
    /// Parameter name.
    pub name: Option<String>,
    /// Data type (as string).
    pub data_type: Option<String>,
    /// Storage address.
    pub address: Option<Address>,
    /// Size in bytes.
    pub size: u32,
    /// Whether the name is locked.
    pub name_locked: bool,
    /// Whether the type is locked.
    pub type_locked: bool,
}

/// Special extrapop value indicating unknown stack cleanup.
pub const UNKNOWN_EXTRAPOP: i32 = -999;

impl FunctionPrototype {
    /// Create a new empty function prototype.
    pub fn new() -> Self {
        Self {
            model_name: None,
            inject_name: None,
            return_type: None,
            return_storage: None,
            params: Vec::new(),
            model_locked: false,
            void_input_locked: false,
            output_locked: false,
            is_vararg: false,
            extra_pop: UNKNOWN_EXTRAPOP,
            is_inline: false,
            no_return: false,
            custom: false,
            has_this: false,
            is_constructor: false,
            is_destructor: false,
        }
    }

    /// Get the number of parameters.
    pub fn get_num_params(&self) -> usize {
        self.params.len()
    }

    /// Get the i-th parameter.
    pub fn get_param(&self, i: usize) -> Option<&ParameterDef> {
        self.params.get(i)
    }

    /// Get the return type.
    pub fn get_return_type(&self) -> Option<&str> {
        self.return_type.as_deref()
    }

    /// Get the return storage address.
    pub fn get_return_storage(&self) -> Option<Address> {
        self.return_storage
    }

    /// Get the extra pop amount.
    pub fn get_extra_pop(&self) -> i32 {
        self.extra_pop
    }

    /// Returns true if this function accepts varargs.
    pub fn is_vararg(&self) -> bool {
        self.is_vararg
    }

    /// Returns true if this function should be inlined.
    pub fn is_inline(&self) -> bool {
        self.is_inline
    }

    /// Returns true if this function does not return.
    pub fn has_no_return(&self) -> bool {
        self.no_return
    }

    /// Returns true if this function has a "this" pointer.
    pub fn has_this_pointer(&self) -> bool {
        self.has_this
    }

    /// Get the calling convention model name.
    pub fn get_model_name(&self) -> Option<&str> {
        self.model_name.as_deref()
    }
}

impl Default for FunctionPrototype {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// HighFunction
// ============================================================================

/// High-level abstraction associated with a function.
///
/// Based on information the decompiler has produced after working on a function.
/// Contains the function prototype, local and global symbol maps, jump tables,
/// and all high-level variables.
#[derive(Debug, Clone)]
pub struct HighFunction {
    /// Entry point address.
    pub entry_point: Address,
    /// Function name.
    pub name: String,
    /// The function prototype.
    pub prototype: FunctionPrototype,
    /// Local symbols.
    pub local_symbols: LocalSymbolMap,
    /// Global symbols.
    pub global_symbols: GlobalSymbolMap,
    /// Jump tables found for this function.
    pub jump_tables: Vec<JumpTable>,
    /// All high-level variables, keyed by representative varnode offset.
    pub high_variables: Vec<HighVariable>,
    /// The data type manager name.
    pub data_type_manager_name: Option<String>,
    /// Override namespace name.
    pub override_namespace: Option<String>,
    /// Compiler spec name.
    pub compiler_spec: Option<String>,
    /// Language id.
    pub language_id: Option<String>,
}

impl HighFunction {
    /// Decompiler tag map name constant.
    pub const DECOMPILER_TAG_MAP: &'static str = "decompiler_tags";
    /// Override namespace name constant.
    pub const OVERRIDE_NAMESPACE_NAME: &'static str = "override";

    /// Create a new HighFunction.
    pub fn new(entry_point: Address, name: String) -> Self {
        Self {
            entry_point,
            name,
            prototype: FunctionPrototype::new(),
            local_symbols: LocalSymbolMap::new(None),
            global_symbols: GlobalSymbolMap::new(),
            jump_tables: Vec::new(),
            high_variables: Vec::new(),
            data_type_manager_name: None,
            override_namespace: None,
            compiler_spec: None,
            language_id: None,
        }
    }

    /// Get the entry point.
    pub fn get_entry_point(&self) -> Address {
        self.entry_point
    }

    /// Get the function name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the function prototype.
    pub fn get_prototype(&self) -> &FunctionPrototype {
        &self.prototype
    }

    /// Get the local symbol map.
    pub fn get_local_symbol_map(&self) -> &LocalSymbolMap {
        &self.local_symbols
    }

    /// Get the global symbol map.
    pub fn get_global_symbol_map(&self) -> &GlobalSymbolMap {
        &self.global_symbols
    }

    /// Get jump tables.
    pub fn get_jump_tables(&self) -> &[JumpTable] {
        &self.jump_tables
    }

    /// Find a symbol by address and PC address.
    pub fn find_symbol(&self, addr: Address, pc: Option<Address>) -> Option<&HighSymbol> {
        // Search local symbols first
        for sym in self.local_symbols.get_symbols() {
            if let Some(entry) = sym.get_first_entry() {
                if entry.get_address() == addr {
                    return Some(sym);
                }
            }
        }
        // Then global
        self.global_symbols.get_symbol_by_addr(addr)
    }

    /// Get a symbol by id.
    pub fn get_symbol(&self, id: u64) -> Option<&HighSymbol> {
        self.local_symbols
            .get_symbol(id)
            .or_else(|| self.global_symbols.get_symbol(id))
    }

    /// Get the PC address for a representative varnode.
    pub fn get_pc_address(&self, rep: &Varnode) -> Option<Address> {
        // Simplified: return entry point as fallback
        Some(self.entry_point)
    }

    /// Add a high-level variable.
    pub fn add_high_variable(&mut self, var: HighVariable) {
        self.high_variables.push(var);
    }
}

// ============================================================================
// JumpTable
// ============================================================================

/// A jump table definition found during decompilation.
///
/// Represents a switch/jump table with case addresses.
#[derive(Debug, Clone)]
pub struct JumpTable {
    /// Address of the switch instruction (CALLIND/BRANCHIND).
    pub op_address: Address,
    /// The case destination addresses.
    pub address_table: Vec<Address>,
    /// Optional label values for each case.
    pub label_table: Vec<Option<i64>>,
    /// Display format for the cases.
    pub display_format: EquateFormat,
    /// Load table entries (for table-driven jumps).
    pub load_tables: Vec<LoadTable>,
    /// Whether this is an override.
    pub is_override: bool,
}

/// A load table entry for indirect jumps through memory.
#[derive(Debug, Clone)]
pub struct LoadTable {
    /// The address of the table in memory.
    pub table_address: Address,
    /// The space id.
    pub space_id: u32,
    /// The size of each entry in bytes.
    pub entry_size: u32,
    /// The number of entries.
    pub num_entries: u32,
}

impl JumpTable {
    /// Create a new jump table.
    pub fn new(op_address: Address, address_table: Vec<Address>) -> Self {
        let len = address_table.len();
        Self {
            op_address,
            address_table,
            label_table: vec![None; len],
            display_format: EquateFormat::Default,
            load_tables: Vec::new(),
            is_override: false,
        }
    }

    /// Create an empty jump table.
    pub fn empty() -> Self {
        Self {
            op_address: Address::NULL,
            address_table: Vec::new(),
            label_table: Vec::new(),
            display_format: EquateFormat::Default,
            load_tables: Vec::new(),
            is_override: false,
        }
    }

    /// Returns true if the jump table is empty.
    pub fn is_empty(&self) -> bool {
        self.address_table.is_empty()
    }

    /// Get the switch address.
    pub fn get_switch_address(&self) -> Address {
        self.op_address
    }

    /// Get the case addresses.
    pub fn get_cases(&self) -> &[Address] {
        &self.address_table
    }

    /// Get the label values.
    pub fn get_label_values(&self) -> &[Option<i64>] {
        &self.label_table
    }

    /// Get the load tables.
    pub fn get_load_tables(&self) -> &[LoadTable] {
        &self.load_tables
    }

    /// Get the display format.
    pub fn get_display_format(&self) -> EquateFormat {
        self.display_format
    }
}

// ============================================================================
// DynamicHash
// ============================================================================

/// Utilities for computing dynamic hashes used to identify varnodes.
pub struct DynamicHash;

impl DynamicHash {
    /// Compute a hash value for a constant varnode used at a specific address.
    pub fn calc_constant_hash(address: u64, value: u64) -> Vec<u64> {
        // Simplified: return a basic hash
        vec![Self::make_hash(address, value, 0)]
    }

    /// Create a hash value from components.
    pub fn make_hash(address: u64, value: u64, method: u32) -> u64 {
        let mut h = address;
        h = h.wrapping_mul(31).wrapping_add(value);
        h = h.wrapping_mul(31).wrapping_add(method as u64);
        h
    }

    /// Get the method field from a hash value.
    pub fn get_method_from_hash(hash: u64) -> u32 {
        // Method is stored in bits 4-7 of the hash
        ((hash >> 4) & 0xF) as u32
    }
}

// ============================================================================
// HighExternalSymbol
// ============================================================================

/// A symbol that references an external function or data.
#[derive(Debug, Clone)]
pub struct HighExternalSymbol {
    /// Base symbol.
    pub base: HighSymbol,
    /// The address of the external symbol.
    pub external_address: Address,
}

impl HighExternalSymbol {
    /// Create a new external symbol.
    pub fn new(id: u64, name: String, addr: Address) -> Self {
        Self {
            base: HighSymbol::new(id, name, None),
            external_address: addr,
        }
    }
}

// ============================================================================
// HighFunctionSymbol
// ============================================================================

/// A symbol representing a function.
#[derive(Debug, Clone)]
pub struct HighFunctionSymbol {
    /// Base symbol.
    pub base: HighSymbol,
    /// Entry point of the function.
    pub entry_point: Address,
}

impl HighFunctionSymbol {
    /// Create a new function symbol.
    pub fn new(id: u64, name: String, entry_point: Address) -> Self {
        Self {
            base: HighSymbol::new(id, name, None),
            entry_point,
        }
    }
}

// ============================================================================
// HighFunctionShellSymbol
// ============================================================================

/// A symbol representing a function shell (minimal function reference).
#[derive(Debug, Clone)]
pub struct HighFunctionShellSymbol {
    /// Base symbol.
    pub base: HighSymbol,
    /// Entry point.
    pub entry_point: Address,
}

impl HighFunctionShellSymbol {
    /// Create a new function shell symbol.
    pub fn new(id: u64, name: String, entry_point: Address) -> Self {
        Self {
            base: HighSymbol::new(id, name, None),
            entry_point,
        }
    }
}

// ============================================================================
// HighCodeSymbol
// ============================================================================

/// A symbol representing a code label or data object.
#[derive(Debug, Clone)]
pub struct HighCodeSymbol {
    /// Base symbol.
    pub base: HighSymbol,
    /// Address of the code/data.
    pub code_address: Address,
    /// Size in bytes.
    pub size: u32,
}

impl HighCodeSymbol {
    /// Create a new code symbol.
    pub fn new(id: u64, name: String, addr: Address, size: u32) -> Self {
        Self {
            base: HighSymbol::new(id, name, None),
            code_address: addr,
            size,
        }
    }

    /// Returns true if this is a global symbol.
    pub fn is_global(&self) -> bool {
        true
    }
}

// ============================================================================
// HighLabelSymbol
// ============================================================================

/// A label symbol within a function.
#[derive(Debug, Clone)]
pub struct HighLabelSymbol {
    /// Base symbol.
    pub base: HighSymbol,
    /// Address of the label.
    pub label_address: Address,
}

impl HighLabelSymbol {
    /// Create a new label symbol.
    pub fn new(id: u64, name: String, addr: Address) -> Self {
        Self {
            base: HighSymbol::new(id, name, None),
            label_address: addr,
        }
    }
}

// ============================================================================
// UnionFacetSymbol
// ============================================================================

/// A symbol used for union facets during decompilation.
#[derive(Debug, Clone)]
pub struct UnionFacetSymbol {
    /// Base symbol.
    pub base: HighSymbol,
}

impl UnionFacetSymbol {
    /// Create a new union facet symbol.
    pub fn new(id: u64, name: String) -> Self {
        Self {
            base: HighSymbol::new(id, name, None),
        }
    }

    /// Check if a data type is a union type.
    pub fn is_union_type(data_type: &str) -> bool {
        data_type.starts_with("union") || data_type.starts_with("Union")
    }
}

// ============================================================================
// DataTypeSymbol
// ============================================================================

/// A data type paired with an address, used for prototype overrides.
#[derive(Debug, Clone)]
pub struct DataTypeSymbol {
    /// The address.
    pub address: Address,
    /// The data type (as string).
    pub data_type: Option<String>,
    /// The symbol name.
    pub name: Option<String>,
}

impl DataTypeSymbol {
    /// Create a new data type symbol.
    pub fn new(address: Address, data_type: Option<String>, name: Option<String>) -> Self {
        Self {
            address,
            data_type,
            name,
        }
    }

    /// Get the address.
    pub fn get_address(&self) -> Address {
        self.address
    }

    /// Get the data type.
    pub fn get_data_type(&self) -> Option<&str> {
        self.data_type.as_deref()
    }
}

// ============================================================================
// HighParamID
// ============================================================================

/// Metadata for parameter identification during decompilation.
#[derive(Debug, Clone)]
pub struct HighParamID {
    /// The parameter slot.
    pub slot: usize,
    /// The data type.
    pub data_type: Option<String>,
    /// The storage address.
    pub address: Address,
    /// Size in bytes.
    pub size: u32,
}

impl HighParamID {
    /// Create a new HighParamID.
    pub fn new(slot: usize, address: Address, size: u32) -> Self {
        Self {
            slot,
            data_type: None,
            address,
            size,
        }
    }
}

// ============================================================================
// ParamMeasure
// ============================================================================

/// How parameters are measured/evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParamMeasure {
    /// Parameter is measured by its final evaluation.
    Final,
    /// Parameter is evaluated at the point of the call.
    Evaluation,
}

// ============================================================================
// HighFunctionDBUtil
// ============================================================================

/// Utility functions for the HighFunction database interaction.
pub struct HighFunctionDBUtil;

impl HighFunctionDBUtil {
    /// Read a prototype override from a symbol.
    pub fn read_override(name: &str, data_type: Option<String>, addr: Address) -> Option<DataTypeSymbol> {
        Some(DataTypeSymbol::new(addr, data_type, Some(name.to_string())))
    }

    /// Get the first vararg index from a program at a given address.
    pub fn get_first_var_arg(program_name: &str, addr: Address) -> i32 {
        // Simplified: return -1 (no varargs)
        -1
    }

    /// Get the address referenced by a spacebase operation.
    pub fn get_spacebase_reference_address(
        addr_factory_name: &str,
        op: Option<&PcodeOpRef>,
    ) -> Option<Address> {
        op.and_then(|o| {
            if let Some(ref inp) = o.inputs.first() {
                Some(Address::new(inp.offset))
            } else {
                None
            }
        })
    }
}

/// A lightweight reference to a PcodeOp for use in HighFunction utilities.
#[derive(Debug, Clone)]
pub struct PcodeOpRef {
    /// Opcode.
    pub opcode: OpCode,
    /// Input varnodes.
    pub inputs: Vec<Varnode>,
    /// Output varnode.
    pub output: Option<Varnode>,
}

impl PcodeOpRef {
    /// Create a new PcodeOpRef.
    pub fn new(opcode: OpCode, inputs: Vec<Varnode>, output: Option<Varnode>) -> Self {
        Self {
            opcode,
            inputs,
            output,
        }
    }

    /// Get the number of inputs.
    pub fn get_num_inputs(&self) -> usize {
        self.inputs.len()
    }

    /// Get an input at index.
    pub fn get_input(&self, i: usize) -> Option<&Varnode> {
        self.inputs.get(i)
    }

    /// Get the output.
    pub fn get_output(&self) -> Option<&Varnode> {
        self.output.as_ref()
    }
}

// ============================================================================
// PcodeException
// ============================================================================

/// Error type for P-code related errors.
#[derive(Debug, Clone)]
pub struct PcodeException {
    /// Error message.
    pub message: String,
}

impl PcodeException {
    /// Create a new PcodeException.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PcodeException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PcodeException: {}", self.message)
    }
}

impl std::error::Error for PcodeException {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_variable_new() {
        let hv = HighVariable::new(HighVariableKind::Local);
        assert!(hv.is_local());
        assert!(!hv.is_param());
        assert_eq!(hv.get_size(), 0);
    }

    #[test]
    fn test_high_variable_with_attributes() {
        let rep = Varnode::ram(0x1000, 4);
        let hv = HighVariable::with_attributes(
            HighVariableKind::Param,
            Some("x".to_string()),
            Some("int".to_string()),
            rep.clone(),
            vec![rep.clone()],
            -1,
        );
        assert!(hv.is_param());
        assert_eq!(hv.get_name(), Some("x"));
        assert_eq!(hv.get_size(), 4);
    }

    #[test]
    fn test_high_symbol_new() {
        let sym = HighSymbol::new(1, "test".to_string(), Some("int".to_string()));
        assert_eq!(sym.get_id(), 1);
        assert_eq!(sym.get_name(), "test");
        assert!(!sym.is_parameter());
    }

    #[test]
    fn test_high_symbol_parameter() {
        let mut sym = HighSymbol::new(2, "param1".to_string(), Some("int".to_string()));
        sym.set_category(0, 0);
        assert!(sym.is_parameter());
        assert_eq!(sym.get_category_index(), 0);
    }

    #[test]
    fn test_equate_format() {
        assert_eq!(EquateFormat::detect_from_name("0xFF"), EquateFormat::Hex);
        assert_eq!(EquateFormat::detect_from_name("42"), EquateFormat::Dec);
        assert_eq!(EquateFormat::detect_from_name("101b"), EquateFormat::Bin);
        assert_eq!(EquateFormat::detect_from_name("77o"), EquateFormat::Oct);
        assert_eq!(EquateFormat::detect_from_name("'a'"), EquateFormat::Char);
    }

    #[test]
    fn test_equate_format_roundtrip() {
        for fmt in &[
            EquateFormat::Hex,
            EquateFormat::Dec,
            EquateFormat::Oct,
            EquateFormat::Bin,
            EquateFormat::Char,
            EquateFormat::Float,
            EquateFormat::Double,
        ] {
            let s = fmt.as_str();
            let parsed = EquateFormat::from_str(s);
            assert_eq!(*fmt, parsed);
        }
    }

    #[test]
    fn test_local_symbol_map() {
        let mut map = LocalSymbolMap::new(Some("stack".to_string()));
        let id = map.next_id();
        let sym = map.new_mapped_symbol(
            id,
            "local_var".to_string(),
            Some("int".to_string()),
            Address::new(0x1000),
            4,
            None,
            None,
        );
        assert!(map.get_symbol(sym.get_id()).is_some());
    }

    #[test]
    fn test_local_symbol_map_params() {
        let mut map = LocalSymbolMap::new(None);
        let sym = map.new_mapped_symbol(
            0,
            "param1".to_string(),
            Some("int".to_string()),
            Address::new(0),
            4,
            Some(Address::new(0x1000)),
            Some(0),
        );
        assert_eq!(map.get_num_params(), 1);
        assert!(map.get_param_symbol(0).is_some());
    }

    #[test]
    fn test_global_symbol_map() {
        let mut map = GlobalSymbolMap::new();
        let addr = Address::new(0x2000);
        let sym = map.new_symbol(100, addr, "global_var".to_string(), Some("int".to_string()), 4);
        assert!(map.get_symbol(100).is_some());
        assert!(map.get_symbol_by_addr(addr).is_some());
    }

    #[test]
    fn test_function_prototype() {
        let mut proto = FunctionPrototype::new();
        proto.return_type = Some("int".to_string());
        proto.model_name = Some("cdecl".to_string());
        proto.is_vararg = true;
        proto.params.push(ParameterDef {
            name: Some("x".to_string()),
            data_type: Some("int".to_string()),
            address: Some(Address::new(0)),
            size: 4,
            name_locked: true,
            type_locked: true,
        });
        assert_eq!(proto.get_num_params(), 1);
        assert!(proto.is_vararg());
    }

    #[test]
    fn test_high_function() {
        let hf = HighFunction::new(Address::new(0x1000), "main".to_string());
        assert_eq!(hf.get_entry_point(), Address::new(0x1000));
        assert_eq!(hf.get_name(), "main");
    }

    #[test]
    fn test_jump_table() {
        let jt = JumpTable::new(
            Address::new(0x1000),
            vec![Address::new(0x2000), Address::new(0x2004)],
        );
        assert!(!jt.is_empty());
        assert_eq!(jt.get_cases().len(), 2);
    }

    #[test]
    fn test_jump_table_empty() {
        let jt = JumpTable::empty();
        assert!(jt.is_empty());
    }

    #[test]
    fn test_symbol_entry() {
        let entry = SymbolEntry::mapped(Address::new(0x1000), 4, None);
        assert_eq!(entry.get_size(), 4);
        assert!(!entry.is_hash_storage());

        let dyn_entry = SymbolEntry::dynamic(Address::new(0x2000), Some(Address::new(0x3000)), 42);
        assert!(dyn_entry.is_hash_storage());
        assert_eq!(dyn_entry.get_hash(), Some(42));
    }

    #[test]
    fn test_dynamic_hash() {
        let hash = DynamicHash::make_hash(0x1000, 42, 0);
        assert_ne!(hash, 0);
        let hashes = DynamicHash::calc_constant_hash(0x1000, 42);
        assert!(!hashes.is_empty());
    }

    #[test]
    fn test_pcode_exception() {
        let err = PcodeException::new("test error");
        assert!(err.message.contains("test error"));
        assert!(format!("{}", err).contains("test error"));
    }

    #[test]
    fn test_high_code_symbol() {
        let sym = HighCodeSymbol::new(100, "data".to_string(), Address::new(0x2000), 16);
        assert!(sym.is_global());
        assert_eq!(sym.size, 16);
    }

    #[test]
    fn test_union_facet_symbol() {
        assert!(UnionFacetSymbol::is_union_type("union my_union"));
        assert!(!UnionFacetSymbol::is_union_type("struct my_struct"));
    }

    #[test]
    fn test_param_measure() {
        assert_ne!(ParamMeasure::Final, ParamMeasure::Evaluation);
    }

    #[test]
    fn test_pcode_op_ref() {
        let op = PcodeOpRef::new(
            OpCode::INT_ADD,
            vec![Varnode::ram(0, 4), Varnode::constant(1, 4)],
            Some(Varnode::unique(0, 4)),
        );
        assert_eq!(op.get_num_inputs(), 2);
        assert!(op.get_output().is_some());
    }
}
