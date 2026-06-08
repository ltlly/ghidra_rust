//! Core program type — the central model for a Ghidra program.
//!
//! A [`Program`] holds all information about a loaded binary: memory layout,
//! disassembly listing, data types, symbols, cross-references, functions,
//! externals, bookmarks, properties, the symbol tree, language and
//! compiler specifications, program context (register values), relocations,
//! metadata, and a change-set for undo/redo support.
//!
//! # Architecture
//!
//! The `Program` delegates to specialised managers (pluggable behind traits
//! where possible) rather than inlining every concern. It implements
//! [`DomainObject`] for integration with Ghidra's domain-file framework.
//!
//! # Subsystems composed by Program
//!
//! - [`AddressFactory`] — creates addresses in different spaces
//! - [`Memory`] — memory blocks, byte-level read/write
//! - [`Listing`] — code units, instructions, data items
//! - [`DataTypeManager`] — type resolution and management
//! - [`SymbolTable`] — symbols, namespaces
//! - [`FunctionManager`] — function CRUD
//! - [`ReferenceManager`] — cross-references (xrefs)
//! - [`BookmarkManager`] — user-placed bookmarks
//! - ProgramContext — register values, flow overrides
//! - RelocationTable — load-time fixups
//! - [`Language`] — processor language descriptor
//! - [`CompilerSpec`] — ABI / calling conventions
//! - Change tracking — undo/redo stack

use crate::addr::{Address, AddressFactory, AddressRange};
use crate::data::{DataType, DataTypeManager, StandaloneDataTypeManager};
use crate::error::{GhidraError, Result};
use crate::listing::ListingRow;
use crate::mem::{Memory, MemoryMap, StubMemory};
use crate::program::lang::{CompilerSpec, Language, Register};
use crate::program::listing::{
    Bookmark, BookmarkManager, CodeUnitComments, CodeUnitData,
    CommentType, FlowOverride, Function, FunctionManager,
    InMemoryListing, Listing, SourceType as ListingSourceType,
};
use crate::symbol::{
    Reference, ReferenceManager, RefType, SourceType,
    Symbol, SymbolPath, SymbolTreeNode, SymbolType,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime};

// ============================================================================
// DomainObject trait
// ============================================================================

/// The fundamental interface for domain objects in the Ghidra framework.
pub trait DomainObject: fmt::Debug + Send + Sync {
    fn get_name(&self) -> &str;
    fn set_name(&mut self, name: String);
    fn get_domain_file_path(&self) -> Option<&str>;
    fn get_last_modified_time(&self) -> SystemTime;
    fn is_changed(&self) -> bool;
    fn set_changed(&mut self, changed: bool);
    fn save(&self) -> Result<()>;
    fn close(&mut self) -> Result<()>;
    fn is_lockable(&self) -> bool;
    fn is_locked(&self) -> bool;
    fn lock(&self) -> Result<DomainObjectLock<'_>>;
    fn force_unlock(&self);
    fn add_listener(&self, listener: Box<dyn DomainObjectListener>);
    fn remove_listener(&self, listener_id: u64);
}

pub struct DomainObjectLock<'a> {
    _obj: &'a dyn DomainObject,
    acquired_at: Instant,
}

impl<'a> DomainObjectLock<'a> {
    pub fn new(obj: &'a dyn DomainObject) -> Self {
        Self { _obj: obj, acquired_at: Instant::now() }
    }
    pub fn acquired_at(&self) -> Instant { self.acquired_at }
}

impl<'a> Drop for DomainObjectLock<'a> { fn drop(&mut self) {} }

// ============================================================================
// DomainObjectListener / DomainObjectChangeEvent / DomainObjectChangeType
// ============================================================================

pub trait DomainObjectListener: fmt::Debug + Send + Sync {
    fn domain_object_changed(&self, ev: &DomainObjectChangeEvent);
    fn domain_object_about_to_close(&self, ev: &DomainObjectChangeEvent);
    fn domain_object_closed(&self);
}

#[derive(Debug, Clone)]
pub struct DomainObjectChangeEvent {
    pub event_type: DomainObjectChangeType,
    pub affected_addresses: Vec<AddressRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainObjectChangeType {
    MemoryChanged, MemoryBlockAdded, MemoryBlockRemoved, MemoryBlockMoved,
    CodeChanged, CodeAdded, CodeRemoved, CodeReplaced,
    DataTypeChanged, DataTypeAdded, DataTypeRemoved,
    SymbolAdded, SymbolRemoved, SymbolRenamed, SymbolMoved,
    SymbolSourceChanged, SymbolPrimaryChanged,
    FunctionAdded, FunctionRemoved, FunctionChanged,
    ReferenceAdded, ReferenceRemoved,
    BookmarkAdded, BookmarkRemoved, BookmarkChanged,
    ExternalProgramAdded, ExternalProgramRemoved,
    RelocationAdded, PropertyChanged, LanguageChanged, Restored,
}

// ============================================================================
// Internal lock state
// ============================================================================

#[derive(Default)]
struct LockState {
    locked: bool,
    lock_owner: Option<String>,
    listeners: HashMap<u64, Box<dyn DomainObjectListener>>,
    next_listener_id: u64,
}

impl fmt::Debug for LockState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockState")
            .field("locked", &self.locked)
            .field("lock_owner", &self.lock_owner)
            .field("listeners", &self.listeners.len())
            .finish()
    }
}

// ============================================================================
// ProgramChangeSet — undo/redo
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct ProgramChangeSet {
    pub memory_changes: HashSet<String>,
    pub code_added: BTreeSet<Address>,
    pub code_removed: BTreeSet<Address>,
    pub code_changed: BTreeSet<Address>,
    pub data_added: BTreeSet<Address>,
    pub data_removed: BTreeSet<Address>,
    pub data_changed: BTreeSet<Address>,
    pub symbols_added: HashMap<Address, Symbol>,
    pub symbols_removed: BTreeSet<Address>,
    pub symbols_renamed: HashMap<Address, String>,
    pub references_added: Vec<(Address, Address)>,
    pub references_removed: Vec<(Address, Address)>,
    pub functions_added: BTreeSet<Address>,
    pub functions_removed: BTreeSet<Address>,
    pub functions_changed: BTreeSet<Address>,
    pub bookmarks_added: Vec<String>,
    pub bookmarks_removed: Vec<String>,
    pub property_changes: Vec<(Address, String, Option<String>)>,
    pub relocations_changed: BTreeSet<Address>,
    pub language_changed: bool,
}

impl ProgramChangeSet {
    pub fn new() -> Self { Self::default() }

    pub fn is_empty(&self) -> bool {
        self.memory_changes.is_empty()
            && self.code_added.is_empty() && self.code_removed.is_empty() && self.code_changed.is_empty()
            && self.data_added.is_empty() && self.data_removed.is_empty() && self.data_changed.is_empty()
            && self.symbols_added.is_empty() && self.symbols_removed.is_empty() && self.symbols_renamed.is_empty()
            && self.references_added.is_empty() && self.references_removed.is_empty()
            && self.functions_added.is_empty() && self.functions_removed.is_empty() && self.functions_changed.is_empty()
            && self.bookmarks_added.is_empty() && self.bookmarks_removed.is_empty()
            && self.property_changes.is_empty() && self.relocations_changed.is_empty()
            && !self.language_changed
    }

    pub fn clear(&mut self) { *self = ProgramChangeSet::new(); }
}

// ============================================================================
// Program — the central type
// ============================================================================

/// A simple concrete data type descriptor for backward compatibility with
/// ghidra-app exporters and loaders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleDataType {
    /// Type name.
    pub name: String,
    /// Size in bytes.
    pub size: usize,
    /// Type kind.
    pub kind: crate::data::DataTypeKind,
    /// Optional description.
    pub description: String,
}

impl SimpleDataType {
    /// Create an i32 data type.
    pub fn i32() -> Self {
        Self { name: "i32".into(), size: 4, kind: crate::data::DataTypeKind::Primitive, description: String::new() }
    }
    /// Create a u32 data type.
    pub fn u32() -> Self {
        Self { name: "u32".into(), size: 4, kind: crate::data::DataTypeKind::Primitive, description: String::new() }
    }
    /// Create a generic data type with the given name and size.
    pub fn new(name: impl Into<String>, size: usize, kind: crate::data::DataTypeKind) -> Self {
        Self { name: name.into(), size, kind, description: String::new() }
    }
}

/// The central representation of a loaded binary program in Ghidra.
///
/// `Program` composes all analysis data: memory, listing, symbols, references,
/// functions, externals, bookmarks, properties, data types, the symbol tree,
/// language/compiler information, program context, relocations, and metadata.
/// A change-set layered on top supports undo/redo.
pub struct Program {
    // ---------- identity ----------
    pub name: String,
    pub domain_file_path: Option<String>,
    pub image_base: Address,
    unique_id: u64,

    // ---------- timestamps ----------
    creation_time: SystemTime,
    last_modified_time: SystemTime,

    // ---------- address factory ----------
    address_factory: AddressFactory,

    // ---------- memory ----------
    pub memory: Box<dyn Memory>,

    // ---------- listing ----------
    pub listing: InMemoryListing,

    // ---------- data types ----------
    pub data_type_manager: Arc<dyn DataTypeManager>,
    applied_data_types: HashMap<Address, Arc<dyn DataType>>,

    // ---------- symbols ----------
    pub symbols: ProgramSymbolTable,

    // ---------- references ----------
    pub references: ReferenceManager,

    // ---------- functions ----------
    pub functions: FunctionManager,

    // ---------- externals ----------
    pub externals: ProgramExternalManager,

    // ---------- bookmarks ----------
    pub bookmarks: BookmarkManager,

    // ---------- properties ----------
    global_properties: HashMap<String, String>,
    address_properties: HashMap<Address, HashMap<String, String>>,

    // ---------- tree ----------
    tree_manager: Option<Arc<RwLock<SymbolTreeNode>>>,

    // ---------- language and compiler ----------
    pub language: Option<Arc<Language>>,
    pub compiler_spec: Option<Arc<CompilerSpec>>,

    // ---------- program context ----------
    program_context: ProgramContextData,

    // ---------- relocations ----------
    relocations: ProgramRelocationTable,

    // ---------- metadata ----------
    pub metadata: BTreeMap<String, String>,

    // ---------- executable metadata ----------
    pub executable_path: Option<String>,
    pub executable_format: Option<String>,
    executable_md5: Option<String>,
    executable_sha256: Option<String>,
    compiler_name: Option<String>,

    // ---------- preferred root namespace ----------
    preferred_root_namespace_category: Option<String>,

    // ---------- change-set ----------
    change_set: Option<ProgramChangeSet>,
    undo_stack: Vec<ProgramChangeSet>,
    redo_stack: Vec<ProgramChangeSet>,

    // ---------- lock state ----------
    lock_state: Mutex<LockState>,

    // ---------- compatibility fields (used by ghidra-app) ----------
    /// File path for backward compatibility with ghidra-app.
    pub file_path: Option<String>,
    /// Memory blocks indexed by name (compatibility layer).
    pub memory_blocks: HashMap<String, MemoryBlock>,
    /// Symbol table (compatibility layer).
    pub symbol_table: SymbolTable,
    /// Cross-references: target address -> list of source addresses.
    pub xrefs: HashMap<Address, Vec<Address>>,
    /// Import names (compatibility layer).
    pub imports: Vec<String>,
    /// Export names (compatibility layer).
    pub exports: Vec<String>,
    /// Comments indexed by address (compatibility layer).
    pub comments: HashMap<Address, Vec<Comment>>,
    /// Data types applied at addresses (compatibility layer).
    pub data_types: HashMap<Address, SimpleDataType>,
    /// Legacy listing data (compatibility layer for ghidra-app).
    pub listing_data: ListingData,
}

// ============================================================================
// Internal sub-structs
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct ProgramSymbolTable {
    pub symbols: HashMap<Address, Symbol>,
    pub by_name: HashMap<String, Vec<Address>>,
    pub tree: SymbolTreeNode,
}

impl ProgramSymbolTable {
    fn add(&mut self, sym: Symbol) {
        self.by_name.entry(sym.name().clone()).or_default().push(*sym.address());
        self.symbols.insert(*sym.address(), sym);
    }
    fn remove(&mut self, addr: &Address) -> Option<Symbol> {
        let sym = self.symbols.remove(addr)?;
        if let Some(addrs) = self.by_name.get_mut(&sym.name()) {
            addrs.retain(|a| a != addr);
            if addrs.is_empty() { self.by_name.remove(&sym.name()); }
        }
        Some(sym)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProgramExternalManager {
    externals: HashMap<String, ProgramExternal>,
    external_locations: HashMap<Address, String>,
}

#[derive(Debug, Clone)]
pub struct ProgramExternal {
    pub name: String,
    _path: Option<String>,
    external_address: Option<Address>,
    _external_data_type: Option<Arc<dyn DataType>>,
    resolved: bool,
}

#[derive(Debug, Clone, Default)]
struct ProgramContextData {
    register_values: HashMap<Address, HashMap<String, Vec<u8>>>,
    flow_override: HashMap<Address, FlowOverride>,
    register_defaults: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
struct ProgramRelocationTable {
    relocations: HashMap<Address, ProgramRelocation>,
}

#[derive(Debug, Clone)]
pub struct ProgramRelocation {
    _address: Address,
    _relocation_type: String,
    _value: Vec<u64>,
    _bytes: Vec<u8>,
    _comment: Option<String>,
}

// ============================================================================
// Program implementation
// ============================================================================

impl fmt::Debug for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Program")
            .field("name", &self.name)
            .field("domain_file_path", &self.domain_file_path)
            .field("image_base", &self.image_base)
            .field("unique_id", &self.unique_id)
            .field("creation_time", &self.creation_time)
            .field("language", &self.language)
            .field("compiler_spec", &self.compiler_spec)
            .field("metadata", &self.metadata)
            .field("symbols_count", &self.symbols.symbols.len())
            .field("functions_count", &self.functions.get_function_count())
            .field("bookmarks_count", &self.bookmarks.num_bookmarks())
            .field("undo_stack_depth", &self.undo_stack.len())
            .field("is_changed", &self.is_changed())
            .finish()
    }
}

impl Program {
    pub fn new(name: impl Into<String>, image_base: Address) -> Self {
        let now = SystemTime::now();
        let unique_id = now.duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64).unwrap_or(0);
        Self {
            name: name.into(),
            domain_file_path: None,
            image_base,
            unique_id,
            creation_time: now,
            last_modified_time: now,
            address_factory: AddressFactory::new(),
            memory: Box::new(StubMemory::new(false)),
            listing: InMemoryListing::new(),
            data_type_manager: Arc::new(StandaloneDataTypeManager::new()),
            applied_data_types: HashMap::new(),
            symbols: ProgramSymbolTable::default(),
            references: ReferenceManager::new(),
            functions: FunctionManager::new(),
            externals: ProgramExternalManager::default(),
            bookmarks: BookmarkManager::new(),
            global_properties: HashMap::new(),
            address_properties: HashMap::new(),
            tree_manager: None,
            language: None,
            compiler_spec: None,
            program_context: ProgramContextData::default(),
            relocations: ProgramRelocationTable::default(),
            metadata: BTreeMap::new(),
            executable_path: None,
            executable_format: None,
            executable_md5: None,
            executable_sha256: None,
            compiler_name: None,
            preferred_root_namespace_category: None,
            change_set: Some(ProgramChangeSet::new()),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            lock_state: Mutex::new(LockState::default()),
            // compatibility fields
            file_path: None,
            memory_blocks: HashMap::new(),
            symbol_table: SymbolTable::default(),
            xrefs: HashMap::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            comments: HashMap::new(),
            data_types: HashMap::new(),
            listing_data: ListingData::default(),
        }
    }

    pub fn with_memory(name: impl Into<String>, image_base: Address, memory: Box<dyn Memory>) -> Self {
        let mut prog = Self::new(name, image_base);
        prog.memory = memory;
        prog
    }

    fn touch(&mut self) { self.last_modified_time = SystemTime::now(); }

    // ---------- Identity ----------
    pub fn get_name(&self) -> &str { &self.name }
    pub fn set_name(&mut self, name: impl Into<String>) { self.name = name.into(); self.touch(); }
    pub fn get_domain_file_path(&self) -> Option<&str> { self.domain_file_path.as_deref() }
    pub fn set_domain_file_path(&mut self, path: impl Into<String>) { self.domain_file_path = Some(path.into()); }
    pub fn get_unique_id(&self) -> u64 { self.unique_id }
    pub fn get_creation_date(&self) -> SystemTime { self.creation_time }
    pub fn get_last_modified_time(&self) -> SystemTime { self.last_modified_time }

    // ---------- Image base ----------
    pub fn get_image_base(&self) -> Address { self.image_base }
    pub fn set_image_base(&mut self, base: Address) { self.image_base = base; self.touch(); }

    // ---------- AddressFactory ----------
    pub fn get_address_factory(&self) -> &AddressFactory { &self.address_factory }
    pub fn set_address_factory(&mut self, factory: AddressFactory) { self.address_factory = factory; }

    pub fn parse_address(&self, addr_str: &str) -> Vec<Address> {
        let trimmed = addr_str.trim().trim_start_matches("0x").trim_start_matches("0X");
        if let Ok(offset) = u64::from_str_radix(trimmed, 16) {
            return vec![Address::new(offset)];
        }
        if let Some(colon_pos) = addr_str.find(':') {
            let offset_str = &addr_str[colon_pos + 1..];
            if let Ok(offset) = u64::from_str_radix(offset_str.trim(), 16) {
                return vec![Address::new(offset)];
            }
        }
        Vec::new()
    }

    // ---------- Memory subsystem ----------
    pub fn get_memory(&self) -> &dyn Memory { self.memory.as_ref() }
    pub fn get_memory_mut(&mut self) -> &mut dyn Memory { self.memory.as_mut() }
    pub fn set_memory(&mut self, memory: Box<dyn Memory>) { self.memory = memory; self.touch(); }
    pub fn get_memory_blocks(&self) -> Vec<&crate::mem::MemoryBlock> { self.memory.get_blocks() }
    pub fn get_memory_block_at(&self, addr: &Address) -> Option<&crate::mem::MemoryBlock> { self.memory.get_block(addr) }
    pub fn get_memory_block(&self, name: &str) -> Option<&crate::mem::MemoryBlock> { self.memory.get_block_by_name(name) }
    pub fn get_min_address(&self) -> Option<Address> {
        self.memory.get_blocks().iter().map(|b| b.range.start).min_by_key(|a| a.offset)
    }
    pub fn get_max_address(&self) -> Option<Address> {
        self.memory.get_blocks().iter().map(|b| b.range.end).max_by_key(|a| a.offset)
    }
    pub fn read_bytes(&self, addr: Address, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        match self.memory.get_bytes(addr, &mut buf, 0, len) {
            Ok(n) => { buf.truncate(n); buf }
            Err(_) => Vec::new(),
        }
    }

    // ---------- Listing subsystem ----------
    pub fn get_listing(&self) -> &InMemoryListing { &self.listing }
    pub fn get_listing_mut(&mut self) -> &mut InMemoryListing { &mut self.listing }
    pub fn get_code_unit_at(&self, addr: &Address) -> Option<CodeUnitData> { self.listing.get_code_unit_at(addr) }
    pub fn is_code_at(&self, addr: &Address) -> bool { self.listing.get_code_unit_at(addr).is_some() }

    pub fn add_code_unit(&mut self, address: Address, length: usize, bytes: Vec<u8>) {
        let _ = self.listing.create_code_unit(address, length, bytes);
        if let Some(cs) = self.change_set.as_mut() { cs.code_added.insert(address); }
        self.touch();
    }
    pub fn remove_code_unit(&mut self, addr: &Address) -> bool {
        let removed = self.listing.remove_code_unit(addr).is_ok();
        if removed { if let Some(cs) = self.change_set.as_mut() { cs.code_removed.insert(*addr); } self.touch(); }
        removed
    }
    pub fn get_comment(&self, comment_type: CommentType, addr: &Address) -> Option<String> {
        self.listing.get_comment(comment_type, addr)
    }
    pub fn set_comment(&mut self, addr: Address, comment_type: CommentType, comment: Option<String>) {
        self.listing.set_comment(addr, comment_type, comment);
        self.touch();
    }
    pub fn get_all_comments(&self, addr: &Address) -> CodeUnitComments { self.listing.get_all_comments(addr) }
    pub fn clear_code_units(&mut self, range: &AddressRange) -> std::result::Result<(), String> { self.listing.clear_code_units(range) }

    // ---------- Data type subsystem ----------
    pub fn get_data_type_manager(&self) -> &Arc<dyn DataTypeManager> { &self.data_type_manager }
    pub fn set_data_type_manager(&mut self, dtm: Arc<dyn DataTypeManager>) { self.data_type_manager = dtm; }
    pub fn get_data_type_at(&self, addr: &Address) -> Option<&Arc<dyn DataType>> { self.applied_data_types.get(addr) }
    pub fn apply_data_type(&mut self, addr: Address, data_type: Arc<dyn DataType>) {
        self.applied_data_types.insert(addr, data_type);
        if let Some(cs) = self.change_set.as_mut() { cs.data_added.insert(addr); }
        self.touch();
    }
    pub fn remove_data_type(&mut self, addr: &Address) -> Option<Arc<dyn DataType>> {
        let removed = self.applied_data_types.remove(addr);
        if removed.is_some() { if let Some(cs) = self.change_set.as_mut() { cs.data_removed.insert(*addr); } self.touch(); }
        removed
    }
    pub fn get_all_data_types(&self) -> &HashMap<Address, Arc<dyn DataType>> { &self.applied_data_types }

    // ---------- Symbol table subsystem ----------
    pub fn get_symbol_at(&self, addr: &Address) -> Option<&Symbol> { self.symbols.symbols.get(addr) }
    pub fn get_symbols_by_name(&self, name: &str) -> Vec<&Symbol> {
        if let Some(addrs) = self.symbols.by_name.get(name) {
            addrs.iter().filter_map(|a| self.symbols.symbols.get(a)).collect()
        } else { Vec::new() }
    }
    pub fn add_symbol(&mut self, symbol: Symbol) {
        self.symbols.add(symbol.clone());
        if let Some(cs) = self.change_set.as_mut() { cs.symbols_added.insert(*symbol.address(), symbol); }
        self.touch();
    }
    pub fn remove_symbol(&mut self, addr: &Address) -> Option<Symbol> {
        let removed = self.symbols.remove(addr);
        if removed.is_some() { if let Some(cs) = self.change_set.as_mut() { cs.symbols_removed.insert(*addr); } self.touch(); }
        removed
    }
    pub fn get_all_symbols(&self) -> Vec<&Symbol> { self.symbols.symbols.values().collect() }
    pub fn get_symbol_tree(&self) -> &SymbolTreeNode { &self.symbols.tree }

    pub fn rebuild_symbol_tree(&mut self) {
        self.symbols.tree = SymbolTreeNode::root();
        let mut funcs = SymbolTreeNode::new("Functions",
            SymbolPath::from_segments(vec!["Global".into(), "Functions".into()]));
        let mut labels = SymbolTreeNode::new("Labels",
            SymbolPath::from_segments(vec!["Global".into(), "Labels".into()]));
        let mut imports = SymbolTreeNode::new("Imports",
            SymbolPath::from_segments(vec!["Global".into(), "Imports".into()]));
        for sym in self.symbols.symbols.values() {
            let node = SymbolTreeNode::leaf(sym.name().clone(),
                SymbolPath::from_segments(vec!["Global".into(), sym.name().clone()]), sym.clone());
            match sym.kind() {
                SymbolType::Function => funcs.add_child(node),
                SymbolType::Library => imports.add_child(node),
                _ => labels.add_child(node),
            }
        }
        self.symbols.tree.add_child(funcs);
        self.symbols.tree.add_child(labels);
        self.symbols.tree.add_child(imports);
        self.touch();
    }

    // ---------- Reference (xref) subsystem ----------
    pub fn get_reference_manager(&self) -> &ReferenceManager { &self.references }
    pub fn get_reference_manager_mut(&mut self) -> &mut ReferenceManager { &mut self.references }

    pub fn add_reference(&mut self, from: Address, to: Address, ref_type: RefType, op_index: i32, source: SourceType) {
        let _ = self.references.add_memory_reference(from, to, ref_type, source, op_index);
        if let Some(cs) = self.change_set.as_mut() { cs.references_added.push((from, to)); }
        self.touch();
    }
    pub fn remove_reference(&mut self, from: &Address, to: &Address) -> bool {
        let removed = self.references.get_reference(*from, *to, -1).is_some();
        if removed {
            self.references.delete(&Reference::new(*from, *to, RefType::DATA, -1)).ok();
            if let Some(cs) = self.change_set.as_mut() { cs.references_removed.push((*from, *to)); }
            self.touch();
        }
        removed
    }
    pub fn get_references_from(&self, addr: &Address) -> Vec<&Reference> { self.references.get_references_from(*addr) }
    pub fn get_references_to(&self, addr: &Address) -> Vec<Address> {
        self.references.get_references_to(*addr).map(|r| *r.get_to_address()).collect()
    }
    pub fn reference_count(&self) -> usize { self.references.get_reference_source_count() }

    // ---------- Function subsystem ----------
    pub fn get_function_manager(&self) -> &FunctionManager { &self.functions }
    pub fn get_function_manager_mut(&mut self) -> &mut FunctionManager { &mut self.functions }
    pub fn get_function_at(&self, entry: &Address) -> Option<&Function> { self.functions.get_function_at(entry) }
    pub fn get_function_at_mut(&mut self, entry: &Address) -> Option<&mut Function> { self.functions.get_function_at_mut(entry) }
    pub fn get_function_containing(&self, addr: &Address) -> Option<&Function> { self.functions.get_function_containing(addr) }
    pub fn get_function_entry_points(&self) -> Vec<Address> { self.functions.get_function_entry_points() }

    pub fn add_function(&mut self, entry: Address, body: AddressRange, name: Option<&str>, source: ListingSourceType) -> std::result::Result<(), String> {
        self.functions.create_function(name, entry, body, source)?;
        if let Some(cs) = self.change_set.as_mut() { cs.functions_added.insert(entry); }
        self.touch();
        Ok(())
    }
    pub fn remove_function(&mut self, entry: &Address) -> bool {
        let removed = self.functions.remove_function(entry);
        if removed { if let Some(cs) = self.change_set.as_mut() { cs.functions_removed.insert(*entry); } self.touch(); }
        removed
    }
    pub fn is_in_function(&self, addr: &Address) -> bool { self.functions.is_in_function(addr) }
    pub fn function_count(&self) -> usize { self.functions.get_function_count() }

    // ---------- External subsystem ----------
    pub fn add_external(&mut self, name: impl Into<String>, path: Option<String>) {
        let name = name.into();
        self.externals.externals.insert(name.clone(), ProgramExternal {
            name, _path: path, external_address: None, _external_data_type: None, resolved: false,
        });
        self.touch();
    }
    pub fn resolve_external(&mut self, name: &str, address: Address) -> bool {
        if let Some(ext) = self.externals.externals.get_mut(name) {
            ext.external_address = Some(address);
            ext.resolved = true;
            self.externals.external_locations.insert(address, name.to_string());
            self.touch();
            true
        } else { false }
    }
    pub fn get_external(&self, name: &str) -> Option<&ProgramExternal> { self.externals.externals.get(name) }
    pub fn get_external_names(&self) -> Vec<&str> { self.externals.externals.keys().map(|s| s.as_str()).collect() }

    // ---------- Bookmark subsystem ----------
    pub fn get_bookmark_manager(&self) -> &BookmarkManager { &self.bookmarks }
    pub fn get_bookmark_manager_mut(&mut self) -> &mut BookmarkManager { &mut self.bookmarks }

    pub fn add_bookmark(&mut self, address: Address, bookmark_type: impl Into<String>, category: impl Into<String>, comment: impl Into<String>) -> Bookmark {
        let bm = self.bookmarks.set_bookmark(address, bookmark_type, category, comment);
        if let Some(cs) = self.change_set.as_mut() { cs.bookmarks_added.push(format!("{}/{}", bm.bookmark_type, bm.category)); }
        self.touch();
        bm
    }
    pub fn get_bookmarks_at(&self, addr: &Address) -> Vec<&Bookmark> { self.bookmarks.get_bookmarks(addr) }
    pub fn remove_bookmarks_at(&mut self, addr: &Address) -> Vec<Bookmark> {
        let removed = self.bookmarks.remove_bookmarks(addr);
        if !removed.is_empty() { self.touch(); }
        removed
    }

    // ---------- Property subsystem ----------
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.global_properties.insert(key.into(), value.into());
        self.touch();
    }
    pub fn get_property(&self, key: &str) -> Option<&str> { self.global_properties.get(key).map(|s| s.as_str()) }
    pub fn has_property(&self, key: &str) -> bool { self.global_properties.contains_key(key) }
    pub fn remove_property(&mut self, key: &str) -> Option<String> {
        let removed = self.global_properties.remove(key);
        if removed.is_some() { self.touch(); }
        removed
    }
    pub fn get_properties(&self) -> &HashMap<String, String> { &self.global_properties }
    pub fn property_keys(&self) -> impl Iterator<Item = &str> {
        self.global_properties.keys().map(String::as_str)
    }
    pub fn property_count(&self) -> usize { self.global_properties.len() }

    pub fn set_address_property(&mut self, addr: Address, key: impl Into<String>, value: impl Into<String>) {
        let key_str: String = key.into();
        self.address_properties.entry(addr).or_default().insert(key_str.clone(), value.into());
        if let Some(cs) = self.change_set.as_mut() { cs.property_changes.push((addr, key_str, None)); }
        self.touch();
    }
    pub fn get_address_property(&self, addr: &Address, key: &str) -> Option<&str> {
        self.address_properties.get(addr).and_then(|props| props.get(key)).map(|s| s.as_str())
    }
    pub fn has_address_property(&self, addr: &Address, key: &str) -> bool {
        self.address_properties
            .get(addr)
            .map(|props| props.contains_key(key))
            .unwrap_or(false)
    }
    pub fn remove_address_property(&mut self, addr: &Address, key: &str) -> Option<String> {
        let removed = if let Some(props) = self.address_properties.get_mut(addr) {
            let removed = props.remove(key);
            let should_remove_entry = props.is_empty();
            let _ = props;
            if should_remove_entry {
                self.address_properties.remove(addr);
            }
            removed
        } else {
            None
        };
        if removed.is_some() { self.touch(); }
        removed
    }
    pub fn get_address_properties(&self, addr: &Address) -> Option<&HashMap<String, String>> {
        self.address_properties.get(addr)
    }
    pub fn address_property_keys(&self, addr: &Address) -> Vec<&str> {
        self.address_properties
            .get(addr)
            .map(|props| props.keys().map(String::as_str).collect())
            .unwrap_or_default()
    }
    pub fn get_address_property_addresses(&self) -> Vec<Address> {
        self.address_properties.keys().copied().collect()
    }
    pub fn total_address_property_count(&self) -> usize {
        self.address_properties.values().map(HashMap::len).sum()
    }

    // ---------- Program metadata helpers ----------
    pub fn has_metadata(&self, key: &str) -> bool { self.metadata.contains_key(key) }
    pub fn remove_metadata(&mut self, key: &str) -> Option<String> {
        let removed = self.metadata.remove(key);
        if removed.is_some() { self.touch(); }
        removed
    }
    pub fn metadata_keys(&self) -> impl Iterator<Item = &str> {
        self.metadata.keys().map(String::as_str)
    }
    pub fn metadata_count(&self) -> usize { self.metadata.len() }
    pub fn get_creation_time(&self) -> SystemTime { self.creation_time }
    pub fn get_language_id(&self) -> Option<&crate::program::lang::LanguageID> {
        self.language.as_ref().map(|language| &language.id)
    }
    pub fn get_compiler_spec_id(&self) -> Option<&crate::program::lang::CompilerSpecID> {
        self.compiler_spec.as_ref().map(|spec| &spec.id)
    }
    pub fn has_executable_path(&self) -> bool { self.executable_path.is_some() }
    pub fn has_executable_format(&self) -> bool { self.executable_format.is_some() }
    pub fn has_executable_md5(&self) -> bool { self.executable_md5.is_some() }
    pub fn has_executable_sha256(&self) -> bool { self.executable_sha256.is_some() }
    pub fn has_preferred_root_namespace_category_path(&self) -> bool {
        self.preferred_root_namespace_category.is_some()
    }
    pub fn get_domain_file_name(&self) -> Option<&str> {
        self.domain_file_path
            .as_deref()
            .and_then(|path| path.rsplit('/').next())
    }
    pub fn has_domain_file_path(&self) -> bool { self.domain_file_path.is_some() }
    pub fn get_comment_map(&self) -> &HashMap<Address, Vec<Comment>> { &self.comments }
    pub fn get_imports(&self) -> &[String] { &self.imports }
    pub fn get_exports(&self) -> &[String] { &self.exports }
    pub fn get_xrefs(&self) -> &HashMap<Address, Vec<Address>> { &self.xrefs }
    pub fn has_comments(&self) -> bool { !self.comments.is_empty() }
    pub fn has_imports(&self) -> bool { !self.imports.is_empty() }
    pub fn has_exports(&self) -> bool { !self.exports.is_empty() }
    pub fn has_xrefs(&self) -> bool { !self.xrefs.is_empty() }
    pub fn has_file_path(&self) -> bool { self.file_path.is_some() }
    pub fn executable_name(&self) -> Option<&str> {
        self.executable_path
            .as_deref()
            .and_then(|path| path.rsplit('/').next())
    }
    pub fn executable_hashes(&self) -> (Option<&str>, Option<&str>) {
        (self.get_executable_md5(), self.get_executable_sha256())
    }
    pub fn compiler_or<'a>(&'a self, default: &'a str) -> &'a str {
        self.compiler_name.as_deref().unwrap_or(default)
    }
    pub fn get_property_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get_property(key).unwrap_or(default)
    }
    pub fn get_metadata_value_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get_metadata(key).unwrap_or(default)
    }
    pub fn get_address_property_or<'a>(&'a self, addr: &Address, key: &str, default: &'a str) -> &'a str {
        self.get_address_property(addr, key).unwrap_or(default)
    }

    // ---------- Lightweight summary helpers ----------
    pub fn has_symbol_at(&self, addr: &Address) -> bool { self.symbols.symbols.contains_key(addr) }
    pub fn has_data_type_at(&self, addr: &Address) -> bool { self.applied_data_types.contains_key(addr) }
    pub fn has_function_at(&self, addr: &Address) -> bool { self.functions.get_function_at(addr).is_some() }
    pub fn has_bookmarks_at(&self, addr: &Address) -> bool { !self.bookmarks.get_bookmarks(addr).is_empty() }
    pub fn has_reference_from(&self, addr: &Address) -> bool { self.references.has_references_from(*addr) }
    pub fn has_reference_to(&self, addr: &Address) -> bool { self.references.has_references_to(*addr) }
    pub fn get_symbol_count(&self) -> usize { self.symbols.symbols.len() }
    pub fn get_data_type_count(&self) -> usize { self.applied_data_types.len() }
    pub fn get_bookmark_count(&self) -> usize { self.bookmarks.num_bookmarks() }
    pub fn get_external_count(&self) -> usize { self.externals.externals.len() }
    pub fn get_memory_block_count(&self) -> usize { self.memory.get_blocks().len() }
    pub fn has_memory(&self) -> bool { !self.memory.get_blocks().is_empty() }
    pub fn get_memory_map_range(&self) -> Option<AddressRange> {
        Some(AddressRange::new(self.get_min_address()?, self.get_max_address()?))
    }
    pub fn memory_contains(&self, addr: &Address) -> bool { self.memory.get_block(addr).is_some() }
    pub fn get_applied_data_type_addresses(&self) -> Vec<Address> { self.applied_data_types.keys().copied().collect() }
    pub fn get_symbol_addresses(&self) -> Vec<Address> { self.symbols.symbols.keys().copied().collect() }
    pub fn get_bookmarked_addresses(&self) -> Vec<Address> { self.bookmarks.get_bookmark_addresses() }
    pub fn get_reference_source_addresses(&self) -> Vec<Address> {
        self.references.get_reference_source_iterator(Address::new(0), true)
    }
    pub fn get_reference_destination_addresses(&self) -> Vec<Address> {
        self.references.get_reference_destination_iterator(Address::new(0), true)
    }
    pub fn get_function_addresses(&self) -> Vec<Address> { self.functions.get_function_entry_points() }
    pub fn get_external_addresses(&self) -> Vec<Address> { self.externals.external_locations.keys().copied().collect() }
    pub fn get_external_names_vec(&self) -> Vec<&str> { self.externals.externals.keys().map(String::as_str).collect() }
    pub fn has_register_default(&self, register: &str) -> bool {
        self.program_context.register_defaults.contains_key(register)
    }
    pub fn has_register_value(&self, addr: &Address, register: &str) -> bool {
        self.program_context
            .register_values
            .get(addr)
            .map(|regs| regs.contains_key(register))
            .unwrap_or(false)
    }
    pub fn get_register_default(&self, register: &str) -> Option<&Vec<u8>> {
        self.program_context.register_defaults.get(register)
    }
    pub fn get_register_defaults(&self) -> &HashMap<String, Vec<u8>> {
        &self.program_context.register_defaults
    }
    pub fn get_register_values(&self, addr: &Address) -> Option<&HashMap<String, Vec<u8>>> {
        self.program_context.register_values.get(addr)
    }
    pub fn has_flow_override_at(&self, addr: &Address) -> bool {
        self.program_context.flow_override.contains_key(addr)
    }
    pub fn get_flow_overrides(&self) -> &HashMap<Address, FlowOverride> {
        &self.program_context.flow_override
    }
    pub fn get_relocations(&self) -> Vec<Address> { self.relocations.relocations.keys().copied().collect() }
    pub fn has_relocation_at(&self, addr: &Address) -> bool { self.relocations.relocations.contains_key(addr) }
    pub fn has_tree_manager(&self) -> bool { self.tree_manager.is_some() }
    pub fn has_language(&self) -> bool { self.language.is_some() }
    pub fn has_compiler_spec(&self) -> bool { self.compiler_spec.is_some() }
    pub fn has_change_set(&self) -> bool { self.change_set.is_some() }
    pub fn undo_depth(&self) -> usize { self.undo_stack.len() }
    pub fn redo_depth(&self) -> usize { self.redo_stack.len() }
    pub fn has_undo(&self) -> bool { !self.undo_stack.is_empty() }
    pub fn has_redo(&self) -> bool { !self.redo_stack.is_empty() }
    pub fn image_base_offset(&self) -> u64 { self.image_base.offset }

    // ---------- Legacy listing data helpers ----------
    pub fn get_symbol_names(&self) -> Vec<&String> { self.symbols.by_name.keys().collect() }
    pub fn get_listing_rows(&self) -> Vec<&ListingRow> { self.listing_data.rows.values().collect() }
    pub fn get_listing_row_count(&self) -> usize { self.listing_data.rows.len() }
    pub fn has_listing_rows(&self) -> bool { !self.listing_data.rows.is_empty() }
    pub fn get_listing_row(&self, addr: &Address) -> Option<&ListingRow> { self.listing_data.rows.get(addr) }
    pub fn get_listing_row_addresses(&self) -> Vec<Address> { self.listing_data.rows.keys().copied().collect() }
    pub fn get_listing_data(&self) -> &ListingData { &self.listing_data }
    pub fn get_listing_data_mut(&mut self) -> &mut ListingData { &mut self.listing_data }
    pub fn get_listing_rows_by_label(&self, label: &str) -> Vec<&ListingRow> {
        self.listing_data.rows.values().filter(|row| row.label.as_deref() == Some(label)).collect()
    }
    pub fn get_listing_rows_with_comments(&self) -> Vec<&ListingRow> {
        self.listing_data.rows.values().filter(|row| row.comment.is_some()).collect()
    }
    pub fn listing_rows_sorted(&self) -> Vec<&ListingRow> {
        let mut rows: Vec<&ListingRow> = self.listing_data.rows.values().collect();
        rows.sort_by_key(|row| row.address);
        rows
    }
    pub fn get_symbol_table_compat(&self) -> &SymbolTable { &self.symbol_table }
    pub fn get_symbol_table_compat_mut(&mut self) -> &mut SymbolTable { &mut self.symbol_table }

    // ---------- Tree manager ----------
    pub fn get_tree_manager(&self) -> Option<&Arc<RwLock<SymbolTreeNode>>> { self.tree_manager.as_ref() }
    pub fn set_tree_manager(&mut self, tree: Arc<RwLock<SymbolTreeNode>>) { self.tree_manager = Some(tree); self.touch(); }

    // ---------- Language subsystem ----------
    pub fn get_language(&self) -> Option<&Arc<Language>> { self.language.as_ref() }
    pub fn set_language(&mut self, language: Language) {
        self.address_factory = language.address_factory.clone();
        self.language = Some(Arc::new(language));
        if let Some(cs) = self.change_set.as_mut() { cs.language_changed = true; }
        self.touch();
    }
    pub fn get_language_id_string(&self) -> Option<String> { self.language.as_ref().map(|l| l.id.to_string()) }

    // ---------- Compiler spec subsystem ----------
    pub fn get_compiler_spec(&self) -> Option<&Arc<CompilerSpec>> { self.compiler_spec.as_ref() }
    pub fn set_compiler_spec(&mut self, spec: CompilerSpec) { self.compiler_spec = Some(Arc::new(spec)); self.touch(); }

    // ---------- Compiler name ----------
    pub fn get_compiler(&self) -> &str { self.compiler_name.as_deref().unwrap_or("unknown") }
    pub fn set_compiler(&mut self, compiler: impl Into<String>) { self.compiler_name = Some(compiler.into()); }

    // ---------- Executable metadata ----------
    pub fn get_executable_path(&self) -> Option<&str> { self.executable_path.as_deref() }
    pub fn set_executable_path(&mut self, path: impl Into<String>) { self.executable_path = Some(path.into()); }
    pub fn get_executable_format(&self) -> Option<&str> { self.executable_format.as_deref() }
    pub fn set_executable_format(&mut self, format: impl Into<String>) { self.executable_format = Some(format.into()); }
    pub fn get_executable_md5(&self) -> Option<&str> { self.executable_md5.as_deref() }
    pub fn set_executable_md5(&mut self, md5: impl Into<String>) { self.executable_md5 = Some(md5.into()); }
    pub fn get_executable_sha256(&self) -> Option<&str> { self.executable_sha256.as_deref() }
    pub fn set_executable_sha256(&mut self, sha256: impl Into<String>) { self.executable_sha256 = Some(sha256.into()); }

    pub fn get_default_pointer_size(&self) -> usize {
        self.compiler_spec.as_ref()
            .map(|cs| cs.data_organization.pointer_size)
            .or_else(|| self.language.as_ref().map(|l| l.data_organization.pointer_size))
            .unwrap_or(8)
    }

    // ---------- Preferred root namespace ----------
    pub fn get_preferred_root_namespace_category_path(&self) -> Option<&str> { self.preferred_root_namespace_category.as_deref() }
    pub fn set_preferred_root_namespace_category_path(&mut self, path: Option<String>) { self.preferred_root_namespace_category = path; }

    // ---------- Program context (register values) ----------
    pub fn set_register_value(&mut self, addr: Address, register: impl Into<String>, value: Vec<u8>) {
        self.program_context.register_values.entry(addr).or_default().insert(register.into(), value);
        self.touch();
    }
    pub fn get_register_value(&self, addr: &Address, register: &str) -> Option<&Vec<u8>> {
        self.program_context.register_values.get(addr).and_then(|regs| regs.get(register))
    }
    pub fn set_register_default(&mut self, register: impl Into<String>, value: Vec<u8>) {
        self.program_context.register_defaults.insert(register.into(), value);
        self.touch();
    }
    pub fn get_register(&self, name: &str) -> Option<&Register> {
        self.language.as_ref().and_then(|l| l.register_manager.get_register(name))
    }
    pub fn set_flow_override(&mut self, addr: Address, flow: FlowOverride) {
        self.program_context.flow_override.insert(addr, flow);
        self.touch();
    }
    pub fn get_flow_override(&self, addr: &Address) -> Option<FlowOverride> {
        self.program_context.flow_override.get(addr).copied()
    }

    // ---------- Relocations ----------
    pub fn add_relocation(&mut self, address: Address, relocation_type: impl Into<String>, value: Vec<u64>, bytes: Vec<u8>) {
        self.relocations.relocations.insert(address, ProgramRelocation {
            _address: address, _relocation_type: relocation_type.into(), _value: value, _bytes: bytes, _comment: None,
        });
        if let Some(cs) = self.change_set.as_mut() { cs.relocations_changed.insert(address); }
        self.touch();
    }
    pub fn get_relocation_at(&self, addr: &Address) -> Option<&ProgramRelocation> { self.relocations.relocations.get(addr) }
    pub fn get_relocation_addresses(&self) -> Vec<Address> { self.relocations.relocations.keys().copied().collect() }
    pub fn relocation_count(&self) -> usize { self.relocations.relocations.len() }

    // ---------- Metadata ----------
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) { self.metadata.insert(key.into(), value.into()); self.touch(); }
    pub fn get_metadata(&self, key: &str) -> Option<&str> { self.metadata.get(key).map(|s| s.as_str()) }
    pub fn get_all_metadata(&self) -> &BTreeMap<String, String> { &self.metadata }

    // ---------- Change-set / undo / redo ----------
    pub fn begin_transaction(&mut self) { self.change_set = Some(ProgramChangeSet::new()); }
    pub fn end_transaction(&mut self) -> ProgramChangeSet {
        let cs = self.change_set.take().unwrap_or_default();
        if !cs.is_empty() { self.undo_stack.push(cs.clone()); self.redo_stack.clear(); }
        self.change_set = Some(ProgramChangeSet::new());
        cs
    }
    pub fn undo(&mut self) -> bool {
        if let Some(cs) = self.undo_stack.pop() { self.redo_stack.push(cs); self.touch(); true }
        else { false }
    }
    pub fn redo(&mut self) -> bool {
        if let Some(cs) = self.redo_stack.pop() { self.undo_stack.push(cs); self.touch(); true }
        else { false }
    }
    pub fn get_change_set(&self) -> Option<&ProgramChangeSet> { self.change_set.as_ref() }
    pub fn can_undo(&self) -> bool { !self.undo_stack.is_empty() }
    pub fn can_redo(&self) -> bool { !self.redo_stack.is_empty() }

    pub fn with_transaction<F, R>(&mut self, f: F) -> (R, ProgramChangeSet)
    where F: FnOnce(&mut Self) -> R {
        self.begin_transaction();
        let result = f(self);
        let cs = self.end_transaction();
        (result, cs)
    }

    // ---------- Listener management ----------
    pub fn add_listener(&mut self, listener: Box<dyn DomainObjectListener>) -> u64 {
        let mut lock = self.lock_state.lock().unwrap();
        let id = lock.next_listener_id;
        lock.next_listener_id += 1;
        lock.listeners.insert(id, listener);
        id
    }
    pub fn remove_listener(&mut self, listener_id: u64) -> bool {
        self.lock_state.lock().unwrap().listeners.remove(&listener_id).is_some()
    }
    pub fn fire_event(&self, ev: &DomainObjectChangeEvent) {
        let lock = self.lock_state.lock().unwrap();
        for listener in lock.listeners.values() { listener.domain_object_changed(ev); }
    }

    // ---------- State ----------
    pub fn is_changed(&self) -> bool { self.change_set.as_ref().map(|cs| !cs.is_empty()).unwrap_or(false) }
    pub fn mark_saved(&mut self) { self.change_set = Some(ProgramChangeSet::new()); }

    // ---------- Compatibility helpers (used by ghidra-app) ----------

    /// Look up a symbol at the given address in the compatibility symbol_table.
    pub fn symbol_at(&self, addr: &Address) -> Option<&Symbol> {
        self.symbol_table.get(addr)
    }

    /// Get cross-references to a target address from the compatibility xrefs map.
    pub fn xrefs_to(&self, addr: &Address) -> Vec<&Address> {
        self.xrefs.get(addr).map(|v| v.iter().collect()).unwrap_or_default()
    }

    /// Get the memory block containing the given address (compatibility).
    pub fn memory_block_at(&self, addr: &Address) -> Option<&MemoryBlock> {
        self.memory_blocks.values().find(|b| {
            addr.offset >= b.range.start.offset && addr.offset <= b.range.end.offset
        })
    }

    // ---------- Demo program ----------
    pub fn demo() -> Self {
        let mut prog = Self::with_memory("demo.bin", Address::new(0x1000), Box::new({
            let mut mem = MemoryMap::new(false);
            let _ = mem.create_initialized_block(".text", Address::new(0x1000), vec![
                0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x89, 0x7d,
                0xfc, 0x48, 0x89, 0x75, 0xf0, 0x48, 0x8d, 0x3d, 0x00, 0x20,
                0x00, 0x00, 0xe8, 0xe5, 0x0f, 0x00, 0x00, 0xb8, 0x00, 0x00,
                0x00, 0x00, 0xc9, 0xc3,
            ], false);
            let _ = mem.create_initialized_block(".data", Address::new(0x2000), vec![
                0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00,
            ], false);
            mem
        }));
        prog.domain_file_path = Some("/tmp/demo.bin".to_string());

        let rows: [(Address, &[u8]); 10] = [
            (Address::new(0x1000), &[0x55]),
            (Address::new(0x1001), &[0x48, 0x89, 0xe5]),
            (Address::new(0x1004), &[0x48, 0x83, 0xec, 0x20]),
            (Address::new(0x1008), &[0x89, 0x7d, 0xfc]),
            (Address::new(0x100b), &[0x48, 0x89, 0x75, 0xf0]),
            (Address::new(0x100f), &[0x48, 0x8d, 0x3d, 0x00, 0x20, 0x00, 0x00]),
            (Address::new(0x1016), &[0xe8, 0xe5, 0x0f, 0x00, 0x00]),
            (Address::new(0x101b), &[0xb8, 0x00, 0x00, 0x00, 0x00]),
            (Address::new(0x1020), &[0xc9]),
            (Address::new(0x1021), &[0xc3]),
        ];
        for (addr, bytes) in &rows { prog.add_code_unit(*addr, bytes.len(), bytes.to_vec()); }

        prog.add_symbol(Symbol::function("main".to_string(), Address::new(0x1000)));
        prog.add_symbol(Symbol::label("str_hello".to_string(), Address::new(0x2000)));
        prog.add_symbol(Symbol::import("printf".to_string(), Address::new(0x2000)));
        prog.add_symbol(Symbol::import("malloc".to_string(), Address::new(0x3010)));

        let _ = prog.references.add_memory_reference(Address::new(0x1016), Address::new(0x2000), RefType::UNCONDITIONAL_CALL, SourceType::UserDefined, 0);
        let _ = prog.references.add_memory_reference(Address::new(0x100f), Address::new(0x2000), RefType::DATA, SourceType::UserDefined, 1);

        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        let _ = prog.add_function(Address::new(0x1000), body, Some("main"), ListingSourceType::UserDefined);

        prog.add_external("printf", Some("libc.so.6".into()));
        prog.add_external("malloc", Some("libc.so.6".into()));
        prog.resolve_external("printf", Address::new(0x2000));
        prog.add_bookmark(Address::new(0x1000), "Analysis", "Entry Point", "Program entry point");
        prog.set_metadata("format", "ELF64");
        prog.set_metadata("arch", "x86_64");
        prog.set_metadata("compiler", "gcc 9.3.0");
        prog.rebuild_symbol_tree();
        prog.mark_saved();
        prog
    }
}

// ============================================================================
// Public types (re-exported)
// ============================================================================

/// A memory block within the program (compatibility struct).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBlock {
    pub name: String,
    pub range: AddressRange,
    pub permissions: MemoryPermissions,
    pub initialized: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPermissions {
    R, RX, RW, RWX,
}

impl MemoryPermissions {
    pub fn can_read(&self) -> bool { true }
    pub fn can_write(&self) -> bool { matches!(self, MemoryPermissions::RW | MemoryPermissions::RWX) }
    pub fn can_execute(&self) -> bool { matches!(self, MemoryPermissions::RX | MemoryPermissions::RWX) }
}

/// A comment on a listing line or address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    pub kind: CommentKind,
    pub text: String,
    pub author: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentKind {
    Plate, Pre, EndOfLine, Post, Repeatable,
}

/// Compact symbol table wrapper.
#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    pub symbols: HashMap<Address, Symbol>,
    pub tree: SymbolTreeNode,
}

impl SymbolTable {
    pub fn add(&mut self, sym: Symbol) { self.symbols.insert(*sym.address(), sym); }
    pub fn get(&self, addr: &Address) -> Option<&Symbol> { self.symbols.get(addr) }
    pub fn iter(&self) -> impl Iterator<Item = &Symbol> { self.symbols.values() }
    pub fn len(&self) -> usize { self.symbols.len() }
    pub fn is_empty(&self) -> bool { self.symbols.is_empty() }

    pub fn rebuild_tree(&mut self) {
        self.tree = SymbolTreeNode::root();
        let mut funcs = SymbolTreeNode::new("Functions",
            SymbolPath::from_segments(vec!["Global".into(), "Functions".into()]));
        let mut labels = SymbolTreeNode::new("Labels",
            SymbolPath::from_segments(vec!["Global".into(), "Labels".into()]));
        let mut imports = SymbolTreeNode::new("Imports",
            SymbolPath::from_segments(vec!["Global".into(), "Imports".into()]));
        for sym in self.symbols.values() {
            let node = SymbolTreeNode::leaf(sym.name().clone(),
                SymbolPath::from_segments(vec!["Global".into(), sym.name().clone()]), sym.clone());
            match sym.kind() {
                SymbolType::Function => funcs.add_child(node),
                SymbolType::Library => imports.add_child(node),
                _ => labels.add_child(node),
            }
        }
        self.tree.add_child(funcs);
        self.tree.add_child(labels);
        self.tree.add_child(imports);
    }
}

/// Legacy listing data type (for backward compatibility).
#[derive(Debug, Clone, Default)]
pub struct ListingData {
    pub rows: HashMap<Address, ListingRow>,
}

impl ListingData {
    pub fn add(&mut self, addr: Address, row: ListingRow) { self.rows.insert(addr, row); }
    pub fn get(&self, addr: &Address) -> Option<&ListingRow> { self.rows.get(addr) }

    pub fn add_demo_rows(&mut self) {
        use crate::listing::InstructionMnemonic;
        let rows = [
            (Address::new(0x1000), "push", "rbp"),
            (Address::new(0x1001), "mov", "rbp, rsp"),
            (Address::new(0x1004), "sub", "rsp, 0x20"),
            (Address::new(0x1008), "mov", "DWORD PTR [rbp-0x4], edi"),
            (Address::new(0x100b), "mov", "QWORD PTR [rbp-0x10], rsi"),
            (Address::new(0x100f), "lea", "rdi, [rip+0x2000]"),
            (Address::new(0x1016), "call", "0x2000"),
            (Address::new(0x101b), "mov", "eax, 0x0"),
            (Address::new(0x1020), "leave", ""),
            (Address::new(0x1021), "ret", ""),
        ];
        for (addr, mn, ops) in &rows {
            self.rows.insert(*addr, ListingRow {
                address: *addr,
                bytes: vec![addr.offset as u8, 0, 0, 0],
                label: if addr.offset == 0x1000 { Some("main".into()) } else { None },
                mnemonic: InstructionMnemonic::new(*mn),
                operands: ops.to_string(),
                full_instruction: if ops.is_empty() { mn.to_string() } else { format!("{} {}", mn, ops) },
                comment: None,
            });
        }
    }
}

// ============================================================================
// DomainFile
// ============================================================================

pub struct DomainFile {
    path: String,
    pub name: String,
    parent_path: String,
    domain_type: String,
    file_id: u64,
    version: u32,
    min_version: u32,
    latest_version: u32,
    checked_out: bool,
    checked_out_by: Option<String>,
    created_at: SystemTime,
    last_modified: SystemTime,
    read_only: bool,
    exists: bool,
    changed: bool,
    open_object: Option<Arc<RwLock<dyn DomainObject>>>,
    consumers: HashSet<String>,
}

impl DomainFile {
    pub fn new(path: impl Into<String>, name: impl Into<String>, domain_type: impl Into<String>, file_id: u64) -> Self {
        let path_str: String = path.into();
        let name_str: String = name.into();
        let parent = {
            let trimmed = path_str.trim_end_matches('/');
            match trimmed.rfind('/') { Some(pos) => trimmed[..pos].to_string(), None => "/".to_string() }
        };
        Self {
            path: path_str, name: name_str, parent_path: parent, domain_type: domain_type.into(),
            file_id, version: 1, min_version: 1, latest_version: 1,
            checked_out: false, checked_out_by: None,
            created_at: SystemTime::now(), last_modified: SystemTime::now(),
            read_only: false, exists: false, changed: false,
            open_object: None, consumers: HashSet::new(),
        }
    }

    pub fn get_pathname(&self) -> &str { &self.path }
    pub fn get_name(&self) -> &str { &self.name }
    pub fn get_parent_path(&self) -> &str { &self.parent_path }
    pub fn get_domain_type(&self) -> &str { &self.domain_type }
    pub fn get_file_id(&self) -> u64 { self.file_id }
    pub fn get_version(&self) -> u32 { self.version }
    pub fn set_version(&mut self, v: u32) { self.version = v; }
    pub fn get_latest_version(&self) -> u32 { self.latest_version }
    pub fn exists(&self) -> bool { self.exists }
    pub fn set_exists(&mut self, e: bool) { self.exists = e; }
    pub fn is_checked_out(&self) -> bool { self.checked_out }

    pub fn checkout(&mut self, user_id: impl Into<String>) -> Result<()> {
        if self.checked_out {
            return Err(GhidraError::NotSupported(format!("File '{}' is already checked out", self.name)));
        }
        self.checked_out = true; self.checked_out_by = Some(user_id.into()); Ok(())
    }

    pub fn checkin(&mut self) -> Result<()> {
        self.checked_out = false; self.checked_out_by = None;
        self.version += 1; self.latest_version = self.version;
        self.changed = false; self.last_modified = SystemTime::now(); Ok(())
    }

    pub fn undo_checkout(&mut self) -> Result<()> { self.checked_out = false; self.checked_out_by = None; self.changed = false; Ok(()) }
    pub fn is_read_only(&self) -> bool { self.read_only }
    pub fn set_read_only(&mut self, ro: bool) { self.read_only = ro; }
    pub fn is_changed(&self) -> bool { self.changed }
    pub fn set_changed(&mut self, c: bool) { self.changed = c; if c { self.last_modified = SystemTime::now(); } }
    pub fn is_open(&self) -> bool { self.open_object.is_some() }
    pub fn get_domain_object(&self) -> Option<&Arc<RwLock<dyn DomainObject>>> { self.open_object.as_ref() }
    pub fn read_domain_object(&self) -> Option<std::sync::RwLockReadGuard<'_, dyn DomainObject>> { self.open_object.as_ref().and_then(|arc| arc.read().ok()) }
    pub fn add_consumer(&mut self, c: impl Into<String>) { self.consumers.insert(c.into()); }
    pub fn release_consumer(&mut self, c: &str) -> bool { self.consumers.remove(c); self.consumers.is_empty() }
    pub fn get_consumers(&self) -> &HashSet<String> { &self.consumers }
    pub fn can_close(&self) -> bool { self.consumers.is_empty() }
    pub fn set_domain_object(&mut self, obj: Arc<RwLock<dyn DomainObject>>) { self.open_object = Some(obj); }
    pub fn take_domain_object(&mut self) -> Option<Arc<RwLock<dyn DomainObject>>> { self.open_object.take() }

    pub fn save(&self) -> Result<()> {
        if let Some(obj) = &self.open_object { if let Ok(obj) = obj.read() { obj.save()?; } }
        Ok(())
    }

    pub fn delete(&mut self) { self.exists = false; self.consumers.clear(); self.open_object = None; }
    pub fn get_created_at(&self) -> SystemTime { self.created_at }
    pub fn get_last_modified(&self) -> SystemTime { self.last_modified }
}

impl Clone for DomainFile {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(), name: self.name.clone(), parent_path: self.parent_path.clone(),
            domain_type: self.domain_type.clone(), file_id: self.file_id,
            version: self.version, min_version: self.min_version, latest_version: self.latest_version,
            checked_out: self.checked_out, checked_out_by: self.checked_out_by.clone(),
            created_at: self.created_at, last_modified: self.last_modified,
            read_only: self.read_only, exists: self.exists, changed: self.changed,
            open_object: None, consumers: self.consumers.clone(),
        }
    }
}

impl fmt::Debug for DomainFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainFile")
            .field("path", &self.path).field("name", &self.name)
            .field("domain_type", &self.domain_type).field("file_id", &self.file_id)
            .field("version", &self.version).field("checked_out", &self.checked_out)
            .field("exists", &self.exists).field("changed", &self.changed)
            .finish()
    }
}

// ============================================================================
// ProgramChangeRecord / ProgramChangeRecordSet
// ============================================================================

#[derive(Debug, Clone)]
pub struct ProgramChangeRecord {
    pub change_type: DomainObjectChangeType,
    pub affected_address: Option<Address>,
    pub start: Option<Address>,
    pub end: Option<Address>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub description: Option<String>,
    pub timestamp: SystemTime,
}

impl ProgramChangeRecord {
    pub fn new(change_type: DomainObjectChangeType) -> Self {
        Self { change_type, affected_address: None, start: None, end: None,
            old_value: None, new_value: None, description: None, timestamp: SystemTime::now() }
    }
    pub fn with_address(mut self, addr: Address) -> Self { self.affected_address = Some(addr); self }
    pub fn with_range(mut self, start: Address, end: Address) -> Self { self.start = Some(start); self.end = Some(end); self }
    pub fn with_values(mut self, old: impl Into<String>, new: impl Into<String>) -> Self { self.old_value = Some(old.into()); self.new_value = Some(new.into()); self }
    pub fn with_description(mut self, desc: impl Into<String>) -> Self { self.description = Some(desc.into()); self }
}

#[derive(Debug, Clone, Default)]
pub struct ProgramChangeRecordSet {
    pub records: Vec<ProgramChangeRecord>,
    pub summary: Option<String>,
}

impl ProgramChangeRecordSet {
    pub fn new() -> Self { Self::default() }
    pub fn add(&mut self, r: ProgramChangeRecord) { self.records.push(r); }
    pub fn len(&self) -> usize { self.records.len() }
    pub fn is_empty(&self) -> bool { self.records.is_empty() }
    pub fn with_summary(mut self, s: impl Into<String>) -> Self { self.summary = Some(s.into()); self }
    pub fn iter(&self) -> impl Iterator<Item = &ProgramChangeRecord> { self.records.iter() }
}

// ============================================================================
// DBHandle trait / InMemoryDBHandle
// ============================================================================

pub trait DBHandle: fmt::Debug + Send + Sync {
    fn begin_transaction(&self, id: u64) -> Result<()>;
    fn commit_transaction(&self, id: u64) -> Result<()>;
    fn rollback_transaction(&self, id: u64) -> Result<()>;
    fn is_transaction_active(&self) -> bool;
    fn flush(&self) -> Result<()>;
    fn close(&self) -> Result<()>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryDBHandle { transaction_active: bool }

impl InMemoryDBHandle {
    pub fn new() -> Self { Self::default() }
}

impl DBHandle for InMemoryDBHandle {
    fn begin_transaction(&self, _id: u64) -> Result<()> { Ok(()) }
    fn commit_transaction(&self, _id: u64) -> Result<()> { Ok(()) }
    fn rollback_transaction(&self, _id: u64) -> Result<()> { Ok(()) }
    fn is_transaction_active(&self) -> bool { self.transaction_active }
    fn flush(&self) -> Result<()> { Ok(()) }
    fn close(&self) -> Result<()> { Ok(()) }
}

// ============================================================================
// ProgramDB
// ============================================================================

#[derive(Debug)]
pub struct ProgramDB {
    program: Program,
    domain_file: Option<Arc<RwLock<DomainFile>>>,
    in_transaction: bool,
    next_transaction_id: u64,
    db_handle: Option<Arc<dyn DBHandle>>,
    closed: bool,
    saved: bool,
    current_change_records: Vec<ProgramChangeRecord>,
    db_listeners: Vec<Box<dyn DomainObjectListener>>,
}

impl ProgramDB {
    pub fn new(name: impl Into<String>, image_base: Address, db_handle: Option<Arc<dyn DBHandle>>) -> Self {
        Self {
            program: Program::new(name, image_base),
            domain_file: None, in_transaction: false, next_transaction_id: 1,
            db_handle, closed: false, saved: true,
            current_change_records: Vec::new(), db_listeners: Vec::new(),
        }
    }

    pub fn from_program(program: Program) -> Self {
        Self { program, domain_file: None, in_transaction: false, next_transaction_id: 1,
            db_handle: None, closed: false, saved: true,
            current_change_records: Vec::new(), db_listeners: Vec::new() }
    }

    pub fn get_program(&self) -> &Program { &self.program }
    pub fn get_program_mut(&mut self) -> &mut Program { &mut self.program }
    pub fn into_program(self) -> Program { self.program }
    pub fn get_domain_file(&self) -> Option<&Arc<RwLock<DomainFile>>> { self.domain_file.as_ref() }
    pub fn set_domain_file(&mut self, file: Arc<RwLock<DomainFile>>) { self.domain_file = Some(file); }
    pub fn get_db_handle(&self) -> Option<&Arc<dyn DBHandle>> { self.db_handle.as_ref() }
    pub fn set_db_handle(&mut self, handle: Arc<dyn DBHandle>) { self.db_handle = Some(handle); }

    pub fn begin_transaction(&mut self) -> u64 {
        let id = self.next_transaction_id; self.next_transaction_id += 1;
        self.in_transaction = true; self.current_change_records.clear();
        self.program.begin_transaction();
        if let Some(db) = &self.db_handle { let _ = db.begin_transaction(id); }
        id
    }

    pub fn end_transaction(&mut self, id: u64, commit: bool) -> Result<()> {
        if !self.in_transaction { return Err(GhidraError::NotSupported("No transaction active".into())); }
        if commit {
            if let Some(db) = &self.db_handle { db.commit_transaction(id)?; }
            let _cs = self.program.end_transaction(); self.saved = false;
        } else {
            if let Some(db) = &self.db_handle { db.rollback_transaction(id)?; }
        }
        self.in_transaction = false; self.fire_db_events(); self.current_change_records.clear();
        Ok(())
    }

    pub fn is_transaction_active(&self) -> bool { self.in_transaction }

    pub fn with_transaction<F, R>(&mut self, f: F) -> Result<(R, ProgramChangeSet)>
    where F: FnOnce(&mut Self) -> Result<R> {
        let tx_id = self.begin_transaction();
        match f(self) {
            Ok(result) => { self.end_transaction(tx_id, true)?; let cs = self.program.end_transaction(); self.program.begin_transaction(); Ok((result, cs)) }
            Err(e) => { self.end_transaction(tx_id, false)?; Err(e) }
        }
    }

    pub fn record_change(&mut self, r: ProgramChangeRecord) { self.current_change_records.push(r); }

    pub fn save(&mut self) -> Result<()> {
        if let Some(db) = &self.db_handle { db.flush()?; }
        self.program.mark_saved(); self.saved = true;
        if let Some(df) = &self.domain_file { if let Ok(mut file) = df.write() { file.checkin()?; } }
        Ok(())
    }

    pub fn save_as(&mut self, _new_path: &str, new_name: &str) -> Result<()> { self.program.set_name(new_name); self.save() }
    pub fn is_changed(&self) -> bool { !self.saved }
    pub fn set_saved(&mut self, s: bool) { self.saved = s; }

    pub fn close(&mut self) -> Result<()> {
        if let Some(db) = &self.db_handle { db.close()?; }
        if let Some(df) = &self.domain_file { if let Ok(mut file) = df.write() { file.take_domain_object(); } }
        self.closed = true; self.db_listeners.clear(); Ok(())
    }

    pub fn is_closed(&self) -> bool { self.closed }

    fn fire_db_events(&mut self) {
        let ev = DomainObjectChangeEvent { event_type: DomainObjectChangeType::CodeChanged, affected_addresses: Vec::new() };
        for listener in &self.db_listeners { listener.domain_object_changed(&ev); }
    }
}
