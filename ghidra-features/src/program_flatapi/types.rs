//! Shared type definitions for the Flat Program API.
//!
//! Ported from `ghidra.program.flatapi.FlatProgramAPI` and its related
//! Ghidra model types (`CommentType`, `SourceType`, `FlowType`, etc.).

use std::collections::HashMap;
use std::fmt;

// ============================================================================
// Address
// ============================================================================

/// A program address in a specific address space.
///
/// Ported from `ghidra.program.model.address.Address`.  In this flat
/// representation the address space is identified by a string name and
/// the offset is a 64-bit unsigned integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    /// Name of the address space (e.g. `"ram"`, `"register"`, `"OTHER"`).
    pub space_name: &'static str,
    /// Numeric offset within the space.
    pub offset: u64,
}

impl Address {
    /// Create a new address in the default `"ram"` space.
    pub const fn new(offset: u64) -> Self {
        Self {
            space_name: "ram",
            offset,
        }
    }

    /// Create an address in a named space.
    pub fn in_space(space: &'static str, offset: u64) -> Self {
        Self {
            space_name: space,
            offset,
        }
    }

    /// Return an address advanced by `delta` bytes.
    pub fn add(&self, delta: u64) -> Self {
        Self {
            space_name: self.space_name,
            offset: self.offset.wrapping_add(delta),
        }
    }

    /// Return an address moved back by `delta` bytes.
    pub fn subtract(&self, delta: u64) -> Self {
        Self {
            space_name: self.space_name,
            offset: self.offset.wrapping_sub(delta),
        }
    }

    /// Check whether this address is in the default `"ram"` space.
    pub fn is_default_space(&self) -> bool {
        self.space_name == "ram"
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.space_name == "ram" {
            write!(f, "{:#x}", self.offset)
        } else {
            write!(f, "{}:{:#x}", self.space_name, self.offset)
        }
    }
}

impl From<u64> for Address {
    fn from(offset: u64) -> Self {
        Address::new(offset)
    }
}

// ============================================================================
// AddressSet / AddressRange
// ============================================================================

/// A contiguous range of addresses `[min, max]` (inclusive on both ends).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRange {
    pub min: Address,
    pub max: Address,
}

impl AddressRange {
    pub fn new(min: Address, max: Address) -> Self {
        assert!(min <= max, "min must be <= max");
        Self { min, max }
    }

    /// Number of bytes in this range (inclusive).
    pub fn length(&self) -> u64 {
        self.max.offset - self.min.offset + 1
    }

    pub fn contains(&self, addr: Address) -> bool {
        addr.space_name == self.min.space_name && addr.offset >= self.min.offset && addr.offset <= self.max.offset
    }
}

/// A mutable set of address ranges.
///
/// Ported from `ghidra.program.model.address.AddressSet`.
#[derive(Debug, Clone, Default)]
pub struct AddressSet {
    ranges: Vec<AddressRange>,
}

impl AddressSet {
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Add a range to the set, merging overlapping/adjacent ranges.
    pub fn add_range(&mut self, min: Address, max: Address) {
        let new_range = AddressRange::new(min, max);
        self.ranges.push(new_range);
        self.ranges.sort_by_key(|r| r.min);
        self.merge_overlapping();
    }

    fn merge_overlapping(&mut self) {
        if self.ranges.len() <= 1 {
            return;
        }
        let mut merged: Vec<AddressRange> = Vec::new();
        for range in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut() {
                if last.max.offset >= range.min.offset {
                    if range.max.offset > last.max.offset {
                        last.max = range.max;
                    }
                    continue;
                }
            }
            merged.push(range);
        }
        self.ranges = merged;
    }

    /// Compute the intersection with another address set.
    pub fn intersect(&self, other: &AddressSet) -> AddressSet {
        let mut result = AddressSet::new();
        for a in &self.ranges {
            for b in &other.ranges {
                if a.min.offset <= b.max.offset && b.min.offset <= a.max.offset {
                    let lo = a.min.offset.max(b.min.offset);
                    let hi = a.max.offset.min(b.max.offset);
                    result.ranges.push(AddressRange::new(
                        Address::new(lo),
                        Address::new(hi),
                    ));
                }
            }
        }
        result
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn num_address_ranges(&self) -> usize {
        self.ranges.len()
    }

    pub fn ranges(&self) -> &[AddressRange] {
        &self.ranges
    }

    pub fn contains_address(&self, addr: Address) -> bool {
        self.ranges.iter().any(|r| r.contains(addr))
    }
}

/// Iterator over address ranges in an `AddressSet`.
pub struct AddressRangeIterator<'a> {
    inner: std::slice::Iter<'a, AddressRange>,
}

impl<'a> Iterator for AddressRangeIterator<'a> {
    type Item = &'a AddressRange;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl AddressSet {
    pub fn iter_ranges(&self) -> AddressRangeIterator<'_> {
        AddressRangeIterator {
            inner: self.ranges.iter(),
        }
    }
}

// ============================================================================
// CommentType
// ============================================================================

/// The type of comment attached to a code unit.
///
/// Ported from `ghidra.program.model.listing.CommentType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    /// Plate (header) comment -- appears above the code unit.
    Plate,
    /// Pre-comment -- appears just before the code unit.
    Pre,
    /// Post-comment -- appears just after the code unit.
    Post,
    /// End-of-line comment -- appears on the same line as the code unit.
    Eol,
    /// Repeatable comment -- propagated to every reference site.
    Repeatable,
}

impl CommentType {
    /// All five comment types.
    pub const ALL: [CommentType; 5] = [
        CommentType::Plate,
        CommentType::Pre,
        CommentType::Post,
        CommentType::Eol,
        CommentType::Repeatable,
    ];

    /// Integer encoding used by Ghidra's Java API.
    pub fn to_int(&self) -> u32 {
        match self {
            CommentType::Plate => 0,
            CommentType::Pre => 1,
            CommentType::Post => 2,
            CommentType::Eol => 3,
            CommentType::Repeatable => 4,
        }
    }

    pub fn from_int(v: u32) -> Option<Self> {
        match v {
            0 => Some(CommentType::Plate),
            1 => Some(CommentType::Pre),
            2 => Some(CommentType::Post),
            3 => Some(CommentType::Eol),
            4 => Some(CommentType::Repeatable),
            _ => None,
        }
    }
}

impl fmt::Display for CommentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommentType::Plate => write!(f, "PLATE"),
            CommentType::Pre => write!(f, "PRE"),
            CommentType::Post => write!(f, "POST"),
            CommentType::Eol => write!(f, "EOL"),
            CommentType::Repeatable => write!(f, "REPEATABLE"),
        }
    }
}

// ============================================================================
// SourceType
// ============================================================================

/// The origin of a symbol or label.
///
/// Ported from `ghidra.program.model.symbol.SourceType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceType {
    /// Created by the user.
    UserDefined,
    /// Created by an analysis pass.
    Analysis,
    /// A default/imported symbol.
    Default,
}

impl SourceType {
    pub fn to_int(&self) -> u32 {
        match self {
            SourceType::UserDefined => 0,
            SourceType::Analysis => 1,
            SourceType::Default => 2,
        }
    }

    pub fn from_int(v: u32) -> Option<Self> {
        match v {
            0 => Some(SourceType::UserDefined),
            1 => Some(SourceType::Analysis),
            2 => Some(SourceType::Default),
            _ => None,
        }
    }
}

impl Default for SourceType {
    fn default() -> Self {
        SourceType::Default
    }
}

impl fmt::Display for SourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceType::UserDefined => write!(f, "USER_DEFINED"),
            SourceType::Analysis => write!(f, "ANALYSIS"),
            SourceType::Default => write!(f, "DEFAULT"),
        }
    }
}

// ============================================================================
// FlowType / RefType
// ============================================================================

/// The type of a code flow or reference.
///
/// Ported from `ghidra.program.model.symbol.FlowType` / `RefType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowType {
    /// Unconditional fall-through.
    FallThrough,
    /// Unconditional jump.
    UnconditionalJump,
    /// Conditional jump.
    ConditionalJump,
    /// Unconditional call.
    UnconditionalCall,
    /// Conditional call.
    ConditionalCall,
    /// Computed (indirect) jump.
    ComputedJump,
    /// Computed (indirect) call.
    ComputedCall,
    /// Return instruction.
    Terminal,
    /// Data reference (not a flow).
    Data,
}

impl FlowType {
    pub fn is_call(&self) -> bool {
        matches!(
            self,
            FlowType::UnconditionalCall
                | FlowType::ConditionalCall
                | FlowType::ComputedCall
        )
    }

    pub fn is_jump(&self) -> bool {
        matches!(
            self,
            FlowType::UnconditionalJump
                | FlowType::ConditionalJump
                | FlowType::ComputedJump
        )
    }

    pub fn is_computed(&self) -> bool {
        matches!(self, FlowType::ComputedJump | FlowType::ComputedCall)
    }

    pub fn is_conditional(&self) -> bool {
        matches!(
            self,
            FlowType::ConditionalJump | FlowType::ConditionalCall
        )
    }

    /// True if this flow type causes execution to leave the current address
    /// without falling through.
    pub fn is_break(&self) -> bool {
        self.is_jump() || matches!(self, FlowType::Terminal)
    }
}

impl fmt::Display for FlowType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowType::FallThrough => write!(f, "f"),
            FlowType::UnconditionalJump => write!(f, "j"),
            FlowType::ConditionalJump => write!(f, "c"),
            FlowType::UnconditionalCall => write!(f, "C"),
            FlowType::ConditionalCall => write!(f, "cC"),
            FlowType::ComputedJump => write!(f, "ij"),
            FlowType::ComputedCall => write!(f, "iC"),
            FlowType::Terminal => write!(f, "t"),
            FlowType::Data => write!(f, "d"),
        }
    }
}

/// Alias used in `createMemoryReference` / `addInstructionXref`.
pub type RefType = FlowType;

// ============================================================================
// SymbolType
// ============================================================================

/// The kind of symbol.
///
/// Ported from `ghidra.program.model.symbol.SymbolType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolType {
    Label,
    Function,
    Class,
    Namespace,
    Library,
    Global,
    External,
    Other(u32),
}

impl SymbolType {
    pub fn is_namespace(&self) -> bool {
        matches!(
            self,
            SymbolType::Namespace | SymbolType::Class | SymbolType::Library
        )
    }
}

// ============================================================================
// Symbol
// ============================================================================

/// A named symbol (label, function name, etc.) at a program address.
///
/// Ported from `ghidra.program.model.symbol.Symbol`.
#[derive(Debug, Clone)]
pub struct Symbol {
    pub address: Address,
    pub name: String,
    pub symbol_type: SymbolType,
    pub source: SourceType,
    pub namespace_id: u32,
    pub is_primary: bool,
    pub id: u64,
}

impl Symbol {
    pub fn new(
        address: Address,
        name: impl Into<String>,
        symbol_type: SymbolType,
        source: SourceType,
    ) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self {
            address,
            name: name.into(),
            symbol_type,
            source,
            namespace_id: 0,
            is_primary: false,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    pub fn is_primary(&self) -> bool {
        self.is_primary
    }
}

// ============================================================================
// Namespace / GhidraClass
// ============================================================================

/// A namespace is a container for symbols (like a folder in a file system).
///
/// Ported from `ghidra.program.model.symbol.Namespace`.
#[derive(Debug, Clone)]
pub struct Namespace {
    pub id: u32,
    pub name: String,
    pub parent_id: Option<u32>,
}

impl Namespace {
    pub fn global() -> Self {
        Self {
            id: 0,
            name: String::from("Global"),
            parent_id: None,
        }
    }
}

/// A Ghidra class namespace -- a namespace that can be used for OOP classes.
///
/// Ported from `ghidra.program.model.symbol.GhidraClass`.
pub type GhidraClass = Namespace;

// ============================================================================
// Scalar
// ============================================================================

/// A scalar (integer constant) operand in a program.
///
/// Ported from `ghidra.program.model.scalar.Scalar`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scalar {
    bit_length: u32,
    value: u64,
    signed: bool,
}

impl Scalar {
    pub fn new(bit_length: u32, value: u64, signed: bool) -> Self {
        Self {
            bit_length,
            value,
            signed,
        }
    }

    pub fn unsigned_value(&self) -> u64 {
        self.value
    }

    pub fn signed_value(&self) -> i64 {
        if self.signed {
            // sign-extend
            let shift = 64 - self.bit_length;
            ((self.value as i64) << shift) >> shift
        } else {
            self.value as i64
        }
    }

    pub fn bit_length(&self) -> u32 {
        self.bit_length
    }

    pub fn value(&self) -> u64 {
        self.value
    }
}

// ============================================================================
// Bookmark
// ============================================================================

/// A bookmark at an address.
///
/// Ported from `ghidra.program.model.listing.Bookmark`.
#[derive(Debug, Clone)]
pub struct Bookmark {
    pub address: Address,
    pub bookmark_type: BookmarkTypeStr,
    pub category: String,
    pub note: String,
    pub id: u64,
}

impl Bookmark {
    pub fn set(&mut self, category: &str, note: &str) {
        self.category = category.to_string();
        self.note = note.to_string();
    }
}

/// Bookmark type string marker.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BookmarkTypeStr(pub String);

impl BookmarkTypeStr {
    pub const NOTE: &'static str = "NOTE";
    pub const INFO: &'static str = "Info";
    pub const WARNING: &'static str = "Warning";
    pub const ERROR: &'static str = "Error";
}

// ============================================================================
// MemoryBlock
// ============================================================================

/// A memory block in the program's address space.
///
/// Ported from `ghidra.program.model.mem.MemoryBlock`.
#[derive(Debug, Clone)]
pub struct MemoryBlock {
    pub name: String,
    pub start: Address,
    pub length: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub initialized: bool,
    pub overlay: bool,
    pub data: Vec<u8>,
}

impl MemoryBlock {
    /// Create an uninitialized block.
    pub fn new_uninitialized(name: impl Into<String>, start: Address, length: u64) -> Self {
        Self {
            name: name.into(),
            start,
            length,
            read: true,
            write: true,
            execute: false,
            initialized: false,
            overlay: false,
            data: vec![0u8; length as usize],
        }
    }

    /// Create an initialized block from byte data.
    pub fn new_initialized(
        name: impl Into<String>,
        start: Address,
        data: Vec<u8>,
        overlay: bool,
    ) -> Self {
        let length = data.len() as u64;
        Self {
            name: name.into(),
            start,
            length,
            read: true,
            write: false,
            execute: false,
            initialized: true,
            overlay,
            data,
        }
    }

    /// Create an initialized block of `length` bytes, filled from `input`.
    pub fn new_initialized_with_length(
        name: impl Into<String>,
        start: Address,
        input: &[u8],
        length: u64,
        overlay: bool,
    ) -> Self {
        let mut data = vec![0u8; length as usize];
        let copy_len = input.len().min(length as usize);
        data[..copy_len].copy_from_slice(&input[..copy_len]);
        Self {
            name: name.into(),
            start,
            length,
            read: true,
            write: false,
            execute: false,
            initialized: true,
            overlay,
            data,
        }
    }

    pub fn contains(&self, addr: Address) -> bool {
        addr.space_name == self.start.space_name
            && addr.offset >= self.start.offset
            && addr.offset < self.start.offset + self.length
    }

    pub fn end(&self) -> Address {
        self.start.add(self.length)
    }
}

// ============================================================================
// Reference
// ============================================================================

/// A cross-reference (reference) between two addresses.
///
/// Ported from `ghidra.program.model.symbol.Reference`.
#[derive(Debug, Clone)]
pub struct Reference {
    pub from_address: Address,
    pub to_address: Address,
    pub op_index: i32,
    pub flow_type: FlowType,
    pub source: SourceType,
    pub is_primary: bool,
}

impl Reference {
    pub fn new(
        from: Address,
        to: Address,
        op_index: i32,
        flow_type: FlowType,
        source: SourceType,
    ) -> Self {
        Self {
            from_address: from,
            to_address: to,
            op_index,
            flow_type,
            source,
            is_primary: false,
        }
    }

    pub fn get_from_address(&self) -> Address {
        self.from_address
    }

    pub fn get_to_address(&self) -> Address {
        self.to_address
    }

    pub fn get_op_index(&self) -> i32 {
        self.op_index
    }
}

// ============================================================================
// Equate
// ============================================================================

/// A named constant (equate) applied to an operand value.
///
/// Ported from `ghidra.program.model.symbol.Equate`.
#[derive(Debug, Clone)]
pub struct Equate {
    pub name: String,
    pub value: u64,
    pub references: Vec<(Address, i32)>,
}

impl Equate {
    pub fn new(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value,
            references: Vec::new(),
        }
    }

    pub fn add_reference(&mut self, address: Address, op_index: i32) {
        self.references.push((address, op_index));
    }

    pub fn remove_reference(&mut self, address: Address, op_index: i32) {
        self.references
            .retain(|(a, o)| *a != address || *o != op_index);
    }

    pub fn get_reference_count(&self) -> usize {
        self.references.len()
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_value(&self) -> u64 {
        self.value
    }
}

// ============================================================================
// DataType
// ============================================================================

/// A data type describes how bytes are interpreted.
///
/// Ported from `ghidra.program.model.data.DataType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataType {
    pub name: String,
    pub length: usize,
    pub category: String,
}

impl DataType {
    pub fn new(name: impl Into<String>, length: usize) -> Self {
        Self {
            name: name.into(),
            length,
            category: String::new(),
        }
    }

    pub fn with_category(mut self, cat: impl Into<String>) -> Self {
        self.category = cat.into();
        self
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_length(&self) -> usize {
        self.length
    }

    pub fn is_equivalent(&self, other: &DataType) -> bool {
        self.name == other.name && self.length == other.length
    }
}

/// Well-known built-in data types.
impl DataType {
    pub fn byte() -> Self {
        DataType::new("byte", 1)
    }
    pub fn word() -> Self {
        DataType::new("word", 2)
    }
    pub fn dword() -> Self {
        DataType::new("dword", 4)
    }
    pub fn qword() -> Self {
        DataType::new("qword", 8)
    }
    pub fn float_type() -> Self {
        DataType::new("float", 4)
    }
    pub fn double_type() -> Self {
        DataType::new("double", 8)
    }
    pub fn char_type() -> Self {
        DataType::new("char", 1)
    }
    pub fn terminated_string() -> Self {
        DataType::new("string", -1_isize as usize)
    }
    pub fn string_with_length(length: usize) -> Self {
        DataType::new("string", length)
    }
    pub fn terminated_unicode() -> Self {
        DataType::new("unicode", -1_isize as usize)
    }
}

// ============================================================================
// Instruction (code unit)
// ============================================================================

/// A disassembled instruction.
///
/// Ported from `ghidra.program.model.listing.Instruction`.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: Address,
    pub mnemonic: String,
    pub length: usize,
    pub bytes: Vec<u8>,
    pub num_operands: usize,
    pub operands: Vec<Vec<OperandObject>>,
    pub flow_type: FlowType,
    pub fall_through: Option<Address>,
}

impl Instruction {
    pub fn get_mnemonic_string(&self) -> &str {
        &self.mnemonic
    }

    pub fn get_min_address(&self) -> Address {
        self.address
    }

    pub fn get_max_address(&self) -> Address {
        self.address.add(self.length as u64 - 1)
    }

    pub fn get_num_operands(&self) -> usize {
        self.num_operands
    }

    pub fn get_op_objects(&self, op_index: usize) -> &[OperandObject] {
        if op_index < self.operands.len() {
            &self.operands[op_index]
        } else {
            &[]
        }
    }

    pub fn get_flow_type(&self) -> FlowType {
        self.flow_type
    }

    pub fn get_fall_through(&self) -> Option<Address> {
        self.fall_through
    }
}

// ============================================================================
// Data (code unit)
// ============================================================================

/// A defined data item at an address.
///
/// Ported from `ghidra.program.model.listing.Data`.
#[derive(Debug, Clone)]
pub struct Data {
    pub address: Address,
    pub data_type: DataType,
    pub value: Option<DataValue>,
    pub bytes: Vec<u8>,
}

impl Data {
    pub fn get_mnemonic_string(&self) -> &str {
        &self.data_type.name
    }

    pub fn get_min_address(&self) -> Address {
        self.address
    }

    pub fn get_max_address(&self) -> Address {
        self.address.add(self.data_type.length as u64 - 1)
    }

    pub fn get_value(&self) -> Option<&DataValue> {
        self.value.as_ref()
    }

    pub fn get_data_type(&self) -> &DataType {
        &self.data_type
    }

    pub fn get_length(&self) -> usize {
        self.data_type.length
    }
}

/// The value of a data item.
#[derive(Debug, Clone)]
pub enum DataValue {
    Byte(u8),
    Word(u16),
    DWord(u32),
    QWord(u64),
    Float(f32),
    Double(f64),
    Char(char),
    String(String),
    Scalar(Scalar),
}

impl DataValue {
    pub fn as_scalar(&self) -> Option<Scalar> {
        match self {
            DataValue::Byte(v) => Some(Scalar::new(8, *v as u64, false)),
            DataValue::Word(v) => Some(Scalar::new(16, *v as u64, false)),
            DataValue::DWord(v) => Some(Scalar::new(32, *v as u64, false)),
            DataValue::QWord(v) => Some(Scalar::new(64, *v, false)),
            DataValue::Scalar(s) => Some(*s),
            _ => None,
        }
    }

    pub fn to_string_value(&self) -> String {
        match self {
            DataValue::Byte(v) => format!("{}", v),
            DataValue::Word(v) => format!("{}", v),
            DataValue::DWord(v) => format!("{}", v),
            DataValue::QWord(v) => format!("{}", v),
            DataValue::Float(v) => format!("{}", v),
            DataValue::Double(v) => format!("{}", v),
            DataValue::Char(v) => format!("{}", v),
            DataValue::String(v) => v.clone(),
            DataValue::Scalar(s) => format!("{}", s.unsigned_value()),
        }
    }
}

impl fmt::Display for DataValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_value())
    }
}

// ============================================================================
// OperandObject
// ============================================================================

/// An object that appears as part of an instruction operand.
///
/// Ported from `ghidra.program.model.lang.Instruction.getOpObjects()`.
#[derive(Debug, Clone)]
pub enum OperandObject {
    Address(Address),
    Scalar(Scalar),
    Register(Register),
    String(String),
}

impl fmt::Display for OperandObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperandObject::Address(a) => write!(f, "{}", a),
            OperandObject::Scalar(s) => write!(f, "{:#x}", s.unsigned_value()),
            OperandObject::Register(r) => write!(f, "{}", r.name),
            OperandObject::String(s) => write!(f, "{}", s),
        }
    }
}

// ============================================================================
// Register
// ============================================================================

/// A processor register.
#[derive(Debug, Clone)]
pub struct Register {
    pub name: String,
    pub address: Address,
    pub bit_length: u32,
}

impl Register {
    pub fn new(name: impl Into<String>, address: Address, bit_length: u32) -> Self {
        Self {
            name: name.into(),
            address,
            bit_length,
        }
    }
}

// ============================================================================
// FoundString
// ============================================================================

/// A string found during memory search.
///
/// Ported from `ghidra.program.util.string.FoundString`.
#[derive(Debug, Clone)]
pub struct FoundString {
    pub address: Address,
    pub length: usize,
    pub string_type: StringType,
    pub value: String,
}

/// Type of string found in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringType {
    Ascii,
    Unicode,
    Pascal,
}

// ============================================================================
// ProgramFragment / ProgramModule
// ============================================================================

/// A fragment (leaf group) in the program tree.
///
/// Ported from `ghidra.program.model.listing.ProgramFragment`.
#[derive(Debug, Clone)]
pub struct ProgramFragment {
    pub name: String,
    pub min: Address,
    pub max: Address,
}

impl ProgramFragment {
    pub fn new(name: impl Into<String>, min: Address, max: Address) -> Self {
        Self {
            name: name.into(),
            min,
            max,
        }
    }

    pub fn move_to(&mut self, min: Address, max: Address) {
        self.min = min;
        self.max = max;
    }
}

/// A module (folder/group) in the program tree.
///
/// Ported from `ghidra.program.model.listing.ProgramModule`.
#[derive(Debug, Clone)]
pub struct ProgramModule {
    pub name: String,
    pub children: Vec<Group>,
}

/// An item in the program tree -- either a module or a fragment.
#[derive(Debug, Clone)]
pub enum Group {
    Module(ProgramModule),
    Fragment(ProgramFragment),
}

impl Group {
    pub fn name(&self) -> &str {
        match self {
            Group::Module(m) => &m.name,
            Group::Fragment(f) => &f.name,
        }
    }
}

// ============================================================================
// BookmarkManager
// ============================================================================

/// Manages bookmarks on a program.
///
/// Ported from `ghidra.program.model.listing.BookmarkManager`.
#[derive(Debug, Clone, Default)]
pub struct BookmarkManager {
    bookmarks: Vec<Bookmark>,
    next_id: u64,
}

impl BookmarkManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_bookmark(
        &mut self,
        address: Address,
        btype: &str,
        category: &str,
        note: &str,
    ) -> Bookmark {
        self.next_id += 1;
        let bm = Bookmark {
            address,
            bookmark_type: BookmarkTypeStr(btype.to_string()),
            category: category.to_string(),
            note: note.to_string(),
            id: self.next_id,
        };
        self.bookmarks.push(bm.clone());
        bm
    }

    pub fn get_bookmarks(&self, address: Address, btype: &str) -> Vec<&Bookmark> {
        self.bookmarks
            .iter()
            .filter(|b| b.address == address && b.bookmark_type.0 == btype)
            .collect()
    }

    pub fn remove_bookmark(&mut self, bookmark_id: u64) {
        self.bookmarks.retain(|b| b.id != bookmark_id);
    }
}

// ============================================================================
// EquateTable
// ============================================================================

/// Manages equates (named constants) on a program.
///
/// Ported from `ghidra.program.model.symbol.EquateTable`.
#[derive(Debug, Clone, Default)]
pub struct EquateTable {
    equates: HashMap<String, Equate>,
}

impl EquateTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_equate(&mut self, name: &str, value: u64) -> &mut Equate {
        self.equates
            .entry(name.to_string())
            .or_insert_with(|| Equate::new(name, value))
    }

    pub fn get_equate(&self, address: Address, op_index: i32, value: u64) -> Option<&Equate> {
        self.equates.values().find(|e| {
            e.value == value
                && e.references
                    .iter()
                    .any(|(a, o)| *a == address && *o == op_index)
        })
    }

    pub fn get_equates(&self, address: Address, op_index: i32) -> Vec<&Equate> {
        self.equates
            .values()
            .filter(|e| e.references.iter().any(|(a, o)| *a == address && *o == op_index))
            .collect()
    }

    pub fn remove_equate(&mut self, name: &str) {
        self.equates.remove(name);
    }

    pub fn get_equate_by_name(&self, name: &str) -> Option<&Equate> {
        self.equates.get(name)
    }
}

// ============================================================================
// SymbolTable
// ============================================================================

/// Manages symbols on a program.
///
/// Ported from `ghidra.program.model.symbol.SymbolTable`.
#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    symbols: Vec<Symbol>,
    namespaces: Vec<Namespace>,
    entry_points: Vec<Address>,
    next_namespace_id: u32,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
            namespaces: vec![Namespace::global()],
            entry_points: Vec::new(),
            next_namespace_id: 1,
        }
    }

    pub fn create_label(
        &mut self,
        address: Address,
        name: &str,
        namespace: Option<&Namespace>,
        source: SourceType,
    ) -> Symbol {
        let ns_id = namespace.map(|n| n.id).unwrap_or(0);
        let mut sym = Symbol::new(address, name, SymbolType::Label, source);
        sym.namespace_id = ns_id;
        sym.is_primary = true;
        self.symbols.push(sym.clone());
        sym
    }

    pub fn get_symbols_at(&self, address: Address) -> Vec<&Symbol> {
        self.symbols.iter().filter(|s| s.address == address).collect()
    }

    pub fn get_primary_symbol(&self, address: Address) -> Option<&Symbol> {
        self.symbols
            .iter()
            .find(|s| s.address == address && s.is_primary)
    }

    pub fn get_symbol(
        &self,
        name: &str,
        address: Address,
        namespace: &Namespace,
    ) -> Option<&Symbol> {
        self.symbols.iter().find(|s| {
            s.name == name && s.address == address && s.namespace_id == namespace.id
        })
    }

    pub fn get_symbols(&self, name: &str, namespace: &Namespace) -> Vec<&Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.name == name && s.namespace_id == namespace.id)
            .collect()
    }

    pub fn get_primary_symbol_iterator(&self, start: Address, forward: bool) -> Vec<&Symbol> {
        let mut syms: Vec<&Symbol> = self
            .symbols
            .iter()
            .filter(|s| s.is_primary && (if forward { s.address >= start } else { s.address <= start }))
            .collect();
        if forward {
            syms.sort_by_key(|s| s.address);
        } else {
            syms.sort_by(|a, b| b.address.cmp(&a.address));
        }
        syms
    }

    pub fn get_symbol_iterator(&self, start: Address, forward: bool) -> Vec<&Symbol> {
        let mut syms: Vec<&Symbol> = self
            .symbols
            .iter()
            .filter(|s| if forward { s.address >= start } else { s.address <= start })
            .collect();
        if forward {
            syms.sort_by_key(|s| s.address);
        } else {
            syms.sort_by(|a, b| b.address.cmp(&a.address));
        }
        syms
    }

    pub fn get_all_symbols(&self, forward: bool) -> Vec<&Symbol> {
        let mut syms: Vec<&Symbol> = self.symbols.iter().collect();
        if forward {
            syms.sort_by_key(|s| s.address);
        } else {
            syms.sort_by(|a, b| b.address.cmp(&a.address));
        }
        syms
    }

    pub fn get_global_functions(&self, name: &str) -> Vec<&Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.name == name && s.symbol_type == SymbolType::Function && s.namespace_id == 0)
            .collect()
    }

    pub fn remove_symbol(&mut self, address: Address, name: &str) -> bool {
        let len_before = self.symbols.len();
        self.symbols
            .retain(|s| !(s.address == address && s.name == name));
        self.symbols.len() != len_before
    }

    pub fn add_external_entry_point(&mut self, address: Address) {
        if !self.entry_points.contains(&address) {
            self.entry_points.push(address);
        }
    }

    pub fn remove_external_entry_point(&mut self, address: Address) {
        self.entry_points.retain(|a| *a != address);
    }

    pub fn get_namespace(&self, name: &str, parent: Option<&Namespace>) -> Option<&Namespace> {
        let parent_id = parent.map(|p| p.id);
        self.namespaces
            .iter()
            .find(|n| n.name == name && n.parent_id == parent_id)
    }

    pub fn create_namespace(
        &mut self,
        parent: Option<&Namespace>,
        name: &str,
    ) -> Namespace {
        let parent_id = parent.map(|p| p.id);
        self.next_namespace_id += 1;
        let ns = Namespace {
            id: self.next_namespace_id,
            name: name.to_string(),
            parent_id,
        };
        self.namespaces.push(ns.clone());
        ns
    }

    pub fn create_class(
        &mut self,
        parent: Option<&Namespace>,
        name: &str,
    ) -> GhidraClass {
        // Reuse create_namespace -- classes are namespaces in Ghidra
        self.create_namespace(parent, name)
    }

    pub fn set_primary(&mut self, address: Address, name: &str, namespace_id: u32) {
        // Clear primary flag for all symbols at this address
        for s in &mut self.symbols {
            if s.address == address {
                s.is_primary = false;
            }
        }
        // Set the target as primary
        for s in &mut self.symbols {
            if s.address == address && s.name == name && s.namespace_id == namespace_id {
                s.is_primary = true;
            }
        }
    }
}
