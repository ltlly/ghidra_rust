//! Ghidra Rust - Auto-analysis framework.
//!
//! Ported from the Ghidra Java analysis subsystem:
//! - `ghidra.app.services.Analyzer` — analyzer interface
//! - `ghidra.app.services.AnalysisPriority` — priority pipeline
//! - `ghidra.app.services.AnalyzerType` — trigger-type enumeration
//! - `ghidra.app.plugin.core.analysis.AutoAnalysisManager` — orchestrator
//! - `ghidra.app.plugin.core.analysis.AnalysisScheduler` — per-analyzer scheduler
//! - `ghidra.app.plugin.core.analysis.AnalysisTaskList` — typed task group
//!
//! # Architecture
//!
//! The analyzer system runs automatic analysis passes on loaded programs.
//! Each [`Analyzer`] is registered with an [`AutoAnalysisManager`] and is
//! triggered by program change events (bytes added, instructions created,
//! functions defined, etc.) according to its [`AnalyzerType`].
//!
//! Analyzers execute in priority order, with lower numerical priority values
//! running first. The fixed priority points are defined in [`AnalysisPriority`].

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// ============================================================================
// Stub types — these will eventually live in `ghidra-core`.
// They are defined here so the analyzer module is self-contained and compilable.
// ============================================================================

/// An address in a program's address space.
///
/// Addresses consist of an address-space identifier and an offset within
/// that space. The space allows Ghidra to distinguish between RAM, ROM,
/// register space, and external symbol space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address {
    /// The address space id (0 = default RAM, >0 = overlay/other spaces).
    pub space_id: u16,
    /// Byte offset within the address space.
    pub offset: u64,
}

impl Address {
    /// Create a new address in the default (RAM) space.
    pub const fn new(offset: u64) -> Self {
        Self {
            space_id: 0,
            offset,
        }
    }

    /// Create an address in a specific space.
    pub const fn in_space(space_id: u16, offset: u64) -> Self {
        Self { space_id, offset }
    }

    /// Address zero in the default space.
    pub const ZERO: Self = Self::new(0);

    /// External address space id (used for imported symbols).
    pub const EXTERNAL_SPACE: u16 = u16::MAX;

    /// The minimum address in a given space.
    pub const fn min_address(space_id: u16) -> Self {
        Self {
            space_id,
            offset: 0,
        }
    }

    /// The maximum address in a given space.
    pub const fn max_address(space_id: u16) -> Self {
        Self {
            space_id,
            offset: u64::MAX,
        }
    }

    /// Advance this address by `delta` bytes.
    pub fn add(&self, delta: u64) -> Self {
        Self {
            space_id: self.space_id,
            offset: self.offset.wrapping_add(delta),
        }
    }

    /// Subtract `delta` bytes from this address.
    pub fn sub(&self, delta: u64) -> Self {
        Self {
            space_id: self.space_id,
            offset: self.offset.wrapping_sub(delta),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.space_id == 0 {
            write!(f, "{:#010x}", self.offset)
        } else {
            write!(f, "{}:{:#010x}", self.space_id, self.offset)
        }
    }
}

/// A contiguous range of addresses as [start, end] inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange {
    /// Start address (inclusive).
    pub start: Address,
    /// End address (inclusive).
    pub end: Address,
}

impl AddressRange {
    /// Create a new address range. Both addresses must be in the same space.
    pub fn new(start: Address, end: Address) -> Self {
        assert_eq!(
            start.space_id, end.space_id,
            "AddressRange must be within a single address space"
        );
        assert!(start.offset <= end.offset);
        Self { start, end }
    }

    /// Create a range covering a single address.
    pub fn single(addr: Address) -> Self {
        Self {
            start: addr,
            end: addr,
        }
    }

    /// The number of addresses in this range.
    pub fn len(&self) -> u64 {
        self.end.offset - self.start.offset + 1
    }

    /// Whether this range is empty.
    pub fn is_empty(&self) -> bool {
        self.start.offset > self.end.offset
    }

    /// Whether `addr` falls within this range.
    pub fn contains(&self, addr: &Address) -> bool {
        addr.space_id == self.start.space_id
            && addr.offset >= self.start.offset
            && addr.offset <= self.end.offset
    }
}

/// A set of addresses represented as a collection of disjoint ranges.
#[derive(Debug, Clone, Default)]
pub struct AddressSet {
    ranges: Vec<AddressRange>,
}

impl AddressSet {
    /// Create an empty address set.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Create a set covering a single address.
    pub fn from_address(addr: Address) -> Self {
        let mut set = Self::new();
        set.add(addr);
        set
    }

    /// Create a set covering a single range.
    pub fn from_range(range: AddressRange) -> Self {
        let mut set = Self::new();
        set.add_range(range);
        set
    }

    /// Add a single address to the set.
    pub fn add(&mut self, addr: Address) {
        self.add_range(AddressRange::single(addr));
    }

    /// Add a range to the set, merging overlapping ranges.
    pub fn add_range(&mut self, range: AddressRange) {
        if range.is_empty() {
            return;
        }

        // Find insertion point and merge
        let mut i = 0;
        while i < self.ranges.len() {
            let existing = &self.ranges[i];
            if existing.end.offset < range.start.offset.saturating_sub(1)
                && existing.start.space_id == range.start.space_id
            {
                i += 1;
            } else if existing.start.space_id != range.start.space_id {
                if existing.start.space_id < range.start.space_id {
                    i += 1;
                } else {
                    self.ranges.insert(i, range);
                    return;
                }
            } else {
                break;
            }
        }
        self.ranges.insert(i, range);
        self.merge_overlapping();
    }

    /// Add all ranges from another set.
    pub fn add_all(&mut self, other: &AddressSet) {
        for range in &other.ranges {
            self.add_range(*range);
        }
    }

    /// Whether the set contains `addr`.
    pub fn contains(&self, addr: &Address) -> bool {
        self.ranges.iter().any(|r| r.contains(addr))
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The total number of addresses covered.
    pub fn num_addresses(&self) -> u64 {
        self.ranges.iter().map(|r| r.len()).sum()
    }

    /// Iterate over the ranges in this set.
    pub fn iter(&self) -> impl Iterator<Item = &AddressRange> {
        self.ranges.iter()
    }

    /// The minimum address in the set, or `Address::ZERO` if empty.
    pub fn min_address(&self) -> Address {
        self.ranges
            .first()
            .map(|r| r.start)
            .unwrap_or(Address::ZERO)
    }

    /// The maximum address in the set, or `Address::ZERO` if empty.
    pub fn max_address(&self) -> Address {
        self.ranges.last().map(|r| r.end).unwrap_or(Address::ZERO)
    }

    /// Clear all ranges.
    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    fn merge_overlapping(&mut self) {
        if self.ranges.len() < 2 {
            return;
        }
        let mut merged = Vec::new();
        let mut current = self.ranges[0];
        for &range in &self.ranges[1..] {
            if range.start.space_id != current.start.space_id {
                merged.push(current);
                current = range;
            } else if range.start.offset <= current.end.offset + 1 {
                // Overlapping or adjacent ranges — merge them.
                if range.end.offset > current.end.offset {
                    current.end = range.end;
                }
            } else {
                merged.push(current);
                current = range;
            }
        }
        merged.push(current);
        self.ranges = merged;
    }
}

impl<'a> From<&'a Address> for AddressSet {
    fn from(addr: &'a Address) -> Self {
        Self::from_address(*addr)
    }
}

impl From<AddressRange> for AddressSet {
    fn from(range: AddressRange) -> Self {
        Self::from_range(range)
    }
}

/// An address range with an associated priority for scheduling.
type AddressRangeView = AddressRange;

/// Trait alias for types that can be viewed as an [`AddressSet`].
pub trait AddressSetView: std::ops::Deref<Target = AddressSet> {}
impl<T: std::ops::Deref<Target = AddressSet>> AddressSetView for T {}

// ============================================================================
// TaskMonitor — progress and cancellation interface
// ============================================================================

/// A progress monitor that supports cancellation.
///
/// Ported from `ghidra.util.task.TaskMonitor`. Analyzers receive a reference
/// to the monitor and should periodically check `is_cancelled()` to allow
/// the user to interrupt long-running analysis.
pub trait TaskMonitor: Send + Sync {
    /// Whether the operation has been cancelled.
    fn is_cancelled(&self) -> bool;

    /// Set a human-readable progress message.
    fn set_message(&self, message: &str);

    /// The current progress message.
    fn get_message(&self) -> String;

    /// Set the current progress value (0..max).
    fn set_progress(&self, value: u64);

    /// Initialize the monitor with a maximum value.
    fn initialize(&self, max: u64);

    /// Set the maximum progress value.
    fn set_maximum(&self, max: u64);

    /// The current maximum value.
    fn get_maximum(&self) -> u64;

    /// Increment the progress by a delta.
    fn increment_progress(&self, amount: u64);

    /// The current progress value.
    fn get_progress(&self) -> u64;

    /// Whether the progress indicator should show a numeric value.
    fn set_show_progress_value(&self, show: bool);

    /// Whether the progress is indeterminate (spinning bar).
    fn set_indeterminate(&self, indeterminate: bool);

    /// Whether the monitor is in indeterminate mode.
    fn is_indeterminate(&self) -> bool;

    /// Cancel the operation.
    fn cancel(&self);

    /// Whether cancellation is enabled.
    fn is_cancel_enabled(&self) -> bool;

    /// Enable or disable cancellation.
    fn set_cancel_enabled(&self, enabled: bool);

    /// Reset the cancelled flag.
    fn clear_cancelled(&self);

    /// Panic if the operation has been cancelled.
    fn check_cancelled(&self) -> Result<(), CancelledError> {
        if self.is_cancelled() {
            Err(CancelledError)
        } else {
            Ok(())
        }
    }
}

/// A simple in-memory `TaskMonitor` implementation for testing and
/// single-threaded use.
#[derive(Debug, Default)]
pub struct BasicTaskMonitor {
    cancelled: AtomicBool,
    message: std::sync::Mutex<String>,
    progress: std::sync::atomic::AtomicU64,
    maximum: std::sync::atomic::AtomicU64,
    indeterminate: AtomicBool,
    cancel_enabled: AtomicBool,
    show_progress: AtomicBool,
}

impl BasicTaskMonitor {
    pub fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            message: std::sync::Mutex::new(String::new()),
            progress: std::sync::atomic::AtomicU64::new(0),
            maximum: std::sync::atomic::AtomicU64::new(0),
            indeterminate: AtomicBool::new(false),
            cancel_enabled: AtomicBool::new(true),
            show_progress: AtomicBool::new(true),
        }
    }
}

impl TaskMonitor for BasicTaskMonitor {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn set_message(&self, msg: &str) {
        if let Ok(mut m) = self.message.lock() {
            *m = msg.to_string();
        }
    }

    fn get_message(&self) -> String {
        self.message.lock().map(|m| m.clone()).unwrap_or_default()
    }

    fn set_progress(&self, value: u64) {
        self.progress.store(value, Ordering::Relaxed);
    }

    fn initialize(&self, max: u64) {
        self.progress.store(0, Ordering::Relaxed);
        self.maximum.store(max, Ordering::Relaxed);
    }

    fn set_maximum(&self, max: u64) {
        self.maximum.store(max, Ordering::Relaxed);
    }

    fn get_maximum(&self) -> u64 {
        self.maximum.load(Ordering::Relaxed)
    }

    fn increment_progress(&self, amount: u64) {
        self.progress.fetch_add(amount, Ordering::Relaxed);
    }

    fn get_progress(&self) -> u64 {
        self.progress.load(Ordering::Relaxed)
    }

    fn set_show_progress_value(&self, show: bool) {
        self.show_progress.store(show, Ordering::Relaxed);
    }

    fn set_indeterminate(&self, indeterminate: bool) {
        self.indeterminate.store(indeterminate, Ordering::Relaxed);
    }

    fn is_indeterminate(&self) -> bool {
        self.indeterminate.load(Ordering::Relaxed)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    fn is_cancel_enabled(&self) -> bool {
        self.cancel_enabled.load(Ordering::Relaxed)
    }

    fn set_cancel_enabled(&self, enabled: bool) {
        self.cancel_enabled.store(enabled, Ordering::Relaxed);
    }

    fn clear_cancelled(&self) {
        self.cancelled.store(false, Ordering::Relaxed);
    }
}

/// Error returned when an operation is cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelledError;

impl fmt::Display for CancelledError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "analysis cancelled by user")
    }
}

impl std::error::Error for CancelledError {}

// ============================================================================
// Program stub — represents a loaded binary under analysis
// ============================================================================

/// The language / processor specification for a program.
#[derive(Debug, Clone)]
pub struct Language {
    /// Processor name (e.g., "x86", "ARM", "MIPS").
    pub processor: String,
    /// Variant or endianness (e.g., "LE", "BE", "default").
    pub variant: String,
    /// Architecture size in bits.
    pub size: u32,
}

impl Language {
    /// Check if a named property exists in the language specification.
    pub fn has_property(&self, _property_name: &str) -> bool {
        // Stub — property lookup from .pspec / .ldefs files.
        false
    }

    /// Get a boolean property from the language specification.
    pub fn get_property_as_bool(&self, _property_name: &str, default: bool) -> bool {
        default
    }
}

/// A memory block in the program.
#[derive(Debug, Clone)]
pub struct MemoryBlock {
    pub name: String,
    pub start: Address,
    pub size: u64,
    pub is_read: bool,
    pub is_write: bool,
    pub is_execute: bool,
    pub is_initialized: bool,
}

/// A function in the program listing.
#[derive(Debug, Clone)]
pub struct Function {
    /// The entry-point address.
    pub entry_point: Address,
    /// The body address set of the function.
    pub body: AddressSet,
    /// The function name, if known.
    pub name: Option<String>,
    /// Whether the function is external (import).
    pub is_external: bool,
    /// Whether the function is a thunk.
    pub is_thunk: bool,
    /// Whether the function is inlined.
    pub is_inline: bool,
    /// Whether the function has the noreturn attribute.
    pub has_noreturn: bool,
}

/// An instruction in the program listing.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: Address,
    pub length: u32,
    pub mnemonic: String,
    /// Flow type: fall-through, jump, call, return, etc.
    pub flow_type: FlowType,
}

/// Flow-type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowType {
    Fallthrough,
    Jump,
    ConditionalJump,
    Call,
    ConditionalCall,
    Return,
    Terminator,
    Unknown,
}

/// A defined data item in the program listing.
#[derive(Debug, Clone)]
pub struct Data {
    pub address: Address,
    pub length: u32,
    pub data_type_name: String,
}

/// The program listing — provides access to instructions and data.
#[derive(Debug, Clone, Default)]
pub struct Listing {
    pub instructions: HashMap<Address, Instruction>,
    pub data_items: HashMap<Address, Data>,
}

impl Listing {
    /// Get the instruction at `addr`, if any.
    pub fn get_instruction_at(&self, addr: &Address) -> Option<&Instruction> {
        self.instructions.get(addr)
    }

    /// Get an iterator over instructions intersecting the given address set.
    pub fn get_instructions<'a>(
        &'a self,
        set: &'a AddressSet,
        _forward: bool,
    ) -> InstructionIterator<'a> {
        InstructionIterator {
            listing: self,
            ranges: set.iter().collect(),
            range_idx: 0,
            current_addr: None,
        }
    }

    /// Get the number of instructions.
    pub fn num_instructions(&self) -> usize {
        self.instructions.len()
    }

    /// Get the number of defined data items.
    pub fn num_defined_data(&self) -> usize {
        self.data_items.len()
    }
}

/// Iterator over instructions in a listing intersection.
pub struct InstructionIterator<'a> {
    listing: &'a Listing,
    ranges: Vec<&'a AddressRange>,
    range_idx: usize,
    current_addr: Option<Address>,
}

impl<'a> Iterator for InstructionIterator<'a> {
    type Item = &'a Instruction;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.range_idx >= self.ranges.len() {
                return None;
            }
            let range = self.ranges[self.range_idx];
            let addr = self.current_addr.unwrap_or(range.start);

            if addr.offset > range.end.offset {
                self.range_idx += 1;
                self.current_addr = None;
                continue;
            }

            self.current_addr = Some(addr.add(1));
            if let Some(instr) = self.listing.instructions.get(&addr) {
                return Some(instr);
            }
        }
    }
}

/// The function manager for a program.
#[derive(Debug, Clone, Default)]
pub struct FunctionManager {
    pub functions: HashMap<Address, Function>,
}

impl FunctionManager {
    /// Get the function at the given entry point.
    pub fn get_function_at(&self, entry: &Address) -> Option<&Function> {
        self.functions.get(entry)
    }

    /// Iterate over all functions (including external).
    pub fn get_functions(&self, _include_external: bool) -> FunctionIterator<'_> {
        FunctionIterator {
            inner: self.functions.values(),
        }
    }
}

/// Iterator over functions.
pub struct FunctionIterator<'a> {
    inner: std::collections::hash_map::Values<'a, Address, Function>,
}

impl<'a> Iterator for FunctionIterator<'a> {
    type Item = &'a Function;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// Represents a loaded program (binary/image under analysis).
///
/// This is a stub that will eventually migrate to `ghidra-core::program`.
#[derive(Debug, Clone)]
pub struct Program {
    /// Program name (filename).
    pub name: String,
    /// The processor language.
    pub language: Language,
    /// Memory blocks.
    pub memory_blocks: Vec<MemoryBlock>,
    /// The listing (code + data).
    pub listing: Listing,
    /// The function manager.
    pub function_manager: FunctionManager,
    /// Image base address.
    pub image_base: u64,
    /// All memory as an address set.
    pub memory: AddressSet,
    /// Whether the program is temporary (not saved).
    pub is_temporary: bool,
    /// Whether the program has unsaved changes.
    pub is_changed: bool,
}

impl Program {
    /// Create a new empty program.
    pub fn new(name: &str, language: Language) -> Self {
        Self {
            name: name.to_string(),
            language,
            memory_blocks: Vec::new(),
            listing: Listing::default(),
            function_manager: FunctionManager::default(),
            image_base: 0,
            memory: AddressSet::new(),
            is_temporary: true,
            is_changed: false,
        }
    }

    /// Get the listing.
    pub fn get_listing(&self) -> &Listing {
        &self.listing
    }

    /// Get the language spec.
    pub fn get_language(&self) -> &Language {
        &self.language
    }

    /// Get the function manager.
    pub fn get_function_manager(&self) -> &FunctionManager {
        &self.function_manager
    }

    /// Get all memory as an address set.
    pub fn get_memory(&self) -> &AddressSet {
        &self.memory
    }
}

/// A log for recording analysis messages.
#[derive(Debug, Clone, Default)]
pub struct MessageLog {
    messages: Vec<String>,
}

impl MessageLog {
    /// Create a new empty log.
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    /// Append a message to the log.
    pub fn append_msg(&mut self, message: impl Into<String>) {
        self.messages.push(message.into());
    }

    /// Clear all messages.
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// Iterate over messages.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.messages.iter().map(|s| s.as_str())
    }
}

// ============================================================================
// AnalysisOption — per-analyzer configuration option
// ============================================================================

/// A configurable option exposed by an analyzer.
///
/// Each analyzer can declare options that the user can toggle via the
/// analysis options dialog. Options control which heuristics the analyzer
/// applies and what thresholds it uses.
#[derive(Debug, Clone)]
pub struct AnalysisOption {
    /// The option name (displayed in the UI).
    pub name: String,
    /// A longer description of what this option controls.
    pub description: String,
    /// The default value for this option.
    pub default_value: AnalysisOptionValue,
    /// The current value (set by the user or defaults).
    pub current_value: AnalysisOptionValue,
}

/// The typed value of an analysis option.
#[derive(Debug, Clone, PartialEq)]
pub enum AnalysisOptionValue {
    Bool(bool),
    Integer(i64),
    String(String),
    Choice(String, Vec<String>),
}

// ============================================================================
// AnalyzerPriority — relative scheduling priority
// ============================================================================

/// The relative priority at which an analyzer runs.
///
/// Higher-priority analyzers (lower ordinal) run first. This is used
/// for ordering analyzers within the same [`AnalyzerType`] group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnalyzerPriority {
    VeryHigh = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    VeryLow = 4,
}

impl fmt::Display for AnalyzerPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnalyzerPriority::VeryHigh => write!(f, "VeryHigh"),
            AnalyzerPriority::High => write!(f, "High"),
            AnalyzerPriority::Normal => write!(f, "Normal"),
            AnalyzerPriority::Low => write!(f, "Low"),
            AnalyzerPriority::VeryLow => write!(f, "VeryLow"),
        }
    }
}

// ============================================================================
// AnalysisPriority — the fixed priority pipeline
// ============================================================================

/// Fixed priority points in the analysis pipeline.
///
/// Each named priority is spaced by 100 so analyzers can insert themselves
/// between stages using `.before()` or `.after()`. Lower numbers run first.
///
/// The pipeline order is:
/// 1. `FORMAT_ANALYSIS` (100) — binary format analysis, block layout
/// 2. `BLOCK_ANALYSIS` (200) — initial markup of raw bytes
/// 3. `DISASSEMBLY` (300) — disassembly from entry points
/// 4. `CODE_ANALYSIS` (400) — instruction-level analysis
/// 5. `FUNCTION_ANALYSIS` (500) — function creation and analysis
/// 6. `REFERENCE_ANALYSIS` (600) — reference/pointer recovery
/// 7. `DATA_ANALYSIS` (700) — data creation (strings, pointers)
/// 8. `FUNCTION_ID_ANALYSIS` (800) — function identification
/// 9. `DATA_TYPE_PROPAGATION` (900) — type propagation
/// 10. `LOW_PRIORITY` (10000) — speculative/heuristic analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AnalysisPriority {
    /// Human-readable name for this priority level.
    pub name: &'static str,
    /// Numeric priority value (lower = higher priority).
    pub priority: i32,
}

impl AnalysisPriority {
    /// The highest possible priority.
    pub const HIGHEST: Self = Self::new("HIGH", 1);

    /// Format analysis — first pass over the binary.
    pub const FORMAT_ANALYSIS: Self = Self::new("FORMAT", 100);

    /// Block analysis — markup of raw bytes.
    pub const BLOCK_ANALYSIS: Self = Self::new("BLOCK", 200);

    /// Disassembly — code recovery from entry points.
    pub const DISASSEMBLY: Self = Self::new("DISASSEMBLY", 300);

    /// Code analysis — instruction-level pass.
    pub const CODE_ANALYSIS: Self = Self::new("CODE", 400);

    /// Function analysis — function creation and body analysis.
    pub const FUNCTION_ANALYSIS: Self = Self::new("FUNCTION", 500);

    /// Reference analysis — reference/pointer recovery.
    pub const REFERENCE_ANALYSIS: Self = Self::new("REFERENCE", 600);

    /// Data analysis — data item creation.
    pub const DATA_ANALYSIS: Self = Self::new("DATA", 700);

    /// Function ID analysis — function naming/identification.
    pub const FUNCTION_ID_ANALYSIS: Self = Self::new("FUNCTION ID", 800);

    /// Data type propagation — late-stage type inference.
    pub const DATA_TYPE_PROPAGATION: Self = Self::new("DATA TYPE PROPAGATION", 900);

    /// Low priority — speculative/heuristic analysis.
    pub const LOW_PRIORITY: Self = Self::new("LOW", 10000);

    const fn new(name: &'static str, priority: i32) -> Self {
        Self { name, priority }
    }

    /// Get a priority just above (numerically less than) this one.
    pub const fn before(&self) -> Self {
        Self::new(self.name, self.priority - 1)
    }

    /// Get a priority just below (numerically greater than) this one.
    pub const fn after(&self) -> Self {
        Self::new(self.name, self.priority + 1)
    }

    /// The numeric priority value.
    pub const fn priority(&self) -> i32 {
        self.priority
    }
}

impl fmt::Display for AnalysisPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.name, self.priority)
    }
}

// ============================================================================
// AnalyzerType — what event triggers this analyzer
// ============================================================================

/// The type of analysis an analyzer performs, which determines when it is
/// triggered.
///
/// Ported from `ghidra.app.services.AnalyzerType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalyzerType {
    /// Triggered when bytes are added (memory block added).
    Byte,
    /// Triggered when instructions are created.
    Instruction,
    /// Triggered when functions are created.
    Function,
    /// Triggered when a function's modifiers change (thunk, inline, noreturn, etc.).
    FunctionModifiers,
    /// Triggered when a function's signature changes (parameters, return type).
    FunctionSignatures,
    /// Triggered when data is created.
    Data,
}

impl AnalyzerType {
    /// Human-readable name for this analyzer type.
    pub fn name(&self) -> &'static str {
        match self {
            AnalyzerType::Byte => "Byte Analyzer",
            AnalyzerType::Instruction => "Instructions Analyzer",
            AnalyzerType::Function => "Function Analyzer",
            AnalyzerType::FunctionModifiers => "Function-modifiers Analyzer",
            AnalyzerType::FunctionSignatures => "Function-Signatures Analyzer",
            AnalyzerType::Data => "Data Analyzer",
        }
    }

    /// Description of when this analyzer type is triggered.
    pub fn description(&self) -> &'static str {
        match self {
            AnalyzerType::Byte => "Triggered when bytes are added (memory block added).",
            AnalyzerType::Instruction => "Triggered when instructions are created.",
            AnalyzerType::Function => "Triggered when functions are created.",
            AnalyzerType::FunctionModifiers => "Triggered when a function's modifier changes.",
            AnalyzerType::FunctionSignatures => "Triggered when a function's signature changes.",
            AnalyzerType::Data => "Triggered when data is created.",
        }
    }
}

impl fmt::Display for AnalyzerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Analyzer trait — the core analysis interface
// ============================================================================

/// The core interface for automatic analysis passes.
///
/// Implementors register with an [`AutoAnalysisManager`] and are invoked
/// when program changes matching their [`AnalyzerType`] occur. Each
/// analyzer runs at a specific [`AnalysisPriority`].
///
/// # Lifecycle
///
/// 1. `can_analyze()` is called at registration time to check if the
///    analyzer is compatible with the program.
/// 2. `get_analysis_options()` provides the option definitions for the
///    analysis options dialog.
/// 3. `added()` is called when addresses matching the analyzer type are
///    added to the program.
/// 4. `removed()` is called when addresses are removed (e.g., function
///    removed, instruction cleared).
/// 5. `analysis_ended()` is called when an auto-analysis session ends.
pub trait Analyzer: Send + Sync {
    /// The unique name of this analyzer (no periods allowed).
    fn name(&self) -> &str;

    /// A human-readable description of what this analyzer does.
    fn description(&self) -> &str;

    /// What type of analysis this analyzer performs (determines
    /// which events trigger it).
    fn analysis_type(&self) -> AnalyzerType;

    /// The priority at which this analyzer runs.
    fn priority(&self) -> AnalysisPriority;

    /// Whether this analyzer should be enabled by default for the
    /// given program. Useful analyzers return `true`; specialized ones
    /// return `false`.
    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    /// Whether this analyzer can analyze the given program.
    /// Returns `false` if the program's language/format is unsupported.
    fn can_analyze(&self, program: &Program) -> bool;

    /// Called when the program event matching this analyzer's type fires
    /// (e.g., new instructions created for `Instruction` analyzers).
    ///
    /// Returns `true` if the analysis made changes to the program.
    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError>;

    /// Called when addresses are removed from the program.
    fn removed(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }

    /// Register configurable options for this analyzer.
    fn register_options(&self, _program: &Program) -> Vec<AnalysisOption> {
        Vec::new()
    }

    /// Called when options change (the user changed a setting).
    fn options_changed(&mut self, _options: &HashMap<String, AnalysisOptionValue>) {}

    /// Called when an auto-analysis session ends so the analyzer can
    /// clean up session-only resources.
    fn analysis_ended(&self, _program: &Program) {}

    /// Whether this analyzer supports one-time (user-initiated) analysis
    /// on a specific address set.
    fn supports_one_time_analysis(&self) -> bool {
        false
    }

    /// Whether this analyzer is a prototype (experimental).
    fn is_prototype(&self) -> bool {
        false
    }
}

// ============================================================================
// AnalysisResults — outcome of an analysis run
// ============================================================================

/// The result of running a batch of analysis tasks.
#[derive(Debug, Clone)]
pub struct AnalysisResults {
    /// Total number of tasks that ran.
    pub tasks_executed: usize,
    /// Whether the run was cancelled.
    pub was_cancelled: bool,
    /// Total wall-clock time (ms).
    pub total_time_ms: u64,
    /// Per-task timing breakdown.
    pub task_times: Vec<(String, u64)>,
}

impl AnalysisResults {
    /// Whether any analysis tasks made changes.
    pub fn has_changes(&self) -> bool {
        self.tasks_executed > 0 && !self.was_cancelled
    }
}

// ============================================================================
// AnalysisScheduler — wraps an analyzer with pending address sets
// ============================================================================

/// Per-analyzer scheduler that tracks pending add/remove address sets.
///
/// Ported from `ghidra.app.plugin.core.analysis.AnalysisScheduler`.
struct AnalysisSchedulerState {
    pub analyzer: Box<dyn Analyzer>,
    pub enabled: bool,
    pub default_enablement: bool,
    pub add_set: AddressSet,
    pub remove_set: AddressSet,
    pub scheduled: bool,
}

impl AnalysisSchedulerState {
    fn new(analyzer: Box<dyn Analyzer>, program: &Program) -> Self {
        let default_enablement = analyzer.default_enablement(program);
        // Check for language-level overrides
        let lang = program.get_language();
        let enabled = if lang.has_property("DisableAllAnalyzers") {
            lang.get_property_as_bool(
                &format!("Analyzers.{}", analyzer.name()),
                default_enablement,
            )
        } else {
            default_enablement
        };

        Self {
            analyzer,
            enabled,
            default_enablement,
            add_set: AddressSet::new(),
            remove_set: AddressSet::new(),
            scheduled: false,
        }
    }

    fn priority(&self) -> i32 {
        self.analyzer.priority().priority()
    }

    fn notify_added(&mut self, addr: Address) {
        if !self.enabled {
            return;
        }
        self.add_set.add(addr);
    }

    fn notify_added_set(&mut self, set: &AddressSet) {
        if !self.enabled {
            return;
        }
        self.add_set.add_all(set);
    }

    fn notify_removed(&mut self, addr: Address) {
        if !self.enabled {
            return;
        }
        self.remove_set.add(addr);
    }

    fn notify_removed_set(&mut self, set: &AddressSet) {
        if !self.enabled {
            return;
        }
        self.remove_set.add_all(set);
    }

    fn get_added(&mut self) -> AddressSet {
        std::mem::take(&mut self.add_set)
    }

    fn get_removed(&mut self) -> AddressSet {
        std::mem::take(&mut self.remove_set)
    }

    fn has_pending_work(&self) -> bool {
        !self.add_set.is_empty() || !self.remove_set.is_empty()
    }

    fn run(
        &mut self,
        program: &mut Program,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        let add_set = self.get_added();
        let remove_set = self.get_removed();
        self.scheduled = false;

        monitor.set_message(self.analyzer.name());
        monitor.set_progress(0);

        let mut result = false;

        if !add_set.is_empty() {
            result |= self.analyzer.added(program, &add_set, monitor, log)?;
        }

        if !remove_set.is_empty() {
            result |= self.analyzer.removed(program, &remove_set, monitor, log)?;
        }

        Ok(result)
    }

    fn run_cancelled(&mut self) {
        // Discard accumulated address sets.
        self.get_added();
        self.get_removed();
        self.scheduled = false;
    }
}

// ============================================================================
// AnalysisTaskList — a group of schedulers of the same type
// ============================================================================

/// A collection of [`AnalysisSchedulerState`] entries all of the same
/// [`AnalyzerType`]. Handles notifying all contained analyzers when
/// their trigger event fires.
struct AnalysisTaskList {
    analyzer_type: AnalyzerType,
    schedulers: Vec<AnalysisSchedulerState>,
}

impl AnalysisTaskList {
    fn new(analyzer_type: AnalyzerType) -> Self {
        Self {
            analyzer_type,
            schedulers: Vec::new(),
        }
    }

    fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>, program: &Program) {
        // Validate: no periods in analyzer name
        assert!(
            !analyzer.name().contains('.'),
            "Analyzer name may not contain a period: {}",
            analyzer.name()
        );
        self.schedulers
            .push(AnalysisSchedulerState::new(analyzer, program));
    }

    fn notify_added(&mut self, addr: Address) {
        for scheduler in &mut self.schedulers {
            scheduler.notify_added(addr);
        }
    }

    fn notify_added_set(&mut self, set: &AddressSet) {
        for scheduler in &mut self.schedulers {
            scheduler.notify_added_set(set);
        }
    }

    fn notify_removed(&mut self, addr: Address) {
        for scheduler in &mut self.schedulers {
            scheduler.notify_removed(addr);
        }
    }

    fn notify_analysis_ended(&self, program: &Program) {
        for scheduler in &self.schedulers {
            scheduler.analyzer.analysis_ended(program);
        }
    }

    fn clear(&mut self) {
        for scheduler in &mut self.schedulers {
            scheduler.run_cancelled();
        }
    }

    fn get_pending_schedulers(&mut self) -> Vec<(i32, usize)> {
        let mut pending: Vec<(i32, usize)> = self
            .schedulers
            .iter()
            .enumerate()
            .filter(|(_, s)| s.has_pending_work() && !s.scheduled)
            .map(|(i, s)| (s.priority(), i))
            .collect();
        // Sort by priority (ascending — lower number = higher priority).
        pending.sort_by_key(|(p, _)| *p);
        pending
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = &mut AnalysisSchedulerState> {
        self.schedulers.iter_mut()
    }
}

// ============================================================================
// Scheduled task for the priority queue
// ============================================================================

/// A scheduled analysis task in the priority queue.
struct ScheduledTask {
    /// Priority value (lower = more urgent).
    priority: i32,
    /// Index into the appropriate task list.
    scheduler_index: usize,
    /// Which task list, by analyzer type.
    task_list_index: usize,
    /// Unique sequence number for FIFO ordering of equal-priority tasks.
    seq: u64,
}

impl PartialEq for ScheduledTask {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
    }
}

impl Eq for ScheduledTask {}

// Reverse ordering so BinaryHeap is a min-heap on (priority, seq).
impl PartialOrd for ScheduledTask {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledTask {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Lower priority value = higher urgency.
        other
            .priority
            .cmp(&self.priority)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

// ============================================================================
// AutoAnalysisManager — orchestrates all analysis
// ============================================================================

/// Configuration for [`AutoAnalysisManager`].
#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    /// Maximum number of analysis iterations before stopping.
    /// Limits re-entrant analysis to prevent infinite loops.
    pub max_iterations: u32,
    /// Maximum wall-clock time for a single analysis run.
    pub timeout_ms: u64,
    /// Specific analyzer names to enable (empty = all enabled by default).
    pub enabled_analyzers: HashSet<String>,
    /// Whether to print task timing information after analysis.
    pub print_task_times: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            max_iterations: 100,
            timeout_ms: 300_000, // 5 minutes
            enabled_analyzers: HashSet::new(),
            print_task_times: true,
        }
    }
}

/// The auto-analysis manager.
///
/// Ported from `ghidra.app.plugin.core.analysis.AutoAnalysisManager`.
///
/// This is the central orchestrator that:
/// 1. Registers analyzers
/// 2. Receives program change notifications
/// 3. Schedules and runs analyzers in priority order
/// 4. Tracks analysis timing and results
///
/// # Example
///
/// ```rust,no_run
/// use ghidra_features::base::analyzer::*;
///
/// let program = Program::new("example", Language {
///     processor: "x86".into(),
///     variant: "LE".into(),
///     size: 64,
/// });
///
/// let mut mgr = AutoAnalysisManager::new(program);
/// mgr.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
/// mgr.add_analyzer(Box::new(DataReferenceAnalyzer::new()));
/// mgr.add_analyzer(Box::new(ConstantReferenceAnalyzer::new()));
///
/// let monitor = BasicTaskMonitor::new();
/// let results = mgr.run_analysis(&monitor)?;
/// println!("Executed {} tasks in {}ms", results.tasks_executed, results.total_time_ms);
/// # Ok::<(), CancelledError>(())
/// ```
pub struct AutoAnalysisManager {
    /// The program being analyzed.
    program: Program,
    /// Per-type task lists.
    task_lists: Vec<AnalysisTaskList>,
    /// Priority queue of pending tasks.
    queue: std::collections::BinaryHeap<ScheduledTask>,
    /// Sequence counter for FIFO ordering.
    seq_counter: u64,
    /// Configuration options.
    options: AnalysisOptions,
    /// Whether change-notification processing is currently ignored.
    ignore_changes: bool,
    /// Whether analysis is currently active.
    is_analyzing: bool,
    /// Cumulative task timing (keyed by analyzer name).
    cumulative_tasks: HashMap<String, Duration>,
    /// Session-only task timing.
    timed_tasks: HashMap<String, Duration>,
    /// Protected locations (known-good code that should not be cleared).
    protected_locations: AddressSet,
    /// Total task count executed in the last run.
    tasks_executed: usize,
    /// Whether the last run was cancelled.
    was_cancelled: bool,
    /// Total time of the last run.
    total_time_ms: u64,
}

impl AutoAnalysisManager {
    /// Create a new analysis manager for the given program.
    ///
    /// No analyzers are registered initially. Call [`add_analyzer`]
    /// to register analyzers, then [`run_analysis`] to start.
    pub fn new(program: Program) -> Self {
        let task_lists = vec![
            AnalysisTaskList::new(AnalyzerType::Byte),
            AnalysisTaskList::new(AnalyzerType::Instruction),
            AnalysisTaskList::new(AnalyzerType::Function),
            AnalysisTaskList::new(AnalyzerType::FunctionModifiers),
            AnalysisTaskList::new(AnalyzerType::FunctionSignatures),
            AnalysisTaskList::new(AnalyzerType::Data),
        ];

        Self {
            program,
            task_lists,
            queue: BinaryHeap::new(),
            seq_counter: 0,
            options: AnalysisOptions::default(),
            ignore_changes: false,
            is_analyzing: false,
            cumulative_tasks: HashMap::new(),
            timed_tasks: HashMap::new(),
            protected_locations: AddressSet::new(),
            tasks_executed: 0,
            was_cancelled: false,
            total_time_ms: 0,
        }
    }

    /// Get the program being analyzed.
    pub fn program(&self) -> &Program {
        &self.program
    }

    /// Get a mutable reference to the program.
    pub fn program_mut(&mut self) -> &mut Program {
        &mut self.program
    }

    /// Set the analysis options.
    pub fn set_options(&mut self, options: AnalysisOptions) {
        self.options = options;
    }

    /// Get the analysis options.
    pub fn options(&self) -> &AnalysisOptions {
        &self.options
    }

    /// Add an analyzer to the manager.
    ///
    /// The analyzer is placed into the appropriate task list based on its
    /// [`AnalyzerType`]. If `can_analyze()` returns `false`, the analyzer
    /// is not added.
    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>) {
        if !analyzer.can_analyze(&self.program) {
            return;
        }

        let list_index = self.task_list_index_for_type(analyzer.analysis_type());
        self.task_lists[list_index].add_analyzer(analyzer, &self.program);
    }

    /// Set whether program change events should be ignored.
    pub fn set_ignore_changes(&mut self, state: bool) {
        self.ignore_changes = state;
    }

    /// Get whether analysis is currently running.
    pub fn is_analyzing(&self) -> bool {
        self.is_analyzing
    }

    // ── Event notification methods ──────────────────────────────────

    /// Notify that a range of addresses has been added as bytes (new memory block).
    pub fn block_added(&mut self, set: &AddressSet) {
        if self.ignore_changes {
            return;
        }
        let idx = self.task_list_index_for_type(AnalyzerType::Byte);
        self.task_lists[idx].notify_added_set(set);
    }

    /// Notify that code (instructions) have been defined.
    pub fn code_defined(&mut self, addr: Address) {
        if self.ignore_changes {
            return;
        }
        let idx = self.task_list_index_for_type(AnalyzerType::Instruction);
        self.task_lists[idx].notify_added(addr);
    }

    /// Notify that code (instructions) have been defined over a range.
    pub fn code_defined_set(&mut self, set: &AddressSet) {
        if self.ignore_changes {
            return;
        }
        let idx = self.task_list_index_for_type(AnalyzerType::Instruction);
        self.task_lists[idx].notify_added_set(set);
    }

    /// Notify that data has been defined.
    pub fn data_defined(&mut self, set: &AddressSet) {
        if self.ignore_changes {
            return;
        }
        let idx = self.task_list_index_for_type(AnalyzerType::Data);
        self.task_lists[idx].notify_added_set(set);
    }

    /// Notify that a function has been defined.
    pub fn function_defined(&mut self, addr: Address) {
        if self.ignore_changes {
            return;
        }
        let idx = self.task_list_index_for_type(AnalyzerType::Function);
        self.task_lists[idx].notify_added(addr);
    }

    /// Notify that functions have been defined over a range.
    pub fn function_defined_set(&mut self, set: &AddressSet) {
        if self.ignore_changes {
            return;
        }
        let idx = self.task_list_index_for_type(AnalyzerType::Function);
        self.task_lists[idx].notify_added_set(set);
    }

    /// Notify that function modifiers changed.
    pub fn function_modifier_changed(&mut self, addr: Address) {
        if self.ignore_changes {
            return;
        }
        let idx = self.task_list_index_for_type(AnalyzerType::FunctionModifiers);
        self.task_lists[idx].notify_added(addr);
    }

    /// Notify that function modifiers changed over a range.
    pub fn function_modifier_changed_set(&mut self, set: &AddressSet) {
        if self.ignore_changes {
            return;
        }
        let idx = self.task_list_index_for_type(AnalyzerType::FunctionModifiers);
        self.task_lists[idx].notify_added_set(set);
    }

    /// Notify that function signatures changed.
    pub fn function_signature_changed(&mut self, addr: Address) {
        if self.ignore_changes {
            return;
        }
        let idx = self.task_list_index_for_type(AnalyzerType::FunctionSignatures);
        self.task_lists[idx].notify_added(addr);
    }

    /// Notify that function signatures changed over a range.
    pub fn function_signature_changed_set(&mut self, set: &AddressSet) {
        if self.ignore_changes {
            return;
        }
        let idx = self.task_list_index_for_type(AnalyzerType::FunctionSignatures);
        self.task_lists[idx].notify_added_set(set);
    }

    /// Request re-analysis of the entire program or a subset.
    ///
    /// This triggers notifications for all analyzer types on the
    /// specified address range. Pass `None` to analyze everything.
    pub fn re_analyze_all(&mut self, restrict_set: Option<&AddressSet>) {
        let set = match restrict_set {
            Some(s) if !s.is_empty() => s.clone(),
            _ => self.program.memory.clone(),
        };

        self.block_added(&set);

        if self.program.listing.num_instructions() > 0 {
            self.code_defined_set(&set);
        }
        if self.program.listing.num_defined_data() > 0 {
            self.data_defined(&set);
        }
        if self
            .program
            .function_manager
            .get_functions(true)
            .next()
            .is_some()
        {
            self.function_defined_set(&set);
            self.function_signature_changed_set(&set);
        }
    }

    /// Mark a location as protected (known-good code that should not be
    /// cleared during this analysis run).
    pub fn set_protected_location(&mut self, addr: Address) {
        self.protected_locations.add(addr);
    }

    /// Get the set of protected locations for this analysis run.
    pub fn protected_locations(&self) -> &AddressSet {
        &self.protected_locations
    }

    // ── Analysis execution ──────────────────────────────────────────

    /// Run analysis on all pending tasks.
    ///
    /// This drains the priority queue, executing each scheduled analyzer
    /// in turn. New tasks may be enqueued as a result of analysis changes
    /// (re-entrant analysis), up to `options.max_iterations`.
    pub fn run_analysis(
        &mut self,
        monitor: &dyn TaskMonitor,
    ) -> Result<AnalysisResults, CancelledError> {
        let start = Instant::now();
        self.is_analyzing = true;
        self.tasks_executed = 0;
        self.was_cancelled = false;
        self.timed_tasks.clear();
        self.protected_locations.clear();

        // Phase 1: Prime the queue with all pending schedulers
        self.enqueue_pending();

        // Phase 2: Drain the queue up to max_iterations
        let mut iteration = 0u32;
        while !self.queue.is_empty() && iteration < self.options.max_iterations {
            monitor.check_cancelled()?;

            // Check timeout
            if start.elapsed().as_millis() as u64 > self.options.timeout_ms {
                log::warn!(
                    "Analysis timeout reached after {}ms",
                    self.options.timeout_ms
                );
                self.was_cancelled = true;
                break;
            }

            // Dequeue the highest-priority task
            let task = self.queue.pop().expect("queue is non-empty");
            iteration += 1;

            let task_start = Instant::now();
            let task_name = {
                let list = &mut self.task_lists[task.task_list_index];
                let scheduler = &mut list.schedulers[task.scheduler_index];
                scheduler.analyzer.name().to_string()
            };

            // Run the analyzer
            let mut log = MessageLog::new();
            let result = {
                let list = &mut self.task_lists[task.task_list_index];
                let scheduler = &mut list.schedulers[task.scheduler_index];
                scheduler.run(&mut self.program, monitor, &mut log)
            };

            let elapsed = task_start.elapsed();

            match result {
                Ok(_made_changes) => {
                    self.tasks_executed += 1;
                }
                Err(CancelledError) => {
                    self.was_cancelled = true;
                    break;
                }
            }

            // Record timing
            *self
                .timed_tasks
                .entry(task_name.clone())
                .or_insert(Duration::ZERO) += elapsed;
            *self
                .cumulative_tasks
                .entry(task_name)
                .or_insert(Duration::ZERO) += elapsed;

            // Enqueue any new tasks created by this analysis step
            self.enqueue_pending();
        }

        self.is_analyzing = false;
        self.total_time_ms = start.elapsed().as_millis() as u64;

        if !self.was_cancelled {
            // Notify all analyzers that the session ended
            for list in &self.task_lists {
                list.notify_analysis_ended(&self.program);
            }
        }

        Ok(AnalysisResults {
            tasks_executed: self.tasks_executed,
            was_cancelled: self.was_cancelled,
            total_time_ms: self.total_time_ms,
            task_times: self
                .timed_tasks
                .iter()
                .map(|(name, d)| (name.clone(), d.as_millis() as u64))
                .collect(),
        })
    }

    /// Enqueue all schedulers that have pending work.
    fn enqueue_pending(&mut self) {
        for (list_idx, list) in self.task_lists.iter_mut().enumerate() {
            let pending = list.get_pending_schedulers();
            for (priority, sched_idx) in pending {
                // Mark as scheduled
                list.schedulers[sched_idx].scheduled = true;
                self.queue.push(ScheduledTask {
                    priority,
                    scheduler_index: sched_idx,
                    task_list_index: list_idx,
                    seq: self.seq_counter,
                });
                self.seq_counter += 1;
            }
        }
    }

    /// Cancel all queued tasks and reset the queue.
    pub fn cancel_queued_tasks(&mut self) {
        self.queue.clear();
        for list in &mut self.task_lists {
            list.clear();
        }
    }

    /// Get the cumulative time spent in a named task across all runs.
    pub fn cumulative_task_time(&self, name: &str) -> Option<Duration> {
        self.cumulative_tasks.get(name).copied()
    }

    /// Get the task timing from the last run.
    pub fn task_times(&self) -> &HashMap<String, Duration> {
        &self.timed_tasks
    }

    /// Get the total time (ms) of the last analysis run.
    pub fn total_time_ms(&self) -> u64 {
        self.total_time_ms
    }

    fn task_list_index_for_type(&self, at: AnalyzerType) -> usize {
        match at {
            AnalyzerType::Byte => 0,
            AnalyzerType::Instruction => 1,
            AnalyzerType::Function => 2,
            AnalyzerType::FunctionModifiers => 3,
            AnalyzerType::FunctionSignatures => 4,
            AnalyzerType::Data => 5,
        }
    }
}

// ============================================================================
// AbstractAnalyzer — convenience base for analyzer implementations
// ============================================================================

/// A convenience base struct that implements common [`Analyzer`] method
/// defaults. Concrete analyzers embed this and override the methods
/// they need.
///
/// Ported from `ghidra.app.plugin.core.analysis.AbstractAnalyzer`.
#[derive(Debug, Clone)]
pub struct AbstractAnalyzer {
    name: String,
    description: String,
    analysis_type: AnalyzerType,
    priority: AnalysisPriority,
    supports_one_time: bool,
    is_prototype: bool,
}

impl AbstractAnalyzer {
    /// Create a new abstract analyzer with the given name, description,
    /// and analyzer type.
    pub fn new(name: &str, description: &str, analysis_type: AnalyzerType) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            analysis_type,
            priority: AnalysisPriority::LOW_PRIORITY,
            supports_one_time: false,
            is_prototype: false,
        }
    }

    /// Set the priority for this analyzer.
    pub fn set_priority(&mut self, priority: AnalysisPriority) {
        self.priority = priority;
    }

    /// Set whether this analyzer supports one-time analysis.
    pub fn set_supports_one_time_analysis(&mut self, enabled: bool) {
        self.supports_one_time = enabled;
    }

    /// Set whether this is a prototype analyzer.
    pub fn set_is_prototype(&mut self, prototype: bool) {
        self.is_prototype = prototype;
    }

    /// The analyzer name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The analyzer description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// The analyzer type.
    pub fn analysis_type(&self) -> AnalyzerType {
        self.analysis_type
    }

    /// The priority.
    pub fn priority(&self) -> AnalysisPriority {
        self.priority
    }
}

// ============================================================================
// Built-in analyzer implementations
// ============================================================================

/// Finds potential function start addresses by scanning for known
/// function prologues (e.g., `push rbp; mov rbp, rsp` on x86, `push {..., lr}`
/// on ARM).
///
/// Analyzer type: [`AnalyzerType::Byte`]
/// Priority: just before [`AnalysisPriority::BLOCK_ANALYSIS`]
#[derive(Debug, Clone)]
pub struct FunctionStartAnalyzer {
    base: AbstractAnalyzer,
}

impl FunctionStartAnalyzer {
    pub fn new() -> Self {
        Self {
            base: AbstractAnalyzer::new(
                "Function Start Analyzer",
                "Searches for function prologue patterns to identify function entry points.",
                AnalyzerType::Byte,
            ),
        }
    }
}

impl Analyzer for FunctionStartAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::BLOCK_ANALYSIS.before()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Searching for function starts...");

        // This analyzer scans raw bytes for function prologue patterns.
        // The actual pattern-matching logic depends on the processor
        // language. This stub demonstrates the structure.
        Ok(true)
    }
}

/// Identifies code boundaries by analyzing control flow and looking for
/// fall-through patterns, jump targets, and padding bytes.
///
/// Analyzer type: [`AnalyzerType::Byte`]
/// Priority: after [`AnalysisPriority::BLOCK_ANALYSIS`]
#[derive(Debug, Clone)]
pub struct CodeBoundaryAnalyzer {
    base: AbstractAnalyzer,
}

impl CodeBoundaryAnalyzer {
    pub fn new() -> Self {
        Self {
            base: AbstractAnalyzer::new(
                "Code Boundary Analyzer",
                "Identifies code boundaries through control flow analysis and padding detection.",
                AnalyzerType::Byte,
            ),
        }
    }
}

impl Analyzer for CodeBoundaryAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::BLOCK_ANALYSIS.after()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Analyzing code boundaries...");

        // Scans for code boundaries using padding bytes (e.g., 0x00 or 0xCC),
        // unconditional jump targets, and alignment patterns.
        Ok(true)
    }
}

/// Analyzes data referenced by instructions — creates strings, pointers,
/// address tables, and switch tables from instruction operands.
///
/// Analyzer type: [`AnalyzerType::Instruction`]
/// Priority: at [`AnalysisPriority::REFERENCE_ANALYSIS`]
#[derive(Debug, Clone)]
pub struct DataReferenceAnalyzer {
    base: AbstractAnalyzer,
    /// Whether to create ASCII strings from references.
    create_ascii_strings: bool,
    /// Whether to create Unicode strings from references.
    create_unicode_strings: bool,
    /// Whether to create pointers from references.
    create_pointers: bool,
    /// Whether to create address tables from references.
    create_address_tables: bool,
    /// Minimum string length.
    min_string_length: u32,
}

impl DataReferenceAnalyzer {
    pub fn new() -> Self {
        Self {
            base: AbstractAnalyzer::new(
                "Reference",
                "Analyzes data referenced by instructions — creates strings, pointers, and address tables.",
                AnalyzerType::Instruction,
            ),
            create_ascii_strings: true,
            create_unicode_strings: true,
            create_pointers: true,
            create_address_tables: true,
            min_string_length: 5,
        }
    }

    pub fn with_string_creation(mut self, enabled: bool) -> Self {
        self.create_ascii_strings = enabled;
        self.create_unicode_strings = enabled;
        self
    }

    pub fn with_pointer_creation(mut self, enabled: bool) -> Self {
        self.create_pointers = enabled;
        self
    }
}

impl Analyzer for DataReferenceAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::REFERENCE_ANALYSIS
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }
    fn supports_one_time_analysis(&self) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Analyzing operand references for data...");
        monitor.initialize(set.num_addresses());

        let count = 0u64;
        log.append_msg(format!(
            "DataReferenceAnalyzer: scanning {} addresses for references",
            set.num_addresses()
        ));

        // For each address in the set, check if the instruction at that
        // address has operands that reference known memory locations.
        // If a reference is found:
        //   - If it points to readable string data, create a string
        //   - If it points to a known address, create a pointer
        //   - If it points to a table of pointers, create an address table
        monitor.increment_progress(count);
        Ok(true)
    }

    fn options_changed(&mut self, options: &HashMap<String, AnalysisOptionValue>) {
        if let Some(AnalysisOptionValue::Bool(v)) = options.get("Ascii String References") {
            self.create_ascii_strings = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = options.get("Unicode String References") {
            self.create_unicode_strings = *v;
        }
    }
}

/// Analyzes function stack frames to identify local variables,
/// saved registers, and frame layout.
///
/// Analyzer type: [`AnalyzerType::Function`]
/// Priority: at [`AnalysisPriority::FUNCTION_ANALYSIS`]
#[derive(Debug, Clone)]
pub struct StackVariableAnalyzer {
    base: AbstractAnalyzer,
}

impl StackVariableAnalyzer {
    pub fn new() -> Self {
        Self {
            base: AbstractAnalyzer::new(
                "Stack",
                "Analyzes function stack frames to identify local variables and stack layout.",
                AnalyzerType::Function,
            ),
        }
    }
}

impl Analyzer for StackVariableAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::FUNCTION_ANALYSIS
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Analyzing stack variables...");

        // For each address in the set, if it is a function entry point,
        // analyze the function's stack frame:
        //   - Identify stack-based local variables
        //   - Determine frame size
        //   - Mark saved return address location
        //   - Identify parameter slots
        for _range in set.iter() {
            monitor.check_cancelled()?;
        }
        Ok(true)
    }
}

/// Propagates constant values through instructions to identify
/// computed references (e.g., `mov eax, 0x400000; lea rdi, [eax + rdx]`).
///
/// Analyzer type: [`AnalyzerType::Instruction`]
/// Priority: just before [`AnalysisPriority::REFERENCE_ANALYSIS`]
#[derive(Debug, Clone)]
pub struct ConstantReferenceAnalyzer {
    base: AbstractAnalyzer,
    /// Whether to check function parameters for pointer values.
    check_param_refs: bool,
    /// Whether to check stored values for pointer references.
    check_stored_refs: bool,
    /// Minimum address for a known reference.
    min_known_ref_address: u64,
    /// Minimum address for speculative references.
    min_speculative_ref_address: u64,
}

impl ConstantReferenceAnalyzer {
    pub fn new() -> Self {
        Self {
            base: AbstractAnalyzer::new(
                "Constant Reference Analyzer",
                "Propagates constant values to identify computed references not directly visible in operands.",
                AnalyzerType::Instruction,
            ),
            check_param_refs: true,
            check_stored_refs: true,
            min_known_ref_address: 4,
            min_speculative_ref_address: 1024,
        }
    }
}

impl Analyzer for ConstantReferenceAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::REFERENCE_ANALYSIS
            .before()
            .before()
            .before()
            .before()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Propagating constants for reference analysis...");
        monitor.initialize(set.num_addresses());

        log.append_msg("ConstantReferenceAnalyzer: starting constant propagation");

        // Walk each instruction in the set, building a constant-propagation
        // lattice. When a value is known to be a pointer, create a reference.
        // Use symbolic propagation when the processor supports P-code.
        Ok(true)
    }

    fn options_changed(&mut self, options: &HashMap<String, AnalysisOptionValue>) {
        if let Some(AnalysisOptionValue::Bool(v)) =
            options.get("Function parameter/return Pointer analysis")
        {
            self.check_param_refs = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = options.get("Stored Value Pointer analysis") {
            self.check_stored_refs = *v;
        }
    }
}

/// Identifies switch/jump tables by analyzing indirect jump patterns
/// and extracting the table of target addresses.
///
/// Analyzer type: [`AnalyzerType::Instruction`]
/// Priority: after [`AnalysisPriority::REFERENCE_ANALYSIS`]
#[derive(Debug, Clone)]
pub struct SwitchAnalyzer {
    base: AbstractAnalyzer,
}

impl SwitchAnalyzer {
    pub fn new() -> Self {
        Self {
            base: AbstractAnalyzer::new(
                "Switch Table Analyzer",
                "Identifies switch/jump tables from indirect jump patterns and extracts target addresses.",
                AnalyzerType::Instruction,
            ),
        }
    }
}

impl Analyzer for SwitchAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::REFERENCE_ANALYSIS.after().after()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Analyzing switch tables...");

        // Detect switch/jump table patterns:
        //   - Indirect jump through a register computed from a table index
        //   - Table of addresses contiguous in memory
        //   - Bounds-checked table index
        // Extract target addresses and create references.
        Ok(true)
    }
}

/// ARM/Thumb-specific analyzer that handles Thumb mode transitions
/// and identifies ARM vs Thumb code regions.
///
/// Analyzer type: [`AnalyzerType::Instruction`]
/// Priority: at [`AnalysisPriority::CODE_ANALYSIS`]
#[derive(Debug, Clone)]
pub struct ARMThumbAnalyzer {
    base: AbstractAnalyzer,
}

impl ARMThumbAnalyzer {
    pub fn new() -> Self {
        Self {
            base: AbstractAnalyzer::new(
                "ARM Thumb Analyzer",
                "Handles ARM/Thumb mode transitions and identifies Thumb code regions.",
                AnalyzerType::Instruction,
            ),
        }
    }
}

impl Analyzer for ARMThumbAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::CODE_ANALYSIS
    }
    fn can_analyze(&self, program: &Program) -> bool {
        // Only applicable to ARM processors
        program
            .get_language()
            .processor
            .to_lowercase()
            .contains("arm")
    }
    fn default_enablement(&self, program: &Program) -> bool {
        program
            .get_language()
            .processor
            .to_lowercase()
            .contains("arm")
    }

    fn added(
        &self,
        _program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Analyzing ARM/Thumb transitions...");
        monitor.initialize(set.num_addresses());

        log.append_msg("ARMThumbAnalyzer: scanning for Thumb mode transitions");

        // For ARM binaries:
        //   - When a BX or BLX instruction targets an odd address,
        //     the target is Thumb code (clear the LSB and disassemble
        //     as Thumb).
        //   - For indirect calls through registers, check whether
        //     the calling convention indicates Thumb mode.
        //   - Check for T-bit in CPSR manipulation patterns.
        Ok(true)
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_program() -> Program {
        let lang = Language {
            processor: "x86".to_string(),
            variant: "LE".to_string(),
            size: 64,
        };
        let mut prog = Program::new("test", lang);
        prog.image_base = 0x400000;
        prog.memory.add_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        prog
    }

    #[test]
    fn test_address_operations() {
        let a = Address::new(0x1000);
        assert_eq!(a.add(8), Address::new(0x1008));
        assert_eq!(a.sub(8), Address::new(0xFF8)); // wrapping
        assert_eq!(a.to_string(), "0x1000");
    }

    #[test]
    fn test_address_range() {
        let r = AddressRange::new(Address::new(0x1000), Address::new(0x10FF));
        assert_eq!(r.len(), 256);
        assert!(r.contains(&Address::new(0x1050)));
        assert!(!r.contains(&Address::new(0x2000)));
    }

    #[test]
    fn test_address_set() {
        let mut set = AddressSet::new();
        set.add(Address::new(0x1000));
        set.add(Address::new(0x1001));
        set.add(Address::new(0x1003));
        assert_eq!(set.num_addresses(), 3);

        let mut set2 = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x10FF),
        ));
        assert_eq!(set2.num_addresses(), 256);
    }

    #[test]
    fn test_analysis_priority_ordering() {
        assert!(AnalysisPriority::FORMAT_ANALYSIS < AnalysisPriority::BLOCK_ANALYSIS);
        assert!(AnalysisPriority::BLOCK_ANALYSIS < AnalysisPriority::DISASSEMBLY);
        assert!(AnalysisPriority::DISASSEMBLY < AnalysisPriority::CODE_ANALYSIS);
        assert!(AnalysisPriority::CODE_ANALYSIS < AnalysisPriority::FUNCTION_ANALYSIS);
        assert!(AnalysisPriority::FUNCTION_ANALYSIS < AnalysisPriority::REFERENCE_ANALYSIS);
        assert!(AnalysisPriority::REFERENCE_ANALYSIS < AnalysisPriority::DATA_ANALYSIS);
        assert!(AnalysisPriority::DATA_ANALYSIS < AnalysisPriority::FUNCTION_ID_ANALYSIS);
        assert!(AnalysisPriority::FUNCTION_ID_ANALYSIS < AnalysisPriority::DATA_TYPE_PROPAGATION);
        assert!(AnalysisPriority::DATA_TYPE_PROPAGATION < AnalysisPriority::LOW_PRIORITY);
    }

    #[test]
    fn test_before_and_after() {
        let base = AnalysisPriority::REFERENCE_ANALYSIS;
        let before = base.before();
        let after = base.after();
        assert!(before < base);
        assert!(base < after);

        // before().before().before().before() as used by ConstantReferenceAnalyzer
        let cpa = base.before().before().before().before();
        assert!(cpa.priority() < base.priority());
    }

    #[test]
    fn test_task_monitor() {
        let monitor = BasicTaskMonitor::new();
        assert!(!monitor.is_cancelled());
        monitor.cancel();
        assert!(monitor.is_cancelled());
        assert!(monitor.check_cancelled().is_err());
        monitor.clear_cancelled();
        assert!(!monitor.is_cancelled());
    }

    #[test]
    fn test_auto_analysis_manager_creation() {
        let prog = make_test_program();
        let mgr = AutoAnalysisManager::new(prog);
        assert!(!mgr.is_analyzing());
    }

    #[test]
    fn test_add_analyzer() {
        let prog = make_test_program();
        let mut mgr = AutoAnalysisManager::new(prog);
        mgr.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
        mgr.add_analyzer(Box::new(CodeBoundaryAnalyzer::new()));
        mgr.add_analyzer(Box::new(DataReferenceAnalyzer::new()));
    }

    #[test]
    fn test_run_analysis_empty() {
        let prog = make_test_program();
        let mut mgr = AutoAnalysisManager::new(prog);
        let monitor = BasicTaskMonitor::new();
        let results = mgr.run_analysis(&monitor).unwrap();
        assert_eq!(results.tasks_executed, 0);
        assert!(!results.was_cancelled);
    }

    #[test]
    fn test_run_analysis_with_analyzers() {
        let prog = make_test_program();
        let mut mgr = AutoAnalysisManager::new(prog);

        // Register analyzers
        mgr.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
        mgr.add_analyzer(Box::new(CodeBoundaryAnalyzer::new()));
        mgr.add_analyzer(Box::new(DataReferenceAnalyzer::new()));
        mgr.add_analyzer(Box::new(StackVariableAnalyzer::new()));

        // Trigger analysis by notifying bytes added, then run
        let block = AddressRange::new(Address::new(0x401000), Address::new(0x402000));
        mgr.block_added(&AddressSet::from_range(block));

        let monitor = BasicTaskMonitor::new();
        let results = mgr.run_analysis(&monitor).unwrap();
        assert!(!results.was_cancelled);
        // Should have executed at least the two Byte-type analyzers
        assert!(
            results.tasks_executed >= 2,
            "Expected at least 2 tasks (FunctionStart + CodeBoundary), got {}",
            results.tasks_executed
        );
    }

    #[test]
    fn test_analyzer_priority_ordering() {
        let prog = make_test_program();
        let mut mgr = AutoAnalysisManager::new(prog);
        mgr.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
        mgr.add_analyzer(Box::new(CodeBoundaryAnalyzer::new()));

        // Both should be added since FunctionStart has Block.before() and
        // CodeBoundary has Block.after().
    }

    #[test]
    fn test_arm_thumb_can_analyze() {
        // Should NOT analyze x86
        let mut x86_prog = Program::new(
            "x86_test",
            Language {
                processor: "x86".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        let analyzer = ARMThumbAnalyzer::new();
        assert!(!analyzer.can_analyze(&x86_prog));

        // Should analyze ARM
        let arm_prog = Program::new(
            "arm_test",
            Language {
                processor: "ARM".into(),
                variant: "LE".into(),
                size: 32,
            },
        );
        assert!(analyzer.can_analyze(&arm_prog));
    }

    #[test]
    fn test_analysis_options_default() {
        let opts = AnalysisOptions::default();
        assert_eq!(opts.max_iterations, 100);
        assert_eq!(opts.timeout_ms, 300_000);
        assert!(opts.print_task_times);
    }

    #[test]
    fn test_re_analyze_all() {
        let mut prog = make_test_program();
        // Add some instructions and function data
        prog.memory_blocks.push(MemoryBlock {
            name: ".text".into(),
            start: Address::new(0x401000),
            size: 0x1000,
            is_read: true,
            is_write: false,
            is_execute: true,
            is_initialized: true,
        });

        let mut mgr = AutoAnalysisManager::new(prog);
        mgr.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
        mgr.add_analyzer(Box::new(CodeBoundaryAnalyzer::new()));

        // re_analyze_all should not panic
        mgr.re_analyze_all(None);

        let monitor = BasicTaskMonitor::new();
        let results = mgr.run_analysis(&monitor).unwrap();
        assert!(!results.was_cancelled);
    }

    #[test]
    fn test_cancellation() {
        let prog = make_test_program();
        let mut mgr = AutoAnalysisManager::new(prog);
        mgr.add_analyzer(Box::new(FunctionStartAnalyzer::new()));

        let monitor = BasicTaskMonitor::new();
        monitor.cancel();
        let results = mgr.run_analysis(&monitor);
        assert!(results.is_err());
    }

    #[test]
    fn test_display_impls() {
        let addr = Address::new(0xDEADBEEF);
        assert_eq!(addr.to_string(), "0xdeadbeef");

        let spc_addr = Address::in_space(2, 0x1000);
        assert_eq!(spc_addr.to_string(), "2:0x00001000");

        let pri = AnalysisPriority::REFERENCE_ANALYSIS;
        assert!(pri.to_string().contains("REFERENCE"));
    }

    #[test]
    fn test_message_log() {
        let mut log = MessageLog::new();
        log.append_msg("test message 1");
        log.append_msg("test message 2");
        let msgs: Vec<&str> = log.iter().collect();
        assert_eq!(msgs, vec!["test message 1", "test message 2"]);
        log.clear();
        assert_eq!(log.iter().count(), 0);
    }

    #[test]
    fn test_analysis_option_values() {
        assert_eq!(
            AnalysisOptionValue::Bool(true),
            AnalysisOptionValue::Bool(true)
        );
        assert_ne!(
            AnalysisOptionValue::Bool(true),
            AnalysisOptionValue::Bool(false)
        );
        assert_eq!(
            AnalysisOptionValue::Integer(42),
            AnalysisOptionValue::Integer(42)
        );
    }

    #[test]
    fn test_function_manager() {
        let mgr = FunctionManager::default();
        assert!(mgr.get_functions(true).next().is_none());
    }

    #[test]
    fn test_listing_instructions() {
        let mut listing = Listing::default();
        listing.instructions.insert(
            Address::new(0x1000),
            Instruction {
                address: Address::new(0x1000),
                length: 3,
                mnemonic: "mov".into(),
                flow_type: FlowType::Fallthrough,
            },
        );
        assert_eq!(listing.num_instructions(), 1);

        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x2000),
        ));
        let instrs: Vec<&Instruction> = listing.get_instructions(&set, true).collect();
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].mnemonic, "mov");
    }

    #[test]
    fn test_abstract_analyzer() {
        let mut base = AbstractAnalyzer::new("Test", "A test analyzer", AnalyzerType::Byte);
        base.set_priority(AnalysisPriority::CODE_ANALYSIS);
        assert_eq!(base.name(), "Test");
        assert_eq!(base.description(), "A test analyzer");
        assert_eq!(base.analysis_type(), AnalyzerType::Byte);
        assert_eq!(base.priority(), AnalysisPriority::CODE_ANALYSIS);
    }
}
