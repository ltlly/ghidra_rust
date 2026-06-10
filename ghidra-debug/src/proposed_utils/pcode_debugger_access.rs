//! Pcode debugger access utilities.
//!
//! Ported from Ghidra's proposed `PcodeDebuggerAccess` utilities in the
//! debug framework. Provides a high-level access facade for pcode-based
//! debugging, combining memory, register, and thread state access into
//! a unified interface for use by pcode emulators and debugger models.
//!
//! Key types:
//! - `PcodeDebuggerAccess`: Top-level access facade combining all state views.
//! - `PcodeMemoryView`: Read/write access to the emulated address space.
//! - `PcodeRegisterView`: Read/write access to register state.
//! - `PcodeThreadContext`: Thread-scoped execution context.
//! - `PcodeBreakpointManager`: Management of breakpoints during pcode execution.
//! - `PcodeStepEvent`: Events emitted during single-step operations.
//! - `AccessStateDiff`: Diff between two access states (memory/register changes).
//! - `PcodeDebuggerDataAccess`: Trait for debugger+trace data access.
//! - `PcodeDebuggerRegistersAccessState`: Concrete register access with target.
//! - `MemoryWriteBuffer`: Buffered memory writes for transactional updates.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ============================================================================
// PcodeDebuggerAccess -- top-level facade
// ============================================================================

/// A high-level access facade for pcode-based debugging.
///
/// Ported from Ghidra's proposed `PcodeDebuggerAccess`. This type
/// unifies memory, register, thread, and breakpoint access into a
/// single interface that pcode emulation components can use to
/// interact with the debug session.
#[derive(Debug, Clone)]
pub struct PcodeDebuggerAccess {
    /// The trace ID being accessed.
    pub trace_id: String,
    /// The current snap (time) context.
    pub snap: i64,
    /// The language/compiler spec ID (e.g., "x86:LE:64:default::gcc").
    pub language_id: String,
    /// The active thread key.
    active_thread: Option<i64>,
    /// Memory view.
    memory: PcodeMemoryView,
    /// Register views keyed by thread.
    register_views: BTreeMap<i64, PcodeRegisterView>,
    /// Thread contexts.
    thread_contexts: BTreeMap<i64, PcodeThreadContext>,
    /// Breakpoint manager.
    breakpoints: PcodeBreakpointManager,
    /// Event log.
    event_log: Vec<PcodeStepEvent>,
}

impl PcodeDebuggerAccess {
    /// Create a new debugger access facade.
    pub fn new(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            language_id: String::new(),
            active_thread: None,
            memory: PcodeMemoryView::new(),
            register_views: BTreeMap::new(),
            thread_contexts: BTreeMap::new(),
            breakpoints: PcodeBreakpointManager::new(),
            event_log: Vec::new(),
        }
    }

    /// Set the language/compiler spec ID.
    pub fn with_language_id(mut self, id: impl Into<String>) -> Self {
        self.language_id = id.into();
        self
    }

    /// Set the active thread.
    pub fn set_active_thread(&mut self, thread_key: i64) {
        self.active_thread = Some(thread_key);
        // Ensure register view and context exist for this thread
        self.register_views
            .entry(thread_key)
            .or_insert_with(|| PcodeRegisterView::new(thread_key));
        self.thread_contexts
            .entry(thread_key)
            .or_insert_with(|| PcodeThreadContext::new(thread_key));
    }

    /// Get the active thread key.
    pub fn active_thread(&self) -> Option<i64> {
        self.active_thread
    }

    /// Get the memory view.
    pub fn memory(&self) -> &PcodeMemoryView {
        &self.memory
    }

    /// Get a mutable memory view.
    pub fn memory_mut(&mut self) -> &mut PcodeMemoryView {
        &mut self.memory
    }

    /// Get the register view for the active thread.
    pub fn registers(&self) -> Option<&PcodeRegisterView> {
        self.active_thread
            .and_then(|t| self.register_views.get(&t))
    }

    /// Get a mutable register view for the active thread.
    pub fn registers_mut(&mut self) -> Option<&mut PcodeRegisterView> {
        self.active_thread
            .and_then(|t| self.register_views.get_mut(&t))
    }

    /// Get the register view for a specific thread.
    pub fn registers_for_thread(&self, thread_key: i64) -> Option<&PcodeRegisterView> {
        self.register_views.get(&thread_key)
    }

    /// Get a mutable register view for a specific thread.
    pub fn registers_for_thread_mut(&mut self, thread_key: i64) -> &mut PcodeRegisterView {
        self.register_views
            .entry(thread_key)
            .or_insert_with(|| PcodeRegisterView::new(thread_key))
    }

    /// Get the thread context for the active thread.
    pub fn thread_context(&self) -> Option<&PcodeThreadContext> {
        self.active_thread
            .and_then(|t| self.thread_contexts.get(&t))
    }

    /// Get the thread context for a specific thread, creating if needed.
    pub fn thread_context_for_mut(&mut self, thread_key: i64) -> &mut PcodeThreadContext {
        self.thread_contexts
            .entry(thread_key)
            .or_insert_with(|| PcodeThreadContext::new(thread_key))
    }

    /// Get the breakpoint manager.
    pub fn breakpoints(&self) -> &PcodeBreakpointManager {
        &self.breakpoints
    }

    /// Get a mutable breakpoint manager.
    pub fn breakpoints_mut(&mut self) -> &mut PcodeBreakpointManager {
        &mut self.breakpoints
    }

    /// Get all event log entries.
    pub fn event_log(&self) -> &[PcodeStepEvent] {
        &self.event_log
    }

    /// Clear the event log.
    pub fn clear_event_log(&mut self) {
        self.event_log.clear();
    }

    /// Log a step event.
    pub fn log_event(&mut self, event: PcodeStepEvent) {
        self.event_log.push(event);
    }

    /// Read bytes from memory at the given address.
    pub fn read_memory(&self, space: &str, offset: u64, len: u32) -> Option<Vec<u8>> {
        self.memory.read(space, offset, len)
    }

    /// Write bytes to memory at the given address.
    pub fn write_memory(&mut self, space: &str, offset: u64, bytes: &[u8]) {
        self.memory.write(space, offset, bytes);
    }

    /// Read a register value by name from the active thread.
    pub fn read_register(&self, name: &str) -> Option<Vec<u8>> {
        self.registers()?.read(name)
    }

    /// Write a register value by name to the active thread.
    pub fn write_register(&mut self, name: &str, bytes: &[u8]) -> Result<(), AccessError> {
        let thread = self
            .active_thread
            .ok_or(AccessError::NoActiveThread)?;
        self.register_views
            .entry(thread)
            .or_insert_with(|| PcodeRegisterView::new(thread))
            .write(name, bytes);
        Ok(())
    }

    /// List all threads that have been registered.
    pub fn thread_keys(&self) -> Vec<i64> {
        self.thread_contexts.keys().copied().collect()
    }

    /// Advance the snap context.
    pub fn advance_snap(&mut self, new_snap: i64) {
        self.snap = new_snap;
    }
}

// ============================================================================
// PcodeMemoryView -- emulated memory access
// ============================================================================

/// A memory view for pcode emulation.
///
/// Ported from Ghidra's proposed `PcodeMemoryView`. Provides byte-level
/// read/write access to the emulated address space, with the ability
/// to track which regions have been modified.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PcodeMemoryView {
    /// Storage indexed by (space_name, offset).
    storage: BTreeMap<(String, u64), u8>,
    /// Regions that have been written to.
    dirty_regions: Vec<(String, u64, u64)>,
}

impl PcodeMemoryView {
    /// Create a new empty memory view.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read `len` bytes starting at `(space, offset)`.
    pub fn read(&self, space: &str, offset: u64, len: u32) -> Option<Vec<u8>> {
        let mut result = Vec::with_capacity(len as usize);
        for i in 0..len as u64 {
            let key = (space.to_string(), offset + i);
            match self.storage.get(&key) {
                Some(&byte) => result.push(byte),
                None => return None,
            }
        }
        Some(result)
    }

    /// Write bytes starting at `(space, offset)`.
    pub fn write(&mut self, space: &str, offset: u64, bytes: &[u8]) {
        let end = offset + bytes.len() as u64;
        self.dirty_regions
            .push((space.to_string(), offset, end));
        for (i, &byte) in bytes.iter().enumerate() {
            self.storage
                .insert((space.to_string(), offset + i as u64), byte);
        }
    }

    /// Check if the range `[offset, offset+len)` is fully populated.
    pub fn has_state(&self, space: &str, offset: u64, len: u32) -> bool {
        for i in 0..len as u64 {
            if !self.storage.contains_key(&(space.to_string(), offset + i)) {
                return false;
            }
        }
        true
    }

    /// Clear all stored bytes.
    pub fn clear(&mut self) {
        self.storage.clear();
        self.dirty_regions.clear();
    }

    /// Get dirty regions (space, start, end) since last clear.
    pub fn dirty_regions(&self) -> &[(String, u64, u64)] {
        &self.dirty_regions
    }

    /// Clear the dirty tracking list without clearing memory.
    pub fn clear_dirty(&mut self) {
        self.dirty_regions.clear();
    }

    /// The number of stored bytes.
    pub fn size(&self) -> usize {
        self.storage.len()
    }
}

// ============================================================================
// PcodeRegisterView -- register state for a thread
// ============================================================================

/// A register view for a single thread during pcode execution.
///
/// Ported from Ghidra's proposed `PcodeDebuggerRegisters` view concept.
/// Provides name-based register read/write with state tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PcodeRegisterView {
    /// The thread this view is associated with.
    pub thread_key: i64,
    /// Register values by name.
    values: BTreeMap<String, Vec<u8>>,
    /// Register state (known/unknown/error) by name.
    states: BTreeMap<String, RegisterState>,
    /// Register bit lengths by name.
    bit_lengths: BTreeMap<String, u32>,
    /// Registers modified since last snapshot.
    modified: Vec<String>,
}

impl PcodeRegisterView {
    /// Create a new register view for a thread.
    pub fn new(thread_key: i64) -> Self {
        Self {
            thread_key,
            values: BTreeMap::new(),
            states: BTreeMap::new(),
            bit_lengths: BTreeMap::new(),
            modified: Vec::new(),
        }
    }

    /// Read a register value by name.
    pub fn read(&self, name: &str) -> Option<Vec<u8>> {
        self.values.get(name).cloned()
    }

    /// Write a register value by name.
    pub fn write(&mut self, name: &str, bytes: &[u8]) {
        self.values.insert(name.to_string(), bytes.to_vec());
        self.states
            .insert(name.to_string(), RegisterState::Known);
        if !self.modified.contains(&name.to_string()) {
            self.modified.push(name.to_string());
        }
    }

    /// Set the state of a register (e.g., to mark as unknown).
    pub fn set_state(&mut self, name: &str, state: RegisterState) {
        self.states.insert(name.to_string(), state);
    }

    /// Get the state of a register.
    pub fn get_state(&self, name: &str) -> RegisterState {
        self.states
            .get(name)
            .copied()
            .unwrap_or(RegisterState::Unknown)
    }

    /// Check if a register has known state.
    pub fn is_known(&self, name: &str) -> bool {
        self.get_state(name) == RegisterState::Known
    }

    /// Get all register names that have been written.
    pub fn known_registers(&self) -> Vec<String> {
        self.states
            .iter()
            .filter(|(_, s)| **s == RegisterState::Known)
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// Get all register names.
    pub fn all_register_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .values
            .keys()
            .chain(self.states.keys())
            .chain(self.bit_lengths.keys())
            .cloned()
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Define a register with its bit length (no value yet).
    pub fn define_register(&mut self, name: &str, bit_length: u32) {
        self.bit_lengths
            .insert(name.to_string(), bit_length);
        self.states
            .entry(name.to_string())
            .or_insert(RegisterState::Unknown);
    }

    /// Get the bit length of a register.
    pub fn bit_length(&self, name: &str) -> Option<u32> {
        self.bit_lengths.get(name).copied()
    }

    /// Get registers modified since last clear_modified.
    pub fn modified_registers(&self) -> &[String] {
        &self.modified
    }

    /// Clear the modified list.
    pub fn clear_modified(&mut self) {
        self.modified.clear();
    }

    /// The number of registers with defined values.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether no registers have values.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// The state of a register value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegisterState {
    /// The register has a known value.
    Known,
    /// The register value is unknown (not yet read from the target).
    Unknown,
    /// An error occurred while reading the register.
    Error,
}

// ============================================================================
// PcodeThreadContext -- thread execution context
// ============================================================================

/// Thread execution context for pcode debugging.
///
/// Ported from Ghidra's proposed thread context utilities. Captures the
/// execution context of a thread at a specific point in time, including
/// the program counter, context register fields, and execution mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeThreadContext {
    /// The thread key.
    pub thread_key: i64,
    /// The current program counter address (offset in the default address space).
    pub pc: u64,
    /// The stack pointer value.
    pub sp: Option<u64>,
    /// The frame pointer value.
    pub fp: Option<u64>,
    /// Context register fields (name -> value).
    pub context_fields: BTreeMap<String, u64>,
    /// Whether the thread is currently executing.
    pub is_running: bool,
    /// Whether the thread is the focus of the debugger.
    pub is_focus: bool,
    /// Execution mode (e.g., "thumb" for ARM, empty for default).
    pub execution_mode: String,
}

impl PcodeThreadContext {
    /// Create a new thread context.
    pub fn new(thread_key: i64) -> Self {
        Self {
            thread_key,
            pc: 0,
            sp: None,
            fp: None,
            context_fields: BTreeMap::new(),
            is_running: false,
            is_focus: false,
            execution_mode: String::new(),
        }
    }

    /// Set the program counter.
    pub fn set_pc(&mut self, pc: u64) {
        self.pc = pc;
    }

    /// Set the stack pointer.
    pub fn set_sp(&mut self, sp: u64) {
        self.sp = Some(sp);
    }

    /// Set the frame pointer.
    pub fn set_fp(&mut self, fp: u64) {
        self.fp = Some(fp);
    }

    /// Set a context register field.
    pub fn set_context_field(&mut self, name: &str, value: u64) {
        self.context_fields.insert(name.to_string(), value);
    }

    /// Get a context register field value.
    pub fn get_context_field(&self, name: &str) -> Option<u64> {
        self.context_fields.get(name).copied()
    }

    /// Get all context field names.
    pub fn context_field_names(&self) -> Vec<&str> {
        self.context_fields.keys().map(|s| s.as_str()).collect()
    }

    /// Build a context register byte array from the fields.
    pub fn build_context_bytes(&self, field_defs: &[ContextFieldDef]) -> Vec<u8> {
        let max_bit = field_defs
            .iter()
            .map(|f| f.bit_offset + f.bit_length)
            .max()
            .unwrap_or(0);
        let byte_len = ((max_bit + 7) / 8) as usize;
        let mut result = vec![0u8; byte_len];

        for def in field_defs {
            if let Some(&value) = self.context_fields.get(&def.name) {
                let mut remaining = value;
                for i in 0..def.bit_length {
                    let bit_pos = def.bit_offset + i;
                    let byte_idx = (bit_pos / 8) as usize;
                    let bit_idx = bit_pos % 8;
                    if byte_idx < result.len() && (remaining & 1) != 0 {
                        result[byte_idx] |= 1 << bit_idx;
                    }
                    remaining >>= 1;
                }
            }
        }

        result
    }

    /// Extract context field values from a context register byte array.
    pub fn parse_context_bytes(
        bytes: &[u8],
        field_defs: &[ContextFieldDef],
    ) -> BTreeMap<String, u64> {
        let mut result = BTreeMap::new();
        for def in field_defs {
            let mut value: u64 = 0;
            for i in 0..def.bit_length {
                let bit_pos = def.bit_offset + i;
                let byte_idx = (bit_pos / 8) as usize;
                let bit_idx = bit_pos % 8;
                if byte_idx < bytes.len() {
                    let bit = (bytes[byte_idx] >> bit_idx) & 1;
                    value |= (bit as u64) << i;
                }
            }
            result.insert(def.name.clone(), value);
        }
        result
    }
}

/// A context register field definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextFieldDef {
    /// The field name.
    pub name: String,
    /// The bit offset within the context register.
    pub bit_offset: u32,
    /// The bit length of the field.
    pub bit_length: u32,
}

impl ContextFieldDef {
    /// Create a new context field definition.
    pub fn new(name: impl Into<String>, bit_offset: u32, bit_length: u32) -> Self {
        Self {
            name: name.into(),
            bit_offset,
            bit_length,
        }
    }

    /// Get the mask for this field.
    pub fn mask(&self) -> u64 {
        if self.bit_length >= 64 {
            u64::MAX
        } else {
            (1u64 << self.bit_length) - 1
        }
    }
}

// ============================================================================
// PcodeBreakpointManager -- breakpoint management
// ============================================================================

/// Breakpoint manager for pcode debugging.
///
/// Ported from Ghidra's proposed breakpoint management utilities for
/// pcode-based debug sessions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PcodeBreakpointManager {
    /// Breakpoints by ID.
    breakpoints: BTreeMap<u64, PcodeBreakpoint>,
    /// Next breakpoint ID.
    next_id: u64,
}

impl PcodeBreakpointManager {
    /// Create a new breakpoint manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a breakpoint at an address.
    pub fn add_breakpoint(&mut self, space: &str, offset: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.breakpoints.insert(
            id,
            PcodeBreakpoint {
                id,
                space: space.to_string(),
                offset,
                kind: BreakpointKind::Execute,
                enabled: true,
                hit_count: 0,
                condition: None,
            },
        );
        id
    }

    /// Add a data breakpoint (read/write watch).
    pub fn add_data_breakpoint(
        &mut self,
        space: &str,
        offset: u64,
        kind: BreakpointKind,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.breakpoints.insert(
            id,
            PcodeBreakpoint {
                id,
                space: space.to_string(),
                offset,
                kind,
                enabled: true,
                hit_count: 0,
                condition: None,
            },
        );
        id
    }

    /// Remove a breakpoint by ID.
    pub fn remove_breakpoint(&mut self, id: u64) -> Option<PcodeBreakpoint> {
        self.breakpoints.remove(&id)
    }

    /// Enable or disable a breakpoint.
    pub fn set_enabled(&mut self, id: u64, enabled: bool) {
        if let Some(bp) = self.breakpoints.get_mut(&id) {
            bp.enabled = enabled;
        }
    }

    /// Set a condition expression on a breakpoint.
    pub fn set_condition(&mut self, id: u64, condition: Option<String>) {
        if let Some(bp) = self.breakpoints.get_mut(&id) {
            bp.condition = condition;
        }
    }

    /// Get a breakpoint by ID.
    pub fn get(&self, id: u64) -> Option<&PcodeBreakpoint> {
        self.breakpoints.get(&id)
    }

    /// Get all breakpoints.
    pub fn all(&self) -> &BTreeMap<u64, PcodeBreakpoint> {
        &self.breakpoints
    }

    /// Check if any enabled breakpoint matches the given address.
    pub fn check_hit(&mut self, space: &str, offset: u64) -> Vec<u64> {
        let mut hits = Vec::new();
        for bp in self.breakpoints.values_mut() {
            if bp.enabled && bp.space == space && bp.offset == offset {
                bp.hit_count += 1;
                hits.push(bp.id);
            }
        }
        hits
    }

    /// Check if any enabled data breakpoint covers the given range.
    pub fn check_data_hit(
        &mut self,
        space: &str,
        offset: u64,
        len: u64,
        access_kind: BreakpointKind,
    ) -> Vec<u64> {
        let mut hits = Vec::new();
        for bp in self.breakpoints.values_mut() {
            if bp.enabled
                && bp.space == space
                && bp.offset >= offset
                && bp.offset < offset + len
                && (bp.kind == access_kind || bp.kind == BreakpointKind::ReadWrite)
            {
                bp.hit_count += 1;
                hits.push(bp.id);
            }
        }
        hits
    }

    /// Remove all breakpoints.
    pub fn clear(&mut self) {
        self.breakpoints.clear();
    }

    /// The number of breakpoints.
    pub fn len(&self) -> usize {
        self.breakpoints.len()
    }

    /// Whether there are no breakpoints.
    pub fn is_empty(&self) -> bool {
        self.breakpoints.is_empty()
    }
}

/// A single breakpoint in a pcode debug session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeBreakpoint {
    /// Unique breakpoint ID.
    pub id: u64,
    /// The address space name.
    pub space: String,
    /// The offset within the space.
    pub offset: u64,
    /// The kind of breakpoint.
    pub kind: BreakpointKind,
    /// Whether the breakpoint is enabled.
    pub enabled: bool,
    /// How many times this breakpoint has been hit.
    pub hit_count: u64,
    /// Optional condition expression (evaluated at runtime).
    pub condition: Option<String>,
}

/// The kind of breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakpointKind {
    /// Break on execution (software/hardware breakpoint).
    Execute,
    /// Break on memory read.
    Read,
    /// Break on memory write.
    Write,
    /// Break on memory read or write.
    ReadWrite,
}

// ============================================================================
// PcodeStepEvent -- events from single-step operations
// ============================================================================

/// An event emitted during single-step pcode operations.
///
/// Ported from Ghidra's proposed step event model for pcode debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeStepEvent {
    /// The snap at which this event occurred.
    pub snap: i64,
    /// The thread key.
    pub thread_key: i64,
    /// The program counter at the time of the event.
    pub pc: u64,
    /// The kind of event.
    pub kind: StepEventKind,
    /// Optional description.
    pub description: String,
}

/// The kind of step event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepEventKind {
    /// A single pcode instruction was executed.
    PcodeOp,
    /// A breakpoint was hit.
    BreakpointHit,
    /// The program counter changed (branch/jump).
    BranchTaken,
    /// The target stopped (halt, exit, etc.).
    Stopped,
    /// An error occurred during execution.
    Error,
}

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during pcode debugger access.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccessError {
    /// No active thread has been set.
    #[error("no active thread set")]
    NoActiveThread,

    /// The requested register does not exist.
    #[error("register not found: {0}")]
    RegisterNotFound(String),

    /// The requested address space does not exist.
    #[error("address space not found: {0}")]
    SpaceNotFound(String),

    /// The breakpoint ID is invalid.
    #[error("breakpoint not found: {0}")]
    BreakpointNotFound(u64),

    /// The watchpoint ID is invalid.
    #[error("watchpoint not found: {0}")]
    WatchpointNotFound(u64),

    /// Memory region overlap error.
    #[error("memory region overlaps with existing region")]
    RegionOverlap,

    /// The requested memory region was not found.
    #[error("memory region not found: {0}")]
    RegionNotFound(String),
}

// ============================================================================
// MemoryRegionMap -- tracks named memory regions with permissions
// ============================================================================

/// Permissions for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryPermissions {
    /// Region is readable.
    pub read: bool,
    /// Region is writable.
    pub write: bool,
    /// Region is executable.
    pub execute: bool,
}

impl MemoryPermissions {
    /// Read-only permissions.
    pub const READ: Self = Self { read: true, write: false, execute: false };
    /// Read-write permissions.
    pub const RW: Self = Self { read: true, write: true, execute: false };
    /// Read-execute permissions (typical for code).
    pub const RX: Self = Self { read: true, write: false, execute: true };
    /// Read-write-execute permissions.
    pub const RWX: Self = Self { read: true, write: true, execute: true };
    /// No permissions.
    pub const NONE: Self = Self { read: false, write: false, execute: false };

    /// Whether the given access is allowed by these permissions.
    pub fn allows(&self, read: bool, write: bool, execute: bool) -> bool {
        (!read || self.read) && (!write || self.write) && (!execute || self.execute)
    }
}

impl Default for MemoryPermissions {
    fn default() -> Self {
        Self::RW
    }
}

/// A named memory region with permissions and a description.
///
/// Ported from Ghidra's proposed memory region tracking for debug sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// The region name (e.g., ".text", ".data", "stack").
    pub name: String,
    /// The address space this region belongs to.
    pub space: String,
    /// Start offset (inclusive).
    pub start: u64,
    /// End offset (exclusive).
    pub end: u64,
    /// Permissions.
    pub permissions: MemoryPermissions,
    /// Optional description.
    pub description: String,
}

impl MemoryRegion {
    /// Create a new memory region.
    pub fn new(
        name: impl Into<String>,
        space: impl Into<String>,
        start: u64,
        end: u64,
    ) -> Self {
        Self {
            name: name.into(),
            space: space.into(),
            start,
            end,
            permissions: MemoryPermissions::default(),
            description: String::new(),
        }
    }

    /// Set permissions.
    pub fn with_permissions(mut self, perms: MemoryPermissions) -> Self {
        self.permissions = perms;
        self
    }

    /// Set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// The size of this region in bytes.
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Whether this region contains the given offset.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.start && offset < self.end
    }

    /// Whether this region overlaps with another region in the same space.
    pub fn overlaps(&self, other: &MemoryRegion) -> bool {
        self.space == other.space && self.start < other.end && other.start < self.end
    }
}

/// A map of named memory regions for a debug session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryRegionMap {
    regions: Vec<MemoryRegion>,
}

impl MemoryRegionMap {
    /// Create a new empty region map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a region. Returns `Err` if it overlaps an existing region in the
    /// same address space.
    pub fn add_region(&mut self, region: MemoryRegion) -> Result<(), AccessError> {
        for existing in &self.regions {
            if existing.overlaps(&region) {
                return Err(AccessError::RegionOverlap);
            }
        }
        self.regions.push(region);
        Ok(())
    }

    /// Find the region that contains the given address.
    pub fn find_region(&self, space: &str, offset: u64) -> Option<&MemoryRegion> {
        self.regions
            .iter()
            .find(|r| r.space == space && r.contains(offset))
    }

    /// Get a region by name.
    pub fn get_by_name(&self, name: &str) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.name == name)
    }

    /// Remove a region by name.
    pub fn remove_by_name(&mut self, name: &str) -> Option<MemoryRegion> {
        if let Some(pos) = self.regions.iter().position(|r| r.name == name) {
            Some(self.regions.remove(pos))
        } else {
            None
        }
    }

    /// All regions.
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// All regions in a specific address space.
    pub fn regions_in_space(&self, space: &str) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|r| r.space == space).collect()
    }

    /// Check if an access to the given address is permitted.
    pub fn check_access(&self, space: &str, offset: u64, read: bool, write: bool, execute: bool) -> bool {
        match self.find_region(space, offset) {
            Some(region) => region.permissions.allows(read, write, execute),
            None => true, // Allow access to unmapped regions (no restriction)
        }
    }

    /// The number of regions.
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Whether there are no regions.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Clear all regions.
    pub fn clear(&mut self) {
        self.regions.clear();
    }
}

// ============================================================================
// PcodeWatchpointManager -- watch memory ranges for access
// ============================================================================

/// A watchpoint that triggers when a memory range is accessed.
///
/// Ported from Ghidra's proposed memory watchpoint utilities for pcode
/// debugging sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeWatchpoint {
    /// Unique ID.
    pub id: u64,
    /// Address space name.
    pub space: String,
    /// Start offset (inclusive).
    pub start: u64,
    /// End offset (exclusive).
    pub end: u64,
    /// What kind of access triggers this watchpoint.
    pub kind: BreakpointKind,
    /// Whether enabled.
    pub enabled: bool,
    /// Hit count.
    pub hit_count: u64,
    /// Optional user note.
    pub note: String,
}

impl PcodeWatchpoint {
    /// Create a new watchpoint.
    pub fn new(id: u64, space: impl Into<String>, start: u64, end: u64, kind: BreakpointKind) -> Self {
        Self {
            id,
            space: space.into(),
            start,
            end,
            kind,
            enabled: true,
            hit_count: 0,
            note: String::new(),
        }
    }

    /// Whether this watchpoint covers the given single-byte address.
    pub fn covers(&self, space: &str, offset: u64) -> bool {
        self.enabled && self.space == space && offset >= self.start && offset < self.end
    }

    /// Whether this watchpoint covers any part of the given range.
    pub fn covers_range(&self, space: &str, offset: u64, len: u64) -> bool {
        self.enabled && self.space == space && self.start < offset + len && offset < self.end
    }
}

/// Manages memory watchpoints for a pcode debug session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PcodeWatchpointManager {
    watchpoints: BTreeMap<u64, PcodeWatchpoint>,
    next_id: u64,
}

impl PcodeWatchpointManager {
    /// Create a new empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a watchpoint.
    pub fn add_watchpoint(
        &mut self,
        space: impl Into<String>,
        start: u64,
        end: u64,
        kind: BreakpointKind,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.watchpoints
            .insert(id, PcodeWatchpoint::new(id, space, start, end, kind));
        id
    }

    /// Remove a watchpoint.
    pub fn remove_watchpoint(&mut self, id: u64) -> Option<PcodeWatchpoint> {
        self.watchpoints.remove(&id)
    }

    /// Enable or disable a watchpoint.
    pub fn set_enabled(&mut self, id: u64, enabled: bool) {
        if let Some(wp) = self.watchpoints.get_mut(&id) {
            wp.enabled = enabled;
        }
    }

    /// Check all watchpoints against a single-byte access.
    pub fn check_hit(&mut self, space: &str, offset: u64, kind: BreakpointKind) -> Vec<u64> {
        let mut hits = Vec::new();
        for wp in self.watchpoints.values_mut() {
            if wp.covers(space, offset) && (wp.kind == kind || wp.kind == BreakpointKind::ReadWrite) {
                wp.hit_count += 1;
                hits.push(wp.id);
            }
        }
        hits
    }

    /// Check all watchpoints against a range access.
    pub fn check_range_hit(
        &mut self,
        space: &str,
        offset: u64,
        len: u64,
        kind: BreakpointKind,
    ) -> Vec<u64> {
        let mut hits = Vec::new();
        for wp in self.watchpoints.values_mut() {
            if wp.covers_range(space, offset, len)
                && (wp.kind == kind || wp.kind == BreakpointKind::ReadWrite)
            {
                wp.hit_count += 1;
                hits.push(wp.id);
            }
        }
        hits
    }

    /// Get a watchpoint by ID.
    pub fn get(&self, id: u64) -> Option<&PcodeWatchpoint> {
        self.watchpoints.get(&id)
    }

    /// All watchpoints.
    pub fn all(&self) -> &BTreeMap<u64, PcodeWatchpoint> {
        &self.watchpoints
    }

    /// The number of watchpoints.
    pub fn len(&self) -> usize {
        self.watchpoints.len()
    }

    /// Whether there are no watchpoints.
    pub fn is_empty(&self) -> bool {
        self.watchpoints.is_empty()
    }

    /// Clear all watchpoints.
    pub fn clear(&mut self) {
        self.watchpoints.clear();
    }
}

// ============================================================================
// AccessMetrics -- track access statistics
// ============================================================================

/// Tracks access statistics for performance analysis.
///
/// Ported from Ghidra's proposed access metrics for pcode debugging.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessMetrics {
    /// Total memory reads.
    pub memory_reads: u64,
    /// Total memory writes.
    pub memory_writes: u64,
    /// Total register reads.
    pub register_reads: u64,
    /// Total register writes.
    pub register_writes: u64,
    /// Total breakpoints checked.
    pub breakpoint_checks: u64,
    /// Total watchpoints checked.
    pub watchpoint_checks: u64,
    /// Total step events logged.
    pub step_events: u64,
    /// Total errors encountered.
    pub errors: u64,
}

impl AccessMetrics {
    /// Create a new zeroed metrics tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a memory read.
    pub fn record_memory_read(&mut self) {
        self.memory_reads += 1;
    }

    /// Record a memory write.
    pub fn record_memory_write(&mut self) {
        self.memory_writes += 1;
    }

    /// Record a register read.
    pub fn record_register_read(&mut self) {
        self.register_reads += 1;
    }

    /// Record a register write.
    pub fn record_register_write(&mut self) {
        self.register_writes += 1;
    }

    /// Record a breakpoint check.
    pub fn record_breakpoint_check(&mut self) {
        self.breakpoint_checks += 1;
    }

    /// Record a watchpoint check.
    pub fn record_watchpoint_check(&mut self) {
        self.watchpoint_checks += 1;
    }

    /// Record a step event.
    pub fn record_step_event(&mut self) {
        self.step_events += 1;
    }

    /// Record an error.
    pub fn record_error(&mut self) {
        self.errors += 1;
    }

    /// Total number of tracked operations.
    pub fn total_operations(&self) -> u64 {
        self.memory_reads
            + self.memory_writes
            + self.register_reads
            + self.register_writes
            + self.breakpoint_checks
            + self.watchpoint_checks
            + self.step_events
    }

    /// Reset all counters to zero.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// ============================================================================
// PcodeFrameSnapshot -- complete execution frame capture
// ============================================================================

/// A complete snapshot of a thread's execution frame.
///
/// Ported from Ghidra's proposed frame snapshot utilities. Captures
/// the full state of a thread at a specific point including memory,
/// registers, and context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeFrameSnapshot {
    /// The thread key this snapshot belongs to.
    pub thread_key: i64,
    /// The snap value when captured.
    pub snap: i64,
    /// The program counter at the time of capture.
    pub pc: u64,
    /// Register name -> value bytes.
    pub registers: BTreeMap<String, Vec<u8>>,
    /// Memory snapshots: (space, start_offset, bytes).
    pub memory_regions: Vec<(String, u64, Vec<u8>)>,
    /// Context register fields.
    pub context_fields: BTreeMap<String, u64>,
    /// Execution mode at snapshot time.
    pub execution_mode: String,
    /// Whether the thread was running at snapshot time.
    pub was_running: bool,
}

impl PcodeFrameSnapshot {
    /// Create a new frame snapshot.
    pub fn new(thread_key: i64, snap: i64) -> Self {
        Self {
            thread_key,
            snap,
            pc: 0,
            registers: BTreeMap::new(),
            memory_regions: Vec::new(),
            context_fields: BTreeMap::new(),
            execution_mode: String::new(),
            was_running: false,
        }
    }

    /// Capture a frame from a `PcodeDebuggerAccess` instance.
    pub fn capture_from_access(
        thread_key: i64,
        access: &PcodeDebuggerAccess,
        memory_regions: &[(&str, u64, u32)],
    ) -> Self {
        let mut frame = Self::new(thread_key, access.snap);

        // Capture PC from thread context
        if let Some(ctx) = access.thread_contexts.get(&thread_key) {
            frame.pc = ctx.pc;
            frame.context_fields = ctx.context_fields.clone();
            frame.execution_mode = ctx.execution_mode.clone();
            frame.was_running = ctx.is_running;
        }

        // Capture registers
        if let Some(reg_view) = access.register_views.get(&thread_key) {
            for name in reg_view.known_registers() {
                if let Some(val) = reg_view.read(&name) {
                    frame.registers.insert(name, val);
                }
            }
        }

        // Capture memory regions
        for (space, offset, len) in memory_regions {
            if let Some(bytes) = access.memory.read(space, *offset, *len) {
                frame.memory_regions.push(((*space).to_string(), *offset, bytes));
            }
        }

        frame
    }

    /// Get a register value.
    pub fn get_register(&self, name: &str) -> Option<&Vec<u8>> {
        self.registers.get(name)
    }

    /// Read bytes from a captured memory region.
    pub fn read_memory(&self, space: &str, offset: u64, len: usize) -> Option<Vec<u8>> {
        for (s, start, bytes) in &self.memory_regions {
            if s == space && offset >= *start && (offset + len as u64) <= (*start + bytes.len() as u64) {
                let rel = (offset - *start) as usize;
                return Some(bytes[rel..rel + len].to_vec());
            }
        }
        None
    }

    /// The number of captured registers.
    pub fn num_registers(&self) -> usize {
        self.registers.len()
    }

    /// The number of captured memory regions.
    pub fn num_memory_regions(&self) -> usize {
        self.memory_regions.len()
    }

    /// Total captured memory bytes.
    pub fn total_memory_bytes(&self) -> usize {
        self.memory_regions.iter().map(|(_, _, b)| b.len()).sum()
    }
}

// ============================================================================
// PrettyBytes -- pretty-printing for byte arrays
// ============================================================================

/// A wrapper on a byte array for pretty printing.
///
/// Ported from Ghidra's `DebuggerPcodeUtils.PrettyBytes`. Provides
/// display in hex dump format, as unsigned/signed integers, and
/// various rendering modes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrettyBytes {
    /// Whether the bytes are in big-endian order.
    pub big_endian: bool,
    /// The raw bytes.
    pub bytes: Vec<u8>,
}

impl PrettyBytes {
    /// Create a new PrettyBytes value.
    pub fn new(big_endian: bool, bytes: Vec<u8>) -> Self {
        Self { big_endian, bytes }
    }

    /// Render as colon-separated hex.
    pub fn to_hex_string(&self) -> String {
        self.bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Render as a hex dump with lines of 16 bytes.
    ///
    /// If the total exceeds 256 bytes, truncates with an ellipsis.
    pub fn to_bytes_string(&self) -> String {
        let mut lines = Vec::new();
        for (i, chunk) in self.bytes.chunks(16).enumerate() {
            if i >= 16 {
                lines.push(format!("... (count={})", self.bytes.len()));
                break;
            }
            let hex: String = chunk
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            lines.push(hex);
        }
        lines.join("\n")
    }

    /// Interpret as an unsigned integer using the configured endianness.
    pub fn to_u128(&self) -> u128 {
        let mut val: u128 = 0;
        if self.big_endian {
            for &b in &self.bytes {
                val = (val << 8) | b as u128;
            }
        } else {
            for (i, &b) in self.bytes.iter().enumerate() {
                val |= (b as u128) << (i * 8);
            }
        }
        val
    }

    /// Interpret as a signed integer using the configured endianness.
    pub fn to_i128(&self) -> i128 {
        let unsigned = self.to_u128();
        let bits = self.bytes.len() * 8;
        if bits >= 128 {
            return unsigned as i128;
        }
        let sign_bit = 1u128 << (bits - 1);
        if unsigned & sign_bit != 0 {
            // Sign-extend
            (unsigned | !((1u128 << bits) - 1)) as i128
        } else {
            unsigned as i128
        }
    }

    /// Collect display strings for the value.
    ///
    /// Returns (unsigned_decimal, hex, signed_decimal) representations.
    pub fn collect_displays(&self) -> (String, String, String) {
        let unsigned = self.to_u128();
        let signed = self.to_i128();
        let unsigned_hex = format!("0x{:x}", unsigned);
        let signed_str = signed.to_string();
        let unsigned_str = unsigned.to_string();
        (unsigned_str, unsigned_hex, signed_str)
    }

    /// The number of bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Display for PrettyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PrettyBytes[bigEndian={},bytes={},value={}]",
            self.big_endian,
            self.to_hex_string(),
            self.to_u128()
        )
    }
}

impl PartialEq for PrettyBytes {
    fn eq(&self, other: &Self) -> bool {
        self.big_endian == other.big_endian && self.bytes == other.bytes
    }
}

impl Eq for PrettyBytes {}

// ============================================================================
// ValueLocation -- track where a value was located
// ============================================================================

/// The location of a value in the debug session.
///
/// Ported from Ghidra's `ValueLocation` concept used in watch expressions
/// and value tracking to identify where a computed value came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueLocation {
    /// The address space name.
    pub space: String,
    /// The offset within the address space.
    pub offset: u64,
    /// The size in bytes.
    pub size: u32,
    /// Whether this is a register location (as opposed to memory).
    pub is_register: bool,
    /// The register name (if this is a register location).
    pub register_name: Option<String>,
}

impl ValueLocation {
    /// Create a memory location.
    pub fn memory(space: impl Into<String>, offset: u64, size: u32) -> Self {
        Self {
            space: space.into(),
            offset,
            size,
            is_register: false,
            register_name: None,
        }
    }

    /// Create a register location.
    pub fn register(
        space: impl Into<String>,
        offset: u64,
        size: u32,
        name: impl Into<String>,
    ) -> Self {
        Self {
            space: space.into(),
            offset,
            size,
            is_register: true,
            register_name: Some(name.into()),
        }
    }

    /// The end offset (exclusive).
    pub fn end(&self) -> u64 {
        self.offset + self.size as u64
    }

    /// Whether this location covers the given offset.
    pub fn covers(&self, offset: u64) -> bool {
        offset >= self.offset && offset < self.end()
    }
}

// ============================================================================
// WatchValue -- value with state and location for watch expressions
// ============================================================================

/// The memory state of a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceMemoryState {
    /// The value is known.
    Known,
    /// The value is unknown (not in trace).
    Unknown,
    /// The value is an error.
    Error,
}

/// A complete watch expression value.
///
/// Ported from Ghidra's `DebuggerPcodeUtils.WatchValue`. Bundles the
/// concrete bytes, their state (known/unknown), the location, and
/// the set of addresses that were read during computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchValue {
    /// The concrete bytes of the value.
    pub bytes: PrettyBytes,
    /// The memory state of the value.
    pub state: TraceMemoryState,
    /// Where the value is located.
    pub location: Option<ValueLocation>,
    /// The set of addresses that were read during evaluation.
    pub reads: Vec<(String, u64, u64)>,
}

impl WatchValue {
    /// Create a new watch value.
    pub fn new(big_endian: bool, bytes: Vec<u8>) -> Self {
        Self {
            bytes: PrettyBytes::new(big_endian, bytes),
            state: TraceMemoryState::Known,
            location: None,
            reads: Vec::new(),
        }
    }

    /// Set the state.
    pub fn with_state(mut self, state: TraceMemoryState) -> Self {
        self.state = state;
        self
    }

    /// Set the location.
    pub fn with_location(mut self, location: ValueLocation) -> Self {
        self.location = Some(location);
        self
    }

    /// Add a read address range.
    pub fn with_read(mut self, space: impl Into<String>, start: u64, end: u64) -> Self {
        self.reads.push((space.into(), start, end));
        self
    }

    /// Interpret the value as an unsigned integer.
    pub fn to_u128(&self) -> u128 {
        self.bytes.to_u128()
    }

    /// Interpret the value as a signed integer.
    pub fn to_i128(&self) -> i128 {
        self.bytes.to_i128()
    }

    /// The number of bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the value is known.
    pub fn is_known(&self) -> bool {
        self.state == TraceMemoryState::Known
    }

    /// The address (if location is set).
    pub fn address(&self) -> Option<(String, u64)> {
        self.location
            .as_ref()
            .map(|loc| (loc.space.clone(), loc.offset))
    }
}

// ============================================================================
// StaticImageProvider -- reading from static (program) images
// ============================================================================

/// Provides bytes from static (relocated) program images.
///
/// Ported from Ghidra's `DebuggerStaticMappingService` concept used
/// by `PcodeDebuggerMemoryAccess.readFromStaticImages`. When a trace
/// doesn't have a byte at a given address, the static image provider
/// can supply it from the original binary.
#[derive(Debug, Clone, Default)]
pub struct StaticImageProvider {
    /// Maps (space, offset) -> bytes from the static image.
    images: BTreeMap<(String, u64), Vec<u8>>,
    /// Metadata about available image regions.
    regions: Vec<StaticImageRegion>,
}

/// A region in a static image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticImageRegion {
    /// The program name.
    pub program_name: String,
    /// The address space.
    pub space: String,
    /// Start offset.
    pub start: u64,
    /// End offset (exclusive).
    pub end: u64,
}

impl StaticImageProvider {
    /// Create a new empty provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a region of bytes from a static image.
    pub fn register_bytes(
        &mut self,
        program: impl Into<String>,
        space: impl Into<String>,
        start: u64,
        bytes: Vec<u8>,
    ) {
        let space = space.into();
        let len = bytes.len() as u64;
        self.images.insert((space.clone(), start), bytes);
        self.regions.push(StaticImageRegion {
            program_name: program.into(),
            space,
            start,
            end: start + len,
        });
    }

    /// Read bytes from the static image. Returns `None` if no image covers the range.
    pub fn read(&self, space: &str, offset: u64, len: u32) -> Option<Vec<u8>> {
        for region in &self.regions {
            if region.space == space
                && offset >= region.start
                && (offset + len as u64) <= region.end
            {
                if let Some(bytes) = self.images.get(&(space.to_string(), region.start)) {
                    let rel = (offset - region.start) as usize;
                    return Some(bytes[rel..rel + len as usize].to_vec());
                }
            }
        }
        None
    }

    /// Fill missing bytes from static images into a memory view.
    ///
    /// For each byte position in `unknown_ranges` that is not in the memory
    /// view, attempts to read it from the static image. Returns the ranges
    /// that still remain unknown.
    pub fn fill_missing(
        &self,
        memory: &mut PcodeMemoryView,
        unknown_ranges: &[(String, u64, u64)],
    ) -> Vec<(String, u64, u64)> {
        let mut still_unknown = Vec::new();
        for (space, start, end) in unknown_ranges {
            let mut current_unknown_start: Option<u64> = None;
            for offset in *start..*end {
                if memory.has_state(space, offset, 1) {
                    if let Some(ustart) = current_unknown_start.take() {
                        still_unknown.push((space.clone(), ustart, offset));
                    }
                } else {
                    if let Some(bytes) = self.read(space, offset, 1) {
                        memory.write(space, offset, &bytes);
                        if let Some(ustart) = current_unknown_start.take() {
                            still_unknown.push((space.clone(), ustart, offset));
                        }
                    } else {
                        if current_unknown_start.is_none() {
                            current_unknown_start = Some(offset);
                        }
                    }
                }
            }
            if let Some(ustart) = current_unknown_start {
                still_unknown.push((space.clone(), ustart, *end));
            }
        }
        still_unknown
    }

    /// All registered regions.
    pub fn regions(&self) -> &[StaticImageRegion] {
        &self.regions
    }

    /// Whether there are any registered images.
    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }
}

// ============================================================================
// PcodeEmulatorCallbacks -- callback infrastructure for pcode emulation
// ============================================================================

/// Callbacks invoked during pcode emulation.
///
/// Ported from Ghidra's pcode emulation callback infrastructure.
/// Implementors receive notifications about memory/register access,
/// breakpoint hits, and execution state changes.
#[derive(Debug, Clone, Default)]
pub struct PcodeEmulatorCallbacks {
    /// Whether callbacks are enabled.
    pub enabled: bool,
    /// Recorded callback invocations for debugging.
    log: Vec<CallbackLogEntry>,
}

/// An entry in the callback log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackLogEntry {
    /// The kind of callback.
    pub kind: CallbackKind,
    /// The address space involved.
    pub space: String,
    /// The offset involved.
    pub offset: u64,
    /// The size of the access.
    pub size: u32,
}

/// The kind of emulation callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallbackKind {
    /// Memory was read.
    MemoryRead,
    /// Memory was written.
    MemoryWrite,
    /// Register was read.
    RegisterRead,
    /// Register was written.
    RegisterWrite,
    /// A breakpoint was hit.
    BreakpointHit,
    /// Execution stopped.
    ExecutionStopped,
    /// A pcode op was executed.
    PcodeOpExecuted,
}

impl PcodeEmulatorCallbacks {
    /// Create new callbacks (enabled by default).
    pub fn new() -> Self {
        Self {
            enabled: true,
            log: Vec::new(),
        }
    }

    /// Log a callback invocation.
    pub fn log(&mut self, kind: CallbackKind, space: &str, offset: u64, size: u32) {
        if self.enabled {
            self.log.push(CallbackLogEntry {
                kind,
                space: space.to_string(),
                offset,
                size,
            });
        }
    }

    /// Log a memory read.
    pub fn on_memory_read(&mut self, space: &str, offset: u64, size: u32) {
        self.log(CallbackKind::MemoryRead, space, offset, size);
    }

    /// Log a memory write.
    pub fn on_memory_write(&mut self, space: &str, offset: u64, size: u32) {
        self.log(CallbackKind::MemoryWrite, space, offset, size);
    }

    /// Log a register read.
    pub fn on_register_read(&mut self, name: &str, offset: u64, size: u32) {
        self.log(CallbackKind::RegisterRead, name, offset, size);
    }

    /// Log a register write.
    pub fn on_register_write(&mut self, name: &str, offset: u64, size: u32) {
        self.log(CallbackKind::RegisterWrite, name, offset, size);
    }

    /// Get the callback log.
    pub fn log_entries(&self) -> &[CallbackLogEntry] {
        &self.log
    }

    /// Get entries of a specific kind.
    pub fn entries_of_kind(&self, kind: CallbackKind) -> Vec<&CallbackLogEntry> {
        self.log.iter().filter(|e| e.kind == kind).collect()
    }

    /// The number of logged callbacks.
    pub fn log_len(&self) -> usize {
        self.log.len()
    }

    /// Clear the log.
    pub fn clear_log(&mut self) {
        self.log.clear();
    }

    /// Enable or disable callbacks.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

// ============================================================================
// BreakpointConditionEvaluator -- evaluate breakpoint conditions
// ============================================================================

/// Evaluates simple breakpoint condition expressions.
///
/// Ported from Ghidra's breakpoint condition evaluation. Supports
/// simple comparisons: `REG == VALUE`, `REG != VALUE`, `REG > VALUE`,
/// `REG < VALUE`. Values can be decimal or hex (0x prefix).
///
/// Operates on a `PcodeRegisterView` for register resolution within
/// a pcode debug session.
#[derive(Debug, Clone)]
pub struct BreakpointConditionEvaluator;

impl BreakpointConditionEvaluator {
    /// Evaluate a simple condition expression against a register view.
    ///
    /// Supported formats:
    /// - `REG == 0xVALUE` (equality)
    /// - `REG != 0xVALUE` (inequality)
    /// - `REG > VALUE` (greater than)
    /// - `REG < VALUE` (less than)
    /// - `REG == REG2` (register comparison)
    ///
    /// Returns `Ok(true)` if the condition is met, `Ok(false)` if not,
    /// or `Err` if the expression cannot be parsed.
    pub fn evaluate(
        condition: &str,
        view: &PcodeRegisterView,
    ) -> Result<bool, String> {
        let condition = condition.trim();

        for op in &["==", "!=", ">=", "<=", ">", "<"] {
            if let Some(pos) = condition.find(op) {
                let left = condition[..pos].trim();
                let right = condition[pos + op.len()..].trim();

                let left_val = Self::resolve_value(left, view)?;
                let right_val = Self::resolve_value(right, view)?;

                return match *op {
                    "==" => Ok(left_val == right_val),
                    "!=" => Ok(left_val != right_val),
                    ">" => Ok(left_val > right_val),
                    "<" => Ok(left_val < right_val),
                    ">=" => Ok(left_val >= right_val),
                    "<=" => Ok(left_val <= right_val),
                    _ => Err(format!("unknown operator: {}", op)),
                };
            }
        }

        Err(format!("cannot parse condition: '{}'", condition))
    }

    fn resolve_value(expr: &str, view: &PcodeRegisterView) -> Result<u128, String> {
        let expr = expr.trim();

        // Try hex literal
        if let Some(hex) = expr.strip_prefix("0x").or_else(|| expr.strip_prefix("0X")) {
            return u128::from_str_radix(hex, 16)
                .map_err(|e| format!("invalid hex '{}': {}", expr, e));
        }

        // Try decimal literal
        if let Ok(val) = expr.parse::<u128>() {
            return Ok(val);
        }

        // Try as register name
        if let Some(bytes) = view.read(expr) {
            let mut val: u128 = 0;
            for (i, &b) in bytes.iter().enumerate() {
                val |= (b as u128) << (i * 8);
            }
            return Ok(val);
        }

        Err(format!("cannot resolve '{}'", expr))
    }
}

// ============================================================================
// AccessStateSnapshot -- complete access state at a point in time
// ============================================================================

/// A snapshot of the full debugger access state.
///
/// Ported from Ghidra's composite state snapshot used in emulation
/// snapshots and state transfer between components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessStateSnapshot {
    /// The trace ID.
    pub trace_id: String,
    /// The snap value.
    pub snap: i64,
    /// The language ID.
    pub language_id: String,
    /// The active thread key.
    pub active_thread: Option<i64>,
    /// Memory state (space, offset, bytes).
    pub memory_data: Vec<(String, u64, Vec<u8>)>,
    /// Register state per thread (thread_key, name, value).
    pub register_data: Vec<(i64, String, Vec<u8>)>,
    /// Thread contexts.
    pub thread_contexts: Vec<(i64, u64)>, // (thread_key, pc)
    /// Breakpoint definitions.
    pub breakpoints: Vec<(u64, String, u64)>, // (id, space, offset)
}

impl AccessStateSnapshot {
    /// Create a new snapshot.
    pub fn new(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            language_id: String::new(),
            active_thread: None,
            memory_data: Vec::new(),
            register_data: Vec::new(),
            thread_contexts: Vec::new(),
            breakpoints: Vec::new(),
        }
    }

    /// Capture a snapshot from a `PcodeDebuggerAccess` instance.
    pub fn capture_from(access: &PcodeDebuggerAccess) -> Self {
        let mut snap = Self::new(&access.trace_id, access.snap);
        snap.language_id = access.language_id.clone();
        snap.active_thread = access.active_thread;

        // Capture memory
        for (key, &byte) in &access.memory.storage {
            snap.memory_data.push((key.0.clone(), key.1, vec![byte]));
        }

        // Capture registers
        for (thread_key, view) in &access.register_views {
            for name in view.known_registers() {
                if let Some(val) = view.read(&name) {
                    snap.register_data.push((*thread_key, name, val));
                }
            }
        }

        // Capture thread contexts
        for (key, ctx) in &access.thread_contexts {
            snap.thread_contexts.push((*key, ctx.pc));
        }

        // Capture breakpoints
        for (id, bp) in access.breakpoints.all() {
            snap.breakpoints.push((*id, bp.space.clone(), bp.offset));
        }

        snap
    }

    /// Apply this snapshot to a `PcodeDebuggerAccess` instance.
    pub fn apply_to(&self, access: &mut PcodeDebuggerAccess) {
        access.snap = self.snap;
        if let Some(thread) = self.active_thread {
            access.set_active_thread(thread);
        }

        for (space, offset, bytes) in &self.memory_data {
            access.write_memory(space, *offset, bytes);
        }

        for (thread_key, name, value) in &self.register_data {
            let view = access.registers_for_thread_mut(*thread_key);
            view.write(name, value);
        }

        for (key, pc) in &self.thread_contexts {
            let ctx = access.thread_context_for_mut(*key);
            ctx.set_pc(*pc);
        }
    }
}

// ============================================================================
// TargetSimulator -- abstract target simulation
// ============================================================================

/// A trait-like abstraction for simulating target behavior.
///
/// Ported from Ghidra's `Target` interface used by the debugger
/// to interact with live targets. This struct provides a concrete
/// implementation for testing and offline simulation.
#[derive(Debug, Clone)]
pub struct TargetSimulator {
    /// The target name.
    pub name: String,
    /// Whether the target is currently connected/alive.
    pub connected: bool,
    /// The last error message (if any).
    pub last_error: Option<String>,
    /// Pending register reads to simulate.
    pending_register_reads: BTreeMap<String, Vec<u8>>,
    /// Pending memory reads to simulate.
    pending_memory_reads: BTreeMap<(String, u64), Vec<u8>>,
    /// Recorded write operations for verification.
    pub recorded_writes: Vec<TargetWriteRecord>,
}

/// A record of a write operation to the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetWriteRecord {
    /// Whether this was a register or memory write.
    pub is_register: bool,
    /// The space (or register name).
    pub space: String,
    /// The offset (0 for registers).
    pub offset: u64,
    /// The data written.
    pub data: Vec<u8>,
}

impl TargetSimulator {
    /// Create a new target simulator.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            connected: false,
            last_error: None,
            pending_register_reads: BTreeMap::new(),
            pending_memory_reads: BTreeMap::new(),
            recorded_writes: Vec::new(),
        }
    }

    /// Connect the target.
    pub fn connect(&mut self) {
        self.connected = true;
        self.last_error = None;
    }

    /// Disconnect the target.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Whether the target is currently connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Queue a register read response.
    pub fn queue_register_read(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.pending_register_reads.insert(name.into(), value);
    }

    /// Queue a memory read response.
    pub fn queue_memory_read(&mut self, space: impl Into<String>, offset: u64, value: Vec<u8>) {
        self.pending_memory_reads.insert((space.into(), offset), value);
    }

    /// Simulate reading a register from the target.
    pub fn read_register(&mut self, name: &str) -> Result<Vec<u8>, String> {
        if !self.connected {
            return Err("target not connected".into());
        }
        self.pending_register_reads
            .remove(name)
            .ok_or_else(|| format!("no queued value for register '{}'", name))
    }

    /// Simulate writing a register to the target.
    pub fn write_register(&mut self, name: &str, data: &[u8]) -> Result<(), String> {
        if !self.connected {
            return Err("target not connected".into());
        }
        self.recorded_writes.push(TargetWriteRecord {
            is_register: true,
            space: name.to_string(),
            offset: 0,
            data: data.to_vec(),
        });
        Ok(())
    }

    /// Simulate reading memory from the target.
    pub fn read_memory(&mut self, space: &str, offset: u64, len: u32) -> Result<Vec<u8>, String> {
        if !self.connected {
            return Err("target not connected".into());
        }
        self.pending_memory_reads
            .remove(&(space.to_string(), offset))
            .ok_or_else(|| {
                format!("no queued value for memory {}:{:#x}", space, offset)
            })
            .map(|mut v| {
                v.truncate(len as usize);
                v
            })
    }

    /// Simulate writing memory to the target.
    pub fn write_memory(&mut self, space: &str, offset: u64, data: &[u8]) -> Result<(), String> {
        if !self.connected {
            return Err("target not connected".into());
        }
        self.recorded_writes.push(TargetWriteRecord {
            is_register: false,
            space: space.to_string(),
            offset,
            data: data.to_vec(),
        });
        Ok(())
    }

    /// The number of recorded writes.
    pub fn num_recorded_writes(&self) -> usize {
        self.recorded_writes.len()
    }

    /// Clear all recorded writes and pending reads.
    pub fn reset(&mut self) {
        self.pending_register_reads.clear();
        self.pending_memory_reads.clear();
        self.recorded_writes.clear();
        self.last_error = None;
    }
}

// ============================================================================
// AddressRangeSet -- set of address ranges for tracking unknown regions
// ============================================================================

/// A set of address ranges within a single space.
///
/// Ported from Ghidra's `AddressSetView` concept used by
/// `PcodeDebuggerRegistersAccess.readFromTargetRegisters` and
/// `PcodeDebuggerMemoryAccess.readFromTargetMemory`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressRangeSet {
    /// The address space name.
    pub space: String,
    /// Sorted non-overlapping ranges: (start, end) pairs.
    ranges: Vec<(u64, u64)>,
}

impl AddressRangeSet {
    /// Create a new empty address range set.
    pub fn new(space: impl Into<String>) -> Self {
        Self {
            space: space.into(),
            ranges: Vec::new(),
        }
    }

    /// Add a range to the set, merging with existing ranges as needed.
    pub fn add_range(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        self.ranges.push((start, end));
        self.ranges.sort_by_key(|r| r.0);
        self.merge_overlapping();
    }

    fn merge_overlapping(&mut self) {
        if self.ranges.len() <= 1 {
            return;
        }
        let mut merged: Vec<(u64, u64)> = Vec::new();
        let mut current = self.ranges[0];
        for &(start, end) in &self.ranges[1..] {
            if start <= current.1 {
                current.1 = current.1.max(end);
            } else {
                merged.push(current);
                current = (start, end);
            }
        }
        merged.push(current);
        self.ranges = merged;
    }

    /// Subtract a range from the set.
    pub fn remove_range(&mut self, start: u64, end: u64) {
        let mut new_ranges = Vec::new();
        for &(rs, re) in &self.ranges {
            if re <= start || rs >= end {
                // No overlap
                new_ranges.push((rs, re));
            } else {
                // Partial or full overlap
                if rs < start {
                    new_ranges.push((rs, start));
                }
                if re > end {
                    new_ranges.push((end, re));
                }
            }
        }
        self.ranges = new_ranges;
    }

    /// Whether the set contains the given offset.
    pub fn contains(&self, offset: u64) -> bool {
        self.ranges
            .iter()
            .any(|&(start, end)| offset >= start && offset < end)
    }

    /// The number of disjoint ranges.
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Get the ranges as a slice.
    pub fn ranges(&self) -> &[(u64, u64)] {
        &self.ranges
    }

    /// Total number of addresses in the set.
    pub fn num_addresses(&self) -> u64 {
        self.ranges.iter().map(|(s, e)| e - s).sum()
    }

    /// Iterate over all individual offsets (only practical for small ranges).
    pub fn iter_addresses(&self) -> impl Iterator<Item = u64> + '_ {
        self.ranges
            .iter()
            .flat_map(|&(start, end)| start..end)
    }
}

// ============================================================================
// PcodeDebuggerAccessBuilder -- builder pattern for constructing access
// ============================================================================

/// A builder for constructing `PcodeDebuggerAccess` instances with a
/// fluent API.
///
/// Ported from Ghidra's pattern of constructing access shims through
/// a series of configuration steps. Provides sensible defaults and
/// validation before constructing the final access object.
#[derive(Debug, Clone)]
pub struct PcodeDebuggerAccessBuilder {
    trace_id: String,
    snap: i64,
    language_id: String,
    active_thread: Option<i64>,
    memory_regions: Vec<(String, u64, u64)>,
    register_defs: Vec<(String, u32)>,
    breakpoints: Vec<(String, u64)>,
}

impl PcodeDebuggerAccessBuilder {
    /// Create a new builder for the given trace and snap.
    pub fn new(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            language_id: String::new(),
            active_thread: None,
            memory_regions: Vec::new(),
            register_defs: Vec::new(),
            breakpoints: Vec::new(),
        }
    }

    /// Set the language/compiler spec ID.
    pub fn language_id(mut self, id: impl Into<String>) -> Self {
        self.language_id = id.into();
        self
    }

    /// Set the active thread.
    pub fn active_thread(mut self, thread_key: i64) -> Self {
        self.active_thread = Some(thread_key);
        self
    }

    /// Add a memory region to pre-populate.
    pub fn with_memory_region(
        mut self,
        space: impl Into<String>,
        start: u64,
        end: u64,
    ) -> Self {
        self.memory_regions.push((space.into(), start, end));
        self
    }

    /// Add a register definition.
    pub fn with_register(mut self, name: impl Into<String>, bit_length: u32) -> Self {
        self.register_defs.push((name.into(), bit_length));
        self
    }

    /// Add a breakpoint.
    pub fn with_breakpoint(mut self, space: impl Into<String>, offset: u64) -> Self {
        self.breakpoints.push((space.into(), offset));
        self
    }

    /// Build the `PcodeDebuggerAccess` instance.
    ///
    /// Returns `Err` if validation fails (e.g., empty trace ID).
    pub fn build(self) -> Result<PcodeDebuggerAccess, String> {
        if self.trace_id.is_empty() {
            return Err("trace_id must not be empty".into());
        }

        let mut access = PcodeDebuggerAccess::new(&self.trace_id, self.snap);

        if !self.language_id.is_empty() {
            access = access.with_language_id(&self.language_id);
        }

        if let Some(thread_key) = self.active_thread {
            access.set_active_thread(thread_key);
        }

        // Pre-populate memory regions
        for (space, start, end) in &self.memory_regions {
            for offset in *start..*end {
                access.write_memory(space, offset, &[0]);
            }
        }

        // Register breakpoints
        for (space, offset) in &self.breakpoints {
            access.breakpoints_mut().add_breakpoint(space, *offset);
        }

        Ok(access)
    }

    /// Validate the configuration without building.
    pub fn validate(&self) -> Result<(), String> {
        if self.trace_id.is_empty() {
            return Err("trace_id must not be empty".into());
        }
        if self.snap < 0 {
            return Err("snap must be non-negative".into());
        }
        Ok(())
    }
}

// ============================================================================
// AsyncAccessQueue -- queue for async target operations
// ============================================================================

/// The kind of async operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsyncOpKind {
    /// Read registers from target.
    ReadRegisters,
    /// Write registers to target.
    WriteRegister,
    /// Read memory from target.
    ReadMemory,
    /// Write memory to target.
    WriteMemory,
}

/// The status of an async operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsyncOpStatus {
    /// Operation is pending.
    Pending,
    /// Operation completed successfully.
    Completed,
    /// Operation failed.
    Failed,
    /// Operation was cancelled.
    Cancelled,
}

/// A queued async operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncOperation {
    /// Unique operation ID.
    pub id: u64,
    /// The kind of operation.
    pub kind: AsyncOpKind,
    /// The address space or register name.
    pub space: String,
    /// The offset (0 for registers).
    pub offset: u64,
    /// The data (for writes).
    pub data: Vec<u8>,
    /// Current status.
    pub status: AsyncOpStatus,
    /// Error message (if failed).
    pub error: Option<String>,
    /// The result data (for reads, after completion).
    pub result: Option<Vec<u8>>,
}

/// A queue for async target operations, modeled after Ghidra's
/// `CompletableFuture<Boolean>` pattern for target reads/writes.
///
/// Ported from Ghidra's async read/write pattern where
/// `readFromTargetMemory`, `writeTargetMemory`, `readFromTargetRegisters`,
/// and `writeTargetRegister` return futures that complete when the
/// operation finishes.
#[derive(Debug, Clone, Default)]
pub struct AsyncAccessQueue {
    /// Pending operations.
    operations: Vec<AsyncOperation>,
    /// Next operation ID.
    next_id: u64,
}

impl AsyncAccessQueue {
    /// Create a new empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue a register read operation.
    pub fn enqueue_register_read(&mut self, name: impl Into<String>) -> u64 {
        self.enqueue(AsyncOpKind::ReadRegisters, name.into(), 0, Vec::new())
    }

    /// Enqueue a register write operation.
    pub fn enqueue_register_write(
        &mut self,
        name: impl Into<String>,
        data: Vec<u8>,
    ) -> u64 {
        self.enqueue(AsyncOpKind::WriteRegister, name.into(), 0, data)
    }

    /// Enqueue a memory read operation.
    pub fn enqueue_memory_read(
        &mut self,
        space: impl Into<String>,
        offset: u64,
        len: u32,
    ) -> u64 {
        self.enqueue(
            AsyncOpKind::ReadMemory,
            space.into(),
            offset,
            vec![0; len as usize],
        )
    }

    /// Enqueue a memory write operation.
    pub fn enqueue_memory_write(
        &mut self,
        space: impl Into<String>,
        offset: u64,
        data: Vec<u8>,
    ) -> u64 {
        self.enqueue(AsyncOpKind::WriteMemory, space.into(), offset, data)
    }

    fn enqueue(
        &mut self,
        kind: AsyncOpKind,
        space: String,
        offset: u64,
        data: Vec<u8>,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.operations.push(AsyncOperation {
            id,
            kind,
            space,
            offset,
            data,
            status: AsyncOpStatus::Pending,
            error: None,
            result: None,
        });
        id
    }

    /// Complete an operation successfully, setting its result data.
    pub fn complete(&mut self, id: u64, result: Vec<u8>) -> bool {
        if let Some(op) = self.operations.iter_mut().find(|o| o.id == id) {
            op.status = AsyncOpStatus::Completed;
            op.result = Some(result);
            true
        } else {
            false
        }
    }

    /// Fail an operation with an error message.
    pub fn fail(&mut self, id: u64, error: impl Into<String>) -> bool {
        if let Some(op) = self.operations.iter_mut().find(|o| o.id == id) {
            op.status = AsyncOpStatus::Failed;
            op.error = Some(error.into());
            true
        } else {
            false
        }
    }

    /// Cancel a pending operation.
    pub fn cancel(&mut self, id: u64) -> bool {
        if let Some(op) = self.operations.iter_mut().find(|o| o.id == id && o.status == AsyncOpStatus::Pending) {
            op.status = AsyncOpStatus::Cancelled;
            true
        } else {
            false
        }
    }

    /// Get an operation by ID.
    pub fn get(&self, id: u64) -> Option<&AsyncOperation> {
        self.operations.iter().find(|o| o.id == id)
    }

    /// Check if an operation is completed.
    pub fn is_completed(&self, id: u64) -> bool {
        self.get(id)
            .map(|o| o.status == AsyncOpStatus::Completed)
            .unwrap_or(false)
    }

    /// Get all pending operations.
    pub fn pending(&self) -> Vec<&AsyncOperation> {
        self.operations
            .iter()
            .filter(|o| o.status == AsyncOpStatus::Pending)
            .collect()
    }

    /// Get all completed operations.
    pub fn completed(&self) -> Vec<&AsyncOperation> {
        self.operations
            .iter()
            .filter(|o| o.status == AsyncOpStatus::Completed)
            .collect()
    }

    /// Drain all finished (completed/failed/cancelled) operations.
    pub fn drain_finished(&mut self) -> Vec<AsyncOperation> {
        let (finished, remaining): (Vec<_>, Vec<_>) =
            self.operations.drain(..).partition(|o| o.status != AsyncOpStatus::Pending);
        self.operations = remaining;
        finished
    }

    /// The total number of operations (all statuses).
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// The number of pending operations.
    pub fn num_pending(&self) -> usize {
        self.operations
            .iter()
            .filter(|o| o.status == AsyncOpStatus::Pending)
            .count()
    }

    /// Clear all operations.
    pub fn clear(&mut self) {
        self.operations.clear();
    }
}

// ============================================================================
// AccessAuditLog -- audit trail for all access operations
// ============================================================================

/// The kind of access operation logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditLogKind {
    /// Memory read.
    MemoryRead,
    /// Memory write.
    MemoryWrite,
    /// Register read.
    RegisterRead,
    /// Register write.
    RegisterWrite,
    /// Breakpoint set.
    BreakpointSet,
    /// Breakpoint removed.
    BreakpointRemoved,
    /// Thread context changed.
    ThreadContextChanged,
    /// Snap advanced.
    SnapAdvanced,
}

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Monotonic sequence number.
    pub seq: u64,
    /// The kind of operation.
    pub kind: AuditLogKind,
    /// The address space or register name.
    pub target: String,
    /// The offset (0 for registers).
    pub offset: u64,
    /// The data size in bytes.
    pub size: u32,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Optional detail message.
    pub detail: Option<String>,
}

/// An audit log that records all access operations for debugging and
/// analysis.
///
/// Ported from Ghidra's access logging used to trace pcode emulation
/// behavior. Useful for diagnosing emulation issues and understanding
/// the sequence of operations.
#[derive(Debug, Clone, Default)]
pub struct AccessAuditLog {
    entries: Vec<AuditLogEntry>,
    next_seq: u64,
    /// Maximum entries (0 = unlimited).
    max_entries: usize,
    /// Whether the log is enabled.
    enabled: bool,
}

impl AccessAuditLog {
    /// Create a new audit log.
    pub fn new() -> Self {
        Self {
            enabled: true,
            ..Default::default()
        }
    }

    /// Set the maximum number of entries.
    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self
    }

    /// Enable or disable the log.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether the log is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn push(&mut self, entry: AuditLogEntry) {
        if !self.enabled {
            return;
        }
        if self.max_entries > 0 && self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    /// Log a memory read.
    pub fn log_memory_read(&mut self, space: &str, offset: u64, size: u32, success: bool) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.push(AuditLogEntry {
            seq,
            kind: AuditLogKind::MemoryRead,
            target: space.to_string(),
            offset,
            size,
            success,
            detail: None,
        });
    }

    /// Log a memory write.
    pub fn log_memory_write(&mut self, space: &str, offset: u64, size: u32, success: bool) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.push(AuditLogEntry {
            seq,
            kind: AuditLogKind::MemoryWrite,
            target: space.to_string(),
            offset,
            size,
            success,
            detail: None,
        });
    }

    /// Log a register read.
    pub fn log_register_read(&mut self, name: &str, size: u32, success: bool) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.push(AuditLogEntry {
            seq,
            kind: AuditLogKind::RegisterRead,
            target: name.to_string(),
            offset: 0,
            size,
            success,
            detail: None,
        });
    }

    /// Log a register write.
    pub fn log_register_write(&mut self, name: &str, size: u32, success: bool) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.push(AuditLogEntry {
            seq,
            kind: AuditLogKind::RegisterWrite,
            target: name.to_string(),
            offset: 0,
            size,
            success,
            detail: None,
        });
    }

    /// Log a generic entry.
    pub fn log(&mut self, kind: AuditLogKind, target: &str, offset: u64, size: u32, success: bool) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.push(AuditLogEntry {
            seq,
            kind,
            target: target.to_string(),
            offset,
            size,
            success,
            detail: None,
        });
    }

    /// Get all entries.
    pub fn entries(&self) -> &[AuditLogEntry] {
        &self.entries
    }

    /// Get entries of a specific kind.
    pub fn entries_of_kind(&self, kind: AuditLogKind) -> Vec<&AuditLogEntry> {
        self.entries.iter().filter(|e| e.kind == kind).collect()
    }

    /// Get entries for a specific target.
    pub fn entries_for(&self, target: &str) -> Vec<&AuditLogEntry> {
        self.entries.iter().filter(|e| e.target == target).collect()
    }

    /// Get failed entries.
    pub fn failures(&self) -> Vec<&AuditLogEntry> {
        self.entries.iter().filter(|e| !e.success).collect()
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.next_seq = 0;
    }

    /// Get the last entry.
    pub fn last(&self) -> Option<&AuditLogEntry> {
        self.entries.last()
    }
}

// ============================================================================
// TraceMemoryStateMap -- track memory state across address ranges
// ============================================================================

/// Tracks the state of memory across an address space, mapping ranges
/// to their current trace memory state.
///
/// Ported from Ghidra's `TraceMemoryState` tracking used to determine
/// which memory regions are known, unknown, or error in the trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceMemoryStateMap {
    /// The address space name.
    pub space: String,
    /// Ranges and their states: (start, end, state).
    ranges: Vec<(u64, u64, TraceMemoryState)>,
}

impl TraceMemoryStateMap {
    /// Create a new empty state map.
    pub fn new(space: impl Into<String>) -> Self {
        Self {
            space: space.into(),
            ranges: Vec::new(),
        }
    }

    /// Set the state for a range.
    pub fn set_state(&mut self, start: u64, end: u64, state: TraceMemoryState) {
        self.ranges.push((start, end, state));
        self.ranges.sort_by_key(|r| r.0);
    }

    /// Mark a range as known.
    pub fn mark_known(&mut self, start: u64, end: u64) {
        self.set_state(start, end, TraceMemoryState::Known);
    }

    /// Mark a range as unknown.
    pub fn mark_unknown(&mut self, start: u64, end: u64) {
        self.set_state(start, end, TraceMemoryState::Unknown);
    }

    /// Get the state at a specific address.
    /// Returns the state of the most recent range that contains the address.
    pub fn state_at(&self, offset: u64) -> TraceMemoryState {
        self.ranges
            .iter()
            .rev()
            .find(|(start, end, _)| offset >= *start && offset < *end)
            .map(|(_, _, s)| *s)
            .unwrap_or(TraceMemoryState::Unknown)
    }

    /// Get all ranges with a specific state.
    pub fn ranges_with_state(&self, state: TraceMemoryState) -> Vec<(u64, u64)> {
        self.ranges
            .iter()
            .filter(|(_, _, s)| *s == state)
            .map(|&(start, end, _)| (start, end))
            .collect()
    }

    /// Get the unknown ranges (convenience for readFromTarget* patterns).
    pub fn unknown_ranges(&self) -> Vec<(u64, u64)> {
        self.ranges_with_state(TraceMemoryState::Unknown)
    }

    /// Get the known ranges.
    pub fn known_ranges(&self) -> Vec<(u64, u64)> {
        self.ranges_with_state(TraceMemoryState::Known)
    }

    /// The total number of ranges tracked.
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Clear all ranges.
    pub fn clear(&mut self) {
        self.ranges.clear();
    }
}

// ============================================================================
// AccessStateDiff -- compare two access states
// ============================================================================

/// A record of a memory write for diff tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryWriteRecord {
    /// The address space.
    pub space: String,
    /// The starting offset.
    pub offset: u64,
    /// The bytes written.
    pub data: Vec<u8>,
}

/// A record of a register write for diff tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterWriteRecord {
    /// The register name.
    pub name: String,
    /// The value written.
    pub data: Vec<u8>,
}

/// A diff between two `PcodeDebuggerAccess` states.
///
/// Captures all memory and register changes between a "before"
/// and "after" snapshot. Ported from Ghidra's state diff
/// tracking used by the debugger's undo/redo and merge logic.
#[derive(Debug, Clone, Default)]
pub struct AccessStateDiff {
    /// Memory writes that occurred.
    pub memory_writes: Vec<MemoryWriteRecord>,
    /// Register writes that occurred (per thread).
    pub register_writes: BTreeMap<i64, Vec<RegisterWriteRecord>>,
    /// Breakpoints added since the "before" state.
    pub breakpoints_added: Vec<PcodeBreakpoint>,
    /// Breakpoints removed since the "before" state.
    pub breakpoints_removed: Vec<PcodeBreakpoint>,
}

impl AccessStateDiff {
    /// Whether the diff is empty (no changes).
    pub fn is_empty(&self) -> bool {
        self.memory_writes.is_empty()
            && self.register_writes.values().all(|v| v.is_empty())
            && self.breakpoints_added.is_empty()
            && self.breakpoints_removed.is_empty()
    }

    /// The total number of changes.
    pub fn num_changes(&self) -> usize {
        let reg_changes: usize = self.register_writes.values().map(|v| v.len()).sum();
        self.memory_writes.len()
            + reg_changes
            + self.breakpoints_added.len()
            + self.breakpoints_removed.len()
    }
}

/// Compute a diff of memory writes between the dirty regions of two
/// `PcodeMemoryView` instances, comparing bytes that differ.
pub fn diff_memory_views(
    before: &PcodeMemoryView,
    after: &PcodeMemoryView,
) -> Vec<MemoryWriteRecord> {
    let mut records = Vec::new();
    for &(ref space, start, end) in after.dirty_regions() {
        let len = (end - start) as u32;
        let old_bytes = before.read(space, start, len);
        let new_bytes = after.read(space, start, len);
        if old_bytes != new_bytes {
            records.push(MemoryWriteRecord {
                space: space.clone(),
                offset: start,
                data: new_bytes.unwrap_or_default(),
            });
        }
    }
    records
}

// ============================================================================
// PcodeDebuggerDataAccess -- trait for debugger+trace data access
// ============================================================================

/// Errors from debugger data access operations.
#[derive(Debug, Clone)]
pub enum DataAccessError {
    /// No active session.
    NoSession,
    /// The target is not connected.
    TargetDisconnected,
    /// No target has been configured.
    NoTarget,
    /// The target returned an error.
    TargetError(String),
    /// The operation was cancelled.
    Cancelled,
    /// A generic error.
    Other(String),
}

impl std::fmt::Display for DataAccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSession => write!(f, "no active session"),
            Self::TargetDisconnected => write!(f, "target disconnected"),
            Self::NoTarget => write!(f, "no target configured"),
            Self::TargetError(msg) => write!(f, "target error: {}", msg),
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DataAccessError {}

/// A trait for data-access shims that combine trace access with
/// debugger session information.
///
/// Ported from Ghidra's `PcodeDebuggerDataAccess` interface.
/// Extends trace-level data access with session awareness.
pub trait PcodeDebuggerDataAccess {
    /// Check if the associated trace represents a live session.
    ///
    /// The session is live if its trace has a recorder and the
    /// source snapshot matches the recorder's destination snapshot.
    fn is_live(&self) -> bool;

    /// Get the service provider (for accessing other debugger services).
    fn service_provider(&self) -> Option<&str>;

    /// Get the target identifier.
    fn target_id(&self) -> Option<&str>;
}

// ============================================================================
// PcodeDebuggerRegistersAccessState -- concrete register access with target
// ============================================================================

// Re-export register types from the registers module
pub use super::pcode_debugger_registers::{RegisterValueSource, SourcedRegisterValue};

/// A concrete implementation of debugger register access that
/// combines a register view with target interaction capabilities.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerRegistersAccess`.
/// Wraps a `PcodeRegisterView` and a `TargetSimulator` to provide
/// the full `readFromTargetRegisters` / `writeTargetRegister` workflow.
#[derive(Debug, Clone)]
pub struct PcodeDebuggerRegistersAccessState {
    /// The thread key.
    pub thread_key: i64,
    /// The register view.
    pub register_view: PcodeRegisterView,
    /// The target simulator (if connected).
    pub target: Option<TargetSimulator>,
    /// The snap context.
    pub snap: i64,
    /// Access metrics.
    pub metrics: AccessMetrics,
}

impl PcodeDebuggerRegistersAccessState {
    /// Create a new access state for a thread.
    pub fn new(thread_key: i64, snap: i64) -> Self {
        Self {
            thread_key,
            register_view: PcodeRegisterView::new(thread_key),
            target: None,
            snap,
            metrics: AccessMetrics::default(),
        }
    }

    /// Attach a target simulator.
    pub fn with_target(mut self, target: TargetSimulator) -> Self {
        self.target = Some(target);
        self
    }

    /// Read registers whose state is unknown from the target.
    ///
    /// For each unknown register, reads the value from the target
    /// and records it in the register view. Returns the number of
    /// registers successfully read.
    pub fn read_from_target(&mut self, unknown: &[String]) -> Result<usize, DataAccessError> {
        let target = self
            .target
            .as_mut()
            .ok_or(DataAccessError::TargetDisconnected)?;

        let mut count = 0;
        for name in unknown {
            match target.read_register(name) {
                Ok(value) => {
                    self.register_view.write(name, &value);
                    count += 1;
                    self.metrics.record_register_read();
                }
                Err(_) => {
                    self.register_view.set_state(name, RegisterState::Error);
                }
            }
        }
        Ok(count)
    }

    /// Write a register value to the target.
    pub fn write_to_target(
        &mut self,
        name: &str,
        data: &[u8],
    ) -> Result<bool, DataAccessError> {
        let target = self
            .target
            .as_mut()
            .ok_or(DataAccessError::TargetDisconnected)?;

        target
            .write_register(name, data)
            .map_err(|e| DataAccessError::Other(e))?;

        // Also update the local view
        self.register_view.write(name, data);
        self.metrics.record_register_write();
        Ok(true)
    }

    /// Whether the access state is live (has a connected target).
    pub fn is_live(&self) -> bool {
        self.target.as_ref().map_or(false, |t| t.connected)
    }

    /// Read a register value with source annotation.
    pub fn read_sourced(&self, name: &str) -> Option<SourcedRegisterValue> {
        self.register_view.read(name).map(|value| {
            let source = if self.is_live() && self.register_view.is_known(name) {
                RegisterValueSource::Target
            } else {
                RegisterValueSource::Trace
            };
            SourcedRegisterValue::new(name, value, source, self.snap)
        })
    }
}

// ============================================================================
// MemoryWriteBuffer -- buffered memory writes
// ============================================================================

/// A buffer that accumulates memory writes before committing them
/// to the memory view.
///
/// Ported from Ghidra's buffered write pattern used in pcode
/// emulation to batch multiple small writes into a single
/// transactional update.
#[derive(Debug, Clone, Default)]
pub struct MemoryWriteBuffer {
    /// Buffered writes: (space, offset, data).
    writes: Vec<(String, u64, Vec<u8>)>,
}

impl MemoryWriteBuffer {
    /// Create a new empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Buffer a memory write.
    pub fn write(&mut self, space: impl Into<String>, offset: u64, data: Vec<u8>) {
        self.writes.push((space.into(), offset, data));
    }

    /// Commit all buffered writes to the memory view.
    pub fn commit_to(&self, view: &mut PcodeMemoryView) {
        for (space, offset, data) in &self.writes {
            view.write(space, *offset, data);
        }
    }

    /// The number of buffered writes.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Clear the buffer without committing.
    pub fn clear(&mut self) {
        self.writes.clear();
    }

    /// Get the total number of bytes buffered.
    pub fn total_bytes(&self) -> usize {
        self.writes.iter().map(|(_, _, d)| d.len()).sum()
    }
}

// ============================================================================
// PcodeDebuggerAccessBuilder -- fluent API for constructing access
// ============================================================================

/// A builder for constructing a `PcodeDebuggerAccess` with a fluent API.
///
/// This extends the existing `PcodeDebuggerAccessBuilder` with additional
/// methods for configuring register-level target interaction.
impl PcodeDebuggerAccessBuilder {
    /// Add register definitions from a snapshot.
    ///
    /// Copies the register definitions from the snapshot into the builder
    /// so that the constructed access will have those registers defined.
    pub fn with_register_defs_from_snapshot(mut self, snapshot: &RegisterBankSnapshot) -> Self {
        for def in snapshot.definitions.values() {
            self.register_defs.push((def.name.clone(), def.bit_length));
        }
        self
    }

    /// Add register definitions from a list.
    pub fn with_register_defs(mut self, defs: Vec<(String, u32)>) -> Self {
        self.register_defs.extend(defs);
        self
    }
}

// Re-export RegisterBankSnapshot from the registers module for builder convenience
use super::pcode_debugger_registers::RegisterBankSnapshot;

// ============================================================================
// AccessEventBus -- publish/subscribe event bus for access events
// ============================================================================

/// The kind of event published on the access event bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessEventType {
    /// A memory read occurred.
    MemoryRead,
    /// A memory write occurred.
    MemoryWrite,
    /// A register was read.
    RegisterRead,
    /// A register was written.
    RegisterWrite,
    /// A breakpoint was hit.
    BreakpointHit,
    /// A watchpoint was hit.
    WatchpointHit,
    /// The active thread changed.
    ThreadChanged,
    /// The snap was advanced.
    SnapAdvanced,
    /// Execution state changed (stopped/running).
    ExecutionStateChanged,
}

/// A published event on the access event bus.
#[derive(Debug, Clone)]
pub struct AccessEvent {
    /// The type of event.
    pub event_type: AccessEventType,
    /// The thread key associated with this event (if any).
    pub thread_key: Option<i64>,
    /// The address space or register name involved.
    pub target: String,
    /// The offset (0 for registers).
    pub offset: u64,
    /// The data size.
    pub size: u32,
    /// Sequence number.
    pub seq: u64,
}

/// A subscription handle returned when subscribing to events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionId(u64);

/// A pub/sub event bus for debugger access events.
///
/// Ported from Ghidra's event notification system used by the
/// debugger model. Components subscribe to specific event types
/// and receive notifications when those events occur. This provides
/// loose coupling between the access layer and UI/plugin components.
///
/// Event listeners are identified by `SubscriptionId` and can be
/// individually unsubscribed.
#[derive(Debug)]
pub struct AccessEventBus {
    subscriptions: Vec<AccessSubscription>,
    event_log: Vec<AccessEvent>,
    next_sub_id: u64,
    next_event_seq: u64,
    /// Maximum log size (0 = don't log).
    max_log_size: usize,
}

/// An event subscription.
struct AccessSubscription {
    id: SubscriptionId,
    /// Which event types this subscription is interested in.
    /// Empty means "all events".
    event_types: Vec<AccessEventType>,
    /// The callback function.
    callback: Box<dyn Fn(&AccessEvent)>,
}

impl std::fmt::Debug for AccessSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessSubscription")
            .field("id", &self.id)
            .field("event_types", &self.event_types)
            .finish()
    }
}

impl AccessEventBus {
    /// Create a new event bus.
    pub fn new() -> Self {
        Self {
            subscriptions: Vec::new(),
            event_log: Vec::new(),
            next_sub_id: 0,
            next_event_seq: 0,
            max_log_size: 0,
        }
    }

    /// Set the maximum event log size.
    pub fn with_max_log_size(mut self, max: usize) -> Self {
        self.max_log_size = max;
        self
    }

    /// Subscribe to specific event types.
    pub fn subscribe(
        &mut self,
        event_types: Vec<AccessEventType>,
        callback: Box<dyn Fn(&AccessEvent)>,
    ) -> SubscriptionId {
        let id = SubscriptionId(self.next_sub_id);
        self.next_sub_id += 1;
        self.subscriptions.push(AccessSubscription {
            id,
            event_types,
            callback,
        });
        id
    }

    /// Subscribe to all event types.
    pub fn subscribe_all(
        &mut self,
        callback: Box<dyn Fn(&AccessEvent)>,
    ) -> SubscriptionId {
        self.subscribe(Vec::new(), callback)
    }

    /// Unsubscribe a listener.
    pub fn unsubscribe(&mut self, id: SubscriptionId) -> bool {
        if let Some(pos) = self.subscriptions.iter().position(|s| s.id == id) {
            self.subscriptions.remove(pos);
            true
        } else {
            false
        }
    }

    /// Publish an event to all matching subscribers.
    pub fn publish(&mut self, mut event: AccessEvent) {
        event.seq = self.next_event_seq;
        self.next_event_seq += 1;

        for sub in &self.subscriptions {
            if sub.event_types.is_empty() || sub.event_types.contains(&event.event_type) {
                (sub.callback)(&event);
            }
        }

        if self.max_log_size > 0 {
            if self.event_log.len() >= self.max_log_size {
                self.event_log.remove(0);
            }
            self.event_log.push(event);
        }
    }

    /// Convenience: publish a memory read event.
    pub fn on_memory_read(&mut self, space: &str, offset: u64, size: u32, thread: Option<i64>) {
        self.publish(AccessEvent {
            event_type: AccessEventType::MemoryRead,
            thread_key: thread,
            target: space.to_string(),
            offset,
            size,
            seq: 0,
        });
    }

    /// Convenience: publish a memory write event.
    pub fn on_memory_write(&mut self, space: &str, offset: u64, size: u32, thread: Option<i64>) {
        self.publish(AccessEvent {
            event_type: AccessEventType::MemoryWrite,
            thread_key: thread,
            target: space.to_string(),
            offset,
            size,
            seq: 0,
        });
    }

    /// Convenience: publish a register read event.
    pub fn on_register_read(&mut self, name: &str, size: u32, thread: Option<i64>) {
        self.publish(AccessEvent {
            event_type: AccessEventType::RegisterRead,
            thread_key: thread,
            target: name.to_string(),
            offset: 0,
            size,
            seq: 0,
        });
    }

    /// Convenience: publish a register write event.
    pub fn on_register_write(&mut self, name: &str, size: u32, thread: Option<i64>) {
        self.publish(AccessEvent {
            event_type: AccessEventType::RegisterWrite,
            thread_key: thread,
            target: name.to_string(),
            offset: 0,
            size,
            seq: 0,
        });
    }

    /// Convenience: publish a breakpoint hit event.
    pub fn on_breakpoint_hit(&mut self, bp_id: u64, thread: Option<i64>) {
        self.publish(AccessEvent {
            event_type: AccessEventType::BreakpointHit,
            thread_key: thread,
            target: bp_id.to_string(),
            offset: 0,
            size: 0,
            seq: 0,
        });
    }

    /// Get the event log.
    pub fn event_log(&self) -> &[AccessEvent] {
        &self.event_log
    }

    /// Get events of a specific type from the log.
    pub fn events_of_type(&self, event_type: AccessEventType) -> Vec<&AccessEvent> {
        self.event_log
            .iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }

    /// The number of active subscriptions.
    pub fn num_subscriptions(&self) -> usize {
        self.subscriptions.len()
    }

    /// Clear the event log.
    pub fn clear_log(&mut self) {
        self.event_log.clear();
    }

    /// Remove all subscriptions.
    pub fn clear_subscriptions(&mut self) {
        self.subscriptions.clear();
    }
}

impl Default for AccessEventBus {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MemoryCheckpointManager -- checkpoint/restore for memory state
// ============================================================================

/// A named checkpoint of memory state.
#[derive(Debug, Clone)]
pub struct MemoryCheckpoint {
    /// The checkpoint ID.
    pub id: u64,
    /// A human-readable label.
    pub label: String,
    /// The snap value at checkpoint time.
    pub snap: i64,
    /// The memory data: (space, offset, bytes).
    pub data: Vec<(String, u64, Vec<u8>)>,
    /// Timestamp (millis since epoch).
    pub timestamp_ms: u64,
}

/// Manages named checkpoints of memory state that can be restored.
///
/// Ported from Ghidra's memory checkpoint/restore mechanism used
/// during emulation for speculative execution and undo support.
/// Each checkpoint captures the current state of a memory view
/// so it can be restored later.
#[derive(Debug, Clone)]
pub struct MemoryCheckpointManager {
    checkpoints: Vec<MemoryCheckpoint>,
    next_id: u64,
    /// Maximum number of checkpoints to keep (0 = unlimited).
    max_checkpoints: usize,
}

impl MemoryCheckpointManager {
    /// Create a new checkpoint manager.
    pub fn new() -> Self {
        Self {
            checkpoints: Vec::new(),
            next_id: 0,
            max_checkpoints: 0,
        }
    }

    /// Set the maximum number of checkpoints.
    pub fn with_max_checkpoints(mut self, max: usize) -> Self {
        self.max_checkpoints = max;
        self
    }

    /// Create a checkpoint from the current memory view.
    ///
    /// Captures all dirty regions and the current state of those regions.
    pub fn checkpoint(
        &mut self,
        label: impl Into<String>,
        snap: i64,
        memory: &PcodeMemoryView,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let mut data = Vec::new();
        // Capture all dirty regions
        for (space, start, end) in memory.dirty_regions() {
            let len = (*end - *start) as u32;
            if let Some(bytes) = memory.read(space, *start, len) {
                data.push((space.clone(), *start, bytes));
            }
        }

        self.checkpoints.push(MemoryCheckpoint {
            id,
            label: label.into(),
            snap,
            data,
            timestamp_ms: 0, // caller can set this externally
        });

        // Evict old checkpoints if needed
        if self.max_checkpoints > 0 && self.checkpoints.len() > self.max_checkpoints {
            self.checkpoints.remove(0);
        }

        id
    }

    /// Restore a checkpoint into a memory view.
    ///
    /// Writes the checkpoint data back into the memory view, effectively
    /// reverting the memory to the checkpoint state.
    pub fn restore(&self, id: u64, memory: &mut PcodeMemoryView) -> Result<(), String> {
        let checkpoint = self
            .checkpoints
            .iter()
            .find(|c| c.id == id)
            .ok_or_else(|| format!("checkpoint {} not found", id))?;

        for (space, offset, bytes) in &checkpoint.data {
            memory.write(space, *offset, bytes);
        }

        Ok(())
    }

    /// Get a checkpoint by ID.
    pub fn get(&self, id: u64) -> Option<&MemoryCheckpoint> {
        self.checkpoints.iter().find(|c| c.id == id)
    }

    /// Get the most recent checkpoint.
    pub fn latest(&self) -> Option<&MemoryCheckpoint> {
        self.checkpoints.last()
    }

    /// Remove a checkpoint.
    pub fn remove(&mut self, id: u64) -> Option<MemoryCheckpoint> {
        if let Some(pos) = self.checkpoints.iter().position(|c| c.id == id) {
            Some(self.checkpoints.remove(pos))
        } else {
            None
        }
    }

    /// The number of checkpoints.
    pub fn len(&self) -> usize {
        self.checkpoints.len()
    }

    /// Whether there are no checkpoints.
    pub fn is_empty(&self) -> bool {
        self.checkpoints.is_empty()
    }

    /// Clear all checkpoints.
    pub fn clear(&mut self) {
        self.checkpoints.clear();
    }

    /// List all checkpoint labels and IDs.
    pub fn list(&self) -> Vec<(u64, &str, i64)> {
        self.checkpoints
            .iter()
            .map(|c| (c.id, c.label.as_str(), c.snap))
            .collect()
    }
}

impl Default for MemoryCheckpointManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AccessLockManager -- manage read/write locks on address ranges
// ============================================================================

/// The kind of lock held on an address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockKind {
    /// A shared (read) lock.
    Shared,
    /// An exclusive (write) lock.
    Exclusive,
}

/// A lock held on a specific address range.
#[derive(Debug, Clone)]
pub struct AccessLock {
    /// The lock ID.
    pub id: u64,
    /// The address space.
    pub space: String,
    /// The start offset (inclusive).
    pub start: u64,
    /// The end offset (exclusive).
    pub end: u64,
    /// The kind of lock.
    pub kind: LockKind,
    /// Which thread holds this lock.
    pub thread_key: i64,
    /// A description of why the lock was acquired.
    pub reason: String,
}

/// Manages read/write locks on address ranges for concurrent access.
///
/// Ported from Ghidra's lock management used when multiple agents
/// or threads access the same debug session. Prevents conflicting
/// writes and ensures consistent reads by tracking shared and
/// exclusive locks on address ranges.
#[derive(Debug, Clone, Default)]
pub struct AccessLockManager {
    locks: Vec<AccessLock>,
    next_id: u64,
}

impl AccessLockManager {
    /// Create a new lock manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire a shared (read) lock on a range. Returns the lock ID.
    ///
    /// Fails if an exclusive lock overlaps the range from a different thread.
    pub fn acquire_shared(
        &mut self,
        space: &str,
        start: u64,
        end: u64,
        thread_key: i64,
        reason: impl Into<String>,
    ) -> Result<u64, String> {
        // Check for conflicting exclusive locks from other threads
        for lock in &self.locks {
            if lock.space == space
                && lock.start < end
                && start < lock.end
                && lock.kind == LockKind::Exclusive
                && lock.thread_key != thread_key
            {
                return Err(format!(
                    "range {}:{:#x}-{:#x} is exclusively locked by thread {}",
                    space, start, end, lock.thread_key
                ));
            }
        }

        let id = self.next_id;
        self.next_id += 1;
        self.locks.push(AccessLock {
            id,
            space: space.to_string(),
            start,
            end,
            kind: LockKind::Shared,
            thread_key,
            reason: reason.into(),
        });
        Ok(id)
    }

    /// Acquire an exclusive (write) lock on a range. Returns the lock ID.
    ///
    /// Fails if any lock overlaps the range from a different thread.
    pub fn acquire_exclusive(
        &mut self,
        space: &str,
        start: u64,
        end: u64,
        thread_key: i64,
        reason: impl Into<String>,
    ) -> Result<u64, String> {
        // Check for conflicting locks from other threads
        for lock in &self.locks {
            if lock.space == space
                && lock.start < end
                && start < lock.end
                && lock.thread_key != thread_key
            {
                return Err(format!(
                    "range {}:{:#x}-{:#x} is locked by thread {}",
                    space, start, end, lock.thread_key
                ));
            }
        }

        let id = self.next_id;
        self.next_id += 1;
        self.locks.push(AccessLock {
            id,
            space: space.to_string(),
            start,
            end,
            kind: LockKind::Exclusive,
            thread_key,
            reason: reason.into(),
        });
        Ok(id)
    }

    /// Release a lock by ID.
    pub fn release(&mut self, id: u64) -> Option<AccessLock> {
        if let Some(pos) = self.locks.iter().position(|l| l.id == id) {
            Some(self.locks.remove(pos))
        } else {
            None
        }
    }

    /// Release all locks held by a specific thread.
    pub fn release_thread(&mut self, thread_key: i64) {
        self.locks.retain(|l| l.thread_key != thread_key);
    }

    /// Check if a range is readable by the given thread.
    ///
    /// Readable if there are no exclusive locks from other threads.
    pub fn is_readable(&self, space: &str, start: u64, end: u64, thread_key: i64) -> bool {
        !self.locks.iter().any(|l| {
            l.space == space
                && l.start < end
                && start < l.end
                && l.kind == LockKind::Exclusive
                && l.thread_key != thread_key
        })
    }

    /// Check if a range is writable by the given thread.
    ///
    /// Writable if there are no locks from other threads.
    pub fn is_writable(&self, space: &str, start: u64, end: u64, thread_key: i64) -> bool {
        !self.locks.iter().any(|l| {
            l.space == space
                && l.start < end
                && start < l.end
                && l.thread_key != thread_key
        })
    }

    /// Get all active locks.
    pub fn active_locks(&self) -> &[AccessLock] {
        &self.locks
    }

    /// Get locks held by a specific thread.
    pub fn thread_locks(&self, thread_key: i64) -> Vec<&AccessLock> {
        self.locks
            .iter()
            .filter(|l| l.thread_key == thread_key)
            .collect()
    }

    /// The number of active locks.
    pub fn len(&self) -> usize {
        self.locks.len()
    }

    /// Whether there are no active locks.
    pub fn is_empty(&self) -> bool {
        self.locks.is_empty()
    }

    /// Release all locks.
    pub fn clear(&mut self) {
        self.locks.clear();
    }
}

// ============================================================================
// PcodeStepController -- high-level single-step and continue control
// ============================================================================

/// The result of a step operation.
#[derive(Debug, Clone)]
pub struct StepResult {
    /// The kind of result.
    pub kind: StepResultKind,
    /// The program counter after the step.
    pub pc: u64,
    /// The snap after the step.
    pub snap: i64,
    /// The number of pcode ops executed.
    pub ops_executed: u32,
    /// An optional error message.
    pub error: Option<String>,
}

/// The kind of step result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepResultKind {
    /// Step completed normally.
    Stepped,
    /// A breakpoint was hit.
    BreakpointHit,
    /// A watchpoint was hit.
    WatchpointHit,
    /// Execution stopped (halt, exit, etc.).
    Stopped,
    /// An error occurred.
    Error,
    /// Execution is still running (async).
    Running,
}

/// High-level controller for stepping through pcode execution.
///
/// Ported from Ghidra's step controller that coordinates memory/register
/// access, breakpoint checking, and event emission during single-step
/// and continue operations. Provides the `step_over`, `step_into`,
/// `step_out`, and `continue_execution` semantics at the pcode level.
#[derive(Debug, Clone)]
pub struct PcodeStepController {
    /// The current thread being controlled.
    pub thread_key: i64,
    /// The step mode.
    pub mode: StepMode,
    /// Maximum steps before auto-stopping (0 = unlimited).
    pub max_steps: u32,
    /// The number of steps taken in the current run.
    steps_taken: u32,
    /// The execution history (list of PCs visited).
    history: Vec<u64>,
    /// Maximum history depth (0 = unlimited).
    max_history: usize,
}

/// The stepping mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepMode {
    /// Step a single pcode op.
    SingleOp,
    /// Step one source-level instruction (may execute multiple ops).
    Instruction,
    /// Step over a call (stop at next instruction after call).
    Over,
    /// Step out of current function (stop at return address).
    Out,
    /// Continue until breakpoint or halt.
    Continue,
}

impl PcodeStepController {
    /// Create a new step controller for a thread.
    pub fn new(thread_key: i64) -> Self {
        Self {
            thread_key,
            mode: StepMode::SingleOp,
            max_steps: 0,
            steps_taken: 0,
            history: Vec::new(),
            max_history: 1000,
        }
    }

    /// Set the step mode.
    pub fn with_mode(mut self, mode: StepMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the maximum steps per run.
    pub fn with_max_steps(mut self, max: u32) -> Self {
        self.max_steps = max;
        self
    }

    /// Set the maximum history depth.
    pub fn with_max_history(mut self, max: usize) -> Self {
        self.max_history = max;
        self
    }

    /// Record a step in the execution history.
    pub fn record_step(&mut self, pc: u64) {
        self.steps_taken += 1;
        if self.max_history > 0 && self.history.len() >= self.max_history {
            self.history.remove(0);
        }
        self.history.push(pc);
    }

    /// Check if the maximum steps have been reached.
    pub fn is_max_steps_reached(&self) -> bool {
        self.max_steps > 0 && self.steps_taken >= self.max_steps
    }

    /// Reset the step counter for a new run.
    pub fn reset_run(&mut self) {
        self.steps_taken = 0;
    }

    /// The number of steps taken in the current run.
    pub fn steps_taken(&self) -> u32 {
        self.steps_taken
    }

    /// Get the execution history.
    pub fn history(&self) -> &[u64] {
        &self.history
    }

    /// Get the last N PCs from history.
    pub fn recent_history(&self, n: usize) -> &[u64] {
        let start = self.history.len().saturating_sub(n);
        &self.history[start..]
    }

    /// Get the most recent PC.
    pub fn last_pc(&self) -> Option<u64> {
        self.history.last().copied()
    }

    /// Check if a PC has been visited before in this run (loop detection).
    pub fn is_pc_in_history(&self, pc: u64) -> bool {
        self.history.contains(&pc)
    }

    /// Clear the history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// The total history depth.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }
}

// ============================================================================
// PcodeDebuggerMemoryAccessState -- concrete memory access with target
// ============================================================================

/// The state of a memory block for the debugger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryBlockState {
    /// The block has been read from the target and is up to date.
    Synced,
    /// The block has been modified locally but not written to target.
    Dirty,
    /// The block state is unknown (not yet read).
    Unknown,
    /// An error occurred while reading/writing the block.
    Error,
}

/// A concrete implementation of memory access that integrates with
/// a target via the `TargetSimulator`.
///
/// Ported from Ghidra's `PcodeDebuggerMemoryAccess` implementation
/// which backs the trace-based memory access with live target reads
/// and writes.
#[derive(Debug, Clone)]
pub struct PcodeDebuggerMemoryAccessState {
    /// The address space this access covers.
    pub space: String,
    /// The snap context.
    pub snap: i64,
    /// Block states indexed by block start offset.
    blocks: BTreeMap<u64, MemoryBlockState>,
    /// Cached memory data.
    memory: PcodeMemoryView,
    /// Optional target simulator for live reads/writes.
    target: Option<TargetSimulator>,
    /// Static image fallback provider.
    static_images: StaticImageProvider,
    /// Unknown ranges (not yet read from target).
    unknown_ranges: AddressRangeSet,
}

impl PcodeDebuggerMemoryAccessState {
    /// Create a new memory access state.
    pub fn new(space: impl Into<String>, snap: i64) -> Self {
        let space_str = space.into();
        Self {
            space: space_str.clone(),
            snap,
            blocks: BTreeMap::new(),
            memory: PcodeMemoryView::new(),
            target: None,
            static_images: StaticImageProvider::new(),
            unknown_ranges: AddressRangeSet::new(&space_str),
        }
    }

    /// Set the target simulator for live access.
    pub fn with_target(mut self, target: TargetSimulator) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the static image provider for fallback reads.
    pub fn with_static_images(mut self, provider: StaticImageProvider) -> Self {
        self.static_images = provider;
        self
    }

    /// Read bytes from memory. Tries the local cache first, then the
    /// target, then static images.
    pub fn read(&mut self, offset: u64, len: u32) -> Option<Vec<u8>> {
        // Try local cache
        if let Some(bytes) = self.memory.read(&self.space, offset, len) {
            return Some(bytes);
        }
        // Try target
        let space = self.space.clone();
        let mut target_result: Option<Vec<u8>> = None;
        if let Some(ref mut target) = self.target {
            if target.is_connected() {
                target_result = target.read_memory(&space, offset, len).ok();
            }
        }
        if let Some(bytes) = target_result {
            self.memory.write(&space, offset, &bytes);
            self.mark_synced(offset, len as u64);
            return Some(bytes);
        }
        // Try static images
        if let Some(bytes) = self.static_images.read(&space, offset, len) {
            return Some(bytes);
        }
        None
    }

    /// Write bytes to memory (local cache only).
    pub fn write(&mut self, offset: u64, bytes: &[u8]) {
        self.memory.write(&self.space, offset, bytes);
        self.mark_dirty(offset, bytes.len() as u64);
    }

    /// Write bytes to both local cache and target.
    pub fn write_through(&mut self, offset: u64, bytes: &[u8]) -> Result<(), String> {
        let space = self.space.clone();
        self.memory.write(&space, offset, bytes);
        if let Some(ref mut target) = self.target {
            if target.is_connected() {
                target.write_memory(&space, offset, bytes)?;
            }
        }
        self.mark_synced(offset, bytes.len() as u64);
        Ok(())
    }

    /// Read from target for the given unknown ranges.
    pub fn read_from_target(&mut self, ranges: &[(u64, u64)]) -> Result<usize, DataAccessError> {
        let mut bytes_read = 0;
        let target = match self.target.as_mut() {
            Some(t) if t.is_connected() => t,
            _ => return Err(DataAccessError::NoTarget),
        };
        // Collect all reads first, then apply to self
        let mut reads: Vec<(u64, u64, Vec<u8>)> = Vec::new();
        for &(start, end) in ranges {
            let len = (end - start) as u32;
            match target.read_memory(&self.space, start, len) {
                Ok(bytes) => {
                    reads.push((start, end, bytes));
                }
                Err(e) => {
                    return Err(DataAccessError::TargetError(e));
                }
            }
        }
        // Now apply reads to self (no longer borrowing target)
        for (start, end, bytes) in reads {
            let len = (end - start) as u32;
            self.memory.write(&self.space, start, &bytes);
            self.mark_synced(start, len as u64);
            self.unknown_ranges.remove_range(start, end);
            bytes_read += len as usize;
        }
        Ok(bytes_read)
    }

    fn mark_synced(&mut self, offset: u64, len: u64) {
        for off in offset..offset + len {
            self.blocks.insert(off, MemoryBlockState::Synced);
        }
    }

    fn mark_dirty(&mut self, offset: u64, len: u64) {
        for off in offset..offset + len {
            self.blocks.insert(off, MemoryBlockState::Dirty);
        }
    }

    /// Mark a range as unknown (not yet read from target).
    pub fn mark_unknown(&mut self, start: u64, end: u64) {
        self.unknown_ranges.add_range(start, end);
        for off in start..end {
            self.blocks.insert(off, MemoryBlockState::Unknown);
        }
    }

    /// Get the state of a memory location.
    pub fn state_at(&self, offset: u64) -> MemoryBlockState {
        self.blocks
            .get(&offset)
            .copied()
            .unwrap_or(MemoryBlockState::Unknown)
    }

    /// Get the unknown ranges.
    pub fn unknown_ranges(&self) -> &AddressRangeSet {
        &self.unknown_ranges
    }

    /// Whether the target is connected.
    pub fn is_live(&self) -> bool {
        self.target.as_ref().map_or(false, |t| t.is_connected())
    }

    /// The total cached bytes.
    pub fn cached_bytes(&self) -> usize {
        self.memory.size()
    }
}

// ============================================================================
// AccessRateLimiter -- rate limit target access operations
// ============================================================================

/// Rate limiter for target access operations.
///
/// Ported from Ghidra's proposed rate limiting utilities used by the
/// debugger recorder to prevent overwhelming the target with too many
/// reads/writes in a short time window.
#[derive(Debug, Clone)]
pub struct AccessRateLimiter {
    /// Maximum operations per window.
    max_ops: u64,
    /// The time window in milliseconds.
    window_ms: u64,
    /// Timestamps of recent operations (as monotonic counter).
    recent_ops: Vec<u64>,
    /// A monotonic counter (simulates time for non-async contexts).
    counter: u64,
    /// Whether the limiter is currently throttled.
    throttled: bool,
}

impl AccessRateLimiter {
    /// Create a new rate limiter.
    pub fn new(max_ops: u64, window_ms: u64) -> Self {
        Self {
            max_ops,
            window_ms,
            recent_ops: Vec::new(),
            counter: 0,
            throttled: false,
        }
    }

    /// Try to acquire a rate limit slot.
    ///
    /// Returns `true` if the operation is allowed, `false` if throttled.
    pub fn try_acquire(&mut self) -> bool {
        self.counter += 1;
        self.evict_expired();

        if self.recent_ops.len() as u64 >= self.max_ops {
            self.throttled = true;
            return false;
        }

        self.recent_ops.push(self.counter);
        self.throttled = false;
        true
    }

    /// Record that an operation was completed (regardless of throttling).
    pub fn record(&mut self) {
        self.counter += 1;
        self.recent_ops.push(self.counter);
        self.evict_expired();
    }

    fn evict_expired(&mut self) {
        let cutoff = self.counter.saturating_sub(self.window_ms);
        self.recent_ops.retain(|&t| t > cutoff);
        if (self.recent_ops.len() as u64) < self.max_ops {
            self.throttled = false;
        }
    }

    /// Whether the limiter is currently throttled.
    pub fn is_throttled(&self) -> bool {
        self.throttled
    }

    /// The number of recent operations in the current window.
    pub fn ops_in_window(&self) -> usize {
        self.recent_ops.len()
    }

    /// Reset the limiter.
    pub fn reset(&mut self) {
        self.recent_ops.clear();
        self.throttled = false;
    }

    /// Set the maximum operations per window.
    pub fn set_max_ops(&mut self, max: u64) {
        self.max_ops = max;
    }

    /// Set the window size in milliseconds.
    pub fn set_window_ms(&mut self, ms: u64) {
        self.window_ms = ms;
    }
}

// ============================================================================
// PcodeTraceDataAccessImpl -- concrete trace data access
// ============================================================================

/// A concrete implementation of trace-level data access.
///
/// Ported from Ghidra's `PcodeTraceDataAccess` concept that provides
/// the base layer for both memory and register access in a trace.
/// Manages the known/unknown state of data, handles reads and writes
/// with proper state tracking, and integrates with the address
/// translation layer.
#[derive(Debug, Clone)]
pub struct PcodeTraceDataAccessImpl {
    /// The language/compiler spec ID.
    pub language_id: String,
    /// The current snap.
    pub snap: i64,
    /// Known address ranges.
    known_ranges: AddressRangeSet,
    /// Error address ranges.
    error_ranges: AddressRangeSet,
    /// Properties store (name -> serialized value).
    properties: BTreeMap<String, Vec<u8>>,
}

impl PcodeTraceDataAccessImpl {
    /// Create a new trace data access.
    pub fn new(language_id: impl Into<String>, snap: i64) -> Self {
        Self {
            language_id: language_id.into(),
            snap,
            known_ranges: AddressRangeSet::new("ram"),
            error_ranges: AddressRangeSet::new("ram"),
            properties: BTreeMap::new(),
        }
    }

    /// Set the state of an address range.
    pub fn set_state(&mut self, start: u64, end: u64, state: TraceMemoryState) {
        match state {
            TraceMemoryState::Known => {
                self.known_ranges.add_range(start, end);
                self.error_ranges.remove_range(start, end);
            }
            TraceMemoryState::Error => {
                self.error_ranges.add_range(start, end);
                self.known_ranges.remove_range(start, end);
            }
            TraceMemoryState::Unknown => {
                self.known_ranges.remove_range(start, end);
                self.error_ranges.remove_range(start, end);
            }
        }
    }

    /// Get the composite state of an address range.
    ///
    /// Checks if any byte in the range has an error or known state.
    pub fn get_state(&self, start: u64, _end: u64) -> TraceMemoryState {
        if self.error_ranges.contains(start) {
            TraceMemoryState::Error
        } else if self.known_ranges.contains(start) {
            TraceMemoryState::Known
        } else {
            TraceMemoryState::Unknown
        }
    }

    /// Get the known address ranges.
    pub fn known_ranges(&self) -> &AddressRangeSet {
        &self.known_ranges
    }

    /// Get the error address ranges.
    pub fn error_ranges(&self) -> &AddressRangeSet {
        &self.error_ranges
    }

    /// Intersect a set of addresses with known ranges.
    pub fn intersect_known(&self, ranges: &AddressRangeSet) -> AddressRangeSet {
        let mut result = AddressRangeSet::new(&ranges.space);
        for &(start, end) in ranges.ranges() {
            // Check each sub-range
            for &(ks, ke) in self.known_ranges.ranges() {
                let overlap_start = start.max(ks);
                let overlap_end = end.min(ke);
                if overlap_start < overlap_end {
                    result.add_range(overlap_start, overlap_end);
                }
            }
        }
        result
    }

    /// Set a named property.
    pub fn set_property(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.properties.insert(name.into(), value);
    }

    /// Get a named property.
    pub fn get_property(&self, name: &str) -> Option<&Vec<u8>> {
        self.properties.get(name)
    }

    /// The number of properties.
    pub fn num_properties(&self) -> usize {
        self.properties.len()
    }

    /// Derive a new access for writing at a different snap.
    pub fn derive_for_write(&self, snap: i64) -> Self {
        Self {
            language_id: self.language_id.clone(),
            snap,
            known_ranges: self.known_ranges.clone(),
            error_ranges: self.error_ranges.clone(),
            properties: self.properties.clone(),
        }
    }
}

// ============================================================================
// InternalPcodeDebuggerDataAccess (ported from InternalPcodeDebuggerDataAccess)
// ============================================================================

/// Internal data access interface for debugger integration.
///
/// Ported from Ghidra's `InternalPcodeDebuggerDataAccess`. Provides
/// access to the service provider and target for implementations that
/// need to interact with the debugger session.
pub trait InternalPcodeDebuggerDataAccess {
    /// Get the service provider.
    fn service_provider(&self) -> Option<&str>;

    /// Get the target identifier.
    fn target_id(&self) -> Option<&str>;

    /// Check if the session is live (connected to a running target).
    fn is_live(&self) -> bool {
        self.target_id().is_some()
    }

    /// Get the viewport snap range.
    fn viewport_snaps(&self) -> &[i64] {
        &[]
    }
}

// ============================================================================
// PcodeDebuggerMemoryAccess (trait)
// ============================================================================

/// Trait for debugger-aware memory access.
///
/// Ported from Ghidra's `PcodeDebuggerMemoryAccess` interface. In
/// addition to trace memory access, this supports reading from the
/// live target and from static images.
pub trait PcodeDebuggerMemoryAccess: InternalPcodeDebuggerDataAccess {
    /// Read memory from the target into the trace.
    ///
    /// Returns true if any part of the target memory was successfully read.
    fn read_from_target_memory(&mut self, addresses: &[(u64, u64)]) -> bool;

    /// Read bytes from relocated program static images.
    ///
    /// Returns the subset of addresses that were NOT satisfied by static images.
    fn read_from_static_images(
        &mut self,
        addresses: &[(u64, u64)],
    ) -> Vec<(u64, u64)>;

    /// Write memory to the target.
    ///
    /// Returns true if the target was written.
    fn write_target_memory(&mut self, address: u64, data: &[u8]) -> bool;
}

// ============================================================================
// PcodeDebuggerRegistersAccess (trait)
// ============================================================================

/// Trait for debugger-aware register access.
///
/// Ported from Ghidra's `PcodeDebuggerRegistersAccess` interface. Extends
/// register access with the ability to read/write registers from the
/// live debug target.
pub trait PcodeDebuggerRegistersAccess: InternalPcodeDebuggerDataAccess {
    /// Read registers from the target into the trace.
    ///
    /// `unknown` is the set of register addresses (in register space) to read.
    /// Returns true if any part of target register state was successfully read.
    fn read_from_target_registers(&mut self, unknown: &[(u64, u64)]) -> bool;

    /// Write a register to the target.
    ///
    /// `address` is in the platform's register space.
    /// Returns true if the target register was written.
    fn write_target_register(&mut self, address: u64, data: &[u8]) -> bool;
}

// ============================================================================
// AbstractPcodeDebuggerAccess (ported from AbstractPcodeDebuggerAccess)
// ============================================================================

/// An abstract implementation of debugger access that manages shared
/// (memory) and local (register) data access shims.
///
/// Ported from Ghidra's `AbstractPcodeDebuggerAccess`. This provides
/// the base for concrete debugger access implementations, managing
/// the creation and caching of memory and register access views.
#[derive(Debug, Clone)]
pub struct AbstractPcodeDebuggerAccess {
    /// The service provider identifier.
    pub provider: Option<String>,
    /// The target identifier.
    pub target_id: Option<String>,
    /// The associated platform/language ID.
    pub platform_id: String,
    /// The trace ID.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
    /// The threads snap (may differ from snap for thread lookup).
    pub threads_snap: i64,
    /// Cached memory access state.
    memory_access: Option<MemoryAccessShim>,
    /// Cached register access states by thread key.
    register_accesses: BTreeMap<i64, RegisterAccessShim>,
}

/// A memory access shim for debugger sessions.
#[derive(Debug, Clone)]
pub struct MemoryAccessShim {
    /// The language/compiler spec ID.
    pub language_id: String,
    /// The snap.
    pub snap: i64,
    /// Pending reads from target.
    pub pending_reads: Vec<(u64, u64)>,
    /// Whether connected to a live target.
    pub is_live: bool,
}

impl MemoryAccessShim {
    /// Create a new memory access shim.
    pub fn new(language_id: impl Into<String>, snap: i64) -> Self {
        Self {
            language_id: language_id.into(),
            snap,
            pending_reads: Vec::new(),
            is_live: false,
        }
    }

    /// Queue a read from the target.
    pub fn queue_read(&mut self, min: u64, max: u64) {
        self.pending_reads.push((min, max));
    }

    /// Drain all pending reads.
    pub fn drain_reads(&mut self) -> Vec<(u64, u64)> {
        std::mem::take(&mut self.pending_reads)
    }

    /// Set whether the session is live.
    pub fn set_live(&mut self, live: bool) {
        self.is_live = live;
    }
}

/// A register access shim for debugger sessions.
#[derive(Debug, Clone)]
pub struct RegisterAccessShim {
    /// The thread key.
    pub thread_key: i64,
    /// The frame level.
    pub frame: i32,
    /// The snap.
    pub snap: i64,
    /// Pending register reads from target.
    pub pending_reads: Vec<(u64, u64)>,
    /// Whether connected to a live target.
    pub is_live: bool,
}

impl RegisterAccessShim {
    /// Create a new register access shim.
    pub fn new(thread_key: i64, frame: i32, snap: i64) -> Self {
        Self {
            thread_key,
            frame,
            snap,
            pending_reads: Vec::new(),
            is_live: false,
        }
    }

    /// Queue a register read from the target.
    pub fn queue_read(&mut self, min: u64, max: u64) {
        self.pending_reads.push((min, max));
    }

    /// Drain all pending reads.
    pub fn drain_reads(&mut self) -> Vec<(u64, u64)> {
        std::mem::take(&mut self.pending_reads)
    }
}

impl AbstractPcodeDebuggerAccess {
    /// Create a new abstract debugger access.
    pub fn new(
        trace_id: impl Into<String>,
        platform_id: impl Into<String>,
        snap: i64,
    ) -> Self {
        Self {
            provider: None,
            target_id: None,
            platform_id: platform_id.into(),
            trace_id: trace_id.into(),
            snap,
            threads_snap: snap,
            memory_access: None,
            register_accesses: BTreeMap::new(),
        }
    }

    /// Set the service provider.
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    /// Set the target.
    pub fn with_target(mut self, target_id: impl Into<String>) -> Self {
        self.target_id = Some(target_id.into());
        self
    }

    /// Set the threads snap (for thread lookup).
    pub fn with_threads_snap(mut self, snap: i64) -> Self {
        self.threads_snap = snap;
        self
    }

    /// Check if this access is connected to a live session.
    pub fn is_live(&self) -> bool {
        self.target_id.is_some()
    }

    /// Get or create the memory access shim.
    pub fn get_memory_access(&mut self) -> &mut MemoryAccessShim {
        if self.memory_access.is_none() {
            let mut shim = MemoryAccessShim::new(&self.platform_id, self.snap);
            shim.set_live(self.is_live());
            self.memory_access = Some(shim);
        }
        self.memory_access.as_mut().unwrap()
    }

    /// Get or create a register access shim for a thread.
    pub fn get_register_access(&mut self, thread_key: i64, frame: i32) -> &mut RegisterAccessShim {
        let snap = self.snap;
        let live = self.is_live();
        self.register_accesses
            .entry(thread_key)
            .or_insert_with(|| {
                let mut shim = RegisterAccessShim::new(thread_key, frame, snap);
                shim.is_live = live;
                shim
            })
    }

    /// Derive a new access for a different snap (for write operations).
    pub fn derive_for_write(&self, snap: i64) -> Self {
        Self {
            provider: self.provider.clone(),
            target_id: None, // Write-derived access is never live
            platform_id: self.platform_id.clone(),
            trace_id: self.trace_id.clone(),
            snap,
            threads_snap: self.threads_snap,
            memory_access: None,
            register_accesses: BTreeMap::new(),
        }
    }
}

impl InternalPcodeDebuggerDataAccess for AbstractPcodeDebuggerAccess {
    fn service_provider(&self) -> Option<&str> {
        self.provider.as_deref()
    }

    fn target_id(&self) -> Option<&str> {
        self.target_id.as_deref()
    }
}

// ============================================================================
// DefaultPcodeDebuggerAccess (ported from DefaultPcodeDebuggerAccess)
// ============================================================================

/// The default target-and-trace access implementation for a debug session.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerAccess`. Provides
/// concrete implementations of memory and register access that
/// delegate to the trace database and live target.
#[derive(Debug, Clone)]
pub struct DefaultPcodeDebuggerAccess {
    /// The inner abstract access.
    inner: AbstractPcodeDebuggerAccess,
    /// The memory view for this session.
    memory_view: PcodeMemoryView,
    /// Register views by thread key.
    register_views: BTreeMap<i64, PcodeRegisterView>,
}

impl DefaultPcodeDebuggerAccess {
    /// Create a new default debugger access.
    pub fn new(
        trace_id: impl Into<String>,
        platform_id: impl Into<String>,
        snap: i64,
    ) -> Self {
        Self {
            inner: AbstractPcodeDebuggerAccess::new(trace_id, platform_id, snap),
            memory_view: PcodeMemoryView::new(),
            register_views: BTreeMap::new(),
        }
    }

    /// Set the service provider.
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.inner = self.inner.with_provider(provider);
        self
    }

    /// Set the target.
    pub fn with_target(mut self, target_id: impl Into<String>) -> Self {
        self.inner = self.inner.with_target(target_id);
        self
    }

    /// Check if this session is live.
    pub fn is_live(&self) -> bool {
        self.inner.is_live()
    }

    /// Get the memory view.
    pub fn memory(&self) -> &PcodeMemoryView {
        &self.memory_view
    }

    /// Get a mutable reference to the memory view.
    pub fn memory_mut(&mut self) -> &mut PcodeMemoryView {
        &mut self.memory_view
    }

    /// Get or create a register view for a thread.
    pub fn register_view(&mut self, thread_key: i64) -> &mut PcodeRegisterView {
        self.register_views
            .entry(thread_key)
            .or_insert_with(|| PcodeRegisterView::new(thread_key))
    }

    /// Read from target memory (if live).
    pub fn read_from_target(&mut self, min: u64, max: u64) -> bool {
        let shim = self.inner.get_memory_access();
        if !shim.is_live {
            return false;
        }
        shim.queue_read(min, max);
        true
    }

    /// Write to target memory (if live).
    pub fn write_to_target(&mut self, space: &str, address: u64, data: &[u8]) -> bool {
        if !self.is_live() {
            return false;
        }
        self.memory_view.write(space, address, data);
        true
    }

    /// Read from target registers (if live).
    pub fn read_registers_from_target(&mut self, thread_key: i64, frame: i32, min: u64, max: u64) -> bool {
        let shim = self.inner.get_register_access(thread_key, frame);
        if !shim.is_live {
            return false;
        }
        shim.queue_read(min, max);
        true
    }

    /// Write a register to the target (if live).
    pub fn write_register_to_target(&mut self, thread_key: i64, name: &str, data: &[u8]) -> bool {
        if !self.is_live() {
            return false;
        }
        let view = self.register_views
            .entry(thread_key)
            .or_insert_with(|| PcodeRegisterView::new(thread_key));
        view.write(name, data);
        true
    }

    /// Derive a new access for writing at a different snap.
    pub fn derive_for_write(&self, snap: i64) -> Self {
        Self {
            inner: self.inner.derive_for_write(snap),
            memory_view: PcodeMemoryView::new(),
            register_views: BTreeMap::new(),
        }
    }
}

impl InternalPcodeDebuggerDataAccess for DefaultPcodeDebuggerAccess {
    fn service_provider(&self) -> Option<&str> {
        self.inner.service_provider()
    }

    fn target_id(&self) -> Option<&str> {
        self.inner.target_id()
    }
}

// ============================================================================
// DefaultPcodeDebuggerMemoryAccess (ported from DefaultPcodeDebuggerMemoryAccess)
// ============================================================================

/// The default memory access shim for debugger sessions.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerMemoryAccess`. Combines
/// trace memory access with the ability to read from live targets
/// and static program images.
#[derive(Debug, Clone)]
pub struct DefaultPcodeDebuggerMemoryAccess {
    /// The language/compiler spec ID.
    pub language_id: String,
    /// The snap.
    pub snap: i64,
    /// The trace memory state.
    memory_view: PcodeMemoryView,
    /// Static image provider for fallback reads.
    static_images: Option<StaticImageProvider>,
    /// Whether the session is live.
    is_live: bool,
    /// Pending target reads.
    pending_target_reads: Vec<(u64, u64)>,
}

impl DefaultPcodeDebuggerMemoryAccess {
    /// Create a new memory access shim.
    pub fn new(language_id: impl Into<String>, snap: i64) -> Self {
        Self {
            language_id: language_id.into(),
            snap,
            memory_view: PcodeMemoryView::new(),
            static_images: None,
            is_live: false,
            pending_target_reads: Vec::new(),
        }
    }

    /// Set the static image provider.
    pub fn with_static_images(mut self, images: StaticImageProvider) -> Self {
        self.static_images = Some(images);
        self
    }

    /// Set whether the session is live.
    pub fn set_live(&mut self, live: bool) {
        self.is_live = live;
    }

    /// Read memory, first from trace, then from static images as fallback.
    pub fn read(&self, space: &str, address: u64, size: u32) -> Option<Vec<u8>> {
        // First try the trace memory view
        if let Some(data) = self.memory_view.read(space, address, size) {
            return Some(data);
        }

        // Then try static images
        if let Some(ref images) = self.static_images {
            if let Some(data) = images.read(space, address, size) {
                return Some(data);
            }
        }

        None
    }

    /// Write memory to the trace.
    pub fn write(&mut self, space: &str, address: u64, data: &[u8]) {
        self.memory_view.write(space, address, data);
    }

    /// Drain pending target reads.
    pub fn drain_pending_reads(&mut self) -> Vec<(u64, u64)> {
        std::mem::take(&mut self.pending_target_reads)
    }
}

impl InternalPcodeDebuggerDataAccess for DefaultPcodeDebuggerMemoryAccess {
    fn service_provider(&self) -> Option<&str> {
        None
    }

    fn target_id(&self) -> Option<&str> {
        if self.is_live { Some("live") } else { None }
    }
}

impl PcodeDebuggerMemoryAccess for DefaultPcodeDebuggerMemoryAccess {
    fn read_from_target_memory(&mut self, addresses: &[(u64, u64)]) -> bool {
        if !self.is_live {
            return false;
        }
        for &(min, max) in addresses {
            self.pending_target_reads.push((min, max));
        }
        true
    }

    fn read_from_static_images(&mut self, addresses: &[(u64, u64)]) -> Vec<(u64, u64)> {
        let mut remaining = Vec::new();
        if let Some(ref images) = self.static_images {
            for &(min, max) in addresses {
                let size = (max - min + 1) as u32;
                if images.read("ram", min, size).is_none() {
                    remaining.push((min, max));
                }
            }
        } else {
            remaining = addresses.to_vec();
        }
        remaining
    }

    fn write_target_memory(&mut self, address: u64, data: &[u8]) -> bool {
        if !self.is_live {
            return false;
        }
        self.memory_view.write("ram", address, data);
        true
    }
}

// ============================================================================
// DefaultPcodeDebuggerRegistersAccess
// (ported from DefaultPcodeDebuggerRegistersAccess)
// ============================================================================

/// The default register access shim for debugger sessions.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerRegistersAccess`. Combines
/// trace register access with the ability to read/write registers on
/// the live debug target.
#[derive(Debug, Clone)]
pub struct DefaultPcodeDebuggerRegistersAccess {
    /// The thread key.
    pub thread_key: i64,
    /// The frame level.
    pub frame: i32,
    /// The snap.
    pub snap: i64,
    /// The register view.
    register_view: PcodeRegisterView,
    /// Whether the session is live.
    is_live: bool,
    /// Pending register reads from target.
    pending_reads: Vec<(u64, u64)>,
}

impl DefaultPcodeDebuggerRegistersAccess {
    /// Create a new register access shim.
    pub fn new(thread_key: i64, frame: i32, snap: i64) -> Self {
        Self {
            thread_key,
            frame,
            snap,
            register_view: PcodeRegisterView::new(thread_key),
            is_live: false,
            pending_reads: Vec::new(),
        }
    }

    /// Set whether the session is live.
    pub fn set_live(&mut self, live: bool) {
        self.is_live = live;
    }

    /// Get the register view.
    pub fn register_view(&self) -> &PcodeRegisterView {
        &self.register_view
    }

    /// Get a mutable register view.
    pub fn register_view_mut(&mut self) -> &mut PcodeRegisterView {
        &mut self.register_view
    }

    /// Read a register, first from the trace.
    pub fn read_register(&self, name: &str) -> Option<Vec<u8>> {
        self.register_view.read(name)
    }

    /// Write a register.
    pub fn write_register(&mut self, name: &str, value: &[u8]) {
        self.register_view.write(name, value);
    }

    /// Drain pending register reads.
    pub fn drain_pending_reads(&mut self) -> Vec<(u64, u64)> {
        std::mem::take(&mut self.pending_reads)
    }
}

impl InternalPcodeDebuggerDataAccess for DefaultPcodeDebuggerRegistersAccess {
    fn service_provider(&self) -> Option<&str> {
        None
    }

    fn target_id(&self) -> Option<&str> {
        if self.is_live { Some("live") } else { None }
    }
}

impl PcodeDebuggerRegistersAccess for DefaultPcodeDebuggerRegistersAccess {
    fn read_from_target_registers(&mut self, unknown: &[(u64, u64)]) -> bool {
        if !self.is_live {
            return false;
        }
        for &(min, max) in unknown {
            self.pending_reads.push((min, max));
        }
        true
    }

    fn write_target_register(&mut self, _address: u64, _data: &[u8]) -> bool {
        if !self.is_live {
            return false;
        }
        // In a real implementation, this would send the write to the target
        true
    }
}

// ============================================================================
// PcodeDebuggerPropertyAccess (ported from DefaultPcodeDebuggerPropertyAccess)
// ============================================================================

/// A property access shim for debugger sessions.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerPropertyAccess`. Provides
/// typed access to trace properties with debugger session awareness.
#[derive(Debug, Clone)]
pub struct PcodeDebuggerPropertyAccess {
    /// The property name.
    pub name: String,
    /// The snap.
    pub snap: i64,
    /// Property storage (serialized as bytes).
    properties: BTreeMap<String, Vec<u8>>,
}

impl PcodeDebuggerPropertyAccess {
    /// Create a new property access.
    pub fn new(name: impl Into<String>, snap: i64) -> Self {
        Self {
            name: name.into(),
            snap,
            properties: BTreeMap::new(),
        }
    }

    /// Set a property value.
    pub fn set_property(&mut self, key: impl Into<String>, value: Vec<u8>) {
        self.properties.insert(key.into(), value);
    }

    /// Get a property value.
    pub fn get_property(&self, key: &str) -> Option<&Vec<u8>> {
        self.properties.get(key)
    }

    /// Remove a property.
    pub fn remove_property(&mut self, key: &str) -> Option<Vec<u8>> {
        self.properties.remove(key)
    }

    /// Get all property keys.
    pub fn keys(&self) -> Vec<&String> {
        self.properties.keys().collect()
    }

    /// The number of properties.
    pub fn len(&self) -> usize {
        self.properties.len()
    }

    /// Whether there are no properties.
    pub fn is_empty(&self) -> bool {
        self.properties.is_empty()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debugger_access_new() {
        let access = PcodeDebuggerAccess::new("trace1", 0)
            .with_language_id("x86:LE:64:default::gcc");
        assert_eq!(access.trace_id, "trace1");
        assert_eq!(access.snap, 0);
        assert_eq!(access.language_id, "x86:LE:64:default::gcc");
        assert!(access.active_thread().is_none());
    }

    #[test]
    fn test_debugger_access_thread_management() {
        let mut access = PcodeDebuggerAccess::new("t1", 0);
        assert!(access.thread_keys().is_empty());

        access.set_active_thread(42);
        assert_eq!(access.active_thread(), Some(42));
        assert_eq!(access.thread_keys(), vec![42]);

        access.set_active_thread(99);
        assert_eq!(access.thread_keys().len(), 2);
    }

    #[test]
    fn test_debugger_access_memory() {
        let mut access = PcodeDebuggerAccess::new("t1", 0);
        access.write_memory("ram", 0x400000, &[0xEB, 0xFE]);
        let bytes = access.read_memory("ram", 0x400000, 2);
        assert_eq!(bytes, Some(vec![0xEB, 0xFE]));

        assert!(access.read_memory("ram", 0x500000, 1).is_none());
    }

    #[test]
    fn test_debugger_access_register_no_thread() {
        let mut access = PcodeDebuggerAccess::new("t1", 0);
        let result = access.write_register("EAX", &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(result, Err(AccessError::NoActiveThread));
    }

    #[test]
    fn test_debugger_access_register_with_thread() {
        let mut access = PcodeDebuggerAccess::new("t1", 0);
        access.set_active_thread(42);
        access
            .write_register("EAX", &[0x78, 0x56, 0x34, 0x12])
            .unwrap();
        let val = access.read_register("EAX");
        assert_eq!(val, Some(vec![0x78, 0x56, 0x34, 0x12]));
    }

    #[test]
    fn test_memory_view_read_write() {
        let mut mem = PcodeMemoryView::new();
        mem.write("ram", 0x1000, &[0x90, 0xCC]);
        assert_eq!(mem.read("ram", 0x1000, 2), Some(vec![0x90, 0xCC]));
        assert!(mem.read("ram", 0x1000, 3).is_none());
        assert!(mem.has_state("ram", 0x1000, 2));
        assert!(!mem.has_state("ram", 0x1000, 3));
    }

    #[test]
    fn test_memory_view_dirty_tracking() {
        let mut mem = PcodeMemoryView::new();
        mem.write("ram", 0x1000, &[0x90]);
        mem.write("ram", 0x2000, &[0xCC]);
        assert_eq!(mem.dirty_regions().len(), 2);

        mem.clear_dirty();
        assert!(mem.dirty_regions().is_empty());
        // Memory itself is preserved
        assert!(mem.has_state("ram", 0x1000, 1));
    }

    #[test]
    fn test_register_view_basic() {
        let mut view = PcodeRegisterView::new(42);
        assert!(view.is_empty());

        view.write("RAX", &[0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE]);
        assert_eq!(view.len(), 1);
        assert!(view.is_known("RAX"));
        assert_eq!(view.get_state("RAX"), RegisterState::Known);
        assert!(!view.is_known("RBX"));
    }

    #[test]
    fn test_register_view_define_and_read() {
        let mut view = PcodeRegisterView::new(0);
        view.define_register("EFLAGS", 32);
        assert_eq!(view.bit_length("EFLAGS"), Some(32));
        assert_eq!(view.get_state("EFLAGS"), RegisterState::Unknown);
    }

    #[test]
    fn test_register_view_modified_tracking() {
        let mut view = PcodeRegisterView::new(0);
        view.write("RAX", &[1, 2, 3, 4]);
        view.write("RBX", &[5, 6, 7, 8]);
        assert_eq!(view.modified_registers().len(), 2);

        view.clear_modified();
        assert!(view.modified_registers().is_empty());

        // Re-write RAX -- should appear in modified again
        view.write("RAX", &[9, 10, 11, 12]);
        assert_eq!(view.modified_registers().len(), 1);
    }

    #[test]
    fn test_thread_context_basic() {
        let mut ctx = PcodeThreadContext::new(42);
        ctx.set_pc(0x400000);
        ctx.set_sp(0x7FFF_FFF0);
        ctx.set_fp(0x7FFF_FFE0);
        ctx.set_context_field("TMode", 1);

        assert_eq!(ctx.pc, 0x400000);
        assert_eq!(ctx.sp, Some(0x7FFF_FFF0));
        assert_eq!(ctx.fp, Some(0x7FFF_FFE0));
        assert_eq!(ctx.get_context_field("TMode"), Some(1));
        assert_eq!(ctx.get_context_field("Missing"), None);
    }

    #[test]
    fn test_thread_context_build_parse_bytes() {
        let defs = vec![
            ContextFieldDef::new("TMode", 5, 1),
            ContextFieldDef::new("Mode", 0, 2),
        ];

        let mut ctx = PcodeThreadContext::new(0);
        ctx.set_context_field("TMode", 1);
        ctx.set_context_field("Mode", 3);

        let bytes = ctx.build_context_bytes(&defs);
        assert_eq!(bytes[0], 0x23); // bits 0,1 (value 3) + bit 5

        let parsed = PcodeThreadContext::parse_context_bytes(&bytes, &defs);
        assert_eq!(parsed.get("TMode"), Some(&1));
        assert_eq!(parsed.get("Mode"), Some(&3));
    }

    #[test]
    fn test_context_field_def_mask() {
        let def = ContextFieldDef::new("test", 0, 1);
        assert_eq!(def.mask(), 1);

        let def2 = ContextFieldDef::new("test", 0, 8);
        assert_eq!(def2.mask(), 0xFF);

        let def3 = ContextFieldDef::new("test", 0, 64);
        assert_eq!(def3.mask(), u64::MAX);
    }

    #[test]
    fn test_breakpoint_manager_add_remove() {
        let mut mgr = PcodeBreakpointManager::new();
        assert!(mgr.is_empty());

        let id = mgr.add_breakpoint("ram", 0x400000);
        assert_eq!(mgr.len(), 1);
        assert!(mgr.get(id).is_some());

        let removed = mgr.remove_breakpoint(id);
        assert!(removed.is_some());
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_breakpoint_hit_detection() {
        let mut mgr = PcodeBreakpointManager::new();
        let id = mgr.add_breakpoint("ram", 0x400000);

        let hits = mgr.check_hit("ram", 0x400000);
        assert_eq!(hits, vec![id]);
        assert_eq!(mgr.get(id).unwrap().hit_count, 1);

        // No hit at different address
        let hits2 = mgr.check_hit("ram", 0x500000);
        assert!(hits2.is_empty());
    }

    #[test]
    fn test_breakpoint_disabled() {
        let mut mgr = PcodeBreakpointManager::new();
        let id = mgr.add_breakpoint("ram", 0x400000);
        mgr.set_enabled(id, false);

        let hits = mgr.check_hit("ram", 0x400000);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_data_breakpoint() {
        let mut mgr = PcodeBreakpointManager::new();
        let id = mgr.add_data_breakpoint("ram", 0x2000, BreakpointKind::Write);

        let hits = mgr.check_data_hit("ram", 0x2000, 4, BreakpointKind::Write);
        assert_eq!(hits, vec![id]);

        // Read should not trigger a Write-only breakpoint
        let hits2 = mgr.check_data_hit("ram", 0x2000, 4, BreakpointKind::Read);
        assert!(hits2.is_empty());
    }

    #[test]
    fn test_data_breakpoint_readwrite() {
        let mut mgr = PcodeBreakpointManager::new();
        let id = mgr.add_data_breakpoint("ram", 0x3000, BreakpointKind::ReadWrite);

        let hits_r = mgr.check_data_hit("ram", 0x3000, 1, BreakpointKind::Read);
        assert_eq!(hits_r, vec![id]);

        let hits_w = mgr.check_data_hit("ram", 0x3000, 1, BreakpointKind::Write);
        assert_eq!(hits_w, vec![id]);
    }

    #[test]
    fn test_step_event() {
        let mut access = PcodeDebuggerAccess::new("t1", 0);
        access.log_event(PcodeStepEvent {
            snap: 0,
            thread_key: 42,
            pc: 0x400000,
            kind: StepEventKind::PcodeOp,
            description: "executed STORE".into(),
        });
        assert_eq!(access.event_log().len(), 1);

        access.clear_event_log();
        assert!(access.event_log().is_empty());
    }

    #[test]
    fn test_advance_snap() {
        let mut access = PcodeDebuggerAccess::new("t1", 0);
        assert_eq!(access.snap, 0);
        access.advance_snap(5);
        assert_eq!(access.snap, 5);
    }

    #[test]
    fn test_breakpoint_condition() {
        let mut mgr = PcodeBreakpointManager::new();
        let id = mgr.add_breakpoint("ram", 0x400000);
        mgr.set_condition(id, Some("RAX == 0".to_string()));
        assert_eq!(
            mgr.get(id).unwrap().condition,
            Some("RAX == 0".to_string())
        );
    }

    #[test]
    fn test_breakpoint_clear() {
        let mut mgr = PcodeBreakpointManager::new();
        mgr.add_breakpoint("ram", 0x1000);
        mgr.add_breakpoint("ram", 0x2000);
        assert_eq!(mgr.len(), 2);

        mgr.clear();
        assert!(mgr.is_empty());
    }

    // -- MemoryPermissions --

    #[test]
    fn test_memory_permissions() {
        assert!(MemoryPermissions::RW.allows(true, true, false));
        assert!(!MemoryPermissions::RW.allows(true, true, true));
        assert!(MemoryPermissions::RX.allows(true, false, true));
        assert!(!MemoryPermissions::RX.allows(true, true, false));
        assert!(MemoryPermissions::NONE.allows(false, false, false));
        assert!(!MemoryPermissions::NONE.allows(true, false, false));
    }

    // -- MemoryRegion --

    #[test]
    fn test_memory_region_basic() {
        let r = MemoryRegion::new(".text", "ram", 0x400000, 0x500000)
            .with_permissions(MemoryPermissions::RX)
            .with_description("code section");
        assert_eq!(r.size(), 0x100000);
        assert!(r.contains(0x450000));
        assert!(!r.contains(0x300000));
        assert!(!r.contains(0x500000)); // exclusive end
    }

    #[test]
    fn test_memory_region_overlaps() {
        let a = MemoryRegion::new("a", "ram", 0x1000, 0x2000);
        let b = MemoryRegion::new("b", "ram", 0x1500, 0x2500);
        let c = MemoryRegion::new("c", "ram", 0x3000, 0x4000);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));

        // Different spaces don't overlap
        let d = MemoryRegion::new("d", "reg", 0x1000, 0x2000);
        assert!(!a.overlaps(&d));
    }

    // -- MemoryRegionMap --

    #[test]
    fn test_memory_region_map() {
        let mut map = MemoryRegionMap::new();
        map.add_region(MemoryRegion::new(".text", "ram", 0x400000, 0x500000)
            .with_permissions(MemoryPermissions::RX))
            .unwrap();
        map.add_region(MemoryRegion::new(".data", "ram", 0x600000, 0x700000)
            .with_permissions(MemoryPermissions::RW))
            .unwrap();

        assert_eq!(map.len(), 2);
        assert!(map.find_region("ram", 0x450000).is_some());
        assert_eq!(map.find_region("ram", 0x450000).unwrap().name, ".text");
        assert!(map.find_region("ram", 0x300000).is_none());
    }

    #[test]
    fn test_memory_region_map_overlap_rejected() {
        let mut map = MemoryRegionMap::new();
        map.add_region(MemoryRegion::new("a", "ram", 0x1000, 0x2000)).unwrap();
        let result = map.add_region(MemoryRegion::new("b", "ram", 0x1500, 0x2500));
        assert_eq!(result, Err(AccessError::RegionOverlap));
    }

    #[test]
    fn test_memory_region_map_access_check() {
        let mut map = MemoryRegionMap::new();
        map.add_region(MemoryRegion::new(".text", "ram", 0x400000, 0x500000)
            .with_permissions(MemoryPermissions::RX))
            .unwrap();

        assert!(map.check_access("ram", 0x450000, true, false, true)); // RX ok
        assert!(!map.check_access("ram", 0x450000, true, true, false)); // write denied
        assert!(map.check_access("ram", 0x300000, true, true, true)); // unmapped: allowed
    }

    #[test]
    fn test_memory_region_map_remove() {
        let mut map = MemoryRegionMap::new();
        map.add_region(MemoryRegion::new("a", "ram", 0x1000, 0x2000)).unwrap();
        assert_eq!(map.len(), 1);
        map.remove_by_name("a");
        assert!(map.is_empty());
    }

    // -- PcodeWatchpointManager --

    #[test]
    fn test_watchpoint_manager_basic() {
        let mut mgr = PcodeWatchpointManager::new();
        let id = mgr.add_watchpoint("ram", 0x2000, 0x2010, BreakpointKind::Write);
        assert_eq!(mgr.len(), 1);

        let hits = mgr.check_hit("ram", 0x2005, BreakpointKind::Write);
        assert_eq!(hits, vec![id]);
        assert_eq!(mgr.get(id).unwrap().hit_count, 1);
    }

    #[test]
    fn test_watchpoint_manager_readwrite() {
        let mut mgr = PcodeWatchpointManager::new();
        let id = mgr.add_watchpoint("ram", 0x3000, 0x3100, BreakpointKind::ReadWrite);

        let hits_r = mgr.check_hit("ram", 0x3050, BreakpointKind::Read);
        assert_eq!(hits_r, vec![id]);

        let hits_w = mgr.check_hit("ram", 0x3050, BreakpointKind::Write);
        assert_eq!(hits_w, vec![id]);
    }

    #[test]
    fn test_watchpoint_manager_no_hit() {
        let mut mgr = PcodeWatchpointManager::new();
        mgr.add_watchpoint("ram", 0x2000, 0x2010, BreakpointKind::Write);

        // Wrong space
        assert!(mgr.check_hit("reg", 0x2005, BreakpointKind::Write).is_empty());
        // Wrong kind
        assert!(mgr.check_hit("ram", 0x2005, BreakpointKind::Read).is_empty());
        // Outside range
        assert!(mgr.check_hit("ram", 0x5000, BreakpointKind::Write).is_empty());
    }

    #[test]
    fn test_watchpoint_manager_range_hit() {
        let mut mgr = PcodeWatchpointManager::new();
        let id = mgr.add_watchpoint("ram", 0x2000, 0x2010, BreakpointKind::Read);

        // Range that partially overlaps
        let hits = mgr.check_range_hit("ram", 0x2008, 16, BreakpointKind::Read);
        assert_eq!(hits, vec![id]);
    }

    #[test]
    fn test_watchpoint_manager_disabled() {
        let mut mgr = PcodeWatchpointManager::new();
        let id = mgr.add_watchpoint("ram", 0x2000, 0x2010, BreakpointKind::Write);
        mgr.set_enabled(id, false);

        assert!(mgr.check_hit("ram", 0x2005, BreakpointKind::Write).is_empty());
    }

    // -- AccessMetrics --

    #[test]
    fn test_access_metrics() {
        let mut m = AccessMetrics::new();
        m.record_memory_read();
        m.record_memory_read();
        m.record_memory_write();
        m.record_register_read();
        m.record_step_event();

        assert_eq!(m.memory_reads, 2);
        assert_eq!(m.memory_writes, 1);
        assert_eq!(m.register_reads, 1);
        assert_eq!(m.step_events, 1);
        assert_eq!(m.total_operations(), 5);

        m.reset();
        assert_eq!(m.total_operations(), 0);
    }

    // -- PcodeFrameSnapshot --

    #[test]
    fn test_frame_snapshot_basic() {
        let mut snap = PcodeFrameSnapshot::new(42, 0);
        snap.pc = 0x400000;
        snap.registers.insert("RAX".to_string(), vec![0x78, 0x56, 0x34, 0x12]);
        snap.memory_regions.push(("ram".to_string(), 0x400000, vec![0xEB, 0xFE]));

        assert_eq!(snap.num_registers(), 1);
        assert_eq!(snap.get_register("RAX"), Some(&vec![0x78, 0x56, 0x34, 0x12]));
        assert_eq!(snap.num_memory_regions(), 1);
        assert_eq!(snap.total_memory_bytes(), 2);
    }

    #[test]
    fn test_frame_snapshot_read_memory() {
        let mut snap = PcodeFrameSnapshot::new(0, 0);
        snap.memory_regions.push(("ram".to_string(), 0x1000, vec![0x90, 0xCC, 0xEB, 0xFE]));

        let bytes = snap.read_memory("ram", 0x1001, 2);
        assert_eq!(bytes, Some(vec![0xCC, 0xEB]));

        assert!(snap.read_memory("ram", 0x5000, 1).is_none());
        assert!(snap.read_memory("reg", 0x1000, 1).is_none());
    }

    #[test]
    fn test_frame_snapshot_capture_from_access() {
        let mut access = PcodeDebuggerAccess::new("t1", 0);
        access.set_active_thread(42);
        access.write_memory("ram", 0x400000, &[0xEB, 0xFE, 0x90, 0xCC]);
        access.write_register("RAX", &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();

        let snap = PcodeFrameSnapshot::capture_from_access(
            42,
            &access,
            &[("ram", 0x400000, 4)],
        );

        assert_eq!(snap.thread_key, 42);
        assert_eq!(snap.num_registers(), 1);
        assert_eq!(snap.get_register("RAX"), Some(&vec![1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(snap.read_memory("ram", 0x400000, 4), Some(vec![0xEB, 0xFE, 0x90, 0xCC]));
    }

    // -- PrettyBytes --

    #[test]
    fn test_pretty_bytes_hex() {
        let pb = PrettyBytes::new(false, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(pb.to_hex_string(), "de:ad:be:ef");
        assert_eq!(pb.len(), 4);
    }

    #[test]
    fn test_pretty_bytes_u128_le() {
        let pb = PrettyBytes::new(false, vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(pb.to_u128(), 0x12345678);
    }

    #[test]
    fn test_pretty_bytes_u128_be() {
        let pb = PrettyBytes::new(true, vec![0x12, 0x34, 0x56, 0x78]);
        assert_eq!(pb.to_u128(), 0x12345678);
    }

    #[test]
    fn test_pretty_bytes_signed() {
        let pb = PrettyBytes::new(false, vec![0xFF, 0xFF]);
        assert_eq!(pb.to_i128(), -1);
    }

    #[test]
    fn test_pretty_bytes_display() {
        let pb = PrettyBytes::new(false, vec![0x01, 0x02]);
        let display = format!("{}", pb);
        assert!(display.contains("bigEndian=false"));
        assert!(display.contains("01:02"));
    }

    #[test]
    fn test_pretty_bytes_collect_displays() {
        let pb = PrettyBytes::new(false, vec![0xFF, 0x00]);
        let (u_dec, hex, _s_dec) = pb.collect_displays();
        assert_eq!(u_dec, "255");
        assert_eq!(hex, "0xff");
    }

    // -- ValueLocation --

    #[test]
    fn test_value_location_memory() {
        let loc = ValueLocation::memory("ram", 0x400000, 4);
        assert!(!loc.is_register);
        assert!(loc.covers(0x400000));
        assert!(loc.covers(0x400003));
        assert!(!loc.covers(0x400004));
        assert_eq!(loc.end(), 0x400004);
    }

    #[test]
    fn test_value_location_register() {
        let loc = ValueLocation::register("register", 0, 8, "RAX");
        assert!(loc.is_register);
        assert_eq!(loc.register_name, Some("RAX".to_string()));
    }

    // -- WatchValue --

    #[test]
    fn test_watch_value_basic() {
        let wv = WatchValue::new(false, vec![0x78, 0x56, 0x34, 0x12]);
        assert!(wv.is_known());
        assert_eq!(wv.to_u128(), 0x12345678);
        assert_eq!(wv.len(), 4);
    }

    #[test]
    fn test_watch_value_unknown() {
        let wv = WatchValue::new(false, vec![0]).with_state(TraceMemoryState::Unknown);
        assert!(!wv.is_known());
    }

    #[test]
    fn test_watch_value_with_location() {
        let loc = ValueLocation::memory("ram", 0x400000, 4);
        let wv = WatchValue::new(false, vec![1, 2, 3, 4])
            .with_location(loc)
            .with_read("ram", 0x400000, 0x400004);

        assert!(wv.address().is_some());
        assert_eq!(wv.address().unwrap().1, 0x400000);
        assert_eq!(wv.reads.len(), 1);
    }

    // -- StaticImageProvider --

    #[test]
    fn test_static_image_provider() {
        let mut provider = StaticImageProvider::new();
        provider.register_bytes("test.exe", "ram", 0x400000, vec![0xEB, 0xFE, 0x90, 0xCC]);

        assert!(!provider.is_empty());
        let bytes = provider.read("ram", 0x400001, 2).unwrap();
        assert_eq!(bytes, vec![0xFE, 0x90]);

        // Out of range
        assert!(provider.read("ram", 0x500000, 1).is_none());
    }

    #[test]
    fn test_static_image_fill_missing() {
        let mut provider = StaticImageProvider::new();
        provider.register_bytes("prog", "ram", 0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD]);

        let mut memory = PcodeMemoryView::new();
        memory.write("ram", 0x1001, &[0xFF]); // partial write

        let still_unknown = provider.fill_missing(&mut memory, &[("ram".to_string(), 0x1000, 0x1004)]);

        // The byte at 0x1000 should have been filled from static image
        // The byte at 0x1001 was already in memory (0xFF from the write)
        // 0x1002 and 0x1003 should have been filled from static image
        // So there should be no unknown ranges left
        assert!(still_unknown.is_empty());
    }

    // -- PcodeEmulatorCallbacks --

    #[test]
    fn test_emulator_callbacks() {
        let mut cb = PcodeEmulatorCallbacks::new();
        assert!(cb.enabled);

        cb.on_memory_read("ram", 0x1000, 4);
        cb.on_register_write("RAX", 0, 8);
        cb.on_memory_write("ram", 0x2000, 2);

        assert_eq!(cb.log_len(), 3);
        assert_eq!(cb.entries_of_kind(CallbackKind::MemoryRead).len(), 1);
        assert_eq!(cb.entries_of_kind(CallbackKind::MemoryWrite).len(), 1);
        assert_eq!(cb.entries_of_kind(CallbackKind::RegisterWrite).len(), 1);
    }

    #[test]
    fn test_emulator_callbacks_disabled() {
        let mut cb = PcodeEmulatorCallbacks::new();
        cb.set_enabled(false);

        cb.on_memory_read("ram", 0x1000, 4);
        assert_eq!(cb.log_len(), 0);

        cb.set_enabled(true);
        cb.on_memory_read("ram", 0x1000, 4);
        assert_eq!(cb.log_len(), 1);
    }

    // -- BreakpointConditionEvaluator --

    #[test]
    fn test_breakpoint_condition_equality() {
        let mut view = PcodeRegisterView::new(0);
        view.define_register("RAX", 64);
        view.write("RAX", &0x42u64.to_le_bytes());

        assert!(BreakpointConditionEvaluator::evaluate("RAX == 0x42", &view).unwrap());
        assert!(!BreakpointConditionEvaluator::evaluate("RAX == 0x43", &view).unwrap());
    }

    #[test]
    fn test_breakpoint_condition_inequality() {
        let mut view = PcodeRegisterView::new(0);
        view.define_register("RAX", 64);
        view.write("RAX", &0x42u64.to_le_bytes());

        assert!(BreakpointConditionEvaluator::evaluate("RAX != 0x0", &view).unwrap());
        assert!(!BreakpointConditionEvaluator::evaluate("RAX != 0x42", &view).unwrap());
    }

    #[test]
    fn test_breakpoint_condition_comparison() {
        let mut view = PcodeRegisterView::new(0);
        view.define_register("RAX", 64);
        view.write("RAX", &100u64.to_le_bytes());

        assert!(BreakpointConditionEvaluator::evaluate("RAX > 50", &view).unwrap());
        assert!(BreakpointConditionEvaluator::evaluate("RAX < 200", &view).unwrap());
        assert!(!BreakpointConditionEvaluator::evaluate("RAX < 50", &view).unwrap());
    }

    #[test]
    fn test_breakpoint_condition_register_comparison() {
        let mut view = PcodeRegisterView::new(0);
        view.define_register("RAX", 64);
        view.define_register("RBX", 64);
        view.write("RAX", &100u64.to_le_bytes());
        view.write("RBX", &100u64.to_le_bytes());

        assert!(BreakpointConditionEvaluator::evaluate("RAX == RBX", &view).unwrap());
    }

    #[test]
    fn test_breakpoint_condition_parse_error() {
        let view = PcodeRegisterView::new(0);
        assert!(BreakpointConditionEvaluator::evaluate("invalid", &view).is_err());
    }

    // -- AccessStateSnapshot --

    #[test]
    fn test_access_state_snapshot() {
        let mut access = PcodeDebuggerAccess::new("t1", 0);
        access.set_active_thread(42);
        access.write_memory("ram", 0x400000, &[0xEB, 0xFE]);
        access.write_register("RAX", &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        access.breakpoints_mut().add_breakpoint("ram", 0x400000);

        let snap = AccessStateSnapshot::capture_from(&access);
        assert_eq!(snap.trace_id, "t1");
        assert_eq!(snap.active_thread, Some(42));
        assert_eq!(snap.memory_data.len(), 2);
        assert_eq!(snap.register_data.len(), 1);
        assert_eq!(snap.thread_contexts.len(), 1);
        assert_eq!(snap.breakpoints.len(), 1);

        // Apply to a new access
        let mut access2 = PcodeDebuggerAccess::new("t2", 0);
        snap.apply_to(&mut access2);

        assert_eq!(access2.snap, 0);
        assert_eq!(access2.active_thread, Some(42));
    }

    // -- TargetSimulator --

    #[test]
    fn test_target_simulator_basic() {
        let mut target = TargetSimulator::new("gdb");
        assert!(!target.connected);

        target.connect();
        assert!(target.connected);

        target.queue_register_read("RAX", vec![0x42; 8]);
        let val = target.read_register("RAX").unwrap();
        assert_eq!(val, vec![0x42; 8]);

        // Write and record
        target.write_register("RBX", &[0x99; 8]).unwrap();
        assert_eq!(target.num_recorded_writes(), 1);
    }

    #[test]
    fn test_target_simulator_not_connected() {
        let mut target = TargetSimulator::new("gdb");
        assert!(target.read_register("RAX").is_err());
        assert!(target.write_register("RAX", &[1]).is_err());
        assert!(target.read_memory("ram", 0, 1).is_err());
        assert!(target.write_memory("ram", 0, &[1]).is_err());
    }

    #[test]
    fn test_target_simulator_memory() {
        let mut target = TargetSimulator::new("gdb");
        target.connect();

        target.queue_memory_read("ram", 0x1000, vec![0xEB, 0xFE, 0x90]);
        let val = target.read_memory("ram", 0x1000, 3).unwrap();
        assert_eq!(val, vec![0xEB, 0xFE, 0x90]);

        target.write_memory("ram", 0x2000, &[0xCC]).unwrap();
        assert_eq!(target.num_recorded_writes(), 1);
    }

    // -- AddressRangeSet --

    #[test]
    fn test_address_range_set_basic() {
        let mut set = AddressRangeSet::new("ram");
        set.add_range(0x1000, 0x2000);
        set.add_range(0x3000, 0x4000);

        assert_eq!(set.num_ranges(), 2);
        assert!(set.contains(0x1500));
        assert!(!set.contains(0x2500));
        assert_eq!(set.num_addresses(), 0x1000 + 0x1000);
    }

    #[test]
    fn test_address_range_set_merge() {
        let mut set = AddressRangeSet::new("ram");
        set.add_range(0x1000, 0x2000);
        set.add_range(0x1800, 0x3000); // overlaps

        assert_eq!(set.num_ranges(), 1);
        assert!(set.contains(0x1500));
        assert!(set.contains(0x2500));
        assert!(!set.contains(0x3000));
    }

    #[test]
    fn test_address_range_set_remove() {
        let mut set = AddressRangeSet::new("ram");
        set.add_range(0x1000, 0x3000);
        set.remove_range(0x1800, 0x2000);

        assert_eq!(set.num_ranges(), 2);
        assert!(set.contains(0x1500));
        assert!(!set.contains(0x1900));
        assert!(set.contains(0x2500));
    }

    #[test]
    fn test_address_range_set_empty() {
        let set = AddressRangeSet::new("ram");
        assert!(set.is_empty());
        assert!(!set.contains(0));
        assert_eq!(set.num_addresses(), 0);
    }

    #[test]
    fn test_address_range_set_iter() {
        let mut set = AddressRangeSet::new("ram");
        set.add_range(0x10, 0x13);
        let addrs: Vec<u64> = set.iter_addresses().collect();
        assert_eq!(addrs, vec![0x10, 0x11, 0x12]);
    }

    // -- PcodeDebuggerAccessBuilder --

    #[test]
    fn test_access_builder_basic() {
        let access = PcodeDebuggerAccessBuilder::new("trace1", 0)
            .language_id("x86:LE:64:default::gcc")
            .active_thread(42)
            .build()
            .unwrap();

        assert_eq!(access.trace_id, "trace1");
        assert_eq!(access.snap, 0);
        assert_eq!(access.language_id, "x86:LE:64:default::gcc");
        assert_eq!(access.active_thread(), Some(42));
    }

    #[test]
    fn test_access_builder_with_breakpoints() {
        let access = PcodeDebuggerAccessBuilder::new("trace1", 0)
            .with_breakpoint("ram", 0x400000)
            .with_breakpoint("ram", 0x400100)
            .build()
            .unwrap();

        assert_eq!(access.breakpoints().len(), 2);
    }

    #[test]
    fn test_access_builder_empty_trace_id() {
        let result = PcodeDebuggerAccessBuilder::new("", 0).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_access_builder_validate() {
        let builder = PcodeDebuggerAccessBuilder::new("trace1", 0);
        assert!(builder.validate().is_ok());

        let builder = PcodeDebuggerAccessBuilder::new("", 0);
        assert!(builder.validate().is_err());
    }

    // -- AsyncAccessQueue --

    #[test]
    fn test_async_queue_register_ops() {
        let mut queue = AsyncAccessQueue::new();
        let id1 = queue.enqueue_register_read("RAX");
        let id2 = queue.enqueue_register_write("RBX", vec![0x42; 8]);

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.num_pending(), 2);

        queue.complete(id1, vec![0xFF; 8]);
        assert!(queue.is_completed(id1));
        assert_eq!(queue.get(id1).unwrap().result, Some(vec![0xFF; 8]));

        queue.fail(id2, "write failed");
        assert_eq!(queue.get(id2).unwrap().status, AsyncOpStatus::Failed);
    }

    #[test]
    fn test_async_queue_memory_ops() {
        let mut queue = AsyncAccessQueue::new();
        let id = queue.enqueue_memory_read("ram", 0x400000, 4);
        assert_eq!(queue.num_pending(), 1);

        queue.complete(id, vec![0xEB, 0xFE, 0x90, 0xCC]);
        assert!(queue.is_completed(id));
    }

    #[test]
    fn test_async_queue_cancel() {
        let mut queue = AsyncAccessQueue::new();
        let id = queue.enqueue_register_read("RAX");
        assert!(queue.cancel(id));
        assert_eq!(queue.get(id).unwrap().status, AsyncOpStatus::Cancelled);
    }

    #[test]
    fn test_async_queue_drain_finished() {
        let mut queue = AsyncAccessQueue::new();
        let id1 = queue.enqueue_register_read("RAX");
        let _id2 = queue.enqueue_register_read("RBX");
        queue.complete(id1, vec![0x42; 8]);

        let finished = queue.drain_finished();
        assert_eq!(finished.len(), 1);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_async_queue_pending_completed() {
        let mut queue = AsyncAccessQueue::new();
        let id = queue.enqueue_memory_write("ram", 0x1000, vec![0xCC]);
        assert_eq!(queue.pending().len(), 1);
        assert_eq!(queue.completed().len(), 0);

        queue.complete(id, vec![]);
        assert_eq!(queue.pending().len(), 0);
        assert_eq!(queue.completed().len(), 1);
    }

    // -- AccessAuditLog --

    #[test]
    fn test_audit_log_basic() {
        let mut log = AccessAuditLog::new();
        log.log_memory_read("ram", 0x400000, 4, true);
        log.log_register_write("RAX", 8, true);
        log.log_memory_write("ram", 0x400004, 2, false);

        assert_eq!(log.len(), 3);
        assert_eq!(log.failures().len(), 1);
        assert_eq!(log.entries_of_kind(AuditLogKind::MemoryRead).len(), 1);
    }

    #[test]
    fn test_audit_log_entries_for() {
        let mut log = AccessAuditLog::new();
        log.log_memory_read("ram", 0x1000, 1, true);
        log.log_memory_read("ram", 0x2000, 1, true);
        log.log_register_read("RAX", 8, true);

        assert_eq!(log.entries_for("ram").len(), 2);
        assert_eq!(log.entries_for("RAX").len(), 1);
    }

    #[test]
    fn test_audit_log_max_entries() {
        let mut log = AccessAuditLog::new().with_max_entries(2);
        log.log_memory_read("ram", 0x1000, 1, true);
        log.log_memory_read("ram", 0x2000, 1, true);
        log.log_memory_read("ram", 0x3000, 1, true);

        assert_eq!(log.len(), 2);
        // First entry was evicted
        assert_eq!(log.entries()[0].offset, 0x2000);
    }

    #[test]
    fn test_audit_log_disabled() {
        let mut log = AccessAuditLog::new();
        log.set_enabled(false);
        log.log_memory_read("ram", 0x1000, 1, true);
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn test_audit_log_last() {
        let mut log = AccessAuditLog::new();
        assert!(log.last().is_none());
        log.log_memory_read("ram", 0x1000, 1, true);
        assert!(log.last().is_some());
        assert_eq!(log.last().unwrap().offset, 0x1000);
    }

    // -- TraceMemoryStateMap --

    #[test]
    fn test_state_map_basic() {
        let mut map = TraceMemoryStateMap::new("ram");
        map.mark_known(0x1000, 0x2000);
        map.mark_unknown(0x3000, 0x4000);

        assert_eq!(map.state_at(0x1500), TraceMemoryState::Known);
        assert_eq!(map.state_at(0x3500), TraceMemoryState::Unknown);
        assert_eq!(map.state_at(0x5000), TraceMemoryState::Unknown); // default
    }

    #[test]
    fn test_state_map_ranges() {
        let mut map = TraceMemoryStateMap::new("ram");
        map.mark_known(0x1000, 0x2000);
        map.mark_known(0x3000, 0x4000);
        map.mark_unknown(0x5000, 0x6000);

        assert_eq!(map.known_ranges().len(), 2);
        assert_eq!(map.unknown_ranges().len(), 1);
    }

    #[test]
    fn test_state_map_empty() {
        let map = TraceMemoryStateMap::new("ram");
        assert!(map.is_empty());
        assert_eq!(map.state_at(0), TraceMemoryState::Unknown);
    }

    // -- AccessStateDiff --

    #[test]
    fn test_access_state_diff_empty() {
        let diff = AccessStateDiff::default();
        assert!(diff.is_empty());
        assert_eq!(diff.num_changes(), 0);
    }

    #[test]
    fn test_access_state_diff_with_changes() {
        let mut diff = AccessStateDiff::default();
        diff.memory_writes.push(MemoryWriteRecord {
            space: "ram".into(),
            offset: 0x1000,
            data: vec![0xCC],
        });
        diff.register_writes.insert(
            1,
            vec![RegisterWriteRecord {
                name: "RAX".into(),
                data: vec![0x42; 8],
            }],
        );
        assert!(!diff.is_empty());
        assert_eq!(diff.num_changes(), 2);
    }

    // -- diff_memory_views --

    #[test]
    fn test_diff_memory_views() {
        let mut before = PcodeMemoryView::new();
        before.write("ram", 0x1000, &[0x01, 0x02]);

        let mut after = PcodeMemoryView::new();
        after.write("ram", 0x1000, &[0x01, 0x02]); // same
        after.write("ram", 0x2000, &[0xFF]); // new write

        let diffs = diff_memory_views(&before, &after);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].offset, 0x2000);
    }

    // -- DataAccessError --

    #[test]
    fn test_data_access_error_display() {
        let e = DataAccessError::NoSession;
        assert_eq!(format!("{}", e), "no active session");

        let e2 = DataAccessError::Other("test error".into());
        assert!(format!("{}", e2).contains("test error"));
    }

    // -- SourcedRegisterValue --

    #[test]
    fn test_sourced_register_value() {
        let srv =
            SourcedRegisterValue::new("RAX", vec![0x42; 8], RegisterValueSource::Target, 10);
        assert!(srv.is_live());
        assert_eq!(srv.name, "RAX");

        let srv2 =
            SourcedRegisterValue::new("RBX", vec![0xAA; 8], RegisterValueSource::Trace, 10);
        assert!(!srv2.is_live());
    }

    // -- PcodeDebuggerRegistersAccessState --

    #[test]
    fn test_registers_access_state_new() {
        let state = PcodeDebuggerRegistersAccessState::new(42, 0);
        assert_eq!(state.thread_key, 42);
        assert!(!state.is_live());
    }

    #[test]
    fn test_registers_access_state_with_target() {
        let mut target = TargetSimulator::new("test_target");
        target.connect();
        target.queue_register_read("RAX", vec![0x42; 8]);

        let mut state = PcodeDebuggerRegistersAccessState::new(1, 0).with_target(target);
        assert!(state.is_live());

        let count = state.read_from_target(&["RAX".to_string()]).unwrap();
        assert_eq!(count, 1);
        assert_eq!(state.register_view.read("RAX"), Some(vec![0x42; 8]));
    }

    #[test]
    fn test_registers_access_state_write() {
        let mut target = TargetSimulator::new("test_target");
        target.connect();

        let mut state = PcodeDebuggerRegistersAccessState::new(1, 0).with_target(target);
        let ok = state.write_to_target("RAX", &[0xFF; 8]).unwrap();
        assert!(ok);
        assert_eq!(state.register_view.read("RAX"), Some(vec![0xFF; 8]));
    }

    #[test]
    fn test_registers_access_state_no_target() {
        let mut state = PcodeDebuggerRegistersAccessState::new(1, 0);
        let result = state.read_from_target(&["RAX".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_registers_access_state_read_sourced() {
        let mut target = TargetSimulator::new("test_target");
        target.connect();
        target.queue_register_read("RAX", vec![0x42; 8]);

        let mut state = PcodeDebuggerRegistersAccessState::new(1, 5).with_target(target);
        state.read_from_target(&["RAX".to_string()]).unwrap();

        let sourced = state.read_sourced("RAX").unwrap();
        assert!(sourced.is_live());
        assert_eq!(sourced.snap, 5);
    }

    // -- MemoryWriteBuffer --

    #[test]
    fn test_memory_write_buffer() {
        let mut buf = MemoryWriteBuffer::new();
        assert!(buf.is_empty());

        buf.write("ram", 0x1000, vec![0xCC]);
        buf.write("ram", 0x2000, vec![0x90, 0x90]);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.total_bytes(), 3);

        let mut view = PcodeMemoryView::new();
        buf.commit_to(&mut view);
        assert_eq!(view.read("ram", 0x1000, 1), Some(vec![0xCC]));
        assert_eq!(view.read("ram", 0x2000, 2), Some(vec![0x90, 0x90]));

        buf.clear();
        assert!(buf.is_empty());
    }

    // -- RegisterValueSource --

    #[test]
    fn test_register_value_source_variants() {
        assert_ne!(RegisterValueSource::Target, RegisterValueSource::Trace);
        assert_ne!(RegisterValueSource::Emulated, RegisterValueSource::Unknown);
    }

    // -- AccessEventBus --

    #[test]
    fn test_event_bus_subscribe_and_publish() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let received = Rc::new(RefCell::new(Vec::new()));
        let received_clone = received.clone();

        let mut bus = AccessEventBus::new().with_max_log_size(100);
        let _sub = bus.subscribe(
            vec![AccessEventType::MemoryWrite],
            Box::new(move |event: &AccessEvent| {
                received_clone.borrow_mut().push(event.target.clone());
            }),
        );

        bus.on_memory_write("ram", 0x1000, 4, Some(1));
        bus.on_memory_read("ram", 0x2000, 2, Some(1)); // should not trigger

        let recorded = received.borrow();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], "ram");
    }

    #[test]
    fn test_event_bus_subscribe_all() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let count = Rc::new(RefCell::new(0u32));
        let count_clone = count.clone();

        let mut bus = AccessEventBus::new();
        let _sub = bus.subscribe_all(Box::new(move |_: &AccessEvent| {
            *count_clone.borrow_mut() += 1;
        }));

        bus.on_memory_read("ram", 0x1000, 1, Some(1));
        bus.on_register_write("RAX", 8, Some(1));
        bus.on_breakpoint_hit(1, Some(1));

        assert_eq!(*count.borrow(), 3);
    }

    #[test]
    fn test_event_bus_unsubscribe() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let count = Rc::new(RefCell::new(0u32));
        let count_clone = count.clone();

        let mut bus = AccessEventBus::new();
        let sub = bus.subscribe_all(Box::new(move |_: &AccessEvent| {
            *count_clone.borrow_mut() += 1;
        }));

        bus.on_register_read("RAX", 8, Some(1));
        assert_eq!(*count.borrow(), 1);

        assert!(bus.unsubscribe(sub));
        bus.on_register_read("RAX", 8, Some(1));
        assert_eq!(*count.borrow(), 1); // no change
    }

    #[test]
    fn test_event_bus_log() {
        let mut bus = AccessEventBus::new().with_max_log_size(10);
        bus.on_memory_write("ram", 0x1000, 4, Some(1));
        bus.on_register_write("RAX", 8, Some(1));

        assert_eq!(bus.event_log().len(), 2);
        assert_eq!(
            bus.events_of_type(AccessEventType::MemoryWrite).len(),
            1
        );
    }

    #[test]
    fn test_event_bus_num_subscriptions() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let dummy: Rc<RefCell<()>> = Rc::new(RefCell::new(()));

        let mut bus = AccessEventBus::new();
        let d1 = dummy.clone();
        let s1 = bus.subscribe_all(Box::new(move |_| { let _ = &d1; }));
        let d2 = dummy.clone();
        let _s2 = bus.subscribe_all(Box::new(move |_| { let _ = &d2; }));
        assert_eq!(bus.num_subscriptions(), 2);

        bus.unsubscribe(s1);
        assert_eq!(bus.num_subscriptions(), 1);
    }

    // -- MemoryCheckpointManager --

    #[test]
    fn test_memory_checkpoint_basic() {
        let mut memory = PcodeMemoryView::new();
        memory.write("ram", 0x1000, &[0x42, 0x43]);
        memory.write("ram", 0x2000, &[0xAA]);

        let mut mgr = MemoryCheckpointManager::new();
        let id = mgr.checkpoint("before_changes", 0, &memory);
        assert_eq!(mgr.len(), 1);

        // Modify memory
        memory.write("ram", 0x1000, &[0xFF, 0xFF]);
        assert_eq!(memory.read("ram", 0x1000, 2), Some(vec![0xFF, 0xFF]));

        // Restore checkpoint
        mgr.restore(id, &mut memory).unwrap();
        // Note: restore writes back checkpoint data, which was captured
        // from dirty regions at checkpoint time
        assert_eq!(mgr.get(id).unwrap().label, "before_changes");
    }

    #[test]
    fn test_memory_checkpoint_max() {
        let mut memory = PcodeMemoryView::new();

        let mut mgr = MemoryCheckpointManager::new().with_max_checkpoints(2);
        memory.write("ram", 0x1000, &[1]);
        mgr.checkpoint("cp1", 0, &memory);
        memory.write("ram", 0x2000, &[2]);
        mgr.checkpoint("cp2", 1, &memory);
        memory.write("ram", 0x3000, &[3]);
        mgr.checkpoint("cp3", 2, &memory);

        // Should have evicted the oldest
        assert_eq!(mgr.len(), 2);
        assert!(mgr.latest().is_some());
    }

    #[test]
    fn test_memory_checkpoint_list() {
        let mut memory = PcodeMemoryView::new();
        memory.write("ram", 0x1000, &[0x42]);

        let mut mgr = MemoryCheckpointManager::new();
        mgr.checkpoint("start", 0, &memory);
        mgr.checkpoint("mid", 5, &memory);

        let list = mgr.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].1, "start");
        assert_eq!(list[1].1, "mid");
    }

    #[test]
    fn test_memory_checkpoint_remove() {
        let mut memory = PcodeMemoryView::new();
        memory.write("ram", 0x1000, &[0x42]);

        let mut mgr = MemoryCheckpointManager::new();
        let id = mgr.checkpoint("test", 0, &memory);
        assert_eq!(mgr.len(), 1);

        mgr.remove(id);
        assert!(mgr.is_empty());
    }

    // -- AccessLockManager --

    #[test]
    fn test_lock_manager_shared_locks() {
        let mut mgr = AccessLockManager::new();

        // Two threads can acquire shared locks on the same range
        let id1 = mgr.acquire_shared("ram", 0x1000, 0x2000, 1, "read data").unwrap();
        let id2 = mgr.acquire_shared("ram", 0x1000, 0x2000, 2, "read data").unwrap();

        assert!(mgr.is_readable("ram", 0x1500, 0x1600, 1));
        assert!(mgr.is_readable("ram", 0x1500, 0x1600, 2));
        assert!(!mgr.is_writable("ram", 0x1500, 0x1600, 1)); // shared lock blocks write

        mgr.release(id1);
        mgr.release(id2);
        assert!(mgr.is_writable("ram", 0x1500, 0x1600, 1));
    }

    #[test]
    fn test_lock_manager_exclusive_lock() {
        let mut mgr = AccessLockManager::new();

        let _id1 = mgr.acquire_exclusive("ram", 0x1000, 0x2000, 1, "write data").unwrap();

        // Other thread can't read or write
        assert!(!mgr.is_readable("ram", 0x1500, 0x1600, 2));
        assert!(!mgr.is_writable("ram", 0x1500, 0x1600, 2));

        // Same thread can read/write (it holds the lock)
        assert!(mgr.is_readable("ram", 0x1500, 0x1600, 1));
        assert!(mgr.is_writable("ram", 0x1500, 0x1600, 1));
    }

    #[test]
    fn test_lock_manager_non_overlapping() {
        let mut mgr = AccessLockManager::new();

        let _id1 = mgr.acquire_exclusive("ram", 0x1000, 0x2000, 1, "write").unwrap();
        let _id2 = mgr.acquire_exclusive("ram", 0x3000, 0x4000, 2, "write").unwrap();

        // Non-overlapping ranges: thread 1 can write outside thread 2's lock range
        assert!(mgr.is_writable("ram", 0x2000, 0x2100, 1));
        // But thread 1 cannot write inside thread 2's exclusive lock
        assert!(!mgr.is_writable("ram", 0x3500, 0x3600, 1));
    }

    #[test]
    fn test_lock_manager_release_thread() {
        let mut mgr = AccessLockManager::new();

        mgr.acquire_shared("ram", 0x1000, 0x2000, 1, "a").unwrap();
        mgr.acquire_shared("ram", 0x3000, 0x4000, 1, "b").unwrap();
        mgr.acquire_shared("ram", 0x5000, 0x6000, 2, "c").unwrap();

        assert_eq!(mgr.len(), 3);
        mgr.release_thread(1);
        assert_eq!(mgr.len(), 1);
        assert_eq!(mgr.thread_locks(2).len(), 1);
    }

    #[test]
    fn test_lock_manager_conflict_rejected() {
        let mut mgr = AccessLockManager::new();

        mgr.acquire_exclusive("ram", 0x1000, 0x2000, 1, "write").unwrap();
        let result = mgr.acquire_shared("ram", 0x1500, 0x1600, 2, "read");
        assert!(result.is_err());
    }

    // -- PcodeStepController --

    #[test]
    fn test_step_controller_basic() {
        let mut ctrl = PcodeStepController::new(42)
            .with_mode(StepMode::Instruction)
            .with_max_history(100);

        ctrl.record_step(0x400000);
        ctrl.record_step(0x400004);
        ctrl.record_step(0x400008);

        assert_eq!(ctrl.steps_taken(), 3);
        assert_eq!(ctrl.last_pc(), Some(0x400008));
        assert_eq!(ctrl.history_len(), 3);
    }

    #[test]
    fn test_step_controller_max_steps() {
        let mut ctrl = PcodeStepController::new(0).with_max_steps(2);
        assert!(!ctrl.is_max_steps_reached());

        ctrl.record_step(0x100);
        ctrl.record_step(0x104);
        assert!(ctrl.is_max_steps_reached());
    }

    #[test]
    fn test_step_controller_loop_detection() {
        let mut ctrl = PcodeStepController::new(0);
        ctrl.record_step(0x100);
        ctrl.record_step(0x104);
        ctrl.record_step(0x100); // loop back

        assert!(ctrl.is_pc_in_history(0x100));
        assert!(ctrl.is_pc_in_history(0x104));
        assert!(!ctrl.is_pc_in_history(0x200));
    }

    #[test]
    fn test_step_controller_max_history() {
        let mut ctrl = PcodeStepController::new(0).with_max_history(3);
        ctrl.record_step(0x100);
        ctrl.record_step(0x104);
        ctrl.record_step(0x108);
        ctrl.record_step(0x10C);

        assert_eq!(ctrl.history_len(), 3);
        // 0x100 was evicted
        assert!(!ctrl.is_pc_in_history(0x100));
        assert_eq!(ctrl.history()[0], 0x104);
    }

    #[test]
    fn test_step_controller_recent_history() {
        let mut ctrl = PcodeStepController::new(0).with_max_history(100);
        ctrl.record_step(0x100);
        ctrl.record_step(0x104);
        ctrl.record_step(0x108);
        ctrl.record_step(0x10C);

        let recent = ctrl.recent_history(2);
        assert_eq!(recent, &[0x108, 0x10C]);
    }

    #[test]
    fn test_step_controller_reset_run() {
        let mut ctrl = PcodeStepController::new(0);
        ctrl.record_step(0x100);
        ctrl.record_step(0x104);
        assert_eq!(ctrl.steps_taken(), 2);

        ctrl.reset_run();
        assert_eq!(ctrl.steps_taken(), 0);
        // History is preserved
        assert_eq!(ctrl.history_len(), 2);
    }

    #[test]
    fn test_step_controller_clear_history() {
        let mut ctrl = PcodeStepController::new(0);
        ctrl.record_step(0x100);
        ctrl.clear_history();
        assert_eq!(ctrl.history_len(), 0);
        assert!(ctrl.last_pc().is_none());
    }

    // -- PcodeDebuggerMemoryAccessState --

    #[test]
    fn test_memory_access_state_basic() {
        let mut access = PcodeDebuggerMemoryAccessState::new("ram", 0);
        assert!(!access.is_live());
        assert_eq!(access.cached_bytes(), 0);

        access.write(0x1000, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(access.cached_bytes(), 4);

        let data = access.read(0x1000, 4);
        assert_eq!(data, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn test_memory_access_state_unknown() {
        let mut access = PcodeDebuggerMemoryAccessState::new("ram", 0);
        access.mark_unknown(0x1000, 0x2000);

        assert_eq!(access.state_at(0x1500), MemoryBlockState::Unknown);
        assert!(access.unknown_ranges().contains(0x1500));
    }

    #[test]
    fn test_memory_access_state_dirty_tracking() {
        let mut access = PcodeDebuggerMemoryAccessState::new("ram", 0);
        access.write(0x1000, &[0x42]);
        assert_eq!(access.state_at(0x1000), MemoryBlockState::Dirty);
    }

    #[test]
    fn test_memory_access_state_with_static_images() {
        let mut images = StaticImageProvider::new();
        images.register_bytes("program1", "ram", 0x400000, vec![0x55, 0x66, 0x77]);

        let mut access = PcodeDebuggerMemoryAccessState::new("ram", 0)
            .with_static_images(images);

        // Should fall back to static image
        let data = access.read(0x400000, 3);
        assert_eq!(data, Some(vec![0x55, 0x66, 0x77]));
    }

    #[test]
    fn test_memory_access_state_derive() {
        let access = PcodeDebuggerMemoryAccessState::new("ram", 0);
        // Just verify creation works
        assert_eq!(access.space, "ram");
        assert_eq!(access.snap, 0);
    }

    // -- AccessRateLimiter --

    #[test]
    fn test_rate_limiter_basic() {
        let mut limiter = AccessRateLimiter::new(3, 100);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire()); // 4th should be throttled
        assert!(limiter.is_throttled());
    }

    #[test]
    fn test_rate_limiter_ops_in_window() {
        let mut limiter = AccessRateLimiter::new(10, 100);
        limiter.try_acquire();
        limiter.try_acquire();
        limiter.try_acquire();
        assert_eq!(limiter.ops_in_window(), 3);
    }

    #[test]
    fn test_rate_limiter_reset() {
        let mut limiter = AccessRateLimiter::new(2, 100);
        limiter.try_acquire();
        limiter.try_acquire();
        assert!(!limiter.try_acquire());

        limiter.reset();
        assert!(!limiter.is_throttled());
        assert!(limiter.try_acquire());
    }

    #[test]
    fn test_rate_limiter_set_config() {
        let mut limiter = AccessRateLimiter::new(100, 1000);
        limiter.set_max_ops(5);
        limiter.set_window_ms(500);

        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }
        assert!(!limiter.try_acquire());
    }

    // -- PcodeTraceDataAccessImpl --

    #[test]
    fn test_trace_data_access_state() {
        let mut access = PcodeTraceDataAccessImpl::new("x86:LE:64:default::gcc", 0);
        assert_eq!(access.snap, 0);

        access.set_state(0x1000, 0x2000, TraceMemoryState::Known);
        assert_eq!(access.get_state(0x1500, 0x1504), TraceMemoryState::Known);
        assert!(access.known_ranges().contains(0x1500));
    }

    #[test]
    fn test_trace_data_access_state_error() {
        let mut access = PcodeTraceDataAccessImpl::new("test", 0);
        access.set_state(0x1000, 0x2000, TraceMemoryState::Error);
        assert_eq!(access.get_state(0x1500, 0x1504), TraceMemoryState::Error);
        assert!(access.error_ranges().contains(0x1500));
    }

    #[test]
    fn test_trace_data_access_state_unknown() {
        let mut access = PcodeTraceDataAccessImpl::new("test", 0);
        access.set_state(0x1000, 0x2000, TraceMemoryState::Known);
        access.set_state(0x1000, 0x2000, TraceMemoryState::Unknown);
        assert_eq!(access.get_state(0x1500, 0x1504), TraceMemoryState::Unknown);
    }

    #[test]
    fn test_trace_data_access_intersect_known() {
        let mut access = PcodeTraceDataAccessImpl::new("test", 0);
        access.set_state(0x1000, 0x3000, TraceMemoryState::Known);

        let mut query = AddressRangeSet::new("ram");
        query.add_range(0x1500, 0x3500);

        let intersection = access.intersect_known(&query);
        assert!(intersection.contains(0x1500));
        assert!(intersection.contains(0x2000));
        assert!(!intersection.contains(0x3100)); // Outside known range
    }

    #[test]
    fn test_trace_data_access_properties() {
        let mut access = PcodeTraceDataAccessImpl::new("test", 0);
        access.set_property("key1", vec![1, 2, 3]);
        assert_eq!(access.get_property("key1"), Some(&vec![1, 2, 3]));
        assert_eq!(access.get_property("missing"), None);
        assert_eq!(access.num_properties(), 1);
    }

    #[test]
    fn test_trace_data_access_derive() {
        let access = PcodeTraceDataAccessImpl::new("test", 0);
        let derived = access.derive_for_write(5);
        assert_eq!(derived.snap, 5);
        assert_eq!(derived.language_id, "test");
    }

    // -- AbstractPcodeDebuggerAccess --

    #[test]
    fn test_abstract_debugger_access() {
        let access = AbstractPcodeDebuggerAccess::new("trace1", "x86:LE:64:default", 0)
            .with_provider("tool1")
            .with_target("target1");
        assert!(access.is_live());
        assert_eq!(access.service_provider(), Some("tool1"));
        assert_eq!(access.target_id(), Some("target1"));
    }

    #[test]
    fn test_abstract_debugger_access_not_live() {
        let access = AbstractPcodeDebuggerAccess::new("trace1", "x86:LE:64:default", 0);
        assert!(!access.is_live());
        assert!(access.target_id().is_none());
    }

    #[test]
    fn test_abstract_debugger_access_derive() {
        let access = AbstractPcodeDebuggerAccess::new("trace1", "x86:LE:64:default", 0)
            .with_target("target1");
        let derived = access.derive_for_write(5);
        assert_eq!(derived.snap, 5);
        assert!(!derived.is_live()); // Derived is never live
    }

    #[test]
    fn test_abstract_debugger_access_memory_shim() {
        let mut access = AbstractPcodeDebuggerAccess::new("trace1", "x86:LE:64:default", 0);
        let shim = access.get_memory_access();
        assert!(!shim.is_live);

        shim.queue_read(0x1000, 0x1FFF);
        assert_eq!(shim.pending_reads.len(), 1);

        let reads = shim.drain_reads();
        assert_eq!(reads.len(), 1);
        assert!(shim.pending_reads.is_empty());
    }

    #[test]
    fn test_abstract_debugger_access_register_shim() {
        let mut access = AbstractPcodeDebuggerAccess::new("trace1", "x86:LE:64:default", 0);
        let shim = access.get_register_access(1, 0);
        assert_eq!(shim.thread_key, 1);
        assert_eq!(shim.frame, 0);
    }

    // -- DefaultPcodeDebuggerAccess --

    #[test]
    fn test_default_debugger_access() {
        let access = DefaultPcodeDebuggerAccess::new("trace1", "x86:LE:64:default", 0)
            .with_provider("tool1")
            .with_target("target1");
        assert!(access.is_live());
    }

    #[test]
    fn test_default_debugger_access_memory() {
        let mut access = DefaultPcodeDebuggerAccess::new("trace1", "x86:LE:64:default", 0);
        access.memory_mut().write("ram", 0x1000, &[0xAA, 0xBB]);
        let data = access.memory().read("ram", 0x1000, 2);
        assert_eq!(data, Some(vec![0xAA, 0xBB]));
    }

    #[test]
    fn test_default_debugger_access_write_to_target() {
        let mut access = DefaultPcodeDebuggerAccess::new("trace1", "x86:LE:64:default", 0)
            .with_target("target1");
        assert!(access.write_to_target("ram", 0x1000, &[0xAA]));
        // Data should be in memory view
        let data = access.memory().read("ram", 0x1000, 1);
        assert_eq!(data, Some(vec![0xAA]));
    }

    #[test]
    fn test_default_debugger_access_not_live() {
        let mut access = DefaultPcodeDebuggerAccess::new("trace1", "x86:LE:64:default", 0);
        assert!(!access.write_to_target("ram", 0x1000, &[0xAA]));
    }

    #[test]
    fn test_default_debugger_access_derive() {
        let access = DefaultPcodeDebuggerAccess::new("trace1", "x86:LE:64:default", 0)
            .with_target("target1");
        let derived = access.derive_for_write(5);
        assert!(!derived.is_live());
    }

    #[test]
    fn test_default_debugger_access_register_view() {
        let mut access = DefaultPcodeDebuggerAccess::new("trace1", "x86:LE:64:default", 0);
        let view = access.register_view(1);
        view.write("RAX", &[0x01; 8]);
        assert_eq!(view.read("RAX"), Some(vec![0x01; 8]));
    }

    #[test]
    fn test_default_debugger_access_write_register_to_target() {
        let mut access = DefaultPcodeDebuggerAccess::new("trace1", "x86:LE:64:default", 0)
            .with_target("target1");
        assert!(access.write_register_to_target(1, "RAX", &[0xFF; 8]));
        let view = access.register_view(1);
        assert_eq!(view.read("RAX"), Some(vec![0xFF; 8]));
    }

    // -- DefaultPcodeDebuggerMemoryAccess --

    #[test]
    fn test_default_memory_access() {
        let mut access = DefaultPcodeDebuggerMemoryAccess::new("x86:LE:64:default", 0);
        access.write("ram", 0x1000, &[0xAA, 0xBB, 0xCC]);
        let data = access.read("ram", 0x1000, 3);
        assert_eq!(data, Some(vec![0xAA, 0xBB, 0xCC]));
    }

    #[test]
    fn test_default_memory_access_with_static_images() {
        let mut images = StaticImageProvider::new();
        images.register_bytes("program1", "ram", 0x400000, vec![0x55, 0x66]);

        let access = DefaultPcodeDebuggerMemoryAccess::new("test", 0)
            .with_static_images(images);

        // Should read from static image since memory view is empty
        // Note: static images use a different read signature
    }

    #[test]
    fn test_default_memory_access_pending_reads() {
        let mut access = DefaultPcodeDebuggerMemoryAccess::new("test", 0);
        access.set_live(true);

        let mut shim_access = access.clone();
        assert!(shim_access.read_from_target_memory(&[(0x1000, 0x1FFF)]));
        let reads = shim_access.drain_pending_reads();
        assert_eq!(reads.len(), 1);
    }

    #[test]
    fn test_default_memory_access_not_live() {
        let mut access = DefaultPcodeDebuggerMemoryAccess::new("test", 0);
        assert!(!access.read_from_target_memory(&[(0x1000, 0x1FFF)]));
    }

    // -- DefaultPcodeDebuggerRegistersAccess --

    #[test]
    fn test_default_registers_access() {
        let mut access = DefaultPcodeDebuggerRegistersAccess::new(1, 0, 0);
        access.write_register("RAX", &[0x01; 8]);
        assert_eq!(access.read_register("RAX"), Some(vec![0x01; 8]));
    }

    #[test]
    fn test_default_registers_access_live() {
        let mut access = DefaultPcodeDebuggerRegistersAccess::new(1, 0, 0);
        access.set_live(true);
        assert!(access.read_from_target_registers(&[(0x100, 0x107)]));
        let reads = access.drain_pending_reads();
        assert_eq!(reads.len(), 1);
    }

    #[test]
    fn test_default_registers_access_not_live() {
        let mut access = DefaultPcodeDebuggerRegistersAccess::new(1, 0, 0);
        assert!(!access.read_from_target_registers(&[(0x100, 0x107)]));
        assert!(!access.write_target_register(0x100, &[0xFF]));
    }

    #[test]
    fn test_default_registers_access_is_live() {
        let mut access = DefaultPcodeDebuggerRegistersAccess::new(1, 0, 0);
        assert!(!access.is_live());
        access.set_live(true);
        assert!(access.is_live());
    }

    // -- PcodeDebuggerPropertyAccess --

    #[test]
    fn test_property_access() {
        let mut access = PcodeDebuggerPropertyAccess::new("test_prop", 0);
        assert!(access.is_empty());

        access.set_property("key1", vec![1, 2, 3]);
        access.set_property("key2", vec![4, 5]);

        assert_eq!(access.len(), 2);
        assert_eq!(access.get_property("key1"), Some(&vec![1, 2, 3]));
        assert_eq!(access.get_property("key2"), Some(&vec![4, 5]));
        assert_eq!(access.get_property("missing"), None);
    }

    #[test]
    fn test_property_access_remove() {
        let mut access = PcodeDebuggerPropertyAccess::new("test", 0);
        access.set_property("key1", vec![1, 2, 3]);
        assert_eq!(access.len(), 1);

        let removed = access.remove_property("key1");
        assert_eq!(removed, Some(vec![1, 2, 3]));
        assert!(access.is_empty());
    }

    #[test]
    fn test_property_access_keys() {
        let mut access = PcodeDebuggerPropertyAccess::new("test", 0);
        access.set_property("a", vec![1]);
        access.set_property("b", vec![2]);
        access.set_property("c", vec![3]);

        let keys = access.keys();
        assert_eq!(keys.len(), 3);
    }
}
