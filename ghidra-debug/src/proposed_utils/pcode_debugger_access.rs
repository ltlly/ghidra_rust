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
}
