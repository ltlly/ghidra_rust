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
}
