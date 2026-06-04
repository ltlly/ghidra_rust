//! Trace emulation integration - connecting pcode emulators to trace data.
//!
//! Ported from Ghidra's `TraceEmulationIntegration` class in
//! Framework-TraceModeling. Provides the `Writer` and `PieceHandler`
//! abstractions for bridging pcode emulator state with trace storage.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::model::Lifespan;
use crate::pcode::data::{PcodeTraceMemoryAccess, PcodeTraceRegistersAccess};

/// The kind of state piece being handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PieceDomain {
    /// Concrete byte-addressed memory state.
    Bytes,
    /// Register state.
    Registers,
    /// Property (key-value) state.
    Property,
    /// Custom/abstract domain.
    Custom(u32),
}

/// Strategy for how writes are flushed to the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WriteStrategy {
    /// Writes are buffered and flushed to the trace later via `write_down`.
    Delayed,
    /// Writes are immediately written to the trace upon each pcode operation.
    Immediate,
}

impl Default for WriteStrategy {
    fn default() -> Self {
        Self::Delayed
    }
}

/// A piece handler processes read and write callbacks for a specific
/// state domain.
///
/// Ported from Ghidra's `TraceEmulationIntegration.PieceHandler`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PieceHandler {
    /// The domain this handler is responsible for.
    pub domain: PieceDomain,
    /// The write strategy.
    pub strategy: WriteStrategy,
    /// Maximum chunk size for buffered writes.
    pub chunk_size: usize,
    /// Tracked set of addresses that have been written (offset pairs).
    pub written_offsets: Vec<(String, u64, u64)>,
}

impl PieceHandler {
    /// Create a piece handler for the given domain.
    pub fn new(domain: PieceDomain, strategy: WriteStrategy) -> Self {
        Self {
            domain,
            strategy,
            chunk_size: 4096,
            written_offsets: Vec::new(),
        }
    }

    /// Create a bytes piece handler with delayed write strategy.
    pub fn bytes_delayed() -> Self {
        Self::new(PieceDomain::Bytes, WriteStrategy::Delayed)
    }

    /// Create a bytes piece handler with immediate write strategy.
    pub fn bytes_immediate() -> Self {
        Self::new(PieceDomain::Bytes, WriteStrategy::Immediate)
    }

    /// Create a property piece handler with delayed write strategy.
    pub fn property_delayed() -> Self {
        Self::new(PieceDomain::Property, WriteStrategy::Delayed)
    }

    /// Record a write at the given address.
    pub fn record_write(&mut self, space: impl Into<String>, offset: u64, length: u64) {
        let entry = (space.into(), offset, length);
        if !self.written_offsets.contains(&entry) {
            self.written_offsets.push(entry);
        }
    }

    /// Check if any writes have been recorded.
    pub fn has_writes(&self) -> bool {
        !self.written_offsets.is_empty()
    }

    /// Clear the recorded writes.
    pub fn clear_writes(&mut self) {
        self.written_offsets.clear();
    }
}

/// A trace writer that logs or immediately flushes emulator state changes
/// to the trace.
///
/// Ported from Ghidra's `TraceEmulationIntegration.TraceWriter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceWriter {
    /// The write strategy.
    pub strategy: WriteStrategy,
    /// Memory access shim.
    pub memory_access: PcodeTraceMemoryAccess,
    /// Per-thread register access shims.
    pub register_access: HashMap<i64, PcodeTraceRegistersAccess>,
    /// Piece handlers, keyed by domain.
    pub handlers: HashMap<PieceDomain, PieceHandler>,
    /// Addresses written in the memory state.
    pub memory_written: Vec<(u64, u64)>,
    /// Per-thread addresses written in the register state.
    pub registers_written: HashMap<i64, Vec<(u64, u64)>>,
}

impl TraceWriter {
    /// Create a new trace writer with delayed write strategy.
    pub fn delayed(memory_access: PcodeTraceMemoryAccess) -> Self {
        Self {
            strategy: WriteStrategy::Delayed,
            memory_access,
            register_access: HashMap::new(),
            handlers: HashMap::new(),
            memory_written: Vec::new(),
            registers_written: HashMap::new(),
        }
    }

    /// Create a new trace writer with immediate write strategy.
    pub fn immediate(memory_access: PcodeTraceMemoryAccess) -> Self {
        Self {
            strategy: WriteStrategy::Immediate,
            memory_access,
            register_access: HashMap::new(),
            handlers: HashMap::new(),
            memory_written: Vec::new(),
            registers_written: HashMap::new(),
        }
    }

    /// Add or replace a piece handler.
    pub fn put_handler(&mut self, handler: PieceHandler) {
        self.handlers.insert(handler.domain, handler);
    }

    /// Get the piece handler for a given domain.
    pub fn handler(&self, domain: PieceDomain) -> Option<&PieceHandler> {
        self.handlers.get(&domain)
    }

    /// Record a memory write.
    pub fn record_memory_write(&mut self, offset: u64, length: u64) {
        self.memory_written.push((offset, length));
        if let Some(handler) = self.handlers.get_mut(&PieceDomain::Bytes) {
            handler.record_write("ram", offset, length);
        }
    }

    /// Record a register write for a given thread.
    pub fn record_register_write(&mut self, thread_key: i64, offset: u64, length: u64) {
        self.registers_written
            .entry(thread_key)
            .or_default()
            .push((offset, length));
    }

    /// Whether there are any recorded writes.
    pub fn has_writes(&self) -> bool {
        !self.memory_written.is_empty()
            || !self.registers_written.is_empty()
            || self.handlers.values().any(|h| h.has_writes())
    }

    /// Clear all recorded writes.
    pub fn clear(&mut self) {
        self.memory_written.clear();
        self.registers_written.clear();
        for handler in self.handlers.values_mut() {
            handler.clear_writes();
        }
    }
}

/// Integration callbacks for connecting a pcode emulator to a trace.
///
/// Ported from Ghidra's `TraceEmulationIntegration` static methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEmulationCallbacks {
    /// The write strategy for this emulation session.
    pub strategy: WriteStrategy,
    /// The snap being emulated.
    pub source_snap: i64,
    /// The lifespan for writes.
    pub write_lifespan: Lifespan,
    /// The trace writer managing state changes.
    pub writer: Option<TraceWriter>,
}

impl TraceEmulationCallbacks {
    /// Create delayed-write callbacks for emulation from a given snap.
    pub fn delayed(source_snap: i64) -> Self {
        Self {
            strategy: WriteStrategy::Delayed,
            source_snap,
            write_lifespan: Lifespan::now_on(source_snap),
            writer: None,
        }
    }

    /// Create immediate-write callbacks for emulation from a given snap.
    pub fn immediate(source_snap: i64) -> Self {
        Self {
            strategy: WriteStrategy::Immediate,
            source_snap,
            write_lifespan: Lifespan::now_on(source_snap),
            writer: None,
        }
    }

    /// Set the writer for this callbacks instance.
    pub fn set_writer(&mut self, writer: TraceWriter) {
        self.writer = Some(writer);
    }

    /// Whether there are buffered writes to flush.
    pub fn has_pending_writes(&self) -> bool {
        self.writer.as_ref().map_or(false, |w| w.has_writes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::data::PcodeTraceMemoryAccess;

    #[test]
    fn test_piece_handler_bytes_delayed() {
        let handler = PieceHandler::bytes_delayed();
        assert_eq!(handler.domain, PieceDomain::Bytes);
        assert_eq!(handler.strategy, WriteStrategy::Delayed);
        assert!(!handler.has_writes());

        let mut handler = handler;
        handler.record_write("ram", 0x400000, 4);
        assert!(handler.has_writes());
        assert_eq!(handler.written_offsets.len(), 1);

        handler.clear_writes();
        assert!(!handler.has_writes());
    }

    #[test]
    fn test_piece_handler_bytes_immediate() {
        let handler = PieceHandler::bytes_immediate();
        assert_eq!(handler.strategy, WriteStrategy::Immediate);
    }

    #[test]
    fn test_trace_writer_creation() {
        let mem_access = PcodeTraceMemoryAccess::new("test_trace", 0);
        let writer = TraceWriter::delayed(mem_access);
        assert_eq!(writer.strategy, WriteStrategy::Delayed);
        assert!(!writer.has_writes());
    }

    #[test]
    fn test_trace_writer_record_writes() {
        let mem_access = PcodeTraceMemoryAccess::new("test_trace", 0);
        let mut writer = TraceWriter::delayed(mem_access);

        writer.put_handler(PieceHandler::bytes_delayed());
        writer.record_memory_write(0x400000, 4);
        assert!(writer.has_writes());
        assert_eq!(writer.memory_written.len(), 1);

        writer.record_register_write(1, 0x100, 8);
        assert_eq!(writer.registers_written.len(), 1);

        writer.clear();
        assert!(!writer.has_writes());
    }

    #[test]
    fn test_trace_emulation_callbacks() {
        let cb = TraceEmulationCallbacks::delayed(10);
        assert_eq!(cb.source_snap, 10);
        assert_eq!(cb.strategy, WriteStrategy::Delayed);
        assert!(!cb.has_pending_writes());

        let cb_imm = TraceEmulationCallbacks::immediate(20);
        assert_eq!(cb_imm.strategy, WriteStrategy::Immediate);
    }

    #[test]
    fn test_piece_domain_equality() {
        assert_eq!(PieceDomain::Bytes, PieceDomain::Bytes);
        assert_ne!(PieceDomain::Bytes, PieceDomain::Registers);
        assert_ne!(PieceDomain::Custom(1), PieceDomain::Custom(2));
    }

    #[test]
    fn test_write_strategy_default() {
        assert_eq!(WriteStrategy::default(), WriteStrategy::Delayed);
    }
}
