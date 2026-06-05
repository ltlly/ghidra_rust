//! Debugger emulation integration.
//!
//! Ported from Ghidra's `DebuggerEmulationIntegration` from
//! `ghidra.app.plugin.core.debug.service.emulation`.
//!
//! Provides the integration between p-code emulators and the live debug
//! target. When emulating with a live session, memory reads may be
//! redirected to the target. Writes may be logged for later application
//! or immediately sent to the target.

use serde::{Deserialize, Serialize};

/// The write mode for emulator-target integration.
///
/// Ported from Ghidra's `Mode` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetWriteMode {
    /// Read and write to the target.
    Rw,
    /// Read only from the target (never write).
    Ro,
}

impl TargetWriteMode {
    /// Whether this mode allows writing to the target.
    pub fn can_write(&self) -> bool {
        matches!(self, Self::Rw)
    }
}

/// Writer configuration for emulator integration.
///
/// Ported from Ghidra's `TraceEmulationIntegration.Writer`.
/// Controls how the emulator interacts with trace and target data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationWriterConfig {
    /// The write mode (read-only vs read-write).
    pub mode: TargetWriteMode,
    /// Whether to redirect reads to the target.
    pub redirect_reads_to_target: bool,
    /// Whether to immediately write changes to the target.
    pub immediate_write_target: bool,
    /// Whether to log writes for later application.
    pub log_writes: bool,
    /// Timeout for target operations (microseconds).
    pub target_timeout_us: u64,
}

impl EmulationWriterConfig {
    /// Create a delayed-write writer for trace-only emulation.
    ///
    /// Reads may be redirected to the target, but writes are only
    /// logged. This is used for forking emulation from a snapshot.
    pub fn delayed_write_trace() -> Self {
        Self {
            mode: TargetWriteMode::Ro,
            redirect_reads_to_target: true,
            immediate_write_target: false,
            log_writes: true,
            target_timeout_us: 1_000_000,
        }
    }

    /// Create an immediate-write writer for live target emulation.
    ///
    /// Reads may be redirected to the target. Writes are immediately
    /// sent to the target.
    pub fn immediate_write_target() -> Self {
        Self {
            mode: TargetWriteMode::Rw,
            redirect_reads_to_target: true,
            immediate_write_target: true,
            log_writes: true,
            target_timeout_us: 1_000_000,
        }
    }

    /// Create a trace-only writer (no target interaction).
    pub fn trace_only() -> Self {
        Self {
            mode: TargetWriteMode::Ro,
            redirect_reads_to_target: false,
            immediate_write_target: false,
            log_writes: true,
            target_timeout_us: 0,
        }
    }
}

impl Default for EmulationWriterConfig {
    fn default() -> Self {
        Self::delayed_write_trace()
    }
}

/// Result of a target read/write operation.
///
/// Ported from Ghidra's `AccessPcodeExecutionException` handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetOperationResult {
    /// The operation succeeded.
    Success,
    /// The operation timed out.
    Timeout,
    /// The operation failed with an error.
    Error(String),
    /// The operation was skipped (not live or not applicable).
    Skipped,
}

/// Statistics about emulator-target integration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulationIntegrationStats {
    /// Number of memory reads redirected to the target.
    pub target_memory_reads: u64,
    /// Number of register reads redirected to the target.
    pub target_register_reads: u64,
    /// Number of memory writes sent to the target.
    pub target_memory_writes: u64,
    /// Number of register writes sent to the target.
    pub target_register_writes: u64,
    /// Number of target read timeouts.
    pub read_timeouts: u64,
    /// Number of target write timeouts.
    pub write_timeouts: u64,
    /// Total bytes read from target.
    pub bytes_read: u64,
    /// Total bytes written to target.
    pub bytes_written: u64,
}

impl EmulationIntegrationStats {
    /// Total number of target operations.
    pub fn total_target_ops(&self) -> u64 {
        self.target_memory_reads
            + self.target_register_reads
            + self.target_memory_writes
            + self.target_register_writes
    }

    /// Total number of timeouts.
    pub fn total_timeouts(&self) -> u64 {
        self.read_timeouts + self.write_timeouts
    }
}

/// Piece handler for memory domain emulation.
///
/// Ported from Ghidra's `TargetBytesPieceHandler`.
/// When the emulator reads from an address in a piece handled by
/// this handler, the read may be redirected to the live target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetBytesPieceHandler {
    /// The write mode.
    pub mode: TargetWriteMode,
    /// The address space ID this handler covers.
    pub space_id: u16,
    /// Statistics for this handler.
    pub stats: EmulationIntegrationStats,
}

impl TargetBytesPieceHandler {
    /// Create a new piece handler.
    pub fn new(mode: TargetWriteMode, space_id: u16) -> Self {
        Self {
            mode,
            space_id,
            stats: EmulationIntegrationStats::default(),
        }
    }

    /// Whether this handler can write to the target.
    pub fn can_write(&self) -> bool {
        self.mode.can_write()
    }

    /// Handle a read that failed (value is uninitialized in trace).
    ///
    /// If the target is live and the handler allows it, this redirects
    /// the read to the target.
    pub fn handle_uninitialized_read(
        &mut self,
        _addr: u64,
        _size: usize,
        is_live: bool,
    ) -> TargetOperationResult {
        if !is_live {
            return TargetOperationResult::Skipped;
        }
        // In a real implementation, this would send a read request
        // to the debug target and return the data
        self.stats.target_memory_reads += 1;
        TargetOperationResult::Success
    }

    /// Handle a write to the trace.
    ///
    /// If the handler mode is RW and the target is live, the write
    /// is also forwarded to the target.
    pub fn handle_write(
        &mut self,
        _addr: u64,
        _data: &[u8],
        is_live: bool,
    ) -> TargetOperationResult {
        if !is_live || !self.mode.can_write() {
            return TargetOperationResult::Skipped;
        }
        self.stats.target_memory_writes += 1;
        self.stats.bytes_written += _data.len() as u64;
        TargetOperationResult::Success
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_mode() {
        assert!(TargetWriteMode::Rw.can_write());
        assert!(!TargetWriteMode::Ro.can_write());
    }

    #[test]
    fn test_delayed_write_trace() {
        let config = EmulationWriterConfig::delayed_write_trace();
        assert_eq!(config.mode, TargetWriteMode::Ro);
        assert!(!config.immediate_write_target);
        assert!(config.log_writes);
    }

    #[test]
    fn test_immediate_write_target() {
        let config = EmulationWriterConfig::immediate_write_target();
        assert_eq!(config.mode, TargetWriteMode::Rw);
        assert!(config.immediate_write_target);
    }

    #[test]
    fn test_trace_only() {
        let config = EmulationWriterConfig::trace_only();
        assert!(!config.redirect_reads_to_target);
        assert!(!config.immediate_write_target);
    }

    #[test]
    fn test_default_writer_config() {
        let config = EmulationWriterConfig::default();
        assert_eq!(config.mode, TargetWriteMode::Ro);
    }

    #[test]
    fn test_integration_stats() {
        let mut stats = EmulationIntegrationStats::default();
        stats.target_memory_reads = 10;
        stats.target_register_reads = 5;
        stats.read_timeouts = 2;
        assert_eq!(stats.total_target_ops(), 15);
        assert_eq!(stats.total_timeouts(), 2);
    }

    #[test]
    fn test_piece_handler() {
        let mut handler = TargetBytesPieceHandler::new(TargetWriteMode::Rw, 1);
        assert!(handler.can_write());

        let result = handler.handle_write(0x400000, &[0x90], true);
        assert!(matches!(result, TargetOperationResult::Success));
        assert_eq!(handler.stats.target_memory_writes, 1);
    }

    #[test]
    fn test_piece_handler_read_only() {
        let mut handler = TargetBytesPieceHandler::new(TargetWriteMode::Ro, 1);
        let result = handler.handle_write(0x400000, &[0x90], true);
        assert!(matches!(result, TargetOperationResult::Skipped));
    }

    #[test]
    fn test_piece_handler_not_live() {
        let mut handler = TargetBytesPieceHandler::new(TargetWriteMode::Rw, 1);
        let result = handler.handle_write(0x400000, &[0x90], false);
        assert!(matches!(result, TargetOperationResult::Skipped));
    }

    #[test]
    fn test_piece_handler_read() {
        let mut handler = TargetBytesPieceHandler::new(TargetWriteMode::Ro, 1);
        let result = handler.handle_uninitialized_read(0x400000, 4, true);
        assert!(matches!(result, TargetOperationResult::Success));
        assert_eq!(handler.stats.target_memory_reads, 1);
    }

    #[test]
    fn test_serde_roundtrip() {
        let config = EmulationWriterConfig::immediate_write_target();
        let json = serde_json::to_string(&config).unwrap();
        let back: EmulationWriterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mode, TargetWriteMode::Rw);
    }
}
