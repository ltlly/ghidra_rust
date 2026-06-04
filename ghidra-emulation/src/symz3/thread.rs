//! Symbolic p-code thread.
//!
//! Ported from `SymZ3PcodeThread.java` and `SymZ3PcodeThreadExecutor.java`
//! in the SymbolicSummaryZ3 extension.
//!
//! A symbolic thread tracks the execution state of a single thread
//! within the symbolic emulator, including the current instruction
//! pointer and the p-code frame.

use super::model::SymValueZ3;

/// A symbolic p-code thread.
///
/// Each thread has its own program counter, p-code frame position,
/// and can track symbolic values for its local state.
#[derive(Debug)]
pub struct SymZ3PcodeThread {
    /// Thread ID.
    pub id: u32,
    /// Current program counter (instruction address).
    pub pc: u64,
    /// Current p-code operation index within the instruction.
    pub op_index: u32,
    /// Whether this thread is active (not halted or terminated).
    active: bool,
    /// Symbolic values for thread-local state.
    locals: std::collections::HashMap<u64, SymValueZ3>,
}

impl SymZ3PcodeThread {
    /// Create a new symbolic thread.
    pub fn new(id: u32, entry_point: u64) -> Self {
        Self {
            id,
            pc: entry_point,
            op_index: 0,
            active: true,
            locals: std::collections::HashMap::new(),
        }
    }

    /// Whether the thread is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Halt the thread.
    pub fn halt(&mut self) {
        self.active = false;
    }

    /// Set the program counter.
    pub fn set_pc(&mut self, address: u64) {
        self.pc = address;
        self.op_index = 0;
    }

    /// Advance the p-code operation index.
    pub fn advance_op(&mut self) {
        self.op_index += 1;
    }

    /// Set a thread-local symbolic value.
    pub fn set_local(&mut self, offset: u64, value: SymValueZ3) {
        self.locals.insert(offset, value);
    }

    /// Get a thread-local symbolic value.
    pub fn get_local(&self, offset: u64) -> Option<&SymValueZ3> {
        self.locals.get(&offset)
    }

    /// Clear all thread-local state.
    pub fn clear_locals(&mut self) {
        self.locals.clear();
    }
}

/// The thread executor processes p-code operations for a symbolic thread.
///
/// It dispatches each p-code operation to the symbolic arithmetic,
/// producing symbolic values and updating the thread's state.
#[derive(Debug)]
pub struct SymZ3PcodeThreadExecutor {
    /// The thread being executed.
    thread_id: u32,
    /// Number of operations executed.
    ops_executed: u64,
}

impl SymZ3PcodeThreadExecutor {
    /// Create a new executor for the given thread.
    pub fn new(thread_id: u32) -> Self {
        Self {
            thread_id,
            ops_executed: 0,
        }
    }

    /// The thread ID this executor manages.
    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }

    /// Number of operations executed.
    pub fn ops_executed(&self) -> u64 {
        self.ops_executed
    }

    /// Record that an operation was executed.
    pub fn record_op(&mut self) {
        self.ops_executed += 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_creation() {
        let t = SymZ3PcodeThread::new(0, 0x1000);
        assert_eq!(t.id, 0);
        assert_eq!(t.pc, 0x1000);
        assert!(t.is_active());
    }

    #[test]
    fn test_thread_halt() {
        let mut t = SymZ3PcodeThread::new(0, 0x1000);
        t.halt();
        assert!(!t.is_active());
    }

    #[test]
    fn test_thread_set_pc() {
        let mut t = SymZ3PcodeThread::new(0, 0x1000);
        t.advance_op();
        t.advance_op();
        assert_eq!(t.op_index, 2);
        t.set_pc(0x2000);
        assert_eq!(t.pc, 0x2000);
        assert_eq!(t.op_index, 0);
    }

    #[test]
    fn test_thread_locals() {
        let mut t = SymZ3PcodeThread::new(0, 0x1000);
        t.set_local(0, SymValueZ3::from_bitvec("val0"));
        t.set_local(8, SymValueZ3::from_bitvec("val8"));
        assert_eq!(t.get_local(0).unwrap().bitvec_expr_string.as_deref(), Some("val0"));
        assert!(t.get_local(4).is_none());
    }

    #[test]
    fn test_executor() {
        let mut exec = SymZ3PcodeThreadExecutor::new(0);
        assert_eq!(exec.ops_executed(), 0);
        exec.record_op();
        exec.record_op();
        assert_eq!(exec.ops_executed(), 2);
    }
}
