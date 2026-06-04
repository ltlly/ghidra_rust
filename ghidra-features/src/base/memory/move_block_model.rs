//! Move-block model — validates and moves memory blocks to a new start address.
//!
//! Ported from `MoveBlockModel` in Ghidra's `ghidra.app.plugin.core.memory`.
//!
//! This model computes the new start/end addresses for a block move,
//! validates the move does not cause overflow or conflicts, and
//! executes the move via [`Program::memory`].

use ghidra_core::addr::Address;
use ghidra_core::mem::MemoryBlock;
use ghidra_core::program::program::Program;

/// Model for moving a memory block to a new start address.
///
/// Ported from `MoveBlockModel` in Java. The model stores the proposed
/// new start and end addresses and validates them before executing.
///
/// # Usage
///
/// ```ignore
/// let mut model = MoveBlockModel::new();
/// model.initialize(&block);
/// model.set_new_start_address(Address::new(0x5000));
/// assert!(model.message().is_empty());
/// model.execute(&mut program).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct MoveBlockModel {
    /// Name of the block to move.
    block_name: String,
    /// Original start address (used for identity after restore).
    original_start: Address,
    /// Current block size (cached).
    block_size: u64,
    /// Proposed new start address.
    new_start: Address,
    /// Proposed new end address.
    new_end: Address,
    /// Current validation message (empty if no issues).
    message: String,
}

impl MoveBlockModel {
    /// Create a new move-block model.
    pub fn new() -> Self {
        Self {
            block_name: String::new(),
            original_start: Address::new(0),
            block_size: 0,
            new_start: Address::new(0),
            new_end: Address::new(0),
            message: String::new(),
        }
    }

    /// Initialize the model from a memory block.
    pub fn initialize(&mut self, block: &MemoryBlock) {
        self.block_name = block.name.clone();
        self.block_size = block.size();
        self.new_start = block.start();
        self.original_start = block.start();
        self.new_end = block.end();
        self.message.clear();
    }

    /// Get the block name.
    pub fn block_name(&self) -> &str {
        &self.block_name
    }

    /// Get the current block size.
    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    /// Get the formatted block length string (decimal and hex).
    pub fn length_string(&self) -> String {
        format!("{}  (0x{:x})", self.block_size, self.block_size)
    }

    /// Get the proposed new start address.
    pub fn new_start_address(&self) -> Address {
        self.new_start
    }

    /// Get the proposed new end address.
    pub fn new_end_address(&self) -> Address {
        self.new_end
    }

    /// Get the current validation message (empty if no issues).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Set a new start address, recomputing the end address.
    ///
    /// The block is moved so that its start is at `new_start` and its
    /// size remains unchanged.
    pub fn set_new_start_address(&mut self, new_start: Address) {
        self.message.clear();
        self.new_start = new_start;

        match self.compute_end(new_start) {
            Some(end) => {
                self.new_end = end;
                if new_start == self.original_start {
                    self.message = format!("Block is already at {}", new_start);
                }
            }
            None => {
                self.message = "Start Address is too big".into();
            }
        }
    }

    /// Set a new end address, recomputing the start address.
    ///
    /// The block is moved so that its end is at `new_end` and its
    /// size remains unchanged.
    pub fn set_new_end_address(&mut self, new_end: Address) {
        self.message.clear();
        self.new_end = new_end;

        match self.compute_start(new_end) {
            Some(start) => {
                self.new_start = start;
            }
            None => {
                self.message = "End Address is too small".into();
            }
        }
    }

    /// Compute the end address given a start address, handling overflow.
    fn compute_end(&self, start: Address) -> Option<Address> {
        let end_offset = start.offset.checked_add(self.block_size.checked_sub(1)?)?;
        Some(Address::new( end_offset))
    }

    /// Compute the start address given an end address, handling underflow.
    fn compute_start(&self, end: Address) -> Option<Address> {
        let start_offset = end.offset.checked_sub(self.block_size.checked_sub(1)?)?;
        Some(Address::new( start_offset))
    }

    /// Execute the block move on the given program.
    ///
    /// Returns `Ok(())` on success.
    pub fn execute(&self, program: &mut Program) -> Result<(), String> {
        if !self.message.is_empty() {
            return Err(self.message.clone());
        }

        program
            .memory
            .move_block(&self.block_name, self.new_start)
            .map_err(|e| format!("{}", e))
    }
}

impl Default for MoveBlockModel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use ghidra_core::mem::MemoryMap;

    fn make_program_with_block() -> Program {
        let memory = MemoryMap::new(false);
        let mut p = Program::with_memory("test", Address::new(0), Box::new(memory));
        let _ = p.memory.create_initialized_block(
            ".text",
            Address::new(0x1000),
            vec![0u8; 0x1000],
            false,
        );
        p
    }

    #[test]
    fn test_initialize() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = MoveBlockModel::new();
        model.initialize(&block);
        assert_eq!(model.block_name(), ".text");
        assert_eq!(model.block_size(), 0x1000);
        assert_eq!(model.new_start_address(), Address::new(0x1000));
        assert_eq!(model.new_end_address(), Address::new(0x1fff));
    }

    #[test]
    fn test_set_new_start_address() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = MoveBlockModel::new();
        model.initialize(&block);
        model.set_new_start_address(Address::new(0x5000));
        assert_eq!(model.new_start_address(), Address::new(0x5000));
        assert_eq!(model.new_end_address(), Address::new(0x5fff));
        assert!(model.message().is_empty());
    }

    #[test]
    fn test_set_new_start_address_same_as_current() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = MoveBlockModel::new();
        model.initialize(&block);
        model.set_new_start_address(Address::new(0x1000)); // same as current
        assert!(model.message().contains("already at"));
    }

    #[test]
    fn test_set_new_end_address() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = MoveBlockModel::new();
        model.initialize(&block);
        model.set_new_end_address(Address::new(0x8fff));
        assert_eq!(model.new_start_address(), Address::new(0x8000));
        assert_eq!(model.new_end_address(), Address::new(0x8fff));
    }

    #[test]
    fn test_length_string() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = MoveBlockModel::new();
        model.initialize(&block);
        let s = model.length_string();
        assert!(s.contains("0x1000"), "length string should contain hex: {}", s);
    }

    #[test]
    fn test_execute_move() {
        let mut program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = MoveBlockModel::new();
        model.initialize(&block);
        model.set_new_start_address(Address::new(0x5000));
        assert!(model.message().is_empty());
        let result = model.execute(&mut program);
        assert!(result.is_ok(), "move should succeed: {:?}", result.err());
        // After move, block should be at 0x5000
        let moved = program.memory.get_block_by_name(".text").unwrap();
        assert_eq!(moved.start(), Address::new(0x5000));
    }
}
