//! Expand-block model — validates and expands memory blocks to a larger range.
//!
//! Ported from `ExpandBlockModel` in Ghidra's `ghidra.app.plugin.core.memory`.
//!
//! This model tracks the proposed new start/end addresses and length for
//! a block expansion, validates the expansion is larger than the current
//! block, and executes the expansion via [`Program`]'s memory API.

use ghidra_core::addr::Address;
use ghidra_core::mem::MemoryBlock;
use ghidra_core::program::program::Program;

/// Direction in which a block is expanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpandDirection {
    /// Expand the block downward (toward lower addresses).
    Down,
    /// Expand the block upward (toward higher addresses).
    Up,
}

/// Model for expanding a memory block.
///
/// Ported from `ExpandBlockModel` in Java. The model stores the current
/// block boundaries and the proposed new start/end/length. Validation
/// checks ensure the new length exceeds the current block size.
///
/// # Usage
///
/// ```ignore
/// let mut model = ExpandBlockModel::new(&program);
/// model.initialize(&block);
/// model.set_length(0x4000); // must be > current size
/// assert!(model.is_valid_length());
/// model.execute(&mut program).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct ExpandBlockModel {
    /// Name of the block being expanded.
    block_name: String,
    /// Original start address (snapshot for restore tracking).
    original_start: Address,
    /// Current proposed start address.
    start_addr: Address,
    /// Current proposed end address.
    end_addr: Address,
    /// Current proposed length.
    length: u64,
    /// Current block size (cached for validation).
    current_size: u64,
    /// Current validation message.
    message: String,
}

impl ExpandBlockModel {
    /// Create a new expand-block model.
    pub fn new() -> Self {
        Self {
            block_name: String::new(),
            original_start: Address::new(0),
            start_addr: Address::new(0),
            end_addr: Address::new(0),
            length: 0,
            current_size: 0,
            message: String::new(),
        }
    }

    /// Initialize the model from a memory block.
    pub fn initialize(&mut self, block: &MemoryBlock) {
        self.block_name = block.name.clone();
        self.start_addr = block.start();
        self.end_addr = block.end();
        self.original_start = block.start();
        self.length = block.size();
        self.current_size = block.size();
        self.message.clear();
    }

    /// Get the current start address.
    pub fn start_address(&self) -> Address {
        self.start_addr
    }

    /// Get the current end address.
    pub fn end_address(&self) -> Address {
        self.end_addr
    }

    /// Get the current proposed length.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Get the current message (empty if no issues).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the block name.
    pub fn block_name(&self) -> &str {
        &self.block_name
    }

    /// Set a new start address (expanding downward), recompute end.
    pub fn set_start_address(&mut self, new_start: Address) {
        self.start_addr = new_start;
        // Recompute length
        self.length = self.end_addr.offset - new_start.offset + 1;
        self.message.clear();
    }

    /// Set a new end address (expanding upward), keep start.
    pub fn set_end_address(&mut self, new_end: Address) {
        self.end_addr = new_end;
        self.length = new_end.offset - self.start_addr.offset + 1;
        self.message.clear();
    }

    /// Set a new total length, adjusting the end address (upward expansion).
    pub fn set_length(&mut self, new_length: u64) {
        self.length = new_length;
        self.end_addr = Address::new(self.start_addr.offset + new_length - 1);
        self.message.clear();
    }

    /// Validate that the proposed length is greater than the current block size.
    ///
    /// Returns `true` if valid, `false` otherwise. Sets [`message()`](Self::message)
    /// on failure.
    pub fn is_valid_length(&mut self) -> bool {
        if self.length <= self.current_size {
            self.message = format!(
                "Block size must be greater than 0x{:x}",
                self.current_size
            );
            false
        } else if self.length > i64::MAX as u64 {
            self.message = "Expanded block is too large".into();
            false
        } else {
            true
        }
    }

    /// Execute the expansion on the given program.
    ///
    /// This creates a new block at the proposed start address with the
    /// proposed length, then joins it with the original block.
    ///
    /// Returns `Ok(())` on success.
    pub fn execute(&mut self, program: &mut Program) -> Result<(), String> {
        if !self.is_valid_length() {
            return Err(self.message.clone());
        }

        // The expansion is done by creating a new block at the expanded
        // start address and joining it with the original block.
        let new_block_name = format!("{}.exp", self.block_name);
        let expanded_size = self.length;

        // Get the original block
        let original_block = program
            .memory
            .get_block_by_name(&self.block_name)
            .ok_or_else(|| format!("Block '{}' not found", self.block_name))?
            .clone();

        // Create a new block covering the expanded range
        let new_start = self.start_addr;
        let new_end = Address::new(new_start.offset + expanded_size - 1);

        // Determine filler block location
        if new_start < original_block.start() {
            // Expanding downward: create block before original
            let filler_size = original_block.start().offset - new_start.offset;
            program
                .memory
                .create_uninitialized_block(
                    &new_block_name,
                    new_start,
                    filler_size,
                    false,
                )
                .map_err(|e| format!("{}", e))?;
            program
                .memory
                .join_blocks(&new_block_name, &self.block_name)
                .map_err(|e| format!("{}", e))?;
        } else if new_end > original_block.end() {
            // Expanding upward: create block after original
            let filler_start = Address::new(original_block.end().offset + 1);
            let filler_size = new_end.offset - original_block.end().offset;
            program
                .memory
                .create_uninitialized_block(
                    &new_block_name,
                    filler_start,
                    filler_size,
                    false,
                )
                .map_err(|e| format!("{}", e))?;
            program
                .memory
                .join_blocks(&self.block_name, &new_block_name)
                .map_err(|e| format!("{}", e))?;
        }

        // Update model state
        if let Some(block) = program.memory.get_block_by_name(&self.block_name) {
            self.current_size = block.size();
            self.start_addr = block.start();
            self.end_addr = block.end();
            self.length = block.size();
        }

        Ok(())
    }
}

impl Default for ExpandBlockModel {
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
    fn test_initialize_from_block() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandBlockModel::new();
        model.initialize(&block);
        assert_eq!(model.block_name(), ".text");
        assert_eq!(model.length(), 0x1000);
        assert_eq!(model.start_address(), Address::new(0x1000));
        assert_eq!(model.end_address(), Address::new(0x1fff));
    }

    #[test]
    fn test_valid_length_greater_than_current() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandBlockModel::new();
        model.initialize(&block);
        model.set_length(0x2000);
        assert!(model.is_valid_length());
        assert!(model.message().is_empty());
    }

    #[test]
    fn test_invalid_length_less_than_or_equal_current() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandBlockModel::new();
        model.initialize(&block);
        model.set_length(0x800);
        assert!(!model.is_valid_length());
        assert!(!model.message().is_empty());
    }

    #[test]
    fn test_set_end_address_recomputes_length() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandBlockModel::new();
        model.initialize(&block);
        model.set_end_address(Address::new(0x3fff));
        assert_eq!(model.length(), 0x3000);
    }

    #[test]
    fn test_execute_expand_upward() {
        let mut program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandBlockModel::new();
        model.initialize(&block);
        model.set_length(0x3000);
        let result = model.execute(&mut program);
        assert!(result.is_ok(), "expand should succeed: {:?}", result.err());
        // After expansion the block should be 0x3000 bytes
        let block = program.memory.get_block_by_name(".text").unwrap();
        assert_eq!(block.size(), 0x3000);
    }

    #[test]
    fn test_execute_fails_with_invalid_length() {
        let mut program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandBlockModel::new();
        model.initialize(&block);
        model.set_length(0x100); // smaller than current
        let result = model.execute(&mut program);
        assert!(result.is_err());
    }
}
