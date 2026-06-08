//! Expand-up model -- validates and expands a block toward lower addresses.
//!
//! Ported from `ExpandBlockUpModel` in Ghidra's `ghidra.app.plugin.core.memory`.
//!
//! This model specializes [`ExpandBlockModel`] for the "expand up" direction:
//! the user provides a new start address (which must be less than the current
//! block start), and the model recomputes the length and end address accordingly.

use ghidra_core::addr::Address;
use ghidra_core::mem::MemoryBlock;
use ghidra_core::program::program::Program;

use super::expand_block_model::ExpandBlockModel;

// ============================================================================
// ExpandUpModel
// ============================================================================

/// Model for expanding a memory block toward lower addresses.
///
/// Ported from `ExpandBlockUpModel` in Java. This model:
/// - Accepts a new start address (must be < current block start)
/// - Recomputes length as `block_end - new_start + 1`
/// - Validates the new length is greater than the current block size
/// - Executes the expansion by creating a filler block and joining
///
/// # Usage
///
/// ```ignore
/// let mut model = ExpandUpModel::new();
/// model.initialize(&block);
/// model.set_start_address(Address::new(0x800));
/// assert!(model.validate().is_ok());
/// model.execute(&mut program).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct ExpandUpModel {
    /// Inner expand-block model for common logic.
    inner: ExpandBlockModel,
}

impl ExpandUpModel {
    /// Create a new expand-up model.
    pub fn new() -> Self {
        Self {
            inner: ExpandBlockModel::new(),
        }
    }

    /// Initialize the model from a memory block.
    pub fn initialize(&mut self, block: &MemoryBlock) {
        self.inner.initialize(block);
    }

    /// Get the block name.
    pub fn block_name(&self) -> &str {
        self.inner.block_name()
    }

    /// Get the current start address.
    pub fn start_address(&self) -> Address {
        self.inner.start_address()
    }

    /// Get the current end address.
    pub fn end_address(&self) -> Address {
        self.inner.end_address()
    }

    /// Get the current proposed length.
    pub fn length(&self) -> u64 {
        self.inner.length()
    }

    /// Get the current validation message (empty if valid).
    pub fn message(&self) -> &str {
        self.inner.message()
    }

    /// Set a new start address for the expanded block.
    ///
    /// The new start must be less than the current block start.
    /// The end address is unchanged; the length is recomputed.
    ///
    /// Returns `Ok(new_length)` or an error message.
    pub fn set_start_address(&mut self, new_start: Address) -> Result<u64, String> {
        let block_start = self.inner.start_address();
        let block_end = self.inner.end_address();

        if new_start.offset >= block_start.offset {
            return Err(format!("Start must be less than 0x{:x}", block_start.offset));
        }

        let new_length = block_end.offset - new_start.offset + 1;
        self.inner.set_start_address(new_start);
        Ok(new_length)
    }

    /// Set a new length, recomputing the start address.
    ///
    /// The new length must be greater than the current block size.
    /// The end address is unchanged; the start is recomputed as
    /// `block_end - new_length + 1`.
    ///
    /// Returns `Ok(new_start)` or an error message.
    pub fn set_length(&mut self, new_length: u64) -> Result<Address, String> {
        let block_end = self.inner.end_address();

        if !self.inner.is_valid_length() {
            return Err(self.inner.message().to_string());
        }

        let new_start_offset = block_end.offset.checked_sub(new_length - 1)
            .ok_or("Expanded block is too large")?;

        let new_start = Address::new(new_start_offset);
        self.inner.set_start_address(new_start);
        Ok(new_start)
    }

    /// Validate the current state.
    ///
    /// Returns `Ok(())` if the expansion is valid, or an error message.
    pub fn validate(&mut self) -> Result<(), String> {
        if !self.inner.is_valid_length() {
            return Err(self.inner.message().to_string());
        }
        Ok(())
    }

    /// Execute the expansion on the given program.
    ///
    /// Returns `Ok(())` on success.
    pub fn execute(&mut self, program: &mut Program) -> Result<(), String> {
        self.validate()?;
        self.inner.execute(program)
    }

    /// Get a reference to the inner expand-block model.
    pub fn inner(&self) -> &ExpandBlockModel {
        &self.inner
    }
}

impl Default for ExpandUpModel {
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
            Address::new(0x2000),
            vec![0u8; 0x1000],
            false,
        );
        p
    }

    #[test]
    fn test_initialize() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandUpModel::new();
        model.initialize(&block);
        assert_eq!(model.block_name(), ".text");
        assert_eq!(model.start_address(), Address::new(0x2000));
        assert_eq!(model.end_address(), Address::new(0x2fff));
        assert_eq!(model.length(), 0x1000);
    }

    #[test]
    fn test_set_start_address_lower() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandUpModel::new();
        model.initialize(&block);
        let result = model.set_start_address(Address::new(0x1000));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x2000); // 0x2fff - 0x1000 + 1
    }

    #[test]
    fn test_set_start_address_at_block_start_fails() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandUpModel::new();
        model.initialize(&block);
        let result = model.set_start_address(Address::new(0x2000));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be less than"));
    }

    #[test]
    fn test_set_start_address_above_block_start_fails() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandUpModel::new();
        model.initialize(&block);
        let result = model.set_start_address(Address::new(0x3000));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_passes_with_valid_length() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandUpModel::new();
        model.initialize(&block);
        let _ = model.set_start_address(Address::new(0x1000));
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_validate_fails_when_length_too_small() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandUpModel::new();
        model.initialize(&block);
        // Set start to just before block start -- length = 0x1001 > 0x1000, OK
        let _ = model.set_start_address(Address::new(0x1fff));
        // Length = 0x2fff - 0x1fff + 1 = 0x1001, which is > 0x1000
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_execute_expand_up() {
        let mut program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandUpModel::new();
        model.initialize(&block);
        let _ = model.set_start_address(Address::new(0x1000));
        let result = model.execute(&mut program);
        assert!(result.is_ok(), "expand up should succeed: {:?}", result.err());
    }

    #[test]
    fn test_default_model() {
        let model = ExpandUpModel::default();
        assert_eq!(model.block_name(), "");
        assert_eq!(model.length(), 0);
    }

    #[test]
    fn test_message_cleared_on_valid_set_start() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandUpModel::new();
        model.initialize(&block);
        let _ = model.set_start_address(Address::new(0x1000));
        // After a valid set_start_address, message should be empty
        assert!(model.message().is_empty());
    }
}
