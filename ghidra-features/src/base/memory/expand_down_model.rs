//! Expand-down model -- validates and expands a block toward higher addresses.
//!
//! Ported from `ExpandBlockDownModel` in Ghidra's `ghidra.app.plugin.core.memory`.
//!
//! This model specializes [`ExpandBlockModel`] for the "expand down" direction:
//! the user provides a new end address (which must be greater than the current
//! block end), and the model recomputes the length accordingly.

use ghidra_core::addr::Address;
use ghidra_core::mem::MemoryBlock;
use ghidra_core::program::program::Program;

use super::expand_block_model::ExpandBlockModel;

// ============================================================================
// ExpandDownModel
// ============================================================================

/// Model for expanding a memory block toward higher addresses.
///
/// Ported from `ExpandBlockDownModel` in Java. This model:
/// - Accepts a new end address (must be > current block end)
/// - Recomputes length as `new_end - block_start + 1`
/// - Validates the new length is greater than the current block size
/// - Executes the expansion by creating a filler block and joining
///
/// # Usage
///
/// ```ignore
/// let mut model = ExpandDownModel::new();
/// model.initialize(&block);
/// model.set_end_address(Address::new(0x5000));
/// assert!(model.validate().is_ok());
/// model.execute(&mut program).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct ExpandDownModel {
    /// Inner expand-block model for common logic.
    inner: ExpandBlockModel,
}

impl ExpandDownModel {
    /// Create a new expand-down model.
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

    /// Set a new end address for the expanded block.
    ///
    /// The new end must be greater than the current block end.
    /// The start address is unchanged; the length is recomputed as
    /// `new_end - block_start + 1`.
    ///
    /// Returns `Ok(new_length)` or an error message.
    pub fn set_end_address(&mut self, new_end: Address) -> Result<u64, String> {
        let block_start = self.inner.start_address();
        let block_end = self.inner.end_address();

        if new_end.offset <= block_end.offset {
            return Err(format!(
                "End must be greater than 0x{:x}",
                block_end.offset
            ));
        }

        let new_length = new_end.offset - block_start.offset + 1;
        self.inner.set_end_address(new_end);
        Ok(new_length)
    }

    /// Set a new length, recomputing the end address.
    ///
    /// The new length must be greater than the current block size.
    /// The start address is unchanged; the end is recomputed as
    /// `block_start + new_length - 1`.
    ///
    /// Returns `Ok(new_end)` or an error message.
    pub fn set_length(&mut self, new_length: u64) -> Result<Address, String> {
        let block_start = self.inner.start_address();
        let block_end = self.inner.end_address();
        let current_size = block_end.offset - block_start.offset + 1;

        if new_length <= current_size {
            return Err(format!(
                "Block size must be greater than 0x{:x}",
                current_size
            ));
        }

        let new_end_offset = block_start
            .offset
            .checked_add(new_length - 1)
            .ok_or("Expanded block is too large")?;

        let new_end = Address::new(new_end_offset);
        self.inner.set_end_address(new_end);
        Ok(new_end)
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

impl Default for ExpandDownModel {
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
        let mut model = ExpandDownModel::new();
        model.initialize(&block);
        assert_eq!(model.block_name(), ".text");
        assert_eq!(model.start_address(), Address::new(0x2000));
        assert_eq!(model.end_address(), Address::new(0x2fff));
        assert_eq!(model.length(), 0x1000);
    }

    #[test]
    fn test_set_end_address_higher() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandDownModel::new();
        model.initialize(&block);
        let result = model.set_end_address(Address::new(0x4fff));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x3000); // 0x4fff - 0x2000 + 1
    }

    #[test]
    fn test_set_end_address_at_block_end_fails() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandDownModel::new();
        model.initialize(&block);
        let result = model.set_end_address(Address::new(0x2fff));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be greater than"));
    }

    #[test]
    fn test_set_end_address_below_block_end_fails() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandDownModel::new();
        model.initialize(&block);
        let result = model.set_end_address(Address::new(0x1000));
        assert!(result.is_err());
    }

    #[test]
    fn test_set_length_greater_than_current() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandDownModel::new();
        model.initialize(&block);
        let result = model.set_length(0x3000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Address::new(0x4fff));
    }

    #[test]
    fn test_set_length_equal_to_current_fails() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandDownModel::new();
        model.initialize(&block);
        let result = model.set_length(0x1000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be greater than"));
    }

    #[test]
    fn test_set_length_smaller_than_current_fails() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandDownModel::new();
        model.initialize(&block);
        let result = model.set_length(0x500);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_passes_with_valid_end() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandDownModel::new();
        model.initialize(&block);
        let _ = model.set_end_address(Address::new(0x4fff));
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_validate_fails_when_length_too_small() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandDownModel::new();
        model.initialize(&block);
        // Manually set a small length via inner model
        model.inner.set_length(0x500);
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_execute_expand_down() {
        let mut program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandDownModel::new();
        model.initialize(&block);
        let _ = model.set_end_address(Address::new(0x4fff));
        let result = model.execute(&mut program);
        assert!(
            result.is_ok(),
            "expand down should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_execute_fails_with_invalid_length() {
        let mut program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandDownModel::new();
        model.initialize(&block);
        model.inner.set_length(0x100); // smaller than current
        let result = model.execute(&mut program);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_model() {
        let model = ExpandDownModel::default();
        assert_eq!(model.block_name(), "");
        assert_eq!(model.length(), 0);
    }

    #[test]
    fn test_message_cleared_on_valid_set_end() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandDownModel::new();
        model.initialize(&block);
        let _ = model.set_end_address(Address::new(0x4fff));
        assert!(model.message().is_empty());
    }

    #[test]
    fn test_inner_model_accessible() {
        let program = make_program_with_block();
        let block = program.memory.get_block_by_name(".text").unwrap().clone();
        let mut model = ExpandDownModel::new();
        model.initialize(&block);
        assert_eq!(model.inner().block_name(), ".text");
    }
}
