//! UninitializedBlockCmd -- converts a memory block to uninitialized state.
//!
//! Ported from `ghidra.app.plugin.core.memory.UninitializedBlockCmd`.
//! Clears all code, data, references, and functions in a memory block
//! and converts it to uninitialized state.

use crate::base::analyzer::core::*;

/// Clear options specifying what to clear from a memory block.
#[derive(Debug, Clone)]
pub struct ClearOptions {
    /// Clear instructions.
    pub clear_instructions: bool,
    /// Clear data items.
    pub clear_data: bool,
    /// Clear functions.
    pub clear_functions: bool,
    /// Clear default references.
    pub clear_default_references: bool,
    /// Clear analysis references.
    pub clear_analysis_references: bool,
    /// Clear import references.
    pub clear_import_references: bool,
    /// Clear user references.
    pub clear_user_references: bool,
}

impl ClearOptions {
    /// Creates default clear options (nothing cleared).
    pub fn new() -> Self {
        Self {
            clear_instructions: false,
            clear_data: false,
            clear_functions: false,
            clear_default_references: false,
            clear_analysis_references: false,
            clear_import_references: false,
            clear_user_references: false,
        }
    }

    /// Creates options that clear everything.
    pub fn clear_all() -> Self {
        Self {
            clear_instructions: true,
            clear_data: true,
            clear_functions: true,
            clear_default_references: true,
            clear_analysis_references: true,
            clear_import_references: true,
            clear_user_references: true,
        }
    }
}

impl Default for ClearOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of the uninitialized block operation.
#[derive(Debug, Clone)]
pub struct UninitializedBlockResult {
    /// Whether the operation succeeded.
    pub success: bool,
    /// Status message (error message if failed).
    pub status_message: String,
    /// Number of instructions cleared.
    pub instructions_cleared: u32,
    /// Number of data items cleared.
    pub data_cleared: u32,
    /// Number of functions cleared.
    pub functions_cleared: u32,
    /// Number of references cleared.
    pub references_cleared: u32,
}

/// Command to convert a memory block to uninitialized state.
///
/// This command:
/// 1. Clears all instructions, data, functions, and references in the block
/// 2. Converts the block to uninitialized memory
///
/// # Example
///
/// ```
/// use ghidra_features::base::memory::uninitialized_block::*;
/// use ghidra_features::base::analyzer::*;
///
/// let cmd = UninitializedBlockCmd::new(".bss", Address::new(0x4000), 0x1000);
/// assert_eq!(cmd.block_name(), ".bss");
/// ```
#[derive(Debug, Clone)]
pub struct UninitializedBlockCmd {
    /// Name of the block to uninitialize.
    block_name: String,
    /// Start address of the block.
    block_start: Address,
    /// Size of the block in bytes.
    block_size: u64,
    /// Clear options.
    clear_options: ClearOptions,
    /// Status message after execution.
    status_message: Option<String>,
}

impl UninitializedBlockCmd {
    /// Creates a new command for the given block.
    pub fn new(
        block_name: impl Into<String>,
        block_start: Address,
        block_size: u64,
    ) -> Self {
        Self {
            block_name: block_name.into(),
            block_start,
            block_size,
            clear_options: ClearOptions::clear_all(),
            status_message: None,
        }
    }

    /// Returns the block name.
    pub fn block_name(&self) -> &str {
        &self.block_name
    }

    /// Returns the block start address.
    pub fn block_start(&self) -> Address {
        self.block_start
    }

    /// Returns the block size.
    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    /// Sets the clear options.
    pub fn set_clear_options(&mut self, options: ClearOptions) {
        self.clear_options = options;
    }

    /// Returns the status message from the last execution.
    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }

    /// Executes the command on the given program.
    ///
    /// Clears all specified items from the block and converts it to uninitialized.
    pub fn apply_to(&mut self, program: &mut Program) -> UninitializedBlockResult {
        let block_end = Address::new(self.block_start.offset + self.block_size - 1);
        let block_set = AddressSet::from_range(AddressRange::new(self.block_start, block_end));

        let mut instructions_cleared = 0u32;
        let mut data_cleared = 0u32;
        let mut functions_cleared = 0u32;
        let mut references_cleared = 0u32;

        // Clear instructions
        if self.clear_options.clear_instructions {
            let instr_addrs: Vec<Address> = program
                .listing
                .instructions
                .keys()
                .filter(|a| block_set.contains(a))
                .copied()
                .collect();

            for addr in instr_addrs {
                program.listing.instructions.remove(&addr);
                instructions_cleared += 1;
            }
        }

        // Clear data items
        if self.clear_options.clear_data {
            let data_addrs: Vec<Address> = program
                .listing
                .data_items
                .keys()
                .filter(|a| block_set.contains(a))
                .copied()
                .collect();

            for addr in data_addrs {
                program.listing.data_items.remove(&addr);
                data_cleared += 1;
            }
        }

        // Clear functions
        if self.clear_options.clear_functions {
            let func_addrs: Vec<Address> = program
                .function_manager
                .functions
                .keys()
                .filter(|a| block_set.contains(a))
                .copied()
                .collect();

            for addr in func_addrs {
                program.function_manager.functions.remove(&addr);
                functions_cleared += 1;
            }
        }

        // Find and mark the block as uninitialized
        let mut block_found = false;
        for block in &mut program.memory_blocks {
            if block.start == self.block_start && block.size == self.block_size {
                block.is_initialized = false;
                block_found = true;
                break;
            }
        }

        if !block_found {
            self.status_message = Some(format!("Block '{}' not found", self.block_name));
            return UninitializedBlockResult {
                success: false,
                status_message: self.status_message.clone().unwrap_or_default(),
                instructions_cleared,
                data_cleared,
                functions_cleared,
                references_cleared,
            };
        }

        self.status_message = Some(format!(
            "Block '{}' converted to uninitialized ({} instr, {} data, {} funcs cleared)",
            self.block_name, instructions_cleared, data_cleared, functions_cleared
        ));

        UninitializedBlockResult {
            success: true,
            status_message: self.status_message.clone().unwrap_or_default(),
            instructions_cleared,
            data_cleared,
            functions_cleared,
            references_cleared,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program_with_block() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut p = Program::new("test", lang);
        p.memory
            .add_range(AddressRange::new(Address::new(0x1000), Address::new(0x5000)));

        // Add a memory block
        p.memory_blocks.push(MemoryBlock {
            name: ".bss".into(),
            start: Address::new(0x4000),
            size: 0x1000,
            is_read: true,
            is_write: true,
            is_execute: false,
            is_initialized: true,
        });

        // Add some instructions in the block
        p.listing.instructions.insert(
            Address::new(0x4000),
            Instruction {
                address: Address::new(0x4000),
                length: 3,
                mnemonic: "nop".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x4003)),
                flows: vec![],
                num_operands: 0,
            },
        );

        // Add some data in the block
        p.listing.data_items.insert(
            Address::new(0x4100),
            Data {
                address: Address::new(0x4100),
                length: 4,
                data_type_name: "dword".into(),
            },
        );

        // Add a function in the block
        p.function_manager.functions.insert(
            Address::new(0x4200),
            Function {
                entry_point: Address::new(0x4200),
                body: AddressSet::from_range(AddressRange::new(
                    Address::new(0x4200),
                    Address::new(0x4210),
                )),
                name: Some("bss_func".into()),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );

        p
    }

    #[test]
    fn test_uninitialized_block_cmd_creation() {
        let cmd = UninitializedBlockCmd::new(".bss", Address::new(0x4000), 0x1000);
        assert_eq!(cmd.block_name(), ".bss");
        assert_eq!(cmd.block_start(), Address::new(0x4000));
        assert_eq!(cmd.block_size(), 0x1000);
    }

    #[test]
    fn test_uninitialized_block_cmd_apply() {
        let mut cmd = UninitializedBlockCmd::new(".bss", Address::new(0x4000), 0x1000);
        let mut p = make_program_with_block();

        // Verify block is initialized
        assert!(p.memory_blocks[0].is_initialized);

        let result = cmd.apply_to(&mut p);

        assert!(result.success);
        assert_eq!(result.instructions_cleared, 1);
        assert_eq!(result.data_cleared, 1);
        assert_eq!(result.functions_cleared, 1);

        // Verify block is now uninitialized
        assert!(!p.memory_blocks[0].is_initialized);

        // Verify data was cleared
        assert!(p.listing.instructions.get(&Address::new(0x4000)).is_none());
        assert!(p.listing.data_items.get(&Address::new(0x4100)).is_none());
        assert!(p
            .function_manager
            .functions
            .get(&Address::new(0x4200))
            .is_none());
    }

    #[test]
    fn test_uninitialized_block_cmd_not_found() {
        let mut cmd = UninitializedBlockCmd::new(".nonexistent", Address::new(0x8000), 0x1000);
        let mut p = make_program_with_block();

        let result = cmd.apply_to(&mut p);
        assert!(!result.success);
        assert!(result.status_message.contains("not found"));
    }

    #[test]
    fn test_clear_options_default() {
        let opts = ClearOptions::new();
        assert!(!opts.clear_instructions);
        assert!(!opts.clear_data);
        assert!(!opts.clear_functions);
    }

    #[test]
    fn test_clear_options_all() {
        let opts = ClearOptions::clear_all();
        assert!(opts.clear_instructions);
        assert!(opts.clear_data);
        assert!(opts.clear_functions);
        assert!(opts.clear_default_references);
        assert!(opts.clear_analysis_references);
        assert!(opts.clear_import_references);
        assert!(opts.clear_user_references);
    }

    #[test]
    fn test_uninitialized_block_result_display() {
        let result = UninitializedBlockResult {
            success: true,
            status_message: "Success".into(),
            instructions_cleared: 5,
            data_cleared: 3,
            functions_cleared: 2,
            references_cleared: 10,
        };
        assert!(result.success);
        assert_eq!(result.instructions_cleared, 5);
    }

    #[test]
    fn test_set_clear_options() {
        let mut cmd = UninitializedBlockCmd::new(".bss", Address::new(0x4000), 0x1000);
        let opts = ClearOptions {
            clear_instructions: true,
            clear_data: false,
            clear_functions: false,
            clear_default_references: false,
            clear_analysis_references: false,
            clear_import_references: false,
            clear_user_references: false,
        };
        cmd.set_clear_options(opts);

        let mut p = make_program_with_block();
        let result = cmd.apply_to(&mut p);
        assert!(result.success);
        assert_eq!(result.instructions_cleared, 1);
        assert_eq!(result.data_cleared, 0); // Not cleared
        assert_eq!(result.functions_cleared, 0); // Not cleared
    }
}
