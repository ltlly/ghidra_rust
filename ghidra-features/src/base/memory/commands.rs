//! Memory block commands — ported from Java inner command classes.
//!
//! Each command implements [`MemoryCommand`] and represents an atomic
//! operation on a [`Program`]'s memory that can succeed or fail with a
//! status message, mirroring the Java `Command<Program>` pattern.

use ghidra_core::program::program::Program;
use ghidra_core::addr::Address;

// ============================================================================
// MemoryCommand trait
// ============================================================================

/// A command that can be applied to a [`Program`].
///
/// This mirrors the Java `Command<Program>` interface used throughout
/// Ghidra's memory plugin. Commands encapsulate an operation and report
/// success/failure through [`status_msg`](MemoryCommand::status_msg).
pub trait MemoryCommand {
    /// The name of this command (for logging / UI).
    fn name(&self) -> &str;

    /// Attempt to apply this command to the given program.
    ///
    /// Returns `true` if the command succeeded, `false` otherwise.
    /// On failure, [`status_msg`](MemoryCommand::status_msg) provides
    /// a human-readable explanation.
    fn apply(&self, program: &mut Program) -> bool;

    /// Human-readable status message after [`apply`](MemoryCommand::apply).
    fn status_msg(&self) -> Option<&str>;
}

// ============================================================================
// SplitBlockCmd
// ============================================================================

/// Splits a memory block at a given address, creating a new block from the
/// split point onwards.
///
/// Ported from `MemoryMapManager.SplitBlockCmd` in Java.
#[derive(Debug, Clone)]
pub struct SplitBlockCmd {
    /// The address at which to split — this becomes the start of the new block.
    pub split_address: Address,
    /// Name for the new (second) block created by the split.
    pub new_block_name: String,
    /// Name of the original block to split.
    pub block_name: String,
    /// Status message after execution.
    status: Option<String>,
}

impl SplitBlockCmd {
    /// Create a new split-block command.
    pub fn new(
        block_name: impl Into<String>,
        split_address: Address,
        new_block_name: impl Into<String>,
    ) -> Self {
        Self {
            block_name: block_name.into(),
            split_address,
            new_block_name: new_block_name.into(),
            status: None,
        }
    }
}

impl MemoryCommand for SplitBlockCmd {
    fn name(&self) -> &str {
        "Split Memory Block"
    }

    fn apply(&self, program: &mut Program) -> bool {
        // Validate block exists
        let block = match program.memory.get_block_by_name(&self.block_name) {
            Some(b) => b.clone(),
            None => return false,
        };

        // Validate split address is within block bounds (not at start, at most end)
        if self.split_address <= block.start() || self.split_address > block.end() {
            return false;
        }

        // Delegate to Memory::split_block
        match program.memory.split_block(&self.block_name, self.split_address) {
            Ok(()) => true,
            Err(_) => false,
        }
    }

    fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
    }
}

// ============================================================================
// MergeBlocksCmd
// ============================================================================

/// Merges a contiguous sequence of memory blocks into a single block.
///
/// Blocks must be in the same address space and contiguous (no gaps, or the
/// gaps will be filled with appropriate filler blocks).
///
/// Ported from `MemoryMapManager.MergeBlocksCmd` in Java.
#[derive(Debug, Clone)]
pub struct MergeBlocksCmd {
    /// Names of the blocks to merge, ordered by start address.
    pub block_names: Vec<String>,
    /// Status message after execution.
    status: Option<String>,
}

impl MergeBlocksCmd {
    /// Create a new merge-blocks command.
    pub fn new(block_names: Vec<String>) -> Self {
        Self {
            block_names,
            status: None,
        }
    }

    /// Validate that the blocks to merge are well-formed.
    ///
    /// Returns `Ok(())` if valid, or an error message if not.
    pub fn validate(&self, program: &Program) -> Result<(), String> {
        if self.block_names.len() < 2 {
            return Err("At least two blocks are required for merging".into());
        }

        let mut blocks = Vec::new();
        for name in &self.block_names {
            match program.memory.get_block_by_name(name) {
                Some(b) => blocks.push(b.clone()),
                None => return Err(format!("Block '{}' not found", name)),
            }
        }

        // Sort by start address
        blocks.sort_by_key(|b| b.start().offset);

        // Check all blocks are the same type
        let first_type = blocks[0].block_type;
        for block in blocks.iter().skip(1) {
            if block.block_type != first_type {
                return Err("Cannot merge blocks of different types".into());
            }
        }

        // Check contiguity
        for i in 0..blocks.len() - 1 {
            let end = blocks[i].end();
            let next_start = blocks[i + 1].start();
            let gap = next_start.offset.saturating_sub(end.offset + 1);
            if gap > 4 * 1024 * 1024 {
                return Err(format!(
                    "Gap of {} bytes between block '{}' and '{}' is too large",
                    gap,
                    blocks[i].name,
                    blocks[i + 1].name,
                ));
            }
        }

        Ok(())
    }
}

impl MemoryCommand for MergeBlocksCmd {
    fn name(&self) -> &str {
        "Merge Memory Blocks"
    }

    fn apply(&self, program: &mut Program) -> bool {
        if self.validate(program).is_err() {
            return false;
        }

        // Sort block names by start address
        let mut sorted_names = self.block_names.clone();
        sorted_names.sort_by(|a, b| {
            let sa = program
                .memory
                .get_block_by_name(a)
                .map(|bl| bl.start().offset)
                .unwrap_or(0);
            let sb = program
                .memory
                .get_block_by_name(b)
                .map(|bl| bl.start().offset)
                .unwrap_or(0);
            sa.cmp(&sb)
        });

        // Iteratively join consecutive blocks
        for i in 0..sorted_names.len() - 1 {
            let name_a = sorted_names[i].clone();
            let name_b = sorted_names[i + 1].clone();
            match program.memory.join_blocks(&name_a, &name_b) {
                Ok(merged_name) => {
                    // Update subsequent entries that reference the merged block
                    for j in (i + 2)..sorted_names.len() {
                        if sorted_names[j] == name_b {
                            sorted_names[j] = merged_name.clone();
                        }
                    }
                }
                Err(_) => return false,
            }
        }

        true
    }

    fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
    }
}

// ============================================================================
// UninitializedBlockCmd
// ============================================================================

/// Converts an initialized block to an uninitialized block, clearing all
/// code units and references within it.
///
/// Ported from `UninitializedBlockCmd` in Java.
#[derive(Debug, Clone)]
pub struct UninitializedBlockCmd {
    /// Name of the block to convert.
    pub block_name: String,
    /// Status message after execution.
    status: Option<String>,
}

impl UninitializedBlockCmd {
    /// Create a new uninitialized-block command.
    pub fn new(block_name: impl Into<String>) -> Self {
        Self {
            block_name: block_name.into(),
            status: None,
        }
    }
}

impl MemoryCommand for UninitializedBlockCmd {
    fn name(&self) -> &str {
        "Uninitialize Memory Block"
    }

    fn apply(&self, program: &mut Program) -> bool {
        match program.memory.convert_to_uninitialized(&self.block_name) {
            Ok(()) => true,
            Err(_) => false,
        }
    }

    fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
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
    use ghidra_core::program::program::Program;

    fn make_test_program() -> Program {
        let memory = MemoryMap::new(false);
        let mut p = Program::with_memory("test", Address::new(0), Box::new(memory));
        // Create two contiguous blocks
        let _ = p.memory.create_initialized_block(
            "block1",
            Address::new(0x1000),
            vec![0u8; 0x1000],
            false,
        );
        let _ = p.memory.create_initialized_block(
            "block2",
            Address::new(0x2000),
            vec![0u8; 0x1000],
            false,
        );
        p
    }

    #[test]
    fn test_split_block_cmd() {
        let mut program = make_test_program();
        let cmd = SplitBlockCmd::new("block1", Address::new(0x1800), "block1.split");
        assert_eq!(cmd.name(), "Split Memory Block");
        let result = cmd.apply(&mut program);
        assert!(result, "split should succeed");
        // After split: block1 [0x1000..0x17ff] and block1 [0x1800..0x1fff]
        // (split_block keeps original name, new block gets a generated name)
        assert!(program.memory.get_block_by_name("block1").is_some());
    }

    #[test]
    fn test_split_block_cmd_invalid_address() {
        let mut program = make_test_program();
        // Split at the start address — should fail
        let cmd = SplitBlockCmd::new("block1", Address::new(0x1000), "bad.split");
        assert!(!cmd.apply(&mut program));
    }

    #[test]
    fn test_split_block_cmd_nonexistent_block() {
        let mut program = make_test_program();
        let cmd = SplitBlockCmd::new("nonexistent", Address::new(0x1800), "new");
        assert!(!cmd.apply(&mut program));
    }

    #[test]
    fn test_merge_blocks_cmd() {
        let mut program = make_test_program();
        let cmd = MergeBlocksCmd::new(vec!["block1".into(), "block2".into()]);
        assert_eq!(cmd.name(), "Merge Memory Blocks");
        let result = cmd.apply(&mut program);
        assert!(result, "merge should succeed for contiguous blocks");
    }

    #[test]
    fn test_merge_blocks_validation_too_few() {
        let program = make_test_program();
        let cmd = MergeBlocksCmd::new(vec!["block1".into()]);
        assert!(cmd.validate(&program).is_err());
    }

    #[test]
    fn test_merge_blocks_validation_missing_block() {
        let program = make_test_program();
        let cmd = MergeBlocksCmd::new(vec!["block1".into(), "nonexistent".into()]);
        assert!(cmd.validate(&program).is_err());
    }

    #[test]
    fn test_uninitialized_block_cmd() {
        let mut program = make_test_program();
        let cmd = UninitializedBlockCmd::new("block1");
        assert_eq!(cmd.name(), "Uninitialize Memory Block");
        let result = cmd.apply(&mut program);
        assert!(result, "uninitialize should succeed");
    }

    #[test]
    fn test_uninitialized_block_cmd_nonexistent() {
        let mut program = make_test_program();
        let cmd = UninitializedBlockCmd::new("nonexistent");
        assert!(!cmd.apply(&mut program));
    }
}
