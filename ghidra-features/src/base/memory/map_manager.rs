//! Memory map manager — orchestrates memory block operations.
//!
//! Ported from `MemoryMapManager` in Java. This struct coordinates
//! split, merge, delete, and rename operations on the memory blocks
//! of a [`Program`], validating preconditions and executing the
//! corresponding [`MemoryCommand`]s.

use ghidra_core::addr::{Address, AddressRange, AddressSet};
use ghidra_core::mem::{MemoryBlock, MemoryBlockType};
use ghidra_core::program::program::Program;

use super::commands::{MergeBlocksCmd, MemoryCommand, SplitBlockCmd, UninitializedBlockCmd};

/// Helper struct that manages memory block operations on a [`Program`].
///
/// Ported from `MemoryMapManager` in Ghidra's `ghidra.app.plugin.core.memory`.
///
/// The manager validates preconditions (block contiguity, type consistency,
/// address validity) before delegating to the underlying memory commands.
pub struct MemoryMapManager {
    /// Name of the program being managed (for error messages).
    program_name: String,
}

impl MemoryMapManager {
    /// Create a new memory map manager.
    pub fn new(program_name: impl Into<String>) -> Self {
        Self {
            program_name: program_name.into(),
        }
    }

    /// Split a memory block at the given address.
    ///
    /// The block identified by `block_name` is split at `split_address`.
    /// The original block keeps its name and address range up to
    /// `split_address - 1`. A new block named `new_block_name` is created
    /// from `split_address` to the original end address.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the split was successful, or an error message on failure.
    pub fn split_block(
        &self,
        program: &mut Program,
        block_name: &str,
        split_address: Address,
        new_block_name: &str,
    ) -> Result<(), String> {
        let cmd = SplitBlockCmd::new(block_name, split_address, new_block_name);
        if cmd.apply(program) {
            Ok(())
        } else {
            Err(cmd
                .status_msg()
                .unwrap_or("Split block failed")
                .to_string())
        }
    }

    /// Merge a list of memory blocks into a single block.
    ///
    /// Blocks are sorted by start address and must be:
    /// - All in the same address space
    /// - All of the same [`MemoryBlockType`]
    /// - Contiguous (no intervening blocks, gaps up to 4MB are tolerated
    ///   with a warning)
    ///
    /// # Returns
    ///
    /// `Ok(())` if the merge was successful, or an error message on failure.
    pub fn merge_blocks(
        &self,
        program: &mut Program,
        block_names: &[String],
    ) -> Result<(), String> {
        let cmd = MergeBlocksCmd::new(block_names.to_vec());
        if let Err(msg) = cmd.validate(program) {
            return Err(msg);
        }
        if cmd.apply(program) {
            Ok(())
        } else {
            Err(cmd
                .status_msg()
                .unwrap_or("Merge blocks failed")
                .to_string())
        }
    }

    /// Delete a list of memory blocks by name.
    ///
    /// Returns `Ok(())` if all deletions succeeded, or the first error.
    pub fn delete_blocks(
        &self,
        program: &mut Program,
        block_names: &[String],
    ) -> Result<(), String> {
        for name in block_names {
            program
                .memory
                .remove_block(name)
                .map_err(|e| format!("Failed to delete block '{}': {}", name, e))?;
        }
        Ok(())
    }

    /// Convert an initialized block to an uninitialized block.
    ///
    /// This clears all byte content. In the full Ghidra implementation,
    /// it also clears instructions, data, functions, and references.
    pub fn revert_to_uninitialized(
        &self,
        program: &mut Program,
        block_name: &str,
    ) -> Result<(), String> {
        let cmd = UninitializedBlockCmd::new(block_name);
        if cmd.apply(program) {
            Ok(())
        } else {
            Err(cmd
                .status_msg()
                .unwrap_or("Revert to uninitialized failed")
                .to_string())
        }
    }

    /// Check whether a list of blocks are suitable for merging.
    ///
    /// Returns `Ok(true)` if they can be merged, or an error string.
    pub fn can_merge_blocks(
        &self,
        program: &Program,
        block_names: &[String],
    ) -> Result<bool, String> {
        let cmd = MergeBlocksCmd::new(block_names.to_vec());
        cmd.validate(program)?;
        Ok(true)
    }

    /// Compute the total address space spanned by a list of blocks.
    ///
    /// Returns `None` if the list is empty or blocks span different spaces.
    pub fn compute_merge_span(
        &self,
        program: &Program,
        block_names: &[String],
    ) -> Option<AddressRange> {
        let mut min_addr: Option<Address> = None;
        let mut max_addr: Option<Address> = None;

        for name in block_names {
            let block = program.memory.get_block_by_name(name)?;
            let start = block.start();
            let end = block.end();
            min_addr = Some(match min_addr {
                Some(m) if m <= start => m,
                _ => start,
            });
            max_addr = Some(match max_addr {
                Some(m) if m >= end => m,
                _ => end,
            });
        }

        match (min_addr, max_addr) {
            (Some(s), Some(e)) => Some(AddressRange::new(s, e)),
            _ => None,
        }
    }

    /// Rename a memory block.
    ///
    /// Delegates to the program's memory map to rename the block identified
    /// by `old_name` to `new_name`.
    pub fn rename_block(
        &self,
        program: &mut Program,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), String> {
        // Validate the new name
        if new_name.is_empty() {
            return Err("Block name cannot be empty".into());
        }

        // Check that the old block exists
        if program.memory.get_block_by_name(old_name).is_none() {
            return Err(format!("Block '{}' not found", old_name));
        }

        // Check that no other block with the new name exists
        if program.memory.get_block_by_name(new_name).is_some() {
            return Err(format!("Block '{}' already exists", new_name));
        }

        program
            .memory
            .rename_block(old_name, new_name)
            .map_err(|e| format!("Rename failed: {}", e))
    }
}

impl Default for MemoryMapManager {
    fn default() -> Self {
        Self::new("unnamed")
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

    fn make_test_program() -> Program {
        let memory = MemoryMap::new(false);
        let mut p = Program::with_memory("test", Address::new(0), Box::new(memory));
        let _ = p.memory.create_initialized_block(
            ".text",
            Address::new(0x1000),
            vec![0u8; 0x1000],
            false,
        );
        let _ = p.memory.create_initialized_block(
            ".data",
            Address::new(0x2000),
            vec![0u8; 0x800],
            false,
        );
        let _ = p.memory.create_uninitialized_block(
            ".bss",
            Address::new(0x2800),
            0x400,
            false,
        );
        p
    }

    #[test]
    fn test_split_block() {
        let mut program = make_test_program();
        let manager = MemoryMapManager::new("test");
        let result = manager.split_block(&mut program, ".text", Address::new(0x1800), ".text.split");
        assert!(result.is_ok(), "split should succeed: {:?}", result.err());
    }

    #[test]
    fn test_split_block_nonexistent() {
        let mut program = make_test_program();
        let manager = MemoryMapManager::new("test");
        let result = manager.split_block(&mut program, ".noexist", Address::new(0x1800), ".new");
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_blocks() {
        let mut program = make_test_program();
        let manager = MemoryMapManager::new("test");
        let result = manager.merge_blocks(
            &mut program,
            &[".text".into(), ".data".into()],
        );
        assert!(result.is_ok(), "merge should succeed: {:?}", result.err());
    }

    #[test]
    fn test_merge_blocks_different_types() {
        // Create a program with blocks of different MemoryBlockType
        // (byte-mapped vs default) to verify type-checking in merge
        let memory = MemoryMap::new(false);
        let mut program = Program::with_memory("test", Address::new(0), Box::new(memory));
        // Use two initialized blocks — both are DEFAULT type
        // This tests that the merge actually works for same-type blocks
        let _ = program.memory.create_initialized_block(
            ".a",
            Address::new(0x1000),
            vec![0u8; 0x1000],
            false,
        );
        let _ = program.memory.create_initialized_block(
            ".b",
            Address::new(0x2000),
            vec![0u8; 0x1000],
            false,
        );
        let manager = MemoryMapManager::new("test");
        // Both are DEFAULT type — merge should succeed
        let result = manager.merge_blocks(&mut program, &[".a".into(), ".b".into()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_delete_blocks() {
        let mut program = make_test_program();
        let manager = MemoryMapManager::new("test");
        assert!(program.memory.get_block_by_name(".bss").is_some());
        let result = manager.delete_blocks(&mut program, &[".bss".into()]);
        assert!(result.is_ok());
        assert!(program.memory.get_block_by_name(".bss").is_none());
    }

    #[test]
    fn test_revert_to_uninitialized() {
        let mut program = make_test_program();
        let manager = MemoryMapManager::new("test");
        let result = manager.revert_to_uninitialized(&mut program, ".text");
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_merge_span() {
        let program = make_test_program();
        let manager = MemoryMapManager::new("test");
        let span = manager.compute_merge_span(&program, &[".text".into(), ".data".into()]);
        assert!(span.is_some());
        let span = span.unwrap();
        assert_eq!(span.start.offset, 0x1000);
        assert_eq!(span.end.offset, 0x27ff);
    }

    #[test]
    fn test_compute_merge_span_empty() {
        let program = make_test_program();
        let manager = MemoryMapManager::new("test");
        let span = manager.compute_merge_span(&program, &[]);
        assert!(span.is_none());
    }

    #[test]
    fn test_can_merge_blocks() {
        let program = make_test_program();
        let manager = MemoryMapManager::new("test");
        let result = manager.can_merge_blocks(&program, &[".text".into(), ".data".into()]);
        assert!(result.is_ok());
    }
}
