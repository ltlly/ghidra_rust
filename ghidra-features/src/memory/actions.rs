//! Memory map actions.
//!
//! Ported from Ghidra's memory plugin action classes.

use serde::{Deserialize, Serialize};

/// Memory actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryAction {
    /// Add a new memory block.
    AddBlock,
    /// Remove a memory block.
    RemoveBlock,
    /// Expand a memory block.
    ExpandBlock,
    /// Contract a memory block.
    ContractBlock,
    /// Split a memory block.
    SplitBlock,
    /// Merge memory blocks.
    MergeBlocks,
    /// Move a memory block.
    MoveBlock,
    /// Rebase the program.
    Rebase,
    /// Set block permissions (read/write/execute).
    SetPermissions,
}

impl MemoryAction {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::AddBlock => "Add Memory Block",
            Self::RemoveBlock => "Remove Memory Block",
            Self::ExpandBlock => "Expand Memory Block",
            Self::ContractBlock => "Contract Memory Block",
            Self::SplitBlock => "Split Memory Block",
            Self::MergeBlocks => "Merge Memory Blocks",
            Self::MoveBlock => "Move Memory Block",
            Self::Rebase => "Rebase Program",
            Self::SetPermissions => "Set Block Permissions",
        }
    }
}

/// Memory block permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl BlockPermissions {
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        Self { read, write, execute }
    }
    pub fn read_only() -> Self { Self { read: true, write: false, execute: false } }
    pub fn read_exec() -> Self { Self { read: true, write: false, execute: true } }
    pub fn read_write() -> Self { Self { read: true, write: true, execute: false } }
    pub fn all() -> Self { Self { read: true, write: true, execute: true } }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_action_display() {
        assert_eq!(MemoryAction::AddBlock.display_name(), "Add Memory Block");
        assert_eq!(MemoryAction::Rebase.display_name(), "Rebase Program");
    }

    #[test]
    fn test_block_permissions() {
        let ro = BlockPermissions::read_only();
        assert!(ro.read);
        assert!(!ro.write);
        assert!(!ro.execute);

        let rx = BlockPermissions::read_exec();
        assert!(rx.read);
        assert!(!rx.write);
        assert!(rx.execute);
    }
}
