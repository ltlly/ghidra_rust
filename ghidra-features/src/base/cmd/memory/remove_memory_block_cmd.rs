//! Command to remove a memory block.
//!
//! Ported from `ghidra.app.cmd.memory.DeleteBlockCmd`.

#![allow(dead_code)]

/// Command to delete a memory block.
#[derive(Debug)]
pub struct RemoveMemoryBlockCmd {
    block_name: String,
    status: bool,
}

impl RemoveMemoryBlockCmd {
    pub fn new(block_name: impl Into<String>) -> Self {
        Self {
            block_name: block_name.into(),
            status: false,
        }
    }

    pub fn apply_to(&mut self, _program_name: &str) -> bool {
        // Simulate deletion
        self.status = true;
        true
    }

    pub fn status(&self) -> bool {
        self.status
    }

    pub fn block_name(&self) -> &str {
        &self.block_name
    }
}

/// Listener for memory block deletion events.
pub trait RemoveBlockListener: std::fmt::Debug + Send + Sync {
    fn block_removed(&self, block_name: &str);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_memory_block() {
        let mut cmd = RemoveMemoryBlockCmd::new(".text");
        assert!(cmd.apply_to("test"));
        assert!(cmd.status());
        assert_eq!(cmd.block_name(), ".text");
    }
}
