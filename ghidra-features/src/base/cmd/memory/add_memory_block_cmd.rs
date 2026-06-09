//! Command to add a memory block.
//!
//! Ported from `ghidra.app.cmd.memory.AddMemoryBlockCmd`.

#![allow(dead_code)]

use super::{AbstractAddMemoryBlockCmd, MemoryPermissions};

/// Command to add an initialized memory block.
#[derive(Debug)]
pub struct AddMemoryBlockCmd {
    inner: AbstractAddMemoryBlockCmd,
    data: Vec<u8>,
}

impl AddMemoryBlockCmd {
    pub fn new(
        name: impl Into<String>,
        start_address: u64,
        data: Vec<u8>,
        permissions: MemoryPermissions,
    ) -> Self {
        let len = data.len() as u64;
        Self {
            inner: AbstractAddMemoryBlockCmd::new(name, start_address, len, permissions),
            data,
        }
    }

    pub fn apply_to(&self, program_name: &str) -> bool {
        self.inner.apply_to(program_name)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_memory_block() {
        let cmd = AddMemoryBlockCmd::new(
            ".text",
            0x401000,
            vec![0x90; 256],
            MemoryPermissions::rx(),
        );
        assert!(cmd.apply_to("test"));
        assert_eq!(cmd.data().len(), 256);
    }
}
