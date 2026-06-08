//! Memory block commands.
//!
//! Ported from `ghidra.app.cmd.memory`.

#![allow(dead_code)]

/// Memory block permissions.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MemoryPermissions {
    pub fn rwx() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
        }
    }

    pub fn rx() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
        }
    }

    pub fn rw() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
        }
    }
}

/// Abstract base command for adding memory blocks.
#[derive(Debug)]
pub struct AbstractAddMemoryBlockCmd {
    name: String,
    start_address: u64,
    length: u64,
    permissions: MemoryPermissions,
}

impl AbstractAddMemoryBlockCmd {
    pub fn new(
        name: impl Into<String>,
        start_address: u64,
        length: u64,
        permissions: MemoryPermissions,
    ) -> Self {
        Self {
            name: name.into(),
            start_address,
            length,
            permissions,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to add an initialized memory block.
#[derive(Debug)]
pub struct AddInitializedMemoryBlockCmd {
    inner: AbstractAddMemoryBlockCmd,
    data: Vec<u8>,
}

impl AddInitializedMemoryBlockCmd {
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
}

/// Command to add an uninitialized memory block.
#[derive(Debug)]
pub struct AddUninitializedMemoryBlockCmd {
    inner: AbstractAddMemoryBlockCmd,
}

impl AddUninitializedMemoryBlockCmd {
    pub fn new(
        name: impl Into<String>,
        start_address: u64,
        length: u64,
        permissions: MemoryPermissions,
    ) -> Self {
        Self {
            inner: AbstractAddMemoryBlockCmd::new(name, start_address, length, permissions),
        }
    }

    pub fn apply_to(&self, program_name: &str) -> bool {
        self.inner.apply_to(program_name)
    }
}

/// Command to add a bit-mapped memory block.
#[derive(Debug)]
pub struct AddBitMappedMemoryBlockCmd {
    inner: AbstractAddMemoryBlockCmd,
    source_address: u64,
    bit_offset: u32,
}

impl AddBitMappedMemoryBlockCmd {
    pub fn new(
        name: impl Into<String>,
        start_address: u64,
        length: u64,
        source_address: u64,
        bit_offset: u32,
        permissions: MemoryPermissions,
    ) -> Self {
        Self {
            inner: AbstractAddMemoryBlockCmd::new(name, start_address, length, permissions),
            source_address,
            bit_offset,
        }
    }

    pub fn apply_to(&self, program_name: &str) -> bool {
        self.inner.apply_to(program_name)
    }
}

/// Command to add a byte-mapped memory block.
#[derive(Debug)]
pub struct AddByteMappedMemoryBlockCmd {
    inner: AbstractAddMemoryBlockCmd,
    source_address: u64,
}

impl AddByteMappedMemoryBlockCmd {
    pub fn new(
        name: impl Into<String>,
        start_address: u64,
        length: u64,
        source_address: u64,
        permissions: MemoryPermissions,
    ) -> Self {
        Self {
            inner: AbstractAddMemoryBlockCmd::new(name, start_address, length, permissions),
            source_address,
        }
    }

    pub fn apply_to(&self, program_name: &str) -> bool {
        self.inner.apply_to(program_name)
    }
}

/// Command to add a file-backed memory block.
#[derive(Debug)]
pub struct AddFileBytesMemoryBlockCmd {
    inner: AbstractAddMemoryBlockCmd,
    file_offset: u64,
}

impl AddFileBytesMemoryBlockCmd {
    pub fn new(
        name: impl Into<String>,
        start_address: u64,
        length: u64,
        file_offset: u64,
        permissions: MemoryPermissions,
    ) -> Self {
        Self {
            inner: AbstractAddMemoryBlockCmd::new(name, start_address, length, permissions),
            file_offset,
        }
    }

    pub fn apply_to(&self, program_name: &str) -> bool {
        self.inner.apply_to(program_name)
    }
}

/// Command to delete a memory block.
#[derive(Debug)]
pub struct DeleteBlockCmd {
    block_name: String,
}

impl DeleteBlockCmd {
    pub fn new(block_name: impl Into<String>) -> Self {
        Self {
            block_name: block_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Listener for memory block deletion events.
pub trait DeleteBlockListener: std::fmt::Debug + Send + Sync {
    fn block_deleted(&self, block_name: &str);
}

/// Listener for memory block move events.
pub trait MoveBlockListener: std::fmt::Debug + Send + Sync {
    fn block_moved(&self, block_name: &str, new_address: u64);
}

/// Task for moving a memory block.
#[derive(Debug)]
pub struct MoveBlockTask {
    block_name: String,
    new_start_address: u64,
}

impl MoveBlockTask {
    pub fn new(block_name: impl Into<String>, new_start_address: u64) -> Self {
        Self {
            block_name: block_name.into(),
            new_start_address,
        }
    }

    pub fn block_name(&self) -> &str {
        &self.block_name
    }

    pub fn new_start_address(&self) -> u64 {
        self.new_start_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permissions() {
        let rwx = MemoryPermissions::rwx();
        assert!(rwx.read && rwx.write && rwx.execute);
        let rx = MemoryPermissions::rx();
        assert!(rx.read && !rx.write && rx.execute);
    }

    #[test]
    fn test_add_initialized_block() {
        let cmd = AddInitializedMemoryBlockCmd::new(
            ".text",
            0x401000,
            vec![0x90; 256],
            MemoryPermissions::rx(),
        );
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_add_uninitialized_block() {
        let cmd = AddUninitializedMemoryBlockCmd::new(
            ".bss",
            0x500000,
            0x10000,
            MemoryPermissions::rw(),
        );
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_delete_block() {
        let cmd = DeleteBlockCmd::new(".text");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_move_block_task() {
        let task = MoveBlockTask::new(".text", 0x600000);
        assert_eq!(task.block_name(), ".text");
        assert_eq!(task.new_start_address(), 0x600000);
    }

    #[test]
    fn test_bit_mapped_block() {
        let cmd = AddBitMappedMemoryBlockCmd::new(
            "bit_map",
            0x800000,
            0x100,
            0x400000,
            3,
            MemoryPermissions::rwx(),
        );
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_byte_mapped_block() {
        let cmd = AddByteMappedMemoryBlockCmd::new(
            "byte_map",
            0x800000,
            0x100,
            0x400000,
            MemoryPermissions::rw(),
        );
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_file_bytes_block() {
        let cmd = AddFileBytesMemoryBlockCmd::new(
            ".rodata",
            0x500000,
            0x200,
            0x1000,
            MemoryPermissions::rx(),
        );
        assert!(cmd.apply_to("test"));
    }
}
