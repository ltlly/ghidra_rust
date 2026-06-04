//! Relocation fixup handlers for binary rebasing.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.reloc` package.
//!
//! Provides handlers that fix up relocations when a binary is loaded at
//! a different base address than its preferred address. The main types are:
//!
//! - [`RelocationFixupHandler`] -- Trait for relocation fixup implementations.
//! - [`GenericRelocationHandler`] -- Handles generic reference-based relocations.
//! - [`Pe32RelocationHandler`] -- Handles PE 32-bit relocations.
//! - [`Pe64RelocationHandler`] -- Handles PE 64-bit relocations.
//! - [`ElfRelocationHandler`] -- Handles ELF relocations.
//!
//! # Architecture
//!
//! Each relocation has:
//! - An address where the fixup is applied.
//! - A type-specific value to adjust.
//! - The old and new image base addresses.
//!
//! The fixup handler reads the current value at the relocation address,
//! adjusts it by the base address difference, and writes it back.

use std::collections::HashMap;

/// Represents a single relocation entry.
///
/// Corresponds to `ghidra.program.model.reloc.Relocation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    /// The address where this relocation applies.
    pub address: u64,
    /// The relocation type (format-specific).
    pub reloc_type: RelocationType,
    /// The symbol name associated with this relocation (if any).
    pub symbol_name: Option<String>,
    /// The original value at the relocation address.
    pub value: u64,
}

/// Relocation type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocationType {
    /// Generic 32-bit relocation.
    Generic32,
    /// Generic 64-bit relocation.
    Generic64,
    /// PE 32-bit image base relocation.
    Pe32,
    /// PE 64-bit image base relocation.
    Pe64,
    /// ELF absolute relocation.
    ElfAbsolute,
    /// ELF relative relocation.
    ElfRelative,
    /// ELF 32-bit relocation.
    Elf32(u32),
    /// ELF 64-bit relocation.
    Elf64(u32),
    /// Format-specific relocation with a custom type ID.
    Custom(u32),
}

/// The result of processing a relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationResult {
    /// Relocation was applied successfully.
    Applied,
    /// Relocation was skipped (not applicable).
    Skipped,
    /// Relocation failed.
    Failed,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Trait for relocation fixup handler implementations.
///
/// Each handler is responsible for processing relocations of a specific
/// format (PE, ELF, etc.) and bit width.
///
/// Ported from `ghidra.app.plugin.core.reloc.RelocationFixupHandler`.
pub trait RelocationFixupHandler: Send + Sync {
    /// Process a single relocation.
    ///
    /// # Arguments
    ///
    /// * `memory` - Mutable reference to the memory image.
    /// * `relocation` - The relocation to process.
    /// * `old_image_base` - The original image base address.
    /// * `new_image_base` - The new image base address.
    ///
    /// # Returns
    ///
    /// `RelocationResult` indicating the outcome.
    fn process_relocation(
        &self,
        memory: &mut MemoryImage,
        relocation: &Relocation,
        old_image_base: u64,
        new_image_base: u64,
    ) -> RelocationResult;

    /// Whether this handler can process relocations for the given format.
    fn handles_format(&self, format: &str) -> bool;

    /// The name of this handler.
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Memory image (simplified for relocation processing)
// ---------------------------------------------------------------------------

/// Simplified memory image for relocation processing.
///
/// Provides read/write access to byte data at specific addresses.
/// In Ghidra, this would be backed by the program's `Memory` interface.
#[derive(Debug, Clone)]
pub struct MemoryImage {
    /// Address -> byte data mapping.
    ///
    /// Addresses are stored as base + offset for simplicity.
    data: HashMap<u64, u8>,
}

impl MemoryImage {
    /// Create a new empty memory image.
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    /// Create a memory image from a byte slice at a given base address.
    pub fn from_bytes(base_addr: u64, bytes: &[u8]) -> Self {
        let mut data = HashMap::new();
        for (i, &b) in bytes.iter().enumerate() {
            data.insert(base_addr + i as u64, b);
        }
        Self { data }
    }

    /// Read a single byte at the given address.
    pub fn get_byte(&self, addr: u64) -> Option<u8> {
        self.data.get(&addr).copied()
    }

    /// Write a single byte at the given address.
    pub fn set_byte(&mut self, addr: u64, value: u8) {
        self.data.insert(addr, value);
    }

    /// Read a 32-bit little-endian integer at the given address.
    pub fn get_u32_le(&self, addr: u64) -> Option<u32> {
        let b0 = self.get_byte(addr)?;
        let b1 = self.get_byte(addr + 1)?;
        let b2 = self.get_byte(addr + 2)?;
        let b3 = self.get_byte(addr + 3)?;
        Some(u32::from_le_bytes([b0, b1, b2, b3]))
    }

    /// Write a 32-bit little-endian integer at the given address.
    pub fn set_u32_le(&mut self, addr: u64, value: u32) {
        let bytes = value.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            self.set_byte(addr + i as u64, b);
        }
    }

    /// Read a 64-bit little-endian integer at the given address.
    pub fn get_u64_le(&self, addr: u64) -> Option<u64> {
        let b0 = self.get_byte(addr)?;
        let b1 = self.get_byte(addr + 1)?;
        let b2 = self.get_byte(addr + 2)?;
        let b3 = self.get_byte(addr + 3)?;
        let b4 = self.get_byte(addr + 4)?;
        let b5 = self.get_byte(addr + 5)?;
        let b6 = self.get_byte(addr + 6)?;
        let b7 = self.get_byte(addr + 7)?;
        Some(u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]))
    }

    /// Write a 64-bit little-endian integer at the given address.
    pub fn set_u64_le(&mut self, addr: u64, value: u64) {
        let bytes = value.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            self.set_byte(addr + i as u64, b);
        }
    }

    /// Get the number of bytes in the memory image.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the memory image is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for MemoryImage {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Generic relocation handler
// ---------------------------------------------------------------------------

/// Handles generic reference-based relocations.
///
/// Ported from `GenericRefernenceBaseRelocationFixupHandler`.
pub struct GenericRelocationHandler;

impl GenericRelocationHandler {
    pub fn new() -> Self {
        Self
    }
}

impl RelocationFixupHandler for GenericRelocationHandler {
    fn process_relocation(
        &self,
        memory: &mut MemoryImage,
        relocation: &Relocation,
        old_image_base: u64,
        new_image_base: u64,
    ) -> RelocationResult {
        match relocation.reloc_type {
            RelocationType::Generic32 => {
                process_32bit_relocation(memory, relocation, old_image_base, new_image_base)
            }
            RelocationType::Generic64 => {
                process_64bit_relocation(memory, relocation, old_image_base, new_image_base)
            }
            _ => RelocationResult::Skipped,
        }
    }

    fn handles_format(&self, _format: &str) -> bool {
        true // Generic handler accepts all formats.
    }

    fn name(&self) -> &str {
        "Generic Relocation Handler"
    }
}

// ---------------------------------------------------------------------------
// PE relocation handlers
// ---------------------------------------------------------------------------

/// Handles PE 32-bit relocations.
///
/// Ported from `Pe32RelocationFixupHandler`.
pub struct Pe32RelocationHandler;

impl Pe32RelocationHandler {
    pub fn new() -> Self {
        Self
    }
}

impl RelocationFixupHandler for Pe32RelocationHandler {
    fn process_relocation(
        &self,
        memory: &mut MemoryImage,
        relocation: &Relocation,
        old_image_base: u64,
        new_image_base: u64,
    ) -> RelocationResult {
        process_32bit_relocation(memory, relocation, old_image_base, new_image_base)
    }

    fn handles_format(&self, format: &str) -> bool {
        format == "PE"
    }

    fn name(&self) -> &str {
        "PE 32-bit Relocation Handler"
    }
}

/// Handles PE 64-bit relocations.
///
/// Ported from `Pe64RelocationFixupHandler`.
pub struct Pe64RelocationHandler;

impl Pe64RelocationHandler {
    pub fn new() -> Self {
        Self
    }
}

impl RelocationFixupHandler for Pe64RelocationHandler {
    fn process_relocation(
        &self,
        memory: &mut MemoryImage,
        relocation: &Relocation,
        old_image_base: u64,
        new_image_base: u64,
    ) -> RelocationResult {
        process_64bit_relocation(memory, relocation, old_image_base, new_image_base)
    }

    fn handles_format(&self, format: &str) -> bool {
        format == "PE"
    }

    fn name(&self) -> &str {
        "PE 64-bit Relocation Handler"
    }
}

// ---------------------------------------------------------------------------
// ELF relocation handler
// ---------------------------------------------------------------------------

/// Handles ELF-format relocations.
///
/// Ported from `ElfRelocationFixupHandler`. This handler manages
/// ELF-specific relocation types, dispatching to appropriate fixup logic
/// based on the relocation type ID.
pub struct ElfRelocationHandler {
    /// Map of relocation type IDs to type names.
    type_map: HashMap<u32, String>,
}

impl ElfRelocationHandler {
    /// Create a new ELF relocation handler with no registered types.
    pub fn new() -> Self {
        Self {
            type_map: HashMap::new(),
        }
    }

    /// Register an ELF relocation type.
    pub fn register_type(&mut self, type_id: u32, name: impl Into<String>) {
        self.type_map.insert(type_id, name.into());
    }

    /// Get the name of a relocation type, if registered.
    pub fn get_type_name(&self, type_id: u32) -> Option<&str> {
        self.type_map.get(&type_id).map(|s| s.as_str())
    }
}

impl Default for ElfRelocationHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl RelocationFixupHandler for ElfRelocationHandler {
    fn process_relocation(
        &self,
        memory: &mut MemoryImage,
        relocation: &Relocation,
        old_image_base: u64,
        new_image_base: u64,
    ) -> RelocationResult {
        match relocation.reloc_type {
            RelocationType::ElfAbsolute | RelocationType::Elf32(_) => {
                process_32bit_relocation(memory, relocation, old_image_base, new_image_base)
            }
            RelocationType::ElfRelative | RelocationType::Elf64(_) => {
                process_64bit_relocation(memory, relocation, old_image_base, new_image_base)
            }
            _ => RelocationResult::Skipped,
        }
    }

    fn handles_format(&self, format: &str) -> bool {
        format == "ELF"
    }

    fn name(&self) -> &str {
        "ELF Relocation Handler"
    }
}

// ---------------------------------------------------------------------------
// Relocation processing helpers
// ---------------------------------------------------------------------------

/// Process a 32-bit relocation.
///
/// Reads the 32-bit value at the relocation address, adds the base
/// address difference, and writes it back.
fn process_32bit_relocation(
    memory: &mut MemoryImage,
    relocation: &Relocation,
    old_image_base: u64,
    new_image_base: u64,
) -> RelocationResult {
    let diff = new_image_base.wrapping_sub(old_image_base) as i64;

    let value = match memory.get_u32_le(relocation.address) {
        Some(v) => v,
        None => return RelocationResult::Failed,
    };

    let new_value = (value as i64 + diff) as u32;
    memory.set_u32_le(relocation.address, new_value);
    RelocationResult::Applied
}

/// Process a 64-bit relocation.
///
/// Reads the 64-bit value at the relocation address, adds the base
/// address difference, and writes it back.
fn process_64bit_relocation(
    memory: &mut MemoryImage,
    relocation: &Relocation,
    old_image_base: u64,
    new_image_base: u64,
) -> RelocationResult {
    let diff = new_image_base.wrapping_sub(old_image_base) as i64;

    let value = match memory.get_u64_le(relocation.address) {
        Some(v) => v,
        None => return RelocationResult::Failed,
    };

    let new_value = (value as i64 + diff) as u64;
    memory.set_u64_le(relocation.address, new_value);
    RelocationResult::Applied
}

/// Apply a sequence of relocations using the appropriate handler.
pub fn apply_relocations(
    handler: &dyn RelocationFixupHandler,
    memory: &mut MemoryImage,
    relocations: &[Relocation],
    old_image_base: u64,
    new_image_base: u64,
) -> Vec<(usize, RelocationResult)> {
    relocations
        .iter()
        .enumerate()
        .map(|(i, reloc)| {
            let result = handler.process_relocation(memory, reloc, old_image_base, new_image_base);
            (i, result)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_image_read_write_byte() {
        let mut mem = MemoryImage::new();
        mem.set_byte(0x1000, 0x42);
        assert_eq!(mem.get_byte(0x1000), Some(0x42));
        assert_eq!(mem.get_byte(0x1001), None);
    }

    #[test]
    fn test_memory_image_from_bytes() {
        let mem = MemoryImage::from_bytes(0x400000, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(mem.get_byte(0x400000), Some(0x01));
        assert_eq!(mem.get_byte(0x400003), Some(0x04));
        assert_eq!(mem.len(), 4);
    }

    #[test]
    fn test_memory_image_u32_le() {
        let mut mem = MemoryImage::new();
        mem.set_u32_le(0x1000, 0x12345678);
        assert_eq!(mem.get_u32_le(0x1000), Some(0x12345678));
        // Verify little-endian byte order.
        assert_eq!(mem.get_byte(0x1000), Some(0x78));
        assert_eq!(mem.get_byte(0x1001), Some(0x56));
        assert_eq!(mem.get_byte(0x1002), Some(0x34));
        assert_eq!(mem.get_byte(0x1003), Some(0x12));
    }

    #[test]
    fn test_memory_image_u64_le() {
        let mut mem = MemoryImage::new();
        mem.set_u64_le(0x2000, 0x0102030405060708);
        assert_eq!(mem.get_u64_le(0x2000), Some(0x0102030405060708));
    }

    #[test]
    fn test_process_32bit_relocation() {
        let mut mem = MemoryImage::new();
        // Value at address is 0x1000. Old base is 0x100000, new base is 0x200000.
        // Diff = 0x100000.
        // New value = 0x1000 + 0x100000 = 0x101000.
        mem.set_u32_le(0x400000, 0x00001000);

        let reloc = Relocation {
            address: 0x400000,
            reloc_type: RelocationType::Generic32,
            symbol_name: None,
            value: 0,
        };

        let result = process_32bit_relocation(&mut mem, &reloc, 0x100000, 0x200000);
        assert_eq!(result, RelocationResult::Applied);
        assert_eq!(mem.get_u32_le(0x400000), Some(0x00101000));
    }

    #[test]
    fn test_process_64bit_relocation() {
        let mut mem = MemoryImage::new();
        mem.set_u64_le(0x400000, 0x0000000000001000);

        let reloc = Relocation {
            address: 0x400000,
            reloc_type: RelocationType::Generic64,
            symbol_name: None,
            value: 0,
        };

        let result = process_64bit_relocation(&mut mem, &reloc, 0x100000, 0x200000);
        assert_eq!(result, RelocationResult::Applied);
        assert_eq!(mem.get_u64_le(0x400000), Some(0x0000000000101000));
    }

    #[test]
    fn test_process_32bit_no_change() {
        let mut mem = MemoryImage::new();
        mem.set_u32_le(0x400000, 0x00001000);

        let reloc = Relocation {
            address: 0x400000,
            reloc_type: RelocationType::Generic32,
            symbol_name: None,
            value: 0,
        };

        // Same base addresses -> no change.
        let result = process_32bit_relocation(&mut mem, &reloc, 0x100000, 0x100000);
        assert_eq!(result, RelocationResult::Applied);
        assert_eq!(mem.get_u32_le(0x400000), Some(0x00001000));
    }

    #[test]
    fn test_generic_handler() {
        let handler = GenericRelocationHandler::new();
        assert!(handler.handles_format("ELF"));
        assert!(handler.handles_format("PE"));
        assert_eq!(handler.name(), "Generic Relocation Handler");
    }

    #[test]
    fn test_pe32_handler() {
        let handler = Pe32RelocationHandler::new();
        assert!(handler.handles_format("PE"));
        assert!(!handler.handles_format("ELF"));
    }

    #[test]
    fn test_pe64_handler() {
        let handler = Pe64RelocationHandler::new();
        assert!(handler.handles_format("PE"));
        assert!(!handler.handles_format("ELF"));
    }

    #[test]
    fn test_elf_handler() {
        let handler = ElfRelocationHandler::new();
        assert!(handler.handles_format("ELF"));
        assert!(!handler.handles_format("PE"));
    }

    #[test]
    fn test_elf_handler_register_type() {
        let mut handler = ElfRelocationHandler::new();
        handler.register_type(1, "R_X86_64_64");
        handler.register_type(2, "R_X86_64_PC32");
        assert_eq!(handler.get_type_name(1), Some("R_X86_64_64"));
        assert_eq!(handler.get_type_name(2), Some("R_X86_64_PC32"));
        assert_eq!(handler.get_type_name(99), None);
    }

    #[test]
    fn test_apply_relocations() {
        let handler = GenericRelocationHandler::new();
        let mut mem = MemoryImage::from_bytes(0x400000, &vec![0u8; 16]);
        mem.set_u32_le(0x400000, 0x1000);
        mem.set_u32_le(0x400004, 0x2000);

        let relocs = vec![
            Relocation {
                address: 0x400000,
                reloc_type: RelocationType::Generic32,
                symbol_name: None,
                value: 0,
            },
            Relocation {
                address: 0x400004,
                reloc_type: RelocationType::Generic32,
                symbol_name: None,
                value: 0,
            },
        ];

        let results = apply_relocations(&handler, &mut mem, &relocs, 0x100000, 0x200000);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1, RelocationResult::Applied);
        assert_eq!(results[1].1, RelocationResult::Applied);
        assert_eq!(mem.get_u32_le(0x400000), Some(0x101000));
        assert_eq!(mem.get_u32_le(0x400004), Some(0x102000));
    }

    #[test]
    fn test_generic_handler_skips_unknown_type() {
        let handler = GenericRelocationHandler::new();
        let mut mem = MemoryImage::new();
        let reloc = Relocation {
            address: 0x400000,
            reloc_type: RelocationType::ElfAbsolute,
            symbol_name: None,
            value: 0,
        };
        let result = handler.process_relocation(&mut mem, &reloc, 0x100000, 0x200000);
        assert_eq!(result, RelocationResult::Skipped);
    }

    #[test]
    fn test_relocation_type_custom() {
        let rt = RelocationType::Custom(42);
        assert_eq!(rt, RelocationType::Custom(42));
    }

    #[test]
    fn test_memory_image_default() {
        let mem = MemoryImage::default();
        assert!(mem.is_empty());
    }
}
