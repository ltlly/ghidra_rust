//! Instruction code unit type.
//!
//! Ported from Ghidra's `DBTraceInstruction`.

use crate::db::listing::code_unit::{AbstractCodeUnit, CodeUnitKind};
use crate::model::CodeUnitType;

/// An instruction code unit in the trace listing.
#[derive(Debug, Clone)]
pub struct DbTraceInstruction {
    /// The base code unit properties.
    pub base: AbstractCodeUnit,
    /// The processor language/mnemonic string.
    pub language: String,
    /// The raw instruction bytes.
    pub bytes: Vec<u8>,
    /// The mnemonic (short instruction name), if known.
    pub mnemonic: Option<String>,
    /// The full assembly representation, if decoded.
    pub assembly: Option<String>,
    /// The delay slot depth (for architectures with delay slots).
    pub delay_slot_depth: u8,
}

impl DbTraceInstruction {
    /// Create a new instruction code unit.
    pub fn new(
        offset: u64,
        length: u32,
        snap: i64,
        language: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            base: AbstractCodeUnit {
                offset,
                length,
                snap,
                thread_id: 0,
                kind: CodeUnitKind::Instruction,
                unit_type: CodeUnitType::Instruction,
                is_overlay: false,
                space_name: "ram".into(),
            },
            language: language.into(),
            bytes,
            mnemonic: None,
            assembly: None,
            delay_slot_depth: 0,
        }
    }

    /// Set the mnemonic for this instruction.
    pub fn with_mnemonic(mut self, mnemonic: impl Into<String>) -> Self {
        self.mnemonic = Some(mnemonic.into());
        self
    }

    /// Set the full assembly representation.
    pub fn with_assembly(mut self, assembly: impl Into<String>) -> Self {
        self.assembly = Some(assembly.into());
        self
    }

    /// Set the delay slot depth.
    pub fn with_delay_slot_depth(mut self, depth: u8) -> Self {
        self.delay_slot_depth = depth;
        self
    }

    /// Check if this instruction has delay slots.
    pub fn has_delay_slots(&self) -> bool {
        self.delay_slot_depth > 0
    }

    /// Get the instruction bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the instruction length from bytes.
    pub fn byte_length(&self) -> usize {
        self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_creation() {
        let inst = DbTraceInstruction::new(0x1000, 3, 0, "x86", vec![0x89, 0xE5, 0x90])
            .with_mnemonic("NOP")
            .with_assembly("nop");

        assert_eq!(inst.base.offset, 0x1000);
        assert_eq!(inst.base.length, 3);
        assert_eq!(inst.mnemonic.as_deref(), Some("NOP"));
        assert_eq!(inst.bytes(), &[0x89, 0xE5, 0x90]);
        assert!(!inst.has_delay_slots());
    }

    #[test]
    fn test_delay_slots() {
        let inst = DbTraceInstruction::new(0x2000, 4, 5, "mips", vec![0; 4])
            .with_delay_slot_depth(1);

        assert!(inst.has_delay_slots());
        assert_eq!(inst.delay_slot_depth, 1);
    }
}
