//! AARCH64 (ARM 64-bit) Processor Module
//!
//! Complete AArch64 processor support for the Ghidra Rust implementation.
//!
//! ## Supported Processor Variants
//!
//! | Variant            | Features                                          |
//! |--------------------|---------------------------------------------------|
//! | ARMv8-A            | A64 ISA, AArch64 execution state                  |
//! | ARMv8.1-A          | Atomic memory ops, limited ordering regions       |
//! | ARMv8.2-A          | FP16, RAS, statistical profiling                  |
//! | ARMv8.3-A          | Pointer authentication (PAC), nested virt         |
//! | ARMv8.4-A          | Secure EL2, MPAM, SHA3/SHA512, SM3/SM4            |
//! | ARMv8.5-A          | MTE (Memory Tagging Extension), BTI               |
//! | ARMv8.6-A          | Fine-grained traps, AMU v1, WFIT                  |
//! | ARMv9-A            | SVE2, MTE, BTI, PAC mandatory                     |
//! | ARMv9.1-A          | Extended MTE                                      |
//! | ARMv9.2-A          | SME (Scalable Matrix Extension)                   |
//!
//! ## Module Structure
//!
//! - [`registers`] -- Register definitions with full dependency graphs (GPRs,
//!   SIMD/FP views, system registers)
//! - [`instructions`] -- Complete instruction mnemonic enumeration (300+
//!   mnemonics), condition codes, shift types, extend types, addressing modes

pub mod instructions;
pub mod registers;

// Re-export key types for convenience
pub use instructions::{
    all_aarch64_mnemonics, Aarch64Mnemonic, AddressingMode, ConditionCode, ExtendType,
    InstructionCategory, ShiftType,
};
pub use registers::{Aarch64RegisterBank, PstateField};

use crate::common::{Endian, Language, ProcessorModule, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

// ============================================================================
// Processor Name Constants
// ============================================================================

/// Processor family name.
pub const PROCESSOR_NAME: &str = "AARCH64";

/// Processor description.
pub const PROCESSOR_DESCRIPTION: &str =
    "ARM 64-bit processor family (AArch64), including SIMD/FP and cryptographic extensions";

// ============================================================================
// AARCH64 Processor Variants
// ============================================================================

/// AArch64 ISA variants / architecture versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Aarch64Variant {
    /// ARMv8-A base A64 ISA
    ArmV8A,
    /// ARMv8.1-A
    ArmV81A,
    /// ARMv8.2-A
    ArmV82A,
    /// ARMv8.3-A
    ArmV83A,
    /// ARMv8.4-A
    ArmV84A,
    /// ARMv8.5-A
    ArmV85A,
    /// ARMv8.6-A
    ArmV86A,
    /// ARMv9-A
    ArmV9A,
    /// ARMv9.1-A
    ArmV91A,
    /// ARMv9.2-A
    ArmV92A,
}

impl Aarch64Variant {
    /// Human-readable variant name.
    pub fn name(&self) -> &'static str {
        match self {
            Aarch64Variant::ArmV8A => "ARMv8-A",
            Aarch64Variant::ArmV81A => "ARMv8.1-A",
            Aarch64Variant::ArmV82A => "ARMv8.2-A",
            Aarch64Variant::ArmV83A => "ARMv8.3-A",
            Aarch64Variant::ArmV84A => "ARMv8.4-A",
            Aarch64Variant::ArmV85A => "ARMv8.5-A",
            Aarch64Variant::ArmV86A => "ARMv8.6-A",
            Aarch64Variant::ArmV9A => "ARMv9-A",
            Aarch64Variant::ArmV91A => "ARMv9.1-A",
            Aarch64Variant::ArmV92A => "ARMv9.2-A",
        }
    }

    /// Does this variant support half-precision (FP16)?
    pub fn has_fp16(&self) -> bool {
        !matches!(self, Aarch64Variant::ArmV8A)
    }

    /// Does this variant support pointer authentication (PAC)?
    pub fn has_pac(&self) -> bool {
        !matches!(
            self,
            Aarch64Variant::ArmV8A | Aarch64Variant::ArmV81A | Aarch64Variant::ArmV82A
        )
    }

    /// Does this variant support Memory Tagging Extension (MTE)?
    pub fn has_mte(&self) -> bool {
        !matches!(
            self,
            Aarch64Variant::ArmV8A
                | Aarch64Variant::ArmV81A
                | Aarch64Variant::ArmV82A
                | Aarch64Variant::ArmV83A
                | Aarch64Variant::ArmV84A
        )
    }

    /// Does this variant support Scalable Vector Extension (SVE)?
    pub fn has_sve(&self) -> bool {
        !matches!(
            self,
            Aarch64Variant::ArmV8A
                | Aarch64Variant::ArmV81A
                | Aarch64Variant::ArmV82A
                | Aarch64Variant::ArmV83A
        )
    }

    /// Default pointer size in bits.
    pub fn pointer_size(&self) -> u32 {
        64
    }
}

impl std::fmt::Display for Aarch64Variant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// ProcessorModule Implementation
// ============================================================================

/// The AArch64 processor module.
pub struct Aarch64Module;

impl ProcessorModule for Aarch64Module {
    fn name() -> &'static str {
        PROCESSOR_NAME
    }

    fn registers() -> RegisterBank {
        let aa64_bank = Aarch64RegisterBank::new_armv8a();
        let mut bank = RegisterBank::new();
        for reg in aa64_bank.iter() {
            bank.add(reg.clone());
        }
        bank
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "AARCH64:LE:64:v8A",
                "AARCH64 ARMv8-A - Little Endian",
                "v8A",
                Endian::Little,
                64,
            ),
            Language::new(
                "AARCH64:BE:64:v8A",
                "AARCH64 ARMv8-A - Big Endian",
                "v8A",
                Endian::Big,
                64,
            ),
            Language::new(
                "AARCH64:LE:64:v8.2A",
                "AARCH64 ARMv8.2-A - Little Endian",
                "v8.2A",
                Endian::Little,
                64,
            ),
            Language::new(
                "AARCH64:LE:64:v9A",
                "AARCH64 ARMv9-A - Little Endian",
                "v9A",
                Endian::Little,
                64,
            ),
            Language::new(
                "AARCH64:LE:64:ILP32",
                "AARCH64 ILP32 - Little Endian (32-bit pointers)",
                "v8A",
                Endian::Little,
                32,
            ),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> {
        all_aarch64_mnemonics()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_module_interface() {
        let regs = Aarch64Module::registers();
        assert!(!regs.is_empty());

        let langs = Aarch64Module::languages();
        assert!(langs.len() >= 4);

        let insts = Aarch64Module::instructions();
        assert!(insts.len() >= 300);
    }

    #[test]
    fn test_variant_names() {
        assert_eq!(Aarch64Variant::ArmV8A.name(), "ARMv8-A");
        assert_eq!(Aarch64Variant::ArmV82A.name(), "ARMv8.2-A");
        assert_eq!(Aarch64Variant::ArmV9A.name(), "ARMv9-A");
    }

    #[test]
    fn test_variant_capabilities() {
        assert!(!Aarch64Variant::ArmV8A.has_fp16());
        assert!(Aarch64Variant::ArmV82A.has_fp16());
        assert!(!Aarch64Variant::ArmV8A.has_pac());
        assert!(Aarch64Variant::ArmV84A.has_pac());
        assert!(!Aarch64Variant::ArmV8A.has_mte());
        assert!(!Aarch64Variant::ArmV8A.has_sve());
    }

    #[test]
    fn test_re_exports() {
        // Verify key types are accessible from the aarch64 module
        let bank = Aarch64RegisterBank::new_armv8a();
        assert!(bank.get("X0").is_some());
        assert!(bank.get("SP").is_some());
        assert_eq!(ConditionCode::AL.encoding(), 0b1110);
        assert_eq!(ShiftType::LSL.suffix(), "LSL");
        assert_eq!(ExtendType::UXTB.encoding(), 0b000);
    }
}
