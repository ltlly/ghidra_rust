//! ARM32 Processor Module
//!
//! Complete ARM (AArch32) processor support for the Ghidra Rust implementation.
//!
//! ## Supported Processor Variants
//!
//! | Variant            | Features                                          |
//! |--------------------|---------------------------------------------------|
//! | ARMv4 / ARMv4T     | ARM + Thumb, 32-bit ISA                           |
//! | ARMv5TE            | Enhanced DSP, Thumb                               |
//! | ARMv6              | SIMD, Thumb-2, TrustZone                          |
//! | ARMv6T2            | Thumb-2 mandatory                                 |
//! | ARMv7-A            | VFPv3/v4, NEON, Virtualization                    |
//! | ARMv7-R            | Real-time profile                                 |
//! | ARMv7-M            | Microcontroller profile (Cortex-M)                |
//! | ARMv8-A (AArch32)  | AArch32 execution state, Crypto extensions        |
//!
//! ## Module Structure
//!
//! - [`registers`] -- Register definitions with full dependency graphs (banked
//!   registers, VFP/NEON)
//! - [`instructions`] -- Complete instruction mnemonic enumeration (200+
//!   mnemonics), condition codes, addressing modes, shift types
//! - [`loader`] -- Binary format detection, ARM/Thumb mode detection, function
//!   boundary detection, calling convention detection

pub mod instructions;
pub mod loader;
pub mod registers;

// Re-export key types for convenience
pub use instructions::{
    all_arm_mnemonics, AddressingMode, ArmMnemonic, ConditionCode, InstructionCategory, ShiftType,
};
pub use loader::{
    detect_epilogue, detect_function_boundaries, detect_prologue, ArmBinaryFormat, ArmBinaryImage,
    ArmCallingConvention, ArmExecutionMode, ArmModeDetector, BoundaryType, FunctionBoundary,
    ProloguePattern, Section,
};
pub use registers::{ArmRegisterBank, CpsrFlagBit, ProcessorMode};

use crate::common::{Endian, Language, ProcessorModule, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

// ============================================================================
// Processor Name Constants
// ============================================================================

/// Processor family name.
pub const PROCESSOR_NAME: &str = "ARM";

/// Processor description.
pub const PROCESSOR_DESCRIPTION: &str =
    "ARM 32-bit processor family (AArch32), including Thumb, VFP, and NEON";

// ============================================================================
// ARM Processor Variants
// ============================================================================

/// ARM ISA variants / architecture versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArmVariant {
    /// ARMv4 / ARMv4T: ARM + Thumb (ARMv4T), 32-bit ISA
    ArmV4,
    /// ARMv5TE: Enhanced DSP instructions, Thumb
    ArmV5TE,
    /// ARMv6: SIMD instructions, Thumb, TrustZone
    ArmV6,
    /// ARMv6T2: Thumb-2 mandatory
    ArmV6T2,
    /// ARMv7-A: Application profile, VFPv3/v4, NEON, Virtualization
    ArmV7A,
    /// ARMv7-R: Real-time profile
    ArmV7R,
    /// ARMv7-M: Microcontroller profile (Cortex-M)
    ArmV7M,
    /// ARMv8-A (AArch32 execution state), Crypto extensions
    ArmV8A,
}

impl ArmVariant {
    /// Human-readable variant name.
    pub fn name(&self) -> &'static str {
        match self {
            ArmVariant::ArmV4 => "ARMv4",
            ArmVariant::ArmV5TE => "ARMv5TE",
            ArmVariant::ArmV6 => "ARMv6",
            ArmVariant::ArmV6T2 => "ARMv6T2",
            ArmVariant::ArmV7A => "ARMv7-A",
            ArmVariant::ArmV7R => "ARMv7-R",
            ArmVariant::ArmV7M => "ARMv7-M",
            ArmVariant::ArmV8A => "ARMv8-A (AArch32)",
        }
    }

    /// Whether this variant supports the Thumb instruction set.
    pub fn has_thumb(&self) -> bool {
        !matches!(self, ArmVariant::ArmV4)
    }

    /// Whether this variant supports Thumb-2.
    pub fn has_thumb2(&self) -> bool {
        matches!(
            self,
            ArmVariant::ArmV6T2
                | ArmVariant::ArmV7A
                | ArmVariant::ArmV7R
                | ArmVariant::ArmV7M
                | ArmVariant::ArmV8A
        )
    }

    /// Whether this variant supports VFP (hardware floating-point).
    pub fn has_vfp(&self) -> bool {
        matches!(
            self,
            ArmVariant::ArmV7A | ArmVariant::ArmV7R | ArmVariant::ArmV8A
        )
    }

    /// Whether this variant supports NEON (Advanced SIMD).
    pub fn has_neon(&self) -> bool {
        matches!(
            self,
            ArmVariant::ArmV7A | ArmVariant::ArmV7R | ArmVariant::ArmV8A
        )
    }

    /// Whether this variant is a microcontroller profile (Cortex-M).
    pub fn is_m_profile(&self) -> bool {
        matches!(self, ArmVariant::ArmV7M)
    }

    /// Default pointer size in bits.
    pub fn pointer_size(&self) -> u32 {
        32
    }
}

impl std::fmt::Display for ArmVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// ProcessorModule Implementation
// ============================================================================

/// The ARM32 processor module.
pub struct ArmModule;

impl ProcessorModule for ArmModule {
    fn name() -> &'static str {
        PROCESSOR_NAME
    }

    fn registers() -> RegisterBank {
        let arm_bank = ArmRegisterBank::new_armv7a();
        let mut bank = RegisterBank::new();
        for reg in arm_bank.iter() {
            bank.add(reg.clone());
        }
        bank
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "ARM:LE:32:v7",
                "ARM v7 - Little Endian",
                "v7",
                Endian::Little,
                32,
            ),
            Language::new("ARM:BE:32:v7", "ARM v7 - Big Endian", "v7", Endian::Big, 32),
            Language::new(
                "ARM:LE:32:v8",
                "ARM v8 (AArch32) - Little Endian",
                "v8",
                Endian::Little,
                32,
            ),
            Language::new(
                "ARM:LE:32:Thumb",
                "ARM Thumb - Little Endian",
                "Thumb",
                Endian::Little,
                32,
            ),
            Language::new(
                "ARM:LE:32:CortexM",
                "ARM Cortex-M - Little Endian",
                "v7-M",
                Endian::Little,
                32,
            ),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> {
        all_arm_mnemonics()
    }
}

/// Create a new ARM32 analysis context (binary image + register bank).
pub fn create_analysis_context(
    binary_data: &[u8],
    base_address: u64,
    entry_point: u64,
) -> (ArmBinaryImage, ArmRegisterBank) {
    let mut image = ArmBinaryImage::new(binary_data.to_vec(), base_address, entry_point);
    let registers = ArmRegisterBank::new_armv7a();
    image.registers = registers.clone();
    (image, registers)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_module_interface() {
        let regs = ArmModule::registers();
        assert!(!regs.is_empty());

        let langs = ArmModule::languages();
        assert!(langs.len() >= 4);

        let insts = ArmModule::instructions();
        assert!(insts.len() >= 200);
    }

    #[test]
    fn test_arm_variant_names() {
        assert_eq!(ArmVariant::ArmV4.name(), "ARMv4");
        assert_eq!(ArmVariant::ArmV7A.name(), "ARMv7-A");
        assert_eq!(ArmVariant::ArmV8A.name(), "ARMv8-A (AArch32)");
    }

    #[test]
    fn test_arm_variant_capabilities() {
        assert!(!ArmVariant::ArmV4.has_thumb());
        assert!(ArmVariant::ArmV7A.has_thumb());
        assert!(ArmVariant::ArmV7A.has_thumb2());
        assert!(!ArmVariant::ArmV6.has_thumb2());
        assert!(ArmVariant::ArmV7A.has_vfp());
        assert!(!ArmVariant::ArmV7M.has_vfp());
        assert!(ArmVariant::ArmV7A.has_neon());
        assert!(ArmVariant::ArmV7M.is_m_profile());
        assert!(!ArmVariant::ArmV7A.is_m_profile());
    }

    #[test]
    fn test_create_analysis_context() {
        let data = vec![0x00u8; 64]; // NOP-equivalent padding
        let (image, registers) = create_analysis_context(&data, 0x400000, 0x400000);
        assert_eq!(image.base_address, 0x400000);
        assert_eq!(image.entry_point, 0x400000);
        assert!(registers.get("R0").is_some());
        assert!(registers.get("PC").is_some());
    }

    #[test]
    fn test_re_exports() {
        // Verify key types are accessible from the arm module
        let bank = ArmRegisterBank::new_armv7a();
        assert!(bank.get("R0").is_some());
        assert!(bank.get("CPSR").is_some());
        assert_eq!(ConditionCode::AL.suffix(), "AL");
        let _mode = ArmExecutionMode::Arm;
        let _cc = ArmCallingConvention::AAPCS;
    }
}
