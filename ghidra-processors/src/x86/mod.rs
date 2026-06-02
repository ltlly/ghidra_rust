//! x86 Processor Module
//!
//! Complete x86/x86-64 processor support for the Ghidra Rust implementation.
//!
//! ## Supported Processor Variants
//!
//! | Variant            | Features                                    |
//! |--------------------|---------------------------------------------|
//! | 8086 / 8088        | 16-bit real mode, base instruction set      |
//! | 80186 / 80188      | Added ENTER/LEAVE, PUSHA/POPA, BOUND        |
//! | 80286              | 16-bit protected mode, LGDT/LIDT/LLDT, ARPL |
//! | 80386              | 32-bit protected mode, paging, V86 mode     |
//! | 80486              | CMPXCHG, XADD, BSWAP, INVD/WBINVD/INVLPG   |
//! | Pentium / P5       | CPUID, RDTSC, RDMSR/WRMSR, CMPXCHG8B        |
//! | Pentium MMX        | MMX instruction set (57 new instructions)    |
//! | Pentium Pro / P6   | CMOVcc, FCMOVcc, RDPMC, UD2                 |
//! | Pentium II         | SSE (70 instructions), FXSAVE/FXRSTOR       |
//! | Pentium III        | SSE, PREFETCH, SFENCE                        |
//! | Pentium 4          | SSE2 (144 instructions), SSE3                |
//! | x86-64 (AMD64)     | 64-bit mode, 16 GPRs, RIP-relative, NX bit  |
//! | Core 2 / SSSE3     | SSSE3 (32 instructions)                     |
//! | Nehalem / SSE4     | SSE4.1 + SSE4.2 (54 instructions), POPCNT   |
//! | Sandy Bridge / AVX | AVX (256-bit vectors, VEX encoding)          |
//! | Haswell / AVX2     | AVX2, FMA3, BMI1/2, ABM                     |
//! | Skylake-X / AVX-512| AVX-512F, CD, BW, DQ, VL                     |
//! | Cannon Lake        | AVX-512 IFMA, VBMI                           |
//! | Ice Lake           | AVX-512 VBMI2, VNNI, BITALG, VPOPCNTDQ      |
//! | Tiger Lake         | AVX-512 VP2INTERSECT                         |
//! | Alder Lake         | AVX-VNNI, AVX-512 FP16                       |
//! | Sapphire Rapids    | AMX, AVX-512 BF16                            |
//!
//! ## Module Structure
//!
//! - [`registers`] -- Full register bank definitions with sub-register aliasing
//! - [`instructions`] -- Complete mnemonic enumeration, encoding helpers,
//!   addressing modes, and decoded instruction representation
//! - [`loader`] -- Binary format detection, instruction decoding, function
//!   boundary detection, calling convention detection
//! - [`analyzer`] -- Stack frame analysis, variable detection, jump table
//!   detection, function discovery, cross-reference analysis

pub mod analyzer;
pub mod instructions;
pub mod loader;
pub mod registers;

// Re-export key types for convenience
pub use analyzer::{
    collect_references, detect_jump_tables, find_string_references, FunctionDetector, JumpTable,
    ReferenceType, StackFrame, StackVariable, VariableAnalyzer,
};
pub use instructions::{
    ConditionCode, DecodedInstruction, InstructionCategory, MemoryOperand, ModRM, Operand,
    PrefixInfo, SegmentRegister, X86Mnemonic, EVEX, REX, SIB, VEX,
};
pub use loader::{
    decode_instructions, detect_epilogue, detect_prologue, BinaryFormat, BoundaryType,
    CallingConvention, EpiloguePattern, ExportSymbol, FunctionBoundary, ImportSymbol,
    ProloguePattern, Section, X86BinaryImage, X86InstructionDecoder,
};
pub use registers::{FlagBit, Register, X86RegisterBank};

/// Processor family name.
pub const PROCESSOR_NAME: &str = "x86";

/// Processor description.
pub const PROCESSOR_DESCRIPTION: &str = "Intel/AMD x86 and x86-64 processor family";

/// Supported processor variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X86Variant {
    I8086,
    I80186,
    I80286,
    I80386,
    I80486,
    Pentium,
    PentiumMMX,
    PentiumPro,
    PentiumII,
    PentiumIII,
    Pentium4,
    X86_64,
    Core2,
    Nehalem,
    SandyBridge,
    Haswell,
    SkylakeX,
    CannonLake,
    IceLake,
    TigerLake,
    AlderLake,
    SapphireRapids,
}

impl X86Variant {
    /// Human-readable variant name.
    pub fn name(&self) -> &'static str {
        match self {
            X86Variant::I8086 => "8086",
            X86Variant::I80186 => "80186",
            X86Variant::I80286 => "80286",
            X86Variant::I80386 => "80386",
            X86Variant::I80486 => "80486",
            X86Variant::Pentium => "Pentium",
            X86Variant::PentiumMMX => "Pentium MMX",
            X86Variant::PentiumPro => "Pentium Pro",
            X86Variant::PentiumII => "Pentium II",
            X86Variant::PentiumIII => "Pentium III",
            X86Variant::Pentium4 => "Pentium 4",
            X86Variant::X86_64 => "x86-64",
            X86Variant::Core2 => "Core 2",
            X86Variant::Nehalem => "Nehalem",
            X86Variant::SandyBridge => "Sandy Bridge",
            X86Variant::Haswell => "Haswell",
            X86Variant::SkylakeX => "Skylake-X",
            X86Variant::CannonLake => "Cannon Lake",
            X86Variant::IceLake => "Ice Lake",
            X86Variant::TigerLake => "Tiger Lake",
            X86Variant::AlderLake => "Alder Lake",
            X86Variant::SapphireRapids => "Sapphire Rapids",
        }
    }

    /// Is this a 64-bit capable variant?
    pub fn is_64bit(&self) -> bool {
        matches!(
            self,
            X86Variant::X86_64
                | X86Variant::Core2
                | X86Variant::Nehalem
                | X86Variant::SandyBridge
                | X86Variant::Haswell
                | X86Variant::SkylakeX
                | X86Variant::CannonLake
                | X86Variant::IceLake
                | X86Variant::TigerLake
                | X86Variant::AlderLake
                | X86Variant::SapphireRapids
        )
    }

    /// Does this variant support AVX?
    pub fn has_avx(&self) -> bool {
        matches!(
            self,
            X86Variant::SandyBridge
                | X86Variant::Haswell
                | X86Variant::SkylakeX
                | X86Variant::CannonLake
                | X86Variant::IceLake
                | X86Variant::TigerLake
                | X86Variant::AlderLake
                | X86Variant::SapphireRapids
        )
    }

    /// Does this variant support AVX-512?
    pub fn has_avx512(&self) -> bool {
        matches!(
            self,
            X86Variant::SkylakeX
                | X86Variant::CannonLake
                | X86Variant::IceLake
                | X86Variant::TigerLake
                | X86Variant::AlderLake
                | X86Variant::SapphireRapids
        )
    }

    /// The default data/address size for this variant.
    pub fn default_size(&self) -> u8 {
        if self.is_64bit() {
            64
        } else {
            32
        }
    }
}

impl std::fmt::Display for X86Variant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Create a new x86-64 register bank and binary image for analyzing a binary.
pub fn create_analysis_context(
    binary_data: &[u8],
    base_address: u64,
    variant: X86Variant,
) -> (X86BinaryImage, X86RegisterBank) {
    let mut image = X86BinaryImage::load(binary_data.to_vec(), base_address);
    let registers = X86RegisterBank::new_x86_64();
    image.registers = registers.clone();
    image.is_64bit = variant.is_64bit();
    (image, registers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variant_names() {
        assert_eq!(X86Variant::I8086.name(), "8086");
        assert_eq!(X86Variant::X86_64.name(), "x86-64");
        assert_eq!(X86Variant::SapphireRapids.name(), "Sapphire Rapids");
    }

    #[test]
    fn test_variant_capabilities() {
        assert!(!X86Variant::I80386.is_64bit());
        assert!(X86Variant::X86_64.is_64bit());
        assert!(!X86Variant::Pentium4.has_avx());
        assert!(X86Variant::Haswell.has_avx());
        assert!(!X86Variant::Haswell.has_avx512());
        assert!(X86Variant::SkylakeX.has_avx512());
    }

    #[test]
    fn test_re_exports() {
        // Verify key types are accessible from the x86 module
        let bank = X86RegisterBank::new_x86_64();
        assert!(bank.get("RAX").is_some());
    }

    #[test]
    fn test_create_analysis_context() {
        let data = vec![0x90u8; 100]; // 100 NOPs
        let (image, registers) = create_analysis_context(&data, 0x400000, X86Variant::X86_64);
        assert_eq!(image.base_address, 0x400000);
        assert!(image.is_64bit);
        assert!(registers.get("RIP").is_some());
    }
}
