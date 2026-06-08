//! Mach-O CPU type and subtype constants ported from Ghidra's
//! `ghidra.app.util.bin.format.macho.CpuTypes` and
//! `ghidra.app.util.bin.format.macho.CpuSubTypes`.
//!
//! References:
//! - <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/machine.h>

// ---------------------------------------------------------------------------
// CPU type architecture masks
// ---------------------------------------------------------------------------

/// Mask for architecture bits.
pub const CPU_ARCH_MASK: u32 = 0xFF00_0000;

/// 64-bit ABI flag.
pub const CPU_ARCH_ABI64: u32 = 0x0100_0000;

/// ABI for 64-bit hardware with 32-bit types; LP32.
pub const CPU_ARCH_ABI64_32: u32 = 0x0200_0000;

// ---------------------------------------------------------------------------
// CPU type values
// ---------------------------------------------------------------------------

pub const CPU_TYPE_ANY: i32 = -1;
pub const CPU_TYPE_VAX: i32 = 0x01;
pub const CPU_TYPE_MC680X0: i32 = 0x06;
pub const CPU_TYPE_X86: i32 = 0x07;
/// Compatibility alias for `CPU_TYPE_X86`.
pub const CPU_TYPE_I386: i32 = CPU_TYPE_X86;
pub const CPU_TYPE_MC98000: i32 = 0x0A;
pub const CPU_TYPE_HPPA: i32 = 0x0B;
pub const CPU_TYPE_ARM: i32 = 0x0C;
pub const CPU_TYPE_MC88000: i32 = 0x0D;
pub const CPU_TYPE_SPARC: i32 = 0x0E;
pub const CPU_TYPE_I860: i32 = 0x0F;
pub const CPU_TYPE_POWERPC: i32 = 0x12;

pub const CPU_TYPE_POWERPC64: i32 = CPU_TYPE_POWERPC | (CPU_ARCH_ABI64 as i32);
pub const CPU_TYPE_X86_64: i32 = CPU_TYPE_X86 | (CPU_ARCH_ABI64 as i32);
pub const CPU_TYPE_ARM_64: i32 = CPU_TYPE_ARM | (CPU_ARCH_ABI64 as i32);
pub const CPU_TYPE_ARM64_32: i32 = CPU_TYPE_ARM | (CPU_ARCH_ABI64_32 as i32);

// ---------------------------------------------------------------------------
// CPU subtypes -- PowerPC
// ---------------------------------------------------------------------------

pub const CPU_SUBTYPE_POWERPC_ALL: i32 = 0;
pub const CPU_SUBTYPE_POWERPC_601: i32 = 1;
pub const CPU_SUBTYPE_POWERPC_602: i32 = 2;
pub const CPU_SUBTYPE_POWERPC_603: i32 = 3;
pub const CPU_SUBTYPE_POWERPC_603E: i32 = 4;
pub const CPU_SUBTYPE_POWERPC_603EV: i32 = 5;
pub const CPU_SUBTYPE_POWERPC_604: i32 = 6;
pub const CPU_SUBTYPE_POWERPC_604E: i32 = 7;
pub const CPU_SUBTYPE_POWERPC_620: i32 = 8;
pub const CPU_SUBTYPE_POWERPC_750: i32 = 9;
pub const CPU_SUBTYPE_POWERPC_7400: i32 = 10;
pub const CPU_SUBTYPE_POWERPC_7450: i32 = 11;
pub const CPU_SUBTYPE_POWERPC_970: i32 = 100;

// ---------------------------------------------------------------------------
// CPU subtypes -- Intel x86
// ---------------------------------------------------------------------------

/// Helper to build Intel CPU subtypes: family + (model << 4).
const fn cpu_subtype_intel(family: i32, model: i32) -> i32 {
    family + (model << 4)
}

pub const CPU_SUBTYPE_I386_ALL: i32 = cpu_subtype_intel(3, 0);
pub const CPU_SUBTYPE_386: i32 = cpu_subtype_intel(3, 0);
pub const CPU_SUBTYPE_486: i32 = cpu_subtype_intel(4, 0);
pub const CPU_SUBTYPE_486SX: i32 = cpu_subtype_intel(4, 8);
pub const CPU_SUBTYPE_586: i32 = cpu_subtype_intel(5, 0);
pub const CPU_SUBTYPE_PENT: i32 = cpu_subtype_intel(5, 0);
pub const CPU_SUBTYPE_PENTPRO: i32 = cpu_subtype_intel(6, 1);
pub const CPU_SUBTYPE_PENTII_M3: i32 = cpu_subtype_intel(6, 3);
pub const CPU_SUBTYPE_PENTII_M5: i32 = cpu_subtype_intel(6, 5);
pub const CPU_SUBTYPE_CELERON: i32 = cpu_subtype_intel(7, 6);
pub const CPU_SUBTYPE_CELERON_MOBILE: i32 = cpu_subtype_intel(7, 7);
pub const CPU_SUBTYPE_PENTIUM_3: i32 = cpu_subtype_intel(8, 0);
pub const CPU_SUBTYPE_PENTIUM_3_M: i32 = cpu_subtype_intel(8, 1);
pub const CPU_SUBTYPE_PENTIUM_3_XEON: i32 = cpu_subtype_intel(8, 2);
pub const CPU_SUBTYPE_PENTIUM_M: i32 = cpu_subtype_intel(9, 0);
pub const CPU_SUBTYPE_PENTIUM_4: i32 = cpu_subtype_intel(10, 0);
pub const CPU_SUBTYPE_PENTIUM_4_M: i32 = cpu_subtype_intel(10, 1);
pub const CPU_SUBTYPE_ITANIUM: i32 = cpu_subtype_intel(11, 0);
pub const CPU_SUBTYPE_ITANIUM_2: i32 = cpu_subtype_intel(11, 1);
pub const CPU_SUBTYPE_XEON: i32 = cpu_subtype_intel(12, 0);
pub const CPU_SUBTYPE_XEON_MP: i32 = cpu_subtype_intel(12, 1);

pub const CPU_SUBTYPE_X86_ALL: i32 = 3;
pub const CPU_SUBTYPE_X86_ARCH1: i32 = 4;

pub const CPU_THREADTYPE_INTEL_HTT: i32 = 1;

// ---------------------------------------------------------------------------
// CPU subtypes -- MIPS
// ---------------------------------------------------------------------------

pub const CPU_SUBTYPE_MIPS_ALL: i32 = 0;
pub const CPU_SUBTYPE_MIPS_R2300: i32 = 1;
pub const CPU_SUBTYPE_MIPS_R2600: i32 = 2;
pub const CPU_SUBTYPE_MIPS_R2800: i32 = 3;
pub const CPU_SUBTYPE_MIPS_R2000A: i32 = 4;
pub const CPU_SUBTYPE_MIPS_R2000: i32 = 5;
pub const CPU_SUBTYPE_MIPS_R3000A: i32 = 6;
pub const CPU_SUBTYPE_MIPS_R3000: i32 = 7;

// ---------------------------------------------------------------------------
// CPU subtypes -- MC98000 (PowerPC)
// ---------------------------------------------------------------------------

pub const CPU_SUBTYPE_MC98000_ALL: i32 = 0;
pub const CPU_SUBTYPE_MC98601: i32 = 1;

// ---------------------------------------------------------------------------
// CPU subtypes -- HPPA
// ---------------------------------------------------------------------------

pub const CPU_SUBTYPE_HPPA_ALL: i32 = 0;
pub const CPU_SUBTYPE_HPPA_7100: i32 = 0;
pub const CPU_SUBTYPE_HPPA_7100LC: i32 = 1;

// ---------------------------------------------------------------------------
// CPU subtypes -- MC88000
// ---------------------------------------------------------------------------

pub const CPU_SUBTYPE_MC88000_ALL: i32 = 0;
pub const CPU_SUBTYPE_MC88100: i32 = 1;
pub const CPU_SUBTYPE_MC88110: i32 = 2;

// ---------------------------------------------------------------------------
// CPU subtypes -- SPARC
// ---------------------------------------------------------------------------

pub const CPU_SUBTYPE_SPARC_ALL: i32 = 0;

// ---------------------------------------------------------------------------
// CPU subtypes -- I860
// ---------------------------------------------------------------------------

pub const CPU_SUBTYPE_I860_ALL: i32 = 0;
pub const CPU_SUBTYPE_I860_860: i32 = 1;

// ---------------------------------------------------------------------------
// CPU subtypes -- VAX
// ---------------------------------------------------------------------------

pub const CPU_SUBTYPE_VAX_ALL: i32 = 0;
pub const CPU_SUBTYPE_VAX780: i32 = 1;
pub const CPU_SUBTYPE_VAX785: i32 = 2;
pub const CPU_SUBTYPE_VAX750: i32 = 3;
pub const CPU_SUBTYPE_VAX730: i32 = 4;
pub const CPU_SUBTYPE_UVAXI: i32 = 5;
pub const CPU_SUBTYPE_UVAXII: i32 = 6;
pub const CPU_SUBTYPE_VAX8200: i32 = 7;
pub const CPU_SUBTYPE_VAX8500: i32 = 8;
pub const CPU_SUBTYPE_VAX8600: i32 = 9;
pub const CPU_SUBTYPE_VAX8650: i32 = 10;
pub const CPU_SUBTYPE_VAX8800: i32 = 11;
pub const CPU_SUBTYPE_UVAXIII: i32 = 12;

// ---------------------------------------------------------------------------
// CPU subtypes -- MC680x0
// ---------------------------------------------------------------------------

pub const CPU_SUBTYPE_MC680X0_ALL: i32 = 1;
pub const CPU_SUBTYPE_MC68030: i32 = 1;
pub const CPU_SUBTYPE_MC68040: i32 = 2;
pub const CPU_SUBTYPE_MC68030_ONLY: i32 = 3;

// ---------------------------------------------------------------------------
// CPU subtypes -- ARM
// ---------------------------------------------------------------------------

pub const CPU_SUBTYPE_ARM_ALL: i32 = 0;
pub const CPU_SUBTYPE_ARM_V4T: i32 = 5;
pub const CPU_SUBTYPE_ARM_V6: i32 = 6;
pub const CPU_SUBTYPE_ARM_V5: i32 = 7;
pub const CPU_SUBTYPE_ARM_V5TEJ: i32 = 7;
pub const CPU_SUBTYPE_ARM_XSCALE: i32 = 8;
pub const CPU_SUBTYPE_ARM_V7: i32 = 9;
pub const CPU_SUBTYPE_ARM_V7F: i32 = 10;
pub const CPU_SUBTYPE_ARM_V7S: i32 = 11;
pub const CPU_SUBTYPE_ARM_V7K: i32 = 12;
pub const CPU_SUBTYPE_ARM_V6M: i32 = 14;
pub const CPU_SUBTYPE_ARM_V7M: i32 = 15;
pub const CPU_SUBTYPE_ARM_V7EM: i32 = 16;

// ---------------------------------------------------------------------------
// Generic subtypes
// ---------------------------------------------------------------------------

pub const CPU_SUBTYPE_MULTIPLE: i32 = -1;
pub const CPU_SUBTYPE_LITTLE_ENDIAN: i32 = 0;
pub const CPU_SUBTYPE_BIG_ENDIAN: i32 = 1;

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Returns the Ghidra processor name for the given CPU type and subtype.
///
/// Returns `None` if the CPU type is not recognized.
pub fn cpu_type_to_processor(cpu_type: i32) -> Option<&'static str> {
    match cpu_type {
        CPU_TYPE_X86 | CPU_TYPE_X86_64 => Some("x86"),
        CPU_TYPE_POWERPC | CPU_TYPE_POWERPC64 => Some("PowerPC"),
        CPU_TYPE_I860 => Some("i860"),
        CPU_TYPE_SPARC => Some("Sparc"),
        CPU_TYPE_ARM => Some("ARM"),
        CPU_TYPE_ARM_64 | CPU_TYPE_ARM64_32 => Some("AARCH64"),
        _ => None,
    }
}

/// Returns the bit size (32 or 64) for the given CPU type.
///
/// Returns `Err` if the CPU type is not recognized.
pub fn cpu_type_bit_size(cpu_type: i32) -> Result<u8, String> {
    match cpu_type {
        CPU_TYPE_ARM
        | CPU_TYPE_SPARC
        | CPU_TYPE_I860
        | CPU_TYPE_POWERPC
        | CPU_TYPE_X86
        | CPU_TYPE_ARM64_32 => Ok(32),
        CPU_TYPE_ARM_64 | CPU_TYPE_POWERPC64 | CPU_TYPE_X86_64 => Ok(64),
        _ => Err(format!(
            "Unrecognized CPU type: 0x{:x}",
            cpu_type as u32
        )),
    }
}

/// Returns a magic string for the given CPU type and subtype.
///
/// For ARM types the string includes the subtype; otherwise just the CPU type.
pub fn cpu_type_magic_string(cpu_type: i32, cpu_subtype: i32) -> String {
    if cpu_type == CPU_TYPE_ARM {
        format!("{}.{}", cpu_type, cpu_subtype)
    } else {
        format!("{}", cpu_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_arch_abi64() {
        assert_eq!(CPU_ARCH_ABI64, 0x0100_0000);
        assert_eq!(CPU_TYPE_POWERPC64, CPU_TYPE_POWERPC | 0x0100_0000);
        assert_eq!(CPU_TYPE_X86_64, CPU_TYPE_X86 | 0x0100_0000);
        assert_eq!(CPU_TYPE_ARM_64, CPU_TYPE_ARM | 0x0100_0000);
    }

    #[test]
    fn test_cpu_type_to_processor() {
        assert_eq!(cpu_type_to_processor(CPU_TYPE_X86), Some("x86"));
        assert_eq!(cpu_type_to_processor(CPU_TYPE_X86_64), Some("x86"));
        assert_eq!(cpu_type_to_processor(CPU_TYPE_POWERPC), Some("PowerPC"));
        assert_eq!(cpu_type_to_processor(CPU_TYPE_ARM), Some("ARM"));
        assert_eq!(cpu_type_to_processor(CPU_TYPE_ARM_64), Some("AARCH64"));
        assert_eq!(cpu_type_to_processor(CPU_TYPE_SPARC), Some("Sparc"));
        assert_eq!(cpu_type_to_processor(CPU_TYPE_I860), Some("i860"));
        assert_eq!(cpu_type_to_processor(0x99), None);
    }

    #[test]
    fn test_cpu_type_bit_size() {
        assert_eq!(cpu_type_bit_size(CPU_TYPE_X86), Ok(32));
        assert_eq!(cpu_type_bit_size(CPU_TYPE_X86_64), Ok(64));
        assert_eq!(cpu_type_bit_size(CPU_TYPE_ARM), Ok(32));
        assert_eq!(cpu_type_bit_size(CPU_TYPE_ARM_64), Ok(64));
        assert_eq!(cpu_type_bit_size(CPU_TYPE_ARM64_32), Ok(32));
        assert!(cpu_type_bit_size(0x99).is_err());
    }

    #[test]
    fn test_intel_subtype_macro() {
        // CPU_SUBTYPE_INTEL(3, 0) = 3
        assert_eq!(CPU_SUBTYPE_I386_ALL, 3);
        // CPU_SUBTYPE_INTEL(4, 8) = 4 + (8 << 4) = 4 + 128 = 132
        assert_eq!(CPU_SUBTYPE_486SX, 132);
    }

    #[test]
    fn test_magic_string() {
        assert_eq!(cpu_type_magic_string(CPU_TYPE_ARM, 9), "12.9");
        assert_eq!(cpu_type_magic_string(CPU_TYPE_X86, 0), "7");
    }
}
