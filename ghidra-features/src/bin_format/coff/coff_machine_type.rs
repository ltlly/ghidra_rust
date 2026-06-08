//! COFF machine types ported from Ghidra's `ghidra.app.util.bin.format.coff.CoffMachineType`.
//!
//! The Machine field has one of the following values that specifies its CPU type.
//! An image file can be run only on the specified machine or on a system that emulates
//! the specified machine.

// TI-specific magic values
/// TI COFF Level 1 magic.
pub const TICOFF1MAGIC: u16 = 0x00c1;
/// TI COFF Level 2 magic.
pub const TICOFF2MAGIC: u16 = 0x00c2;

/// The contents of this field are assumed to be applicable to any machine type.
pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0x0000;
/// Alpha
pub const IMAGE_FILE_MACHINE_ALPHA: u16 = 0x0184;
/// Alpha 64
pub const IMAGE_FILE_MACHINE_ALPHA64: u16 = 0x0284;
/// Matsushita AM33
pub const IMAGE_FILE_MACHINE_AM33: u16 = 0x01d3;
/// x64
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
/// AMD Am29000 big endian
pub const IMAGE_FILE_MACHINE_AM29KBIGMAGIC: u16 = 0x017a;
/// AMD Am29000 little endian
pub const IMAGE_FILE_MACHINE_AM29KLITTLEMAGIC: u16 = 0x017b;
/// ARM little endian
pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
/// ARM64 little endian
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
/// ARM Thumb-2 little endian
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
/// EFI byte code
pub const IMAGE_FILE_MACHINE_EBC: u16 = 0x0ebc;
/// Intel 386 or later processors and compatible processors
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
/// Intel 386 or later processors and compatible processors (PTX)
pub const IMAGE_FILE_MACHINE_I386_PTX: u16 = 0x0154;
/// Intel 386 or later processors and compatible processors (AIX)
pub const IMAGE_FILE_MACHINE_I386_AIX: u16 = 0x0175;
/// Intel i960 with read-only text segment
pub const IMAGE_FILE_MACHINE_I960ROMAGIC: u16 = 0x0160;
/// Intel i960 with read-write text segment
pub const IMAGE_FILE_MACHINE_I960RWMAGIC: u16 = 0x0161;
/// Intel Itanium processor family
pub const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;
/// Mitsubishi M32R little endian
pub const IMAGE_FILE_MACHINE_M32R: u16 = 0x9041;
/// MIPS16
pub const IMAGE_FILE_MACHINE_MIPS16: u16 = 0x0266;
/// MIPS with FPU
pub const IMAGE_FILE_MACHINE_MIPSFPU: u16 = 0x0366;
/// MIPS16 with FPU
pub const IMAGE_FILE_MACHINE_MIPSFPU16: u16 = 0x0466;
/// Motorola 68000
pub const IMAGE_FILE_MACHINE_M68KMAGIC: u16 = 0x0268;
/// Motorola 68000 Apple A/UX (big endian)
pub const IMAGE_FILE_MACHINE_M68KAUX: u16 = 0x0150;
/// PIC-30 (dsPIC30F)
pub const IMAGE_FILE_MACHINE_PIC30: u16 = 0x1236;
/// Power PC little endian
pub const IMAGE_FILE_MACHINE_POWERPC: u16 = 0x01f0;
/// Power PC with floating point support
pub const IMAGE_FILE_MACHINE_POWERPCFP: u16 = 0x01f1;
/// MIPS little endian
pub const IMAGE_FILE_MACHINE_R3000: u16 = 0x0162;
/// MIPS little endian
pub const IMAGE_FILE_MACHINE_R4000: u16 = 0x0166;
/// MIPS little endian
pub const IMAGE_FILE_MACHINE_R10000: u16 = 0x0168;
/// RISC-V 32-bit address space
pub const IMAGE_FILE_MACHINE_RISCV32: u16 = 0x5032;
/// RISC-V 64-bit address space
pub const IMAGE_FILE_MACHINE_RISCV64: u16 = 0x5064;
/// RISC-V 128-bit address space
pub const IMAGE_FILE_MACHINE_RISCV128: u16 = 0x5128;
/// Hitachi SH3
pub const IMAGE_FILE_MACHINE_SH3: u16 = 0x01a2;
/// Hitachi SH3 DSP
pub const IMAGE_FILE_MACHINE_SH3DSP: u16 = 0x01a3;
/// Hitachi SH4
pub const IMAGE_FILE_MACHINE_SH4: u16 = 0x01a6;
/// Hitachi SH5
pub const IMAGE_FILE_MACHINE_SH5: u16 = 0x01a8;
/// Texas Instruments TMS320C3x/4x
pub const IMAGE_FILE_MACHINE_TI_TMS320C3X4X: u16 = 0x0093;
/// Texas Instruments TMS470
pub const IMAGE_FILE_MACHINE_TI_TMS470: u16 = 0x0097;
/// Texas Instruments TMS320C5400
pub const IMAGE_FILE_MACHINE_TI_TMS320C5400: u16 = 0x0098;
/// Texas Instruments TMS320C6000
pub const IMAGE_FILE_MACHINE_TI_TMS320C6000: u16 = 0x0099;
/// Texas Instruments TMS320C5500
pub const IMAGE_FILE_MACHINE_TI_TMS320C5500: u16 = 0x009c;
/// Texas Instruments TMS320C2800
pub const IMAGE_FILE_MACHINE_TI_TMS320C2800: u16 = 0x009d;
/// Texas Instruments MSP430
pub const IMAGE_FILE_MACHINE_TI_MSP430: u16 = 0x00a0;
/// Texas Instruments TMS320C5500+
pub const IMAGE_FILE_MACHINE_TI_TMS320C5500_PLUS: u16 = 0x00a1;
/// Thumb
pub const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01c2;
/// MIPS little-endian WCE v2
pub const IMAGE_FILE_MACHINE_WCEMIPSV2: u16 = 0x0169;

/// All known COFF machine types (excluding UNKNOWN).
const KNOWN_MACHINE_TYPES: &[u16] = &[
    IMAGE_FILE_MACHINE_ALPHA,
    IMAGE_FILE_MACHINE_ALPHA64,
    IMAGE_FILE_MACHINE_AM33,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_AM29KBIGMAGIC,
    IMAGE_FILE_MACHINE_AM29KLITTLEMAGIC,
    IMAGE_FILE_MACHINE_ARM,
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_ARMNT,
    IMAGE_FILE_MACHINE_EBC,
    IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_MACHINE_I386_PTX,
    IMAGE_FILE_MACHINE_I386_AIX,
    IMAGE_FILE_MACHINE_I960ROMAGIC,
    IMAGE_FILE_MACHINE_I960RWMAGIC,
    IMAGE_FILE_MACHINE_IA64,
    IMAGE_FILE_MACHINE_M32R,
    IMAGE_FILE_MACHINE_MIPS16,
    IMAGE_FILE_MACHINE_MIPSFPU,
    IMAGE_FILE_MACHINE_MIPSFPU16,
    IMAGE_FILE_MACHINE_M68KMAGIC,
    IMAGE_FILE_MACHINE_M68KAUX,
    IMAGE_FILE_MACHINE_PIC30,
    IMAGE_FILE_MACHINE_POWERPC,
    IMAGE_FILE_MACHINE_POWERPCFP,
    IMAGE_FILE_MACHINE_R3000,
    IMAGE_FILE_MACHINE_R4000,
    IMAGE_FILE_MACHINE_R10000,
    IMAGE_FILE_MACHINE_RISCV32,
    IMAGE_FILE_MACHINE_RISCV64,
    IMAGE_FILE_MACHINE_RISCV128,
    IMAGE_FILE_MACHINE_SH3,
    IMAGE_FILE_MACHINE_SH3DSP,
    IMAGE_FILE_MACHINE_SH4,
    IMAGE_FILE_MACHINE_SH5,
    IMAGE_FILE_MACHINE_TI_TMS320C3X4X,
    IMAGE_FILE_MACHINE_TI_TMS470,
    IMAGE_FILE_MACHINE_TI_TMS320C5400,
    IMAGE_FILE_MACHINE_TI_TMS320C6000,
    IMAGE_FILE_MACHINE_TI_TMS320C5500,
    IMAGE_FILE_MACHINE_TI_TMS320C2800,
    IMAGE_FILE_MACHINE_TI_MSP430,
    IMAGE_FILE_MACHINE_TI_TMS320C5500_PLUS,
    IMAGE_FILE_MACHINE_THUMB,
    IMAGE_FILE_MACHINE_WCEMIPSV2,
];

/// Returns true if the given machine type is a recognized COFF machine type.
///
/// `IMAGE_FILE_MACHINE_UNKNOWN` is not considered a valid type for this check.
/// Ported from `CoffMachineType.isMachineTypeDefined()`.
pub fn is_machine_type_defined(machine_type: u16) -> bool {
    if machine_type == IMAGE_FILE_MACHINE_UNKNOWN {
        return false;
    }
    KNOWN_MACHINE_TYPES.contains(&machine_type)
}

/// Returns true if the magic value indicates a TI COFF Level 1 or Level 2 file.
pub fn is_ticoff(magic: u16) -> bool {
    magic == TICOFF1MAGIC || magic == TICOFF2MAGIC
}

/// Returns a human-readable name for the given machine type, if known.
pub fn machine_type_name(machine_type: u16) -> Option<&'static str> {
    match machine_type {
        IMAGE_FILE_MACHINE_UNKNOWN => Some("Unknown"),
        IMAGE_FILE_MACHINE_ALPHA => Some("Alpha"),
        IMAGE_FILE_MACHINE_ALPHA64 => Some("Alpha 64"),
        IMAGE_FILE_MACHINE_AM33 => Some("Matsushita AM33"),
        IMAGE_FILE_MACHINE_AMD64 => Some("x64 (AMD64)"),
        IMAGE_FILE_MACHINE_AM29KBIGMAGIC => Some("AMD Am29000 (big endian)"),
        IMAGE_FILE_MACHINE_AM29KLITTLEMAGIC => Some("AMD Am29000 (little endian)"),
        IMAGE_FILE_MACHINE_ARM => Some("ARM"),
        IMAGE_FILE_MACHINE_ARM64 => Some("ARM64"),
        IMAGE_FILE_MACHINE_ARMNT => Some("ARM Thumb-2"),
        IMAGE_FILE_MACHINE_EBC => Some("EFI Byte Code"),
        IMAGE_FILE_MACHINE_I386 => Some("Intel 386"),
        IMAGE_FILE_MACHINE_I386_PTX => Some("Intel 386 (PTX)"),
        IMAGE_FILE_MACHINE_I386_AIX => Some("Intel 386 (AIX)"),
        IMAGE_FILE_MACHINE_I960ROMAGIC => Some("Intel i960 (RO)"),
        IMAGE_FILE_MACHINE_I960RWMAGIC => Some("Intel i960 (RW)"),
        IMAGE_FILE_MACHINE_IA64 => Some("Intel Itanium"),
        IMAGE_FILE_MACHINE_M32R => Some("Mitsubishi M32R"),
        IMAGE_FILE_MACHINE_MIPS16 => Some("MIPS16"),
        IMAGE_FILE_MACHINE_MIPSFPU => Some("MIPS with FPU"),
        IMAGE_FILE_MACHINE_MIPSFPU16 => Some("MIPS16 with FPU"),
        IMAGE_FILE_MACHINE_M68KMAGIC => Some("Motorola 68000"),
        IMAGE_FILE_MACHINE_M68KAUX => Some("Motorola 68000 (A/UX)"),
        IMAGE_FILE_MACHINE_PIC30 => Some("PIC-30 (dsPIC30F)"),
        IMAGE_FILE_MACHINE_POWERPC => Some("PowerPC"),
        IMAGE_FILE_MACHINE_POWERPCFP => Some("PowerPC with FPU"),
        IMAGE_FILE_MACHINE_R3000 => Some("MIPS R3000"),
        IMAGE_FILE_MACHINE_R4000 => Some("MIPS R4000"),
        IMAGE_FILE_MACHINE_R10000 => Some("MIPS R10000"),
        IMAGE_FILE_MACHINE_RISCV32 => Some("RISC-V 32"),
        IMAGE_FILE_MACHINE_RISCV64 => Some("RISC-V 64"),
        IMAGE_FILE_MACHINE_RISCV128 => Some("RISC-V 128"),
        IMAGE_FILE_MACHINE_SH3 => Some("Hitachi SH3"),
        IMAGE_FILE_MACHINE_SH3DSP => Some("Hitachi SH3 DSP"),
        IMAGE_FILE_MACHINE_SH4 => Some("Hitachi SH4"),
        IMAGE_FILE_MACHINE_SH5 => Some("Hitachi SH5"),
        IMAGE_FILE_MACHINE_TI_TMS320C3X4X => Some("TI TMS320C3x/4x"),
        IMAGE_FILE_MACHINE_TI_TMS470 => Some("TI TMS470"),
        IMAGE_FILE_MACHINE_TI_TMS320C5400 => Some("TI TMS320C5400"),
        IMAGE_FILE_MACHINE_TI_TMS320C6000 => Some("TI TMS320C6000"),
        IMAGE_FILE_MACHINE_TI_TMS320C5500 => Some("TI TMS320C5500"),
        IMAGE_FILE_MACHINE_TI_TMS320C2800 => Some("TI TMS320C2800"),
        IMAGE_FILE_MACHINE_TI_MSP430 => Some("TI MSP430"),
        IMAGE_FILE_MACHINE_TI_TMS320C5500_PLUS => Some("TI TMS320C5500+"),
        IMAGE_FILE_MACHINE_THUMB => Some("Thumb"),
        IMAGE_FILE_MACHINE_WCEMIPSV2 => Some("MIPS (WCE v2)"),
        TICOFF1MAGIC => Some("TI COFF Level 1"),
        TICOFF2MAGIC => Some("TI COFF Level 2"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_machine_type_defined() {
        assert!(is_machine_type_defined(IMAGE_FILE_MACHINE_I386));
        assert!(is_machine_type_defined(IMAGE_FILE_MACHINE_AMD64));
        assert!(is_machine_type_defined(IMAGE_FILE_MACHINE_ARM64));
        assert!(!is_machine_type_defined(IMAGE_FILE_MACHINE_UNKNOWN));
        assert!(!is_machine_type_defined(0xFFFF));
    }

    #[test]
    fn test_is_ticoff() {
        assert!(is_ticoff(TICOFF1MAGIC));
        assert!(is_ticoff(TICOFF2MAGIC));
        assert!(!is_ticoff(IMAGE_FILE_MACHINE_I386));
    }

    #[test]
    fn test_machine_type_name() {
        assert_eq!(machine_type_name(IMAGE_FILE_MACHINE_I386), Some("Intel 386"));
        assert_eq!(machine_type_name(IMAGE_FILE_MACHINE_AMD64), Some("x64 (AMD64)"));
        assert_eq!(machine_type_name(0xFFFF), None);
    }
}
