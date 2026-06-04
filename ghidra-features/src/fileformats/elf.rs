//! ELF (Executable and Linkable Format) parser.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.elf` package.
//! Provides complete parsing of ELF32/ELF64, LE/BE, including:
//! - ELF header, program headers, section headers
//! - Symbol tables (SYMTAB, DYNSYM)
//! - Relocations (REL, RELA)
//! - Dynamic section
//! - GNU hash and SYSV hash tables
//! - Note sections (NT_GNU_BUILD_ID, NT_GNU_GOLD_VERSION)
//! - GOT/PLT stub detection
//! - String table extraction
//! - All standard ELF constants
//!
//! References:
//! - ELF Specification v1.2 (TIS)
//! - System V ABI: <http://www.sco.com/developers/gabi/>
//! - Linux Standard Base: <https://refspecs.linuxfoundation.org/elf/>
//! - x86-64 ABI: <https://gitlab.com/x86-psABIs/x86-64-ABI>

use nom::bytes::complete::take;
use nom::IResult;
use std::fmt;
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════════════════
// Magic & Identification Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// ELF magic bytes: `0x7f 'E' 'L' 'F'`
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF identification indices (e_ident[]).
pub const EI_MAG0: usize = 0;
pub const EI_MAG1: usize = 1;
pub const EI_MAG2: usize = 2;
pub const EI_MAG3: usize = 3;
pub const EI_CLASS: usize = 4;
pub const EI_DATA: usize = 5;
pub const EI_VERSION: usize = 6;
pub const EI_OSABI: usize = 7;
pub const EI_ABIVERSION: usize = 8;
pub const EI_PAD: usize = 9;
pub const EI_NIDENT: usize = 16;

/// ELF class constants (EI_CLASS).
pub const ELFCLASSNONE: u8 = 0;
pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;

/// ELF data encoding constants (EI_DATA).
pub const ELFDATANONE: u8 = 0;
pub const ELFDATA2LSB: u8 = 1;
pub const ELFDATA2MSB: u8 = 2;

/// ELF version constants (EI_VERSION, e_version).
pub const EV_NONE: u8 = 0;
pub const EV_CURRENT: u8 = 1;

// ═══════════════════════════════════════════════════════════════════════════════════
// ELF Class & Data Encoding
// ═══════════════════════════════════════════════════════════════════════════════════

/// ELF class (32-bit or 64-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfClass {
    /// 32-bit ELF (ELFCLASS32)
    ELF32,
    /// 64-bit ELF (ELFCLASS64)
    ELF64,
}

impl ElfClass {
    /// Parse from the EI_CLASS byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            ELFCLASS32 => Some(ElfClass::ELF32),
            ELFCLASS64 => Some(ElfClass::ELF64),
            _ => None,
        }
    }

    /// Return the size of an address in bytes (4 for 32-bit, 8 for 64-bit).
    pub fn addr_size(&self) -> usize {
        match self {
            ElfClass::ELF32 => 4,
            ElfClass::ELF64 => 8,
        }
    }
}

impl fmt::Display for ElfClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfClass::ELF32 => write!(f, "ELF32"),
            ElfClass::ELF64 => write!(f, "ELF64"),
        }
    }
}

/// ELF data encoding (endianness).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfData {
    /// Invalid/unknown encoding.
    None,
    /// Little-endian (ELFDATA2LSB).
    LittleEndian,
    /// Big-endian (ELFDATA2MSB).
    BigEndian,
}

impl ElfData {
    /// Parse from the EI_DATA byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            ELFDATANONE => Some(ElfData::None),
            ELFDATA2LSB => Some(ElfData::LittleEndian),
            ELFDATA2MSB => Some(ElfData::BigEndian),
            _ => None,
        }
    }

    /// Returns true if little-endian.
    pub fn is_le(&self) -> bool {
        matches!(self, ElfData::LittleEndian)
    }

    /// Returns true if big-endian.
    pub fn is_be(&self) -> bool {
        matches!(self, ElfData::BigEndian)
    }
}

impl fmt::Display for ElfData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfData::None => write!(f, "NONE"),
            ElfData::LittleEndian => write!(f, "2's complement, little-endian"),
            ElfData::BigEndian => write!(f, "2's complement, big-endian"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ELF OS/ABI Constants (EI_OSABI)
// ═══════════════════════════════════════════════════════════════════════════════════

pub const ELFOSABI_NONE: u8 = 0;
pub const ELFOSABI_SYSV: u8 = 0;
pub const ELFOSABI_HPUX: u8 = 1;
pub const ELFOSABI_NETBSD: u8 = 2;
pub const ELFOSABI_GNU: u8 = 3;
pub const ELFOSABI_LINUX: u8 = 3;
pub const ELFOSABI_SOLARIS: u8 = 6;
pub const ELFOSABI_AIX: u8 = 7;
pub const ELFOSABI_IRIX: u8 = 8;
pub const ELFOSABI_FREEBSD: u8 = 9;
pub const ELFOSABI_TRU64: u8 = 10;
pub const ELFOSABI_MODESTO: u8 = 11;
pub const ELFOSABI_OPENBSD: u8 = 12;
pub const ELFOSABI_ARM_AEABI: u8 = 64;
pub const ELFOSABI_ARM: u8 = 97;
pub const ELFOSABI_STANDALONE: u8 = 255;

/// Return a human-readable name for an OS/ABI value.
pub fn osabi_name(osabi: u8) -> &'static str {
    match osabi {
        ELFOSABI_NONE => "UNIX System V",
        ELFOSABI_HPUX => "HP-UX",
        ELFOSABI_NETBSD => "NetBSD",
        ELFOSABI_GNU => "GNU/Linux",
        ELFOSABI_SOLARIS => "Sun Solaris",
        ELFOSABI_AIX => "AIX",
        ELFOSABI_IRIX => "IRIX",
        ELFOSABI_FREEBSD => "FreeBSD",
        ELFOSABI_TRU64 => "TRU64",
        ELFOSABI_MODESTO => "Novell Modesto",
        ELFOSABI_OPENBSD => "OpenBSD",
        ELFOSABI_ARM_AEABI => "ARM EABI",
        ELFOSABI_ARM => "ARM",
        ELFOSABI_STANDALONE => "Standalone (embedded)",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// e_type (Object File Type) Constants
// ═══════════════════════════════════════════════════════════════════════════════════

pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;
pub const ET_LOOS: u16 = 0xFE00;
pub const ET_HIOS: u16 = 0xFEFF;
pub const ET_LOPROC: u16 = 0xFF00;
pub const ET_HIPROC: u16 = 0xFFFF;

/// Return a human-readable name for an ELF file type.
pub fn etype_name(etype: u16) -> &'static str {
    match etype {
        ET_NONE => "NONE (No file type)",
        ET_REL => "REL (Relocatable file)",
        ET_EXEC => "EXEC (Executable file)",
        ET_DYN => "DYN (Shared object file)",
        ET_CORE => "CORE (Core file)",
        _ if etype >= ET_LOOS && etype <= ET_HIOS => "OS-specific",
        _ if etype >= ET_LOPROC && etype <= ET_HIPROC => "Processor-specific",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// e_machine (Machine/Architecture) Constants
// ═══════════════════════════════════════════════════════════════════════════════════

pub const EM_NONE: u16 = 0;
pub const EM_M32: u16 = 1;
pub const EM_SPARC: u16 = 2;
pub const EM_386: u16 = 3;
pub const EM_68K: u16 = 4;
pub const EM_88K: u16 = 5;
pub const EM_IAMCU: u16 = 6;
pub const EM_860: u16 = 7;
pub const EM_MIPS: u16 = 8;
pub const EM_S370: u16 = 9;
pub const EM_MIPS_RS3_LE: u16 = 10;
pub const EM_PARISC: u16 = 15;
pub const EM_VPP500: u16 = 17;
pub const EM_SPARC32PLUS: u16 = 18;
pub const EM_960: u16 = 19;
pub const EM_PPC: u16 = 20;
pub const EM_PPC64: u16 = 21;
pub const EM_S390: u16 = 22;
pub const EM_SPU: u16 = 23;
pub const EM_V800: u16 = 36;
pub const EM_FR20: u16 = 37;
pub const EM_RH32: u16 = 38;
pub const EM_RCE: u16 = 39;
pub const EM_ARM: u16 = 40;
pub const EM_FAKE_ALPHA: u16 = 41;
pub const EM_SH: u16 = 42;
pub const EM_SPARCV9: u16 = 43;
pub const EM_TRICORE: u16 = 44;
pub const EM_ARC: u16 = 45;
pub const EM_H8_300: u16 = 46;
pub const EM_H8_300H: u16 = 47;
pub const EM_H8S: u16 = 48;
pub const EM_H8_500: u16 = 49;
pub const EM_IA_64: u16 = 50;
pub const EM_MIPS_X: u16 = 51;
pub const EM_COLDFIRE: u16 = 52;
pub const EM_68HC12: u16 = 53;
pub const EM_MMA: u16 = 54;
pub const EM_PCP: u16 = 55;
pub const EM_NCPU: u16 = 56;
pub const EM_NDR1: u16 = 57;
pub const EM_STARCORE: u16 = 58;
pub const EM_ME16: u16 = 59;
pub const EM_ST100: u16 = 60;
pub const EM_TINYJ: u16 = 61;
pub const EM_X86_64: u16 = 62;
pub const EM_PDSP: u16 = 63;
pub const EM_PDP10: u16 = 64;
pub const EM_PDP11: u16 = 65;
pub const EM_FX66: u16 = 66;
pub const EM_ST9PLUS: u16 = 67;
pub const EM_ST7: u16 = 68;
pub const EM_68HC16: u16 = 69;
pub const EM_68HC11: u16 = 70;
pub const EM_68HC08: u16 = 71;
pub const EM_68HC05: u16 = 72;
pub const EM_SVX: u16 = 73;
pub const EM_ST19: u16 = 74;
pub const EM_VAX: u16 = 75;
pub const EM_CRIS: u16 = 76;
pub const EM_JAVELIN: u16 = 77;
pub const EM_FIREPATH: u16 = 78;
pub const EM_ZSP: u16 = 79;
pub const EM_MMIX: u16 = 80;
pub const EM_HUANY: u16 = 81;
pub const EM_PRISM: u16 = 82;
pub const EM_AVR: u16 = 83;
pub const EM_FR30: u16 = 84;
pub const EM_D10V: u16 = 85;
pub const EM_D30V: u16 = 86;
pub const EM_V850: u16 = 87;
pub const EM_M32R: u16 = 88;
pub const EM_MN10300: u16 = 89;
pub const EM_MN10200: u16 = 90;
pub const EM_PJ: u16 = 91;
pub const EM_OPENRISC: u16 = 92;
pub const EM_ARC_COMPACT: u16 = 93;
pub const EM_XTENSA: u16 = 94;
pub const EM_VIDEOCORE: u16 = 95;
pub const EM_TMM_GPP: u16 = 96;
pub const EM_NS32K: u16 = 97;
pub const EM_TPC: u16 = 98;
pub const EM_SNP1K: u16 = 99;
pub const EM_ST200: u16 = 100;
pub const EM_IP2K: u16 = 101;
pub const EM_MAX: u16 = 102;
pub const EM_CR: u16 = 103;
pub const EM_F2MC16: u16 = 104;
pub const EM_MSP430: u16 = 105;
pub const EM_BLACKFIN: u16 = 106;
pub const EM_SE_C33: u16 = 107;
pub const EM_SEP: u16 = 108;
pub const EM_ARCA: u16 = 109;
pub const EM_UNICORE: u16 = 110;
pub const EM_EXCESS: u16 = 111;
pub const EM_DXP: u16 = 112;
pub const EM_ALTERA_NIOS2: u16 = 113;
pub const EM_CRX: u16 = 114;
pub const EM_XGATE: u16 = 115;
pub const EM_C166: u16 = 116;
pub const EM_M16C: u16 = 117;
pub const EM_DSPIC30F: u16 = 118;
pub const EM_CE: u16 = 119;
pub const EM_M32C: u16 = 120;
pub const EM_TSK3000: u16 = 131;
pub const EM_RS08: u16 = 132;
pub const EM_SHARC: u16 = 133;
pub const EM_ECOG2: u16 = 134;
pub const EM_SCORE7: u16 = 135;
pub const EM_DSP24: u16 = 136;
pub const EM_VIDEOCORE3: u16 = 137;
pub const EM_LATTICEMICO32: u16 = 138;
pub const EM_SE_C17: u16 = 139;
pub const EM_TI_C6000: u16 = 140;
pub const EM_TI_C2000: u16 = 141;
pub const EM_TI_C5500: u16 = 142;
pub const EM_TI_ARP32: u16 = 143;
pub const EM_TI_PRU: u16 = 144;
pub const EM_MMDSP_PLUS: u16 = 160;
pub const EM_CYPRESS_M8C: u16 = 161;
pub const EM_R32C: u16 = 162;
pub const EM_TRIMEDIA: u16 = 163;
pub const EM_QDSP6: u16 = 164;
pub const EM_8051: u16 = 165;
pub const EM_STXP7X: u16 = 166;
pub const EM_NDS32: u16 = 167;
pub const EM_ECOG1X: u16 = 168;
pub const EM_MAXQ30: u16 = 169;
pub const EM_XIMO16: u16 = 170;
pub const EM_MANIK: u16 = 171;
pub const EM_CRAYNV2: u16 = 172;
pub const EM_RX: u16 = 173;
pub const EM_METAG: u16 = 174;
pub const EM_MCST_ELBRUS: u16 = 175;
pub const EM_ECOG16: u16 = 176;
pub const EM_CR16: u16 = 177;
pub const EM_ETPU: u16 = 178;
pub const EM_SLE9X: u16 = 179;
pub const EM_L10M: u16 = 180;
pub const EM_K10M: u16 = 181;
pub const EM_AARCH64: u16 = 183;
pub const EM_AVR32: u16 = 185;
pub const EM_STM8: u16 = 186;
pub const EM_TILE64: u16 = 187;
pub const EM_TILEPRO: u16 = 188;
pub const EM_MICROBLAZE: u16 = 189;
pub const EM_CUDA: u16 = 190;
pub const EM_TILEGX: u16 = 191;
pub const EM_CLOUDSHIELD: u16 = 192;
pub const EM_COREA_1ST: u16 = 193;
pub const EM_COREA_2ND: u16 = 194;
pub const EM_ARC_COMPACT2: u16 = 195;
pub const EM_OPEN8: u16 = 196;
pub const EM_RL78: u16 = 197;
pub const EM_VIDEOCORE5: u16 = 198;
pub const EM_78KOR: u16 = 199;
pub const EM_56800EX: u16 = 200;
pub const EM_BA1: u16 = 201;
pub const EM_BA2: u16 = 202;
pub const EM_XCORE: u16 = 203;
pub const EM_MCHP_PIC: u16 = 204;
pub const EM_KM32: u16 = 210;
pub const EM_KMX32: u16 = 211;
pub const EM_EMX16: u16 = 212;
pub const EM_EMX8: u16 = 213;
pub const EM_KVARC: u16 = 214;
pub const EM_CDP: u16 = 215;
pub const EM_COGE: u16 = 216;
pub const EM_COOL: u16 = 217;
pub const EM_NORC: u16 = 218;
pub const EM_CSR_KALIMBA: u16 = 219;
pub const EM_Z80: u16 = 220;
pub const EM_VISIUM: u16 = 221;
pub const EM_FT32: u16 = 222;
pub const EM_MOXIE: u16 = 223;
pub const EM_AMDGPU: u16 = 224;
pub const EM_RISCV: u16 = 243;
pub const EM_BPF: u16 = 247;
pub const EM_CSKY: u16 = 252;
pub const EM_LOONGARCH: u16 = 258;
pub const EM_FRV: u16 = 0x5441;

/// Return a human-readable name for a machine type.
pub fn machine_name(machine: u16) -> &'static str {
    match machine {
        EM_NONE => "NONE",
        EM_M32 => "AT&T WE 32100",
        EM_SPARC => "SPARC",
        EM_386 => "Intel 80386",
        EM_68K => "Motorola 68000",
        EM_88K => "Motorola 88000",
        EM_IAMCU => "Intel MCU",
        EM_860 => "Intel 80860",
        EM_MIPS => "MIPS I",
        EM_S370 => "IBM System/370",
        EM_MIPS_RS3_LE => "MIPS RS3000 LE",
        EM_PARISC => "HP PA-RISC",
        EM_VPP500 => "Fujitsu VPP500",
        EM_SPARC32PLUS => "SPARC v8+",
        EM_960 => "Intel 80960",
        EM_PPC => "PowerPC",
        EM_PPC64 => "PowerPC 64-bit",
        EM_S390 => "IBM S/390",
        EM_SPU => "SPU",
        EM_V800 => "NEC V800",
        EM_FR20 => "Fujitsu FR20",
        EM_RH32 => "TRW RH-32",
        EM_RCE => "Motorola RCE",
        EM_ARM => "ARM",
        EM_FAKE_ALPHA => "Digital Alpha (fake)",
        EM_SH => "Hitachi SH",
        EM_SPARCV9 => "SPARC v9",
        EM_TRICORE => "Siemens TriCore",
        EM_ARC => "Argonaut RISC Core",
        EM_H8_300 => "Hitachi H8/300",
        EM_H8_300H => "Hitachi H8/300H",
        EM_H8S => "Hitachi H8S",
        EM_H8_500 => "Hitachi H8/500",
        EM_IA_64 => "Intel IA-64",
        EM_MIPS_X => "Stanford MIPS-X",
        EM_COLDFIRE => "Motorola ColdFire",
        EM_68HC12 => "Motorola M68HC12",
        EM_MMA => "Fujitsu MMA",
        EM_PCP => "Siemens PCP",
        EM_NCPU => "Sony nCPU",
        EM_NDR1 => "Denso NDR1",
        EM_STARCORE => "Motorola Star*Core",
        EM_ME16 => "Toyota ME16",
        EM_ST100 => "ST100",
        EM_TINYJ => "TinyJ",
        EM_X86_64 => "x86-64",
        EM_AARCH64 => "AArch64",
        EM_AVR => "Atmel AVR",
        EM_MSP430 => "TI MSP430",
        EM_BLACKFIN => "Analog Devices Blackfin",
        EM_M32R => "Mitsubishi M32R",
        EM_RISCV => "RISC-V",
        EM_BPF => "Linux BPF",
        EM_CSKY => "C-SKY",
        EM_LOONGARCH => "LoongArch",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Program Header: p_type Constants
// ═══════════════════════════════════════════════════════════════════════════════════

pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_LOOS: u32 = 0x60000000;
pub const PT_HIOS: u32 = 0x6FFFFFFF;
pub const PT_LOPROC: u32 = 0x70000000;
pub const PT_HIPROC: u32 = 0x7FFFFFFF;

// GNU extensions
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
pub const PT_GNU_STACK: u32 = 0x6474e551;
pub const PT_GNU_RELRO: u32 = 0x6474e552;
pub const PT_GNU_PROPERTY: u32 = 0x6474e553;

// ARM extensions
pub const PT_ARM_ARCHEXT: u32 = 0x70000000;
pub const PT_ARM_EXIDX: u32 = 0x70000001;

/// Return a human-readable name for a segment type.
pub fn segment_type_name(ptype: u32) -> &'static str {
    match ptype {
        PT_NULL => "NULL",
        PT_LOAD => "LOAD",
        PT_DYNAMIC => "DYNAMIC",
        PT_INTERP => "INTERP",
        PT_NOTE => "NOTE",
        PT_SHLIB => "SHLIB",
        PT_PHDR => "PHDR",
        PT_TLS => "TLS",
        PT_GNU_EH_FRAME => "GNU_EH_FRAME",
        PT_GNU_STACK => "GNU_STACK",
        PT_GNU_RELRO => "GNU_RELRO",
        PT_GNU_PROPERTY => "GNU_PROPERTY",
        PT_ARM_EXIDX => "ARM_EXIDX",
        _ if ptype >= PT_LOOS && ptype <= PT_HIOS => "OS-specific",
        _ if ptype >= PT_LOPROC && ptype <= PT_HIPROC => "Processor-specific",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Program Header: p_flags Constants
// ═══════════════════════════════════════════════════════════════════════════════════

pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;
pub const PF_MASKOS: u32 = 0x0FF00000;
pub const PF_MASKPROC: u32 = 0xF0000000;

/// Format p_flags as a human-readable string (e.g., "RWX").
pub fn flags_to_string(flags: u32) -> String {
    let mut s = String::with_capacity(3);
    if flags & PF_R != 0 { s.push('R'); }
    if flags & PF_W != 0 { s.push('W'); }
    if flags & PF_X != 0 { s.push('E'); }
    s
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Section Header: sh_type Constants
// ═══════════════════════════════════════════════════════════════════════════════════

pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_SHLIB: u32 = 10;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;
pub const SHT_PREINIT_ARRAY: u32 = 16;
pub const SHT_GROUP: u32 = 17;
pub const SHT_SYMTAB_SHNDX: u32 = 18;
pub const SHT_LOOS: u32 = 0x60000000;
pub const SHT_HIOS: u32 = 0x6FFFFFFF;
pub const SHT_LOPROC: u32 = 0x70000000;
pub const SHT_HIPROC: u32 = 0x7FFFFFFF;
pub const SHT_LOUSER: u32 = 0x80000000;
pub const SHT_HIUSER: u32 = 0xFFFFFFFF;

// GNU extensions
pub const SHT_GNU_HASH: u32 = 0x6ffffff6;
pub const SHT_GNU_LIBLIST: u32 = 0x6ffffff7;
pub const SHT_CHECKSUM: u32 = 0x6ffffff8;
pub const SHT_GNU_ATTRIBUTES: u32 = 0x6ffffff5;
pub const SHT_GNU_VERDEF: u32 = 0x6ffffffd;
pub const SHT_GNU_VERNEED: u32 = 0x6ffffffe;
pub const SHT_GNU_VERSYM: u32 = 0x6fffffff;

/// Return a human-readable name for a section type.
pub fn section_type_name(shtype: u32) -> &'static str {
    match shtype {
        SHT_NULL => "NULL",
        SHT_PROGBITS => "PROGBITS",
        SHT_SYMTAB => "SYMTAB",
        SHT_STRTAB => "STRTAB",
        SHT_RELA => "RELA",
        SHT_HASH => "HASH",
        SHT_DYNAMIC => "DYNAMIC",
        SHT_NOTE => "NOTE",
        SHT_NOBITS => "NOBITS",
        SHT_REL => "REL",
        SHT_SHLIB => "SHLIB",
        SHT_DYNSYM => "DYNSYM",
        SHT_INIT_ARRAY => "INIT_ARRAY",
        SHT_FINI_ARRAY => "FINI_ARRAY",
        SHT_PREINIT_ARRAY => "PREINIT_ARRAY",
        SHT_GROUP => "GROUP",
        SHT_SYMTAB_SHNDX => "SYMTAB_SHNDX",
        SHT_GNU_HASH => "GNU_HASH",
        SHT_GNU_LIBLIST => "GNU_LIBLIST",
        SHT_CHECKSUM => "CHECKSUM",
        SHT_GNU_ATTRIBUTES => "GNU_ATTRIBUTES",
        SHT_GNU_VERDEF => "GNU_verdef",
        SHT_GNU_VERNEED => "GNU_verneed",
        SHT_GNU_VERSYM => "GNU_versym",
        _ if shtype >= SHT_LOOS && shtype <= SHT_HIOS => "OS-specific",
        _ if shtype >= SHT_LOPROC && shtype <= SHT_HIPROC => "Processor-specific",
        _ if shtype >= SHT_LOUSER && shtype <= SHT_HIUSER => "User-specific",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Section Header: sh_flags Constants
// ═══════════════════════════════════════════════════════════════════════════════════

pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_MERGE: u64 = 0x10;
pub const SHF_STRINGS: u64 = 0x20;
pub const SHF_INFO_LINK: u64 = 0x40;
pub const SHF_LINK_ORDER: u64 = 0x80;
pub const SHF_OS_NONCONFORMING: u64 = 0x100;
pub const SHF_GROUP: u64 = 0x200;
pub const SHF_TLS: u64 = 0x400;
pub const SHF_COMPRESSED: u64 = 0x800;
pub const SHF_MASKOS: u64 = 0x0FF00000;
pub const SHF_MASKPROC: u64 = 0xF0000000;
pub const SHF_GNU_RETAIN: u64 = 0x200000;
pub const SHF_GNU_MBIND: u64 = 0x1000000;

// ═══════════════════════════════════════════════════════════════════════════════════
// Special Section Indices (st_shndx)
// ═══════════════════════════════════════════════════════════════════════════════════

pub const SHN_UNDEF: u16 = 0;
pub const SHN_LORESERVE: u16 = 0xFF00;
pub const SHN_LOPROC: u16 = 0xFF00;
pub const SHN_HIPROC: u16 = 0xFF1F;
pub const SHN_LOOS: u16 = 0xFF20;
pub const SHN_HIOS: u16 = 0xFF3F;
pub const SHN_ABS: u16 = 0xFFF1;
pub const SHN_COMMON: u16 = 0xFFF2;
pub const SHN_XINDEX: u16 = 0xFFFF;
pub const SHN_HIRESERVE: u16 = 0xFFFF;

/// Return a human-readable name for a special section index.
pub fn shndx_name(shndx: u16) -> &'static str {
    match shndx {
        SHN_UNDEF => "UNDEF",
        SHN_ABS => "ABS",
        SHN_COMMON => "COMMON",
        SHN_XINDEX => "XINDEX",
        _ => "NORMAL",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Symbol Binding (extracted from st_info)
// ═══════════════════════════════════════════════════════════════════════════════════

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const STB_LOOS: u8 = 10;
pub const STB_HIOS: u8 = 12;
pub const STB_LOPROC: u8 = 13;
pub const STB_HIPROC: u8 = 15;
pub const STB_GNU_UNIQUE: u8 = 10;

/// Extract the symbol binding from an st_info byte.
pub fn st_bind(info: u8) -> u8 {
    info >> 4
}

/// Return a human-readable name for a symbol binding.
pub fn bind_name(bind: u8) -> &'static str {
    match bind {
        STB_LOCAL => "LOCAL",
        STB_GLOBAL => "GLOBAL",
        STB_WEAK => "WEAK",
        STB_GNU_UNIQUE => "GNU_UNIQUE",
        _ if bind >= STB_LOOS && bind <= STB_HIOS => "OS-specific",
        _ if bind >= STB_LOPROC && bind <= STB_HIPROC => "Processor-specific",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Symbol Type (extracted from st_info)
// ═══════════════════════════════════════════════════════════════════════════════════

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;
pub const STT_LOOS: u8 = 10;
pub const STT_HIOS: u8 = 12;
pub const STT_LOPROC: u8 = 13;
pub const STT_HIPROC: u8 = 15;
pub const STT_GNU_IFUNC: u8 = 10;

/// Extract the symbol type from an st_info byte.
pub fn st_type(info: u8) -> u8 {
    info & 0x0f
}

/// Return a human-readable name for a symbol type.
pub fn type_name(stype: u8) -> &'static str {
    match stype {
        STT_NOTYPE => "NOTYPE",
        STT_OBJECT => "OBJECT",
        STT_FUNC => "FUNC",
        STT_SECTION => "SECTION",
        STT_FILE => "FILE",
        STT_COMMON => "COMMON",
        STT_TLS => "TLS",
        STT_GNU_IFUNC => "GNU_IFUNC",
        _ if stype >= STT_LOOS && stype <= STT_HIOS => "OS-specific",
        _ if stype >= STT_LOPROC && stype <= STT_HIPROC => "Processor-specific",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Symbol Visibility (extracted from st_other)
// ═══════════════════════════════════════════════════════════════════════════════════

pub const STV_DEFAULT: u8 = 0;
pub const STV_INTERNAL: u8 = 1;
pub const STV_HIDDEN: u8 = 2;
pub const STV_PROTECTED: u8 = 3;

/// Extract the symbol visibility from st_other.
pub fn st_visibility(other: u8) -> u8 {
    other & 0x3
}

/// Return a human-readable name for a symbol visibility.
pub fn visibility_name(vis: u8) -> &'static str {
    match vis {
        STV_DEFAULT => "DEFAULT",
        STV_INTERNAL => "INTERNAL",
        STV_HIDDEN => "HIDDEN",
        STV_PROTECTED => "PROTECTED",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Dynamic Entry Tags (d_tag)
// ═══════════════════════════════════════════════════════════════════════════════════

pub const DT_NULL: u64 = 0;
pub const DT_NEEDED: u64 = 1;
pub const DT_PLTRELSZ: u64 = 2;
pub const DT_PLTGOT: u64 = 3;
pub const DT_HASH: u64 = 4;
pub const DT_STRTAB: u64 = 5;
pub const DT_SYMTAB: u64 = 6;
pub const DT_RELA: u64 = 7;
pub const DT_RELASZ: u64 = 8;
pub const DT_RELAENT: u64 = 9;
pub const DT_STRSZ: u64 = 10;
pub const DT_SYMENT: u64 = 11;
pub const DT_INIT: u64 = 12;
pub const DT_FINI: u64 = 13;
pub const DT_SONAME: u64 = 14;
pub const DT_RPATH: u64 = 15;
pub const DT_SYMBOLIC: u64 = 16;
pub const DT_REL: u64 = 17;
pub const DT_RELSZ: u64 = 18;
pub const DT_RELENT: u64 = 19;
pub const DT_PLTREL: u64 = 20;
pub const DT_DEBUG: u64 = 21;
pub const DT_TEXTREL: u64 = 22;
pub const DT_JMPREL: u64 = 23;
pub const DT_BIND_NOW: u64 = 24;
pub const DT_INIT_ARRAY: u64 = 25;
pub const DT_FINI_ARRAY: u64 = 26;
pub const DT_INIT_ARRAYSZ: u64 = 27;
pub const DT_FINI_ARRAYSZ: u64 = 28;
pub const DT_RUNPATH: u64 = 29;
pub const DT_FLAGS: u64 = 30;
pub const DT_ENCODING: u64 = 32;
pub const DT_PREINIT_ARRAY: u64 = 32;
pub const DT_PREINIT_ARRAYSZ: u64 = 33;
pub const DT_SYMTAB_SHNDX: u64 = 34;
pub const DT_NUM: u64 = 35;
pub const DT_LOOS: u64 = 0x6000000D;
pub const DT_HIOS: u64 = 0x6FFFF000;
pub const DT_LOPROC: u64 = 0x70000000;
pub const DT_HIPROC: u64 = 0x7FFFFFFF;

// GNU extensions
pub const DT_GNU_HASH: u64 = 0x6ffffef5;
pub const DT_TLSDESC_PLT: u64 = 0x6ffffef6;
pub const DT_TLSDESC_GOT: u64 = 0x6ffffef7;
pub const DT_GNU_CONFLICT: u64 = 0x6ffffef8;
pub const DT_GNU_LIBLIST: u64 = 0x6ffffef9;
pub const DT_CONFIG: u64 = 0x6ffffefa;
pub const DT_DEPAUDIT: u64 = 0x6ffffefb;
pub const DT_AUDIT: u64 = 0x6ffffefc;
pub const DT_PLTPAD: u64 = 0x6ffffefd;
pub const DT_MOVETAB: u64 = 0x6ffffefe;
pub const DT_SYMINFO: u64 = 0x6ffffeff;
pub const DT_VERSYM: u64 = 0x6ffffff0;
pub const DT_RELACOUNT: u64 = 0x6ffffff9;
pub const DT_RELCOUNT: u64 = 0x6ffffffa;
pub const DT_FLAGS_1: u64 = 0x6ffffffb;
pub const DT_VERDEF: u64 = 0x6ffffffc;
pub const DT_VERDEFNUM: u64 = 0x6ffffffd;
pub const DT_VERNEED: u64 = 0x6ffffffe;
pub const DT_VERNEEDNUM: u64 = 0x6fffffff;
pub const DT_AUXILIARY: u64 = 0x7ffffffd;
pub const DT_FILTER: u64 = 0x7fffffff;

/// DT_FLAGS values
pub const DF_ORIGIN: u64 = 0x1;
pub const DF_SYMBOLIC: u64 = 0x2;
pub const DF_TEXTREL: u64 = 0x4;
pub const DF_BIND_NOW: u64 = 0x8;
pub const DF_STATIC_TLS: u64 = 0x10;

/// DT_FLAGS_1 values
pub const DF_1_NOW: u64 = 0x1;
pub const DF_1_GLOBAL: u64 = 0x2;
pub const DF_1_GROUP: u64 = 0x4;
pub const DF_1_NODELETE: u64 = 0x8;
pub const DF_1_INITFIRST: u64 = 0x20;
pub const DF_1_NOOPEN: u64 = 0x40;
pub const DF_1_ORIGIN: u64 = 0x80;
pub const DF_1_DIRECT: u64 = 0x100;
pub const DF_1_TRANS: u64 = 0x200;
pub const DF_1_PIE: u64 = 0x08000000;

/// Return a human-readable name for a dynamic tag.
pub fn dynamic_tag_name(tag: u64) -> &'static str {
    match tag {
        DT_NULL => "NULL",
        DT_NEEDED => "NEEDED",
        DT_PLTRELSZ => "PLTRELSZ",
        DT_PLTGOT => "PLTGOT",
        DT_HASH => "HASH",
        DT_STRTAB => "STRTAB",
        DT_SYMTAB => "SYMTAB",
        DT_RELA => "RELA",
        DT_RELASZ => "RELASZ",
        DT_RELAENT => "RELAENT",
        DT_STRSZ => "STRSZ",
        DT_SYMENT => "SYMENT",
        DT_INIT => "INIT",
        DT_FINI => "FINI",
        DT_SONAME => "SONAME",
        DT_RPATH => "RPATH",
        DT_SYMBOLIC => "SYMBOLIC",
        DT_REL => "REL",
        DT_RELSZ => "RELSZ",
        DT_RELENT => "RELENT",
        DT_PLTREL => "PLTREL",
        DT_DEBUG => "DEBUG",
        DT_TEXTREL => "TEXTREL",
        DT_JMPREL => "JMPREL",
        DT_BIND_NOW => "BIND_NOW",
        DT_INIT_ARRAY => "INIT_ARRAY",
        DT_FINI_ARRAY => "FINI_ARRAY",
        DT_INIT_ARRAYSZ => "INIT_ARRAYSZ",
        DT_FINI_ARRAYSZ => "FINI_ARRAYSZ",
        DT_RUNPATH => "RUNPATH",
        DT_FLAGS => "FLAGS",
        DT_PREINIT_ARRAY => "PREINIT_ARRAY",
        DT_PREINIT_ARRAYSZ => "PREINIT_ARRAYSZ",
        DT_SYMTAB_SHNDX => "SYMTAB_SHNDX",
        DT_GNU_HASH => "GNU_HASH",
        DT_TLSDESC_PLT => "TLSDESC_PLT",
        DT_TLSDESC_GOT => "TLSDESC_GOT",
        DT_GNU_CONFLICT => "GNU_CONFLICT",
        DT_GNU_LIBLIST => "GNU_LIBLIST",
        DT_CONFIG => "CONFIG",
        DT_DEPAUDIT => "DEPAUDIT",
        DT_AUDIT => "AUDIT",
        DT_PLTPAD => "PLTPAD",
        DT_MOVETAB => "MOVETAB",
        DT_SYMINFO => "SYMINFO",
        DT_VERSYM => "VERSYM",
        DT_RELACOUNT => "RELACOUNT",
        DT_RELCOUNT => "RELCOUNT",
        DT_FLAGS_1 => "FLAGS_1",
        DT_VERDEF => "VERDEF",
        DT_VERDEFNUM => "VERDEFNUM",
        DT_VERNEED => "VERNEED",
        DT_VERNEEDNUM => "VERNEEDNUM",
        DT_AUXILIARY => "AUXILIARY",
        DT_FILTER => "FILTER",
        _ if tag >= DT_LOOS && tag <= DT_HIOS => "OS-specific",
        _ if tag >= DT_LOPROC && tag <= DT_HIPROC => "Processor-specific",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Relocation Types: x86-64 (R_X86_64_*)
// ═══════════════════════════════════════════════════════════════════════════════════

pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_GOT32: u32 = 3;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_COPY: u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_GOTPCREL: u32 = 9;
pub const R_X86_64_32: u32 = 10;
pub const R_X86_64_32S: u32 = 11;
pub const R_X86_64_16: u32 = 12;
pub const R_X86_64_PC16: u32 = 13;
pub const R_X86_64_8: u32 = 14;
pub const R_X86_64_PC8: u32 = 15;
pub const R_X86_64_DTPMOD64: u32 = 16;
pub const R_X86_64_DTPOFF64: u32 = 17;
pub const R_X86_64_TPOFF64: u32 = 18;
pub const R_X86_64_TLSGD: u32 = 19;
pub const R_X86_64_TLSLD: u32 = 20;
pub const R_X86_64_DTPOFF32: u32 = 21;
pub const R_X86_64_GOTTPOFF: u32 = 22;
pub const R_X86_64_TPOFF32: u32 = 23;
pub const R_X86_64_PC64: u32 = 24;
pub const R_X86_64_GOTOFF64: u32 = 25;
pub const R_X86_64_GOTPC32: u32 = 26;
pub const R_X86_64_GOT64: u32 = 27;
pub const R_X86_64_GOTPCREL64: u32 = 28;
pub const R_X86_64_GOTPC64: u32 = 29;
pub const R_X86_64_GOTPLT64: u32 = 30;
pub const R_X86_64_PLTOFF64: u32 = 31;
pub const R_X86_64_SIZE32: u32 = 32;
pub const R_X86_64_SIZE64: u32 = 33;
pub const R_X86_64_GOTPC32_TLSDESC: u32 = 34;
pub const R_X86_64_TLSDESC_CALL: u32 = 35;
pub const R_X86_64_TLSDESC: u32 = 36;
pub const R_X86_64_IRELATIVE: u32 = 37;
pub const R_X86_64_RELATIVE64: u32 = 38;
pub const R_X86_64_GOTPCRELX: u32 = 41;
pub const R_X86_64_REX_GOTPCRELX: u32 = 42;

/// Return a human-readable name for an x86-64 relocation type.
pub fn x86_64_reloc_name(rtype: u32) -> &'static str {
    match rtype {
        R_X86_64_NONE => "R_X86_64_NONE",
        R_X86_64_64 => "R_X86_64_64",
        R_X86_64_PC32 => "R_X86_64_PC32",
        R_X86_64_GOT32 => "R_X86_64_GOT32",
        R_X86_64_PLT32 => "R_X86_64_PLT32",
        R_X86_64_COPY => "R_X86_64_COPY",
        R_X86_64_GLOB_DAT => "R_X86_64_GLOB_DAT",
        R_X86_64_JUMP_SLOT => "R_X86_64_JUMP_SLOT",
        R_X86_64_RELATIVE => "R_X86_64_RELATIVE",
        R_X86_64_GOTPCREL => "R_X86_64_GOTPCREL",
        R_X86_64_32 => "R_X86_64_32",
        R_X86_64_32S => "R_X86_64_32S",
        R_X86_64_16 => "R_X86_64_16",
        R_X86_64_PC16 => "R_X86_64_PC16",
        R_X86_64_8 => "R_X86_64_8",
        R_X86_64_PC8 => "R_X86_64_PC8",
        R_X86_64_DTPMOD64 => "R_X86_64_DTPMOD64",
        R_X86_64_DTPOFF64 => "R_X86_64_DTPOFF64",
        R_X86_64_TPOFF64 => "R_X86_64_TPOFF64",
        R_X86_64_TLSGD => "R_X86_64_TLSGD",
        R_X86_64_TLSLD => "R_X86_64_TLSLD",
        R_X86_64_DTPOFF32 => "R_X86_64_DTPOFF32",
        R_X86_64_GOTTPOFF => "R_X86_64_GOTTPOFF",
        R_X86_64_TPOFF32 => "R_X86_64_TPOFF32",
        R_X86_64_PC64 => "R_X86_64_PC64",
        R_X86_64_GOTOFF64 => "R_X86_64_GOTOFF64",
        R_X86_64_GOTPC32 => "R_X86_64_GOTPC32",
        R_X86_64_GOT64 => "R_X86_64_GOT64",
        R_X86_64_GOTPCREL64 => "R_X86_64_GOTPCREL64",
        R_X86_64_GOTPC64 => "R_X86_64_GOTPC64",
        R_X86_64_GOTPLT64 => "R_X86_64_GOTPLT64",
        R_X86_64_PLTOFF64 => "R_X86_64_PLTOFF64",
        R_X86_64_SIZE32 => "R_X86_64_SIZE32",
        R_X86_64_SIZE64 => "R_X86_64_SIZE64",
        R_X86_64_GOTPC32_TLSDESC => "R_X86_64_GOTPC32_TLSDESC",
        R_X86_64_TLSDESC_CALL => "R_X86_64_TLSDESC_CALL",
        R_X86_64_TLSDESC => "R_X86_64_TLSDESC",
        R_X86_64_IRELATIVE => "R_X86_64_IRELATIVE",
        R_X86_64_GOTPCRELX => "R_X86_64_GOTPCRELX",
        R_X86_64_REX_GOTPCRELX => "R_X86_64_REX_GOTPCRELX",
        _ => "R_X86_64_UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Relocation Types: i386 (R_386_*)
// ═══════════════════════════════════════════════════════════════════════════════════

pub const R_386_NONE: u32 = 0;
pub const R_386_32: u32 = 1;
pub const R_386_PC32: u32 = 2;
pub const R_386_GOT32: u32 = 3;
pub const R_386_PLT32: u32 = 4;
pub const R_386_COPY: u32 = 5;
pub const R_386_GLOB_DAT: u32 = 6;
pub const R_386_JMP_SLOT: u32 = 7;
pub const R_386_RELATIVE: u32 = 8;
pub const R_386_GOTOFF: u32 = 9;
pub const R_386_GOTPC: u32 = 10;

// ═══════════════════════════════════════════════════════════════════════════════════
// Relocation Types: ARM (R_ARM_*)
// ═══════════════════════════════════════════════════════════════════════════════════

pub const R_ARM_NONE: u32 = 0;
pub const R_ARM_ABS32: u32 = 2;
pub const R_ARM_REL32: u32 = 3;
pub const R_ARM_CALL: u32 = 28;
pub const R_ARM_JUMP24: u32 = 29;
pub const R_ARM_THM_CALL: u32 = 10;
pub const R_ARM_GLOB_DAT: u32 = 21;
pub const R_ARM_JUMP_SLOT: u32 = 22;
pub const R_ARM_RELATIVE: u32 = 23;

// ═══════════════════════════════════════════════════════════════════════════════════
// Relocation Types: AArch64 (R_AARCH64_*)
// ═══════════════════════════════════════════════════════════════════════════════════

pub const R_AARCH64_NONE: u32 = 0;
pub const R_AARCH64_ABS64: u32 = 257;
pub const R_AARCH64_ABS32: u32 = 258;
pub const R_AARCH64_GLOB_DAT: u32 = 1025;
pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
pub const R_AARCH64_RELATIVE: u32 = 1027;
pub const R_AARCH64_CALL26: u32 = 283;
pub const R_AARCH64_ADR_PREL_PG_HI21: u32 = 275;

// ═══════════════════════════════════════════════════════════════════════════════════
// Relocation Types: RISC-V (R_RISCV_*)
// ═══════════════════════════════════════════════════════════════════════════════════

pub const R_RISCV_NONE: u32 = 0;
pub const R_RISCV_32: u32 = 1;
pub const R_RISCV_64: u32 = 2;
pub const R_RISCV_RELATIVE: u32 = 3;
pub const R_RISCV_COPY: u32 = 4;
pub const R_RISCV_JUMP_SLOT: u32 = 5;

// ═══════════════════════════════════════════════════════════════════════════════════
// Relocation Types: RELR (R_RISCV / generic compressed relocations)
// ═══════════════════════════════════════════════════════════════════════════════════

/// SHT_RELR section type for packed relative relocations (DT_RELR).
pub const SHT_RELR: u32 = 19;

/// DT_RELR dynamic tag for packed relative relocations.
pub const DT_RELR: u64 = 36;
/// Size of DT_RELR relocation table.
pub const DT_RELRSZ: u64 = 35;
/// Entry size of DT_RELR table.
pub const DT_RELRENT: u64 = 37;

// ═══════════════════════════════════════════════════════════════════════════════════
// GNU Versioning Constants (for SHT_GNU_VERSYM, SHT_GNU_VERDEF, SHT_GNU_VERNEED)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Current version of the version structure.
pub const VER_NDX_GLOBAL: u16 = 1;
/// Symbol is hidden (local scope).
pub const VER_NDX_LOCAL: u16 = 0;
/// Version is weak (default if no other version applies).
pub const VER_NDX_LORESERVE: u16 = 0xFF00;

/// Version definition flags.
pub const VER_FLG_BASE: u32 = 0x1;
pub const VER_FLG_WEAK: u32 = 0x2;

/// Version definition / need structure version.
pub const VER_NEED_CURRENT: u16 = 1;
pub const VER_DEF_CURRENT: u16 = 1;

// ═══════════════════════════════════════════════════════════════════════════════════
// Compressed Section Constants (ELF32_Chdr / ELF64_Chdr)
// ═══════════════════════════════════════════════════════════════════════════════════

/// ZLIB/DEFLATE compression.
pub const ELFCOMPRESS_ZLIB: u32 = 1;
/// OS-specific compression range start.
pub const ELFCOMPRESS_LOOS: u32 = 0x60000000;
/// OS-specific compression range end.
pub const ELFCOMPRESS_HIOS: u32 = 0x6FFFFFFF;
/// Processor-specific compression range start.
pub const ELFCOMPRESS_LOPROC: u32 = 0x70000000;
/// Processor-specific compression range end.
pub const ELFCOMPRESS_HIPROC: u32 = 0x7FFFFFFF;

// ═══════════════════════════════════════════════════════════════════════════════════
// Note Types (Elf64_Nhdr n_type)
// ═══════════════════════════════════════════════════════════════════════════════════

pub const NT_GNU_BUILD_ID: u32 = 3;
pub const NT_GNU_GOLD_VERSION: u32 = 4;
pub const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
pub const NT_GNU_ABI_TAG: u32 = 1;
pub const NT_GNU_HWCAP: u32 = 2;
pub const NT_PRSTATUS: u32 = 1;
pub const NT_PRPSINFO: u32 = 3;
pub const NT_AUXV: u32 = 6;
pub const NT_FILE: u32 = 0x46494c45;

/// Return a human-readable name for a note type.
///
/// Note: NT_GNU_ABI_TAG (1) and NT_PRSTATUS (1) share the same numeric value;
/// NT_GNU_BUILD_ID (3) and NT_PRPSINFO (3) also share the same value.
pub fn note_type_name(n_type: u32) -> &'static str {
    match n_type {
        1 => "GNU_ABI_TAG / PRSTATUS",
        NT_GNU_HWCAP => "GNU_HWCAP",
        3 => "GNU_BUILD_ID / PRPSINFO",
        NT_GNU_GOLD_VERSION => "GNU_GOLD_VERSION",
        NT_GNU_PROPERTY_TYPE_0 => "GNU_PROPERTY_TYPE_0",
        NT_AUXV => "AUXV",
        NT_FILE => "FILE",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// GRP_COMDAT Flags (for SHT_GROUP sections)
// ═══════════════════════════════════════════════════════════════════════════════════

pub const GRP_COMDAT: u32 = 0x1;

// ═══════════════════════════════════════════════════════════════════════════════════
// Error Types
// ═══════════════════════════════════════════════════════════════════════════════════

/// Errors that can occur during ELF parsing.
#[derive(Debug, Clone)]
pub enum ElfError {
    /// Invalid ELF magic bytes (first 4 bytes).
    InvalidMagic,
    /// Invalid EI_CLASS byte (not 1 or 2).
    InvalidClass(u8),
    /// Invalid EI_DATA byte (not 1 or 2).
    InvalidData(u8),
    /// Invalid or corrupted ELF header fields.
    InvalidHeader(String),
    /// Data is truncated (too short).
    TruncatedData,
    /// Too many program headers (sanity check).
    TooManyProgramHeaders(u16),
    /// Too many section headers (sanity check).
    TooManySectionHeaders(u16),
    /// Section string table index out of range.
    InvalidShstrndx(u16),
    /// A generic nom parse error.
    NomError(String),
    /// Invalid string table (not null-terminated properly).
    InvalidStringTable,
    /// Invalid GNU hash table structure.
    InvalidGnuHash,
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfError::InvalidMagic => write!(f, "Invalid ELF magic bytes"),
            ElfError::InvalidClass(c) => write!(f, "Invalid ELF class byte: {}", c),
            ElfError::InvalidData(d) => write!(f, "Invalid ELF data encoding byte: {}", d),
            ElfError::InvalidHeader(s) => write!(f, "Invalid ELF header: {}", s),
            ElfError::TruncatedData => write!(f, "Truncated ELF data"),
            ElfError::TooManyProgramHeaders(n) => write!(f, "Too many program headers: {}", n),
            ElfError::TooManySectionHeaders(n) => write!(f, "Too many section headers: {}", n),
            ElfError::InvalidShstrndx(n) => write!(f, "Invalid section string table index: {}", n),
            ElfError::NomError(s) => write!(f, "Parse error: {}", s),
            ElfError::InvalidStringTable => write!(f, "Invalid string table"),
            ElfError::InvalidGnuHash => write!(f, "Invalid GNU hash table"),
        }
    }
}

impl std::error::Error for ElfError {}

impl From<nom::Err<nom::error::Error<&[u8]>>> for ElfError {
    fn from(e: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        ElfError::NomError(format!("{:?}", e))
    }
}

/// Type alias for ELF parse results.
pub type ElfResult<T> = Result<T, ElfError>;

// ═══════════════════════════════════════════════════════════════════════════════════
// Data Structures
// ═══════════════════════════════════════════════════════════════════════════════════

/// The complete parsed ELF file with all extracted contents.
///
/// All numeric fields are unified to 64-bit for consistency; the `header.class`
/// and `header.data` fields indicate whether the original file was 32-bit or 64-bit
/// and little-endian or big-endian.
#[derive(Debug, Clone)]
pub struct ElfFile {
    /// The parsed ELF file header.
    pub header: ElfHeader,
    /// All program headers (segments).
    pub program_headers: Vec<ProgramHeader>,
    /// All section headers.
    pub section_headers: Vec<SectionHeader>,
    /// All symbols from SHT_SYMTAB and SHT_DYNSYM sections.
    pub symbols: Vec<SymbolEntry>,
    /// Dynamic section entries (from PT_DYNAMIC).
    pub dynamic_entries: Vec<DynamicEntry>,
    /// SHT_REL relocation entries (without addends).
    pub relocations: Vec<RelocationEntry>,
    /// SHT_RELA relocation entries (with addends).
    pub rela_relocations: Vec<RelaEntry>,
    /// The section header string table (raw bytes).
    pub shstrtab: Option<Vec<u8>>,
    /// Parsed GNU hash table (if present in .gnu.hash).
    pub gnu_hash: Option<GnuHashTable>,
    /// Parsed SYSV hash table (if present in .hash).
    pub sysv_hash: Option<HashTable>,
    /// Parsed note entries from PT_NOTE segment(s) / SHT_NOTE section(s).
    pub notes: Vec<NoteEntry>,
    /// Detected GOT/PLT stub addresses.
    pub got_plt_stubs: Vec<GotPltStub>,
    /// Extracted dynamic string table (if available).
    pub dynstr: Option<Vec<u8>>,
    /// Extracted dynamic symbol table entries (if available).
    pub dynsyms: Vec<SymbolEntry>,
    /// Map from dynamic tag to address/value for quick lookup.
    pub dynamic_map: HashMap<u64, u64>,
}

/// ELF file identification information (from e_ident[]).
#[derive(Debug, Clone)]
pub struct ElfIdentification {
    /// Raw e_ident bytes.
    pub magic: [u8; 4],
    pub class: ElfClass,
    pub data: ElfData,
    pub ei_version: u8,
    pub ei_osabi: u8,
    pub ei_abiversion: u8,
    /// Remaining padding bytes.
    pub ei_pad: [u8; 7],
}

/// ELF file header (Elf32_Ehdr / Elf64_Ehdr, unified).
///
/// Contains all fields from both 32-bit and 64-bit ELF headers; 32-bit values
/// are zero-extended to 64-bit.
#[derive(Debug, Clone)]
pub struct ElfHeader {
    pub ident: ElfIdentification,
    pub e_type: u16,
    pub machine: u16,
    pub e_version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

impl ElfHeader {
    /// Returns true if this is a 64-bit ELF file.
    pub fn is_64bit(&self) -> bool {
        matches!(self.ident.class, ElfClass::ELF64)
    }

    /// Returns true if this is a 32-bit ELF file.
    pub fn is_32bit(&self) -> bool {
        matches!(self.ident.class, ElfClass::ELF32)
    }

    /// Returns true if little-endian.
    pub fn is_le(&self) -> bool {
        self.ident.data.is_le()
    }

    /// Returns true if big-endian.
    pub fn is_be(&self) -> bool {
        self.ident.data.is_be()
    }

    /// Returns the address size in bytes (4 or 8).
    pub fn addr_size(&self) -> usize {
        self.ident.class.addr_size()
    }

    /// Returns the file type as a human-readable string.
    pub fn type_name(&self) -> &'static str {
        etype_name(self.e_type)
    }

    /// Returns the machine name as a human-readable string.
    pub fn machine_name(&self) -> &'static str {
        machine_name(self.machine)
    }
}

/// ELF program header (Elf32_Phdr / Elf64_Phdr, unified to 64-bit fields).
#[derive(Debug, Clone)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl ProgramHeader {
    pub fn is_load(&self) -> bool { self.p_type == PT_LOAD }

    pub fn is_dynamic(&self) -> bool { self.p_type == PT_DYNAMIC }

    pub fn is_interp(&self) -> bool { self.p_type == PT_INTERP }

    pub fn is_note(&self) -> bool { self.p_type == PT_NOTE }

    pub fn is_tls(&self) -> bool { self.p_type == PT_TLS }

    pub fn is_phdr(&self) -> bool { self.p_type == PT_PHDR }

    pub fn is_gnu_stack(&self) -> bool { self.p_type == PT_GNU_STACK }

    pub fn is_gnu_relro(&self) -> bool { self.p_type == PT_GNU_RELRO }

    pub fn is_gnu_eh_frame(&self) -> bool { self.p_type == PT_GNU_EH_FRAME }

    pub fn is_readable(&self) -> bool { (self.p_flags & PF_R) != 0 }

    pub fn is_writable(&self) -> bool { (self.p_flags & PF_W) != 0 }

    pub fn is_executable(&self) -> bool { (self.p_flags & PF_X) != 0 }

    /// Returns the segment type name.
    pub fn type_name(&self) -> &'static str { segment_type_name(self.p_type) }

    /// Returns the flags as a string like "RWE".
    pub fn flags_str(&self) -> String { flags_to_string(self.p_flags) }

    /// Returns the file bytes covered by this segment.
    pub fn file_data<'a>(&self, file_bytes: &'a [u8]) -> Option<&'a [u8]> {
        let start = self.p_offset as usize;
        let end = start + self.p_filesz as usize;
        if end <= file_bytes.len() {
            Some(&file_bytes[start..end])
        } else {
            None
        }
    }
}

/// ELF section header (Elf32_Shdr / Elf64_Shdr, unified to 64-bit).
#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

impl SectionHeader {
    /// Returns the section type name.
    pub fn type_name(&self) -> &'static str { section_type_name(self.sh_type) }

    /// Returns true if this section is allocated (occupies memory).
    pub fn is_alloc(&self) -> bool { (self.sh_flags & SHF_ALLOC) != 0 }

    /// Returns true if this section is writable.
    pub fn is_writable(&self) -> bool { (self.sh_flags & SHF_WRITE) != 0 }

    /// Returns true if this section is executable.
    pub fn is_executable(&self) -> bool { (self.sh_flags & SHF_EXECINSTR) != 0 }

    /// Returns true if this is a string table section.
    pub fn is_strtab(&self) -> bool { self.sh_type == SHT_STRTAB }

    /// Returns true if this is a symbol table section.
    pub fn is_symtab(&self) -> bool {
        self.sh_type == SHT_SYMTAB || self.sh_type == SHT_DYNSYM
    }

    /// Returns the section name by looking it up in a string table.
    pub fn get_name<'a>(&self, strtab: &'a [u8]) -> Option<&'a str> {
        let start = self.sh_name as usize;
        if start >= strtab.len() {
            return None;
        }
        let end = strtab[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(strtab.len());
        std::str::from_utf8(&strtab[start..end]).ok()
    }

    /// Returns the section data from the file bytes.
    pub fn data<'a>(&self, file_bytes: &'a [u8]) -> Option<&'a [u8]> {
        if self.sh_type == SHT_NOBITS {
            return None; // NOBITS sections have no data in the file
        }
        let start = self.sh_offset as usize;
        let end = start + self.sh_size as usize;
        if end <= file_bytes.len() && start < end {
            Some(&file_bytes[start..end])
        } else {
            None
        }
    }
}

/// ELF symbol entry (Elf32_Sym / Elf64_Sym, unified to 64-bit fields).
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

impl SymbolEntry {
    /// Extract the symbol binding (STB_*).
    pub fn bind(&self) -> u8 { st_bind(self.st_info) }

    /// Extract the symbol type (STT_*).
    pub fn stype(&self) -> u8 { st_type(self.st_info) }

    /// Extract the symbol visibility (STV_*).
    pub fn visibility(&self) -> u8 { st_visibility(self.st_other) }

    /// Returns true if the symbol is undefined (st_shndx == SHN_UNDEF).
    pub fn is_undefined(&self) -> bool { self.st_shndx == SHN_UNDEF }

    /// Returns true if the symbol has global binding (STB_GLOBAL or STB_WEAK).
    pub fn is_global(&self) -> bool {
        let b = self.bind();
        b == STB_GLOBAL || b == STB_WEAK
    }

    /// Returns true if the symbol represents a function.
    pub fn is_function(&self) -> bool { self.stype() == STT_FUNC }

    /// Returns true if the symbol represents an object (variable).
    pub fn is_object(&self) -> bool { self.stype() == STT_OBJECT }

    /// Returns true if the symbol has hidden visibility.
    pub fn is_hidden(&self) -> bool { self.visibility() == STV_HIDDEN }

    /// Returns the binding name (LOCAL, GLOBAL, WEAK, etc.).
    pub fn bind_name(&self) -> &'static str { bind_name(self.bind()) }

    /// Returns the type name (NOTYPE, FUNC, OBJECT, etc.).
    pub fn type_name(&self) -> &'static str { type_name(self.stype()) }

    /// Get the symbol name from a string table.
    pub fn get_name<'a>(&self, strtab: &'a [u8]) -> Option<&'a str> {
        let start = self.st_name as usize;
        if start >= strtab.len() {
            return None;
        }
        let end = strtab[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(strtab.len());
        std::str::from_utf8(&strtab[start..end]).ok()
    }
}

/// ELF relocation entry without addend (Elf32_Rel / Elf64_Rel, unified).
#[derive(Debug, Clone)]
pub struct RelocationEntry {
    pub r_offset: u64,
    pub r_info: u64,
}

impl RelocationEntry {
    /// Extract the symbol index.
    /// For ELF64: upper 32 bits. For ELF32: upper 24 bits.
    pub fn sym(&self, is_64bit: bool) -> u64 {
        if is_64bit { self.r_info >> 32 } else { self.r_info >> 8 }
    }

    /// Extract the relocation type.
    /// For ELF64: lower 32 bits. For ELF32: lower 8 bits.
    pub fn rtype(&self, is_64bit: bool) -> u64 {
        if is_64bit { self.r_info & 0xFFFF_FFFF } else { self.r_info & 0xFF }
    }

    /// Get the x86-64 relocation type name.
    pub fn rtype_name_x86_64(&self) -> &'static str {
        x86_64_reloc_name(self.rtype(true) as u32)
    }
}

/// ELF relocation entry with addend (Elf32_Rela / Elf64_Rela, unified).
#[derive(Debug, Clone)]
pub struct RelaEntry {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

impl RelaEntry {
    /// Extract the symbol index.
    pub fn sym(&self, is_64bit: bool) -> u64 {
        if is_64bit { self.r_info >> 32 } else { self.r_info >> 8 }
    }

    /// Extract the relocation type.
    pub fn rtype(&self, is_64bit: bool) -> u64 {
        if is_64bit { self.r_info & 0xFFFF_FFFF } else { self.r_info & 0xFF }
    }

    /// Get the x86-64 relocation type name.
    pub fn rtype_name_x86_64(&self) -> &'static str {
        x86_64_reloc_name(self.rtype(true) as u32)
    }
}

/// ELF dynamic entry (Elf32_Dyn / Elf64_Dyn, unified to 64-bit).
#[derive(Debug, Clone)]
pub struct DynamicEntry {
    pub d_tag: u64,
    pub d_val: u64,
}

impl DynamicEntry {
    /// Returns the dynamic tag name.
    pub fn tag_name(&self) -> &'static str { dynamic_tag_name(self.d_tag) }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Compressed Section Header (Elf32_Chdr / Elf64_Chdr)
// ═══════════════════════════════════════════════════════════════════════════════════

/// ELF compressed section header (Elf32_Chdr / Elf64_Chdr, unified to 64-bit).
///
/// Present at the start of a section whose `SHF_COMPRESSED` flag is set.
///
/// Layout:
/// - ELF32: ch_type(u32), ch_size(u32), ch_addralign(u32) = 12 bytes
/// - ELF64: ch_type(u32), ch_reserved(u32), ch_size(u64), ch_addralign(u64) = 24 bytes
#[derive(Debug, Clone)]
pub struct CompressedSectionHeader {
    /// Compression algorithm (ELFCOMPRESS_ZLIB, etc.).
    pub ch_type: u32,
    /// Size of the uncompressed data in bytes.
    pub ch_size: u64,
    /// Alignment of the uncompressed data.
    pub ch_addralign: u64,
}

impl CompressedSectionHeader {
    /// Returns true if this uses ZLIB compression.
    pub fn is_zlib(&self) -> bool {
        self.ch_type == ELFCOMPRESS_ZLIB
    }

    /// Parse from raw bytes.
    /// `is_64bit` selects ELF32 vs ELF64 layout.
    pub fn parse(data: &[u8], is_64bit: bool, is_le: bool) -> Option<Self> {
        if is_64bit {
            if data.len() < 24 {
                return None;
            }
            let ch_type = if is_le {
                u32::from_le_bytes(data[0..4].try_into().unwrap())
            } else {
                u32::from_be_bytes(data[0..4].try_into().unwrap())
            };
            // Skip ch_reserved (4 bytes at offset 4)
            let ch_size = if is_le {
                u64::from_le_bytes(data[8..16].try_into().unwrap())
            } else {
                u64::from_be_bytes(data[8..16].try_into().unwrap())
            };
            let ch_addralign = if is_le {
                u64::from_le_bytes(data[16..24].try_into().unwrap())
            } else {
                u64::from_be_bytes(data[16..24].try_into().unwrap())
            };
            Some(CompressedSectionHeader { ch_type, ch_size, ch_addralign })
        } else {
            if data.len() < 12 {
                return None;
            }
            let (ch_type, ch_size, ch_addralign);
            if is_le {
                ch_type = u32::from_le_bytes(data[0..4].try_into().unwrap());
                ch_size = u32::from_le_bytes(data[4..8].try_into().unwrap()) as u64;
                ch_addralign = u32::from_le_bytes(data[8..12].try_into().unwrap()) as u64;
            } else {
                ch_type = u32::from_be_bytes(data[0..4].try_into().unwrap());
                ch_size = u32::from_be_bytes(data[4..8].try_into().unwrap()) as u64;
                ch_addralign = u32::from_be_bytes(data[8..12].try_into().unwrap()) as u64;
            }
            Some(CompressedSectionHeader { ch_type, ch_size, ch_addralign })
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// GNU Versioning Structures (SHT_GNU_VERDEF, SHT_GNU_VERNEED, SHT_GNU_VERSYM)
// ═══════════════════════════════════════════════════════════════════════════════════

/// ELF version definition entry (Elf_Verdef).
///
/// Found in SHT_GNU_VERDEF sections. Each entry defines a version
/// and references one or more `GnuVerdaux` auxiliary entries.
///
/// Layout (same for ELF32 and ELF64):
/// ```text
/// vd_version: u16   // Version revision (VER_DEF_CURRENT)
/// vd_flags:   u16   // Version information (VER_FLG_BASE, VER_FLG_WEAK)
/// vd_ndx:     u16   // Version index (used in versym table)
/// vd_cnt:     u16   // Number of associated verdaux entries
/// vd_hash:    u32   // Version name hash value
/// vd_aux:     u32   // Offset in bytes to verdaux array
/// vd_next:    u32   // Offset in bytes to next verdef entry
/// ```
#[derive(Debug, Clone)]
pub struct GnuVerdef {
    pub vd_version: u16,
    pub vd_flags: u16,
    pub vd_ndx: u16,
    pub vd_cnt: u16,
    pub vd_hash: u32,
    pub vd_aux: u32,
    pub vd_next: u32,
}

impl GnuVerdef {
    /// Returns true if this is the base (global) version definition.
    pub fn is_base(&self) -> bool {
        self.vd_flags & VER_FLG_BASE as u16 != 0
    }

    /// Returns true if this is a weak version definition.
    pub fn is_weak(&self) -> bool {
        self.vd_flags & VER_FLG_WEAK as u16 != 0
    }

    /// Parse a GnuVerdef from a byte slice.
    /// Returns (entry, bytes_consumed).
    pub fn parse_from(data: &[u8], is_le: bool) -> Option<(Self, usize)> {
        if data.len() < 20 {
            return None;
        }
        let rd16 = |off: usize| -> u16 {
            if is_le { u16::from_le_bytes(data[off..off+2].try_into().unwrap()) }
            else { u16::from_be_bytes(data[off..off+2].try_into().unwrap()) }
        };
        let rd32 = |off: usize| -> u32 {
            if is_le { u32::from_le_bytes(data[off..off+4].try_into().unwrap()) }
            else { u32::from_be_bytes(data[off..off+4].try_into().unwrap()) }
        };
        let entry = GnuVerdef {
            vd_version: rd16(0),
            vd_flags: rd16(2),
            vd_ndx: rd16(4),
            vd_cnt: rd16(6),
            vd_hash: rd32(8),
            vd_aux: rd32(12),
            vd_next: rd32(16),
        };
        Some((entry, 20))
    }
}

/// ELF version definition auxiliary entry (Elf_Verdaux).
///
/// Each `GnuVerdef` has one or more `GnuVerdaux` entries providing
/// the version name(s) via string table offsets.
///
/// Layout:
/// ```text
/// vda_name: u32  // Version or dependency name string table offset
/// vda_next: u32  // Offset in bytes to next verdaux entry (0 = last)
/// ```
#[derive(Debug, Clone)]
pub struct GnuVerdaux {
    pub vda_name: u32,
    pub vda_next: u32,
}

impl GnuVerdaux {
    /// Parse a GnuVerdaux from a byte slice.
    pub fn parse(data: &[u8], is_le: bool) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let rd32 = |off: usize| -> u32 {
            if is_le { u32::from_le_bytes(data[off..off+4].try_into().unwrap()) }
            else { u32::from_be_bytes(data[off..off+4].try_into().unwrap()) }
        };
        Some(GnuVerdaux {
            vda_name: rd32(0),
            vda_next: rd32(4),
        })
    }

    /// Get the version name from a string table.
    pub fn get_name<'a>(&self, strtab: &'a [u8]) -> Option<&'a str> {
        get_string(strtab, self.vda_name as usize)
    }
}

/// ELF version needed entry (Elf_Verneed).
///
/// Found in SHT_GNU_VERNEED sections. Each entry represents a
/// version dependency on a shared library and references one or more
/// `GnuVernaux` auxiliary entries.
///
/// Layout:
/// ```text
/// vn_version: u16 // Version of structure (VER_NEED_CURRENT)
/// vn_cnt:     u16 // Number of associated vernaux entries
/// vn_file:    u32 // Offset of filename for this dependency
/// vn_aux:     u32 // Offset in bytes to vernaux array
/// vn_next:    u32 // Offset in bytes to next verneed entry
/// ```
#[derive(Debug, Clone)]
pub struct GnuVerneed {
    pub vn_version: u16,
    pub vn_cnt: u16,
    pub vn_file: u32,
    pub vn_aux: u32,
    pub vn_next: u32,
}

impl GnuVerneed {
    /// Parse a GnuVerneed from a byte slice.
    /// Returns (entry, bytes_consumed).
    pub fn parse_from(data: &[u8], is_le: bool) -> Option<(Self, usize)> {
        if data.len() < 16 {
            return None;
        }
        let rd16 = |off: usize| -> u16 {
            if is_le { u16::from_le_bytes(data[off..off+2].try_into().unwrap()) }
            else { u16::from_be_bytes(data[off..off+2].try_into().unwrap()) }
        };
        let rd32 = |off: usize| -> u32 {
            if is_le { u32::from_le_bytes(data[off..off+4].try_into().unwrap()) }
            else { u32::from_be_bytes(data[off..off+4].try_into().unwrap()) }
        };
        let entry = GnuVerneed {
            vn_version: rd16(0),
            vn_cnt: rd16(2),
            vn_file: rd32(4),
            vn_aux: rd32(8),
            vn_next: rd32(12),
        };
        Some((entry, 16))
    }

    /// Get the dependency file name from a string table.
    pub fn get_file_name<'a>(&self, strtab: &'a [u8]) -> Option<&'a str> {
        get_string(strtab, self.vn_file as usize)
    }
}

/// ELF version needed auxiliary entry (Elf_Vernaux).
///
/// Each `GnuVerneed` has one or more `GnuVernaux` entries providing
/// the version name(s) the dependency requires.
///
/// Layout:
/// ```text
/// vna_hash:  u32 // Hash value of dependency name
/// vna_flags: u16 // Dependency specific information
/// vna_other: u16 // Version index for this dependency
/// vna_name:  u32 // Dependency name string offset
/// vna_next:  u32 // Offset in bytes to next vernaux entry (0 = last)
/// ```
#[derive(Debug, Clone)]
pub struct GnuVernaux {
    pub vna_hash: u32,
    pub vna_flags: u16,
    pub vna_other: u16,
    pub vna_name: u32,
    pub vna_next: u32,
}

impl GnuVernaux {
    /// Parse a GnuVernaux from a byte slice.
    pub fn parse(data: &[u8], is_le: bool) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let rd16 = |off: usize| -> u16 {
            if is_le { u16::from_le_bytes(data[off..off+2].try_into().unwrap()) }
            else { u16::from_be_bytes(data[off..off+2].try_into().unwrap()) }
        };
        let rd32 = |off: usize| -> u32 {
            if is_le { u32::from_le_bytes(data[off..off+4].try_into().unwrap()) }
            else { u32::from_be_bytes(data[off..off+4].try_into().unwrap()) }
        };
        Some(GnuVernaux {
            vna_hash: rd32(0),
            vna_flags: rd16(4),
            vna_other: rd16(6),
            vna_name: rd32(8),
            vna_next: rd32(12),
        })
    }

    /// Get the version name from a string table.
    pub fn get_name<'a>(&self, strtab: &'a [u8]) -> Option<&'a str> {
        get_string(strtab, self.vna_name as usize)
    }
}

/// Type alias for the version symbol table (SHT_GNU_VERSYM).
///
/// Each entry is a u16 index into the version definition/need tables.
pub type GnuVersym = u16;

// ═══════════════════════════════════════════════════════════════════════════════════
// GNU Hash Table (.gnu.hash)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parsed GNU hash table.
///
/// Structure:
/// - nbuckets: number of hash buckets
/// - symndx: index of the first symbol in the dynamic symbol table that is accessible via the hash
/// - maskwords: number of words in the bloom filter (must be power of 2)
/// - shift2: bloom filter shift count
/// - bloom: bloom filter words (maskwords entries)
/// - buckets: hash bucket array (nbuckets entries, each is a symbol index)
/// - chain: hash chain values (valid only for entries >= symndx)
#[derive(Debug, Clone)]
pub struct GnuHashTable {
    pub nbuckets: u32,
    pub symndx: u32,
    pub maskwords: u32,
    pub shift2: u32,
    pub bloom: Vec<u64>,   // ELFCLASS64: u64; ELFCLASS32: u32 (stored as u64)
    pub buckets: Vec<u32>,
    pub chains: Vec<u32>,  // chain values (only valid for indices matching the hash)
}

impl GnuHashTable {
    /// Look up a symbol name in the GNU hash table.
    /// Returns the symbol index in the dynamic symbol table, or None.
    pub fn lookup(&self, name: &str, symtab: &[SymbolEntry], strtab: &[u8]) -> Option<usize> {
        let hash = gnu_hash(name);
        let bucket_idx = (hash % self.nbuckets as u64) as usize;
        let mut sym_idx = self.buckets[bucket_idx] as usize;

        if sym_idx < self.symndx as usize {
            return None;
        }

        loop {
            if sym_idx >= symtab.len() {
                break;
            }
            let chain_hash = self.chains[sym_idx - self.symndx as usize] as u64;
            // Check if the symbol matches
            if (chain_hash | 1) == (hash | 1) {
                // Hash collision possible; verify by name
                if let Some(sym_name) = symtab[sym_idx].get_name(strtab) {
                    if sym_name == name {
                        return Some(sym_idx);
                    }
                }
            }
            // Check termination bit
            if (chain_hash & 1) != 0 {
                break;
            }
            sym_idx += 1;
        }
        None
    }

    /// Check if a symbol name is in the bloom filter.
    pub fn bloom_test(&self, name: &str) -> bool {
        let hash = gnu_hash(name);
        let h1 = hash as u32;
        let h2 = (hash >> 32) as u32;
        let maskwords = self.maskwords as usize;
        if maskwords == 0 {
            return false;
        }
        let bit1 = h1 % (maskwords as u32 * 64);
        let bit2 = h2 % (maskwords as u32 * 64);
        let word1 = self.bloom[(bit1 / 64) as usize];
        let word2 = self.bloom[(bit2 / 64) as usize];
        ((word1 >> (bit1 % 64)) & 1) != 0 && ((word2 >> (bit2 % 64)) & 1) != 0
    }
}

/// Compute the GNU hash of a symbol name.
pub fn gnu_hash(name: &str) -> u64 {
    let mut h: u64 = 5381;
    for b in name.bytes() {
        h = h.wrapping_mul(33).wrapping_add(b as u64);
    }
    h
}

/// Parse a GNU hash table from raw bytes.
/// `is_64bit` determines whether bloom filter uses u64 (ELF64) or u32 (ELF32) entries.
pub fn parse_gnu_hash(data: &[u8], is_64bit: bool) -> ElfResult<GnuHashTable> {
    if data.len() < 16 {
        return Err(ElfError::InvalidGnuHash);
    }
    let _is_le = true; // We use little-endian as default; the caller should handle endianness

    let nbuckets = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let symndx = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let maskwords = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let shift2 = u32::from_le_bytes(data[12..16].try_into().unwrap());

    // Validate
    if nbuckets == 0 || maskwords == 0 {
        return Err(ElfError::InvalidGnuHash);
    }

    let bloom_offset = 16;
    let mut bloom = Vec::with_capacity(maskwords as usize);
    if is_64bit {
        let bloom_end = bloom_offset + (maskwords as usize) * 8;
        if bloom_end > data.len() {
            return Err(ElfError::InvalidGnuHash);
        }
        for i in 0..maskwords as usize {
            let off = bloom_offset + i * 8;
            bloom.push(u64::from_le_bytes(data[off..off + 8].try_into().unwrap()));
        }
    } else {
        let bloom_end = bloom_offset + (maskwords as usize) * 4;
        if bloom_end > data.len() {
            return Err(ElfError::InvalidGnuHash);
        }
        for i in 0..maskwords as usize {
            let off = bloom_offset + i * 4;
            bloom.push(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as u64);
        }
    }

    let bloom_size = maskwords as usize * if is_64bit { 8 } else { 4 };
    let buckets_offset = bloom_offset + bloom_size;
    let buckets_end = buckets_offset + nbuckets as usize * 4;
    if buckets_end > data.len() {
        return Err(ElfError::InvalidGnuHash);
    }
    let mut buckets = Vec::with_capacity(nbuckets as usize);
    for i in 0..nbuckets as usize {
        let off = buckets_offset + i * 4;
        buckets.push(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()));
    }

    let chains_offset = buckets_end;
    let remaining = (data.len() - chains_offset) / 4;
    let mut chains = Vec::with_capacity(remaining);
    for i in 0..remaining {
        let off = chains_offset + i * 4;
        chains.push(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()));
    }

    Ok(GnuHashTable {
        nbuckets,
        symndx,
        maskwords,
        shift2,
        bloom,
        buckets,
        chains,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════════
// SYSV Hash Table (.hash)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parsed SYSV (standard ELF) hash table.
///
/// Structure:
/// - nbucket: number of hash buckets
/// - nchain: number of chain entries (= number of symbols)
/// - buckets: nbucket entries, each is a symbol index
/// - chains: nchain entries, each is the next symbol index in the chain
#[derive(Debug, Clone)]
pub struct HashTable {
    pub nbucket: u32,
    pub nchain: u32,
    pub buckets: Vec<u32>,
    pub chains: Vec<u32>,
}

impl HashTable {
    /// Look up a symbol name in the SYSV hash table.
    /// Returns the symbol index, or None.
    pub fn lookup(&self, name: &str, symtab: &[SymbolEntry], strtab: &[u8]) -> Option<usize> {
        let hash = sysv_hash(name);
        let mut idx = self.buckets[(hash % self.nbucket as u64) as usize] as usize;

        while idx != 0 && idx < self.chains.len() {
            if idx >= symtab.len() {
                break;
            }
            if let Some(sym_name) = symtab[idx].get_name(strtab) {
                if sym_name == name {
                    return Some(idx);
                }
            }
            idx = self.chains[idx] as usize;
        }
        None
    }
}

/// Compute the SYSV (standard ELF) hash of a symbol name.
pub fn sysv_hash(name: &str) -> u64 {
    let mut h: u64 = 0;
    for b in name.bytes() {
        h = (h << 4).wrapping_add(b as u64);
        let g = h & 0xF0000000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// Parse a SYSV hash table from raw bytes.
pub fn parse_sysv_hash(data: &[u8]) -> ElfResult<HashTable> {
    if data.len() < 8 {
        return Err(ElfError::TruncatedData);
    }
    let nbucket = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let nchain = u32::from_le_bytes(data[4..8].try_into().unwrap());

    let buckets_offset = 8;
    let buckets_end = buckets_offset + nbucket as usize * 4;
    if buckets_end > data.len() {
        return Err(ElfError::TruncatedData);
    }
    let mut buckets = Vec::with_capacity(nbucket as usize);
    for i in 0..nbucket as usize {
        let off = buckets_offset + i * 4;
        buckets.push(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()));
    }

    let chains_offset = buckets_end;
    let chains_end = chains_offset + nchain as usize * 4;
    if chains_end > data.len() {
        return Err(ElfError::TruncatedData);
    }
    let mut chains = Vec::with_capacity(nchain as usize);
    for i in 0..nchain as usize {
        let off = chains_offset + i * 4;
        chains.push(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()));
    }

    Ok(HashTable { nbucket, nchain, buckets, chains })
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Note Section Parsing
// ═══════════════════════════════════════════════════════════════════════════════════

/// A single ELF note entry.
///
/// Structure: namesz + descsz + type, followed by name (aligned to 4) and desc (aligned to 4).
#[derive(Debug, Clone)]
pub struct NoteEntry {
    pub n_namesz: u32,
    pub n_descsz: u32,
    pub n_type: u32,
    pub name: String,
    pub desc: Vec<u8>,
}

impl NoteEntry {
    /// Returns the note type name (e.g., "GNU_BUILD_ID").
    pub fn type_name(&self) -> &'static str {
        note_type_name(self.n_type)
    }

    /// Returns the description as a hex string.
    pub fn desc_hex(&self) -> String {
        self.desc.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
    }
}

/// Align `val` up to `align` (must be a power of 2).
fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

/// Parse all note entries from a note section or segment data.
pub fn parse_notes(data: &[u8]) -> ElfResult<Vec<NoteEntry>> {
    let mut notes = Vec::new();
    let mut offset = 0;
    // Determine note header size based on class (assume 32-bit for the generic case)
    // We parse based on the actual structure. Both ELF32 and ELF64 use the same note layout
    // (namesz, descsz, type are all 4-byte fields).
    let nhdr_size = 12;

    while offset + nhdr_size <= data.len() {
        let namesz = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let descsz = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
        let n_type = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap());

        let name_offset = offset + nhdr_size;
        let name_end = name_offset + namesz as usize;
        let desc_offset = align_up(name_end, 4);
        let desc_end = desc_offset + descsz as usize;

        if desc_end > data.len() {
            break;
        }

        let name = if namesz > 0 {
            let len = std::cmp::min(namesz as usize - 1, data.len() - name_offset);
            String::from_utf8_lossy(&data[name_offset..name_offset + len]).to_string()
        } else {
            String::new()
        };

        let desc = if descsz > 0 {
            data[desc_offset..desc_end].to_vec()
        } else {
            Vec::new()
        };

        notes.push(NoteEntry {
            n_namesz: namesz,
            n_descsz: descsz,
            n_type,
            name,
            desc,
        });

        offset = desc_end;
        // Align to 4-byte boundary
        offset = align_up(offset, 4);
    }

    Ok(notes)
}

// ═══════════════════════════════════════════════════════════════════════════════════
// GOT/PLT Stub Detection
// ═══════════════════════════════════════════════════════════════════════════════════

/// A detected GOT or PLT stub entry.
#[derive(Debug, Clone)]
pub struct GotPltStub {
    /// Virtual address of the GOT/PLT entry.
    pub address: u64,
    /// The type of entry: "GOT", "PLT", "PLT_GOT", or "IFUNC".
    pub entry_type: GotPltType,
    /// The symbol this entry references (if known).
    pub symbol_name: Option<String>,
}

/// Type of a GOT/PLT stub entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GotPltType {
    /// Global Offset Table entry.
    GOT,
    /// Procedure Linkage Table entry.
    PLT,
    /// PLT GOT entry (.got.plt).
    PLTGOT,
    /// Indirect function (IFUNC) resolver.
    IFUNC,
}

impl fmt::Display for GotPltType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GotPltType::GOT => write!(f, "GOT"),
            GotPltType::PLT => write!(f, "PLT"),
            GotPltType::PLTGOT => write!(f, "PLT_GOT"),
            GotPltType::IFUNC => write!(f, "IFUNC"),
        }
    }
}

/// Detect GOT/PLT stubs from the dynamic section and relocation entries.
///
/// For x86-64 ELF files, this identifies GOT entries from R_X86_64_GLOB_DAT and
/// R_X86_64_JUMP_SLOT relocations, and maps them to symbol names.
pub fn detect_got_plt_stubs(
    dynamic_map: &HashMap<u64, u64>,
    rela_relocations: &[RelaEntry],
    symbols: &[SymbolEntry],
    strtab: &[u8],
    is_64bit: bool,
) -> Vec<GotPltStub> {
    let mut stubs = Vec::new();

    // Get the GOT address from DT_PLTGOT
    let pltgot_addr = dynamic_map.get(&DT_PLTGOT).copied();

    for rela in rela_relocations {
        let rtype = rela.rtype(is_64bit) as u32;
        let entry_type = match rtype {
            R_X86_64_GLOB_DAT => {
                // GOT entry for global data symbols
                // Check if this falls within .got section range
                if let Some(got_base) = pltgot_addr {
                    if rela.r_offset >= got_base {
                        GotPltType::GOT
                    } else {
                        continue;
                    }
                } else {
                    GotPltType::GOT
                }
            }
            R_X86_64_JUMP_SLOT => {
                // PLT GOT entry (function lazy binding stub)
                GotPltType::PLTGOT
            }
            R_X86_64_IRELATIVE => GotPltType::IFUNC,
            R_X86_64_RELATIVE => continue, // No symbol associated
            _ => continue,
        };

        let sym_idx = rela.sym(is_64bit) as usize;
        let symbol_name = if sym_idx > 0 && sym_idx < symbols.len() {
            symbols[sym_idx].get_name(strtab).map(|s| s.to_string())
        } else {
            None
        };

        stubs.push(GotPltStub {
            address: rela.r_offset,
            entry_type,
            symbol_name,
        });
    }

    stubs
}

// ═══════════════════════════════════════════════════════════════════════════════════
// String Table Extraction
// ═══════════════════════════════════════════════════════════════════════════════════

/// Extract a null-terminated string from a string table at the given offset.
///
/// This is the core function for looking up names in ELF string tables
/// (section name string table, symbol string table, dynamic string table).
pub fn get_string(strtab: &[u8], offset: usize) -> Option<&str> {
    if offset >= strtab.len() {
        return None;
    }
    let end = strtab[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(strtab.len());
    std::str::from_utf8(&strtab[offset..end]).ok()
}

/// Extract all strings from a string table.
///
/// Returns a vector of (offset, string) pairs.
pub fn extract_strings(strtab: &[u8]) -> Vec<(usize, String)> {
    let mut strings = Vec::new();
    let mut start = 0;
    while start < strtab.len() {
        let end = strtab[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(strtab.len());
        if end > start {
            if let Ok(s) = std::str::from_utf8(&strtab[start..end]) {
                if !s.is_empty() {
                    strings.push((start, s.to_string()));
                }
            }
        }
        start = end + 1;
    }
    strings
}

/// Extract a string table section from the ELF data.
///
/// Looks for the SHT_STRTAB section with the given name (e.g., ".strtab", ".dynstr").
/// Returns the raw string table bytes.
pub fn extract_string_table<'a>(
    section_headers: &[SectionHeader],
    file_data: &'a [u8],
    shstrtab: &[u8],
    section_name: &str,
) -> Option<&'a [u8]> {
    for shdr in section_headers {
        if shdr.sh_type == SHT_STRTAB {
            if let Some(name) = shdr.get_name(shstrtab) {
                if name == section_name {
                    return shdr.data(file_data);
                }
            }
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Endian-aware Nom Parsers (runtime-determined endianness)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parse a u16 with runtime endianness.
fn parse_u16(is_le: bool) -> impl Fn(&[u8]) -> IResult<&[u8], u16> {
    move |input: &[u8]| {
        if input.len() < 2 {
            return Err(nom::Err::Incomplete(nom::Needed::new(2)));
        }
        let val = if is_le {
            u16::from_le_bytes(input[..2].try_into().unwrap())
        } else {
            u16::from_be_bytes(input[..2].try_into().unwrap())
        };
        Ok((&input[2..], val))
    }
}

/// Parse a u32 with runtime endianness.
fn parse_u32(is_le: bool) -> impl Fn(&[u8]) -> IResult<&[u8], u32> {
    move |input: &[u8]| {
        if input.len() < 4 {
            return Err(nom::Err::Incomplete(nom::Needed::new(4)));
        }
        let val = if is_le {
            u32::from_le_bytes(input[..4].try_into().unwrap())
        } else {
            u32::from_be_bytes(input[..4].try_into().unwrap())
        };
        Ok((&input[4..], val))
    }
}

/// Parse a u64 with runtime endianness.
fn parse_u64(is_le: bool) -> impl Fn(&[u8]) -> IResult<&[u8], u64> {
    move |input: &[u8]| {
        if input.len() < 8 {
            return Err(nom::Err::Incomplete(nom::Needed::new(8)));
        }
        let val = if is_le {
            u64::from_le_bytes(input[..8].try_into().unwrap())
        } else {
            u64::from_be_bytes(input[..8].try_into().unwrap())
        };
        Ok((&input[8..], val))
    }
}

/// Parse an i64 with runtime endianness.
fn parse_i64(is_le: bool) -> impl Fn(&[u8]) -> IResult<&[u8], i64> {
    move |input: &[u8]| {
        if input.len() < 8 {
            return Err(nom::Err::Incomplete(nom::Needed::new(8)));
        }
        let val = if is_le {
            i64::from_le_bytes(input[..8].try_into().unwrap())
        } else {
            i64::from_be_bytes(input[..8].try_into().unwrap())
        };
        Ok((&input[8..], val))
    }
}

/// Parse an ELF32_Phdr using nom combinators.
fn parse_elf32_phdr(input: &[u8], is_le: bool) -> IResult<&[u8], ProgramHeader> {
    let (input, p_type) = parse_u32(is_le)(input)?;
    let (input, p_offset) = parse_u32(is_le)(input)?;
    let (input, p_vaddr) = parse_u32(is_le)(input)?;
    let (input, p_paddr) = parse_u32(is_le)(input)?;
    let (input, p_filesz) = parse_u32(is_le)(input)?;
    let (input, p_memsz) = parse_u32(is_le)(input)?;
    let (input, p_flags) = parse_u32(is_le)(input)?;
    let (input, p_align) = parse_u32(is_le)(input)?;

    Ok((input, ProgramHeader {
        p_type,
        p_flags,
        p_offset: p_offset as u64,
        p_vaddr: p_vaddr as u64,
        p_paddr: p_paddr as u64,
        p_filesz: p_filesz as u64,
        p_memsz: p_memsz as u64,
        p_align: p_align as u64,
    }))
}

/// Parse an ELF64_Phdr using nom combinators.
fn parse_elf64_phdr(input: &[u8], is_le: bool) -> IResult<&[u8], ProgramHeader> {
    let (input, p_type) = parse_u32(is_le)(input)?;
    let (input, p_flags) = parse_u32(is_le)(input)?;
    let (input, p_offset) = parse_u64(is_le)(input)?;
    let (input, p_vaddr) = parse_u64(is_le)(input)?;
    let (input, p_paddr) = parse_u64(is_le)(input)?;
    let (input, p_filesz) = parse_u64(is_le)(input)?;
    let (input, p_memsz) = parse_u64(is_le)(input)?;
    let (input, p_align) = parse_u64(is_le)(input)?;

    Ok((input, ProgramHeader {
        p_type,
        p_flags,
        p_offset,
        p_vaddr,
        p_paddr,
        p_filesz,
        p_memsz,
        p_align,
    }))
}

/// Parse an ELF32_Shdr using nom combinators.
fn parse_elf32_shdr(input: &[u8], is_le: bool) -> IResult<&[u8], SectionHeader> {
    let (input, sh_name) = parse_u32(is_le)(input)?;
    let (input, sh_type) = parse_u32(is_le)(input)?;
    let (input, sh_flags) = parse_u32(is_le)(input)?;
    let (input, sh_addr) = parse_u32(is_le)(input)?;
    let (input, sh_offset) = parse_u32(is_le)(input)?;
    let (input, sh_size) = parse_u32(is_le)(input)?;
    let (input, sh_link) = parse_u32(is_le)(input)?;
    let (input, sh_info) = parse_u32(is_le)(input)?;
    let (input, sh_addralign) = parse_u32(is_le)(input)?;
    let (input, sh_entsize) = parse_u32(is_le)(input)?;

    Ok((input, SectionHeader {
        sh_name,
        sh_type,
        sh_flags: sh_flags as u64,
        sh_addr: sh_addr as u64,
        sh_offset: sh_offset as u64,
        sh_size: sh_size as u64,
        sh_link,
        sh_info,
        sh_addralign: sh_addralign as u64,
        sh_entsize: sh_entsize as u64,
    }))
}

/// Parse an ELF64_Shdr using nom combinators.
fn parse_elf64_shdr(input: &[u8], is_le: bool) -> IResult<&[u8], SectionHeader> {
    let (input, sh_name) = parse_u32(is_le)(input)?;
    let (input, sh_type) = parse_u32(is_le)(input)?;
    let (input, sh_flags) = parse_u64(is_le)(input)?;
    let (input, sh_addr) = parse_u64(is_le)(input)?;
    let (input, sh_offset) = parse_u64(is_le)(input)?;
    let (input, sh_size) = parse_u64(is_le)(input)?;
    let (input, sh_link) = parse_u32(is_le)(input)?;
    let (input, sh_info) = parse_u32(is_le)(input)?;
    let (input, sh_addralign) = parse_u64(is_le)(input)?;
    let (input, sh_entsize) = parse_u64(is_le)(input)?;

    Ok((input, SectionHeader {
        sh_name,
        sh_type,
        sh_flags,
        sh_addr,
        sh_offset,
        sh_size,
        sh_link,
        sh_info,
        sh_addralign,
        sh_entsize,
    }))
}

/// Parse an ELF32_Sym using nom combinators.
fn parse_elf32_sym(input: &[u8], is_le: bool) -> IResult<&[u8], SymbolEntry> {
    let (input, st_name) = parse_u32(is_le)(input)?;
    let (input, st_value) = parse_u32(is_le)(input)?;
    let (input, st_size) = parse_u32(is_le)(input)?;
    let (input, st_info) = take(1usize)(input)?;
    let (input, st_other) = take(1usize)(input)?;
    let (input, st_shndx) = parse_u16(is_le)(input)?;

    Ok((input, SymbolEntry {
        st_name,
        st_info: st_info[0],
        st_other: st_other[0],
        st_shndx,
        st_value: st_value as u64,
        st_size: st_size as u64,
    }))
}

/// Parse an ELF64_Sym using nom combinators.
fn parse_elf64_sym(input: &[u8], is_le: bool) -> IResult<&[u8], SymbolEntry> {
    let (input, st_name) = parse_u32(is_le)(input)?;
    let (input, st_info) = take(1usize)(input)?;
    let (input, st_other) = take(1usize)(input)?;
    let (input, st_shndx) = parse_u16(is_le)(input)?;
    let (input, st_value) = parse_u64(is_le)(input)?;
    let (input, st_size) = parse_u64(is_le)(input)?;

    Ok((input, SymbolEntry {
        st_name,
        st_info: st_info[0],
        st_other: st_other[0],
        st_shndx,
        st_value,
        st_size,
    }))
}

/// Parse an ELF32_Rel using nom combinators.
fn parse_elf32_rel(input: &[u8], is_le: bool) -> IResult<&[u8], RelocationEntry> {
    let (input, r_offset) = parse_u32(is_le)(input)?;
    let (input, r_info) = parse_u32(is_le)(input)?;

    Ok((input, RelocationEntry {
        r_offset: r_offset as u64,
        r_info: r_info as u64,
    }))
}

/// Parse an ELF64_Rel using nom combinators.
fn parse_elf64_rel(input: &[u8], is_le: bool) -> IResult<&[u8], RelocationEntry> {
    let (input, r_offset) = parse_u64(is_le)(input)?;
    let (input, r_info) = parse_u64(is_le)(input)?;

    Ok((input, RelocationEntry { r_offset, r_info }))
}

/// Parse an ELF32_Rela using nom combinators.
fn parse_elf32_rela(input: &[u8], is_le: bool) -> IResult<&[u8], RelaEntry> {
    let (input, r_offset) = parse_u32(is_le)(input)?;
    let (input, r_info) = parse_u32(is_le)(input)?;
    let (input, r_addend) = parse_u32(is_le)(input)?;

    Ok((input, RelaEntry {
        r_offset: r_offset as u64,
        r_info: r_info as u64,
        r_addend: r_addend as i32 as i64,
    }))
}

/// Parse an ELF64_Rela using nom combinators.
fn parse_elf64_rela(input: &[u8], is_le: bool) -> IResult<&[u8], RelaEntry> {
    let (input, r_offset) = parse_u64(is_le)(input)?;
    let (input, r_info) = parse_u64(is_le)(input)?;
    let (input, r_addend) = parse_i64(is_le)(input)?;

    Ok((input, RelaEntry { r_offset, r_info, r_addend }))
}

/// Parse an ELF32_Dyn using nom combinators.
fn parse_elf32_dyn(input: &[u8], is_le: bool) -> IResult<&[u8], DynamicEntry> {
    let (input, d_tag) = parse_u32(is_le)(input)?;
    let (input, d_val) = parse_u32(is_le)(input)?;

    Ok((input, DynamicEntry {
        d_tag: d_tag as u64,
        d_val: d_val as u64,
    }))
}

/// Parse an ELF64_Dyn using nom combinators.
fn parse_elf64_dyn(input: &[u8], is_le: bool) -> IResult<&[u8], DynamicEntry> {
    let (input, d_tag) = parse_u64(is_le)(input)?;
    let (input, d_val) = parse_u64(is_le)(input)?;

    Ok((input, DynamicEntry { d_tag, d_val }))
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Main ELF Parser
// ═══════════════════════════════════════════════════════════════════════════════════

/// Maximum number of program headers (sanity limit).
const MAX_PROGRAM_HEADERS: u16 = 4096;
/// Maximum number of section headers (sanity limit).
const MAX_SECTION_HEADERS: u16 = 32767;

/// Parse the ELF header (e_ident + fixed fields) using nom combinators.
fn parse_elf_header(input: &[u8]) -> IResult<&[u8], ElfHeader> {
    if input.len() < EI_NIDENT {
        return Err(nom::Err::Incomplete(nom::Needed::new(EI_NIDENT)));
    }

    // Parse e_ident magic
    let (input, magic) = take(4usize)(input)?;
    let (input, ei_class) = take(1usize)(input)?;
    let (input, ei_data) = take(1usize)(input)?;
    let (input, ei_version) = take(1usize)(input)?;
    let (input, ei_osabi) = take(1usize)(input)?;
    let (input, ei_abiversion) = take(1usize)(input)?;
    let (input, ei_pad) = take(7usize)(input)?;

    let class = ElfClass::from_byte(ei_class[0])
        .ok_or(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))?;
    let data_enc = ElfData::from_byte(ei_data[0])
        .unwrap_or(ElfData::None);
    let is_64bit = matches!(class, ElfClass::ELF64);
    let is_le = data_enc.is_le();
    let is_be = data_enc.is_be();

    // We must have valid endianness
    if !is_le && !is_be {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)));
    }

    let ident = ElfIdentification {
        magic: magic.try_into().unwrap(),
        class,
        data: data_enc,
        ei_version: ei_version[0],
        ei_osabi: ei_osabi[0],
        ei_abiversion: ei_abiversion[0],
        ei_pad: ei_pad.try_into().unwrap(),
    };

    let mut remaining = input;

    // Parse remaining header fields with runtime endianness using destructuring
    let (rem, e_type) = parse_u16(is_le)(remaining)?;
    remaining = rem;
    let (rem, machine) = parse_u16(is_le)(remaining)?;
    remaining = rem;
    let (rem, e_version) = parse_u32(is_le)(remaining)?;
    remaining = rem;

    let (entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx);

    if is_64bit {
        let (rem, entry64) = parse_u64(is_le)(remaining)?;
        remaining = rem;
        let (rem, phoff64) = parse_u64(is_le)(remaining)?;
        remaining = rem;
        let (rem, shoff64) = parse_u64(is_le)(remaining)?;
        remaining = rem;
        let (rem, flags32) = parse_u32(is_le)(remaining)?;
        remaining = rem;
        let (rem, ehsize16) = parse_u16(is_le)(remaining)?;
        remaining = rem;
        let (rem, phentsize16) = parse_u16(is_le)(remaining)?;
        remaining = rem;
        let (rem, phnum16) = parse_u16(is_le)(remaining)?;
        remaining = rem;
        let (rem, shentsize16) = parse_u16(is_le)(remaining)?;
        remaining = rem;
        let (rem, shnum16) = parse_u16(is_le)(remaining)?;
        remaining = rem;
        let (rem, shstrndx16) = parse_u16(is_le)(remaining)?;
        remaining = rem;

        entry = entry64;
        phoff = phoff64;
        shoff = shoff64;
        flags = flags32;
        ehsize = ehsize16;
        phentsize = phentsize16;
        phnum = phnum16;
        shentsize = shentsize16;
        shnum = shnum16;
        shstrndx = shstrndx16;
    } else {
        let (rem, entry32) = parse_u32(is_le)(remaining)?;
        remaining = rem;
        let (rem, phoff32) = parse_u32(is_le)(remaining)?;
        remaining = rem;
        let (rem, shoff32) = parse_u32(is_le)(remaining)?;
        remaining = rem;
        let (rem, flags32) = parse_u32(is_le)(remaining)?;
        remaining = rem;
        let (rem, ehsize16) = parse_u16(is_le)(remaining)?;
        remaining = rem;
        let (rem, phentsize16) = parse_u16(is_le)(remaining)?;
        remaining = rem;
        let (rem, phnum16) = parse_u16(is_le)(remaining)?;
        remaining = rem;
        let (rem, shentsize16) = parse_u16(is_le)(remaining)?;
        remaining = rem;
        let (rem, shnum16) = parse_u16(is_le)(remaining)?;
        remaining = rem;
        let (rem, shstrndx16) = parse_u16(is_le)(remaining)?;
        remaining = rem;

        entry = entry32 as u64;
        phoff = phoff32 as u64;
        shoff = shoff32 as u64;
        flags = flags32;
        ehsize = ehsize16;
        phentsize = phentsize16;
        phnum = phnum16;
        shentsize = shentsize16;
        shnum = shnum16;
        shstrndx = shstrndx16;
    }

    Ok((remaining, ElfHeader {
        ident,
        e_type,
        machine,
        e_version,
        entry,
        phoff,
        shoff,
        flags,
        ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx,
    }))
}

/// Parse a complete ELF file from a byte slice.
///
/// This is the main entry point. It parses the ELF header, program headers,
/// section headers, symbols, dynamic entries, relocations, hash tables, notes,
/// and detects GOT/PLT stubs.
///
/// # Example
///
/// ```rust,ignore
/// use ghidra_features::fileformats::elf;
///
/// let data = std::fs::read("my_elf_binary").unwrap();
/// let elf_file = elf::parse_elf(&data).unwrap();
/// println!("ELF type: {}", elf_file.header.type_name());
/// println!("Machine: {}", elf_file.header.machine_name());
/// println!("Entry point: {:#x}", elf_file.header.entry);
/// ```
pub fn parse_elf(data: &[u8]) -> ElfResult<ElfFile> {
    // First pass: use nom to validate magic bytes
    let (remaining, header) = parse_elf_header(data)
        .map_err(|e| match e {
            nom::Err::Incomplete(_) => ElfError::TruncatedData,
            nom::Err::Error(_) => {
                if data.len() >= 4 && data[0..4] != ELF_MAGIC {
                    ElfError::InvalidMagic
                } else {
                    ElfError::TruncatedData
                }
            }
            nom::Err::Failure(_) => ElfError::InvalidHeader("Failed to parse ELF header".into()),
        })?;

    // Validate magic
    if header.ident.magic != ELF_MAGIC {
        return Err(ElfError::InvalidMagic);
    }

    let is_64bit = header.is_64bit();
    let is_le = header.is_le();

    // Sanity checks on header counts
    if header.phnum > MAX_PROGRAM_HEADERS {
        return Err(ElfError::TooManyProgramHeaders(header.phnum));
    }
    if header.shnum > MAX_SECTION_HEADERS {
        return Err(ElfError::TooManySectionHeaders(header.shnum));
    }

    let _ = remaining; // Use remaining bytes for program/section headers

    // Parse program headers using nom combinators
    let mut program_headers: Vec<ProgramHeader> = Vec::with_capacity(header.phnum as usize);
    if header.phoff > 0 && header.phentsize > 0 && header.phnum > 0 {
        let phdr_size = if is_64bit { 56 } else { 32 };
        for i in 0..header.phnum as usize {
            let offset = header.phoff as usize + i * header.phentsize as usize;
            if offset + phdr_size > data.len() {
                break;
            }
            let phdr_data = &data[offset..offset + phdr_size];
            let result = if is_64bit {
                parse_elf64_phdr(phdr_data, is_le)
            } else {
                parse_elf32_phdr(phdr_data, is_le)
            };
            if let Ok((_, ph)) = result {
                program_headers.push(ph);
            }
        }
    }

    // Parse section headers using nom combinators
    let mut section_headers: Vec<SectionHeader> = Vec::with_capacity(header.shnum as usize);
    let shdr_size = if is_64bit { 64 } else { 40 };
    if header.shoff > 0 && header.shentsize > 0 && header.shnum > 0 {
        for i in 0..header.shnum as usize {
            let offset = header.shoff as usize + i * header.shentsize as usize;
            if offset + shdr_size > data.len() {
                break;
            }
            let shdr_data = &data[offset..offset + shdr_size];
            let result = if is_64bit {
                parse_elf64_shdr(shdr_data, is_le)
            } else {
                parse_elf32_shdr(shdr_data, is_le)
            };
            if let Ok((_, sh)) = result {
                section_headers.push(sh);
            }
        }
    }

    // Load section header string table
    let shstrtab: Option<Vec<u8>> = {
        let idx = header.shstrndx as usize;
        section_headers.get(idx).and_then(|shdr| {
            let off = shdr.sh_offset as usize;
            let sz = shdr.sh_size as usize;
            if off + sz <= data.len() && sz > 0 {
                Some(data[off..off + sz].to_vec())
            } else {
                None
            }
        })
    };

    // Parse symbols from SYMTAB and DYNSYM sections using nom combinators
    let mut symbols: Vec<SymbolEntry> = Vec::new();
    let mut dynsyms: Vec<SymbolEntry> = Vec::new();
    for shdr in &section_headers {
        if shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM {
            if let Some(sec_data) = shdr.data(data) {
                let ent_size = if shdr.sh_entsize > 0 {
                    shdr.sh_entsize as usize
                } else if is_64bit {
                    24
                } else {
                    16
                };
                let count = sec_data.len() / ent_size;
                let mut section_syms = Vec::with_capacity(count);
                for i in 0..count {
                    let off = i * ent_size;
                    if off + ent_size > sec_data.len() {
                        break;
                    }
                    let sym_data = &sec_data[off..off + ent_size];
                    let result = if is_64bit {
                        parse_elf64_sym(sym_data, is_le)
                    } else {
                        parse_elf32_sym(sym_data, is_le)
                    };
                    if let Ok((_, sym)) = result {
                        section_syms.push(sym);
                    }
                }
                if shdr.sh_type == SHT_DYNSYM {
                    dynsyms = section_syms;
                } else {
                    symbols.extend(section_syms);
                }
            }
        }
    }
    // Also include dynsyms in the main symbols list
    symbols.extend_from_slice(&dynsyms);

    // Parse dynamic entries from the PT_DYNAMIC segment using nom combinators
    let mut dynamic_entries: Vec<DynamicEntry> = Vec::new();
    let mut dynamic_map: HashMap<u64, u64> = HashMap::new();
    for phdr in &program_headers {
        if phdr.p_type == PT_DYNAMIC {
            let dent_size = if is_64bit { 16 } else { 8 };
            if let Some(dyn_data) = phdr.file_data(data) {
                let count = dyn_data.len() / dent_size;
                for i in 0..count {
                    let off = i * dent_size;
                    if off + dent_size > dyn_data.len() {
                        break;
                    }
                    let entry_data = &dyn_data[off..off + dent_size];
                    let result = if is_64bit {
                        parse_elf64_dyn(entry_data, is_le)
                    } else {
                        parse_elf32_dyn(entry_data, is_le)
                    };
                    if let Ok((_, entry)) = result {
                        dynamic_map.insert(entry.d_tag, entry.d_val);
                        dynamic_entries.push(entry.clone());
                        if entry.d_tag == DT_NULL {
                            break;
                        }
                    }
                }
            }
            break; // Only process one PT_DYNAMIC segment
        }
    }

    // Parse relocations (SHT_REL and SHT_RELA) using nom combinators
    let mut relocations: Vec<RelocationEntry> = Vec::new();
    let mut rela_relocations: Vec<RelaEntry> = Vec::new();
    for shdr in &section_headers {
        match shdr.sh_type {
            SHT_REL => {
                if let Some(sec_data) = shdr.data(data) {
                    let ent_size = if shdr.sh_entsize > 0 {
                        shdr.sh_entsize as usize
                    } else if is_64bit {
                        16
                    } else {
                        8
                    };
                    let count = sec_data.len() / ent_size;
                    for i in 0..count {
                        let off = i * ent_size;
                        if off + ent_size > sec_data.len() {
                            break;
                        }
                        let rel_data = &sec_data[off..off + ent_size];
                        let result = if is_64bit {
                            parse_elf64_rel(rel_data, is_le)
                        } else {
                            parse_elf32_rel(rel_data, is_le)
                        };
                        if let Ok((_, rel)) = result {
                            relocations.push(rel);
                        }
                    }
                }
            }
            SHT_RELA => {
                if let Some(sec_data) = shdr.data(data) {
                    let ent_size = if shdr.sh_entsize > 0 {
                        shdr.sh_entsize as usize
                    } else if is_64bit {
                        24
                    } else {
                        12
                    };
                    let count = sec_data.len() / ent_size;
                    for i in 0..count {
                        let off = i * ent_size;
                        if off + ent_size > sec_data.len() {
                            break;
                        }
                        let rela_data = &sec_data[off..off + ent_size];
                        let result = if is_64bit {
                            parse_elf64_rela(rela_data, is_le)
                        } else {
                            parse_elf32_rela(rela_data, is_le)
                        };
                        if let Ok((_, rela)) = result {
                            rela_relocations.push(rela);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Parse GNU hash table
    let gnu_hash: Option<GnuHashTable> = {
        section_headers.iter().find_map(|shdr| {
            if shdr.sh_type == SHT_GNU_HASH {
                shdr.data(data).and_then(|d| parse_gnu_hash(d, is_64bit).ok())
            } else {
                None
            }
        })
    };

    // Parse SYSV hash table
    let sysv_hash: Option<HashTable> = {
        section_headers.iter().find_map(|shdr| {
            if shdr.sh_type == SHT_HASH {
                shdr.data(data).and_then(|d| parse_sysv_hash(d).ok())
            } else {
                None
            }
        })
    };

    // Extract dynamic string table (.dynstr)
    let dynstr: Option<Vec<u8>> = {
        let shstrtab_ref = shstrtab.as_deref().unwrap_or(&[]);
        section_headers.iter().find_map(|shdr| {
            if shdr.sh_type == SHT_STRTAB && shdr.get_name(shstrtab_ref) == Some(".dynstr") {
                shdr.data(data).map(|d| d.to_vec())
            } else {
                None
            }
        })
    };

    // Parse notes from PT_NOTE segments
    let mut notes: Vec<NoteEntry> = Vec::new();
    for phdr in &program_headers {
        if phdr.p_type == PT_NOTE {
            if let Some(note_data) = phdr.file_data(data) {
                if let Ok(parsed_notes) = parse_notes(note_data) {
                    notes.extend(parsed_notes);
                }
            }
        }
    }
    // Also parse notes from SHT_NOTE sections
    for shdr in &section_headers {
        if shdr.sh_type == SHT_NOTE {
            if let Some(note_data) = shdr.data(data) {
                if let Ok(parsed_notes) = parse_notes(note_data) {
                    notes.extend(parsed_notes);
                }
            }
        }
    }

    // Detect GOT/PLT stubs
    let got_plt_stubs: Vec<GotPltStub> = {
        let strtab = dynstr.as_deref().unwrap_or(&[]);
        // Use dynsyms if available, otherwise fall back to regular symbols
        if dynsyms.is_empty() {
            detect_got_plt_stubs(&dynamic_map, &rela_relocations, &symbols, strtab, is_64bit)
        } else {
            detect_got_plt_stubs(&dynamic_map, &rela_relocations, &dynsyms, strtab, is_64bit)
        }
    };

    Ok(ElfFile {
        header,
        program_headers,
        section_headers,
        symbols,
        dynamic_entries,
        relocations,
        rela_relocations,
        shstrtab,
        gnu_hash,
        sysv_hash,
        notes,
        got_plt_stubs,
        dynstr,
        dynsyms,
        dynamic_map,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ElfFile Implementation
// ═══════════════════════════════════════════════════════════════════════════════════

impl ElfFile {
    /// Find a section header by name.
    pub fn section_by_name(&self, name: &str) -> Option<&SectionHeader> {
        let strtab = self.shstrtab.as_deref().unwrap_or(&[]);
        self.section_headers
            .iter()
            .find(|sh| sh.get_name(strtab).map_or(false, |n| n == name))
    }

    /// Find a section header by type.
    pub fn sections_by_type(&self, shtype: u32) -> Vec<&SectionHeader> {
        self.section_headers
            .iter()
            .filter(|sh| sh.sh_type == shtype)
            .collect()
    }

    /// Return all LOAD program headers (segments).
    pub fn load_segments(&self) -> Vec<&ProgramHeader> {
        self.program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .collect()
    }

    /// Find the program header containing a given virtual address.
    pub fn segment_for_vaddr(&self, vaddr: u64) -> Option<&ProgramHeader> {
        self.program_headers.iter().find(|ph| {
            ph.p_type == PT_LOAD && vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr + ph.p_memsz
        })
    }

    /// Find a program header by type.
    pub fn segment_by_type(&self, ptype: u32) -> Option<&ProgramHeader> {
        self.program_headers.iter().find(|ph| ph.p_type == ptype)
    }

    /// Find a dynamic entry by tag.
    pub fn dynamic_by_tag(&self, tag: u64) -> Option<&DynamicEntry> {
        self.dynamic_entries.iter().find(|d| d.d_tag == tag)
    }

    /// Get a dynamic entry value by tag (from the pre-built map).
    pub fn dynamic_value(&self, tag: u64) -> Option<u64> {
        self.dynamic_map.get(&tag).copied()
    }

    /// Return the interpreter path (from PT_INTERP segment data).
    pub fn interpreter(&self, file_data: &[u8]) -> Option<String> {
        let phdr = self.segment_by_type(PT_INTERP)?;
        let data = phdr.file_data(file_data)?;
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        std::str::from_utf8(&data[..end]).ok().map(|s| s.to_string())
    }

    /// Return the SONAME from the dynamic section.
    pub fn soname(&self) -> Option<String> {
        let soname_tag = self.dynamic_value(DT_SONAME)?;
        let strtab = self.dynstr.as_deref().unwrap_or(&[]);
        get_string(strtab, soname_tag as usize).map(|s| s.to_string())
    }

    /// Return the list of NEEDED shared libraries.
    pub fn needed_libraries(&self) -> Vec<String> {
        let mut libs = Vec::new();
        let strtab = self.dynstr.as_deref().unwrap_or(&[]);
        for entry in &self.dynamic_entries {
            if entry.d_tag == DT_NEEDED && entry.d_val > 0 {
                if let Some(name) = get_string(strtab, entry.d_val as usize) {
                    libs.push(name.to_string());
                }
            }
        }
        libs
    }

    /// Return the RPATH/RUNPATH from the dynamic section.
    pub fn rpath(&self) -> Option<String> {
        let rpath_val = self.dynamic_value(DT_RPATH)
            .or_else(|| self.dynamic_value(DT_RUNPATH))?;
        let strtab = self.dynstr.as_deref().unwrap_or(&[]);
        get_string(strtab, rpath_val as usize).map(|s| s.to_string())
    }

    /// Find a symbol by name in the symbol table.
    pub fn symbol_by_name(&self, name: &str, strtab: &[u8]) -> Option<&SymbolEntry> {
        self.symbols
            .iter()
            .find(|sym| sym.get_name(strtab).map_or(false, |n| n == name))
    }

    /// Find all symbols with a given binding (STB_LOCAL, STB_GLOBAL, STB_WEAK).
    pub fn symbols_by_binding(&self, bind: u8) -> Vec<&SymbolEntry> {
        self.symbols.iter().filter(|sym| sym.bind() == bind).collect()
    }

    /// Find all symbols with a given type (STT_FUNC, STT_OBJECT, etc.).
    pub fn symbols_by_type(&self, stype: u8) -> Vec<&SymbolEntry> {
        self.symbols.iter().filter(|sym| sym.stype() == stype).collect()
    }

    /// Return all exported (global) function symbols.
    pub fn exported_functions(&self, strtab: &[u8]) -> Vec<(u64, String)> {
        self.symbols
            .iter()
            .filter(|sym| sym.is_global() && sym.is_function() && !sym.is_undefined())
            .filter_map(|sym| {
                sym.get_name(strtab)
                    .map(|n| (sym.st_value, n.to_string()))
            })
            .collect()
    }

    /// Return the .text section header if it exists.
    pub fn text_section(&self) -> Option<&SectionHeader> {
        self.section_by_name(".text")
    }

    /// Return the .data section header if it exists.
    pub fn data_section(&self) -> Option<&SectionHeader> {
        self.section_by_name(".data")
    }

    /// Return the .rodata section header if it exists.
    pub fn rodata_section(&self) -> Option<&SectionHeader> {
        self.section_by_name(".rodata")
    }

    /// Return the .bss section header if it exists.
    pub fn bss_section(&self) -> Option<&SectionHeader> {
        self.section_by_name(".bss")
    }

    /// Return the symbol string table (.strtab) data.
    pub fn sym_strtab<'a>(&self, file_data: &'a [u8]) -> Option<&'a [u8]> {
        let strtab = self.shstrtab.as_deref().unwrap_or(&[]);
        for shdr in &self.section_headers {
            if shdr.sh_type == SHT_STRTAB && shdr.get_name(strtab) == Some(".strtab") {
                return shdr.data(file_data);
            }
        }
        None
    }

    /// Count the number of symbols with each binding type.
    pub fn symbol_binding_counts(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for sym in &self.symbols {
            *counts.entry(bind_name(sym.bind()).to_string()).or_insert(0) += 1;
        }
        counts
    }

    /// Print a summary of the ELF file for debugging.
    pub fn summary(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("ELF File Summary\n"));
        s.push_str(&format!("=================\n"));
        s.push_str(&format!("  Class:       {}\n", self.header.ident.class));
        s.push_str(&format!("  Data:        {}\n", self.header.ident.data));
        s.push_str(&format!("  Type:        {}\n", self.header.type_name()));
        s.push_str(&format!("  Machine:     {}\n", self.header.machine_name()));
        s.push_str(&format!("  Entry:       {:#018x}\n", self.header.entry));
        s.push_str(&format!("  OS/ABI:      {}\n", osabi_name(self.header.ident.ei_osabi)));
        s.push_str(&format!("  ABIVersion:  {}\n", self.header.ident.ei_abiversion));
        s.push_str(&format!("  Flags:       {:#010x}\n", self.header.flags));
        s.push_str(&format!("  Program Hdrs: {} (offset {:#x})\n", self.program_headers.len(), self.header.phoff));
        s.push_str(&format!("  Section Hdrs: {} (offset {:#x})\n", self.section_headers.len(), self.header.shoff));
        s.push_str(&format!("  Shstrndx:    {}\n", self.header.shstrndx));
        s.push_str(&format!("  Symbols:     {}\n", self.symbols.len()));
        s.push_str(&format!("  .dynsym:     {}\n", self.dynsyms.len()));
        s.push_str(&format!("  Dynamic:     {}\n", self.dynamic_entries.len()));
        s.push_str(&format!("  REL:         {}\n", self.relocations.len()));
        s.push_str(&format!("  RELA:        {}\n", self.rela_relocations.len()));
        s.push_str(&format!("  GNU Hash:    {}\n", if self.gnu_hash.is_some() { "yes" } else { "no" }));
        s.push_str(&format!("  SYSV Hash:   {}\n", if self.sysv_hash.is_some() { "yes" } else { "no" }));
        s.push_str(&format!("  Notes:       {}\n", self.notes.len()));
        s.push_str(&format!("  GOT/PLT:     {}\n", self.got_plt_stubs.len()));
        s.push_str(&format!("  NEEDED:      [{}]\n", self.needed_libraries().join(", ")));

        // Print segments
        if !self.program_headers.is_empty() {
            s.push_str(&format!("\n  Segments:\n"));
            for phdr in &self.program_headers {
                if phdr.p_type != PT_NULL {
                    s.push_str(&format!(
                        "    {:14} offset={:#010x} vaddr={:#018x} filesz={:#x} memsz={:#x} flags={}\n",
                        phdr.type_name(),
                        phdr.p_offset,
                        phdr.p_vaddr,
                        phdr.p_filesz,
                        phdr.p_memsz,
                        phdr.flags_str(),
                    ));
                }
            }
        }

        // Print sections
        if !self.section_headers.is_empty() {
            s.push_str(&format!("\n  Sections:\n"));
            let strtab = self.shstrtab.as_deref().unwrap_or(&[]);
            for shdr in &self.section_headers {
                if shdr.sh_type != SHT_NULL {
                    let name = shdr.get_name(strtab).unwrap_or("<unknown>");
                    s.push_str(&format!(
                        "    {:20} {:14} addr={:#018x} offset={:#x} size={:#x}\n",
                        name,
                        shdr.type_name(),
                        shdr.sh_addr,
                        shdr.sh_offset,
                        shdr.sh_size,
                    ));
                }
            }
        }

        s
    }

    /// Returns true if this is a position-independent executable (PIE).
    pub fn is_pie(&self) -> bool {
        self.header.e_type == ET_DYN
            && self.header.entry != 0
            && !self.segment_by_type(PT_INTERP).is_none()
    }

    /// Returns true if this is a shared library (.so).
    pub fn is_shared_library(&self) -> bool {
        self.header.e_type == ET_DYN && self.header.entry == 0
    }

    /// Returns true if this is a statically linked executable.
    pub fn is_static(&self) -> bool {
        self.header.e_type == ET_EXEC
            && self.dynamic_entries.is_empty()
            && self.segment_by_type(PT_INTERP).is_none()
    }

    /// Returns true if this is a core dump.
    pub fn is_core(&self) -> bool {
        self.header.e_type == ET_CORE
    }

    /// Search for a build ID note and return it as a hex string.
    pub fn build_id(&self) -> Option<String> {
        for note in &self.notes {
            if note.n_type == NT_GNU_BUILD_ID && !note.desc.is_empty() {
                return Some(note.desc_hex());
            }
        }
        None
    }

    /// Search for the GNU gold version note.
    pub fn gold_version(&self) -> Option<&str> {
        for note in &self.notes {
            if note.n_type == NT_GNU_GOLD_VERSION && !note.desc.is_empty() {
                let end = note.desc.iter().position(|&b| b == 0).unwrap_or(note.desc.len());
                return std::str::from_utf8(&note.desc[..end]).ok();
            }
        }
        None
    }

    /// Get the initialization function address (DT_INIT).
    pub fn init_address(&self) -> Option<u64> {
        self.dynamic_value(DT_INIT)
    }

    /// Get the finalization function address (DT_FINI).
    pub fn fini_address(&self) -> Option<u64> {
        self.dynamic_value(DT_FINI)
    }

    /// Get the init array addresses (DT_INIT_ARRAY).
    pub fn init_array(&self, file_data: &[u8]) -> Vec<u64> {
        let addr = match self.dynamic_value(DT_INIT_ARRAY) {
            Some(a) => a,
            None => return Vec::new(),
        };
        let sz = match self.dynamic_value(DT_INIT_ARRAYSZ) {
            Some(s) => s,
            None => return Vec::new(),
        };
        let entry_size = self.header.addr_size() as u64;
        let mut addrs = Vec::new();
        let is_le = self.header.is_le();

        // Find the segment containing this address
        for phdr in &self.program_headers {
            if phdr.p_type == PT_LOAD
                && addr >= phdr.p_vaddr
                && addr < phdr.p_vaddr + phdr.p_filesz
            {
                let file_offset = phdr.p_offset + (addr - phdr.p_vaddr);
                let file_end = file_offset + sz;
                if file_end <= file_data.len() as u64 {
                    for off in (file_offset..file_end).step_by(entry_size as usize) {
                        let a = if is_le {
                            if entry_size == 8 {
                                u64::from_le_bytes(file_data[off as usize..off as usize + 8].try_into().unwrap())
                            } else {
                                u32::from_le_bytes(file_data[off as usize..off as usize + 4].try_into().unwrap()) as u64
                            }
                        } else {
                            if entry_size == 8 {
                                u64::from_be_bytes(file_data[off as usize..off as usize + 8].try_into().unwrap())
                            } else {
                                u32::from_be_bytes(file_data[off as usize..off as usize + 4].try_into().unwrap()) as u64
                            }
                        };
                        if a == 0 { break; }
                        addrs.push(a);
                    }
                }
                break;
            }
        }
        addrs
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// BinaryLoader Implementation
// ═══════════════════════════════════════════════════════════════════════════════════

use crate::base::analyzer::{
    Address, AddressRange, AddressSet, Function, FunctionManager, Language,
    Listing, MemoryBlock, Program,
};

/// ELF machine code to Ghidra processor name mapping.
fn elf_machine_to_processor(machine: u16) -> (&'static str, &'static str, u32) {
    match machine {
        EM_386 => ("x86", "LE", 32),
        EM_X86_64 => ("x86", "LE", 64),
        EM_ARM => ("ARM", "LE", 32),
        EM_AARCH64 => ("AARCH64", "LE", 64),
        EM_MIPS => ("MIPS", "BE", 32),
        EM_PPC => ("PowerPC", "BE", 32),
        EM_PPC64 => ("PowerPC", "BE", 64),
        EM_SPARC => ("sparc", "BE", 32),
        EM_SPARCV9 => ("sparc", "BE", 64),
        EM_RISCV => ("RISCV", "LE", 64),
        EM_S390 => ("S390", "BE", 64),
        EM_SH => ("SuperH", "LE", 32),
        EM_IA_64 => ("IA64", "LE", 64),
        EM_MSP430 => ("MSP430", "LE", 16),
        EM_AVR => ("avr", "LE", 8),
        EM_LOONGARCH => ("LoongArch", "LE", 64),
        _ => ("unknown", "LE", 32),
    }
}

/// ELF binary loader — implements the [`crate::BinaryLoader`] trait.
///
/// Loads an ELF file into a [`Program`] by:
/// 1. Parsing headers and segments via [`parse_elf`]
/// 2. Creating memory blocks for each `PT_LOAD` segment
/// 3. Populating the function manager from the symbol table
/// 4. Setting the image base from the ELF entry point
///
/// Supports ELF32 and ELF64, all endiannesses, all standard architectures.
pub struct ElfLoader;

impl crate::BinaryLoader for ElfLoader {
    fn name(&self) -> &str {
        "ELF"
    }

    fn can_load(&self, data: &[u8]) -> bool {
        data.len() >= 4 && data[0..4] == ELF_MAGIC
    }

    fn load(&self, data: &[u8], options: &crate::LoadOptions) -> anyhow::Result<Program> {
        let elf = parse_elf(data)
            .map_err(|e| anyhow::anyhow!("ELF parse error: {}", e))?;

        let (processor, variant, size) = elf_machine_to_processor(elf.header.machine);
        let architecture = options.architecture.clone().unwrap_or_else(|| {
            format!("{}:{}:{}", processor, variant, size)
        });

        // Extract language components from architecture string
        let lang = {
            let parts: Vec<&str> = architecture.split(':').collect();
            Language {
                processor: parts.first().unwrap_or(&processor).to_string(),
                variant: parts.get(1).unwrap_or(&variant).to_string(),
                size: parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(size),
            }
        };

        let base_addr = if options.base_address != 0 {
            options.base_address
        } else {
            // For shared libraries (ET_DYN), use the first LOAD segment's vaddr
            // For executables, use the entry point from the header
            if elf.header.e_type == ET_DYN {
                elf.program_headers
                    .iter()
                    .find(|ph| ph.is_load())
                    .map(|ph| ph.p_vaddr)
                    .unwrap_or(0)
            } else {
                0 // Default base for PIE / executables
            }
        };

        let mut program = Program::new("elf_binary", lang);
        program.image_base = base_addr;

        // Create memory blocks from PT_LOAD segments
        for phdr in &elf.program_headers {
            if phdr.p_type != PT_LOAD {
                continue;
            }
            let vaddr = phdr.p_vaddr;
            let size = phdr.p_memsz;
            if size == 0 {
                continue;
            }
            let block = MemoryBlock {
                name: format!("segment_{:#x}", vaddr),
                start: Address::new(vaddr),
                size,
                is_read: phdr.is_readable(),
                is_write: phdr.is_writable(),
                is_execute: phdr.is_executable(),
                is_initialized: phdr.p_filesz > 0,
            };
            program.memory.add_range(AddressRange {
                start: Address::new(vaddr),
                end: Address::new(vaddr + size - 1),
            });
            program.memory_blocks.push(block);
        }

        // Also create blocks from alloc sections (catches sections not covered by segments)
        if program.memory_blocks.is_empty() {
            for shdr in &elf.section_headers {
                if !shdr.is_alloc() || shdr.sh_size == 0 {
                    continue;
                }
                let vaddr = shdr.sh_addr;
                let size = shdr.sh_size;
                let block = MemoryBlock {
                    name: format!("section_{:#x}", vaddr),
                    start: Address::new(vaddr),
                    size,
                    is_read: (shdr.sh_flags & SHF_WRITE) == 0 || true, // alloc sections are readable
                    is_write: shdr.is_writable(),
                    is_execute: shdr.is_executable(),
                    is_initialized: shdr.sh_type != SHT_NOBITS,
                };
                program.memory.add_range(AddressRange {
                    start: Address::new(vaddr),
                    end: Address::new(vaddr + size - 1),
                });
                program.memory_blocks.push(block);
            }
        }

        // Populate functions from STT_FUNC symbols
        let strtab = elf.dynstr.as_deref()
            .or_else(|| elf.sym_strtab(data))
            .unwrap_or(&[]);
        for sym in &elf.symbols {
            if sym.stype() == STT_FUNC && sym.st_value != 0 && !sym.is_undefined() {
                let name = sym.get_name(strtab).map(|s| s.to_string());
                let func = Function {
                    entry_point: Address::new(sym.st_value),
                    body: AddressSet::from_range(AddressRange {
                        start: Address::new(sym.st_value),
                        end: Address::new(sym.st_value + sym.st_size.max(1) - 1),
                    }),
                    name,
                    is_external: false,
                    is_thunk: false,
                    is_inline: false,
                    has_noreturn: false,
                    call_fixup: None,
                };
                program
                    .function_manager
                    .functions
                    .insert(Address::new(sym.st_value), func);
            }
        }

        // Add external (imported) functions
        for sym in &elf.dynsyms {
            if sym.stype() == STT_FUNC && sym.is_undefined() && sym.is_global() {
                let name = sym.get_name(strtab).map(|s| s.to_string());
                if let Some(n) = &name {
                    if !n.is_empty() {
                        let func = Function {
                            entry_point: Address::in_space(Address::EXTERNAL_SPACE, 0),
                            body: AddressSet::from_address(Address::in_space(
                                Address::EXTERNAL_SPACE,
                                0,
                            )),
                            name: Some(n.clone()),
                            is_external: true,
                            is_thunk: false,
                            is_inline: false,
                            has_noreturn: false,
                    call_fixup: None,
                        };
                        // Use a synthetic address for external functions
                        let ext_addr = Address::in_space(Address::EXTERNAL_SPACE, sym.st_name as u64);
                        program.function_manager.functions.insert(ext_addr, func);
                    }
                }
            }
        }

        Ok(program)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper: Build a minimal 64-bit LE ELF executable header ──────────

    fn minimal_elf64_le() -> Vec<u8> {
        let mut buf = vec![0u8; 64];
        // e_ident
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[EI_CLASS] = ELFCLASS64;
        buf[EI_DATA] = ELFDATA2LSB;
        buf[EI_VERSION] = EV_CURRENT;
        buf[EI_OSABI] = ELFOSABI_SYSV;
        // e_type = ET_EXEC
        buf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        // e_machine = EM_X86_64
        buf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        // e_version = 1
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_entry = 0x400000
        buf[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
        // phoff = 0, shoff = 0
        // ehsize = 64
        buf[52..54].copy_from_slice(&64u16.to_le_bytes());
        buf
    }

    fn minimal_elf32_le() -> Vec<u8> {
        let mut buf = vec![0u8; 52];
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[EI_CLASS] = ELFCLASS32;
        buf[EI_DATA] = ELFDATA2LSB;
        buf[EI_VERSION] = EV_CURRENT;
        buf[EI_OSABI] = ELFOSABI_SYSV;
        buf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        buf[18..20].copy_from_slice(&EM_386.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[24..28].copy_from_slice(&0x08048000u32.to_le_bytes());
        // ehsize = 52
        buf[40..42].copy_from_slice(&52u16.to_le_bytes());
        buf
    }

    // ── Basic parsing tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_minimal_elf64() {
        let data = minimal_elf64_le();
        let elf = parse_elf(&data).expect("parse minimal ELF64");
        assert_eq!(elf.header.ident.class, ElfClass::ELF64);
        assert_eq!(elf.header.ident.data, ElfData::LittleEndian);
        assert_eq!(elf.header.machine, EM_X86_64);
        assert_eq!(elf.header.entry, 0x400000);
        assert!(elf.header.is_64bit());
        assert!(elf.header.is_le());
        assert_eq!(elf.header.type_name(), "EXEC (Executable file)");
        assert!(elf.program_headers.is_empty());
        assert!(elf.section_headers.is_empty());
    }

    #[test]
    fn test_parse_minimal_elf32() {
        let data = minimal_elf32_le();
        let elf = parse_elf(&data).expect("parse minimal ELF32");
        assert_eq!(elf.header.ident.class, ElfClass::ELF32);
        assert_eq!(elf.header.machine, EM_386);
        assert!(elf.header.is_32bit());
        assert!(!elf.header.is_64bit());
    }

    #[test]
    fn test_invalid_magic() {
        let data = [0u8; 64];
        assert!(matches!(parse_elf(&data), Err(ElfError::InvalidMagic)));
    }

    #[test]
    fn test_truncated() {
        let data = [0x7f, b'E', b'L', b'F'];
        assert!(matches!(parse_elf(&data), Err(ElfError::TruncatedData)));
    }

    #[test]
    fn test_invalid_class() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&ELF_MAGIC);
        data[EI_CLASS] = 99; // invalid
        // The nom parser returns an Error which gets mapped to TruncatedData
        assert!(parse_elf(&data).is_err());
    }

    #[test]
    fn test_big_endian_elf64() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[EI_CLASS] = ELFCLASS64;
        buf[EI_DATA] = ELFDATA2MSB; // Big-endian
        buf[EI_VERSION] = EV_CURRENT;
        buf[16..18].copy_from_slice(&ET_EXEC.to_be_bytes());
        buf[18..20].copy_from_slice(&EM_X86_64.to_be_bytes());
        buf[20..24].copy_from_slice(&1u32.to_be_bytes());
        buf[24..32].copy_from_slice(&0x400000u64.to_be_bytes());
        buf[52..54].copy_from_slice(&64u16.to_be_bytes());

        let elf = parse_elf(&buf).expect("parse BE ELF64");
        assert!(elf.header.is_be());
        assert_eq!(elf.header.entry, 0x400000);
        assert_eq!(elf.header.machine, EM_X86_64);
    }

    // ── Helper: Build a minimal ELF with program headers ────────────────

    /// Build a minimal 64-bit LE ELF with one LOAD segment.
    fn elf64_with_load_segment() -> Vec<u8> {
        let mut buf = vec![0u8; 128];
        // e_ident
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[EI_CLASS] = ELFCLASS64;
        buf[EI_DATA] = ELFDATA2LSB;
        buf[EI_VERSION] = EV_CURRENT;
        buf[EI_OSABI] = ELFOSABI_SYSV;
        // e_type = ET_EXEC
        buf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        buf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
        // phoff = 64 (immediately after header)
        buf[32..40].copy_from_slice(&64u64.to_le_bytes());
        // shoff = 0
        // flags = 0
        // ehsize = 64
        buf[52..54].copy_from_slice(&64u16.to_le_bytes());
        // phentsize = 56
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        // phnum = 1
        buf[56..58].copy_from_slice(&1u16.to_le_bytes());
        // shentsize = 0, shnum = 0, shstrndx = 0

        // Program header at offset 64
        let ph_off = 64;
        buf[ph_off..ph_off+4].copy_from_slice(&PT_LOAD.to_le_bytes());
        buf[ph_off+4..ph_off+8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        buf[ph_off+8..ph_off+16].copy_from_slice(&0u64.to_le_bytes());     // p_offset
        buf[ph_off+16..ph_off+24].copy_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
        buf[ph_off+24..ph_off+32].copy_from_slice(&0x400000u64.to_le_bytes()); // p_paddr
        buf[ph_off+32..ph_off+40].copy_from_slice(&0x1000u64.to_le_bytes());   // p_filesz
        buf[ph_off+40..ph_off+48].copy_from_slice(&0x1000u64.to_le_bytes());   // p_memsz
        buf[ph_off+48..ph_off+56].copy_from_slice(&0x1000u64.to_le_bytes());   // p_align

        buf
    }

    #[test]
    fn test_parse_segment() {
        let data = elf64_with_load_segment();
        let elf = parse_elf(&data).expect("parse ELF with LOAD segment");
        assert_eq!(elf.program_headers.len(), 1);
        let phdr = &elf.program_headers[0];
        assert_eq!(phdr.p_type, PT_LOAD);
        assert!(phdr.is_load());
        assert!(phdr.is_readable());
        assert!(!phdr.is_writable());
        assert!(phdr.is_executable());
        assert_eq!(phdr.p_vaddr, 0x400000);
        assert_eq!(phdr.type_name(), "LOAD");
        assert_eq!(phdr.flags_str(), "RE");
    }

    // ── Helper: Build minimal ELF with section headers ──────────────────

    fn elf64_with_sections() -> Vec<u8> {
        let strtab = b"\0.text\0.data\0.shstrtab\0";
        let mut buf = vec![0u8; 300];
        // e_ident
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[EI_CLASS] = ELFCLASS64;
        buf[EI_DATA] = ELFDATA2LSB;
        buf[EI_VERSION] = EV_CURRENT;
        buf[EI_OSABI] = ELFOSABI_SYSV;
        // e_type
        buf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        buf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        // entry
        buf[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
        // phoff = 0
        // shoff = 64 (immediately after header)
        buf[40..48].copy_from_slice(&64u64.to_le_bytes());
        // flags = 0
        // ehsize = 64
        buf[52..54].copy_from_slice(&64u16.to_le_bytes());
        // phentsize = 0
        // phnum = 0
        // shentsize = 64
        buf[58..60].copy_from_slice(&64u16.to_le_bytes());
        // shnum = 3
        buf[60..62].copy_from_slice(&3u16.to_le_bytes());
        // shstrndx = 2
        buf[62..64].copy_from_slice(&2u16.to_le_bytes());

        // String table data at offset 256
        let strtab_off = 256;
        buf[strtab_off..strtab_off + strtab.len()].copy_from_slice(strtab);

        // Section 0: NULL (offset 64)
        // All zeros by default

        // Section 1: .text (offset 128)
        let sh1 = 128;
        buf[sh1..sh1+4].copy_from_slice(&1u32.to_le_bytes());  // sh_name = 1 (.text)
        buf[sh1+4..sh1+8].copy_from_slice(&SHT_PROGBITS.to_le_bytes());
        buf[sh1+8..sh1+16].copy_from_slice(&(SHF_ALLOC | SHF_EXECINSTR).to_le_bytes()); // sh_flags
        buf[sh1+16..sh1+24].copy_from_slice(&0x400000u64.to_le_bytes()); // sh_addr
        buf[sh1+24..sh1+32].copy_from_slice(&0u64.to_le_bytes());        // sh_offset
        buf[sh1+32..sh1+40].copy_from_slice(&0x100u64.to_le_bytes());    // sh_size

        // Section 2: .shstrtab (offset 192)
        let sh2 = 192;
        buf[sh2..sh2+4].copy_from_slice(&7u32.to_le_bytes());  // sh_name = 7 (.shstrtab)
        buf[sh2+4..sh2+8].copy_from_slice(&SHT_STRTAB.to_le_bytes());
        buf[sh2+24..sh2+32].copy_from_slice(&(strtab_off as u64).to_le_bytes()); // sh_offset
        buf[sh2+32..sh2+40].copy_from_slice(&(strtab.len() as u64).to_le_bytes()); // sh_size

        buf
    }

    #[test]
    fn test_parse_sections() {
        let data = elf64_with_sections();
        let elf = parse_elf(&data).expect("parse ELF with sections");
        assert_eq!(elf.section_headers.len(), 3);
        assert!(elf.shstrtab.is_some());

        let text = elf.section_by_name(".text");
        assert!(text.is_some());
        let text = text.unwrap();
        assert_eq!(text.sh_type, SHT_PROGBITS);
        assert!(text.is_alloc());
        assert!(text.is_executable());
    }

    // ── Constant tests ──────────────────────────────────────────────────

    #[test]
    fn test_machine_name() {
        assert_eq!(machine_name(EM_386), "Intel 80386");
        assert_eq!(machine_name(EM_X86_64), "x86-64");
        assert_eq!(machine_name(EM_ARM), "ARM");
        assert_eq!(machine_name(EM_AARCH64), "AArch64");
        assert_eq!(machine_name(EM_RISCV), "RISC-V");
        assert_eq!(machine_name(999), "UNKNOWN");
    }

    #[test]
    fn test_symbol_bind_and_type() {
        let info = (STB_GLOBAL << 4) | STT_FUNC;
        assert_eq!(st_bind(info), STB_GLOBAL);
        assert_eq!(st_type(info), STT_FUNC);
        assert_eq!(bind_name(STB_GLOBAL), "GLOBAL");
        assert_eq!(type_name(STT_FUNC), "FUNC");
        assert_eq!(bind_name(STB_LOCAL), "LOCAL");
        assert_eq!(bind_name(STB_WEAK), "WEAK");
    }

    #[test]
    fn test_visibility() {
        assert_eq!(st_visibility(STV_DEFAULT), STV_DEFAULT);
        assert_eq!(st_visibility(STV_HIDDEN), STV_HIDDEN);
        assert_eq!(visibility_name(STV_DEFAULT), "DEFAULT");
        assert_eq!(visibility_name(STV_HIDDEN), "HIDDEN");
        assert_eq!(visibility_name(STV_PROTECTED), "PROTECTED");
    }

    #[test]
    fn test_segment_type_name() {
        assert_eq!(segment_type_name(PT_LOAD), "LOAD");
        assert_eq!(segment_type_name(PT_DYNAMIC), "DYNAMIC");
        assert_eq!(segment_type_name(PT_GNU_STACK), "GNU_STACK");
        assert_eq!(segment_type_name(PT_GNU_RELRO), "GNU_RELRO");
        assert_eq!(segment_type_name(PT_GNU_EH_FRAME), "GNU_EH_FRAME");
    }

    #[test]
    fn test_section_type_name() {
        assert_eq!(section_type_name(SHT_PROGBITS), "PROGBITS");
        assert_eq!(section_type_name(SHT_SYMTAB), "SYMTAB");
        assert_eq!(section_type_name(SHT_RELA), "RELA");
        assert_eq!(section_type_name(SHT_GNU_HASH), "GNU_HASH");
    }

    #[test]
    fn test_etype_name() {
        assert_eq!(etype_name(ET_REL), "REL (Relocatable file)");
        assert_eq!(etype_name(ET_EXEC), "EXEC (Executable file)");
        assert_eq!(etype_name(ET_DYN), "DYN (Shared object file)");
        assert_eq!(etype_name(ET_CORE), "CORE (Core file)");
    }

    #[test]
    fn test_osabi_name() {
        assert_eq!(osabi_name(ELFOSABI_SYSV), "UNIX System V");
        assert_eq!(osabi_name(ELFOSABI_LINUX), "GNU/Linux");
        assert_eq!(osabi_name(ELFOSABI_FREEBSD), "FreeBSD");
    }

    #[test]
    fn test_dynamic_tag_name() {
        assert_eq!(dynamic_tag_name(DT_NEEDED), "NEEDED");
        assert_eq!(dynamic_tag_name(DT_SONAME), "SONAME");
        assert_eq!(dynamic_tag_name(DT_RPATH), "RPATH");
        assert_eq!(dynamic_tag_name(DT_RUNPATH), "RUNPATH");
        assert_eq!(dynamic_tag_name(DT_GNU_HASH), "GNU_HASH");
    }

    #[test]
    fn test_shndx_name() {
        assert_eq!(shndx_name(SHN_UNDEF), "UNDEF");
        assert_eq!(shndx_name(SHN_ABS), "ABS");
        assert_eq!(shndx_name(SHN_COMMON), "COMMON");
        assert_eq!(shndx_name(SHN_XINDEX), "XINDEX");
        assert_eq!(shndx_name(5), "NORMAL");
    }

    #[test]
    fn test_flags_to_string() {
        assert_eq!(flags_to_string(PF_R | PF_X), "RE");
        assert_eq!(flags_to_string(PF_R | PF_W | PF_X), "RWE");
        assert_eq!(flags_to_string(PF_R), "R");
        assert_eq!(flags_to_string(0), "");
    }

    // ── Nom parser tests ────────────────────────────────────────────────

    #[test]
    fn test_nom_parse_u16_le() {
        let data = [0x34, 0x12, 0x00];
        let result = parse_u16(true)(&data);
        assert!(result.is_ok());
        let (remaining, val) = result.unwrap();
        assert_eq!(val, 0x1234);
        assert_eq!(remaining.len(), 1);
    }

    #[test]
    fn test_nom_parse_u16_be() {
        let data = [0x12, 0x34, 0x00];
        let result = parse_u16(false)(&data);
        assert!(result.is_ok());
        let (_, val) = result.unwrap();
        assert_eq!(val, 0x1234);
    }

    #[test]
    fn test_nom_parse_u64_le() {
        let data = [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        let result = parse_u64(true)(&data);
        assert!(result.is_ok());
        let (_, val) = result.unwrap();
        assert_eq!(val, 0x0123456789ABCDEF);
    }

    #[test]
    fn test_nom_parse_elf64_phdr() {
        let mut buf = vec![0u8; 56];
        buf[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
        buf[4..8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        buf[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        buf[16..24].copy_from_slice(&0x400000u64.to_le_bytes());
        buf[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
        buf[32..40].copy_from_slice(&0x2000u64.to_le_bytes());
        buf[40..48].copy_from_slice(&0x3000u64.to_le_bytes());
        buf[48..56].copy_from_slice(&0x1000u64.to_le_bytes());

        let (remaining, phdr) = parse_elf64_phdr(&buf, true).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(phdr.p_type, PT_LOAD);
        assert_eq!(phdr.p_offset, 0x1000);
        assert_eq!(phdr.p_vaddr, 0x400000);
        assert_eq!(phdr.p_filesz, 0x2000);
        assert_eq!(phdr.p_memsz, 0x3000);
    }

    #[test]
    fn test_nom_parse_elf64_sym() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&0x05u32.to_le_bytes());  // st_name
        buf[4] = (STB_GLOBAL << 4) | STT_FUNC;               // st_info
        buf[5] = STV_HIDDEN;                                  // st_other
        buf[6..8].copy_from_slice(&0x01u16.to_le_bytes());    // st_shndx
        buf[8..16].copy_from_slice(&0x401000u64.to_le_bytes()); // st_value
        buf[16..24].copy_from_slice(&0x100u64.to_le_bytes());   // st_size

        let (remaining, sym) = parse_elf64_sym(&buf, true).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(sym.st_name, 5);
        assert_eq!(sym.bind(), STB_GLOBAL);
        assert_eq!(sym.stype(), STT_FUNC);
        assert_eq!(sym.visibility(), STV_HIDDEN);
        assert_eq!(sym.st_value, 0x401000);
        assert_eq!(sym.st_size, 0x100);
    }

    #[test]
    fn test_nom_parse_elf64_rela() {
        let mut buf = vec![0u8; 24];
        buf[0..8].copy_from_slice(&0x2000u64.to_le_bytes());  // r_offset
        buf[8..16].copy_from_slice(&((5u64 << 32) | R_X86_64_PC32 as u64).to_le_bytes()); // r_info
        buf[16..24].copy_from_slice(&(-4i64).to_le_bytes());   // r_addend

        let (remaining, rela) = parse_elf64_rela(&buf, true).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(rela.r_offset, 0x2000);
        assert_eq!(rela.sym(true), 5);
        assert_eq!(rela.rtype(true), R_X86_64_PC32 as u64);
        assert_eq!(rela.r_addend, -4);
        assert_eq!(rela.rtype_name_x86_64(), "R_X86_64_PC32");
    }

    #[test]
    fn test_nom_parse_elf64_dyn() {
        let mut buf = vec![0u8; 16];
        buf[0..8].copy_from_slice(&DT_NEEDED.to_le_bytes());
        buf[8..16].copy_from_slice(&42u64.to_le_bytes());

        let (remaining, dyn_entry) = parse_elf64_dyn(&buf, true).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(dyn_entry.d_tag, DT_NEEDED);
        assert_eq!(dyn_entry.d_val, 42);
        assert_eq!(dyn_entry.tag_name(), "NEEDED");
    }

    // ── Relocation type tests ────────────────────────────────────────────

    #[test]
    fn test_reloc_sym_x86_64() {
        let rel = RelocationEntry {
            r_offset: 0x1000,
            r_info: (5u64 << 32) | R_X86_64_PC32 as u64,
        };
        assert_eq!(rel.sym(true), 5);
        assert_eq!(rel.rtype(true), R_X86_64_PC32 as u64);
    }

    #[test]
    fn test_rela_x86_64_types() {
        assert_eq!(x86_64_reloc_name(R_X86_64_NONE), "R_X86_64_NONE");
        assert_eq!(x86_64_reloc_name(R_X86_64_64), "R_X86_64_64");
        assert_eq!(x86_64_reloc_name(R_X86_64_PC32), "R_X86_64_PC32");
        assert_eq!(x86_64_reloc_name(R_X86_64_GOTPCREL), "R_X86_64_GOTPCREL");
        assert_eq!(x86_64_reloc_name(R_X86_64_JUMP_SLOT), "R_X86_64_JUMP_SLOT");
        assert_eq!(x86_64_reloc_name(R_X86_64_IRELATIVE), "R_X86_64_IRELATIVE");
    }

    // ── Hash table tests ────────────────────────────────────────────────

    #[test]
    fn test_gnu_hash_function() {
        let h1 = gnu_hash("printf");
        let h2 = gnu_hash("printf");
        assert_eq!(h1, h2);
        // Different strings should (usually) produce different hashes
        let h3 = gnu_hash("malloc");
        // Not a strict assertion, but they're extremely unlikely to collide
        // for these simple strings.
        assert!(h1 != h3 || h2 != h3);
    }

    #[test]
    fn test_sysv_hash_function() {
        let h1 = sysv_hash("printf");
        let h2 = sysv_hash("printf");
        assert_eq!(h1, h2);
    }

    // ── String table tests ──────────────────────────────────────────────

    #[test]
    fn test_get_string() {
        let strtab = b"hello\0world\0\0";
        assert_eq!(get_string(strtab, 0), Some("hello"));
        assert_eq!(get_string(strtab, 6), Some("world"));
        assert_eq!(get_string(strtab, 12), Some(""));
        assert_eq!(get_string(strtab, 100), None);
    }

    #[test]
    fn test_extract_strings() {
        let strtab = b"\0hello\0world\0\0";
        let strings = extract_strings(strtab);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0], (1, "hello".to_string()));
        assert_eq!(strings[1], (7, "world".to_string()));
    }

    // ── Note parsing tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_notes_build_id() {
        // Construct a minimal GNU_BUILD_ID note
        let name = b"GNU\0";
        let desc = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78";
        let mut buf = Vec::new();
        // n_namesz = 4 (including null terminator)
        buf.extend_from_slice(&4u32.to_le_bytes());
        // n_descsz = 20
        buf.extend_from_slice(&20u32.to_le_bytes());
        // n_type = NT_GNU_BUILD_ID
        buf.extend_from_slice(&NT_GNU_BUILD_ID.to_le_bytes());
        // name (4 bytes, aligned to 4)
        buf.extend_from_slice(name);
        // desc
        buf.extend_from_slice(desc);

        let notes = parse_notes(&buf).expect("parse notes");
        assert_eq!(notes.len(), 1);
        let note = &notes[0];
        assert_eq!(note.n_type, NT_GNU_BUILD_ID);
        assert_eq!(note.name, "GNU");
        assert_eq!(note.type_name(), "GNU_BUILD_ID / PRPSINFO");
        assert_eq!(note.desc.len(), 20);
    }

    #[test]
    fn test_note_type_name() {
        assert_eq!(note_type_name(NT_GNU_BUILD_ID), "GNU_BUILD_ID / PRPSINFO");
        assert_eq!(note_type_name(NT_GNU_GOLD_VERSION), "GNU_GOLD_VERSION");
        assert_eq!(note_type_name(NT_GNU_ABI_TAG), "GNU_ABI_TAG / PRSTATUS");
        assert_eq!(note_type_name(999), "UNKNOWN");
    }

    // ── ElfFile implementation tests ────────────────────────────────────

    #[test]
    fn test_elf_is_static() {
        let data = minimal_elf64_le();
        let elf = parse_elf(&data).unwrap();
        // No INTERP segment, no dynamic entries
        assert!(elf.is_static());
        assert!(!elf.is_shared_library());
        assert!(!elf.is_pie());
        assert!(!elf.is_core());
    }

    #[test]
    fn test_needed_libraries_empty() {
        let data = minimal_elf64_le();
        let elf = parse_elf(&data).unwrap();
        assert!(elf.needed_libraries().is_empty());
    }

    #[test]
    fn test_build_id_none() {
        let data = minimal_elf64_le();
        let elf = parse_elf(&data).unwrap();
        assert!(elf.build_id().is_none());
    }

    #[test]
    fn test_gold_version_none() {
        let data = minimal_elf64_le();
        let elf = parse_elf(&data).unwrap();
        assert!(elf.gold_version().is_none());
    }

    #[test]
    fn test_summary_does_not_panic() {
        let data = minimal_elf64_le();
        let elf = parse_elf(&data).unwrap();
        let summary = elf.summary();
        assert!(summary.contains("ELF File Summary"));
        assert!(summary.contains("x86-64"));
    }

    // ── Too-many-headers sanity test ─────────────────────────────────────

    #[test]
    fn test_too_many_program_headers() {
        let mut data = elf64_with_load_segment();
        // Set phnum to > MAX_PROGRAM_HEADERS
        data[56..58].copy_from_slice(&(MAX_PROGRAM_HEADERS + 1).to_le_bytes());
        assert!(matches!(parse_elf(&data), Err(ElfError::TooManyProgramHeaders(_))));
    }

    #[test]
    fn test_too_many_section_headers() {
        let mut data = elf64_with_sections();
        // Set shnum to > MAX_SECTION_HEADERS
        data[60..62].copy_from_slice(&(MAX_SECTION_HEADERS + 1).to_le_bytes());
        assert!(matches!(parse_elf(&data), Err(ElfError::TooManySectionHeaders(_))));
    }

    // ── GOT/PLT detection test ──────────────────────────────────────────

    #[test]
    fn test_detect_got_plt() {
        let dynamic_map = HashMap::new();

        let rela = vec![
            RelaEntry {
                r_offset: 0x403000,
                r_info: (1u64 << 32) | R_X86_64_GLOB_DAT as u64,
                r_addend: 0,
            },
            RelaEntry {
                r_offset: 0x403008,
                r_info: (2u64 << 32) | R_X86_64_JUMP_SLOT as u64,
                r_addend: 0,
            },
            RelaEntry {
                r_offset: 0x403010,
                r_info: (0u64 << 32) | R_X86_64_RELATIVE as u64, // No symbol
                r_addend: 0x400000,
            },
        ];

        let stubs = detect_got_plt_stubs(&dynamic_map, &rela, &[], b"", true);
        assert_eq!(stubs.len(), 2); // GLOB_DAT + JUMP_SLOT; RELATIVE is skipped (no symbol)
    }

    // ── ElfClass and ElfData tests ───────────────────────────────────────

    #[test]
    fn test_elf_class_from_byte() {
        assert_eq!(ElfClass::from_byte(1), Some(ElfClass::ELF32));
        assert_eq!(ElfClass::from_byte(2), Some(ElfClass::ELF64));
        assert_eq!(ElfClass::from_byte(99), None);
    }

    #[test]
    fn test_elf_data_from_byte() {
        assert_eq!(ElfData::from_byte(1), Some(ElfData::LittleEndian));
        assert_eq!(ElfData::from_byte(2), Some(ElfData::BigEndian));
        assert_eq!(ElfData::from_byte(99), None);
    }

    #[test]
    fn test_addr_size() {
        assert_eq!(ElfClass::ELF32.addr_size(), 4);
        assert_eq!(ElfClass::ELF64.addr_size(), 8);
    }

    #[test]
    fn test_elf_header_is_methods() {
        let data = minimal_elf64_le();
        let elf = parse_elf(&data).unwrap();
        assert!(elf.header.is_64bit());
        assert!(!elf.header.is_32bit());
        assert!(elf.header.is_le());
        assert!(!elf.header.is_be());
        assert_eq!(elf.header.addr_size(), 8);
    }

    #[test]
    fn test_x86_64_all_reloc_types_have_names() {
        // Verify every defined x86-64 relocation type has a name
        let types = [
            R_X86_64_NONE, R_X86_64_64, R_X86_64_PC32, R_X86_64_GOT32,
            R_X86_64_PLT32, R_X86_64_COPY, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT,
            R_X86_64_RELATIVE, R_X86_64_GOTPCREL, R_X86_64_32, R_X86_64_32S,
            R_X86_64_16, R_X86_64_PC16, R_X86_64_8, R_X86_64_PC8,
            R_X86_64_DTPMOD64, R_X86_64_DTPOFF64, R_X86_64_TPOFF64, R_X86_64_TLSGD,
            R_X86_64_TLSLD, R_X86_64_DTPOFF32, R_X86_64_GOTTPOFF, R_X86_64_TPOFF32,
            R_X86_64_PC64, R_X86_64_GOTOFF64, R_X86_64_GOTPC32, R_X86_64_GOT64,
            R_X86_64_GOTPCREL64, R_X86_64_GOTPC64, R_X86_64_GOTPLT64, R_X86_64_PLTOFF64,
            R_X86_64_SIZE32, R_X86_64_SIZE64, R_X86_64_GOTPC32_TLSDESC,
            R_X86_64_TLSDESC_CALL, R_X86_64_TLSDESC, R_X86_64_IRELATIVE,
            R_X86_64_GOTPCRELX, R_X86_64_REX_GOTPCRELX,
        ];
        for t in &types {
            let name = x86_64_reloc_name(*t);
            assert!(!name.contains("UNKNOWN"), "No name for relocation type {}", t);
        }
    }
}
