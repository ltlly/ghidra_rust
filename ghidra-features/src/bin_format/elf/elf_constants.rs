//! ELF identification and header constants ported from Ghidra's `ElfConstants.java`.
//!
//! Provides a comprehensive set of constants used in ELF headers including:
//! - ELF identification area indices and values
//! - ELF class (32/64-bit) constants
//! - Data encoding (endianness) constants
//! - OS/ABI identification constants
//! - ELF file type constants (ET_NONE through ET_CORE)
//! - Machine type constants (EM_NONE through EM_LOONGARCH and beyond)
//! - Special values (PN_XNUM, ELF32_INVALID_OFFSET)

// ---------------------------------------------------------------------------
// ELF Identification Area Indexes
// ---------------------------------------------------------------------------

/// Length of the ELF file identification area.
pub const EI_NIDENT: usize = 16;

/// Index of the first magic byte in e_ident.
pub const EI_MAG0: usize = 0;
/// Index of the second magic byte in e_ident.
pub const EI_MAG1: usize = 1;
/// Index of the third magic byte in e_ident.
pub const EI_MAG2: usize = 2;
/// Index of the fourth magic byte in e_ident.
pub const EI_MAG3: usize = 3;
/// Index of the file class byte in e_ident.
pub const EI_CLASS: usize = 4;
/// Index of the data encoding byte in e_ident.
pub const EI_DATA: usize = 5;
/// Index of the file version byte in e_ident.
pub const EI_VERSION: usize = 6;
/// Index of the OS/ABI identification byte in e_ident.
pub const EI_OSABI: usize = 7;
/// Index of the ABI version byte in e_ident.
pub const EI_ABIVERSION: usize = 8;
/// Start of padding bytes in e_ident.
pub const EI_PAD: usize = 9;

// ---------------------------------------------------------------------------
// ELF Magic
// ---------------------------------------------------------------------------

/// The ELF magic number (0x7f).
pub const MAGIC_NUM: u8 = 0x7f;

/// The ELF magic string "ELF".
pub const MAGIC_STR: &str = "ELF";

/// The complete ELF magic bytes: `{ 0x7f, 'E', 'L', 'F' }`.
pub const MAGIC_BYTES: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Length of the ELF magic string (excluding the magic number byte).
pub const MAGIC_STR_LEN: usize = 3;

// ---------------------------------------------------------------------------
// ELF Class (EI_CLASS values)
// ---------------------------------------------------------------------------

/// Invalid ELF class.
pub const ELF_CLASS_NONE: u8 = 0;
/// 32-bit ELF objects.
pub const ELF_CLASS_32: u8 = 1;
/// 64-bit ELF objects.
pub const ELF_CLASS_64: u8 = 2;
/// Number of defined ELF classes.
pub const ELF_CLASS_NUM: u8 = 3;

// ---------------------------------------------------------------------------
// Data Encoding (EI_DATA values)
// ---------------------------------------------------------------------------

/// Invalid byte order.
pub const ELF_DATA_NONE: u8 = 0;
/// Little-endian byte order.
pub const ELF_DATA_LE: u8 = 1;
/// Big-endian byte order.
pub const ELF_DATA_BE: u8 = 2;

// ---------------------------------------------------------------------------
// ELF Version (EI_VERSION / e_version values)
// ---------------------------------------------------------------------------

/// Invalid version.
pub const EV_NONE: u8 = 0;
/// Current (valid) version.
pub const EV_CURRENT: u8 = 1;

// ---------------------------------------------------------------------------
// OS/ABI Identification (EI_OSABI values)
// ---------------------------------------------------------------------------

/// No extension or unspecified.
pub const ELFOSABI_NONE: u8 = 0;
/// Hewlett-Packard HP-UX.
pub const ELFOSABI_HPUX: u8 = 1;
/// NetBSD.
pub const ELFOSABI_NETBSD: u8 = 2;
/// Linux (also used for GNU/Linux).
pub const ELFOSABI_LINUX: u8 = 3;
/// GNU/Hurd.
pub const ELFOSABI_GNU: u8 = 3;
/// GNU/Hurd (alternative value).
pub const ELFOSABI_HURD: u8 = 4;
/// Sun Solaris.
pub const ELFOSABI_SOLARIS: u8 = 6;
/// AIX.
pub const ELFOSABI_AIX: u8 = 7;
/// IRIX.
pub const ELFOSABI_IRIX: u8 = 8;
/// FreeBSD.
pub const ELFOSABI_FREEBSD: u8 = 9;
/// Compaq TRU64 UNIX.
pub const ELFOSABI_TRUE64: u8 = 10;
/// Novell Modesto.
pub const ELFOSABI_MODESTO: u8 = 11;
/// OpenBSD.
pub const ELFOSABI_OPENBSD: u8 = 12;
/// OpenVMS.
pub const ELFOSABI_OPENVMS: u8 = 13;
/// Hewlett-Packard Non-Stop Kernel.
pub const ELFOSABI_NSK: u8 = 14;
/// AROS.
pub const ELFOSABI_AROS: u8 = 15;
/// FenixOS.
pub const ELFOSABI_FENIXOS: u8 = 16;
/// Nuxi CloudABI.
pub const ELFOSABI_CLOUDABI: u8 = 17;
/// Bare-metal TMS320C6000.
pub const ELFOSABI_C6000_ELFABI: u8 = 64;
/// Linux TMS320C6000.
pub const ELFOSABI_C6000_LINUX: u8 = 65;
/// ARM.
pub const ELFOSABI_ARM: u8 = 97;
/// Standalone (embedded) application.
pub const ELFOSABI_STANDALONE: u8 = 255;

// ---------------------------------------------------------------------------
// File Types (e_type values)
// ---------------------------------------------------------------------------

/// No file type.
pub const ET_NONE: u16 = 0;
/// Relocatable file (suitable for linking).
pub const ET_REL: u16 = 1;
/// Executable file.
pub const ET_EXEC: u16 = 2;
/// Shared object file.
pub const ET_DYN: u16 = 3;
/// Core file.
pub const ET_CORE: u16 = 4;
/// Processor-specific (low bound).
pub const ET_LOPROC: u16 = 0xff00;
/// Processor-specific (high bound).
pub const ET_HIPROC: u16 = 0xffff;

// ---------------------------------------------------------------------------
// Machine Types (e_machine values)
// ---------------------------------------------------------------------------

/// No machine.
pub const EM_NONE: u16 = 0;
/// AT&T WE 32100.
pub const EM_M32: u16 = 1;
/// SUN SPARC.
pub const EM_SPARC: u16 = 2;
/// Intel 80386.
pub const EM_386: u16 = 3;
/// Motorola m68k family.
pub const EM_68K: u16 = 4;
/// Motorola m88k family.
pub const EM_88K: u16 = 5;
/// Intel 486 (deprecated).
pub const EM_486: u16 = 6;
/// Intel 80860.
pub const EM_860: u16 = 7;
/// MIPS R3000 big-endian.
pub const EM_MIPS: u16 = 8;
/// IBM System/370.
pub const EM_S370: u16 = 9;
/// MIPS R3000 little-endian.
pub const EM_MIPS_RS3_LE: u16 = 10;
/// HPPA.
pub const EM_PARISC: u16 = 15;
/// Fujitsu VPP500.
pub const EM_VPP500: u16 = 17;
/// Sun's "v8plus".
pub const EM_SPARC32PLUS: u16 = 18;
/// Intel 80960.
pub const EM_960: u16 = 19;
/// PowerPC.
pub const EM_PPC: u16 = 20;
/// PowerPC 64-bit.
pub const EM_PPC64: u16 = 21;
/// IBM S390.
pub const EM_S390: u16 = 22;
/// IBM SPU/SPC.
pub const EM_SPU: u16 = 23;
/// NEC V800 series.
pub const EM_V800: u16 = 36;
/// Fujitsu FR20.
pub const EM_FR20: u16 = 37;
/// TRW RH-32.
pub const EM_RH32: u16 = 38;
/// Motorola RCE.
pub const EM_RCE: u16 = 39;
/// ARM.
pub const EM_ARM: u16 = 40;
/// Digital Alpha.
pub const EM_FAKE_ALPHA: u16 = 41;
/// Hitachi SH.
pub const EM_SH: u16 = 42;
/// SPARC v9 64-bit.
pub const EM_SPARCV9: u16 = 43;
/// Infineon Tricore.
pub const EM_TRICORE: u16 = 44;
/// Argonaut RISC Core.
pub const EM_ARC: u16 = 45;
/// Hitachi H8/300.
pub const EM_H8_300: u16 = 46;
/// Hitachi H8/300H.
pub const EM_H8_300H: u16 = 47;
/// Hitachi H8S.
pub const EM_H8S: u16 = 48;
/// Hitachi H8/500.
pub const EM_H8_500: u16 = 49;
/// Intel Merced (IA-64).
pub const EM_IA_64: u16 = 50;
/// Stanford MIPS-X.
pub const EM_MIPS_X: u16 = 51;
/// Motorola Coldfire.
pub const EM_COLDFIRE: u16 = 52;
/// Motorola M68HC12.
pub const EM_68HC12: u16 = 53;
/// Fujitsu MMA Multimedia Accelerator.
pub const EM_MMA: u16 = 54;
/// Siemens PCP.
pub const EM_PCP: u16 = 55;
/// Sony nCPU embedded RISC.
pub const EM_NCPU: u16 = 56;
/// Denso NDR1 microprocessor.
pub const EM_NDR1: u16 = 57;
/// Motorola Start*Core processor.
pub const EM_STARCORE: u16 = 58;
/// Toyota ME16 processor.
pub const EM_ME16: u16 = 59;
/// STMicroelectronics ST100 processor.
pub const EM_ST100: u16 = 60;
/// Advanced Logic Corp. Tinyj emb.fam.
pub const EM_TINYJ: u16 = 61;
/// AMD x86-64 architecture.
pub const EM_X86_64: u16 = 62;
/// Sony DSP Processor.
pub const EM_PDSP: u16 = 63;
/// Digital Equipment Corp. PDP-10.
pub const EM_PDP10: u16 = 64;
/// Digital Equipment Corp. PDP-11.
pub const EM_PDP11: u16 = 65;
/// Siemens FX66 microcontroller.
pub const EM_FX66: u16 = 66;
/// STMicroelectronics ST9+ 8/16 mc.
pub const EM_ST9PLUS: u16 = 67;
/// STMicroelectronics ST7 8 bit mc.
pub const EM_ST7: u16 = 68;
/// Motorola MC68HC16 microcontroller.
pub const EM_68HC16: u16 = 69;
/// Motorola MC68HC11 microcontroller.
pub const EM_68HC11: u16 = 70;
/// Motorola MC68HC08 microcontroller.
pub const EM_68HC08: u16 = 71;
/// Motorola MC68HC05 microcontroller.
pub const EM_68HC05: u16 = 72;
/// Silicon Graphics SVx.
pub const EM_SVX: u16 = 73;
/// STMicroelectronics ST19 8 bit mc.
pub const EM_ST19: u16 = 74;
/// Digital VAX.
pub const EM_VAX: u16 = 75;
/// Axis Communications 32-bit embedded processor.
pub const EM_CRIS: u16 = 76;
/// Infineon Technologies 32-bit embedded processor.
pub const EM_JAVELIN: u16 = 77;
/// Element 14 64-bit DSP Processor.
pub const EM_FIREPATH: u16 = 78;
/// LSI Logic 16-bit DSP Processor.
pub const EM_ZSP: u16 = 79;
/// Donald Knuth's educational 64-bit processor.
pub const EM_MMIX: u16 = 80;
/// Harvard University machine-independent object files.
pub const EM_HUANY: u16 = 81;
/// SiTera Prism.
pub const EM_PRISM: u16 = 82;
/// Atmel AVR 8-bit microcontroller.
pub const EM_AVR: u16 = 83;
/// Fujitsu FR30.
pub const EM_FR30: u16 = 84;
/// Mitsubishi D10V.
pub const EM_D10V: u16 = 85;
/// Mitsubishi D30V.
pub const EM_D30V: u16 = 86;
/// NEC v850.
pub const EM_V850: u16 = 87;
/// Mitsubishi M32R.
pub const EM_M32R: u16 = 88;
/// Matsushita MN10300.
pub const EM_MN10300: u16 = 89;
/// Matsushita MN10200.
pub const EM_MN10200: u16 = 90;
/// picoJava.
pub const EM_PJ: u16 = 91;
/// OpenRISC 32-bit embedded processor.
pub const EM_OPENRISC: u16 = 92;
/// ARC Cores Tangent-A5.
pub const EM_ARC_A5: u16 = 93;
/// Tensilica Xtensa Architecture.
pub const EM_XTENSA: u16 = 94;
/// Alphamosaic VideoCore processor.
pub const EM_VIDEOCORE: u16 = 95;
/// Thompson Multimedia General Purpose Processor.
pub const EM_TMM_GPP: u16 = 96;
/// National Semiconductor 32000 series.
pub const EM_NS32K: u16 = 97;
/// Tenor Network TPC processor.
pub const EM_TPC: u16 = 98;
/// Trebia SNP 1000 processor.
pub const EM_SNP1K: u16 = 99;
/// STMicroelectronics ST200.
pub const EM_ST200: u16 = 100;
/// Ubicom IP2xxx microcontroller family.
pub const EM_IP2K: u16 = 101;
/// MAX Processor.
pub const EM_MAX: u16 = 102;
/// National Semiconductor CompactRISC microprocessor.
pub const EM_CR: u16 = 103;
/// Fujitsu F2MC16.
pub const EM_F2MC16: u16 = 104;
/// Texas Instruments msp430.
pub const EM_MSP430: u16 = 105;
/// Analog Devices Blackfin (DSP) processor.
pub const EM_BLACKFIN: u16 = 106;
/// S1C33 Family of Seiko Epson processors.
pub const EM_SE_C33: u16 = 107;
/// Sharp embedded microprocessor.
pub const EM_SEP: u16 = 108;
/// Arca RISC Microprocessor.
pub const EM_ARCA: u16 = 109;
/// PKU-Unity / MPRC Unicore32.
pub const EM_UNICORE: u16 = 110;
/// eXcess: 16/32/64-bit configurable embedded CPU.
pub const EM_EXCESS: u16 = 111;
/// Icera Semiconductor Deep Execution Processor.
pub const EM_DXP: u16 = 112;
/// Altera Nios II soft-core processor.
pub const EM_ALTERA_NIOS2: u16 = 113;
/// National Semiconductor CompactRISC CRX.
pub const EM_CRX: u16 = 114;
/// Motorola XGATE embedded processor.
pub const EM_XGATE: u16 = 115;
/// Infineon C16x/XC16x processor.
pub const EM_C166: u16 = 116;
/// Renesas M16C series microprocessors.
pub const EM_M16C: u16 = 117;
/// Microchip Technology dsPIC30F Digital Signal Controller.
pub const EM_DSPIC30F: u16 = 118;
/// Freescale Communication Engine RISC core.
pub const EM_CE: u16 = 119;
/// Renesas M32C series microprocessors.
pub const EM_M32C: u16 = 120;
/// Altium TSK3000 core.
pub const EM_TSK3000: u16 = 131;
/// Freescale RS08 embedded processor.
pub const EM_RS08: u16 = 132;
/// Analog Devices SHARC family of 32-bit DSP processors.
pub const EM_SHARC: u16 = 133;
/// Cyan Technology eCOG2 microprocessor.
pub const EM_ECOG2: u16 = 134;
/// Sunplus S+core7 RISC processor.
pub const EM_SCORE7: u16 = 135;
/// New Japan Radio (NJR) 24-bit DSP Processor.
pub const EM_DSP24: u16 = 136;
/// Broadcom VideoCore III processor.
pub const EM_VIDEOCORE3: u16 = 137;
/// RISC processor for Lattice FPGA architecture.
pub const EM_LATTICEMICO32: u16 = 138;
/// Seiko Epson C17 family.
pub const EM_SE_C17: u16 = 139;
/// Texas Instruments TMS320C6000 DSP family.
pub const EM_TI_C6000: u16 = 140;
/// Texas Instruments TMS320C2000 DSP family.
pub const EM_TI_C2000: u16 = 141;
/// Texas Instruments TMS320C55x DSP family.
pub const EM_TI_C5500: u16 = 142;
/// Texas Instruments Programmable Realtime Unit.
pub const EM_TI_PRU: u16 = 144;
/// STMicroelectronics 64bit VLIW Data Signal Processor.
pub const EM_MMDSP_PLUS: u16 = 160;
/// Cypress M8C microprocessor.
pub const EM_CYPRESS_M8C: u16 = 161;
/// Renesas R32C series microprocessors.
pub const EM_R32C: u16 = 162;
/// NXP Semiconductors TriMedia architecture family.
pub const EM_TRIMEDIA: u16 = 163;
/// Qualcomm Hexagon processor.
pub const EM_HEXAGON: u16 = 164;
/// Intel 8051 and variants.
pub const EM_8051: u16 = 165;
/// STMicroelectronics STxP7x family of RISC processors.
pub const EM_STXP7X: u16 = 166;
/// Andes Technology compact code size embedded RISC processor family.
pub const EM_NDS32: u16 = 167;
/// Cyan Technology eCOG1X family.
pub const EM_ECOG1: u16 = 168;
/// Cyan Technology eCOG1X family (alias).
pub const EM_ECOG1X: u16 = 168;
/// Dallas Semiconductor MAXQ30 Core Micro-controllers.
pub const EM_MAXQ30: u16 = 169;
/// New Japan Radio (NJR) 16-bit DSP Processor.
pub const EM_XIMO16: u16 = 170;
/// M2000 Reconfigurable RISC Microprocessor.
pub const EM_MANIK: u16 = 171;
/// Cray Inc. NV2 vector architecture.
pub const EM_CRAYNV2: u16 = 172;
/// Renesas RX family.
pub const EM_RX: u16 = 173;
/// Imagination Technologies META processor architecture.
pub const EM_METAG: u16 = 174;
/// MCST Elbrus general purpose hardware architecture.
pub const EM_MCST_ELBRUS: u16 = 175;
/// Cyan Technology eCOG16 family.
pub const EM_ECOG16: u16 = 176;
/// National Semiconductor CompactRISC CR16 16-bit microprocessor.
pub const EM_CR16: u16 = 177;
/// Freescale Extended Time Processing Unit.
pub const EM_ETPU: u16 = 178;
/// Infineon Technologies SLE9X core.
pub const EM_SLE9X: u16 = 179;
/// Intel L10M.
pub const EM_L10M: u16 = 180;
/// Intel K10M.
pub const EM_K10M: u16 = 181;
/// AARCH64 Architecture.
pub const EM_AARCH64: u16 = 183;
/// Atmel Corporation 32-bit microprocessor family.
pub const EM_AVR32: u16 = 185;
/// STMicroelectronics STM8 8-bit microcontroller.
pub const EM_STM8: u16 = 186;
/// Tilera TILE64 multicore architecture family.
pub const EM_TILE64: u16 = 187;
/// Tilera TILEPro multicore architecture family.
pub const EM_TILEPRO: u16 = 188;
/// NVIDIA CUDA architecture.
pub const EM_CUDA: u16 = 190;
/// Tilera TILE-Gx multicore architecture family.
pub const EM_TILEGX: u16 = 191;
/// CloudShield architecture family.
pub const EM_CLOUDSHIELD: u16 = 192;
/// KIPO-KAIST Core-A 1st generation processor family.
pub const EM_COREA_1ST: u16 = 193;
/// KIPO-KAIST Core-A 2nd generation processor family.
pub const EM_COREA_2ND: u16 = 194;
/// Synopsys ARCompact V2.
pub const EM_ARC_COMPACT2: u16 = 195;
/// Open8 8-bit RISC soft processor core.
pub const EM_OPEN8: u16 = 196;
/// Renesas RL78 family.
pub const EM_RL78: u16 = 197;
/// Broadcom VideoCore V processor.
pub const EM_VIDEOCORE5: u16 = 198;
/// Renesas 78KOR family.
pub const EM_78KOR: u16 = 199;
/// Freescale 56800EX Digital Signal Controller (DSC).
pub const EM_56800EX: u16 = 200;
/// Beyond BA1 CPU.
pub const EM_BA1: u16 = 201;
/// Beyond BA2 CPU.
pub const EM_BA2: u16 = 202;
/// XMOS xCORE processor family.
pub const EM_XCORE: u16 = 203;
/// Microchip 8-bit PIC(r) family.
pub const EM_MCHP_PIC: u16 = 204;
/// Intel Graphics Technology.
pub const EM_INTELGT: u16 = 205;
/// KM211 KM32 32-bit processor.
pub const EM_KM32: u16 = 210;
/// KM211 KMX32 32-bit processor.
pub const EM_KMX32: u16 = 211;
/// KM211 KMX16 16-bit processor.
pub const EM_KMX16: u16 = 212;
/// KM211 KMX8 8-bit processor.
pub const EM_KMX8: u16 = 213;
/// KM211 KVARC processor.
pub const EM_KVARC: u16 = 214;
/// Paneve CDP architecture family.
pub const EM_CDP: u16 = 215;
/// Cognitive Smart Memory Processor.
pub const EM_COGE: u16 = 216;
/// iCelero CoolEngine.
pub const EM_COOL: u16 = 217;
/// Nanoradio Optimized RISC.
pub const EM_NORC: u16 = 218;
/// CSR Kalimba architecture family.
pub const EM_CSR_KALIMBA: u16 = 219;
/// Zilog Z80.
pub const EM_Z80: u16 = 220;
/// Controls and Data Services VISIUMcore processor.
pub const EM_VISIUM: u16 = 221;
/// FTDI Chip FT32 high performance 32-bit RISC architecture.
pub const EM_FT32: u16 = 222;
/// Moxie processor family.
pub const EM_MOXIE: u16 = 223;
/// AMD GPU architecture.
pub const EM_AMDGPU: u16 = 224;
/// RISC-V.
pub const EM_RISCV: u16 = 243;
/// Lanai 32-bit processor.
pub const EM_LANAI: u16 = 244;
/// CEVA Processor Architecture Family.
pub const EM_CEVA: u16 = 245;
/// CEVA X2 Processor Family.
pub const EM_CEVA_X2: u16 = 246;
/// Linux kernel BPF virtual machine.
pub const EM_BPF: u16 = 247;
/// Graphcore Intelligent Processing Unit.
pub const EM_GRAPHCORE_IPU: u16 = 248;
/// Imagination Technologies.
pub const EM_IMG1: u16 = 249;
/// Netronome Flow Processor.
pub const EM_NFP: u16 = 250;
/// NEC Vector Engine.
pub const EM_VE: u16 = 251;
/// C-SKY processor family.
pub const EM_CSKY: u16 = 252;
/// Synopsys ARCv2.3 64-bit.
pub const EM_ARC_COMPACT3_64: u16 = 253;
/// MOS Technology MCS 6502 processor.
pub const EM_MCS6502: u16 = 254;
/// Synopsys ARCv2.3 32-bit.
pub const EM_ARC_COMPACT3: u16 = 255;
/// Kalray VLIW core of the MPPA processor family.
pub const EM_KVX: u16 = 256;
/// WDC 65816/65C816.
pub const EM_65816: u16 = 257;
/// LoongArch.
pub const EM_LOONGARCH: u16 = 258;
/// ChipON KungFu32.
pub const EM_KF32: u16 = 259;
/// Linux kernel BPF virtual machine (u16/u8 core).
pub const EM_U16_U8CORE: u16 = 260;
/// Tachyum.
pub const EM_TACHYUM: u16 = 261;
/// NXP 56800EF Digital Signal Controller (DSC).
pub const EM_56800EF: u16 = 262;

/// Unofficial AVR 32-bit machine type used by NetBSD.
pub const EM_AVR32_UNOFFICIAL: u16 = 0x18ad;

// ---------------------------------------------------------------------------
// Special Values
// ---------------------------------------------------------------------------

/// Used by `e_phnum` field to signal alternate storage of program header count
/// within `section[0].sh_info` field.
pub const PN_XNUM: u16 = 0xffff;

/// 32-bit "-1", used in 32-bit files to signal an invalid offset.
pub const ELF32_INVALID_OFFSET: u64 = 0xFFFFFFFF;

// ---------------------------------------------------------------------------
// GOT symbol name
// ---------------------------------------------------------------------------

/// The symbol name for the Global Offset Table.
pub const GOT_SYMBOL_NAME: &str = "_GLOBAL_OFFSET_TABLE_";

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Returns a human-readable name for the given ELF machine type.
///
/// # Arguments
///
/// * `machine` - The `e_machine` value from the ELF header.
///
/// # Returns
///
/// A static string slice with the machine name (e.g., `"EM_X86_64"`).
pub fn elf_machine_name(machine: u16) -> &'static str {
    match machine {
        EM_NONE => "EM_NONE",
        EM_M32 => "EM_M32",
        EM_SPARC => "EM_SPARC",
        EM_386 => "EM_386",
        EM_68K => "EM_68K",
        EM_88K => "EM_88K",
        EM_486 => "EM_486",
        EM_860 => "EM_860",
        EM_MIPS => "EM_MIPS",
        EM_S370 => "EM_S370",
        EM_MIPS_RS3_LE => "EM_MIPS_RS3_LE",
        EM_PARISC => "EM_PARISC",
        EM_VPP500 => "EM_VPP500",
        EM_SPARC32PLUS => "EM_SPARC32PLUS",
        EM_960 => "EM_960",
        EM_PPC => "EM_PPC",
        EM_PPC64 => "EM_PPC64",
        EM_S390 => "EM_S390",
        EM_SPU => "EM_SPU",
        EM_V800 => "EM_V800",
        EM_FR20 => "EM_FR20",
        EM_RH32 => "EM_RH32",
        EM_RCE => "EM_RCE",
        EM_ARM => "EM_ARM",
        EM_FAKE_ALPHA => "EM_FAKE_ALPHA",
        EM_SH => "EM_SH",
        EM_SPARCV9 => "EM_SPARCV9",
        EM_TRICORE => "EM_TRICORE",
        EM_ARC => "EM_ARC",
        EM_H8_300 => "EM_H8_300",
        EM_H8_300H => "EM_H8_300H",
        EM_H8S => "EM_H8S",
        EM_H8_500 => "EM_H8_500",
        EM_IA_64 => "EM_IA_64",
        EM_MIPS_X => "EM_MIPS_X",
        EM_COLDFIRE => "EM_COLDFIRE",
        EM_68HC12 => "EM_68HC12",
        EM_MMA => "EM_MMA",
        EM_PCP => "EM_PCP",
        EM_NCPU => "EM_NCPU",
        EM_NDR1 => "EM_NDR1",
        EM_STARCORE => "EM_STARCORE",
        EM_ME16 => "EM_ME16",
        EM_ST100 => "EM_ST100",
        EM_TINYJ => "EM_TINYJ",
        EM_X86_64 => "EM_X86_64",
        EM_PDSP => "EM_PDSP",
        EM_PDP10 => "EM_PDP10",
        EM_PDP11 => "EM_PDP11",
        EM_FX66 => "EM_FX66",
        EM_ST9PLUS => "EM_ST9PLUS",
        EM_ST7 => "EM_ST7",
        EM_68HC16 => "EM_68HC16",
        EM_68HC11 => "EM_68HC11",
        EM_68HC08 => "EM_68HC08",
        EM_68HC05 => "EM_68HC05",
        EM_SVX => "EM_SVX",
        EM_ST19 => "EM_ST19",
        EM_VAX => "EM_VAX",
        EM_CRIS => "EM_CRIS",
        EM_JAVELIN => "EM_JAVELIN",
        EM_FIREPATH => "EM_FIREPATH",
        EM_ZSP => "EM_ZSP",
        EM_MMIX => "EM_MMIX",
        EM_HUANY => "EM_HUANY",
        EM_PRISM => "EM_PRISM",
        EM_AVR => "EM_AVR",
        EM_FR30 => "EM_FR30",
        EM_D10V => "EM_D10V",
        EM_D30V => "EM_D30V",
        EM_V850 => "EM_V850",
        EM_M32R => "EM_M32R",
        EM_MN10300 => "EM_MN10300",
        EM_MN10200 => "EM_MN10200",
        EM_PJ => "EM_PJ",
        EM_OPENRISC => "EM_OPENRISC",
        EM_ARC_A5 => "EM_ARC_A5",
        EM_XTENSA => "EM_XTENSA",
        EM_VIDEOCORE => "EM_VIDEOCORE",
        EM_TMM_GPP => "EM_TMM_GPP",
        EM_NS32K => "EM_NS32K",
        EM_TPC => "EM_TPC",
        EM_SNP1K => "EM_SNP1K",
        EM_ST200 => "EM_ST200",
        EM_IP2K => "EM_IP2K",
        EM_MAX => "EM_MAX",
        EM_CR => "EM_CR",
        EM_F2MC16 => "EM_F2MC16",
        EM_MSP430 => "EM_MSP430",
        EM_BLACKFIN => "EM_BLACKFIN",
        EM_SE_C33 => "EM_SE_C33",
        EM_SEP => "EM_SEP",
        EM_ARCA => "EM_ARCA",
        EM_UNICORE => "EM_UNICORE",
        EM_EXCESS => "EM_EXCESS",
        EM_DXP => "EM_DXP",
        EM_ALTERA_NIOS2 => "EM_ALTERA_NIOS2",
        EM_CRX => "EM_CRX",
        EM_XGATE => "EM_XGATE",
        EM_C166 => "EM_C166",
        EM_M16C => "EM_M16C",
        EM_DSPIC30F => "EM_DSPIC30F",
        EM_CE => "EM_CE",
        EM_M32C => "EM_M32C",
        EM_TSK3000 => "EM_TSK3000",
        EM_RS08 => "EM_RS08",
        EM_SHARC => "EM_SHARC",
        EM_ECOG2 => "EM_ECOG2",
        EM_SCORE7 => "EM_SCORE7",
        EM_DSP24 => "EM_DSP24",
        EM_VIDEOCORE3 => "EM_VIDEOCORE3",
        EM_LATTICEMICO32 => "EM_LATTICEMICO32",
        EM_SE_C17 => "EM_SE_C17",
        EM_TI_C6000 => "EM_TI_C6000",
        EM_TI_C2000 => "EM_TI_C2000",
        EM_TI_C5500 => "EM_TI_C5500",
        EM_TI_PRU => "EM_TI_PRU",
        EM_MMDSP_PLUS => "EM_MMDSP_PLUS",
        EM_CYPRESS_M8C => "EM_CYPRESS_M8C",
        EM_R32C => "EM_R32C",
        EM_TRIMEDIA => "EM_TRIMEDIA",
        EM_HEXAGON => "EM_HEXAGON",
        EM_8051 => "EM_8051",
        EM_STXP7X => "EM_STXP7X",
        EM_NDS32 => "EM_NDS32",
        EM_ECOG1 => "EM_ECOG1",
        EM_MAXQ30 => "EM_MAXQ30",
        EM_XIMO16 => "EM_XIMO16",
        EM_MANIK => "EM_MANIK",
        EM_CRAYNV2 => "EM_CRAYNV2",
        EM_RX => "EM_RX",
        EM_METAG => "EM_METAG",
        EM_MCST_ELBRUS => "EM_MCST_ELBRUS",
        EM_ECOG16 => "EM_ECOG16",
        EM_CR16 => "EM_CR16",
        EM_ETPU => "EM_ETPU",
        EM_SLE9X => "EM_SLE9X",
        EM_L10M => "EM_L10M",
        EM_K10M => "EM_K10M",
        EM_AARCH64 => "EM_AARCH64",
        EM_AVR32 => "EM_AVR32",
        EM_STM8 => "EM_STM8",
        EM_TILE64 => "EM_TILE64",
        EM_TILEPRO => "EM_TILEPRO",
        EM_CUDA => "EM_CUDA",
        EM_TILEGX => "EM_TILEGX",
        EM_CLOUDSHIELD => "EM_CLOUDSHIELD",
        EM_COREA_1ST => "EM_COREA_1ST",
        EM_COREA_2ND => "EM_COREA_2ND",
        EM_ARC_COMPACT2 => "EM_ARC_COMPACT2",
        EM_OPEN8 => "EM_OPEN8",
        EM_RL78 => "EM_RL78",
        EM_VIDEOCORE5 => "EM_VIDEOCORE5",
        EM_78KOR => "EM_78KOR",
        EM_56800EX => "EM_56800EX",
        EM_BA1 => "EM_BA1",
        EM_BA2 => "EM_BA2",
        EM_XCORE => "EM_XCORE",
        EM_MCHP_PIC => "EM_MCHP_PIC",
        EM_INTELGT => "EM_INTELGT",
        EM_KM32 => "EM_KM32",
        EM_KMX32 => "EM_KMX32",
        EM_KMX16 => "EM_KMX16",
        EM_KMX8 => "EM_KMX8",
        EM_KVARC => "EM_KVARC",
        EM_CDP => "EM_CDP",
        EM_COGE => "EM_COGE",
        EM_COOL => "EM_COOL",
        EM_NORC => "EM_NORC",
        EM_CSR_KALIMBA => "EM_CSR_KALIMBA",
        EM_Z80 => "EM_Z80",
        EM_VISIUM => "EM_VISIUM",
        EM_FT32 => "EM_FT32",
        EM_MOXIE => "EM_MOXIE",
        EM_AMDGPU => "EM_AMDGPU",
        EM_RISCV => "EM_RISCV",
        EM_LANAI => "EM_LANAI",
        EM_CEVA => "EM_CEVA",
        EM_CEVA_X2 => "EM_CEVA_X2",
        EM_BPF => "EM_BPF",
        EM_GRAPHCORE_IPU => "EM_GRAPHCORE_IPU",
        EM_IMG1 => "EM_IMG1",
        EM_NFP => "EM_NFP",
        EM_VE => "EM_VE",
        EM_CSKY => "EM_CSKY",
        EM_ARC_COMPACT3_64 => "EM_ARC_COMPACT3_64",
        EM_MCS6502 => "EM_MCS6502",
        EM_ARC_COMPACT3 => "EM_ARC_COMPACT3",
        EM_KVX => "EM_KVX",
        EM_65816 => "EM_65816",
        EM_LOONGARCH => "EM_LOONGARCH",
        EM_KF32 => "EM_KF32",
        EM_U16_U8CORE => "EM_U16_U8CORE",
        EM_TACHYUM => "EM_TACHYUM",
        EM_56800EF => "EM_56800EF",
        EM_AVR32_UNOFFICIAL => "EM_AVR32_unofficial",
        _ => "EM_UNKNOWN",
    }
}

/// Returns a human-readable name for the given ELF file type.
///
/// # Arguments
///
/// * `e_type` - The `e_type` value from the ELF header.
///
/// # Returns
///
/// A static string slice with the file type name (e.g., `"ET_EXEC"`).
pub fn elf_type_name(e_type: u16) -> &'static str {
    match e_type {
        ET_NONE => "ET_NONE",
        ET_REL => "ET_REL",
        ET_EXEC => "ET_EXEC",
        ET_DYN => "ET_DYN",
        ET_CORE => "ET_CORE",
        _ => "ET_UNKNOWN",
    }
}

/// Returns a human-readable name for the given ELF OS/ABI value.
///
/// # Arguments
///
/// * `osabi` - The EI_OSABI value from the ELF header.
///
/// # Returns
///
/// A static string slice with the OS/ABI name (e.g., `"ELFOSABI_LINUX"`).
pub fn elf_osabi_name(osabi: u8) -> &'static str {
    match osabi {
        ELFOSABI_NONE => "ELFOSABI_NONE",
        ELFOSABI_HPUX => "ELFOSABI_HPUX",
        ELFOSABI_NETBSD => "ELFOSABI_NETBSD",
        ELFOSABI_LINUX => "ELFOSABI_LINUX",
        ELFOSABI_HURD => "ELFOSABI_HURD",
        ELFOSABI_SOLARIS => "ELFOSABI_SOLARIS",
        ELFOSABI_AIX => "ELFOSABI_AIX",
        ELFOSABI_IRIX => "ELFOSABI_IRIX",
        ELFOSABI_FREEBSD => "ELFOSABI_FREEBSD",
        ELFOSABI_TRUE64 => "ELFOSABI_TRUE64",
        ELFOSABI_MODESTO => "ELFOSABI_MODESTO",
        ELFOSABI_OPENBSD => "ELFOSABI_OPENBSD",
        ELFOSABI_OPENVMS => "ELFOSABI_OPENVMS",
        ELFOSABI_NSK => "ELFOSABI_NSK",
        ELFOSABI_AROS => "ELFOSABI_AROS",
        ELFOSABI_FENIXOS => "ELFOSABI_FENIXOS",
        ELFOSABI_CLOUDABI => "ELFOSABI_CLOUDABI",
        ELFOSABI_C6000_ELFABI => "ELFOSABI_C6000_ELFABI",
        ELFOSABI_C6000_LINUX => "ELFOSABI_C6000_LINUX",
        ELFOSABI_ARM => "ELFOSABI_ARM",
        ELFOSABI_STANDALONE => "ELFOSABI_STANDALONE",
        _ => "ELFOSABI_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_bytes() {
        assert_eq!(MAGIC_BYTES, [0x7f, b'E', b'L', b'F']);
        assert_eq!(MAGIC_NUM, 0x7f);
        assert_eq!(MAGIC_STR, "ELF");
    }

    #[test]
    fn test_elf_class_constants() {
        assert_eq!(ELF_CLASS_NONE, 0);
        assert_eq!(ELF_CLASS_32, 1);
        assert_eq!(ELF_CLASS_64, 2);
    }

    #[test]
    fn test_data_encoding() {
        assert_eq!(ELF_DATA_NONE, 0);
        assert_eq!(ELF_DATA_LE, 1);
        assert_eq!(ELF_DATA_BE, 2);
    }

    #[test]
    fn test_file_types() {
        assert_eq!(ET_NONE, 0);
        assert_eq!(ET_REL, 1);
        assert_eq!(ET_EXEC, 2);
        assert_eq!(ET_DYN, 3);
        assert_eq!(ET_CORE, 4);
    }

    #[test]
    fn test_machine_name_common() {
        assert_eq!(elf_machine_name(EM_386), "EM_386");
        assert_eq!(elf_machine_name(EM_X86_64), "EM_X86_64");
        assert_eq!(elf_machine_name(EM_ARM), "EM_ARM");
        assert_eq!(elf_machine_name(EM_AARCH64), "EM_AARCH64");
        assert_eq!(elf_machine_name(EM_RISCV), "EM_RISCV");
        assert_eq!(elf_machine_name(EM_MIPS), "EM_MIPS");
        assert_eq!(elf_machine_name(EM_PPC), "EM_PPC");
        assert_eq!(elf_machine_name(9999), "EM_UNKNOWN");
    }

    #[test]
    fn test_type_name() {
        assert_eq!(elf_type_name(ET_EXEC), "ET_EXEC");
        assert_eq!(elf_type_name(ET_DYN), "ET_DYN");
        assert_eq!(elf_type_name(99), "ET_UNKNOWN");
    }

    #[test]
    fn test_osabi_name() {
        assert_eq!(elf_osabi_name(ELFOSABI_LINUX), "ELFOSABI_LINUX");
        assert_eq!(elf_osabi_name(ELFOSABI_FREEBSD), "ELFOSABI_FREEBSD");
        assert_eq!(elf_osabi_name(ELFOSABI_NONE), "ELFOSABI_NONE");
        assert_eq!(elf_osabi_name(200), "ELFOSABI_UNKNOWN");
    }

    #[test]
    fn test_special_values() {
        assert_eq!(PN_XNUM, 0xffff);
        assert_eq!(ELF32_INVALID_OFFSET, 0xFFFFFFFF);
        assert_eq!(GOT_SYMBOL_NAME, "_GLOBAL_OFFSET_TABLE_");
    }

    #[test]
    fn test_osabi_aliases() {
        // ELFOSABI_LINUX and ELFOSABI_GNU share value 3
        assert_eq!(ELFOSABI_LINUX, ELFOSABI_GNU);
        assert_eq!(ELFOSABI_LINUX, 3);
    }

    #[test]
    fn test_eident_indices() {
        assert_eq!(EI_NIDENT, 16);
        assert_eq!(EI_MAG0, 0);
        assert_eq!(EI_CLASS, 4);
        assert_eq!(EI_DATA, 5);
        assert_eq!(EI_OSABI, 7);
    }
}
