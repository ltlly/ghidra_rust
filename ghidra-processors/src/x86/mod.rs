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

use crate::common::{Endian, Language, ProcessorModule, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

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

/// Return all supported x86 instruction mnemonic strings.
fn all_x86_mnemonics() -> Vec<InstructionMnemonic> {
    let names: &[&str] = &[
        // Data Movement
        "MOV", "MOVSX", "MOVZX", "MOVSXD", "XCHG", "BSWAP", "XADD",
        "CMPXCHG", "CMPXCHG8B", "CMPXCHG16B", "LEA",
        // Conditional move
        "CMOVO", "CMOVNO", "CMOVB", "CMOVNAE", "CMOVAE", "CMOVNB", "CMOVNC",
        "CMOVE", "CMOVZ", "CMOVNE", "CMOVNZ", "CMOVBE", "CMOVNA", "CMOVA",
        "CMOVNBE", "CMOVS", "CMOVNS", "CMOVP", "CMOVPE", "CMOVNP", "CMOVPO",
        "CMOVL", "CMOVNGE", "CMOVGE", "CMOVNL", "CMOVLE", "CMOVNG", "CMOVG",
        "CMOVNLE",
        // Stack
        "PUSH", "POP", "PUSHA", "POPA", "PUSHF", "POPF", "PUSHFD", "POPFD",
        "PUSHFQ", "POPFQ", "ENTER", "LEAVE",
        // Arithmetic
        "ADD", "ADC", "SUB", "SBB", "IMUL", "MUL", "IDIV", "DIV", "INC",
        "DEC", "NEG", "CMP", "DAA", "DAS", "AAA", "AAS", "AAM", "AAD",
        // Logical
        "AND", "OR", "XOR", "NOT", "TEST",
        // Shift/Rotate
        "SHL", "SHR", "SAL", "SAR", "ROL", "ROR", "RCL", "RCR", "SHLD", "SHRD",
        // Bit manipulation
        "BT", "BTS", "BTR", "BTC", "BSF", "BSR", "LZCNT", "TZCNT", "POPCNT",
        "ANDN", "BEXTR", "BLSI", "BLSMSK", "BLSR", "BZHI", "MULX", "PDEP",
        "PEXT", "RORX", "SARX", "SHLX", "SHRX",
        // Control flow
        "JMP", "CALL", "RET", "RETF", "JECXZ", "JRCXZ", "LOOP", "LOOPE", "LOOPNE",
        "JO", "JNO", "JB", "JC", "JNAE", "JAE", "JNB", "JNC", "JE", "JZ",
        "JNE", "JNZ", "JBE", "JNA", "JA", "JNBE", "JS", "JNS", "JP", "JPE",
        "JNP", "JPO", "JL", "JNGE", "JGE", "JNL", "JLE", "JNG", "JG", "JNLE",
        // Conditional set
        "SETO", "SETNO", "SETB", "SETC", "SETNAE", "SETAE", "SETNB", "SETNC",
        "SETE", "SETZ", "SETNE", "SETNZ", "SETBE", "SETNA", "SETA", "SETNBE",
        "SETS", "SETNS", "SETP", "SETPE", "SETNP", "SETPO", "SETL", "SETNGE",
        "SETGE", "SETNL", "SETLE", "SETNG", "SETG", "SETNLE",
        // String ops
        "MOVS", "MOVSB", "MOVSW", "MOVSQ", "CMPS", "CMPSB", "CMPSW", "CMPSQ",
        "SCAS", "SCASB", "SCASW", "SCASD", "SCASQ", "LODS", "LODSB", "LODSW",
        "LODSD", "LODSQ", "STOS", "STOSB", "STOSW", "STOSD", "STOSQ",
        "INS", "INSB", "INSW", "INSD", "OUTS", "OUTSB", "OUTSW", "OUTSD",
        "REP", "REPE", "REPZ", "REPNE", "REPNZ",
        // I/O
        "IN", "OUT",
        // Flag control
        "STC", "CLC", "CMC", "STD", "CLD", "STI", "CLI", "LAHF", "SAHF",
        // Segment
        "LDS", "LES", "LFS", "LGS", "LSS",
        // System
        "SYSCALL", "SYSRET", "SYSENTER", "SYSEXIT", "INT", "INT3", "INTO",
        "IRET", "IRETD", "IRETQ", "HLT", "PAUSE", "RSM", "UD2",
        "LGDT", "SGDT", "LIDT", "SIDT", "LLDT", "SLDT", "LTR", "STR",
        "LMSW", "SMSW", "CLTS", "LAR", "LSL", "VERR", "VERW",
        "MOV_CR", "MOV_DR",
        // Cache/TLB
        "INVD", "WBINVD", "INVLPG", "INVLPGA", "INVPCID", "CLFLUSH",
        "CLFLUSHOPT", "CLWB", "PREFETCH", "PREFETCHW",
        // Model-specific
        "RDTSC", "RDTSCP", "RDPMC", "RDMSR", "WRMSR", "CPUID", "XGETBV",
        "XSETBV", "RDRAND", "RDSEED",
        // NOP
        "NOP", "UD0", "UD1",
        // MMX
        "MOVD", "MOVQ", "PACKSSWB", "PACKSSDW", "PACKUSWB", "PUNPCKLBW",
        "PUNPCKHBW", "PUNPCKLWD", "PUNPCKHWD", "PUNPCKLDQ", "PUNPCKHDQ",
        "PADDB", "PADDW", "PADDD", "PADDSB", "PADDSW", "PADDUSB", "PADDUSW",
        "PSUBB", "PSUBW", "PSUBD", "PSUBSB", "PSUBSW", "PSUBUSB", "PSUBUSW",
        "PMULLW", "PMULHW", "PMULHUW", "PMADDWD", "PCMPEQB", "PCMPEQW",
        "PCMPEQD", "PCMPGTB", "PCMPGTW", "PCMPGTD", "PAND", "PANDN", "POR",
        "PXOR", "PSLLW", "PSLLD", "PSLLQ", "PSRLW", "PSRLD", "PSRLQ",
        "PSRAW", "PSRAD", "EMMS",
        // SSE
        "MOVAPS", "MOVUPS", "MOVHPS", "MOVLPS", "MOVHLPS", "MOVLHPS",
        "MOVMSKPS", "MOVSS", "ADDPS", "ADDSS", "SUBPS", "SUBSS", "MULPS",
        "MULSS", "DIVPS", "DIVSS", "RCPPS", "RCPSS", "SQRTPS", "SQRTSS",
        "RSQRTPS", "RSQRTSS", "MAXPS", "MAXSS", "MINPS", "MINSS", "ANDPS",
        "ANDNPS", "ORPS", "XORPS", "CMPPS", "CMPSS", "SHUFPS", "UNPCKHPS",
        "UNPCKLPS", "CVTPI2PS", "CVTSI2SS", "CVTPS2PI", "CVTTPS2PI",
        "CVTSS2SI", "CVTTSS2SI", "LDMXCSR", "STMXCSR", "PAVGB", "PAVGW",
        "PEXTRW", "PINSRW", "PMAXUB", "PMAXSW", "PMINUB", "PMINSW",
        "PMOVMSKB", "PSADBW", "PSHUFW", "MASKMOVQ", "MOVNTQ", "MOVNTPS", "SFENCE",
        // SSE2
        "MOVAPD", "MOVUPD", "MOVHPD", "MOVLPD", "MOVMSKPD", "MOVSD",
        "ADDPD", "ADDSD", "SUBPD", "SUBSD", "MULPD", "MULSD", "DIVPD",
        "DIVSD", "SQRTPD", "SQRTSD", "MAXPD", "MAXSD", "MINPD", "MINSD",
        "ANDPD", "ANDNPD", "ORPD", "XORPD", "CMPPD", "SHUFPD", "UNPCKHPD",
        "UNPCKLPD", "CVTDQ2PD", "CVTDQ2PS", "CVTPD2DQ", "CVTPD2PI", "CVTPD2PS",
        "CVTPI2PD", "CVTPS2DQ", "CVTPS2PD", "CVTSD2SI", "CVTSD2SS", "CVTSI2SD",
        "CVTSS2SD", "CVTTPD2DQ", "CVTTPD2PI", "CVTTPS2DQ", "CVTTSD2SI",
        "MOVDQA", "MOVDQU", "MOVQ2DQ", "MOVDQ2Q", "PMULUDQ", "PADDQ", "PSUBQ",
        "PSHUFLW", "PSHUFHW", "PSHUFD", "PSLLDQ", "PSRLDQ", "PUNPCKLQDQ",
        "PUNPCKHQDQ", "MOVNTDQ", "MOVNTI", "MOVNTPD", "MASKMOVDQU", "LFENCE", "MFENCE",
        // SSE3
        "FISTTP", "ADDSUBPS", "ADDSUBPD", "HADDPS", "HADDPD", "HSUBPS",
        "HSUBPD", "MOVSHDUP", "MOVSLDUP", "MOVDDUP", "MONITOR", "MWAIT", "LDDQU",
        // SSSE3
        "PHADDW", "PHADDD", "PHADDSW", "PHSUBW", "PHSUBD", "PHSUBSW",
        "PABSB", "PABSW", "PABSD", "PMADDUBSW", "PMULHRSW", "PSHUFB",
        "PSIGNB", "PSIGNW", "PSIGND", "PALIGNR",
        // SSE4.1
        "BLENDPD", "BLENDPS", "BLENDVPD", "BLENDVPS", "DPPD", "DPPS",
        "EXTRACTPS", "INSERTPS", "MOVNTDQA", "MPSADBW", "PACKUSDW", "PBLENDVB",
        "PBLENDW", "PCMPEQQ", "PEXTRB", "PEXTRD", "PEXTRQ", "PHMINPOSUW",
        "PINSRB", "PINSRD", "PINSRQ", "PMAXSB", "PMAXSD", "PMAXUD", "PMAXUW",
        "PMINSB", "PMINSD", "PMINUD", "PMINUW", "PMOVSXBW", "PMOVSXBD",
        "PMOVSXBQ", "PMOVSXWD", "PMOVSXWQ", "PMOVSXDQ", "PMOVZXBW", "PMOVZXBD",
        "PMOVZXBQ", "PMOVZXWD", "PMOVZXWQ", "PMOVZXDQ", "PMULDQ", "PMULLD",
        "PTEST", "ROUNDPS", "ROUNDPD", "ROUNDSS", "ROUNDSD",
        // SSE4.2
        "CRC32", "PCMPESTRI", "PCMPESTRM", "PCMPISTRI", "PCMPISTRM", "PCMPGTQ",
        // AES-NI
        "AESDEC", "AESDECLAST", "AESENC", "AESENCLAST", "AESIMC",
        "AESKEYGENASSIST", "PCLMULQDQ",
        // SHA
        "SHA1RNDS4", "SHA1NEXTE", "SHA1MSG1", "SHA1MSG2", "SHA256RNDS2",
        "SHA256MSG1", "SHA256MSG2",
        // AVX
        "VADDPS", "VADDSS", "VADDPD", "VADDSD", "VSUBPS", "VSUBSS", "VSUBPD",
        "VSUBSD", "VMULPS", "VMULSS", "VMULPD", "VMULSD", "VDIVPS", "VDIVSS",
        "VDIVPD", "VDIVSD", "VSQRTPS", "VSQRTSS", "VSQRTPD", "VSQRTSD",
        "VMAXPS", "VMAXSS", "VMAXPD", "VMAXSD", "VMINPS", "VMINSS", "VMINPD",
        "VMINSD", "VANDPS", "VANDNPS", "VORPS", "VXORPS", "VANDPD", "VANDNPD",
        "VORPD", "VXORPD", "VCMPPS", "VCMPSS", "VCMPPD", "VCMPSD", "VSHUFPS",
        "VSHUFPD", "VUNPCKHPS", "VUNPCKLPS", "VUNPCKHPD", "VUNPCKLPD",
        "VMOVAPS", "VMOVUPS", "VMOVAPD", "VMOVUPD", "VMOVSS", "VMOVSD",
        "VMOVHLPS", "VMOVLHPS", "VMOVHPS", "VMOVLPS", "VMOVHPD", "VMOVLPD",
        "VMOVMSKPS", "VMOVMSKPD", "VMOVDQA", "VMOVDQU", "VMOVNTDQ", "VMOVNTPS",
        "VMOVNTPD", "VCVTSI2SS", "VCVTSI2SD", "VCVTSS2SI", "VCVTSD2SI",
        "VCVTTSS2SI", "VCVTTSD2SI", "VCVTDQ2PS", "VCVTPS2DQ", "VCVTTPS2DQ",
        "VCVTDQ2PD", "VCVTPD2DQ", "VCVTTPD2DQ", "VCVTPS2PD", "VCVTPD2PS",
        "VCVTSS2SD", "VCVTSD2SS", "VBROADCASTSS", "VBROADCASTSD",
        "VBROADCASTF128", "VINSERTF128", "VEXTRACTF128", "VMASKMOVPS",
        "VMASKMOVPD", "VPERMILPS", "VPERMILPD", "VPERM2F128", "VTESTPS",
        "VTESTPD", "VZEROUPPER", "VZEROALL", "VLDMXCSR", "VSTMXCSR",
        // FMA
        "VFMADD132PS", "VFMADD132PD", "VFMADD132SS", "VFMADD132SD",
        "VFMADD213PS", "VFMADD213PD", "VFMADD213SS", "VFMADD213SD",
        "VFMADD231PS", "VFMADD231PD", "VFMADD231SS", "VFMADD231SD",
        "VFMSUB132PS", "VFMSUB132PD", "VFMSUB132SS", "VFMSUB132SD",
        "VFMSUB213PS", "VFMSUB213PD", "VFMSUB213SS", "VFMSUB213SD",
        "VFMSUB231PS", "VFMSUB231PD", "VFMSUB231SS", "VFMSUB231SD",
        "VFNMADD132PS", "VFNMADD132PD", "VFNMADD132SS", "VFNMADD132SD",
        "VFNMADD213PS", "VFNMADD213PD", "VFNMADD213SS", "VFNMADD213SD",
        "VFNMADD231PS", "VFNMADD231PD", "VFNMADD231SS", "VFNMADD231SD",
        "VFNMSUB132PS", "VFNMSUB132PD", "VFNMSUB132SS", "VFNMSUB132SD",
        "VFNMSUB213PS", "VFNMSUB213PD", "VFNMSUB213SS", "VFNMSUB213SD",
        "VFNMSUB231PS", "VFNMSUB231PD", "VFNMSUB231SS", "VFNMSUB231SD",
        // AVX2
        "VPBROADCASTB", "VPBROADCASTW", "VPBROADCASTD", "VPBROADCASTQ",
        "VINSERTI128", "VEXTRACTI128", "VPERM2I128", "VPERMD", "VPERMQ",
        "VPERMPS", "VPERMPD", "VPSLLVD", "VPSLLVQ", "VPSRLVD", "VPSRLVQ",
        "VPSRAVD", "VPMASKMOVD", "VPMASKMOVQ", "VGATHERDPS", "VGATHERDPD",
        "VGATHERQPS", "VGATHERQPD", "VPGATHERDD", "VPGATHERDQ", "VPGATHERQD",
        "VPGATHERQQ", "VPMULLD", "VPMULLW", "VPMULHW", "VPMULHUW", "VPMULHRSW",
        "VPMULUDQ", "VPMULDQ", "VPADDUSB", "VPADDUSW", "VPSUBUSB", "VPSUBUSW",
        "VPADDSB", "VPADDSW", "VPSUBSB", "VPSUBSW", "VPHADDW", "VPHADDD",
        "VPHADDSW", "VPHSUBW", "VPHSUBD", "VPHSUBSW", "VBLENDVPS", "VBLENDVPD",
        "VPBLENDVB",
        // AVX-512
        "KAND", "KANDN", "KNOT", "KOR", "KXNOR", "KXOR", "KADD", "KTEST",
        "KSHIFTL", "KSHIFTR", "KUNPCKBW", "KUNPCKWD", "KUNPCKDQ", "KMOV",
        "VPLZCNTD", "VPLZCNTQ", "VPCONFLICTD", "VPCONFLICTQ",
        "VEXP2PS", "VEXP2PD", "VRCP28PS", "VRCP28PD", "VRCP28SS", "VRCP28SD",
        "VRSQRT28PS", "VRSQRT28PD", "VRSQRT28SS", "VRSQRT28SD",
        "VGATHERPF0DPS", "VGATHERPF0DPD", "VGATHERPF0QPS", "VGATHERPF0QPD",
        "VGATHERPF1DPS", "VGATHERPF1DPD", "VGATHERPF1QPS", "VGATHERPF1QPD",
        "VSCATTERPF0DPS", "VSCATTERPF0DPD", "VSCATTERPF0QPS", "VSCATTERPF0QPD",
        "VSCATTERPF1DPS", "VSCATTERPF1DPD", "VSCATTERPF1QPS", "VSCATTERPF1QPD",
        "VPCMPB", "VPCMPUB", "VPCMPW", "VPCMPUW", "VPMOVM2B", "VPMOVM2W",
        "VPMOVB2M", "VPMOVW2M", "VPMOVWB", "VPMOVSWB", "VPMOVUSWB",
        "VPBLENDMB", "VPBLENDMW", "VPTESTNMB", "VPTESTNMW", "VDBPSADBW",
        "VFPCLASSPS", "VFPCLASSPD", "VFPCLASSSS", "VFPCLASSSD", "VRANGEPD",
        "VRANGEPS", "VRANGESD", "VRANGESS", "VREDUCEPD", "VREDUCEPS",
        "VREDUCESD", "VREDUCESS", "VCVTUDQ2PD", "VCVTUDQ2PS", "VCVTPS2UDQ",
        "VCVTPD2UDQ", "VCVTTPS2UDQ", "VCVTTPD2UDQ", "VCVTQQ2PD", "VCVTQQ2PS",
        "VCVTPD2QQ", "VCVTPS2QQ", "VCVTTPD2QQ", "VCVTTPS2QQ", "VCVTUQQ2PD",
        "VCVTUQQ2PS", "VCVTPD2UQQ", "VCVTPS2UQQ", "VCVTTPD2UQQ", "VCVTTPS2UQQ",
        "VPERMB", "VPERMI2B", "VPERMT2B", "VPMULTISHIFTQB", "VPERMW",
        "VPMADD52LUQ", "VPMADD52HUQ", "VPSHRDV", "VPSHRDQ", "VPSHLDV", "VPSHLDQ",
        "VPCOMPRESSB", "VPCOMPRESSW", "VPEXPANDB", "VPEXPANDW",
        "VPDPBUSD", "VPDPBUSDS", "VPDPWSSD", "VPDPWSSDS",
        "VPOPCNTB", "VPOPCNTW", "VPOPCNTD", "VPOPCNTQ", "VPSHUFBITQMB",
        "VCVTNE2PS2BF16", "VCVTNEPS2BF16", "VDPBF16PS",
        "VP2INTERSECTD", "VP2INTERSECTQ",
        "VADDPH", "VADDSH", "VSUBPH", "VSUBSH", "VMULPH", "VMULSH", "VDIVPH",
        "VDIVSH", "VFMADD132PH", "VFMADD213PH", "VFMADD231PH", "VFMSUB132PH",
        "VFMSUB213PH", "VFMSUB231PH", "VCVTPH2PD", "VCVTPH2PS", "VCVTPD2PH",
        "VCVTPS2PH", "VCVTSH2SI", "VCVTSI2SH", "VCVTTSH2SI",
        // x87
        "FADD", "FADDP", "FIADD", "FSUB", "FSUBP", "FISUB", "FSUBR", "FSUBRP",
        "FISUBR", "FMUL", "FMULP", "FIMUL", "FDIV", "FDIVP", "FIDIV", "FDIVR",
        "FDIVRP", "FIDIVR", "FABS", "FCHS", "FRNDINT", "FSCALE", "FSQRT",
        "FXTRACT", "FPREM", "FPREM1", "FCOM", "FCOMP", "FCOMPP", "FICOM",
        "FICOMP", "FUCOM", "FUCOMP", "FUCOMPP", "FTST", "FXAM", "FLD", "FLD1",
        "FLDZ", "FLDPI", "FLDL2E", "FLDL2T", "FLDLG2", "FLDLN2", "FST", "FSTP",
        "FIST", "FISTP", "FBLD", "FBSTP", "FXCH", "FCMOVB", "FCMOVE", "FCMOVBE",
        "FCMOVU", "FCMOVNB", "FCMOVNE", "FCMOVNBE", "FCMOVNU", "FILD", "FNOP",
        "FNCLEX", "FNINIT", "FNSAVE", "FNRSTOR", "FNSTCW", "FNSTENV", "FNSTSW",
        "FFREE", "FDECSTP", "FINCSTP", "FPTAN", "FPATAN", "FYL2X", "FYL2XP1",
        "F2XM1", "FCOS", "FSIN", "FSINCOS",
        // VMX
        "VMXON", "VMXOFF", "VMCLEAR", "VMPTRLD", "VMPTRST", "VMREAD", "VMWRITE",
        "VMLAUNCH", "VMRESUME", "VMCALL", "INVEPT", "INVVPID", "VMFUNC",
        // SVM
        "VMRUN", "VMLOAD", "VMSAVE", "STGI", "CLGI", "SKINIT",
        // SGX/SMX/TSX/MPX
        "ENCLS", "ENCLU", "ENCLV", "GETSEC", "XBEGIN", "XEND", "XABORT", "XTEST",
        "BNDMK", "BNDCL", "BNDCU", "BNDCN", "BNDMOV", "BNDLDX", "BNDSTX",
        // Misc system
        "RDFSBASE", "RDGSBASE", "WRFSBASE", "WRGSBASE", "RDPID", "CLDEMOTE",
        "MOVDIRI", "MOVDIR64B", "ENQCMD", "ENQCMDS", "PCONFIG", "UMWAIT",
        "UMONITOR", "TPAUSE",
        // CET
        "ENDBR64", "ENDBR32", "RDSSPD", "RDSSPQ", "INCSSPD", "INCSSPQ",
        "SETSSBSY", "CLRSSBSY", "WRSSD", "WRSSQ", "WRUSSD", "WRUSSQ",
        // UINTR
        "UIRET", "SENDUPI", "STUI", "TESTUI", "CLUI",
    ];
    names.iter().map(|&s| InstructionMnemonic::new(s)).collect()
}

// ============================================================================
// ProcessorModule Implementation
// ============================================================================

/// x86/x86-64 processor module adapter for the processor registry.
pub struct X86Module;

impl ProcessorModule for X86Module {
    fn name() -> &'static str {
        PROCESSOR_NAME
    }

    fn registers() -> RegisterBank {
        let x86_bank = X86RegisterBank::new_x86_64();
        let mut bank = RegisterBank::new();
        for reg in x86_bank.iter() {
            let common_reg = match reg.parent {
                Some(ref parent) => crate::common::Register::sub_register(
                    &reg.name,
                    reg.bit_size,
                    reg.offset,
                    parent,
                    reg.lsb,
                ),
                None => crate::common::Register::new(
                    &reg.name,
                    reg.bit_size,
                    reg.offset,
                ),
            };
            bank.add(common_reg);
        }
        bank
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "x86:LE:16:RealMode",
                "x86 16-bit Real Mode (8086)",
                "RealMode",
                Endian::Little,
                16,
            ),
            Language::new(
                "x86:LE:32:default",
                "x86 32-bit Protected Mode",
                "default",
                Endian::Little,
                32,
            ),
            Language::new(
                "x86:LE:32:Protected",
                "x86 32-bit Protected Mode (detailed)",
                "Protected",
                Endian::Little,
                32,
            ),
            Language::new(
                "x86:LE:32:SystemManagement",
                "x86 32-bit System Management Mode",
                "SystemManagement",
                Endian::Little,
                32,
            ),
            Language::new(
                "x86:LE:64:default",
                "x86-64 Long Mode",
                "default",
                Endian::Little,
                64,
            ),
            Language::new(
                "x86:LE:64:LongMode",
                "x86-64 Long Mode (detailed)",
                "LongMode",
                Endian::Little,
                64,
            ),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> {
        all_x86_mnemonics()
    }
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

    #[test]
    fn test_processor_module_name() {
        assert_eq!(X86Module::name(), "x86");
    }

    #[test]
    fn test_processor_module_registers() {
        let bank = X86Module::registers();
        assert!(bank.len() > 100);
        assert!(bank.get("RAX").is_some());
        assert!(bank.get("EAX").is_some());
        assert!(bank.get("XMM0").is_some());
        assert!(bank.get("CR3").is_some());
        assert!(bank.get("EFLAGS").is_some());
        assert!(bank.get("RIP").is_some());
        assert!(bank.get("FS").is_some());
        assert!(bank.get("GS").is_some());
    }

    #[test]
    fn test_processor_module_languages() {
        let langs = X86Module::languages();
        assert!(!langs.is_empty());
        let ids: Vec<&str> = langs.iter().map(|l| l.id.as_str()).collect();
        assert!(ids.contains(&"x86:LE:32:default"));
        assert!(ids.contains(&"x86:LE:64:default"));
        assert!(ids.contains(&"x86:LE:16:RealMode"));
        for lang in &langs {
            assert_eq!(lang.endian, Endian::Little);
        }
    }

    #[test]
    fn test_processor_module_instructions() {
        let insts = X86Module::instructions();
        assert!(insts.len() > 500);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"MOV"));
        assert!(texts.contains(&"ADD"));
        assert!(texts.contains(&"CALL"));
        assert!(texts.contains(&"RET"));
        assert!(texts.contains(&"JMP"));
        assert!(texts.contains(&"PUSH"));
        assert!(texts.contains(&"LEA"));
        assert!(texts.contains(&"SYSCALL"));
        assert!(texts.contains(&"VADDPS"));
        assert!(texts.contains(&"FADD"));
    }
}
