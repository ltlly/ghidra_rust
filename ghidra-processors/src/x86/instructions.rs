//! x86 Instruction Mnemonics, Encoding Helpers, and Addressing Modes
//!
//! Covers the complete x86 instruction set across all extensions:
//! - Base x86 (8086 through Pentium)
//! - x86-64 (AMD64 / Intel 64)
//! - MMX, SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4.2
//! - AVX, AVX2, FMA, AVX-512
//! - AES-NI, SHA, BMI1, BMI2, ADX
//! - System instructions (SYSCALL, VMX, SVM, SGX, etc.)

/// Complete x86 instruction mnemonic enumeration.
///
/// Organised by functional category. Every mnemonic maps to one or more
/// actual opcodes depending on operand types, operand sizes, and prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum X86Mnemonic {
    // ======================================================================
    // Data Movement
    // ======================================================================
    MOV,
    MOVSX,
    MOVZX,
    MOVSXD,
    CMOVcc(ConditionCode),
    XCHG,
    BSWAP,
    XADD,
    CMPXCHG,
    CMPXCHG8B,
    CMPXCHG16B,

    // ======================================================================
    // Stack Operations
    // ======================================================================
    PUSH,
    POP,
    PUSHA,
    POPA,
    PUSHF,
    POPF,
    PUSHFD,
    POPFD,
    PUSHFQ,
    POPFQ,
    ENTER,
    LEAVE,

    // ======================================================================
    // Binary Arithmetic
    // ======================================================================
    ADD,
    ADC,
    SUB,
    SBB,
    IMUL,
    MUL,
    IDIV,
    DIV,
    INC,
    DEC,
    NEG,
    CMP,

    // ======================================================================
    // Decimal Arithmetic
    // ======================================================================
    DAA,
    DAS,
    AAA,
    AAS,
    AAM,
    AAD,

    // ======================================================================
    // Logical Operations
    // ======================================================================
    AND,
    OR,
    XOR,
    NOT,
    TEST,

    // ======================================================================
    // Shift and Rotate
    // ======================================================================
    SHL,
    SHR,
    SAL,
    SAR,
    ROL,
    ROR,
    RCL,
    RCR,
    SHLD,
    SHRD,

    // ======================================================================
    // Bit Manipulation
    // ======================================================================
    BT,
    BTS,
    BTR,
    BTC,
    BSF,
    BSR,
    LZCNT,
    TZCNT,
    POPCNT,
    // BMI1
    ANDN,
    BEXTR,
    BLSI,
    BLSMSK,
    BLSR,
    // BMI2
    BZHI,
    MULX,
    PDEP,
    PEXT,
    RORX,
    SARX,
    SHLX,
    SHRX,

    // ======================================================================
    // Control Transfer
    // ======================================================================
    JMP,
    Jcc(ConditionCode),
    CALL,
    RET,
    RETF,
    JECXZ,
    JRCXZ,
    LOOP,
    LOOPE,
    LOOPNE,

    // ======================================================================
    // Conditional Set / Move
    // ======================================================================
    SETcc(ConditionCode),

    // ======================================================================
    // String Operations
    // ======================================================================
    MOVS,
    MOVSB,
    MOVSW,
    MOVSD,
    MOVSQ,
    CMPS,
    CMPSB,
    CMPSW,
    CMPSD,
    CMPSQ,
    SCAS,
    SCASB,
    SCASW,
    SCASD,
    SCASQ,
    LODS,
    LODSB,
    LODSW,
    LODSD,
    LODSQ,
    STOS,
    STOSB,
    STOSW,
    STOSD,
    STOSQ,
    INS,
    INSB,
    INSW,
    INSD,
    OUTS,
    OUTSB,
    OUTSW,
    OUTSD,
    REP,
    REPE,
    REPZ,
    REPNE,
    REPNZ,

    // ======================================================================
    // I/O Instructions
    // ======================================================================
    IN,
    OUT,

    // ======================================================================
    // Flag Control
    // ======================================================================
    STC,
    CLC,
    CMC,
    STD,
    CLD,
    STI,
    CLI,
    LAHF,
    SAHF,

    // ======================================================================
    // Segment Register
    // ======================================================================
    LDS,
    LES,
    LFS,
    LGS,
    LSS,

    // ======================================================================
    // System Instructions
    // ======================================================================
    SYSCALL,
    SYSRET,
    SYSENTER,
    SYSEXIT,
    INT,
    INT3,
    INTO,
    IRET,
    IRETD,
    IRETQ,
    HLT,
    PAUSE,
    RSM,
    UD2,

    // ======================================================================
    // System Table Management
    // ======================================================================
    LGDT,
    SGDT,
    LIDT,
    SIDT,
    LLDT,
    SLDT,
    LTR,
    STR,
    LMSW,
    SMSW,
    CLTS,
    LAR,
    LSL,
    VERR,
    VERW,

    // ======================================================================
    // Control / Debug Register
    // ======================================================================
    MOV_CR,
    MOV_DR,

    // ======================================================================
    // Cache and TLB Management
    // ======================================================================
    INVD,
    WBINVD,
    INVLPG,
    INVLPGA,
    INVPCID,
    CLFLUSH,
    CLFLUSHOPT,
    CLWB,
    PREFETCH,
    PREFETCHW,
    PREFETCH_NTA,
    PREFETCH_T0,
    PREFETCH_T1,
    PREFETCH_T2,

    // ======================================================================
    // Model-Specific and Performance
    // ======================================================================
    RDTSC,
    RDTSCP,
    RDPMC,
    RDMSR,
    WRMSR,
    CPUID,
    XGETBV,
    XSETBV,
    RDRAND,
    RDSEED,

    // ======================================================================
    // LEA / NOP
    // ======================================================================
    LEA,
    NOP,
    UD0,
    UD1,

    // ======================================================================
    // Address size / operand size override (prefixes)
    // ======================================================================
    PREFIX_LOCK,
    PREFIX_REP,
    PREFIX_REPNE,
    PREFIX_CS,
    PREFIX_DS,
    PREFIX_ES,
    PREFIX_FS,
    PREFIX_GS,
    PREFIX_SS,
    PREFIX_DATA16,
    PREFIX_ADDR16,
    PREFIX_REX,
    PREFIX_REX_W,
    PREFIX_REX_R,
    PREFIX_REX_X,
    PREFIX_REX_B,

    // ======================================================================
    // MMX Instructions
    // ======================================================================
    MOVD,
    MOVQ,
    PACKSSWB,
    PACKSSDW,
    PACKUSWB,
    PUNPCKLBW,
    PUNPCKHBW,
    PUNPCKLWD,
    PUNPCKHWD,
    PUNPCKLDQ,
    PUNPCKHDQ,
    PADDB,
    PADDW,
    PADDD,
    PADDSB,
    PADDSW,
    PADDUSB,
    PADDUSW,
    PSUBB,
    PSUBW,
    PSUBD,
    PSUBSB,
    PSUBSW,
    PSUBUSB,
    PSUBUSW,
    PMULLW,
    PMULHW,
    PMULLW_HIGH,
    PMULHUW,
    PMADDWD,
    PCMPEQB,
    PCMPEQW,
    PCMPEQD,
    PCMPGTB,
    PCMPGTW,
    PCMPGTD,
    PAND,
    PANDN,
    POR,
    PXOR,
    PSLLW,
    PSLLD,
    PSLLQ,
    PSRLW,
    PSRLD,
    PSRLQ,
    PSRAW,
    PSRAD,
    EMMS,

    // ======================================================================
    // SSE Instructions
    // ======================================================================
    MOVAPS,
    MOVUPS,
    MOVHPS,
    MOVLPS,
    MOVHLPS,
    MOVLHPS,
    MOVMSKPS,
    MOVSS,
    ADDPS,
    ADDSS,
    SUBPS,
    SUBSS,
    MULPS,
    MULSS,
    DIVPS,
    DIVSS,
    RCPPS,
    RCPSS,
    SQRTPS,
    SQRTSS,
    RSQRTPS,
    RSQRTSS,
    MAXPS,
    MAXSS,
    MINPS,
    MINSS,
    ANDPS,
    ANDNPS,
    ORPS,
    XORPS,
    CMPPS,
    CMPSS,
    SHUFPS,
    UNPCKHPS,
    UNPCKLPS,
    CVTPI2PS,
    CVTSI2SS,
    CVTPS2PI,
    CVTTPS2PI,
    CVTSS2SI,
    CVTTSS2SI,
    LDMXCSR,
    STMXCSR,
    PAVGB,
    PAVGW,
    PEXTRW,
    PINSRW,
    PMAXUB,
    PMAXSW,
    PMINUB,
    PMINSW,
    PMOVMSKB,
    PMULHUW_SSE,
    PSADBW,
    PSHUFW,
    MASKMOVQ,
    MOVNTQ,
    MOVNTPS,
    SFENCE,
    PREFETCH_NTA_SSE,
    PREFETCH_T0_SSE,
    PREFETCH_T1_SSE,
    PREFETCH_T2_SSE,

    // ======================================================================
    // SSE2 Instructions
    // ======================================================================
    MOVAPD,
    MOVUPD,
    MOVHPD,
    MOVLPD,
    MOVMSKPD,
    MOVSD_SCALAR,
    ADDPD,
    ADDSD,
    SUBPD,
    SUBSD,
    MULPD,
    MULSD,
    DIVPD,
    DIVSD,
    SQRTPD,
    SQRTSD,
    MAXPD,
    MAXSD,
    MINPD,
    MINSD,
    ANDPD,
    ANDNPD,
    ORPD,
    XORPD,
    CMPPD,
    CMPSD_SCALAR,
    SHUFPD,
    UNPCKHPD,
    UNPCKLPD,
    CVTDQ2PD,
    CVTDQ2PS,
    CVTPD2DQ,
    CVTPD2PI,
    CVTPD2PS,
    CVTPI2PD,
    CVTPS2DQ,
    CVTPS2PD,
    CVTSD2SI,
    CVTSD2SS,
    CVTSI2SD,
    CVTSS2SD,
    CVTTPD2DQ,
    CVTTPD2PI,
    CVTTPS2DQ,
    CVTTSD2SI,
    MOVDQA,
    MOVDQU,
    MOVQ2DQ,
    MOVDQ2Q,
    PMULUDQ,
    PADDQ,
    PSUBQ,
    PSHUFLW,
    PSHUFHW,
    PSHUFD,
    PSLLDQ,
    PSRLDQ,
    PUNPCKLQDQ,
    PUNPCKHQDQ,
    MOVNTDQ,
    MOVNTI,
    MOVNTPD,
    MASKMOVDQU,
    CLFLUSH_SSE2,
    LFENCE,
    MFENCE,

    // ======================================================================
    // SSE3 Instructions
    // ======================================================================
    FISTTP,
    ADDSUBPS,
    ADDSUBPD,
    HADDPS,
    HADDPD,
    HSUBPS,
    HSUBPD,
    MOVSHDUP,
    MOVSLDUP,
    MOVDDUP,
    MONITOR,
    MWAIT,
    LDDQU,

    // ======================================================================
    // SSSE3 Instructions
    // ======================================================================
    PHADDW,
    PHADDD,
    PHADDSW,
    PHSUBW,
    PHSUBD,
    PHSUBSW,
    PABSB,
    PABSW,
    PABSD,
    PMADDUBSW,
    PMULHRSW,
    PSHUFB,
    PSIGNB,
    PSIGNW,
    PSIGND,
    PALIGNR,

    // ======================================================================
    // SSE4.1 Instructions
    // ======================================================================
    BLENDPD,
    BLENDPS,
    BLENDVPD,
    BLENDVPS,
    DPPD,
    DPPS,
    EXTRACTPS,
    INSERTPS,
    MOVNTDQA,
    MPSADBW,
    PACKUSDW,
    PBLENDVB,
    PBLENDW,
    PCMPEQQ,
    PEXTRB,
    PEXTRD,
    PEXTRQ,
    PHMINPOSUW,
    PINSRB,
    PINSRD,
    PINSRQ,
    PMAXSB,
    PMAXSD,
    PMAXUD,
    PMAXUW,
    PMINSB,
    PMINSD,
    PMINUD,
    PMINUW,
    PMOVSXBW,
    PMOVSXBD,
    PMOVSXBQ,
    PMOVSXWD,
    PMOVSXWQ,
    PMOVSXDQ,
    PMOVZXBW,
    PMOVZXBD,
    PMOVZXBQ,
    PMOVZXWD,
    PMOVZXWQ,
    PMOVZXDQ,
    PMULDQ,
    PMULLD,
    PTEST,
    ROUNDPS,
    ROUNDPD,
    ROUNDSS,
    ROUNDSD,

    // ======================================================================
    // SSE4.2 Instructions
    // ======================================================================
    CRC32,
    PCMPESTRI,
    PCMPESTRM,
    PCMPISTRI,
    PCMPISTRM,
    PCMPGTQ,
    POPCNT_SSE42,

    // ======================================================================
    // AES-NI
    // ======================================================================
    AESDEC,
    AESDECLAST,
    AESENC,
    AESENCLAST,
    AESIMC,
    AESKEYGENASSIST,
    PCLMULQDQ,

    // ======================================================================
    // SHA
    // ======================================================================
    SHA1RNDS4,
    SHA1NEXTE,
    SHA1MSG1,
    SHA1MSG2,
    SHA256RNDS2,
    SHA256MSG1,
    SHA256MSG2,

    // ======================================================================
    // AVX Instructions
    // ======================================================================
    VADDPS,
    VADDSS,
    VADDPD,
    VADDSD,
    VSUBPS,
    VSUBSS,
    VSUBPD,
    VSUBSD,
    VMULPS,
    VMULSS,
    VMULPD,
    VMULSD,
    VDIVPS,
    VDIVSS,
    VDIVPD,
    VDIVSD,
    VSQRTPS,
    VSQRTSS,
    VSQRTPD,
    VSQRTSD,
    VMAXPS,
    VMAXSS,
    VMAXPD,
    VMAXSD,
    VMINPS,
    VMINSS,
    VMINPD,
    VMINSD,
    VANDPS,
    VANDNPS,
    VORPS,
    VXORPS,
    VANDPD,
    VANDNPD,
    VORPD,
    VXORPD,
    VCMPPS,
    VCMPSS,
    VCMPPD,
    VCMPSD,
    VSHUFPS,
    VSHUFPD,
    VUNPCKHPS,
    VUNPCKLPS,
    VUNPCKHPD,
    VUNPCKLPD,
    VMOVAPS,
    VMOVUPS,
    VMOVAPD,
    VMOVUPD,
    VMOVSS,
    VMOVSD,
    VMOVHLPS,
    VMOVLHPS,
    VMOVHPS,
    VMOVLPS,
    VMOVHPD,
    VMOVLPD,
    VMOVMSKPS,
    VMOVMSKPD,
    VMOVDQA,
    VMOVDQU,
    VMOVNTDQ,
    VMOVNTPS,
    VMOVNTPD,
    VCVTSI2SS,
    VCVTSI2SD,
    VCVTSS2SI,
    VCVTSD2SI,
    VCVTTSS2SI,
    VCVTTSD2SI,
    VCVTDQ2PS,
    VCVTPS2DQ,
    VCVTTPS2DQ,
    VCVTDQ2PD,
    VCVTPD2DQ,
    VCVTTPD2DQ,
    VCVTPS2PD,
    VCVTPD2PS,
    VCVTSS2SD,
    VCVTSD2SS,
    VBROADCASTSS,
    VBROADCASTSD,
    VBROADCASTF128,
    VINSERTF128,
    VEXTRACTF128,
    VMASKMOVPS,
    VMASKMOVPD,
    VPERMILPS,
    VPERMILPD,
    VPERM2F128,
    VTESTPS,
    VTESTPD,
    VZEROUPPER,
    VZEROALL,
    VLDMXCSR,
    VSTMXCSR,

    // ======================================================================
    // FMA (Fused Multiply-Add)
    // ======================================================================
    VFMADD132PS,
    VFMADD132PD,
    VFMADD132SS,
    VFMADD132SD,
    VFMADD213PS,
    VFMADD213PD,
    VFMADD213SS,
    VFMADD213SD,
    VFMADD231PS,
    VFMADD231PD,
    VFMADD231SS,
    VFMADD231SD,
    VFMSUB132PS,
    VFMSUB132PD,
    VFMSUB132SS,
    VFMSUB132SD,
    VFMSUB213PS,
    VFMSUB213PD,
    VFMSUB213SS,
    VFMSUB213SD,
    VFMSUB231PS,
    VFMSUB231PD,
    VFMSUB231SS,
    VFMSUB231SD,
    VFNMADD132PS,
    VFNMADD132PD,
    VFNMADD132SS,
    VFNMADD132SD,
    VFNMADD213PS,
    VFNMADD213PD,
    VFNMADD213SS,
    VFNMADD213SD,
    VFNMADD231PS,
    VFNMADD231PD,
    VFNMADD231SS,
    VFNMADD231SD,
    VFNMSUB132PS,
    VFNMSUB132PD,
    VFNMSUB132SS,
    VFNMSUB132SD,
    VFNMSUB213PS,
    VFNMSUB213PD,
    VFNMSUB213SS,
    VFNMSUB213SD,
    VFNMSUB231PS,
    VFNMSUB231PD,
    VFNMSUB231SS,
    VFNMSUB231SD,

    // ======================================================================
    // AVX2 Instructions
    // ======================================================================
    VPBROADCASTB,
    VPBROADCASTW,
    VPBROADCASTD,
    VPBROADCASTQ,
    VINSERTI128,
    VEXTRACTI128,
    VPERM2I128,
    VPERMD,
    VPERMQ,
    VPERMPS,
    VPERMPD,
    VPSLLVD,
    VPSLLVQ,
    VPSRLVD,
    VPSRLVQ,
    VPSRAVD,
    VPMASKMOVD,
    VPMASKMOVQ,
    VGATHERDPS,
    VGATHERDPD,
    VGATHERQPS,
    VGATHERQPD,
    VPGATHERDD,
    VPGATHERDQ,
    VPGATHERQD,
    VPGATHERQQ,
    VPMULLD,
    VPMULLW,
    VPMULHW,
    VPMULHUW,
    VPMULHRSW,
    VPMULUDQ,
    VPMULDQ,
    VPADDUSB,
    VPADDUSW,
    VPSUBUSB,
    VPSUBUSW,
    VPADDSB,
    VPADDSW,
    VPSUBSB,
    VPSUBSW,
    VPHADDW,
    VPHADDD,
    VPHADDSW,
    VPHSUBW,
    VPHSUBD,
    VPHSUBSW,
    VBLENDVPS,
    VBLENDVPD,
    VPBLENDVB,

    // ======================================================================
    // AVX-512 Foundation (AVX-512F)
    // ======================================================================
    // Mask management
    KAND,
    KANDN,
    KNOT,
    KOR,
    KXNOR,
    KXOR,
    KADD,
    KTEST,
    KSHIFTL,
    KSHIFTR,
    KUNPCKBW,
    KUNPCKWD,
    KUNPCKDQ,
    KMOV,

    // ======================================================================
    // AVX-512 Conflict Detection (AVX-512CD)
    // ======================================================================
    VPLZCNTD,
    VPLZCNTQ,
    VPCONFLICTD,
    VPCONFLICTQ,
    VPBROADCASTM,
    VPBROADCASTMW,

    // ======================================================================
    // AVX-512 Exponential and Reciprocal (AVX-512ER)
    // ======================================================================
    VEXP2PS,
    VEXP2PD,
    VRCP28PS,
    VRCP28PD,
    VRCP28SS,
    VRCP28SD,
    VRSQRT28PS,
    VRSQRT28PD,
    VRSQRT28SS,
    VRSQRT28SD,

    // ======================================================================
    // AVX-512 Prefetch (AVX-512PF)
    // ======================================================================
    VGATHERPF0DPS,
    VGATHERPF0DPD,
    VGATHERPF0QPS,
    VGATHERPF0QPD,
    VGATHERPF1DPS,
    VGATHERPF1DPD,
    VGATHERPF1QPS,
    VGATHERPF1QPD,
    VSCATTERPF0DPS,
    VSCATTERPF0DPD,
    VSCATTERPF0QPS,
    VSCATTERPF0QPD,
    VSCATTERPF1DPS,
    VSCATTERPF1DPD,
    VSCATTERPF1QPS,
    VSCATTERPF1QPD,

    // ======================================================================
    // AVX-512 Byte and Word (AVX-512BW)
    // ======================================================================
    VPCMPB,
    VPCMPUB,
    VPCMPW,
    VPCMPUW,
    VPMOVM2B,
    VPMOVM2W,
    VPMOVB2M,
    VPMOVW2M,
    VPMOVWB,
    VPMOVSWB,
    VPMOVUSWB,
    VPADDB_Z,
    VPADDW_Z,
    VPSUBB_Z,
    VPSUBW_Z,
    VPMULLW_Z,
    VPBLENDMB,
    VPBLENDMW,
    VPTESTNMB,
    VPTESTNMW,
    VDBPSADBW,

    // ======================================================================
    // AVX-512 DWord and QWord (AVX-512DQ)
    // ======================================================================
    VANDPS_Z,
    VANDNPS_Z,
    VORPS_Z,
    VXORPS_Z,
    VANDPD_Z,
    VANDNPD_Z,
    VORPD_Z,
    VXORPD_Z,
    VFPCLASSPS,
    VFPCLASSPD,
    VFPCLASSSS,
    VFPCLASSSD,
    VRANGEPD,
    VRANGEPS,
    VRANGESD,
    VRANGESS,
    VREDUCEPD,
    VREDUCEPS,
    VREDUCESD,
    VREDUCESS,
    VCVTUDQ2PD,
    VCVTUDQ2PS,
    VCVTPS2UDQ,
    VCVTPD2UDQ,
    VCVTTPS2UDQ,
    VCVTTPD2UDQ,
    VCVTQQ2PD,
    VCVTQQ2PS,
    VCVTPD2QQ,
    VCVTPS2QQ,
    VCVTTPD2QQ,
    VCVTTPS2QQ,
    VCVTUQQ2PD,
    VCVTUQQ2PS,
    VCVTPD2UQQ,
    VCVTPS2UQQ,
    VCVTTPD2UQQ,
    VCVTTPS2UQQ,

    // ======================================================================
    // AVX-512 VL (Vector Length)
    // ======================================================================
    // Handled as attribute of instructions operating on 128/256/512-bit vectors

    // ======================================================================
    // AVX-512 VBMI (Vector Byte Manipulation Instructions)
    // ======================================================================
    VPERMB,
    VPERMI2B,
    VPERMT2B,
    VPMULTISHIFTQB,
    VPERMW,

    // ======================================================================
    // AVX-512 IFMA
    // ======================================================================
    VPMADD52LUQ,
    VPMADD52HUQ,

    // ======================================================================
    // AVX-512 VBMI2
    // ======================================================================
    VPSHRDV,
    VPSHRDQ,
    VPSHLDV,
    VPSHLDQ,
    VPCOMPRESSB,
    VPCOMPRESSW,
    VPEXPANDB,
    VPEXPANDW,

    // ======================================================================
    // AVX-512 VNNI (Vector Neural Network Instructions)
    // ======================================================================
    VPDPBUSD,
    VPDPBUSDS,
    VPDPWSSD,
    VPDPWSSDS,

    // ======================================================================
    // AVX-512 BITALG
    // ======================================================================
    VPOPCNTB,
    VPOPCNTW,
    VPOPCNTD,
    VPOPCNTQ,
    VPSHUFBITQMB,

    // ======================================================================
    // AVX-512 BF16 (Bfloat16)
    // ======================================================================
    VCVTNE2PS2BF16,
    VCVTNEPS2BF16,
    VDPBF16PS,

    // ======================================================================
    // AVX-512 VP2INTERSECT
    // ======================================================================
    VP2INTERSECTD,
    VP2INTERSECTQ,

    // ======================================================================
    // AVX-512 FP16 (Half-precision floating point)
    // ======================================================================
    VADDPH,
    VADDSH,
    VSUBPH,
    VSUBSH,
    VMULPH,
    VMULSH,
    VDIVPH,
    VDIVSH,
    VFMADD132PH,
    VFMADD213PH,
    VFMADD231PH,
    VFMSUB132PH,
    VFMSUB213PH,
    VFMSUB231PH,
    VCVTPH2PD,
    VCVTPH2PS,
    VCVTPD2PH,
    VCVTPS2PH,
    VCVTSH2SI,
    VCVTSI2SH,
    VCVTTSH2SI,

    // ======================================================================
    // x87 FPU Instructions
    // ======================================================================
    FADD,
    FADDP,
    FIADD,
    FSUB,
    FSUBP,
    FISUB,
    FSUBR,
    FSUBRP,
    FISUBR,
    FMUL,
    FMULP,
    FIMUL,
    FDIV,
    FDIVP,
    FIDIV,
    FDIVR,
    FDIVRP,
    FIDIVR,
    FABS,
    FCHS,
    FRNDINT,
    FSCALE,
    FSQRT,
    FXTRACT,
    FPREM,
    FPREM1,
    FCOM,
    FCOMP,
    FCOMPP,
    FICOM,
    FICOMP,
    FUCOM,
    FUCOMP,
    FUCOMPP,
    FTST,
    FXAM,
    FLD,
    FLD1,
    FLDZ,
    FLDPI,
    FLDL2E,
    FLDL2T,
    FLDLG2,
    FLDLN2,
    FST,
    FSTP,
    FIST,
    FISTP,
    FBLD,
    FBSTP,
    FXCH,
    FCMOVcc(ConditionCode),
    FILD,
    FNOP,
    FNCLEX,
    FNINIT,
    FNSAVE,
    FNRSTOR,
    FNSTCW,
    FNSTENV,
    FNSTSW,
    FFREE,
    FDECSTP,
    FINCSTP,
    FPTAN,
    FPATAN,
    FYL2X,
    FYL2XP1,
    F2XM1,
    FCOS,
    FSIN,
    FSINCOS,

    // ======================================================================
    // VMX (Intel Virtual Machine Extensions)
    // ======================================================================
    VMXON,
    VMXOFF,
    VMCLEAR,
    VMPTRLD,
    VMPTRST,
    VMREAD,
    VMWRITE,
    VMLAUNCH,
    VMRESUME,
    VMX_VMCALL,
    INVEPT,
    INVVPID,
    VMFUNC,

    // ======================================================================
    // SVM (AMD Secure Virtual Machine)
    // ======================================================================
    VMRUN,
    VMLOAD,
    VMSAVE,
    STGI,
    CLGI,
    SKINIT,
    INVLPGA_SVM,

    // ======================================================================
    // SGX (Software Guard Extensions)
    // ======================================================================
    ENCLS,
    ENCLU,
    ENCLV,

    // ======================================================================
    // SMX (Safer Mode Extensions)
    // ======================================================================
    GETSEC,

    // ======================================================================
    // TSX (Transactional Synchronization Extensions)
    // ======================================================================
    XBEGIN,
    XEND,
    XABORT,
    XTEST,

    // ======================================================================
    // MPX (Memory Protection Extensions)
    // ======================================================================
    BNDMK,
    BNDCL,
    BNDCU,
    BNDCN,
    BNDMOV,
    BNDLDX,
    BNDSTX,

    // ======================================================================
    // RDPID / RDFSBASE / RDGSBASE / WRFSBASE / WRGSBASE
    // ======================================================================
    RDFSBASE,
    RDGSBASE,
    WRFSBASE,
    WRGSBASE,
    RDPID,

    // ======================================================================
    // CLDEMOTE / MOVDIRI / MOVDIR64B / ENQCMD / PCONFIG / WAITPKG
    // ======================================================================
    CLDEMOTE,
    MOVDIRI,
    MOVDIR64B,
    ENQCMD,
    ENQCMDS,
    PCONFIG,
    UMWAIT,
    UMONITOR,
    TPAUSE,

    // ======================================================================
    // CET (Control-flow Enforcement Technology)
    // ======================================================================
    ENDBR64,
    ENDBR32,
    RDSSPD,
    RDSSPQ,
    INCSSPD,
    INCSSPQ,
    SETSSBSY,
    CLRSSBSY,
    WRSSD,
    WRSSQ,
    WRUSSD,
    WRUSSQ,

    // ======================================================================
    // UINTR (User Interrupts)
    // ======================================================================
    UIRET,
    SENDUPI,
    STUI,
    TESTUI,
    CLUI,
}

// ========================================================================
// Condition Codes
// ========================================================================

/// x86 condition codes used by Jcc, SETcc, CMOVcc, and FCMOVcc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionCode {
    /// Overflow (OF=1)
    O,
    /// No overflow (OF=0)
    NO,
    /// Below / Carry (CF=1)
    B,
    C,
    NAE,
    /// Above or equal / Not carry (CF=0)
    AE,
    NB,
    NC,
    /// Equal / Zero (ZF=1)
    E,
    Z,
    /// Not equal / Not zero (ZF=0)
    NE,
    NZ,
    /// Below or equal / Not above (CF=1 or ZF=1)
    BE,
    NA,
    /// Above (CF=0 and ZF=0)
    A,
    NBE,
    /// Sign (SF=1)
    S,
    /// Not sign (SF=0)
    NS,
    /// Parity / Parity even (PF=1)
    P,
    PE,
    /// Not parity / Parity odd (PF=0)
    NP,
    PO,
    /// Less (SF!=OF)
    L,
    NGE,
    /// Greater or equal (SF=OF)
    GE,
    NL,
    /// Less or equal (ZF=1 or SF!=OF)
    LE,
    NG,
    /// Greater (ZF=0 and SF=OF)
    G,
    NLE,
}

impl ConditionCode {
    /// Human-readable name of this condition.
    pub fn name(&self) -> &'static str {
        match self {
            ConditionCode::O => "O",
            ConditionCode::NO => "NO",
            ConditionCode::B | ConditionCode::C | ConditionCode::NAE => "B",
            ConditionCode::AE | ConditionCode::NB | ConditionCode::NC => "AE",
            ConditionCode::E | ConditionCode::Z => "E",
            ConditionCode::NE | ConditionCode::NZ => "NE",
            ConditionCode::BE | ConditionCode::NA => "BE",
            ConditionCode::A | ConditionCode::NBE => "A",
            ConditionCode::S => "S",
            ConditionCode::NS => "NS",
            ConditionCode::P | ConditionCode::PE => "P",
            ConditionCode::NP | ConditionCode::PO => "NP",
            ConditionCode::L | ConditionCode::NGE => "L",
            ConditionCode::GE | ConditionCode::NL => "GE",
            ConditionCode::LE | ConditionCode::NG => "LE",
            ConditionCode::G | ConditionCode::NLE => "G",
        }
    }
}

// ========================================================================
// Instruction Categories
// ========================================================================

/// Broad functional category of an x86 instruction.
/// Used to organise the instruction set and guide analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstructionCategory {
    /// Data movement: MOV, PUSH, POP, LEA, XCHG, etc.
    DataMovement,
    /// Binary arithmetic: ADD, SUB, IMUL, IDIV, INC, DEC, etc.
    Arithmetic,
    /// Logical and bitwise: AND, OR, XOR, NOT, SHL, SHR, ROL, ROR, etc.
    Logical,
    /// Control flow: JMP, Jcc, CALL, RET, LOOP, INT, IRET, etc.
    ControlFlow,
    /// Conditional set/move: SETcc, CMOVcc
    Conditional,
    /// String operations: MOVS, CMPS, SCAS, LODS, STOS, REP, etc.
    String,
    /// I/O: IN, OUT, INS, OUTS
    IO,
    /// Flag manipulation: STC, CLC, STI, CLI, LAHF, SAHF
    FlagControl,
    /// System: SYSCALL, HLT, CPUID, RDMSR, WRMSR, LGDT, MOV_CR, etc.
    System,
    /// x87 floating point: FADD, FMUL, FLD, FST, etc.
    X87,
    /// MMX SIMD: PADDB, PADDW, PXOR, etc.
    MMX,
    /// SSE / SSE2 SIMD: ADDPS, MULPD, MOVDQA, etc.
    SSE,
    /// SSE3 / SSSE3: HADDPS, PHADDW, PSHUFB, etc.
    SSE3,
    /// SSE4: PMULLD, PTEST, PCMPEQQ, etc.
    SSE4,
    /// AES-NI / SHA: AESENC, SHA1RNDS4, etc.
    Crypto,
    /// AVX / AVX2 / AVX-512: VADDPS, VPERMD, VEXP2PS, etc.
    AVX,
    /// FMA: VFMADD132PS, etc.
    FMA,
    /// Virtualization: VMXON, VMRUN, etc.
    Virtualization,
    /// Cache/TLB: INVLPG, CLFLUSH, PREFETCH, etc.
    Cache,
    /// Transactional memory: XBEGIN, XEND, etc.
    Transactional,
    /// Security extensions: ENCLS, ENDBR64, etc.
    Security,
    /// Miscellaneous / unknown
    Misc,
}

impl X86Mnemonic {
    /// Return the functional category for this mnemonic.
    pub fn category(&self) -> InstructionCategory {
        use InstructionCategory::*;
        use X86Mnemonic::*;
        match self {
            MOV | MOVSX | MOVZX | MOVSXD | XCHG | BSWAP | XADD | CMPXCHG | CMPXCHG8B
            | CMPXCHG16B | LEA => DataMovement,
            CMOVcc(_) => Conditional,

            PUSH | POP | PUSHA | POPA | PUSHF | POPF | PUSHFD | POPFD | PUSHFQ | POPFQ | ENTER
            | LEAVE => DataMovement,

            ADD | ADC | SUB | SBB | IMUL | MUL | IDIV | DIV | INC | DEC | NEG | CMP => Arithmetic,

            DAA | DAS | AAA | AAS | AAM | AAD => Arithmetic,
            AND | OR | XOR | NOT | TEST => Logical,
            SHL | SHR | SAL | SAR | ROL | ROR | RCL | RCR | SHLD | SHRD => Logical,
            BT | BTS | BTR | BTC | BSF | BSR | LZCNT | TZCNT | POPCNT => Logical,
            ANDN | BEXTR | BLSI | BLSMSK | BLSR => Logical,
            BZHI | MULX | PDEP | PEXT | RORX | SARX | SHLX | SHRX => Logical,

            JMP | Jcc(_) | CALL | RET | RETF | JECXZ | JRCXZ | LOOP | LOOPE | LOOPNE => ControlFlow,

            SETcc(_) => Conditional,
            MOVS | MOVSB | MOVSW | MOVSD | MOVSQ | CMPS | CMPSB | CMPSW | CMPSD | CMPSQ | SCAS
            | SCASB | SCASW | SCASD | SCASQ | LODS | LODSB | LODSW | LODSD | LODSQ | STOS
            | STOSB | STOSW | STOSD | STOSQ | INS | INSB | INSW | INSD | OUTS | OUTSB | OUTSW
            | OUTSD | REP | REPE | REPZ | REPNE | REPNZ => String,

            IN | OUT => IO,
            STC | CLC | CMC | STD | CLD | STI | CLI | LAHF | SAHF => FlagControl,
            LDS | LES | LFS | LGS | LSS => DataMovement,

            SYSCALL | SYSRET | SYSENTER | SYSEXIT | INT | INT3 | INTO | IRET | IRETD | IRETQ
            | HLT | PAUSE | RSM | UD2 => System,
            LGDT | SGDT | LIDT | SIDT | LLDT | SLDT | LTR | STR | LMSW | SMSW | CLTS | LAR
            | LSL | VERR | VERW => System,
            MOV_CR | MOV_DR => System,
            INVD | WBINVD | INVLPG | INVLPGA | INVPCID | CLFLUSH | CLFLUSHOPT | CLWB | PREFETCH
            | PREFETCHW | PREFETCH_NTA | PREFETCH_T0 | PREFETCH_T1 | PREFETCH_T2 => Cache,
            RDTSC | RDTSCP | RDPMC | RDMSR | WRMSR | CPUID | XGETBV | XSETBV | RDRAND | RDSEED => {
                System
            }
            NOP => Misc,
            UD0 | UD1 => Misc,

            PREFIX_LOCK | PREFIX_REP | PREFIX_REPNE | PREFIX_CS | PREFIX_DS | PREFIX_ES
            | PREFIX_FS | PREFIX_GS | PREFIX_SS | PREFIX_DATA16 | PREFIX_ADDR16 | PREFIX_REX
            | PREFIX_REX_W | PREFIX_REX_R | PREFIX_REX_X | PREFIX_REX_B => Misc,

            MOVD | MOVQ | PACKSSWB | PACKSSDW | PACKUSWB | PUNPCKLBW | PUNPCKHBW | PUNPCKLWD
            | PUNPCKHWD | PUNPCKLDQ | PUNPCKHDQ | PADDB | PADDW | PADDD | PADDSB | PADDSW
            | PADDUSB | PADDUSW | PSUBB | PSUBW | PSUBD | PSUBSB | PSUBSW | PSUBUSB | PSUBUSW
            | PMULLW | PMULHW | PMULLW_HIGH | PMULHUW | PMADDWD | PCMPEQB | PCMPEQW | PCMPEQD
            | PCMPGTB | PCMPGTW | PCMPGTD | PAND | PANDN | POR | PXOR | PSLLW | PSLLD | PSLLQ
            | PSRLW | PSRLD | PSRLQ | PSRAW | PSRAD | EMMS => MMX,

            MOVAPS | MOVUPS | MOVHPS | MOVLPS | MOVHLPS | MOVLHPS | MOVMSKPS | MOVSS | ADDPS
            | ADDSS | SUBPS | SUBSS | MULPS | MULSS | DIVPS | DIVSS | RCPPS | RCPSS | SQRTPS
            | SQRTSS | RSQRTPS | RSQRTSS | MAXPS | MAXSS | MINPS | MINSS | ANDPS | ANDNPS
            | ORPS | XORPS | CMPPS | CMPSS | SHUFPS | UNPCKHPS | UNPCKLPS | CVTPI2PS | CVTSI2SS
            | CVTPS2PI | CVTTPS2PI | CVTSS2SI | CVTTSS2SI | LDMXCSR | STMXCSR | PAVGB | PAVGW
            | PEXTRW | PINSRW | PMAXUB | PMAXSW | PMINUB | PMINSW | PMOVMSKB | PMULHUW_SSE
            | PSADBW | PSHUFW | MASKMOVQ | MOVNTQ | MOVNTPS | SFENCE | PREFETCH_NTA_SSE
            | PREFETCH_T0_SSE | PREFETCH_T1_SSE | PREFETCH_T2_SSE => SSE,

            MOVAPD | MOVUPD | MOVHPD | MOVLPD | MOVMSKPD | MOVSD_SCALAR | ADDPD | ADDSD | SUBPD
            | SUBSD | MULPD | MULSD | DIVPD | DIVSD | SQRTPD | SQRTSD | MAXPD | MAXSD | MINPD
            | MINSD | ANDPD | ANDNPD | ORPD | XORPD | CMPPD | CMPSD_SCALAR | SHUFPD | UNPCKHPD
            | UNPCKLPD | CVTDQ2PD | CVTDQ2PS | CVTPD2DQ | CVTPD2PI | CVTPD2PS | CVTPI2PD
            | CVTPS2DQ | CVTPS2PD | CVTSD2SI | CVTSD2SS | CVTSI2SD | CVTSS2SD | CVTTPD2DQ
            | CVTTPD2PI | CVTTPS2DQ | CVTTSD2SI | MOVDQA | MOVDQU | MOVQ2DQ | MOVDQ2Q | PMULUDQ
            | PADDQ | PSUBQ | PSHUFLW | PSHUFHW | PSHUFD | PSLLDQ | PSRLDQ | PUNPCKLQDQ
            | PUNPCKHQDQ | MOVNTDQ | MOVNTI | MOVNTPD | MASKMOVDQU | CLFLUSH_SSE2 | LFENCE
            | MFENCE => SSE,

            FISTTP | ADDSUBPS | ADDSUBPD | HADDPS | HADDPD | HSUBPS | HSUBPD | MOVSHDUP
            | MOVSLDUP | MOVDDUP | MONITOR | MWAIT | LDDQU => SSE3,

            PHADDW | PHADDD | PHADDSW | PHSUBW | PHSUBD | PHSUBSW | PABSB | PABSW | PABSD
            | PMADDUBSW | PMULHRSW | PSHUFB | PSIGNB | PSIGNW | PSIGND | PALIGNR => SSE3,

            BLENDPD | BLENDPS | BLENDVPD | BLENDVPS | DPPD | DPPS | EXTRACTPS | INSERTPS
            | MOVNTDQA | MPSADBW | PACKUSDW | PBLENDVB | PBLENDW | PCMPEQQ | PEXTRB | PEXTRD
            | PEXTRQ | PHMINPOSUW | PINSRB | PINSRD | PINSRQ | PMAXSB | PMAXSD | PMAXUD
            | PMAXUW | PMINSB | PMINSD | PMINUD | PMINUW | PMOVSXBW | PMOVSXBD | PMOVSXBQ
            | PMOVSXWD | PMOVSXWQ | PMOVSXDQ | PMOVZXBW | PMOVZXBD | PMOVZXBQ | PMOVZXWD
            | PMOVZXWQ | PMOVZXDQ | PMULDQ | PMULLD | PTEST | ROUNDPS | ROUNDPD | ROUNDSS
            | ROUNDSD => SSE4,

            CRC32 | PCMPESTRI | PCMPESTRM | PCMPISTRI | PCMPISTRM | PCMPGTQ | POPCNT_SSE42 => SSE4,

            AESDEC | AESDECLAST | AESENC | AESENCLAST | AESIMC | AESKEYGENASSIST | PCLMULQDQ => {
                Crypto
            }

            SHA1RNDS4 | SHA1NEXTE | SHA1MSG1 | SHA1MSG2 | SHA256RNDS2 | SHA256MSG1 | SHA256MSG2 => {
                Crypto
            }

            // AVX
            VADDPS | VADDSS | VADDPD | VADDSD | VSUBPS | VSUBSS | VSUBPD | VSUBSD | VMULPS
            | VMULSS | VMULPD | VMULSD | VDIVPS | VDIVSS | VDIVPD | VDIVSD | VSQRTPS | VSQRTSS
            | VSQRTPD | VSQRTSD | VMAXPS | VMAXSS | VMAXPD | VMAXSD | VMINPS | VMINSS | VMINPD
            | VMINSD | VANDPS | VANDNPS | VORPS | VXORPS | VANDPD | VANDNPD | VORPD | VXORPD
            | VCMPPS | VCMPSS | VCMPPD | VCMPSD | VSHUFPS | VSHUFPD | VUNPCKHPS | VUNPCKLPS
            | VUNPCKHPD | VUNPCKLPD | VMOVAPS | VMOVUPS | VMOVAPD | VMOVUPD | VMOVSS | VMOVSD
            | VMOVHLPS | VMOVLHPS | VMOVHPS | VMOVLPS | VMOVHPD | VMOVLPD | VMOVMSKPS
            | VMOVMSKPD | VMOVDQA | VMOVDQU | VMOVNTDQ | VMOVNTPS | VMOVNTPD | VCVTSI2SS
            | VCVTSI2SD | VCVTSS2SI | VCVTSD2SI | VCVTTSS2SI | VCVTTSD2SI | VCVTDQ2PS
            | VCVTPS2DQ | VCVTTPS2DQ | VCVTDQ2PD | VCVTPD2DQ | VCVTTPD2DQ | VCVTPS2PD
            | VCVTPD2PS | VCVTSS2SD | VCVTSD2SS | VBROADCASTSS | VBROADCASTSD | VBROADCASTF128
            | VINSERTF128 | VEXTRACTF128 | VMASKMOVPS | VMASKMOVPD | VPERMILPS | VPERMILPD
            | VPERM2F128 | VTESTPS | VTESTPD | VZEROUPPER | VZEROALL | VLDMXCSR | VSTMXCSR => AVX,

            VFMADD132PS | VFMADD132PD | VFMADD132SS | VFMADD132SD | VFMADD213PS | VFMADD213PD
            | VFMADD213SS | VFMADD213SD | VFMADD231PS | VFMADD231PD | VFMADD231SS | VFMADD231SD
            | VFMSUB132PS | VFMSUB132PD | VFMSUB132SS | VFMSUB132SD | VFMSUB213PS | VFMSUB213PD
            | VFMSUB213SS | VFMSUB213SD | VFMSUB231PS | VFMSUB231PD | VFMSUB231SS | VFMSUB231SD
            | VFNMADD132PS | VFNMADD132PD | VFNMADD132SS | VFNMADD132SD | VFNMADD213PS
            | VFNMADD213PD | VFNMADD213SS | VFNMADD213SD | VFNMADD231PS | VFNMADD231PD
            | VFNMADD231SS | VFNMADD231SD | VFNMSUB132PS | VFNMSUB132PD | VFNMSUB132SS
            | VFNMSUB132SD | VFNMSUB213PS | VFNMSUB213PD | VFNMSUB213SS | VFNMSUB213SD
            | VFNMSUB231PS | VFNMSUB231PD | VFNMSUB231SS | VFNMSUB231SD => FMA,

            VPBROADCASTB | VPBROADCASTW | VPBROADCASTD | VPBROADCASTQ | VINSERTI128
            | VEXTRACTI128 | VPERM2I128 | VPERMD | VPERMQ | VPERMPS | VPERMPD | VPSLLVD
            | VPSLLVQ | VPSRLVD | VPSRLVQ | VPSRAVD | VPMASKMOVD | VPMASKMOVQ | VGATHERDPS
            | VGATHERDPD | VGATHERQPS | VGATHERQPD | VPGATHERDD | VPGATHERDQ | VPGATHERQD
            | VPGATHERQQ | VPMULLD | VPMULLW | VPMULHW | VPMULHUW | VPMULHRSW | VPMULUDQ
            | VPMULDQ | VPADDUSB | VPADDUSW | VPSUBUSB | VPSUBUSW | VPADDSB | VPADDSW | VPSUBSB
            | VPSUBSW | VPHADDW | VPHADDD | VPHADDSW | VPHSUBW | VPHSUBD | VPHSUBSW | VBLENDVPS
            | VBLENDVPD | VPBLENDVB => AVX,

            KAND | KANDN | KNOT | KOR | KXNOR | KXOR | KADD | KTEST | KSHIFTL | KSHIFTR
            | KUNPCKBW | KUNPCKWD | KUNPCKDQ | KMOV | VPLZCNTD | VPLZCNTQ | VPCONFLICTD
            | VPCONFLICTQ | VPBROADCASTM | VPBROADCASTMW | VEXP2PS | VEXP2PD | VRCP28PS
            | VRCP28PD | VRCP28SS | VRCP28SD | VRSQRT28PS | VRSQRT28PD | VRSQRT28SS
            | VRSQRT28SD | VGATHERPF0DPS | VGATHERPF0DPD | VGATHERPF0QPS | VGATHERPF0QPD
            | VGATHERPF1DPS | VGATHERPF1DPD | VGATHERPF1QPS | VGATHERPF1QPD | VSCATTERPF0DPS
            | VSCATTERPF0DPD | VSCATTERPF0QPS | VSCATTERPF0QPD | VSCATTERPF1DPS
            | VSCATTERPF1DPD | VSCATTERPF1QPS | VSCATTERPF1QPD | VPCMPB | VPCMPUB | VPCMPW
            | VPCMPUW | VPMOVM2B | VPMOVM2W | VPMOVB2M | VPMOVW2M | VPMOVWB | VPMOVSWB
            | VPMOVUSWB | VPADDB_Z | VPADDW_Z | VPSUBB_Z | VPSUBW_Z | VPMULLW_Z | VPBLENDMB
            | VPBLENDMW | VPTESTNMB | VPTESTNMW | VDBPSADBW | VANDPS_Z | VANDNPS_Z | VORPS_Z
            | VXORPS_Z | VANDPD_Z | VANDNPD_Z | VORPD_Z | VXORPD_Z | VFPCLASSPS | VFPCLASSPD
            | VFPCLASSSS | VFPCLASSSD | VRANGEPD | VRANGEPS | VRANGESD | VRANGESS | VREDUCEPD
            | VREDUCEPS | VREDUCESD | VREDUCESS | VCVTUDQ2PD | VCVTUDQ2PS | VCVTPS2UDQ
            | VCVTPD2UDQ | VCVTTPS2UDQ | VCVTTPD2UDQ | VCVTQQ2PD | VCVTQQ2PS | VCVTPD2QQ
            | VCVTPS2QQ | VCVTTPD2QQ | VCVTTPS2QQ | VCVTUQQ2PD | VCVTUQQ2PS | VCVTPD2UQQ
            | VCVTPS2UQQ | VCVTTPD2UQQ | VCVTTPS2UQQ | VPERMB | VPERMI2B | VPERMT2B
            | VPMULTISHIFTQB | VPERMW | VPMADD52LUQ | VPMADD52HUQ | VPSHRDV | VPSHRDQ | VPSHLDV
            | VPSHLDQ | VPCOMPRESSB | VPCOMPRESSW | VPEXPANDB | VPEXPANDW | VPDPBUSD
            | VPDPBUSDS | VPDPWSSD | VPDPWSSDS | VPOPCNTB | VPOPCNTW | VPOPCNTD | VPOPCNTQ
            | VPSHUFBITQMB | VCVTNE2PS2BF16 | VCVTNEPS2BF16 | VDPBF16PS | VP2INTERSECTD
            | VP2INTERSECTQ | VADDPH | VADDSH | VSUBPH | VSUBSH | VMULPH | VMULSH | VDIVPH
            | VDIVSH | VFMADD132PH | VFMADD213PH | VFMADD231PH | VFMSUB132PH | VFMSUB213PH
            | VFMSUB231PH | VCVTPH2PD | VCVTPH2PS | VCVTPD2PH | VCVTPS2PH | VCVTSH2SI
            | VCVTSI2SH | VCVTTSH2SI => AVX,

            FADD | FADDP | FIADD | FSUB | FSUBP | FISUB | FSUBR | FSUBRP | FISUBR | FMUL
            | FMULP | FIMUL | FDIV | FDIVP | FIDIV | FDIVR | FDIVRP | FIDIVR | FABS | FCHS
            | FRNDINT | FSCALE | FSQRT | FXTRACT | FPREM | FPREM1 | FCOM | FCOMP | FCOMPP
            | FICOM | FICOMP | FUCOM | FUCOMP | FUCOMPP | FTST | FXAM | FLD | FLD1 | FLDZ
            | FLDPI | FLDL2E | FLDL2T | FLDLG2 | FLDLN2 | FST | FSTP | FIST | FISTP
            | FBLD | FBSTP | FXCH | FCMOVcc(_) | FILD | FNOP | FNCLEX | FNINIT | FNSAVE
            | FNRSTOR | FNSTCW | FNSTENV | FNSTSW | FFREE | FDECSTP | FINCSTP | FPTAN | FPATAN
            | FYL2X | FYL2XP1 | F2XM1 | FCOS | FSIN | FSINCOS => X87,

            VMXON | VMXOFF | VMCLEAR | VMPTRLD | VMPTRST | VMREAD | VMWRITE | VMLAUNCH
            | VMRESUME | VMX_VMCALL | INVEPT | INVVPID | VMFUNC | VMRUN | VMLOAD | VMSAVE
            | STGI | CLGI | SKINIT | INVLPGA_SVM => Virtualization,

            ENCLS | ENCLU | ENCLV | GETSEC => Security,
            XBEGIN | XEND | XABORT | XTEST => Transactional,
            BNDMK | BNDCL | BNDCU | BNDCN | BNDMOV | BNDLDX | BNDSTX => Security,
            RDFSBASE | RDGSBASE | WRFSBASE | WRGSBASE | RDPID => System,
            CLDEMOTE | MOVDIRI | MOVDIR64B | ENQCMD | ENQCMDS | PCONFIG | UMWAIT | UMONITOR
            | TPAUSE => System,
            ENDBR64 | ENDBR32 | RDSSPD | RDSSPQ | INCSSPD | INCSSPQ | SETSSBSY | CLRSSBSY
            | WRSSD | WRSSQ | WRUSSD | WRUSSQ => Security,
            UIRET | SENDUPI | STUI | TESTUI | CLUI => System,
        }
    }

    /// Returns the human-readable string for this mnemonic.
    pub fn as_str(&self) -> String {
        format!("{:?}", self)
            .replace('(', "_")
            .replace(')', "")
            .replace("cc_", "")
    }
}

// ========================================================================
// Encoding Helpers: ModR/M, SIB, REX, VEX, EVEX
// ========================================================================

/// ModR/M byte structure.
///
/// Bits: `mod(2) : reg/opcode(3) : rm(3)`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModRM {
    pub raw: u8,
}

impl ModRM {
    pub fn new(raw: u8) -> Self {
        ModRM { raw }
    }

    /// The `mod` field (bits 7-6).
    pub fn mod_bits(&self) -> u8 {
        (self.raw >> 6) & 0b11
    }

    /// The `reg` or opcode extension field (bits 5-3).
    pub fn reg(&self) -> u8 {
        (self.raw >> 3) & 0b111
    }

    /// The `r/m` field (bits 2-0).
    pub fn rm(&self) -> u8 {
        self.raw & 0b111
    }

    /// True if this ModR/M encodes a register operand (mod == 0b11).
    pub fn is_register(&self) -> bool {
        self.mod_bits() == 0b11
    }

    /// True if a SIB byte follows this ModR/M (rm == 0b100 and mod != 0b11).
    pub fn has_sib(&self) -> bool {
        self.rm() == 0b100 && self.mod_bits() != 0b11
    }

    /// True if a displacement follows:
    /// - mod == 0b01: 8-bit displacement
    /// - mod == 0b10: 32-bit displacement
    /// - mod == 0b00 and rm == 0b101: 32-bit displacement (RIP-relative)
    pub fn displacement_size(&self) -> u8 {
        match self.mod_bits() {
            0b00 if self.rm() == 0b101 => 4,
            0b01 => 1,
            0b10 => 4,
            _ => 0,
        }
    }
}

impl From<u8> for ModRM {
    fn from(raw: u8) -> Self {
        ModRM::new(raw)
    }
}

/// SIB (Scale-Index-Base) byte structure.
///
/// Bits: `scale(2) : index(3) : base(3)`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SIB {
    pub raw: u8,
}

impl SIB {
    pub fn new(raw: u8) -> Self {
        SIB { raw }
    }

    /// The `scale` field (bits 7-6): 0, 1, 2, or 3 (multiplier = 1, 2, 4, 8).
    pub fn scale(&self) -> u8 {
        (self.raw >> 6) & 0b11
    }

    /// The `index` field (bits 5-3).
    pub fn index(&self) -> u8 {
        (self.raw >> 3) & 0b111
    }

    /// The `base` field (bits 2-0).
    pub fn base(&self) -> u8 {
        self.raw & 0b111
    }

    /// True if the index register is *not* used (index == 0b100).
    pub fn no_index(&self) -> bool {
        self.index() == 0b100
    }

    /// The scale multiplier (1, 2, 4, or 8).
    pub fn scale_multiplier(&self) -> u8 {
        1u8 << self.scale()
    }
}

impl From<u8> for SIB {
    fn from(raw: u8) -> Self {
        SIB::new(raw)
    }
}

/// REX prefix byte (used in 64-bit mode for register extension and operand size).
///
/// Bits: `0100 : W : R : X : B`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct REX {
    pub raw: u8,
}

impl REX {
    /// Create from raw byte (only lower nibble matters for fields).
    pub fn new(raw: u8) -> Self {
        REX { raw }
    }

    /// Return true if this byte is a valid REX prefix (0x40-0x4F).
    pub fn is_rex(byte: u8) -> bool {
        (byte & 0xF0) == 0x40
    }

    /// W bit: 64-bit operand size when set.
    pub fn w(&self) -> bool {
        (self.raw & 0b1000) != 0
    }

    /// R bit: extends ModR/M reg field.
    pub fn r(&self) -> bool {
        (self.raw & 0b0100) != 0
    }

    /// X bit: extends SIB index field.
    pub fn x(&self) -> bool {
        (self.raw & 0b0010) != 0
    }

    /// B bit: extends ModR/M r/m field, SIB base, or opcode reg field.
    pub fn b(&self) -> bool {
        (self.raw & 0b0001) != 0
    }
}

impl From<u8> for REX {
    fn from(raw: u8) -> Self {
        REX::new(raw)
    }
}

/// VEX prefix (2-byte or 3-byte).
///
/// 2-byte: `0xC5 RvvvvLpp`
/// 3-byte: `0xC4 RXBmmmmm WvvvvLpp`
///
/// Used for AVX/AVX2 instructions; replaces REX + opcode prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VEX {
    /// True for 3-byte form (0xC4), false for 2-byte form (0xC5).
    pub three_byte: bool,
    /// REX.R complement (~R)
    pub r: bool,
    /// REX.X complement (~X)
    pub x: bool,
    /// REX.B complement (~B)
    pub b: bool,
    /// `mmmmm` field: implied leading opcode bytes (0x0F, 0x0F38, 0x0F3A).
    pub map_select: u8,
    /// W bit: 64-bit operand size override (only in 3-byte form).
    pub w: bool,
    /// `vvvv` complement: additional source register specifier.
    pub vvvv: u8,
    /// L bit: vector length (0=128-bit, 1=256-bit).
    pub l: bool,
    /// `pp` field: implied mandatory prefix (None=0, 0x66=1, 0xF3=2, 0xF2=3).
    pub pp: u8,
}

/// EVEX prefix (4-byte) for AVX-512.
///
/// Format: `0x62 P0 P1 P2`
/// - P0: `0 1 1 0 R' R X B R' 0 0 m m m m m` (R', X, B, R', mmmmm)
/// - P1: `1 W v v v v 1 p p` (W, vvvv, pp)
/// - P2: `z L' L b V' a a a` (z, L'L, b, V', aaa)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EVEX {
    /// REX.R' complement
    pub r_prime: bool,
    /// REX.X complement
    pub x: bool,
    /// REX.B complement
    pub b: bool,
    /// REX.R complement
    pub r: bool,
    /// R' bit (P0 bit 4) — extends R for 32-register encoding
    pub r2: bool,
    /// `mmmmm` field: opcode map selection (0x0F, 0x0F38, 0x0F3A).
    pub map_select: u8,
    /// W bit: 64-bit operand size override.
    pub w: bool,
    /// `vvvv` complement: additional source register.
    pub vvvv: u8,
    /// `pp` field: implied mandatory prefix.
    pub pp: u8,
    /// Zeroing/Merging: 1 = merge with destination, 0 = zero upper bits.
    pub z: bool,
    /// Vector length: 0=128, 1=256, 2=512 (L'L combined).
    pub vector_length: u8,
    /// Broadcast/rounding control (b-bit in EVEX P2).
    pub broadcast_rounding: bool,
    /// V' bit: extends vvvv for 32-register encoding.
    pub v_prime: bool,
    /// `aaa` field: opmask register specifier.
    pub aaa: u8,
}

// ========================================================================
// Addressing Mode
// ========================================================================

/// An x86 instruction operand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    /// No operand.
    None,
    /// Register: name (e.g., "RAX", "XMM0").
    Reg(String),
    /// Immediate: signed or unsigned value.
    Imm(i64),
    /// Memory reference.
    Mem(Box<MemoryOperand>),
    /// Relative offset (for branches).
    RelOffset(i64),
    /// Absolute address.
    AbsAddr(u64),
}

/// A memory operand with full x86 addressing capabilities.
///
/// Models: `segment:[base + index * scale + displacement]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryOperand {
    /// Segment override register name, or None for default.
    pub segment: Option<String>,
    /// Base register name (e.g., "RAX", "RBP").
    pub base: Option<String>,
    /// Index register name (e.g., "RSI").
    pub index: Option<String>,
    /// Scale factor (1, 2, 4, or 8).
    pub scale: u8,
    /// Signed displacement.
    pub displacement: i64,
    /// Size of the memory operand in bytes.
    pub size: u8,
}

impl MemoryOperand {
    /// Create a simple register-indirect operand (e.g., `[RAX]`).
    pub fn indirect(base: &str, size: u8) -> Self {
        MemoryOperand {
            segment: None,
            base: Some(base.to_string()),
            index: None,
            scale: 1,
            displacement: 0,
            size,
        }
    }

    /// Create a base + displacement operand (e.g., `[RBP-8]`).
    pub fn base_disp(base: &str, displacement: i64, size: u8) -> Self {
        MemoryOperand {
            segment: None,
            base: Some(base.to_string()),
            index: None,
            scale: 1,
            displacement,
            size,
        }
    }

    /// Create a base + index * scale operand (e.g., `[RAX+RSI*4]`).
    pub fn base_index_scale(base: &str, index: &str, scale: u8, size: u8) -> Self {
        MemoryOperand {
            segment: None,
            base: Some(base.to_string()),
            index: Some(index.to_string()),
            scale,
            displacement: 0,
            size,
        }
    }

    /// Create the full `[segment:base + index * scale + displacement]` form.
    pub fn full(
        segment: Option<&str>,
        base: Option<&str>,
        index: Option<&str>,
        scale: u8,
        displacement: i64,
        size: u8,
    ) -> Self {
        MemoryOperand {
            segment: segment.map(|s| s.to_string()),
            base: base.map(|s| s.to_string()),
            index: index.map(|s| s.to_string()),
            scale,
            displacement,
            size,
        }
    }

    /// Returns a human-readable representation of this memory operand.
    pub fn display(&self) -> String {
        let mut s = String::new();
        if let Some(ref seg) = self.segment {
            s.push_str(seg);
            s.push(':');
        }
        s.push('[');
        let mut first = true;
        if let Some(ref base) = self.base {
            s.push_str(base);
            first = false;
        }
        if let Some(ref index) = self.index {
            if !first {
                s.push('+');
            }
            s.push_str(index);
            if self.scale != 1 {
                s.push('*');
                s.push_str(&self.scale.to_string());
            }
            first = false;
        }
        if self.displacement != 0 || first {
            if self.displacement >= 0 && !first {
                s.push('+');
            }
            s.push_str(&format!("{:#x}", self.displacement));
        }
        s.push(']');
        s
    }
}

// ========================================================================
// Decoded Instruction
// ========================================================================

/// A fully decoded x86 instruction.
#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    /// Instruction mnemonic.
    pub mnemonic: X86Mnemonic,
    /// Operands (0 to 4 typically).
    pub operands: Vec<Operand>,
    /// Instruction address in the binary.
    pub address: u64,
    /// Total length of the instruction in bytes (including prefixes).
    pub length: u8,
    /// Operand-size attribute: 16, 32, or 64 bits.
    pub operand_size: u8,
    /// Address-size attribute: 16, 32, or 64 bits.
    pub address_size: u8,
    /// Prefixes present (REX, segment override, lock, rep, operand-size, address-size).
    pub prefixes: Vec<PrefixInfo>,
    /// Whether this is a branch/jump/call/return.
    pub is_branch: bool,
    /// If a branch, the target address (if statically known).
    pub branch_target: Option<u64>,
    /// Whether this instruction terminates a basic block.
    pub is_terminator: bool,
    /// The raw bytes that encode this instruction.
    pub raw_bytes: Vec<u8>,
}

/// Information about a prefix byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixInfo {
    Lock,
    Rep,
    Repne,
    SegmentOverride(SegmentRegister),
    OperandSizeOverride,
    AddressSizeOverride,
    Rex(REX),
    Vex { has_w: bool, has_l: bool },
    Evex,
}

/// Segment register identifiers for segment-override prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentRegister {
    ES,
    CS,
    SS,
    DS,
    FS,
    GS,
}

impl DecodedInstruction {
    /// Returns the mnemonic string for display.
    pub fn mnemonic_str(&self) -> String {
        match self.mnemonic {
            X86Mnemonic::Jcc(cc) => format!("J{}", cc.name()),
            X86Mnemonic::SETcc(cc) => format!("SET{}", cc.name()),
            X86Mnemonic::CMOVcc(cc) => format!("CMOV{}", cc.name()),
            X86Mnemonic::FCMOVcc(cc) => format!("FCMOV{}", cc.name()),
            ref other => format!("{:?}", other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modrm_fields() {
        // mod=11, reg=000, rm=000  => 0b11000000 = 0xC0
        let m = ModRM::new(0xC0);
        assert_eq!(m.mod_bits(), 3);
        assert_eq!(m.reg(), 0);
        assert_eq!(m.rm(), 0);
        assert!(m.is_register());

        // mod=00, reg=100, rm=100 => [esp] with SIB, no displacement
        let m = ModRM::new(0x24);
        assert_eq!(m.mod_bits(), 0);
        assert_eq!(m.reg(), 4);
        assert_eq!(m.rm(), 4);
        assert!(m.has_sib());
        assert_eq!(m.displacement_size(), 0);

        // mod=01, reg=010, rm=101 => [ebp]+disp8
        let m = ModRM::new(0x55);
        assert_eq!(m.mod_bits(), 1);
        assert_eq!(m.displacement_size(), 1);
    }

    #[test]
    fn test_sib_fields() {
        // scale=10 (*4), index=100 (none), base=101 (ebp)
        // 0xA5 = 0b10_100_101
        let s = SIB::new(0xA5);
        assert_eq!(s.scale(), 2);
        assert_eq!(s.scale_multiplier(), 4);
        assert_eq!(s.index(), 4);
        assert!(s.no_index());
        assert_eq!(s.base(), 5);
    }

    #[test]
    fn test_rex_flags() {
        let rex = REX::new(0x48); // REX.W
        assert!(rex.w());
        assert!(!rex.r());
        assert!(!rex.x());
        assert!(!rex.b());

        assert!(REX::is_rex(0x48));
        assert!(REX::is_rex(0x4F));
        assert!(!REX::is_rex(0x50));
    }

    #[test]
    fn test_memory_operand_display() {
        let m = MemoryOperand {
            segment: Some("FS".into()),
            base: Some("RAX".into()),
            index: Some("RSI".into()),
            scale: 4,
            displacement: 0x10,
            size: 8,
        };
        assert_eq!(m.display(), "FS:[RAX+RSI*4+0x10]");
    }

    #[test]
    fn test_mnemonic_category() {
        assert_eq!(
            X86Mnemonic::MOV.category(),
            InstructionCategory::DataMovement
        );
        assert_eq!(X86Mnemonic::ADD.category(), InstructionCategory::Arithmetic);
        assert_eq!(
            X86Mnemonic::JMP.category(),
            InstructionCategory::ControlFlow
        );
        assert_eq!(X86Mnemonic::FADD.category(), InstructionCategory::X87);
        assert_eq!(X86Mnemonic::VADDPS.category(), InstructionCategory::AVX);
        assert_eq!(X86Mnemonic::SYSCALL.category(), InstructionCategory::System);
    }
}
