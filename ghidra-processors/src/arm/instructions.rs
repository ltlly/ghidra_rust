//! ARM32 Instruction Mnemonics, Condition Codes, and Addressing Modes
//!
//! Covers the full ARM, Thumb, Thumb-2, VFP, NEON, and Security instruction
//! sets. Organized by functional category.

use ghidra_core::listing::InstructionMnemonic;

// ============================================================================
// Condition Codes
// ============================================================================

/// ARM condition codes (4-bit field in instruction encoding).
///
/// Every ARM instruction is conditionally executed based on these codes.
/// The condition is encoded in the top 4 bits (bits 31-28) of the instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionCode {
    /// Equal (Z=1)
    EQ,
    /// Not equal (Z=0)
    NE,
    /// Carry set / unsigned higher or same (C=1)
    CS,
    /// Carry clear / unsigned lower (C=0)
    CC,
    /// Negative / minus (N=1)
    MI,
    /// Positive or zero / plus (N=0)
    PL,
    /// Overflow set (V=1)
    VS,
    /// Overflow clear (V=0)
    VC,
    /// Unsigned higher (C=1 AND Z=0)
    HI,
    /// Unsigned lower or same (C=0 OR Z=1)
    LS,
    /// Signed greater than or equal (N=V)
    GE,
    /// Signed less than (N!=V)
    LT,
    /// Signed greater than (Z=0 AND N=V)
    GT,
    /// Signed less than or equal (Z=1 OR N!=V)
    LE,
    /// Always (unconditional)
    AL,
    /// Always, with special semantics for some encodings (e.g., NV in ARMv5 and earlier)
    NV,
}

impl ConditionCode {
    /// The 2-letter suffix used in assembly syntax.
    pub fn suffix(&self) -> &'static str {
        match self {
            ConditionCode::EQ => "EQ",
            ConditionCode::NE => "NE",
            ConditionCode::CS => "CS",
            ConditionCode::CC => "CC",
            ConditionCode::MI => "MI",
            ConditionCode::PL => "PL",
            ConditionCode::VS => "VS",
            ConditionCode::VC => "VC",
            ConditionCode::HI => "HI",
            ConditionCode::LS => "LS",
            ConditionCode::GE => "GE",
            ConditionCode::LT => "LT",
            ConditionCode::GT => "GT",
            ConditionCode::LE => "LE",
            ConditionCode::AL => "AL",
            ConditionCode::NV => "NV",
        }
    }

    /// The 4-bit encoding value for this condition.
    pub fn encoding(&self) -> u8 {
        match self {
            ConditionCode::EQ => 0b0000,
            ConditionCode::NE => 0b0001,
            ConditionCode::CS => 0b0010,
            ConditionCode::CC => 0b0011,
            ConditionCode::MI => 0b0100,
            ConditionCode::PL => 0b0101,
            ConditionCode::VS => 0b0110,
            ConditionCode::VC => 0b0111,
            ConditionCode::HI => 0b1000,
            ConditionCode::LS => 0b1001,
            ConditionCode::GE => 0b1010,
            ConditionCode::LT => 0b1011,
            ConditionCode::GT => 0b1100,
            ConditionCode::LE => 0b1101,
            ConditionCode::AL => 0b1110,
            ConditionCode::NV => 0b1111,
        }
    }

    /// Alternative `HS` suffix (same as CS).
    pub fn alt_suffix(&self) -> Option<&'static str> {
        match self {
            ConditionCode::CS => Some("HS"),
            ConditionCode::CC => Some("LO"),
            _ => None,
        }
    }
}

impl std::fmt::Display for ConditionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.suffix())
    }
}

// ============================================================================
// Addressing Modes
// ============================================================================

/// ARM addressing mode categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressingMode {
    /// Register direct: Rn
    RegisterDirect,
    /// Immediate: #imm
    Immediate,
    /// Register indirect: [Rn]
    RegisterIndirect,
    /// Pre-indexed: [Rn, #offset]!
    PreIndexed,
    /// Post-indexed: [Rn], #offset
    PostIndexed,
    /// Register offset: [Rn, +/-Rm]
    RegisterOffset,
    /// Scaled register offset: [Rn, +/-Rm, shift #n]
    ScaledRegisterOffset,
    /// PC-relative: [PC, #offset]
    PcRelative,
    /// SP-relative: [SP, #offset]
    SpRelative,
    /// Multiple register: {Rlist} (for LDM/STM)
    RegisterList,
    /// Coprocessor: {coprocessor}
    Coprocessor,
}

impl AddressingMode {
    pub fn name(&self) -> &'static str {
        match self {
            AddressingMode::RegisterDirect => "RegisterDirect",
            AddressingMode::Immediate => "Immediate",
            AddressingMode::RegisterIndirect => "RegisterIndirect",
            AddressingMode::PreIndexed => "PreIndexed",
            AddressingMode::PostIndexed => "PostIndexed",
            AddressingMode::RegisterOffset => "RegisterOffset",
            AddressingMode::ScaledRegisterOffset => "ScaledRegisterOffset",
            AddressingMode::PcRelative => "PcRelative",
            AddressingMode::SpRelative => "SpRelative",
            AddressingMode::RegisterList => "RegisterList",
            AddressingMode::Coprocessor => "Coprocessor",
        }
    }
}

// ============================================================================
// Shift Types
// ============================================================================

/// Barrel shifter operation types used in data-processing instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShiftType {
    /// Logical shift left
    LSL,
    /// Logical shift right
    LSR,
    /// Arithmetic shift right
    ASR,
    /// Rotate right
    ROR,
    /// Rotate right with extend (RRX, 1-bit ROR with C flag)
    RRX,
}

impl ShiftType {
    pub fn suffix(&self) -> &'static str {
        match self {
            ShiftType::LSL => "LSL",
            ShiftType::LSR => "LSR",
            ShiftType::ASR => "ASR",
            ShiftType::ROR => "ROR",
            ShiftType::RRX => "RRX",
        }
    }
}

// ============================================================================
// ARM Instruction Mnemonic
// ============================================================================

/// Complete ARM32 instruction mnemonic enumeration.
///
/// Covers the full ARM, Thumb, Thumb-2, VFP, NEON, and Security instruction
/// sets. Organized by functional category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArmMnemonic {
    // ======================================================================
    // Data Processing (Register)
    // ======================================================================
    AND,
    EOR,
    SUB,
    RSB,
    ADD,
    ADC,
    SBC,
    RSC,
    TST,
    TEQ,
    CMP,
    CMN,
    ORR,
    MOV,
    BIC,
    MVN,

    // ======================================================================
    // Data Processing (Immediate)
    // ======================================================================
    AND_IMM,
    EOR_IMM,
    SUB_IMM,
    RSB_IMM,
    ADD_IMM,
    ADC_IMM,
    SBC_IMM,
    RSC_IMM,
    TST_IMM,
    TEQ_IMM,
    CMP_IMM,
    CMN_IMM,
    ORR_IMM,
    MOV_IMM,
    BIC_IMM,
    MVN_IMM,

    // ======================================================================
    // Multiply and Multiply-Accumulate
    // ======================================================================
    MUL,
    MLA,
    UMULL,
    UMLAL,
    SMULL,
    SMLAL,
    UMAAL,
    MLS,
    SMMUL,
    SMMLA,
    SMMLS,
    SMULBB,
    SMULBT,
    SMULTB,
    SMULTT,
    SMLABB,
    SMLABT,
    SMLATB,
    SMLATT,
    SMLALBB,
    SMLALBT,
    SMLALTB,
    SMLALTT,
    SMULWB,
    SMULWT,
    SMLAWB,
    SMLAWT,
    USAD8,
    USADA8,
    SDIV,
    UDIV,

    // ======================================================================
    // Branch Instructions
    // ======================================================================
    B,
    BL,
    BX,
    BLX,
    BXJ,

    // ======================================================================
    // Load/Store (Word, Byte, Halfword)
    // ======================================================================
    LDR,
    LDRB,
    LDRH,
    LDRSB,
    LDRSH,
    LDRD,
    STR,
    STRB,
    STRH,
    STRD,
    LDRT,
    LDRBT,
    STRT,
    STRBT,

    // ======================================================================
    // Load/Store Multiple
    // ======================================================================
    LDM,
    STM,
    LDMDA,
    STMDA,
    LDMDB,
    STMDB,
    LDMIB,
    STMIB,
    LDMFD,
    LDMFA,
    LDMED,
    LDMFA_FD,
    STMFD,
    STMFA,
    STMED,
    STMEA,
    PUSH,
    POP,

    // ======================================================================
    // Status Register Access
    // ======================================================================
    MRS,
    MSR,
    MSR_IMM,
    CPS,
    SETEND,

    // ======================================================================
    // Exception / System
    // ======================================================================
    SWI,
    SVC,
    SMC,
    HVC,
    BKPT,
    UDF,
    RFE,
    SRS,
    ERET,
    WFI,
    WFE,
    SEV,
    SEVL,
    YIELD,
    NOP,
    DBG,
    DMB,
    DSB,
    ISB,
    PLD,
    PLI,
    PLDW,
    CLREX,

    // ======================================================================
    // Coprocessor Instructions
    // ======================================================================
    CDP,
    LDC,
    STC,
    MCR,
    MRC,
    MCRR,
    MRRC,

    // ======================================================================
    // Saturating Arithmetic
    // ======================================================================
    QADD,
    QSUB,
    QDADD,
    QDSUB,
    SSAT,
    USAT,
    SSAT16,
    USAT16,

    // ======================================================================
    // Parallel Addition/Subtraction (SIMD within ARM core)
    // ======================================================================
    SADD8,
    SSUB8,
    SADD16,
    SSUB16,
    UADD8,
    USUB8,
    UADD16,
    USUB16,
    SHADD8,
    SHSUB8,
    SHADD16,
    SHSUB16,
    UHADD8,
    UHSUB8,
    UHADD16,
    UHSUB16,
    QADD8,
    QSUB8,
    QADD16,
    QSUB16,
    UQADD8,
    UQSUB8,
    UQADD16,
    UQSUB16,
    SASX,
    SSAX,
    UASX,
    USAX,
    SHASX,
    SHSAX,
    UHASX,
    UHSAX,
    QASX,
    QSAX,
    UQASX,
    UQSAX,
    SEL,

    // ======================================================================
    // Packing/Unpacking
    // ======================================================================
    PKHBT,
    PKHTB,
    SXTAB,
    SXTAB16,
    SXTAH,
    SXTB,
    SXTB16,
    SXTH,
    UXTAB,
    UXTAB16,
    UXTAH,
    UXTB,
    UXTB16,
    UXTH,
    REV,
    REV16,
    REVSH,
    RBIT,

    // ======================================================================
    // Bit Field
    // ======================================================================
    BFC,
    BFI,
    SBFX,
    UBFX,

    // ======================================================================
    // CLZ / Count Leading Zeros
    // ======================================================================
    CLZ,

    // ======================================================================
    // Swap
    // ======================================================================
    SWP,
    SWPB,

    // ======================================================================
    // Load/Store Exclusive
    // ======================================================================
    LDREX,
    LDREXB,
    LDREXH,
    LDREXD,
    STREX,
    STREXB,
    STREXH,
    STREXD,

    // ======================================================================
    // Table Branch (Thumb-2)
    // ======================================================================
    TBB,
    TBH,

    // ======================================================================
    // If-Then (Thumb-2)
    // ======================================================================
    IT,
    ITE,
    ITT,
    ITEE,
    ITET,
    ITTE,
    ITTT,
    ITEEE,
    ITEET,
    ITETE,
    ITETT,
    ITTEE,
    ITTET,
    ITTTE,
    ITTTT,

    // ======================================================================
    // Change Processor State
    // ======================================================================
    CPSID,
    CPSIE,

    // ======================================================================
    // VFP (Floating-Point)
    // ======================================================================
    VLDR,
    VSTR,
    VLDM,
    VSTM,
    VPUSH,
    VPOP,
    VMOV_CORE,
    VMOV_CORE_S,
    VMOV_DOUBLE,
    VMOV_SINGLE,
    VMOV_IMM,
    VADD_F32,
    VSUB_F32,
    VMUL_F32,
    VMLA_F32,
    VMLS_F32,
    VNMUL,
    VNMLA,
    VNMLS,
    VDIV,
    VNEG,
    VABS,
    VSQRT,
    VCMP,
    VCMPE,
    VCMPZ,
    VCMPEZ,
    VCVT,
    VCVTR,
    VCVTB,
    VCVTT,
    VCVT_F32_S32,
    VCVT_S32_F32,
    VCVT_F32_U32,
    VCVT_U32_F32,
    VCVT_F64_F32,
    VCVT_F32_F64,
    VMRS,
    VMSR,
    VSEL_F32,
    VMAXNM,
    VMINNM,
    VRINTR,
    VRINTZ,
    VRINTX,
    VRINT,
    VRINTA,
    VRINTM,
    VRINTN,
    VRINTP,

    // ======================================================================
    // NEON / Advanced SIMD
    // ======================================================================
    VLD1_8,
    VLD1_16,
    VLD1_32,
    VLD1_64,
    VLD2_8,
    VLD2_16,
    VLD2_32,
    VLD3_8,
    VLD3_16,
    VLD3_32,
    VLD4_8,
    VLD4_16,
    VLD4_32,
    VST1_8,
    VST1_16,
    VST1_32,
    VST1_64,
    VST2_8,
    VST2_16,
    VST2_32,
    VST3_8,
    VST3_16,
    VST3_32,
    VST4_8,
    VST4_16,
    VST4_32,
    VADD_I8,
    VADD_I16,
    VADD_I32,
    VADD_I64,
    VADD_F32_SIMD,
    VADD_F64,
    VSUB_I8,
    VSUB_I16,
    VSUB_I32,
    VSUB_I64,
    VSUB_F32_SIMD,
    VSUB_F64,
    VMUL_I8,
    VMUL_I16,
    VMUL_I32,
    VMUL_F32_SIMD,
    VMUL_F64,
    VMLA,
    VMLS,
    VABD,
    VABA,
    VMAX,
    VMIN,
    VPADD,
    VPMAX,
    VPMIN,
    VCEQ,
    VCGE,
    VCGT,
    VCLE,
    VCLT,
    VTST,
    VAND,
    VBIC,
    VEOR,
    VORR,
    VORN,
    VMVN,
    VSHL,
    VSHLL,
    VSHR,
    VSHRA,
    VSLI,
    VSRI,
    VQSHL,
    VQSHLU,
    VRSHR,
    VRSRA,
    VMOVL,
    VMOVN,
    VQMOVN,
    VQMOVUN,
    VADDL,
    VADDW,
    VSUBL,
    VSUBW,
    VMULL,
    VMLAL,
    VMLSL,
    VEXT,
    VDUP,
    VREV,
    VTRN,
    VZIP,
    VUZP,
    VSWP,
    VTBL,
    VTBX,
    VBSL,
    VBIT,
    VBIF,
    VCNT,
    VCLS,
    VCLZ,
    VPADAL,
    VCVT_SIMD,
    VRECPE,
    VRSQRTE,
    VRECPS,
    VRSQRTS,
    VABS_SIMD,
    VNEG_SIMD,
    VMOV_SIMD,
    VMVN_SIMD,
    // Crypto
    AESD,
    AESE,
    AESIMC,
    AESMC,
    SHA1C,
    SHA1P,
    SHA1M,
    SHA1H,
    SHA1SU0,
    SHA1SU1,
    SHA256H,
    SHA256H2,
    SHA256SU0,
    SHA256SU1,
    VMULL_P64,
}

impl ArmMnemonic {
    /// The assembly mnemonic string.
    pub fn as_str(&self) -> &'static str {
        match self {
            ArmMnemonic::AND => "AND",
            ArmMnemonic::EOR => "EOR",
            ArmMnemonic::SUB => "SUB",
            ArmMnemonic::RSB => "RSB",
            ArmMnemonic::ADD => "ADD",
            ArmMnemonic::ADC => "ADC",
            ArmMnemonic::SBC => "SBC",
            ArmMnemonic::RSC => "RSC",
            ArmMnemonic::TST => "TST",
            ArmMnemonic::TEQ => "TEQ",
            ArmMnemonic::CMP => "CMP",
            ArmMnemonic::CMN => "CMN",
            ArmMnemonic::ORR => "ORR",
            ArmMnemonic::MOV => "MOV",
            ArmMnemonic::BIC => "BIC",
            ArmMnemonic::MVN => "MVN",
            ArmMnemonic::AND_IMM => "AND",
            ArmMnemonic::EOR_IMM => "EOR",
            ArmMnemonic::SUB_IMM => "SUB",
            ArmMnemonic::RSB_IMM => "RSB",
            ArmMnemonic::ADD_IMM => "ADD",
            ArmMnemonic::ADC_IMM => "ADC",
            ArmMnemonic::SBC_IMM => "SBC",
            ArmMnemonic::RSC_IMM => "RSC",
            ArmMnemonic::TST_IMM => "TST",
            ArmMnemonic::TEQ_IMM => "TEQ",
            ArmMnemonic::CMP_IMM => "CMP",
            ArmMnemonic::CMN_IMM => "CMN",
            ArmMnemonic::ORR_IMM => "ORR",
            ArmMnemonic::MOV_IMM => "MOV",
            ArmMnemonic::BIC_IMM => "BIC",
            ArmMnemonic::MVN_IMM => "MVN",
            ArmMnemonic::MUL => "MUL",
            ArmMnemonic::MLA => "MLA",
            ArmMnemonic::UMULL => "UMULL",
            ArmMnemonic::UMLAL => "UMLAL",
            ArmMnemonic::SMULL => "SMULL",
            ArmMnemonic::SMLAL => "SMLAL",
            ArmMnemonic::UMAAL => "UMAAL",
            ArmMnemonic::MLS => "MLS",
            ArmMnemonic::SMMUL => "SMMUL",
            ArmMnemonic::SMMLA => "SMMLA",
            ArmMnemonic::SMMLS => "SMMLS",
            ArmMnemonic::SMULBB => "SMULBB",
            ArmMnemonic::SMULBT => "SMULBT",
            ArmMnemonic::SMULTB => "SMULTB",
            ArmMnemonic::SMULTT => "SMULTT",
            ArmMnemonic::SMLABB => "SMLABB",
            ArmMnemonic::SMLABT => "SMLABT",
            ArmMnemonic::SMLATB => "SMLATB",
            ArmMnemonic::SMLATT => "SMLATT",
            ArmMnemonic::SMLALBB => "SMLALBB",
            ArmMnemonic::SMLALBT => "SMLALBT",
            ArmMnemonic::SMLALTB => "SMLALTB",
            ArmMnemonic::SMLALTT => "SMLALTT",
            ArmMnemonic::SMULWB => "SMULWB",
            ArmMnemonic::SMULWT => "SMULWT",
            ArmMnemonic::SMLAWB => "SMLAWB",
            ArmMnemonic::SMLAWT => "SMLAWT",
            ArmMnemonic::USAD8 => "USAD8",
            ArmMnemonic::USADA8 => "USADA8",
            ArmMnemonic::SDIV => "SDIV",
            ArmMnemonic::UDIV => "UDIV",
            ArmMnemonic::B => "B",
            ArmMnemonic::BL => "BL",
            ArmMnemonic::BX => "BX",
            ArmMnemonic::BLX => "BLX",
            ArmMnemonic::BXJ => "BXJ",
            ArmMnemonic::LDR => "LDR",
            ArmMnemonic::LDRB => "LDRB",
            ArmMnemonic::LDRH => "LDRH",
            ArmMnemonic::LDRSB => "LDRSB",
            ArmMnemonic::LDRSH => "LDRSH",
            ArmMnemonic::LDRD => "LDRD",
            ArmMnemonic::STR => "STR",
            ArmMnemonic::STRB => "STRB",
            ArmMnemonic::STRH => "STRH",
            ArmMnemonic::STRD => "STRD",
            ArmMnemonic::LDRT => "LDRT",
            ArmMnemonic::LDRBT => "LDRBT",
            ArmMnemonic::STRT => "STRT",
            ArmMnemonic::STRBT => "STRBT",
            ArmMnemonic::LDM => "LDM",
            ArmMnemonic::STM => "STM",
            ArmMnemonic::LDMDA => "LDMDA",
            ArmMnemonic::STMDA => "STMDA",
            ArmMnemonic::LDMDB => "LDMDB",
            ArmMnemonic::STMDB => "STMDB",
            ArmMnemonic::LDMIB => "LDMIB",
            ArmMnemonic::STMIB => "STMIB",
            ArmMnemonic::LDMFD => "LDMFD",
            ArmMnemonic::LDMFA => "LDMFA",
            ArmMnemonic::LDMED => "LDMED",
            ArmMnemonic::LDMFA_FD => "LDMFA",
            ArmMnemonic::STMFD => "STMFD",
            ArmMnemonic::STMFA => "STMFA",
            ArmMnemonic::STMED => "STMED",
            ArmMnemonic::STMEA => "STMEA",
            ArmMnemonic::PUSH => "PUSH",
            ArmMnemonic::POP => "POP",
            ArmMnemonic::MRS => "MRS",
            ArmMnemonic::MSR => "MSR",
            ArmMnemonic::MSR_IMM => "MSR",
            ArmMnemonic::CPS => "CPS",
            ArmMnemonic::SETEND => "SETEND",
            ArmMnemonic::SWI => "SWI",
            ArmMnemonic::SVC => "SVC",
            ArmMnemonic::SMC => "SMC",
            ArmMnemonic::HVC => "HVC",
            ArmMnemonic::BKPT => "BKPT",
            ArmMnemonic::UDF => "UDF",
            ArmMnemonic::RFE => "RFE",
            ArmMnemonic::SRS => "SRS",
            ArmMnemonic::ERET => "ERET",
            ArmMnemonic::WFI => "WFI",
            ArmMnemonic::WFE => "WFE",
            ArmMnemonic::SEV => "SEV",
            ArmMnemonic::SEVL => "SEVL",
            ArmMnemonic::YIELD => "YIELD",
            ArmMnemonic::NOP => "NOP",
            ArmMnemonic::DBG => "DBG",
            ArmMnemonic::DMB => "DMB",
            ArmMnemonic::DSB => "DSB",
            ArmMnemonic::ISB => "ISB",
            ArmMnemonic::PLD => "PLD",
            ArmMnemonic::PLI => "PLI",
            ArmMnemonic::PLDW => "PLDW",
            ArmMnemonic::CLREX => "CLREX",
            ArmMnemonic::CDP => "CDP",
            ArmMnemonic::LDC => "LDC",
            ArmMnemonic::STC => "STC",
            ArmMnemonic::MCR => "MCR",
            ArmMnemonic::MRC => "MRC",
            ArmMnemonic::MCRR => "MCRR",
            ArmMnemonic::MRRC => "MRRC",
            ArmMnemonic::QADD => "QADD",
            ArmMnemonic::QSUB => "QSUB",
            ArmMnemonic::QDADD => "QDADD",
            ArmMnemonic::QDSUB => "QDSUB",
            ArmMnemonic::SSAT => "SSAT",
            ArmMnemonic::USAT => "USAT",
            ArmMnemonic::SSAT16 => "SSAT16",
            ArmMnemonic::USAT16 => "USAT16",
            ArmMnemonic::SADD8 => "SADD8",
            ArmMnemonic::SSUB8 => "SSUB8",
            ArmMnemonic::SADD16 => "SADD16",
            ArmMnemonic::SSUB16 => "SSUB16",
            ArmMnemonic::UADD8 => "UADD8",
            ArmMnemonic::USUB8 => "USUB8",
            ArmMnemonic::UADD16 => "UADD16",
            ArmMnemonic::USUB16 => "USUB16",
            ArmMnemonic::SHADD8 => "SHADD8",
            ArmMnemonic::SHSUB8 => "SHSUB8",
            ArmMnemonic::SHADD16 => "SHADD16",
            ArmMnemonic::SHSUB16 => "SHSUB16",
            ArmMnemonic::UHADD8 => "UHADD8",
            ArmMnemonic::UHSUB8 => "UHSUB8",
            ArmMnemonic::UHADD16 => "UHADD16",
            ArmMnemonic::UHSUB16 => "UHSUB16",
            ArmMnemonic::QADD8 => "QADD8",
            ArmMnemonic::QSUB8 => "QSUB8",
            ArmMnemonic::QADD16 => "QADD16",
            ArmMnemonic::QSUB16 => "QSUB16",
            ArmMnemonic::UQADD8 => "UQADD8",
            ArmMnemonic::UQSUB8 => "UQSUB8",
            ArmMnemonic::UQADD16 => "UQADD16",
            ArmMnemonic::UQSUB16 => "UQSUB16",
            ArmMnemonic::SASX => "SASX",
            ArmMnemonic::SSAX => "SSAX",
            ArmMnemonic::UASX => "UASX",
            ArmMnemonic::USAX => "USAX",
            ArmMnemonic::SHASX => "SHASX",
            ArmMnemonic::SHSAX => "SHSAX",
            ArmMnemonic::UHASX => "UHASX",
            ArmMnemonic::UHSAX => "UHSAX",
            ArmMnemonic::QASX => "QASX",
            ArmMnemonic::QSAX => "QSAX",
            ArmMnemonic::UQASX => "UQASX",
            ArmMnemonic::UQSAX => "UQSAX",
            ArmMnemonic::SEL => "SEL",
            ArmMnemonic::PKHBT => "PKHBT",
            ArmMnemonic::PKHTB => "PKHTB",
            ArmMnemonic::SXTAB => "SXTAB",
            ArmMnemonic::SXTAB16 => "SXTAB16",
            ArmMnemonic::SXTAH => "SXTAH",
            ArmMnemonic::SXTB => "SXTB",
            ArmMnemonic::SXTB16 => "SXTB16",
            ArmMnemonic::SXTH => "SXTH",
            ArmMnemonic::UXTAB => "UXTAB",
            ArmMnemonic::UXTAB16 => "UXTAB16",
            ArmMnemonic::UXTAH => "UXTAH",
            ArmMnemonic::UXTB => "UXTB",
            ArmMnemonic::UXTB16 => "UXTB16",
            ArmMnemonic::UXTH => "UXTH",
            ArmMnemonic::REV => "REV",
            ArmMnemonic::REV16 => "REV16",
            ArmMnemonic::REVSH => "REVSH",
            ArmMnemonic::RBIT => "RBIT",
            ArmMnemonic::BFC => "BFC",
            ArmMnemonic::BFI => "BFI",
            ArmMnemonic::SBFX => "SBFX",
            ArmMnemonic::UBFX => "UBFX",
            ArmMnemonic::CLZ => "CLZ",
            ArmMnemonic::SWP => "SWP",
            ArmMnemonic::SWPB => "SWPB",
            ArmMnemonic::LDREX => "LDREX",
            ArmMnemonic::LDREXB => "LDREXB",
            ArmMnemonic::LDREXH => "LDREXH",
            ArmMnemonic::LDREXD => "LDREXD",
            ArmMnemonic::STREX => "STREX",
            ArmMnemonic::STREXB => "STREXB",
            ArmMnemonic::STREXH => "STREXH",
            ArmMnemonic::STREXD => "STREXD",
            ArmMnemonic::TBB => "TBB",
            ArmMnemonic::TBH => "TBH",
            ArmMnemonic::IT => "IT",
            ArmMnemonic::ITE => "ITE",
            ArmMnemonic::ITT => "ITT",
            ArmMnemonic::ITEE => "ITEE",
            ArmMnemonic::ITET => "ITET",
            ArmMnemonic::ITTE => "ITTE",
            ArmMnemonic::ITTT => "ITTT",
            ArmMnemonic::ITEEE => "ITEEE",
            ArmMnemonic::ITEET => "ITEET",
            ArmMnemonic::ITETE => "ITETE",
            ArmMnemonic::ITETT => "ITETT",
            ArmMnemonic::ITTEE => "ITTEE",
            ArmMnemonic::ITTET => "ITTET",
            ArmMnemonic::ITTTE => "ITTTE",
            ArmMnemonic::ITTTT => "ITTTT",
            ArmMnemonic::CPSID => "CPSID",
            ArmMnemonic::CPSIE => "CPSIE",
            ArmMnemonic::VLDR => "VLDR",
            ArmMnemonic::VSTR => "VSTR",
            ArmMnemonic::VLDM => "VLDM",
            ArmMnemonic::VSTM => "VSTM",
            ArmMnemonic::VPUSH => "VPUSH",
            ArmMnemonic::VPOP => "VPOP",
            ArmMnemonic::VMOV_CORE => "VMOV",
            ArmMnemonic::VMOV_CORE_S => "VMOV",
            ArmMnemonic::VMOV_DOUBLE => "VMOV",
            ArmMnemonic::VMOV_SINGLE => "VMOV",
            ArmMnemonic::VMOV_IMM => "VMOV",
            ArmMnemonic::VADD_F32 => "VADD.F32",
            ArmMnemonic::VSUB_F32 => "VSUB.F32",
            ArmMnemonic::VMUL_F32 => "VMUL.F32",
            ArmMnemonic::VMLA_F32 => "VMLA.F32",
            ArmMnemonic::VMLS_F32 => "VMLS.F32",
            ArmMnemonic::VNMUL => "VNMUL",
            ArmMnemonic::VNMLA => "VNMLA",
            ArmMnemonic::VNMLS => "VNMLS",
            ArmMnemonic::VDIV => "VDIV",
            ArmMnemonic::VNEG => "VNEG",
            ArmMnemonic::VABS => "VABS",
            ArmMnemonic::VSQRT => "VSQRT",
            ArmMnemonic::VCMP => "VCMP",
            ArmMnemonic::VCMPE => "VCMPE",
            ArmMnemonic::VCMPZ => "VCMPZ",
            ArmMnemonic::VCMPEZ => "VCMPEZ",
            ArmMnemonic::VCVT => "VCVT",
            ArmMnemonic::VCVTR => "VCVTR",
            ArmMnemonic::VCVTB => "VCVTB",
            ArmMnemonic::VCVTT => "VCVTT",
            ArmMnemonic::VCVT_F32_S32 => "VCVT.F32.S32",
            ArmMnemonic::VCVT_S32_F32 => "VCVT.S32.F32",
            ArmMnemonic::VCVT_F32_U32 => "VCVT.F32.U32",
            ArmMnemonic::VCVT_U32_F32 => "VCVT.U32.F32",
            ArmMnemonic::VCVT_F64_F32 => "VCVT.F64.F32",
            ArmMnemonic::VCVT_F32_F64 => "VCVT.F32.F64",
            ArmMnemonic::VMRS => "VMRS",
            ArmMnemonic::VMSR => "VMSR",
            ArmMnemonic::VSEL_F32 => "VSEL.F32",
            ArmMnemonic::VMAXNM => "VMAXNM",
            ArmMnemonic::VMINNM => "VMINNM",
            ArmMnemonic::VRINTR => "VRINTR",
            ArmMnemonic::VRINTZ => "VRINTZ",
            ArmMnemonic::VRINTX => "VRINTX",
            ArmMnemonic::VRINT => "VRINT",
            ArmMnemonic::VRINTA => "VRINTA",
            ArmMnemonic::VRINTM => "VRINTM",
            ArmMnemonic::VRINTN => "VRINTN",
            ArmMnemonic::VRINTP => "VRINTP",
            ArmMnemonic::VLD1_8 => "VLD1.8",
            ArmMnemonic::VLD1_16 => "VLD1.16",
            ArmMnemonic::VLD1_32 => "VLD1.32",
            ArmMnemonic::VLD1_64 => "VLD1.64",
            ArmMnemonic::VLD2_8 => "VLD2.8",
            ArmMnemonic::VLD2_16 => "VLD2.16",
            ArmMnemonic::VLD2_32 => "VLD2.32",
            ArmMnemonic::VLD3_8 => "VLD3.8",
            ArmMnemonic::VLD3_16 => "VLD3.16",
            ArmMnemonic::VLD3_32 => "VLD3.32",
            ArmMnemonic::VLD4_8 => "VLD4.8",
            ArmMnemonic::VLD4_16 => "VLD4.16",
            ArmMnemonic::VLD4_32 => "VLD4.32",
            ArmMnemonic::VST1_8 => "VST1.8",
            ArmMnemonic::VST1_16 => "VST1.16",
            ArmMnemonic::VST1_32 => "VST1.32",
            ArmMnemonic::VST1_64 => "VST1.64",
            ArmMnemonic::VST2_8 => "VST2.8",
            ArmMnemonic::VST2_16 => "VST2.16",
            ArmMnemonic::VST2_32 => "VST2.32",
            ArmMnemonic::VST3_8 => "VST3.8",
            ArmMnemonic::VST3_16 => "VST3.16",
            ArmMnemonic::VST3_32 => "VST3.32",
            ArmMnemonic::VST4_8 => "VST4.8",
            ArmMnemonic::VST4_16 => "VST4.16",
            ArmMnemonic::VST4_32 => "VST4.32",
            ArmMnemonic::VADD_I8 => "VADD.I8",
            ArmMnemonic::VADD_I16 => "VADD.I16",
            ArmMnemonic::VADD_I32 => "VADD.I32",
            ArmMnemonic::VADD_I64 => "VADD.I64",
            ArmMnemonic::VADD_F32_SIMD => "VADD.F32",
            ArmMnemonic::VADD_F64 => "VADD.F64",
            ArmMnemonic::VSUB_I8 => "VSUB.I8",
            ArmMnemonic::VSUB_I16 => "VSUB.I16",
            ArmMnemonic::VSUB_I32 => "VSUB.I32",
            ArmMnemonic::VSUB_I64 => "VSUB.I64",
            ArmMnemonic::VSUB_F32_SIMD => "VSUB.F32",
            ArmMnemonic::VSUB_F64 => "VSUB.F64",
            ArmMnemonic::VMUL_I8 => "VMUL.I8",
            ArmMnemonic::VMUL_I16 => "VMUL.I16",
            ArmMnemonic::VMUL_I32 => "VMUL.I32",
            ArmMnemonic::VMUL_F32_SIMD => "VMUL.F32",
            ArmMnemonic::VMUL_F64 => "VMUL.F64",
            ArmMnemonic::VMLA => "VMLA",
            ArmMnemonic::VMLS => "VMLS",
            ArmMnemonic::VABD => "VABD",
            ArmMnemonic::VABA => "VABA",
            ArmMnemonic::VMAX => "VMAX",
            ArmMnemonic::VMIN => "VMIN",
            ArmMnemonic::VPADD => "VPADD",
            ArmMnemonic::VPMAX => "VPMAX",
            ArmMnemonic::VPMIN => "VPMIN",
            ArmMnemonic::VCEQ => "VCEQ",
            ArmMnemonic::VCGE => "VCGE",
            ArmMnemonic::VCGT => "VCGT",
            ArmMnemonic::VCLE => "VCLE",
            ArmMnemonic::VCLT => "VCLT",
            ArmMnemonic::VTST => "VTST",
            ArmMnemonic::VAND => "VAND",
            ArmMnemonic::VBIC => "VBIC",
            ArmMnemonic::VEOR => "VEOR",
            ArmMnemonic::VORR => "VORR",
            ArmMnemonic::VORN => "VORN",
            ArmMnemonic::VMVN => "VMVN",
            ArmMnemonic::VSHL => "VSHL",
            ArmMnemonic::VSHLL => "VSHLL",
            ArmMnemonic::VSHR => "VSHR",
            ArmMnemonic::VSHRA => "VSHRA",
            ArmMnemonic::VSLI => "VSLI",
            ArmMnemonic::VSRI => "VSRI",
            ArmMnemonic::VQSHL => "VQSHL",
            ArmMnemonic::VQSHLU => "VQSHLU",
            ArmMnemonic::VRSHR => "VRSHR",
            ArmMnemonic::VRSRA => "VRSRA",
            ArmMnemonic::VMOVL => "VMOVL",
            ArmMnemonic::VMOVN => "VMOVN",
            ArmMnemonic::VQMOVN => "VQMOVN",
            ArmMnemonic::VQMOVUN => "VQMOVUN",
            ArmMnemonic::VADDL => "VADDL",
            ArmMnemonic::VADDW => "VADDW",
            ArmMnemonic::VSUBL => "VSUBL",
            ArmMnemonic::VSUBW => "VSUBW",
            ArmMnemonic::VMULL => "VMULL",
            ArmMnemonic::VMLAL => "VMLAL",
            ArmMnemonic::VMLSL => "VMLSL",
            ArmMnemonic::VEXT => "VEXT",
            ArmMnemonic::VDUP => "VDUP",
            ArmMnemonic::VREV => "VREV",
            ArmMnemonic::VTRN => "VTRN",
            ArmMnemonic::VZIP => "VZIP",
            ArmMnemonic::VUZP => "VUZP",
            ArmMnemonic::VSWP => "VSWP",
            ArmMnemonic::VTBL => "VTBL",
            ArmMnemonic::VTBX => "VTBX",
            ArmMnemonic::VBSL => "VBSL",
            ArmMnemonic::VBIT => "VBIT",
            ArmMnemonic::VBIF => "VBIF",
            ArmMnemonic::VCNT => "VCNT",
            ArmMnemonic::VCLS => "VCLS",
            ArmMnemonic::VCLZ => "VCLZ",
            ArmMnemonic::VPADAL => "VPADAL",
            ArmMnemonic::VCVT_SIMD => "VCVT",
            ArmMnemonic::VRECPE => "VRECPE",
            ArmMnemonic::VRSQRTE => "VRSQRTE",
            ArmMnemonic::VRECPS => "VRECPS",
            ArmMnemonic::VRSQRTS => "VRSQRTS",
            ArmMnemonic::VABS_SIMD => "VABS",
            ArmMnemonic::VNEG_SIMD => "VNEG",
            ArmMnemonic::VMOV_SIMD => "VMOV",
            ArmMnemonic::VMVN_SIMD => "VMVN",
            ArmMnemonic::AESD => "AESD",
            ArmMnemonic::AESE => "AESE",
            ArmMnemonic::AESIMC => "AESIMC",
            ArmMnemonic::AESMC => "AESMC",
            ArmMnemonic::SHA1C => "SHA1C",
            ArmMnemonic::SHA1P => "SHA1P",
            ArmMnemonic::SHA1M => "SHA1M",
            ArmMnemonic::SHA1H => "SHA1H",
            ArmMnemonic::SHA1SU0 => "SHA1SU0",
            ArmMnemonic::SHA1SU1 => "SHA1SU1",
            ArmMnemonic::SHA256H => "SHA256H",
            ArmMnemonic::SHA256H2 => "SHA256H2",
            ArmMnemonic::SHA256SU0 => "SHA256SU0",
            ArmMnemonic::SHA256SU1 => "SHA256SU1",
            ArmMnemonic::VMULL_P64 => "VMULL.P64",
        }
    }

    /// The instruction category.
    pub fn category(&self) -> InstructionCategory {
        match self {
            ArmMnemonic::AND
            | ArmMnemonic::EOR
            | ArmMnemonic::SUB
            | ArmMnemonic::RSB
            | ArmMnemonic::ADD
            | ArmMnemonic::ADC
            | ArmMnemonic::SBC
            | ArmMnemonic::RSC
            | ArmMnemonic::TST
            | ArmMnemonic::TEQ
            | ArmMnemonic::CMP
            | ArmMnemonic::CMN
            | ArmMnemonic::ORR
            | ArmMnemonic::MOV
            | ArmMnemonic::BIC
            | ArmMnemonic::MVN
            | ArmMnemonic::AND_IMM
            | ArmMnemonic::EOR_IMM
            | ArmMnemonic::SUB_IMM
            | ArmMnemonic::RSB_IMM
            | ArmMnemonic::ADD_IMM
            | ArmMnemonic::ADC_IMM
            | ArmMnemonic::SBC_IMM
            | ArmMnemonic::RSC_IMM
            | ArmMnemonic::TST_IMM
            | ArmMnemonic::TEQ_IMM
            | ArmMnemonic::CMP_IMM
            | ArmMnemonic::CMN_IMM
            | ArmMnemonic::ORR_IMM
            | ArmMnemonic::MOV_IMM
            | ArmMnemonic::BIC_IMM
            | ArmMnemonic::MVN_IMM => InstructionCategory::DataProcessing,
            ArmMnemonic::MUL
            | ArmMnemonic::MLA
            | ArmMnemonic::UMULL
            | ArmMnemonic::UMLAL
            | ArmMnemonic::SMULL
            | ArmMnemonic::SMLAL
            | ArmMnemonic::UMAAL
            | ArmMnemonic::MLS
            | ArmMnemonic::SMMUL
            | ArmMnemonic::SMMLA
            | ArmMnemonic::SMMLS
            | ArmMnemonic::SMULBB
            | ArmMnemonic::SMULBT
            | ArmMnemonic::SMULTB
            | ArmMnemonic::SMULTT
            | ArmMnemonic::SMLABB
            | ArmMnemonic::SMLABT
            | ArmMnemonic::SMLATB
            | ArmMnemonic::SMLATT
            | ArmMnemonic::SMLALBB
            | ArmMnemonic::SMLALBT
            | ArmMnemonic::SMLALTB
            | ArmMnemonic::SMLALTT
            | ArmMnemonic::SMULWB
            | ArmMnemonic::SMULWT
            | ArmMnemonic::SMLAWB
            | ArmMnemonic::SMLAWT
            | ArmMnemonic::USAD8
            | ArmMnemonic::USADA8
            | ArmMnemonic::SDIV
            | ArmMnemonic::UDIV => InstructionCategory::Multiply,
            ArmMnemonic::B
            | ArmMnemonic::BL
            | ArmMnemonic::BX
            | ArmMnemonic::BLX
            | ArmMnemonic::BXJ => InstructionCategory::Branch,
            ArmMnemonic::LDR
            | ArmMnemonic::LDRB
            | ArmMnemonic::LDRH
            | ArmMnemonic::LDRSB
            | ArmMnemonic::LDRSH
            | ArmMnemonic::LDRD
            | ArmMnemonic::STR
            | ArmMnemonic::STRB
            | ArmMnemonic::STRH
            | ArmMnemonic::STRD
            | ArmMnemonic::LDRT
            | ArmMnemonic::LDRBT
            | ArmMnemonic::STRT
            | ArmMnemonic::STRBT
            | ArmMnemonic::LDM
            | ArmMnemonic::STM
            | ArmMnemonic::LDMDA
            | ArmMnemonic::STMDA
            | ArmMnemonic::LDMDB
            | ArmMnemonic::STMDB
            | ArmMnemonic::LDMIB
            | ArmMnemonic::STMIB
            | ArmMnemonic::LDMFD
            | ArmMnemonic::LDMFA
            | ArmMnemonic::LDMED
            | ArmMnemonic::LDMFA_FD
            | ArmMnemonic::STMFD
            | ArmMnemonic::STMFA
            | ArmMnemonic::STMED
            | ArmMnemonic::STMEA
            | ArmMnemonic::PUSH
            | ArmMnemonic::POP
            | ArmMnemonic::LDREX
            | ArmMnemonic::LDREXB
            | ArmMnemonic::LDREXH
            | ArmMnemonic::LDREXD
            | ArmMnemonic::STREX
            | ArmMnemonic::STREXB
            | ArmMnemonic::STREXH
            | ArmMnemonic::STREXD
            | ArmMnemonic::SWP
            | ArmMnemonic::SWPB => InstructionCategory::LoadStore,
            ArmMnemonic::MRS | ArmMnemonic::MSR | ArmMnemonic::MSR_IMM => {
                InstructionCategory::StatusRegister
            }
            ArmMnemonic::SWI
            | ArmMnemonic::SVC
            | ArmMnemonic::SMC
            | ArmMnemonic::HVC
            | ArmMnemonic::BKPT
            | ArmMnemonic::UDF
            | ArmMnemonic::RFE
            | ArmMnemonic::SRS
            | ArmMnemonic::ERET
            | ArmMnemonic::WFI
            | ArmMnemonic::WFE
            | ArmMnemonic::SEV
            | ArmMnemonic::SEVL
            | ArmMnemonic::YIELD
            | ArmMnemonic::NOP
            | ArmMnemonic::DBG
            | ArmMnemonic::DMB
            | ArmMnemonic::DSB
            | ArmMnemonic::ISB
            | ArmMnemonic::CLREX => InstructionCategory::Exception,
            ArmMnemonic::CDP
            | ArmMnemonic::LDC
            | ArmMnemonic::STC
            | ArmMnemonic::MCR
            | ArmMnemonic::MRC
            | ArmMnemonic::MCRR
            | ArmMnemonic::MRRC => InstructionCategory::Coprocessor,
            ArmMnemonic::VLDR
            | ArmMnemonic::VSTR
            | ArmMnemonic::VLDM
            | ArmMnemonic::VSTM
            | ArmMnemonic::VPUSH
            | ArmMnemonic::VPOP
            | ArmMnemonic::VMOV_CORE
            | ArmMnemonic::VMOV_CORE_S
            | ArmMnemonic::VMOV_DOUBLE
            | ArmMnemonic::VMOV_SINGLE
            | ArmMnemonic::VMOV_IMM
            | ArmMnemonic::VADD_F32
            | ArmMnemonic::VSUB_F32
            | ArmMnemonic::VMUL_F32
            | ArmMnemonic::VMLA_F32
            | ArmMnemonic::VMLS_F32
            | ArmMnemonic::VNMUL
            | ArmMnemonic::VNMLA
            | ArmMnemonic::VNMLS
            | ArmMnemonic::VDIV
            | ArmMnemonic::VNEG
            | ArmMnemonic::VABS
            | ArmMnemonic::VSQRT
            | ArmMnemonic::VCMP
            | ArmMnemonic::VCMPE
            | ArmMnemonic::VCMPZ
            | ArmMnemonic::VCMPEZ
            | ArmMnemonic::VCVT
            | ArmMnemonic::VCVTR
            | ArmMnemonic::VCVTB
            | ArmMnemonic::VCVTT
            | ArmMnemonic::VCVT_F32_S32
            | ArmMnemonic::VCVT_S32_F32
            | ArmMnemonic::VCVT_F32_U32
            | ArmMnemonic::VCVT_U32_F32
            | ArmMnemonic::VCVT_F64_F32
            | ArmMnemonic::VCVT_F32_F64
            | ArmMnemonic::VMRS
            | ArmMnemonic::VMSR
            | ArmMnemonic::VSEL_F32
            | ArmMnemonic::VMAXNM
            | ArmMnemonic::VMINNM
            | ArmMnemonic::VRINTR
            | ArmMnemonic::VRINTZ
            | ArmMnemonic::VRINTX
            | ArmMnemonic::VRINT
            | ArmMnemonic::VRINTA
            | ArmMnemonic::VRINTM
            | ArmMnemonic::VRINTN
            | ArmMnemonic::VRINTP => InstructionCategory::Vfp,
            _ => InstructionCategory::Simd,
        }
    }
}

/// ARM instruction categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstructionCategory {
    DataProcessing,
    Multiply,
    Branch,
    LoadStore,
    StatusRegister,
    Exception,
    Coprocessor,
    Vfp,
    Simd,
    Miscellaneous,
}

// ============================================================================
// Conversion to common InstructionMnemonic
// ============================================================================

/// Convert all ARM mnemonics to common `InstructionMnemonic` strings.
pub fn all_arm_mnemonics() -> Vec<InstructionMnemonic> {
    use ArmMnemonic::*;
    let variants = [
        AND,
        EOR,
        SUB,
        RSB,
        ADD,
        ADC,
        SBC,
        RSC,
        TST,
        TEQ,
        CMP,
        CMN,
        ORR,
        MOV,
        BIC,
        MVN,
        AND_IMM,
        EOR_IMM,
        SUB_IMM,
        RSB_IMM,
        ADD_IMM,
        ADC_IMM,
        SBC_IMM,
        RSC_IMM,
        TST_IMM,
        TEQ_IMM,
        CMP_IMM,
        CMN_IMM,
        ORR_IMM,
        MOV_IMM,
        BIC_IMM,
        MVN_IMM,
        MUL,
        MLA,
        UMULL,
        UMLAL,
        SMULL,
        SMLAL,
        UMAAL,
        MLS,
        SMMUL,
        SMMLA,
        SMMLS,
        SMULBB,
        SMULBT,
        SMULTB,
        SMULTT,
        SMLABB,
        SMLABT,
        SMLATB,
        SMLATT,
        SMLALBB,
        SMLALBT,
        SMLALTB,
        SMLALTT,
        SMULWB,
        SMULWT,
        SMLAWB,
        SMLAWT,
        USAD8,
        USADA8,
        SDIV,
        UDIV,
        B,
        BL,
        BX,
        BLX,
        BXJ,
        LDR,
        LDRB,
        LDRH,
        LDRSB,
        LDRSH,
        LDRD,
        STR,
        STRB,
        STRH,
        STRD,
        LDRT,
        LDRBT,
        STRT,
        STRBT,
        LDM,
        STM,
        LDMDA,
        STMDA,
        LDMDB,
        STMDB,
        LDMIB,
        STMIB,
        LDMFD,
        LDMFA,
        LDMED,
        LDMFA_FD,
        STMFD,
        STMFA,
        STMED,
        STMEA,
        PUSH,
        POP,
        MRS,
        MSR,
        MSR_IMM,
        CPS,
        SETEND,
        SWI,
        SVC,
        SMC,
        HVC,
        BKPT,
        UDF,
        RFE,
        SRS,
        ERET,
        WFI,
        WFE,
        SEV,
        SEVL,
        YIELD,
        NOP,
        DBG,
        DMB,
        DSB,
        ISB,
        PLD,
        PLI,
        PLDW,
        CLREX,
        CDP,
        LDC,
        STC,
        MCR,
        MRC,
        MCRR,
        MRRC,
        QADD,
        QSUB,
        QDADD,
        QDSUB,
        SSAT,
        USAT,
        SSAT16,
        USAT16,
        SADD8,
        SSUB8,
        SADD16,
        SSUB16,
        UADD8,
        USUB8,
        UADD16,
        USUB16,
        SHADD8,
        SHSUB8,
        SHADD16,
        SHSUB16,
        UHADD8,
        UHSUB8,
        UHADD16,
        UHSUB16,
        QADD8,
        QSUB8,
        QADD16,
        QSUB16,
        UQADD8,
        UQSUB8,
        UQADD16,
        UQSUB16,
        SASX,
        SSAX,
        UASX,
        USAX,
        SHASX,
        SHSAX,
        UHASX,
        UHSAX,
        QASX,
        QSAX,
        UQASX,
        UQSAX,
        SEL,
        PKHBT,
        PKHTB,
        SXTAB,
        SXTAB16,
        SXTAH,
        SXTB,
        SXTB16,
        SXTH,
        UXTAB,
        UXTAB16,
        UXTAH,
        UXTB,
        UXTB16,
        UXTH,
        REV,
        REV16,
        REVSH,
        RBIT,
        BFC,
        BFI,
        SBFX,
        UBFX,
        CLZ,
        SWP,
        SWPB,
        LDREX,
        LDREXB,
        LDREXH,
        LDREXD,
        STREX,
        STREXB,
        STREXH,
        STREXD,
        TBB,
        TBH,
        IT,
        ITE,
        ITT,
        ITEE,
        ITET,
        ITTE,
        ITTT,
        ITEEE,
        ITEET,
        ITETE,
        ITETT,
        ITTEE,
        ITTET,
        ITTTE,
        ITTTT,
        CPSID,
        CPSIE,
        VLDR,
        VSTR,
        VLDM,
        VSTM,
        VPUSH,
        VPOP,
        VMOV_CORE,
        VMOV_CORE_S,
        VMOV_DOUBLE,
        VMOV_SINGLE,
        VMOV_IMM,
        VADD_F32,
        VSUB_F32,
        VMUL_F32,
        VMLA_F32,
        VMLS_F32,
        VNMUL,
        VNMLA,
        VNMLS,
        VDIV,
        VNEG,
        VABS,
        VSQRT,
        VCMP,
        VCMPE,
        VCMPZ,
        VCMPEZ,
        VCVT,
        VCVTR,
        VCVTB,
        VCVTT,
        VCVT_F32_S32,
        VCVT_S32_F32,
        VCVT_F32_U32,
        VCVT_U32_F32,
        VCVT_F64_F32,
        VCVT_F32_F64,
        VMRS,
        VMSR,
        VSEL_F32,
        VMAXNM,
        VMINNM,
        VRINTR,
        VRINTZ,
        VRINTX,
        VRINT,
        VRINTA,
        VRINTM,
        VRINTN,
        VRINTP,
        VLD1_8,
        VLD1_16,
        VLD1_32,
        VLD1_64,
        VLD2_8,
        VLD2_16,
        VLD2_32,
        VLD3_8,
        VLD3_16,
        VLD3_32,
        VLD4_8,
        VLD4_16,
        VLD4_32,
        VST1_8,
        VST1_16,
        VST1_32,
        VST1_64,
        VST2_8,
        VST2_16,
        VST2_32,
        VST3_8,
        VST3_16,
        VST3_32,
        VST4_8,
        VST4_16,
        VST4_32,
        VADD_I8,
        VADD_I16,
        VADD_I32,
        VADD_I64,
        VADD_F32_SIMD,
        VADD_F64,
        VSUB_I8,
        VSUB_I16,
        VSUB_I32,
        VSUB_I64,
        VSUB_F32_SIMD,
        VSUB_F64,
        VMUL_I8,
        VMUL_I16,
        VMUL_I32,
        VMUL_F32_SIMD,
        VMUL_F64,
        VMLA,
        VMLS,
        VABD,
        VABA,
        VMAX,
        VMIN,
        VPADD,
        VPMAX,
        VPMIN,
        VCEQ,
        VCGE,
        VCGT,
        VCLE,
        VCLT,
        VTST,
        VAND,
        VBIC,
        VEOR,
        VORR,
        VORN,
        VMVN,
        VSHL,
        VSHLL,
        VSHR,
        VSHRA,
        VSLI,
        VSRI,
        VQSHL,
        VQSHLU,
        VRSHR,
        VRSRA,
        VMOVL,
        VMOVN,
        VQMOVN,
        VQMOVUN,
        VADDL,
        VADDW,
        VSUBL,
        VSUBW,
        VMULL,
        VMLAL,
        VMLSL,
        VEXT,
        VDUP,
        VREV,
        VTRN,
        VZIP,
        VUZP,
        VSWP,
        VTBL,
        VTBX,
        VBSL,
        VBIT,
        VBIF,
        VCNT,
        VCLS,
        VCLZ,
        VPADAL,
        VCVT_SIMD,
        VRECPE,
        VRSQRTE,
        VRECPS,
        VRSQRTS,
        VABS_SIMD,
        VNEG_SIMD,
        VMOV_SIMD,
        VMVN_SIMD,
        AESD,
        AESE,
        AESIMC,
        AESMC,
        SHA1C,
        SHA1P,
        SHA1M,
        SHA1H,
        SHA1SU0,
        SHA1SU1,
        SHA256H,
        SHA256H2,
        SHA256SU0,
        SHA256SU1,
        VMULL_P64,
    ];

    let mut mnemonics: Vec<InstructionMnemonic> = variants
        .iter()
        .map(|m| InstructionMnemonic::new(m.as_str()))
        .collect();
    mnemonics.sort_by(|a, b| a.text.cmp(&b.text));
    mnemonics.dedup_by(|a, b| a.text == b.text);
    mnemonics
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_codes() {
        assert_eq!(ConditionCode::EQ.encoding(), 0b0000);
        assert_eq!(ConditionCode::AL.encoding(), 0b1110);
        assert_eq!(ConditionCode::NE.suffix(), "NE");
        assert_eq!(ConditionCode::CS.alt_suffix(), Some("HS"));
    }

    #[test]
    fn test_mnemonic_count() {
        let mnemonics = all_arm_mnemonics();
        assert!(
            mnemonics.len() >= 200,
            "Expected >= 200 unique ARM mnemonics, got {}",
            mnemonics.len()
        );
    }

    #[test]
    fn test_addressing_mode_completeness() {
        let modes = [
            AddressingMode::RegisterDirect,
            AddressingMode::Immediate,
            AddressingMode::RegisterIndirect,
            AddressingMode::PreIndexed,
            AddressingMode::PostIndexed,
            AddressingMode::RegisterOffset,
            AddressingMode::ScaledRegisterOffset,
            AddressingMode::PcRelative,
            AddressingMode::SpRelative,
            AddressingMode::RegisterList,
            AddressingMode::Coprocessor,
        ];
        for mode in &modes {
            assert!(!mode.name().is_empty());
        }
    }

    #[test]
    fn test_shift_types() {
        assert_eq!(ShiftType::LSL.suffix(), "LSL");
        assert_eq!(ShiftType::LSR.suffix(), "LSR");
        assert_eq!(ShiftType::ASR.suffix(), "ASR");
        assert_eq!(ShiftType::ROR.suffix(), "ROR");
        assert_eq!(ShiftType::RRX.suffix(), "RRX");
    }
}
