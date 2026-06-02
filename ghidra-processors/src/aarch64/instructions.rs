//! AArch64 Instruction Mnemonics, Condition Codes, and Addressing Modes
//!
//! Covers the A64 ISA across ARMv8.x and ARMv9.x, organized by functional
//! category. Includes data processing, load/store, branch, exception,
//! system, SIMD/FP, and cryptographic instructions.

use ghidra_core::listing::InstructionMnemonic;

// ============================================================================
// Condition Codes
// ============================================================================

/// AArch64 condition codes.
///
/// Used by conditional branch (B.cond) and conditional select (CSEL, etc.)
/// instructions. Similarly encoded to ARM32 but only used on a subset of
/// instructions (not universally conditional like ARM32).
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
    /// Always (alternative encoding)
    NV,
}

impl ConditionCode {
    /// The 2-letter suffix used in assembly syntax.
    pub fn suffix(&self) -> &'static str {
        match self {
            ConditionCode::EQ => "eq",
            ConditionCode::NE => "ne",
            ConditionCode::CS => "cs",
            ConditionCode::CC => "cc",
            ConditionCode::MI => "mi",
            ConditionCode::PL => "pl",
            ConditionCode::VS => "vs",
            ConditionCode::VC => "vc",
            ConditionCode::HI => "hi",
            ConditionCode::LS => "ls",
            ConditionCode::GE => "ge",
            ConditionCode::LT => "lt",
            ConditionCode::GT => "gt",
            ConditionCode::LE => "le",
            ConditionCode::AL => "al",
            ConditionCode::NV => "nv",
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
}

impl std::fmt::Display for ConditionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.suffix())
    }
}

// ============================================================================
// Shift Types
// ============================================================================

/// Shift types used in AArch64 data-processing instructions.
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
    /// Rotate right with extend (MSB.B = C flag) -- deprecated alias for EXTR
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

    pub fn encoding(&self) -> u8 {
        match self {
            ShiftType::LSL => 0b00,
            ShiftType::LSR => 0b01,
            ShiftType::ASR => 0b10,
            ShiftType::ROR => 0b11,
            ShiftType::RRX => 0b00,
        }
    }
}

// ============================================================================
// Extend Types
// ============================================================================

/// Register extension types for address generation and data processing.
///
/// Used with the `extend` operand modifier: e.g., `ADD X0, X1, W2, UXTB #2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtendType {
    /// Unsigned extend byte (bits 7..0 zero-extended)
    UXTB,
    /// Unsigned extend halfword (bits 15..0 zero-extended)
    UXTH,
    /// Unsigned extend word (bits 31..0 zero-extended)
    UXTW,
    /// Unsigned extend doubleword (bits 63..0, no actual extension)
    UXTX,
    /// Signed extend byte (bits 7..0 sign-extended)
    SXTB,
    /// Signed extend halfword (bits 15..0 sign-extended)
    SXTH,
    /// Signed extend word (bits 31..0 sign-extended)
    SXTW,
    /// Signed extend doubleword (bits 63..0, no actual extension)
    SXTX,
}

impl ExtendType {
    pub fn suffix(&self) -> &'static str {
        match self {
            ExtendType::UXTB => "UXTB",
            ExtendType::UXTH => "UXTH",
            ExtendType::UXTW => "UXTW",
            ExtendType::UXTX => "UXTX",
            ExtendType::SXTB => "SXTB",
            ExtendType::SXTH => "SXTH",
            ExtendType::SXTW => "SXTW",
            ExtendType::SXTX => "SXTX",
        }
    }

    pub fn encoding(&self) -> u8 {
        match self {
            ExtendType::UXTB => 0b000,
            ExtendType::UXTH => 0b001,
            ExtendType::UXTW => 0b010,
            ExtendType::UXTX => 0b011,
            ExtendType::SXTB => 0b100,
            ExtendType::SXTH => 0b101,
            ExtendType::SXTW => 0b110,
            ExtendType::SXTX => 0b111,
        }
    }
}

// ============================================================================
// Addressing Modes
// ============================================================================

/// AArch64 addressing mode categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressingMode {
    /// Register direct
    RegisterDirect,
    /// Immediate (e.g., #imm12 for arithmetic, #imm for MOVZ/MOVK)
    Immediate,
    /// Base register only: [Xn|SP]
    BaseRegister,
    /// Base + unsigned immediate offset: [Xn|SP, #imm]
    BasePlusImm,
    /// Base + register offset: [Xn|SP, Xm, extend]
    BasePlusRegister,
    /// Pre-indexed: [Xn|SP, #imm]!
    PreIndexed,
    /// Post-indexed: [Xn|SP], #imm
    PostIndexed,
    /// PC-relative (literal): [PC, #imm]
    PcRelative,
    /// Register pair: [Xn, Xm] (for LDP/STP)
    RegisterPair,
    /// SIMD structure load/store (element lists)
    SimdStructure,
    /// Register list (for LD1/LD2/LD3/LD4, ST1/ST2/ST3/ST4)
    RegisterList,
    /// System register direct
    SystemRegister,
    /// Exclusive access
    Exclusive,
    /// Acquire/Release semantics
    AcquireRelease,
}

impl AddressingMode {
    pub fn name(&self) -> &'static str {
        match self {
            AddressingMode::RegisterDirect => "RegisterDirect",
            AddressingMode::Immediate => "Immediate",
            AddressingMode::BaseRegister => "BaseRegister",
            AddressingMode::BasePlusImm => "BasePlusImm",
            AddressingMode::BasePlusRegister => "BasePlusRegister",
            AddressingMode::PreIndexed => "PreIndexed",
            AddressingMode::PostIndexed => "PostIndexed",
            AddressingMode::PcRelative => "PcRelative",
            AddressingMode::RegisterPair => "RegisterPair",
            AddressingMode::SimdStructure => "SimdStructure",
            AddressingMode::RegisterList => "RegisterList",
            AddressingMode::SystemRegister => "SystemRegister",
            AddressingMode::Exclusive => "Exclusive",
            AddressingMode::AcquireRelease => "AcquireRelease",
        }
    }
}

// ============================================================================
// AARCH64 Instruction Mnemonic
// ============================================================================

/// Complete AArch64 instruction mnemonic enumeration.
///
/// Covers the A64 ISA across ARMv8.x and ARMv9.x, organized by functional
/// category. Includes data processing, load/store, branch, exception,
/// system, SIMD/FP, and cryptographic instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Aarch64Mnemonic {
    // Data Processing -- Immediate
    ADD_IMM,
    ADDS_IMM,
    SUB_IMM,
    SUBS_IMM,
    AND_IMM,
    ANDS_IMM,
    EOR_IMM,
    ORR_IMM,
    MOVN,
    MOVZ,
    MOVK,
    ADR,
    ADRP,

    // Data Processing -- Register
    ADD_REG,
    ADDS_REG,
    SUB_REG,
    SUBS_REG,
    AND_REG,
    ANDS_REG,
    BIC_REG,
    BICS_REG,
    EOR_REG,
    EON_REG,
    ORR_REG,
    ORN_REG,
    ADC,
    ADCS,
    SBC,
    SBCS,
    NEG,
    NEGS,
    NGC,
    NGCS,
    CMP,
    CMN,
    TST,

    // Data Processing -- Shifted Register
    ADD_SHIFT,
    ADDS_SHIFT,
    SUB_SHIFT,
    SUBS_SHIFT,
    AND_SHIFT,
    ANDS_SHIFT,
    BIC_SHIFT,
    EOR_SHIFT,
    ORR_SHIFT,
    ORN_SHIFT,
    EON_SHIFT,
    LSLV,
    LSRV,
    ASRV,
    RORV,

    // Bitfield
    BFM,
    SBFM,
    UBFM,
    BFI,
    BFXIL,
    SBFIZ,
    SBFX,
    UBFIZ,
    UBFX,

    // Extract
    EXTR,

    // Conditional Compare / Conditional Select
    CCMN,
    CCMP,
    CSEL,
    CSINC,
    CSINV,
    CSNEG,

    // Logical
    AND_LOG,
    BIC_LOG,
    ORR_LOG,
    ORN_LOG,
    EOR_LOG,
    EON_LOG,
    MOV_LOG,

    // Move Wide Immediate
    MOVN_WIDE,
    MOVZ_WIDE,
    MOVK_WIDE,

    // Address Generation
    ADR_AG,
    ADRP_AG,

    // Multiply and Divide
    MUL,
    MNEG,
    MADD,
    MSUB,
    SMADDL,
    SMSUBL,
    SMULH,
    UMADDL,
    UMSUBL,
    UMULH,
    SDIV,
    UDIV,

    // CRC32
    CRC32B,
    CRC32H,
    CRC32W,
    CRC32X,
    CRC32CB,
    CRC32CH,
    CRC32CW,
    CRC32CX,

    // Bit Manipulation
    CLZ,
    CLS,
    RBIT,
    REV,
    REV16,
    REV32,
    REV64,

    // Load/Store -- Register
    LDR,
    LDRB,
    LDRH,
    LDRSB,
    LDRSH,
    LDRSW,
    STR,
    STRB,
    STRH,
    LDR_REG,
    LDRB_REG,
    LDRH_REG,
    LDRSB_REG,
    LDRSH_REG,
    LDRSW_REG,
    STR_REG,
    STRB_REG,
    STRH_REG,

    // Load/Store -- Unsigned Immediate
    LDUR,
    LDURB,
    LDURH,
    LDURSB,
    LDURSH,
    LDURSW,
    STUR,
    STURB,
    STURH,

    // Load/Store -- Pair
    LDP,
    LDPSW,
    STP,
    LDP_POST,
    LDP_PRE,
    STP_POST,
    STP_PRE,

    // Load/Store -- Exclusive
    LDXR,
    LDXRB,
    LDXRH,
    STXR,
    STXRB,
    STXRH,
    LDAXR,
    LDAXRB,
    LDAXRH,
    STLXR,
    STLXRB,
    STLXRH,
    LDXP,
    STXP,
    LDAXP,
    STLXP,
    CAS,
    CASA,
    CASL,
    CASAL,
    CASB,
    CASAB,
    CASLB,
    CASALB,
    CASH,
    CASAH,
    CASLH,
    CASALH,
    SWP,
    SWPA,
    SWPL,
    SWPAL,
    SWPB,
    SWPAB,
    SWPLB,
    SWPALB,
    SWPH,
    SWPAH,
    SWPLH,
    SWPALH,
    LDADD,
    LDADDA,
    LDADDL,
    LDADDAL,
    LDADDB,
    LDADDAB,
    LDADDLB,
    LDADDALB,
    LDADDH,
    LDADDAH,
    LDADDLH,
    LDADDALH,

    // Load/Store -- Acquire/Release
    LDAR,
    LDARB,
    LDARH,
    STLR,
    STLRB,
    STLRH,

    // Load Literal
    LDR_LIT,
    LDRSW_LIT,
    LDR_LIT_32,
    LDR_LIT_64,

    // Branch
    B_COND,
    B,
    BL,
    BR,
    BLR,
    RET,
    RET_LR,
    CBZ,
    CBNZ,
    TBZ,
    TBNZ,

    // Exception
    SVC,
    HVC,
    SMC,
    BRK,
    HLT,
    DCPS1,
    DCPS2,
    DCPS3,

    // System
    MSR_REG,
    MSR_IMM,
    MRS,
    SYS,
    SYSL,
    ISB,
    DSB,
    DMB,
    WFI,
    WFE,
    SEV,
    SEVL,
    YIELD,
    CLREX_64,
    NOP_64,
    HINT,

    // Return from Exception
    ERET,
    ERETAA,
    ERETAB,

    // Pointer Authentication
    PACIA,
    PACIA1716,
    PACIASP,
    PACIAZ,
    PACIB,
    PACIB1716,
    PACIBSP,
    PACIBZ,
    AUTIA,
    AUTIA1716,
    AUTIASP,
    AUTIAZ,
    AUTIB,
    AUTIB1716,
    AUTIBSP,
    AUTIBZ,
    PACGA,
    XPACI,
    XPACD,

    // Branch Target Identification
    BTIC,

    // SIMD/FP -- Data Processing (Scalar)
    FADD_S,
    FSUB_S,
    FMUL_S,
    FDIV_S,
    FADD_D,
    FSUB_D,
    FMUL_D,
    FDIV_D,
    FABS_S,
    FABS_D,
    FNEG_S,
    FNEG_D,
    FSQRT_S,
    FSQRT_D,
    FNMADD_S,
    FNMADD_D,
    FNMSUB_S,
    FNMSUB_D,
    FMADD_S,
    FMADD_D,
    FMSUB_S,
    FMSUB_D,
    FMAX_S,
    FMAX_D,
    FMIN_S,
    FMIN_D,
    FMAXNM_S,
    FMAXNM_D,
    FMINNM_S,
    FMINNM_D,

    // SIMD/FP -- Compare (Scalar)
    FCMP_S,
    FCMP_D,
    FCMPE_S,
    FCMPE_D,
    FCMPZ_S,
    FCMPZ_D,
    FCMPEZ_S,
    FCMPEZ_D,
    FCCMP_S,
    FCCMP_D,
    FCCMPE_S,
    FCCMPE_D,

    // SIMD/FP -- Conditional Select
    FCSEL_S,
    FCSEL_D,

    // SIMD/FP -- Conversion (Scalar)
    FCVT_S_D,
    FCVT_D_S,
    FCVTAS,
    FCVTAU,
    FCVTMS,
    FCVTMU,
    FCVTNS,
    FCVTNU,
    FCVTPS,
    FCVTPU,
    FCVTZS,
    FCVTZU,
    SCVTF,
    UCVTF,
    FMOV_S,
    FMOV_D,
    FMOV_GP_S,
    FMOV_GP_D,
    FMOV_S_GP,
    FMOV_D_GP,
    FMOV_GP_64,
    FMOV_GP_64_REV,
    FMOV_GP_TOP,

    // SIMD/FP -- Rounding (Scalar)
    FRINTA_S,
    FRINTA_D,
    FRINTI_S,
    FRINTI_D,
    FRINTM_S,
    FRINTM_D,
    FRINTN_S,
    FRINTN_D,
    FRINTP_S,
    FRINTP_D,
    FRINTX_S,
    FRINTX_D,
    FRINTZ_S,
    FRINTZ_D,

    // SIMD -- Vector Arithmetic
    ADD_V,
    SUB_V,
    MUL_V,
    MLA_V,
    MLS_V,
    SABA_V,
    UABA_V,
    SABD_V,
    UABD_V,
    SMAX_V,
    SMIN_V,
    UMAX_V,
    UMIN_V,
    SMAXP_V,
    SMINP_V,
    UMAXP_V,
    UMINP_V,
    SADDL_V,
    SADDW_V,
    UADDL_V,
    UADDW_V,
    SSUBL_V,
    SSUBW_V,
    USUBL_V,
    USUBW_V,
    SMULL_V,
    UMULL_V,
    SMLAL_V,
    UMLAL_V,
    SMLSL_V,
    UMLSL_V,
    SADDLP_V,
    UADDLP_V,
    SADALP_V,
    UADALP_V,
    ADDV,
    SADDLV,
    UADDLV,
    SMAXV,
    SMINV,
    UMAXV,
    UMINV,

    // SIMD -- Vector Shift
    SHL_V,
    SSHL_V,
    USHL_V,
    SHRN_V,
    SHRN2_V,
    SQSHRN_V,
    SQSHRN2_V,
    UQSHRN_V,
    UQSHRN2_V,
    SQRSHRN_V,
    SQRSHRN2_V,
    UQRSHRN_V,
    UQRSHRN2_V,
    SSHLL_V,
    SSHLL2_V,
    USHLL_V,
    USHLL2_V,
    SSRA_V,
    USRA_V,
    SRSRA_V,
    URSRA_V,
    SLI_V,
    SRI_V,
    SHLL_V,
    SHLL2_V,

    // SIMD -- Vector Logical
    AND_V,
    BIC_V,
    ORR_V,
    ORN_V,
    EOR_V,
    BSL_V,
    BIT_V,
    BIF_V,
    MVN_V,
    NOT_V,
    MOV_V,
    MOVI_V,
    MVNI_V,

    // SIMD -- Vector Compare
    CMEQ_V,
    CMGE_V,
    CMGT_V,
    CMLE_V,
    CMLT_V,
    CMHI_V,
    CMHS_V,
    CMTST_V,
    FCMEQ_V,
    FCMGE_V,
    FCMGT_V,
    FCMLE_V,
    FCMLT_V,
    FACGE_V,
    FACGT_V,

    // SIMD -- Vector Floating-Point
    FADD_V,
    FSUB_V,
    FMUL_V,
    FDIV_V,
    FMLA_V,
    FMLS_V,
    FMAX_V,
    FMIN_V,
    FMAXNM_V,
    FMINNM_V,
    FABD_V,
    FABS_V,
    FNEG_V,
    FSQRT_V,
    FRINTA_V,
    FRINTI_V,
    FRINTM_V,
    FRINTN_V,
    FRINTP_V,
    FRINTX_V,
    FRINTZ_V,
    FCVTAS_V,
    FCVTAU_V,
    FCVTMS_V,
    FCVTMU_V,
    FCVTNS_V,
    FCVTNU_V,
    FCVTPS_V,
    FCVTPU_V,
    FCVTZS_V,
    FCVTZU_V,
    SCVTF_V,
    UCVTF_V,
    FRECPE_V,
    FRECPS_V,
    FRSQRTE_V,
    FRSQRTS_V,

    // SIMD -- Vector Misc
    EXT_V,
    DUP_V,
    DUP_ELEM,
    INS_ELEM,
    INS_GEN,
    SMOV,
    UMOV,
    TBL_V,
    TBX_V,
    TRN1_V,
    TRN2_V,
    ZIP1_V,
    ZIP2_V,
    UZP1_V,
    UZP2_V,
    REV16_V,
    REV32_V,
    REV64_V,
    XTN_V,
    XTN2_V,
    SQXTN_V,
    SQXTN2_V,
    UQXTN_V,
    UQXTN2_V,
    SQXTUN_V,
    SQXTUN2_V,
    CNT_V,
    CLS_V,
    CLZ_V,
    RBIT_V,
    ABS_V,
    NEG_V,

    // SIMD -- Load/Store Structure
    LD1,
    LD1R,
    LD2,
    LD2R,
    LD3,
    LD3R,
    LD4,
    LD4R,
    ST1,
    ST2,
    ST3,
    ST4,

    // Cryptographic Extensions
    AESD_64,
    AESE_64,
    AESIMC_64,
    AESMC_64,
    SHA1C_64,
    SHA1P_64,
    SHA1M_64,
    SHA1H_64,
    SHA1SU0_64,
    SHA1SU1_64,
    SHA256H_64,
    SHA256H2_64,
    SHA256SU0_64,
    SHA256SU1_64,
    SHA512H,
    SHA512H2,
    SHA512SU0,
    SHA512SU1,
    SM3PARTW1,
    SM3PARTW2,
    SM3SS1,
    SM3TT1A,
    SM3TT1B,
    SM3TT2A,
    SM3TT2B,
    SM4E,
    SM4ENCKEY,
    EOR3,
    RAX1,
    XAR,
    BCAX,

    // Memory Barriers and Cache
    PRFM,
    PRFUM,
    DC,
    IC,

    // Floating-point immediate
    FMOV_IMM_S,
    FMOV_IMM_D,
}

impl Aarch64Mnemonic {
    /// The assembly mnemonic string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Aarch64Mnemonic::ADD_IMM => "ADD",
            Aarch64Mnemonic::ADDS_IMM => "ADDS",
            Aarch64Mnemonic::SUB_IMM => "SUB",
            Aarch64Mnemonic::SUBS_IMM => "SUBS",
            Aarch64Mnemonic::AND_IMM => "AND",
            Aarch64Mnemonic::ANDS_IMM => "ANDS",
            Aarch64Mnemonic::EOR_IMM => "EOR",
            Aarch64Mnemonic::ORR_IMM => "ORR",
            Aarch64Mnemonic::MOVN => "MOVN",
            Aarch64Mnemonic::MOVZ => "MOVZ",
            Aarch64Mnemonic::MOVK => "MOVK",
            Aarch64Mnemonic::ADR => "ADR",
            Aarch64Mnemonic::ADRP => "ADRP",
            Aarch64Mnemonic::ADD_REG => "ADD",
            Aarch64Mnemonic::ADDS_REG => "ADDS",
            Aarch64Mnemonic::SUB_REG => "SUB",
            Aarch64Mnemonic::SUBS_REG => "SUBS",
            Aarch64Mnemonic::AND_REG => "AND",
            Aarch64Mnemonic::ANDS_REG => "ANDS",
            Aarch64Mnemonic::BIC_REG => "BIC",
            Aarch64Mnemonic::BICS_REG => "BICS",
            Aarch64Mnemonic::EOR_REG => "EOR",
            Aarch64Mnemonic::EON_REG => "EON",
            Aarch64Mnemonic::ORR_REG => "ORR",
            Aarch64Mnemonic::ORN_REG => "ORN",
            Aarch64Mnemonic::ADC => "ADC",
            Aarch64Mnemonic::ADCS => "ADCS",
            Aarch64Mnemonic::SBC => "SBC",
            Aarch64Mnemonic::SBCS => "SBCS",
            Aarch64Mnemonic::NEG => "NEG",
            Aarch64Mnemonic::NEGS => "NEGS",
            Aarch64Mnemonic::NGC => "NGC",
            Aarch64Mnemonic::NGCS => "NGCS",
            Aarch64Mnemonic::CMP => "CMP",
            Aarch64Mnemonic::CMN => "CMN",
            Aarch64Mnemonic::TST => "TST",
            Aarch64Mnemonic::ADD_SHIFT => "ADD",
            Aarch64Mnemonic::ADDS_SHIFT => "ADDS",
            Aarch64Mnemonic::SUB_SHIFT => "SUB",
            Aarch64Mnemonic::SUBS_SHIFT => "SUBS",
            Aarch64Mnemonic::AND_SHIFT => "AND",
            Aarch64Mnemonic::ANDS_SHIFT => "ANDS",
            Aarch64Mnemonic::BIC_SHIFT => "BIC",
            Aarch64Mnemonic::EOR_SHIFT => "EOR",
            Aarch64Mnemonic::ORR_SHIFT => "ORR",
            Aarch64Mnemonic::ORN_SHIFT => "ORN",
            Aarch64Mnemonic::EON_SHIFT => "EON",
            Aarch64Mnemonic::LSLV => "LSLV",
            Aarch64Mnemonic::LSRV => "LSRV",
            Aarch64Mnemonic::ASRV => "ASRV",
            Aarch64Mnemonic::RORV => "RORV",
            Aarch64Mnemonic::BFM => "BFM",
            Aarch64Mnemonic::SBFM => "SBFM",
            Aarch64Mnemonic::UBFM => "UBFM",
            Aarch64Mnemonic::BFI => "BFI",
            Aarch64Mnemonic::BFXIL => "BFXIL",
            Aarch64Mnemonic::SBFIZ => "SBFIZ",
            Aarch64Mnemonic::SBFX => "SBFX",
            Aarch64Mnemonic::UBFIZ => "UBFIZ",
            Aarch64Mnemonic::UBFX => "UBFX",
            Aarch64Mnemonic::EXTR => "EXTR",
            Aarch64Mnemonic::CCMN => "CCMN",
            Aarch64Mnemonic::CCMP => "CCMP",
            Aarch64Mnemonic::CSEL => "CSEL",
            Aarch64Mnemonic::CSINC => "CSINC",
            Aarch64Mnemonic::CSINV => "CSINV",
            Aarch64Mnemonic::CSNEG => "CSNEG",
            Aarch64Mnemonic::AND_LOG => "AND",
            Aarch64Mnemonic::BIC_LOG => "BIC",
            Aarch64Mnemonic::ORR_LOG => "ORR",
            Aarch64Mnemonic::ORN_LOG => "ORN",
            Aarch64Mnemonic::EOR_LOG => "EOR",
            Aarch64Mnemonic::EON_LOG => "EON",
            Aarch64Mnemonic::MOV_LOG => "MOV",
            Aarch64Mnemonic::MOVN_WIDE => "MOVN",
            Aarch64Mnemonic::MOVZ_WIDE => "MOVZ",
            Aarch64Mnemonic::MOVK_WIDE => "MOVK",
            Aarch64Mnemonic::ADR_AG => "ADR",
            Aarch64Mnemonic::ADRP_AG => "ADRP",
            Aarch64Mnemonic::MUL => "MUL",
            Aarch64Mnemonic::MNEG => "MNEG",
            Aarch64Mnemonic::MADD => "MADD",
            Aarch64Mnemonic::MSUB => "MSUB",
            Aarch64Mnemonic::SMADDL => "SMADDL",
            Aarch64Mnemonic::SMSUBL => "SMSUBL",
            Aarch64Mnemonic::SMULH => "SMULH",
            Aarch64Mnemonic::UMADDL => "UMADDL",
            Aarch64Mnemonic::UMSUBL => "UMSUBL",
            Aarch64Mnemonic::UMULH => "UMULH",
            Aarch64Mnemonic::SDIV => "SDIV",
            Aarch64Mnemonic::UDIV => "UDIV",
            Aarch64Mnemonic::CRC32B => "CRC32B",
            Aarch64Mnemonic::CRC32H => "CRC32H",
            Aarch64Mnemonic::CRC32W => "CRC32W",
            Aarch64Mnemonic::CRC32X => "CRC32X",
            Aarch64Mnemonic::CRC32CB => "CRC32CB",
            Aarch64Mnemonic::CRC32CH => "CRC32CH",
            Aarch64Mnemonic::CRC32CW => "CRC32CW",
            Aarch64Mnemonic::CRC32CX => "CRC32CX",
            Aarch64Mnemonic::CLZ => "CLZ",
            Aarch64Mnemonic::CLS => "CLS",
            Aarch64Mnemonic::RBIT => "RBIT",
            Aarch64Mnemonic::REV => "REV",
            Aarch64Mnemonic::REV16 => "REV16",
            Aarch64Mnemonic::REV32 => "REV32",
            Aarch64Mnemonic::REV64 => "REV64",
            Aarch64Mnemonic::LDR => "LDR",
            Aarch64Mnemonic::LDRB => "LDRB",
            Aarch64Mnemonic::LDRH => "LDRH",
            Aarch64Mnemonic::LDRSB => "LDRSB",
            Aarch64Mnemonic::LDRSH => "LDRSH",
            Aarch64Mnemonic::LDRSW => "LDRSW",
            Aarch64Mnemonic::STR => "STR",
            Aarch64Mnemonic::STRB => "STRB",
            Aarch64Mnemonic::STRH => "STRH",
            Aarch64Mnemonic::LDR_REG => "LDR",
            Aarch64Mnemonic::LDRB_REG => "LDRB",
            Aarch64Mnemonic::LDRH_REG => "LDRH",
            Aarch64Mnemonic::LDRSB_REG => "LDRSB",
            Aarch64Mnemonic::LDRSH_REG => "LDRSH",
            Aarch64Mnemonic::LDRSW_REG => "LDRSW",
            Aarch64Mnemonic::STR_REG => "STR",
            Aarch64Mnemonic::STRB_REG => "STRB",
            Aarch64Mnemonic::STRH_REG => "STRH",
            Aarch64Mnemonic::LDUR => "LDUR",
            Aarch64Mnemonic::LDURB => "LDURB",
            Aarch64Mnemonic::LDURH => "LDURH",
            Aarch64Mnemonic::LDURSB => "LDURSB",
            Aarch64Mnemonic::LDURSH => "LDURSH",
            Aarch64Mnemonic::LDURSW => "LDURSW",
            Aarch64Mnemonic::STUR => "STUR",
            Aarch64Mnemonic::STURB => "STURB",
            Aarch64Mnemonic::STURH => "STURH",
            Aarch64Mnemonic::LDP => "LDP",
            Aarch64Mnemonic::LDPSW => "LDPSW",
            Aarch64Mnemonic::STP => "STP",
            Aarch64Mnemonic::LDP_POST => "LDP",
            Aarch64Mnemonic::LDP_PRE => "LDP",
            Aarch64Mnemonic::STP_POST => "STP",
            Aarch64Mnemonic::STP_PRE => "STP",
            Aarch64Mnemonic::LDXR => "LDXR",
            Aarch64Mnemonic::LDXRB => "LDXRB",
            Aarch64Mnemonic::LDXRH => "LDXRH",
            Aarch64Mnemonic::STXR => "STXR",
            Aarch64Mnemonic::STXRB => "STXRB",
            Aarch64Mnemonic::STXRH => "STXRH",
            Aarch64Mnemonic::LDAXR => "LDAXR",
            Aarch64Mnemonic::LDAXRB => "LDAXRB",
            Aarch64Mnemonic::LDAXRH => "LDAXRH",
            Aarch64Mnemonic::STLXR => "STLXR",
            Aarch64Mnemonic::STLXRB => "STLXRB",
            Aarch64Mnemonic::STLXRH => "STLXRH",
            Aarch64Mnemonic::LDXP => "LDXP",
            Aarch64Mnemonic::STXP => "STXP",
            Aarch64Mnemonic::LDAXP => "LDAXP",
            Aarch64Mnemonic::STLXP => "STLXP",
            Aarch64Mnemonic::CAS => "CAS",
            Aarch64Mnemonic::CASA => "CASA",
            Aarch64Mnemonic::CASL => "CASL",
            Aarch64Mnemonic::CASAL => "CASAL",
            Aarch64Mnemonic::CASB => "CASB",
            Aarch64Mnemonic::CASAB => "CASAB",
            Aarch64Mnemonic::CASLB => "CASLB",
            Aarch64Mnemonic::CASALB => "CASALB",
            Aarch64Mnemonic::CASH => "CASH",
            Aarch64Mnemonic::CASAH => "CASAH",
            Aarch64Mnemonic::CASLH => "CASLH",
            Aarch64Mnemonic::CASALH => "CASALH",
            Aarch64Mnemonic::SWP => "SWP",
            Aarch64Mnemonic::SWPA => "SWPA",
            Aarch64Mnemonic::SWPL => "SWPL",
            Aarch64Mnemonic::SWPAL => "SWPAL",
            Aarch64Mnemonic::SWPB => "SWPB",
            Aarch64Mnemonic::SWPAB => "SWPAB",
            Aarch64Mnemonic::SWPLB => "SWPLB",
            Aarch64Mnemonic::SWPALB => "SWPALB",
            Aarch64Mnemonic::SWPH => "SWPH",
            Aarch64Mnemonic::SWPAH => "SWPAH",
            Aarch64Mnemonic::SWPLH => "SWPLH",
            Aarch64Mnemonic::SWPALH => "SWPALH",
            Aarch64Mnemonic::LDADD => "LDADD",
            Aarch64Mnemonic::LDADDA => "LDADDA",
            Aarch64Mnemonic::LDADDL => "LDADDL",
            Aarch64Mnemonic::LDADDAL => "LDADDAL",
            Aarch64Mnemonic::LDADDB => "LDADDB",
            Aarch64Mnemonic::LDADDAB => "LDADDAB",
            Aarch64Mnemonic::LDADDLB => "LDADDLB",
            Aarch64Mnemonic::LDADDALB => "LDADDALB",
            Aarch64Mnemonic::LDADDH => "LDADDH",
            Aarch64Mnemonic::LDADDAH => "LDADDAH",
            Aarch64Mnemonic::LDADDLH => "LDADDLH",
            Aarch64Mnemonic::LDADDALH => "LDADDALH",
            Aarch64Mnemonic::LDAR => "LDAR",
            Aarch64Mnemonic::LDARB => "LDARB",
            Aarch64Mnemonic::LDARH => "LDARH",
            Aarch64Mnemonic::STLR => "STLR",
            Aarch64Mnemonic::STLRB => "STLRB",
            Aarch64Mnemonic::STLRH => "STLRH",
            Aarch64Mnemonic::LDR_LIT => "LDR",
            Aarch64Mnemonic::LDRSW_LIT => "LDRSW",
            Aarch64Mnemonic::LDR_LIT_32 => "LDR",
            Aarch64Mnemonic::LDR_LIT_64 => "LDR",
            Aarch64Mnemonic::B_COND => "B.cond",
            Aarch64Mnemonic::B => "B",
            Aarch64Mnemonic::BL => "BL",
            Aarch64Mnemonic::BR => "BR",
            Aarch64Mnemonic::BLR => "BLR",
            Aarch64Mnemonic::RET => "RET",
            Aarch64Mnemonic::RET_LR => "RET",
            Aarch64Mnemonic::CBZ => "CBZ",
            Aarch64Mnemonic::CBNZ => "CBNZ",
            Aarch64Mnemonic::TBZ => "TBZ",
            Aarch64Mnemonic::TBNZ => "TBNZ",
            Aarch64Mnemonic::SVC => "SVC",
            Aarch64Mnemonic::HVC => "HVC",
            Aarch64Mnemonic::SMC => "SMC",
            Aarch64Mnemonic::BRK => "BRK",
            Aarch64Mnemonic::HLT => "HLT",
            Aarch64Mnemonic::DCPS1 => "DCPS1",
            Aarch64Mnemonic::DCPS2 => "DCPS2",
            Aarch64Mnemonic::DCPS3 => "DCPS3",
            Aarch64Mnemonic::MSR_REG => "MSR",
            Aarch64Mnemonic::MSR_IMM => "MSR",
            Aarch64Mnemonic::MRS => "MRS",
            Aarch64Mnemonic::SYS => "SYS",
            Aarch64Mnemonic::SYSL => "SYSL",
            Aarch64Mnemonic::ISB => "ISB",
            Aarch64Mnemonic::DSB => "DSB",
            Aarch64Mnemonic::DMB => "DMB",
            Aarch64Mnemonic::WFI => "WFI",
            Aarch64Mnemonic::WFE => "WFE",
            Aarch64Mnemonic::SEV => "SEV",
            Aarch64Mnemonic::SEVL => "SEVL",
            Aarch64Mnemonic::YIELD => "YIELD",
            Aarch64Mnemonic::CLREX_64 => "CLREX",
            Aarch64Mnemonic::NOP_64 => "NOP",
            Aarch64Mnemonic::HINT => "HINT",
            Aarch64Mnemonic::ERET => "ERET",
            Aarch64Mnemonic::ERETAA => "ERETAA",
            Aarch64Mnemonic::ERETAB => "ERETAB",
            Aarch64Mnemonic::PACIA => "PACIA",
            Aarch64Mnemonic::PACIA1716 => "PACIA1716",
            Aarch64Mnemonic::PACIASP => "PACIASP",
            Aarch64Mnemonic::PACIAZ => "PACIAZ",
            Aarch64Mnemonic::PACIB => "PACIB",
            Aarch64Mnemonic::PACIB1716 => "PACIB1716",
            Aarch64Mnemonic::PACIBSP => "PACIBSP",
            Aarch64Mnemonic::PACIBZ => "PACIBZ",
            Aarch64Mnemonic::AUTIA => "AUTIA",
            Aarch64Mnemonic::AUTIA1716 => "AUTIA1716",
            Aarch64Mnemonic::AUTIASP => "AUTIASP",
            Aarch64Mnemonic::AUTIAZ => "AUTIAZ",
            Aarch64Mnemonic::AUTIB => "AUTIB",
            Aarch64Mnemonic::AUTIB1716 => "AUTIB1716",
            Aarch64Mnemonic::AUTIBSP => "AUTIBSP",
            Aarch64Mnemonic::AUTIBZ => "AUTIBZ",
            Aarch64Mnemonic::PACGA => "PACGA",
            Aarch64Mnemonic::XPACI => "XPACI",
            Aarch64Mnemonic::XPACD => "XPACD",
            Aarch64Mnemonic::BTIC => "BTI",
            Aarch64Mnemonic::FADD_S => "FADD",
            Aarch64Mnemonic::FSUB_S => "FSUB",
            Aarch64Mnemonic::FMUL_S => "FMUL",
            Aarch64Mnemonic::FDIV_S => "FDIV",
            Aarch64Mnemonic::FADD_D => "FADD",
            Aarch64Mnemonic::FSUB_D => "FSUB",
            Aarch64Mnemonic::FMUL_D => "FMUL",
            Aarch64Mnemonic::FDIV_D => "FDIV",
            Aarch64Mnemonic::FABS_S => "FABS",
            Aarch64Mnemonic::FABS_D => "FABS",
            Aarch64Mnemonic::FNEG_S => "FNEG",
            Aarch64Mnemonic::FNEG_D => "FNEG",
            Aarch64Mnemonic::FSQRT_S => "FSQRT",
            Aarch64Mnemonic::FSQRT_D => "FSQRT",
            Aarch64Mnemonic::FNMADD_S => "FNMADD",
            Aarch64Mnemonic::FNMADD_D => "FNMADD",
            Aarch64Mnemonic::FNMSUB_S => "FNMSUB",
            Aarch64Mnemonic::FNMSUB_D => "FNMSUB",
            Aarch64Mnemonic::FMADD_S => "FMADD",
            Aarch64Mnemonic::FMADD_D => "FMADD",
            Aarch64Mnemonic::FMSUB_S => "FMSUB",
            Aarch64Mnemonic::FMSUB_D => "FMSUB",
            Aarch64Mnemonic::FMAX_S => "FMAX",
            Aarch64Mnemonic::FMAX_D => "FMAX",
            Aarch64Mnemonic::FMIN_S => "FMIN",
            Aarch64Mnemonic::FMIN_D => "FMIN",
            Aarch64Mnemonic::FMAXNM_S => "FMAXNM",
            Aarch64Mnemonic::FMAXNM_D => "FMAXNM",
            Aarch64Mnemonic::FMINNM_S => "FMINNM",
            Aarch64Mnemonic::FMINNM_D => "FMINNM",
            Aarch64Mnemonic::FCMP_S => "FCMP",
            Aarch64Mnemonic::FCMP_D => "FCMP",
            Aarch64Mnemonic::FCMPE_S => "FCMPE",
            Aarch64Mnemonic::FCMPE_D => "FCMPE",
            Aarch64Mnemonic::FCMPZ_S => "FCMP",
            Aarch64Mnemonic::FCMPZ_D => "FCMP",
            Aarch64Mnemonic::FCMPEZ_S => "FCMPE",
            Aarch64Mnemonic::FCMPEZ_D => "FCMPE",
            Aarch64Mnemonic::FCCMP_S => "FCCMP",
            Aarch64Mnemonic::FCCMP_D => "FCCMP",
            Aarch64Mnemonic::FCCMPE_S => "FCCMPE",
            Aarch64Mnemonic::FCCMPE_D => "FCCMPE",
            Aarch64Mnemonic::FCSEL_S => "FCSEL",
            Aarch64Mnemonic::FCSEL_D => "FCSEL",
            Aarch64Mnemonic::FCVT_S_D => "FCVT",
            Aarch64Mnemonic::FCVT_D_S => "FCVT",
            Aarch64Mnemonic::FCVTAS => "FCVTAS",
            Aarch64Mnemonic::FCVTAU => "FCVTAU",
            Aarch64Mnemonic::FCVTMS => "FCVTMS",
            Aarch64Mnemonic::FCVTMU => "FCVTMU",
            Aarch64Mnemonic::FCVTNS => "FCVTNS",
            Aarch64Mnemonic::FCVTNU => "FCVTNU",
            Aarch64Mnemonic::FCVTPS => "FCVTPS",
            Aarch64Mnemonic::FCVTPU => "FCVTPU",
            Aarch64Mnemonic::FCVTZS => "FCVTZS",
            Aarch64Mnemonic::FCVTZU => "FCVTZU",
            Aarch64Mnemonic::SCVTF => "SCVTF",
            Aarch64Mnemonic::UCVTF => "UCVTF",
            Aarch64Mnemonic::FMOV_S => "FMOV",
            Aarch64Mnemonic::FMOV_D => "FMOV",
            Aarch64Mnemonic::FMOV_GP_S => "FMOV",
            Aarch64Mnemonic::FMOV_GP_D => "FMOV",
            Aarch64Mnemonic::FMOV_S_GP => "FMOV",
            Aarch64Mnemonic::FMOV_D_GP => "FMOV",
            Aarch64Mnemonic::FMOV_GP_64 => "FMOV",
            Aarch64Mnemonic::FMOV_GP_64_REV => "FMOV",
            Aarch64Mnemonic::FMOV_GP_TOP => "FMOV",
            Aarch64Mnemonic::FRINTA_S => "FRINTA",
            Aarch64Mnemonic::FRINTA_D => "FRINTA",
            Aarch64Mnemonic::FRINTI_S => "FRINTI",
            Aarch64Mnemonic::FRINTI_D => "FRINTI",
            Aarch64Mnemonic::FRINTM_S => "FRINTM",
            Aarch64Mnemonic::FRINTM_D => "FRINTM",
            Aarch64Mnemonic::FRINTN_S => "FRINTN",
            Aarch64Mnemonic::FRINTN_D => "FRINTN",
            Aarch64Mnemonic::FRINTP_S => "FRINTP",
            Aarch64Mnemonic::FRINTP_D => "FRINTP",
            Aarch64Mnemonic::FRINTX_S => "FRINTX",
            Aarch64Mnemonic::FRINTX_D => "FRINTX",
            Aarch64Mnemonic::FRINTZ_S => "FRINTZ",
            Aarch64Mnemonic::FRINTZ_D => "FRINTZ",
            Aarch64Mnemonic::ADD_V => "ADD",
            Aarch64Mnemonic::SUB_V => "SUB",
            Aarch64Mnemonic::MUL_V => "MUL",
            Aarch64Mnemonic::MLA_V => "MLA",
            Aarch64Mnemonic::MLS_V => "MLS",
            Aarch64Mnemonic::SABA_V => "SABA",
            Aarch64Mnemonic::UABA_V => "UABA",
            Aarch64Mnemonic::SABD_V => "SABD",
            Aarch64Mnemonic::UABD_V => "UABD",
            Aarch64Mnemonic::SMAX_V => "SMAX",
            Aarch64Mnemonic::SMIN_V => "SMIN",
            Aarch64Mnemonic::UMAX_V => "UMAX",
            Aarch64Mnemonic::UMIN_V => "UMIN",
            Aarch64Mnemonic::SMAXP_V => "SMAXP",
            Aarch64Mnemonic::SMINP_V => "SMINP",
            Aarch64Mnemonic::UMAXP_V => "UMAXP",
            Aarch64Mnemonic::UMINP_V => "UMINP",
            Aarch64Mnemonic::SADDL_V => "SADDL",
            Aarch64Mnemonic::SADDW_V => "SADDW",
            Aarch64Mnemonic::UADDL_V => "UADDL",
            Aarch64Mnemonic::UADDW_V => "UADDW",
            Aarch64Mnemonic::SSUBL_V => "SSUBL",
            Aarch64Mnemonic::SSUBW_V => "SSUBW",
            Aarch64Mnemonic::USUBL_V => "USUBL",
            Aarch64Mnemonic::USUBW_V => "USUBW",
            Aarch64Mnemonic::SMULL_V => "SMULL",
            Aarch64Mnemonic::UMULL_V => "UMULL",
            Aarch64Mnemonic::SMLAL_V => "SMLAL",
            Aarch64Mnemonic::UMLAL_V => "UMLAL",
            Aarch64Mnemonic::SMLSL_V => "SMLSL",
            Aarch64Mnemonic::UMLSL_V => "UMLSL",
            Aarch64Mnemonic::SADDLP_V => "SADDLP",
            Aarch64Mnemonic::UADDLP_V => "UADDLP",
            Aarch64Mnemonic::SADALP_V => "SADALP",
            Aarch64Mnemonic::UADALP_V => "UADALP",
            Aarch64Mnemonic::ADDV => "ADDV",
            Aarch64Mnemonic::SADDLV => "SADDLV",
            Aarch64Mnemonic::UADDLV => "UADDLV",
            Aarch64Mnemonic::SMAXV => "SMAXV",
            Aarch64Mnemonic::SMINV => "SMINV",
            Aarch64Mnemonic::UMAXV => "UMAXV",
            Aarch64Mnemonic::UMINV => "UMINV",
            Aarch64Mnemonic::SHL_V => "SHL",
            Aarch64Mnemonic::SSHL_V => "SSHL",
            Aarch64Mnemonic::USHL_V => "USHL",
            Aarch64Mnemonic::SHRN_V => "SHRN",
            Aarch64Mnemonic::SHRN2_V => "SHRN2",
            Aarch64Mnemonic::SQSHRN_V => "SQSHRN",
            Aarch64Mnemonic::SQSHRN2_V => "SQSHRN2",
            Aarch64Mnemonic::UQSHRN_V => "UQSHRN",
            Aarch64Mnemonic::UQSHRN2_V => "UQSHRN2",
            Aarch64Mnemonic::SQRSHRN_V => "SQRSHRN",
            Aarch64Mnemonic::SQRSHRN2_V => "SQRSHRN2",
            Aarch64Mnemonic::UQRSHRN_V => "UQRSHRN",
            Aarch64Mnemonic::UQRSHRN2_V => "UQRSHRN2",
            Aarch64Mnemonic::SSHLL_V => "SSHLL",
            Aarch64Mnemonic::SSHLL2_V => "SSHLL2",
            Aarch64Mnemonic::USHLL_V => "USHLL",
            Aarch64Mnemonic::USHLL2_V => "USHLL2",
            Aarch64Mnemonic::SSRA_V => "SSRA",
            Aarch64Mnemonic::USRA_V => "USRA",
            Aarch64Mnemonic::SRSRA_V => "SRSRA",
            Aarch64Mnemonic::URSRA_V => "URSRA",
            Aarch64Mnemonic::SLI_V => "SLI",
            Aarch64Mnemonic::SRI_V => "SRI",
            Aarch64Mnemonic::SHLL_V => "SHLL",
            Aarch64Mnemonic::SHLL2_V => "SHLL2",
            Aarch64Mnemonic::AND_V => "AND",
            Aarch64Mnemonic::BIC_V => "BIC",
            Aarch64Mnemonic::ORR_V => "ORR",
            Aarch64Mnemonic::ORN_V => "ORN",
            Aarch64Mnemonic::EOR_V => "EOR",
            Aarch64Mnemonic::BSL_V => "BSL",
            Aarch64Mnemonic::BIT_V => "BIT",
            Aarch64Mnemonic::BIF_V => "BIF",
            Aarch64Mnemonic::MVN_V => "MVN",
            Aarch64Mnemonic::NOT_V => "NOT",
            Aarch64Mnemonic::MOV_V => "MOV",
            Aarch64Mnemonic::MOVI_V => "MOVI",
            Aarch64Mnemonic::MVNI_V => "MVNI",
            Aarch64Mnemonic::CMEQ_V => "CMEQ",
            Aarch64Mnemonic::CMGE_V => "CMGE",
            Aarch64Mnemonic::CMGT_V => "CMGT",
            Aarch64Mnemonic::CMLE_V => "CMLE",
            Aarch64Mnemonic::CMLT_V => "CMLT",
            Aarch64Mnemonic::CMHI_V => "CMHI",
            Aarch64Mnemonic::CMHS_V => "CMHS",
            Aarch64Mnemonic::CMTST_V => "CMTST",
            Aarch64Mnemonic::FCMEQ_V => "FCMEQ",
            Aarch64Mnemonic::FCMGE_V => "FCMGE",
            Aarch64Mnemonic::FCMGT_V => "FCMGT",
            Aarch64Mnemonic::FCMLE_V => "FCMLE",
            Aarch64Mnemonic::FCMLT_V => "FCMLT",
            Aarch64Mnemonic::FACGE_V => "FACGE",
            Aarch64Mnemonic::FACGT_V => "FACGT",
            Aarch64Mnemonic::FADD_V => "FADD",
            Aarch64Mnemonic::FSUB_V => "FSUB",
            Aarch64Mnemonic::FMUL_V => "FMUL",
            Aarch64Mnemonic::FDIV_V => "FDIV",
            Aarch64Mnemonic::FMLA_V => "FMLA",
            Aarch64Mnemonic::FMLS_V => "FMLS",
            Aarch64Mnemonic::FMAX_V => "FMAX",
            Aarch64Mnemonic::FMIN_V => "FMIN",
            Aarch64Mnemonic::FMAXNM_V => "FMAXNM",
            Aarch64Mnemonic::FMINNM_V => "FMINNM",
            Aarch64Mnemonic::FABD_V => "FABD",
            Aarch64Mnemonic::FABS_V => "FABS",
            Aarch64Mnemonic::FNEG_V => "FNEG",
            Aarch64Mnemonic::FSQRT_V => "FSQRT",
            Aarch64Mnemonic::FRINTA_V => "FRINTA",
            Aarch64Mnemonic::FRINTI_V => "FRINTI",
            Aarch64Mnemonic::FRINTM_V => "FRINTM",
            Aarch64Mnemonic::FRINTN_V => "FRINTN",
            Aarch64Mnemonic::FRINTP_V => "FRINTP",
            Aarch64Mnemonic::FRINTX_V => "FRINTX",
            Aarch64Mnemonic::FRINTZ_V => "FRINTZ",
            Aarch64Mnemonic::FCVTAS_V => "FCVTAS",
            Aarch64Mnemonic::FCVTAU_V => "FCVTAU",
            Aarch64Mnemonic::FCVTMS_V => "FCVTMS",
            Aarch64Mnemonic::FCVTMU_V => "FCVTMU",
            Aarch64Mnemonic::FCVTNS_V => "FCVTNS",
            Aarch64Mnemonic::FCVTNU_V => "FCVTNU",
            Aarch64Mnemonic::FCVTPS_V => "FCVTPS",
            Aarch64Mnemonic::FCVTPU_V => "FCVTPU",
            Aarch64Mnemonic::FCVTZS_V => "FCVTZS",
            Aarch64Mnemonic::FCVTZU_V => "FCVTZU",
            Aarch64Mnemonic::SCVTF_V => "SCVTF",
            Aarch64Mnemonic::UCVTF_V => "UCVTF",
            Aarch64Mnemonic::FRECPE_V => "FRECPE",
            Aarch64Mnemonic::FRECPS_V => "FRECPS",
            Aarch64Mnemonic::FRSQRTE_V => "FRSQRTE",
            Aarch64Mnemonic::FRSQRTS_V => "FRSQRTS",
            Aarch64Mnemonic::EXT_V => "EXT",
            Aarch64Mnemonic::DUP_V => "DUP",
            Aarch64Mnemonic::DUP_ELEM => "DUP",
            Aarch64Mnemonic::INS_ELEM => "INS",
            Aarch64Mnemonic::INS_GEN => "INS",
            Aarch64Mnemonic::SMOV => "SMOV",
            Aarch64Mnemonic::UMOV => "UMOV",
            Aarch64Mnemonic::TBL_V => "TBL",
            Aarch64Mnemonic::TBX_V => "TBX",
            Aarch64Mnemonic::TRN1_V => "TRN1",
            Aarch64Mnemonic::TRN2_V => "TRN2",
            Aarch64Mnemonic::ZIP1_V => "ZIP1",
            Aarch64Mnemonic::ZIP2_V => "ZIP2",
            Aarch64Mnemonic::UZP1_V => "UZP1",
            Aarch64Mnemonic::UZP2_V => "UZP2",
            Aarch64Mnemonic::REV16_V => "REV16",
            Aarch64Mnemonic::REV32_V => "REV32",
            Aarch64Mnemonic::REV64_V => "REV64",
            Aarch64Mnemonic::XTN_V => "XTN",
            Aarch64Mnemonic::XTN2_V => "XTN2",
            Aarch64Mnemonic::SQXTN_V => "SQXTN",
            Aarch64Mnemonic::SQXTN2_V => "SQXTN2",
            Aarch64Mnemonic::UQXTN_V => "UQXTN",
            Aarch64Mnemonic::UQXTN2_V => "UQXTN2",
            Aarch64Mnemonic::SQXTUN_V => "SQXTUN",
            Aarch64Mnemonic::SQXTUN2_V => "SQXTUN2",
            Aarch64Mnemonic::CNT_V => "CNT",
            Aarch64Mnemonic::CLS_V => "CLS",
            Aarch64Mnemonic::CLZ_V => "CLZ",
            Aarch64Mnemonic::RBIT_V => "RBIT",
            Aarch64Mnemonic::ABS_V => "ABS",
            Aarch64Mnemonic::NEG_V => "NEG",
            Aarch64Mnemonic::LD1 => "LD1",
            Aarch64Mnemonic::LD1R => "LD1R",
            Aarch64Mnemonic::LD2 => "LD2",
            Aarch64Mnemonic::LD2R => "LD2R",
            Aarch64Mnemonic::LD3 => "LD3",
            Aarch64Mnemonic::LD3R => "LD3R",
            Aarch64Mnemonic::LD4 => "LD4",
            Aarch64Mnemonic::LD4R => "LD4R",
            Aarch64Mnemonic::ST1 => "ST1",
            Aarch64Mnemonic::ST2 => "ST2",
            Aarch64Mnemonic::ST3 => "ST3",
            Aarch64Mnemonic::ST4 => "ST4",
            Aarch64Mnemonic::AESD_64 => "AESD",
            Aarch64Mnemonic::AESE_64 => "AESE",
            Aarch64Mnemonic::AESIMC_64 => "AESIMC",
            Aarch64Mnemonic::AESMC_64 => "AESMC",
            Aarch64Mnemonic::SHA1C_64 => "SHA1C",
            Aarch64Mnemonic::SHA1P_64 => "SHA1P",
            Aarch64Mnemonic::SHA1M_64 => "SHA1M",
            Aarch64Mnemonic::SHA1H_64 => "SHA1H",
            Aarch64Mnemonic::SHA1SU0_64 => "SHA1SU0",
            Aarch64Mnemonic::SHA1SU1_64 => "SHA1SU1",
            Aarch64Mnemonic::SHA256H_64 => "SHA256H",
            Aarch64Mnemonic::SHA256H2_64 => "SHA256H2",
            Aarch64Mnemonic::SHA256SU0_64 => "SHA256SU0",
            Aarch64Mnemonic::SHA256SU1_64 => "SHA256SU1",
            Aarch64Mnemonic::SHA512H => "SHA512H",
            Aarch64Mnemonic::SHA512H2 => "SHA512H2",
            Aarch64Mnemonic::SHA512SU0 => "SHA512SU0",
            Aarch64Mnemonic::SHA512SU1 => "SHA512SU1",
            Aarch64Mnemonic::SM3PARTW1 => "SM3PARTW1",
            Aarch64Mnemonic::SM3PARTW2 => "SM3PARTW2",
            Aarch64Mnemonic::SM3SS1 => "SM3SS1",
            Aarch64Mnemonic::SM3TT1A => "SM3TT1A",
            Aarch64Mnemonic::SM3TT1B => "SM3TT1B",
            Aarch64Mnemonic::SM3TT2A => "SM3TT2A",
            Aarch64Mnemonic::SM3TT2B => "SM3TT2B",
            Aarch64Mnemonic::SM4E => "SM4E",
            Aarch64Mnemonic::SM4ENCKEY => "SM4ENCKEY",
            Aarch64Mnemonic::EOR3 => "EOR3",
            Aarch64Mnemonic::RAX1 => "RAX1",
            Aarch64Mnemonic::XAR => "XAR",
            Aarch64Mnemonic::BCAX => "BCAX",
            Aarch64Mnemonic::PRFM => "PRFM",
            Aarch64Mnemonic::PRFUM => "PRFUM",
            Aarch64Mnemonic::DC => "DC",
            Aarch64Mnemonic::IC => "IC",
            Aarch64Mnemonic::FMOV_IMM_S => "FMOV",
            Aarch64Mnemonic::FMOV_IMM_D => "FMOV",
        }
    }

    /// The instruction category.
    pub fn category(&self) -> InstructionCategory {
        match self {
            Aarch64Mnemonic::ADD_IMM
            | Aarch64Mnemonic::ADDS_IMM
            | Aarch64Mnemonic::SUB_IMM
            | Aarch64Mnemonic::SUBS_IMM
            | Aarch64Mnemonic::AND_IMM
            | Aarch64Mnemonic::ANDS_IMM
            | Aarch64Mnemonic::EOR_IMM
            | Aarch64Mnemonic::ORR_IMM
            | Aarch64Mnemonic::ADD_REG
            | Aarch64Mnemonic::ADDS_REG
            | Aarch64Mnemonic::SUB_REG
            | Aarch64Mnemonic::SUBS_REG
            | Aarch64Mnemonic::AND_REG
            | Aarch64Mnemonic::ANDS_REG
            | Aarch64Mnemonic::BIC_REG
            | Aarch64Mnemonic::BICS_REG
            | Aarch64Mnemonic::EOR_REG
            | Aarch64Mnemonic::EON_REG
            | Aarch64Mnemonic::ORR_REG
            | Aarch64Mnemonic::ORN_REG
            | Aarch64Mnemonic::ADC
            | Aarch64Mnemonic::ADCS
            | Aarch64Mnemonic::SBC
            | Aarch64Mnemonic::SBCS
            | Aarch64Mnemonic::NEG
            | Aarch64Mnemonic::NEGS
            | Aarch64Mnemonic::NGC
            | Aarch64Mnemonic::NGCS
            | Aarch64Mnemonic::CMP
            | Aarch64Mnemonic::CMN
            | Aarch64Mnemonic::TST
            | Aarch64Mnemonic::ADD_SHIFT
            | Aarch64Mnemonic::ADDS_SHIFT
            | Aarch64Mnemonic::SUB_SHIFT
            | Aarch64Mnemonic::SUBS_SHIFT
            | Aarch64Mnemonic::AND_SHIFT
            | Aarch64Mnemonic::ANDS_SHIFT
            | Aarch64Mnemonic::BIC_SHIFT
            | Aarch64Mnemonic::EOR_SHIFT
            | Aarch64Mnemonic::ORR_SHIFT
            | Aarch64Mnemonic::ORN_SHIFT
            | Aarch64Mnemonic::EON_SHIFT
            | Aarch64Mnemonic::MOVN
            | Aarch64Mnemonic::MOVZ
            | Aarch64Mnemonic::MOVK
            | Aarch64Mnemonic::LSLV
            | Aarch64Mnemonic::LSRV
            | Aarch64Mnemonic::ASRV
            | Aarch64Mnemonic::RORV
            | Aarch64Mnemonic::BFM
            | Aarch64Mnemonic::SBFM
            | Aarch64Mnemonic::UBFM
            | Aarch64Mnemonic::BFI
            | Aarch64Mnemonic::BFXIL
            | Aarch64Mnemonic::SBFIZ
            | Aarch64Mnemonic::SBFX
            | Aarch64Mnemonic::UBFIZ
            | Aarch64Mnemonic::UBFX
            | Aarch64Mnemonic::EXTR
            | Aarch64Mnemonic::MUL
            | Aarch64Mnemonic::MNEG
            | Aarch64Mnemonic::MADD
            | Aarch64Mnemonic::MSUB
            | Aarch64Mnemonic::SMADDL
            | Aarch64Mnemonic::SMSUBL
            | Aarch64Mnemonic::SMULH
            | Aarch64Mnemonic::UMADDL
            | Aarch64Mnemonic::UMSUBL
            | Aarch64Mnemonic::UMULH
            | Aarch64Mnemonic::SDIV
            | Aarch64Mnemonic::UDIV
            | Aarch64Mnemonic::CLZ
            | Aarch64Mnemonic::CLS
            | Aarch64Mnemonic::RBIT
            | Aarch64Mnemonic::REV
            | Aarch64Mnemonic::REV16
            | Aarch64Mnemonic::REV32
            | Aarch64Mnemonic::REV64
            | Aarch64Mnemonic::CRC32B
            | Aarch64Mnemonic::CRC32H
            | Aarch64Mnemonic::CRC32W
            | Aarch64Mnemonic::CRC32X
            | Aarch64Mnemonic::CRC32CB
            | Aarch64Mnemonic::CRC32CH
            | Aarch64Mnemonic::CRC32CW
            | Aarch64Mnemonic::CRC32CX => InstructionCategory::DataProcessing,
            Aarch64Mnemonic::CCMN
            | Aarch64Mnemonic::CCMP
            | Aarch64Mnemonic::CSEL
            | Aarch64Mnemonic::CSINC
            | Aarch64Mnemonic::CSINV
            | Aarch64Mnemonic::CSNEG => InstructionCategory::Conditional,
            Aarch64Mnemonic::ADR
            | Aarch64Mnemonic::ADRP
            | Aarch64Mnemonic::ADR_AG
            | Aarch64Mnemonic::ADRP_AG => InstructionCategory::AddressGen,
            Aarch64Mnemonic::LDR
            | Aarch64Mnemonic::LDRB
            | Aarch64Mnemonic::LDRH
            | Aarch64Mnemonic::LDRSB
            | Aarch64Mnemonic::LDRSH
            | Aarch64Mnemonic::LDRSW
            | Aarch64Mnemonic::STR
            | Aarch64Mnemonic::STRB
            | Aarch64Mnemonic::STRH
            | Aarch64Mnemonic::LDR_REG
            | Aarch64Mnemonic::LDRB_REG
            | Aarch64Mnemonic::LDRH_REG
            | Aarch64Mnemonic::LDRSB_REG
            | Aarch64Mnemonic::LDRSH_REG
            | Aarch64Mnemonic::LDRSW_REG
            | Aarch64Mnemonic::STR_REG
            | Aarch64Mnemonic::STRB_REG
            | Aarch64Mnemonic::STRH_REG
            | Aarch64Mnemonic::LDUR
            | Aarch64Mnemonic::LDURB
            | Aarch64Mnemonic::LDURH
            | Aarch64Mnemonic::LDURSB
            | Aarch64Mnemonic::LDURSH
            | Aarch64Mnemonic::LDURSW
            | Aarch64Mnemonic::STUR
            | Aarch64Mnemonic::STURB
            | Aarch64Mnemonic::STURH
            | Aarch64Mnemonic::LDP
            | Aarch64Mnemonic::LDPSW
            | Aarch64Mnemonic::STP
            | Aarch64Mnemonic::LDP_POST
            | Aarch64Mnemonic::LDP_PRE
            | Aarch64Mnemonic::STP_POST
            | Aarch64Mnemonic::STP_PRE
            | Aarch64Mnemonic::LDR_LIT
            | Aarch64Mnemonic::LDRSW_LIT
            | Aarch64Mnemonic::LDR_LIT_32
            | Aarch64Mnemonic::LDR_LIT_64 => InstructionCategory::LoadStore,
            Aarch64Mnemonic::LDXR
            | Aarch64Mnemonic::LDXRB
            | Aarch64Mnemonic::LDXRH
            | Aarch64Mnemonic::STXR
            | Aarch64Mnemonic::STXRB
            | Aarch64Mnemonic::STXRH
            | Aarch64Mnemonic::LDAXR
            | Aarch64Mnemonic::LDAXRB
            | Aarch64Mnemonic::LDAXRH
            | Aarch64Mnemonic::STLXR
            | Aarch64Mnemonic::STLXRB
            | Aarch64Mnemonic::STLXRH
            | Aarch64Mnemonic::LDXP
            | Aarch64Mnemonic::STXP
            | Aarch64Mnemonic::LDAXP
            | Aarch64Mnemonic::STLXP
            | Aarch64Mnemonic::LDAR
            | Aarch64Mnemonic::LDARB
            | Aarch64Mnemonic::LDARH
            | Aarch64Mnemonic::STLR
            | Aarch64Mnemonic::STLRB
            | Aarch64Mnemonic::STLRH
            | Aarch64Mnemonic::CAS
            | Aarch64Mnemonic::CASA
            | Aarch64Mnemonic::CASL
            | Aarch64Mnemonic::CASAL
            | Aarch64Mnemonic::CASB
            | Aarch64Mnemonic::CASAB
            | Aarch64Mnemonic::CASLB
            | Aarch64Mnemonic::CASALB
            | Aarch64Mnemonic::CASH
            | Aarch64Mnemonic::CASAH
            | Aarch64Mnemonic::CASLH
            | Aarch64Mnemonic::CASALH
            | Aarch64Mnemonic::SWP
            | Aarch64Mnemonic::SWPA
            | Aarch64Mnemonic::SWPL
            | Aarch64Mnemonic::SWPAL
            | Aarch64Mnemonic::SWPB
            | Aarch64Mnemonic::SWPAB
            | Aarch64Mnemonic::SWPLB
            | Aarch64Mnemonic::SWPALB
            | Aarch64Mnemonic::SWPH
            | Aarch64Mnemonic::SWPAH
            | Aarch64Mnemonic::SWPLH
            | Aarch64Mnemonic::SWPALH
            | Aarch64Mnemonic::LDADD
            | Aarch64Mnemonic::LDADDA
            | Aarch64Mnemonic::LDADDL
            | Aarch64Mnemonic::LDADDAL
            | Aarch64Mnemonic::LDADDB
            | Aarch64Mnemonic::LDADDAB
            | Aarch64Mnemonic::LDADDLB
            | Aarch64Mnemonic::LDADDALB
            | Aarch64Mnemonic::LDADDH
            | Aarch64Mnemonic::LDADDAH
            | Aarch64Mnemonic::LDADDLH
            | Aarch64Mnemonic::LDADDALH => InstructionCategory::Exclusive,
            Aarch64Mnemonic::B_COND
            | Aarch64Mnemonic::B
            | Aarch64Mnemonic::BL
            | Aarch64Mnemonic::BR
            | Aarch64Mnemonic::BLR
            | Aarch64Mnemonic::RET
            | Aarch64Mnemonic::RET_LR
            | Aarch64Mnemonic::CBZ
            | Aarch64Mnemonic::CBNZ
            | Aarch64Mnemonic::TBZ
            | Aarch64Mnemonic::TBNZ => InstructionCategory::Branch,
            Aarch64Mnemonic::SVC
            | Aarch64Mnemonic::HVC
            | Aarch64Mnemonic::SMC
            | Aarch64Mnemonic::BRK
            | Aarch64Mnemonic::HLT
            | Aarch64Mnemonic::DCPS1
            | Aarch64Mnemonic::DCPS2
            | Aarch64Mnemonic::DCPS3
            | Aarch64Mnemonic::ERET
            | Aarch64Mnemonic::ERETAA
            | Aarch64Mnemonic::ERETAB => InstructionCategory::Exception,
            Aarch64Mnemonic::MSR_REG
            | Aarch64Mnemonic::MSR_IMM
            | Aarch64Mnemonic::MRS
            | Aarch64Mnemonic::SYS
            | Aarch64Mnemonic::SYSL
            | Aarch64Mnemonic::ISB
            | Aarch64Mnemonic::DSB
            | Aarch64Mnemonic::DMB
            | Aarch64Mnemonic::WFI
            | Aarch64Mnemonic::WFE
            | Aarch64Mnemonic::SEV
            | Aarch64Mnemonic::SEVL
            | Aarch64Mnemonic::YIELD
            | Aarch64Mnemonic::CLREX_64
            | Aarch64Mnemonic::NOP_64
            | Aarch64Mnemonic::HINT => InstructionCategory::System,
            Aarch64Mnemonic::PACIA
            | Aarch64Mnemonic::PACIA1716
            | Aarch64Mnemonic::PACIASP
            | Aarch64Mnemonic::PACIAZ
            | Aarch64Mnemonic::PACIB
            | Aarch64Mnemonic::PACIB1716
            | Aarch64Mnemonic::PACIBSP
            | Aarch64Mnemonic::PACIBZ
            | Aarch64Mnemonic::AUTIA
            | Aarch64Mnemonic::AUTIA1716
            | Aarch64Mnemonic::AUTIASP
            | Aarch64Mnemonic::AUTIAZ
            | Aarch64Mnemonic::AUTIB
            | Aarch64Mnemonic::AUTIB1716
            | Aarch64Mnemonic::AUTIBSP
            | Aarch64Mnemonic::AUTIBZ
            | Aarch64Mnemonic::PACGA
            | Aarch64Mnemonic::XPACI
            | Aarch64Mnemonic::XPACD
            | Aarch64Mnemonic::BTIC => InstructionCategory::PointerAuth,
            _ => InstructionCategory::SimdFp,
        }
    }
}

/// AArch64 instruction categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstructionCategory {
    DataProcessing,
    AddressGen,
    Conditional,
    LoadStore,
    Exclusive,
    Branch,
    Exception,
    System,
    PointerAuth,
    SimdFp,
    Crypto,
    Cache,
}

// ============================================================================
// Conversion to common InstructionMnemonic
// ============================================================================

/// Convert all AArch64 mnemonics to common `InstructionMnemonic` strings.
pub fn all_aarch64_mnemonics() -> Vec<InstructionMnemonic> {
    use Aarch64Mnemonic::*;
    let variants = [
        ADD_IMM,
        ADDS_IMM,
        SUB_IMM,
        SUBS_IMM,
        AND_IMM,
        ANDS_IMM,
        EOR_IMM,
        ORR_IMM,
        MOVN,
        MOVZ,
        MOVK,
        ADR,
        ADRP,
        ADD_REG,
        ADDS_REG,
        SUB_REG,
        SUBS_REG,
        AND_REG,
        ANDS_REG,
        BIC_REG,
        BICS_REG,
        EOR_REG,
        EON_REG,
        ORR_REG,
        ORN_REG,
        ADC,
        ADCS,
        SBC,
        SBCS,
        NEG,
        NEGS,
        NGC,
        NGCS,
        CMP,
        CMN,
        TST,
        ADD_SHIFT,
        ADDS_SHIFT,
        SUB_SHIFT,
        SUBS_SHIFT,
        AND_SHIFT,
        ANDS_SHIFT,
        BIC_SHIFT,
        EOR_SHIFT,
        ORR_SHIFT,
        ORN_SHIFT,
        EON_SHIFT,
        LSLV,
        LSRV,
        ASRV,
        RORV,
        BFM,
        SBFM,
        UBFM,
        BFI,
        BFXIL,
        SBFIZ,
        SBFX,
        UBFIZ,
        UBFX,
        EXTR,
        CCMN,
        CCMP,
        CSEL,
        CSINC,
        CSINV,
        CSNEG,
        AND_LOG,
        BIC_LOG,
        ORR_LOG,
        ORN_LOG,
        EOR_LOG,
        EON_LOG,
        MOV_LOG,
        MOVN_WIDE,
        MOVZ_WIDE,
        MOVK_WIDE,
        ADR_AG,
        ADRP_AG,
        MUL,
        MNEG,
        MADD,
        MSUB,
        SMADDL,
        SMSUBL,
        SMULH,
        UMADDL,
        UMSUBL,
        UMULH,
        SDIV,
        UDIV,
        CRC32B,
        CRC32H,
        CRC32W,
        CRC32X,
        CRC32CB,
        CRC32CH,
        CRC32CW,
        CRC32CX,
        CLZ,
        CLS,
        RBIT,
        REV,
        REV16,
        REV32,
        REV64,
        LDR,
        LDRB,
        LDRH,
        LDRSB,
        LDRSH,
        LDRSW,
        STR,
        STRB,
        STRH,
        LDR_REG,
        LDRB_REG,
        LDRH_REG,
        LDRSB_REG,
        LDRSH_REG,
        LDRSW_REG,
        STR_REG,
        STRB_REG,
        STRH_REG,
        LDUR,
        LDURB,
        LDURH,
        LDURSB,
        LDURSH,
        LDURSW,
        STUR,
        STURB,
        STURH,
        LDP,
        LDPSW,
        STP,
        LDP_POST,
        LDP_PRE,
        STP_POST,
        STP_PRE,
        LDXR,
        LDXRB,
        LDXRH,
        STXR,
        STXRB,
        STXRH,
        LDAXR,
        LDAXRB,
        LDAXRH,
        STLXR,
        STLXRB,
        STLXRH,
        LDXP,
        STXP,
        LDAXP,
        STLXP,
        CAS,
        CASA,
        CASL,
        CASAL,
        CASB,
        CASAB,
        CASLB,
        CASALB,
        CASH,
        CASAH,
        CASLH,
        CASALH,
        SWP,
        SWPA,
        SWPL,
        SWPAL,
        SWPB,
        SWPAB,
        SWPLB,
        SWPALB,
        SWPH,
        SWPAH,
        SWPLH,
        SWPALH,
        LDADD,
        LDADDA,
        LDADDL,
        LDADDAL,
        LDADDB,
        LDADDAB,
        LDADDLB,
        LDADDALB,
        LDADDH,
        LDADDAH,
        LDADDLH,
        LDADDALH,
        LDAR,
        LDARB,
        LDARH,
        STLR,
        STLRB,
        STLRH,
        LDR_LIT,
        LDRSW_LIT,
        LDR_LIT_32,
        LDR_LIT_64,
        B_COND,
        B,
        BL,
        BR,
        BLR,
        RET,
        RET_LR,
        CBZ,
        CBNZ,
        TBZ,
        TBNZ,
        SVC,
        HVC,
        SMC,
        BRK,
        HLT,
        DCPS1,
        DCPS2,
        DCPS3,
        MSR_REG,
        MSR_IMM,
        MRS,
        SYS,
        SYSL,
        ISB,
        DSB,
        DMB,
        WFI,
        WFE,
        SEV,
        SEVL,
        YIELD,
        CLREX_64,
        NOP_64,
        HINT,
        ERET,
        ERETAA,
        ERETAB,
        PACIA,
        PACIA1716,
        PACIASP,
        PACIAZ,
        PACIB,
        PACIB1716,
        PACIBSP,
        PACIBZ,
        AUTIA,
        AUTIA1716,
        AUTIASP,
        AUTIAZ,
        AUTIB,
        AUTIB1716,
        AUTIBSP,
        AUTIBZ,
        PACGA,
        XPACI,
        XPACD,
        BTIC,
        FADD_S,
        FSUB_S,
        FMUL_S,
        FDIV_S,
        FADD_D,
        FSUB_D,
        FMUL_D,
        FDIV_D,
        FABS_S,
        FABS_D,
        FNEG_S,
        FNEG_D,
        FSQRT_S,
        FSQRT_D,
        FNMADD_S,
        FNMADD_D,
        FNMSUB_S,
        FNMSUB_D,
        FMADD_S,
        FMADD_D,
        FMSUB_S,
        FMSUB_D,
        FMAX_S,
        FMAX_D,
        FMIN_S,
        FMIN_D,
        FMAXNM_S,
        FMAXNM_D,
        FMINNM_S,
        FMINNM_D,
        FCMP_S,
        FCMP_D,
        FCMPE_S,
        FCMPE_D,
        FCMPZ_S,
        FCMPZ_D,
        FCMPEZ_S,
        FCMPEZ_D,
        FCCMP_S,
        FCCMP_D,
        FCCMPE_S,
        FCCMPE_D,
        FCSEL_S,
        FCSEL_D,
        FCVT_S_D,
        FCVT_D_S,
        FCVTAS,
        FCVTAU,
        FCVTMS,
        FCVTMU,
        FCVTNS,
        FCVTNU,
        FCVTPS,
        FCVTPU,
        FCVTZS,
        FCVTZU,
        SCVTF,
        UCVTF,
        FMOV_S,
        FMOV_D,
        FMOV_GP_S,
        FMOV_GP_D,
        FMOV_S_GP,
        FMOV_D_GP,
        FMOV_GP_64,
        FMOV_GP_64_REV,
        FMOV_GP_TOP,
        FRINTA_S,
        FRINTA_D,
        FRINTI_S,
        FRINTI_D,
        FRINTM_S,
        FRINTM_D,
        FRINTN_S,
        FRINTN_D,
        FRINTP_S,
        FRINTP_D,
        FRINTX_S,
        FRINTX_D,
        FRINTZ_S,
        FRINTZ_D,
        ADD_V,
        SUB_V,
        MUL_V,
        MLA_V,
        MLS_V,
        SABA_V,
        UABA_V,
        SABD_V,
        UABD_V,
        SMAX_V,
        SMIN_V,
        UMAX_V,
        UMIN_V,
        SMAXP_V,
        SMINP_V,
        UMAXP_V,
        UMINP_V,
        SADDL_V,
        SADDW_V,
        UADDL_V,
        UADDW_V,
        SSUBL_V,
        SSUBW_V,
        USUBL_V,
        USUBW_V,
        SMULL_V,
        UMULL_V,
        SMLAL_V,
        UMLAL_V,
        SMLSL_V,
        UMLSL_V,
        SADDLP_V,
        UADDLP_V,
        SADALP_V,
        UADALP_V,
        ADDV,
        SADDLV,
        UADDLV,
        SMAXV,
        SMINV,
        UMAXV,
        UMINV,
        SHL_V,
        SSHL_V,
        USHL_V,
        SHRN_V,
        SHRN2_V,
        SQSHRN_V,
        SQSHRN2_V,
        UQSHRN_V,
        UQSHRN2_V,
        SQRSHRN_V,
        SQRSHRN2_V,
        UQRSHRN_V,
        UQRSHRN2_V,
        SSHLL_V,
        SSHLL2_V,
        USHLL_V,
        USHLL2_V,
        SSRA_V,
        USRA_V,
        SRSRA_V,
        URSRA_V,
        SLI_V,
        SRI_V,
        SHLL_V,
        SHLL2_V,
        AND_V,
        BIC_V,
        ORR_V,
        ORN_V,
        EOR_V,
        BSL_V,
        BIT_V,
        BIF_V,
        MVN_V,
        NOT_V,
        MOV_V,
        MOVI_V,
        MVNI_V,
        CMEQ_V,
        CMGE_V,
        CMGT_V,
        CMLE_V,
        CMLT_V,
        CMHI_V,
        CMHS_V,
        CMTST_V,
        FCMEQ_V,
        FCMGE_V,
        FCMGT_V,
        FCMLE_V,
        FCMLT_V,
        FACGE_V,
        FACGT_V,
        FADD_V,
        FSUB_V,
        FMUL_V,
        FDIV_V,
        FMLA_V,
        FMLS_V,
        FMAX_V,
        FMIN_V,
        FMAXNM_V,
        FMINNM_V,
        FABD_V,
        FABS_V,
        FNEG_V,
        FSQRT_V,
        FRINTA_V,
        FRINTI_V,
        FRINTM_V,
        FRINTN_V,
        FRINTP_V,
        FRINTX_V,
        FRINTZ_V,
        FCVTAS_V,
        FCVTAU_V,
        FCVTMS_V,
        FCVTMU_V,
        FCVTNS_V,
        FCVTNU_V,
        FCVTPS_V,
        FCVTPU_V,
        FCVTZS_V,
        FCVTZU_V,
        SCVTF_V,
        UCVTF_V,
        FRECPE_V,
        FRECPS_V,
        FRSQRTE_V,
        FRSQRTS_V,
        EXT_V,
        DUP_V,
        DUP_ELEM,
        INS_ELEM,
        INS_GEN,
        SMOV,
        UMOV,
        TBL_V,
        TBX_V,
        TRN1_V,
        TRN2_V,
        ZIP1_V,
        ZIP2_V,
        UZP1_V,
        UZP2_V,
        REV16_V,
        REV32_V,
        REV64_V,
        XTN_V,
        XTN2_V,
        SQXTN_V,
        SQXTN2_V,
        UQXTN_V,
        UQXTN2_V,
        SQXTUN_V,
        SQXTUN2_V,
        CNT_V,
        CLS_V,
        CLZ_V,
        RBIT_V,
        ABS_V,
        NEG_V,
        LD1,
        LD1R,
        LD2,
        LD2R,
        LD3,
        LD3R,
        LD4,
        LD4R,
        ST1,
        ST2,
        ST3,
        ST4,
        AESD_64,
        AESE_64,
        AESIMC_64,
        AESMC_64,
        SHA1C_64,
        SHA1P_64,
        SHA1M_64,
        SHA1H_64,
        SHA1SU0_64,
        SHA1SU1_64,
        SHA256H_64,
        SHA256H2_64,
        SHA256SU0_64,
        SHA256SU1_64,
        SHA512H,
        SHA512H2,
        SHA512SU0,
        SHA512SU1,
        SM3PARTW1,
        SM3PARTW2,
        SM3SS1,
        SM3TT1A,
        SM3TT1B,
        SM3TT2A,
        SM3TT2B,
        SM4E,
        SM4ENCKEY,
        EOR3,
        RAX1,
        XAR,
        BCAX,
        PRFM,
        PRFUM,
        DC,
        IC,
        FMOV_IMM_S,
        FMOV_IMM_D,
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
        assert_eq!(ConditionCode::NE.encoding(), 0b0001);
        assert_eq!(ConditionCode::AL.encoding(), 0b1110);
        assert_eq!(ConditionCode::NV.encoding(), 0b1111);
        assert_eq!(ConditionCode::EQ.suffix(), "eq");
        assert_eq!(ConditionCode::GE.suffix(), "ge");
    }

    #[test]
    fn test_shift_types() {
        assert_eq!(ShiftType::LSL.encoding(), 0b00);
        assert_eq!(ShiftType::LSR.encoding(), 0b01);
        assert_eq!(ShiftType::ASR.encoding(), 0b10);
        assert_eq!(ShiftType::ROR.encoding(), 0b11);
        assert_eq!(ShiftType::LSL.suffix(), "LSL");
        assert_eq!(ShiftType::ASR.suffix(), "ASR");
    }

    #[test]
    fn test_extend_types() {
        assert_eq!(ExtendType::UXTB.encoding(), 0b000);
        assert_eq!(ExtendType::UXTH.encoding(), 0b001);
        assert_eq!(ExtendType::UXTW.encoding(), 0b010);
        assert_eq!(ExtendType::SXTB.encoding(), 0b100);
        assert_eq!(ExtendType::SXTH.encoding(), 0b101);
        assert_eq!(ExtendType::SXTW.encoding(), 0b110);
        assert_eq!(ExtendType::SXTX.encoding(), 0b111);
    }

    #[test]
    fn test_mnemonic_count() {
        let mnemonics = all_aarch64_mnemonics();
        assert!(
            mnemonics.len() >= 300,
            "Expected >= 300 unique AArch64 mnemonics, got {}",
            mnemonics.len()
        );
    }

    #[test]
    fn test_addressing_modes() {
        let modes = [
            AddressingMode::RegisterDirect,
            AddressingMode::Immediate,
            AddressingMode::BaseRegister,
            AddressingMode::BasePlusImm,
            AddressingMode::BasePlusRegister,
            AddressingMode::PreIndexed,
            AddressingMode::PostIndexed,
            AddressingMode::PcRelative,
            AddressingMode::RegisterPair,
            AddressingMode::SimdStructure,
            AddressingMode::RegisterList,
            AddressingMode::SystemRegister,
            AddressingMode::Exclusive,
            AddressingMode::AcquireRelease,
        ];
        for mode in &modes {
            assert!(!mode.name().is_empty());
        }
    }

    #[test]
    fn test_instruction_categories() {
        assert!(matches!(
            Aarch64Mnemonic::ADD_IMM.category(),
            InstructionCategory::DataProcessing
        ));
        assert!(matches!(
            Aarch64Mnemonic::LDR.category(),
            InstructionCategory::LoadStore
        ));
        assert!(matches!(
            Aarch64Mnemonic::B.category(),
            InstructionCategory::Branch
        ));
        assert!(matches!(
            Aarch64Mnemonic::SVC.category(),
            InstructionCategory::Exception
        ));
        assert!(matches!(
            Aarch64Mnemonic::MSR_REG.category(),
            InstructionCategory::System
        ));
        assert!(matches!(
            Aarch64Mnemonic::FADD_S.category(),
            InstructionCategory::SimdFp
        ));
        assert!(matches!(
            Aarch64Mnemonic::CAS.category(),
            InstructionCategory::Exclusive
        ));
        assert!(matches!(
            Aarch64Mnemonic::CSEL.category(),
            InstructionCategory::Conditional
        ));
    }
}
