//! MIPS Processor Module
//!
//! Complete MIPS processor support for the Ghidra Rust implementation.
//!
//! ## Supported ISA Variants
//!
//! | Variant              | Features                                               |
//! |----------------------|--------------------------------------------------------|
//! | MIPS I               | 32-bit base ISA                                        |
//! | MIPS II              | Branch-likely, LL/SC                                   |
//! | MIPS III             | 64-bit, LD/SD                                          |
//! | MIPS IV              | FPU improvements, indexed load/store                   |
//! | MIPS32               | 32-bit unified ISA (Release 1/2/5/6)                   |
//! | MIPS64               | 64-bit unified ISA (Release 1/2/5/6)                   |
//! | microMIPS            | 16/32-bit compressed encoding                          |
//! | MIPS16e              | 16-bit compressed encoding                             |
//! | MSA                  | 128-bit SIMD (MIPS SIMD Architecture)                  |
//! | DSP R2/R3            | Digital Signal Processing extensions                   |
//! | VZ                   | Hardware virtualization                                |
//!
//! ## Register Model
//!
//! - GPR: R0(zero)-R31(ra), with ABI names
//! - Special: HI, LO, PC
//! - CP0: System control registers (Index, Random, EntryLo, Context, etc.)
//! - FPU: F0-F31, FCSR, FCCR, FEXR, FENR
//! - MSA SIMD: W0-W31 (128-bit)
//!
//! ## Module Structure
//!
//! - Register definitions with full ABI name aliasing
//! - CP0 control register definitions with bit-field layouts
//! - Complete instruction mnemonic enumeration (250+ mnemonics)
//! - Processor variant and language definitions
//! - ProcessorModule trait implementation

pub mod registers;

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;
use std::collections::HashMap;

// ============================================================================
// Processor Name Constants
// ============================================================================

pub const PROCESSOR_NAME: &str = "MIPS";
pub const PROCESSOR_DESCRIPTION: &str =
    "MIPS processor family (32/64-bit) including CP0, FPU, MSA, DSP, microMIPS, MIPS16e, and VZ";

// ============================================================================
// MIPS ISA Variants
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MipsVariant {
    MipsI,
    MipsII,
    MipsIII,
    MipsIV,
    MipsV,
    Mips32,
    Mips32R2,
    Mips32R5,
    Mips32R6,
    Mips64,
    Mips64R2,
    Mips64R5,
    Mips64R6,
    MicroMips,
    Mips16e,
}

impl MipsVariant {
    pub fn name(&self) -> &'static str {
        match self {
            MipsVariant::MipsI => "MIPS I",
            MipsVariant::MipsII => "MIPS II",
            MipsVariant::MipsIII => "MIPS III",
            MipsVariant::MipsIV => "MIPS IV",
            MipsVariant::MipsV => "MIPS V",
            MipsVariant::Mips32 => "MIPS32",
            MipsVariant::Mips32R2 => "MIPS32 R2",
            MipsVariant::Mips32R5 => "MIPS32 R5",
            MipsVariant::Mips32R6 => "MIPS32 R6",
            MipsVariant::Mips64 => "MIPS64",
            MipsVariant::Mips64R2 => "MIPS64 R2",
            MipsVariant::Mips64R5 => "MIPS64 R5",
            MipsVariant::Mips64R6 => "MIPS64 R6",
            MipsVariant::MicroMips => "microMIPS",
            MipsVariant::Mips16e => "MIPS16e",
        }
    }

    pub fn is_64bit(&self) -> bool {
        matches!(
            self,
            MipsVariant::MipsIII
                | MipsVariant::MipsIV
                | MipsVariant::MipsV
                | MipsVariant::Mips64
                | MipsVariant::Mips64R2
                | MipsVariant::Mips64R5
                | MipsVariant::Mips64R6
        )
    }

    pub fn has_fpu(&self) -> bool { true }

    pub fn has_msa(&self) -> bool {
        matches!(self, MipsVariant::Mips32R5 | MipsVariant::Mips64R5 | MipsVariant::Mips64R6)
    }

    pub fn has_dsp(&self) -> bool {
        matches!(self, MipsVariant::Mips32R2 | MipsVariant::Mips64R2 | MipsVariant::Mips64R5)
    }

    pub fn has_vz(&self) -> bool {
        matches!(self, MipsVariant::Mips64R5 | MipsVariant::Mips64R6)
    }
}

impl std::fmt::Display for MipsVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Register Offsets
// ============================================================================

const GPR_OFFSET_BASE: u64 = 0x0000;
const SPECIAL_OFFSET_BASE: u64 = 0x0100;
const CP0_OFFSET_BASE: u64 = 0x0200;
const FPU_OFFSET_BASE: u64 = 0x0400;
const FPU_CTRL_OFFSET_BASE: u64 = 0x0500;
const MSA_OFFSET_BASE: u64 = 0x0600;
const DSP_ACC_OFFSET_BASE: u64 = 0x0700;

// ============================================================================
// CP0 Register Select Numbers
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cp0Register {
    Index = 0,
    Random = 1,
    EntryLo0 = 2,
    EntryLo1 = 3,
    Context = 4,
    PageMask = 5,
    Wired = 6,
    HWREna = 7,
    BadVAddr = 8,
    Count = 9,
    EntryHi = 10,
    Compare = 11,
    Status = 12,
    Cause = 13,
    EPC = 14,
    PRId = 15,
    Config = 16,
    LLAddr = 17,
    WatchLo = 18,
    WatchHi = 19,
    XContext = 20,
    Debug = 23,
    DEPC = 24,
    PerfCnt = 25,
    ErrCtl = 26,
    CacheErr = 27,
    TagLo = 28,
    TagHi = 29,
    ErrorEPC = 30,
    DESAVE = 31,
}

impl Cp0Register {
    pub fn select_number(&self) -> u8 { *self as u8 }
    pub fn name(&self) -> &'static str {
        match self {
            Cp0Register::Index => "Index", Cp0Register::Random => "Random",
            Cp0Register::EntryLo0 => "EntryLo0", Cp0Register::EntryLo1 => "EntryLo1",
            Cp0Register::Context => "Context", Cp0Register::PageMask => "PageMask",
            Cp0Register::Wired => "Wired", Cp0Register::HWREna => "HWREna",
            Cp0Register::BadVAddr => "BadVAddr", Cp0Register::Count => "Count",
            Cp0Register::EntryHi => "EntryHi", Cp0Register::Compare => "Compare",
            Cp0Register::Status => "Status", Cp0Register::Cause => "Cause",
            Cp0Register::EPC => "EPC", Cp0Register::PRId => "PRId",
            Cp0Register::Config => "Config", Cp0Register::LLAddr => "LLAddr",
            Cp0Register::WatchLo => "WatchLo", Cp0Register::WatchHi => "WatchHi",
            Cp0Register::XContext => "XContext", Cp0Register::Debug => "Debug",
            Cp0Register::DEPC => "DEPC", Cp0Register::PerfCnt => "PerfCnt",
            Cp0Register::ErrCtl => "ErrCtl", Cp0Register::CacheErr => "CacheErr",
            Cp0Register::TagLo => "TagLo", Cp0Register::TagHi => "TagHi",
            Cp0Register::ErrorEPC => "ErrorEPC", Cp0Register::DESAVE => "DESAVE",
        }
    }
}

// ============================================================================
// CP0 Status Register Bit Fields
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatusField {
    IE = 0, EXL = 1, ERL = 2, KSU = 3, UM = 4, UX = 5, SX = 6, KX = 7,
    IM0 = 8, IM1 = 9, IM2 = 10, IM3 = 11, IM4 = 12, IM5 = 13, IM6 = 14, IM7 = 15,
    DE = 16, CE = 17, CH = 18, NMI = 19, SR = 20, TS = 21, BEV = 22,
    CU0 = 28, CU1 = 29, CU2 = 30, CU3 = 31,
}

impl StatusField {
    pub fn bit(&self) -> u32 { *self as u32 }
    pub fn mask(&self) -> u32 { 1u32 << (*self as u32) }
    pub fn name(&self) -> &'static str {
        match self {
            StatusField::IE => "IE", StatusField::EXL => "EXL", StatusField::ERL => "ERL",
            StatusField::KSU => "KSU", StatusField::UM => "UM", StatusField::UX => "UX",
            StatusField::SX => "SX", StatusField::KX => "KX",
            StatusField::IM0 => "IM0", StatusField::IM1 => "IM1", StatusField::IM2 => "IM2",
            StatusField::IM3 => "IM3", StatusField::IM4 => "IM4", StatusField::IM5 => "IM5",
            StatusField::IM6 => "IM6", StatusField::IM7 => "IM7",
            StatusField::DE => "DE", StatusField::CE => "CE", StatusField::CH => "CH",
            StatusField::NMI => "NMI", StatusField::SR => "SR", StatusField::TS => "TS",
            StatusField::BEV => "BEV",
            StatusField::CU0 => "CU0", StatusField::CU1 => "CU1",
            StatusField::CU2 => "CU2", StatusField::CU3 => "CU3",
        }
    }
}

// ============================================================================
// CP0 Cause Register Bit Fields
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CauseField {
    ExcCode = 2,
    IP0 = 8, IP1 = 9, IP2 = 10, IP3 = 11,
    IP4 = 12, IP5 = 13, IP6 = 14, IP7 = 15,
    WP = 22, IV = 23,
    CE = 28, TI = 30, BD = 31,
}

impl CauseField {
    pub fn bit(&self) -> u32 { *self as u32 }
    pub fn mask(&self) -> u32 { 1u32 << (*self as u32) }
    pub fn name(&self) -> &'static str {
        match self {
            CauseField::ExcCode => "ExcCode",
            CauseField::IP0 => "IP0", CauseField::IP1 => "IP1", CauseField::IP2 => "IP2",
            CauseField::IP3 => "IP3", CauseField::IP4 => "IP4", CauseField::IP5 => "IP5",
            CauseField::IP6 => "IP6", CauseField::IP7 => "IP7",
            CauseField::WP => "WP", CauseField::IV => "IV",
            CauseField::CE => "CE", CauseField::TI => "TI", CauseField::BD => "BD",
        }
    }
}

// ============================================================================
// CP0 Config Register Bit Fields
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigField {
    K0 = 0, VI = 3, MT = 7, AR = 10, AT = 13, BE = 15,
    KU = 25, K21 = 29, K22 = 30, K23 = 28, M = 31,
}

impl ConfigField {
    pub fn bit(&self) -> u32 { *self as u32 }
    pub fn name(&self) -> &'static str {
        match self {
            ConfigField::K0 => "K0", ConfigField::VI => "VI", ConfigField::MT => "MT",
            ConfigField::AR => "AR", ConfigField::AT => "AT", ConfigField::BE => "BE",
            ConfigField::KU => "KU", ConfigField::K21 => "K21", ConfigField::K22 => "K22",
            ConfigField::K23 => "K23", ConfigField::M => "M",
        }
    }
}

// ============================================================================
// Exception Codes (ExcCode values)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExceptionCode {
    Int = 0, Mod = 1, TLBL = 2, TLBS = 3, AdEL = 4, AdES = 5,
    IBE = 6, DBE = 7, Syscall = 8, Bp = 9, RI = 10, CpU = 11,
    Ov = 12, Tr = 13, MSADis = 14, FPE = 15, C2E = 16,
    TLBRI = 19, TLBLI = 20, TLBXI = 21, MDMX = 22, WATCH = 23,
    MCheck = 24, Thread = 25, DSPDis = 26, GE = 27, CacheErr = 30,
}

impl ExceptionCode {
    pub fn code(&self) -> u8 { *self as u8 }
    pub fn name(&self) -> &'static str {
        match self {
            ExceptionCode::Int => "Interrupt", ExceptionCode::Mod => "TLB Modified",
            ExceptionCode::TLBL => "TLB Load", ExceptionCode::TLBS => "TLB Store",
            ExceptionCode::AdEL => "Address Error Load", ExceptionCode::AdES => "Address Error Store",
            ExceptionCode::IBE => "Bus Error Instruction", ExceptionCode::DBE => "Bus Error Data",
            ExceptionCode::Syscall => "Syscall", ExceptionCode::Bp => "Breakpoint",
            ExceptionCode::RI => "Reserved Instruction", ExceptionCode::CpU => "Coprocessor Unusable",
            ExceptionCode::Ov => "Arithmetic Overflow", ExceptionCode::Tr => "Trap",
            ExceptionCode::MSADis => "MSA Disabled", ExceptionCode::FPE => "Floating Point",
            ExceptionCode::C2E => "Coprocessor 2", ExceptionCode::TLBRI => "TLB Read Inhibit",
            ExceptionCode::TLBLI => "TLB Load Inhibit", ExceptionCode::TLBXI => "TLB Execute Inhibit",
            ExceptionCode::MDMX => "MDMX", ExceptionCode::WATCH => "Watch",
            ExceptionCode::MCheck => "Machine Check", ExceptionCode::Thread => "Thread",
            ExceptionCode::DSPDis => "DSP Disabled", ExceptionCode::GE => "Guest Exception",
            ExceptionCode::CacheErr => "Cache Error",
        }
    }
}

// ============================================================================
// ABI Names
// ============================================================================

/// ABI names for GPR R0..R31.
pub const MIPS_GPR_ABI_NAMES: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
    "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
];

// ============================================================================
// MIPS Register Bank
// ============================================================================

/// The complete register bank for a MIPS processor.
#[derive(Debug, Clone)]
pub struct MipsRegisterBank {
    pub gpr: [Register; 32],
    pub gpr_abi_names: HashMap<String, usize>,
    pub hi: Register,
    pub lo: Register,
    pub pc: Register,
    pub cp0: [Register; 32],
    pub fpu: [Register; 32],
    pub fcsr: Register,
    pub fccr: Register,
    pub fexr: Register,
    pub fenr: Register,
    pub msa: [Register; 32],
    pub dsp_acc: [Register; 4],
    register_by_name: HashMap<String, Register>,
}

impl MipsRegisterBank {
    /// Create the full MIPS64 (64-bit) register bank with CP0, FPU, MSA, and DSP.
    pub fn new_mips64() -> Self {
        // GPR R0-R31 (64-bit)
        let gpr: [Register; 32] = std::array::from_fn(|i| {
            Register::new(&format!("R{}", i), 64, GPR_OFFSET_BASE + (i as u64) * 8)
        });
        let mut gpr_abi_names = HashMap::new();
        for (i, abi) in MIPS_GPR_ABI_NAMES.iter().enumerate() {
            gpr_abi_names.insert(abi.to_string(), i);
        }

        // Special registers (64-bit)
        let hi = Register::new("HI", 64, SPECIAL_OFFSET_BASE + 0x00);
        let lo = Register::new("LO", 64, SPECIAL_OFFSET_BASE + 0x08);
        let pc = Register::new("PC", 64, SPECIAL_OFFSET_BASE + 0x10);

        // CP0 registers (64-bit each, indexed by select number)
        let cp0_names: [&str; 32] = [
            "Index", "Random", "EntryLo0", "EntryLo1", "Context", "PageMask",
            "Wired", "HWREna", "BadVAddr", "Count", "EntryHi", "Compare",
            "Status", "Cause", "EPC", "PRId", "Config", "LLAddr",
            "WatchLo", "WatchHi", "XContext", "Debug21", "Debug22", "Debug",
            "DEPC", "PerfCnt", "ErrCtl", "CacheErr", "TagLo", "TagHi",
            "ErrorEPC", "DESAVE",
        ];
        let cp0: [Register; 32] = std::array::from_fn(|i| {
            Register::new(cp0_names[i], 64, CP0_OFFSET_BASE + (i as u64) * 8)
        });

        // FPU registers F0-F31 (64-bit)
        let fpu: [Register; 32] = std::array::from_fn(|i| {
            Register::new(&format!("F{}", i), 64, FPU_OFFSET_BASE + (i as u64) * 8)
        });

        // FPU control registers (32-bit)
        let fcsr = Register::new("FCSR", 32, FPU_CTRL_OFFSET_BASE + 0x00);
        let fccr = Register::new("FCCR", 32, FPU_CTRL_OFFSET_BASE + 0x04);
        let fexr = Register::new("FEXR", 32, FPU_CTRL_OFFSET_BASE + 0x08);
        let fenr = Register::new("FENR", 32, FPU_CTRL_OFFSET_BASE + 0x0C);

        // MSA SIMD registers W0-W31 (128-bit)
        let msa: [Register; 32] = std::array::from_fn(|i| {
            Register::new(&format!("W{}", i), 128, MSA_OFFSET_BASE + (i as u64) * 16)
        });

        // DSP accumulator registers AC0-AC3 (64-bit)
        let dsp_acc: [Register; 4] = std::array::from_fn(|i| {
            Register::new(&format!("AC{}", i), 64, DSP_ACC_OFFSET_BASE + (i as u64) * 8)
        });

        // Build name lookup
        let mut register_by_name = HashMap::new();
        for (i, reg) in gpr.iter().enumerate() {
            register_by_name.insert(format!("R{}", i), reg.clone());
            register_by_name.insert(format!("${}", i), reg.clone());
            let abi = MIPS_GPR_ABI_NAMES[i];
            register_by_name.insert(abi.to_string(), reg.clone());
        }
        register_by_name.insert("HI".to_string(), hi.clone());
        register_by_name.insert("LO".to_string(), lo.clone());
        register_by_name.insert("PC".to_string(), pc.clone());
        for (i, reg) in cp0.iter().enumerate() {
            register_by_name.insert(reg.name.clone(), reg.clone());
        }
        for (i, reg) in fpu.iter().enumerate() {
            register_by_name.insert(format!("F{}", i), reg.clone());
        }
        register_by_name.insert("FCSR".to_string(), fcsr.clone());
        register_by_name.insert("FCCR".to_string(), fccr.clone());
        register_by_name.insert("FEXR".to_string(), fexr.clone());
        register_by_name.insert("FENR".to_string(), fenr.clone());
        for (i, reg) in msa.iter().enumerate() {
            register_by_name.insert(format!("W{}", i), reg.clone());
        }
        for (i, reg) in dsp_acc.iter().enumerate() {
            register_by_name.insert(format!("AC{}", i), reg.clone());
        }

        MipsRegisterBank { gpr, gpr_abi_names, hi, lo, pc, cp0, fpu, fcsr, fccr, fexr, fenr, msa, dsp_acc, register_by_name }
    }

    pub fn get(&self, name: &str) -> Option<&Register> { self.register_by_name.get(name) }
    pub fn gpr_index_by_abi(&self, abi_name: &str) -> Option<usize> { self.gpr_abi_names.get(abi_name).copied() }
    pub fn len(&self) -> usize { self.register_by_name.len() }
    pub fn is_empty(&self) -> bool { self.register_by_name.is_empty() }
    pub fn iter(&self) -> impl Iterator<Item = &Register> { self.register_by_name.values() }
}

impl Default for MipsRegisterBank {
    fn default() -> Self { Self::new_mips64() }
}

// ============================================================================
// MIPS Instruction Mnemonic
// ============================================================================

/// Complete MIPS instruction mnemonic enumeration (250+ mnemonics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MipsMnemonic {
    // Integer Arithmetic
    ADD, ADDI, ADDIU, ADDU, SUB, SUBU,
    SLT, SLTI, SLTIU, SLTU,
    DADD, DADDI, DADDIU, DADDU, DSUB, DSUBU,
    MUL, MUH, MULU, MUHU, DMUL, DMUH, DMULU, DMUHU,
    MULT, MULTU, DMULT, DMULTU, DIV, DIVU, DDIV, DDIVU,
    MADD, MADDU, MSUB, MSUBU,
    CLO, CLZ, DCLO, DCLZ,
    SEB, SEH, NEGU, NEG,
    // Logical
    AND, ANDI, OR, ORI, XOR, XORI, NOR, LUI,
    AUI, DAUI, DAHI, DATI, AUIPC, ALUIPC,
    // Shift / Rotate
    SLL, SLLV, SRL, SRLV, SRA, SRAV,
    DSLL, DSLLV, DSLL32,
    DSRL, DSRLV, DSRL32,
    DSRA, DSRAV, DSRA32,
    ROTR, ROTRV, DROTR, DROTRV, DROTR32,
    WSBH, DSBH, DSHD,
    // Move
    MFHI, MTHI, MFLO, MTLO, MOVN, MOVZ, MOVF, MOVT,
    MFC0, MTC0, DMFC0, DMTC0, MTC2, MFC2,
    MFC1, DMFC1, MTC1, DMTC1,
    MFHC1, MTHC1, MFHC2, MTHC2,
    CFC1, CTC1, CFC2, CTC2,
    RDHWR, RDPGPR, WRPGPR,
    SELEQZ, SELNEZ,
    // Bit Field
    EXT, INS, DEXT, DEXTM, DEXTU, DINS, DINSM, DINSU,
    // Branch
    BEQ, BEQL, BNE, BNEL,
    BLEZ, BLEZL, BGTZ, BGTZL,
    BLTZ, BLTZL, BLTZAL, BLTZALL,
    BGEZ, BGEZL, BGEZAL, BGEZALL,
    BC1F, BC1T, BC1FL, BC1TL,
    BC2F, BC2T, BC2FL, BC2TL,
    J, JAL, JR, JALR,
    JR_HB, JALR_HB, JALX,
    B, BAL, NAL,
    // Compact Branches (R6)
    BEQC, BNEC, BOVC, BNVC,
    BGEC, BLTC, BGEUC, BLTUC,
    BGEZC, BLEZC, BGTZC, BLTZC,
    BC1EQZ, BC1NEZ, BC2EQZ, BC2NEZ,
    BALC, BC, BEQZC, BNEZC, JIC, JIALC,
    BLEZALC, BGEZALC, BGTZALC, BLTZALC,
    BEQZALC, BNEZALC,
    // Load/Store
    LB, LBU, LH, LHU, LW, LWU, LD,
    SB, SH, SW, SD,
    LDL, LDR, SDL, SDR,
    LWL, LWR, SWL, SWR,
    LL, LLD, SC, SCD,
    LLWP, SCWP,
    PREF, PREFX, CACHE,
    SYNC, SYNCI, SYNCIE,
    LWPC, LWUPC, LDPC, ADDIUPC, ADDIUR2, ADDIUSP,
    // Coprocessor Load/Store
    LWC1, SWC1, LDC1, SDC1,
    LWC2, SWC2, LDC2, SDC2,
    LDC3, SDC3,
    LWXC1, LDXC1, SWXC1, SDXC1, LUXC1, SUXC1,
    // Trap
    TGE, TGEU, TLT, TLTU, TEQ, TNE,
    TGEI, TGEIU, TLTI, TLTIU, TEQI, TNEI,
    TGEL, TGEUL, TLTL, TLTUL, TEQL, TNEL,
    // Exception / System
    SYSCALL, BREAK, ERET, ERETNC,
    WAIT, SSNOP, NOP, EHB, PAUSE, DI, EI, DERET,
    TLBP, TLBR, TLBWI, TLBWR,
    TLBINV, TLBINVF, TLBINVF_FULL,
    // FPU
    ADD_S, ADD_D, SUB_S, SUB_D, MUL_S, MUL_D, DIV_S, DIV_D,
    SQRT_S, SQRT_D, ABS_S, ABS_D, NEG_S, NEG_D,
    MOV_S, MOV_D, MOVF_S, MOVF_D, MOVT_S, MOVT_D,
    MOVZ_S, MOVZ_D, MOVN_S, MOVN_D,
    CVT_S_D, CVT_S_W, CVT_S_L,
    CVT_D_S, CVT_D_W, CVT_D_L,
    CVT_W_S, CVT_W_D, CVT_L_S, CVT_L_D,
    CVT_PS_S,
    CEIL_W_S, CEIL_W_D, CEIL_L_S, CEIL_L_D,
    FLOOR_W_S, FLOOR_W_D, FLOOR_L_S, FLOOR_L_D,
    ROUND_W_S, ROUND_W_D, ROUND_L_S, ROUND_L_D,
    TRUNC_W_S, TRUNC_W_D, TRUNC_L_S, TRUNC_L_D,
    RECIP_S, RECIP_D, RSQRT_S, RSQRT_D,
    C_F_S, C_F_D, C_UN_S, C_UN_D,
    C_EQ_S, C_EQ_D, C_LT_S, C_LT_D, C_LE_S, C_LE_D,
    C_UEQ_S, C_UEQ_D, C_ULT_S, C_ULT_D, C_ULE_S, C_ULE_D,
    C_OLE_S, C_OLE_D, C_OLT_S, C_OLT_D,
    C_SEQ_S, C_SEQ_D, C_NGE_S, C_NGE_D,
    C_NGT_S, C_NGT_D, C_NGLE_S, C_NGLE_D, C_NGL_S, C_NGL_D,
    MADDF_S, MADDF_D, MSUBF_S, MSUBF_D,
    MAX_S, MAX_D, MIN_S, MIN_D,
    MAXA_S, MAXA_D, MINA_S, MINA_D,
    SEL_S, SEL_D, SELEQZ_S, SELEQZ_D, SELNEZ_S, SELNEZ_D,
    CLASS_S, CLASS_D, RINT_S, RINT_D,
    BC1ANY2F, BC1ANY2T, BC1ANY4F, BC1ANY4T,
    MADD_S, MSUB_S, NMADD_S, NMSUB_S,
    MADD_D, MSUB_D, NMADD_D, NMSUB_D,
    CMP_AF_S, CMP_UN_S, CMP_EQ_S, CMP_UEQ_S, CMP_LT_S, CMP_ULT_S,
    CMP_LE_S, CMP_ULE_S, CMP_SAF_S, CMP_SUN_S, CMP_SEQ_S,
    CMP_AF_D, CMP_UN_D, CMP_EQ_D, CMP_UEQ_D, CMP_LT_D, CMP_ULT_D,
    CMP_LE_D, CMP_ULE_D, CMP_SAF_D, CMP_SUN_D, CMP_SEQ_D,
    // MSA Data Transfer
    LD_B, LD_H, LD_W, LD_D,
    ST_B, ST_H, ST_W, ST_D,
    LD_MSA, ST_MSA,
    LDI_B, LDI_H, LDI_W, LDI_D,
    INSERT_B, INSERT_H, INSERT_W, INSERT_D,
    INSVE_B, INSVE_H, INSVE_W, INSVE_D,
    COPY_S_B, COPY_S_H, COPY_S_W, COPY_S_D,
    COPY_U_B, COPY_U_H, COPY_U_W,
    FILL_B, FILL_H, FILL_W, FILL_D,
    SPLAT_B, SPLAT_H, SPLAT_W, SPLAT_D,
    // MSA Integer Arithmetic
    ADDV_B, ADDV_H, ADDV_W, ADDV_D,
    SUBV_B, SUBV_H, SUBV_W, SUBV_D,
    MULV_B, MULV_H, MULV_W, MULV_D,
    DIV_S_B, DIV_S_H, DIV_S_W, DIV_S_D,
    DIV_U_B, DIV_U_H, DIV_U_W, DIV_U_D,
    MOD_S_B, MOD_S_H, MOD_S_W, MOD_S_D,
    MOD_U_B, MOD_U_H, MOD_U_W, MOD_U_D,
    MADDV_B, MADDV_H, MADDV_W, MADDV_D,
    MSUBV_B, MSUBV_H, MSUBV_W, MSUBV_D,
    AVE_S_B, AVE_S_H, AVE_S_W, AVE_S_D,
    AVE_U_B, AVE_U_H, AVE_U_W, AVE_U_D,
    AVER_S_B, AVER_S_H, AVER_S_W, AVER_S_D,
    AVER_U_B, AVER_U_H, AVER_U_W, AVER_U_D,
    ASUB_S_B, ASUB_S_H, ASUB_S_W, ASUB_S_D,
    ASUB_U_B, ASUB_U_H, ASUB_U_W, ASUB_U_D,
    HADD_S_H, HADD_S_W, HADD_S_D,
    HADD_U_H, HADD_U_W, HADD_U_D,
    HSUB_S_H, HSUB_S_W, HSUB_S_D,
    HSUB_U_H, HSUB_U_W, HSUB_U_D,
    DOTP_S_H, DOTP_S_W, DOTP_S_D,
    DOTP_U_H, DOTP_U_W, DOTP_U_D,
    DPADD_S_H, DPADD_S_W, DPADD_S_D,
    DPADD_U_H, DPADD_U_W, DPADD_U_D,
    DPSUB_S_H, DPSUB_S_W, DPSUB_S_D,
    DPSUB_U_H, DPSUB_U_W, DPSUB_U_D,
    MUL_Q_H, MUL_Q_W, MULR_Q_H, MULR_Q_W,
    MADD_Q_H, MADD_Q_W, MADDR_Q_H, MADDR_Q_W,
    MSUB_Q_H, MSUB_Q_W, MSUBR_Q_H, MSUBR_Q_W,
    SAT_S_B, SAT_S_H, SAT_S_W, SAT_S_D,
    SAT_U_B, SAT_U_H, SAT_U_W, SAT_U_D,
    SUBS_S_B, SUBS_S_H, SUBS_S_W, SUBS_S_D,
    SUBS_U_B, SUBS_U_H, SUBS_U_W, SUBS_U_D,
    SUBSUS_U_B, SUBSUS_U_H, SUBSUS_U_W, SUBSUS_U_D,
    SUBSUU_S_B, SUBSUU_S_H, SUBSUU_S_W, SUBSUU_S_D,
    // MSA Bitwise
    AND_V, OR_V, NOR_V, XOR_V,
    BCLR_B, BCLR_H, BCLR_W, BCLR_D,
    BSET_B, BSET_H, BSET_W, BSET_D,
    BNEG_B, BNEG_H, BNEG_W, BNEG_D,
    BMNZ_V, BMZ_V, BSEL_V,
    // MSA Shift
    SLL_B, SLL_H, SLL_W, SLL_D,
    SRA_B, SRA_H, SRA_W, SRA_D,
    SRL_B, SRL_H, SRL_W, SRL_D,
    SRAR_B, SRAR_H, SRAR_W, SRAR_D,
    SRLR_B, SRLR_H, SRLR_W, SRLR_D,
    // MSA Compare
    CEQ_B, CEQ_H, CEQ_W, CEQ_D,
    CLE_S_B, CLE_S_H, CLE_S_W, CLE_S_D,
    CLE_U_B, CLE_U_H, CLE_U_W, CLE_U_D,
    CLT_S_B, CLT_S_H, CLT_S_W, CLT_S_D,
    CLT_U_B, CLT_U_H, CLT_U_W, CLT_U_D,
    CMP_EQ_B, CMP_EQ_H, CMP_EQ_W, CMP_EQ_D,
    CMP_LE_S_B, CMP_LE_S_H, CMP_LE_S_W, CMP_LE_S_D,
    CMP_LE_U_B, CMP_LE_U_H, CMP_LE_U_W, CMP_LE_U_D,
    CMP_LT_S_B, CMP_LT_S_H, CMP_LT_S_W, CMP_LT_S_D,
    CMP_LT_U_B, CMP_LT_U_H, CMP_LT_U_W, CMP_LT_U_D,
    // MSA Pack/Interleave
    PCKEV_B, PCKEV_H, PCKEV_W, PCKEV_D,
    PCKOD_B, PCKOD_H, PCKOD_W, PCKOD_D,
    ILVEV_B, ILVEV_H, ILVEV_W, ILVEV_D,
    ILVOD_B, ILVOD_H, ILVOD_W, ILVOD_D,
    ILVL_B, ILVL_H, ILVL_W, ILVL_D,
    ILVR_B, ILVR_H, ILVR_W, ILVR_D,
    // MSA Min/Max
    MAX_S_B, MAX_S_H, MAX_S_W, MAX_S_D,
    MAX_U_B, MAX_U_H, MAX_U_W, MAX_U_D,
    MIN_S_B, MIN_S_H, MIN_S_W, MIN_S_D,
    MIN_U_B, MIN_U_H, MIN_U_W, MIN_U_D,
    MAX_A_B, MAX_A_H, MAX_A_W, MAX_A_D,
    MIN_A_B, MIN_A_H, MIN_A_W, MIN_A_D,
    // MSA Float
    FADD_W, FADD_D, FSUB_W, FSUB_D, FMUL_W, FMUL_D, FDIV_W, FDIV_D,
    FMADD_W, FMADD_D, FMSUB_W, FMSUB_D,
    FEXP2_W, FEXP2_D, FEXDO_H, FEXDO_W,
    FTQ_H, FTQ_W,
    FMIN_W, FMIN_D, FMIN_A_W, FMIN_A_D,
    FMAX_W, FMAX_D, FMAX_A_W, FMAX_A_D,
    FCOR_W, FCOR_D, FCUNE_W, FCUNE_D,
    FCNE_W, FCNE_D, FCEQ_W, FCEQ_D,
    FCUN_W, FCUN_D, FCUEQ_W, FCUEQ_D,
    FCULE_W, FCULE_D, FCULT_W, FCULT_D,
    FCUGE_W, FCUGE_D, FCUGT_W, FCUGT_D,
    FCLT_W, FCLT_D, FCLE_W, FCLE_D,
    FSAF_W, FSAF_D, FSOR_W, FSOR_D,
    FSEQ_W, FSEQ_D, FSUNE_W, FSUNE_D, FSNE_W, FSNE_D,
    FINT_S_W, FINT_S_D, FINT_U_W, FINT_U_D,
    FRINT_W, FRINT_D,
    FLOG2_W, FLOG2_D,
    FTRUNC_S_W, FTRUNC_S_D, FTRUNC_U_W, FTRUNC_U_D,
    FRSQRT2_S_W, FRSQRT2_S_D, FRCP2_S_W, FRCP2_S_D,
    FFINT_S_W, FFINT_S_D, FFINT_U_W, FFINT_U_D,
    FTINT_S_W, FTINT_S_D, FTINT_U_W, FTINT_U_D,
    FFQL_W, FFQL_D, FFQR_W, FFQR_D,
    FSQRT_W, FSQRT_D,
    FRCP_W, FRCP_D, FRSQRT_W, FRSQRT_D,
    FCLASS_W, FCLASS_D,
    // MSA Misc
    BNZ_V, BZ_V, BNZ_B, BNZ_H, BNZ_W, BNZ_D,
    BZ_B, BZ_H, BZ_W, BZ_D,
    CTCMSA, CFCMSA,
    VSHF_B, VSHF_H, VSHF_W, VSHF_D,
    SLD_B, SLD_H, SLD_W, SLD_D,
    SPLATI_B, SPLATI_H, SPLATI_W, SPLATI_D,
    NLOC_B, NLOC_H, NLOC_W, NLOC_D,
    NLZC_B, NLZC_H, NLZC_W, NLZC_D,
    PCNT_B, PCNT_H, PCNT_W, PCNT_D,
    MOVE_V,
    FEXUPL_W, FEXUPL_D, FEXUPR_W, FEXUPR_D,
    SHF_B, SHF_H, SHF_W,
    FTINT_RNE_W, FTINT_RNE_D, FTINT_RZ_W, FTINT_RZ_D,
    FTINT_RP_W, FTINT_RP_D, FTINT_RM_W, FTINT_RM_D,
    FCAF_W, FCAF_D,
    // DSP R2/R3
    ABSQ_S_PH, ABSQ_S_W, ABSQ_S_QB, ABSQ_S_QH,
    ADDQ_PH, ADDQ_S_PH, ADDQ_S_W, ADDQH_PH, ADDQH_W,
    ADDQH_R_PH, ADDQH_R_W, ADDSC, ADDWC,
    ADDU_PH, ADDU_S_PH, ADDU_QB, ADDU_S_QB,
    ADDUH_QB, ADDUH_R_QB, APPEND, PREPEND, BALIGN, BITREV, BPOSGE32,
    CMP_EQ_PH, CMP_LE_PH, CMP_LT_PH,
    CMPGU_EQ_QB, CMPGU_LE_QB, CMPGU_LT_QB,
    CMPU_EQ_QB, CMPU_LE_QB, CMPU_LT_QB,
    DPA_W_PH, DPAQX_S_W_PH, DPAQX_SA_W_PH,
    DPAU_H_QBL, DPAU_H_QBR,
    DPS_W_PH, DPSQX_S_W_PH, DPSQX_SA_W_PH,
    DPSU_H_QBL, DPSU_H_QBR,
    EXTP, EXTPDP, EXTPDPV, EXTPV,
    EXTR_W, EXTR_R_W, EXTR_RS_W, EXTR_S_H,
    EXTRV_W, EXTRV_R_W, EXTRV_RS_W, EXTRV_S_H,
    INSV, LBUX, LHX, LWX,
    MADD_DSP, MADDU_DSP,
    MAQ_S_W_PHL, MAQ_S_W_PHR, MAQ_SA_W_PHL, MAQ_SA_W_PHR,
    MFHIDSP, MTHIDSP,
    MODSUB, MSUB_DSP, MSUBU_DSP, MTHLIP,
    MUL_PH, MUL_S_PH,
    MULEQ_S_W_PHL, MULEQ_S_W_PHR,
    MULEU_S_PH_QBL, MULEU_S_PH_QBR,
    MULQ_RS_PH, MULQ_RS_W, MULQ_S_PH, MULQ_S_W,
    MULSA_W_PH, MULSAQ_S_W_PH,
    PACKRL_PH,
    PICK_PH, PICK_QB,
    PRECEQ_W_PHL, PRECEQ_W_PHR,
    PRECEQU_PH_QBL, PRECEQU_PH_QBR,
    PRECEU_PH_QBL, PRECEU_PH_QBR,
    PRECR_QB_PH, PRECR_SRA_PH_W, PRECR_SRA_R_PH_W,
    PRECRQ_PH_W, PRECRQ_QB_PH, PRECRQ_RS_PH_W,
    RADDU_W_QB,
    RDDSP, WRDSP,
    REPL_PH, REPL_QB, REPLV_PH, REPLV_QB,
    SHILO, SHILOV,
    SHLL_PH, SHLL_S_PH, SHLL_QB, SHLL_S_QB, SHLL_S_W,
    SHLLV_PH, SHLLV_S_PH, SHLLV_QB, SHLLV_S_QB, SHLLV_S_W,
    SHRA_PH, SHRA_R_PH, SHRA_R_QB, SHRA_R_W, SHRAV_PH,
    SHRAV_R_PH, SHRAV_R_QB, SHRAV_R_W,
    SHRL_PH, SHRL_QB, SHRLV_PH, SHRLV_QB,
    SUBQ_PH, SUBQ_S_PH, SUBQ_S_W, SUBQH_PH, SUBQH_W,
    SUBQH_R_PH, SUBQH_R_W,
    SUBU_PH, SUBU_S_PH, SUBU_QB, SUBU_S_QB,
    SUBUH_QB, SUBUH_R_QB,
    // VZ (Virtualization)
    HYPCALL, DMFC0G, DMTC0G, MFC0G, MTC0G,
    TLBGINV, TLBGINVF, TLBGP, TLBGR, TLBGWI, TLBGWR,
    MFGC0, MTGC0,
    // MIPS16e
    M16_ADDIUS5, M16_ADDIUSP, M16_ADDIUPC, M16_ADDIUR1SP, M16_ADDIUR2,
    M16_ADDU16, M16_AND16, M16_BEQZ16, M16_BNEZ16,
    M16_BTEQZ, M16_BTNEZ, M16_CMPI, M16_CMP, M16_DIV16,
    M16_EXTEND, M16_JAL16, M16_JALRC16, M16_JALX, M16_JRC16,
    M16_LB16, M16_LBU16, M16_LH16, M16_LHU16, M16_LI16, M16_LW16,
    M16_LWPC, M16_LWSP, M16_MFHI16, M16_MFLO16, M16_MOVE,
    M16_MOVEN, M16_MOVEZ, M16_MUL16, M16_MULT16,
    M16_NEG16, M16_NOT16, M16_OR16,
    M16_RESTORE, M16_RESTORE_JALRC, M16_SAVE, M16_SB16,
    M16_SEB16, M16_SEH16, M16_SH16, M16_SLL16,
    M16_SRA16, M16_SRL16, M16_SUBU16, M16_SW16, M16_SWSP,
    M16_XOR16, M16_ZEB16, M16_ZEH16,
    // microMIPS
    UMM_ADDIU32, UMM_ADDIUPC, UMM_ADDIUSP,
    UMM_ALIGN, UMM_ALNV4,
    UMM_AND16, UMM_ANDI16,
    UMM_B16, UMM_BALC16, UMM_BC16, UMM_BEQZC16, UMM_BNEZC16,
    UMM_BREAK16, UMM_CACHE, UMM_DIV,
    UMM_JALR16, UMM_JALRS16, UMM_JALRS, UMM_JALRX, UMM_JALX,
    UMM_JR16, UMM_JRADDIUSP, UMM_JRC16, UMM_JRCADDIUSP,
    UMM_LB16, UMM_LBU16, UMM_LH16, UMM_LHU16, UMM_LI16, UMM_LW16,
    UMM_LWGP, UMM_LWSP, UMM_MFHI16, UMM_MFLO16,
    UMM_MOVE16, UMM_MOVEP, UMM_MUL, UMM_NOP16,
    UMM_NOT16, UMM_OR16, UMM_SDBBP16,
    UMM_SH16, UMM_SLL16, UMM_SRA16, UMM_SRL16,
    UMM_SUB16, UMM_SUBU16, UMM_SW16, UMM_SWGP, UMM_SWSP,
    UMM_TEQ, UMM_TGE, UMM_TGEU, UMM_TLT, UMM_TLTU, UMM_TNE,
    UMM_XOR16, UMM_XORI16, UMM_PREF, UMM_SYSCALL,
    UMM_BAL, UMM_BEQ, UMM_BGEZ, UMM_BGTZ, UMM_BLEZ, UMM_BLTZ, UMM_BNE,
    UMM_MTHI16, UMM_MTLO16,
    UMM_LSA, UMM_DLSA,
    UMM_SELEQZ, UMM_SELNEZ, UMM_EHB,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MipsInstructionCategory {
    ArithmeticLogical, Move, Branch, LoadStore, Trap, System, Fpu, Simd, Dsp, Virtualization,
}
impl MipsMnemonic {
    pub fn as_str(&self) -> &'static str {
        use MipsMnemonic::*;
        match self {
            ADD => "ADD", ADDI => "ADDI", ADDIU => "ADDIU", ADDU => "ADDU",
            SUB => "SUB", SUBU => "SUBU",
            SLT => "SLT", SLTI => "SLTI", SLTIU => "SLTIU", SLTU => "SLTU",
            DADD => "DADD", DADDI => "DADDI", DADDIU => "DADDIU", DADDU => "DADDU",
            DSUB => "DSUB", DSUBU => "DSUBU",
            MUL => "MUL", MUH => "MUH", MULU => "MULU", MUHU => "MUHU",
            DMUL => "DMUL", DMUH => "DMUH", DMULU => "DMULU", DMUHU => "DMUHU",
            MULT => "MULT", MULTU => "MULTU", DMULT => "DMULT", DMULTU => "DMULTU",
            DIV => "DIV", DIVU => "DIVU", DDIV => "DDIV", DDIVU => "DDIVU",
            MADD => "MADD", MADDU => "MADDU", MSUB => "MSUB", MSUBU => "MSUBU",
            CLO => "CLO", CLZ => "CLZ", DCLO => "DCLO", DCLZ => "DCLZ",
            SEB => "SEB", SEH => "SEH", NEGU => "NEGU", NEG => "NEG",
            AND => "AND", ANDI => "ANDI", OR => "OR", ORI => "ORI",
            XOR => "XOR", XORI => "XORI", NOR => "NOR", LUI => "LUI",
            AUI => "AUI", DAUI => "DAUI", DAHI => "DAHI", DATI => "DATI",
            AUIPC => "AUIPC", ALUIPC => "ALUIPC",
            SLL => "SLL", SLLV => "SLLV", SRL => "SRL", SRLV => "SRLV",
            SRA => "SRA", SRAV => "SRAV",
            DSLL => "DSLL", DSLLV => "DSLLV", DSLL32 => "DSLL32",
            DSRL => "DSRL", DSRLV => "DSRLV", DSRL32 => "DSRL32",
            DSRA => "DSRA", DSRAV => "DSRAV", DSRA32 => "DSRA32",
            ROTR => "ROTR", ROTRV => "ROTRV", DROTR => "DROTR",
            DROTRV => "DROTRV", DROTR32 => "DROTR32",
            WSBH => "WSBH", DSBH => "DSBH", DSHD => "DSHD",
            MFHI => "MFHI", MTHI => "MTHI", MFLO => "MFLO", MTLO => "MTLO",
            MOVN => "MOVN", MOVZ => "MOVZ", MOVF => "MOVF", MOVT => "MOVT",
            MFC0 => "MFC0", MTC0 => "MTC0", DMFC0 => "DMFC0", DMTC0 => "DMTC0",
            MTC2 => "MTC2", MFC2 => "MFC2", MFC1 => "MFC1", DMFC1 => "DMFC1",
            MTC1 => "MTC1", DMTC1 => "DMTC1",
            MFHC1 => "MFHC1", MTHC1 => "MTHC1", MFHC2 => "MFHC2", MTHC2 => "MTHC2",
            CFC1 => "CFC1", CTC1 => "CTC1", CFC2 => "CFC2", CTC2 => "CTC2",
            RDHWR => "RDHWR", RDPGPR => "RDPGPR", WRPGPR => "WRPGPR",
            SELEQZ => "SELEQZ", SELNEZ => "SELNEZ",
            EXT => "EXT", INS => "INS",
            DEXT => "DEXT", DEXTM => "DEXTM", DEXTU => "DEXTU",
            DINS => "DINS", DINSM => "DINSM", DINSU => "DINSU",
            BEQ => "BEQ", BEQL => "BEQL", BNE => "BNE", BNEL => "BNEL",
            BLEZ => "BLEZ", BLEZL => "BLEZL", BGTZ => "BGTZ", BGTZL => "BGTZL",
            BLTZ => "BLTZ", BLTZL => "BLTZL", BLTZAL => "BLTZAL", BLTZALL => "BLTZALL",
            BGEZ => "BGEZ", BGEZL => "BGEZL", BGEZAL => "BGEZAL", BGEZALL => "BGEZALL",
            BC1F => "BC1F", BC1T => "BC1T", BC1FL => "BC1FL", BC1TL => "BC1TL",
            BC2F => "BC2F", BC2T => "BC2T", BC2FL => "BC2FL", BC2TL => "BC2TL",
            J => "J", JAL => "JAL", JR => "JR", JALR => "JALR",
            JR_HB => "JR.HB", JALR_HB => "JALR.HB", JALX => "JALX",
            B => "B", BAL => "BAL", NAL => "NAL",
            BEQC => "BEQC", BNEC => "BNEC", BOVC => "BOVC", BNVC => "BNVC",
            BGEC => "BGEC", BLTC => "BLTC", BGEUC => "BGEUC", BLTUC => "BLTUC",
            BGEZC => "BGEZC", BLEZC => "BLEZC", BGTZC => "BGTZC", BLTZC => "BLTZC",
            BC1EQZ => "BC1EQZ", BC1NEZ => "BC1NEZ",
            BC2EQZ => "BC2EQZ", BC2NEZ => "BC2NEZ",
            BALC => "BALC", BC => "BC", BEQZC => "BEQZC", BNEZC => "BNEZC",
            JIC => "JIC", JIALC => "JIALC",
            BLEZALC => "BLEZALC", BGEZALC => "BGEZALC",
            BGTZALC => "BGTZALC", BLTZALC => "BLTZALC",
            BEQZALC => "BEQZALC", BNEZALC => "BNEZALC",
            LB => "LB", LBU => "LBU", LH => "LH", LHU => "LHU",
            LW => "LW", LWU => "LWU", LD => "LD",
            SB => "SB", SH => "SH", SW => "SW", SD => "SD",
            LDL => "LDL", LDR => "LDR", SDL => "SDL", SDR => "SDR",
            LWL => "LWL", LWR => "LWR", SWL => "SWL", SWR => "SWR",
            LL => "LL", LLD => "LLD", SC => "SC", SCD => "SCD",
            LLWP => "LLWP", SCWP => "SCWP",
            PREF => "PREF", PREFX => "PREFX", CACHE => "CACHE",
            SYNC => "SYNC", SYNCI => "SYNCI", SYNCIE => "SYNCIE",
            LWPC => "LWPC", LWUPC => "LWUPC", LDPC => "LDPC",
            ADDIUPC => "ADDIUPC", ADDIUR2 => "ADDIUR2", ADDIUSP => "ADDIUSP",
            LWC1 => "LWC1", SWC1 => "SWC1", LDC1 => "LDC1", SDC1 => "SDC1",
            LWC2 => "LWC2", SWC2 => "SWC2", LDC2 => "LDC2", SDC2 => "SDC2",
            LDC3 => "LDC3", SDC3 => "SDC3",
            LWXC1 => "LWXC1", LDXC1 => "LDXC1", SWXC1 => "SWXC1",
            SDXC1 => "SDXC1", LUXC1 => "LUXC1", SUXC1 => "SUXC1",
            TGE => "TGE", TGEU => "TGEU", TLT => "TLT", TLTU => "TLTU",
            TEQ => "TEQ", TNE => "TNE",
            TGEI => "TGEI", TGEIU => "TGEIU", TLTI => "TLTI", TLTIU => "TLTIU",
            TEQI => "TEQI", TNEI => "TNEI",
            TGEL => "TGEL", TGEUL => "TGEUL", TLTL => "TLTL", TLTUL => "TLTUL",
            TEQL => "TEQL", TNEL => "TNEL",
            SYSCALL => "SYSCALL", BREAK => "BREAK",
            ERET => "ERET", ERETNC => "ERETNC", WAIT => "WAIT",
            SSNOP => "SSNOP", NOP => "NOP", EHB => "EHB", PAUSE => "PAUSE",
            DI => "DI", EI => "EI", DERET => "DERET",
            TLBP => "TLBP", TLBR => "TLBR", TLBWI => "TLBWI", TLBWR => "TLBWR",
            TLBINV => "TLBINV", TLBINVF => "TLBINVF", TLBINVF_FULL => "TLBINVF",
            ADD_S => "ADD.S", ADD_D => "ADD.D",
            SUB_S => "SUB.S", SUB_D => "SUB.D",
            MUL_S => "MUL.S", MUL_D => "MUL.D",
            DIV_S => "DIV.S", DIV_D => "DIV.D",
            SQRT_S => "SQRT.S", SQRT_D => "SQRT.D",
            ABS_S => "ABS.S", ABS_D => "ABS.D",
            NEG_S => "NEG.S", NEG_D => "NEG.D",
            MOV_S => "MOV.S", MOV_D => "MOV.D",
            MOVF_S => "MOVF.S", MOVF_D => "MOVF.D",
            MOVT_S => "MOVT.S", MOVT_D => "MOVT.D",
            MOVZ_S => "MOVZ.S", MOVZ_D => "MOVZ.D",
            MOVN_S => "MOVN.S", MOVN_D => "MOVN.D",
            CVT_S_D => "CVT.S.D", CVT_S_W => "CVT.S.W", CVT_S_L => "CVT.S.L",
            CVT_D_S => "CVT.D.S", CVT_D_W => "CVT.D.W", CVT_D_L => "CVT.D.L",
            CVT_W_S => "CVT.W.S", CVT_W_D => "CVT.W.D",
            CVT_L_S => "CVT.L.S", CVT_L_D => "CVT.L.D",
            CVT_PS_S => "CVT.PS.S",
            CEIL_W_S => "CEIL.W.S", CEIL_W_D => "CEIL.W.D",
            CEIL_L_S => "CEIL.L.S", CEIL_L_D => "CEIL.L.D",
            FLOOR_W_S => "FLOOR.W.S", FLOOR_W_D => "FLOOR.W.D",
            FLOOR_L_S => "FLOOR.L.S", FLOOR_L_D => "FLOOR.L.D",
            ROUND_W_S => "ROUND.W.S", ROUND_W_D => "ROUND.W.D",
            ROUND_L_S => "ROUND.L.S", ROUND_L_D => "ROUND.L.D",
            TRUNC_W_S => "TRUNC.W.S", TRUNC_W_D => "TRUNC.W.D",
            TRUNC_L_S => "TRUNC.L.S", TRUNC_L_D => "TRUNC.L.D",
            RECIP_S => "RECIP.S", RECIP_D => "RECIP.D",
            RSQRT_S => "RSQRT.S", RSQRT_D => "RSQRT.D",
            C_F_S => "C.F.S", C_F_D => "C.F.D",
            C_UN_S => "C.UN.S", C_UN_D => "C.UN.D",
            C_EQ_S => "C.EQ.S", C_EQ_D => "C.EQ.D",
            C_LT_S => "C.LT.S", C_LT_D => "C.LT.D",
            C_LE_S => "C.LE.S", C_LE_D => "C.LE.D",
            C_UEQ_S => "C.UEQ.S", C_UEQ_D => "C.UEQ.D",
            C_ULT_S => "C.ULT.S", C_ULT_D => "C.ULT.D",
            C_ULE_S => "C.ULE.S", C_ULE_D => "C.ULE.D",
            C_OLE_S => "C.OLE.S", C_OLE_D => "C.OLE.D",
            C_OLT_S => "C.OLT.S", C_OLT_D => "C.OLT.D",
            C_SEQ_S => "C.SEQ.S", C_SEQ_D => "C.SEQ.D",
            C_NGT_S => "C.NGT.S", C_NGT_D => "C.NGT.D",
            C_NGE_S => "C.NGE.S", C_NGE_D => "C.NGE.D",
            C_NGLE_S => "C.NGLE.S", C_NGLE_D => "C.NGLE.D",
            C_NGL_S => "C.NGL.S", C_NGL_D => "C.NGL.D",
            MADDF_S => "MADDF.S", MADDF_D => "MADDF.D",
            MSUBF_S => "MSUBF.S", MSUBF_D => "MSUBF.D",
            MAX_S => "MAX.S", MAX_D => "MAX.D",
            MIN_S => "MIN.S", MIN_D => "MIN.D",
            MAXA_S => "MAXA.S", MAXA_D => "MAXA.D",
            MINA_S => "MINA.S", MINA_D => "MINA.D",
            SEL_S => "SEL.S", SEL_D => "SEL.D",
            SELEQZ_S => "SELEQZ.S", SELEQZ_D => "SELEQZ.D",
            SELNEZ_S => "SELNEZ.S", SELNEZ_D => "SELNEZ.D",
            CLASS_S => "CLASS.S", CLASS_D => "CLASS.D",
            RINT_S => "RINT.S", RINT_D => "RINT.D",
            BC1ANY2F => "BC1ANY2F", BC1ANY2T => "BC1ANY2T",
            BC1ANY4F => "BC1ANY4F", BC1ANY4T => "BC1ANY4T",
            MADD_S => "MADD.S", MSUB_S => "MSUB.S",
            NMADD_S => "NMADD.S", NMSUB_S => "NMSUB.S",
            MADD_D => "MADD.D", MSUB_D => "MSUB.D",
            NMADD_D => "NMADD.D", NMSUB_D => "NMSUB.D",
            CMP_AF_S => "CMP.AF.S", CMP_AF_D => "CMP.AF.D",
            CMP_UN_S => "CMP.UN.S", CMP_UN_D => "CMP.UN.D",
            CMP_EQ_S => "CMP.EQ.S", CMP_EQ_D => "CMP.EQ.D",
            CMP_UEQ_S => "CMP.UEQ.S", CMP_UEQ_D => "CMP.UEQ.D",
            CMP_LT_S => "CMP.LT.S", CMP_LT_D => "CMP.LT.D",
            CMP_ULT_S => "CMP.ULT.S", CMP_ULT_D => "CMP.ULT.D",
            CMP_LE_S => "CMP.LE.S", CMP_LE_D => "CMP.LE.D",
            CMP_ULE_S => "CMP.ULE.S", CMP_ULE_D => "CMP.ULE.D",
            CMP_SAF_S => "CMP.SAF.S", CMP_SAF_D => "CMP.SAF.D",
            CMP_SUN_S => "CMP.SUN.S", CMP_SUN_D => "CMP.SUN.D",
            CMP_SEQ_S => "CMP.SEQ.S", CMP_SEQ_D => "CMP.SEQ.D",
            LD_B => "LD.B", LD_H => "LD.H", LD_W => "LD.W", LD_D => "LD.D",
            ST_B => "ST.B", ST_H => "ST.H", ST_W => "ST.W", ST_D => "ST.D",
            LD_MSA => "LD.MSA", ST_MSA => "ST.MSA",
            LDI_B => "LDI.B", LDI_H => "LDI.H", LDI_W => "LDI.W", LDI_D => "LDI.D",
            INSERT_B => "INSERT.B", INSERT_H => "INSERT.H", INSERT_W => "INSERT.W", INSERT_D => "INSERT.D",
            INSVE_B => "INSVE.B", INSVE_H => "INSVE.H", INSVE_W => "INSVE.W", INSVE_D => "INSVE.D",
            COPY_S_B => "COPY_S.B", COPY_S_H => "COPY_S.H", COPY_S_W => "COPY_S.W", COPY_S_D => "COPY_S.D",
            COPY_U_B => "COPY_U.B", COPY_U_H => "COPY_U.H", COPY_U_W => "COPY_U.W",
            FILL_B => "FILL.B", FILL_H => "FILL.H", FILL_W => "FILL.W", FILL_D => "FILL.D",
            SPLAT_B => "SPLAT.B", SPLAT_H => "SPLAT.H", SPLAT_W => "SPLAT.W", SPLAT_D => "SPLAT.D",
            ADDV_B => "ADDV.B", ADDV_H => "ADDV.H", ADDV_W => "ADDV.W", ADDV_D => "ADDV.D",
            SUBV_B => "SUBV.B", SUBV_H => "SUBV.H", SUBV_W => "SUBV.W", SUBV_D => "SUBV.D",
            MULV_B => "MULV.B", MULV_H => "MULV.H", MULV_W => "MULV.W", MULV_D => "MULV.D",
            DIV_S_B => "DIV_S.B", DIV_S_H => "DIV_S.H", DIV_S_W => "DIV_S.W", DIV_S_D => "DIV_S.D",
            DIV_U_B => "DIV_U.B", DIV_U_H => "DIV_U.H", DIV_U_W => "DIV_U.W", DIV_U_D => "DIV_U.D",
            MOD_S_B => "MOD_S.B", MOD_S_H => "MOD_S.H", MOD_S_W => "MOD_S.W", MOD_S_D => "MOD_S.D",
            MOD_U_B => "MOD_U.B", MOD_U_H => "MOD_U.H", MOD_U_W => "MOD_U.W", MOD_U_D => "MOD_U.D",
            MADDV_B => "MADDV.B", MADDV_H => "MADDV.H", MADDV_W => "MADDV.W", MADDV_D => "MADDV.D",
            MSUBV_B => "MSUBV.B", MSUBV_H => "MSUBV.H", MSUBV_W => "MSUBV.W", MSUBV_D => "MSUBV.D",
            AND_V => "AND.V", OR_V => "OR.V", NOR_V => "NOR.V", XOR_V => "XOR.V",
            BCLR_B => "BCLR.B", BCLR_H => "BCLR.H", BCLR_W => "BCLR.W", BCLR_D => "BCLR.D",
            BSET_B => "BSET.B", BSET_H => "BSET.H", BSET_W => "BSET.W", BSET_D => "BSET.D",
            BNEG_B => "BNEG.B", BNEG_H => "BNEG.H", BNEG_W => "BNEG.W", BNEG_D => "BNEG.D",
            BMNZ_V => "BMNZ.V", BMZ_V => "BMZ.V", BSEL_V => "BSEL.V",
            SLL_B => "SLL.B", SLL_H => "SLL.H", SLL_W => "SLL.W", SLL_D => "SLL.D",
            SRA_B => "SRA.B", SRA_H => "SRA.H", SRA_W => "SRA.W", SRA_D => "SRA.D",
            SRL_B => "SRL.B", SRL_H => "SRL.H", SRL_W => "SRL.W", SRL_D => "SRL.D",
            SRAR_B => "SRAR.B", SRAR_H => "SRAR.H", SRAR_W => "SRAR.W", SRAR_D => "SRAR.D",
            SRLR_B => "SRLR.B", SRLR_H => "SRLR.H", SRLR_W => "SRLR.W", SRLR_D => "SRLR.D",
            CEQ_B => "CEQ.B", CEQ_H => "CEQ.H", CEQ_W => "CEQ.W", CEQ_D => "CEQ.D",
            CLE_S_B => "CLE_S.B", CLE_S_H => "CLE_S.H", CLE_S_W => "CLE_S.W", CLE_S_D => "CLE_S.D",
            CLE_U_B => "CLE_U.B", CLE_U_H => "CLE_U.H", CLE_U_W => "CLE_U.W", CLE_U_D => "CLE_U.D",
            CLT_S_B => "CLT_S.B", CLT_S_H => "CLT_S.H", CLT_S_W => "CLT_S.W", CLT_S_D => "CLT_S.D",
            CLT_U_B => "CLT_U.B", CLT_U_H => "CLT_U.H", CLT_U_W => "CLT_U.W", CLT_U_D => "CLT_U.D",
            PCKEV_B => "PCKEV.B", PCKEV_H => "PCKEV.H", PCKEV_W => "PCKEV.W", PCKEV_D => "PCKEV.D",
            PCKOD_B => "PCKOD.B", PCKOD_H => "PCKOD.H", PCKOD_W => "PCKOD.W", PCKOD_D => "PCKOD.D",
            ILVEV_B => "ILVEV.B", ILVEV_H => "ILVEV.H", ILVEV_W => "ILVEV.W", ILVEV_D => "ILVEV.D",
            ILVOD_B => "ILVOD.B", ILVOD_H => "ILVOD.H", ILVOD_W => "ILVOD.W", ILVOD_D => "ILVOD.D",
            ILVL_B => "ILVL.B", ILVL_H => "ILVL.H", ILVL_W => "ILVL.W", ILVL_D => "ILVL.D",
            ILVR_B => "ILVR.B", ILVR_H => "ILVR.H", ILVR_W => "ILVR.W", ILVR_D => "ILVR.D",
            MAX_S_B => "MAX_S.B", MAX_S_H => "MAX_S.H", MAX_S_W => "MAX_S.W", MAX_S_D => "MAX_S.D",
            MAX_U_B => "MAX_U.B", MAX_U_H => "MAX_U.H", MAX_U_W => "MAX_U.W", MAX_U_D => "MAX_U.D",
            MIN_S_B => "MIN_S.B", MIN_S_H => "MIN_S.H", MIN_S_W => "MIN_S.W", MIN_S_D => "MIN_S.D",
            MIN_U_B => "MIN_U.B", MIN_U_H => "MIN_U.H", MIN_U_W => "MIN_U.W", MIN_U_D => "MIN_U.D",
            MAX_A_B => "MAX_A.B", MAX_A_H => "MAX_A.H", MAX_A_W => "MAX_A.W", MAX_A_D => "MAX_A.D",
            MIN_A_B => "MIN_A.B", MIN_A_H => "MIN_A.H", MIN_A_W => "MIN_A.W", MIN_A_D => "MIN_A.D",
            FADD_W => "FADD.W", FADD_D => "FADD.D",
            FSUB_W => "FSUB.W", FSUB_D => "FSUB.D",
            FMUL_W => "FMUL.W", FMUL_D => "FMUL.D",
            FDIV_W => "FDIV.W", FDIV_D => "FDIV.D",
            FMADD_W => "FMADD.W", FMADD_D => "FMADD.D",
            FMSUB_W => "FMSUB.W", FMSUB_D => "FMSUB.D",
            FEXP2_W => "FEXP2.W", FEXP2_D => "FEXP2.D",
            FCEQ_W => "FCEQ.W", FCEQ_D => "FCEQ.D",
            FCLT_W => "FCLT.W", FCLT_D => "FCLT.D",
            FCLE_W => "FCLE.W", FCLE_D => "FCLE.D",
            FMIN_W => "FMIN.W", FMIN_D => "FMIN.D",
            FMIN_A_W => "FMIN_A.W", FMIN_A_D => "FMIN_A.D",
            FMAX_W => "FMAX.W", FMAX_D => "FMAX.D",
            FMAX_A_W => "FMAX_A.W", FMAX_A_D => "FMAX_A.D",
            FSQRT_W => "FSQRT.W", FSQRT_D => "FSQRT.D",
            FCLASS_W => "FCLASS.W", FCLASS_D => "FCLASS.D",
            FTRUNC_S_W => "FTRUNC_S.W", FTRUNC_S_D => "FTRUNC_S.D",
            FTRUNC_U_W => "FTRUNC_U.W", FTRUNC_U_D => "FTRUNC_U.D",
            FINT_S_W => "FINT_S.W", FINT_S_D => "FINT_S.D",
            FINT_U_W => "FINT_U.W", FINT_U_D => "FINT_U.D",
            FRINT_W => "FRINT.W", FRINT_D => "FRINT.D",
            FFINT_S_W => "FFINT_S.W", FFINT_S_D => "FFINT_S.D",
            FFINT_U_W => "FFINT_U.W", FFINT_U_D => "FFINT_U.D",
            FTINT_S_W => "FTINT_S.W", FTINT_S_D => "FTINT_S.D",
            FTINT_U_W => "FTINT_U.W", FTINT_U_D => "FTINT_U.D",
            BNZ_V => "BNZ.V", BZ_V => "BZ.V",
            BNZ_B => "BNZ.B", BNZ_H => "BNZ.H", BNZ_W => "BNZ.W", BNZ_D => "BNZ.D",
            BZ_B => "BZ.B", BZ_H => "BZ.H", BZ_W => "BZ.W", BZ_D => "BZ.D",
            CTCMSA => "CTCMSA", CFCMSA => "CFCMSA",
            MOVE_V => "MOVE.V",
            VSHF_B => "VSHF.B", VSHF_H => "VSHF.H", VSHF_W => "VSHF.W", VSHF_D => "VSHF.D",
            SLD_B => "SLD.B", SLD_H => "SLD.H", SLD_W => "SLD.W", SLD_D => "SLD.D",
            SPLATI_B => "SPLATI.B", SPLATI_H => "SPLATI.H", SPLATI_W => "SPLATI.W", SPLATI_D => "SPLATI.D",
            NLOC_B => "NLOC.B", NLOC_H => "NLOC.H", NLOC_W => "NLOC.W", NLOC_D => "NLOC.D",
            NLZC_B => "NLZC.B", NLZC_H => "NLZC.H", NLZC_W => "NLZC.W", NLZC_D => "NLZC.D",
            PCNT_B => "PCNT.B", PCNT_H => "PCNT.H", PCNT_W => "PCNT.W", PCNT_D => "PCNT.D",
            FCAF_W => "FCAF.W", FCAF_D => "FCAF.D",
            FCOR_W => "FCOR.W", FCOR_D => "FCOR.D",
            FCUNE_W => "FCUNE.W", FCUNE_D => "FCUNE.D",
            FCNE_W => "FCNE.W", FCNE_D => "FCNE.D",
            FCUN_W => "FCUN.W", FCUN_D => "FCUN.D",
            FCUEQ_W => "FCUEQ.W", FCUEQ_D => "FCUEQ.D",
            FCULE_W => "FCULE.W", FCULE_D => "FCULE.D",
            FCULT_W => "FCULT.W", FCULT_D => "FCULT.D",
            FCUGE_W => "FCUGE.W", FCUGE_D => "FCUGE.D",
            FCUGT_W => "FCUGT.W", FCUGT_D => "FCUGT.D",
            FSAF_W => "FSAF.W", FSAF_D => "FSAF.D",
            FSOR_W => "FSOR.W", FSOR_D => "FSOR.D",
            FSEQ_W => "FSEQ.W", FSEQ_D => "FSEQ.D",
            FSUNE_W => "FSUNE.W", FSUNE_D => "FSUNE.D",
            FSNE_W => "FSNE.W", FSNE_D => "FSNE.D",
            FEXDO_H => "FEXDO.H", FEXDO_W => "FEXDO.W",
            FTQ_H => "FTQ.H", FTQ_W => "FTQ.W",
            FFQL_W => "FFQL.W", FFQL_D => "FFQL.D",
            FFQR_W => "FFQR.W", FFQR_D => "FFQR.D",
            FRCP_W => "FRCP.W", FRCP_D => "FRCP.D",
            FRSQRT_W => "FRSQRT.W", FRSQRT_D => "FRSQRT.D",
            FRSQRT2_S_W => "FRSQRT2_S.W", FRSQRT2_S_D => "FRSQRT2_S.D",
            FRCP2_S_W => "FRCP2_S.W", FRCP2_S_D => "FRCP2_S.D",
            FTINT_RNE_W => "FTINT_RNE.W", FTINT_RNE_D => "FTINT_RNE.D",
            FTINT_RZ_W => "FTINT_RZ.W", FTINT_RZ_D => "FTINT_RZ.D",
            FTINT_RP_W => "FTINT_RP.W", FTINT_RP_D => "FTINT_RP.D",
            FTINT_RM_W => "FTINT_RM.W", FTINT_RM_D => "FTINT_RM.D",
            SHF_B => "SHF.B", SHF_H => "SHF.H", SHF_W => "SHF.W",
            AVE_S_B => "AVE_S.B", AVE_S_H => "AVE_S.H", AVE_S_W => "AVE_S.W", AVE_S_D => "AVE_S.D",
            AVE_U_B => "AVE_U.B", AVE_U_H => "AVE_U.H", AVE_U_W => "AVE_U.W", AVE_U_D => "AVE_U.D",
            AVER_S_B => "AVER_S.B", AVER_S_H => "AVER_S.H", AVER_S_W => "AVER_S.W", AVER_S_D => "AVER_S.D",
            AVER_U_B => "AVER_U.B", AVER_U_H => "AVER_U.H", AVER_U_W => "AVER_U.W", AVER_U_D => "AVER_U.D",
            ASUB_S_B => "ASUB_S.B", ASUB_S_H => "ASUB_S.H", ASUB_S_W => "ASUB_S.W", ASUB_S_D => "ASUB_S.D",
            ASUB_U_B => "ASUB_U.B", ASUB_U_H => "ASUB_U.H", ASUB_U_W => "ASUB_U.W", ASUB_U_D => "ASUB_U.D",
            HADD_S_H => "HADD_S.H", HADD_S_W => "HADD_S.W", HADD_S_D => "HADD_S.D",
            HADD_U_H => "HADD_U.H", HADD_U_W => "HADD_U.W", HADD_U_D => "HADD_U.D",
            HSUB_S_H => "HSUB_S.H", HSUB_S_W => "HSUB_S.W", HSUB_S_D => "HSUB_S.D",
            HSUB_U_H => "HSUB_U.H", HSUB_U_W => "HSUB_U.W", HSUB_U_D => "HSUB_U.D",
            DOTP_S_H => "DOTP_S.H", DOTP_S_W => "DOTP_S.W", DOTP_S_D => "DOTP_S.D",
            DOTP_U_H => "DOTP_U.H", DOTP_U_W => "DOTP_U.W", DOTP_U_D => "DOTP_U.D",
            DPADD_S_H => "DPADD_S.H", DPADD_S_W => "DPADD_S.W", DPADD_S_D => "DPADD_S.D",
            DPADD_U_H => "DPADD_U.H", DPADD_U_W => "DPADD_U.W", DPADD_U_D => "DPADD_U.D",
            DPSUB_S_H => "DPSUB_S.H", DPSUB_S_W => "DPSUB_S.W", DPSUB_S_D => "DPSUB_S.D",
            DPSUB_U_H => "DPSUB_U.H", DPSUB_U_W => "DPSUB_U.W", DPSUB_U_D => "DPSUB_U.D",
            MUL_Q_H => "MUL_Q.H", MUL_Q_W => "MUL_Q.W",
            MULR_Q_H => "MULR_Q.H", MULR_Q_W => "MULR_Q.W",
            MADD_Q_H => "MADD_Q.H", MADD_Q_W => "MADD_Q.W",
            MADDR_Q_H => "MADDR_Q.H", MADDR_Q_W => "MADDR_Q.W",
            MSUB_Q_H => "MSUB_Q.H", MSUB_Q_W => "MSUB_Q.W",
            MSUBR_Q_H => "MSUBR_Q.H", MSUBR_Q_W => "MSUBR_Q.W",
            SAT_S_B => "SAT_S.B", SAT_S_H => "SAT_S.H", SAT_S_W => "SAT_S.W", SAT_S_D => "SAT_S.D",
            SAT_U_B => "SAT_U.B", SAT_U_H => "SAT_U.H", SAT_U_W => "SAT_U.W", SAT_U_D => "SAT_U.D",
            SUBS_S_B => "SUBS_S.B", SUBS_S_H => "SUBS_S.H", SUBS_S_W => "SUBS_S.W", SUBS_S_D => "SUBS_S.D",
            SUBS_U_B => "SUBS_U.B", SUBS_U_H => "SUBS_U.H", SUBS_U_W => "SUBS_U.W", SUBS_U_D => "SUBS_U.D",
            SUBSUS_U_B => "SUBSUS_U.B", SUBSUS_U_H => "SUBSUS_U.H", SUBSUS_U_W => "SUBSUS_U.W", SUBSUS_U_D => "SUBSUS_U.D",
            SUBSUU_S_B => "SUBSUU_S.B", SUBSUU_S_H => "SUBSUU_S.H", SUBSUU_S_W => "SUBSUU_S.W", SUBSUU_S_D => "SUBSUU_S.D",
            CMP_EQ_B => "CMP_EQ.B", CMP_EQ_H => "CMP_EQ.H", CMP_EQ_W => "CMP_EQ.W", CMP_EQ_D => "CMP_EQ.D",
            CMP_LE_S_B => "CMP_LE_S.B", CMP_LE_S_H => "CMP_LE_S.H", CMP_LE_S_W => "CMP_LE_S.W", CMP_LE_S_D => "CMP_LE_S.D",
            CMP_LE_U_B => "CMP_LE_U.B", CMP_LE_U_H => "CMP_LE_U.H", CMP_LE_U_W => "CMP_LE_U.W", CMP_LE_U_D => "CMP_LE_U.D",
            CMP_LT_S_B => "CMP_LT_S.B", CMP_LT_S_H => "CMP_LT_S.H", CMP_LT_S_W => "CMP_LT_S.W", CMP_LT_S_D => "CMP_LT_S.D",
            CMP_LT_U_B => "CMP_LT_U.B", CMP_LT_U_H => "CMP_LT_U.H", CMP_LT_U_W => "CMP_LT_U.W", CMP_LT_U_D => "CMP_LT_U.D",
            ABSQ_S_PH => "ABSQ_S.PH", ABSQ_S_W => "ABSQ_S.W",
            ABSQ_S_QB => "ABSQ_S.QB", ABSQ_S_QH => "ABSQ_S.QH",
            ADDQ_PH => "ADDQ.PH", ADDQ_S_PH => "ADDQ_S.PH", ADDQ_S_W => "ADDQ_S.W",
            ADDQH_PH => "ADDQH.PH", ADDQH_W => "ADDQH.W",
            ADDQH_R_PH => "ADDQH_R.PH", ADDQH_R_W => "ADDQH_R.W",
            ADDSC => "ADDSC", ADDWC => "ADDWC",
            ADDU_PH => "ADDU.PH", ADDU_S_PH => "ADDU_S.PH",
            ADDU_QB => "ADDU.QB", ADDU_S_QB => "ADDU_S.QB",
            ADDUH_QB => "ADDUH.QB", ADDUH_R_QB => "ADDUH_R.QB",
            APPEND => "APPEND", PREPEND => "PREPEND",
            BALIGN => "BALIGN", BITREV => "BITREV", BPOSGE32 => "BPOSGE32",
            CMP_EQ_PH => "CMP.EQ.PH", CMP_LE_PH => "CMP.LE.PH", CMP_LT_PH => "CMP.LT.PH",
            CMPGU_EQ_QB => "CMPGU.EQ.QB", CMPGU_LE_QB => "CMPGU.LE.QB", CMPGU_LT_QB => "CMPGU.LT.QB",
            CMPU_EQ_QB => "CMPU.EQ.QB", CMPU_LE_QB => "CMPU.LE.QB", CMPU_LT_QB => "CMPU.LT.QB",
            DPA_W_PH => "DPA.W.PH", DPAQX_S_W_PH => "DPAQX_S.W.PH", DPAQX_SA_W_PH => "DPAQX_SA.W.PH",
            DPAU_H_QBL => "DPAU.H.QBL", DPAU_H_QBR => "DPAU.H.QBR",
            DPS_W_PH => "DPS.W.PH", DPSQX_S_W_PH => "DPSQX_S.W.PH", DPSQX_SA_W_PH => "DPSQX_SA.W.PH",
            DPSU_H_QBL => "DPSU.H.QBL", DPSU_H_QBR => "DPSU.H.QBR",
            EXTP => "EXTP", EXTPDP => "EXTPDP", EXTPDPV => "EXTPDPV", EXTPV => "EXTPV",
            EXTR_W => "EXTR.W", EXTR_R_W => "EXTR_R.W", EXTR_RS_W => "EXTR_RS.W", EXTR_S_H => "EXTR_S.H",
            EXTRV_W => "EXTRV.W", EXTRV_R_W => "EXTRV_R.W", EXTRV_RS_W => "EXTRV_RS.W", EXTRV_S_H => "EXTRV_S.H",
            INSV => "INSV", LBUX => "LBUX", LHX => "LHX", LWX => "LWX",
            MADD_DSP => "MADD", MADDU_DSP => "MADDU",
            MAQ_S_W_PHL => "MAQ_S.W.PHL", MAQ_S_W_PHR => "MAQ_S.W.PHR",
            MAQ_SA_W_PHL => "MAQ_SA.W.PHL", MAQ_SA_W_PHR => "MAQ_SA.W.PHR",
            MFHIDSP => "MFHIDSP", MTHIDSP => "MTHIDSP",
            MODSUB => "MODSUB", MSUB_DSP => "MSUB", MSUBU_DSP => "MSUBU", MTHLIP => "MTHLIP",
            MUL_PH => "MUL.PH", MUL_S_PH => "MUL_S.PH",
            MULEQ_S_W_PHL => "MULEQ_S.W.PHL", MULEQ_S_W_PHR => "MULEQ_S.W.PHR",
            MULEU_S_PH_QBL => "MULEU_S.PH.QBL", MULEU_S_PH_QBR => "MULEU_S.PH.QBR",
            MULQ_RS_PH => "MULQ_RS.PH", MULQ_RS_W => "MULQ_RS.W",
            MULQ_S_PH => "MULQ_S.PH", MULQ_S_W => "MULQ_S.W",
            MULSA_W_PH => "MULSA.W.PH", MULSAQ_S_W_PH => "MULSAQ_S.W.PH",
            PACKRL_PH => "PACKRL.PH",
            PICK_PH => "PICK.PH", PICK_QB => "PICK.QB",
            PRECEQ_W_PHL => "PRECEQ.W.PHL", PRECEQ_W_PHR => "PRECEQ.W.PHR",
            PRECEQU_PH_QBL => "PRECEQU.PH.QBL", PRECEQU_PH_QBR => "PRECEQU.PH.QBR",
            PRECEU_PH_QBL => "PRECEU.PH.QBL", PRECEU_PH_QBR => "PRECEU.PH.QBR",
            PRECR_QB_PH => "PRECR.QB.PH",
            PRECR_SRA_PH_W => "PRECR_SRA.PH.W", PRECR_SRA_R_PH_W => "PRECR_SRA_R.PH.W",
            PRECRQ_PH_W => "PRECRQ.PH.W", PRECRQ_QB_PH => "PRECRQ.QB.PH",
            PRECRQ_RS_PH_W => "PRECRQ_RS.PH.W",
            RADDU_W_QB => "RADDU.W.QB",
            RDDSP => "RDDSP", WRDSP => "WRDSP",
            REPL_PH => "REPL.PH", REPL_QB => "REPL.QB",
            REPLV_PH => "REPLV.PH", REPLV_QB => "REPLV.QB",
            SHILO => "SHILO", SHILOV => "SHILOV",
            SHLL_PH => "SHLL.PH", SHLL_S_PH => "SHLL_S.PH",
            SHLL_QB => "SHLL.QB", SHLL_S_QB => "SHLL_S.QB", SHLL_S_W => "SHLL_S.W",
            SHLLV_PH => "SHLLV.PH", SHLLV_S_PH => "SHLLV_S.PH",
            SHLLV_QB => "SHLLV.QB", SHLLV_S_QB => "SHLLV_S.QB", SHLLV_S_W => "SHLLV_S.W",
            SHRA_PH => "SHRA.PH", SHRA_R_PH => "SHRA_R.PH",
            SHRA_R_QB => "SHRA_R.QB", SHRA_R_W => "SHRA_R.W",
            SHRAV_PH => "SHRAV.PH", SHRAV_R_PH => "SHRAV_R.PH",
            SHRAV_R_QB => "SHRAV_R.QB", SHRAV_R_W => "SHRAV_R.W",
            SHRL_PH => "SHRL.PH", SHRL_QB => "SHRL.QB",
            SHRLV_PH => "SHRLV.PH", SHRLV_QB => "SHRLV.QB",
            SUBQ_PH => "SUBQ.PH", SUBQ_S_PH => "SUBQ_S.PH", SUBQ_S_W => "SUBQ_S.W",
            SUBQH_PH => "SUBQH.PH", SUBQH_W => "SUBQH.W",
            SUBQH_R_PH => "SUBQH_R.PH", SUBQH_R_W => "SUBQH_R.W",
            SUBU_PH => "SUBU.PH", SUBU_S_PH => "SUBU_S.PH",
            SUBU_QB => "SUBU.QB", SUBU_S_QB => "SUBU_S.QB",
            SUBUH_QB => "SUBUH.QB", SUBUH_R_QB => "SUBUH_R.QB",
            HYPCALL => "HYPCALL",
            DMFC0G => "DMFC0G", DMTC0G => "DMTC0G",
            MFC0G => "MFC0G", MTC0G => "MTC0G",
            TLBGINV => "TLBGINV", TLBGINVF => "TLBGINVF",
            TLBGP => "TLBGP", TLBGR => "TLBGR", TLBGWI => "TLBGWI", TLBGWR => "TLBGWR",
            MFGC0 => "MFGC0", MTGC0 => "MTGC0",
            M16_ADDIUS5 => "ADDIUS5", M16_ADDIUSP => "ADDIUSP",
            M16_ADDIUPC => "ADDIUPC", M16_ADDIUR1SP => "ADDIUR1SP", M16_ADDIUR2 => "ADDIUR2",
            M16_ADDU16 => "ADDU16", M16_AND16 => "AND16",
            M16_BEQZ16 => "BEQZ16", M16_BNEZ16 => "BNEZ16",
            M16_BTEQZ => "BTEQZ", M16_BTNEZ => "BTNEZ",
            M16_CMPI => "CMPI", M16_CMP => "CMP", M16_DIV16 => "DIV16",
            M16_EXTEND => "EXTEND", M16_JAL16 => "JAL16",
            M16_JALRC16 => "JALRC16", M16_JALX => "JALX", M16_JRC16 => "JRC16",
            M16_LB16 => "LB16", M16_LBU16 => "LBU16", M16_LH16 => "LH16",
            M16_LHU16 => "LHU16", M16_LI16 => "LI16", M16_LW16 => "LW16",
            M16_LWPC => "LWPC", M16_LWSP => "LWSP",
            M16_MFHI16 => "MFHI16", M16_MFLO16 => "MFLO16",
            M16_MOVE => "MOVE", M16_MOVEN => "MOVEN", M16_MOVEZ => "MOVEZ",
            M16_MUL16 => "MUL16", M16_MULT16 => "MULT16",
            M16_NEG16 => "NEG16", M16_NOT16 => "NOT16", M16_OR16 => "OR16",
            M16_RESTORE => "RESTORE", M16_RESTORE_JALRC => "RESTORE.JALRC",
            M16_SAVE => "SAVE", M16_SB16 => "SB16",
            M16_SEB16 => "SEB16", M16_SEH16 => "SEH16",
            M16_SH16 => "SH16", M16_SLL16 => "SLL16",
            M16_SRA16 => "SRA16", M16_SRL16 => "SRL16",
            M16_SUBU16 => "SUBU16", M16_SW16 => "SW16", M16_SWSP => "SWSP",
            M16_XOR16 => "XOR16", M16_ZEB16 => "ZEB16", M16_ZEH16 => "ZEH16",
            UMM_ADDIU32 => "ADDIU32", UMM_ADDIUPC => "ADDIUPC", UMM_ADDIUSP => "ADDIUSP",
            UMM_ALIGN => "ALIGN", UMM_ALNV4 => "ALNV.4",
            UMM_AND16 => "AND16", UMM_ANDI16 => "ANDI16",
            UMM_B16 => "B16", UMM_BALC16 => "BALC16", UMM_BC16 => "BC16",
            UMM_BEQZC16 => "BEQZC16", UMM_BNEZC16 => "BNEZC16",
            UMM_BREAK16 => "BREAK16", UMM_CACHE => "CACHE", UMM_DIV => "DIV",
            UMM_JALR16 => "JALR16", UMM_JALRS16 => "JALRS16",
            UMM_JALRS => "JALRS", UMM_JALRX => "JALRX", UMM_JALX => "JALX",
            UMM_JR16 => "JR16", UMM_JRADDIUSP => "JRADDIUSP",
            UMM_JRC16 => "JRC16", UMM_JRCADDIUSP => "JRCADDIUSP",
            UMM_LB16 => "LB16", UMM_LBU16 => "LBU16",
            UMM_LH16 => "LH16", UMM_LHU16 => "LHU16",
            UMM_LI16 => "LI16", UMM_LW16 => "LW16",
            UMM_LWGP => "LWGP", UMM_LWSP => "LWSP",
            UMM_MFHI16 => "MFHI16", UMM_MFLO16 => "MFLO16",
            UMM_MOVE16 => "MOVE16", UMM_MOVEP => "MOVEP", UMM_MUL => "MUL",
            UMM_NOP16 => "NOP16",
            UMM_NOT16 => "NOT16", UMM_OR16 => "OR16", UMM_SDBBP16 => "SDBBP16",
            UMM_SH16 => "SH16", UMM_SLL16 => "SLL16",
            UMM_SRA16 => "SRA16", UMM_SRL16 => "SRL16",
            UMM_SUB16 => "SUB16", UMM_SUBU16 => "SUBU16",
            UMM_SW16 => "SW16", UMM_SWGP => "SWGP", UMM_SWSP => "SWSP",
            UMM_TEQ => "TEQ", UMM_TGE => "TGE", UMM_TGEU => "TGEU",
            UMM_TLT => "TLT", UMM_TLTU => "TLTU", UMM_TNE => "TNE",
            UMM_XOR16 => "XOR16", UMM_XORI16 => "XORI16",
            UMM_PREF => "PREF", UMM_SYSCALL => "SYSCALL",
            UMM_BAL => "BAL", UMM_BEQ => "BEQ", UMM_BGEZ => "BGEZ",
            UMM_BGTZ => "BGTZ", UMM_BLEZ => "BLEZ", UMM_BLTZ => "BLTZ", UMM_BNE => "BNE",
            UMM_MTHI16 => "MTHI16", UMM_MTLO16 => "MTLO16",
            UMM_LSA => "LSA", UMM_DLSA => "DLSA",
            UMM_SELEQZ => "SELEQZ", UMM_SELNEZ => "SELNEZ", UMM_EHB => "EHB",
            FEXUPL_W => "FEXUPL.W", FEXUPL_D => "FEXUPL.D",
            FEXUPR_W => "FEXUPR.W", FEXUPR_D => "FEXUPR.D",
            FLOG2_W => "FLOG2.W", FLOG2_D => "FLOG2.D",
        }
    }

    pub fn category(&self) -> MipsInstructionCategory {
        use MipsMnemonic::*;
        match self {
            ADD | ADDI | ADDIU | ADDU | SUB | SUBU | SLT | SLTI | SLTIU | SLTU
            | DADD | DADDI | DADDIU | DADDU | DSUB | DSUBU | MUL | MUH | MULU | MUHU
            | DMUL | DMUH | DMULU | DMUHU | MULT | MULTU | DMULT | DMULTU
            | DIV | DIVU | DDIV | DDIVU | MADD | MADDU | MSUB | MSUBU
            | CLO | CLZ | DCLO | DCLZ | SEB | SEH | NEGU | NEG
            | AND | ANDI | OR | ORI | XOR | XORI | NOR | LUI
            | AUI | DAUI | DAHI | DATI | AUIPC | ALUIPC
            | SLL | SLLV | SRL | SRLV | SRA | SRAV
            | DSLL | DSLLV | DSLL32 | DSRL | DSRLV | DSRL32
            | DSRA | DSRAV | DSRA32 | ROTR | ROTRV | DROTR | DROTRV | DROTR32
            | WSBH | DSBH | DSHD
            | MFHI | MTHI | MFLO | MTLO | MOVN | MOVZ | MOVF | MOVT
            | SELEQZ | SELNEZ | EXT | INS | DEXT | DEXTM | DEXTU | DINS | DINSM | DINSU
            => MipsInstructionCategory::ArithmeticLogical,

            MFC0 | MTC0 | DMFC0 | DMTC0 | MTC2 | MFC2 | MFC1 | DMFC1 | MTC1 | DMTC1
            | MFHC1 | MTHC1 | MFHC2 | MTHC2 | CFC1 | CTC1 | CFC2 | CTC2
            | RDHWR | RDPGPR | WRPGPR => MipsInstructionCategory::Move,

            BEQ | BEQL | BNE | BNEL | BLEZ | BLEZL | BGTZ | BGTZL
            | BLTZ | BLTZL | BLTZAL | BLTZALL | BGEZ | BGEZL | BGEZAL | BGEZALL
            | BC1F | BC1T | BC1FL | BC1TL | BC2F | BC2T | BC2FL | BC2TL
            | J | JAL | JR | JALR | JR_HB | JALR_HB | JALX | B | BAL | NAL
            | BEQC | BNEC | BOVC | BNVC | BGEC | BLTC | BGEUC | BLTUC
            | BGEZC | BLEZC | BGTZC | BLTZC
            | BC1EQZ | BC1NEZ | BC2EQZ | BC2NEZ
            | BALC | BC | BEQZC | BNEZC | JIC | JIALC
            | BLEZALC | BGEZALC | BGTZALC | BLTZALC | BEQZALC | BNEZALC
            => MipsInstructionCategory::Branch,

            LB | LBU | LH | LHU | LW | LWU | LD
            | SB | SH | SW | SD | LDL | LDR | SDL | SDR
            | LWL | LWR | SWL | SWR | LL | LLD | SC | SCD | LLWP | SCWP
            | PREF | PREFX | CACHE | SYNC | SYNCI | SYNCIE
            | LWPC | LWUPC | LDPC | ADDIUPC | ADDIUR2 | ADDIUSP
            | LWC1 | SWC1 | LDC1 | SDC1 | LWC2 | SWC2 | LDC2 | SDC2 | LDC3 | SDC3
            | LWXC1 | LDXC1 | SWXC1 | SDXC1 | LUXC1 | SUXC1
            => MipsInstructionCategory::LoadStore,

            TGE | TGEU | TLT | TLTU | TEQ | TNE
            | TGEI | TGEIU | TLTI | TLTIU | TEQI | TNEI
            | TGEL | TGEUL | TLTL | TLTUL | TEQL | TNEL
            => MipsInstructionCategory::Trap,

            SYSCALL | BREAK | ERET | ERETNC | WAIT | SSNOP | NOP | EHB | PAUSE
            | DI | EI | DERET | TLBP | TLBR | TLBWI | TLBWR
            | TLBINV | TLBINVF | TLBINVF_FULL
            => MipsInstructionCategory::System,

            ADD_S | ADD_D | SUB_S | SUB_D | MUL_S | MUL_D | DIV_S | DIV_D
            | SQRT_S | SQRT_D | ABS_S | ABS_D | NEG_S | NEG_D | MOV_S | MOV_D
            | MOVF_S | MOVF_D | MOVT_S | MOVT_D | MOVZ_S | MOVZ_D | MOVN_S | MOVN_D
            | CVT_S_D | CVT_S_W | CVT_S_L | CVT_D_S | CVT_D_W | CVT_D_L
            | CVT_W_S | CVT_W_D | CVT_L_S | CVT_L_D | CVT_PS_S
            | CEIL_W_S | CEIL_W_D | CEIL_L_S | CEIL_L_D
            | FLOOR_W_S | FLOOR_W_D | FLOOR_L_S | FLOOR_L_D
            | ROUND_W_S | ROUND_W_D | ROUND_L_S | ROUND_L_D
            | TRUNC_W_S | TRUNC_W_D | TRUNC_L_S | TRUNC_L_D
            | RECIP_S | RECIP_D | RSQRT_S | RSQRT_D
            | C_F_S | C_F_D | C_UN_S | C_UN_D | C_EQ_S | C_EQ_D
            | C_LT_S | C_LT_D | C_LE_S | C_LE_D
            | C_UEQ_S | C_UEQ_D | C_ULT_S | C_ULT_D | C_ULE_S | C_ULE_D
            | C_OLE_S | C_OLE_D | C_OLT_S | C_OLT_D
            | C_SEQ_S | C_SEQ_D | C_NGT_S | C_NGT_D | C_NGE_S | C_NGE_D
            | C_NGLE_S | C_NGLE_D | C_NGL_S | C_NGL_D
            | MADDF_S | MADDF_D | MSUBF_S | MSUBF_D
            | MAX_S | MAX_D | MIN_S | MIN_D | MAXA_S | MAXA_D | MINA_S | MINA_D
            | SEL_S | SEL_D | SELEQZ_S | SELEQZ_D | SELNEZ_S | SELNEZ_D
            | CLASS_S | CLASS_D | RINT_S | RINT_D
            | BC1ANY2F | BC1ANY2T | BC1ANY4F | BC1ANY4T
            | MADD_S | MSUB_S | NMADD_S | NMSUB_S
            | MADD_D | MSUB_D | NMADD_D | NMSUB_D
            | CMP_AF_S | CMP_AF_D | CMP_UN_S | CMP_UN_D | CMP_EQ_S | CMP_EQ_D
            | CMP_UEQ_S | CMP_UEQ_D | CMP_LT_S | CMP_LT_D
            | CMP_ULT_S | CMP_ULT_D | CMP_LE_S | CMP_LE_D | CMP_ULE_S | CMP_ULE_D
            | CMP_SAF_S | CMP_SAF_D | CMP_SUN_S | CMP_SUN_D | CMP_SEQ_S | CMP_SEQ_D
            => MipsInstructionCategory::Fpu,

            HYPCALL | DMFC0G | DMTC0G | MFC0G | MTC0G
            | TLBGINV | TLBGINVF | TLBGP | TLBGR | TLBGWI | TLBGWR
            | MFGC0 | MTGC0 => MipsInstructionCategory::Virtualization,

            ABSQ_S_PH | ABSQ_S_W | ADDQ_PH | ADDQ_S_PH | ADDQ_S_W
            | ADDSC | ADDU_QB | ADDU_S_QB | ADDWC | BITREV | BPOSGE32
            | CMPGU_EQ_QB | CMPU_EQ_QB | DPA_W_PH | DPS_W_PH
            | EXTP | EXTPDP | EXTR_W | EXTR_R_W | EXTR_RS_W
            | EXTRV_W | EXTRV_R_W | INSV | MADD_DSP | MADDU_DSP
            | MSUB_DSP | MSUBU_DSP | MUL_PH | MUL_S_PH | MULQ_RS_PH | MULQ_S_PH
            | MULSA_W_PH | RADDU_W_QB | RDDSP | WRDSP | REPL_PH | REPL_QB
            | SHLL_PH | SHLL_QB | SHLL_S_W | SHLLV_PH | SHLLV_QB | SHLLV_S_W
            | SHRA_PH | SHRA_R_PH | SHRA_R_W | SHRAV_PH | SHRAV_R_PH | SHRAV_R_W
            | SHRL_PH | SHRL_QB | SHRLV_PH | SHRLV_QB
            | SUBQ_PH | SUBQ_S_PH | SUBQ_S_W | SUBU_PH | SUBU_S_PH
            | SUBU_QB | SUBU_S_QB => MipsInstructionCategory::Dsp,

            _ => MipsInstructionCategory::Simd,
        }
    }
}

// ============================================================================
// Conversion to common InstructionMnemonic
// ============================================================================

pub fn all_mips_mnemonics() -> Vec<InstructionMnemonic> {
    use MipsMnemonic::*;
    let variants = [
        ADD, ADDI, ADDIU, ADDU, SUB, SUBU, SLT, SLTI, SLTIU, SLTU,
        DADD, DADDI, DADDIU, DADDU, DSUB, DSUBU,
        MUL, MUH, MULU, MUHU, DMUL, DMUH, DMULU, DMUHU,
        MULT, MULTU, DMULT, DMULTU, DIV, DIVU, DDIV, DDIVU,
        MADD, MADDU, MSUB, MSUBU, CLO, CLZ, DCLO, DCLZ, SEB, SEH, NEGU, NEG,
        AND, ANDI, OR, ORI, XOR, XORI, NOR, LUI,
        AUI, DAUI, DAHI, DATI, AUIPC, ALUIPC,
        SLL, SLLV, SRL, SRLV, SRA, SRAV,
        DSLL, DSLLV, DSLL32, DSRL, DSRLV, DSRL32, DSRA, DSRAV, DSRA32,
        ROTR, ROTRV, DROTR, DROTRV, DROTR32, WSBH, DSBH, DSHD,
        MFHI, MTHI, MFLO, MTLO, MOVN, MOVZ, MOVF, MOVT,
        MFC0, MTC0, DMFC0, DMTC0, MTC2, MFC2, MFC1, DMFC1, MTC1, DMTC1,
        MFHC1, MTHC1, MFHC2, MTHC2, CFC1, CTC1, CFC2, CTC2,
        RDHWR, RDPGPR, WRPGPR, SELEQZ, SELNEZ,
        EXT, INS, DEXT, DEXTM, DEXTU, DINS, DINSM, DINSU,
        BEQ, BEQL, BNE, BNEL, BLEZ, BLEZL, BGTZ, BGTZL,
        BLTZ, BLTZL, BLTZAL, BLTZALL, BGEZ, BGEZL, BGEZAL, BGEZALL,
        BC1F, BC1T, BC1FL, BC1TL, BC2F, BC2T, BC2FL, BC2TL,
        J, JAL, JR, JALR, JR_HB, JALR_HB, JALX, B, BAL, NAL,
        BEQC, BNEC, BOVC, BNVC, BGEC, BLTC, BGEUC, BLTUC,
        BGEZC, BLEZC, BGTZC, BLTZC, BC1EQZ, BC1NEZ, BC2EQZ, BC2NEZ,
        BALC, BC, BEQZC, BNEZC, JIC, JIALC,
        BLEZALC, BGEZALC, BGTZALC, BLTZALC, BEQZALC, BNEZALC,
        LB, LBU, LH, LHU, LW, LWU, LD,
        SB, SH, SW, SD, LDL, LDR, SDL, SDR, LWL, LWR, SWL, SWR,
        LL, LLD, SC, SCD, LLWP, SCWP,
        PREF, PREFX, CACHE, SYNC, SYNCI, SYNCIE,
        LWPC, LWUPC, LDPC, ADDIUPC, ADDIUR2, ADDIUSP,
        LWC1, SWC1, LDC1, SDC1, LWC2, SWC2, LDC2, SDC2, LDC3, SDC3,
        LWXC1, LDXC1, SWXC1, SDXC1, LUXC1, SUXC1,
        TGE, TGEU, TLT, TLTU, TEQ, TNE,
        TGEI, TGEIU, TLTI, TLTIU, TEQI, TNEI,
        TGEL, TGEUL, TLTL, TLTUL, TEQL, TNEL,
        SYSCALL, BREAK, ERET, ERETNC, WAIT, SSNOP, NOP, EHB, PAUSE,
        DI, EI, DERET, TLBP, TLBR, TLBWI, TLBWR, TLBINV, TLBINVF, TLBINVF_FULL,
        ADD_S, ADD_D, SUB_S, SUB_D, MUL_S, MUL_D, DIV_S, DIV_D,
        SQRT_S, SQRT_D, ABS_S, ABS_D, NEG_S, NEG_D, MOV_S, MOV_D,
        MOVF_S, MOVF_D, MOVT_S, MOVT_D, MOVZ_S, MOVZ_D, MOVN_S, MOVN_D,
        CVT_S_D, CVT_S_W, CVT_S_L, CVT_D_S, CVT_D_W, CVT_D_L,
        CVT_W_S, CVT_W_D, CVT_L_S, CVT_L_D, CVT_PS_S,
        CEIL_W_S, CEIL_W_D, CEIL_L_S, CEIL_L_D,
        FLOOR_W_S, FLOOR_W_D, FLOOR_L_S, FLOOR_L_D,
        ROUND_W_S, ROUND_W_D, ROUND_L_S, ROUND_L_D,
        TRUNC_W_S, TRUNC_W_D, TRUNC_L_S, TRUNC_L_D,
        RECIP_S, RECIP_D, RSQRT_S, RSQRT_D,
        C_F_S, C_F_D, C_UN_S, C_UN_D, C_EQ_S, C_EQ_D,
        C_LT_S, C_LT_D, C_LE_S, C_LE_D,
        C_UEQ_S, C_UEQ_D, C_ULT_S, C_ULT_D, C_ULE_S, C_ULE_D,
        C_OLE_S, C_OLE_D, C_OLT_S, C_OLT_D,
        C_SEQ_S, C_SEQ_D, C_NGT_S, C_NGT_D, C_NGE_S, C_NGE_D,
        C_NGLE_S, C_NGLE_D, C_NGL_S, C_NGL_D,
        MADDF_S, MADDF_D, MSUBF_S, MSUBF_D,
        MAX_S, MAX_D, MIN_S, MIN_D, MAXA_S, MAXA_D, MINA_S, MINA_D,
        SEL_S, SEL_D, SELEQZ_S, SELEQZ_D, SELNEZ_S, SELNEZ_D,
        CLASS_S, CLASS_D, RINT_S, RINT_D,
        BC1ANY2F, BC1ANY2T, BC1ANY4F, BC1ANY4T,
        MADD_S, MSUB_S, NMADD_S, NMSUB_S,
        MADD_D, MSUB_D, NMADD_D, NMSUB_D,
        CMP_AF_S, CMP_AF_D, CMP_UN_S, CMP_UN_D, CMP_EQ_S, CMP_EQ_D,
        CMP_UEQ_S, CMP_UEQ_D, CMP_LT_S, CMP_LT_D, CMP_ULT_S, CMP_ULT_D,
        CMP_LE_S, CMP_LE_D, CMP_ULE_S, CMP_ULE_D,
        CMP_SAF_S, CMP_SAF_D, CMP_SUN_S, CMP_SUN_D, CMP_SEQ_S, CMP_SEQ_D,
        LD_B, LD_H, LD_W, LD_D, ST_B, ST_H, ST_W, ST_D,
        LD_MSA, ST_MSA,
        LDI_B, LDI_H, LDI_W, LDI_D,
        INSERT_B, INSERT_H, INSERT_W, INSERT_D,
        INSVE_B, INSVE_H, INSVE_W, INSVE_D,
        COPY_S_B, COPY_S_H, COPY_S_W, COPY_S_D,
        COPY_U_B, COPY_U_H, COPY_U_W,
        FILL_B, FILL_H, FILL_W, FILL_D,
        SPLAT_B, SPLAT_H, SPLAT_W, SPLAT_D,
        ADDV_B, ADDV_H, ADDV_W, ADDV_D, SUBV_B, SUBV_H, SUBV_W, SUBV_D,
        MULV_B, MULV_H, MULV_W, MULV_D,
        DIV_S_B, DIV_S_H, DIV_S_W, DIV_S_D,
        DIV_U_B, DIV_U_H, DIV_U_W, DIV_U_D,
        MOD_S_B, MOD_S_H, MOD_S_W, MOD_S_D,
        MOD_U_B, MOD_U_H, MOD_U_W, MOD_U_D,
        MADDV_B, MADDV_H, MADDV_W, MADDV_D,
        MSUBV_B, MSUBV_H, MSUBV_W, MSUBV_D,
        AND_V, OR_V, NOR_V, XOR_V,
        BCLR_B, BCLR_H, BCLR_W, BCLR_D,
        BSET_B, BSET_H, BSET_W, BSET_D,
        BNEG_B, BNEG_H, BNEG_W, BNEG_D,
        BMNZ_V, BMZ_V, BSEL_V,
        SLL_B, SLL_H, SLL_W, SLL_D,
        SRA_B, SRA_H, SRA_W, SRA_D,
        SRL_B, SRL_H, SRL_W, SRL_D,
        SRAR_B, SRAR_H, SRAR_W, SRAR_D,
        SRLR_B, SRLR_H, SRLR_W, SRLR_D,
        CEQ_B, CEQ_H, CEQ_W, CEQ_D,
        CLE_S_B, CLE_S_H, CLE_S_W, CLE_S_D,
        CLE_U_B, CLE_U_H, CLE_U_W, CLE_U_D,
        CLT_S_B, CLT_S_H, CLT_S_W, CLT_S_D,
        CLT_U_B, CLT_U_H, CLT_U_W, CLT_U_D,
        CMP_EQ_B, CMP_EQ_H, CMP_EQ_W, CMP_EQ_D,
        CMP_LE_S_B, CMP_LE_S_H, CMP_LE_S_W, CMP_LE_S_D,
        CMP_LE_U_B, CMP_LE_U_H, CMP_LE_U_W, CMP_LE_U_D,
        CMP_LT_S_B, CMP_LT_S_H, CMP_LT_S_W, CMP_LT_S_D,
        CMP_LT_U_B, CMP_LT_U_H, CMP_LT_U_W, CMP_LT_U_D,
        PCKEV_B, PCKEV_H, PCKEV_W, PCKEV_D,
        PCKOD_B, PCKOD_H, PCKOD_W, PCKOD_D,
        ILVEV_B, ILVEV_H, ILVEV_W, ILVEV_D,
        ILVOD_B, ILVOD_H, ILVOD_W, ILVOD_D,
        ILVL_B, ILVL_H, ILVL_W, ILVL_D,
        ILVR_B, ILVR_H, ILVR_W, ILVR_D,
        MAX_S_B, MAX_S_H, MAX_S_W, MAX_S_D,
        MAX_U_B, MAX_U_H, MAX_U_W, MAX_U_D,
        MIN_S_B, MIN_S_H, MIN_S_W, MIN_S_D,
        MIN_U_B, MIN_U_H, MIN_U_W, MIN_U_D,
        MAX_A_B, MAX_A_H, MAX_A_W, MAX_A_D,
        MIN_A_B, MIN_A_H, MIN_A_W, MIN_A_D,
        FADD_W, FADD_D, FSUB_W, FSUB_D, FMUL_W, FMUL_D, FDIV_W, FDIV_D,
        FMADD_W, FMADD_D, FMSUB_W, FMSUB_D,
        FEXP2_W, FEXP2_D, FEXDO_H, FEXDO_W, FTQ_H, FTQ_W,
        FMIN_W, FMIN_D, FMIN_A_W, FMIN_A_D,
        FMAX_W, FMAX_D, FMAX_A_W, FMAX_A_D,
        FCOR_W, FCOR_D, FCUNE_W, FCUNE_D,
        FCNE_W, FCNE_D, FCEQ_W, FCEQ_D,
        FCUN_W, FCUN_D, FCUEQ_W, FCUEQ_D,
        FCULE_W, FCULE_D, FCULT_W, FCULT_D,
        FCUGE_W, FCUGE_D, FCUGT_W, FCUGT_D,
        FCLT_W, FCLT_D, FCLE_W, FCLE_D,
        FSAF_W, FSAF_D, FSOR_W, FSOR_D,
        FSEQ_W, FSEQ_D, FSUNE_W, FSUNE_D, FSNE_W, FSNE_D,
        FINT_S_W, FINT_S_D, FINT_U_W, FINT_U_D,
        FRINT_W, FRINT_D, FLOG2_W, FLOG2_D,
        FTRUNC_S_W, FTRUNC_S_D, FTRUNC_U_W, FTRUNC_U_D,
        FRSQRT2_S_W, FRSQRT2_S_D, FRCP2_S_W, FRCP2_S_D,
        FFINT_S_W, FFINT_S_D, FFINT_U_W, FFINT_U_D,
        FTINT_S_W, FTINT_S_D, FTINT_U_W, FTINT_U_D,
        FFQL_W, FFQL_D, FFQR_W, FFQR_D,
        FSQRT_W, FSQRT_D, FRCP_W, FRCP_D, FRSQRT_W, FRSQRT_D,
        FCLASS_W, FCLASS_D,
        BNZ_V, BZ_V, BNZ_B, BNZ_H, BNZ_W, BNZ_D,
        BZ_B, BZ_H, BZ_W, BZ_D,
        CTCMSA, CFCMSA,
        VSHF_B, VSHF_H, VSHF_W, VSHF_D,
        SLD_B, SLD_H, SLD_W, SLD_D,
        SPLATI_B, SPLATI_H, SPLATI_W, SPLATI_D,
        NLOC_B, NLZC_B, PCNT_B, PCNT_H, PCNT_W, PCNT_D,
        MOVE_V, FEXUPL_W, FEXUPL_D, FEXUPR_W, FEXUPR_D,
        SHF_B, SHF_H, SHF_W,
        FTINT_RNE_W, FTINT_RNE_D, FTINT_RZ_W, FTINT_RZ_D,
        FTINT_RP_W, FTINT_RP_D, FTINT_RM_W, FTINT_RM_D,
        FCAF_W, FCAF_D,
        AVE_S_B, AVE_S_H, AVE_S_W, AVE_S_D,
        AVE_U_B, AVE_U_H, AVE_U_W, AVE_U_D,
        AVER_S_B, AVER_S_H, AVER_S_W, AVER_S_D,
        AVER_U_B, AVER_U_H, AVER_U_W, AVER_U_D,
        ASUB_S_B, ASUB_S_H, ASUB_S_W, ASUB_S_D,
        ASUB_U_B, ASUB_U_H, ASUB_U_W, ASUB_U_D,
        HADD_S_H, HADD_S_W, HADD_S_D,
        HADD_U_H, HADD_U_W, HADD_U_D,
        HSUB_S_H, HSUB_S_W, HSUB_S_D,
        HSUB_U_H, HSUB_U_W, HSUB_U_D,
        DOTP_S_H, DOTP_S_W, DOTP_S_D,
        DOTP_U_H, DOTP_U_W, DOTP_U_D,
        DPADD_S_H, DPADD_S_W, DPADD_S_D,
        DPADD_U_H, DPADD_U_W, DPADD_U_D,
        DPSUB_S_H, DPSUB_S_W, DPSUB_S_D,
        DPSUB_U_H, DPSUB_U_W, DPSUB_U_D,
        MUL_Q_H, MUL_Q_W, MULR_Q_H, MULR_Q_W,
        MADD_Q_H, MADD_Q_W, MADDR_Q_H, MADDR_Q_W,
        MSUB_Q_H, MSUB_Q_W, MSUBR_Q_H, MSUBR_Q_W,
        SAT_S_B, SAT_S_H, SAT_S_W, SAT_S_D,
        SAT_U_B, SAT_U_H, SAT_U_W, SAT_U_D,
        SUBS_S_B, SUBS_S_H, SUBS_S_W, SUBS_S_D,
        SUBS_U_B, SUBS_U_H, SUBS_U_W, SUBS_U_D,
        SUBSUS_U_B, SUBSUS_U_H, SUBSUS_U_W, SUBSUS_U_D,
        SUBSUU_S_B, SUBSUU_S_H, SUBSUU_S_W, SUBSUU_S_D,
        ABSQ_S_PH, ABSQ_S_W, ABSQ_S_QB, ABSQ_S_QH,
        ADDQ_PH, ADDQ_S_PH, ADDQ_S_W, ADDQH_PH, ADDQH_W,
        ADDQH_R_PH, ADDQH_R_W, ADDSC, ADDWC,
        ADDU_PH, ADDU_S_PH, ADDU_QB, ADDU_S_QB,
        ADDUH_QB, ADDUH_R_QB, APPEND, PREPEND, BALIGN, BITREV, BPOSGE32,
        CMP_EQ_PH, CMP_LE_PH, CMP_LT_PH,
        CMPGU_EQ_QB, CMPGU_LE_QB, CMPGU_LT_QB,
        CMPU_EQ_QB, CMPU_LE_QB, CMPU_LT_QB,
        DPA_W_PH, DPAQX_S_W_PH, DPAQX_SA_W_PH,
        DPAU_H_QBL, DPAU_H_QBR,
        DPS_W_PH, DPSQX_S_W_PH, DPSQX_SA_W_PH,
        DPSU_H_QBL, DPSU_H_QBR,
        EXTP, EXTPDP, EXTPDPV, EXTPV,
        EXTR_W, EXTR_R_W, EXTR_RS_W, EXTR_S_H,
        EXTRV_W, EXTRV_R_W, EXTRV_RS_W, EXTRV_S_H,
        INSV, LBUX, LHX, LWX,
        MADD_DSP, MADDU_DSP,
        MAQ_S_W_PHL, MAQ_S_W_PHR, MAQ_SA_W_PHL, MAQ_SA_W_PHR,
        MFHIDSP, MTHIDSP, MODSUB, MSUB_DSP, MSUBU_DSP, MTHLIP,
        MUL_PH, MUL_S_PH,
        MULEQ_S_W_PHL, MULEQ_S_W_PHR,
        MULEU_S_PH_QBL, MULEU_S_PH_QBR,
        MULQ_RS_PH, MULQ_RS_W, MULQ_S_PH, MULQ_S_W,
        MULSA_W_PH, MULSAQ_S_W_PH, PACKRL_PH,
        PICK_PH, PICK_QB,
        PRECEQ_W_PHL, PRECEQ_W_PHR,
        PRECEQU_PH_QBL, PRECEQU_PH_QBR,
        PRECEU_PH_QBL, PRECEU_PH_QBR,
        PRECR_QB_PH, PRECR_SRA_PH_W, PRECR_SRA_R_PH_W,
        PRECRQ_PH_W, PRECRQ_QB_PH, PRECRQ_RS_PH_W,
        RADDU_W_QB, RDDSP, WRDSP,
        REPL_PH, REPL_QB, REPLV_PH, REPLV_QB,
        SHILO, SHILOV,
        SHLL_PH, SHLL_S_PH, SHLL_QB, SHLL_S_QB, SHLL_S_W,
        SHLLV_PH, SHLLV_S_PH, SHLLV_QB, SHLLV_S_QB, SHLLV_S_W,
        SHRA_PH, SHRA_R_PH, SHRA_R_QB, SHRA_R_W, SHRAV_PH,
        SHRAV_R_PH, SHRAV_R_QB, SHRAV_R_W,
        SHRL_PH, SHRL_QB, SHRLV_PH, SHRLV_QB,
        SUBQ_PH, SUBQ_S_PH, SUBQ_S_W, SUBQH_PH, SUBQH_W,
        SUBQH_R_PH, SUBQH_R_W,
        SUBU_PH, SUBU_S_PH, SUBU_QB, SUBU_S_QB,
        SUBUH_QB, SUBUH_R_QB,
        HYPCALL, DMFC0G, DMTC0G, MFC0G, MTC0G,
        TLBGINV, TLBGINVF, TLBGP, TLBGR, TLBGWI, TLBGWR, MFGC0, MTGC0,
        M16_ADDIUS5, M16_ADDIUSP, M16_ADDIUPC, M16_ADDIUR1SP, M16_ADDIUR2,
        M16_ADDU16, M16_AND16, M16_BEQZ16, M16_BNEZ16,
        M16_BTEQZ, M16_BTNEZ, M16_CMPI, M16_CMP, M16_DIV16,
        M16_EXTEND, M16_JAL16, M16_JALRC16, M16_JALX, M16_JRC16,
        M16_LB16, M16_LBU16, M16_LH16, M16_LHU16, M16_LI16, M16_LW16,
        M16_LWPC, M16_LWSP, M16_MFHI16, M16_MFLO16, M16_MOVE,
        M16_MOVEN, M16_MOVEZ, M16_MUL16, M16_MULT16,
        M16_NEG16, M16_NOT16, M16_OR16,
        M16_RESTORE, M16_RESTORE_JALRC, M16_SAVE, M16_SB16,
        M16_SEB16, M16_SEH16, M16_SH16, M16_SLL16,
        M16_SRA16, M16_SRL16, M16_SUBU16, M16_SW16, M16_SWSP,
        M16_XOR16, M16_ZEB16, M16_ZEH16,
        UMM_ADDIU32, UMM_ADDIUPC, UMM_ADDIUSP,
        UMM_ALIGN, UMM_ALNV4, UMM_AND16, UMM_ANDI16,
        UMM_B16, UMM_BALC16, UMM_BC16, UMM_BEQZC16, UMM_BNEZC16,
        UMM_BREAK16, UMM_CACHE, UMM_DIV,
        UMM_JALR16, UMM_JALRS16, UMM_JALRS, UMM_JALRX, UMM_JALX,
        UMM_JR16, UMM_JRADDIUSP, UMM_JRC16, UMM_JRCADDIUSP,
        UMM_LB16, UMM_LBU16, UMM_LH16, UMM_LHU16, UMM_LI16, UMM_LW16,
        UMM_LWGP, UMM_LWSP, UMM_MFHI16, UMM_MFLO16,
        UMM_MOVE16, UMM_MOVEP, UMM_MUL, UMM_NOP16,
        UMM_NOT16, UMM_OR16, UMM_SDBBP16,
        UMM_SH16, UMM_SLL16, UMM_SRA16, UMM_SRL16,
        UMM_SUB16, UMM_SUBU16, UMM_SW16, UMM_SWGP, UMM_SWSP,
        UMM_TEQ, UMM_TGE, UMM_TGEU, UMM_TLT, UMM_TLTU, UMM_TNE,
        UMM_XOR16, UMM_XORI16, UMM_PREF, UMM_SYSCALL,
        UMM_BAL, UMM_BEQ, UMM_BGEZ, UMM_BGTZ, UMM_BLEZ, UMM_BLTZ, UMM_BNE,
        UMM_MTHI16, UMM_MTLO16, UMM_LSA, UMM_DLSA,
        UMM_SELEQZ, UMM_SELNEZ, UMM_EHB,
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
// ProcessorModule Implementation
// ============================================================================

pub struct MipsModule;

impl ProcessorModule for MipsModule {
    fn name() -> &'static str { PROCESSOR_NAME }

    fn registers() -> RegisterBank {
        let mips_bank = MipsRegisterBank::new_mips64();
        let mut bank = RegisterBank::new();
        for reg in mips_bank.iter() {
            bank.add(reg.clone());
        }
        bank
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new("MIPS:BE:32:default", "MIPS 32-bit Big Endian", "MIPS32", Endian::Big, 32),
            Language::new("MIPS:LE:32:default", "MIPS 32-bit Little Endian", "MIPS32", Endian::Little, 32),
            Language::new("MIPS:BE:64:default", "MIPS 64-bit Big Endian", "MIPS64", Endian::Big, 64),
            Language::new("MIPS:LE:64:default", "MIPS 64-bit Little Endian", "MIPS64", Endian::Little, 64),
            Language::new("MIPS:BE:32:micro", "microMIPS Big Endian", "microMIPS", Endian::Big, 32),
            Language::new("MIPS:LE:32:micro", "microMIPS Little Endian", "microMIPS", Endian::Little, 32),
            Language::new("MIPS:BE:32:r6", "MIPS32 Release 6 Big Endian", "R6", Endian::Big, 32),
            Language::new("MIPS:BE:64:r6", "MIPS64 Release 6 Big Endian", "R6", Endian::Big, 64),
            Language::new("MIPS:LE:64:r6", "MIPS64 Release 6 Little Endian", "R6", Endian::Little, 64),
            Language::new("MIPS:BE:64:64-32addr", "MIPS 64-bit with 32-bit addresses", "MIPS64-32", Endian::Big, 32),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> { all_mips_mnemonics() }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_count() {
        let bank = MipsRegisterBank::new_mips64();
        assert!(bank.len() > 100, "MIPS bank should have >100 registers, got {}", bank.len());
    }

    #[test]
    fn test_gpr_registers() {
        let bank = MipsRegisterBank::new_mips64();
        for i in 0..=31 {
            assert!(bank.get(&format!("R{}", i)).is_some(), "Missing R{}", i);
            assert!(bank.get(&format!("${}", i)).is_some(), "Missing ${}", i);
        }
    }

    #[test]
    fn test_abi_names() {
        let bank = MipsRegisterBank::new_mips64();
        for abi in &MIPS_GPR_ABI_NAMES {
            assert!(bank.get(abi).is_some(), "Missing ABI name: {}", abi);
        }
        assert_eq!(bank.gpr_index_by_abi("zero"), Some(0));
        assert_eq!(bank.gpr_index_by_abi("at"), Some(1));
        assert_eq!(bank.gpr_index_by_abi("v0"), Some(2));
        assert_eq!(bank.gpr_index_by_abi("a0"), Some(4));
        assert_eq!(bank.gpr_index_by_abi("t0"), Some(8));
        assert_eq!(bank.gpr_index_by_abi("s0"), Some(16));
        assert_eq!(bank.gpr_index_by_abi("k0"), Some(26));
        assert_eq!(bank.gpr_index_by_abi("gp"), Some(28));
        assert_eq!(bank.gpr_index_by_abi("sp"), Some(29));
        assert_eq!(bank.gpr_index_by_abi("fp"), Some(30));
        assert_eq!(bank.gpr_index_by_abi("ra"), Some(31));
    }

    #[test]
    fn test_special_registers() {
        let bank = MipsRegisterBank::new_mips64();
        assert!(bank.get("HI").is_some());
        assert!(bank.get("LO").is_some());
        assert!(bank.get("PC").is_some());
    }

    #[test]
    fn test_cp0_registers() {
        let bank = MipsRegisterBank::new_mips64();
        let cp0_names = ["Index", "Random", "EntryLo0", "EntryLo1", "Context",
            "PageMask", "Wired", "BadVAddr", "Count", "EntryHi",
            "Compare", "Status", "Cause", "EPC", "PRId", "Config"];
        for name in &cp0_names {
            assert!(bank.get(name).is_some(), "Missing CP0: {}", name);
        }
    }

    #[test]
    fn test_fpu_registers() {
        let bank = MipsRegisterBank::new_mips64();
        for i in 0..32 {
            assert!(bank.get(&format!("F{}", i)).is_some(), "Missing F{}", i);
        }
        assert!(bank.get("FCSR").is_some());
        assert!(bank.get("FCCR").is_some());
        assert!(bank.get("FEXR").is_some());
        assert!(bank.get("FENR").is_some());
    }

    #[test]
    fn test_msa_registers() {
        let bank = MipsRegisterBank::new_mips64();
        for i in 0..32 {
            assert!(bank.get(&format!("W{}", i)).is_some(), "Missing W{}", i);
        }
    }

    #[test]
    fn test_dsp_acc_registers() {
        let bank = MipsRegisterBank::new_mips64();
        for i in 0..4 {
            assert!(bank.get(&format!("AC{}", i)).is_some(), "Missing AC{}", i);
        }
    }

    #[test]
    fn test_cp0_select_numbers() {
        assert_eq!(Cp0Register::Index.select_number(), 0);
        assert_eq!(Cp0Register::Status.select_number(), 12);
        assert_eq!(Cp0Register::Cause.select_number(), 13);
        assert_eq!(Cp0Register::EPC.select_number(), 14);
        assert_eq!(Cp0Register::DESAVE.select_number(), 31);
    }

    #[test]
    fn test_status_fields() {
        assert_eq!(StatusField::IE.mask(), 1 << 0);
        assert_eq!(StatusField::EXL.mask(), 1 << 1);
        assert_eq!(StatusField::CU0.mask(), 1 << 28);
        assert_eq!(StatusField::CU1.mask(), 1 << 29);
    }

    #[test]
    fn test_cause_fields() {
        assert_eq!(CauseField::BD.mask(), 1 << 31);
        assert_eq!(CauseField::TI.mask(), 1 << 30);
        assert_eq!(CauseField::IP0.mask(), 1 << 8);
    }

    #[test]
    fn test_exception_codes() {
        assert_eq!(ExceptionCode::Int.code(), 0);
        assert_eq!(ExceptionCode::Syscall.code(), 8);
        assert_eq!(ExceptionCode::Bp.code(), 9);
        assert_eq!(ExceptionCode::FPE.code(), 15);
    }

    #[test]
    fn test_mnemonic_count() {
        let mnemonics = all_mips_mnemonics();
        assert!(mnemonics.len() >= 250, "Expected >= 250 unique MIPS mnemonics, got {}", mnemonics.len());
    }

    #[test]
    fn test_processor_module_interface() {
        let regs = MipsModule::registers();
        assert!(!regs.is_empty());
        let langs = MipsModule::languages();
        assert!(langs.len() >= 5);
        let insts = MipsModule::instructions();
        assert!(insts.len() >= 250);
    }

    #[test]
    fn test_variant_properties() {
        assert!(!MipsVariant::Mips32.is_64bit());
        assert!(MipsVariant::Mips64.is_64bit());
        assert!(MipsVariant::Mips64R6.has_msa());
        assert!(MipsVariant::Mips64R5.has_vz());
        assert!(!MipsVariant::Mips32.has_msa());
    }

    #[test]
    fn test_mnemonic_categories() {
        assert!(matches!(MipsMnemonic::ADD.category(), MipsInstructionCategory::ArithmeticLogical));
        assert!(matches!(MipsMnemonic::BEQ.category(), MipsInstructionCategory::Branch));
        assert!(matches!(MipsMnemonic::LW.category(), MipsInstructionCategory::LoadStore));
        assert!(matches!(MipsMnemonic::SYSCALL.category(), MipsInstructionCategory::System));
        assert!(matches!(MipsMnemonic::ADD_S.category(), MipsInstructionCategory::Fpu));
        assert!(matches!(MipsMnemonic::ADDV_B.category(), MipsInstructionCategory::Simd));
        assert!(matches!(MipsMnemonic::ABSQ_S_PH.category(), MipsInstructionCategory::Dsp));
        assert!(matches!(MipsMnemonic::HYPCALL.category(), MipsInstructionCategory::Virtualization));
    }

    #[test]
    fn test_register_sizes() {
        let bank = MipsRegisterBank::new_mips64();
        assert_eq!(bank.get("R0").unwrap().bit_size, 64);
        assert_eq!(bank.get("W0").unwrap().bit_size, 128);
        assert_eq!(bank.get("F0").unwrap().bit_size, 64);
        assert_eq!(bank.get("FCSR").unwrap().bit_size, 32);
    }
}
