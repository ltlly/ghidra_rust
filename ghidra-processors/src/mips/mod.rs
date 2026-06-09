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

pub mod language_provider;
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
        for (_i, reg) in cp0.iter().enumerate() {
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
    JrHb, JalrHb, JALX,
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
    TLBINV, TLBINVF, TlbinvfFull,
    // FPU
    AddS, AddD, SubS, SubD, MulS, MulD, DivS, DivD,
    SqrtS, SqrtD, AbsS, AbsD, NegS, NegD,
    MovS, MovD, MovfS, MovfD, MovtS, MovtD,
    MovzS, MovzD, MovnS, MovnD,
    CvtSD, CvtSW, CvtSL,
    CvtDS, CvtDW, CvtDL,
    CvtWS, CvtWD, CvtLS, CvtLD,
    CvtPsS,
    CeilWS, CeilWD, CeilLS, CeilLD,
    FloorWS, FloorWD, FloorLS, FloorLD,
    RoundWS, RoundWD, RoundLS, RoundLD,
    TruncWS, TruncWD, TruncLS, TruncLD,
    RecipS, RecipD, RsqrtS, RsqrtD,
    CFS, CFD, CUnS, CUnD,
    CEqS, CEqD, CLtS, CLtD, CLeS, CLeD,
    CUeqS, CUeqD, CUltS, CUltD, CUleS, CUleD,
    COleS, COleD, COltS, COltD,
    CSeqS, CSeqD, CNgeS, CNgeD,
    CNgtS, CNgtD, CNgleS, CNgleD, CNglS, CNglD,
    MaddfS, MaddfD, MsubfS, MsubfD,
    MaxS, MaxD, MinS, MinD,
    MaxaS, MaxaD, MinaS, MinaD,
    SelS, SelD, SeleqzS, SeleqzD, SelnezS, SelnezD,
    ClassS, ClassD, RintS, RintD,
    BC1ANY2F, BC1ANY2T, BC1ANY4F, BC1ANY4T,
    MaddS, MsubS, NmaddS, NmsubS,
    MaddD, MsubD, NmaddD, NmsubD,
    CmpAfS, CmpUnS, CmpEqS, CmpUeqS, CmpLtS, CmpUltS,
    CmpLeS, CmpUleS, CmpSafS, CmpSunS, CmpSeqS,
    CmpAfD, CmpUnD, CmpEqD, CmpUeqD, CmpLtD, CmpUltD,
    CmpLeD, CmpUleD, CmpSafD, CmpSunD, CmpSeqD,
    // MSA Data Transfer
    LdB, LdH, LdW, LdD,
    StB, StH, StW, StD,
    LdMsa, StMsa,
    LdiB, LdiH, LdiW, LdiD,
    InsertB, InsertH, InsertW, InsertD,
    InsveB, InsveH, InsveW, InsveD,
    CopySB, CopySH, CopySW, CopySD,
    CopyUB, CopyUH, CopyUW,
    FillB, FillH, FillW, FillD,
    SplatB, SplatH, SplatW, SplatD,
    // MSA Integer Arithmetic
    AddvB, AddvH, AddvW, AddvD,
    SubvB, SubvH, SubvW, SubvD,
    MulvB, MulvH, MulvW, MulvD,
    DivSB, DivSH, DivSW, DivSD,
    DivUB, DivUH, DivUW, DivUD,
    ModSB, ModSH, ModSW, ModSD,
    ModUB, ModUH, ModUW, ModUD,
    MaddvB, MaddvH, MaddvW, MaddvD,
    MsubvB, MsubvH, MsubvW, MsubvD,
    AveSB, AveSH, AveSW, AveSD,
    AveUB, AveUH, AveUW, AveUD,
    AverSB, AverSH, AverSW, AverSD,
    AverUB, AverUH, AverUW, AverUD,
    AsubSB, AsubSH, AsubSW, AsubSD,
    AsubUB, AsubUH, AsubUW, AsubUD,
    HaddSH, HaddSW, HaddSD,
    HaddUH, HaddUW, HaddUD,
    HsubSH, HsubSW, HsubSD,
    HsubUH, HsubUW, HsubUD,
    DotpSH, DotpSW, DotpSD,
    DotpUH, DotpUW, DotpUD,
    DpaddSH, DpaddSW, DpaddSD,
    DpaddUH, DpaddUW, DpaddUD,
    DpsubSH, DpsubSW, DpsubSD,
    DpsubUH, DpsubUW, DpsubUD,
    MulQH, MulQW, MulrQH, MulrQW,
    MaddQH, MaddQW, MaddrQH, MaddrQW,
    MsubQH, MsubQW, MsubrQH, MsubrQW,
    SatSB, SatSH, SatSW, SatSD,
    SatUB, SatUH, SatUW, SatUD,
    SubsSB, SubsSH, SubsSW, SubsSD,
    SubsUB, SubsUH, SubsUW, SubsUD,
    SubsusUB, SubsusUH, SubsusUW, SubsusUD,
    SubsuuSB, SubsuuSH, SubsuuSW, SubsuuSD,
    // MSA Bitwise
    AndV, OrV, NorV, XorV,
    BclrB, BclrH, BclrW, BclrD,
    BsetB, BsetH, BsetW, BsetD,
    BnegB, BnegH, BnegW, BnegD,
    BmnzV, BmzV, BselV,
    // MSA Shift
    SllB, SllH, SllW, SllD,
    SraB, SraH, SraW, SraD,
    SrlB, SrlH, SrlW, SrlD,
    SrarB, SrarH, SrarW, SrarD,
    SrlrB, SrlrH, SrlrW, SrlrD,
    // MSA Compare
    CeqB, CeqH, CeqW, CeqD,
    CleSB, CleSH, CleSW, CleSD,
    CleUB, CleUH, CleUW, CleUD,
    CltSB, CltSH, CltSW, CltSD,
    CltUB, CltUH, CltUW, CltUD,
    CmpEqB, CmpEqH, CmpEqW, MsaCmpEqD,
    CmpLeSB, CmpLeSH, CmpLeSW, CmpLeSD,
    CmpLeUB, CmpLeUH, CmpLeUW, CmpLeUD,
    CmpLtSB, CmpLtSH, CmpLtSW, CmpLtSD,
    CmpLtUB, CmpLtUH, CmpLtUW, CmpLtUD,
    // MSA Pack/Interleave
    PckevB, PckevH, PckevW, PckevD,
    PckodB, PckodH, PckodW, PckodD,
    IlvevB, IlvevH, IlvevW, IlvevD,
    IlvodB, IlvodH, IlvodW, IlvodD,
    IlvlB, IlvlH, IlvlW, IlvlD,
    IlvrB, IlvrH, IlvrW, IlvrD,
    // MSA Min/Max
    MaxSB, MaxSH, MaxSW, MaxSD,
    MaxUB, MaxUH, MaxUW, MaxUD,
    MinSB, MinSH, MinSW, MinSD,
    MinUB, MinUH, MinUW, MinUD,
    MaxAB, MaxAH, MaxAW, MaxAD,
    MinAB, MinAH, MinAW, MinAD,
    // MSA Float
    FaddW, FaddD, FsubW, FsubD, FmulW, FmulD, FdivW, FdivD,
    FmaddW, FmaddD, FmsubW, FmsubD,
    Fexp2W, Fexp2D, FexdoH, FexdoW,
    FtqH, FtqW,
    FminW, FminD, FminAW, FminAD,
    FmaxW, FmaxD, FmaxAW, FmaxAD,
    FcorW, FcorD, FcuneW, FcuneD,
    FcneW, FcneD, FceqW, FceqD,
    FcunW, FcunD, FcueqW, FcueqD,
    FculeW, FculeD, FcultW, FcultD,
    FcugeW, FcugeD, FcugtW, FcugtD,
    FcltW, FcltD, FcleW, FcleD,
    FsafW, FsafD, FsorW, FsorD,
    FseqW, FseqD, FsuneW, FsuneD, FsneW, FsneD,
    FintSW, FintSD, FintUW, FintUD,
    FrintW, FrintD,
    Flog2W, Flog2D,
    FtruncSW, FtruncSD, FtruncUW, FtruncUD,
    Frsqrt2SW, Frsqrt2SD, Frcp2SW, Frcp2SD,
    FfintSW, FfintSD, FfintUW, FfintUD,
    FtintSW, FtintSD, FtintUW, FtintUD,
    FfqlW, FfqlD, FfqrW, FfqrD,
    FsqrtW, FsqrtD,
    FrcpW, FrcpD, FrsqrtW, FrsqrtD,
    FclassW, FclassD,
    // MSA Misc
    BnzV, BzV, BnzB, BnzH, BnzW, BnzD,
    BzB, BzH, BzW, BzD,
    CTCMSA, CFCMSA,
    VshfB, VshfH, VshfW, VshfD,
    SldB, SldH, SldW, SldD,
    SplatiB, SplatiH, SplatiW, SplatiD,
    NlocB, NlocH, NlocW, NlocD,
    NlzcB, NlzcH, NlzcW, NlzcD,
    PcntB, PcntH, PcntW, PcntD,
    MoveV,
    FexuplW, FexuplD, FexuprW, FexuprD,
    ShfB, ShfH, ShfW,
    FtintRneW, FtintRneD, FtintRzW, FtintRzD,
    FtintRpW, FtintRpD, FtintRmW, FtintRmD,
    FcafW, FcafD,
    // DSP R2/R3
    AbsqSPh, AbsqSW, AbsqSQb, AbsqSQh,
    AddqPh, AddqSPh, AddqSW, AddqhPh, AddqhW,
    AddqhRPh, AddqhRW, ADDSC, ADDWC,
    AdduPh, AdduSPh, AdduQb, AdduSQb,
    AdduhQb, AdduhRQb, APPEND, PREPEND, BALIGN, BITREV, BPOSGE32,
    CmpEqPh, CmpLePh, CmpLtPh,
    CmpguEqQb, CmpguLeQb, CmpguLtQb,
    CmpuEqQb, CmpuLeQb, CmpuLtQb,
    DpaWPh, DpaqxSWPh, DpaqxSaWPh,
    DpauHQbl, DpauHQbr,
    DpsWPh, DpsqxSWPh, DpsqxSaWPh,
    DpsuHQbl, DpsuHQbr,
    EXTP, EXTPDP, EXTPDPV, EXTPV,
    ExtrW, ExtrRW, ExtrRsW, ExtrSH,
    ExtrvW, ExtrvRW, ExtrvRsW, ExtrvSH,
    INSV, LBUX, LHX, LWX,
    MaddDsp, MadduDsp,
    MaqSWPhl, MaqSWPhr, MaqSaWPhl, MaqSaWPhr,
    MFHIDSP, MTHIDSP,
    MODSUB, MsubDsp, MsubuDsp, MTHLIP,
    MulPh, MulSPh,
    MuleqSWPhl, MuleqSWPhr,
    MuleuSPhQbl, MuleuSPhQbr,
    MulqRsPh, MulqRsW, MulqSPh, MulqSW,
    MulsaWPh, MulsaqSWPh,
    PackrlPh,
    PickPh, PickQb,
    PreceqWPhl, PreceqWPhr,
    PrecequPhQbl, PrecequPhQbr,
    PreceuPhQbl, PreceuPhQbr,
    PrecrQbPh, PrecrSraPhW, PrecrSraRPhW,
    PrecrqPhW, PrecrqQbPh, PrecrqRsPhW,
    RadduWQb,
    RDDSP, WRDSP,
    ReplPh, ReplQb, ReplvPh, ReplvQb,
    SHILO, SHILOV,
    ShllPh, ShllSPh, ShllQb, ShllSQb, ShllSW,
    ShllvPh, ShllvSPh, ShllvQb, ShllvSQb, ShllvSW,
    ShraPh, ShraRPh, ShraRQb, ShraRW, ShravPh,
    ShravRPh, ShravRQb, ShravRW,
    ShrlPh, ShrlQb, ShrlvPh, ShrlvQb,
    SubqPh, SubqSPh, SubqSW, SubqhPh, SubqhW,
    SubqhRPh, SubqhRW,
    SubuPh, SubuSPh, SubuQb, SubuSQb,
    SubuhQb, SubuhRQb,
    // VZ (Virtualization)
    HYPCALL, DMFC0G, DMTC0G, MFC0G, MTC0G,
    TLBGINV, TLBGINVF, TLBGP, TLBGR, TLBGWI, TLBGWR,
    MFGC0, MTGC0,
    // MIPS16e
    M16Addius5, M16Addiusp, M16Addiupc, M16Addiur1sp, M16Addiur2,
    M16Addu16, M16And16, M16Beqz16, M16Bnez16,
    M16Bteqz, M16Btnez, M16Cmpi, M16Cmp, M16Div16,
    M16Extend, M16Jal16, M16Jalrc16, M16Jalx, M16Jrc16,
    M16Lb16, M16Lbu16, M16Lh16, M16Lhu16, M16Li16, M16Lw16,
    M16Lwpc, M16Lwsp, M16Mfhi16, M16Mflo16, M16Move,
    M16Moven, M16Movez, M16Mul16, M16Mult16,
    M16Neg16, M16Not16, M16Or16,
    M16Restore, M16RestoreJalrc, M16Save, M16Sb16,
    M16Seb16, M16Seh16, M16Sh16, M16Sll16,
    M16Sra16, M16Srl16, M16Subu16, M16Sw16, M16Swsp,
    M16Xor16, M16Zeb16, M16Zeh16,
    // microMIPS
    UmmAddiu32, UmmAddiupc, UmmAddiusp,
    UmmAlign, UmmAlnv4,
    UmmAnd16, UmmAndi16,
    UmmB16, UmmBalc16, UmmBc16, UmmBeqzc16, UmmBnezc16,
    UmmBreak16, UmmCache, UmmDiv,
    UmmJalr16, UmmJalrs16, UmmJalrs, UmmJalrx, UmmJalx,
    UmmJr16, UmmJraddiusp, UmmJrc16, UmmJrcaddiusp,
    UmmLb16, UmmLbu16, UmmLh16, UmmLhu16, UmmLi16, UmmLw16,
    UmmLwgp, UmmLwsp, UmmMfhi16, UmmMflo16,
    UmmMove16, UmmMovep, UmmMul, UmmNop16,
    UmmNot16, UmmOr16, UmmSdbbp16,
    UmmSh16, UmmSll16, UmmSra16, UmmSrl16,
    UmmSub16, UmmSubu16, UmmSw16, UmmSwgp, UmmSwsp,
    UmmTeq, UmmTge, UmmTgeu, UmmTlt, UmmTltu, UmmTne,
    UmmXor16, UmmXori16, UmmPref, UmmSyscall,
    UmmBal, UmmBeq, UmmBgez, UmmBgtz, UmmBlez, UmmBltz, UmmBne,
    UmmMthi16, UmmMtlo16,
    UmmLsa, UmmDlsa,
    UmmSeleqz, UmmSelnez, UmmEhb,
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
            JrHb => "JR.HB", JalrHb => "JALR.HB", JALX => "JALX",
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
            TLBINV => "TLBINV", TLBINVF => "TLBINVF", TlbinvfFull => "TLBINVF",
            AddS => "ADD.S", AddD => "ADD.D",
            SubS => "SUB.S", SubD => "SUB.D",
            MulS => "MUL.S", MulD => "MUL.D",
            DivS => "DIV.S", DivD => "DIV.D",
            SqrtS => "SQRT.S", SqrtD => "SQRT.D",
            AbsS => "ABS.S", AbsD => "ABS.D",
            NegS => "NEG.S", NegD => "NEG.D",
            MovS => "MOV.S", MovD => "MOV.D",
            MovfS => "MOVF.S", MovfD => "MOVF.D",
            MovtS => "MOVT.S", MovtD => "MOVT.D",
            MovzS => "MOVZ.S", MovzD => "MOVZ.D",
            MovnS => "MOVN.S", MovnD => "MOVN.D",
            CvtSD => "CVT.S.D", CvtSW => "CVT.S.W", CvtSL => "CVT.S.L",
            CvtDS => "CVT.D.S", CvtDW => "CVT.D.W", CvtDL => "CVT.D.L",
            CvtWS => "CVT.W.S", CvtWD => "CVT.W.D",
            CvtLS => "CVT.L.S", CvtLD => "CVT.L.D",
            CvtPsS => "CVT.PS.S",
            CeilWS => "CEIL.W.S", CeilWD => "CEIL.W.D",
            CeilLS => "CEIL.L.S", CeilLD => "CEIL.L.D",
            FloorWS => "FLOOR.W.S", FloorWD => "FLOOR.W.D",
            FloorLS => "FLOOR.L.S", FloorLD => "FLOOR.L.D",
            RoundWS => "ROUND.W.S", RoundWD => "ROUND.W.D",
            RoundLS => "ROUND.L.S", RoundLD => "ROUND.L.D",
            TruncWS => "TRUNC.W.S", TruncWD => "TRUNC.W.D",
            TruncLS => "TRUNC.L.S", TruncLD => "TRUNC.L.D",
            RecipS => "RECIP.S", RecipD => "RECIP.D",
            RsqrtS => "RSQRT.S", RsqrtD => "RSQRT.D",
            CFS => "C.F.S", CFD => "C.F.D",
            CUnS => "C.UN.S", CUnD => "C.UN.D",
            CEqS => "C.EQ.S", CEqD => "C.EQ.D",
            CLtS => "C.LT.S", CLtD => "C.LT.D",
            CLeS => "C.LE.S", CLeD => "C.LE.D",
            CUeqS => "C.UEQ.S", CUeqD => "C.UEQ.D",
            CUltS => "C.ULT.S", CUltD => "C.ULT.D",
            CUleS => "C.ULE.S", CUleD => "C.ULE.D",
            COleS => "C.OLE.S", COleD => "C.OLE.D",
            COltS => "C.OLT.S", COltD => "C.OLT.D",
            CSeqS => "C.SEQ.S", CSeqD => "C.SEQ.D",
            CNgtS => "C.NGT.S", CNgtD => "C.NGT.D",
            CNgeS => "C.NGE.S", CNgeD => "C.NGE.D",
            CNgleS => "C.NGLE.S", CNgleD => "C.NGLE.D",
            CNglS => "C.NGL.S", CNglD => "C.NGL.D",
            MaddfS => "MADDF.S", MaddfD => "MADDF.D",
            MsubfS => "MSUBF.S", MsubfD => "MSUBF.D",
            MaxS => "MAX.S", MaxD => "MAX.D",
            MinS => "MIN.S", MinD => "MIN.D",
            MaxaS => "MAXA.S", MaxaD => "MAXA.D",
            MinaS => "MINA.S", MinaD => "MINA.D",
            SelS => "SEL.S", SelD => "SEL.D",
            SeleqzS => "SELEQZ.S", SeleqzD => "SELEQZ.D",
            SelnezS => "SELNEZ.S", SelnezD => "SELNEZ.D",
            ClassS => "CLASS.S", ClassD => "CLASS.D",
            RintS => "RINT.S", RintD => "RINT.D",
            BC1ANY2F => "BC1ANY2F", BC1ANY2T => "BC1ANY2T",
            BC1ANY4F => "BC1ANY4F", BC1ANY4T => "BC1ANY4T",
            MaddS => "MADD.S", MsubS => "MSUB.S",
            NmaddS => "NMADD.S", NmsubS => "NMSUB.S",
            MaddD => "MADD.D", MsubD => "MSUB.D",
            NmaddD => "NMADD.D", NmsubD => "NMSUB.D",
            CmpAfS => "CMP.AF.S", CmpAfD => "CMP.AF.D",
            CmpUnS => "CMP.UN.S", CmpUnD => "CMP.UN.D",
            CmpEqS => "CMP.EQ.S", CmpEqD => "CMP.EQ.D",
            CmpUeqS => "CMP.UEQ.S", CmpUeqD => "CMP.UEQ.D",
            CmpLtS => "CMP.LT.S", CmpLtD => "CMP.LT.D",
            CmpUltS => "CMP.ULT.S", CmpUltD => "CMP.ULT.D",
            CmpLeS => "CMP.LE.S", CmpLeD => "CMP.LE.D",
            CmpUleS => "CMP.ULE.S", CmpUleD => "CMP.ULE.D",
            CmpSafS => "CMP.SAF.S", CmpSafD => "CMP.SAF.D",
            CmpSunS => "CMP.SUN.S", CmpSunD => "CMP.SUN.D",
            CmpSeqS => "CMP.SEQ.S", CmpSeqD => "CMP.SEQ.D",
            LdB => "LD.B", LdH => "LD.H", LdW => "LD.W", LdD => "LD.D",
            StB => "ST.B", StH => "ST.H", StW => "ST.W", StD => "ST.D",
            LdMsa => "LD.MSA", StMsa => "ST.MSA",
            LdiB => "LDI.B", LdiH => "LDI.H", LdiW => "LDI.W", LdiD => "LDI.D",
            InsertB => "INSERT.B", InsertH => "INSERT.H", InsertW => "INSERT.W", InsertD => "INSERT.D",
            InsveB => "INSVE.B", InsveH => "INSVE.H", InsveW => "INSVE.W", InsveD => "INSVE.D",
            CopySB => "COPY_S.B", CopySH => "COPY_S.H", CopySW => "COPY_S.W", CopySD => "COPY_S.D",
            CopyUB => "COPY_U.B", CopyUH => "COPY_U.H", CopyUW => "COPY_U.W",
            FillB => "FILL.B", FillH => "FILL.H", FillW => "FILL.W", FillD => "FILL.D",
            SplatB => "SPLAT.B", SplatH => "SPLAT.H", SplatW => "SPLAT.W", SplatD => "SPLAT.D",
            AddvB => "ADDV.B", AddvH => "ADDV.H", AddvW => "ADDV.W", AddvD => "ADDV.D",
            SubvB => "SUBV.B", SubvH => "SUBV.H", SubvW => "SUBV.W", SubvD => "SUBV.D",
            MulvB => "MULV.B", MulvH => "MULV.H", MulvW => "MULV.W", MulvD => "MULV.D",
            DivSB => "DivS.B", DivSH => "DivS.H", DivSW => "DivS.W", DivSD => "DivS.D",
            DivUB => "DIV_U.B", DivUH => "DIV_U.H", DivUW => "DIV_U.W", DivUD => "DIV_U.D",
            ModSB => "MOD_S.B", ModSH => "MOD_S.H", ModSW => "MOD_S.W", ModSD => "MOD_S.D",
            ModUB => "MOD_U.B", ModUH => "MOD_U.H", ModUW => "MOD_U.W", ModUD => "MOD_U.D",
            MaddvB => "MADDV.B", MaddvH => "MADDV.H", MaddvW => "MADDV.W", MaddvD => "MADDV.D",
            MsubvB => "MSUBV.B", MsubvH => "MSUBV.H", MsubvW => "MSUBV.W", MsubvD => "MSUBV.D",
            AndV => "AND.V", OrV => "OR.V", NorV => "NOR.V", XorV => "XOR.V",
            BclrB => "BCLR.B", BclrH => "BCLR.H", BclrW => "BCLR.W", BclrD => "BCLR.D",
            BsetB => "BSET.B", BsetH => "BSET.H", BsetW => "BSET.W", BsetD => "BSET.D",
            BnegB => "BNEG.B", BnegH => "BNEG.H", BnegW => "BNEG.W", BnegD => "BNEG.D",
            BmnzV => "BMNZ.V", BmzV => "BMZ.V", BselV => "BSEL.V",
            SllB => "SLL.B", SllH => "SLL.H", SllW => "SLL.W", SllD => "SLL.D",
            SraB => "SRA.B", SraH => "SRA.H", SraW => "SRA.W", SraD => "SRA.D",
            SrlB => "SRL.B", SrlH => "SRL.H", SrlW => "SRL.W", SrlD => "SRL.D",
            SrarB => "SRAR.B", SrarH => "SRAR.H", SrarW => "SRAR.W", SrarD => "SRAR.D",
            SrlrB => "SRLR.B", SrlrH => "SRLR.H", SrlrW => "SRLR.W", SrlrD => "SRLR.D",
            CeqB => "CEQ.B", CeqH => "CEQ.H", CeqW => "CEQ.W", CeqD => "CEQ.D",
            CleSB => "CLE_S.B", CleSH => "CLE_S.H", CleSW => "CLE_S.W", CleSD => "CLE_S.D",
            CleUB => "CLE_U.B", CleUH => "CLE_U.H", CleUW => "CLE_U.W", CleUD => "CLE_U.D",
            CltSB => "CLT_S.B", CltSH => "CLT_S.H", CltSW => "CLT_S.W", CltSD => "CLT_S.D",
            CltUB => "CLT_U.B", CltUH => "CLT_U.H", CltUW => "CLT_U.W", CltUD => "CLT_U.D",
            PckevB => "PCKEV.B", PckevH => "PCKEV.H", PckevW => "PCKEV.W", PckevD => "PCKEV.D",
            PckodB => "PCKOD.B", PckodH => "PCKOD.H", PckodW => "PCKOD.W", PckodD => "PCKOD.D",
            IlvevB => "ILVEV.B", IlvevH => "ILVEV.H", IlvevW => "ILVEV.W", IlvevD => "ILVEV.D",
            IlvodB => "ILVOD.B", IlvodH => "ILVOD.H", IlvodW => "ILVOD.W", IlvodD => "ILVOD.D",
            IlvlB => "ILVL.B", IlvlH => "ILVL.H", IlvlW => "ILVL.W", IlvlD => "ILVL.D",
            IlvrB => "ILVR.B", IlvrH => "ILVR.H", IlvrW => "ILVR.W", IlvrD => "ILVR.D",
            MaxSB => "MaxS.B", MaxSH => "MaxS.H", MaxSW => "MaxS.W", MaxSD => "MaxS.D",
            MaxUB => "MAX_U.B", MaxUH => "MAX_U.H", MaxUW => "MAX_U.W", MaxUD => "MAX_U.D",
            MinSB => "MinS.B", MinSH => "MinS.H", MinSW => "MinS.W", MinSD => "MinS.D",
            MinUB => "MIN_U.B", MinUH => "MIN_U.H", MinUW => "MIN_U.W", MinUD => "MIN_U.D",
            MaxAB => "MAX_A.B", MaxAH => "MAX_A.H", MaxAW => "MAX_A.W", MaxAD => "MAX_A.D",
            MinAB => "MIN_A.B", MinAH => "MIN_A.H", MinAW => "MIN_A.W", MinAD => "MIN_A.D",
            FaddW => "FADD.W", FaddD => "FADD.D",
            FsubW => "FSUB.W", FsubD => "FSUB.D",
            FmulW => "FMUL.W", FmulD => "FMUL.D",
            FdivW => "FDIV.W", FdivD => "FDIV.D",
            FmaddW => "FMADD.W", FmaddD => "FMADD.D",
            FmsubW => "FMSUB.W", FmsubD => "FMSUB.D",
            Fexp2W => "FEXP2.W", Fexp2D => "FEXP2.D",
            FceqW => "FCEQ.W", FceqD => "FCEQ.D",
            FcltW => "FCLT.W", FcltD => "FCLT.D",
            FcleW => "FCLE.W", FcleD => "FCLE.D",
            FminW => "FMIN.W", FminD => "FMIN.D",
            FminAW => "FMIN_A.W", FminAD => "FMIN_A.D",
            FmaxW => "FMAX.W", FmaxD => "FMAX.D",
            FmaxAW => "FMAX_A.W", FmaxAD => "FMAX_A.D",
            FsqrtW => "FSQRT.W", FsqrtD => "FSQRT.D",
            FclassW => "FCLASS.W", FclassD => "FCLASS.D",
            FtruncSW => "FTRUNC_S.W", FtruncSD => "FTRUNC_S.D",
            FtruncUW => "FTRUNC_U.W", FtruncUD => "FTRUNC_U.D",
            FintSW => "FINT_S.W", FintSD => "FINT_S.D",
            FintUW => "FINT_U.W", FintUD => "FINT_U.D",
            FrintW => "FRINT.W", FrintD => "FRINT.D",
            FfintSW => "FFINT_S.W", FfintSD => "FFINT_S.D",
            FfintUW => "FFINT_U.W", FfintUD => "FFINT_U.D",
            FtintSW => "FTINT_S.W", FtintSD => "FTINT_S.D",
            FtintUW => "FTINT_U.W", FtintUD => "FTINT_U.D",
            BnzV => "BNZ.V", BzV => "BZ.V",
            BnzB => "BNZ.B", BnzH => "BNZ.H", BnzW => "BNZ.W", BnzD => "BNZ.D",
            BzB => "BZ.B", BzH => "BZ.H", BzW => "BZ.W", BzD => "BZ.D",
            CTCMSA => "CTCMSA", CFCMSA => "CFCMSA",
            MoveV => "MOVE.V",
            VshfB => "VSHF.B", VshfH => "VSHF.H", VshfW => "VSHF.W", VshfD => "VSHF.D",
            SldB => "SLD.B", SldH => "SLD.H", SldW => "SLD.W", SldD => "SLD.D",
            SplatiB => "SPLATI.B", SplatiH => "SPLATI.H", SplatiW => "SPLATI.W", SplatiD => "SPLATI.D",
            NlocB => "NLOC.B", NlocH => "NLOC.H", NlocW => "NLOC.W", NlocD => "NLOC.D",
            NlzcB => "NLZC.B", NlzcH => "NLZC.H", NlzcW => "NLZC.W", NlzcD => "NLZC.D",
            PcntB => "PCNT.B", PcntH => "PCNT.H", PcntW => "PCNT.W", PcntD => "PCNT.D",
            FcafW => "FCAF.W", FcafD => "FCAF.D",
            FcorW => "FCOR.W", FcorD => "FCOR.D",
            FcuneW => "FCUNE.W", FcuneD => "FCUNE.D",
            FcneW => "FCNE.W", FcneD => "FCNE.D",
            FcunW => "FCUN.W", FcunD => "FCUN.D",
            FcueqW => "FCUEQ.W", FcueqD => "FCUEQ.D",
            FculeW => "FCULE.W", FculeD => "FCULE.D",
            FcultW => "FCULT.W", FcultD => "FCULT.D",
            FcugeW => "FCUGE.W", FcugeD => "FCUGE.D",
            FcugtW => "FCUGT.W", FcugtD => "FCUGT.D",
            FsafW => "FSAF.W", FsafD => "FSAF.D",
            FsorW => "FSOR.W", FsorD => "FSOR.D",
            FseqW => "FSEQ.W", FseqD => "FSEQ.D",
            FsuneW => "FSUNE.W", FsuneD => "FSUNE.D",
            FsneW => "FSNE.W", FsneD => "FSNE.D",
            FexdoH => "FEXDO.H", FexdoW => "FEXDO.W",
            FtqH => "FTQ.H", FtqW => "FTQ.W",
            FfqlW => "FFQL.W", FfqlD => "FFQL.D",
            FfqrW => "FFQR.W", FfqrD => "FFQR.D",
            FrcpW => "FRCP.W", FrcpD => "FRCP.D",
            FrsqrtW => "FRSQRT.W", FrsqrtD => "FRSQRT.D",
            Frsqrt2SW => "FRSQRT2_S.W", Frsqrt2SD => "FRSQRT2_S.D",
            Frcp2SW => "FRCP2_S.W", Frcp2SD => "FRCP2_S.D",
            FtintRneW => "FTINT_RNE.W", FtintRneD => "FTINT_RNE.D",
            FtintRzW => "FTINT_RZ.W", FtintRzD => "FTINT_RZ.D",
            FtintRpW => "FTINT_RP.W", FtintRpD => "FTINT_RP.D",
            FtintRmW => "FTINT_RM.W", FtintRmD => "FTINT_RM.D",
            ShfB => "SHF.B", ShfH => "SHF.H", ShfW => "SHF.W",
            AveSB => "AVE_S.B", AveSH => "AVE_S.H", AveSW => "AVE_S.W", AveSD => "AVE_S.D",
            AveUB => "AVE_U.B", AveUH => "AVE_U.H", AveUW => "AVE_U.W", AveUD => "AVE_U.D",
            AverSB => "AVER_S.B", AverSH => "AVER_S.H", AverSW => "AVER_S.W", AverSD => "AVER_S.D",
            AverUB => "AVER_U.B", AverUH => "AVER_U.H", AverUW => "AVER_U.W", AverUD => "AVER_U.D",
            AsubSB => "ASUB_S.B", AsubSH => "ASUB_S.H", AsubSW => "ASUB_S.W", AsubSD => "ASUB_S.D",
            AsubUB => "ASUB_U.B", AsubUH => "ASUB_U.H", AsubUW => "ASUB_U.W", AsubUD => "ASUB_U.D",
            HaddSH => "HADD_S.H", HaddSW => "HADD_S.W", HaddSD => "HADD_S.D",
            HaddUH => "HADD_U.H", HaddUW => "HADD_U.W", HaddUD => "HADD_U.D",
            HsubSH => "HSUB_S.H", HsubSW => "HSUB_S.W", HsubSD => "HSUB_S.D",
            HsubUH => "HSUB_U.H", HsubUW => "HSUB_U.W", HsubUD => "HSUB_U.D",
            DotpSH => "DOTP_S.H", DotpSW => "DOTP_S.W", DotpSD => "DOTP_S.D",
            DotpUH => "DOTP_U.H", DotpUW => "DOTP_U.W", DotpUD => "DOTP_U.D",
            DpaddSH => "DPADD_S.H", DpaddSW => "DPADD_S.W", DpaddSD => "DPADD_S.D",
            DpaddUH => "DPADD_U.H", DpaddUW => "DPADD_U.W", DpaddUD => "DPADD_U.D",
            DpsubSH => "DPSUB_S.H", DpsubSW => "DPSUB_S.W", DpsubSD => "DPSUB_S.D",
            DpsubUH => "DPSUB_U.H", DpsubUW => "DPSUB_U.W", DpsubUD => "DPSUB_U.D",
            MulQH => "MUL_Q.H", MulQW => "MUL_Q.W",
            MulrQH => "MULR_Q.H", MulrQW => "MULR_Q.W",
            MaddQH => "MADD_Q.H", MaddQW => "MADD_Q.W",
            MaddrQH => "MADDR_Q.H", MaddrQW => "MADDR_Q.W",
            MsubQH => "MSUB_Q.H", MsubQW => "MSUB_Q.W",
            MsubrQH => "MSUBR_Q.H", MsubrQW => "MSUBR_Q.W",
            SatSB => "SAT_S.B", SatSH => "SAT_S.H", SatSW => "SAT_S.W", SatSD => "SAT_S.D",
            SatUB => "SAT_U.B", SatUH => "SAT_U.H", SatUW => "SAT_U.W", SatUD => "SAT_U.D",
            SubsSB => "SUBS_S.B", SubsSH => "SUBS_S.H", SubsSW => "SUBS_S.W", SubsSD => "SUBS_S.D",
            SubsUB => "SUBS_U.B", SubsUH => "SUBS_U.H", SubsUW => "SUBS_U.W", SubsUD => "SUBS_U.D",
            SubsusUB => "SUBSUS_U.B", SubsusUH => "SUBSUS_U.H", SubsusUW => "SUBSUS_U.W", SubsusUD => "SUBSUS_U.D",
            SubsuuSB => "SUBSUU_S.B", SubsuuSH => "SUBSUU_S.H", SubsuuSW => "SUBSUU_S.W", SubsuuSD => "SUBSUU_S.D",
            CmpEqB => "CMP_EQ.B", CmpEqH => "CMP_EQ.H", CmpEqW => "CMP_EQ.W", MsaCmpEqD => "CMP_EQ.D",
            CmpLeSB => "CmpLeS.B", CmpLeSH => "CmpLeS.H", CmpLeSW => "CmpLeS.W", CmpLeSD => "CmpLeS.D",
            CmpLeUB => "CMP_LE_U.B", CmpLeUH => "CMP_LE_U.H", CmpLeUW => "CMP_LE_U.W", CmpLeUD => "CMP_LE_U.D",
            CmpLtSB => "CmpLtS.B", CmpLtSH => "CmpLtS.H", CmpLtSW => "CmpLtS.W", CmpLtSD => "CmpLtS.D",
            CmpLtUB => "CMP_LT_U.B", CmpLtUH => "CMP_LT_U.H", CmpLtUW => "CMP_LT_U.W", CmpLtUD => "CMP_LT_U.D",
            AbsqSPh => "ABSQ_S.PH", AbsqSW => "ABSQ_S.W",
            AbsqSQb => "ABSQ_S.QB", AbsqSQh => "ABSQ_S.QH",
            AddqPh => "ADDQ.PH", AddqSPh => "ADDQ_S.PH", AddqSW => "ADDQ_S.W",
            AddqhPh => "ADDQH.PH", AddqhW => "ADDQH.W",
            AddqhRPh => "ADDQH_R.PH", AddqhRW => "ADDQH_R.W",
            ADDSC => "ADDSC", ADDWC => "ADDWC",
            AdduPh => "ADDU.PH", AdduSPh => "ADDU_S.PH",
            AdduQb => "ADDU.QB", AdduSQb => "ADDU_S.QB",
            AdduhQb => "ADDUH.QB", AdduhRQb => "ADDUH_R.QB",
            APPEND => "APPEND", PREPEND => "PREPEND",
            BALIGN => "BALIGN", BITREV => "BITREV", BPOSGE32 => "BPOSGE32",
            CmpEqPh => "CMP.EQ.PH", CmpLePh => "CMP.LE.PH", CmpLtPh => "CMP.LT.PH",
            CmpguEqQb => "CMPGU.EQ.QB", CmpguLeQb => "CMPGU.LE.QB", CmpguLtQb => "CMPGU.LT.QB",
            CmpuEqQb => "CMPU.EQ.QB", CmpuLeQb => "CMPU.LE.QB", CmpuLtQb => "CMPU.LT.QB",
            DpaWPh => "DPA.W.PH", DpaqxSWPh => "DPAQX_S.W.PH", DpaqxSaWPh => "DPAQX_SA.W.PH",
            DpauHQbl => "DPAU.H.QBL", DpauHQbr => "DPAU.H.QBR",
            DpsWPh => "DPS.W.PH", DpsqxSWPh => "DPSQX_S.W.PH", DpsqxSaWPh => "DPSQX_SA.W.PH",
            DpsuHQbl => "DPSU.H.QBL", DpsuHQbr => "DPSU.H.QBR",
            EXTP => "EXTP", EXTPDP => "EXTPDP", EXTPDPV => "EXTPDPV", EXTPV => "EXTPV",
            ExtrW => "EXTR.W", ExtrRW => "EXTR_R.W", ExtrRsW => "EXTR_RS.W", ExtrSH => "EXTR_S.H",
            ExtrvW => "EXTRV.W", ExtrvRW => "EXTRV_R.W", ExtrvRsW => "EXTRV_RS.W", ExtrvSH => "EXTRV_S.H",
            INSV => "INSV", LBUX => "LBUX", LHX => "LHX", LWX => "LWX",
            MaddDsp => "MADD", MadduDsp => "MADDU",
            MaqSWPhl => "MAQ_S.W.PHL", MaqSWPhr => "MAQ_S.W.PHR",
            MaqSaWPhl => "MAQ_SA.W.PHL", MaqSaWPhr => "MAQ_SA.W.PHR",
            MFHIDSP => "MFHIDSP", MTHIDSP => "MTHIDSP",
            MODSUB => "MODSUB", MsubDsp => "MSUB", MsubuDsp => "MSUBU", MTHLIP => "MTHLIP",
            MulPh => "MUL.PH", MulSPh => "MulS.PH",
            MuleqSWPhl => "MULEQ_S.W.PHL", MuleqSWPhr => "MULEQ_S.W.PHR",
            MuleuSPhQbl => "MULEU_S.PH.QBL", MuleuSPhQbr => "MULEU_S.PH.QBR",
            MulqRsPh => "MULQ_RS.PH", MulqRsW => "MULQ_RS.W",
            MulqSPh => "MULQ_S.PH", MulqSW => "MULQ_S.W",
            MulsaWPh => "MULSA.W.PH", MulsaqSWPh => "MULSAQ_S.W.PH",
            PackrlPh => "PACKRL.PH",
            PickPh => "PICK.PH", PickQb => "PICK.QB",
            PreceqWPhl => "PRECEQ.W.PHL", PreceqWPhr => "PRECEQ.W.PHR",
            PrecequPhQbl => "PRECEQU.PH.QBL", PrecequPhQbr => "PRECEQU.PH.QBR",
            PreceuPhQbl => "PRECEU.PH.QBL", PreceuPhQbr => "PRECEU.PH.QBR",
            PrecrQbPh => "PRECR.QB.PH",
            PrecrSraPhW => "PRECR_SRA.PH.W", PrecrSraRPhW => "PRECR_SRA_R.PH.W",
            PrecrqPhW => "PRECRQ.PH.W", PrecrqQbPh => "PRECRQ.QB.PH",
            PrecrqRsPhW => "PRECRQ_RS.PH.W",
            RadduWQb => "RADDU.W.QB",
            RDDSP => "RDDSP", WRDSP => "WRDSP",
            ReplPh => "REPL.PH", ReplQb => "REPL.QB",
            ReplvPh => "REPLV.PH", ReplvQb => "REPLV.QB",
            SHILO => "SHILO", SHILOV => "SHILOV",
            ShllPh => "SHLL.PH", ShllSPh => "SHLL_S.PH",
            ShllQb => "SHLL.QB", ShllSQb => "SHLL_S.QB", ShllSW => "SHLL_S.W",
            ShllvPh => "SHLLV.PH", ShllvSPh => "SHLLV_S.PH",
            ShllvQb => "SHLLV.QB", ShllvSQb => "SHLLV_S.QB", ShllvSW => "SHLLV_S.W",
            ShraPh => "SHRA.PH", ShraRPh => "SHRA_R.PH",
            ShraRQb => "SHRA_R.QB", ShraRW => "SHRA_R.W",
            ShravPh => "SHRAV.PH", ShravRPh => "SHRAV_R.PH",
            ShravRQb => "SHRAV_R.QB", ShravRW => "SHRAV_R.W",
            ShrlPh => "SHRL.PH", ShrlQb => "SHRL.QB",
            ShrlvPh => "SHRLV.PH", ShrlvQb => "SHRLV.QB",
            SubqPh => "SUBQ.PH", SubqSPh => "SUBQ_S.PH", SubqSW => "SUBQ_S.W",
            SubqhPh => "SUBQH.PH", SubqhW => "SUBQH.W",
            SubqhRPh => "SUBQH_R.PH", SubqhRW => "SUBQH_R.W",
            SubuPh => "SUBU.PH", SubuSPh => "SUBU_S.PH",
            SubuQb => "SUBU.QB", SubuSQb => "SUBU_S.QB",
            SubuhQb => "SUBUH.QB", SubuhRQb => "SUBUH_R.QB",
            HYPCALL => "HYPCALL",
            DMFC0G => "DMFC0G", DMTC0G => "DMTC0G",
            MFC0G => "MFC0G", MTC0G => "MTC0G",
            TLBGINV => "TLBGINV", TLBGINVF => "TLBGINVF",
            TLBGP => "TLBGP", TLBGR => "TLBGR", TLBGWI => "TLBGWI", TLBGWR => "TLBGWR",
            MFGC0 => "MFGC0", MTGC0 => "MTGC0",
            M16Addius5 => "ADDIUS5", M16Addiusp => "ADDIUSP",
            M16Addiupc => "ADDIUPC", M16Addiur1sp => "ADDIUR1SP", M16Addiur2 => "ADDIUR2",
            M16Addu16 => "ADDU16", M16And16 => "AND16",
            M16Beqz16 => "BEQZ16", M16Bnez16 => "BNEZ16",
            M16Bteqz => "BTEQZ", M16Btnez => "BTNEZ",
            M16Cmpi => "CMPI", M16Cmp => "CMP", M16Div16 => "DIV16",
            M16Extend => "EXTEND", M16Jal16 => "JAL16",
            M16Jalrc16 => "JALRC16", M16Jalx => "JALX", M16Jrc16 => "JRC16",
            M16Lb16 => "LB16", M16Lbu16 => "LBU16", M16Lh16 => "LH16",
            M16Lhu16 => "LHU16", M16Li16 => "LI16", M16Lw16 => "LW16",
            M16Lwpc => "LWPC", M16Lwsp => "LWSP",
            M16Mfhi16 => "MFHI16", M16Mflo16 => "MFLO16",
            M16Move => "MOVE", M16Moven => "MOVEN", M16Movez => "MOVEZ",
            M16Mul16 => "MUL16", M16Mult16 => "MULT16",
            M16Neg16 => "NEG16", M16Not16 => "NOT16", M16Or16 => "OR16",
            M16Restore => "RESTORE", M16RestoreJalrc => "RESTORE.JALRC",
            M16Save => "SAVE", M16Sb16 => "SB16",
            M16Seb16 => "SEB16", M16Seh16 => "SEH16",
            M16Sh16 => "SH16", M16Sll16 => "SLL16",
            M16Sra16 => "SRA16", M16Srl16 => "SRL16",
            M16Subu16 => "SUBU16", M16Sw16 => "SW16", M16Swsp => "SWSP",
            M16Xor16 => "XOR16", M16Zeb16 => "ZEB16", M16Zeh16 => "ZEH16",
            UmmAddiu32 => "ADDIU32", UmmAddiupc => "ADDIUPC", UmmAddiusp => "ADDIUSP",
            UmmAlign => "ALIGN", UmmAlnv4 => "ALNV.4",
            UmmAnd16 => "AND16", UmmAndi16 => "ANDI16",
            UmmB16 => "B16", UmmBalc16 => "BALC16", UmmBc16 => "BC16",
            UmmBeqzc16 => "BEQZC16", UmmBnezc16 => "BNEZC16",
            UmmBreak16 => "BREAK16", UmmCache => "CACHE", UmmDiv => "DIV",
            UmmJalr16 => "JALR16", UmmJalrs16 => "JALRS16",
            UmmJalrs => "JALRS", UmmJalrx => "JALRX", UmmJalx => "JALX",
            UmmJr16 => "JR16", UmmJraddiusp => "JRADDIUSP",
            UmmJrc16 => "JRC16", UmmJrcaddiusp => "JRCADDIUSP",
            UmmLb16 => "LB16", UmmLbu16 => "LBU16",
            UmmLh16 => "LH16", UmmLhu16 => "LHU16",
            UmmLi16 => "LI16", UmmLw16 => "LW16",
            UmmLwgp => "LWGP", UmmLwsp => "LWSP",
            UmmMfhi16 => "MFHI16", UmmMflo16 => "MFLO16",
            UmmMove16 => "MOVE16", UmmMovep => "MOVEP", UmmMul => "MUL",
            UmmNop16 => "NOP16",
            UmmNot16 => "NOT16", UmmOr16 => "OR16", UmmSdbbp16 => "SDBBP16",
            UmmSh16 => "SH16", UmmSll16 => "SLL16",
            UmmSra16 => "SRA16", UmmSrl16 => "SRL16",
            UmmSub16 => "SUB16", UmmSubu16 => "SUBU16",
            UmmSw16 => "SW16", UmmSwgp => "SWGP", UmmSwsp => "SWSP",
            UmmTeq => "TEQ", UmmTge => "TGE", UmmTgeu => "TGEU",
            UmmTlt => "TLT", UmmTltu => "TLTU", UmmTne => "TNE",
            UmmXor16 => "XOR16", UmmXori16 => "XORI16",
            UmmPref => "PREF", UmmSyscall => "SYSCALL",
            UmmBal => "BAL", UmmBeq => "BEQ", UmmBgez => "BGEZ",
            UmmBgtz => "BGTZ", UmmBlez => "BLEZ", UmmBltz => "BLTZ", UmmBne => "BNE",
            UmmMthi16 => "MTHI16", UmmMtlo16 => "MTLO16",
            UmmLsa => "LSA", UmmDlsa => "DLSA",
            UmmSeleqz => "SELEQZ", UmmSelnez => "SELNEZ", UmmEhb => "EHB",
            FexuplW => "FEXUPL.W", FexuplD => "FEXUPL.D",
            FexuprW => "FEXUPR.W", FexuprD => "FEXUPR.D",
            Flog2W => "FLOG2.W", Flog2D => "FLOG2.D",
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
            | J | JAL | JR | JALR | JrHb | JalrHb | JALX | B | BAL | NAL
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
            | TLBINV | TLBINVF | TlbinvfFull
            => MipsInstructionCategory::System,

            AddS | AddD | SubS | SubD | MulS | MulD | DivS | DivD
            | SqrtS | SqrtD | AbsS | AbsD | NegS | NegD | MovS | MovD
            | MovfS | MovfD | MovtS | MovtD | MovzS | MovzD | MovnS | MovnD
            | CvtSD | CvtSW | CvtSL | CvtDS | CvtDW | CvtDL
            | CvtWS | CvtWD | CvtLS | CvtLD | CvtPsS
            | CeilWS | CeilWD | CeilLS | CeilLD
            | FloorWS | FloorWD | FloorLS | FloorLD
            | RoundWS | RoundWD | RoundLS | RoundLD
            | TruncWS | TruncWD | TruncLS | TruncLD
            | RecipS | RecipD | RsqrtS | RsqrtD
            | CFS | CFD | CUnS | CUnD | CEqS | CEqD
            | CLtS | CLtD | CLeS | CLeD
            | CUeqS | CUeqD | CUltS | CUltD | CUleS | CUleD
            | COleS | COleD | COltS | COltD
            | CSeqS | CSeqD | CNgtS | CNgtD | CNgeS | CNgeD
            | CNgleS | CNgleD | CNglS | CNglD
            | MaddfS | MaddfD | MsubfS | MsubfD
            | MaxS | MaxD | MinS | MinD | MaxaS | MaxaD | MinaS | MinaD
            | SelS | SelD | SeleqzS | SeleqzD | SelnezS | SelnezD
            | ClassS | ClassD | RintS | RintD
            | BC1ANY2F | BC1ANY2T | BC1ANY4F | BC1ANY4T
            | MaddS | MsubS | NmaddS | NmsubS
            | MaddD | MsubD | NmaddD | NmsubD
            | CmpAfS | CmpAfD | CmpUnS | CmpUnD | CmpEqS | CmpEqD
            | CmpUeqS | CmpUeqD | CmpLtS | CmpLtD
            | CmpUltS | CmpUltD | CmpLeS | CmpLeD | CmpUleS | CmpUleD
            | CmpSafS | CmpSafD | CmpSunS | CmpSunD | CmpSeqS | CmpSeqD
            => MipsInstructionCategory::Fpu,

            HYPCALL | DMFC0G | DMTC0G | MFC0G | MTC0G
            | TLBGINV | TLBGINVF | TLBGP | TLBGR | TLBGWI | TLBGWR
            | MFGC0 | MTGC0 => MipsInstructionCategory::Virtualization,

            AbsqSPh | AbsqSW | AddqPh | AddqSPh | AddqSW
            | ADDSC | AdduQb | AdduSQb | ADDWC | BITREV | BPOSGE32
            | CmpguEqQb | CmpuEqQb | DpaWPh | DpsWPh
            | EXTP | EXTPDP | ExtrW | ExtrRW | ExtrRsW
            | ExtrvW | ExtrvRW | INSV | MaddDsp | MadduDsp
            | MsubDsp | MsubuDsp | MulPh | MulSPh | MulqRsPh | MulqSPh
            | MulsaWPh | RadduWQb | RDDSP | WRDSP | ReplPh | ReplQb
            | ShllPh | ShllQb | ShllSW | ShllvPh | ShllvQb | ShllvSW
            | ShraPh | ShraRPh | ShraRW | ShravPh | ShravRPh | ShravRW
            | ShrlPh | ShrlQb | ShrlvPh | ShrlvQb
            | SubqPh | SubqSPh | SubqSW | SubuPh | SubuSPh
            | SubuQb | SubuSQb => MipsInstructionCategory::Dsp,

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
        J, JAL, JR, JALR, JrHb, JalrHb, JALX, B, BAL, NAL,
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
        DI, EI, DERET, TLBP, TLBR, TLBWI, TLBWR, TLBINV, TLBINVF, TlbinvfFull,
        AddS, AddD, SubS, SubD, MulS, MulD, DivS, DivD,
        SqrtS, SqrtD, AbsS, AbsD, NegS, NegD, MovS, MovD,
        MovfS, MovfD, MovtS, MovtD, MovzS, MovzD, MovnS, MovnD,
        CvtSD, CvtSW, CvtSL, CvtDS, CvtDW, CvtDL,
        CvtWS, CvtWD, CvtLS, CvtLD, CvtPsS,
        CeilWS, CeilWD, CeilLS, CeilLD,
        FloorWS, FloorWD, FloorLS, FloorLD,
        RoundWS, RoundWD, RoundLS, RoundLD,
        TruncWS, TruncWD, TruncLS, TruncLD,
        RecipS, RecipD, RsqrtS, RsqrtD,
        CFS, CFD, CUnS, CUnD, CEqS, CEqD,
        CLtS, CLtD, CLeS, CLeD,
        CUeqS, CUeqD, CUltS, CUltD, CUleS, CUleD,
        COleS, COleD, COltS, COltD,
        CSeqS, CSeqD, CNgtS, CNgtD, CNgeS, CNgeD,
        CNgleS, CNgleD, CNglS, CNglD,
        MaddfS, MaddfD, MsubfS, MsubfD,
        MaxS, MaxD, MinS, MinD, MaxaS, MaxaD, MinaS, MinaD,
        SelS, SelD, SeleqzS, SeleqzD, SelnezS, SelnezD,
        ClassS, ClassD, RintS, RintD,
        BC1ANY2F, BC1ANY2T, BC1ANY4F, BC1ANY4T,
        MaddS, MsubS, NmaddS, NmsubS,
        MaddD, MsubD, NmaddD, NmsubD,
        CmpAfS, CmpAfD, CmpUnS, CmpUnD, CmpEqS, CmpEqD,
        CmpUeqS, CmpUeqD, CmpLtS, CmpLtD, CmpUltS, CmpUltD,
        CmpLeS, CmpLeD, CmpUleS, CmpUleD,
        CmpSafS, CmpSafD, CmpSunS, CmpSunD, CmpSeqS, CmpSeqD,
        LdB, LdH, LdW, LdD, StB, StH, StW, StD,
        LdMsa, StMsa,
        LdiB, LdiH, LdiW, LdiD,
        InsertB, InsertH, InsertW, InsertD,
        InsveB, InsveH, InsveW, InsveD,
        CopySB, CopySH, CopySW, CopySD,
        CopyUB, CopyUH, CopyUW,
        FillB, FillH, FillW, FillD,
        SplatB, SplatH, SplatW, SplatD,
        AddvB, AddvH, AddvW, AddvD, SubvB, SubvH, SubvW, SubvD,
        MulvB, MulvH, MulvW, MulvD,
        DivSB, DivSH, DivSW, DivSD,
        DivUB, DivUH, DivUW, DivUD,
        ModSB, ModSH, ModSW, ModSD,
        ModUB, ModUH, ModUW, ModUD,
        MaddvB, MaddvH, MaddvW, MaddvD,
        MsubvB, MsubvH, MsubvW, MsubvD,
        AndV, OrV, NorV, XorV,
        BclrB, BclrH, BclrW, BclrD,
        BsetB, BsetH, BsetW, BsetD,
        BnegB, BnegH, BnegW, BnegD,
        BmnzV, BmzV, BselV,
        SllB, SllH, SllW, SllD,
        SraB, SraH, SraW, SraD,
        SrlB, SrlH, SrlW, SrlD,
        SrarB, SrarH, SrarW, SrarD,
        SrlrB, SrlrH, SrlrW, SrlrD,
        CeqB, CeqH, CeqW, CeqD,
        CleSB, CleSH, CleSW, CleSD,
        CleUB, CleUH, CleUW, CleUD,
        CltSB, CltSH, CltSW, CltSD,
        CltUB, CltUH, CltUW, CltUD,
        CmpEqB, CmpEqH, CmpEqW, MsaCmpEqD,
        CmpLeSB, CmpLeSH, CmpLeSW, CmpLeSD,
        CmpLeUB, CmpLeUH, CmpLeUW, CmpLeUD,
        CmpLtSB, CmpLtSH, CmpLtSW, CmpLtSD,
        CmpLtUB, CmpLtUH, CmpLtUW, CmpLtUD,
        PckevB, PckevH, PckevW, PckevD,
        PckodB, PckodH, PckodW, PckodD,
        IlvevB, IlvevH, IlvevW, IlvevD,
        IlvodB, IlvodH, IlvodW, IlvodD,
        IlvlB, IlvlH, IlvlW, IlvlD,
        IlvrB, IlvrH, IlvrW, IlvrD,
        MaxSB, MaxSH, MaxSW, MaxSD,
        MaxUB, MaxUH, MaxUW, MaxUD,
        MinSB, MinSH, MinSW, MinSD,
        MinUB, MinUH, MinUW, MinUD,
        MaxAB, MaxAH, MaxAW, MaxAD,
        MinAB, MinAH, MinAW, MinAD,
        FaddW, FaddD, FsubW, FsubD, FmulW, FmulD, FdivW, FdivD,
        FmaddW, FmaddD, FmsubW, FmsubD,
        Fexp2W, Fexp2D, FexdoH, FexdoW, FtqH, FtqW,
        FminW, FminD, FminAW, FminAD,
        FmaxW, FmaxD, FmaxAW, FmaxAD,
        FcorW, FcorD, FcuneW, FcuneD,
        FcneW, FcneD, FceqW, FceqD,
        FcunW, FcunD, FcueqW, FcueqD,
        FculeW, FculeD, FcultW, FcultD,
        FcugeW, FcugeD, FcugtW, FcugtD,
        FcltW, FcltD, FcleW, FcleD,
        FsafW, FsafD, FsorW, FsorD,
        FseqW, FseqD, FsuneW, FsuneD, FsneW, FsneD,
        FintSW, FintSD, FintUW, FintUD,
        FrintW, FrintD, Flog2W, Flog2D,
        FtruncSW, FtruncSD, FtruncUW, FtruncUD,
        Frsqrt2SW, Frsqrt2SD, Frcp2SW, Frcp2SD,
        FfintSW, FfintSD, FfintUW, FfintUD,
        FtintSW, FtintSD, FtintUW, FtintUD,
        FfqlW, FfqlD, FfqrW, FfqrD,
        FsqrtW, FsqrtD, FrcpW, FrcpD, FrsqrtW, FrsqrtD,
        FclassW, FclassD,
        BnzV, BzV, BnzB, BnzH, BnzW, BnzD,
        BzB, BzH, BzW, BzD,
        CTCMSA, CFCMSA,
        VshfB, VshfH, VshfW, VshfD,
        SldB, SldH, SldW, SldD,
        SplatiB, SplatiH, SplatiW, SplatiD,
        NlocB, NlzcB, PcntB, PcntH, PcntW, PcntD,
        MoveV, FexuplW, FexuplD, FexuprW, FexuprD,
        ShfB, ShfH, ShfW,
        FtintRneW, FtintRneD, FtintRzW, FtintRzD,
        FtintRpW, FtintRpD, FtintRmW, FtintRmD,
        FcafW, FcafD,
        AveSB, AveSH, AveSW, AveSD,
        AveUB, AveUH, AveUW, AveUD,
        AverSB, AverSH, AverSW, AverSD,
        AverUB, AverUH, AverUW, AverUD,
        AsubSB, AsubSH, AsubSW, AsubSD,
        AsubUB, AsubUH, AsubUW, AsubUD,
        HaddSH, HaddSW, HaddSD,
        HaddUH, HaddUW, HaddUD,
        HsubSH, HsubSW, HsubSD,
        HsubUH, HsubUW, HsubUD,
        DotpSH, DotpSW, DotpSD,
        DotpUH, DotpUW, DotpUD,
        DpaddSH, DpaddSW, DpaddSD,
        DpaddUH, DpaddUW, DpaddUD,
        DpsubSH, DpsubSW, DpsubSD,
        DpsubUH, DpsubUW, DpsubUD,
        MulQH, MulQW, MulrQH, MulrQW,
        MaddQH, MaddQW, MaddrQH, MaddrQW,
        MsubQH, MsubQW, MsubrQH, MsubrQW,
        SatSB, SatSH, SatSW, SatSD,
        SatUB, SatUH, SatUW, SatUD,
        SubsSB, SubsSH, SubsSW, SubsSD,
        SubsUB, SubsUH, SubsUW, SubsUD,
        SubsusUB, SubsusUH, SubsusUW, SubsusUD,
        SubsuuSB, SubsuuSH, SubsuuSW, SubsuuSD,
        AbsqSPh, AbsqSW, AbsqSQb, AbsqSQh,
        AddqPh, AddqSPh, AddqSW, AddqhPh, AddqhW,
        AddqhRPh, AddqhRW, ADDSC, ADDWC,
        AdduPh, AdduSPh, AdduQb, AdduSQb,
        AdduhQb, AdduhRQb, APPEND, PREPEND, BALIGN, BITREV, BPOSGE32,
        CmpEqPh, CmpLePh, CmpLtPh,
        CmpguEqQb, CmpguLeQb, CmpguLtQb,
        CmpuEqQb, CmpuLeQb, CmpuLtQb,
        DpaWPh, DpaqxSWPh, DpaqxSaWPh,
        DpauHQbl, DpauHQbr,
        DpsWPh, DpsqxSWPh, DpsqxSaWPh,
        DpsuHQbl, DpsuHQbr,
        EXTP, EXTPDP, EXTPDPV, EXTPV,
        ExtrW, ExtrRW, ExtrRsW, ExtrSH,
        ExtrvW, ExtrvRW, ExtrvRsW, ExtrvSH,
        INSV, LBUX, LHX, LWX,
        MaddDsp, MadduDsp,
        MaqSWPhl, MaqSWPhr, MaqSaWPhl, MaqSaWPhr,
        MFHIDSP, MTHIDSP, MODSUB, MsubDsp, MsubuDsp, MTHLIP,
        MulPh, MulSPh,
        MuleqSWPhl, MuleqSWPhr,
        MuleuSPhQbl, MuleuSPhQbr,
        MulqRsPh, MulqRsW, MulqSPh, MulqSW,
        MulsaWPh, MulsaqSWPh, PackrlPh,
        PickPh, PickQb,
        PreceqWPhl, PreceqWPhr,
        PrecequPhQbl, PrecequPhQbr,
        PreceuPhQbl, PreceuPhQbr,
        PrecrQbPh, PrecrSraPhW, PrecrSraRPhW,
        PrecrqPhW, PrecrqQbPh, PrecrqRsPhW,
        RadduWQb, RDDSP, WRDSP,
        ReplPh, ReplQb, ReplvPh, ReplvQb,
        SHILO, SHILOV,
        ShllPh, ShllSPh, ShllQb, ShllSQb, ShllSW,
        ShllvPh, ShllvSPh, ShllvQb, ShllvSQb, ShllvSW,
        ShraPh, ShraRPh, ShraRQb, ShraRW, ShravPh,
        ShravRPh, ShravRQb, ShravRW,
        ShrlPh, ShrlQb, ShrlvPh, ShrlvQb,
        SubqPh, SubqSPh, SubqSW, SubqhPh, SubqhW,
        SubqhRPh, SubqhRW,
        SubuPh, SubuSPh, SubuQb, SubuSQb,
        SubuhQb, SubuhRQb,
        HYPCALL, DMFC0G, DMTC0G, MFC0G, MTC0G,
        TLBGINV, TLBGINVF, TLBGP, TLBGR, TLBGWI, TLBGWR, MFGC0, MTGC0,
        M16Addius5, M16Addiusp, M16Addiupc, M16Addiur1sp, M16Addiur2,
        M16Addu16, M16And16, M16Beqz16, M16Bnez16,
        M16Bteqz, M16Btnez, M16Cmpi, M16Cmp, M16Div16,
        M16Extend, M16Jal16, M16Jalrc16, M16Jalx, M16Jrc16,
        M16Lb16, M16Lbu16, M16Lh16, M16Lhu16, M16Li16, M16Lw16,
        M16Lwpc, M16Lwsp, M16Mfhi16, M16Mflo16, M16Move,
        M16Moven, M16Movez, M16Mul16, M16Mult16,
        M16Neg16, M16Not16, M16Or16,
        M16Restore, M16RestoreJalrc, M16Save, M16Sb16,
        M16Seb16, M16Seh16, M16Sh16, M16Sll16,
        M16Sra16, M16Srl16, M16Subu16, M16Sw16, M16Swsp,
        M16Xor16, M16Zeb16, M16Zeh16,
        UmmAddiu32, UmmAddiupc, UmmAddiusp,
        UmmAlign, UmmAlnv4, UmmAnd16, UmmAndi16,
        UmmB16, UmmBalc16, UmmBc16, UmmBeqzc16, UmmBnezc16,
        UmmBreak16, UmmCache, UmmDiv,
        UmmJalr16, UmmJalrs16, UmmJalrs, UmmJalrx, UmmJalx,
        UmmJr16, UmmJraddiusp, UmmJrc16, UmmJrcaddiusp,
        UmmLb16, UmmLbu16, UmmLh16, UmmLhu16, UmmLi16, UmmLw16,
        UmmLwgp, UmmLwsp, UmmMfhi16, UmmMflo16,
        UmmMove16, UmmMovep, UmmMul, UmmNop16,
        UmmNot16, UmmOr16, UmmSdbbp16,
        UmmSh16, UmmSll16, UmmSra16, UmmSrl16,
        UmmSub16, UmmSubu16, UmmSw16, UmmSwgp, UmmSwsp,
        UmmTeq, UmmTge, UmmTgeu, UmmTlt, UmmTltu, UmmTne,
        UmmXor16, UmmXori16, UmmPref, UmmSyscall,
        UmmBal, UmmBeq, UmmBgez, UmmBgtz, UmmBlez, UmmBltz, UmmBne,
        UmmMthi16, UmmMtlo16, UmmLsa, UmmDlsa,
        UmmSeleqz, UmmSelnez, UmmEhb,
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
            // -- 32-bit default (mips16e mode) --
            Language::new("MIPS:BE:32:default", "MIPS32 32-bit addresses, big endian, with mips16e", "1.9", Endian::Big, 32),
            Language::new("MIPS:LE:32:default", "MIPS32 32-bit addresses, little endian, with mips16e", "1.9", Endian::Little, 32),
            // -- 32-bit mips16e --
            Language::new("MIPS:BE:32:16e", "MIPS32 32-bit addresses, big endian, in mips16e mode", "1.9", Endian::Big, 32),
            Language::new("MIPS:LE:32:16e", "MIPS32 32-bit addresses, little endian, in mips16e mode", "1.9", Endian::Little, 32),
            // -- 32-bit microMIPS --
            Language::new("MIPS:BE:32:micro", "MIPS32 32-bit addresses, big endian, with microMIPS", "1.9", Endian::Big, 32),
            Language::new("MIPS:LE:32:micro", "MIPS32 32-bit addresses, little endian, with microMIPS", "1.9", Endian::Little, 32),
            // -- 32-bit R6 --
            Language::new("MIPS:BE:32:R6", "MIPS32 Release-6 32-bit addresses, big endian, with microMIPS", "1.9", Endian::Big, 32),
            Language::new("MIPS:LE:32:R6", "MIPS32 Release-6 32-bit addresses, little endian, with microMIPS", "1.9", Endian::Little, 32),
            // -- 64-bit default (mips16e mode) --
            Language::new("MIPS:BE:64:default", "MIPS64 64-bit addresses, big endian, with mips16e", "1.9", Endian::Big, 64),
            Language::new("MIPS:LE:64:default", "MIPS64 64-bit addresses, little endian, with mips16e", "1.9", Endian::Little, 64),
            // -- 64-bit mips16e --
            Language::new("MIPS:BE:64:16e", "MIPS64 64-bit addresses, big endian, in mips16e mode", "1.9", Endian::Big, 64),
            Language::new("MIPS:LE:64:16e", "MIPS64 64-bit addresses, little endian, in mips16e mode", "1.9", Endian::Little, 64),
            // -- 64-bit microMIPS --
            Language::new("MIPS:BE:64:micro", "MIPS64 64-bit addresses, big endian, with microMIPS", "1.9", Endian::Big, 64),
            Language::new("MIPS:LE:64:micro", "MIPS64 64-bit addresses, little endian, with microMIPS", "1.9", Endian::Little, 64),
            // -- 64-bit R6 --
            Language::new("MIPS:BE:64:R6", "MIPS64 Release-6 64-bit addresses, big endian, with microMIPS", "1.9", Endian::Big, 64),
            Language::new("MIPS:LE:64:R6", "MIPS64 Release-6 64-bit addresses, little endian, with microMIPS", "1.9", Endian::Little, 64),
            // -- 64-bit with 32-bit addressing --
            Language::new("MIPS:BE:64:64-32addr", "MIPS64 32-bit addresses, big endian, with mips16e", "1.9", Endian::Big, 32),
            Language::new("MIPS:LE:64:64-32addr", "MIPS64 32-bit addresses, little endian, with mips16e", "1.9", Endian::Little, 32),
            // -- 64-bit microMIPS with 32-bit addressing --
            Language::new("MIPS:BE:64:micro64-32addr", "MIPS64 32-bit addresses, big endian, with microMIPS", "1.9", Endian::Big, 32),
            Language::new("MIPS:LE:64:micro64-32addr", "MIPS64 32-bit addresses, little endian, with microMIPS", "1.9", Endian::Little, 32),
            // -- 64-bit R6 with 32-bit addressing --
            Language::new("MIPS:BE:64:64-32R6addr", "MIPS64 Release-6 big endian with 32 bit addressing and microMIPS", "1.9", Endian::Big, 32),
            Language::new("MIPS:LE:64:64-32R6addr", "MIPS64 Release-6 with 32-bit addresses, little endian, with microMIPS", "1.9", Endian::Little, 32),
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
        assert!(langs.len() >= 20, "Expected >= 20 MIPS language variants, got {}", langs.len());
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
        assert!(matches!(MipsMnemonic::AddS.category(), MipsInstructionCategory::Fpu));
        assert!(matches!(MipsMnemonic::AddvB.category(), MipsInstructionCategory::Simd));
        assert!(matches!(MipsMnemonic::AbsqSPh.category(), MipsInstructionCategory::Dsp));
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
