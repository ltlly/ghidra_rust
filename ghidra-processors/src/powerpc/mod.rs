//! PowerPC Processor Module
//!
//! Complete PowerPC 32/64-bit processor support for the Ghidra Rust implementation.
//!
//! ## Supported ISA Variants
//!
//! | Variant          | Features                                          |
//! |------------------|---------------------------------------------------|
//! | PPC 601          | Original PowerPC 601                              |
//! | PPC 603          | PowerPC 603/603e                                  |
//! | PPC 604          | PowerPC 604/604e                                  |
//! | PPC 740/750 (G3) | PowerPC G3                                        |
//! | PPC 74xx (G4)    | PowerPC G4 with Altivec/VMX                       |
//! | PPC 970 (G5)     | PowerPC G5, 64-bit, VMX                           |
//! | PPC 4xx          | Embedded PowerPC 4xx                              |
//! | PPC 440          | Embedded PowerPC 440, Book-E                      |
//! | PPC e500         | Freescale e500 (Book-E, SPE)                      |
//! | PPC e6500        | Freescale e6500 (Book-E, Altivec)                 |
//! | PPC64            | 64-bit PowerPC                                    |
//! | PPC64LE          | 64-bit Little Endian                              |
//! | POWER8           | IBM POWER8, VSX/VMX                                |
//! | POWER9           | IBM POWER9                                         |
//! | POWER10          | IBM POWER10                                        |
//!
//! ## Register Model
//!
//! - GPR: GPR0-GPR31 (64-bit in 64-bit mode)
//! - FPR: FPR0-FPR31 (64-bit double)
//! - Special: CR (with CR0-CR7 fields), LR, CTR, XER, MSR
//! - System: SRR0, SRR1, SPRG0-SPRG3, DSISR, DAR, DEC, TB, PVR
//! - VSX: VSR0-VSR63 (128-bit), unified with FPR
//! - VMX/Altivec: VR0-VR31 (128-bit), VSCR, VRSAVE
//! - FPSCR with full status/control bits
//!
//! ## Module Structure
//!
//! - Register definitions with full SPR coverage
//! - MSR and FPSCR bit-field definitions
//! - SPR number constants
//! - Complete instruction mnemonic enumeration (250+ mnemonics)
//! - Processor variant and language definitions
//! - ProcessorModule trait implementation

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;
use std::collections::HashMap;

// ============================================================================
// Processor Name Constants
// ============================================================================

/// Processor family name.
pub const PROCESSOR_NAME: &str = "PowerPC";

/// Processor description.
pub const PROCESSOR_DESCRIPTION: &str =
    "PowerPC 32/64-bit processor family including VMX/Altivec, VSX, VLE, DFP, and EABI";

// ============================================================================
// PowerPC Processor Variants
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PowerPcVariant {
    Ppc601, Ppc603, Ppc604,
    Ppc740, Ppc750,
    Ppc74xx,
    Ppc970,
    Ppc4xx, Ppc440,
    PpcE500, PpcE6500,
    Ppc64, Ppc64LE,
    Power8, Power9, Power10,
}

impl PowerPcVariant {
    pub fn name(&self) -> &'static str {
        match self {
            PowerPcVariant::Ppc601 => "PowerPC 601",
            PowerPcVariant::Ppc603 => "PowerPC 603",
            PowerPcVariant::Ppc604 => "PowerPC 604",
            PowerPcVariant::Ppc740 => "PowerPC 740 (G3)",
            PowerPcVariant::Ppc750 => "PowerPC 750 (G3)",
            PowerPcVariant::Ppc74xx => "PowerPC 74xx (G4)",
            PowerPcVariant::Ppc970 => "PowerPC 970 (G5)",
            PowerPcVariant::Ppc4xx => "PowerPC 4xx",
            PowerPcVariant::Ppc440 => "PowerPC 440",
            PowerPcVariant::PpcE500 => "PowerPC e500",
            PowerPcVariant::PpcE6500 => "PowerPC e6500",
            PowerPcVariant::Ppc64 => "PowerPC 64-bit",
            PowerPcVariant::Ppc64LE => "PowerPC 64-bit LE",
            PowerPcVariant::Power8 => "POWER8",
            PowerPcVariant::Power9 => "POWER9",
            PowerPcVariant::Power10 => "POWER10",
        }
    }

    pub fn is_64bit(&self) -> bool {
        matches!(self, PowerPcVariant::Ppc970 | PowerPcVariant::Ppc64
            | PowerPcVariant::Ppc64LE | PowerPcVariant::Power8
            | PowerPcVariant::Power9 | PowerPcVariant::Power10)
    }

    pub fn has_vmx(&self) -> bool {
        matches!(self, PowerPcVariant::Ppc74xx | PowerPcVariant::Ppc970
            | PowerPcVariant::PpcE6500 | PowerPcVariant::Power8
            | PowerPcVariant::Power9 | PowerPcVariant::Power10)
    }

    pub fn has_vsx(&self) -> bool {
        matches!(self, PowerPcVariant::Power8 | PowerPcVariant::Power9 | PowerPcVariant::Power10)
    }

    pub fn has_dfp(&self) -> bool {
        matches!(self, PowerPcVariant::Power8 | PowerPcVariant::Power9 | PowerPcVariant::Power10)
    }

    pub fn has_spe(&self) -> bool {
        matches!(self, PowerPcVariant::PpcE500)
    }

    pub fn has_vle(&self) -> bool {
        matches!(self, PowerPcVariant::PpcE500 | PowerPcVariant::PpcE6500)
    }
}

impl std::fmt::Display for PowerPcVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Register Offsets
// ============================================================================

const GPR_OFFSET_BASE: u64 = 0x0000;
const FPR_OFFSET_BASE: u64 = 0x0100;
const SPECIAL_OFFSET_BASE: u64 = 0x0200;
const SYSTEM_OFFSET_BASE: u64 = 0x0300;
const VMX_OFFSET_BASE: u64 = 0x0500;
const VSX_OFFSET_BASE: u64 = 0x0600;
const SPE_OFFSET_BASE: u64 = 0x0800;
const SPR_OFFSET_BASE: u64 = 0x0A00;

// ============================================================================
// CR Field Names
// ============================================================================

pub const CR_FIELD_NAMES: [&str; 8] = ["CR0", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7"];

// ============================================================================
// MSR Bit Fields
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum MsrField {
    SF = 0,
    ISF = 1,
    HV = 3,
    PR = 49,
    EE = 48,
    IR = 58,
    DR = 59,
    RI = 62,
    LE = 63,
    FE0 = 52,
    FE1 = 55,
    FP = 50,
    ME = 51,
    DE = 54,
    SE = 53,
    BE = 57,
    IP = 56,
    IR_32 = 4,
    DR_32 = 5,
    PMM = 61,
    VEC = 38,
    VSX = 40,
    WE = 2,
    CE = 7,
    POW = 44,
    ILE_32 = 16,
    EE_32 = 15,
    PR_32 = 14,
    FP_32 = 13,
    ME_32 = 12,
    FE0_32 = 11,
    SE_32 = 6,
    BE_32 = 9,
    FE1_32 = 8,
    IP_32 = 10,
    // IR_32B shares bit 10 with IP_32 in 32-bit mode
    IR_32B = 100,
    // DR_32B shares bit 8 with FE1_32 in 32-bit mode
    DR_32B = 101,
    RI_32 = 19,
    LE_32 = 20,
}

impl MsrField {
    pub fn bit(&self) -> u32 { *self as u32 }
    pub fn mask(&self) -> u64 { 1u64 << (*self as u32) }
    pub fn name(&self) -> &'static str {
        match self {
            MsrField::SF => "SF", MsrField::ISF => "ISF",
            MsrField::HV => "HV", MsrField::PR => "PR",
            MsrField::EE => "EE", MsrField::IR => "IR",
            MsrField::DR => "DR", MsrField::RI => "RI",
            MsrField::LE => "LE", MsrField::FE0 => "FE0",
            MsrField::FE1 => "FE1", MsrField::FP => "FP",
            MsrField::ME => "ME", MsrField::DE => "DE",
            MsrField::SE => "SE", MsrField::BE => "BE",
            MsrField::IP => "IP", MsrField::VEC => "VEC",
            MsrField::VSX => "VSX", MsrField::WE => "WE",
            MsrField::CE => "CE", MsrField::POW => "POW",
            MsrField::PR_32 => "PR", MsrField::EE_32 => "EE",
            MsrField::FP_32 => "FP", MsrField::ME_32 => "ME",
            MsrField::IR_32 => "IR", MsrField::DR_32 => "DR",
            MsrField::PMM => "PMM", MsrField::ILE_32 => "ILE",
            MsrField::FE0_32 => "FE0", MsrField::FE1_32 => "FE1",
            MsrField::SE_32 => "SE", MsrField::BE_32 => "BE",
            MsrField::IP_32 => "IP", MsrField::IR_32B => "IR",
            MsrField::DR_32B => "DR", MsrField::RI_32 => "RI",
            MsrField::LE_32 => "LE",
        }
    }
}

// ============================================================================
// FPSCR Bit Fields
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum FpscrField {
    FX = 31, FEX = 30, VX = 29, OX = 28,
    UX = 27, ZX = 26, XX = 25, VXSNAN = 24,
    VXISI = 23, VXIDI = 22, VXZDZ = 21, VXIMZ = 20,
    VXVC = 19, FR = 18, FI = 17, VXCVI = 16,
    C0 = 15, C1 = 14, C2 = 13, C3 = 12,
    FL = 11, FG = 10, FE = 9, FU = 8,
    VXSOFT = 7, VXSQRT = 6, VXCVI_RN = 5, NI = 3,
    RN0 = 0, RN1 = 1,
}

impl FpscrField {
    pub fn bit(&self) -> u32 { *self as u32 }
    pub fn mask(&self) -> u32 { 1u32 << (*self as u32) }
    pub fn name(&self) -> &'static str {
        match self {
            FpscrField::FX => "FX", FpscrField::FEX => "FEX",
            FpscrField::VX => "VX", FpscrField::OX => "OX",
            FpscrField::UX => "UX", FpscrField::ZX => "ZX",
            FpscrField::XX => "XX", FpscrField::VXSNAN => "VXSNAN",
            FpscrField::VXISI => "VXISI", FpscrField::VXIDI => "VXIDI",
            FpscrField::VXZDZ => "VXZDZ", FpscrField::VXIMZ => "VXIMZ",
            FpscrField::VXVC => "VXVC", FpscrField::FR => "FR",
            FpscrField::FI => "FI", FpscrField::VXCVI => "VXCVI",
            FpscrField::C0 => "C0", FpscrField::C1 => "C1",
            FpscrField::C2 => "C2", FpscrField::C3 => "C3",
            FpscrField::FL => "FL", FpscrField::FG => "FG",
            FpscrField::FE => "FE", FpscrField::FU => "FU",
            FpscrField::VXSOFT => "VXSOFT", FpscrField::VXSQRT => "VXSQRT",
            FpscrField::VXCVI_RN => "VXCVI_RN", FpscrField::NI => "NI",
            FpscrField::RN0 => "RN0", FpscrField::RN1 => "RN1",
        }
    }
}

// ============================================================================
// XER Bit Fields
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XerField {
    SO = 0, OV = 1, CA = 2,
}

impl XerField {
    pub fn bit(&self) -> u32 { *self as u32 }
    pub fn mask(&self) -> u32 { 1u32 << (*self as u32) }
    pub fn name(&self) -> &'static str {
        match self { XerField::SO => "SO", XerField::OV => "OV", XerField::CA => "CA" }
    }
}

// ============================================================================
// CR Bit Fields
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CrField {
    LT = 0, GT = 1, EQ = 2, SO = 3,
}

impl CrField {
    pub fn bit(&self) -> u32 { *self as u32 }
    pub fn name(&self) -> &'static str {
        match self { CrField::LT => "LT", CrField::GT => "GT", CrField::EQ => "EQ", CrField::SO => "SO" }
    }
}

// ============================================================================
// SPR Numbers
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SprNumber {
    XER = 1, LR = 8, CTR = 9,
    DSISR = 18, DAR = 19,
    DEC = 22, SDR1 = 25, SRR0 = 26, SRR1 = 27,
    CFAR = 28, HSPRG0 = 304, HSPRG1 = 305,
    PVR = 287,
    SPRG0 = 272, SPRG1 = 273, SPRG2 = 274, SPRG3 = 275,
    SPRG4 = 276, SPRG5 = 277, SPRG6 = 278, SPRG7 = 279,
    TB = 268, TBU = 269,
    DABR = 1013, DABRX = 1015,
    IABR = 900,
    PMC1 = 769, PMC2 = 770, PMC3 = 771, PMC4 = 772, PMC5 = 773, PMC6 = 774,
    MMCR0 = 779, MMCR1 = 782, MMCR2 = 785,
    SIAR = 796, SDAR = 797, SIER = 798,
    HFSCR = 921,
    DHSCR = 928, // RMOR is also 928 in some contexts
    EBBHR = 837, EBBRR = 838, BESCR = 839,
    TAR = 815,
    LPCR = 813, LPIDR = 814,
    PIDR = 48,
    HFID = 914, HRMOR = 924, RMOR = 997,
    PTCR = 1019, AMR = 29, IAMR = 30,
    UAMOR = 31, DAWR = 916, DAWRX = 917,
    CIABR = 945,
    PPR = 896, PPR32 = 898,
    SPEFSCR = 512,
    IVPR = 63, IVOR0 = 400, IVOR1 = 401, IVOR2 = 402, IVOR3 = 403,
    IVOR4 = 404, IVOR5 = 405, IVOR6 = 406, IVOR7 = 407,
    IVOR8 = 408, IVOR9 = 409, IVOR10 = 410, IVOR11 = 411,
    IVOR12 = 412, IVOR13 = 413, IVOR14 = 414, IVOR15 = 415,
    VRSAVE = 256, VSCR = 257,
    DABR2 = 1018,
    EIE = 80, EID = 81, NRI = 82,
    DBCR = 1010, DBCR0, DBSR = 1008,
    IAC1 = 1012, IAC2 = 999, IAC3 = 1014, IAC4 = 998,
    DAC1 = 1020, DAC2 = 1021,
}

impl SprNumber {
    pub fn number(&self) -> u32 { *self as u32 }
    pub fn name(&self) -> &'static str {
        match self {
            SprNumber::XER => "XER", SprNumber::LR => "LR", SprNumber::CTR => "CTR",
            SprNumber::DSISR => "DSISR", SprNumber::DAR => "DAR",
            SprNumber::DEC => "DEC", SprNumber::SDR1 => "SDR1",
            SprNumber::SRR0 => "SRR0", SprNumber::SRR1 => "SRR1",
            SprNumber::CFAR => "CFAR", SprNumber::PVR => "PVR",
            SprNumber::SPRG0 => "SPRG0", SprNumber::SPRG1 => "SPRG1",
            SprNumber::SPRG2 => "SPRG2", SprNumber::SPRG3 => "SPRG3",
            SprNumber::SPRG4 => "SPRG4", SprNumber::SPRG5 => "SPRG5",
            SprNumber::SPRG6 => "SPRG6", SprNumber::SPRG7 => "SPRG7",
            SprNumber::TB => "TB", SprNumber::TBU => "TBU",
            SprNumber::HSPRG0 => "HSPRG0", SprNumber::HSPRG1 => "HSPRG1",
            SprNumber::DABR => "DABR", SprNumber::IABR => "IABR",
            SprNumber::PMC1 => "PMC1", SprNumber::MMCR0 => "MMCR0",
            SprNumber::SIAR => "SIAR", SprNumber::SDAR => "SDAR",
            SprNumber::HFSCR => "HFSCR", SprNumber::TAR => "TAR",
            SprNumber::LPCR => "LPCR", SprNumber::LPIDR => "LPIDR",
            SprNumber::PIDR => "PIDR", SprNumber::AMR => "AMR",
            SprNumber::VRSAVE => "VRSAVE", SprNumber::VSCR => "VSCR",
            SprNumber::IVPR => "IVPR", SprNumber::IVOR0 => "IVOR0",
            SprNumber::SPEFSCR => "SPEFSCR",
            SprNumber::PPR => "PPR", SprNumber::PPR32 => "PPR32",
            _ => "SPR",
        }
    }
}

// ============================================================================
// PowerPC Register Bank
// ============================================================================

/// The complete register bank for a PowerPC 64-bit processor.
#[derive(Debug, Clone)]
pub struct PowerPcRegisterBank {
    pub gpr: [Register; 32],
    pub fpr: [Register; 32],
    pub cr: Register,
    pub lr: Register,
    pub ctr: Register,
    pub xer: Register,
    pub msr: Register,
    pub pc: Register,
    pub srr0: Register,
    pub srr1: Register,
    pub sprs: HashMap<u32, Register>,
    pub fpscr: Register,
    pub vr: [Register; 32],
    pub vscr: Register,
    pub vrsave: Register,
    pub vsr: [Register; 64],
    pub evr: [Register; 32],
    pub spe_acc: Register,
    pub spefscr: Register,
    pub cr_fields: [Register; 8],
    register_by_name: HashMap<String, Register>,
}

impl PowerPcRegisterBank {
    pub fn new_ppc64() -> Self {
        // GPR0-GPR31 (64-bit)
        let gpr: [Register; 32] = std::array::from_fn(|i| {
            Register::new(&format!("GPR{}", i), 64, GPR_OFFSET_BASE + (i as u64) * 8)
        });

        // FPR0-FPR31 (64-bit)
        let fpr: [Register; 32] = std::array::from_fn(|i| {
            Register::new(&format!("FPR{}", i), 64, FPR_OFFSET_BASE + (i as u64) * 8)
        });

        // Special registers
        let cr = Register::new("CR", 32, SPECIAL_OFFSET_BASE + 0x00);
        let lr = Register::new("LR", 64, SPECIAL_OFFSET_BASE + 0x08);
        let ctr = Register::new("CTR", 64, SPECIAL_OFFSET_BASE + 0x10);
        let xer = Register::new("XER", 64, SPECIAL_OFFSET_BASE + 0x18);
        let msr = Register::new("MSR", 64, SPECIAL_OFFSET_BASE + 0x20);
        let pc = Register::new("PC", 64, SPECIAL_OFFSET_BASE + 0x28);

        // CR fields (sub-registers of CR)
        let cr_fields: [Register; 8] = std::array::from_fn(|i| {
            Register::sub_register(
                CR_FIELD_NAMES[i], 4, SPECIAL_OFFSET_BASE + 0x30 + (i as u64) * 4,
                "CR", (28 - i * 4) as u32,
            )
        });

        // System registers
        let srr0 = Register::new("SRR0", 64, SYSTEM_OFFSET_BASE + 0x00);
        let srr1 = Register::new("SRR1", 64, SYSTEM_OFFSET_BASE + 0x08);
        let ds_isr = Register::new("DSISR", 32, SYSTEM_OFFSET_BASE + 0x10);
        let dar = Register::new("DAR", 64, SYSTEM_OFFSET_BASE + 0x18);
        let dec = Register::new("DEC", 32, SYSTEM_OFFSET_BASE + 0x20);
        let tb = Register::new("TB", 64, SYSTEM_OFFSET_BASE + 0x28);
        let pvr = Register::new("PVR", 32, SYSTEM_OFFSET_BASE + 0x30);

        // SPR map
        let mut sprs: HashMap<u32, Register> = HashMap::new();
        let spr_registers: [(u32, &str, u32); 30] = [
            (1, "SPR_XER", 64), (8, "SPR_LR", 64), (9, "SPR_CTR", 64),
            (18, "SPR_DSISR", 32), (19, "SPR_DAR", 64),
            (22, "SPR_DEC", 32), (26, "SPR_SRR0", 64), (27, "SPR_SRR1", 64),
            (272, "SPR_SPRG0", 64), (273, "SPR_SPRG1", 64),
            (274, "SPR_SPRG2", 64), (275, "SPR_SPRG3", 64),
            (268, "SPR_TB", 64), (269, "SPR_TBU", 32),
            (287, "SPR_PVR", 32), (256, "SPR_VRSAVE", 32), (257, "SPR_VSCR", 32),
            (63, "SPR_IVPR", 64),
            (400, "SPR_IVOR0", 32), (401, "SPR_IVOR1", 32), (402, "SPR_IVOR2", 32),
            (403, "SPR_IVOR3", 32), (404, "SPR_IVOR4", 32), (405, "SPR_IVOR5", 32),
            (406, "SPR_IVOR6", 32), (407, "SPR_IVOR7", 32),
            (408, "SPR_IVOR8", 32), (409, "SPR_IVOR9", 32), (410, "SPR_IVOR10", 32),
            (411, "SPR_IVOR11", 32),
        ];
        for (num, name, bits) in spr_registers.iter() {
            sprs.insert(*num, Register::new(name, *bits, SPR_OFFSET_BASE + (*num as u64) * 8));
        }

        // FPSCR
        let fpscr = Register::new("FPSCR", 32, SYSTEM_OFFSET_BASE + 0x40);

        // VMX/Altivec VR0-VR31 (128-bit)
        let vr: [Register; 32] = std::array::from_fn(|i| {
            Register::new(&format!("VR{}", i), 128, VMX_OFFSET_BASE + (i as u64) * 16)
        });
        let vscr = Register::new("VSCR", 32, VMX_OFFSET_BASE + 0x200);
        let vrsave = Register::new("VRSAVE", 32, VMX_OFFSET_BASE + 0x204);

        // VSX VSR0-VSR63 (128-bit), VSR0..VSR31 overlap FPR0..FPR31
        let vsr: [Register; 64] = std::array::from_fn(|i| {
            Register::new(&format!("VSR{}", i), 128, VSX_OFFSET_BASE + (i as u64) * 16)
        });

        // SPE registers (e500)
        let evr: [Register; 32] = std::array::from_fn(|i| {
            Register::new(&format!("EVR{}", i), 64, SPE_OFFSET_BASE + (i as u64) * 8)
        });
        let spe_acc = Register::new("ACC", 64, SPE_OFFSET_BASE + 0x100);
        let spefscr = Register::new("SPEFSCR", 32, SPE_OFFSET_BASE + 0x108);

        // Build lookup
        let mut register_by_name = HashMap::new();
        for (i, reg) in gpr.iter().enumerate() {
            register_by_name.insert(format!("GPR{}", i), reg.clone());
            register_by_name.insert(format!("R{}", i), reg.clone());
        }
        for (i, reg) in fpr.iter().enumerate() {
            register_by_name.insert(format!("FPR{}", i), reg.clone());
            register_by_name.insert(format!("F{}", i), reg.clone());
        }
        register_by_name.insert("CR".to_string(), cr.clone());
        register_by_name.insert("LR".to_string(), lr.clone());
        register_by_name.insert("CTR".to_string(), ctr.clone());
        register_by_name.insert("XER".to_string(), xer.clone());
        register_by_name.insert("MSR".to_string(), msr.clone());
        register_by_name.insert("PC".to_string(), pc.clone());
        register_by_name.insert("SRR0".to_string(), srr0.clone());
        register_by_name.insert("SRR1".to_string(), srr1.clone());
        register_by_name.insert("DSISR".to_string(), ds_isr.clone());
        register_by_name.insert("DAR".to_string(), dar.clone());
        register_by_name.insert("DEC".to_string(), dec.clone());
        register_by_name.insert("TB".to_string(), tb.clone());
        register_by_name.insert("PVR".to_string(), pvr.clone());
        register_by_name.insert("FPSCR".to_string(), fpscr.clone());

        for field in &cr_fields {
            register_by_name.insert(field.name.clone(), field.clone());
        }

        for (num, reg) in &sprs {
            register_by_name.insert(format!("SPR{}", num), reg.clone());
        }

        for (i, reg) in vr.iter().enumerate() {
            register_by_name.insert(format!("VR{}", i), reg.clone());
        }
        register_by_name.insert("VSCR".to_string(), vscr.clone());
        register_by_name.insert("VRSAVE".to_string(), vrsave.clone());

        for (i, reg) in vsr.iter().enumerate() {
            register_by_name.insert(format!("VSR{}", i), reg.clone());
        }

        for (i, reg) in evr.iter().enumerate() {
            register_by_name.insert(format!("EVR{}", i), reg.clone());
        }
        register_by_name.insert("ACC".to_string(), spe_acc.clone());
        register_by_name.insert("SPEFSCR".to_string(), spefscr.clone());

        PowerPcRegisterBank {
            gpr, fpr, cr, lr, ctr, xer, msr, pc,
            srr0, srr1, sprs, fpscr,
            vr, vscr, vrsave, vsr,
            evr, spe_acc, spefscr, cr_fields,
            register_by_name,
        }
    }

    pub fn get(&self, name: &str) -> Option<&Register> { self.register_by_name.get(name) }
    pub fn len(&self) -> usize { self.register_by_name.len() }
    pub fn is_empty(&self) -> bool { self.register_by_name.is_empty() }
    pub fn iter(&self) -> impl Iterator<Item = &Register> { self.register_by_name.values() }
    pub fn spr(&self, num: u32) -> Option<&Register> { self.sprs.get(&num) }
}

impl Default for PowerPcRegisterBank {
    fn default() -> Self { Self::new_ppc64() }
}

// ============================================================================
// PowerPC Instruction Mnemonic
// ============================================================================

/// Complete PowerPC instruction mnemonic enumeration (250+ mnemonics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum PowerPcMnemonic {
    // ------------------------------------------------------------------
    // Integer Arithmetic
    // ------------------------------------------------------------------
    ADD, ADDC, ADDE, ADDI, ADDIC, ADDIC_DOT, ADDIS, ADDME, ADDZE,
    ADDO, ADDCO, ADDEO, ADDMEO, ADDZEO,
    SUBF, SUBFC, SUBFE, SUBFIC, SUBFME, SUBFZE,
    SUBFO, SUBFCO, SUBFEO, SUBFMEO, SUBFZEO,
    MULLI, MULLW, MULHW, MULHWU, MULHD, MULHDU,
    DIVW, DIVWU, DIVD, DIVDU, DIVWE, DIVWEU, DIVDE, DIVDEU,
    NEG, NEGO,
    EXTSB, EXTSH, EXTSW,
    CNTLZW, CNTLZD, CNTTZW, CNTTZD,
    POPCNTB, POPCNTW, POPCNTD,
    CMPB, PRTYD, BPERMD,
    MODSW, MODUW, MODSD, MODUD,

    // ------------------------------------------------------------------
    // Logical
    // ------------------------------------------------------------------
    AND, ANDC, ANDI_DOT, ANDIS_DOT,
    OR, ORC, ORI, ORIS,
    XOR, XORI, XORIS,
    NAND, NOR, EQV,
    EXTSWSLI,
    SETB,

    // ------------------------------------------------------------------
    // Shift / Rotate
    // ------------------------------------------------------------------
    SLW, SRW, SRAW, SRAWI,
    SLD, SRD, SRAD, SRADI,
    RLDCL, RLDCR, RLDIC, RLDICL, RLDICR, RLDIMI,
    RLWIMI, RLWINM, RLWNM,
    ROTLW, ROTLWI, ROTRW, ROTRWI,
    ROTLD, ROTLDI, ROTRD, ROTRDI,

    // ------------------------------------------------------------------
    // Compare
    // ------------------------------------------------------------------
    CMP, CMPI, CMPL, CMPLI,
    CMPW, CMPWI, CMPLW, CMPLWI,
    CMPD, CMPDI, CMPLD, CMPLDI,
    CMPB_2,

    // ------------------------------------------------------------------
    // Branch
    // ------------------------------------------------------------------
    B, BA, BL, BLA,
    BC, BCA, BCL, BCLA,
    BCCTR, BCCTRL,
    BCLR, BCLRL,
    BCTR, BCTRL, BLR, BLRL,
    BT, BF, BTA, BFA,
    BDNZ, BDZ, BDNZT, BDZT, BDNZF, BDZF,
    BDNZL, BDZL, BDNZTL, BDZTL, BDNZFL, BDZFL,
    BDNZLR, BDZLR, BDNZTLR, BDZTLR, BDNZFLR, BDZFLR,

    // ------------------------------------------------------------------
    // Condition Register Logical
    // ------------------------------------------------------------------
    CRAND, CRANDC, CREQV, CRNAND, CRNOR, CROR, CRORC, CRXOR,
    MCRF, MCRXR, MCRFS,
    MFCR, MTCRF,
    MFOCRF, MTOCRF,

    // ------------------------------------------------------------------
    // Trap
    // ------------------------------------------------------------------
    TW, TWI, TD, TDI,
    TWLT, TWGT, TWEQ, TWLLT, TWLGT, TWLEQ,
    TWLNL, TWLNG, TWNE, TWLTI, TWGTI, TWEQI,
    TDLT, TDGT, TDEQ, TDLLT, TDLGT, TDLEQ,
    TDLNL, TDLNG, TDNE, TDLTI, TDGTI, TDEQI,

    // ------------------------------------------------------------------
    // Load / Store (Integer)
    // ------------------------------------------------------------------
    LBZ, LBZU, LBZX, LBZUX,
    LHZ, LHZU, LHZX, LHZUX,
    LHA, LHAU, LHAX, LHAUX,
    LWZ, LWZU, LWZX, LWZUX,
    LWA, LWAX, LWAUX,
    LD, LDU, LDX, LDUX,
    LMW,
    STB, STBU, STBX, STBUX,
    STH, STHU, STHX, STHUX,
    STW, STWU, STWX, STWUX,
    STD, STDU, STDX, STDUX,
    STMW,
    LDBRX, LWBRX, LHBRX,
    STDBRX, STWBRX, STHBRX,

    // ------------------------------------------------------------------
    // Load / Store (Multiple / String)
    // ------------------------------------------------------------------
    LSWI, LSWX, STSWI, STSWX,

    // ------------------------------------------------------------------
    // Load / Store with Reservation
    // ------------------------------------------------------------------
    LWARX, LDARX,
    STWCX_DOT, STDCX_DOT,
    LWAT, LDAT, STWAT, STDAT,

    // ------------------------------------------------------------------
    // Fixed-Point Move Assist
    // ------------------------------------------------------------------
    MCRXRX,

    // ------------------------------------------------------------------
    // System
    // ------------------------------------------------------------------
    MFSPR, MTSPR,
    MFMSR, MTMSR, MFPVR,
    MFTB, MFTBU,
    MFSR, MTSR,
    MFSRIN, MTSRIN,
    MTCRF_SYS,
    MTOCRF_SYS, MFOCRF_SYS,

    ISYNC, MSYNC, ICS, ICS_E,
    DCB, DCBF, DCBI, DCBST, DCBT, DCBTST, DCBZ, DCBZL,
    DCBA, DCBL, DCBZEP, DCBZL_2,
    ICBI, ICBT, ICBL,
    SYNC, LWSYNC, PTESYNC,
    EIEIO, HWSYNC,
    TLBIE, TLBIEL, TLBSYNC, TLBIA, TLBIVAX, TLBLD, TLBLI,
    SLBIE, SLBIEG, SLBIA, SLBMFE, SLBMTE, SLBSYNC,
    RFI, RFSCV, RFCI, RFMCI,
    HRFID,
    SC, SVC,
    NOP, ORI_NOP,
    ATTN, STOP,

    // ------------------------------------------------------------------
    // Floating-Point (FPU)
    // ------------------------------------------------------------------
    // Arithmetic
    FADD, FADDS, FSUB, FSUBS, FMUL, FMULS, FDIV, FDIVS,
    FMADD, FMADDS, FMSUB, FMSUBS,
    FNMADD, FNMADDS, FNMSUB, FNMSUBS,
    FSQRT, FSQRTS, FRE, FRES, FRSQRTE, FRSQRTES,
    FSEL, FSELS,
    // Move
    FMOV, FMOVS, FMR, FCP,
    FABS, FABSS, FNABS, FNABSS, FNEG, FNEGS,
    FCPSGN, FCPSGNS,
    // Compare
    FCMP, FCMPU, FCMPO, FCMPS,
    // Conversion
    FCTIW, FCTIWZ, FCTID, FCTIDZ,
    FCFID, FCFIDS, FCFIDU, FCFIDUS,
    FCTIWU, FCTIWUZ, FCTIDU, FCTIDUZ,
    FRSP, FRIN, FRIZ, FRIP, FRIM,
    // Status / Control
    MFFS, MTFSF, MTFSFI, MTFSB1, MTFSB0,
    MFFSCE, MFFSCRN, MFFSCRNI, MFFSL,
    // Floating-Point Record forms
    FADD_DOT, FSUB_DOT, FMUL_DOT, FDIV_DOT,
    FADDS_DOT, FSUBS_DOT, FMULS_DOT, FDIVS_DOT,
    FMADD_DOT, FMSUB_DOT, FNMADD_DOT, FNMSUB_DOT,
    FMADDS_DOT, FMSUBS_DOT, FNMADDS_DOT, FNMSUBS_DOT,
    FSQRT_DOT, FSQRTS_DOT, FRE_DOT, FRES_DOT, FRSQRTE_DOT, FRSQRTES_DOT,
    FMR_DOT, FNEG_DOT, FABS_DOT, FNABS_DOT,
    // FIF / FTF / FTW
    FRIN_DOT, FRIZ_DOT, FRIP_DOT, FRIM_DOT,

    // ------------------------------------------------------------------
    // VMX / Altivec
    // ------------------------------------------------------------------
    // Integer
    VADDU, VADDS, VADD,
    VSUB, VSUBS,
    VMUL,
    VAVG, VABS,
    VMAX, VMIN,
    VAND, VANDC, VOR, VORC, VXOR, VNOR, VNAND,
    VEQV,
    VRLB, VRLH, VRLW, VRLD,
    VSLB, VSLH, VSLW, VSLD,
    VSRB, VSRH, VSRW, VSRD,
    VSRAB, VSRAH, VSRAW, VSRAD,
    // Compare
    VCMPEQ, VCMPGT, VCMPLT, VCMPNE,
    VCMPGTU, VCMPLTU,
    VCMPBFP,
    // Logical
    VSEL,
    VPERM, VPERMXOR, VPERMI,
    VMRGHB, VMRGHH, VMRGHW, VMRGLB, VMRGLH, VMRGLW,
    VSPLTB, VSPLTH, VSPLTW, VSPLTISB, VSPLTISH, VSPLTISW,
    VPKSH, VPKSW, VPKSD,
    VPKUH, VPKUW, VPKUD,
    VPKSHS, VPKSWS,
    VPKUHUS, VPKUWUS, VPKUDUS,
    VUPKHSB, VUPKHSH, VUPKHSW,
    VUPKLSB, VUPKLSH, VUPKLSW,
    VUPKHPX, VUPKLPX,
    VMHADDSHS, VMHRADDSHS, VMLADDUHM,
    VMSUM, VMSUMS,
    VMHADDSHS_V2,
    VSUMSWS, VSUM2SWS, VSUM4SBS, VSUM4SHS, VSUM4UBS,
    VADDCUW, VADDFP, VSUBFP,
    VMADDFP, VNMSUBFP,
    VREFP, VRSQRTEFP, VEXPTEFP, VLOGEFP,
    VRFIN, VRFIZ, VRFIP, VRFIM,
    VCFUX, VCFSX, VCTUXS, VCTSXS,
    VCMPBFP_DOT, VCMPEQFP_DOT, VCMPGEFP_DOT, VCMPGTFP_DOT,
    VCMPNEB_DOT, VCMPNEH_DOT, VCMPNEW_DOT,
    VCMPNEZB_DOT, VCMPNEZH_DOT, VCMPNEZW_DOT,
    VCMPEQUB_DOT, VCMPEQUH_DOT, VCMPEQUW_DOT,
    VCMPGTSB_DOT, VCMPGTSH_DOT, VCMPGTSW_DOT,
    VCMPGTUB_DOT, VCMPGTUH_DOT, VCMPGTUW_DOT,
    // Vector Load / Store
    LV, LVR,
    LVX, LVXL, LVE, LVEL,
    LVSL, LVSR, LVEBX, LVEHX, LVEWX,
    LVLX, LVRX, LVLXL, LVRXL,
    STV, STVX, STVXL, STVEBX, STVEHX, STVEWX,
    STVLX, STVRX, STVLXL, STVRXL,
    // Vector Element
    VEXT, VINS,
    // Vector Shift
    VSLDOI, VSL, VSR, VSRO, VSLO,
    // Vector bit counting
    VPOPCNTB, VPOPCNTH, VPOPCNTW, VPOPCNTD,
    VCLZ, VCLZB, VCLZH, VCLZW, VCLZD,
    VCTZ, VCTZB, VCTZH, VCTZW, VCTZD,
    // Vector gather
    VGBBD,
    // Vector crypto
    VCIPHER, VCIPHERLAST, VNCIPHER, VNCIPHERLAST,
    VSBOX, VSHASIGMA,
    // Vector BCD
    VBCDADD, VBCDSUB, VBCDMUL, VBCDDIV,
    // Vector mask
    VEXTSB2, VEXTSH2, VEXTSW2,
    VEXPANDBM, VEXPANDHM, VEXPANDWM, VEXPANDDM, VEXPANDQM,
    VEXTRACTBM, VEXTRACTHM, VEXTRACTWM, VEXTRACTDM, VEXTRACTQM,
    VMTVTB, VMTVTH, VMTVTW, VMTVTD,
    VCNTMBB, VCNTMBH, VCNTMBW, VCNTMBD,
    VCFUGED, VCLRLB, VCLRRB, VGNB,
    VPDEPD, VPEXTD,
    VMOD, VREMB, VREMH, VREMW, VREMD,

    // ------------------------------------------------------------------
    // VSX
    // ------------------------------------------------------------------
    // Data transfer
    LX, LXS, LXV,
    STX, STXS, STXV,
    LXSDX, LXSIWAX, LXSIWZX, LXSSPX,
    LXVD2X, LXVW4X, LXVH8X, LXVB16X,
    LXVDSX, LXVWSX,
    STXSDX, STXSIWX, STXSSPX,
    STXVD2X, STXVW4X, STXVH8X, STXVB16X,
    LXVKQ, LXVP, STXVP,
    LXVL, LXVLL, STXVL, STXVLL,
    // Scalar arithmetic
    XSADD, XSSUB, XSMUL, XSDIV,
    XSMADD, XSMSUB, XSNMADD, XSNMSUB,
    XSSQRT, XSABS, XSNABS, XSNEG, XSCPSGN,
    XSCMP, XSMAX, XSMIN,
    XSRDPI, XSRDPIC, XSRDPIM, XSRDPIP, XSRDPIZ,
    XSREDP, XSRSQRTEDP,
    XSCV, XSCVSXDDP, XSCVUXDDP, XSCVDPSXDS, XSCVDPUXDS,
    XSCVDPSP, XSCVSPDP, XSCVDPSPN, XSCVSPDPN,
    XSROUND,
    XSTDIVDP, XSTSQRTDP,
    XSTRUNC,
    // Vector
    XVADD, XVSUB, XVMUL, XVDIV,
    XVMADD, XVMSUB, XVNMADD, XVNMSUB,
    XVSQRT, XVABS, XVNABS, XVNEG, XVCPSGN,
    XVCMP, XVMAX, XVMIN,
    XVRDPI, XVRDPIC, XVRDPIM, XVRDPIP, XVRDPIZ,
    XVREDP, XVRSQRTEDP,
    XVCV, XVCVSXDDP, XVCVUXDDP, XVCVDPSXDS, XVCVDPUXDS,
    XVCVDPSP, XVCVSPDP,
    // VSX Move / Merge / Splat / Permute
    MFVSRD, MFVSRLD, MFVSRWZ, MTMSR_VSX,
    MTVSRD, MTVSRWA, MTVSRWZ, MTVSRDD, MTVSRWS,
    XXMRGHW, XXMRGLW, XXMRGHD, XXMRGLD,
    XXSPLTW, XXSPLTIB, XXSPLTID, XXSPLTIW,
    XXPERM, XXPERMR, XXPERMDI,
    XXSEL,
    XXLAND, XXLANDC, XXLOR, XXLORC, XXLXOR, XXLNAND, XXLNOR, XXLEQV,


    // ------------------------------------------------------------------
    // Decimal Floating Point (DFP)
    // ------------------------------------------------------------------
    DADD, DSUB, DMUL, DDIV,
    DMADD, DMSUB,
    DCMPU, DCMO, DTSTDC, DTSTDG, DTSTEX, DTSTEX_,
    DQUA, DQUAI, DRRND, DRINTX, DRINTN,
    DRINTX_DOT, DRINTN_DOT,
    DCTDP, DCTFIX, DCTFIXQ, DCFFIX, DCFFIXQ,
    DRSP, DRDPQ, DCTQPQ, DDEDPD, DENBCD, DXEX, DIEX,
    DSCLI, DSCRI,
    DMUL_DFP, DADD_DFP, DSUB_DFP, DDIV_DFP,

    // ------------------------------------------------------------------
    // VLE (Variable Length Encoding)
    // ------------------------------------------------------------------
    // 16-bit arithmetic
    SE_ADDI, SE_ADD, SE_SUB, SE_SUBF,
    SE_MULLW,
    SE_AND, SE_OR, SE_XOR, SE_NOR,
    SE_SLWI, SE_SRWI, SE_SRAWI,
    SE_CMPLI, SE_CMPI, SE_CMP,
    SE_CMPL, SE_CM,
    // 16-bit branches
    SE_B, SE_BC, SE_BL, SE_BT, SE_BF,
    SE_BDNZ, SE_BDZ,
    // 16-bit loads
    SE_LBZ, SE_LHZ, SE_LHA, SE_LWZ,
    SE_STB, SE_STH, SE_STW,
    SE_LWZU, SE_STWU,
    // 32-bit extensions
    E_ADD, E_SUBF, E_MULL, E_AND, E_OR, E_XOR, E_NOR,
    E_ADDI, E_ADDI_DOT,
    E_ORI, E_ORIS,
    E_LBZ, E_LHZ, E_LHA, E_LWZ, E_LD,
    E_STB, E_STH, E_STW, E_STD,
    E_RLWIMI, E_RLWINM,
    E_CMPLI, E_CMPI,
    E_B, E_BL, E_BC, E_BCL,
    E_MTSPR, E_MFSPR, E_MTCRF, E_MFCR,
    E_ISYNC, E_SYNC, E_SC, E_NOP,
    // VLE multiple
    E_LMW, E_STMW,
    E_MFMSR, E_MTMSR,
    E_RFI,

    // ------------------------------------------------------------------
    // EABI / Embedded
    // ------------------------------------------------------------------
    // SPE (Signal Processing Engine)
    EVADD, EVSUB, EVMUL, EVABS, EVNEG,
    EVCMPEQ, EVCMPGT, EVCMPLT,
    EVMERGEHI, EVMERGELO, EVMERGELOHI,
    EVSPLATFI, EVSPLATI,
    EVSLH, EVSRH, EVSH,
    EVCNTLSW, EVCNTLZW,
    EVFSADD, EVFSSUB, EVFSMUL, EVFSABS, EVFSNEG,
    EVCMP, EVFCMPEQ, EVFCMPGT, EVFCMPLT,
    EVSEL,
    EVLD, EVST,
    EVLDD, EVSTD,
    EVLDDX, EVSTDX, EVLDHX, EVSTHX, EVLDWX, EVSTWX,
    BRINC,
    // WAIT / DOZE / NAP / SLEEP
    WAIT,
    DOZE, NAP, SLEEP, RVWINKLE,
    DCCCI, ICCCI,

    // ------------------------------------------------------------------
    // Misc system / virtualization
    // ------------------------------------------------------------------
    TLBIL,
    PTE_SYNC,
    // Power ISA 3.0+
    MSGSND, MSGSNDP, MSGCLR,
    MSGSYNC,
    // Copy/Paste
    CP_ABORT, CP_COPY, CP_PASTE,
    // Transactional Memory
    TBEGIN, TBEGIN_DOT, TEND, TEND_DOT,
    TABORT, TABORTWC_DOT, TABORTWCI_DOT, TABORTDC_DOT, TABORTDCI_DOT,
    TCHECK, TSR,
    TRECLAIM, TRECHKPT,
    TSUSPEND, TRESUME,
    // BHRB
    MFSIAR, MFBHRBE,
    // Misc Power
    CCTPL, CCTPM, DB8, DCBZ_L,
    DCI,
    MCRX,
    TLBSRX,
    DARN, UD, UDE, TRAP,
    // Power ISA 3.1
    BRD, BRW, BRH,
    SETBC, SETNBC,
    CFUGED, CNTLZDM, CNTTZDM, PDEPD, PEXTD,
    VCLZDM, VCTZDM,
    XXGENPCV, XXEVAL,
    XVBF16GER, XVBF16GER2,
    PMXVI4GER8, PMXVBF16GER2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PowerPcInstructionCategory {
    Integer, Logical, ShiftRotate, Compare, Branch, ConditionReg,
    Trap, LoadStore, System, Fpu, Vmx, Vsx, Dfp, Vle, Spe, Misc,
}

impl PowerPcMnemonic {
    pub fn as_str(&self) -> &'static str {
        use PowerPcMnemonic::*;
        match self {
            ADD => "ADD", ADDC => "ADDC", ADDE => "ADDE", ADDI => "ADDI",
            ADDIC => "ADDIC", ADDIC_DOT => "ADDIC.", ADDIS => "ADDIS",
            ADDME => "ADDME", ADDZE => "ADDZE",
            ADDO => "ADDO", ADDCO => "ADDCO", ADDEO => "ADDEO",
            ADDMEO => "ADDMEO", ADDZEO => "ADDZEO",
            SUBF => "SUBF", SUBFC => "SUBFC", SUBFE => "SUBFE",
            SUBFIC => "SUBFIC", SUBFME => "SUBFME", SUBFZE => "SUBFZE",
            SUBFO => "SUBFO", SUBFCO => "SUBFCO", SUBFEO => "SUBFEO",
            SUBFMEO => "SUBFMEO", SUBFZEO => "SUBFZEO",
            MULLI => "MULLI", MULLW => "MULLW",
            MULHW => "MULHW", MULHWU => "MULHWU", MULHD => "MULHD", MULHDU => "MULHDU",
            DIVW => "DIVW", DIVWU => "DIVWU", DIVD => "DIVD", DIVDU => "DIVDU",
            DIVWE => "DIVWE", DIVWEU => "DIVWEU", DIVDE => "DIVDE", DIVDEU => "DIVDEU",
            NEG => "NEG", NEGO => "NEGO",
            EXTSB => "EXTSB", EXTSH => "EXTSH", EXTSW => "EXTSW",
            CNTLZW => "CNTLZW", CNTLZD => "CNTLZD", CNTTZW => "CNTTZW", CNTTZD => "CNTTZD",
            POPCNTB => "POPCNTB", POPCNTW => "POPCNTW", POPCNTD => "POPCNTD",
            CMPB => "CMPB", PRTYD => "PRTYD", BPERMD => "BPERMD",
            MODSW => "MODSW", MODUW => "MODUW", MODSD => "MODSD", MODUD => "MODUD",
            AND => "AND", ANDC => "ANDC", ANDI_DOT => "ANDI.", ANDIS_DOT => "ANDIS.",
            OR => "OR", ORC => "ORC", ORI => "ORI", ORIS => "ORIS",
            XOR => "XOR", XORI => "XORI", XORIS => "XORIS",
            NAND => "NAND", NOR => "NOR", EQV => "EQV",
            EXTSWSLI => "EXTSWSLI", SETB => "SETB",
            SLW => "SLW", SRW => "SRW", SRAW => "SRAW", SRAWI => "SRAWI",
            SLD => "SLD", SRD => "SRD", SRAD => "SRAD", SRADI => "SRADI",
            RLDCL => "RLDCL", RLDCR => "RLDCR",
            RLDIC => "RLDIC", RLDICL => "RLDICL", RLDICR => "RLDICR", RLDIMI => "RLDIMI",
            RLWIMI => "RLWIMI", RLWINM => "RLWINM", RLWNM => "RLWNM",
            CMP => "CMP", CMPI => "CMPI", CMPL => "CMPL", CMPLI => "CMPLI",
            CMPW => "CMPW", CMPWI => "CMPWI", CMPLW => "CMPLW", CMPLWI => "CMPLWI",
            CMPD => "CMPD", CMPDI => "CMPDI", CMPLD => "CMPLD", CMPLDI => "CMPLDI",
            CMPB_2 => "CMPB",
            B => "B", BA => "BA", BL => "BL", BLA => "BLA",
            BC => "BC", BCA => "BCA", BCL => "BCL", BCLA => "BCLA",
            BCCTR => "BCCTR", BCCTRL => "BCCTRL",
            BCLR => "BCLR", BCLRL => "BCLRL",
            BCTR => "BCTR", BCTRL => "BCTRL", BLR => "BLR", BLRL => "BLRL",
            BT => "BT", BF => "BF", BTA => "BTA", BFA => "BFA",
            BDNZ => "BDNZ", BDZ => "BDZ",
            BDNZT => "BDNZT", BDZT => "BDZT", BDNZF => "BDNZF", BDZF => "BDZF",
            BDNZL => "BDNZL", BDZL => "BDZL",
            BDNZLR => "BDNZLR", BDZLR => "BDZLR",
            CRAND => "CRAND", CRANDC => "CRANDC", CREQV => "CREQV",
            CRNAND => "CRNAND", CRNOR => "CRNOR", CROR => "CROR",
            CRORC => "CRORC", CRXOR => "CRXOR",
            MCRF => "MCRF", MCRXR => "MCRXR", MCRFS => "MCRFS",
            MFCR => "MFCR", MTCRF => "MTCRF",
            MFOCRF => "MFOCRF", MTOCRF => "MTOCRF",
            TW => "TW", TWI => "TWI", TD => "TD", TDI => "TDI",
            TWLT => "TWLT", TWGT => "TWGT", TWEQ => "TWEQ",
            TDLT => "TDLT", TDGT => "TDGT", TDEQ => "TDEQ",
            LBZ => "LBZ", LBZU => "LBZU", LBZX => "LBZX", LBZUX => "LBZUX",
            LHZ => "LHZ", LHZU => "LHZU", LHZX => "LHZX", LHZUX => "LHZUX",
            LHA => "LHA", LHAU => "LHAU", LHAX => "LHAX", LHAUX => "LHAUX",
            LWZ => "LWZ", LWZU => "LWZU", LWZX => "LWZX", LWZUX => "LWZUX",
            LWA => "LWA", LWAX => "LWAX", LWAUX => "LWAUX",
            LD => "LD", LDU => "LDU", LDX => "LDX", LDUX => "LDUX",
            LMW => "LMW",
            STB => "STB", STBU => "STBU", STBX => "STBX", STBUX => "STBUX",
            STH => "STH", STHU => "STHU", STHX => "STHX", STHUX => "STHUX",
            STW => "STW", STWU => "STWU", STWX => "STWX", STWUX => "STWUX",
            STD => "STD", STDU => "STDU", STDX => "STDX", STDUX => "STDUX",
            STMW => "STMW",
            LSWI => "LSWI", LSWX => "LSWX", STSWI => "STSWI", STSWX => "STSWX",
            LWARX => "LWARX", LDARX => "LDARX",
            STWCX_DOT => "STWCX.", STDCX_DOT => "STDCX.",
            MFSPR => "MFSPR", MTSPR => "MTSPR",
            MFMSR => "MFMSR", MTMSR => "MTMSR", MFPVR => "MFPVR",
            MFTB => "MFTB", MFTBU => "MFTBU",
            MFSR => "MFSR", MTSR => "MTSR",
            MFSRIN => "MFSRIN", MTSRIN => "MTSRIN",
            ISYNC => "ISYNC", MSYNC => "MSYNC",
            SYNC => "SYNC", LWSYNC => "LWSYNC", PTESYNC => "PTESYNC",
            EIEIO => "EIEIO",
            DCB => "DCB", DCBF => "DCBF", DCBI => "DCBI", DCBST => "DCBST",
            DCBT => "DCBT", DCBTST => "DCBTST", DCBZ => "DCBZ",
            ICBI => "ICBI", ICBT => "ICBT",
            TLBIE => "TLBIE", TLBIEL => "TLBIEL", TLBIA => "TLBIA",
            TLBSYNC => "TLBSYNC",
            SLBIE => "SLBIE", SLBIA => "SLBIA", SLBSYNC => "SLBSYNC",
            RFI => "RFI", RFSCV => "RFSCV", RFCI => "RFCI", RFMCI => "RFMCI",
            HRFID => "HRFID",
            SC => "SC", SVC => "SVC",
            NOP => "NOP", ORI_NOP => "ORI",
            ATTN => "ATTN", STOP => "STOP",
            FADD => "FADD", FADDS => "FADDS", FSUB => "FSUB", FSUBS => "FSUBS",
            FMUL => "FMUL", FMULS => "FMULS", FDIV => "FDIV", FDIVS => "FDIVS",
            FMADD => "FMADD", FMADDS => "FMADDS",
            FMSUB => "FMSUB", FMSUBS => "FMSUBS",
            FNMADD => "FNMADD", FNMADDS => "FNMADDS",
            FNMSUB => "FNMSUB", FNMSUBS => "FNMSUBS",
            FSQRT => "FSQRT", FSQRTS => "FSQRTS",
            FRE => "FRE", FRES => "FRES",
            FRSQRTE => "FRSQRTE", FRSQRTES => "FRSQRTES",
            FSEL => "FSEL", FSELS => "FSELS",
            FMOV => "FMOV", FMOVS => "FMOVS", FMR => "FMR", FCP => "FCP",
            FABS => "FABS", FABSS => "FABSS", FNABS => "FNABS", FNABSS => "FNABSS",
            FNEG => "FNEG", FNEGS => "FNEGS",
            FCPSGN => "FCPSGN", FCPSGNS => "FCPSGNS",
            FCMP => "FCMP", FCMPU => "FCMPU", FCMPO => "FCMPO", FCMPS => "FCMPS",
            FCTIW => "FCTIW", FCTIWZ => "FCTIWZ", FCTID => "FCTID", FCTIDZ => "FCTIDZ",
            FCFID => "FCFID", FCFIDS => "FCFIDS", FCFIDU => "FCFIDU", FCFIDUS => "FCFIDUS",
            FCTIWU => "FCTIWU", FCTIWUZ => "FCTIWUZ",
            FCTIDU => "FCTIDU", FCTIDUZ => "FCTIDUZ",
            FRSP => "FRSP", FRIN => "FRIN", FRIZ => "FRIZ", FRIP => "FRIP", FRIM => "FRIM",
            MFFS => "MFFS", MTFSF => "MTFSF", MTFSFI => "MTFSFI",
            MTFSB1 => "MTFSB1", MTFSB0 => "MTFSB0",
            MFFSCE => "MFFSCE", MFFSCRN => "MFFSCRN", MFFSCRNI => "MFFSCRNI",
            MFFSL => "MFFSL",
            FADD_DOT => "FADD.", FSUB_DOT => "FSUB.",
            FMUL_DOT => "FMUL.", FDIV_DOT => "FDIV.",
            FMADD_DOT => "FMADD.", FMSUB_DOT => "FMSUB.",
            VADDU => "VADDU", VADDS => "VADDS", VADD => "VADD",
            VSUB => "VSUB", VSUBS => "VSUBS",
            VMUL => "VMUL",
            VAVG => "VAVG", VABS => "VABS",
            VMAX => "VMAX", VMIN => "VMIN",
            VAND => "VAND", VANDC => "VANDC", VOR => "VOR", VORC => "VORC",
            VXOR => "VXOR", VNOR => "VNOR", VNAND => "VNAND",
            VEQV => "VEQV",
            VSEL => "VSEL",
            VPERM => "VPERM", VPERMXOR => "VPERMXOR",
            VSLO => "VSLO", VSRO => "VSRO",
            VSL => "VSL", VSR => "VSR",
            VRLB => "VRLB", VRLH => "VRLH", VRLW => "VRLW", VRLD => "VRLD",
            VSLB => "VSLB", VSLH => "VSLH", VSLW => "VSLW", VSLD => "VSLD",
            VSRB => "VSRB", VSRH => "VSRH", VSRW => "VSRW", VSRD => "VSRD",
            VSRAB => "VSRAB", VSRAH => "VSRAH", VSRAW => "VSRAW", VSRAD => "VSRAD",
            VCMPEQ => "VCMPEQ", VCMPGT => "VCMPGT",
            VCMPLT => "VCMPLT", VCMPNE => "VCMPNE",
            VCMPGTU => "VCMPGTU", VCMPLTU => "VCMPLTU",
            VCMPBFP => "VCMPBFP",
            VMRGHB => "VMRGHB", VMRGHH => "VMRGHH", VMRGHW => "VMRGHW",
            VMRGLB => "VMRGLB", VMRGLH => "VMRGLH", VMRGLW => "VMRGLW",
            VSPLTB => "VSPLTB", VSPLTH => "VSPLTH", VSPLTW => "VSPLTW",
            VSPLTISB => "VSPLTISB", VSPLTISH => "VSPLTISH", VSPLTISW => "VSPLTISW",
            VPKSH => "VPKSH", VPKSW => "VPKSW", VPKSD => "VPKSD",
            VPKUH => "VPKUH", VPKUW => "VPKUW", VPKUD => "VPKUD",
            VUPKHSB => "VUPKHSB", VUPKHSH => "VUPKHSH", VUPKHSW => "VUPKHSW",
            VUPKLSB => "VUPKLSB", VUPKLSH => "VUPKLSH", VUPKLSW => "VUPKLSW",
            VSUMSWS => "VSUMSWS", VSUM2SWS => "VSUM2SWS",
            VSUM4SBS => "VSUM4SBS", VSUM4SHS => "VSUM4SHS",
            VADDCUW => "VADDCUW", VADDFP => "VADDFP", VSUBFP => "VSUBFP",
            VMADDFP => "VMADDFP", VNMSUBFP => "VNMSUBFP",
            VREFP => "VREFP", VRSQRTEFP => "VRSQRTEFP",
            VEXPTEFP => "VEXPTEFP", VLOGEFP => "VLOGEFP",
            VRFIN => "VRFIN", VRFIZ => "VRFIZ", VRFIP => "VRFIP", VRFIM => "VRFIM",
            VCFUX => "VCFUX", VCFSX => "VCFSX", VCTUXS => "VCTUXS", VCTSXS => "VCTSXS",
            LV => "LV", LVR => "LVR",
            LVX => "LVX", LVXL => "LVXL", LVE => "LVE", LVEL => "LVEL",
            LVSL => "LVSL", LVSR => "LVSR",
            LVEBX => "LVEBX", LVEHX => "LVEHX", LVEWX => "LVEWX",
            LVLX => "LVLX", LVRX => "LVRX",
            STV => "STV", STVX => "STVX", STVXL => "STVXL",
            STVEBX => "STVEBX", STVEHX => "STVEHX", STVEWX => "STVEWX",
            VEXT => "VEXT", VINS => "VINS",
            VSLDOI => "VSLDOI",
            VPOPCNTB => "VPOPCNTB", VPOPCNTH => "VPOPCNTH",
            VPOPCNTW => "VPOPCNTW", VPOPCNTD => "VPOPCNTD",
            VCLZ => "VCLZ", VCLZB => "VCLZB", VCLZH => "VCLZH",
            VCLZW => "VCLZW", VCLZD => "VCLZD",
            VCTZ => "VCTZ", VCTZB => "VCTZB", VCTZH => "VCTZH",
            VCTZW => "VCTZW", VCTZD => "VCTZD",
            VGBBD => "VGBBD",
            VCIPHER => "VCIPHER", VCIPHERLAST => "VCIPHERLAST",
            VNCIPHER => "VNCIPHER", VNCIPHERLAST => "VNCIPHERLAST",
            VSBOX => "VSBOX", VSHASIGMA => "VSHASIGMA",
            LX => "LX", LXS => "LXS", LXV => "LXV",
            STX => "STX", STXS => "STXS", STXV => "STXV",
            XSADD => "XSADD", XSSUB => "XSSUB", XSMUL => "XSMUL", XSDIV => "XSDIV",
            XSMADD => "XSMADD", XSMSUB => "XSMSUB",
            XSNMADD => "XSNMADD", XSNMSUB => "XSNMSUB",
            XSSQRT => "XSSQRT", XSABS => "XSABS", XSNABS => "XSNABS",
            XSNEG => "XSNEG", XSCPSGN => "XSCPSGN",
            XSCMP => "XSCMP", XSMAX => "XSMAX", XSMIN => "XSMIN",
            XVADD => "XVADD", XVSUB => "XVSUB", XVMUL => "XVMUL", XVDIV => "XVDIV",
            XVMADD => "XVMADD", XVMSUB => "XVMSUB",
            XVNMADD => "XVNMADD", XVNMSUB => "XVNMSUB",
            XVSQRT => "XVSQRT", XVABS => "XVABS", XVNABS => "XVNABS",
            XVNEG => "XVNEG", XVCPSGN => "XVCPSGN",
            XVCMP => "XVCMP", XVMAX => "XVMAX", XVMIN => "XVMIN",
            MFVSRD => "MFVSRD", MTVSRD => "MTVSRD",
            MTVSRWA => "MTVSRWA", MTVSRWZ => "MTVSRWZ",
            XXMRGHW => "XXMRGHW", XXMRGLW => "XXMRGLW",
            XXSPLTW => "XXSPLTW", XXSPLTIB => "XXSPLTIB",
            XXPERM => "XXPERM", XXPERMR => "XXPERMR",
            XXSEL => "XXSEL",
            XXLAND => "XXLAND", XXLOR => "XXLOR", XXLXOR => "XXLXOR",
            XXLNAND => "XXLNAND", XXLNOR => "XXLNOR", XXLEQV => "XXLEQV",
            DADD => "DADD", DSUB => "DSUB", DMUL => "DMUL", DDIV => "DDIV",
            DMADD => "DMADD", DMSUB => "DMSUB",
            DCMPU => "DCMPU", DCMO => "DCMO",
            DQUA => "DQUA", DQUAI => "DQUAI",
            DRINTX => "DRINTX", DRINTN => "DRINTN",
            DSCLI => "DSCLI", DSCRI => "DSCRI",
            SE_ADDI => "SE_ADDI", SE_ADD => "SE_ADD", SE_SUB => "SE_SUB",
            SE_SUBF => "SE_SUBF", SE_MULLW => "SE_MULLW",
            SE_AND => "SE_AND", SE_OR => "SE_OR", SE_XOR => "SE_XOR", SE_NOR => "SE_NOR",
            SE_SLWI => "SE_SLWI", SE_SRWI => "SE_SRWI", SE_SRAWI => "SE_SRAWI",
            SE_CMPLI => "SE_CMPLI", SE_CMPI => "SE_CMPI", SE_CMP => "SE_CMP",
            SE_CMPL => "SE_CMPL", SE_CM => "SE_CM",
            SE_B => "SE_B", SE_BC => "SE_BC", SE_BL => "SE_BL",
            SE_BT => "SE_BT", SE_BF => "SE_BF",
            SE_BDNZ => "SE_BDNZ", SE_BDZ => "SE_BDZ",
            SE_LBZ => "SE_LBZ", SE_LHZ => "SE_LHZ", SE_LHA => "SE_LHA", SE_LWZ => "SE_LWZ",
            SE_STB => "SE_STB", SE_STH => "SE_STH", SE_STW => "SE_STW",
            SE_LWZU => "SE_LWZU", SE_STWU => "SE_STWU",
            E_ADD => "E_ADD", E_SUBF => "E_SUBF", E_MULL => "E_MULL",
            E_AND => "E_AND", E_OR => "E_OR", E_XOR => "E_XOR", E_NOR => "E_NOR",
            E_ADDI => "E_ADDI", E_ORI => "E_ORI", E_ORIS => "E_ORIS",
            E_LBZ => "E_LBZ", E_LHZ => "E_LHZ", E_LHA => "E_LHA", E_LWZ => "E_LWZ",
            E_LD => "E_LD", E_STB => "E_STB", E_STH => "E_STH",
            E_STW => "E_STW", E_STD => "E_STD",
            E_RLWIMI => "E_RLWIMI", E_RLWINM => "E_RLWINM",
            E_CMPLI => "E_CMPLI", E_CMPI => "E_CMPI",
            E_B => "E_B", E_BL => "E_BL", E_BC => "E_BC", E_BCL => "E_BCL",
            E_MTSPR => "E_MTSPR", E_MFSPR => "E_MFSPR",
            E_MTCRF => "E_MTCRF", E_MFCR => "E_MFCR",
            E_ISYNC => "E_ISYNC", E_SYNC => "E_SYNC", E_SC => "E_SC", E_NOP => "E_NOP",
            E_LMW => "E_LMW", E_STMW => "E_STMW",
            E_MFMSR => "E_MFMSR", E_MTMSR => "E_MTMSR",
            E_RFI => "E_RFI",
            EVADD => "EVADD", EVSUB => "EVSUB", EVMUL => "EVMUL",
            EVABS => "EVABS", EVNEG => "EVNEG",
            EVCMPEQ => "EVCMPEQ", EVCMPGT => "EVCMPGT", EVCMPLT => "EVCMPLT",
            EVMERGEHI => "EVMERGEHI", EVMERGELO => "EVMERGELO",
            EVSPLATFI => "EVSPLATFI", EVSPLATI => "EVSPLATI",
            EVFSADD => "EVFSADD", EVFSSUB => "EVFSSUB", EVFSMUL => "EVFSMUL",
            EVFSABS => "EVFSABS", EVFSNEG => "EVFSNEG",
            EVFCMPEQ => "EVFCMPEQ", EVFCMPGT => "EVFCMPGT", EVFCMPLT => "EVFCMPLT",
            EVSEL => "EVSEL",
            EVLD => "EVLD", EVST => "EVST",
            EVLDD => "EVLDD", EVSTD => "EVSTD",
            BRINC => "BRINC",
            WAIT => "WAIT", DOZE => "DOZE", NAP => "NAP", SLEEP => "SLEEP",
            RVWINKLE => "RVWINKLE",
            DCCCI => "DCCCI", ICCCI => "ICCCI",
            TLBIL => "TLBIL",
            MSGSND => "MSGSND", MSGSNDP => "MSGSNDP", MSGCLR => "MSGCLR",
            MSGSYNC => "MSGSYNC",
            CP_ABORT => "CP_ABORT", CP_COPY => "CP_COPY", CP_PASTE => "CP_PASTE",
            TBEGIN => "TBEGIN", TEND => "TEND",
            TABORT => "TABORT", TCHECK => "TCHECK",
            TSR => "TSR", TRECLAIM => "TRECLAIM", TRECHKPT => "TRECHKPT",
            DARN => "DARN", UD => "UD", UDE => "UDE", TRAP => "TRAP",
            BRD => "BRD", BRW => "BRW", BRH => "BRH",
            SETBC => "SETBC", SETNBC => "SETNBC",
            CFUGED => "CFUGED", CNTLZDM => "CNTLZDM",
            CNTTZDM => "CNTTZDM", PDEPD => "PDEPD", PEXTD => "PEXTD",
            VCLZDM => "VCLZDM", VCTZDM => "VCTZDM",
            VPDEPD => "VPDEPD", VPEXTD => "VPEXTD", VGNB => "VGNB",
            XXGENPCV => "XXGENPCV", XXEVAL => "XXEVAL",
            XVBF16GER => "XVBF16GER", XVBF16GER2 => "XVBF16GER2",
            PMXVI4GER8 => "PMXVI4GER8", PMXVBF16GER2 => "PMXVBF16GER2",
            DCI => "DCI",
            MCRX => "MCRX",
            _ => "UNIMPL",
        }
    }

    pub fn category(&self) -> PowerPcInstructionCategory {
        use PowerPcMnemonic::*;
        match self {
            ADD | ADDC | ADDE | ADDI | ADDIC | ADDIC_DOT | ADDIS | ADDME | ADDZE
            | ADDO | ADDCO | ADDEO | ADDMEO | ADDZEO
            | SUBF | SUBFC | SUBFE | SUBFIC | SUBFME | SUBFZE
            | SUBFO | SUBFCO | SUBFEO | SUBFMEO | SUBFZEO
            | MULLI | MULLW | MULHW | MULHWU | MULHD | MULHDU
            | DIVW | DIVWU | DIVD | DIVDU | DIVWE | DIVWEU | DIVDE | DIVDEU
            | NEG | NEGO | EXTSB | EXTSH | EXTSW
            | CNTLZW | CNTLZD | CNTTZW | CNTTZD | POPCNTB | POPCNTW | POPCNTD
            | CMPB | PRTYD | MODSW | MODUW | MODSD | MODUD
            => PowerPcInstructionCategory::Integer,
            AND | ANDC | ANDI_DOT | ANDIS_DOT | OR | ORC | ORI | ORIS
            | XOR | XORI | XORIS | NAND | NOR | EQV | EXTSWSLI | SETB
            => PowerPcInstructionCategory::Logical,
            SLW | SRW | SRAW | SRAWI | SLD | SRD | SRAD | SRADI
            | RLDCL | RLDCR | RLDIC | RLDICL | RLDICR | RLDIMI
            | RLWIMI | RLWINM | RLWNM
            => PowerPcInstructionCategory::ShiftRotate,
            CMP | CMPI | CMPL | CMPLI | CMPW | CMPWI | CMPLW | CMPLWI
            | CMPD | CMPDI | CMPLD | CMPLDI | CMPB_2
            => PowerPcInstructionCategory::Compare,
            B | BA | BL | BLA | BC | BCA | BCL | BCLA | BCCTR | BCCTRL
            | BCLR | BCLRL | BCTR | BCTRL | BLR | BLRL | BT | BF | BTA | BFA
            | BDNZ | BDZ | BDNZT | BDZT | BDNZF | BDZF
            | BDNZL | BDZL | BDNZLR | BDZLR
            => PowerPcInstructionCategory::Branch,
            TW | TWI | TD | TDI | TWLT | TWGT | TWEQ | TDLT | TDGT | TDEQ
            => PowerPcInstructionCategory::Trap,
            LBZ | LBZU | LBZX | LBZUX | LHZ | LHZU | LHZX | LHZUX
            | LHA | LHAU | LHAX | LHAUX | LWZ | LWZU | LWZX | LWZUX
            | LWA | LWAX | LWAUX | LD | LDU | LDX | LDUX | LMW
            | STB | STBU | STBX | STBUX | STH | STHU | STHX | STHUX
            | STW | STWU | STWX | STWUX | STD | STDU | STDX | STDUX | STMW
            | LSWI | LSWX | STSWI | STSWX | LWARX | LDARX | STWCX_DOT | STDCX_DOT
            => PowerPcInstructionCategory::LoadStore,
            MFSPR | MTSPR | MFMSR | MTMSR | MFPVR | MFTB | MFTBU
            | MFSR | MTSR | MFSRIN | MTSRIN | MTCRF_SYS | MFOCRF_SYS | MTOCRF_SYS
            | ISYNC | MSYNC | SYNC | LWSYNC | PTESYNC | EIEIO
            | DCB | DCBF | DCBI | DCBST | DCBT | DCBTST | DCBZ
            | ICBI | ICBT | TLBIE | TLBIEL | TLBIA | TLBSYNC
            | SLBIE | SLBIA | SLBSYNC
            | RFI | RFSCV | RFCI | RFMCI | HRFID | SC | SVC
            | NOP | ORI_NOP | ATTN | STOP
            => PowerPcInstructionCategory::System,
            FADD | FADDS | FSUB | FSUBS | FMUL | FMULS | FDIV | FDIVS
            | FMADD | FMADDS | FMSUB | FMSUBS | FNMADD | FNMADDS | FNMSUB | FNMSUBS
            | FSQRT | FSQRTS | FRE | FRES | FRSQRTE | FRSQRTES | FSEL | FSELS
            | FMOV | FMOVS | FMR | FCP | FABS | FABSS | FNABS | FNABSS | FNEG | FNEGS
            | FCPSGN | FCPSGNS | FCMP | FCMPU | FCMPO | FCMPS
            | FCTIW | FCTIWZ | FCTID | FCTIDZ | FCFID | FCFIDS | FCFIDU | FCFIDUS
            | FCTIWU | FCTIWUZ | FCTIDU | FCTIDUZ | FRSP | FRIN | FRIZ | FRIP | FRIM
            | MFFS | MTFSF | MTFSFI | MTFSB1 | MTFSB0
            | MFFSCE | MFFSCRN | MFFSCRNI | MFFSL
            | FADD_DOT | FSUB_DOT | FMUL_DOT | FDIV_DOT | FMADD_DOT | FMSUB_DOT
            => PowerPcInstructionCategory::Fpu,
            VADDU | VADDS | VADD | VSUB | VSUBS | VMUL | VAVG | VABS
            | VMAX | VMIN | VAND | VANDC | VOR | VORC | VXOR | VNOR | VNAND | VEQV
            | VSEL | VPERM | VPERMXOR | VSLO | VSRO | VSL | VSR
            | VRLB | VRLH | VRLW | VRLD | VSLB | VSLH | VSLW | VSLD
            | VSRB | VSRH | VSRW | VSRD | VSRAB | VSRAH | VSRAW | VSRAD
            | VCMPEQ | VCMPGT | VCMPLT | VCMPNE | VCMPGTU | VCMPLTU | VCMPBFP
            | VMRGHB | VMRGHH | VMRGHW | VMRGLB | VMRGLH | VMRGLW
            | VSPLTB | VSPLTH | VSPLTW | VSPLTISB | VSPLTISH | VSPLTISW
            | VPKSH | VPKSW | VPKSD | VPKUH | VPKUW | VPKUD
            | VUPKHSB | VUPKHSH | VUPKHSW | VUPKLSB | VUPKLSH | VUPKLSW
            | VSUMSWS | VSUM2SWS | VSUM4SBS | VSUM4SHS
            | VADDCUW | VADDFP | VSUBFP | VMADDFP | VNMSUBFP
            | VREFP | VRSQRTEFP | VEXPTEFP | VLOGEFP
            | VRFIN | VRFIZ | VRFIP | VRFIM | VCFUX | VCFSX | VCTUXS | VCTSXS
            | LV | LVR | LVX | LVXL | LVE | LVEL | LVSL | LVSR
            | LVEBX | LVEHX | LVEWX | LVLX | LVRX
            | STV | STVX | STVXL | STVEBX | STVEHX | STVEWX
            | VEXT | VINS | VSLDOI | VPOPCNTB | VPOPCNTH | VPOPCNTW | VPOPCNTD
            | VCLZ | VCLZB | VCLZH | VCLZW | VCLZD
            | VCTZ | VCTZB | VCTZH | VCTZW | VCTZD | VGBBD
            | VCIPHER | VCIPHERLAST | VNCIPHER | VNCIPHERLAST | VSBOX | VSHASIGMA
            => PowerPcInstructionCategory::Vmx,
            LX | LXS | LXV | STX | STXS | STXV
            | XSADD | XSSUB | XSMUL | XSDIV | XSMADD | XSMSUB | XSNMADD | XSNMSUB
            | XSSQRT | XSABS | XSNABS | XSNEG | XSCPSGN | XSCMP | XSMAX | XSMIN
            | XVADD | XVSUB | XVMUL | XVDIV | XVMADD | XVMSUB | XVNMADD | XVNMSUB
            | XVSQRT | XVABS | XVNABS | XVNEG | XVCPSGN | XVCMP | XVMAX | XVMIN
            | MFVSRD | MTVSRD | MTVSRWA | MTVSRWZ
            | XXMRGHW | XXMRGLW | XXSPLTW | XXSPLTIB
            | XXPERM | XXPERMR | XXSEL
            | XXLAND | XXLOR | XXLXOR | XXLNAND | XXLNOR | XXLEQV
            => PowerPcInstructionCategory::Vsx,
            DADD | DSUB | DMUL | DDIV | DMADD | DMSUB
            | DCMPU | DCMO | DQUA | DQUAI | DRINTX | DRINTN
            | DSCLI | DSCRI => PowerPcInstructionCategory::Dfp,
            SE_ADDI | SE_ADD | SE_SUB | SE_SUBF | SE_MULLW
            | SE_AND | SE_OR | SE_XOR | SE_NOR
            | SE_SLWI | SE_SRWI | SE_SRAWI
            | SE_CMPLI | SE_CMPI | SE_CMP | SE_CMPL | SE_CM
            | SE_B | SE_BC | SE_BL | SE_BT | SE_BF | SE_BDNZ | SE_BDZ
            | SE_LBZ | SE_LHZ | SE_LHA | SE_LWZ | SE_STB | SE_STH | SE_STW
            | SE_LWZU | SE_STWU
            | E_ADD | E_SUBF | E_MULL | E_AND | E_OR | E_XOR | E_NOR
            | E_ADDI | E_ORI | E_ORIS
            | E_LBZ | E_LHZ | E_LHA | E_LWZ | E_LD
            | E_STB | E_STH | E_STW | E_STD
            | E_RLWIMI | E_RLWINM | E_CMPLI | E_CMPI
            | E_B | E_BL | E_BC | E_BCL
            | E_MTSPR | E_MFSPR | E_MTCRF | E_MFCR
            | E_ISYNC | E_SYNC | E_SC | E_NOP
            | E_LMW | E_STMW | E_MFMSR | E_MTMSR | E_RFI
            => PowerPcInstructionCategory::Vle,
            EVADD | EVSUB | EVMUL | EVABS | EVNEG
            | EVCMPEQ | EVCMPGT | EVCMPLT
            | EVMERGEHI | EVMERGELO | EVSPLATFI | EVSPLATI
            | EVSLH | EVSRH | EVSH | EVCNTLSW | EVCNTLZW
            | EVFSADD | EVFSSUB | EVFSMUL | EVFSABS | EVFSNEG
            | EVCMP | EVFCMPEQ | EVFCMPGT | EVFCMPLT | EVSEL
            | EVLD | EVST | EVLDD | EVSTD
            | BRINC => PowerPcInstructionCategory::Spe,
            _ => PowerPcInstructionCategory::Misc,
        }
    }
}

// ============================================================================
// Conversion to common InstructionMnemonic
// ============================================================================

pub fn all_powerpc_mnemonics() -> Vec<InstructionMnemonic> {
    use PowerPcMnemonic::*;
    let variants = [
        ADD, ADDC, ADDE, ADDI, ADDIC, ADDIC_DOT, ADDIS, ADDME, ADDZE,
        ADDO, ADDCO, ADDEO, ADDMEO, ADDZEO,
        SUBF, SUBFC, SUBFE, SUBFIC, SUBFME, SUBFZE,
        SUBFO, SUBFCO, SUBFEO, SUBFMEO, SUBFZEO,
        MULLI, MULLW, MULHW, MULHWU, MULHD, MULHDU,
        DIVW, DIVWU, DIVD, DIVDU, DIVWE, DIVWEU, DIVDE, DIVDEU,
        NEG, NEGO, EXTSB, EXTSH, EXTSW,
        CNTLZW, CNTLZD, CNTTZW, CNTTZD, POPCNTB, POPCNTW, POPCNTD,
        CMPB, PRTYD, BPERMD, MODSW, MODUW, MODSD, MODUD,
        AND, ANDC, ANDI_DOT, ANDIS_DOT, OR, ORC, ORI, ORIS,
        XOR, XORI, XORIS, NAND, NOR, EQV, EXTSWSLI,
        SLW, SRW, SRAW, SRAWI, SLD, SRD, SRAD, SRADI,
        RLDCL, RLDCR, RLDIC, RLDICL, RLDICR, RLDIMI, RLWIMI, RLWINM, RLWNM,
        CMP, CMPI, CMPL, CMPLI, CMPW, CMPWI, CMPLW, CMPLWI,
        CMPD, CMPDI, CMPLD, CMPLDI, CMPB_2,
        B, BA, BL, BLA, BC, BCA, BCL, BCLA, BCCTR, BCCTRL,
        BCLR, BCLRL, BCTR, BCTRL, BLR, BLRL, BT, BF, BTA, BFA,
        BDNZ, BDZ, BDNZT, BDZT, BDNZF, BDZF,
        BDNZL, BDZL, BDNZLR, BDZLR,
        CRAND, CRANDC, CREQV, CRNAND, CRNOR, CROR, CRORC, CRXOR,
        MCRF, MCRXR, MCRFS, MFCR, MTCRF, MFOCRF, MTOCRF,
        TW, TWI, TD, TDI, TWLT, TWGT, TWEQ, TDLT, TDGT, TDEQ,
        LBZ, LBZU, LBZX, LBZUX, LHZ, LHZU, LHZX, LHZUX,
        LHA, LHAU, LHAX, LHAUX, LWZ, LWZU, LWZX, LWZUX,
        LWA, LWAX, LWAUX, LD, LDU, LDX, LDUX, LMW,
        STB, STBU, STBX, STBUX, STH, STHU, STHX, STHUX,
        STW, STWU, STWX, STWUX, STD, STDU, STDX, STDUX, STMW,
        LSWI, LSWX, STSWI, STSWX, LWARX, LDARX, STWCX_DOT, STDCX_DOT,

        MFSR, MTSR, MFSRIN, MTSRIN, MTCRF_SYS, MFOCRF_SYS, MTOCRF_SYS,
        SYNC, LWSYNC, PTESYNC, EIEIO,
        DCB, DCBF, DCBI, DCBST, DCBT, DCBTST, DCBZ,
        ICBI, TLBIE, TLBIA, TLBSYNC,
        SLBIE, SLBIA, SLBSYNC,
        RFI, RFSCV, RFCI, RFMCI, HRFID, SC, SVC, NOP, ORI_NOP, ATTN, STOP,
        FADD, FADDS, FSUB, FSUBS, FMUL, FMULS, FDIV, FDIVS,
        FMADD, FMADDS, FMSUB, FMSUBS,
        FNMADD, FNMADDS, FNMSUB, FNMSUBS,
        FSQRT, FSQRTS, FRE, FRES, FRSQRTE, FRSQRTES, FSEL, FSELS,
        FMOV, FMOVS, FMR, FCP, FABS, FABSS, FNABS, FNABSS, FNEG, FNEGS,
        FCPSGN, FCPSGNS, FCMP, FCMPU, FCMPO, FCMPS,
        FCTIW, FCTIWZ, FCTID, FCTIDZ, FCFID, FCFIDS, FCFIDU, FCFIDUS,
        FCTIWU, FCTIWUZ, FCTIDU, FCTIDUZ, FRSP, FRIN, FRIZ, FRIP, FRIM,

        FADD_DOT, FSUB_DOT, FMUL_DOT, FDIV_DOT, FMADD_DOT, FMSUB_DOT,
        VADDU, VADDS, VADD, VSUB, VSUBS, VMUL, VAVG, VABS,
        VMAX, VMIN, VAND, VANDC, VOR, VORC, VXOR, VNOR, VNAND, VEQV,
        VSEL, VPERM, VPERMXOR, VSLO, VSRO, VSL, VSR,
        VRLB, VRLH, VRLW, VRLD, VSLB, VSLH, VSLW, VSLD,
        VSRB, VSRH, VSRW, VSRD, VSRAB, VSRAH, VSRAW, VSRAD,
        VCMPEQ, VCMPGT, VCMPLT, VCMPNE, VCMPGTU, VCMPLTU, VCMPBFP,
        VMRGHB, VMRGHH, VMRGHW, VMRGLB, VMRGLH, VMRGLW,
        VSPLTB, VSPLTH, VSPLTW, VSPLTISB, VSPLTISH, VSPLTISW,
        VPKSH, VPKSW, VPKUH, VPKUW, VPKUD,
        VUPKHSB, VUPKHSH, VUPKHSW, VUPKLSB, VUPKLSH, VUPKLSW,
        VSUMSWS, VSUM2SWS, VSUM4SBS, VSUM4SHS,
        VADDCUW, VADDFP, VSUBFP, VMADDFP, VNMSUBFP,
        VREFP, VRSQRTEFP, VEXPTEFP, VLOGEFP,
        VRFIN, VRFIZ, VRFIP, VRFIM, VCFUX, VCFSX, VCTUXS, VCTSXS,
        LV, LVR, LVX, LVXL, LVE, LVEL, LVSL, LVSR,
        LVEBX, LVEHX, LVEWX, LVLX, LVRX,
        STV, STVX, STVXL, STVEBX, STVEHX, STVEWX,
        VEXT, VINS, VSLDOI, VPOPCNTB, VPOPCNTH, VPOPCNTW, VPOPCNTD,
        VCLZ, VCLZB, VCLZH, VCLZW, VCLZD,
        VCTZ, VCTZB, VCTZH, VCTZW, VCTZD, VGBBD,
        VCIPHER, VCIPHERLAST, VNCIPHER, VNCIPHERLAST, VSBOX, VSHASIGMA,
        LX, STXS,
        XSADD, XSSUB, XSMUL, XSDIV, XSMADD, XSMSUB, XSNMADD, XSNMSUB,
        XSSQRT, XSABS, XSNABS, XSNEG, XSCPSGN, XSCMP, XSMAX, XSMIN,
        XVADD, XVSUB, XVMUL, XVDIV, XVMADD, XVMSUB, XVNMADD, XVNMSUB,
        XVSQRT, XVABS, XVNABS, XVNEG, XVCPSGN, XVCMP, XVMAX, XVMIN,
        MFVSRD, MTVSRD, MTVSRWA, MTVSRWZ,
        XXMRGHW, XXMRGLW, XXSPLTW, XXSPLTIB,
        XXPERMR, XXSEL,
        XXLAND, XXLOR, XXLXOR, XXLNAND, XXLNOR, XXLEQV,
        DADD, DSUB, DMUL, DDIV, DMADD, DMSUB,
        DCMPU, DCMO, DQUA, DQUAI, DRINTX, DRINTN, DSCLI, DSCRI,
        SE_ADDI, SE_ADD, SE_SUB, SE_SUBF, SE_MULLW,
        SE_AND, SE_OR, SE_XOR, SE_NOR,
        SE_SLWI, SE_SRWI, SE_SRAWI,
        SE_CMPLI, SE_CMPI, SE_CMP, SE_CMPL, SE_CM,
        SE_B, SE_BC, SE_BL, SE_BT, SE_BF, SE_BDNZ, SE_BDZ,
        SE_LBZ, SE_LHZ, SE_LHA, SE_LWZ, SE_STB, SE_STH, SE_STW,
        SE_LWZU, SE_STWU,
        E_ADD, E_SUBF, E_MULL, E_AND, E_OR, E_XOR, E_NOR,
        E_ADDI, E_ORI, E_ORIS,
        E_LBZ, E_LHZ, E_LHA, E_LWZ, E_LD,
        E_STB, E_STH, E_STW, E_STD,
        E_RLWIMI, E_RLWINM, E_CMPLI, E_CMPI,
        E_B, E_BL, E_BC, E_BCL,
        E_MTSPR, E_MFSPR, E_MTCRF, E_MFCR,
        E_ISYNC, E_SYNC, E_SC, E_NOP,
        E_LMW, E_STMW, E_MFMSR, E_MTMSR, E_RFI,
        EVADD, EVSUB, EVMUL, EVABS, EVNEG,
        EVCMPEQ, EVCMPGT, EVCMPLT,
        EVMERGEHI, EVMERGELO, EVSPLATFI, EVSPLATI,
        EVFSADD, EVFSSUB, EVFSMUL, EVFSABS, EVFSNEG,
        EVCMP, EVFCMPEQ, EVFCMPGT, EVFCMPLT, EVSEL,
        EVLD, EVST, EVLDD, EVSTD, BRINC,
        WAIT, DOZE, NAP, SLEEP, RVWINKLE, DCCCI, ICCCI,
        TLBIL, MSGSND, MSGSNDP, MSGCLR, MSGSYNC,
        CP_ABORT, CP_COPY, CP_PASTE,
        TBEGIN, TEND, TABORT, TCHECK, TSR, TRECLAIM, TRECHKPT,
        DARN, UD, UDE, TRAP, BRD, BRW, BRH,
        SETBC, SETNBC, CFUGED, CNTLZDM, CNTTZDM, PDEPD, PEXTD,
        VCLZDM, VCTZDM,
        XXGENPCV, XXEVAL, XVBF16GER, XVBF16GER2, PMXVI4GER8, PMXVBF16GER2,
        DCI, MCRX,
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

/// The PowerPC processor module.
pub struct PowerPcModule;

impl ProcessorModule for PowerPcModule {
    fn name() -> &'static str { PROCESSOR_NAME }

    fn registers() -> RegisterBank {
        let ppc_bank = PowerPcRegisterBank::new_ppc64();
        let mut bank = RegisterBank::new();
        for reg in ppc_bank.iter() {
            bank.add(reg.clone());
        }
        bank
    }

    fn languages() -> Vec<Language> {
        vec![
            // -- 32-bit default --
            Language::new("PowerPC:BE:32:default", "PowerPC 32-bit big endian w/Altivec, G2", "1.7", Endian::Big, 32),
            Language::new("PowerPC:LE:32:default", "PowerPC 32-bit little endian w/Altivec, G2", "1.7", Endian::Little, 32),
            // -- 64-bit default --
            Language::new("PowerPC:BE:64:default", "PowerPC 64-bit big endian w/Altivec, G2", "1.7", Endian::Big, 64),
            Language::new("PowerPC:LE:64:default", "PowerPC 64-bit little endian w/Altivec, G2", "1.7", Endian::Little, 64),
            // -- 64-bit with 32-bit addressing --
            Language::new("PowerPC:BE:64:64-32addr", "PowerPC 64-bit big endian w/Altivec and 32 bit addressing, G2", "1.7", Endian::Big, 32),
            Language::new("PowerPC:LE:64:64-32addr", "PowerPC 64-bit little endian w/Altivec and 32 bit addressing, G2", "1.7", Endian::Little, 32),
            // -- 4xx embedded --
            Language::new("PowerPC:BE:32:4xx", "PowerPC 4xx 32-bit big endian embedded core", "1.7", Endian::Big, 32),
            Language::new("PowerPC:LE:32:4xx", "PowerPC 4xx 32-bit little endian embedded core", "1.7", Endian::Little, 32),
            // -- MPC8270 --
            Language::new("PowerPC:BE:32:MPC8270", "Freescale MPC8280 32-bit big endian family (PowerQUICC-III)", "1.7", Endian::Big, 32),
            // -- PowerQUICC-III --
            Language::new("PowerPC:BE:32:QUICC", "PowerQUICC-III 32-bit big endian family", "1.7", Endian::Big, 32),
            Language::new("PowerPC:LE:32:QUICC", "PowerQUICC-III 32-bit little endian family", "1.7", Endian::Little, 32),
            // -- e500 --
            Language::new("PowerPC:BE:32:e500", "PowerQUICC-III e500 32-bit big-endian family", "1.7", Endian::Big, 32),
            Language::new("PowerPC:LE:32:e500", "PowerQUICC-III e500 32-bit little-endian family", "1.7", Endian::Little, 32),
            // -- e500mc --
            Language::new("PowerPC:BE:32:e500mc", "PowerQUICC-III e500mc 32-bit big-endian family", "1.7", Endian::Big, 32),
            Language::new("PowerPC:LE:32:e500mc", "PowerQUICC-III e500mc 32-bit little-endian family", "1.7", Endian::Little, 32),
            // -- Power ISA A2 (EVX, 32-bit addressing) --
            Language::new("PowerPC:BE:64:A2-32addr", "Power ISA 3.0 Big Endian w/EVX and 32-bit Addressing", "1.7", Endian::Big, 32),
            Language::new("PowerPC:LE:64:A2-32addr", "Power ISA 3.0 Little Endian w/EVX and 32-bit Addressing", "1.7", Endian::Little, 32),
            // -- Power ISA A2+Altivec (32-bit addressing) --
            Language::new("PowerPC:BE:64:A2ALT-32addr", "Power ISA 3.0 Big Endian w/Altivec and 32-bit Addressing", "1.7", Endian::Big, 32),
            Language::new("PowerPC:LE:64:A2ALT-32addr", "Power ISA 3.0 Little Endian w/Altivec and 32-bit Addressing", "1.7", Endian::Little, 32),
            // -- Power ISA A2+Altivec (64-bit) --
            Language::new("PowerPC:BE:64:A2ALT", "Power ISA 3.0 Big Endian w/Altivec", "1.7", Endian::Big, 64),
            Language::new("PowerPC:LE:64:A2ALT", "Power ISA 3.0 Little Endian w/Altivec", "1.7", Endian::Little, 64),
            // -- Power ISA VLE (32-bit addressing) --
            Language::new("PowerPC:BE:64:VLE-32addr", "Power ISA 3.0 Big Endian w/VLE, EVX and 32-bit Addressing", "1.7", Endian::Big, 32),
            // -- Power ISA VLE+Altivec (32-bit addressing) --
            Language::new("PowerPC:BE:64:VLEALT-32addr", "Power ISA 3.0 Big Endian w/VLE, Altivec and 32-bit Addressing", "1.7", Endian::Big, 32),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> { all_powerpc_mnemonics() }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_count() {
        let bank = PowerPcRegisterBank::new_ppc64();
        assert!(bank.len() > 100, "PowerPC bank should have >100 registers, got {}", bank.len());
    }

    #[test]
    fn test_gpr_registers() {
        let bank = PowerPcRegisterBank::new_ppc64();
        for i in 0..32 {
            assert!(bank.get(&format!("GPR{}", i)).is_some(), "Missing GPR{}", i);
            assert!(bank.get(&format!("R{}", i)).is_some(), "Missing R{}", i);
        }
    }

    #[test]
    fn test_fpr_registers() {
        let bank = PowerPcRegisterBank::new_ppc64();
        for i in 0..32 {
            assert!(bank.get(&format!("FPR{}", i)).is_some(), "Missing FPR{}", i);
            assert!(bank.get(&format!("F{}", i)).is_some(), "Missing F{}", i);
        }
    }

    #[test]
    fn test_special_registers() {
        let bank = PowerPcRegisterBank::new_ppc64();
        assert!(bank.get("CR").is_some());
        assert!(bank.get("LR").is_some());
        assert!(bank.get("CTR").is_some());
        assert!(bank.get("XER").is_some());
        assert!(bank.get("MSR").is_some());
        assert!(bank.get("PC").is_some());
    }

    #[test]
    fn test_system_registers() {
        let bank = PowerPcRegisterBank::new_ppc64();
        assert!(bank.get("SRR0").is_some());
        assert!(bank.get("SRR1").is_some());
        assert!(bank.get("DSISR").is_some());
        assert!(bank.get("DAR").is_some());
        assert!(bank.get("DEC").is_some());
        assert!(bank.get("TB").is_some());
        assert!(bank.get("PVR").is_some());
    }

    #[test]
    fn test_cr_fields() {
        let bank = PowerPcRegisterBank::new_ppc64();
        for name in &CR_FIELD_NAMES {
            assert!(bank.get(name).is_some(), "Missing CR field: {}", name);
        }
    }

    #[test]
    fn test_fpu_registers() {
        let bank = PowerPcRegisterBank::new_ppc64();
        assert!(bank.get("FPSCR").is_some());
    }

    #[test]
    fn test_vmx_registers() {
        let bank = PowerPcRegisterBank::new_ppc64();
        for i in 0..32 {
            assert!(bank.get(&format!("VR{}", i)).is_some(), "Missing VR{}", i);
        }
        assert!(bank.get("VSCR").is_some());
        assert!(bank.get("VRSAVE").is_some());
    }

    #[test]
    fn test_vsx_registers() {
        let bank = PowerPcRegisterBank::new_ppc64();
        for i in 0..64 {
            assert!(bank.get(&format!("VSR{}", i)).is_some(), "Missing VSR{}", i);
        }
    }

    #[test]
    fn test_spe_registers() {
        let bank = PowerPcRegisterBank::new_ppc64();
        for i in 0..32 {
            assert!(bank.get(&format!("EVR{}", i)).is_some(), "Missing EVR{}", i);
        }
        assert!(bank.get("ACC").is_some());
        assert!(bank.get("SPEFSCR").is_some());
    }

    #[test]
    fn test_spr_lookup() {
        let bank = PowerPcRegisterBank::new_ppc64();
        assert!(bank.spr(8).is_some());
        assert!(bank.spr(9).is_some());
        assert!(bank.spr(287).is_some());
    }

    #[test]
    fn test_msr_fields() {
        assert_eq!(MsrField::SF.mask(), 1);
        assert_eq!(MsrField::LE.mask(), 1u64 << 63);
        assert_eq!(MsrField::PR.mask(), 1u64 << 49);
        assert_eq!(MsrField::VEC.bit(), 38);
    }

    #[test]
    fn test_fpscr_fields() {
        assert_eq!(FpscrField::FX.mask(), 1u32 << 31);
        assert_eq!(FpscrField::RN0.mask(), 1u32 << 0);
    }

    #[test]
    fn test_spr_numbers() {
        assert_eq!(SprNumber::XER.number(), 1);
        assert_eq!(SprNumber::LR.number(), 8);
        assert_eq!(SprNumber::CTR.number(), 9);
        assert_eq!(SprNumber::PVR.number(), 287);
        assert_eq!(SprNumber::SPRG0.number(), 272);
    }

    #[test]
    fn test_mnemonic_count() {
        let mnemonics = all_powerpc_mnemonics();
        assert!(mnemonics.len() >= 250, "Expected >= 250 unique PowerPC mnemonics, got {}", mnemonics.len());
    }

    #[test]
    fn test_processor_module_interface() {
        let regs = PowerPcModule::registers();
        assert!(!regs.is_empty());
        let langs = PowerPcModule::languages();
        assert!(langs.len() >= 20, "Expected >= 20 PowerPC language variants, got {}", langs.len());
        let insts = PowerPcModule::instructions();
        assert!(insts.len() >= 250);
    }

    #[test]
    fn test_variant_properties() {
        assert!(PowerPcVariant::Ppc64.is_64bit());
        assert!(!PowerPcVariant::Ppc601.is_64bit());
        assert!(PowerPcVariant::Ppc74xx.has_vmx());
        assert!(PowerPcVariant::Power8.has_vsx());
        assert!(!PowerPcVariant::Ppc4xx.has_vmx());
        assert!(PowerPcVariant::PpcE500.has_spe());
    }

    #[test]
    fn test_mnemonic_categories() {
        assert!(matches!(PowerPcMnemonic::ADD.category(), PowerPcInstructionCategory::Integer));
        assert!(matches!(PowerPcMnemonic::AND.category(), PowerPcInstructionCategory::Logical));
        assert!(matches!(PowerPcMnemonic::B.category(), PowerPcInstructionCategory::Branch));
        assert!(matches!(PowerPcMnemonic::LWZ.category(), PowerPcInstructionCategory::LoadStore));
        assert!(matches!(PowerPcMnemonic::SC.category(), PowerPcInstructionCategory::System));
        assert!(matches!(PowerPcMnemonic::FADD.category(), PowerPcInstructionCategory::Fpu));
        assert!(matches!(PowerPcMnemonic::VADDU.category(), PowerPcInstructionCategory::Vmx));
        assert!(matches!(PowerPcMnemonic::XSADD.category(), PowerPcInstructionCategory::Vsx));
        assert!(matches!(PowerPcMnemonic::DADD.category(), PowerPcInstructionCategory::Dfp));
        assert!(matches!(PowerPcMnemonic::EVADD.category(), PowerPcInstructionCategory::Spe));
    }

    #[test]
    fn test_register_sizes() {
        let bank = PowerPcRegisterBank::new_ppc64();
        assert_eq!(bank.get("GPR0").unwrap().bit_size, 64);
        assert_eq!(bank.get("FPR0").unwrap().bit_size, 64);
        assert_eq!(bank.get("VR0").unwrap().bit_size, 128);
        assert_eq!(bank.get("VSR0").unwrap().bit_size, 128);
        assert_eq!(bank.get("CR").unwrap().bit_size, 32);
    }
}
