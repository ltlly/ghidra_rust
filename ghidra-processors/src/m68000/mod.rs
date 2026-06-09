//! Motorola 68000 Family Processor Module (M68K)
//!
//! Complete M68K processor support for 68000 through 68060 and ColdFire variants,
//! with 200+ instruction mnemonics.
//!
//! ## Supported Variants
//!
//! | Variant    | Features                                                   |
//! |------------|------------------------------------------------------------|
//! | 68000      | 16/32-bit, 24-bit addr bus, no VBR/SFC/DFC                 |
//! | 68010      | VBR, loop mode, RTD                                         |
//! | 68020      | 32-bit ALU, bit fields, CAS/CAS2, instruction cache         |
//! | 68030      | 68020 + data cache, MMU, burst mode                         |
//! | 68040      | Integrated FPU, dual cache, larger pipelines               |
//! | 68060      | Superscalar, branch prediction, deeper pipeline             |
//! | ColdFire V1-5 | Simplified ISA, MAC/EMAC, embedded focus                 |
//!
//! ## Register Model
//!
//! M68K has a flat register set with specialized roles:
//! - D0-D7: 32-bit data registers
//! - A0-A7: 32-bit address registers (A7 = SSP/USP stack pointer)
//! - PC: 32-bit program counter
//! - SR/CCR: 16-bit status register / 8-bit condition code register
//! - VBR: 32-bit vector base register (68010+)
//! - SFC/DFC: 3-bit source/destination function codes (68020+)
//! - CACR/CAAR: cache control registers (68020+)
//! - USP/ISP/MSP: stack pointers (USP always, ISP/MSP 68020+)
//! - FP0-FP7: 80-bit extended precision FPU registers (68881/68882/68040+)
//! - FPSR/FPCR/FPIAR: FPU control registers
//! - MACSR/MASK/ACC/MACEXT: ColdFire MAC registers
//! - EMAC0-3: ColdFire EMAC accumulators (ColdFire V4+)
//!
//! ## Register Space Layout
//! - D0-D7 (data):                  0x0000 - 0x001C  (32-bit each)
//! - A0-A7 (address):               0x0020 - 0x003C  (32-bit each)
//! - PC:                             0x0040            (32-bit)
//! - SR/CCR:                         0x0048            (16/8-bit)
//! - SSP:                            0x0050            (32-bit)
//! - VBR:                            0x0058            (32-bit)
//! - SFC/DFC:                        0x0060            (3-bit each)
//! - CACR/CAAR:                      0x0068            (32-bit each)
//! - USP/ISP/MSP:                    0x0078            (32-bit each)
//! - MMU (68030):                    0x0090 - 0x00B4
//! - Bus/MMU (68040):                0x00B8 - 0x00C8
//! - FPU FP0-FP7:                    0x0100 - 0x0170  (80-bit each)
//! - FPSR/FPCR/FPIAR:               0x0180            (32-bit each)
//! - ColdFire MAC/EMAC:             0x0200 - 0x0268  (32-bit each)

pub mod language_provider;

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

// ============================================================================
// Processor Name Constants
// ============================================================================

pub const PROCESSOR_NAME: &str = "Motorola 68000 Family";
pub const PROCESSOR_DESCRIPTION: &str =
    "Motorola 68000 processor family from 68000 through 68060 and ColdFire";

// ============================================================================
// M68K Variants
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum M68kVariant {
    MC68000,
    MC68010,
    MC68020,
    MC68030,
    MC68040,
    MC68060,
    ColdFireV1,
    ColdFireV2,
    ColdFireV3,
    ColdFireV4,
    ColdFireV5,
    CPU32,
    Freescale5475,
}

impl M68kVariant {
    pub fn name(&self) -> &'static str {
        match self {
            M68kVariant::MC68000 => "68000",
            M68kVariant::MC68010 => "68010",
            M68kVariant::MC68020 => "68020",
            M68kVariant::MC68030 => "68030",
            M68kVariant::MC68040 => "68040",
            M68kVariant::MC68060 => "68060",
            M68kVariant::ColdFireV1 => "ColdFire V1",
            M68kVariant::ColdFireV2 => "ColdFire V2",
            M68kVariant::ColdFireV3 => "ColdFire V3",
            M68kVariant::ColdFireV4 => "ColdFire V4",
            M68kVariant::ColdFireV5 => "ColdFire V5",
            M68kVariant::CPU32 => "CPU32",
            M68kVariant::Freescale5475 => "Freescale 5475 (ColdFire V4e)",
        }
    }

    pub fn has_fpu(&self) -> bool {
        matches!(self, M68kVariant::MC68040 | M68kVariant::MC68060
            | M68kVariant::Freescale5475)
    }

    pub fn has_mmu(&self) -> bool {
        matches!(self, M68kVariant::MC68030 | M68kVariant::MC68040
            | M68kVariant::MC68060 | M68kVariant::Freescale5475)
    }

    pub fn has_bitfield(&self) -> bool {
        !matches!(self, M68kVariant::MC68000 | M68kVariant::MC68010
            | M68kVariant::ColdFireV1 | M68kVariant::ColdFireV2)
    }
}

impl std::fmt::Display for M68kVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// SR / CCR Bit Fields
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SrBit {
    C = 0,  // Carry
    V = 1,  // Overflow
    Z = 2,  // Zero
    N = 3,  // Negative
    X = 4,  // Extend
    I0 = 8, // Interrupt mask bit 0
    I1 = 9, // Interrupt mask bit 1
    I2 = 10,// Interrupt mask bit 2
    S  = 13,// Supervisor flag
    T0 = 14,// Trace 0 (68000 trace)
    T1 = 15,// Trace 1 (68020+ trace enable)
}

impl SrBit {
    pub fn mask(&self) -> u16 {
        1u16 << (*self as u32)
    }

    pub fn bit(&self) -> u32 {
        *self as u32
    }

    pub fn name(&self) -> &'static str {
        match self {
            SrBit::C => "C", SrBit::V => "V", SrBit::Z => "Z", SrBit::N => "N",
            SrBit::X => "X",
            SrBit::I0 => "I0", SrBit::I1 => "I1", SrBit::I2 => "I2",
            SrBit::S => "S", SrBit::T0 => "T0", SrBit::T1 => "T1",
        }
    }
}

// ============================================================================
// Register Offset Layout
// ============================================================================

const DREG_BASE: u64 = 0x0000;
const AREG_BASE: u64 = 0x0020;
const PC_OFFSET: u64 = 0x0040;
const SR_OFFSET: u64 = 0x0048;
const SSP_OFFSET: u64 = 0x0050;
const VBR_OFFSET: u64 = 0x0058;
const SFC_OFFSET: u64 = 0x0060;
const DFC_OFFSET: u64 = 0x0064;
const CACR_OFFSET: u64 = 0x0068;
const CAAR_OFFSET: u64 = 0x0070;
const USP_OFFSET: u64 = 0x0078;
const ISP_OFFSET: u64 = 0x0080;
const MSP_OFFSET: u64 = 0x0088;
const MMU_BASE: u64 = 0x0090;
const BUSCTL_BASE: u64 = 0x00B8;
const FPU_BASE: u64 = 0x0100;
const FPU_CTL_BASE: u64 = 0x0180;
const CF_BASE: u64 = 0x0200;

// ============================================================================
// M68000 Register Bank
// ============================================================================

#[derive(Debug, Clone)]
pub struct M68000RegisterBank {
    pub d: [Register; 8],
    pub a: [Register; 8],
    pub pc: Register,
    pub sr: Register,
    pub ssp: Register,
    pub vbr: Register,
    pub sfc: Register,
    pub dfc: Register,
    pub cacr: Register,
    pub caar: Register,
    pub usp: Register,
    pub isp: Register,
    pub msp: Register,
    // MMU (68030+)
    pub tc: Register,
    pub tt0: Register,
    pub tt1: Register,
    pub srp: Register,
    pub crp: Register,
    pub mmusr: Register,
    // Bus control (68040+)
    pub itt0: Register,
    pub itt1: Register,
    pub dtt0: Register,
    pub dtt1: Register,
    pub urp: Register,
    // FPU
    pub fp: [Register; 8],
    pub fpsr: Register,
    pub fpcr: Register,
    pub fpiar: Register,
    pub fpres: Register,
    // ColdFire
    pub macsr: Register,
    pub mask: Register,
    pub acc: Register,
    pub macext: Register,
    pub emac: [Register; 4],
    pub emac_status: Register,
    pub emac_ext: Register,
    pub ccr_cf: Register,
    pub rambar: Register,
    pub rambar0: Register,
    pub rambar1: Register,
    register_by_name: std::collections::HashMap<String, Register>,
}

impl M68000RegisterBank {
    pub fn new_68060() -> Self {
        // ---- Data registers D0-D7 (32-bit) ----
        let d: [Register; 8] = std::array::from_fn(|i| {
            Register::new(&format!("D{}", i), 32, DREG_BASE + (i as u64) * 4)
        });
        // Sub-register aliases Dx.W and Dx.B
        let _dw: Vec<Register> = (0..8)
            .map(|i| {
                Register::sub_register(
                    &format!("D{}.W", i), 16,
                    DREG_BASE + (i as u64) * 4,
                    &format!("D{}", i), 0,
                )
            })
            .collect();
        let _db: Vec<Register> = (0..8)
            .map(|i| {
                Register::sub_register(
                    &format!("D{}.B", i), 8,
                    DREG_BASE + (i as u64) * 4,
                    &format!("D{}", i), 0,
                )
            })
            .collect();

        // ---- Address registers A0-A7 (32-bit) ----
        let a: [Register; 8] = std::array::from_fn(|i| {
            Register::new(&format!("A{}", i), 32, AREG_BASE + (i as u64) * 4)
        });

        // ---- PC, SR, SSP ----
        let pc = Register::new("PC", 32, PC_OFFSET);
        let sr = Register::new("SR", 16, SR_OFFSET);
        let ccr = Register::sub_register("CCR", 8, SR_OFFSET, "SR", 0);

        // SR bit field sub-registers
        let sr_flag = |name: &str, bit: u32| {
            Register::sub_register(name, 1, SR_OFFSET, "SR", bit)
        };

        let ssp = Register::new("SSP", 32, SSP_OFFSET);
        let a7_prime = Register::sub_register("A7_PRIME", 32, SSP_OFFSET, "SSP", 0);

        // ---- VBR, SFC, DFC, CACR, CAAR (68020+) ----
        let vbr = Register::new("VBR", 32, VBR_OFFSET);
        let sfc = Register::new("SFC", 3, SFC_OFFSET);
        let dfc = Register::new("DFC", 3, DFC_OFFSET);
        let cacr = Register::new("CACR", 32, CACR_OFFSET);
        let caar = Register::new("CAAR", 32, CAAR_OFFSET);

        // ---- Stack pointers ----
        let usp = Register::new("USP", 32, USP_OFFSET);
        let isp = Register::new("ISP", 32, ISP_OFFSET);
        let msp = Register::new("MSP", 32, MSP_OFFSET);

        // ---- MMU (68030+) ----
        let tc = Register::new("TC", 32, MMU_BASE + 0x00);
        let tt0 = Register::new("TT0", 32, MMU_BASE + 0x04);
        let tt1 = Register::new("TT1", 32, MMU_BASE + 0x08);
        let srp = Register::new("SRP", 64, MMU_BASE + 0x10);
        let crp = Register::new("CRP", 64, MMU_BASE + 0x18);
        let mmusr = Register::new("MMUSR", 16, MMU_BASE + 0x20);

        // ---- Bus control (68040+) ----
        let itt0 = Register::new("ITT0", 32, BUSCTL_BASE + 0x00);
        let itt1 = Register::new("ITT1", 32, BUSCTL_BASE + 0x04);
        let dtt0 = Register::new("DTT0", 32, BUSCTL_BASE + 0x08);
        let dtt1 = Register::new("DTT1", 32, BUSCTL_BASE + 0x0C);
        let urp = Register::new("URP", 32, BUSCTL_BASE + 0x10);

        // ---- FPU FP0-FP7 (80-bit extended) ----
        let fp: [Register; 8] = std::array::from_fn(|i| {
            Register::new(&format!("FP{}", i), 80, FPU_BASE + (i as u64) * 16)
        });

        // ---- FPU control ----
        let fpsr = Register::new("FPSR", 32, FPU_CTL_BASE + 0x00);
        let fpcr = Register::new("FPCR", 32, FPU_CTL_BASE + 0x04);
        let fpiar = Register::new("FPIAR", 32, FPU_CTL_BASE + 0x08);
        let fpres = Register::new("FPRES", 96, FPU_CTL_BASE + 0x0C);

        // ---- ColdFire MAC/EMAC ----
        let macsr = Register::new("MACSR", 32, CF_BASE + 0x00);
        let mask = Register::new("MASK", 32, CF_BASE + 0x08);
        let acc = Register::new("ACC", 32, CF_BASE + 0x10);
        let macext = Register::new("MACEXT", 32, CF_BASE + 0x14);
        let emac: [Register; 4] = std::array::from_fn(|i| {
            Register::new(&format!("EMAC{}", i), 32, CF_BASE + 0x20 + (i as u64) * 4)
        });
        let emac_status = Register::new("EMAC_STATUS", 32, CF_BASE + 0x40);
        let emac_ext = Register::new("EMAC_EXT", 32, CF_BASE + 0x48);
        let ccr_cf = Register::new("CCR_CF", 32, CF_BASE + 0x50);
        let rambar = Register::new("RAMBAR", 32, CF_BASE + 0x58);
        let rambar0 = Register::new("RAMBAR0", 32, CF_BASE + 0x60);
        let rambar1 = Register::new("RAMBAR1", 32, CF_BASE + 0x68);

        // ---- Build lookup table ----
        let mut register_by_name = std::collections::HashMap::new();

        // Data registers + sub-registers
        for (i, reg) in d.iter().enumerate() {
            register_by_name.insert(format!("D{}", i), reg.clone());
            let dw = Register::sub_register(
                &format!("D{}.W", i), 16,
                DREG_BASE + (i as u64) * 4,
                &format!("D{}", i), 0,
            );
            register_by_name.insert(format!("D{}.W", i), dw);
            let db = Register::sub_register(
                &format!("D{}.B", i), 8,
                DREG_BASE + (i as u64) * 4,
                &format!("D{}", i), 0,
            );
            register_by_name.insert(format!("D{}.B", i), db);
        }

        // Address registers
        for (i, reg) in a.iter().enumerate() {
            register_by_name.insert(format!("A{}", i), reg.clone());
        }
        // A7 aliases
        register_by_name.insert("USP".to_string(), usp.clone());
        register_by_name.insert("SP".to_string(), a[7].clone());

        // Special
        register_by_name.insert("PC".to_string(), pc.clone());
        register_by_name.insert("SR".to_string(), sr.clone());
        register_by_name.insert("CCR".to_string(), ccr.clone());

        // SR bit fields
        for (name, bit) in [
            ("C", 0u32), ("V", 1), ("Z", 2), ("N", 3), ("X", 4),
            ("I0", 8), ("I1", 9), ("I2", 10),
            ("S", 13), ("T0", 14), ("T1", 15),
        ] {
            register_by_name.insert(name.to_string(), sr_flag(name, bit));
        }

        register_by_name.insert("SSP".to_string(), ssp.clone());
        register_by_name.insert("A7_PRIME".to_string(), a7_prime);

        // 68020+ registers
        for (name, reg) in [
            ("VBR", &vbr), ("SFC", &sfc), ("DFC", &dfc),
            ("CACR", &cacr), ("CAAR", &caar),
            ("ISP", &isp), ("MSP", &msp),
        ] {
            register_by_name.insert(name.to_string(), reg.clone());
        }

        // MMU
        for (name, reg) in [
            ("TC", &tc), ("TT0", &tt0), ("TT1", &tt1),
            ("SRP", &srp), ("CRP", &crp), ("MMUSR", &mmusr),
        ] {
            register_by_name.insert(name.to_string(), reg.clone());
        }

        // Bus control
        for (name, reg) in [
            ("ITT0", &itt0), ("ITT1", &itt1),
            ("DTT0", &dtt0), ("DTT1", &dtt1), ("URP", &urp),
        ] {
            register_by_name.insert(name.to_string(), reg.clone());
        }

        // FPU
        for (i, reg) in fp.iter().enumerate() {
            register_by_name.insert(format!("FP{}", i), reg.clone());
        }
        for (name, reg) in [
            ("FPSR", &fpsr), ("FPCR", &fpcr), ("FPIAR", &fpiar),
        ] {
            register_by_name.insert(name.to_string(), reg.clone());
        }

        // FPSR bit fields
        for (name, bit) in [
            ("FP_N", 31u32), ("FP_Z", 30), ("FP_INF", 29), ("FP_NAN", 28),
            ("BSUN", 7), ("SNAN", 6), ("OPERR", 5),
            ("OVFL", 4), ("UNFL", 3), ("DZ", 2),
            ("INEX2", 1), ("INEX1", 0),
        ] {
            register_by_name.insert(
                name.to_string(),
                Register::sub_register(name, 1, FPU_CTL_BASE + 0x00, "FPSR", bit),
            );
        }
        register_by_name.insert(
            "FPCC".to_string(),
            Register::sub_register("FPCC", 4, FPU_CTL_BASE + 0x00, "FPSR", 28),
        );

        // FPCR bit fields
        register_by_name.insert(
            "FPCR_RND".to_string(),
            Register::sub_register("FPCR_RND", 2, FPU_CTL_BASE + 0x04, "FPCR", 4),
        );
        register_by_name.insert(
            "FPCR_PREC".to_string(),
            Register::sub_register("FPCR_PREC", 3, FPU_CTL_BASE + 0x04, "FPCR", 6),
        );

        // ColdFire
        for (name, reg) in [
            ("MACSR", &macsr), ("MASK", &mask), ("ACC", &acc), ("MACEXT", &macext),
        ] {
            register_by_name.insert(name.to_string(), reg.clone());
        }
        for (i, reg) in emac.iter().enumerate() {
            register_by_name.insert(format!("EMAC{}", i), reg.clone());
        }
        for (name, reg) in [
            ("EMAC_STATUS", &emac_status), ("EMAC_EXT", &emac_ext),
            ("CCR_CF", &ccr_cf), ("RAMBAR", &rambar),
            ("RAMBAR0", &rambar0), ("RAMBAR1", &rambar1),
        ] {
            register_by_name.insert(name.to_string(), reg.clone());
        }

        M68000RegisterBank {
            d, a, pc, sr, ssp, vbr, sfc, dfc, cacr, caar,
            usp, isp, msp,
            tc, tt0, tt1, srp, crp, mmusr,
            itt0, itt1, dtt0, dtt1, urp,
            fp, fpsr, fpcr, fpiar, fpres,
            macsr, mask, acc, macext,
            emac, emac_status, emac_ext,
            ccr_cf, rambar, rambar0, rambar1,
            register_by_name,
        }
    }

    pub fn get(&self, name: &str) -> Option<&Register> {
        self.register_by_name.get(name)
    }

    pub fn sub_registers_of(&self, parent: &str) -> Vec<&Register> {
        self.register_by_name
            .values()
            .filter(|r| r.parent.as_deref() == Some(parent))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.register_by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.register_by_name.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Register> {
        self.register_by_name.values()
    }
}

impl Default for M68000RegisterBank {
    fn default() -> Self {
        Self::new_68060()
    }
}

// ============================================================================
// M68000 Instruction Mnemonics (200+)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum M68000Mnemonic {
    // ---- Data Movement ----
    Move, Movea, Moveq, Movem, Movep, Move16, Mov3q,
    Lea, Pea, Link, Unlk, Exg, Swap,
    // ---- Arithmetic ----
    Add, Adda, Addi, Addq, Addx,
    Sub, Suba, Subi, Subq, Subx,
    Muls, Mulu, Divs, Divu,
    Divsl, Divul,  // 68020+
    MulsL, MuluL,  // 68020+ 32x32->32
    Neg, Negx, Clr,
    Cmp, Cmpa, Cmpi, Cmp2, Cmpm, Tst, Tas,
    Ext, Extb,
    // ---- Logical ----
    And, Andi, AndiCcr, AndiSr,
    Or, Ori, OriCcr, OriSr,
    Eor, Eori, EoriCcr, EoriSr,
    Not,
    // ---- Shift / Rotate ----
    Asl, Asr, Lsl, Lsr,
    Rol, Ror, Roxl, Roxr,
    // ---- Bit Manipulation (68020+) ----
    Bfchg, Bfclr, Bfexts, Bfextu, Bfffo, Bfins, Bfset, Bftst,
    // ---- Bit Operations ----
    Bchg, Bclr, Bset, Btst,
    // ---- BCD Arithmetic ----
    Abcd, Sbcd, Nbcd,
    // ---- Branch (all 16 conditions) ----
    Bra, Bsr,
    Beq, Bne, Bcs, Bcc, Bhs, Blo,
    Bmi, Bpl, Bvs, Bvc,
    Bhi, Bls, Bge, Blt, Bgt, Ble,
    // ---- DBcc (Decrement and Branch) ----
    Dbt, Dbf, Dbra,
    Dbeq, Dbne, Dbcs, Dbcc, Dbhs, Dblo,
    Dbmi, Dbpl, Dbvs, Dbvc,
    Dbhi, Dbls, Dbge, Dblt, Dbgt, Dble,
    // ---- Scc (Set according to condition) ----
    StCc, SfCc,
    Seq, Sne, Scs, SccSt, Shs, Slo,
    Smi, Spl, Svs, Svc,
    Shi, Sls, Sge, Slt, Sgt, Sle,
    // ---- Jump / Subroutine ----
    Jmp, Jsr, Rts, Rtd, Rtr,
    // ---- Trap / Exception ----
    Trap, Trapv, Trapcc,
    Bkpt, Chk, Chk2,
    Rte, Illegal, Nop,
    Reset, Stop, Halt, Pulse, Wddata,
    // ---- Privileged ----
    Movec, Moves, MoveSr, MoveCcr, MoveUsp,
    RteExt, Wdebug,
    // ---- Cache Maintenance (68030+) ----
    Cinva, Cinvl, Cinvp,
    Cpusha, Cpushl, Cpushp,
    // ---- Pack / Unpack (68020+) ----
    Pack, Unpk,
    // ---- CAS/CAS2 (68020+) ----
    Cas, Cas2,
    // ---- Move with Sign Extend (68020+) ----
    Move16Ax, Move16Al,
    // ---- Address register indirect with index ----
    // (covered by addressing modes, not separate mnemonics)
    // ---- ColdFire MAC ----
    Mac, Macw, Macl, Msac, MoveMac, ClrAcc,
    // ---- ColdFire EMAC ----
    Emac, Emacw, Emsac, Emsacw,
    // ---- ColdFire Other ----
    Stldsr, Byterev, Ff1, Sats, Bitrev,
    // ---- Floating Point (68881/68882 / 68040+) ----
    // FP Move
    Fmove, FmoveCr, FmoveSr, FmoveIar,
    FmoveS, FmoveD, FmoveX, FmoveP,
    FmoveFpcr, FmoveFpsr, FmoveFpiar,
    Fmovem, FmovemCr, FmovemDr,
    // FP Arithmetic
    Fadd, FaddS, FaddD, FaddX, FaddP,
    Fsub, FsubS, FsubD, FsubX, FsubP,
    Fmul, FmulS, FmulD, FmulX, FmulP,
    Fdiv, FdivS, FdivD, FdivX, FdivP,
    Fabs, FabsS, FabsD, FabsX, FabsP,
    Fneg, FnegS, FnegD, FnegX, FnegP,
    Fsqrt, FsqrtS, FsqrtD, FsqrtX, FsqrtP,
    // FP Transcendental
    Fsin, FsinS, FsinD, FsinX, FsinP,
    Fcos, FcosS, FcosD, FcosX, FcosP,
    Ftan, FtanS, FtanD, FtanX, FtanP,
    Fasin, Facos, Fatan, Fatanh,
    Fsinh, Fcosh, Ftanh,
    Fetox, Fetoxm1, Ftentox, Ftwotox,
    Flog2, Flog10, Flogn, Flognp1,
    Fgetexp, Fgetman,
    Fmod, Frem, Fscale,
    Fsglmul, Fsgldiv,
    // FP Comparison / Test
    Fcmp, Ftst,
    // FP Branch
    Fbeq, Fbne, Fbgt, Fbge, Fblt, Fble,
    Fbgl, Fbgle, Fbngl, Fbngle,
    Fbogt, Fboge, Fbolt, Fbole,
    Fbor, Fbun, Fbueq, Fbugt, Fbuge, Fbult, Fbule, FbneOr,
    // FP Set
    Fseq, Fsne, Fsgt, Fsge, Fslt, Fsle,
    Fsgl, Fsgle, Fsngl, Fsngle,
    Fsogt, Fsoge, Fsolt, Fsole,
    Fsor, Fsun, Fsueq, Fsugt, Fsuge, Fsult, Fsule, FsneOr,
    // FP Integer / Conversion
    Fint, Fintrz, FintS, FintD, FintX, FintP,
    Fsubb, Faddb, Fmulb, Fdivb,
    Fmul3,
    // FP NOP / Return
    Fnop,
    // ---- Pc-relative Addressing (treated separately in some tools) ----
    MoveaPc,   // MOVE.L (d16,PC), An
    // ---- NOP placeholder ----
    NopPlain,
}

impl M68000Mnemonic {
    pub fn as_str(&self) -> &'static str {
        match self {
            M68000Mnemonic::Move => "move",
            M68000Mnemonic::Movea => "movea",
            M68000Mnemonic::Moveq => "moveq",
            M68000Mnemonic::Movem => "movem",
            M68000Mnemonic::Movep => "movep",
            M68000Mnemonic::Move16 => "move16",
            M68000Mnemonic::Mov3q => "mov3q",
            M68000Mnemonic::Lea => "lea",
            M68000Mnemonic::Pea => "pea",
            M68000Mnemonic::Link => "link",
            M68000Mnemonic::Unlk => "unlk",
            M68000Mnemonic::Exg => "exg",
            M68000Mnemonic::Swap => "swap",
            M68000Mnemonic::Add => "add",
            M68000Mnemonic::Adda => "adda",
            M68000Mnemonic::Addi => "addi",
            M68000Mnemonic::Addq => "addq",
            M68000Mnemonic::Addx => "addx",
            M68000Mnemonic::Sub => "sub",
            M68000Mnemonic::Suba => "suba",
            M68000Mnemonic::Subi => "subi",
            M68000Mnemonic::Subq => "subq",
            M68000Mnemonic::Subx => "subx",
            M68000Mnemonic::Muls => "muls",
            M68000Mnemonic::Mulu => "mulu",
            M68000Mnemonic::Divs => "divs",
            M68000Mnemonic::Divu => "divu",
            M68000Mnemonic::Divsl => "divsl",
            M68000Mnemonic::Divul => "divul",
            M68000Mnemonic::MulsL => "muls.l",
            M68000Mnemonic::MuluL => "mulu.l",
            M68000Mnemonic::Neg => "neg",
            M68000Mnemonic::Negx => "negx",
            M68000Mnemonic::Clr => "clr",
            M68000Mnemonic::Cmp => "cmp",
            M68000Mnemonic::Cmpa => "cmpa",
            M68000Mnemonic::Cmpi => "cmpi",
            M68000Mnemonic::Cmp2 => "cmp2",
            M68000Mnemonic::Cmpm => "cmpm",
            M68000Mnemonic::Tst => "tst",
            M68000Mnemonic::Tas => "tas",
            M68000Mnemonic::Ext => "ext",
            M68000Mnemonic::Extb => "extb",
            M68000Mnemonic::And => "and",
            M68000Mnemonic::Andi => "andi",
            M68000Mnemonic::AndiCcr => "andi_ccr",
            M68000Mnemonic::AndiSr => "andi_sr",
            M68000Mnemonic::Or => "or",
            M68000Mnemonic::Ori => "ori",
            M68000Mnemonic::OriCcr => "ori_ccr",
            M68000Mnemonic::OriSr => "ori_sr",
            M68000Mnemonic::Eor => "eor",
            M68000Mnemonic::Eori => "eori",
            M68000Mnemonic::EoriCcr => "eori_ccr",
            M68000Mnemonic::EoriSr => "eori_sr",
            M68000Mnemonic::Not => "not",
            M68000Mnemonic::Asl => "asl",
            M68000Mnemonic::Asr => "asr",
            M68000Mnemonic::Lsl => "lsl",
            M68000Mnemonic::Lsr => "lsr",
            M68000Mnemonic::Rol => "rol",
            M68000Mnemonic::Ror => "ror",
            M68000Mnemonic::Roxl => "roxl",
            M68000Mnemonic::Roxr => "roxr",
            M68000Mnemonic::Bfchg => "bfchg",
            M68000Mnemonic::Bfclr => "bfclr",
            M68000Mnemonic::Bfexts => "bfexts",
            M68000Mnemonic::Bfextu => "bfextu",
            M68000Mnemonic::Bfffo => "bfffo",
            M68000Mnemonic::Bfins => "bfins",
            M68000Mnemonic::Bfset => "bfset",
            M68000Mnemonic::Bftst => "bftst",
            M68000Mnemonic::Bchg => "bchg",
            M68000Mnemonic::Bclr => "bclr",
            M68000Mnemonic::Bset => "bset",
            M68000Mnemonic::Btst => "btst",
            M68000Mnemonic::Abcd => "abcd",
            M68000Mnemonic::Sbcd => "sbcd",
            M68000Mnemonic::Nbcd => "nbcd",
            M68000Mnemonic::Bra => "bra",
            M68000Mnemonic::Bsr => "bsr",
            M68000Mnemonic::Beq => "beq",
            M68000Mnemonic::Bne => "bne",
            M68000Mnemonic::Bcs => "bcs",
            M68000Mnemonic::Bcc => "bcc",
            M68000Mnemonic::Bhs => "bhs",
            M68000Mnemonic::Blo => "blo",
            M68000Mnemonic::Bmi => "bmi",
            M68000Mnemonic::Bpl => "bpl",
            M68000Mnemonic::Bvs => "bvs",
            M68000Mnemonic::Bvc => "bvc",
            M68000Mnemonic::Bhi => "bhi",
            M68000Mnemonic::Bls => "bls",
            M68000Mnemonic::Bge => "bge",
            M68000Mnemonic::Blt => "blt",
            M68000Mnemonic::Bgt => "bgt",
            M68000Mnemonic::Ble => "ble",
            M68000Mnemonic::Dbt => "dbt",
            M68000Mnemonic::Dbf => "dbf",
            M68000Mnemonic::Dbra => "dbra",
            M68000Mnemonic::Dbeq => "dbeq",
            M68000Mnemonic::Dbne => "dbne",
            M68000Mnemonic::Dbcs => "dbcs",
            M68000Mnemonic::Dbcc => "dbcc",
            M68000Mnemonic::Dbhs => "dbhs",
            M68000Mnemonic::Dblo => "dblo",
            M68000Mnemonic::Dbmi => "dbmi",
            M68000Mnemonic::Dbpl => "dbpl",
            M68000Mnemonic::Dbvs => "dbvs",
            M68000Mnemonic::Dbvc => "dbvc",
            M68000Mnemonic::Dbhi => "dbhi",
            M68000Mnemonic::Dbls => "dbls",
            M68000Mnemonic::Dbge => "dbge",
            M68000Mnemonic::Dblt => "dblt",
            M68000Mnemonic::Dbgt => "dbgt",
            M68000Mnemonic::Dble => "dble",
            M68000Mnemonic::StCc => "st",
            M68000Mnemonic::SfCc => "sf",
            M68000Mnemonic::Seq => "seq",
            M68000Mnemonic::Sne => "sne",
            M68000Mnemonic::Scs => "scs",
            M68000Mnemonic::SccSt => "scc",
            M68000Mnemonic::Shs => "shs",
            M68000Mnemonic::Slo => "slo",
            M68000Mnemonic::Smi => "smi",
            M68000Mnemonic::Spl => "spl",
            M68000Mnemonic::Svs => "svs",
            M68000Mnemonic::Svc => "svc",
            M68000Mnemonic::Shi => "shi",
            M68000Mnemonic::Sls => "sls",
            M68000Mnemonic::Sge => "sge",
            M68000Mnemonic::Slt => "slt",
            M68000Mnemonic::Sgt => "sgt",
            M68000Mnemonic::Sle => "sle",
            M68000Mnemonic::Jmp => "jmp",
            M68000Mnemonic::Jsr => "jsr",
            M68000Mnemonic::Rts => "rts",
            M68000Mnemonic::Rtd => "rtd",
            M68000Mnemonic::Rtr => "rtr",
            M68000Mnemonic::Trap => "trap",
            M68000Mnemonic::Trapv => "trapv",
            M68000Mnemonic::Trapcc => "trapcc",
            M68000Mnemonic::Bkpt => "bkpt",
            M68000Mnemonic::Chk => "chk",
            M68000Mnemonic::Chk2 => "chk2",
            M68000Mnemonic::Rte => "rte",
            M68000Mnemonic::Illegal => "illegal",
            M68000Mnemonic::Nop => "nop",
            M68000Mnemonic::Reset => "reset",
            M68000Mnemonic::Stop => "stop",
            M68000Mnemonic::Halt => "halt",
            M68000Mnemonic::Pulse => "pulse",
            M68000Mnemonic::Wddata => "wddata",
            M68000Mnemonic::Movec => "movec",
            M68000Mnemonic::Moves => "moves",
            M68000Mnemonic::MoveSr => "move_sr",
            M68000Mnemonic::MoveCcr => "move_ccr",
            M68000Mnemonic::MoveUsp => "move_usp",
            M68000Mnemonic::RteExt => "rte_ext",
            M68000Mnemonic::Wdebug => "wdebug",
            M68000Mnemonic::Cinva => "cinva",
            M68000Mnemonic::Cinvl => "cinvl",
            M68000Mnemonic::Cinvp => "cinvp",
            M68000Mnemonic::Cpusha => "cpusha",
            M68000Mnemonic::Cpushl => "cpushl",
            M68000Mnemonic::Cpushp => "cpushp",
            M68000Mnemonic::Pack => "pack",
            M68000Mnemonic::Unpk => "unpk",
            M68000Mnemonic::Cas => "cas",
            M68000Mnemonic::Cas2 => "cas2",
            M68000Mnemonic::Mac => "mac",
            M68000Mnemonic::Macw => "macw",
            M68000Mnemonic::Macl => "macl",
            M68000Mnemonic::Msac => "msac",
            M68000Mnemonic::MoveMac => "move_mac",
            M68000Mnemonic::ClrAcc => "clr_acc",
            M68000Mnemonic::Emac => "emac",
            M68000Mnemonic::Emacw => "emacw",
            M68000Mnemonic::Emsac => "emsac",
            M68000Mnemonic::Emsacw => "emsacw",
            M68000Mnemonic::Stldsr => "stldsr",
            M68000Mnemonic::Byterev => "byterev",
            M68000Mnemonic::Ff1 => "ff1",
            M68000Mnemonic::Sats => "sats",
            M68000Mnemonic::Bitrev => "bitrev",
            M68000Mnemonic::Fmove => "fmove",
            M68000Mnemonic::FmoveCr => "fmove_cr",
            M68000Mnemonic::FmoveSr => "fmove_sr",
            M68000Mnemonic::FmoveIar => "fmove_iar",
            M68000Mnemonic::FmoveS => "fmove.s",
            M68000Mnemonic::FmoveD => "fmove.d",
            M68000Mnemonic::FmoveX => "fmove.x",
            M68000Mnemonic::FmoveP => "fmove.p",
            M68000Mnemonic::FmoveFpcr => "fmove_fpcr",
            M68000Mnemonic::FmoveFpsr => "fmove_fpsr",
            M68000Mnemonic::FmoveFpiar => "fmove_fpiar",
            M68000Mnemonic::Fmovem => "fmovem",
            M68000Mnemonic::FmovemCr => "fmovem_cr",
            M68000Mnemonic::FmovemDr => "fmovem_dr",
            M68000Mnemonic::Fadd => "fadd",
            M68000Mnemonic::FaddS => "fadd.s",
            M68000Mnemonic::FaddD => "fadd.d",
            M68000Mnemonic::FaddX => "fadd.x",
            M68000Mnemonic::FaddP => "fadd.p",
            M68000Mnemonic::Fsub => "fsub",
            M68000Mnemonic::FsubS => "fsub.s",
            M68000Mnemonic::FsubD => "fsub.d",
            M68000Mnemonic::FsubX => "fsub.x",
            M68000Mnemonic::FsubP => "fsub.p",
            M68000Mnemonic::Fmul => "fmul",
            M68000Mnemonic::FmulS => "fmul.s",
            M68000Mnemonic::FmulD => "fmul.d",
            M68000Mnemonic::FmulX => "fmul.x",
            M68000Mnemonic::FmulP => "fmul.p",
            M68000Mnemonic::Fdiv => "fdiv",
            M68000Mnemonic::FdivS => "fdiv.s",
            M68000Mnemonic::FdivD => "fdiv.d",
            M68000Mnemonic::FdivX => "fdiv.x",
            M68000Mnemonic::FdivP => "fdiv.p",
            M68000Mnemonic::Fabs => "fabs",
            M68000Mnemonic::FabsS => "fabs.s",
            M68000Mnemonic::FabsD => "fabs.d",
            M68000Mnemonic::FabsX => "fabs.x",
            M68000Mnemonic::FabsP => "fabs.p",
            M68000Mnemonic::Fneg => "fneg",
            M68000Mnemonic::FnegS => "fneg.s",
            M68000Mnemonic::FnegD => "fneg.d",
            M68000Mnemonic::FnegX => "fneg.x",
            M68000Mnemonic::FnegP => "fneg.p",
            M68000Mnemonic::Fsqrt => "fsqrt",
            M68000Mnemonic::FsqrtS => "fsqrt.s",
            M68000Mnemonic::FsqrtD => "fsqrt.d",
            M68000Mnemonic::FsqrtX => "fsqrt.x",
            M68000Mnemonic::FsqrtP => "fsqrt.p",
            M68000Mnemonic::Fsin => "fsin",
            M68000Mnemonic::Fcos => "fcos",
            M68000Mnemonic::Ftan => "ftan",
            M68000Mnemonic::Fasin => "fasin",
            M68000Mnemonic::Facos => "facos",
            M68000Mnemonic::Fatan => "fatan",
            M68000Mnemonic::Fatanh => "fatanh",
            M68000Mnemonic::Fsinh => "fsinh",
            M68000Mnemonic::Fcosh => "fcosh",
            M68000Mnemonic::Ftanh => "ftanh",
            M68000Mnemonic::Fetox => "fetox",
            M68000Mnemonic::Fetoxm1 => "fetoxm1",
            M68000Mnemonic::Ftentox => "ftentox",
            M68000Mnemonic::Ftwotox => "ftwotox",
            M68000Mnemonic::Flog2 => "flog2",
            M68000Mnemonic::Flog10 => "flog10",
            M68000Mnemonic::Flogn => "flogn",
            M68000Mnemonic::Flognp1 => "flognp1",
            M68000Mnemonic::Fgetexp => "fgetexp",
            M68000Mnemonic::Fgetman => "fgetman",
            M68000Mnemonic::Fmod => "fmod",
            M68000Mnemonic::Frem => "frem",
            M68000Mnemonic::Fscale => "fscale",
            M68000Mnemonic::Fsglmul => "fsglmul",
            M68000Mnemonic::Fsgldiv => "fsgldiv",
            M68000Mnemonic::Fcmp => "fcmp",
            M68000Mnemonic::Ftst => "ftst",
            M68000Mnemonic::Fbeq => "fbeq",
            M68000Mnemonic::Fbne => "fbne",
            M68000Mnemonic::Fbgt => "fbgt",
            M68000Mnemonic::Fbge => "fbge",
            M68000Mnemonic::Fblt => "fblt",
            M68000Mnemonic::Fble => "fble",
            M68000Mnemonic::Fbgl => "fbgl",
            M68000Mnemonic::Fbgle => "fbgle",
            M68000Mnemonic::Fbngl => "fbngl",
            M68000Mnemonic::Fbngle => "fbngle",
            M68000Mnemonic::Fbogt => "fbogt",
            M68000Mnemonic::Fboge => "fboge",
            M68000Mnemonic::Fbolt => "fbolt",
            M68000Mnemonic::Fbole => "fbole",
            M68000Mnemonic::Fbor => "fbor",
            M68000Mnemonic::Fbun => "fbun",
            M68000Mnemonic::Fbueq => "fbueq",
            M68000Mnemonic::Fbugt => "fbugt",
            M68000Mnemonic::Fbuge => "fbuge",
            M68000Mnemonic::Fbult => "fbult",
            M68000Mnemonic::Fbule => "fbule",
            M68000Mnemonic::FbneOr => "fbne_or",
            M68000Mnemonic::Fseq => "fseq",
            M68000Mnemonic::Fsne => "fsne",
            M68000Mnemonic::Fsgt => "fsgt",
            M68000Mnemonic::Fsge => "fsge",
            M68000Mnemonic::Fslt => "fslt",
            M68000Mnemonic::Fsle => "fsle",
            M68000Mnemonic::Fsgl => "fsgl",
            M68000Mnemonic::Fsgle => "fsgle",
            M68000Mnemonic::Fsngl => "fsngl",
            M68000Mnemonic::Fsngle => "fsngle",
            M68000Mnemonic::Fsogt => "fsogt",
            M68000Mnemonic::Fsoge => "fsoge",
            M68000Mnemonic::Fsolt => "fsolt",
            M68000Mnemonic::Fsole => "fsole",
            M68000Mnemonic::Fsor => "fsor",
            M68000Mnemonic::Fsun => "fsun",
            M68000Mnemonic::Fsueq => "fsueq",
            M68000Mnemonic::Fsugt => "fsugt",
            M68000Mnemonic::Fsuge => "fsuge",
            M68000Mnemonic::Fsult => "fsult",
            M68000Mnemonic::Fsule => "fsule",
            M68000Mnemonic::FsneOr => "fsne_or",
            M68000Mnemonic::Fint => "fint",
            M68000Mnemonic::Fintrz => "fintrz",
            M68000Mnemonic::FintS => "fint.s",
            M68000Mnemonic::FintD => "fint.d",
            M68000Mnemonic::FintX => "fint.x",
            M68000Mnemonic::FintP => "fint.p",
            M68000Mnemonic::Fsubb => "fsubb",
            M68000Mnemonic::Faddb => "faddb",
            M68000Mnemonic::Fmulb => "fmulb",
            M68000Mnemonic::Fdivb => "fdivb",
            M68000Mnemonic::Fmul3 => "fmul3",
            M68000Mnemonic::Fnop => "fnop",
            M68000Mnemonic::Move16Ax => "move16_ax",
            M68000Mnemonic::Move16Al => "move16_al",
            M68000Mnemonic::MoveaPc => "movea_pc",
            M68000Mnemonic::NopPlain => "nop",
            M68000Mnemonic::FsinS => "fsin.s",
            M68000Mnemonic::FsinD => "fsin.d",
            M68000Mnemonic::FsinX => "fsin.x",
            M68000Mnemonic::FsinP => "fsin.p",
            M68000Mnemonic::FcosS => "fcos.s",
            M68000Mnemonic::FcosD => "fcos.d",
            M68000Mnemonic::FcosX => "fcos.x",
            M68000Mnemonic::FcosP => "fcos.p",
            M68000Mnemonic::FtanS => "ftan.s",
            M68000Mnemonic::FtanD => "ftan.d",
            M68000Mnemonic::FtanX => "ftan.x",
            M68000Mnemonic::FtanP => "ftan.p",
        }
    }
}

// ============================================================================
// Conversion to common InstructionMnemonic
// ============================================================================

pub fn all_m68000_mnemonics() -> Vec<InstructionMnemonic> {
    use M68000Mnemonic::*;
    let variants = [
        Move, Movea, Moveq, Movem, Movep, Move16, Mov3q,
        Lea, Pea, Link, Unlk, Exg, Swap,
        Add, Adda, Addi, Addq, Addx,
        Sub, Suba, Subi, Subq, Subx,
        Muls, Mulu, Divs, Divu,
        Divsl, Divul, MulsL, MuluL,
        Neg, Negx, Clr,
        Cmp, Cmpa, Cmpi, Cmp2, Cmpm, Tst, Tas,
        Ext, Extb,
        And, Andi, AndiCcr, AndiSr,
        Or, Ori, OriCcr, OriSr,
        Eor, Eori, EoriCcr, EoriSr, Not,
        Asl, Asr, Lsl, Lsr, Rol, Ror, Roxl, Roxr,
        Bfchg, Bfclr, Bfexts, Bfextu, Bfffo, Bfins, Bfset, Bftst,
        Bchg, Bclr, Bset, Btst,
        Abcd, Sbcd, Nbcd,
        Bra, Bsr,
        Beq, Bne, Bcs, Bcc, Bhs, Blo,
        Bmi, Bpl, Bvs, Bvc,
        Bhi, Bls, Bge, Blt, Bgt, Ble,
        Dbt, Dbf, Dbra,
        Dbeq, Dbne, Dbcs, Dbcc, Dbhs, Dblo,
        Dbmi, Dbpl, Dbvs, Dbvc,
        Dbhi, Dbls, Dbge, Dblt, Dbgt, Dble,
        StCc, SfCc, Seq, Sne, Scs, SccSt, Shs, Slo,
        Smi, Spl, Svs, Svc, Shi, Sls, Sge, Slt, Sgt, Sle,
        Jmp, Jsr, Rts, Rtd, Rtr,
        Trap, Trapv, Trapcc,
        Bkpt, Chk, Chk2,
        Rte, Illegal, Nop,
        Reset, Stop, Halt, Pulse,
        Movec, Moves, MoveSr, MoveCcr, MoveUsp,
        RteExt, Wdebug,
        Cinva, Cinvl, Cinvp,
        Cpusha, Cpushl, Cpushp,
        Pack, Unpk, Cas, Cas2,
        Mac, Macw, Macl, Msac, MoveMac, ClrAcc,
        Emac, Emacw, Emsac, Emsacw,
        Stldsr, Byterev, Ff1, Sats, Bitrev,
        Fmove, FmoveCr, FmoveSr, FmoveIar,
        FmoveS, FmoveD, FmoveX, FmoveP,
        FmoveFpcr, FmoveFpsr, FmoveFpiar,
        Fmovem, FmovemCr, FmovemDr,
        Fadd, FaddS, FaddD, FaddX, FaddP,
        Fsub, FsubS, FsubD, FsubX, FsubP,
        Fmul, FmulS, FmulD, FmulX, FmulP,
        Fdiv, FdivS, FdivD, FdivX, FdivP,
        Fabs, FabsS, FabsD, FabsX, FabsP,
        Fneg, FnegS, FnegD, FnegX, FnegP,
        Fsqrt, FsqrtS, FsqrtD, FsqrtX, FsqrtP,
        Fsin, FsinS, FsinD, FsinX, FsinP,
        Fcos, FcosS, FcosD, FcosX, FcosP,
        Ftan, FtanS, FtanD, FtanX, FtanP,
        Fasin, Facos, Fatan, Fatanh,
        Fsinh, Fcosh, Ftanh,
        Fetox, Fetoxm1, Ftentox, Ftwotox,
        Flog2, Flog10, Flogn, Flognp1,
        Fgetexp, Fgetman, Fmod, Frem, Fscale,
        Fsglmul, Fsgldiv,
        Fcmp, Ftst,
        Fbeq, Fbne, Fbgt, Fbge, Fblt, Fble,
        Fbgl, Fbgle, Fbngl, Fbngle,
        Fbogt, Fboge, Fbolt, Fbole,
        Fbor, Fbun, Fbueq, Fbugt, Fbuge, Fbult, Fbule, FbneOr,
        Fseq, Fsne, Fsgt, Fsge, Fslt, Fsle,
        Fsgl, Fsgle, Fsngl, Fsngle,
        Fsogt, Fsoge, Fsolt, Fsole,
        Fsor, Fsun, Fsueq, Fsugt, Fsuge, Fsult, Fsule, FsneOr,
        Fint, Fintrz, FintS, FintD, FintX, FintP,
        Fsubb, Faddb, Fmulb, Fdivb, Fmul3,
        Fnop, Move16Ax, Move16Al, MoveaPc,
        NopPlain,
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

pub struct M68000Module;

impl ProcessorModule for M68000Module {
    fn name() -> &'static str {
        PROCESSOR_NAME
    }

    fn registers() -> RegisterBank {
        let m68k_bank = M68000RegisterBank::new_68060();
        let mut bank = RegisterBank::new();
        for reg in m68k_bank.iter() {
            bank.add(reg.clone());
        }
        bank
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new("m68000:BE:32:68000", "Motorola 68000", "68000", Endian::Big, 32),
            Language::new("m68000:BE:32:68010", "Motorola 68010", "68010", Endian::Big, 32),
            Language::new("m68000:BE:32:68020", "Motorola 68020", "68020", Endian::Big, 32),
            Language::new("m68000:BE:32:68030", "Motorola 68030 (MMU)", "68030", Endian::Big, 32),
            Language::new("m68000:BE:32:68040", "Motorola 68040 (FPU+MMU)", "68040", Endian::Big, 32),
            Language::new("m68000:BE:32:68060", "Motorola 68060 (Superscalar)", "68060", Endian::Big, 32),
            Language::new("m68000:BE:32:ColdFire_V1", "ColdFire V1", "CFv1", Endian::Big, 32),
            Language::new("m68000:BE:32:ColdFire_V2", "ColdFire V2 (MAC)", "CFv2", Endian::Big, 32),
            Language::new("m68000:BE:32:ColdFire_V3", "ColdFire V3", "CFv3", Endian::Big, 32),
            Language::new("m68000:BE:32:ColdFire_V4", "ColdFire V4 (EMAC)", "CFv4", Endian::Big, 32),
            Language::new("m68000:BE:32:ColdFire_V5", "ColdFire V5", "CFv5", Endian::Big, 32),
            Language::new("m68000:BE:32:CPU32", "CPU32 (68300 family)", "CPU32", Endian::Big, 32),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> {
        all_m68000_mnemonics()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        assert_eq!(M68000Module::name(), "Motorola 68000 Family");
    }

    #[test]
    fn test_register_count() {
        let bank = M68000RegisterBank::new_68060();
        assert!(bank.len() > 80, "M68000 bank should have >80 registers, got {}", bank.len());
    }

    #[test]
    fn test_data_registers() {
        let bank = M68000RegisterBank::new_68060();
        for i in 0..8 {
            assert!(bank.get(&format!("D{}", i)).is_some());
            assert_eq!(bank.get(&format!("D{}", i)).unwrap().bit_size, 32);
        }
    }

    #[test]
    fn test_data_sub_registers() {
        let bank = M68000RegisterBank::new_68060();
        for i in 0..8 {
            let dw = bank.get(&format!("D{}.W", i)).unwrap();
            assert_eq!(dw.bit_size, 16);
            assert_eq!(dw.parent.as_deref(), Some(format!("D{}", i).as_str()));
            let db = bank.get(&format!("D{}.B", i)).unwrap();
            assert_eq!(db.bit_size, 8);
            assert_eq!(db.parent.as_deref(), Some(format!("D{}", i).as_str()));
        }
    }

    #[test]
    fn test_address_registers() {
        let bank = M68000RegisterBank::new_68060();
        for i in 0..8 {
            assert!(bank.get(&format!("A{}", i)).is_some());
        }
    }

    #[test]
    fn test_special_registers() {
        let bank = M68000RegisterBank::new_68060();
        for name in ["PC", "SR", "SSP", "VBR", "SFC", "DFC", "CACR", "CAAR",
                     "USP", "ISP", "MSP"] {
            assert!(bank.get(name).is_some(), "Missing {}", name);
        }
    }

    #[test]
    fn test_sr_flags() {
        let bank = M68000RegisterBank::new_68060();
        for name in ["C", "V", "Z", "N", "X", "I0", "I1", "I2", "S", "T0", "T1"] {
            assert!(bank.get(name).is_some(), "Missing SR flag {}", name);
        }
        let c = bank.get("C").unwrap();
        assert_eq!(c.parent.as_deref(), Some("SR"));
        assert_eq!(c.lsb, 0);
        let n = bank.get("N").unwrap();
        assert_eq!(n.lsb, 3);
        let s = bank.get("S").unwrap();
        assert_eq!(s.lsb, 13);
    }

    #[test]
    fn test_mmu_registers() {
        let bank = M68000RegisterBank::new_68060();
        for name in ["TC", "TT0", "TT1", "SRP", "CRP", "MMUSR"] {
            assert!(bank.get(name).is_some(), "Missing MMU register {}", name);
        }
    }

    #[test]
    fn test_bus_control_registers() {
        let bank = M68000RegisterBank::new_68060();
        for name in ["ITT0", "ITT1", "DTT0", "DTT1", "URP"] {
            assert!(bank.get(name).is_some(), "Missing bus control {}", name);
        }
    }

    #[test]
    fn test_fpu_registers() {
        let bank = M68000RegisterBank::new_68060();
        for i in 0..8 {
            assert!(bank.get(&format!("FP{}", i)).is_some(), "Missing FP{}", i);
            assert_eq!(bank.get(&format!("FP{}", i)).unwrap().bit_size, 80);
        }
        for name in ["FPSR", "FPCR", "FPIAR"] {
            assert!(bank.get(name).is_some(), "Missing FPU ctl {}", name);
        }
    }

    #[test]
    fn test_fpsr_flags() {
        let bank = M68000RegisterBank::new_68060();
        for name in ["FP_N", "FP_Z", "FP_INF", "FP_NAN",
                     "BSUN", "SNAN", "OPERR", "OVFL", "UNFL", "DZ",
                     "INEX2", "INEX1", "FPCC"] {
            assert!(bank.get(name).is_some(), "Missing FPSR bit {}", name);
        }
    }

    #[test]
    fn test_coldfire_registers() {
        let bank = M68000RegisterBank::new_68060();
        for name in ["MACSR", "MASK", "ACC", "MACEXT",
                     "EMAC0", "EMAC1", "EMAC2", "EMAC3",
                     "EMAC_STATUS", "EMAC_EXT", "CCR_CF", "RAMBAR"] {
            assert!(bank.get(name).is_some(), "Missing ColdFire register {}", name);
        }
    }

    #[test]
    fn test_register_sizes() {
        let bank = M68000RegisterBank::new_68060();
        assert_eq!(bank.get("D0").unwrap().bit_size, 32);
        assert_eq!(bank.get("SR").unwrap().bit_size, 16);
        assert_eq!(bank.get("CCR").unwrap().bit_size, 8);
        assert_eq!(bank.get("SFC").unwrap().bit_size, 3);
        assert_eq!(bank.get("FP0").unwrap().bit_size, 80);
    }

    #[test]
    fn test_mnemonic_count() {
        let mnemonics = all_m68000_mnemonics();
        assert!(mnemonics.len() >= 200, "Expected >=200, got {}", mnemonics.len());
    }

    #[test]
    fn test_key_mnemonics_exist() {
        let mnemonics = all_m68000_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["move", "add", "sub", "muls", "divs", "and", "or", "eor", "not",
                  "asl", "asr", "lsl", "lsr", "rol", "ror",
                  "bra", "bsr", "beq", "bne", "bcs", "bcc", "bmi", "bpl",
                  "jmp", "jsr", "rts", "rte",
                  "trap", "nop", "illegal",
                  "link", "unlk", "lea", "pea",
                  "bfchg", "bfclr", "bfset", "bfins",
                  "bchg", "bclr", "bset", "btst",
                  "cas", "cas2",
                  "fadd", "fsub", "fmul", "fdiv", "fsqrt",
                  "fmove", "fcmp", "ftst",
                  "mac", "emac", "byterev", "ff1"] {
            assert!(texts.contains(&m), "Missing key mnemonic: {}", m);
        }
    }

    #[test]
    fn test_dbcc_mnemonics() {
        let mnemonics = all_m68000_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["dbt", "dbf", "dbra", "dbeq", "dbne", "dbmi", "dbpl"] {
            assert!(texts.contains(&m), "Missing DBcc mnemonic: {}", m);
        }
    }

    #[test]
    fn test_scc_mnemonics() {
        let mnemonics = all_m68000_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["st", "sf", "seq", "sne", "sge", "slt", "sgt", "sle"] {
            assert!(texts.contains(&m), "Missing Scc mnemonic: {}", m);
        }
    }

    #[test]
    fn test_fpu_branch_mnemonics() {
        let mnemonics = all_m68000_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["fbeq", "fbne", "fbgt", "fbge", "fblt", "fble", "fbun", "fbor"] {
            assert!(texts.contains(&m), "Missing FP branch mnemonic: {}", m);
        }
    }

    #[test]
    fn test_processor_module_interface() {
        assert_eq!(M68000Module::name(), "Motorola 68000 Family");
        let regs = M68000Module::registers();
        assert!(!regs.is_empty());
        let langs = M68000Module::languages();
        assert!(langs.len() >= 7);
        let insts = M68000Module::instructions();
        assert!(insts.len() >= 200);
    }

    #[test]
    fn test_variant_features() {
        assert!(!M68kVariant::MC68000.has_fpu());
        assert!(M68kVariant::MC68040.has_fpu());
        assert!(M68kVariant::MC68060.has_fpu());
        assert!(!M68kVariant::MC68000.has_mmu());
        assert!(M68kVariant::MC68030.has_mmu());
        assert!(!M68kVariant::MC68000.has_bitfield());
        assert!(M68kVariant::MC68020.has_bitfield());
    }

    #[test]
    fn test_sr_bit_values() {
        assert_eq!(SrBit::C.mask(), 1);
        assert_eq!(SrBit::S.mask(), 1u16 << 13);
        assert_eq!(SrBit::T1.mask(), 1u16 << 15);
    }
}
