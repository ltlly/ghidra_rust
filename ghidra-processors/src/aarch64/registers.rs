//! AArch64 Register Definitions
//!
//! Defines the complete register set for AArch64 (ARM 64-bit) processors.
//!
//! Register space layout (offsets):
//! - General-purpose X0-X30: 0x0000 - 0x00F0
//! - W0-W30 (32-bit alias):  0x0100 - 0x0178
//! - XZR / WZR:              0x00F8 / 0x017C
//! - SP:                     0x0180 - 0x0187
//! - PSTATE:                 0x0190 - 0x0197
//! - NZCV:                   0x01A0 - 0x01A3
//! - FPCR:                   0x01B0 - 0x01B3
//! - FPSR:                   0x01B4 - 0x01B7
//! - SIMD/FP V0-V31:         0x0200 - 0x03FF
//! - System registers:       0x1000 - 0x1FFF
//!
//! AArch64 provides 31 general-purpose 64-bit registers (X0-X30) with:
//! - W0-W30: 32-bit aliases (lower half of X registers)
//! - XZR/WZR: Zero register (aliases X31/W31 in many contexts)
//! - SP: Stack pointer (not a GPR, accessed via special encodings)
//! - PC: Program Counter (not directly accessible as a GPR)
//! - X29 = FP (Frame Pointer), X30 = LR (Link Register)
//! - PSTATE: Processor state (replaces CPSR, with expanded flags)
//!
//! SIMD/FP:
//! - V0-V31: 128-bit registers with B/H/S/D/Q views (8/16/32/64/128-bit)
//!
//! System registers: SPSel, CurrentEL, DAIF, NZCV, FPCR, FPSR,
//! TPIDR_EL0, TPIDRRO_EL0, TPIDR_EL1, TTBR0_EL1, TTBR1_EL1,
//! TCR_EL1, SCTLR_EL1, VBAR_EL1, ESR_EL1, FAR_EL1, PAR_EL1,
//! MAIR_EL1, AMAIR_EL1, CONTEXTIDR_EL1

use crate::common::Register;

// ============================================================================
// Register Offsets
// ============================================================================

const GP64_OFFSET_BASE: u64 = 0x0000;
const GP32_OFFSET_BASE: u64 = 0x0100;
const SP_OFFSET: u64 = 0x0180;
const PSTATE_OFFSET: u64 = 0x0190;
const NZCV_OFFSET: u64 = 0x01A0;
const FPCR_OFFSET: u64 = 0x01B0;
const FPSR_OFFSET: u64 = 0x01B4;
const SIMD_OFFSET_BASE: u64 = 0x0200;
const SYSREG_OFFSET_BASE: u64 = 0x1000;

// ============================================================================
// PSTATE Flags
// ============================================================================

/// PSTATE (Processor State) field definitions.
///
/// PSTATE replaces the ARM32 CPSR in AArch64. It includes condition flags
/// (NZCV), exception mask bits (DAIF), and execution state control bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PstateField {
    /// Negative condition flag
    N,
    /// Zero condition flag
    Z,
    /// Carry condition flag
    C,
    /// Overflow condition flag
    V,
    /// Debug exception mask (EL0)
    D,
    /// Asynchronous abort mask (SError)
    A,
    /// IRQ interrupt mask
    I,
    /// FIQ interrupt mask
    F,
    /// Software step (single-step) enabled
    SS,
    /// Illegal execution state (PSTATE.IL)
    IL,
    /// Branch target identification type (BTYPE[1:0])
    BTYPE,
    /// Exception level (EL0-EL3)
    EL,
    /// Not register width: 0 = AArch64, 1 = AArch32
    NRW,
    /// Stack pointer selection: 0 = SP_EL0, 1 = SP_ELx
    SPSEL,
    /// Privileged execute-never (UXN/PXN controls)
    PAN,
    /// User access override
    UAO,
    /// Tag check override (MTE)
    TCO,
    /// Speculative Store Bypass Safe
    SSBS,
    /// Branch Target Identification
    BTI,
}

impl PstateField {
    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            PstateField::N => "N",
            PstateField::Z => "Z",
            PstateField::C => "C",
            PstateField::V => "V",
            PstateField::D => "D",
            PstateField::A => "A",
            PstateField::I => "I",
            PstateField::F => "F",
            PstateField::SS => "SS",
            PstateField::IL => "IL",
            PstateField::BTYPE => "BTYPE",
            PstateField::EL => "EL",
            PstateField::NRW => "nRW",
            PstateField::SPSEL => "SPSel",
            PstateField::PAN => "PAN",
            PstateField::UAO => "UAO",
            PstateField::TCO => "TCO",
            PstateField::SSBS => "SSBS",
            PstateField::BTI => "BTI",
        }
    }

    /// The field bit position in NZCV (condition flags subset).
    pub fn nzcv_bit(&self) -> Option<u8> {
        match self {
            PstateField::N => Some(31),
            PstateField::Z => Some(30),
            PstateField::C => Some(29),
            PstateField::V => Some(28),
            _ => None,
        }
    }

    /// The DAIF mask bit position (exception mask subset).
    pub fn daif_bit(&self) -> Option<u8> {
        match self {
            PstateField::D => Some(9),
            PstateField::A => Some(8),
            PstateField::I => Some(7),
            PstateField::F => Some(6),
            _ => None,
        }
    }
}

// ============================================================================
// AARCH64 Register Bank
// ============================================================================

/// The complete register bank for an AArch64 processor.
///
/// Contains all GPRs (X/W), SIMD/FP registers (V with B/H/S/D/Q views),
/// PSTATE, system registers.
#[derive(Debug, Clone)]
pub struct Aarch64RegisterBank {
    /// General-purpose registers X0-X30 (64-bit).
    pub x_regs: [Register; 31],
    /// General-purpose register aliases W0-W30 (32-bit, low half of X).
    pub w_regs: [Register; 31],
    /// Zero register (64-bit view, alias of XZR).
    pub xzr: Register,
    /// Zero register (32-bit view, alias of WZR).
    pub wzr: Register,
    /// Stack pointer (64-bit).
    pub sp: Register,
    /// Stack pointer alias (WSP, 32-bit view of SP).
    pub wsp: Register,
    /// Program counter.
    pub pc: Register,
    /// Frame pointer alias (X29).
    pub fp: Register,
    /// Link register alias (X30).
    pub lr: Register,
    /// Processor state (PSTATE).
    pub pstate: Register,
    /// NZCV condition flags (directly accessible as system register).
    pub nzcv: Register,
    /// Floating-point control register.
    pub fpcr: Register,
    /// Floating-point status register.
    pub fpsr: Register,
    /// SIMD/FP registers V0-V31 (128-bit).
    pub v_regs: [Register; 32],
    /// SIMD/FP byte view B0-B31 (8-bit).
    pub b_regs: [Register; 32],
    /// SIMD/FP halfword view H0-H31 (16-bit).
    pub h_regs: [Register; 32],
    /// SIMD/FP single-precision view S0-S31 (32-bit).
    pub s_regs: [Register; 32],
    /// SIMD/FP double-precision view D0-D31 (64-bit).
    pub d_regs: [Register; 32],
    /// SIMD/FP quad-precision view Q0-Q31 (128-bit).
    pub q_regs: [Register; 32],
    /// System registers (by name).
    pub system_registers: Vec<Register>,
    /// All registers indexed by name for fast lookup.
    register_by_name: std::collections::HashMap<String, Register>,
}

impl Aarch64RegisterBank {
    /// Create the full AArch64 register bank (ARMv8-A base).
    pub fn new_armv8a() -> Self {
        // ------------------------------------------------------------------
        // General-purpose registers X0-X30 (64-bit)
        // ------------------------------------------------------------------
        let x_regs: [Register; 31] = std::array::from_fn(|i| {
            Register::new(&format!("X{}", i), 64, GP64_OFFSET_BASE + (i as u64) * 8)
        });

        // ------------------------------------------------------------------
        // W0-W30 (32-bit aliases, lower half of X registers)
        // ------------------------------------------------------------------
        let w_regs: [Register; 31] = std::array::from_fn(|i| {
            Register::sub_register(
                &format!("W{}", i),
                32,
                GP32_OFFSET_BASE + (i as u64) * 4,
                &format!("X{}", i),
                0,
            )
        });

        // ------------------------------------------------------------------
        // Zero registers XZR and WZR (conceptually always read as 0)
        // ------------------------------------------------------------------
        let xzr = Register::new("XZR", 64, GP64_OFFSET_BASE + 31 * 8);
        let wzr = Register::sub_register("WZR", 32, GP32_OFFSET_BASE + 31 * 4, "XZR", 0);

        // ------------------------------------------------------------------
        // Stack pointer (64-bit, not a GPR)
        // ------------------------------------------------------------------
        let sp = Register::new("SP", 64, SP_OFFSET);
        let wsp = Register::sub_register("WSP", 32, SP_OFFSET, "SP", 0);

        // ------------------------------------------------------------------
        // Program counter, frame pointer, link register
        // ------------------------------------------------------------------
        let pc = Register::new("PC", 64, GP64_OFFSET_BASE + 32 * 8);
        let fp = Register::new("FP", 64, GP64_OFFSET_BASE + 29 * 8);
        let lr = Register::new("LR", 64, GP64_OFFSET_BASE + 30 * 8);

        // ------------------------------------------------------------------
        // PSTATE (64-bit virtual register holding all state fields)
        // ------------------------------------------------------------------
        let pstate = Register::new("PSTATE", 64, PSTATE_OFFSET);

        // ------------------------------------------------------------------
        // NZCV condition flags (32-bit system register, accessible via MRS/MSR)
        // ------------------------------------------------------------------
        let nzcv = Register::new("NZCV", 32, NZCV_OFFSET);

        // ------------------------------------------------------------------
        // FPCR and FPSR (32-bit each)
        // ------------------------------------------------------------------
        let fpcr = Register::new("FPCR", 32, FPCR_OFFSET);
        let fpsr = Register::new("FPSR", 32, FPSR_OFFSET);

        // ------------------------------------------------------------------
        // SIMD/FP registers V0-V31 (128-bit)
        // ------------------------------------------------------------------
        let v_regs: [Register; 32] = std::array::from_fn(|i| {
            Register::new(&format!("V{}", i), 128, SIMD_OFFSET_BASE + (i as u64) * 16)
        });

        // ------------------------------------------------------------------
        // SIMD/FP element views:
        //   B0-B31 = V0-V31[7:0]     (8-bit, byte)
        //   H0-H31 = V0-V31[15:0]    (16-bit, halfword)
        //   S0-S31 = V0-V31[31:0]    (32-bit, single)
        //   D0-D31 = V0-V31[63:0]    (64-bit, double)
        //   Q0-Q31 = V0-V31[127:0]   (128-bit, quad)
        // ------------------------------------------------------------------
        let b_regs: [Register; 32] = std::array::from_fn(|i| {
            Register::sub_register(
                &format!("B{}", i),
                8,
                SIMD_OFFSET_BASE + (i as u64) * 16,
                &format!("V{}", i),
                0,
            )
        });

        let h_regs: [Register; 32] = std::array::from_fn(|i| {
            Register::sub_register(
                &format!("H{}", i),
                16,
                SIMD_OFFSET_BASE + (i as u64) * 16 + 2,
                &format!("V{}", i),
                0,
            )
        });

        let s_regs: [Register; 32] = std::array::from_fn(|i| {
            Register::sub_register(
                &format!("S{}", i),
                32,
                SIMD_OFFSET_BASE + (i as u64) * 16 + 4,
                &format!("V{}", i),
                0,
            )
        });

        let d_regs: [Register; 32] = std::array::from_fn(|i| {
            Register::sub_register(
                &format!("D{}", i),
                64,
                SIMD_OFFSET_BASE + (i as u64) * 16 + 8,
                &format!("V{}", i),
                0,
            )
        });

        let q_regs: [Register; 32] = std::array::from_fn(|i| {
            Register::sub_register(
                &format!("Q{}", i),
                128,
                SIMD_OFFSET_BASE + (i as u64) * 16 + 16,
                &format!("V{}", i),
                0,
            )
        });

        // ------------------------------------------------------------------
        // System registers
        // ------------------------------------------------------------------
        let system_registers = vec![
            Register::new("CurrentEL", 64, SYSREG_OFFSET_BASE + 0x00),
            Register::new("SPSel", 64, SYSREG_OFFSET_BASE + 0x08),
            Register::new("DAIF", 64, SYSREG_OFFSET_BASE + 0x10),
            Register::new("NZCV_sys", 32, SYSREG_OFFSET_BASE + 0x18),
            Register::new("FPCR_sys", 32, SYSREG_OFFSET_BASE + 0x20),
            Register::new("FPSR_sys", 32, SYSREG_OFFSET_BASE + 0x28),
            Register::new("TPIDR_EL0", 64, SYSREG_OFFSET_BASE + 0x30),
            Register::new("TPIDRRO_EL0", 64, SYSREG_OFFSET_BASE + 0x38),
            Register::new("TPIDR_EL1", 64, SYSREG_OFFSET_BASE + 0x40),
            Register::new("TTBR0_EL1", 64, SYSREG_OFFSET_BASE + 0x48),
            Register::new("TTBR1_EL1", 64, SYSREG_OFFSET_BASE + 0x50),
            Register::new("TCR_EL1", 64, SYSREG_OFFSET_BASE + 0x58),
            Register::new("SCTLR_EL1", 64, SYSREG_OFFSET_BASE + 0x60),
            Register::new("VBAR_EL1", 64, SYSREG_OFFSET_BASE + 0x68),
            Register::new("ESR_EL1", 64, SYSREG_OFFSET_BASE + 0x70),
            Register::new("FAR_EL1", 64, SYSREG_OFFSET_BASE + 0x78),
            Register::new("PAR_EL1", 64, SYSREG_OFFSET_BASE + 0x80),
            Register::new("MAIR_EL1", 64, SYSREG_OFFSET_BASE + 0x88),
            Register::new("AMAIR_EL1", 64, SYSREG_OFFSET_BASE + 0x90),
            Register::new("CONTEXTIDR_EL1", 64, SYSREG_OFFSET_BASE + 0x98),
            Register::new("CNTVCT_EL0", 64, SYSREG_OFFSET_BASE + 0xA0),
            Register::new("CNTFRQ_EL0", 64, SYSREG_OFFSET_BASE + 0xA8),
            Register::new("CNTKCTL_EL1", 64, SYSREG_OFFSET_BASE + 0xB0),
            Register::new("CNTPCT_EL0", 64, SYSREG_OFFSET_BASE + 0xB8),
            Register::new("CPACR_EL1", 64, SYSREG_OFFSET_BASE + 0xC0),
            Register::new("ELR_EL1", 64, SYSREG_OFFSET_BASE + 0xC8),
            Register::new("SP_EL0", 64, SYSREG_OFFSET_BASE + 0xD0),
            Register::new("SP_EL1", 64, SYSREG_OFFSET_BASE + 0xD8),
            Register::new("SPSR_EL1", 64, SYSREG_OFFSET_BASE + 0xE0),
            Register::new("MDSCR_EL1", 64, SYSREG_OFFSET_BASE + 0xE8),
            Register::new("PMCCNTR_EL0", 64, SYSREG_OFFSET_BASE + 0xF0),
            Register::new("PMCR_EL0", 64, SYSREG_OFFSET_BASE + 0xF8),
            Register::new("PMCNTENSET_EL0", 64, SYSREG_OFFSET_BASE + 0x100),
            Register::new("PMOVSCLR_EL0", 64, SYSREG_OFFSET_BASE + 0x108),
            Register::new("PMSELR_EL0", 64, SYSREG_OFFSET_BASE + 0x110),
            Register::new("PMUSERENR_EL0", 64, SYSREG_OFFSET_BASE + 0x118),
            Register::new("PMXEVCNTR_EL0", 64, SYSREG_OFFSET_BASE + 0x120),
            Register::new("PMXEVTYPER_EL0", 64, SYSREG_OFFSET_BASE + 0x128),
            Register::new("MIDR_EL1", 64, SYSREG_OFFSET_BASE + 0x130),
            Register::new("MPIDR_EL1", 64, SYSREG_OFFSET_BASE + 0x138),
            Register::new("ID_AA64PFR0_EL1", 64, SYSREG_OFFSET_BASE + 0x140),
            Register::new("ID_AA64ISAR0_EL1", 64, SYSREG_OFFSET_BASE + 0x148),
            Register::new("ID_AA64MMFR0_EL1", 64, SYSREG_OFFSET_BASE + 0x150),
            Register::new("ACTLR_EL1", 64, SYSREG_OFFSET_BASE + 0x158),
        ];

        // ------------------------------------------------------------------
        // Build the name lookup table
        // ------------------------------------------------------------------
        let mut register_by_name = std::collections::HashMap::new();

        for reg in &x_regs {
            register_by_name.insert(reg.name.clone(), reg.clone());
        }
        for reg in &w_regs {
            register_by_name.insert(reg.name.clone(), reg.clone());
        }
        register_by_name.insert("XZR".to_string(), xzr.clone());
        register_by_name.insert("WZR".to_string(), wzr.clone());
        register_by_name.insert("SP".to_string(), sp.clone());
        register_by_name.insert("WSP".to_string(), wsp.clone());
        register_by_name.insert("PC".to_string(), pc.clone());
        register_by_name.insert("FP".to_string(), fp.clone());
        register_by_name.insert("LR".to_string(), lr.clone());
        register_by_name.insert("PSTATE".to_string(), pstate.clone());
        register_by_name.insert("NZCV".to_string(), nzcv.clone());
        register_by_name.insert("FPCR".to_string(), fpcr.clone());
        register_by_name.insert("FPSR".to_string(), fpsr.clone());

        for reg in &v_regs {
            register_by_name.insert(reg.name.clone(), reg.clone());
        }
        for reg in &b_regs {
            register_by_name.insert(reg.name.clone(), reg.clone());
        }
        for reg in &h_regs {
            register_by_name.insert(reg.name.clone(), reg.clone());
        }
        for reg in &s_regs {
            register_by_name.insert(reg.name.clone(), reg.clone());
        }
        for reg in &d_regs {
            register_by_name.insert(reg.name.clone(), reg.clone());
        }
        for reg in &q_regs {
            register_by_name.insert(reg.name.clone(), reg.clone());
        }
        for reg in &system_registers {
            register_by_name.insert(reg.name.clone(), reg.clone());
        }

        Aarch64RegisterBank {
            x_regs,
            w_regs,
            xzr,
            wzr,
            sp,
            wsp,
            pc,
            fp,
            lr,
            pstate,
            nzcv,
            fpcr,
            fpsr,
            v_regs,
            b_regs,
            h_regs,
            s_regs,
            d_regs,
            q_regs,
            system_registers,
            register_by_name,
        }
    }

    /// Look up a register by its name (case-sensitive, e.g., "X0", "V0", "SP").
    pub fn get(&self, name: &str) -> Option<&Register> {
        self.register_by_name.get(name)
    }

    /// Return all registers that alias (are sub-registers of) the given parent.
    pub fn sub_registers_of(&self, parent_name: &str) -> Vec<&Register> {
        self.register_by_name
            .values()
            .filter(|r| r.parent.as_deref() == Some(parent_name))
            .collect()
    }

    /// Return all top-level registers (those without a parent).
    pub fn top_level_registers(&self) -> Vec<&Register> {
        self.register_by_name
            .values()
            .filter(|r| r.parent.is_none())
            .collect()
    }

    /// Return the total number of defined registers.
    pub fn len(&self) -> usize {
        self.register_by_name.len()
    }

    /// Returns true if the register bank is empty.
    pub fn is_empty(&self) -> bool {
        self.register_by_name.is_empty()
    }

    /// Iterate over all registered registers.
    pub fn iter(&self) -> impl Iterator<Item = &Register> {
        self.register_by_name.values()
    }
}

impl Default for Aarch64RegisterBank {
    fn default() -> Self {
        Self::new_armv8a()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_count() {
        let bank = Aarch64RegisterBank::new_armv8a();
        assert!(
            bank.len() > 100,
            "AArch64 bank should have >100 registers, got {}",
            bank.len()
        );
    }

    #[test]
    fn test_x_registers() {
        let bank = Aarch64RegisterBank::new_armv8a();
        for i in 0..=30 {
            let name = format!("X{}", i);
            assert!(bank.get(&name).is_some(), "Missing register {}", name);
        }
        assert!(bank.get("XZR").is_some());
    }

    #[test]
    fn test_w_registers_aliasing() {
        let bank = Aarch64RegisterBank::new_armv8a();
        for i in 0..=30 {
            let w_name = format!("W{}", i);
            let w = bank.get(&w_name).expect(&format!("Missing {}", w_name));
            assert_eq!(w.parent.as_deref(), Some(format!("X{}", i).as_str()));
            assert_eq!(w.bit_size, 32);
        }
        let wzr = bank.get("WZR").unwrap();
        assert_eq!(wzr.parent.as_deref(), Some("XZR"));
        assert_eq!(wzr.bit_size, 32);
    }

    #[test]
    fn test_special_registers() {
        let bank = Aarch64RegisterBank::new_armv8a();
        assert!(bank.get("SP").is_some());
        assert!(bank.get("WSP").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("FP").is_some());
        assert!(bank.get("LR").is_some());
        assert!(bank.get("PSTATE").is_some());
        assert!(bank.get("NZCV").is_some());
        assert!(bank.get("FPCR").is_some());
        assert!(bank.get("FPSR").is_some());
    }

    #[test]
    fn test_simd_registers() {
        let bank = Aarch64RegisterBank::new_armv8a();
        for i in 0..32 {
            let names = [
                format!("V{}", i),
                format!("B{}", i),
                format!("H{}", i),
                format!("S{}", i),
                format!("D{}", i),
                format!("Q{}", i),
            ];
            for name in &names {
                assert!(bank.get(name).is_some(), "Missing register {}", name);
            }
        }
    }

    #[test]
    fn test_simd_sub_register_aliasing() {
        let bank = Aarch64RegisterBank::new_armv8a();

        let b0 = bank.get("B0").unwrap();
        assert_eq!(b0.parent.as_deref(), Some("V0"));
        assert_eq!(b0.bit_size, 8);

        let h0 = bank.get("H0").unwrap();
        assert_eq!(h0.parent.as_deref(), Some("V0"));
        assert_eq!(h0.bit_size, 16);

        let s0 = bank.get("S0").unwrap();
        assert_eq!(s0.parent.as_deref(), Some("V0"));
        assert_eq!(s0.bit_size, 32);

        let d0 = bank.get("D0").unwrap();
        assert_eq!(d0.parent.as_deref(), Some("V0"));
        assert_eq!(d0.bit_size, 64);

        let q0 = bank.get("Q0").unwrap();
        assert_eq!(q0.parent.as_deref(), Some("V0"));
        assert_eq!(q0.bit_size, 128);
    }

    #[test]
    fn test_system_registers() {
        let bank = Aarch64RegisterBank::new_armv8a();
        let sys_regs = [
            "CurrentEL",
            "SPSel",
            "DAIF",
            "TPIDR_EL0",
            "TPIDRRO_EL0",
            "TPIDR_EL1",
            "TTBR0_EL1",
            "TTBR1_EL1",
            "TCR_EL1",
            "SCTLR_EL1",
            "VBAR_EL1",
            "ESR_EL1",
            "FAR_EL1",
            "PAR_EL1",
            "MAIR_EL1",
            "AMAIR_EL1",
            "CONTEXTIDR_EL1",
            "CNTVCT_EL0",
            "CNTFRQ_EL0",
            "CNTKCTL_EL1",
            "CNTPCT_EL0",
            "CPACR_EL1",
            "ELR_EL1",
            "SP_EL0",
            "SP_EL1",
            "SPSR_EL1",
            "MIDR_EL1",
            "MPIDR_EL1",
            "ID_AA64PFR0_EL1",
            "ID_AA64ISAR0_EL1",
            "ID_AA64MMFR0_EL1",
            "ACTLR_EL1",
        ];
        for name in &sys_regs {
            assert!(bank.get(name).is_some(), "Missing system register {}", name);
        }
    }

    #[test]
    fn test_pstate_flags() {
        assert_eq!(PstateField::N.nzcv_bit(), Some(31));
        assert_eq!(PstateField::Z.nzcv_bit(), Some(30));
        assert_eq!(PstateField::C.nzcv_bit(), Some(29));
        assert_eq!(PstateField::V.nzcv_bit(), Some(28));

        assert_eq!(PstateField::D.daif_bit(), Some(9));
        assert_eq!(PstateField::A.daif_bit(), Some(8));
        assert_eq!(PstateField::I.daif_bit(), Some(7));
        assert_eq!(PstateField::F.daif_bit(), Some(6));

        // Non-DAIF fields should return None for daif_bit
        assert_eq!(PstateField::N.daif_bit(), None);
    }

    #[test]
    fn test_sub_registers_of() {
        let bank = Aarch64RegisterBank::new_armv8a();

        let subs = bank.sub_registers_of("V0");
        let sub_names: Vec<&str> = subs.iter().map(|r| r.name.as_str()).collect();
        assert!(sub_names.contains(&"B0"));
        assert!(sub_names.contains(&"H0"));
        assert!(sub_names.contains(&"S0"));
        assert!(sub_names.contains(&"D0"));
        assert!(sub_names.contains(&"Q0"));
    }

    #[test]
    fn test_top_level_registers() {
        let bank = Aarch64RegisterBank::new_armv8a();
        let top = bank.top_level_registers();
        let top_names: Vec<&str> = top.iter().map(|r| r.name.as_str()).collect();

        assert!(top_names.contains(&"V0"));
        assert!(top_names.contains(&"X0"));
        assert!(!top_names.contains(&"B0"));
        assert!(!top_names.contains(&"H0"));
    }
}
