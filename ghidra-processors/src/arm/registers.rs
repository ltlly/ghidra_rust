//! ARM32 (AArch32) Register Definitions
//!
//! Defines the complete register set for ARMv7-A processors including:
//! - R0-R15 (general purpose, with banked R8-R12 in FIQ mode)
//! - R13=SP, R14=LR, R15=PC (banked across modes)
//! - CPSR and SPSR (banked per exception mode)
//! - VFP/NEON: D0-D31, S0-S31, Q0-Q15, FPSCR
//!
//! Register space layout (offsets):
//! - General-purpose R0-R15:      0x0000 - 0x007C
//! - FIQ banked R8-R12:           0x0034 - 0x0044
//! - Banked SP (R13) per mode:    0x0048 - 0x0064
//! - Banked LR (R14) per mode:    0x0068 - 0x0084
//! - CPSR:                        0x0080 - 0x0083
//! - SPSR banked:                 0x0088 - 0x00BF
//! - VFP D0-D31:                  0x0200 - 0x02FF
//! - VFP S0-S31:                  0x0300 - 0x037F
//! - NEON Q0-Q15:                 0x0400 - 0x047F
//! - FPSCR:                       0x0500 - 0x0503

use crate::common::Register;

// ============================================================================
// Register Offsets
// ============================================================================

const GP_OFFSET_BASE: u64 = 0x0000;
const CPSR_OFFSET: u64 = 0x0080;
const SPSR_OFFSET_BASE: u64 = 0x0088;
const VFP_D_OFFSET_BASE: u64 = 0x0200;
const VFP_S_OFFSET_BASE: u64 = 0x0300;
const NEON_Q_OFFSET_BASE: u64 = 0x0400;
const FPSCR_OFFSET: u64 = 0x0500;

// ============================================================================
// CPSR / SPSR Flag Bits
// ============================================================================

/// Bit positions in the CPSR (Current Program Status Register).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CpsrFlagBit {
    /// Mode field (bits 0-4)
    MODE = 0,
    /// Thumb state bit (bit 5) - T in ARMv6+, part of IT in ARMv7
    T = 5,
    /// FIQ disable (bit 6)
    F = 6,
    /// IRQ disable (bit 7)
    I = 7,
    /// Asynchronous abort disable (bit 8)
    A = 8,
    /// Endianness (bit 9) - E bit
    E = 9,
    /// IT/GE field (bits 10-15 or 16-19 depending on architecture)
    IT_GE = 10,
    /// Greater-than-or-equal flags for SIMD (bits 16-19)
    GE = 16,
    /// IT execution state bits (bits 10-15, 25-26 in ARMv7)
    /// Same bit range as IT_GE — IT is used for execution control, GE for SIMD.
    IT,
    /// Java state bit (bit 24) - deprecated in ARMv7
    J = 24,
    /// DSP saturation (Q) flag (bit 27)
    Q = 27,
    /// Overflow flag (bit 28)
    V = 28,
    /// Carry / borrow / extend flag (bit 29)
    C = 29,
    /// Zero flag (bit 30)
    Z = 30,
    /// Negative / less than flag (bit 31)
    N = 31,
}

impl CpsrFlagBit {
    /// The bit position of this flag in CPSR.
    pub fn bit(&self) -> u32 {
        *self as u32
    }

    /// The bit mask for this flag.
    pub fn mask(&self) -> u32 {
        1u32 << (*self as u32)
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            CpsrFlagBit::MODE => "MODE",
            CpsrFlagBit::T => "T",
            CpsrFlagBit::F => "F",
            CpsrFlagBit::I => "I",
            CpsrFlagBit::A => "A",
            CpsrFlagBit::E => "E",
            CpsrFlagBit::IT_GE => "IT/GE",
            CpsrFlagBit::GE => "GE",
            CpsrFlagBit::IT => "IT",
            CpsrFlagBit::J => "J",
            CpsrFlagBit::Q => "Q",
            CpsrFlagBit::V => "V",
            CpsrFlagBit::C => "C",
            CpsrFlagBit::Z => "Z",
            CpsrFlagBit::N => "N",
        }
    }
}

// ============================================================================
// Processor Modes
// ============================================================================

/// ARM processor operating modes.
///
/// Each mode has its own banked SP, LR, and SPSR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessorMode {
    /// User mode (unprivileged)
    USR = 0b10000,
    /// Fast Interrupt Request mode
    FIQ = 0b10001,
    /// Interrupt Request mode
    IRQ = 0b10010,
    /// Supervisor mode (reset and SWI/SVC)
    SVC = 0b10011,
    /// Monitor mode (Secure Monitor Call)
    MON = 0b10110,
    /// Abort mode (data or prefetch abort)
    ABT = 0b10111,
    /// Hypervisor mode
    HYP = 0b11010,
    /// Undefined instruction mode
    UND = 0b11011,
    /// System mode (privileged, same registers as USR)
    SYS = 0b11111,
}

impl ProcessorMode {
    /// Human-readable mode name.
    pub fn name(&self) -> &'static str {
        match self {
            ProcessorMode::USR => "User",
            ProcessorMode::FIQ => "FIQ",
            ProcessorMode::IRQ => "IRQ",
            ProcessorMode::SVC => "Supervisor",
            ProcessorMode::MON => "Monitor",
            ProcessorMode::ABT => "Abort",
            ProcessorMode::HYP => "Hypervisor",
            ProcessorMode::UND => "Undefined",
            ProcessorMode::SYS => "System",
        }
    }

    /// The 5-bit M field value in CPSR/SPSR.
    pub fn encoding(&self) -> u8 {
        *self as u8
    }

    /// Return the banked register suffixes associated with this mode.
    pub fn banked_suffix(&self) -> &'static str {
        match self {
            ProcessorMode::USR | ProcessorMode::SYS => "usr",
            ProcessorMode::FIQ => "fiq",
            ProcessorMode::IRQ => "irq",
            ProcessorMode::SVC => "svc",
            ProcessorMode::MON => "mon",
            ProcessorMode::ABT => "abt",
            ProcessorMode::HYP => "hyp",
            ProcessorMode::UND => "und",
        }
    }
}

impl std::fmt::Display for ProcessorMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// ARM Register Bank
// ============================================================================

/// The complete register bank for an ARM32 processor.
///
/// Contains all 37 physical registers (GP + banked) plus VFP/NEON registers.
#[derive(Debug, Clone)]
pub struct ArmRegisterBank {
    /// General-purpose registers R0-R12 (unbanked, 16 byte offsets).
    pub general: [Register; 13],
    /// Stack Pointer R13 (banked per mode).
    pub sp_usr: Register,
    pub sp_fiq: Register,
    pub sp_irq: Register,
    pub sp_svc: Register,
    pub sp_mon: Register,
    pub sp_abt: Register,
    pub sp_hyp: Register,
    pub sp_und: Register,
    /// Link Register R14 (banked per mode).
    pub lr_usr: Register,
    pub lr_fiq: Register,
    pub lr_irq: Register,
    pub lr_svc: Register,
    pub lr_mon: Register,
    pub lr_abt: Register,
    pub lr_hyp: Register,
    pub lr_und: Register,
    /// Program Counter R15.
    pub pc: Register,
    /// Current Program Status Register.
    pub cpsr: Register,
    /// Saved Program Status Registers (one per exception mode).
    pub spsr_fiq: Register,
    pub spsr_irq: Register,
    pub spsr_svc: Register,
    pub spsr_abt: Register,
    pub spsr_und: Register,
    pub spsr_mon: Register,
    pub spsr_hyp: Register,
    /// VFP double-precision registers D0-D31 (64-bit).
    pub vfp_d: [Register; 32],
    /// VFP single-precision registers S0-S31 (32-bit), aliased with D registers.
    pub vfp_s: [Register; 32],
    /// NEON quad registers Q0-Q15 (128-bit), aliased with D register pairs.
    pub neon_q: [Register; 16],
    /// Floating-Point Status and Control Register.
    pub fpscr: Register,
    /// Copy of R13 in the current mode (convenience alias for disassembly).
    pub sp: Register,
    /// Copy of R14 in the current mode (convenience alias for disassembly).
    pub lr: Register,
    /// All registers indexed by name for fast lookup.
    register_by_name: std::collections::HashMap<String, Register>,
}

impl ArmRegisterBank {
    /// Create the full ARM32 register bank (ARMv7-A profile with VFP/NEON).
    pub fn new_armv7a() -> Self {
        // ------------------------------------------------------------------
        // General-purpose registers R0-R12 (unbanked, 32-bit)
        // ------------------------------------------------------------------
        let r0 = Register::new("R0", 32, GP_OFFSET_BASE + 0x00);
        let r1 = Register::new("R1", 32, GP_OFFSET_BASE + 0x04);
        let r2 = Register::new("R2", 32, GP_OFFSET_BASE + 0x08);
        let r3 = Register::new("R3", 32, GP_OFFSET_BASE + 0x0C);
        let r4 = Register::new("R4", 32, GP_OFFSET_BASE + 0x10);
        let r5 = Register::new("R5", 32, GP_OFFSET_BASE + 0x14);
        let r6 = Register::new("R6", 32, GP_OFFSET_BASE + 0x18);
        let r7 = Register::new("R7", 32, GP_OFFSET_BASE + 0x1C);
        let r8 = Register::new("R8", 32, GP_OFFSET_BASE + 0x20);
        let r9 = Register::new("R9", 32, GP_OFFSET_BASE + 0x24);
        let r10 = Register::new("R10", 32, GP_OFFSET_BASE + 0x28);
        let r11 = Register::new("R11", 32, GP_OFFSET_BASE + 0x2C);
        let r12 = Register::new("R12", 32, GP_OFFSET_BASE + 0x30);

        // FIQ banked R8-R12
        let r8_fiq = Register::new("R8_FIQ", 32, GP_OFFSET_BASE + 0x34);
        let r9_fiq = Register::new("R9_FIQ", 32, GP_OFFSET_BASE + 0x38);
        let r10_fiq = Register::new("R10_FIQ", 32, GP_OFFSET_BASE + 0x3C);
        let r11_fiq = Register::new("R11_FIQ", 32, GP_OFFSET_BASE + 0x40);
        let r12_fiq = Register::new("R12_FIQ", 32, GP_OFFSET_BASE + 0x44);

        // ------------------------------------------------------------------
        // Stack Pointer R13 (banked per mode, 32-bit)
        // ------------------------------------------------------------------
        let sp_usr = Register::new("SP_USR", 32, GP_OFFSET_BASE + 0x48);
        let sp_fiq = Register::new("SP_FIQ", 32, GP_OFFSET_BASE + 0x4C);
        let sp_irq = Register::new("SP_IRQ", 32, GP_OFFSET_BASE + 0x50);
        let sp_svc = Register::new("SP_SVC", 32, GP_OFFSET_BASE + 0x54);
        let sp_mon = Register::new("SP_MON", 32, GP_OFFSET_BASE + 0x58);
        let sp_abt = Register::new("SP_ABT", 32, GP_OFFSET_BASE + 0x5C);
        let sp_hyp = Register::new("SP_HYP", 32, GP_OFFSET_BASE + 0x60);
        let sp_und = Register::new("SP_UND", 32, GP_OFFSET_BASE + 0x64);

        // Convenience aliases SP (maps to SP_USR by default)
        let sp = Register::new("SP", 32, GP_OFFSET_BASE + 0x48);
        let r13 = Register::new("R13", 32, GP_OFFSET_BASE + 0x48);

        // ------------------------------------------------------------------
        // Link Register R14 (banked per mode, 32-bit)
        // ------------------------------------------------------------------
        let lr_usr = Register::new("LR_USR", 32, GP_OFFSET_BASE + 0x68);
        let lr_fiq = Register::new("LR_FIQ", 32, GP_OFFSET_BASE + 0x6C);
        let lr_irq = Register::new("LR_IRQ", 32, GP_OFFSET_BASE + 0x70);
        let lr_svc = Register::new("LR_SVC", 32, GP_OFFSET_BASE + 0x74);
        let lr_mon = Register::new("LR_MON", 32, GP_OFFSET_BASE + 0x78);
        let lr_abt = Register::new("LR_ABT", 32, GP_OFFSET_BASE + 0x7C);
        let lr_hyp = Register::new("LR_HYP", 32, GP_OFFSET_BASE + 0x80);
        let lr_und = Register::new("LR_UND", 32, GP_OFFSET_BASE + 0x84);

        // Convenience aliases
        let lr = Register::new("LR", 32, GP_OFFSET_BASE + 0x68);
        let r14 = Register::new("R14", 32, GP_OFFSET_BASE + 0x68);

        // ------------------------------------------------------------------
        // Program Counter R15 (32-bit)
        // ------------------------------------------------------------------
        let pc = Register::new("PC", 32, GP_OFFSET_BASE + 0x7C);
        let r15 = Register::new("R15", 32, GP_OFFSET_BASE + 0x7C);

        // ------------------------------------------------------------------
        // CPSR and SPSR registers (32-bit)
        // ------------------------------------------------------------------
        let cpsr = Register::new("CPSR", 32, CPSR_OFFSET);
        let spsr_fiq = Register::new("SPSR_FIQ", 32, SPSR_OFFSET_BASE + 0x00);
        let spsr_irq = Register::new("SPSR_IRQ", 32, SPSR_OFFSET_BASE + 0x04);
        let spsr_svc = Register::new("SPSR_SVC", 32, SPSR_OFFSET_BASE + 0x08);
        let spsr_abt = Register::new("SPSR_ABT", 32, SPSR_OFFSET_BASE + 0x0C);
        let spsr_und = Register::new("SPSR_UND", 32, SPSR_OFFSET_BASE + 0x10);
        let spsr_mon = Register::new("SPSR_MON", 32, SPSR_OFFSET_BASE + 0x14);
        let spsr_hyp = Register::new("SPSR_HYP", 32, SPSR_OFFSET_BASE + 0x18);

        // ------------------------------------------------------------------
        // VFP Double-precision registers D0-D31 (64-bit)
        // ------------------------------------------------------------------
        let vfp_d: [Register; 32] = std::array::from_fn(|i| {
            Register::new(&format!("D{}", i), 64, VFP_D_OFFSET_BASE + (i as u64) * 8)
        });

        // ------------------------------------------------------------------
        // VFP Single-precision registers S0-S31 (32-bit), aliased with D
        //
        // S{2n}   maps to lower half of D{n}
        // S{2n+1} maps to upper half of D{n}
        // ------------------------------------------------------------------
        let vfp_s: [Register; 32] = std::array::from_fn(|i| {
            let d_idx = i / 2;
            let lsb = if i % 2 == 0 { 0 } else { 32 };
            Register::sub_register(
                &format!("S{}", i),
                32,
                VFP_S_OFFSET_BASE + (i as u64) * 4,
                &format!("D{}", d_idx),
                lsb,
            )
        });

        // ------------------------------------------------------------------
        // NEON Quad registers Q0-Q15 (128-bit), aliased with D register pairs
        //
        // Q{n} maps to the concatenation of D{2n} and D{2n+1}
        // ------------------------------------------------------------------
        let neon_q: [Register; 16] = std::array::from_fn(|i| {
            Register::sub_register(
                &format!("Q{}", i),
                128,
                NEON_Q_OFFSET_BASE + (i as u64) * 16,
                &format!("D{}", i * 2),
                0,
            )
        });

        // ------------------------------------------------------------------
        // FPSCR (32-bit)
        // ------------------------------------------------------------------
        let fpscr = Register::new("FPSCR", 32, FPSCR_OFFSET);

        // ------------------------------------------------------------------
        // Build the name lookup table
        // ------------------------------------------------------------------
        let mut register_by_name = std::collections::HashMap::new();

        // R0-R12
        let gp_names = [
            "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12",
        ];
        let gp_regs = [
            &r0, &r1, &r2, &r3, &r4, &r5, &r6, &r7, &r8, &r9, &r10, &r11, &r12,
        ];
        for (name, reg) in gp_names.iter().zip(gp_regs.iter()) {
            register_by_name.insert(name.to_string(), (**reg).clone());
        }

        // FIQ banked R8-R12
        register_by_name.insert("R8_FIQ".to_string(), r8_fiq.clone());
        register_by_name.insert("R9_FIQ".to_string(), r9_fiq.clone());
        register_by_name.insert("R10_FIQ".to_string(), r10_fiq.clone());
        register_by_name.insert("R11_FIQ".to_string(), r11_fiq.clone());
        register_by_name.insert("R12_FIQ".to_string(), r12_fiq.clone());

        // SP aliases
        register_by_name.insert("SP".to_string(), sp.clone());
        register_by_name.insert("R13".to_string(), r13);
        let sp_names = [
            ("SP_USR", &sp_usr),
            ("SP_FIQ", &sp_fiq),
            ("SP_IRQ", &sp_irq),
            ("SP_SVC", &sp_svc),
            ("SP_MON", &sp_mon),
            ("SP_ABT", &sp_abt),
            ("SP_HYP", &sp_hyp),
            ("SP_UND", &sp_und),
        ];
        for (name, reg) in &sp_names {
            register_by_name.insert(name.to_string(), (*reg).clone());
        }

        // LR aliases
        register_by_name.insert("LR".to_string(), lr.clone());
        register_by_name.insert("R14".to_string(), r14);
        let lr_names = [
            ("LR_USR", &lr_usr),
            ("LR_FIQ", &lr_fiq),
            ("LR_IRQ", &lr_irq),
            ("LR_SVC", &lr_svc),
            ("LR_MON", &lr_mon),
            ("LR_ABT", &lr_abt),
            ("LR_HYP", &lr_hyp),
            ("LR_UND", &lr_und),
        ];
        for (name, reg) in &lr_names {
            register_by_name.insert(name.to_string(), (*reg).clone());
        }

        // PC
        register_by_name.insert("PC".to_string(), pc.clone());
        register_by_name.insert("R15".to_string(), r15);

        // CPSR + SPSRs
        register_by_name.insert("CPSR".to_string(), cpsr.clone());
        register_by_name.insert("SPSR_FIQ".to_string(), spsr_fiq.clone());
        register_by_name.insert("SPSR_IRQ".to_string(), spsr_irq.clone());
        register_by_name.insert("SPSR_SVC".to_string(), spsr_svc.clone());
        register_by_name.insert("SPSR_ABT".to_string(), spsr_abt.clone());
        register_by_name.insert("SPSR_UND".to_string(), spsr_und.clone());
        register_by_name.insert("SPSR_MON".to_string(), spsr_mon.clone());
        register_by_name.insert("SPSR_HYP".to_string(), spsr_hyp.clone());

        // VFP D
        for (i, reg) in vfp_d.iter().enumerate() {
            register_by_name.insert(format!("D{}", i), reg.clone());
        }

        // VFP S
        for (i, reg) in vfp_s.iter().enumerate() {
            register_by_name.insert(format!("S{}", i), reg.clone());
        }

        // NEON Q
        for (i, reg) in neon_q.iter().enumerate() {
            register_by_name.insert(format!("Q{}", i), reg.clone());
        }

        // FPSCR
        register_by_name.insert("FPSCR".to_string(), fpscr.clone());

        ArmRegisterBank {
            general: [r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12],
            sp_usr,
            sp_fiq,
            sp_irq,
            sp_svc,
            sp_mon,
            sp_abt,
            sp_hyp,
            sp_und,
            lr_usr,
            lr_fiq,
            lr_irq,
            lr_svc,
            lr_mon,
            lr_abt,
            lr_hyp,
            lr_und,
            pc,
            cpsr,
            spsr_fiq,
            spsr_irq,
            spsr_svc,
            spsr_abt,
            spsr_und,
            spsr_mon,
            spsr_hyp,
            vfp_d,
            vfp_s,
            neon_q,
            fpscr,
            sp,
            lr,
            register_by_name,
        }
    }

    /// Look up a register by its name (case-sensitive, e.g., "R0", "D0", "CPSR").
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

impl Default for ArmRegisterBank {
    fn default() -> Self {
        Self::new_armv7a()
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
        let bank = ArmRegisterBank::new_armv7a();
        assert!(
            bank.len() > 50,
            "ARM bank should have >50 registers, got {}",
            bank.len()
        );
    }

    #[test]
    fn test_gp_registers() {
        let bank = ArmRegisterBank::new_armv7a();
        for i in 0..=12 {
            let name = format!("R{}", i);
            assert!(bank.get(&name).is_some(), "Missing register {}", name);
        }
        assert!(bank.get("SP").is_some());
        assert!(bank.get("LR").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("R13").is_some());
        assert!(bank.get("R14").is_some());
        assert!(bank.get("R15").is_some());
    }

    #[test]
    fn test_banked_registers() {
        let bank = ArmRegisterBank::new_armv7a();
        let modes = ["USR", "FIQ", "IRQ", "SVC", "ABT", "UND", "MON", "HYP"];
        for mode in &modes {
            assert!(
                bank.get(&format!("SP_{}", mode)).is_some(),
                "Missing SP_{}",
                mode
            );
            assert!(
                bank.get(&format!("LR_{}", mode)).is_some(),
                "Missing LR_{}",
                mode
            );
        }
    }

    #[test]
    fn test_spsr_registers() {
        let bank = ArmRegisterBank::new_armv7a();
        let modes = ["FIQ", "IRQ", "SVC", "ABT", "UND", "MON", "HYP"];
        for mode in &modes {
            assert!(
                bank.get(&format!("SPSR_{}", mode)).is_some(),
                "Missing SPSR_{}",
                mode
            );
        }
    }

    #[test]
    fn test_vfp_neon_registers() {
        let bank = ArmRegisterBank::new_armv7a();
        for i in 0..32 {
            assert!(bank.get(&format!("D{}", i)).is_some(), "Missing D{}", i);
            assert!(bank.get(&format!("S{}", i)).is_some(), "Missing S{}", i);
        }
        for i in 0..16 {
            assert!(bank.get(&format!("Q{}", i)).is_some(), "Missing Q{}", i);
        }
        assert!(bank.get("FPSCR").is_some());
    }

    #[test]
    fn test_processor_modes() {
        assert_eq!(ProcessorMode::USR.encoding(), 0b10000);
        assert_eq!(ProcessorMode::SYS.encoding(), 0b11111);
        assert_eq!(ProcessorMode::HYP.encoding(), 0b11010);
    }

    #[test]
    fn test_sub_register_aliasing() {
        let bank = ArmRegisterBank::new_armv7a();

        // S0 should alias D0
        let s0 = bank.get("S0").unwrap();
        assert_eq!(s0.parent.as_deref(), Some("D0"));
        assert_eq!(s0.lsb, 0);

        // S1 should alias D0 (upper half)
        let s1 = bank.get("S1").unwrap();
        assert_eq!(s1.parent.as_deref(), Some("D0"));
        assert_eq!(s1.lsb, 32);

        // Q0 should alias D0
        let q0 = bank.get("Q0").unwrap();
        assert_eq!(q0.parent.as_deref(), Some("D0"));
        assert_eq!(q0.bit_size, 128);

        // Q1 should alias D2
        let q1 = bank.get("Q1").unwrap();
        assert_eq!(q1.parent.as_deref(), Some("D2"));
    }

    #[test]
    fn test_vfp_s_to_d_mapping() {
        let bank = ArmRegisterBank::new_armv7a();
        // S4 (index 4) -> D2, lsb 0; S5 -> D2, lsb 32
        let s4 = bank.get("S4").unwrap();
        assert_eq!(s4.parent.as_deref(), Some("D2"));
        assert_eq!(s4.lsb, 0);
        let s5 = bank.get("S5").unwrap();
        assert_eq!(s5.parent.as_deref(), Some("D2"));
        assert_eq!(s5.lsb, 32);
    }

    #[test]
    fn test_cpsr_flag_bits() {
        assert_eq!(CpsrFlagBit::N.mask(), 1u32 << 31);
        assert_eq!(CpsrFlagBit::Z.mask(), 1u32 << 30);
        assert_eq!(CpsrFlagBit::C.mask(), 1u32 << 29);
        assert_eq!(CpsrFlagBit::V.mask(), 1u32 << 28);
        assert_eq!(CpsrFlagBit::Q.mask(), 1u32 << 27);
    }
}
