//! Renesas V850 Processor Module
//!
//! Supports V850, V850E, V850E2, V850ES, and V850E2M ISA variants.
//!
//! The V850 is a 32-bit RISC architecture developed by NEC (later Renesas),
//! designed for embedded control applications in automotive, industrial,
//! and consumer electronics.
//!
//! ## Key features
//! - 32 general-purpose registers (GR0 = always zero, GR3 = stack pointer,
//!   GR31 = link pointer for calls)
//! - Compact 16-bit and standard 32-bit instruction encodings
//! - Rich bit manipulation instructions (SET1, CLR1, NOT1)
//! - Hardware multiply-accumulate (V850E+)
//! - Optional FPU (V850E2)
//!
//! ## Register space layout
//! - General-purpose (GR0-GR31):   0x0000 - 0x007C  (32-bit each)
//! - System (SR/PSW, PC):          0x0080 - 0x0088
//! - Multiply (MULH, MULL):        0x0090 - 0x0098
//! - FPU (VR0-VR31, FPSR, FPEPC):  0x0100 - 0x0188

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// V850 processor struct.
pub struct V850Processor;

/// Build the complete V850 register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- General-purpose registers GR0-GR31 (32-bit) ----
    // GR0 is hardwired to zero
    // GR3 is conventionally the stack pointer (SP)
    // GR4 is conventionally the global pointer (GP)
    // GR5 is conventionally the text pointer (TP)
    // GR30 is conventionally the element pointer (EP)
    // GR31 is the link pointer (LP), used for return addresses from calls
    for i in 0..32u32 {
        bank.add(Register::new(
            &format!("GR{}", i),
            32,
            0x0000 + (i as u64) * 4,
        ));
    }

    // Register aliases for conventional usage
    bank.add(Register::sub_register("ZERO", 32, 0x0000 + 0 * 4, "GR0", 0)); // Always zero
    bank.add(Register::sub_register("SP", 32, 0x0000 + 3 * 4, "GR3", 0)); // Stack pointer
    bank.add(Register::sub_register("GP", 32, 0x0000 + 4 * 4, "GR4", 0)); // Global pointer
    bank.add(Register::sub_register("TP", 32, 0x0000 + 5 * 4, "GR5", 0)); // Text pointer
    bank.add(Register::sub_register("EP", 32, 0x0000 + 30 * 4, "GR30", 0)); // Element pointer
    bank.add(Register::sub_register("LP", 32, 0x0000 + 31 * 4, "GR31", 0)); // Link pointer
    bank.add(Register::sub_register("RP", 32, 0x0000 + 31 * 4, "GR31", 0)); // Return pointer (alias for LP)

    // ---- System registers ----
    // PSW (Program Status Word) - primary system register
    bank.add(Register::new("PSW", 32, 0x0080));

    // PSW bit fields
    bank.add(Register::sub_register("CY", 1, 0x0080, "PSW", 0)); // Carry flag
    bank.add(Register::sub_register("OV", 1, 0x0080, "PSW", 1)); // Overflow flag
    bank.add(Register::sub_register("S", 1, 0x0080, "PSW", 2)); // Sign flag
    bank.add(Register::sub_register("Z", 1, 0x0080, "PSW", 3)); // Zero flag
    bank.add(Register::sub_register("SAT", 1, 0x0080, "PSW", 4)); // Saturation flag
    bank.add(Register::sub_register("NP", 1, 0x0080, "PSW", 16)); // NMI pending
    bank.add(Register::sub_register("EP", 1, 0x0080, "PSW", 17)); // Exception pending
    bank.add(Register::sub_register("ID", 1, 0x0080, "PSW", 18)); // Interrupt disable
    bank.add(Register::sub_register("AE", 1, 0x0080, "PSW", 19)); // Alignment exception enable

    // Aliases for common PSW name (some manuals call it SR)
    bank.add(Register::sub_register("SR", 32, 0x0080, "PSW", 0));

    // Program Counter
    bank.add(Register::new("PC", 32, 0x0084));

    // Exception/interrupt handling registers
    bank.add(Register::new("EIPC", 32, 0x0088)); // Exception/interrupt PC
    bank.add(Register::new("EIPSW", 32, 0x008C)); // Exception/interrupt PSW
    bank.add(Register::new("FEPC", 32, 0x0090)); // FE-level exception PC
    bank.add(Register::new("FEPSW", 32, 0x0094)); // FE-level exception PSW
    bank.add(Register::new("ECR", 32, 0x0098)); // Exception cause register
    bank.add(Register::new("PSMR", 32, 0x009C)); // Power save mode register

    // ---- Multiply registers (V850E+) ----
    bank.add(Register::new("MULH", 32, 0x00A0)); // Multiply result high 32 bits
    bank.add(Register::new("MULL", 32, 0x00A4)); // Multiply result low 32 bits
    bank.add(Register::new("MULH_R", 32, 0x00A8)); // Multiply high (read-only copy for pipelining)

    // ---- MAC / SAT registers (V850E2) ----
    bank.add(Register::new("MACC", 64, 0x00B0)); // MAC result (64-bit)
    bank.add(Register::new("MACH", 32, 0x00B0)); // MAC high 32 bits
    bank.add(Register::new("MACL", 32, 0x00B4)); // MAC low 32 bits
    bank.add(Register::new("SAT_CY", 1, 0x00B8)); // Saturate carry flag

    // ---- CPU system registers ----
    bank.add(Register::new("CTPC", 32, 0x00C0)); // CALLT base PC
    bank.add(Register::new("CTPSW", 32, 0x00C4)); // CALLT base PSW
    bank.add(Register::new("DBPC", 32, 0x00C8)); // Debug base PC
    bank.add(Register::new("DBPSW", 32, 0x00CC)); // Debug base PSW
    bank.add(Register::new("CTBP", 32, 0x00D0)); // CALLT base pointer
    bank.add(Register::new("DIR", 32, 0x00D4)); // Debug interface register
    bank.add(Register::new("DBIC", 32, 0x00D8)); // Debug instruction count register
    bank.add(Register::new("PMC0", 32, 0x00DC)); // Performance monitor counter 0
    bank.add(Register::new("PMC1", 32, 0x00E0)); // Performance monitor counter 1
    bank.add(Register::new("PMCR", 32, 0x00E4)); // Performance monitor control

    // ---- Cache / memory control (V850E2) ----
    bank.add(Register::new("ICC", 32, 0x00F0)); // Instruction cache control
    bank.add(Register::new("DCC", 32, 0x00F4)); // Data cache control
    bank.add(Register::new("BPACR", 32, 0x00F8)); // Branch prediction array control
    bank.add(Register::new("MPM", 32, 0x00FC)); // Memory protection mode

    // ---- FPU registers (V850E2M) ----
    // 32 single-precision FPU registers (VR0-VR31)
    for i in 0..32u32 {
        bank.add(Register::new(
            &format!("VR{}", i),
            32,
            0x0100 + (i as u64) * 4,
        ));
    }

    // FPU System registers
    bank.add(Register::new("FPSR", 32, 0x0180)); // FPU status register
    bank.add(Register::new("FPEPC", 32, 0x0184)); // FPU exception PC
    bank.add(Register::new("FPST", 32, 0x0188)); // FPU status (copy)

    // FPU condition flags (within FPSR)
    bank.add(Register::sub_register("FC", 1, 0x0180, "FPSR", 0)); // FPU condition 0
    bank.add(Register::sub_register("FCC0", 1, 0x0180, "FPSR", 0)); // FPU condition code 0
    bank.add(Register::sub_register("FCC1", 1, 0x0180, "FPSR", 1)); // FPU condition code 1
    bank.add(Register::sub_register("FCC2", 1, 0x0180, "FPSR", 2)); // FPU condition code 2
    bank.add(Register::sub_register("FCC3", 1, 0x0180, "FPSR", 3)); // FPU condition code 3
    bank.add(Register::sub_register("FIV", 1, 0x0180, "FPSR", 4)); // FPU invalid operation
    bank.add(Register::sub_register("FDZ", 1, 0x0180, "FPSR", 5)); // FPU divide by zero
    bank.add(Register::sub_register("FOF", 1, 0x0180, "FPSR", 6)); // FPU overflow
    bank.add(Register::sub_register("FUF", 1, 0x0180, "FPSR", 7)); // FPU underflow
    bank.add(Register::sub_register("FPR", 1, 0x0180, "FPSR", 8)); // FPU inexact

    // ---- SEL (Processor selection / CPU ID) ----
    bank.add(Register::new("SELID", 32, 0x01A0)); // Processor ID / selection

    // ---- Timer registers ----
    bank.add(Register::new("TMC0", 32, 0x01B0)); // Timer mode control 0
    bank.add(Register::new("TMC1", 32, 0x01B4)); // Timer mode control 1
    bank.add(Register::new("TMS0", 32, 0x01B8)); // Timer match 0
    bank.add(Register::new("TMS1", 32, 0x01BC)); // Timer match 1

    bank
}

/// Build the V850 instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Load / Store ===
        InstructionMnemonic::new("ld_b"),
        InstructionMnemonic::new("ld_h"),
        InstructionMnemonic::new("ld_w"),
        InstructionMnemonic::new("ld_bu"),
        InstructionMnemonic::new("ld_hu"),
        InstructionMnemonic::new("st_b"),
        InstructionMnemonic::new("st_h"),
        InstructionMnemonic::new("st_w"),
        // Short (16-bit) load/store
        InstructionMnemonic::new("sld_b"),
        InstructionMnemonic::new("sld_h"),
        InstructionMnemonic::new("sld_w"),
        InstructionMnemonic::new("sld_bu"),
        InstructionMnemonic::new("sld_hu"),
        InstructionMnemonic::new("sst_b"),
        InstructionMnemonic::new("sst_h"),
        InstructionMnemonic::new("sst_w"),
        // Bit load/store
        InstructionMnemonic::new("ld_bit"),
        InstructionMnemonic::new("st_bit"),
        // Multi-load/store (V850E2)
        InstructionMnemonic::new("ldm"),
        InstructionMnemonic::new("stm"),
        // === Move ===
        InstructionMnemonic::new("mov"),
        InstructionMnemonic::new("movhi"),
        InstructionMnemonic::new("movea"),
        InstructionMnemonic::new("mov32"),
        // === Arithmetic ===
        InstructionMnemonic::new("add"),
        InstructionMnemonic::new("addi"),
        InstructionMnemonic::new("sub"),
        InstructionMnemonic::new("subr"),
        InstructionMnemonic::new("mul"),
        InstructionMnemonic::new("mulu"),
        InstructionMnemonic::new("mulh"),
        InstructionMnemonic::new("mulhi"),
        InstructionMnemonic::new("div"),
        InstructionMnemonic::new("divu"),
        InstructionMnemonic::new("divh"),
        InstructionMnemonic::new("divhu"),
        // Saturating arithmetic (V850E2)
        InstructionMnemonic::new("satadd"),
        InstructionMnemonic::new("satsub"),
        InstructionMnemonic::new("satsubi"),
        InstructionMnemonic::new("sataddi"),
        // === Compare ===
        InstructionMnemonic::new("cmp"),
        InstructionMnemonic::new("cmpi"),
        InstructionMnemonic::new("setf"),
        // === Logic ===
        InstructionMnemonic::new("and"),
        InstructionMnemonic::new("andi"),
        InstructionMnemonic::new("or"),
        InstructionMnemonic::new("ori"),
        InstructionMnemonic::new("xor"),
        InstructionMnemonic::new("xori"),
        InstructionMnemonic::new("not"),
        InstructionMnemonic::new("tst"),
        InstructionMnemonic::new("tsti"),
        // === Shift ===
        InstructionMnemonic::new("shl"),
        InstructionMnemonic::new("shli"),
        InstructionMnemonic::new("shr"),
        InstructionMnemonic::new("shri"),
        InstructionMnemonic::new("sar"),
        InstructionMnemonic::new("sari"),
        // === Branch ===
        InstructionMnemonic::new("jmp"),
        InstructionMnemonic::new("jmpi"),
        InstructionMnemonic::new("jr"),
        InstructionMnemonic::new("jarl"),
        InstructionMnemonic::new("be"),
        InstructionMnemonic::new("bne"),
        InstructionMnemonic::new("bge"),
        InstructionMnemonic::new("bgt"),
        InstructionMnemonic::new("ble"),
        InstructionMnemonic::new("blt"),
        InstructionMnemonic::new("bgeu"),
        InstructionMnemonic::new("bgtu"),
        InstructionMnemonic::new("bleu"),
        InstructionMnemonic::new("bltu"),
        InstructionMnemonic::new("bc"),
        InstructionMnemonic::new("bnc"),
        InstructionMnemonic::new("bv"),
        InstructionMnemonic::new("bnv"),
        InstructionMnemonic::new("bz"),
        InstructionMnemonic::new("bnz"),
        InstructionMnemonic::new("bs"),
        InstructionMnemonic::new("bns"),
        InstructionMnemonic::new("bp"),
        InstructionMnemonic::new("bnp"),
        InstructionMnemonic::new("bn"),
        InstructionMnemonic::new("bnn"),
        InstructionMnemonic::new("bl"),
        InstructionMnemonic::new("bnh"),
        // === Subroutine ===
        InstructionMnemonic::new("callt"),
        InstructionMnemonic::new("ctret"),
        InstructionMnemonic::new("dispose"),
        InstructionMnemonic::new("prepare"),
        // === Switch ===
        InstructionMnemonic::new("switch"),
        // === Bit manipulation ===
        InstructionMnemonic::new("set1"),
        InstructionMnemonic::new("clr1"),
        InstructionMnemonic::new("not1"),
        InstructionMnemonic::new("tst1"),
        InstructionMnemonic::new("bsh"),
        InstructionMnemonic::new("bsw"),
        // === Extended bit manipulation (V850E2) ===
        InstructionMnemonic::new("sch0l"),
        InstructionMnemonic::new("sch0r"),
        InstructionMnemonic::new("sch1l"),
        InstructionMnemonic::new("sch1r"),
        // === System control ===
        InstructionMnemonic::new("ei"),
        InstructionMnemonic::new("di"),
        InstructionMnemonic::new("halt"),
        InstructionMnemonic::new("trap"),
        InstructionMnemonic::new("reti"),
        InstructionMnemonic::new("feret"),
        InstructionMnemonic::new("ldsr"),
        InstructionMnemonic::new("stsr"),
        InstructionMnemonic::new("nop"),
        // === Cache control (V850E2) ===
        InstructionMnemonic::new("cache"),
        InstructionMnemonic::new("prefetch"),
        // === Byte swap (V850E2) ===
        InstructionMnemonic::new("bsw"),
        InstructionMnemonic::new("hsw"),
        // === Exclusive load/store (V850E2) ===
        InstructionMnemonic::new("ldl_w"),
        InstructionMnemonic::new("stc_w"),
        InstructionMnemonic::new("cax"),
        // === MAC instructions (V850E2) ===
        InstructionMnemonic::new("mac"),
        InstructionMnemonic::new("macu"),
        InstructionMnemonic::new("macsu"),
        // === FPU instructions (V850E2M) ===
        InstructionMnemonic::new("fadd_s"),
        InstructionMnemonic::new("fsub_s"),
        InstructionMnemonic::new("fmul_s"),
        InstructionMnemonic::new("fdiv_s"),
        InstructionMnemonic::new("fabs_s"),
        InstructionMnemonic::new("fneg_s"),
        InstructionMnemonic::new("fsqrt_s"),
        InstructionMnemonic::new("fcmp_s"),
        InstructionMnemonic::new("fmov_s"),
        InstructionMnemonic::new("ftrc_s"),
        InstructionMnemonic::new("fceil_s"),
        InstructionMnemonic::new("ffloor_s"),
        InstructionMnemonic::new("fcvt_sw"),
        InstructionMnemonic::new("fcvt_ws"),
        InstructionMnemonic::new("fcvt_dw"),
        InstructionMnemonic::new("fcvt_wd"),
        InstructionMnemonic::new("fcnv_sw"),
        InstructionMnemonic::new("fcnv_ws"),
        // === DSP instructions (V850E2) ===
        InstructionMnemonic::new("dst"),
        // === Special (V850E2) ===
        InstructionMnemonic::new("snooze"),
    ]
}

impl ProcessorModule for V850Processor {
    fn name() -> &'static str {
        "Renesas V850"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "v850:LE:32:V850",
                "V850 (32-bit, little-endian)",
                "V850",
                Endian::Little,
                32,
            ),
            Language::new(
                "v850:LE:32:V850E",
                "V850E (32-bit, little-endian, with MAC)",
                "V850E",
                Endian::Little,
                32,
            ),
            Language::new(
                "v850:LE:32:V850E1",
                "V850E1 (32-bit, little-endian)",
                "V850E1",
                Endian::Little,
                32,
            ),
            Language::new(
                "v850:LE:32:V850ES",
                "V850ES (32-bit, little-endian)",
                "V850ES",
                Endian::Little,
                32,
            ),
            Language::new(
                "v850:LE:32:V850E2",
                "V850E2 (32-bit, little-endian, with cache/prefetch)",
                "V850E2",
                Endian::Little,
                32,
            ),
            Language::new(
                "v850:LE:32:V850E2M",
                "V850E2M (32-bit, little-endian, with FPU)",
                "V850E2M",
                Endian::Little,
                32,
            ),
            Language::new(
                "v850:LE:32:V850E3",
                "V850E3 (32-bit, little-endian)",
                "V850E3",
                Endian::Little,
                32,
            ),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> {
        build_instructions()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v850_name() {
        assert_eq!(V850Processor::name(), "Renesas V850");
    }

    #[test]
    fn test_v850_registers() {
        let bank = V850Processor::registers();
        assert!(
            bank.len() > 40,
            "Expected many registers, got {}",
            bank.len()
        );
        // GPRs
        assert!(bank.get("GR0").is_some());
        assert!(bank.get("GR31").is_some());
        assert!(bank.get("ZERO").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("GP").is_some());
        assert!(bank.get("TP").is_some());
        assert!(bank.get("EP").is_some());
        assert!(bank.get("LP").is_some());
        assert!(bank.get("RP").is_some());
        // System
        assert!(bank.get("PSW").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("EIPC").is_some());
        assert!(bank.get("EIPSW").is_some());
        assert!(bank.get("ECR").is_some());
        // Multiply
        assert!(bank.get("MULH").is_some());
        assert!(bank.get("MULL").is_some());
        assert!(bank.get("MACC").is_some());
        // FPU
        assert!(bank.get("VR0").is_some());
        assert!(bank.get("VR31").is_some());
        assert!(bank.get("FPSR").is_some());
        assert!(bank.get("FPEPC").is_some());
    }

    #[test]
    fn test_v850_register_bits() {
        let bank = V850Processor::registers();
        assert_eq!(bank.get("GR0").unwrap().bit_size, 32);
        assert_eq!(bank.get("GR31").unwrap().bit_size, 32);
        assert_eq!(bank.get("PSW").unwrap().bit_size, 32);
        assert_eq!(bank.get("PC").unwrap().bit_size, 32);
        assert_eq!(bank.get("MACC").unwrap().bit_size, 64);
        assert_eq!(bank.get("VR0").unwrap().bit_size, 32);
        assert_eq!(bank.get("CY").unwrap().bit_size, 1);
    }

    #[test]
    fn test_v850_psw_flags() {
        let bank = V850Processor::registers();
        let cy = bank.get("CY").unwrap();
        assert_eq!(cy.parent.as_deref(), Some("PSW"));
        assert_eq!(cy.lsb, 0);

        let ov = bank.get("OV").unwrap();
        assert_eq!(ov.parent.as_deref(), Some("PSW"));
        assert_eq!(ov.lsb, 1);

        let z = bank.get("Z").unwrap();
        assert_eq!(z.parent.as_deref(), Some("PSW"));
        assert_eq!(z.lsb, 3);

        let id = bank.get("ID").unwrap();
        assert_eq!(id.parent.as_deref(), Some("PSW"));
        assert_eq!(id.lsb, 18);
    }

    #[test]
    fn test_v850_alias_registers() {
        let bank = V850Processor::registers();
        let zero = bank.get("ZERO").unwrap();
        assert_eq!(zero.parent.as_deref(), Some("GR0"));

        let sp = bank.get("SP").unwrap();
        assert_eq!(sp.parent.as_deref(), Some("GR3"));

        let lp = bank.get("LP").unwrap();
        assert_eq!(lp.parent.as_deref(), Some("GR31"));

        let rp = bank.get("RP").unwrap();
        assert_eq!(rp.parent.as_deref(), Some("GR31"));
    }

    #[test]
    fn test_v850_languages() {
        let langs = V850Processor::languages();
        assert!(langs.len() >= 4);
        assert!(langs.iter().any(|l| l.id == "v850:LE:32:V850"));
        assert!(langs.iter().any(|l| l.id == "v850:LE:32:V850E"));
        assert!(langs.iter().any(|l| l.id == "v850:LE:32:V850E2"));
        assert!(langs.iter().any(|l| l.id == "v850:LE:32:V850E2M"));
        assert!(langs.iter().all(|l| l.endian == Endian::Little));
        assert!(langs.iter().all(|l| l.pointer_size == 32));
    }

    #[test]
    fn test_v850_instructions() {
        let insts = V850Processor::instructions();
        assert!(insts.len() > 50);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"mul"));
        assert!(texts.contains(&"div"));
        assert!(texts.contains(&"ld_w"));
        assert!(texts.contains(&"st_w"));
        assert!(texts.contains(&"jmp"));
        assert!(texts.contains(&"jarl"));
        assert!(texts.contains(&"be"));
        assert!(texts.contains(&"bne"));
        assert!(texts.contains(&"set1"));
        assert!(texts.contains(&"clr1"));
        assert!(texts.contains(&"not1"));
        assert!(texts.contains(&"ei"));
        assert!(texts.contains(&"di"));
        assert!(texts.contains(&"reti"));
        assert!(texts.contains(&"fadd_s"));
        assert!(texts.contains(&"fdiv_s"));
    }

    #[test]
    fn test_v850_fpu_registers() {
        let bank = V850Processor::registers();
        for i in 0..32u32 {
            let name = format!("VR{}", i);
            assert!(bank.get(&name).is_some(), "Missing FPU register {}", name);
        }
    }

    #[test]
    fn test_v850_gr0_is_zero() {
        let bank = V850Processor::registers();
        let zero = bank.get("ZERO").unwrap();
        assert_eq!(zero.parent.as_deref(), Some("GR0"));
        // GR0 is hardwired to zero - this is a convention that must be upheld
        assert_eq!(zero.lsb, 0);
    }
}
