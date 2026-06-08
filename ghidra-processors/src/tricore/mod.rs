//! Infineon TriCore Processor Module
//!
//! Supports TriCore TC1.3 and TC1.6 ISA variants.
//!
//! The TriCore is a 32-bit unified processor architecture combining RISC, CISC,
//! and DSP capabilities, used primarily in automotive and industrial embedded
//! systems. It features a hardware-supported context switching mechanism
//! through linked lists of context save areas.
//!
//! ## Register space layout
//! - Data registers (D0-D15):      0x0000 - 0x003C  (32-bit each)
//! - Address registers (A0-A15):   0x0040 - 0x007C  (32-bit each)
//! - Program Status Word (PSW):    0x0080            (32-bit)
//! - Previous Context Info (PCXI): 0x0084            (32-bit)
//! - Free Context List (FCX):      0x0088            (32-bit)
//! - Loop Counter (LCX):           0x008C            (32-bit)
//! - Interrupt Stack Pointer (ISP): 0x0090           (32-bit)
//! - Base Trap Vector (BTV):       0x0094            (32-bit)
//! - System Control (SYSCON):      0x0098            (32-bit)
//! - Program Counter (PC):         0x00A0            (32-bit)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// TriCore processor struct.
pub struct TricoreProcessor;

/// Build the complete TriCore register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- Data registers D0-D15 (32-bit) ----
    for i in 0..16u32 {
        bank.add(Register::new(
            &format!("D{}", i),
            32,
            0x0000 + (i as u64) * 4,
        ));
    }

    // Data register pairs D1D0, D3D2, ..., D15D14 (64-bit)
    for i in 0..8u32 {
        let d_even = i * 2;
        let d_odd = d_even + 1;
        bank.add(Register::new(
            &format!("D{}D{}", d_odd, d_even),
            64,
            0x0600 + (i as u64) * 8,
        ));
    }

    // ---- Address registers A0-A15 (32-bit) ----
    for i in 0..16u32 {
        bank.add(Register::new(
            &format!("A{}", i),
            32,
            0x0040 + (i as u64) * 4,
        ));
    }

    // Address register aliases
    bank.add(Register::sub_register("SP", 32, 0x0040 + 10 * 4, "A10", 0)); // Stack Pointer = A10
    bank.add(Register::sub_register("FP", 32, 0x0040 + 11 * 4, "A11", 0)); // Return Address = A11
    bank.add(Register::sub_register("RA", 32, 0x0040 + 11 * 4, "A11", 0)); // Return Address alias
    bank.add(Register::sub_register("GP", 32, 0x0040 + 0 * 4, "A0", 0)); // Implicit base = A0

    // Address register pairs A1A0, A3A2, ..., A15A14 (64-bit)
    for i in 0..8u32 {
        let a_even = i * 2;
        let a_odd = a_even + 1;
        bank.add(Register::new(
            &format!("A{}A{}", a_odd, a_even),
            64,
            0x0680 + (i as u64) * 8,
        ));
    }

    // ---- Extended data registers E0-E15 (pair D[n+1]:D[n]) ----
    // E0 = D1:D0, E2 = D3:D2, etc.
    for i in 0..8u32 {
        let d_even = i * 2;
        let _d_odd = d_even + 1;
        bank.add(Register::new(
            &format!("E{}", d_even),
            64,
            0x0700 + (i as u64) * 8,
        ));
    }

    // ---- Extended address registers P0-P15 (pair A[n+1]:A[n]) ----
    for i in 0..8u32 {
        let a_even = i * 2;
        bank.add(Register::new(
            &format!("P{}", a_even),
            64,
            0x0780 + (i as u64) * 8,
        ));
    }

    // ---- Program Status Word (PSW) ----
    bank.add(Register::new("PSW", 32, 0x0080));

    // PSW sub-fields (bit ranges)
    bank.add(Register::sub_register("C", 1, 0x0080, "PSW", 0)); // Carry
    bank.add(Register::sub_register("V", 1, 0x0080, "PSW", 1)); // Overflow
    bank.add(Register::sub_register("SV", 1, 0x0080, "PSW", 2)); // Sticky overflow
    bank.add(Register::sub_register("AV", 1, 0x0080, "PSW", 3)); // Advance overflow
    bank.add(Register::sub_register("SAV", 1, 0x0080, "PSW", 4)); // Sticky advance overflow
    bank.add(Register::sub_register("N", 1, 0x0080, "PSW", 31)); // Negative

    // ---- Context management registers ----
    bank.add(Register::new("PCXI", 32, 0x0084)); // Previous Context Information
    bank.add(Register::new("FCX", 32, 0x0088)); // Free CSA list head pointer
    bank.add(Register::new("LCX", 32, 0x008C)); // Free CSA list limit pointer

    // ---- Interrupt and trap registers ----
    bank.add(Register::new("ISP", 32, 0x0090)); // Interrupt Stack Pointer
    bank.add(Register::new("BTV", 32, 0x0094)); // Base Trap Vector table pointer
    bank.add(Register::new("SYSCON", 32, 0x0098)); // System Configuration register
    bank.add(Register::new("ICR", 32, 0x009C)); // Interrupt Control Register
    bank.add(Register::new("PC", 32, 0x00A0)); // Program Counter

    // ---- Additional system registers ----
    bank.add(Register::new("COMPAT", 32, 0x00A4)); // Compatibility mode
    bank.add(Register::new("FPU_TRAP_CON", 32, 0x00A8)); // FPU trap control
    bank.add(Register::new("BMK", 32, 0x00AC)); // Boot mode, misc keys
    bank.add(Register::new("DBGSR", 32, 0x00B0)); // Debug Status Register
    bank.add(Register::new("EXEVT", 32, 0x00B4)); // Exception Event
    bank.add(Register::new("CREVT", 32, 0x00B8)); // Core Event
    bank.add(Register::new("SWEVT", 32, 0x00BC)); // Software Event
    bank.add(Register::new("TR0EVT", 32, 0x00C0)); // Trigger Event 0
    bank.add(Register::new("TR1EVT", 32, 0x00C4)); // Trigger Event 1
    bank.add(Register::new("DMS", 32, 0x00C8)); // Debug Monitor Start
    bank.add(Register::new("DCX", 32, 0x00CC)); // Debug Context
    bank.add(Register::new("IMASK", 32, 0x00D0)); // Interrupt Mask

    // ---- Core Special Function Registers (CSFR) for TC1.6 ----
    bank.add(Register::new("CPU_ID", 32, 0x00E0)); // CPU Identification
    bank.add(Register::new("CORE_ID", 32, 0x00E4)); // Core Identification
    bank.add(Register::new("PSPR", 32, 0x00E8)); // Processor Special-Purpose Register
    bank.add(Register::new("PM_CNT", 32, 0x00EC)); // Performance Monitor Counter
    bank.add(Register::new("PM_SR", 32, 0x00F0)); // Performance Monitor Status
    bank.add(Register::new("PM_CR", 32, 0x00F4)); // Performance Monitor Control
    bank.add(Register::new("FPU_ID", 32, 0x00F8)); // FPU Identification
    bank.add(Register::new("MMU_ID", 32, 0x00FC)); // MMU Identification

    bank
}

/// Build the TriCore instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Data arithmetic ===
        InstructionMnemonic::new("add"),
        InstructionMnemonic::new("addc"),
        InstructionMnemonic::new("addi"),
        InstructionMnemonic::new("addih"),
        InstructionMnemonic::new("addih_a"),
        InstructionMnemonic::new("addx"),
        InstructionMnemonic::new("sub"),
        InstructionMnemonic::new("subc"),
        InstructionMnemonic::new("subx"),
        InstructionMnemonic::new("and"),
        InstructionMnemonic::new("andn"),
        InstructionMnemonic::new("or"),
        InstructionMnemonic::new("orn"),
        InstructionMnemonic::new("xor"),
        InstructionMnemonic::new("xnor"),
        InstructionMnemonic::new("not"),
        InstructionMnemonic::new("neg"),
        InstructionMnemonic::new("abs"),
        InstructionMnemonic::new("absdif"),
        InstructionMnemonic::new("absdifs"),
        InstructionMnemonic::new("min"),
        InstructionMnemonic::new("minu"),
        InstructionMnemonic::new("max"),
        InstructionMnemonic::new("maxu"),
        InstructionMnemonic::new("sh"),
        InstructionMnemonic::new("sha"),
        InstructionMnemonic::new("shas"),
        InstructionMnemonic::new("pack"),
        InstructionMnemonic::new("unpack"),
        InstructionMnemonic::new("cad"),
        InstructionMnemonic::new("cadn"),
        InstructionMnemonic::new("sel"),
        InstructionMnemonic::new("slen"),
        // Saturating arithmetic
        InstructionMnemonic::new("sadds"),
        InstructionMnemonic::new("ssubs"),
        InstructionMnemonic::new("sadds_h"),
        InstructionMnemonic::new("ssubs_h"),
        InstructionMnemonic::new("sat_bu"),
        InstructionMnemonic::new("sat_b"),
        InstructionMnemonic::new("sat_hu"),
        InstructionMnemonic::new("sat_h"),
        // Multiply
        InstructionMnemonic::new("mul"),
        InstructionMnemonic::new("muls"),
        InstructionMnemonic::new("muls_u"),
        InstructionMnemonic::new("madd"),
        InstructionMnemonic::new("madds"),
        InstructionMnemonic::new("madds_u"),
        InstructionMnemonic::new("msub"),
        InstructionMnemonic::new("msubs"),
        InstructionMnemonic::new("msubs_u"),
        InstructionMnemonic::new("div"),
        InstructionMnemonic::new("div_u"),
        InstructionMnemonic::new("dvstep"),
        InstructionMnemonic::new("dvstep_u"),
        // === Address arithmetic ===
        InstructionMnemonic::new("add_a"),
        InstructionMnemonic::new("addsc_a"),
        InstructionMnemonic::new("adda"),
        InstructionMnemonic::new("sub_a"),
        InstructionMnemonic::new("subsc_a"),
        InstructionMnemonic::new("eq"),
        InstructionMnemonic::new("ne"),
        InstructionMnemonic::new("lt"),
        InstructionMnemonic::new("lt_u"),
        InstructionMnemonic::new("ge"),
        InstructionMnemonic::new("ge_u"),
        InstructionMnemonic::new("mov"),
        InstructionMnemonic::new("mov_a"),
        InstructionMnemonic::new("movh"),
        InstructionMnemonic::new("movh_a"),
        InstructionMnemonic::new("mov_u"),
        InstructionMnemonic::new("lea"),
        InstructionMnemonic::new("dextr"),
        InstructionMnemonic::new("insert"),
        // === Branch ===
        InstructionMnemonic::new("j"),
        InstructionMnemonic::new("ja"),
        InstructionMnemonic::new("jl"),
        InstructionMnemonic::new("jla"),
        InstructionMnemonic::new("jeq"),
        InstructionMnemonic::new("jne"),
        InstructionMnemonic::new("jge"),
        InstructionMnemonic::new("jge_u"),
        InstructionMnemonic::new("jlt"),
        InstructionMnemonic::new("jlt_u"),
        InstructionMnemonic::new("jnz"),
        InstructionMnemonic::new("jz"),
        InstructionMnemonic::new("jz_a"),
        InstructionMnemonic::new("jnz_a"),
        InstructionMnemonic::new("jz_t"),
        InstructionMnemonic::new("jnz_t"),
        InstructionMnemonic::new("jned"),
        InstructionMnemonic::new("jnei"),
        InstructionMnemonic::new("loop"),
        InstructionMnemonic::new("loopu"),
        InstructionMnemonic::new("call"),
        InstructionMnemonic::new("calla"),
        InstructionMnemonic::new("calli"),
        InstructionMnemonic::new("ret"),
        InstructionMnemonic::new("rets"),
        InstructionMnemonic::new("rfe"),
        InstructionMnemonic::new("rfm"),
        // === Load/Store ===
        InstructionMnemonic::new("ld_b"),
        InstructionMnemonic::new("ld_bu"),
        InstructionMnemonic::new("ld_h"),
        InstructionMnemonic::new("ld_hu"),
        InstructionMnemonic::new("ld_w"),
        InstructionMnemonic::new("ld_d"),
        InstructionMnemonic::new("ld_a"),
        InstructionMnemonic::new("ld_da"),
        InstructionMnemonic::new("st_b"),
        InstructionMnemonic::new("st_h"),
        InstructionMnemonic::new("st_w"),
        InstructionMnemonic::new("st_d"),
        InstructionMnemonic::new("st_a"),
        InstructionMnemonic::new("st_da"),
        InstructionMnemonic::new("ldlcx"),
        InstructionMnemonic::new("lducx"),
        InstructionMnemonic::new("stlcx"),
        InstructionMnemonic::new("stucx"),
        InstructionMnemonic::new("swap_msk"),
        InstructionMnemonic::new("swap_w"),
        InstructionMnemonic::new("cmpswap_w"),
        InstructionMnemonic::new("ldmst"),
        // === Context management (CSA) ===
        InstructionMnemonic::new("svlcx"),
        InstructionMnemonic::new("rslcx"),
        InstructionMnemonic::new("bISa"),
        InstructionMnemonic::new("bisr"),
        // === System ===
        InstructionMnemonic::new("syscall"),
        InstructionMnemonic::new("sync"),
        InstructionMnemonic::new("dsync"),
        InstructionMnemonic::new("isync"),
        InstructionMnemonic::new("trapv"),
        InstructionMnemonic::new("tapsv"),
        InstructionMnemonic::new("debug"),
        InstructionMnemonic::new("disable"),
        InstructionMnemonic::new("enable"),
        InstructionMnemonic::new("mtcr"),
        InstructionMnemonic::new("mfcr"),
        InstructionMnemonic::new("cachei"),
        InstructionMnemonic::new("cachea"),
        // === Bit operations ===
        InstructionMnemonic::new("clz"),
        InstructionMnemonic::new("clo"),
        InstructionMnemonic::new("cls"),
        InstructionMnemonic::new("shuffle"),
        InstructionMnemonic::new("crc32"),
        // === DSP extensions ===
        InstructionMnemonic::new("madd_h"),
        InstructionMnemonic::new("msub_h"),
        InstructionMnemonic::new("mul_h"),
        InstructionMnemonic::new("mulm_h"),
        InstructionMnemonic::new("mulr_h"),
        // === FPU (TC1.6) ===
        InstructionMnemonic::new("add_f"),
        InstructionMnemonic::new("sub_f"),
        InstructionMnemonic::new("mul_f"),
        InstructionMnemonic::new("div_f"),
        InstructionMnemonic::new("cmp_f"),
        InstructionMnemonic::new("ftoi"),
        InstructionMnemonic::new("itof"),
        InstructionMnemonic::new("utof"),
        InstructionMnemonic::new("ftouz"),
        InstructionMnemonic::new("ftoq31"),
        InstructionMnemonic::new("q31tof"),
        InstructionMnemonic::new("madd_f"),
        InstructionMnemonic::new("msub_f"),
        InstructionMnemonic::new("fabs"),
        InstructionMnemonic::new("fneg"),
        InstructionMnemonic::new("fsqrt"),
        // === Miscellaneous ===
        InstructionMnemonic::new("nop"),
        InstructionMnemonic::new("wait"),
        InstructionMnemonic::new("rsub"),
    ]
}

impl ProcessorModule for TricoreProcessor {
    fn name() -> &'static str {
        "Infineon TriCore"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "tricore:LE:32:TC13",
                "TriCore TC1.3 (32-bit, little-endian)",
                "TC1.3",
                Endian::Little,
                32,
            ),
            Language::new(
                "tricore:LE:32:TC16",
                "TriCore TC1.6 (32-bit, little-endian, with FPU)",
                "TC1.6",
                Endian::Little,
                32,
            ),
            Language::new(
                "tricore:LE:32:TC16E",
                "TriCore TC1.6E (32-bit, little-endian, with FPU, extended)",
                "TC1.6E",
                Endian::Little,
                32,
            ),
            Language::new(
                "tricore:LE:32:TC16P",
                "TriCore TC1.6P (32-bit, little-endian, with FPU, performance)",
                "TC1.6P",
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
    fn test_tricore_name() {
        assert_eq!(TricoreProcessor::name(), "Infineon TriCore");
    }

    #[test]
    fn test_tricore_registers() {
        let bank = TricoreProcessor::registers();
        assert!(
            bank.len() > 60,
            "Expected many registers, got {}",
            bank.len()
        );
        assert!(bank.get("D0").is_some());
        assert!(bank.get("D15").is_some());
        assert!(bank.get("A0").is_some());
        assert!(bank.get("A15").is_some());
        assert!(bank.get("PSW").is_some());
        assert!(bank.get("PCXI").is_some());
        assert!(bank.get("FCX").is_some());
        assert!(bank.get("ISP").is_some());
        assert!(bank.get("BTV").is_some());
        assert!(bank.get("SYSCON").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("RA").is_some());
    }

    #[test]
    fn test_tricore_register_bits() {
        let bank = TricoreProcessor::registers();
        assert_eq!(bank.get("D0").unwrap().bit_size, 32);
        assert_eq!(bank.get("A0").unwrap().bit_size, 32);
        assert_eq!(bank.get("PSW").unwrap().bit_size, 32);
        assert_eq!(bank.get("C").unwrap().bit_size, 1);
        assert_eq!(bank.get("PC").unwrap().bit_size, 32);
        assert_eq!(bank.get("D1D0").unwrap().bit_size, 64);
    }

    #[test]
    fn test_tricore_psw_flags() {
        let bank = TricoreProcessor::registers();
        let c = bank.get("C").unwrap();
        assert_eq!(c.parent.as_deref(), Some("PSW"));
        assert_eq!(c.lsb, 0);
        let v = bank.get("V").unwrap();
        assert_eq!(v.parent.as_deref(), Some("PSW"));
        assert_eq!(v.lsb, 1);
        let n = bank.get("N").unwrap();
        assert_eq!(n.parent.as_deref(), Some("PSW"));
        assert_eq!(n.lsb, 31);
    }

    #[test]
    fn test_tricore_alias_registers() {
        let bank = TricoreProcessor::registers();
        let sp = bank.get("SP").unwrap();
        assert_eq!(sp.parent.as_deref(), Some("A10"));
        let ra = bank.get("RA").unwrap();
        assert_eq!(ra.parent.as_deref(), Some("A11"));
    }

    #[test]
    fn test_tricore_languages() {
        let langs = TricoreProcessor::languages();
        assert!(langs.len() >= 3);
        assert!(langs.iter().any(|l| l.id == "tricore:LE:32:TC13"));
        assert!(langs.iter().any(|l| l.id == "tricore:LE:32:TC16"));
        assert!(langs.iter().all(|l| l.endian == Endian::Little));
        assert!(langs.iter().all(|l| l.pointer_size == 32));
    }

    #[test]
    fn test_tricore_instructions() {
        let insts = TricoreProcessor::instructions();
        assert!(insts.len() > 60);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"ld_w"));
        assert!(texts.contains(&"st_w"));
        assert!(texts.contains(&"call"));
        assert!(texts.contains(&"ret"));
        assert!(texts.contains(&"rfe"));
        assert!(texts.contains(&"svlcx"));
        assert!(texts.contains(&"rslcx"));
        assert!(texts.contains(&"add_f"));
    }
}
