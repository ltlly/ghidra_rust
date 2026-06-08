//! Renesas SuperH Processor Module
//!
//! Supports SH-2, SH-2A, SH-3, SH-4, and SH-4A ISA variants.
//!
//! SuperH is a 32-bit RISC architecture developed by Hitachi (later Renesas),
//! used extensively in the Sega Dreamcast, Sega Saturn, HP Jornada, and
//! numerous automotive ECUs.
//!
//! ## Key features
//! - Compact 16-bit instruction encoding (SHcompact mode) reduces code density
//! - Register banks for fast interrupt context switching
//! - Single/double precision FPU (SH-4)
//! - Integrated MAC unit (MACH/MACL multiply-accumulate)
//!
//! ## Register space layout
//! - General-purpose (R0-R15):    0x0000 - 0x003C  (32-bit each)
//! - Banked GPRs (R0_BANK-R7_BANK): 0x0040 - 0x005C
//! - Control (SR, GBR, VBR, etc.): 0x0080 - 0x00A0
//! - System (MACH, MACL, PR, PC):  0x00C0 - 0x00D8
//! - FPU single (FR0-FR15):        0x0100 - 0x013C
//! - FPU double (DR0-DR14):        0x0140 - 0x0178
//! - FPU extended (XF0-XF15):      0x0200 - 0x023C
//! - FPU control (FPSCR, FPUL):     0x0280 - 0x0288

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// SuperH processor struct.
pub struct SuperHProcessor;

/// Build the complete SuperH register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- General-purpose registers R0-R15 (32-bit) ----
    for i in 0..16u32 {
        bank.add(Register::new(
            &format!("R{}", i),
            32,
            0x0000 + (i as u64) * 4,
        ));
    }

    // Register aliases
    bank.add(Register::sub_register("SP", 32, 0x0000 + 15 * 4, "R15", 0)); // Stack pointer = R15
    bank.add(Register::sub_register("FP", 32, 0x0000 + 14 * 4, "R14", 0)); // Frame pointer = R14

    // ---- Banked registers (R0_BANK - R7_BANK) for fast interrupt context switching ----
    for i in 0..8u32 {
        bank.add(Register::new(
            &format!("R{}_BANK", i),
            32,
            0x0040 + (i as u64) * 4,
        ));
    }

    // GBANK (global bank number, selects which bank is active)
    bank.add(Register::new("GBANK", 8, 0x0070));

    // ---- Control registers ----
    bank.add(Register::new("SR", 32, 0x0080)); // Status Register
                                               // SR bit fields
    bank.add(Register::sub_register("T", 1, 0x0080, "SR", 0)); // True/False bit
    bank.add(Register::sub_register("S", 1, 0x0080, "SR", 1)); // Saturation
    bank.add(Register::sub_register("IMASK", 4, 0x0080, "SR", 4)); // Interrupt mask (bits 4-7)
    bank.add(Register::sub_register("Q", 1, 0x0080, "SR", 8)); // Divide step Q
    bank.add(Register::sub_register("M", 1, 0x0080, "SR", 9)); // Divide step M
    bank.add(Register::sub_register("FD", 1, 0x0080, "SR", 14)); // FPU disable
    bank.add(Register::sub_register("BL", 1, 0x0080, "SR", 28)); // Exception block
    bank.add(Register::sub_register("RB", 1, 0x0080, "SR", 29)); // Register bank
    bank.add(Register::sub_register("MD", 1, 0x0080, "SR", 30)); // Processor mode (0=user, 1=privileged)

    bank.add(Register::new("GBR", 32, 0x0084)); // Global Base Register
    bank.add(Register::new("VBR", 32, 0x0088)); // Vector Base Register

    // SH-2A specific control registers
    bank.add(Register::new("TBR", 32, 0x008C)); // Trap Base Register
    bank.add(Register::new("IBCR", 32, 0x0090)); // Instruction Bus Control Register
    bank.add(Register::new("IBNR", 32, 0x0094)); // Instruction Bus Number Register
    bank.add(Register::new("DBCR", 32, 0x0098)); // Data Bus Control Register
    bank.add(Register::new("DBNR", 32, 0x009C)); // Data Bus Number Register
    bank.add(Register::new("BRCR", 32, 0x00A0)); // Branch Control Register

    bank.add(Register::new("SGR", 32, 0x00A4)); // Saved GBR (exception)
    bank.add(Register::new("SSR", 32, 0x00A8)); // Saved Status Register
    bank.add(Register::new("SPC", 32, 0x00AC)); // Saved Program Counter
    bank.add(Register::new("SFP", 32, 0x00B0)); // Saved Frame Pointer / R14

    // ---- System registers ----
    bank.add(Register::new("MACH", 32, 0x00C0)); // Multiply-Accumulate High
    bank.add(Register::new("MACL", 32, 0x00C4)); // Multiply-Accumulate Low
    bank.add(Register::new("PR", 32, 0x00C8)); // Procedure Register (return address)
    bank.add(Register::new("PC", 32, 0x00D0)); // Program Counter

    // SH-2A DSP extension registers
    bank.add(Register::new("DSR", 32, 0x00D4)); // DSP Status Register
    bank.add(Register::new("A0", 40, 0x00D8)); // DSP accumulator 0 (40-bit)
    bank.add(Register::new("A0G", 8, 0x00D8)); // A0 guard bits (bits 32-39)
    bank.add(Register::new("A1", 40, 0x00E0)); // DSP accumulator 1 (40-bit)
    bank.add(Register::new("A1G", 8, 0x00E0)); // A1 guard bits
    bank.add(Register::new("X0", 32, 0x00E8)); // DSP data register X0
    bank.add(Register::new("X1", 32, 0x00EC)); // DSP data register X1
    bank.add(Register::new("Y0", 32, 0x00F0)); // DSP data register Y0
    bank.add(Register::new("Y1", 32, 0x00F4)); // DSP data register Y1
    bank.add(Register::new("RS", 32, 0x00F8)); // DSP repeat start address
    bank.add(Register::new("RE", 32, 0x00FC)); // DSP repeat end address
    bank.add(Register::new("MOD", 32, 0x0100)); // DSP modulo register

    // ---- FPU registers (SH-4 / SH-4A) ----
    // Single-precision floating-point registers FR0-FR15 (32-bit each)
    for i in 0..16u32 {
        bank.add(Register::new(
            &format!("FR{}", i),
            32,
            0x0100 + (i as u64) * 4,
        ));
    }

    // Double-precision aliases: DR0 = FR0|FR1, DR2 = FR2|FR3, ..., DR14 = FR14|FR15
    for i in 0..8u32 {
        let fr_even = i * 2;
        let _fr_odd = fr_even + 1;
        bank.add(Register::new(
            &format!("DR{}", fr_even),
            64,
            0x0140 + (i as u64) * 8,
        ));
    }

    // FPU vector registers FV0-FV3 (4x32-bit, 128-bit each)
    // FV0 = FR0|FR1|FR2|FR3, FV4 = FR4|FR5|FR6|FR7, etc.
    for i in 0..4u32 {
        bank.add(Register::new(
            &format!("FV{}", i * 4),
            128,
            0x0180 + (i as u64) * 16,
        ));
    }

    // ---- Extended FPU registers XF0-XF15 (32-bit each, SH-4 double-precision bank) ----
    for i in 0..16u32 {
        bank.add(Register::new(
            &format!("XF{}", i),
            32,
            0x0200 + (i as u64) * 4,
        ));
    }

    // Extended double-precision: XD0 = XF0|XF1, XD2 = XF2|XF3, ..., XD14 = XF14|XF15
    for i in 0..8u32 {
        let xf_even = i * 2;
        bank.add(Register::new(
            &format!("XD{}", xf_even),
            64,
            0x0240 + (i as u64) * 8,
        ));
    }

    // ---- FPU control registers ----
    bank.add(Register::new("FPSCR", 32, 0x0280)); // FPU Status/Control Register
    bank.add(Register::new("FPUL", 32, 0x0284)); // FPU Communication Register

    // FPSCR bit fields
    bank.add(Register::sub_register("FR", 1, 0x0280, "FPSCR", 21)); // FPU rounding mode (bit 21)
    bank.add(Register::sub_register("SZ", 1, 0x0280, "FPSCR", 20)); // Transfer size mode
    bank.add(Register::sub_register("PR", 1, 0x0280, "FPSCR", 19)); // Precision mode
    bank.add(Register::sub_register("DN", 1, 0x0280, "FPSCR", 18)); // Denormalization mode
    bank.add(Register::sub_register("CAUSE", 5, 0x0280, "FPSCR", 17)); // FPU exception cause
    bank.add(Register::sub_register("ENABLE", 5, 0x0280, "FPSCR", 12)); // FPU exception enable
    bank.add(Register::sub_register("FLAG", 5, 0x0280, "FPSCR", 7)); // FPU exception flag
    bank.add(Register::sub_register("RM", 2, 0x0280, "FPSCR", 0)); // Rounding mode

    // ---- Additional SH-4A registers ----
    bank.add(Register::new("PASSCR", 32, 0x0290)); // Physical Address Space Control
    bank.add(Register::new("IRMCR", 32, 0x0294)); // Instruction Re-fetch inhibit
    bank.add(Register::new("CCR", 32, 0x0298)); // Cache Control Register
    bank.add(Register::new("QACR0", 32, 0x029C)); // Queue Address Control 0
    bank.add(Register::new("QACR1", 32, 0x02A0)); // Queue Address Control 1
    bank.add(Register::new("MMUCR", 32, 0x02A4)); // MMU Control Register
    bank.add(Register::new("PTEH", 32, 0x02A8)); // Page Table Entry High
    bank.add(Register::new("PTEL", 32, 0x02AC)); // Page Table Entry Low
    bank.add(Register::new("PTEA", 32, 0x02B0)); // Page Table Entry Assistance
    bank.add(Register::new("TTB", 32, 0x02B4)); // Translation Table Base
    bank.add(Register::new("TEA", 32, 0x02B8)); // TLB Exception Address
    bank.add(Register::new("TRA", 32, 0x02BC)); // TRAPA Exception Address

    bank
}

/// Build the SuperH instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Data transfer ===
        InstructionMnemonic::new("mov"),
        InstructionMnemonic::new("movi"),
        InstructionMnemonic::new("movt"),
        InstructionMnemonic::new("mova"),
        InstructionMnemonic::new("swap_b"),
        InstructionMnemonic::new("swap_w"),
        InstructionMnemonic::new("xtrct"),
        InstructionMnemonic::new("extu_b"),
        InstructionMnemonic::new("extu_w"),
        InstructionMnemonic::new("exts_b"),
        InstructionMnemonic::new("exts_w"),
        // === Arithmetic ===
        InstructionMnemonic::new("add"),
        InstructionMnemonic::new("addc"),
        InstructionMnemonic::new("addv"),
        InstructionMnemonic::new("sub"),
        InstructionMnemonic::new("subc"),
        InstructionMnemonic::new("subv"),
        InstructionMnemonic::new("cmp_eq"),
        InstructionMnemonic::new("cmp_ge"),
        InstructionMnemonic::new("cmp_gt"),
        InstructionMnemonic::new("cmp_hi"),
        InstructionMnemonic::new("cmp_hs"),
        InstructionMnemonic::new("cmp_pl"),
        InstructionMnemonic::new("cmp_pz"),
        InstructionMnemonic::new("cmp_str"),
        InstructionMnemonic::new("neg"),
        InstructionMnemonic::new("negc"),
        InstructionMnemonic::new("not"),
        // === Logic ===
        InstructionMnemonic::new("and"),
        InstructionMnemonic::new("or"),
        InstructionMnemonic::new("xor"),
        InstructionMnemonic::new("tst"),
        InstructionMnemonic::new("tst_b"),
        InstructionMnemonic::new("tas_b"),
        // === Shifts ===
        InstructionMnemonic::new("shll"),
        InstructionMnemonic::new("shal"),
        InstructionMnemonic::new("shlr"),
        InstructionMnemonic::new("shar"),
        InstructionMnemonic::new("shll2"),
        InstructionMnemonic::new("shlr2"),
        InstructionMnemonic::new("shll8"),
        InstructionMnemonic::new("shlr8"),
        InstructionMnemonic::new("shll16"),
        InstructionMnemonic::new("shlr16"),
        InstructionMnemonic::new("rotl"),
        InstructionMnemonic::new("rotr"),
        InstructionMnemonic::new("rotcl"),
        InstructionMnemonic::new("rotcr"),
        // === Multiply / MAC ===
        InstructionMnemonic::new("mul_l"),
        InstructionMnemonic::new("mulu_w"),
        InstructionMnemonic::new("muls_w"),
        InstructionMnemonic::new("mac_l"),
        InstructionMnemonic::new("mac_w"),
        InstructionMnemonic::new("dmuls_l"),
        InstructionMnemonic::new("dmulu_l"),
        InstructionMnemonic::new("dt"),
        // === Divide ===
        InstructionMnemonic::new("div0s"),
        InstructionMnemonic::new("div0u"),
        InstructionMnemonic::new("div1"),
        InstructionMnemonic::new("divs"),
        // === Branch ===
        InstructionMnemonic::new("bf"),
        InstructionMnemonic::new("bf_s"),
        InstructionMnemonic::new("bt"),
        InstructionMnemonic::new("bt_s"),
        InstructionMnemonic::new("bra"),
        InstructionMnemonic::new("braf"),
        InstructionMnemonic::new("bsr"),
        InstructionMnemonic::new("bsrf"),
        InstructionMnemonic::new("jmp"),
        InstructionMnemonic::new("jsr"),
        InstructionMnemonic::new("rts"),
        InstructionMnemonic::new("rtd"),
        // === System / control ===
        InstructionMnemonic::new("trapa"),
        InstructionMnemonic::new("rte"),
        InstructionMnemonic::new("sleep"),
        InstructionMnemonic::new("clrt"),
        InstructionMnemonic::new("sett"),
        InstructionMnemonic::new("clrmac"),
        InstructionMnemonic::new("ldtlb"),
        InstructionMnemonic::new("nop"),
        // === Load / Store (R0-relative) ===
        InstructionMnemonic::new("mov_b"),
        InstructionMnemonic::new("mov_w"),
        InstructionMnemonic::new("mov_l"),
        InstructionMnemonic::new("mov_b_ind"),
        InstructionMnemonic::new("mov_w_ind"),
        InstructionMnemonic::new("mov_l_ind"),
        // Pre-decrement / post-increment
        InstructionMnemonic::new("mov_b_predec"),
        InstructionMnemonic::new("mov_w_predec"),
        InstructionMnemonic::new("mov_l_predec"),
        InstructionMnemonic::new("mov_b_postinc"),
        InstructionMnemonic::new("mov_w_postinc"),
        InstructionMnemonic::new("mov_l_postinc"),
        // === GBR-relative ===
        InstructionMnemonic::new("mov_b_gbr"),
        InstructionMnemonic::new("mov_w_gbr"),
        InstructionMnemonic::new("mov_l_gbr"),
        InstructionMnemonic::new("mova_gbr"),
        // === PC-relative ===
        InstructionMnemonic::new("mov_b_pc"),
        InstructionMnemonic::new("mov_w_pc"),
        InstructionMnemonic::new("mov_l_pc"),
        // === Store from system register ===
        InstructionMnemonic::new("ldc"),
        InstructionMnemonic::new("ldc_l"),
        InstructionMnemonic::new("stc"),
        InstructionMnemonic::new("stc_l"),
        InstructionMnemonic::new("lds"),
        InstructionMnemonic::new("lds_l"),
        InstructionMnemonic::new("sts"),
        InstructionMnemonic::new("sts_l"),
        // === Repeat (SH-2A) ===
        InstructionMnemonic::new("setrc"),
        // === Bit manipulation ===
        InstructionMnemonic::new("band_b"),
        InstructionMnemonic::new("bor_b"),
        InstructionMnemonic::new("bxor_b"),
        InstructionMnemonic::new("bclr"),
        InstructionMnemonic::new("bset"),
        InstructionMnemonic::new("bld_b"),
        InstructionMnemonic::new("bst_b"),
        InstructionMnemonic::new("bnot"),
        // === Conditional operations ===
        InstructionMnemonic::new("movt_c"),
        InstructionMnemonic::new("movbf"),
        InstructionMnemonic::new("movbt"),
        // === Bank switch (SH-2A) ===
        InstructionMnemonic::new("resbank"),
        // === Synch / prefetch ===
        InstructionMnemonic::new("synco"),
        InstructionMnemonic::new("pref"),
        InstructionMnemonic::new("prefi"),
        InstructionMnemonic::new("icbi"),
        InstructionMnemonic::new("ocbi"),
        InstructionMnemonic::new("ocbp"),
        InstructionMnemonic::new("ocbwb"),
        // === DSP (SH-2A) ===
        InstructionMnemonic::new("pabs"),
        InstructionMnemonic::new("padd"),
        InstructionMnemonic::new("paddc"),
        InstructionMnemonic::new("pand"),
        InstructionMnemonic::new("pclr"),
        InstructionMnemonic::new("pcmp"),
        InstructionMnemonic::new("pcopy"),
        InstructionMnemonic::new("pdec"),
        InstructionMnemonic::new("pdmsb"),
        InstructionMnemonic::new("pinc"),
        InstructionMnemonic::new("plds"),
        InstructionMnemonic::new("pmuls"),
        InstructionMnemonic::new("pneg"),
        InstructionMnemonic::new("por"),
        InstructionMnemonic::new("prnd"),
        InstructionMnemonic::new("psha"),
        InstructionMnemonic::new("psub"),
        InstructionMnemonic::new("pswap"),
        InstructionMnemonic::new("pxor"),
        // === FPU (SH-4) ===
        InstructionMnemonic::new("fabs"),
        InstructionMnemonic::new("fadd"),
        InstructionMnemonic::new("fcmp_eq"),
        InstructionMnemonic::new("fcmp_gt"),
        InstructionMnemonic::new("fcnvds"),
        InstructionMnemonic::new("fcnvsd"),
        InstructionMnemonic::new("fdiv"),
        InstructionMnemonic::new("fipr"),
        InstructionMnemonic::new("fldi0"),
        InstructionMnemonic::new("fldi1"),
        InstructionMnemonic::new("flds"),
        InstructionMnemonic::new("fsts"),
        InstructionMnemonic::new("fmac"),
        InstructionMnemonic::new("fmov"),
        InstructionMnemonic::new("fmul"),
        InstructionMnemonic::new("fneg"),
        InstructionMnemonic::new("frchg"),
        InstructionMnemonic::new("fschg"),
        InstructionMnemonic::new("fsqrt"),
        InstructionMnemonic::new("fsub"),
        InstructionMnemonic::new("ftrc"),
        InstructionMnemonic::new("fsca"),
        InstructionMnemonic::new("fsrra"),
        // Vector FPU operations
        InstructionMnemonic::new("fadd_v"),
        InstructionMnemonic::new("fsub_v"),
        InstructionMnemonic::new("fmul_v"),
        InstructionMnemonic::new("fdiv_v"),
        InstructionMnemonic::new("fmtrx"),
        InstructionMnemonic::new("ftrv"),
    ]
}

impl ProcessorModule for SuperHProcessor {
    fn name() -> &'static str {
        "Renesas SuperH"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "superh:LE:32:SH2",
                "SuperH SH-2 (32-bit, little-endian)",
                "SH-2",
                Endian::Little,
                32,
            ),
            Language::new(
                "superh:LE:32:SH2A",
                "SuperH SH-2A (32-bit, little-endian, with DSP)",
                "SH-2A",
                Endian::Little,
                32,
            ),
            Language::new(
                "superh:LE:32:SH3",
                "SuperH SH-3 (32-bit, little-endian, with MMU)",
                "SH-3",
                Endian::Little,
                32,
            ),
            Language::new(
                "superh:LE:32:SH4",
                "SuperH SH-4 (32-bit, little-endian, with FPU)",
                "SH-4",
                Endian::Little,
                32,
            ),
            Language::new(
                "superh:LE:32:SH4A",
                "SuperH SH-4A (32-bit, little-endian, with FPU + MMU)",
                "SH-4A",
                Endian::Little,
                32,
            ),
            Language::new(
                "superh:BE:32:SH2",
                "SuperH SH-2 (big-endian variant)",
                "SH-2",
                Endian::Big,
                32,
            ),
            Language::new(
                "superh:BE:32:SH4",
                "SuperH SH-4 (big-endian variant, with FPU)",
                "SH-4",
                Endian::Big,
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
    fn test_superh_name() {
        assert_eq!(SuperHProcessor::name(), "Renesas SuperH");
    }

    #[test]
    fn test_superh_registers() {
        let bank = SuperHProcessor::registers();
        assert!(
            bank.len() > 60,
            "Expected many registers, got {}",
            bank.len()
        );
        // GPRs
        assert!(bank.get("R0").is_some());
        assert!(bank.get("R15").is_some());
        assert!(bank.get("SP").is_some());
        // Banked
        assert!(bank.get("R0_BANK").is_some());
        assert!(bank.get("R7_BANK").is_some());
        // Control
        assert!(bank.get("SR").is_some());
        assert!(bank.get("GBR").is_some());
        assert!(bank.get("VBR").is_some());
        // System
        assert!(bank.get("MACH").is_some());
        assert!(bank.get("MACL").is_some());
        assert!(bank.get("PR").is_some());
        assert!(bank.get("PC").is_some());
        // FPU
        assert!(bank.get("FR0").is_some());
        assert!(bank.get("FR15").is_some());
        assert!(bank.get("DR0").is_some());
        assert!(bank.get("FPSCR").is_some());
        assert!(bank.get("FPUL").is_some());
        // Extended FPU
        assert!(bank.get("XF0").is_some());
        assert!(bank.get("XF15").is_some());
    }

    #[test]
    fn test_superh_sr_flags() {
        let bank = SuperHProcessor::registers();
        let t = bank.get("T").unwrap();
        assert_eq!(t.parent.as_deref(), Some("SR"));
        assert_eq!(t.lsb, 0);
        assert_eq!(t.bit_size, 1);

        let m = bank.get("M").unwrap();
        assert_eq!(m.lsb, 9);

        let md = bank.get("MD").unwrap();
        assert_eq!(md.lsb, 30);
    }

    #[test]
    fn test_superh_register_bits() {
        let bank = SuperHProcessor::registers();
        assert_eq!(bank.get("R0").unwrap().bit_size, 32);
        assert_eq!(bank.get("SR").unwrap().bit_size, 32);
        assert_eq!(bank.get("FR0").unwrap().bit_size, 32);
        assert_eq!(bank.get("DR0").unwrap().bit_size, 64);
        assert_eq!(bank.get("FV0").unwrap().bit_size, 128);
        assert_eq!(bank.get("A0").unwrap().bit_size, 40);
        assert_eq!(bank.get("A0G").unwrap().bit_size, 8);
    }

    #[test]
    fn test_superh_languages() {
        let langs = SuperHProcessor::languages();
        assert!(langs.len() >= 5);
        assert!(langs.iter().any(|l| l.id == "superh:LE:32:SH2"));
        assert!(langs.iter().any(|l| l.id == "superh:LE:32:SH4"));
        assert!(langs.iter().any(|l| l.id == "superh:LE:32:SH4A"));
        // Should have big-endian variants
        assert!(langs.iter().any(|l| l.id == "superh:BE:32:SH4"));
    }

    #[test]
    fn test_superh_instructions() {
        let insts = SuperHProcessor::instructions();
        assert!(insts.len() > 60);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"mov"));
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"bf"));
        assert!(texts.contains(&"bt"));
        assert!(texts.contains(&"bra"));
        assert!(texts.contains(&"bsr"));
        assert!(texts.contains(&"jmp"));
        assert!(texts.contains(&"jsr"));
        assert!(texts.contains(&"rts"));
        assert!(texts.contains(&"rte"));
        assert!(texts.contains(&"mul_l"));
        assert!(texts.contains(&"mac_l"));
        assert!(texts.contains(&"ldc"));
        assert!(texts.contains(&"stc"));
        assert!(texts.contains(&"fadd"));
        assert!(texts.contains(&"fmul"));
        assert!(texts.contains(&"fdiv"));
        assert!(texts.contains(&"fsqrt"));
        assert!(texts.contains(&"ftrv"));
    }

    #[test]
    fn test_superh_banked_registers() {
        let bank = SuperHProcessor::registers();
        for i in 0..8u32 {
            let name = format!("R{}_BANK", i);
            assert!(
                bank.get(&name).is_some(),
                "Missing banked register {}",
                name
            );
            assert_eq!(bank.get(&name).unwrap().bit_size, 32);
        }
    }
}
