//! Tensilica Xtensa Processor Module
//!
//! Supports Xtensa LX6 (ESP32), LX7 (ESP32-S2/S3), and NX (ESP32-S3) variants.
//!
//! Xtensa is a configurable 32-bit RISC processor core with register windows,
//! designed by Tensilica (now Cadence). It is used extensively in Espressif
//! ESP32 series microcontrollers.
//!
//! ## Key features
//! - Register windows: 64 physical AR registers, 16 visible at a time
//! - Windowed call/return with automatic spill/fill via exceptions
//! - HiFi DSP extensions (optional)
//! - Configurable instruction set
//!
//! ## Register space layout
//! - Address registers (AR0-AR63):  0x0000 - 0x00FC  (32-bit each)
//! - Special registers:             0x0100 - 0x01FF
//! - HiFi DSP registers (AE):       0x0200 - 0x02FF

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Xtensa processor struct.
pub struct XtensaProcessor;

/// Build the complete Xtensa register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- Physical address registers AR0-AR63 (32-bit each) ----
    // Only 16 are visible at any time through the register window.
    // AR0-AR3 are the "rotating" window base; caller-saved registers start at AR4.
    // AR0 = sp, AR1 = a1 (return address / stack pointer alternate)
    for i in 0..64u32 {
        let visible = i < 16;
        let desc = if visible {
            format!("AR{}", i)
        } else {
            format!("AR{}", i)
        };
        bank.add(Register::new(&desc, 32, 0x0000 + (i as u64) * 4));
    }

    // Visible register aliases (as seen through current window)
    bank.add(Register::sub_register("SP", 32, 0x0000 + 1 * 4, "AR1", 0)); // Stack pointer (typically AR1)
    bank.add(Register::sub_register("A0", 32, 0x0000 + 0 * 4, "AR0", 0)); // Return address
    bank.add(Register::sub_register("A1", 32, 0x0000 + 1 * 4, "AR1", 0)); // Stack pointer
    bank.add(Register::sub_register("A2", 32, 0x0000 + 2 * 4, "AR2", 0)); // Function argument 0
    bank.add(Register::sub_register("A3", 32, 0x0000 + 3 * 4, "AR3", 0)); // Function argument 1
    bank.add(Register::sub_register("A4", 32, 0x0000 + 4 * 4, "AR4", 0)); // Function argument 2
    bank.add(Register::sub_register("A5", 32, 0x0000 + 5 * 4, "AR5", 0)); // Function argument 3
    bank.add(Register::sub_register("A6", 32, 0x0000 + 6 * 4, "AR6", 0)); // Function argument 4
    bank.add(Register::sub_register("A7", 32, 0x0000 + 7 * 4, "AR7", 0)); // Function argument 5
    bank.add(Register::sub_register("A8", 32, 0x0000 + 8 * 4, "AR8", 0));
    bank.add(Register::sub_register("A9", 32, 0x0000 + 9 * 4, "AR9", 0));
    bank.add(Register::sub_register(
        "A10",
        32,
        0x0000 + 10 * 4,
        "AR10",
        0,
    ));
    bank.add(Register::sub_register(
        "A11",
        32,
        0x0000 + 11 * 4,
        "AR11",
        0,
    ));
    bank.add(Register::sub_register(
        "A12",
        32,
        0x0000 + 12 * 4,
        "AR12",
        0,
    ));
    bank.add(Register::sub_register(
        "A13",
        32,
        0x0000 + 13 * 4,
        "AR13",
        0,
    ));
    bank.add(Register::sub_register(
        "A14",
        32,
        0x0000 + 14 * 4,
        "AR14",
        0,
    ));
    bank.add(Register::sub_register(
        "A15",
        32,
        0x0000 + 15 * 4,
        "AR15",
        0,
    ));

    // ---- Program Counter ----
    bank.add(Register::new("PC", 32, 0x0100));

    // ---- Special Registers (SR) ----
    bank.add(Register::new("SAR", 32, 0x0104)); // Shift Amount Register (bits 0-4/0-5)
    bank.add(Register::new("LITBASE", 32, 0x0108)); // Literal base address
    bank.add(Register::new("LCOUNT", 32, 0x010C)); // Zero-overhead loop count
    bank.add(Register::new("LBEGIN", 32, 0x0110)); // Zero-overhead loop begin address
    bank.add(Register::new("LEND", 32, 0x0114)); // Zero-overhead loop end address

    // Window management
    bank.add(Register::new("WINDOWBASE", 32, 0x0118)); // Window base register
    bank.add(Register::new("WINDOWSTART", 32, 0x011C)); // Window start bitmask

    // Processor state
    bank.add(Register::new("PS", 32, 0x0120)); // Program State (PS, includes INTLEVEL, EXCM, etc.)
    bank.add(Register::new("EXCCAUSE", 32, 0x0124)); // Exception cause register
    bank.add(Register::new("EXCVADDR", 32, 0x0128)); // Exception virtual address
    bank.add(Register::new("EXCSAVE1", 32, 0x012C)); // Exception save register 1
    bank.add(Register::new("EXCSAVE2", 32, 0x0130)); // Exception save register 2
    bank.add(Register::new("EPC1", 32, 0x0134)); // Exception PC 1
    bank.add(Register::new("EPC2", 32, 0x0138)); // Exception PC 2
    bank.add(Register::new("EPC3", 32, 0x013C)); // Exception PC 3
    bank.add(Register::new("EPC4", 32, 0x0140)); // Exception PC 4
    bank.add(Register::new("DEPC", 32, 0x0144)); // Double exception PC
    bank.add(Register::new("EPS2", 32, 0x0148)); // Exception PS 2
    bank.add(Register::new("EPS3", 32, 0x014C)); // Exception PS 3
    bank.add(Register::new("EPS4", 32, 0x0150)); // Exception PS 4

    // Interrupt control
    bank.add(Register::new("INTENABLE", 32, 0x0154)); // Interrupt enable
    bank.add(Register::new("INTSET", 32, 0x0158)); // Interrupt set
    bank.add(Register::new("INTCLEAR", 32, 0x015C)); // Interrupt clear
    bank.add(Register::new("INTSTATUS", 32, 0x0160)); // Interrupt status

    // Debug
    bank.add(Register::new("DEBUGCAUSE", 32, 0x0164)); // Debug cause
    bank.add(Register::new("ICOUNT", 32, 0x0168)); // Instruction count
    bank.add(Register::new("ICOUNTLEVEL", 32, 0x016C)); // Instruction count level
    bank.add(Register::new("DDR", 32, 0x0170)); // Debug data register

    // Cache / MMU
    bank.add(Register::new("CACHEATTR", 32, 0x0180)); // Cache attribute
    bank.add(Register::new("CACHEADDR", 32, 0x0184)); // Cache address register
    bank.add(Register::new("PREFCTL", 32, 0x0188)); // Prefetch control
    bank.add(Register::new("MEMCTL", 32, 0x018C)); // Memory control
    bank.add(Register::new("DTLBCFG", 32, 0x0190)); // DTLB configuration
    bank.add(Register::new("ITLBCFG", 32, 0x0194)); // ITLB configuration
    bank.add(Register::new("RASID", 32, 0x0198)); // Ring ASID
    bank.add(Register::new("PTEVADDR", 32, 0x019C)); // PTE virtual address

    // Misc system
    bank.add(Register::new("PRID", 32, 0x01A0)); // Processor ID
    bank.add(Register::new("MISC0", 32, 0x01A4)); // Misc special 0
    bank.add(Register::new("MISC1", 32, 0x01A8)); // Misc special 1
    bank.add(Register::new("MISC2", 32, 0x01AC)); // Misc special 2
    bank.add(Register::new("MISC3", 32, 0x01B0)); // Misc special 3
    bank.add(Register::new("VECBASE", 32, 0x01B4)); // Vector base
    bank.add(Register::new("THREADPTR", 32, 0x01B8)); // Thread pointer
    bank.add(Register::new("ATOMCTL", 32, 0x01BC)); // Atomic operation control
    bank.add(Register::new("SCOMPARE1", 32, 0x01C0)); // S32C1I compare value

    // ---- HiFi DSP Extension Registers (Audio Engine / AE) ----
    // AE data registers (64-bit accumulator pairs)
    bank.add(Register::new("AE_OVF_SAR", 32, 0x0200)); // AE overflow and shift amount
    bank.add(Register::new("AE_BITHEAD", 16, 0x0204)); // Bitstream head pointer
    bank.add(Register::new("AE_BITPTR", 32, 0x0208)); // Bitstream pointer
    bank.add(Register::new("AE_BITAMOUNT", 5, 0x020C)); // Bits consumed
    bank.add(Register::new("AE_TS_REG", 16, 0x0210)); // TIE state register
    bank.add(Register::new("AE_SAR_SHIFT", 8, 0x0214)); // SAR Shift for DSP
    bank.add(Register::new("QR0", 56, 0x0218)); // 56-bit accumulator 0
    bank.add(Register::new("QR1", 56, 0x0220)); // 56-bit accumulator 1
    bank.add(Register::new("QR2", 56, 0x0228)); // 56-bit accumulator 2
    bank.add(Register::new("QR3", 56, 0x0230)); // 56-bit accumulator 3
    bank.add(Register::new("QR4", 56, 0x0238)); // 56-bit accumulator 4
    bank.add(Register::new("QR5", 56, 0x0240)); // 56-bit accumulator 5
    bank.add(Register::new("QR6", 56, 0x0248)); // 56-bit accumulator 6
    bank.add(Register::new("QR7", 56, 0x0250)); // 56-bit accumulator 7

    // ---- MAC16 extension registers ----
    bank.add(Register::new("M0", 32, 0x0280));
    bank.add(Register::new("M1", 32, 0x0284));
    bank.add(Register::new("M2", 32, 0x0288));
    bank.add(Register::new("M3", 32, 0x028C));
    bank.add(Register::new("ACCLO", 32, 0x0290));
    bank.add(Register::new("ACCHI", 32, 0x0294));
    bank.add(Register::new("MR0", 32, 0x0298));
    bank.add(Register::new("MR1", 32, 0x029C));
    bank.add(Register::new("MR2", 32, 0x02A0));
    bank.add(Register::new("MR3", 32, 0x02A4));

    // ---- FPU / Co-processor registers ----
    bank.add(Register::new("FCR", 32, 0x02C0)); // FPU control register
    bank.add(Register::new("FSR", 32, 0x02C4)); // FPU status register
    for i in 0..16u32 {
        bank.add(Register::new(
            &format!("F{}", i),
            32,
            0x02D0 + (i as u64) * 4,
        ));
    }

    bank
}

/// Build the Xtensa instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === ALU (RRI8 / RRR formats) ===
        InstructionMnemonic::new("add"),
        InstructionMnemonic::new("addi"),
        InstructionMnemonic::new("addmi"),
        InstructionMnemonic::new("addx2"),
        InstructionMnemonic::new("addx4"),
        InstructionMnemonic::new("addx8"),
        InstructionMnemonic::new("sub"),
        InstructionMnemonic::new("subx2"),
        InstructionMnemonic::new("subx4"),
        InstructionMnemonic::new("subx8"),
        InstructionMnemonic::new("and"),
        InstructionMnemonic::new("or"),
        InstructionMnemonic::new("xor"),
        InstructionMnemonic::new("neg"),
        InstructionMnemonic::new("abs"),
        InstructionMnemonic::new("min"),
        InstructionMnemonic::new("minu"),
        InstructionMnemonic::new("max"),
        InstructionMnemonic::new("maxu"),
        InstructionMnemonic::new("movi"),
        InstructionMnemonic::new("mov"),
        InstructionMnemonic::new("moveqz"),
        InstructionMnemonic::new("movnez"),
        InstructionMnemonic::new("movltz"),
        InstructionMnemonic::new("movgez"),
        InstructionMnemonic::new("ssl"),
        InstructionMnemonic::new("ssr"),
        InstructionMnemonic::new("ssa8l"),
        InstructionMnemonic::new("ssa8b"),
        InstructionMnemonic::new("ssai"),
        InstructionMnemonic::new("sll"),
        InstructionMnemonic::new("slli"),
        InstructionMnemonic::new("srl"),
        InstructionMnemonic::new("srli"),
        InstructionMnemonic::new("sra"),
        InstructionMnemonic::new("srai"),
        InstructionMnemonic::new("src"),
        // === Multiply (MAC16 / 32-bit MUL) ===
        InstructionMnemonic::new("mul16u"),
        InstructionMnemonic::new("mul16s"),
        InstructionMnemonic::new("mull"),
        InstructionMnemonic::new("muluh"),
        InstructionMnemonic::new("mulsh"),
        InstructionMnemonic::new("mula"),
        InstructionMnemonic::new("muls"),
        InstructionMnemonic::new("umul"),
        InstructionMnemonic::new("umula"),
        // MAC16 operations
        InstructionMnemonic::new("mula_da"),
        InstructionMnemonic::new("muls_da"),
        InstructionMnemonic::new("mula_dd"),
        InstructionMnemonic::new("muls_dd"),
        InstructionMnemonic::new("mul_ad"),
        InstructionMnemonic::new("muls_ad"),
        // === Extended Arithmetic ===
        InstructionMnemonic::new("sext"),
        InstructionMnemonic::new("nsa"),
        InstructionMnemonic::new("nsau"),
        InstructionMnemonic::new("clamps"),
        // === Load / Store ===
        InstructionMnemonic::new("l32i"),
        InstructionMnemonic::new("l32r"),
        InstructionMnemonic::new("l16ui"),
        InstructionMnemonic::new("l16si"),
        InstructionMnemonic::new("l8ui"),
        InstructionMnemonic::new("s32i"),
        InstructionMnemonic::new("s16i"),
        InstructionMnemonic::new("s8i"),
        InstructionMnemonic::new("l32e"),
        InstructionMnemonic::new("s32e"),
        InstructionMnemonic::new("l32i_n"),
        InstructionMnemonic::new("s32i_n"),
        // Cache prefetch
        InstructionMnemonic::new("dpfr"),
        InstructionMnemonic::new("dpfro"),
        InstructionMnemonic::new("dpf"),
        InstructionMnemonic::new("dhwb"),
        InstructionMnemonic::new("dhwbi"),
        InstructionMnemonic::new("dhi"),
        InstructionMnemonic::new("dii"),
        InstructionMnemonic::new("dciu"),
        // === Branch ===
        InstructionMnemonic::new("beq"),
        InstructionMnemonic::new("bne"),
        InstructionMnemonic::new("bge"),
        InstructionMnemonic::new("bgeu"),
        InstructionMnemonic::new("blt"),
        InstructionMnemonic::new("bltu"),
        InstructionMnemonic::new("bgez"),
        InstructionMnemonic::new("bltz"),
        InstructionMnemonic::new("beqz"),
        InstructionMnemonic::new("bnez"),
        InstructionMnemonic::new("bany"),
        InstructionMnemonic::new("bnone"),
        InstructionMnemonic::new("ball"),
        InstructionMnemonic::new("bnall"),
        InstructionMnemonic::new("bbc"),
        InstructionMnemonic::new("bbs"),
        InstructionMnemonic::new("j"),
        InstructionMnemonic::new("jx"),
        // === Call / Return (windowed) ===
        InstructionMnemonic::new("call0"),
        InstructionMnemonic::new("callx0"),
        InstructionMnemonic::new("call4"),
        InstructionMnemonic::new("callx4"),
        InstructionMnemonic::new("call8"),
        InstructionMnemonic::new("callx8"),
        InstructionMnemonic::new("call12"),
        InstructionMnemonic::new("callx12"),
        InstructionMnemonic::new("ret"),
        InstructionMnemonic::new("retw"),
        InstructionMnemonic::new("retw_n"),
        InstructionMnemonic::new("entry"),
        // === Window management ===
        InstructionMnemonic::new("rotw"),
        // === Zero-overhead loop ===
        InstructionMnemonic::new("loop"),
        InstructionMnemonic::new("loopnez"),
        InstructionMnemonic::new("loopgtz"),
        InstructionMnemonic::new("nop"),
        // === System / break ===
        InstructionMnemonic::new("break"),
        InstructionMnemonic::new("break_n"),
        InstructionMnemonic::new("syscall"),
        InstructionMnemonic::new("simcall"),
        InstructionMnemonic::new("rsr"),
        InstructionMnemonic::new("wsr"),
        InstructionMnemonic::new("xsr"),
        InstructionMnemonic::new("rsil"),
        InstructionMnemonic::new("waiti"),
        InstructionMnemonic::new("rfdd"),
        InstructionMnemonic::new("rfde"),
        InstructionMnemonic::new("rfi"),
        InstructionMnemonic::new("rfe"),
        InstructionMnemonic::new("rfwo"),
        InstructionMnemonic::new("rfwu"),
        // === Atomic ===
        InstructionMnemonic::new("s32c1i"),
        // === Bit manipulation ===
        InstructionMnemonic::new("extui"),
        InstructionMnemonic::new("extw"),
        // === TIE / Coprocessor ===
        InstructionMnemonic::new("bany_c"),
        InstructionMnemonic::new("bnone_c"),
        InstructionMnemonic::new("rur"),
        InstructionMnemonic::new("wur"),
        InstructionMnemonic::new("ldc"),
        InstructionMnemonic::new("sdc"),
        // === HiFi DSP instructions (AE_xxx) ===
        InstructionMnemonic::new("ae_l32"),
        InstructionMnemonic::new("ae_s32"),
        InstructionMnemonic::new("ae_l16"),
        InstructionMnemonic::new("ae_s16"),
        InstructionMnemonic::new("ae_mul"),
        InstructionMnemonic::new("ae_mac"),
        InstructionMnemonic::new("ae_msu"),
        InstructionMnemonic::new("ae_add"),
        InstructionMnemonic::new("ae_sub"),
        InstructionMnemonic::new("ae_and"),
        InstructionMnemonic::new("ae_or"),
        InstructionMnemonic::new("ae_xor"),
        InstructionMnemonic::new("ae_neg"),
        InstructionMnemonic::new("ae_abs"),
        InstructionMnemonic::new("ae_shift_sat"),
        InstructionMnemonic::new("ae_round"),
        InstructionMnemonic::new("ae_trunc"),
        InstructionMnemonic::new("ae_min"),
        InstructionMnemonic::new("ae_max"),
        InstructionMnemonic::new("ae_sel"),
        InstructionMnemonic::new("ae_mov"),
        InstructionMnemonic::new("ae_zerop48"),
        InstructionMnemonic::new("ae_mulaf"),
        InstructionMnemonic::new("ae_mulsf"),
        // === FPU ===
        InstructionMnemonic::new("add_s"),
        InstructionMnemonic::new("sub_s"),
        InstructionMnemonic::new("mul_s"),
        InstructionMnemonic::new("madd_s"),
        InstructionMnemonic::new("msub_s"),
        InstructionMnemonic::new("div_s"),
        InstructionMnemonic::new("sqrt_s"),
        InstructionMnemonic::new("abs_s"),
        InstructionMnemonic::new("neg_s"),
        InstructionMnemonic::new("round_s"),
        InstructionMnemonic::new("trunc_s"),
        InstructionMnemonic::new("ceil_s"),
        InstructionMnemonic::new("floor_s"),
        InstructionMnemonic::new("float_s"),
        InstructionMnemonic::new("ufloat_s"),
        InstructionMnemonic::new("mov_s"),
        InstructionMnemonic::new("cmp_s"),
        InstructionMnemonic::new("lsi"),
        InstructionMnemonic::new("ssi"),
        InstructionMnemonic::new("lsip"),
        InstructionMnemonic::new("ssip"),
    ]
}

impl ProcessorModule for XtensaProcessor {
    fn name() -> &'static str {
        "Tensilica Xtensa"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "xtensa:LE:32:LX6",
                "Xtensa LX6 (ESP32, 32-bit, little-endian)",
                "LX6",
                Endian::Little,
                32,
            ),
            Language::new(
                "xtensa:LE:32:LX7",
                "Xtensa LX7 (ESP32-S2/S3, 32-bit, little-endian)",
                "LX7",
                Endian::Little,
                32,
            ),
            Language::new(
                "xtensa:LE:32:LX7_HiFi",
                "Xtensa LX7 with HiFi DSP (ESP32-S3, 32-bit, little-endian)",
                "LX7_HiFi",
                Endian::Little,
                32,
            ),
            Language::new(
                "xtensa:LE:32:NX",
                "Xtensa NX (ESP32-S3, 32-bit, little-endian)",
                "NX",
                Endian::Little,
                32,
            ),
            Language::new(
                "xtensa:LE:32:DC233L",
                "Xtensa DC233L (Diamond Standard 233L)",
                "DC233L",
                Endian::Little,
                32,
            ),
            Language::new(
                "xtensa:BE:32:LX6",
                "Xtensa LX6 (big-endian variant)",
                "LX6",
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
    fn test_xtensa_name() {
        assert_eq!(XtensaProcessor::name(), "Tensilica Xtensa");
    }

    #[test]
    fn test_xtensa_registers() {
        let bank = XtensaProcessor::registers();
        assert!(
            bank.len() > 80,
            "Expected many registers, got {}",
            bank.len()
        );
        assert!(bank.get("AR0").is_some());
        assert!(bank.get("AR63").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("SAR").is_some());
        assert!(bank.get("LITBASE").is_some());
        assert!(bank.get("LCOUNT").is_some());
        assert!(bank.get("LBEGIN").is_some());
        assert!(bank.get("LEND").is_some());
        assert!(bank.get("WINDOWBASE").is_some());
        assert!(bank.get("WINDOWSTART").is_some());
        assert!(bank.get("PS").is_some());
        assert!(bank.get("EXCCAUSE").is_some());
        assert!(bank.get("EPC1").is_some());
        assert!(bank.get("INTENABLE").is_some());
        assert!(bank.get("AE_OVF_SAR").is_some());
        assert!(bank.get("QR0").is_some());
        assert!(bank.get("QR7").is_some());
    }

    #[test]
    fn test_xtensa_register_bits() {
        let bank = XtensaProcessor::registers();
        assert_eq!(bank.get("AR0").unwrap().bit_size, 32);
        assert_eq!(bank.get("AR63").unwrap().bit_size, 32);
        assert_eq!(bank.get("PC").unwrap().bit_size, 32);
        assert_eq!(bank.get("SAR").unwrap().bit_size, 32);
        assert_eq!(bank.get("QR0").unwrap().bit_size, 56);
        assert_eq!(bank.get("AE_BITAMOUNT").unwrap().bit_size, 5);
    }

    #[test]
    fn test_xtensa_languages() {
        let langs = XtensaProcessor::languages();
        assert!(langs.len() >= 4);
        assert!(langs.iter().any(|l| l.id == "xtensa:LE:32:LX6"));
        assert!(langs.iter().any(|l| l.id == "xtensa:LE:32:LX7"));
        assert!(langs.iter().any(|l| l.id == "xtensa:LE:32:NX"));
        // Should have at least one big-endian variant
        assert!(langs.iter().any(|l| l.id == "xtensa:BE:32:LX6"));
    }

    #[test]
    fn test_xtensa_instructions() {
        let insts = XtensaProcessor::instructions();
        assert!(insts.len() > 60);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"l32i"));
        assert!(texts.contains(&"s32i"));
        assert!(texts.contains(&"call0"));
        assert!(texts.contains(&"call8"));
        assert!(texts.contains(&"ret"));
        assert!(texts.contains(&"loop"));
        assert!(texts.contains(&"entry"));
        assert!(texts.contains(&"ae_mul"));
        assert!(texts.contains(&"ae_mac"));
        assert!(texts.contains(&"add_s"));
    }

    #[test]
    fn test_xtensa_window_registers() {
        let bank = XtensaProcessor::registers();
        // Window management registers should exist
        assert!(bank.get("WINDOWBASE").is_some());
        assert!(bank.get("WINDOWSTART").is_some());
        // All 64 physical AR registers
        for i in 0..64 {
            let name = format!("AR{}", i);
            assert!(bank.get(&name).is_some(), "Missing register {}", name);
        }
    }
}
