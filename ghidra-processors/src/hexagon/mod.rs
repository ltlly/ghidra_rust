//! Qualcomm Hexagon DSP Processor Module
//!
//! Supports Hexagon V4, V5, V6, V7, and V8 ISA variants.
//!
//! The Hexagon is a VLIW DSP architecture used in Qualcomm Snapdragon SoCs.
//! Instructions are organized into packets of up to 4 instructions that
//! execute in parallel.
//!
//! ## Register space layout
//! - General-purpose (R0-R31):  0x0000 - 0x00F8  (32-bit each)
//! - Predicate (P0-P3):         0x0100 - 0x010C  (8-bit each)
//! - Modifier (M0-M1):          0x0140 - 0x0148  (32-bit each)
//! - Control (LC0-LC1, SA0-SA1): 0x0180 - 0x0198 (32-bit each)
//! - Special (USR, UGP, GP, CS0-CS1, PC): 0x0200 - 0x0228
//! - Coprocessor (C0-C31):      0x0300 - 0x03F8  (64-bit each)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Hexagon processor struct.
pub struct HexagonProcessor;

/// Build the complete Hexagon register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- General-purpose registers R0-R31 (32-bit) ----
    for i in 0..32u32 {
        bank.add(Register::new(
            &format!("R{}", i),
            32,
            0x0000 + (i as u64) * 4,
        ));
    }

    // Aliases: R29 = SP (stack pointer), R30 = FP (frame pointer), R31 = LR (link register)
    bank.add(Register::sub_register("SP", 32, 0x0000 + 29 * 4, "R29", 0));
    bank.add(Register::sub_register("FP", 32, 0x0000 + 30 * 4, "R30", 0));
    bank.add(Register::sub_register("LR", 32, 0x0000 + 31 * 4, "R31", 0));

    // 64-bit register pairs: R1:0, R3:2, ..., R31:30
    for i in 0..16u32 {
        let r_even = i * 2;
        let r_odd = r_even + 1;
        bank.add(Register::new(
            &format!("R{}:{}", r_odd, r_even),
            64,
            0x0400 + (i as u64) * 8,
        ));
    }

    // ---- Predicate registers P0-P3 (8-bit) ----
    for i in 0..4u32 {
        bank.add(Register::new(
            &format!("P{}", i),
            8,
            0x0100 + (i as u64) * 4,
        ));
    }

    // ---- Modifier registers M0-M1 (32-bit) ----
    bank.add(Register::new("M0", 32, 0x0140));
    bank.add(Register::new("M1", 32, 0x0144));

    // ---- Hardware loop registers ----
    bank.add(Register::new("LC0", 32, 0x0180)); // Loop count 0
    bank.add(Register::new("LC1", 32, 0x0184)); // Loop count 1
    bank.add(Register::new("SA0", 32, 0x0188)); // Start address 0
    bank.add(Register::new("SA1", 32, 0x018C)); // Start address 1
    bank.add(Register::new("LE0", 32, 0x0190)); // Loop end 0
    bank.add(Register::new("LE1", 32, 0x0194)); // Loop end 1

    // ---- Special registers ----
    bank.add(Register::new("PC", 32, 0x0200)); // Program counter
    bank.add(Register::new("USR", 32, 0x0204)); // User status register
    bank.add(Register::new("UGP", 32, 0x0208)); // User global pointer
    bank.add(Register::new("GP", 32, 0x020C)); // Global pointer
    bank.add(Register::new("CS0", 32, 0x0210)); // Core status 0
    bank.add(Register::new("CS1", 32, 0x0214)); // Core status 1
    bank.add(Register::new("SSR", 32, 0x0218)); // Sub-system register
    bank.add(Register::new("IMASK", 32, 0x021C)); // Interrupt mask
    bank.add(Register::new("IPEND", 32, 0x0220)); // Interrupt pending
    bank.add(Register::new("IEL", 32, 0x0224)); // Interrupt enable local
    bank.add(Register::new("IAHL", 32, 0x0228)); // Interrupt acknowledge high/low
    bank.add(Register::new("BADVA", 32, 0x022C)); // Bad virtual address
    bank.add(Register::new("EVB", 32, 0x0230)); // Exception vector base
    bank.add(Register::new("MODECTL", 32, 0x0234)); // Mode control
    bank.add(Register::new("SYSCFG", 32, 0x0238)); // System configuration
    bank.add(Register::new("UTIMERLO", 32, 0x023C)); // User timer low
    bank.add(Register::new("UTIMERHI", 32, 0x0240)); // User timer high

    // ---- Coprocessor registers C0-C31 (64-bit) ----
    for i in 0..32u32 {
        bank.add(Register::new(
            &format!("C{}", i),
            64,
            0x0300 + (i as u64) * 8,
        ));
    }

    // ---- Q6 vector registers (128-bit) for HVX (Hexagon Vector eXtensions) ----
    for i in 0..32u32 {
        bank.add(Register::new(
            &format!("V{}", i),
            1024,
            0x0500 + (i as u64) * 128,
        ));
    }
    // Vector predicate registers
    for i in 0..4u32 {
        bank.add(Register::new(
            &format!("Q{}", i),
            128,
            0x1500 + (i as u64) * 16,
        ));
    }

    bank
}

/// Build the Hexagon instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === ALU instructions ===
        InstructionMnemonic::new("add"),
        InstructionMnemonic::new("addi"),
        InstructionMnemonic::new("sub"),
        InstructionMnemonic::new("subi"),
        InstructionMnemonic::new("and"),
        InstructionMnemonic::new("andn"),
        InstructionMnemonic::new("or"),
        InstructionMnemonic::new("orn"),
        InstructionMnemonic::new("xor"),
        InstructionMnemonic::new("xnor"),
        InstructionMnemonic::new("not"),
        InstructionMnemonic::new("neg"),
        InstructionMnemonic::new("abs"),
        InstructionMnemonic::new("min"),
        InstructionMnemonic::new("max"),
        InstructionMnemonic::new("cmp"),
        InstructionMnemonic::new("cmpi"),
        InstructionMnemonic::new("tst"),
        InstructionMnemonic::new("tsti"),
        InstructionMnemonic::new("lsl"),
        InstructionMnemonic::new("lsr"),
        InstructionMnemonic::new("asr"),
        InstructionMnemonic::new("rotl"),
        InstructionMnemonic::new("rotr"),
        InstructionMnemonic::new("cl0"),
        InstructionMnemonic::new("cl1"),
        InstructionMnemonic::new("mux"),
        InstructionMnemonic::new("extract"),
        InstructionMnemonic::new("insert"),
        InstructionMnemonic::new("sxt"),
        InstructionMnemonic::new("zxt"),
        // Saturating arithmetic
        InstructionMnemonic::new("sadd"),
        InstructionMnemonic::new("ssub"),
        InstructionMnemonic::new("smin"),
        InstructionMnemonic::new("smax"),
        // Multiply-accumulate
        InstructionMnemonic::new("mpy"),
        InstructionMnemonic::new("mpyi"),
        InstructionMnemonic::new("mpyu"),
        InstructionMnemonic::new("mac"),
        InstructionMnemonic::new("maci"),
        InstructionMnemonic::new("dmac"),
        InstructionMnemonic::new("qmac"),
        // Complex multiply
        InstructionMnemonic::new("cmpy"),
        InstructionMnemonic::new("cmpyi"),
        InstructionMnemonic::new("cmac"),
        // === Load/store instructions ===
        InstructionMnemonic::new("ld"),
        InstructionMnemonic::new("ldi"),
        InstructionMnemonic::new("ldb"),
        InstructionMnemonic::new("ldh"),
        InstructionMnemonic::new("ldw"),
        InstructionMnemonic::new("ldd"),
        InstructionMnemonic::new("st"),
        InstructionMnemonic::new("stb"),
        InstructionMnemonic::new("sth"),
        InstructionMnemonic::new("stw"),
        InstructionMnemonic::new("std"),
        InstructionMnemonic::new("ldr"),
        InstructionMnemonic::new("str"),
        // Memop instructions (load-modify-store)
        InstructionMnemonic::new("memseth"),
        InstructionMnemonic::new("memsetw"),
        InstructionMnemonic::new("memclrh"),
        InstructionMnemonic::new("memclrw"),
        InstructionMnemonic::new("memaddh"),
        InstructionMnemonic::new("memaddw"),
        InstructionMnemonic::new("memsubh"),
        InstructionMnemonic::new("memsubw"),
        // === Transfer/control instructions ===
        InstructionMnemonic::new("move"),
        InstructionMnemonic::new("mov"),
        InstructionMnemonic::new("tfr"),
        InstructionMnemonic::new("set"),
        InstructionMnemonic::new("clear"),
        InstructionMnemonic::new("toggle"),
        InstructionMnemonic::new("transfer"),
        InstructionMnemonic::new("jump"),
        InstructionMnemonic::new("j"),
        InstructionMnemonic::new("jr"),
        InstructionMnemonic::new("call"),
        InstructionMnemonic::new("callr"),
        InstructionMnemonic::new("ret"),
        InstructionMnemonic::new("dealloc_return"),
        InstructionMnemonic::new("deallocframe"),
        InstructionMnemonic::new("allocframe"),
        InstructionMnemonic::new("swi"),
        InstructionMnemonic::new("trap"),
        InstructionMnemonic::new("pause"),
        InstructionMnemonic::new("barrier"),
        InstructionMnemonic::new("syncht"),
        InstructionMnemonic::new("dccleana"),
        InstructionMnemonic::new("dccleanva"),
        InstructionMnemonic::new("dccleaninva"),
        InstructionMnemonic::new("dcfetch"),
        InstructionMnemonic::new("icinva"),
        InstructionMnemonic::new("isync"),
        InstructionMnemonic::new("l2lock"),
        InstructionMnemonic::new("l2unlock"),
        InstructionMnemonic::new("l2fetch"),
        // === Conditional instructions (predicated) ===
        InstructionMnemonic::new("if_eq"),
        InstructionMnemonic::new("if_ne"),
        InstructionMnemonic::new("if_gt"),
        InstructionMnemonic::new("if_ge"),
        InstructionMnemonic::new("if_lt"),
        InstructionMnemonic::new("if_le"),
        InstructionMnemonic::new("if_lo"),
        InstructionMnemonic::new("if_hs"),
        InstructionMnemonic::new("if_p0"),
        InstructionMnemonic::new("if_p1"),
        InstructionMnemonic::new("if_p2"),
        InstructionMnemonic::new("if_p3"),
        InstructionMnemonic::new("if_np0"),
        InstructionMnemonic::new("if_np1"),
        // === Hardware loop instructions ===
        InstructionMnemonic::new("loop0"),
        InstructionMnemonic::new("loop1"),
        InstructionMnemonic::new("endloop0"),
        InstructionMnemonic::new("endloop1"),
        InstructionMnemonic::new("sp0loop0"),
        InstructionMnemonic::new("sp1loop1"),
        InstructionMnemonic::new("sp2loop0"),
        InstructionMnemonic::new("sp3loop1"),
        // === Coprocessor instructions ===
        InstructionMnemonic::new("vadd"),
        InstructionMnemonic::new("vsub"),
        InstructionMnemonic::new("vmpy"),
        InstructionMnemonic::new("vmac"),
        InstructionMnemonic::new("vmin"),
        InstructionMnemonic::new("vmax"),
        InstructionMnemonic::new("vsh"),
        InstructionMnemonic::new("vabs"),
        InstructionMnemonic::new("vneg"),
        InstructionMnemonic::new("vcmov"),
        InstructionMnemonic::new("vpack"),
        InstructionMnemonic::new("vunpack"),
        InstructionMnemonic::new("vshuff"),
        InstructionMnemonic::new("vsplat"),
        InstructionMnemonic::new("vld"),
        InstructionMnemonic::new("vst"),
        InstructionMnemonic::new("vldu"),
        InstructionMnemonic::new("vstu"),
        // === Packet directives ===
        InstructionMnemonic::new("nop"),
        InstructionMnemonic::new("packet_begin"),
        InstructionMnemonic::new("packet_end"),
    ]
}

impl ProcessorModule for HexagonProcessor {
    fn name() -> &'static str {
        "Qualcomm Hexagon DSP"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "hexagon:LE:32:V4",
                "Hexagon V4 (32-bit, little-endian)",
                "V4",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V5",
                "Hexagon V5 (32-bit, little-endian)",
                "V5",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V55",
                "Hexagon V55 (32-bit, little-endian)",
                "V55",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V60",
                "Hexagon V60 (32-bit, little-endian)",
                "V60",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V61",
                "Hexagon V61 (32-bit, little-endian)",
                "V61",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V62",
                "Hexagon V62 (32-bit, little-endian)",
                "V62",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V65",
                "Hexagon V65 (32-bit, little-endian)",
                "V65",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V66",
                "Hexagon V66 (32-bit, little-endian)",
                "V66",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V67",
                "Hexagon V67 (32-bit, little-endian)",
                "V67",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V68",
                "Hexagon V68 (32-bit, little-endian)",
                "V68",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V69",
                "Hexagon V69 (32-bit, little-endian)",
                "V69",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V71",
                "Hexagon V71 (32-bit, little-endian)",
                "V71",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V73",
                "Hexagon V73 (32-bit, little-endian)",
                "V73",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V75",
                "Hexagon V75 (32-bit, little-endian)",
                "V75",
                Endian::Little,
                32,
            ),
            Language::new(
                "hexagon:LE:32:V79",
                "Hexagon V79 (32-bit, little-endian)",
                "V79",
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
    fn test_hexagon_name() {
        assert_eq!(HexagonProcessor::name(), "Qualcomm Hexagon DSP");
    }

    #[test]
    fn test_hexagon_registers() {
        let bank = HexagonProcessor::registers();
        assert!(
            bank.len() > 50,
            "Expected many registers, got {}",
            bank.len()
        );
        assert!(bank.get("R0").is_some());
        assert!(bank.get("R31").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("FP").is_some());
        assert!(bank.get("LR").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("USR").is_some());
        assert!(bank.get("GP").is_some());
        assert!(bank.get("P0").is_some());
        assert!(bank.get("P3").is_some());
        assert!(bank.get("M0").is_some());
        assert!(bank.get("M1").is_some());
        assert!(bank.get("LC0").is_some());
        assert!(bank.get("LC1").is_some());
        assert!(bank.get("SA0").is_some());
        assert!(bank.get("SA1").is_some());
        assert!(bank.get("CS0").is_some());
        assert!(bank.get("CS1").is_some());
        assert!(bank.get("C0").is_some());
        assert!(bank.get("C31").is_some());
    }

    #[test]
    fn test_hexagon_register_bits() {
        let bank = HexagonProcessor::registers();
        assert_eq!(bank.get("R0").unwrap().bit_size, 32);
        assert_eq!(bank.get("P0").unwrap().bit_size, 8);
        assert_eq!(bank.get("PC").unwrap().bit_size, 32);
        assert_eq!(bank.get("C0").unwrap().bit_size, 64);
        assert_eq!(bank.get("R1:0").unwrap().bit_size, 64);
    }

    #[test]
    fn test_hexagon_languages() {
        let langs = HexagonProcessor::languages();
        assert!(langs.len() >= 10);
        assert!(langs.iter().any(|l| l.id == "hexagon:LE:32:V5"));
        assert!(langs.iter().any(|l| l.id == "hexagon:LE:32:V73"));
        assert!(langs.iter().all(|l| l.endian == Endian::Little));
    }

    #[test]
    fn test_hexagon_instructions() {
        let insts = HexagonProcessor::instructions();
        assert!(insts.len() > 50);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"mpy"));
        assert!(texts.contains(&"ld"));
        assert!(texts.contains(&"st"));
        assert!(texts.contains(&"jump"));
        assert!(texts.contains(&"call"));
        assert!(texts.contains(&"ret"));
        assert!(texts.contains(&"loop0"));
        assert!(texts.contains(&"vadd"));
    }

    #[test]
    fn test_hexagon_alias_registers() {
        let bank = HexagonProcessor::registers();
        let sp = bank.get("SP").unwrap();
        assert_eq!(sp.parent.as_deref(), Some("R29"));
        let fp = bank.get("FP").unwrap();
        assert_eq!(fp.parent.as_deref(), Some("R30"));
        let lr = bank.get("LR").unwrap();
        assert_eq!(lr.parent.as_deref(), Some("R31"));
    }
}
