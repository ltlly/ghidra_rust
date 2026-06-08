//! Berkeley Packet Filter (BPF) Processor Module
//!
//! Supports the classic BPF virtual machine used for packet filtering
//! in Unix-like operating systems.
//!
//! ## Architecture overview
//! - 32-bit accumulator A
//! - 32-bit index register X
//! - 32-bit scratch registers RS (return value) and R
//! - 32-bit program counter PC
//! - 512-word scratch memory store (M[])
//! - Little-endian byte order
//!
//! ## Register space layout
//! - Accumulator (A):         0x00  (32-bit)
//! - Index (X):               0x04  (32-bit)
//! - Scratch (RS, R):         0x08, 0x0C  (32-bit each)
//! - Program Counter (PC):    0x10  (32-bit)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// BPF processor struct.
pub struct BpfProcessor;

/// Build the complete BPF register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- Accumulator ----
    bank.add(Register::new("A", 32, 0x0000)
        .with_description("Accumulator register")
        .with_group("General Purpose"));

    // ---- Index register ----
    bank.add(Register::new("X", 32, 0x0004)
        .with_description("Index register")
        .with_group("General Purpose"));

    // ---- Scratch registers ----
    bank.add(Register::new("RS", 32, 0x0008)
        .with_description("Return value / scratch register")
        .with_group("General Purpose"));
    bank.add(Register::new("R", 32, 0x000C)
        .with_description("Scratch register")
        .with_group("General Purpose"));

    // ---- Program Counter ----
    bank.add(Register::new("PC", 32, 0x0010)
        .with_type(crate::common::RegisterType::PC)
        .with_description("Program counter")
        .with_group("Control"));

    // ---- Sub-register views (high/low bytes) ----
    bank.add(Register::sub_register("AH", 16, 0x0000, "A", 16)
        .with_description("High half of accumulator"));
    bank.add(Register::sub_register("AB", 8, 0x0000, "A", 0)
        .with_description("Low byte of accumulator"));
    bank.add(Register::sub_register("XH", 16, 0x0004, "X", 16)
        .with_description("High half of index register"));
    bank.add(Register::sub_register("XB", 8, 0x0004, "X", 0)
        .with_description("Low byte of index register"));
    bank.add(Register::sub_register("RSH", 16, 0x0008, "RS", 16)
        .with_description("High half of RS"));
    bank.add(Register::sub_register("RSB", 8, 0x0008, "RS", 0)
        .with_description("Low byte of RS"));
    bank.add(Register::sub_register("RH", 16, 0x000C, "R", 16)
        .with_description("High half of R"));
    bank.add(Register::sub_register("RB", 8, 0x000C, "R", 0)
        .with_description("Low byte of R"));
    bank.add(Register::sub_register("PCH", 16, 0x0010, "PC", 16)
        .with_description("High half of PC"));
    bank.add(Register::sub_register("PCB", 8, 0x0010, "PC", 0)
        .with_description("Low byte of PC"));

    bank
}

/// Build the BPF instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Load/Store ===
        InstructionMnemonic::new("ld"),     // Load A from packet
        InstructionMnemonic::new("ldi"),    // Load A immediate
        InstructionMnemonic::new("ldh"),    // Load A half-word from packet
        InstructionMnemonic::new("ldb"),    // Load A byte from packet
        InstructionMnemonic::new("ldx"),    // Load X from packet
        InstructionMnemonic::new("ldxi"),   // Load X immediate
        InstructionMnemonic::new("ldxb"),   // Load X byte from packet (low nibble * 4)
        InstructionMnemonic::new("st"),     // Store A to scratch memory
        InstructionMnemonic::new("stx"),    // Store X to scratch memory
        // === Arithmetic ===
        InstructionMnemonic::new("add"),    // Add X to A
        InstructionMnemonic::new("sub"),    // Subtract X from A
        InstructionMnemonic::new("mul"),    // Multiply A by X
        InstructionMnemonic::new("div"),    // Divide A by X
        InstructionMnemonic::new("mod"),    // A modulo X
        InstructionMnemonic::new("neg"),    // Negate A
        // === Logical ===
        InstructionMnemonic::new("and"),    // Bitwise AND A with X
        InstructionMnemonic::new("or"),     // Bitwise OR A with X
        InstructionMnemonic::new("xor"),    // Bitwise XOR A with X
        InstructionMnemonic::new("lsh"),    // Left shift A by X
        InstructionMnemonic::new("rsh"),    // Right shift A by X
        // === Jump ===
        InstructionMnemonic::new("ja"),     // Jump always
        InstructionMnemonic::new("jeq"),    // Jump if A == X
        InstructionMnemonic::new("jgt"),    // Jump if A > X
        InstructionMnemonic::new("jge"),    // Jump if A >= X
        InstructionMnemonic::new("jset"),   // Jump if A & X != 0
        InstructionMnemonic::new("jmp"),    // Jump (alias for ja)
        // === Return ===
        InstructionMnemonic::new("ret"),    // Return
        InstructionMnemonic::new("tax"),    // Transfer A to X
        InstructionMnemonic::new("txa"),    // Transfer X to A
        // === Extensions (cBPF) ===
        InstructionMnemonic::new("abs"),    // Absolute value
        InstructionMnemonic::new("len"),    // Packet length
        InstructionMnemonic::new("msh"),    // Load IP header length
    ]
}

impl ProcessorModule for BpfProcessor {
    fn name() -> &'static str {
        "BPF (Berkeley Packet Filter)"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "BPF:LE:32:default",
                "BPF processor 32-bit little-endian",
                "default",
                Endian::Little,
                32,
            )
            .with_instruction_alignment(1)
            .with_pc_register("PC"),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> {
        build_instructions()
    }

    fn description() -> &'static str {
        "Berkeley Packet Filter (BPF) virtual machine"
    }

    fn family() -> &'static str {
        "BPF"
    }

    fn default_pointer_size() -> u32 {
        32
    }

    fn default_endian() -> Endian {
        Endian::Little
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_name() {
        assert_eq!(BpfProcessor::name(), "BPF (Berkeley Packet Filter)");
    }

    #[test]
    fn test_bpf_registers() {
        let bank = BpfProcessor::registers();
        assert!(bank.len() >= 10, "Expected at least 10 registers, got {}", bank.len());
        assert!(bank.get("A").is_some());
        assert!(bank.get("X").is_some());
        assert!(bank.get("RS").is_some());
        assert!(bank.get("R").is_some());
        assert!(bank.get("PC").is_some());
        // Sub-registers
        assert!(bank.get("AH").is_some());
        assert!(bank.get("AB").is_some());
        assert!(bank.get("XH").is_some());
        assert!(bank.get("XB").is_some());
        assert!(bank.get("PCH").is_some());
        assert!(bank.get("PCB").is_some());
    }

    #[test]
    fn test_bpf_register_bits() {
        let bank = BpfProcessor::registers();
        assert_eq!(bank.get("A").unwrap().bit_size, 32);
        assert_eq!(bank.get("X").unwrap().bit_size, 32);
        assert_eq!(bank.get("RS").unwrap().bit_size, 32);
        assert_eq!(bank.get("R").unwrap().bit_size, 32);
        assert_eq!(bank.get("PC").unwrap().bit_size, 32);
        assert_eq!(bank.get("AH").unwrap().bit_size, 16);
        assert_eq!(bank.get("AB").unwrap().bit_size, 8);
    }

    #[test]
    fn test_bpf_sub_registers() {
        let bank = BpfProcessor::registers();
        let ah = bank.get("AH").unwrap();
        assert_eq!(ah.parent.as_deref(), Some("A"));
        assert_eq!(ah.lsb, 16);

        let ab = bank.get("AB").unwrap();
        assert_eq!(ab.parent.as_deref(), Some("A"));
        assert_eq!(ab.lsb, 0);
    }

    #[test]
    fn test_bpf_languages() {
        let langs = BpfProcessor::languages();
        assert!(langs.len() >= 1);
        assert!(langs.iter().any(|l| l.id == "BPF:LE:32:default"));
        assert!(langs.iter().all(|l| l.endian == Endian::Little));
    }

    #[test]
    fn test_bpf_instructions() {
        let insts = BpfProcessor::instructions();
        assert!(insts.len() > 20);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        // Load/Store
        assert!(texts.contains(&"ld"));
        assert!(texts.contains(&"ldi"));
        assert!(texts.contains(&"ldh"));
        assert!(texts.contains(&"ldb"));
        assert!(texts.contains(&"ldx"));
        assert!(texts.contains(&"ldxi"));
        assert!(texts.contains(&"st"));
        assert!(texts.contains(&"stx"));
        // Arithmetic
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"mul"));
        assert!(texts.contains(&"div"));
        assert!(texts.contains(&"mod"));
        // Logical
        assert!(texts.contains(&"and"));
        assert!(texts.contains(&"or"));
        assert!(texts.contains(&"xor"));
        assert!(texts.contains(&"lsh"));
        assert!(texts.contains(&"rsh"));
        // Jump
        assert!(texts.contains(&"ja"));
        assert!(texts.contains(&"jeq"));
        assert!(texts.contains(&"jgt"));
        assert!(texts.contains(&"jge"));
        assert!(texts.contains(&"jset"));
        // Return
        assert!(texts.contains(&"ret"));
        assert!(texts.contains(&"tax"));
        assert!(texts.contains(&"txa"));
    }

    #[test]
    fn test_bpf_metadata() {
        assert_eq!(BpfProcessor::family(), "BPF");
        assert_eq!(BpfProcessor::default_pointer_size(), 32);
        assert_eq!(BpfProcessor::default_endian(), Endian::Little);
    }
}
