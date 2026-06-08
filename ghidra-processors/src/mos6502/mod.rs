//! MOS 6502 / 65C02 Processor Module
//!
//! Supports the MOS Technology 6502 and 65C02 8-bit microprocessor families.
//!
//! ## Architecture overview
//! - 8-bit accumulator A
//! - 8-bit index registers X and Y
//! - 8-bit stack pointer SP (within page 1: 0x0100-0x01FF)
//! - 16-bit program counter PC
//! - 8-bit processor status register P: N, V, B, D, I, Z, C
//! - 64KB address space (16-bit)
//!
//! ## Register space layout
//! - Accumulator (A):         0x00  (8-bit)
//! - Index (X, Y):            0x01-0x02  (8-bit each)
//! - Processor Status (P):    0x03  (8-bit)
//! - Program Counter (PC):    0x20  (16-bit)
//! - Stack Pointer (SP):      0x22  (16-bit, but only low byte used)
//! - Status bits:             0x30  (N, V, B, D, I, Z, C)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// MOS 6502 processor struct.
pub struct Mos6502Processor;

/// Build the complete 6502 register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- Accumulator ----
    bank.add(Register::new("A", 8, 0x0000)
        .with_description("Accumulator register")
        .with_group("General Purpose"));

    // ---- Index registers ----
    bank.add(Register::new("X", 8, 0x0001)
        .with_description("Index register X")
        .with_group("General Purpose"));
    bank.add(Register::new("Y", 8, 0x0002)
        .with_description("Index register Y")
        .with_group("General Purpose"));

    // ---- Processor Status Register ----
    bank.add(Register::new("P", 8, 0x0003)
        .with_description("Processor status register")
        .with_group("Status"));

    // ---- Program Counter ----
    bank.add(Register::new("PC", 16, 0x0020)
        .with_type(crate::common::RegisterType::PC)
        .with_description("Program counter")
        .with_group("Control"));

    // ---- Stack Pointer ----
    bank.add(Register::new("SP", 16, 0x0022)
        .with_type(crate::common::RegisterType::SP)
        .with_description("Stack pointer (points to page 1)")
        .with_group("Control"));

    // ---- Individual status flags ----
    bank.add(Register::sub_register("C", 1, 0x0003, "P", 0)
        .with_description("Carry flag"));
    bank.add(Register::sub_register("Z", 1, 0x0003, "P", 1)
        .with_description("Zero flag"));
    bank.add(Register::sub_register("I", 1, 0x0003, "P", 2)
        .with_description("Interrupt disable flag"));
    bank.add(Register::sub_register("D", 1, 0x0003, "P", 3)
        .with_description("Decimal mode flag"));
    bank.add(Register::sub_register("B", 1, 0x0003, "P", 4)
        .with_description("Break command flag"));
    bank.add(Register::sub_register("V", 1, 0x0003, "P", 6)
        .with_description("Overflow flag"));
    bank.add(Register::sub_register("N", 1, 0x0003, "P", 7)
        .with_description("Negative flag"));

    bank
}

/// Build the 6502 instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Load/Store ===
        InstructionMnemonic::new("lda"),    // Load accumulator
        InstructionMnemonic::new("ldx"),    // Load X
        InstructionMnemonic::new("ldy"),    // Load Y
        InstructionMnemonic::new("sta"),    // Store accumulator
        InstructionMnemonic::new("stx"),    // Store X
        InstructionMnemonic::new("sty"),    // Store Y
        // === Transfer ===
        InstructionMnemonic::new("tax"),    // Transfer A to X
        InstructionMnemonic::new("tay"),    // Transfer A to Y
        InstructionMnemonic::new("txa"),    // Transfer X to A
        InstructionMnemonic::new("tya"),    // Transfer Y to A
        InstructionMnemonic::new("tsx"),    // Transfer SP to X
        InstructionMnemonic::new("txs"),    // Transfer X to SP
        // === Stack ===
        InstructionMnemonic::new("pha"),    // Push A
        InstructionMnemonic::new("php"),    // Push processor status
        InstructionMnemonic::new("pla"),    // Pull A
        InstructionMnemonic::new("plp"),    // Pull processor status
        // === Arithmetic ===
        InstructionMnemonic::new("adc"),    // Add with carry
        InstructionMnemonic::new("sbc"),    // Subtract with carry
        InstructionMnemonic::new("inc"),    // Increment memory
        InstructionMnemonic::new("inx"),    // Increment X
        InstructionMnemonic::new("iny"),    // Increment Y
        InstructionMnemonic::new("dec"),    // Decrement memory
        InstructionMnemonic::new("dex"),    // Decrement X
        InstructionMnemonic::new("dey"),    // Decrement Y
        // === Logical ===
        InstructionMnemonic::new("and"),    // Logical AND
        InstructionMnemonic::new("ora"),    // Logical OR
        InstructionMnemonic::new("eor"),    // Exclusive OR
        InstructionMnemonic::new("bit"),    // Bit test
        // === Shift/Rotate ===
        InstructionMnemonic::new("asl"),    // Arithmetic shift left
        InstructionMnemonic::new("lsr"),    // Logical shift right
        InstructionMnemonic::new("rol"),    // Rotate left
        InstructionMnemonic::new("ror"),    // Rotate right
        // === Compare ===
        InstructionMnemonic::new("cmp"),    // Compare A
        InstructionMnemonic::new("cpx"),    // Compare X
        InstructionMnemonic::new("cpy"),    // Compare Y
        // === Branch ===
        InstructionMnemonic::new("bcc"),    // Branch if carry clear
        InstructionMnemonic::new("bcs"),    // Branch if carry set
        InstructionMnemonic::new("beq"),    // Branch if equal (Z=1)
        InstructionMnemonic::new("bne"),    // Branch if not equal (Z=0)
        InstructionMnemonic::new("bmi"),    // Branch if minus (N=1)
        InstructionMnemonic::new("bpl"),    // Branch if plus (N=0)
        InstructionMnemonic::new("bvc"),    // Branch if overflow clear
        InstructionMnemonic::new("bvs"),    // Branch if overflow set
        // === Jump/Call ===
        InstructionMnemonic::new("jmp"),    // Jump
        InstructionMnemonic::new("jsr"),    // Jump to subroutine
        InstructionMnemonic::new("rts"),    // Return from subroutine
        InstructionMnemonic::new("rti"),    // Return from interrupt
        // === Flags ===
        InstructionMnemonic::new("clc"),    // Clear carry
        InstructionMnemonic::new("cld"),    // Clear decimal
        InstructionMnemonic::new("cli"),    // Clear interrupt disable
        InstructionMnemonic::new("clv"),    // Clear overflow
        InstructionMnemonic::new("sec"),    // Set carry
        InstructionMnemonic::new("sed"),    // Set decimal
        InstructionMnemonic::new("sei"),    // Set interrupt disable
        // === System ===
        InstructionMnemonic::new("brk"),    // Force interrupt
        InstructionMnemonic::new("nop"),    // No operation
        // === Undocumented (6502) ===
        InstructionMnemonic::new("lax"),    // Load A and X
        InstructionMnemonic::new("sax"),    // Store A AND X
        InstructionMnemonic::new("dcp"),    // Decrement and compare
        InstructionMnemonic::new("isb"),    // Increment and subtract
        InstructionMnemonic::new("slo"),    // Shift left and OR
        InstructionMnemonic::new("sre"),    // Shift right and EOR
        InstructionMnemonic::new("rla"),    // Rotate left and AND
        InstructionMnemonic::new("rra"),    // Rotate right and ADC
    ]
}

impl ProcessorModule for Mos6502Processor {
    fn name() -> &'static str {
        "6502"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "6502:LE:16:default",
                "6502 Microcontroller Family",
                "default",
                Endian::Little,
                16,
            )
            .with_instruction_alignment(1)
            .with_pc_register("PC"),
            Language::new(
                "65C02:LE:16:default",
                "65C02 Microcontroller Family",
                "default",
                Endian::Little,
                16,
            )
            .with_instruction_alignment(1)
            .with_pc_register("PC"),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> {
        build_instructions()
    }

    fn description() -> &'static str {
        "MOS Technology 6502 / 65C02 8-bit microprocessor"
    }

    fn family() -> &'static str {
        "6502"
    }

    fn default_pointer_size() -> u32 {
        16
    }

    fn default_endian() -> Endian {
        Endian::Little
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_6502_name() {
        assert_eq!(Mos6502Processor::name(), "6502");
    }

    #[test]
    fn test_6502_registers() {
        let bank = Mos6502Processor::registers();
        assert!(bank.len() >= 10, "Expected at least 10 registers, got {}", bank.len());
        // Core registers
        assert!(bank.get("A").is_some());
        assert!(bank.get("X").is_some());
        assert!(bank.get("Y").is_some());
        assert!(bank.get("P").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("SP").is_some());
        // Status flags
        assert!(bank.get("C").is_some());
        assert!(bank.get("Z").is_some());
        assert!(bank.get("I").is_some());
        assert!(bank.get("D").is_some());
        assert!(bank.get("B").is_some());
        assert!(bank.get("V").is_some());
        assert!(bank.get("N").is_some());
    }

    #[test]
    fn test_6502_register_bits() {
        let bank = Mos6502Processor::registers();
        assert_eq!(bank.get("A").unwrap().bit_size, 8);
        assert_eq!(bank.get("X").unwrap().bit_size, 8);
        assert_eq!(bank.get("Y").unwrap().bit_size, 8);
        assert_eq!(bank.get("P").unwrap().bit_size, 8);
        assert_eq!(bank.get("PC").unwrap().bit_size, 16);
        assert_eq!(bank.get("SP").unwrap().bit_size, 16);
        assert_eq!(bank.get("C").unwrap().bit_size, 1);
    }

    #[test]
    fn test_6502_status_flags() {
        let bank = Mos6502Processor::registers();
        let c = bank.get("C").unwrap();
        assert_eq!(c.parent.as_deref(), Some("P"));
        assert_eq!(c.lsb, 0);

        let z = bank.get("Z").unwrap();
        assert_eq!(z.parent.as_deref(), Some("P"));
        assert_eq!(z.lsb, 1);

        let n = bank.get("N").unwrap();
        assert_eq!(n.parent.as_deref(), Some("P"));
        assert_eq!(n.lsb, 7);
    }

    #[test]
    fn test_6502_languages() {
        let langs = Mos6502Processor::languages();
        assert!(langs.len() >= 2);
        assert!(langs.iter().any(|l| l.id == "6502:LE:16:default"));
        assert!(langs.iter().any(|l| l.id == "65C02:LE:16:default"));
        assert!(langs.iter().all(|l| l.endian == Endian::Little));
    }

    #[test]
    fn test_6502_instructions() {
        let insts = Mos6502Processor::instructions();
        assert!(insts.len() > 40);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        // Load/Store
        assert!(texts.contains(&"lda"));
        assert!(texts.contains(&"ldx"));
        assert!(texts.contains(&"ldy"));
        assert!(texts.contains(&"sta"));
        assert!(texts.contains(&"stx"));
        assert!(texts.contains(&"sty"));
        // Transfer
        assert!(texts.contains(&"tax"));
        assert!(texts.contains(&"tay"));
        assert!(texts.contains(&"txa"));
        assert!(texts.contains(&"tya"));
        assert!(texts.contains(&"tsx"));
        assert!(texts.contains(&"txs"));
        // Arithmetic
        assert!(texts.contains(&"adc"));
        assert!(texts.contains(&"sbc"));
        assert!(texts.contains(&"inc"));
        assert!(texts.contains(&"dec"));
        // Branch
        assert!(texts.contains(&"bcc"));
        assert!(texts.contains(&"bcs"));
        assert!(texts.contains(&"beq"));
        assert!(texts.contains(&"bne"));
        assert!(texts.contains(&"bmi"));
        assert!(texts.contains(&"bpl"));
        // Jump/Call
        assert!(texts.contains(&"jmp"));
        assert!(texts.contains(&"jsr"));
        assert!(texts.contains(&"rts"));
        assert!(texts.contains(&"rti"));
        // System
        assert!(texts.contains(&"brk"));
        assert!(texts.contains(&"nop"));
    }

    #[test]
    fn test_6502_metadata() {
        assert_eq!(Mos6502Processor::family(), "6502");
        assert_eq!(Mos6502Processor::default_pointer_size(), 16);
        assert_eq!(Mos6502Processor::default_endian(), Endian::Little);
    }
}
