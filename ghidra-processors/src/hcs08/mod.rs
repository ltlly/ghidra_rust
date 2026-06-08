//! Freescale HCS08 / HC08 Processor Module
//!
//! Supports the Freescale (formerly Motorola) HCS08 and HC08 8-bit
//! microcontroller families.
//!
//! ## Architecture overview
//! - 8-bit accumulator A
//! - 8-bit index register X (H:X for 16-bit indexing)
//! - 16-bit stack pointer SP
//! - 16-bit program counter PC
//! - 8-bit condition code register CCR: V, H, I, N, Z, C
//! - 64KB address space (16-bit)
//!
//! ## Register space layout
//! - Accumulator (A):           0x00  (8-bit)
//! - Index (X, H):              0x10-0x11  (8-bit each, H:X = 16-bit)
//! - Control (PC, SP):          0x20-0x24  (16-bit each)
//! - Condition Code (CCR):      0x30  (8-bit)
//! - CCR bits:                  0x30  (V, H, I, N, Z, C)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Freescale HCS08 processor struct.
pub struct Hcs08Processor;

/// Build the complete HCS08 register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- Accumulator ----
    bank.add(Register::new("A", 8, 0x0000)
        .with_description("Accumulator A")
        .with_group("General Purpose"));

    // ---- Index registers ----
    bank.add(Register::new("H", 8, 0x0010)
        .with_description("Index register high byte")
        .with_group("General Purpose"));
    bank.add(Register::new("X", 8, 0x0011)
        .with_description("Index register X")
        .with_group("General Purpose"));
    bank.add(Register::new("HIX", 16, 0x0010)
        .with_description("Index register pair H:X (16-bit)")
        .with_group("General Purpose"));

    // ---- Program Counter ----
    bank.add(Register::new("PC", 16, 0x0020)
        .with_type(crate::common::RegisterType::PC)
        .with_description("Program counter")
        .with_group("Control"));
    bank.add(Register::sub_register("PCH", 8, 0x0020, "PC", 8)
        .with_description("Program counter high byte"));
    bank.add(Register::sub_register("PCL", 8, 0x0020, "PC", 0)
        .with_description("Program counter low byte"));

    // ---- Stack Pointer ----
    bank.add(Register::new("SP", 16, 0x0022)
        .with_type(crate::common::RegisterType::SP)
        .with_description("Stack pointer")
        .with_group("Control"));
    bank.add(Register::sub_register("SPH", 8, 0x0022, "SP", 8)
        .with_description("Stack pointer high byte"));
    bank.add(Register::sub_register("SPL", 8, 0x0022, "SP", 0)
        .with_description("Stack pointer low byte"));

    // ---- Condition Code Register (CCR) ----
    bank.add(Register::new("CCR", 8, 0x0030)
        .with_description("Condition code register")
        .with_group("Status"));

    // ---- Individual CCR bits ----
    bank.add(Register::sub_register("C", 1, 0x0030, "CCR", 0)
        .with_description("Carry / Borrow"));
    bank.add(Register::sub_register("Z", 1, 0x0030, "CCR", 1)
        .with_description("Zero"));
    bank.add(Register::sub_register("N", 1, 0x0030, "CCR", 2)
        .with_description("Negative (sign)"));
    bank.add(Register::sub_register("I", 1, 0x0030, "CCR", 3)
        .with_description("IRQ interrupt mask"));
    bank.add(Register::sub_register("H_flag", 1, 0x0030, "CCR", 4)
        .with_description("Half-carry (BCD)"));
    bank.add(Register::sub_register("V", 1, 0x0030, "CCR", 5)
        .with_description("Overflow (2's complement)"));

    bank
}

/// Build the HCS08 instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Data movement ===
        InstructionMnemonic::new("lda"),    // Load accumulator A
        InstructionMnemonic::new("sta"),    // Store accumulator A
        InstructionMnemonic::new("ldhx"),   // Load H:X
        InstructionMnemonic::new("sthx"),   // Store H:X
        InstructionMnemonic::new("ldx"),    // Load X
        InstructionMnemonic::new("stx"),    // Store X
        InstructionMnemonic::new("tax"),    // Transfer A to X
        InstructionMnemonic::new("txa"),    // Transfer X to A
        InstructionMnemonic::new("tsx"),    // Transfer SP to H:X
        InstructionMnemonic::new("txs"),    // Transfer H:X to SP
        InstructionMnemonic::new("psha"),   // Push A onto stack
        InstructionMnemonic::new("pshh"),   // Push H onto stack
        InstructionMnemonic::new("pshx"),   // Push X onto stack
        InstructionMnemonic::new("pula"),   // Pull A from stack
        InstructionMnemonic::new("pulh"),   // Pull H from stack
        InstructionMnemonic::new("pulx"),   // Pull X from stack
        InstructionMnemonic::new("mov"),    // Move (memory to memory)
        // === Arithmetic ===
        InstructionMnemonic::new("add"),    // Add to A
        InstructionMnemonic::new("adc"),    // Add with carry to A
        InstructionMnemonic::new("sub"),    // Subtract from A
        InstructionMnemonic::new("sbc"),    // Subtract with carry from A
        InstructionMnemonic::new("mul"),    // Multiply (unsigned 8x8 -> 16 in H:X)
        InstructionMnemonic::new("div"),    // Divide (unsigned 16/8 -> 8)
        InstructionMnemonic::new("inc"),    // Increment memory
        InstructionMnemonic::new("inca"),   // Increment A
        InstructionMnemonic::new("incx"),   // Increment X
        InstructionMnemonic::new("dec"),    // Decrement memory
        InstructionMnemonic::new("deca"),   // Decrement A
        InstructionMnemonic::new("decx"),   // Decrement X
        InstructionMnemonic::new("neg"),    // Negate (2's complement)
        InstructionMnemonic::new("nega"),   // Negate A
        InstructionMnemonic::new("daa"),    // Decimal adjust A
        InstructionMnemonic::new("ais"),    // Add immediate to SP
        InstructionMnemonic::new("aix"),    // Add immediate to H:X
        // === Logical ===
        InstructionMnemonic::new("and"),    // AND with A
        InstructionMnemonic::new("or"),     // OR with A
        InstructionMnemonic::new("eor"),    // XOR with A
        InstructionMnemonic::new("com"),    // Complement (1's complement)
        InstructionMnemonic::new("coma"),   // Complement A
        // === Bit manipulation ===
        InstructionMnemonic::new("bit"),    // Bit test A
        InstructionMnemonic::new("bclr"),   // Clear bit in memory
        InstructionMnemonic::new("bset"),   // Set bit in memory
        InstructionMnemonic::new("brclr"),  // Branch if bit clear
        InstructionMnemonic::new("brset"),  // Branch if bit set
        // === Compare ===
        InstructionMnemonic::new("cmp"),    // Compare A
        InstructionMnemonic::new("cphx"),   // Compare H:X
        InstructionMnemonic::new("cpx"),    // Compare X
        InstructionMnemonic::new("tst"),    // Test memory (compare to zero)
        InstructionMnemonic::new("tsta"),   // Test A
        InstructionMnemonic::new("tstx"),   // Test X
        // === Shift/Rotate ===
        InstructionMnemonic::new("lsla"),   // Logical shift left A
        InstructionMnemonic::new("lslx"),   // Logical shift left X
        InstructionMnemonic::new("lsl"),    // Logical shift left memory
        InstructionMnemonic::new("lsra"),   // Logical shift right A
        InstructionMnemonic::new("lsrx"),   // Logical shift right X
        InstructionMnemonic::new("lsr"),    // Logical shift right memory
        InstructionMnemonic::new("asla"),   // Arithmetic shift left A
        InstructionMnemonic::new("aslx"),   // Arithmetic shift left X
        InstructionMnemonic::new("asl"),    // Arithmetic shift left memory
        InstructionMnemonic::new("asra"),   // Arithmetic shift right A
        InstructionMnemonic::new("asrx"),   // Arithmetic shift right X
        InstructionMnemonic::new("asr"),    // Arithmetic shift right memory
        InstructionMnemonic::new("rola"),   // Rotate left A through carry
        InstructionMnemonic::new("rolx"),   // Rotate left X through carry
        InstructionMnemonic::new("rol"),    // Rotate left memory through carry
        InstructionMnemonic::new("rora"),   // Rotate right A through carry
        InstructionMnemonic::new("rorx"),   // Rotate right X through carry
        InstructionMnemonic::new("ror"),    // Rotate right memory through carry
        // === Branch ===
        InstructionMnemonic::new("bra"),    // Branch always
        InstructionMnemonic::new("brn"),    // Branch never
        InstructionMnemonic::new("beq"),    // Branch if equal (Z=1)
        InstructionMnemonic::new("bne"),    // Branch if not equal (Z=0)
        InstructionMnemonic::new("bcc"),    // Branch if carry clear (C=0)
        InstructionMnemonic::new("bcs"),    // Branch if carry set (C=1)
        InstructionMnemonic::new("bmi"),    // Branch if minus (N=1)
        InstructionMnemonic::new("bpl"),    // Branch if plus (N=0)
        InstructionMnemonic::new("bvs"),    // Branch if overflow set (V=1)
        InstructionMnemonic::new("bvc"),    // Branch if overflow clear (V=0)
        InstructionMnemonic::new("bhi"),    // Branch if higher (unsigned)
        InstructionMnemonic::new("bhs"),    // Branch if higher or same (unsigned)
        InstructionMnemonic::new("blo"),    // Branch if lower (unsigned)
        InstructionMnemonic::new("bls"),    // Branch if lower or same (unsigned)
        InstructionMnemonic::new("bgt"),    // Branch if greater than (signed)
        InstructionMnemonic::new("bge"),    // Branch if greater or equal (signed)
        InstructionMnemonic::new("ble"),    // Branch if less or equal (signed)
        InstructionMnemonic::new("blt"),    // Branch if less than (signed)
        InstructionMnemonic::new("dbnz"),   // Decrement and branch if not zero
        InstructionMnemonic::new("jmp"),    // Jump
        InstructionMnemonic::new("jsr"),    // Jump to subroutine
        InstructionMnemonic::new("bsr"),    // Branch to subroutine
        InstructionMnemonic::new("call"),   // Call (paged)
        InstructionMnemonic::new("rts"),    // Return from subroutine
        InstructionMnemonic::new("rti"),    // Return from interrupt
        InstructionMnemonic::new("rtc"),    // Return from call (paged)
        // === System ===
        InstructionMnemonic::new("swi"),    // Software interrupt
        InstructionMnemonic::new("wai"),    // Wait for interrupt
        InstructionMnemonic::new("stop"),   // Stop
        InstructionMnemonic::new("nop"),    // No operation
        InstructionMnemonic::new("sec"),    // Set carry
        InstructionMnemonic::new("clc"),    // Clear carry
        InstructionMnemonic::new("cli"),    // Clear interrupt mask
        InstructionMnemonic::new("sei"),    // Set interrupt mask
    ]
}

impl ProcessorModule for Hcs08Processor {
    fn name() -> &'static str {
        "Freescale HCS08 / HC08"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "HCS08:BE:16:default",
                "HCS08 Microcontroller Family",
                "default",
                Endian::Big,
                16,
            )
            .with_instruction_alignment(1)
            .with_pc_register("PC"),
            Language::new(
                "HCS08:BE:16:MC9S08GB60",
                "HCS08 Microcontroller Family - MC9S08GB60",
                "MC9S08GB60",
                Endian::Big,
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
        "Freescale HCS08 / HC08 8-bit microcontroller"
    }

    fn family() -> &'static str {
        "HCS08"
    }

    fn default_pointer_size() -> u32 {
        16
    }

    fn default_endian() -> Endian {
        Endian::Big
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hcs08_name() {
        assert_eq!(Hcs08Processor::name(), "Freescale HCS08 / HC08");
    }

    #[test]
    fn test_hcs08_registers() {
        let bank = Hcs08Processor::registers();
        assert!(bank.len() >= 15, "Expected at least 15 registers, got {}", bank.len());
        // Core registers
        assert!(bank.get("A").is_some());
        assert!(bank.get("H").is_some());
        assert!(bank.get("X").is_some());
        assert!(bank.get("HIX").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("CCR").is_some());
        // Sub-registers
        assert!(bank.get("PCH").is_some());
        assert!(bank.get("PCL").is_some());
        assert!(bank.get("SPH").is_some());
        assert!(bank.get("SPL").is_some());
        // CCR bits
        assert!(bank.get("C").is_some());
        assert!(bank.get("Z").is_some());
        assert!(bank.get("N").is_some());
        assert!(bank.get("I").is_some());
        assert!(bank.get("H_flag").is_some());
        assert!(bank.get("V").is_some());
    }

    #[test]
    fn test_hcs08_register_bits() {
        let bank = Hcs08Processor::registers();
        assert_eq!(bank.get("A").unwrap().bit_size, 8);
        assert_eq!(bank.get("H").unwrap().bit_size, 8);
        assert_eq!(bank.get("X").unwrap().bit_size, 8);
        assert_eq!(bank.get("HIX").unwrap().bit_size, 16);
        assert_eq!(bank.get("PC").unwrap().bit_size, 16);
        assert_eq!(bank.get("SP").unwrap().bit_size, 16);
        assert_eq!(bank.get("CCR").unwrap().bit_size, 8);
    }

    #[test]
    fn test_hcs08_ccr_bits() {
        let bank = Hcs08Processor::registers();
        let c = bank.get("C").unwrap();
        assert_eq!(c.parent.as_deref(), Some("CCR"));
        assert_eq!(c.lsb, 0);

        let z = bank.get("Z").unwrap();
        assert_eq!(z.parent.as_deref(), Some("CCR"));
        assert_eq!(z.lsb, 1);

        let v = bank.get("V").unwrap();
        assert_eq!(v.parent.as_deref(), Some("CCR"));
        assert_eq!(v.lsb, 5);
    }

    #[test]
    fn test_hcs08_languages() {
        let langs = Hcs08Processor::languages();
        assert!(langs.len() >= 2);
        assert!(langs.iter().any(|l| l.id == "HCS08:BE:16:default"));
        assert!(langs.iter().any(|l| l.id == "HCS08:BE:16:MC9S08GB60"));
        assert!(langs.iter().all(|l| l.endian == Endian::Big));
    }

    #[test]
    fn test_hcs08_instructions() {
        let insts = Hcs08Processor::instructions();
        assert!(insts.len() > 60);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        // Data movement
        assert!(texts.contains(&"lda"));
        assert!(texts.contains(&"sta"));
        assert!(texts.contains(&"ldhx"));
        assert!(texts.contains(&"sthx"));
        assert!(texts.contains(&"ldx"));
        assert!(texts.contains(&"stx"));
        assert!(texts.contains(&"tax"));
        assert!(texts.contains(&"txa"));
        assert!(texts.contains(&"psha"));
        assert!(texts.contains(&"pula"));
        // Arithmetic
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"adc"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"sbc"));
        assert!(texts.contains(&"mul"));
        assert!(texts.contains(&"div"));
        assert!(texts.contains(&"inc"));
        assert!(texts.contains(&"dec"));
        // Logical
        assert!(texts.contains(&"and"));
        assert!(texts.contains(&"or"));
        assert!(texts.contains(&"eor"));
        // Compare
        assert!(texts.contains(&"cmp"));
        assert!(texts.contains(&"cphx"));
        assert!(texts.contains(&"cpx"));
        assert!(texts.contains(&"tst"));
        // Shift
        assert!(texts.contains(&"lsla"));
        assert!(texts.contains(&"lsra"));
        assert!(texts.contains(&"asla"));
        assert!(texts.contains(&"asra"));
        assert!(texts.contains(&"rola"));
        assert!(texts.contains(&"rora"));
        // Branch
        assert!(texts.contains(&"bra"));
        assert!(texts.contains(&"beq"));
        assert!(texts.contains(&"bne"));
        assert!(texts.contains(&"bcc"));
        assert!(texts.contains(&"bcs"));
        assert!(texts.contains(&"jmp"));
        assert!(texts.contains(&"jsr"));
        assert!(texts.contains(&"rts"));
        assert!(texts.contains(&"rti"));
        // System
        assert!(texts.contains(&"swi"));
        assert!(texts.contains(&"nop"));
    }

    #[test]
    fn test_hcs08_metadata() {
        assert_eq!(Hcs08Processor::family(), "HCS08");
        assert_eq!(Hcs08Processor::default_pointer_size(), 16);
        assert_eq!(Hcs08Processor::default_endian(), Endian::Big);
    }
}
