//! Motorola 6800 / 6809 / Hitachi 6309 Processor Module
//!
//! Supports the Motorola 6800, 6809, and Hitachi 6309 8-bit microprocessor
//! families.
//!
//! ## Architecture overview (6809)
//! - 8-bit accumulators A and B (combined as 16-bit D = A:B)
//! - 16-bit index registers X, Y, U (user stack), S (system stack)
//! - 8-bit direct page register DP
//! - 8-bit condition code register CC
//! - 16-bit program counter PC
//! - 64KB address space
//!
//! ## Register space layout
//! - Accumulators (A, B):     0x00-0x01  (8-bit each)
//! - Accumulator D (A:B):     0x00  (16-bit, A=high, B=low)
//! - Condition Code (CC):     0x08  (8-bit)
//! - Direct Page (DP):        0x09  (8-bit)
//! - Index (X, Y, U, S):      0x10-0x17  (16-bit each)
//! - Program Counter (PC):    0x10  (16-bit)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Motorola 6800/6809 processor struct.
pub struct Mc6800Processor;

/// Build the complete MC6800/6809 register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- Accumulators ----
    bank.add(Register::new("A", 8, 0x0000)
        .with_description("Accumulator A")
        .with_group("General Purpose"));
    bank.add(Register::new("B", 8, 0x0001)
        .with_description("Accumulator B")
        .with_group("General Purpose"));
    bank.add(Register::new("D", 16, 0x0000)
        .with_description("Accumulator D = A:B (16-bit)")
        .with_group("General Purpose"));

    // ---- Condition Code Register ----
    bank.add(Register::new("CC", 8, 0x0008)
        .with_description("Condition code register")
        .with_group("Status"));

    // ---- Direct Page Register ----
    bank.add(Register::new("DP", 8, 0x0009)
        .with_description("Direct page register")
        .with_group("Control"));

    // ---- Index Registers ----
    bank.add(Register::new("X", 16, 0x0010)
        .with_description("Index register X")
        .with_group("General Purpose"));
    bank.add(Register::new("Y", 16, 0x0012)
        .with_description("Index register Y")
        .with_group("General Purpose"));
    bank.add(Register::new("U", 16, 0x0014)
        .with_description("User stack pointer")
        .with_group("Stack"));
    bank.add(Register::new("S", 16, 0x0016)
        .with_type(crate::common::RegisterType::SP)
        .with_description("System stack pointer")
        .with_group("Stack"));

    // ---- Program Counter ----
    bank.add(Register::new("PC", 16, 0x0010)
        .with_type(crate::common::RegisterType::PC)
        .with_description("Program counter")
        .with_group("Control"));

    // ---- Condition Code bits ----
    bank.add(Register::sub_register("C", 1, 0x0008, "CC", 0)
        .with_description("Carry"));
    bank.add(Register::sub_register("V", 1, 0x0008, "CC", 1)
        .with_description("Overflow"));
    bank.add(Register::sub_register("Z", 1, 0x0008, "CC", 2)
        .with_description("Zero"));
    bank.add(Register::sub_register("N", 1, 0x0008, "CC", 3)
        .with_description("Negative"));
    bank.add(Register::sub_register("I", 1, 0x0008, "CC", 4)
        .with_description("IRQ mask"));
    bank.add(Register::sub_register("H", 1, 0x0008, "CC", 5)
        .with_description("Half-carry"));
    bank.add(Register::sub_register("F", 1, 0x0008, "CC", 6)
        .with_description("FIRQ mask"));
    bank.add(Register::sub_register("E", 1, 0x0008, "CC", 7)
        .with_description("Entire state saved"));

    bank
}

/// Build the MC6800/6809 instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Load/Store ===
        InstructionMnemonic::new("lda"),    // Load A
        InstructionMnemonic::new("ldb"),    // Load B
        InstructionMnemonic::new("ldd"),    // Load D
        InstructionMnemonic::new("ldx"),    // Load X
        InstructionMnemonic::new("ldy"),    // Load Y
        InstructionMnemonic::new("ldu"),    // Load U
        InstructionMnemonic::new("lds"),    // Load S
        InstructionMnemonic::new("sta"),    // Store A
        InstructionMnemonic::new("stb"),    // Store B
        InstructionMnemonic::new("std"),    // Store D
        InstructionMnemonic::new("stx"),    // Store X
        InstructionMnemonic::new("sty"),    // Store Y
        InstructionMnemonic::new("stu"),    // Store U
        InstructionMnemonic::new("sts"),    // Store S
        // === Transfer ===
        InstructionMnemonic::new("tfr"),    // Transfer register to register
        InstructionMnemonic::new("exg"),    // Exchange registers
        InstructionMnemonic::new("tab"),    // Transfer A to B
        InstructionMnemonic::new("tba"),    // Transfer B to A
        InstructionMnemonic::new("tap"),    // Transfer A to CC
        InstructionMnemonic::new("tpa"),    // Transfer CC to A
        InstructionMnemonic::new("tsx"),    // Transfer S to X
        InstructionMnemonic::new("txs"),    // Transfer X to S
        // === Stack ===
        InstructionMnemonic::new("pshs"),   // Push to S
        InstructionMnemonic::new("pshu"),   // Push to U
        InstructionMnemonic::new("puls"),   // Pull from S
        InstructionMnemonic::new("pulu"),   // Pull from U
        // === Arithmetic ===
        InstructionMnemonic::new("adda"),   // Add to A
        InstructionMnemonic::new("addb"),   // Add to B
        InstructionMnemonic::new("addd"),   // Add to D
        InstructionMnemonic::new("adca"),   // Add with carry to A
        InstructionMnemonic::new("adcb"),   // Add with carry to B
        InstructionMnemonic::new("suba"),   // Subtract from A
        InstructionMnemonic::new("subb"),   // Subtract from B
        InstructionMnemonic::new("subd"),   // Subtract from D
        InstructionMnemonic::new("sbca"),   // Subtract with carry from A
        InstructionMnemonic::new("sbcb"),   // Subtract with carry from B
        InstructionMnemonic::new("mul"),    // Multiply (unsigned 8x8 -> 16)
        InstructionMnemonic::new("divd"),   // Divide D (6809)
        InstructionMnemonic::new("divq"),   // Divide Q (6309)
        InstructionMnemonic::new("inc"),    // Increment memory
        InstructionMnemonic::new("inca"),   // Increment A
        InstructionMnemonic::new("incb"),   // Increment B
        InstructionMnemonic::new("dec"),    // Decrement memory
        InstructionMnemonic::new("deca"),   // Decrement A
        InstructionMnemonic::new("decb"),   // Decrement B
        InstructionMnemonic::new("neg"),    // Negate (2's complement)
        InstructionMnemonic::new("nega"),   // Negate A
        InstructionMnemonic::new("negb"),   // Negate B
        InstructionMnemonic::new("daa"),    // Decimal adjust A
        InstructionMnemonic::new("abx"),    // Add B to X
        InstructionMnemonic::new("aby"),    // Add B to Y
        InstructionMnemonic::new("leax"),   // Load effective address X
        InstructionMnemonic::new("leay"),   // Load effective address Y
        InstructionMnemonic::new("leau"),   // Load effective address U
        InstructionMnemonic::new("leas"),   // Load effective address S
        // === Logical ===
        InstructionMnemonic::new("anda"),   // AND A
        InstructionMnemonic::new("andb"),   // AND B
        InstructionMnemonic::new("ora"),    // OR A
        InstructionMnemonic::new("orb"),    // OR B
        InstructionMnemonic::new("eora"),   // XOR A
        InstructionMnemonic::new("eorb"),   // XOR B
        InstructionMnemonic::new("coma"),   // Complement A
        InstructionMnemonic::new("comb"),   // Complement B
        InstructionMnemonic::new("com"),    // Complement memory
        InstructionMnemonic::new("andcc"),  // AND CC
        InstructionMnemonic::new("orcc"),   // OR CC
        // === Bit test ===
        InstructionMnemonic::new("bita"),   // Bit test A
        InstructionMnemonic::new("bitb"),   // Bit test B
        InstructionMnemonic::new("tst"),    // Test memory
        InstructionMnemonic::new("tsta"),   // Test A
        InstructionMnemonic::new("tstb"),   // Test B
        // === Compare ===
        InstructionMnemonic::new("cmpa"),   // Compare A
        InstructionMnemonic::new("cmpb"),   // Compare B
        InstructionMnemonic::new("cmpd"),   // Compare D
        InstructionMnemonic::new("cmpx"),   // Compare X
        InstructionMnemonic::new("cmpy"),   // Compare Y
        InstructionMnemonic::new("cmpu"),   // Compare U
        InstructionMnemonic::new("cmps"),   // Compare S
        InstructionMnemonic::new("cba"),    // Compare A to B
        // === Shift/Rotate ===
        InstructionMnemonic::new("lsla"),   // Logical shift left A
        InstructionMnemonic::new("lslb"),   // Logical shift left B
        InstructionMnemonic::new("lsl"),    // Logical shift left memory
        InstructionMnemonic::new("lsra"),   // Logical shift right A
        InstructionMnemonic::new("lsrb"),   // Logical shift right B
        InstructionMnemonic::new("lsr"),    // Logical shift right memory
        InstructionMnemonic::new("asla"),   // Arithmetic shift left A
        InstructionMnemonic::new("aslb"),   // Arithmetic shift left B
        InstructionMnemonic::new("asl"),    // Arithmetic shift left memory
        InstructionMnemonic::new("asra"),   // Arithmetic shift right A
        InstructionMnemonic::new("asrb"),   // Arithmetic shift right B
        InstructionMnemonic::new("asr"),    // Arithmetic shift right memory
        InstructionMnemonic::new("rola"),   // Rotate left A
        InstructionMnemonic::new("rolb"),   // Rotate left B
        InstructionMnemonic::new("rol"),    // Rotate left memory
        InstructionMnemonic::new("rora"),   // Rotate right A
        InstructionMnemonic::new("rorb"),   // Rotate right B
        InstructionMnemonic::new("ror"),    // Rotate right memory
        // === Branch ===
        InstructionMnemonic::new("bra"),    // Branch always
        InstructionMnemonic::new("brn"),    // Branch never
        InstructionMnemonic::new("beq"),    // Branch if equal
        InstructionMnemonic::new("bne"),    // Branch if not equal
        InstructionMnemonic::new("bcc"),    // Branch if carry clear
        InstructionMnemonic::new("bcs"),    // Branch if carry set
        InstructionMnemonic::new("bmi"),    // Branch if minus
        InstructionMnemonic::new("bpl"),    // Branch if plus
        InstructionMnemonic::new("bvs"),    // Branch if overflow set
        InstructionMnemonic::new("bvc"),    // Branch if overflow clear
        InstructionMnemonic::new("bhi"),    // Branch if higher
        InstructionMnemonic::new("bhs"),    // Branch if higher or same
        InstructionMnemonic::new("blo"),    // Branch if lower
        InstructionMnemonic::new("bls"),    // Branch if lower or same
        InstructionMnemonic::new("bgt"),    // Branch if greater than
        InstructionMnemonic::new("bge"),    // Branch if greater or equal
        InstructionMnemonic::new("ble"),    // Branch if less or equal
        InstructionMnemonic::new("blt"),    // Branch if less than
        InstructionMnemonic::new("lbrn"),   // Long branch never
        InstructionMnemonic::new("lbeq"),   // Long branch equal
        InstructionMnemonic::new("lbne"),   // Long branch not equal
        InstructionMnemonic::new("lbcc"),   // Long branch carry clear
        InstructionMnemonic::new("lbcs"),   // Long branch carry set
        InstructionMnemonic::new("lbmi"),   // Long branch minus
        InstructionMnemonic::new("lbpl"),   // Long branch plus
        InstructionMnemonic::new("lbvs"),   // Long branch overflow set
        InstructionMnemonic::new("lbvc"),   // Long branch overflow clear
        InstructionMnemonic::new("lbhi"),   // Long branch higher
        InstructionMnemonic::new("lbhs"),   // Long branch higher or same
        InstructionMnemonic::new("lblo"),   // Long branch lower
        InstructionMnemonic::new("lbls"),   // Long branch lower or same
        InstructionMnemonic::new("lbgt"),   // Long branch greater than
        InstructionMnemonic::new("lbge"),   // Long branch greater or equal
        InstructionMnemonic::new("lble"),   // Long branch less or equal
        InstructionMnemonic::new("lblt"),   // Long branch less than
        // === Jump/Call ===
        InstructionMnemonic::new("jmp"),    // Jump
        InstructionMnemonic::new("jsr"),    // Jump to subroutine
        InstructionMnemonic::new("bsr"),    // Branch to subroutine
        InstructionMnemonic::new("lbsr"),   // Long branch to subroutine
        InstructionMnemonic::new("rts"),    // Return from subroutine
        InstructionMnemonic::new("rti"),    // Return from interrupt
        InstructionMnemonic::new("cwai"),   // Clear and wait for interrupt
        // === System ===
        InstructionMnemonic::new("swi"),    // Software interrupt 1
        InstructionMnemonic::new("swi2"),   // Software interrupt 2
        InstructionMnemonic::new("swi3"),   // Software interrupt 3
        InstructionMnemonic::new("nop"),    // No operation
        InstructionMnemonic::new("sync"),   // Synchronize
        InstructionMnemonic::new("clr"),    // Clear memory
        InstructionMnemonic::new("clra"),   // Clear A
        InstructionMnemonic::new("clrb"),   // Clear B
        // === Bit manipulation ===
        InstructionMnemonic::new("bclr"),   // Clear bit
        InstructionMnemonic::new("bset"),   // Set bit
        InstructionMnemonic::new("brclr"),  // Branch if bit clear
        InstructionMnemonic::new("brset"),  // Branch if bit set
        // === 6309 extensions ===
        InstructionMnemonic::new("ldw"),    // Load W (6309)
        InstructionMnemonic::new("stw"),    // Store W (6309)
        InstructionMnemonic::new("ldq"),    // Load Q (6309)
        InstructionMnemonic::new("stq"),    // Store Q (6309)
        InstructionMnemonic::new("addr"),   // Add register (6309)
        InstructionMnemonic::new("subr"),   // Subtract register (6309)
        InstructionMnemonic::new("andd"),   // AND D (6309)
        InstructionMnemonic::new("ord"),    // OR D (6309)
        InstructionMnemonic::new("eord"),   // XOR D (6309)
        InstructionMnemonic::new("adcr"),   // Add with carry register (6309)
        InstructionMnemonic::new("sbcr"),   // Subtract with carry register (6309)
    ]
}

impl ProcessorModule for Mc6800Processor {
    fn name() -> &'static str {
        "Motorola 6800/6809"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "6809:BE:16:default",
                "6809 Microprocessor",
                "default",
                Endian::Big,
                16,
            )
            .with_instruction_alignment(1)
            .with_pc_register("PC"),
            Language::new(
                "H6309:BE:16:default",
                "Hitachi 6309 Microprocessor (6809 extension)",
                "default",
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
        "Motorola 6800/6809 and Hitachi 6309 8-bit microprocessors"
    }

    fn family() -> &'static str {
        "6800"
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
    fn test_mc6800_name() {
        assert_eq!(Mc6800Processor::name(), "Motorola 6800/6809");
    }

    #[test]
    fn test_mc6800_registers() {
        let bank = Mc6800Processor::registers();
        assert!(bank.len() >= 15, "Expected at least 15 registers, got {}", bank.len());
        // Core registers
        assert!(bank.get("A").is_some());
        assert!(bank.get("B").is_some());
        assert!(bank.get("D").is_some());
        assert!(bank.get("X").is_some());
        assert!(bank.get("Y").is_some());
        assert!(bank.get("U").is_some());
        assert!(bank.get("S").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("CC").is_some());
        assert!(bank.get("DP").is_some());
        // CC bits
        assert!(bank.get("C").is_some());
        assert!(bank.get("V").is_some());
        assert!(bank.get("Z").is_some());
        assert!(bank.get("N").is_some());
        assert!(bank.get("I").is_some());
        assert!(bank.get("H").is_some());
        assert!(bank.get("F").is_some());
        assert!(bank.get("E").is_some());
    }

    #[test]
    fn test_mc6800_register_bits() {
        let bank = Mc6800Processor::registers();
        assert_eq!(bank.get("A").unwrap().bit_size, 8);
        assert_eq!(bank.get("B").unwrap().bit_size, 8);
        assert_eq!(bank.get("D").unwrap().bit_size, 16);
        assert_eq!(bank.get("X").unwrap().bit_size, 16);
        assert_eq!(bank.get("PC").unwrap().bit_size, 16);
        assert_eq!(bank.get("CC").unwrap().bit_size, 8);
        assert_eq!(bank.get("DP").unwrap().bit_size, 8);
    }

    #[test]
    fn test_mc6800_cc_bits() {
        let bank = Mc6800Processor::registers();
        let c = bank.get("C").unwrap();
        assert_eq!(c.parent.as_deref(), Some("CC"));
        assert_eq!(c.lsb, 0);

        let e = bank.get("E").unwrap();
        assert_eq!(e.parent.as_deref(), Some("CC"));
        assert_eq!(e.lsb, 7);
    }

    #[test]
    fn test_mc6800_languages() {
        let langs = Mc6800Processor::languages();
        assert!(langs.len() >= 2);
        assert!(langs.iter().any(|l| l.id == "6809:BE:16:default"));
        assert!(langs.iter().any(|l| l.id == "H6309:BE:16:default"));
        assert!(langs.iter().all(|l| l.endian == Endian::Big));
    }

    #[test]
    fn test_mc6800_instructions() {
        let insts = Mc6800Processor::instructions();
        assert!(insts.len() > 100);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        // Load/Store
        assert!(texts.contains(&"lda"));
        assert!(texts.contains(&"ldb"));
        assert!(texts.contains(&"ldd"));
        assert!(texts.contains(&"ldx"));
        assert!(texts.contains(&"ldy"));
        assert!(texts.contains(&"sta"));
        assert!(texts.contains(&"stb"));
        assert!(texts.contains(&"std"));
        // Transfer
        assert!(texts.contains(&"tfr"));
        assert!(texts.contains(&"exg"));
        assert!(texts.contains(&"tab"));
        assert!(texts.contains(&"tba"));
        // Stack
        assert!(texts.contains(&"pshs"));
        assert!(texts.contains(&"pshu"));
        assert!(texts.contains(&"puls"));
        assert!(texts.contains(&"pulu"));
        // Arithmetic
        assert!(texts.contains(&"adda"));
        assert!(texts.contains(&"addb"));
        assert!(texts.contains(&"addd"));
        assert!(texts.contains(&"suba"));
        assert!(texts.contains(&"subb"));
        assert!(texts.contains(&"mul"));
        assert!(texts.contains(&"daa"));
        // Compare
        assert!(texts.contains(&"cmpa"));
        assert!(texts.contains(&"cmpb"));
        assert!(texts.contains(&"cmpd"));
        assert!(texts.contains(&"cmpx"));
        // Shift
        assert!(texts.contains(&"lsla"));
        assert!(texts.contains(&"lsra"));
        assert!(texts.contains(&"asla"));
        assert!(texts.contains(&"rola"));
        assert!(texts.contains(&"rora"));
        // Branch
        assert!(texts.contains(&"bra"));
        assert!(texts.contains(&"beq"));
        assert!(texts.contains(&"bne"));
        assert!(texts.contains(&"bcc"));
        assert!(texts.contains(&"bcs"));
        // Long branch
        assert!(texts.contains(&"lbeq"));
        assert!(texts.contains(&"lbne"));
        // Jump/Call
        assert!(texts.contains(&"jmp"));
        assert!(texts.contains(&"jsr"));
        assert!(texts.contains(&"rts"));
        assert!(texts.contains(&"rti"));
        // System
        assert!(texts.contains(&"swi"));
        assert!(texts.contains(&"swi2"));
        assert!(texts.contains(&"swi3"));
        assert!(texts.contains(&"nop"));
        // 6309 extensions
        assert!(texts.contains(&"ldw"));
        assert!(texts.contains(&"ldq"));
        assert!(texts.contains(&"addr"));
    }

    #[test]
    fn test_mc6800_metadata() {
        assert_eq!(Mc6800Processor::family(), "6800");
        assert_eq!(Mc6800Processor::default_pointer_size(), 16);
        assert_eq!(Mc6800Processor::default_endian(), Endian::Big);
    }
}
