//! National Semiconductor CompactRISC CR16C Processor Module
//!
//! Supports the CR16C 16-bit microcontroller from National Semiconductor.
//!
//! ## Architecture overview
//! - 16 general-purpose 16-bit registers R0-R11, R12, R13, RA, SP
//! - R12, R13, RA, SP can be used as 32-bit register pairs
//! - 16-bit/32-bit program counter PC
//! - Processor Status Register (PSR) with flags: C, T, L, U, F, Z, N, E, P, I
//! - Configuration Register (CFG)
//! - Interrupt Stack Pointer (ISP), User Stack Pointer (USP)
//! - Interrupt Base register (INTBASE)
//! - 2-byte instruction alignment
//!
//! ## Register space layout
//! - General Purpose (R0-R11):     0x00-0x17  (16-bit each)
//! - R12/R13/RA/SP (16-bit):      0x18-0x27  (16-bit each)
//! - Register pairs (32-bit):      0x00-0x28  (R1R0, R3R2, ..., SP)
//! - Program Counter (PC):         0x32  (32-bit)
//! - ISP/USP/INTBASE:             0x3C-0x44  (32-bit each)
//! - PSR:                          0x50  (16-bit)
//! - CFG:                          0x64  (16-bit)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// CR16C processor struct.
pub struct Cr16cProcessor;

/// Build the complete CR16C register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- General-purpose 16-bit registers ----
    for i in 0..12u64 {
        let name = format!("R{}", i);
        bank.add(Register::new(&name, 16, i * 2)
            .with_description(format!("General-purpose register R{}", i))
            .with_group("General Purpose"));
    }

    // ---- Special 16-bit registers ----
    bank.add(Register::new("R12_L", 16, 0x0018)
        .with_description("R12 low word")
        .with_group("General Purpose"));
    bank.add(Register::new("R12_H", 16, 0x001A)
        .with_description("R12 high word")
        .with_group("General Purpose"));
    bank.add(Register::new("R13_L", 16, 0x001C)
        .with_description("R13 low word")
        .with_group("General Purpose"));
    bank.add(Register::new("R13_H", 16, 0x001E)
        .with_description("R13 high word")
        .with_group("General Purpose"));
    bank.add(Register::new("RA_L", 16, 0x0020)
        .with_description("Return address low word")
        .with_group("General Purpose"));
    bank.add(Register::new("RA_H", 16, 0x0022)
        .with_description("Return address high word")
        .with_group("General Purpose"));
    bank.add(Register::new("SP_L", 16, 0x0024)
        .with_description("Stack pointer low word")
        .with_group("General Purpose"));
    bank.add(Register::new("SP_H", 16, 0x0026)
        .with_description("Stack pointer high word")
        .with_group("General Purpose"));

    // ---- 32-bit register pairs ----
    bank.add(Register::new("R1R0", 32, 0x0000)
        .with_description("Register pair R1:R0")
        .with_group("Register Pairs"));
    bank.add(Register::new("R3R2", 32, 0x0004)
        .with_description("Register pair R3:R2")
        .with_group("Register Pairs"));
    bank.add(Register::new("R5R4", 32, 0x0008)
        .with_description("Register pair R5:R4")
        .with_group("Register Pairs"));
    bank.add(Register::new("R7R6", 32, 0x000C)
        .with_description("Register pair R7:R6")
        .with_group("Register Pairs"));
    bank.add(Register::new("R9R8", 32, 0x0010)
        .with_description("Register pair R9:R8")
        .with_group("Register Pairs"));
    bank.add(Register::new("R11R10", 32, 0x0014)
        .with_description("Register pair R11:R10")
        .with_group("Register Pairs"));
    bank.add(Register::new("R12", 32, 0x0018)
        .with_description("Register R12 (32-bit)")
        .with_group("Register Pairs"));
    bank.add(Register::new("R13", 32, 0x001C)
        .with_description("Register R13 (32-bit)")
        .with_group("Register Pairs"));
    bank.add(Register::new("RA", 32, 0x0020)
        .with_description("Return address (32-bit)")
        .with_group("Register Pairs"));
    bank.add(Register::new("SP", 32, 0x0024)
        .with_type(crate::common::RegisterType::SP)
        .with_description("Stack pointer (32-bit)")
        .with_group("Register Pairs"));

    // ---- Program Counter ----
    bank.add(Register::new("PC", 32, 0x0032)
        .with_type(crate::common::RegisterType::PC)
        .with_description("Program counter")
        .with_group("Control"));

    // ---- System registers ----
    bank.add(Register::new("ISP", 32, 0x003C)
        .with_description("Interrupt stack pointer")
        .with_group("System"));
    bank.add(Register::new("USP", 32, 0x0040)
        .with_description("User stack pointer")
        .with_group("System"));
    bank.add(Register::new("INTBASE", 32, 0x0044)
        .with_description("Interrupt base address")
        .with_group("System"));

    // ---- Processor Status Register ----
    bank.add(Register::new("PSR", 16, 0x0050)
        .with_description("Processor status register")
        .with_group("Status"));

    // ---- PSR flag bits ----
    bank.add(Register::new("C", 1, 0x0050)
        .with_description("Carry flag")
        .with_group("Flags"));
    bank.add(Register::new("T", 1, 0x0051)
        .with_description("Trace flag")
        .with_group("Flags"));
    bank.add(Register::new("L", 1, 0x0052)
        .with_description("Less than flag")
        .with_group("Flags"));
    bank.add(Register::new("U", 1, 0x0053)
        .with_description("Upper flag")
        .with_group("Flags"));
    bank.add(Register::new("F", 1, 0x0055)
        .with_description("Flag flag")
        .with_group("Flags"));
    bank.add(Register::new("Z", 1, 0x0056)
        .with_description("Zero flag")
        .with_group("Flags"));
    bank.add(Register::new("N", 1, 0x0057)
        .with_description("Negative flag")
        .with_group("Flags"));
    bank.add(Register::new("E", 1, 0x0059)
        .with_description("Exception flag")
        .with_group("Flags"));
    bank.add(Register::new("P", 1, 0x005A)
        .with_description("Pending interrupt flag")
        .with_group("Flags"));
    bank.add(Register::new("I", 1, 0x005B)
        .with_description("Interrupt enable flag")
        .with_group("Flags"));

    // ---- Configuration Register ----
    bank.add(Register::new("CFG", 16, 0x0064)
        .with_description("Configuration register")
        .with_group("System"));

    // ---- Debug registers ----
    bank.add(Register::new("DBS", 16, 0x006E)
        .with_description("Debug status register")
        .with_group("Debug"));
    bank.add(Register::new("DSR", 16, 0x0070)
        .with_description("Debug select register")
        .with_group("Debug"));
    bank.add(Register::new("DCR", 32, 0x0074)
        .with_description("Debug control register")
        .with_group("Debug"));
    bank.add(Register::new("CAR0", 32, 0x0078)
        .with_description("Compare address register 0")
        .with_group("Debug"));
    bank.add(Register::new("CAR1", 32, 0x007C)
        .with_description("Compare address register 1")
        .with_group("Debug"));

    bank
}

/// Build the CR16C instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Load/Store ===
        InstructionMnemonic::new("movb"),   // Move byte
        InstructionMnemonic::new("movw"),   // Move word
        InstructionMnemonic::new("movd"),   // Move doubleword
        InstructionMnemonic::new("loadb"),  // Load byte
        InstructionMnemonic::new("loadw"),  // Load word
        InstructionMnemonic::new("loadd"),  // Load doubleword
        InstructionMnemonic::new("storb"),  // Store byte
        InstructionMnemonic::new("storw"),  // Store word
        InstructionMnemonic::new("stord"),  // Store doubleword
        InstructionMnemonic::new("push"),   // Push
        InstructionMnemonic::new("pop"),    // Pop
        // === Arithmetic ===
        InstructionMnemonic::new("addb"),   // Add byte
        InstructionMnemonic::new("addw"),   // Add word
        InstructionMnemonic::new("addd"),   // Add doubleword
        InstructionMnemonic::new("addcw"),  // Add with carry word
        InstructionMnemonic::new("subb"),   // Subtract byte
        InstructionMnemonic::new("subw"),   // Subtract word
        InstructionMnemonic::new("subd"),   // Subtract doubleword
        InstructionMnemonic::new("subcw"),  // Subtract with carry word
        InstructionMnemonic::new("mulb"),   // Multiply byte
        InstructionMnemonic::new("mulw"),   // Multiply word
        InstructionMnemonic::new("muld"),   // Multiply doubleword
        InstructionMnemonic::new("divb"),   // Divide byte
        InstructionMnemonic::new("divw"),   // Divide word
        InstructionMnemonic::new("divd"),   // Divide doubleword
        InstructionMnemonic::new("incb"),   // Increment byte
        InstructionMnemonic::new("incw"),   // Increment word
        InstructionMnemonic::new("incd"),   // Increment doubleword
        InstructionMnemonic::new("decb"),   // Decrement byte
        InstructionMnemonic::new("decw"),   // Decrement word
        InstructionMnemonic::new("decd"),   // Decrement doubleword
        InstructionMnemonic::new("negw"),   // Negate word
        InstructionMnemonic::new("negd"),   // Negate doubleword
        InstructionMnemonic::new("notw"),   // Bitwise NOT word
        InstructionMnemonic::new("notd"),   // Bitwise NOT doubleword
        // === Logical ===
        InstructionMnemonic::new("andb"),   // AND byte
        InstructionMnemonic::new("andw"),   // AND word
        InstructionMnemonic::new("andd"),   // AND doubleword
        InstructionMnemonic::new("orb"),    // OR byte
        InstructionMnemonic::new("orw"),    // OR word
        InstructionMnemonic::new("ord"),    // OR doubleword
        InstructionMnemonic::new("xorb"),   // XOR byte
        InstructionMnemonic::new("xorw"),   // XOR word
        InstructionMnemonic::new("xord"),   // XOR doubleword
        // === Shift ===
        InstructionMnemonic::new("ashuw"),  // Arithmetic shift word
        InstructionMnemonic::new("ashud"),  // Arithmetic shift doubleword
        InstructionMnemonic::new("lshw"),   // Logical shift word
        InstructionMnemonic::new("lshd"),   // Logical shift doubleword
        // === Compare ===
        InstructionMnemonic::new("cmpb"),   // Compare byte
        InstructionMnemonic::new("cmpw"),   // Compare word
        InstructionMnemonic::new("cmpd"),   // Compare doubleword
        InstructionMnemonic::new("tbit"),   // Test bit
        InstructionMnemonic::new("sbit"),   // Set bit
        InstructionMnemonic::new("cbit"),   // Clear bit
        InstructionMnemonic::new("tbitb"),  // Test bit byte
        InstructionMnemonic::new("sbitb"),  // Set bit byte
        InstructionMnemonic::new("cbitb"),  // Clear bit byte
        // === Branch ===
        InstructionMnemonic::new("b"),      // Branch unconditional
        InstructionMnemonic::new("beq"),    // Branch if equal
        InstructionMnemonic::new("bne"),    // Branch if not equal
        InstructionMnemonic::new("bcs"),    // Branch if carry set
        InstructionMnemonic::new("bcc"),    // Branch if carry clear
        InstructionMnemonic::new("bhi"),    // Branch if higher
        InstructionMnemonic::new("bls"),    // Branch if lower or same
        InstructionMnemonic::new("bgt"),    // Branch if greater than
        InstructionMnemonic::new("ble"),    // Branch if less or equal
        InstructionMnemonic::new("bge"),    // Branch if greater or equal
        InstructionMnemonic::new("blt"),    // Branch if less than
        InstructionMnemonic::new("bmi"),    // Branch if minus
        InstructionMnemonic::new("bpl"),    // Branch if plus
        InstructionMnemonic::new("jump"),   // Jump
        InstructionMnemonic::new("jal"),    // Jump and link
        InstructionMnemonic::new("jsr"),    // Jump to subroutine
        InstructionMnemonic::new("ret"),    // Return
        InstructionMnemonic::new("rete"),   // Return from exception
        InstructionMnemonic::new("reti"),   // Return from interrupt
        // === System ===
        InstructionMnemonic::new("ei"),     // Enable interrupts
        InstructionMnemonic::new("di"),     // Disable interrupts
        InstructionMnemonic::new("nop"),    // No operation
        InstructionMnemonic::new("wait"),   // Wait for interrupt
        InstructionMnemonic::new("excp"),   // Exception
    ]
}

impl ProcessorModule for Cr16cProcessor {
    fn name() -> &'static str {
        "CR16C"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "CR16C:LE:16:default",
                "National Semiconductor CompactRISC CR16C little endian",
                "default",
                Endian::Little,
                16,
            )
            .with_instruction_alignment(2)
            .with_pc_register("PC"),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> {
        build_instructions()
    }

    fn description() -> &'static str {
        "National Semiconductor CompactRISC CR16C 16-bit microcontroller"
    }

    fn family() -> &'static str {
        "CompactRISC"
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
    fn test_cr16_name() {
        assert_eq!(Cr16cProcessor::name(), "CR16C");
    }

    #[test]
    fn test_cr16_registers() {
        let bank = Cr16cProcessor::registers();
        assert!(bank.len() >= 30, "Expected at least 30 registers, got {}", bank.len());
        // General purpose
        assert!(bank.get("R0").is_some());
        assert!(bank.get("R1").is_some());
        assert!(bank.get("R11").is_some());
        // Special registers
        assert!(bank.get("R12").is_some());
        assert!(bank.get("R13").is_some());
        assert!(bank.get("RA").is_some());
        assert!(bank.get("SP").is_some());
        // Register pairs
        assert!(bank.get("R1R0").is_some());
        assert!(bank.get("R3R2").is_some());
        assert!(bank.get("R11R10").is_some());
        // Control
        assert!(bank.get("PC").is_some());
        // System
        assert!(bank.get("ISP").is_some());
        assert!(bank.get("USP").is_some());
        assert!(bank.get("INTBASE").is_some());
        assert!(bank.get("PSR").is_some());
        assert!(bank.get("CFG").is_some());
        // Flags
        assert!(bank.get("C").is_some());
        assert!(bank.get("Z").is_some());
        assert!(bank.get("N").is_some());
    }

    #[test]
    fn test_cr16_register_bits() {
        let bank = Cr16cProcessor::registers();
        assert_eq!(bank.get("R0").unwrap().bit_size, 16);
        assert_eq!(bank.get("R12").unwrap().bit_size, 32);
        assert_eq!(bank.get("PC").unwrap().bit_size, 32);
        assert_eq!(bank.get("PSR").unwrap().bit_size, 16);
        assert_eq!(bank.get("CFG").unwrap().bit_size, 16);
    }

    #[test]
    fn test_cr16_languages() {
        let langs = Cr16cProcessor::languages();
        assert!(langs.len() >= 1);
        assert!(langs.iter().any(|l| l.id == "CR16C:LE:16:default"));
        assert!(langs.iter().all(|l| l.endian == Endian::Little));
    }

    #[test]
    fn test_cr16_instructions() {
        let insts = Cr16cProcessor::instructions();
        assert!(insts.len() > 50);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        // Load/Store
        assert!(texts.contains(&"movb"));
        assert!(texts.contains(&"movw"));
        assert!(texts.contains(&"loadb"));
        assert!(texts.contains(&"loadw"));
        assert!(texts.contains(&"storb"));
        assert!(texts.contains(&"storw"));
        // Arithmetic
        assert!(texts.contains(&"addb"));
        assert!(texts.contains(&"addw"));
        assert!(texts.contains(&"subb"));
        assert!(texts.contains(&"subw"));
        assert!(texts.contains(&"mulw"));
        assert!(texts.contains(&"divw"));
        // Logical
        assert!(texts.contains(&"andw"));
        assert!(texts.contains(&"orw"));
        assert!(texts.contains(&"xorw"));
        // Compare
        assert!(texts.contains(&"cmpb"));
        assert!(texts.contains(&"cmpw"));
        assert!(texts.contains(&"tbit"));
        // Branch
        assert!(texts.contains(&"b"));
        assert!(texts.contains(&"beq"));
        assert!(texts.contains(&"bne"));
        assert!(texts.contains(&"bcs"));
        assert!(texts.contains(&"bcc"));
        assert!(texts.contains(&"jump"));
        assert!(texts.contains(&"jsr"));
        assert!(texts.contains(&"ret"));
        assert!(texts.contains(&"reti"));
        // System
        assert!(texts.contains(&"ei"));
        assert!(texts.contains(&"di"));
        assert!(texts.contains(&"nop"));
    }

    #[test]
    fn test_cr16_metadata() {
        assert_eq!(Cr16cProcessor::family(), "CompactRISC");
        assert_eq!(Cr16cProcessor::default_pointer_size(), 16);
        assert_eq!(Cr16cProcessor::default_endian(), Endian::Little);
    }
}
