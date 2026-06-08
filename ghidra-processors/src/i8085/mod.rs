//! Intel 8085 Processor Module
//!
//! Supports the Intel 8085 8-bit microprocessor.
//!
//! ## Architecture overview
//! - 8-bit accumulator A
//! - 8-bit register pairs: BC, DE, HL (B, C, D, E, H, L)
//! - Alternate register set: AF', BC', DE', HL'
//! - 16-bit stack pointer SP
//! - 16-bit program counter PC
//! - Flags: S, Z, AC, P, CY
//!
//! ## Register space layout
//! - Main registers (A, F, B, C, D, E, H, L):  0x00-0x07  (8-bit each)
//! - Register pairs (AF, BC, DE, HL):            0x00-0x07  (16-bit each)
//! - Alternate registers (A', F', etc.):         0x10-0x17  (8-bit each)
//! - Alternate register pairs:                   0x10-0x17  (16-bit each)
//! - Control (PC, SP):                           0x20-0x23  (16-bit each)
//! - Flags (S, Z, AC, P, CY):                   0x30  (1-bit each)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Intel 8085 processor struct.
pub struct I8085Processor;

/// Build the complete 8085 register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- Main registers ----
    bank.add(Register::new("A", 8, 0x0000)
        .with_description("Accumulator")
        .with_group("General Purpose"));
    bank.add(Register::new("F", 8, 0x0001)
        .with_description("Flags register")
        .with_group("Status"));
    bank.add(Register::new("B", 8, 0x0002)
        .with_description("Register B")
        .with_group("General Purpose"));
    bank.add(Register::new("C", 8, 0x0003)
        .with_description("Register C")
        .with_group("General Purpose"));
    bank.add(Register::new("D", 8, 0x0004)
        .with_description("Register D")
        .with_group("General Purpose"));
    bank.add(Register::new("E", 8, 0x0005)
        .with_description("Register E")
        .with_group("General Purpose"));
    bank.add(Register::new("H", 8, 0x0006)
        .with_description("Register H")
        .with_group("General Purpose"));
    bank.add(Register::new("L", 8, 0x0007)
        .with_description("Register L")
        .with_group("General Purpose"));

    // ---- Register pairs ----
    bank.add(Register::new("AF", 16, 0x0000)
        .with_description("Register pair A:F")
        .with_group("General Purpose"));
    bank.add(Register::new("BC", 16, 0x0002)
        .with_description("Register pair B:C")
        .with_group("General Purpose"));
    bank.add(Register::new("DE", 16, 0x0004)
        .with_description("Register pair D:E")
        .with_group("General Purpose"));
    bank.add(Register::new("HL", 16, 0x0006)
        .with_description("Register pair H:L")
        .with_group("General Purpose"));

    // ---- Alternate register set ----
    bank.add(Register::new("A_", 8, 0x0010)
        .with_description("Alternate accumulator")
        .with_group("Alternate"));
    bank.add(Register::new("F_", 8, 0x0011)
        .with_description("Alternate flags")
        .with_group("Alternate"));
    bank.add(Register::new("B_", 8, 0x0012)
        .with_description("Alternate register B")
        .with_group("Alternate"));
    bank.add(Register::new("C_", 8, 0x0013)
        .with_description("Alternate register C")
        .with_group("Alternate"));
    bank.add(Register::new("D_", 8, 0x0014)
        .with_description("Alternate register D")
        .with_group("Alternate"));
    bank.add(Register::new("E_", 8, 0x0015)
        .with_description("Alternate register E")
        .with_group("Alternate"));
    bank.add(Register::new("H_", 8, 0x0016)
        .with_description("Alternate register H")
        .with_group("Alternate"));
    bank.add(Register::new("L_", 8, 0x0017)
        .with_description("Alternate register L")
        .with_group("Alternate"));

    // ---- Alternate register pairs ----
    bank.add(Register::new("AF_", 16, 0x0010)
        .with_description("Alternate register pair A':F'")
        .with_group("Alternate"));
    bank.add(Register::new("BC_", 16, 0x0012)
        .with_description("Alternate register pair B':C'")
        .with_group("Alternate"));
    bank.add(Register::new("DE_", 16, 0x0014)
        .with_description("Alternate register pair D':E'")
        .with_group("Alternate"));
    bank.add(Register::new("HL_", 16, 0x0016)
        .with_description("Alternate register pair H':L'")
        .with_group("Alternate"));

    // ---- Control registers ----
    bank.add(Register::new("PC", 16, 0x0020)
        .with_type(crate::common::RegisterType::PC)
        .with_description("Program counter")
        .with_group("Control"));
    bank.add(Register::new("SP", 16, 0x0022)
        .with_type(crate::common::RegisterType::SP)
        .with_description("Stack pointer")
        .with_group("Control"));

    // ---- Individual flag bits ----
    bank.add(Register::new("S_flag", 1, 0x0030)
        .with_description("Sign flag")
        .with_group("Flags"));
    bank.add(Register::new("Z_flag", 1, 0x0031)
        .with_description("Zero flag")
        .with_group("Flags"));
    bank.add(Register::new("AC_flag", 1, 0x0032)
        .with_description("Auxiliary carry flag")
        .with_group("Flags"));
    bank.add(Register::new("P_flag", 1, 0x0033)
        .with_description("Parity flag")
        .with_group("Flags"));
    bank.add(Register::new("CY_flag", 1, 0x0034)
        .with_description("Carry flag")
        .with_group("Flags"));

    bank
}

/// Build the 8085 instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Data transfer ===
        InstructionMnemonic::new("mov"),    // Move register to register
        InstructionMnemonic::new("mvi"),    // Move immediate
        InstructionMnemonic::new("lda"),    // Load accumulator direct
        InstructionMnemonic::new("sta"),    // Store accumulator direct
        InstructionMnemonic::new("ldax"),   // Load accumulator indirect
        InstructionMnemonic::new("stax"),   // Store accumulator indirect
        InstructionMnemonic::new("lhld"),   // Load H:L direct
        InstructionMnemonic::new("shld"),   // Store H:L direct
        InstructionMnemonic::new("lxi"),    // Load register pair immediate
        InstructionMnemonic::new("xchg"),   // Exchange DE and HL
        InstructionMnemonic::new("sphl"),   // Move HL to SP
        InstructionMnemonic::new("xthl"),   // Exchange top of stack with HL
        InstructionMnemonic::new("push"),   // Push register pair
        InstructionMnemonic::new("pop"),    // Pop register pair
        // === Arithmetic ===
        InstructionMnemonic::new("add"),    // Add register to A
        InstructionMnemonic::new("adi"),    // Add immediate to A
        InstructionMnemonic::new("adc"),    // Add with carry
        InstructionMnemonic::new("aci"),    // Add immediate with carry
        InstructionMnemonic::new("sub"),    // Subtract from A
        InstructionMnemonic::new("sui"),    // Subtract immediate
        InstructionMnemonic::new("sbb"),    // Subtract with borrow
        InstructionMnemonic::new("sbi"),    // Subtract immediate with borrow
        InstructionMnemonic::new("inr"),    // Increment register
        InstructionMnemonic::new("dcr"),    // Decrement register
        InstructionMnemonic::new("inx"),    // Increment register pair
        InstructionMnemonic::new("dcx"),    // Decrement register pair
        InstructionMnemonic::new("dad"),    // Add register pair to HL
        InstructionMnemonic::new("daa"),    // Decimal adjust accumulator
        // === Logical ===
        InstructionMnemonic::new("ana"),    // AND register with A
        InstructionMnemonic::new("ani"),    // AND immediate with A
        InstructionMnemonic::new("xra"),    // XOR register with A
        InstructionMnemonic::new("xri"),    // XOR immediate with A
        InstructionMnemonic::new("ora"),    // OR register with A
        InstructionMnemonic::new("ori"),    // OR immediate with A
        InstructionMnemonic::new("cmp"),    // Compare register with A
        InstructionMnemonic::new("cpi"),    // Compare immediate with A
        InstructionMnemonic::new("rlc"),    // Rotate A left
        InstructionMnemonic::new("rrc"),    // Rotate A right
        InstructionMnemonic::new("ral"),    // Rotate A left through carry
        InstructionMnemonic::new("rar"),    // Rotate A right through carry
        InstructionMnemonic::new("cma"),    // Complement A
        InstructionMnemonic::new("cmc"),    // Complement carry
        InstructionMnemonic::new("stc"),    // Set carry
        // === Branch ===
        InstructionMnemonic::new("jmp"),    // Jump
        InstructionMnemonic::new("jc"),     // Jump if carry
        InstructionMnemonic::new("jnc"),    // Jump if no carry
        InstructionMnemonic::new("jz"),     // Jump if zero
        InstructionMnemonic::new("jnz"),    // Jump if not zero
        InstructionMnemonic::new("jm"),     // Jump if minus
        InstructionMnemonic::new("jp"),     // Jump if plus
        InstructionMnemonic::new("jpe"),    // Jump if parity even
        InstructionMnemonic::new("jpo"),    // Jump if parity odd
        InstructionMnemonic::new("call"),   // Call subroutine
        InstructionMnemonic::new("cc"),     // Call if carry
        InstructionMnemonic::new("cnc"),    // Call if no carry
        InstructionMnemonic::new("cz"),     // Call if zero
        InstructionMnemonic::new("cnz"),    // Call if not zero
        InstructionMnemonic::new("cm"),     // Call if minus
        InstructionMnemonic::new("cp"),     // Call if plus
        InstructionMnemonic::new("cpe"),    // Call if parity even
        InstructionMnemonic::new("cpo"),    // Call if parity odd
        InstructionMnemonic::new("ret"),    // Return
        InstructionMnemonic::new("rc"),     // Return if carry
        InstructionMnemonic::new("rnc"),    // Return if no carry
        InstructionMnemonic::new("rz"),     // Return if zero
        InstructionMnemonic::new("rnz"),    // Return if not zero
        InstructionMnemonic::new("rm"),     // Return if minus
        InstructionMnemonic::new("rp"),     // Return if plus
        InstructionMnemonic::new("rpe"),    // Return if parity even
        InstructionMnemonic::new("rpo"),    // Return if parity odd
        // === Restart ===
        InstructionMnemonic::new("rst"),    // Restart (interrupt vector)
        // === I/O ===
        InstructionMnemonic::new("in"),     // Input
        InstructionMnemonic::new("out"),    // Output
        // === Control ===
        InstructionMnemonic::new("hlt"),    // Halt
        InstructionMnemonic::new("nop"),    // No operation
        InstructionMnemonic::new("ei"),     // Enable interrupts
        InstructionMnemonic::new("di"),     // Disable interrupts
        InstructionMnemonic::new("rim"),    // Read interrupt mask
        InstructionMnemonic::new("sim"),    // Set interrupt mask
        InstructionMnemonic::new("pchl"),   // Move HL to PC
        InstructionMnemonic::new("rc"),     // Return if carry (duplicate for completeness)
    ]
}

impl ProcessorModule for I8085Processor {
    fn name() -> &'static str {
        "8085"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "8085:LE:16:default",
                "Intel 8085",
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
        "Intel 8085 8-bit microprocessor"
    }

    fn family() -> &'static str {
        "8085"
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
    fn test_8085_name() {
        assert_eq!(I8085Processor::name(), "8085");
    }

    #[test]
    fn test_8085_registers() {
        let bank = I8085Processor::registers();
        assert!(bank.len() >= 20, "Expected at least 20 registers, got {}", bank.len());
        // Main registers
        assert!(bank.get("A").is_some());
        assert!(bank.get("F").is_some());
        assert!(bank.get("B").is_some());
        assert!(bank.get("C").is_some());
        assert!(bank.get("D").is_some());
        assert!(bank.get("E").is_some());
        assert!(bank.get("H").is_some());
        assert!(bank.get("L").is_some());
        // Register pairs
        assert!(bank.get("AF").is_some());
        assert!(bank.get("BC").is_some());
        assert!(bank.get("DE").is_some());
        assert!(bank.get("HL").is_some());
        // Alternate registers
        assert!(bank.get("A_").is_some());
        assert!(bank.get("B_").is_some());
        assert!(bank.get("BC_").is_some());
        // Control
        assert!(bank.get("PC").is_some());
        assert!(bank.get("SP").is_some());
        // Flags
        assert!(bank.get("S_flag").is_some());
        assert!(bank.get("Z_flag").is_some());
        assert!(bank.get("AC_flag").is_some());
        assert!(bank.get("P_flag").is_some());
        assert!(bank.get("CY_flag").is_some());
    }

    #[test]
    fn test_8085_register_bits() {
        let bank = I8085Processor::registers();
        assert_eq!(bank.get("A").unwrap().bit_size, 8);
        assert_eq!(bank.get("B").unwrap().bit_size, 8);
        assert_eq!(bank.get("AF").unwrap().bit_size, 16);
        assert_eq!(bank.get("BC").unwrap().bit_size, 16);
        assert_eq!(bank.get("PC").unwrap().bit_size, 16);
        assert_eq!(bank.get("SP").unwrap().bit_size, 16);
    }

    #[test]
    fn test_8085_languages() {
        let langs = I8085Processor::languages();
        assert!(langs.len() >= 1);
        assert!(langs.iter().any(|l| l.id == "8085:LE:16:default"));
        assert!(langs.iter().all(|l| l.endian == Endian::Little));
    }

    #[test]
    fn test_8085_instructions() {
        let insts = I8085Processor::instructions();
        assert!(insts.len() > 50);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        // Data transfer
        assert!(texts.contains(&"mov"));
        assert!(texts.contains(&"mvi"));
        assert!(texts.contains(&"lda"));
        assert!(texts.contains(&"sta"));
        assert!(texts.contains(&"lxi"));
        assert!(texts.contains(&"push"));
        assert!(texts.contains(&"pop"));
        // Arithmetic
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"adi"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"sui"));
        assert!(texts.contains(&"inr"));
        assert!(texts.contains(&"dcr"));
        assert!(texts.contains(&"inx"));
        assert!(texts.contains(&"dcx"));
        assert!(texts.contains(&"dad"));
        assert!(texts.contains(&"daa"));
        // Logical
        assert!(texts.contains(&"ana"));
        assert!(texts.contains(&"xra"));
        assert!(texts.contains(&"ora"));
        assert!(texts.contains(&"cmp"));
        // Branch
        assert!(texts.contains(&"jmp"));
        assert!(texts.contains(&"call"));
        assert!(texts.contains(&"ret"));
        // Control
        assert!(texts.contains(&"hlt"));
        assert!(texts.contains(&"nop"));
        assert!(texts.contains(&"ei"));
        assert!(texts.contains(&"di"));
    }

    #[test]
    fn test_8085_metadata() {
        assert_eq!(I8085Processor::family(), "8085");
        assert_eq!(I8085Processor::default_pointer_size(), 16);
        assert_eq!(I8085Processor::default_endian(), Endian::Little);
    }
}
