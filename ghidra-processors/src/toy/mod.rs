//! Toy / BISA Processor Module
//!
//! A simple example processor designed for teaching, testing, and education
//! purposes. This is a basic instruction set architecture (BISA) used by
//! Ghidra as a disassembler development example and for demonstrating the
//! processor module framework.
//!
//! ## Architecture overview
//! - Minimalist ISA with a small number of registers
//! - Designed for testing the processor module infrastructure
//! - Useful as a template for creating new processor modules
//!
//! ## Register space layout
//! - General-purpose (R0-R7):   0x0000 - 0x001C  (16-bit each)
//! - Status (FLAGS):            0x0020 (8-bit)
//! - Program counter (PC):      0x0024 (16-bit)
//! - Stack pointer (SP):        0x0028 (16-bit)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Toy/BISA processor struct.
pub struct ToyProcessor;

/// Build the complete Toy register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- General-purpose registers R0-R7 (16-bit) ----
    for i in 0..8u32 {
        bank.add(Register::new(
            &format!("R{}", i),
            16,
            (i as u64) * 4,
        ));
    }

    // Register aliases for conventional usage
    bank.add(Register::sub_register("ACC", 16, 0 * 4, "R0", 0)); // Accumulator
    bank.add(Register::sub_register("TMP", 16, 1 * 4, "R1", 0)); // Temporary
    bank.add(Register::sub_register("RES", 16, 2 * 4, "R2", 0)); // Result
    bank.add(Register::sub_register("BASE", 16, 3 * 4, "R3", 0)); // Base pointer

    // ---- Status flags (8-bit) ----
    bank.add(Register::new("FLAGS", 8, 0x0020)); // Status/condition flags
    bank.add(Register::sub_register("Z", 1, 0x0020, "FLAGS", 0)); // Zero flag
    bank.add(Register::sub_register("N", 1, 0x0020, "FLAGS", 1)); // Negative (sign) flag
    bank.add(Register::sub_register("C", 1, 0x0020, "FLAGS", 2)); // Carry flag
    bank.add(Register::sub_register("V", 1, 0x0020, "FLAGS", 3)); // Overflow flag

    // ---- Program counter ----
    bank.add(Register::new("PC", 16, 0x0024));

    // ---- Stack pointer ----
    bank.add(Register::new("SP", 16, 0x0028));

    bank
}

/// Build the Toy instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Data movement ===
        InstructionMnemonic::new("LOAD"),     // Load from memory to register
        InstructionMnemonic::new("STORE"),    // Store from register to memory
        InstructionMnemonic::new("MOV"),      // Move register to register
        InstructionMnemonic::new("LI"),       // Load immediate (load constant)
        InstructionMnemonic::new("LDI"),      // Load immediate (alternate mnemonic)
        // === Arithmetic ===
        InstructionMnemonic::new("ADD"),      // Add two registers
        InstructionMnemonic::new("ADDI"),     // Add immediate
        InstructionMnemonic::new("SUB"),      // Subtract two registers
        InstructionMnemonic::new("SUBI"),     // Subtract immediate
        InstructionMnemonic::new("MUL"),      // Multiply two registers (low result)
        InstructionMnemonic::new("DIV"),      // Divide (integer division)
        InstructionMnemonic::new("INC"),      // Increment register
        InstructionMnemonic::new("DEC"),      // Decrement register
        InstructionMnemonic::new("NEG"),      // Negate (2's complement)
        // === Logical ===
        InstructionMnemonic::new("AND"),      // Bitwise AND
        InstructionMnemonic::new("ANDI"),     // Bitwise AND immediate
        InstructionMnemonic::new("OR"),       // Bitwise OR
        InstructionMnemonic::new("ORI"),      // Bitwise OR immediate
        InstructionMnemonic::new("XOR"),      // Bitwise XOR
        InstructionMnemonic::new("XORI"),     // Bitwise XOR immediate
        InstructionMnemonic::new("NOT"),      // Bitwise NOT (1's complement)
        // === Shift ===
        InstructionMnemonic::new("SHL"),      // Shift left logical
        InstructionMnemonic::new("SHR"),      // Shift right logical
        InstructionMnemonic::new("SHLI"),     // Shift left logical immediate
        InstructionMnemonic::new("SHRI"),     // Shift right logical immediate
        InstructionMnemonic::new("SAR"),      // Shift right arithmetic
        InstructionMnemonic::new("SARI"),     // Shift right arithmetic immediate
        // === Compare ===
        InstructionMnemonic::new("CMP"),      // Compare two registers (set flags)
        InstructionMnemonic::new("CMPI"),     // Compare immediate
        InstructionMnemonic::new("TEST"),     // Test (AND with self, set flags)
        // === Branch / Jump ===
        InstructionMnemonic::new("JMP"),      // Jump (unconditional)
        InstructionMnemonic::new("JMPR"),     // Jump register (indirect)
        InstructionMnemonic::new("JZ"),       // Jump if zero (Z=1)
        InstructionMnemonic::new("JNZ"),      // Jump if not zero (Z=0)
        InstructionMnemonic::new("JN"),       // Jump if negative (N=1)
        InstructionMnemonic::new("JNN"),      // Jump if not negative (N=0)
        InstructionMnemonic::new("JC"),       // Jump if carry (C=1)
        InstructionMnemonic::new("JNC"),      // Jump if not carry (C=0)
        InstructionMnemonic::new("JV"),       // Jump if overflow (V=1)
        InstructionMnemonic::new("JNV"),      // Jump if not overflow (V=0)
        InstructionMnemonic::new("JE"),       // Jump if equal (Z=1)
        InstructionMnemonic::new("JNE"),      // Jump if not equal (Z=0)
        InstructionMnemonic::new("JG"),       // Jump if greater than (signed)
        InstructionMnemonic::new("JGE"),      // Jump if greater or equal (signed)
        InstructionMnemonic::new("JL"),       // Jump if less than (signed)
        InstructionMnemonic::new("JLE"),      // Jump if less or equal (signed)
        // === Subroutine ===
        InstructionMnemonic::new("CALL"),     // Call subroutine
        InstructionMnemonic::new("RET"),      // Return from subroutine
        // === Stack ===
        InstructionMnemonic::new("PUSH"),     // Push register onto stack
        InstructionMnemonic::new("POP"),      // Pop register from stack
        // === System ===
        InstructionMnemonic::new("HALT"),     // Halt / stop execution
        InstructionMnemonic::new("NOP"),      // No operation
        InstructionMnemonic::new("BREAK"),    // Breakpoint (debug trap)
        // === I/O (basic) ===
        InstructionMnemonic::new("IN"),       // Input from I/O port
        InstructionMnemonic::new("OUT"),      // Output to I/O port
        // === Extended (for education/testing) ===
        InstructionMnemonic::new("SWAP"),     // Swap two registers
        InstructionMnemonic::new("CLR"),      // Clear register (set to zero)
        InstructionMnemonic::new("SET"),      // Set register (set to all ones)
        // Pseudo-instructions
        InstructionMnemonic::new("ZERO"),     // Pseudo: clear to zero
        InstructionMnemonic::new("DATA"),     // Data directive (not an instruction)
    ]
}

impl ProcessorModule for ToyProcessor {
    fn name() -> &'static str {
        "Toy BISA (Basic Instruction Set Architecture)"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "toy:BE:16:default",
                "Toy BISA (16-bit, big-endian, example language)",
                "default",
                Endian::Big,
                16,
            ),
            Language::new(
                "toy:LE:16:default",
                "Toy BISA (16-bit, little-endian, example language)",
                "default",
                Endian::Little,
                16,
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
    fn test_toy_name() {
        assert_eq!(
            ToyProcessor::name(),
            "Toy BISA (Basic Instruction Set Architecture)"
        );
    }

    #[test]
    fn test_toy_registers() {
        let bank = ToyProcessor::registers();
        assert!(bank.len() >= 10, "Expected registers, got {}", bank.len());
        // GPRs
        for i in 0..8u32 {
            assert!(bank.get(&format!("R{}", i)).is_some());
        }
        assert!(bank.get("ACC").is_some());
        assert!(bank.get("TMP").is_some());
        assert!(bank.get("RES").is_some());
        assert!(bank.get("BASE").is_some());
        // Flags
        assert!(bank.get("FLAGS").is_some());
        assert!(bank.get("Z").is_some());
        assert!(bank.get("N").is_some());
        assert!(bank.get("C").is_some());
        assert!(bank.get("V").is_some());
        // PC, SP
        assert!(bank.get("PC").is_some());
        assert!(bank.get("SP").is_some());
    }

    #[test]
    fn test_toy_aliases() {
        let bank = ToyProcessor::registers();
        assert_eq!(bank.get("ACC").unwrap().parent.as_deref(), Some("R0"));
        assert_eq!(bank.get("TMP").unwrap().parent.as_deref(), Some("R1"));
        assert_eq!(bank.get("RES").unwrap().parent.as_deref(), Some("R2"));
        assert_eq!(bank.get("BASE").unwrap().parent.as_deref(), Some("R3"));
    }

    #[test]
    fn test_toy_flag_bits() {
        let bank = ToyProcessor::registers();
        let z = bank.get("Z").unwrap();
        assert_eq!(z.parent.as_deref(), Some("FLAGS"));
        assert_eq!(z.lsb, 0);
        assert_eq!(z.bit_size, 1);

        let v = bank.get("V").unwrap();
        assert_eq!(v.parent.as_deref(), Some("FLAGS"));
        assert_eq!(v.lsb, 3);
    }

    #[test]
    fn test_toy_register_bits() {
        let bank = ToyProcessor::registers();
        for i in 0..8u32 {
            assert_eq!(bank.get(&format!("R{}", i)).unwrap().bit_size, 16);
        }
        assert_eq!(bank.get("FLAGS").unwrap().bit_size, 8);
        assert_eq!(bank.get("PC").unwrap().bit_size, 16);
        assert_eq!(bank.get("SP").unwrap().bit_size, 16);
    }

    #[test]
    fn test_toy_languages() {
        let langs = ToyProcessor::languages();
        assert!(langs.len() >= 2);
        assert!(langs.iter().any(|l| l.id == "toy:BE:16:default"));
        assert!(langs.iter().any(|l| l.id == "toy:LE:16:default"));
        let be = langs.iter().find(|l| l.id == "toy:BE:16:default").unwrap();
        assert_eq!(be.endian, Endian::Big);
        let le = langs.iter().find(|l| l.id == "toy:LE:16:default").unwrap();
        assert_eq!(le.endian, Endian::Little);
    }

    #[test]
    fn test_toy_instructions() {
        let insts = ToyProcessor::instructions();
        assert!(insts.len() > 30);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"LOAD"));
        assert!(texts.contains(&"STORE"));
        assert!(texts.contains(&"MOV"));
        assert!(texts.contains(&"ADD"));
        assert!(texts.contains(&"SUB"));
        assert!(texts.contains(&"MUL"));
        assert!(texts.contains(&"DIV"));
        assert!(texts.contains(&"AND"));
        assert!(texts.contains(&"OR"));
        assert!(texts.contains(&"XOR"));
        assert!(texts.contains(&"SHL"));
        assert!(texts.contains(&"SHR"));
        assert!(texts.contains(&"CMP"));
        assert!(texts.contains(&"JMP"));
        assert!(texts.contains(&"JZ"));
        assert!(texts.contains(&"JNZ"));
        assert!(texts.contains(&"CALL"));
        assert!(texts.contains(&"RET"));
        assert!(texts.contains(&"PUSH"));
        assert!(texts.contains(&"POP"));
        assert!(texts.contains(&"HALT"));
        assert!(texts.contains(&"NOP"));
        assert!(texts.contains(&"BREAK"));
    }

    #[test]
    fn test_toy_simple_example() {
        // Verify basic register and instruction lookup works
        let bank = ToyProcessor::registers();
        assert_eq!(bank.get("R4").unwrap().bit_size, 16);
        assert_eq!(bank.get("PC").unwrap().bit_size, 16);

        let insts = ToyProcessor::instructions();
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        // Essential instructions that any toy CPU should have
        assert!(texts.contains(&"LOAD"));
        assert!(texts.contains(&"STORE"));
        assert!(texts.contains(&"ADD"));
        assert!(texts.contains(&"JMP"));
        assert!(texts.contains(&"HALT"));
    }
}
