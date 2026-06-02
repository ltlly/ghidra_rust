//! General Instrument CP1600 Processor Module
//!
//! Supports the CP1600 16-bit microprocessor from General Instrument, notable
//! for being the CPU used in the Intellivision video game console.
//!
//! ## Architecture overview
//! - 8 general-purpose 16-bit registers: R0-R7
//!   - R6 used as stack pointer (no dedicated SP)
//!   - R7 used as program counter
//! - 16-bit address bus (64KB direct addressing)
//! - Microcode-based architecture with 10-bit opcodes
//! - Condition flags: Sign, Zero, Overflow, Carry
//!
//! ## Register space layout
//! - General-purpose (R0-R7):   0x0000 - 0x000E  (16-bit each)
//! - Status flags:              0x0010 (SZC - 4-bit status register)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// General Instrument CP1600 processor struct.
pub struct Cp1600Processor;

/// Build the complete CP1600 register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- General-purpose registers R0-R7 (16-bit) ----
    // R0-R5: General-purpose registers
    // R6: Stack pointer (used by JSR, etc.)
    // R7: Program counter
    for i in 0..8u32 {
        let name = format!("R{}", i);
        let description = match i {
            6 => "Stack pointer (implied for JSR)",
            7 => "Program counter",
            _ => "General-purpose register",
        };
        bank.add(Register::new(&name, 16, (i as u64) * 2));
    }

    // Register aliases
    bank.add(Register::sub_register("SP", 16, 6 * 2, "R6", 0)); // Stack pointer
    bank.add(Register::sub_register("PC", 16, 7 * 2, "R7", 0)); // Program counter

    // ---- Status flags (4-bit status register) ----
    bank.add(Register::new("FLAGS", 16, 0x0010));  // Full flags register (16-bit container)
    bank.add(Register::sub_register("S", 1, 0x0010, "FLAGS", 0));  // Sign flag (bit 0)
    bank.add(Register::sub_register("Z", 1, 0x0010, "FLAGS", 1));  // Zero flag (bit 1)
    bank.add(Register::sub_register("OV", 1, 0x0010, "FLAGS", 2)); // Overflow flag (bit 2)
    bank.add(Register::sub_register("C", 1, 0x0010, "FLAGS", 3));  // Carry flag (bit 3)
    // Convenience aliases
    bank.add(Register::sub_register("SIGN", 1, 0x0010, "FLAGS", 0));
    bank.add(Register::sub_register("ZERO", 1, 0x0010, "FLAGS", 1));
    bank.add(Register::sub_register("OVER", 1, 0x0010, "FLAGS", 2));
    bank.add(Register::sub_register("CARRY", 1, 0x0010, "FLAGS", 3));

    // ---- Interrupt enable flag ----
    bank.add(Register::new("INTEN", 1, 0x0018)); // Interrupt enable (EIS flag)

    bank
}

/// Build the CP1600 instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Move / Transfer ===
        InstructionMnemonic::new("MVO"),      // Move out (Rx -> memory)
        InstructionMnemonic::new("MVI"),      // Move in (memory -> Rx)
        InstructionMnemonic::new("MVOI"),     // Move out immediate
        InstructionMnemonic::new("MVII"),     // Move in immediate
        // Register moves
        InstructionMnemonic::new("MOVR"),     // Move register to register
        InstructionMnemonic::new("MOVR_pc"),  // Move register to register (PC variant)
        // Swap
        InstructionMnemonic::new("SWAP"),     // Swap bytes in register (exchange high/low)
        // === Arithmetic ===
        InstructionMnemonic::new("ADD"),      // Add memory to register
        InstructionMnemonic::new("ADDI"),     // Add immediate to register
        InstructionMnemonic::new("ADDR"),     // Add register to register
        InstructionMnemonic::new("ADCR"),     // Add with carry (register)
        InstructionMnemonic::new("SUB"),      // Subtract memory from register
        InstructionMnemonic::new("SUBI"),     // Subtract immediate from register
        InstructionMnemonic::new("SUBR"),     // Subtract register from register
        InstructionMnemonic::new("INCR"),     // Increment register
        InstructionMnemonic::new("DECR"),     // Decrement register
        InstructionMnemonic::new("NEGR"),     // Negate register (2's complement)
        // === Logical ===
        InstructionMnemonic::new("AND"),      // Bitwise AND memory with register
        InstructionMnemonic::new("ANDI"),     // Bitwise AND immediate with register
        InstructionMnemonic::new("ANDR"),     // Bitwise AND registers
        InstructionMnemonic::new("XOR"),      // Bitwise XOR memory with register
        InstructionMnemonic::new("XORI"),     // Bitwise XOR immediate with register
        InstructionMnemonic::new("XORR"),     // Bitwise XOR registers
        InstructionMnemonic::new("COM"),      // Complement register (1's complement)
        // === Compare ===
        InstructionMnemonic::new("CMP"),      // Compare memory to register
        InstructionMnemonic::new("CMPI"),     // Compare immediate to register
        InstructionMnemonic::new("CMPR"),     // Compare register to register
        InstructionMnemonic::new("TSTR"),     // Test register (AND with itself, set flags)
        // === Shift / Rotate ===
        InstructionMnemonic::new("SLL"),      // Shift left logical (1 pos; 2 if repeated)
        InstructionMnemonic::new("SLR"),      // Shift right logical
        InstructionMnemonic::new("SAR"),      // Shift right arithmetic
        InstructionMnemonic::new("SLLC"),     // Shift left logical, through carry
        InstructionMnemonic::new("SLRC"),     // Shift right logical, through carry
        InstructionMnemonic::new("SARC"),     // Shift right arithmetic, through carry
        InstructionMnemonic::new("RLC"),      // Rotate left through carry
        InstructionMnemonic::new("RRC"),      // Rotate right through carry
        // Shift multiple (SDBD prefix allows double shifts)
        InstructionMnemonic::new("SDBD"),     // Double shift prefix
        InstructionMnemonic::new("SLL_2"),    // Shift left logical x2
        InstructionMnemonic::new("SLR_2"),    // Shift right logical x2
        InstructionMnemonic::new("SAR_2"),    // Shift right arithmetic x2
        InstructionMnemonic::new("SLLC_2"),   // Shift left logical through carry x2
        InstructionMnemonic::new("SLRC_2"),   // Shift right logical through carry x2
        InstructionMnemonic::new("SARC_2"),   // Shift right arithmetic through carry x2
        // === Branch / Jump ===
        InstructionMnemonic::new("B"),        // Branch unconditional (-1024 to +1023)
        InstructionMnemonic::new("BNC"),      // Branch if no carry (C=0)
        InstructionMnemonic::new("BC"),       // Branch if carry (C=1)
        InstructionMnemonic::new("BOV"),      // Branch if overflow (OV=1)
        InstructionMnemonic::new("BNOV"),     // Branch if no overflow (OV=0)
        InstructionMnemonic::new("BPL"),      // Branch if plus (S=0)
        InstructionMnemonic::new("BMI"),      // Branch if minus (S=1)
        InstructionMnemonic::new("BEQ"),      // Branch if equal / zero (Z=1)
        InstructionMnemonic::new("BNEQ"),     // Branch if not equal / not zero (Z=0)
        InstructionMnemonic::new("BLE"),      // Branch if less or equal (signed)
        InstructionMnemonic::new("BGT"),      // Branch if greater than (signed)
        InstructionMnemonic::new("BLT"),      // Branch if less than (signed)
        InstructionMnemonic::new("BGE"),      // Branch if greater or equal (signed)
        InstructionMnemonic::new("BLEU"),     // Branch if lower or same (unsigned)
        InstructionMnemonic::new("BGTU"),     // Branch if greater than (unsigned)
        InstructionMnemonic::new("BNE"),      // Branch if not equal
        InstructionMnemonic::new("BZE"),      // Branch if zero
        InstructionMnemonic::new("BNZE"),     // Branch if not zero
        // Indirect branch through register
        InstructionMnemonic::new("JR"),       // Jump to address in register (PC = Rx)
        InstructionMnemonic::new("JD"),       // Jump and disable interrupts
        InstructionMnemonic::new("JE"),       // Jump and enable interrupts
        // === Subroutine ===
        InstructionMnemonic::new("JSR"),      // Jump to subroutine (R7->R6, PC=R5, PC+=5)
        InstructionMnemonic::new("JSR_pc"),   // JSR with PC variant
        InstructionMnemonic::new("Rtn"),      // Return from subroutine (pseudo: MOVR PC,R7)
        // === Stack ===
        InstructionMnemonic::new("PSHR"),     // Push register onto stack
        InstructionMnemonic::new("PULR"),     // Pull register from stack
        // === Address / external ===
        InstructionMnemonic::new("MVO@"),     // Move out indirect (through register)
        InstructionMnemonic::new("MVI@"),     // Move in indirect (through register)
        InstructionMnemonic::new("ADD@"),     // Add indirect
        InstructionMnemonic::new("SUB@"),     // Subtract indirect
        InstructionMnemonic::new("CMP@"),     // Compare indirect
        InstructionMnemonic::new("AND@"),     // AND indirect
        // === Interrupt / system ===
        InstructionMnemonic::new("EIS"),      // Enable interrupt system
        InstructionMnemonic::new("DIS"),      // Disable interrupt system
        InstructionMnemonic::new("TCI"),      // Transfer control to interrupt (pseudo)
        InstructionMnemonic::new("HLT"),      // Halt (invalid opcode / debug stop)
        // === Set/Clear flags ===
        InstructionMnemonic::new("SETC"),     // Set carry flag
        InstructionMnemonic::new("CLRC"),     // Clear carry flag
        // === NOP ===
        InstructionMnemonic::new("NOP"),      // No operation
        // === Wait ===
        InstructionMnemonic::new("SIN"),      // Single input (external device)
        // === No-op extended operations ===
        InstructionMnemonic::new("NOPP"),     // NOP with parameter (two-word NOP)
    ]
}

impl ProcessorModule for Cp1600Processor {
    fn name() -> &'static str {
        "General Instrument CP1600"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "cp1600:LE:16:default",
                "CP1600 / CP1610 (16-bit, little-endian)",
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
    fn test_cp1600_name() {
        assert_eq!(Cp1600Processor::name(), "General Instrument CP1600");
    }

    #[test]
    fn test_cp1600_registers() {
        let bank = Cp1600Processor::registers();
        assert!(bank.len() >= 8, "Expected registers, got {}", bank.len());
        // GPRs
        for i in 0..8u32 {
            assert!(bank.get(&format!("R{}", i)).is_some());
        }
        // Aliases
        assert!(bank.get("SP").is_some());
        assert!(bank.get("PC").is_some());
        // Flags
        assert!(bank.get("FLAGS").is_some());
        assert!(bank.get("S").is_some());
        assert!(bank.get("Z").is_some());
        assert!(bank.get("OV").is_some());
        assert!(bank.get("C").is_some());
        assert!(bank.get("SIGN").is_some());
        assert!(bank.get("ZERO").is_some());
        assert!(bank.get("OVER").is_some());
        assert!(bank.get("CARRY").is_some());
        assert!(bank.get("INTEN").is_some());
    }

    #[test]
    fn test_cp1600_aliases() {
        let bank = Cp1600Processor::registers();
        assert_eq!(bank.get("SP").unwrap().parent.as_deref(), Some("R6"));
        assert_eq!(bank.get("PC").unwrap().parent.as_deref(), Some("R7"));
        assert_eq!(bank.get("S").unwrap().parent.as_deref(), Some("FLAGS"));
        assert_eq!(bank.get("C").unwrap().parent.as_deref(), Some("FLAGS"));
    }

    #[test]
    fn test_cp1600_register_bits() {
        let bank = Cp1600Processor::registers();
        for i in 0..8u32 {
            assert_eq!(bank.get(&format!("R{}", i)).unwrap().bit_size, 16);
        }
        assert_eq!(bank.get("FLAGS").unwrap().bit_size, 16);
        assert_eq!(bank.get("S").unwrap().bit_size, 1);
        assert_eq!(bank.get("INTEN").unwrap().bit_size, 1);
    }

    #[test]
    fn test_cp1600_languages() {
        let langs = Cp1600Processor::languages();
        assert_eq!(langs.len(), 1);
        assert_eq!(langs[0].id, "cp1600:LE:16:default");
        assert_eq!(langs[0].endian, Endian::Little);
        assert_eq!(langs[0].pointer_size, 16);
    }

    #[test]
    fn test_cp1600_instructions() {
        let insts = Cp1600Processor::instructions();
        assert!(insts.len() > 30);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"MVO"));
        assert!(texts.contains(&"MVI"));
        assert!(texts.contains(&"ADD"));
        assert!(texts.contains(&"SUB"));
        assert!(texts.contains(&"ADDR"));
        assert!(texts.contains(&"CMP"));
        assert!(texts.contains(&"CMPR"));
        assert!(texts.contains(&"AND"));
        assert!(texts.contains(&"XOR"));
        assert!(texts.contains(&"SLL"));
        assert!(texts.contains(&"SAR"));
        assert!(texts.contains(&"RLC"));
        assert!(texts.contains(&"B"));
        assert!(texts.contains(&"BEQ"));
        assert!(texts.contains(&"BNE"));
        assert!(texts.contains(&"JSR"));
        assert!(texts.contains(&"PSHR"));
        assert!(texts.contains(&"PULR"));
        assert!(texts.contains(&"EIS"));
        assert!(texts.contains(&"DIS"));
        assert!(texts.contains(&"NOP"));
    }
}
