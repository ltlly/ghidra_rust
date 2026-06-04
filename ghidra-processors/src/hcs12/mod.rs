//! Freescale HCS12 / MC9S12 Processor Module
//!
//! Supports the HCS12 and MC9S12 16-bit microcontroller families from
//! Freescale Semiconductor (formerly Motorola).
//!
//! ## Architecture overview
//! - 8-bit accumulator A and B, combined as 16-bit D register (A:B)
//! - 16-bit index registers X and Y
//! - 16-bit stack pointer (SP)
//! - 16-bit program counter (PC)
//! - 8-bit condition code register (CCR): S, X, H, I, N, Z, V, C
//! - Memory paging support for extended addressing (PPAGE, RPAGE, EPAGE, GPAGE)
//!
//! ## Register space layout
//! - Accumulators (A, B, D):  0x0000 - 0x0003  (A: 8-bit, B: 8-bit, D: 16-bit)
//! - Index (X, Y):            0x0010 - 0x0014  (16-bit each)
//! - Control (SP, PC, CCR):   0x0020 - 0x0028  (16/16/8-bit)
//! - Paging:                  0x0030 - 0x003F  (PPAGE, RPAGE, EPAGE, GPAGE)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Freescale HCS12 processor struct.
pub struct Hcs12Processor;

/// Build the complete HCS12 register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- Accumulators ----
    bank.add(Register::new("A", 8, 0x0000));    // 8-bit accumulator A
    bank.add(Register::new("B", 8, 0x0001));    // 8-bit accumulator B
    bank.add(Register::new("D", 16, 0x0002));   // 16-bit accumulator D = A:B
    // D is the concatenation of A (high) and B (low)
    bank.add(Register::sub_register("D_H", 8, 0x0002, "D", 8));   // High byte of D (= A)
    bank.add(Register::sub_register("D_L", 8, 0x0002, "D", 0));   // Low byte of D (= B)

    // ---- Index registers ----
    bank.add(Register::new("X", 16, 0x0010));     // Index register X (16-bit)
    bank.add(Register::new("Y", 16, 0x0012));     // Index register Y (16-bit)

    // ---- Stack pointer ----
    bank.add(Register::new("SP", 16, 0x0020));    // Stack pointer (16-bit)

    // ---- Program counter ----
    bank.add(Register::new("PC", 16, 0x0024));    // Program counter (16-bit)

    // ---- Condition Code Register (CCR) bits ----
    bank.add(Register::new("CCR", 8, 0x0028));    // Condition code register (full)
    // Individual CCR bits
    bank.add(Register::sub_register("C", 1, 0x0028, "CCR", 0));   // Carry / Borrow
    bank.add(Register::sub_register("V", 1, 0x0028, "CCR", 1));   // Overflow (2's complement)
    bank.add(Register::sub_register("Z", 1, 0x0028, "CCR", 2));   // Zero
    bank.add(Register::sub_register("N", 1, 0x0028, "CCR", 3));   // Negative (sign)
    bank.add(Register::sub_register("I", 1, 0x0028, "CCR", 4));   // IRQ interrupt mask
    bank.add(Register::sub_register("H", 1, 0x0028, "CCR", 5));   // Half-carry (BCD)
    bank.add(Register::sub_register("XIRQ", 1, 0x0028, "CCR", 6)); // XIRQ interrupt mask
    bank.add(Register::sub_register("S", 1, 0x0028, "CCR", 7));   // Stop disable

    // ---- Memory paging registers (for extended addressing) ----
    bank.add(Register::new("PPAGE", 8, 0x0030));  // Program page register (for CALL/RTC)
    bank.add(Register::new("RPAGE", 8, 0x0031));  // RAM page register
    bank.add(Register::new("EPAGE", 8, 0x0032));  // EEPROM page register
    bank.add(Register::new("GPAGE", 8, 0x0033));  // Global page register (for g-ldaa etc.)

    // ---- Debug / Background Debug Mode (BDM) registers ----
    bank.add(Register::new("BDMCCR", 8, 0x0040));   // BDM CCR mirror
    bank.add(Register::new("BDM_STATUS", 8, 0x0041));// BDM status register
    bank.add(Register::new("BDMINR", 8, 0x0042));    // BDM CCR holding register

    // ---- HCS12X / XGATE registers (optional) ----
    bank.add(Register::new("XGATE_PC", 16, 0x0100)); // XGATE program counter
    bank.add(Register::new("XGATE_R1", 16, 0x0102)); // XGATE register 1
    bank.add(Register::new("XGATE_R2", 16, 0x0104)); // XGATE register 2
    bank.add(Register::new("XGATE_R3", 16, 0x0106)); // XGATE register 3
    bank.add(Register::new("XGATE_R4", 16, 0x0108)); // XGATE register 4
    bank.add(Register::new("XGATE_R5", 16, 0x010A)); // XGATE register 5
    bank.add(Register::new("XGATE_R6", 16, 0x010C)); // XGATE register 6
    bank.add(Register::new("XGATE_R7", 16, 0x010E)); // XGATE register 7
    bank.add(Register::new("XGATE_CCR", 8, 0x0110)); // XGATE CCR

    // ---- Direct page register (for direct addressing mode) ----
    bank.add(Register::new("DIRECT", 8, 0x0120)); // Direct page base address (high byte)

    bank
}

/// Build the HCS12 instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Data movement ===
        InstructionMnemonic::new("ldaa"),    // Load accumulator A
        InstructionMnemonic::new("ldab"),    // Load accumulator B
        InstructionMnemonic::new("ldd"),     // Load double accumulator D
        InstructionMnemonic::new("lds"),     // Load stack pointer
        InstructionMnemonic::new("ldx"),     // Load index register X
        InstructionMnemonic::new("ldy"),     // Load index register Y
        InstructionMnemonic::new("staa"),    // Store accumulator A
        InstructionMnemonic::new("stab"),    // Store accumulator B
        InstructionMnemonic::new("std"),     // Store double accumulator D
        InstructionMnemonic::new("sts"),     // Store stack pointer
        InstructionMnemonic::new("stx"),     // Store index register X
        InstructionMnemonic::new("sty"),     // Store index register Y
        InstructionMnemonic::new("tfr"),     // Transfer register to register
        InstructionMnemonic::new("exg"),     // Exchange register with register
        InstructionMnemonic::new("movb"),    // Move byte (memory to memory)
        InstructionMnemonic::new("movw"),    // Move word (memory to memory)
        InstructionMnemonic::new("tab"),     // Transfer A to B
        InstructionMnemonic::new("tba"),     // Transfer B to A
        InstructionMnemonic::new("tpa"),     // Transfer CCR to A
        InstructionMnemonic::new("tap"),     // Transfer A to CCR
        InstructionMnemonic::new("tsx"),     // Transfer SP to X
        InstructionMnemonic::new("tsxf"),    // Transfer SP+offset to X (HCS12X)
        InstructionMnemonic::new("tsxy"),    // Transfer SP to X and Y (HCS12X)
        InstructionMnemonic::new("tsxyr"),   // Transfer SP to X and Y restore (HCS12X)
        InstructionMnemonic::new("tsy"),     // Transfer SP to Y
        InstructionMnemonic::new("txs"),     // Transfer X to SP
        InstructionMnemonic::new("txys"),    // Transfer X and Y to SP (HCS12X)
        InstructionMnemonic::new("tys"),     // Transfer Y to SP
        InstructionMnemonic::new("xgdx"),    // Exchange D with X
        InstructionMnemonic::new("xgdy"),    // Exchange D with Y
        InstructionMnemonic::new("leas"),    // Load effective address into SP
        InstructionMnemonic::new("leax"),    // Load effective address into X
        InstructionMnemonic::new("leay"),    // Load effective address into Y
        InstructionMnemonic::new("clra"),    // Clear accumulator A
        InstructionMnemonic::new("clrb"),    // Clear accumulator B
        InstructionMnemonic::new("clr"),     // Clear memory
        // === Stack operations ===
        InstructionMnemonic::new("psha"),    // Push A onto stack
        InstructionMnemonic::new("pshb"),    // Push B onto stack
        InstructionMnemonic::new("pshc"),    // Push CCR onto stack
        InstructionMnemonic::new("pshd"),    // Push D onto stack
        InstructionMnemonic::new("pshx"),    // Push X onto stack
        InstructionMnemonic::new("pshy"),    // Push Y onto stack
        InstructionMnemonic::new("pula"),    // Pull A from stack
        InstructionMnemonic::new("pulb"),    // Pull B from stack
        InstructionMnemonic::new("pulc"),    // Pull CCR from stack
        InstructionMnemonic::new("puld"),    // Pull D from stack
        InstructionMnemonic::new("pulx"),    // Pull X from stack
        InstructionMnemonic::new("puly"),    // Pull Y from stack
        // === Arithmetic ===
        InstructionMnemonic::new("adda"),    // Add to A
        InstructionMnemonic::new("addb"),    // Add to B
        InstructionMnemonic::new("addd"),    // Add to D
        InstructionMnemonic::new("adca"),    // Add with carry to A (includes C flag)
        InstructionMnemonic::new("adcb"),    // Add with carry to B
        InstructionMnemonic::new("suba"),    // Subtract from A
        InstructionMnemonic::new("subb"),    // Subtract from B
        InstructionMnemonic::new("subd"),    // Subtract from D
        InstructionMnemonic::new("sbca"),    // Subtract with carry from A
        InstructionMnemonic::new("sbcb"),    // Subtract with carry from B
        InstructionMnemonic::new("mul"),     // Multiply (unsigned 8x8 -> 16 in D)
        InstructionMnemonic::new("emul"),    // Extended multiply (unsigned 16x16 -> 32)
        InstructionMnemonic::new("emuls"),   // Extended multiply signed (16x16 -> 32)
        InstructionMnemonic::new("idiv"),    // Integer divide (unsigned 16/16 -> 16)
        InstructionMnemonic::new("idivs"),   // Integer divide signed (16/16 -> 16)
        InstructionMnemonic::new("ediv"),    // Extended divide (unsigned 32/16 -> 16)
        InstructionMnemonic::new("edivs"),   // Extended divide signed (32/16 -> 16)
        InstructionMnemonic::new("fdiv"),    // Fractional divide (unsigned 16/16 -> 16)
        InstructionMnemonic::new("inc"),     // Increment memory
        InstructionMnemonic::new("inca"),    // Increment A
        InstructionMnemonic::new("incb"),    // Increment B
        InstructionMnemonic::new("ins"),     // Increment SP
        InstructionMnemonic::new("inx"),     // Increment X
        InstructionMnemonic::new("iny"),     // Increment Y
        InstructionMnemonic::new("dec"),     // Decrement memory
        InstructionMnemonic::new("deca"),    // Decrement A
        InstructionMnemonic::new("decb"),    // Decrement B
        InstructionMnemonic::new("des"),     // Decrement SP
        InstructionMnemonic::new("dex"),     // Decrement X
        InstructionMnemonic::new("dey"),     // Decrement Y
        InstructionMnemonic::new("aba"),     // Add B to A
        InstructionMnemonic::new("abx"),     // Add B to X
        InstructionMnemonic::new("aby"),     // Add B to Y
        InstructionMnemonic::new("sba"),     // Subtract B from A
        InstructionMnemonic::new("neg"),     // Negate memory (2's complement)
        InstructionMnemonic::new("nega"),    // Negate A (2's complement)
        InstructionMnemonic::new("negb"),    // Negate B (2's complement)
        InstructionMnemonic::new("com"),     // Complement memory (1's complement)
        InstructionMnemonic::new("coma"),    // Complement A
        InstructionMnemonic::new("comb"),    // Complement B
        // === BCD arithmetic ===
        InstructionMnemonic::new("daa"),     // Decimal adjust A (after add)
        // === Compare / Test ===
        InstructionMnemonic::new("cmpa"),    // Compare A
        InstructionMnemonic::new("cmpb"),    // Compare B
        InstructionMnemonic::new("cpd"),     // Compare D
        InstructionMnemonic::new("cpx"),     // Compare X
        InstructionMnemonic::new("cpy"),     // Compare Y
        InstructionMnemonic::new("cps"),     // Compare SP
        InstructionMnemonic::new("cba"),     // Compare B to A
        InstructionMnemonic::new("tst"),     // Test memory (same as compare to zero)
        InstructionMnemonic::new("tsta"),    // Test A
        InstructionMnemonic::new("tstb"),    // Test B
        // === Logical ===
        InstructionMnemonic::new("anda"),    // Bitwise AND A
        InstructionMnemonic::new("andb"),    // Bitwise AND B
        InstructionMnemonic::new("andcc"),   // AND CCR (clear mask bits)
        InstructionMnemonic::new("oraa"),    // Bitwise OR A
        InstructionMnemonic::new("orab"),    // Bitwise OR B
        InstructionMnemonic::new("orcc"),    // OR CCR (set mask bits)
        InstructionMnemonic::new("eora"),    // Bitwise XOR A
        InstructionMnemonic::new("eorb"),    // Bitwise XOR B
        // === Bit manipulation ===
        InstructionMnemonic::new("bclr"),    // Clear bit(s) in memory
        InstructionMnemonic::new("bset"),    // Set bit(s) in memory
        InstructionMnemonic::new("bita"),    // Bit test A
        InstructionMnemonic::new("bitb"),    // Bit test B
        InstructionMnemonic::new("brclr"),   // Branch if bit(s) clear
        InstructionMnemonic::new("brset"),   // Branch if bit(s) set
        // === Shift / Rotate ===
        InstructionMnemonic::new("lsla"),    // Logical shift left A
        InstructionMnemonic::new("lslb"),    // Logical shift left B
        InstructionMnemonic::new("lsl"),     // Logical shift left memory
        InstructionMnemonic::new("lsld"),    // Logical shift left D
        InstructionMnemonic::new("lsra"),    // Logical shift right A
        InstructionMnemonic::new("lsrb"),    // Logical shift right B
        InstructionMnemonic::new("lsr"),     // Logical shift right memory
        InstructionMnemonic::new("lsrd"),    // Logical shift right D
        InstructionMnemonic::new("asla"),    // Arithmetic shift left A (= LSLA)
        InstructionMnemonic::new("aslb"),    // Arithmetic shift left B (= LSLB)
        InstructionMnemonic::new("asl"),     // Arithmetic shift left memory (= LSL)
        InstructionMnemonic::new("asld"),    // Arithmetic shift left D
        InstructionMnemonic::new("asra"),    // Arithmetic shift right A
        InstructionMnemonic::new("asrb"),    // Arithmetic shift right B
        InstructionMnemonic::new("asr"),     // Arithmetic shift right memory
        InstructionMnemonic::new("rola"),    // Rotate left A through carry
        InstructionMnemonic::new("rolb"),    // Rotate left B through carry
        InstructionMnemonic::new("rol"),     // Rotate left memory through carry
        InstructionMnemonic::new("rora"),    // Rotate right A through carry
        InstructionMnemonic::new("rorb"),    // Rotate right B through carry
        InstructionMnemonic::new("ror"),     // Rotate right memory through carry
        // === Branch / Jump ===
        InstructionMnemonic::new("bra"),     // Branch always (relative)
        InstructionMnemonic::new("brn"),     // Branch never
        InstructionMnemonic::new("beq"),     // Branch if equal (Z=1)
        InstructionMnemonic::new("bne"),     // Branch if not equal (Z=0)
        InstructionMnemonic::new("bcc"),     // Branch if carry clear (C=0) / BHS
        InstructionMnemonic::new("bcs"),     // Branch if carry set (C=1) / BLO
        InstructionMnemonic::new("bmi"),     // Branch if minus (N=1)
        InstructionMnemonic::new("bpl"),     // Branch if plus (N=0)
        InstructionMnemonic::new("bvs"),     // Branch if overflow set (V=1)
        InstructionMnemonic::new("bvc"),     // Branch if overflow clear (V=0)
        InstructionMnemonic::new("bhi"),     // Branch if higher (C=0 and Z=0, unsigned)
        InstructionMnemonic::new("bhs"),     // Branch if higher or same (C=0, unsigned)
        InstructionMnemonic::new("blo"),     // Branch if lower (C=1, unsigned)
        InstructionMnemonic::new("bls"),     // Branch if lower or same (C=1 or Z=1)
        InstructionMnemonic::new("bgt"),     // Branch if greater than (signed)
        InstructionMnemonic::new("bge"),     // Branch if greater or equal (signed)
        InstructionMnemonic::new("ble"),     // Branch if less or equal (signed)
        InstructionMnemonic::new("blt"),     // Branch if less than (signed)
        InstructionMnemonic::new("dbeq"),    // Decrement and branch if equal (DBNE loop)
        InstructionMnemonic::new("dbne"),    // Decrement and branch if not equal
        InstructionMnemonic::new("ibeq"),    // Increment and branch if equal
        InstructionMnemonic::new("ibne"),    // Increment and branch if not equal
        InstructionMnemonic::new("tbeq"),    // Test and branch if equal
        InstructionMnemonic::new("tbne"),    // Test and branch if not equal
        InstructionMnemonic::new("jmp"),     // Jump (absolute)
        InstructionMnemonic::new("jsr"),     // Jump to subroutine
        InstructionMnemonic::new("bsr"),     // Branch to subroutine (relative)
        // === Subroutine return ===
        InstructionMnemonic::new("rts"),     // Return from subroutine
        InstructionMnemonic::new("rti"),     // Return from interrupt
        InstructionMnemonic::new("call"),    // Call (paged addressing, for >64K)
        InstructionMnemonic::new("rtc"),     // Return from call (paged return)
        // === Interrupt and special ===
        InstructionMnemonic::new("swi"),     // Software interrupt
        InstructionMnemonic::new("wai"),     // Wait for interrupt
        InstructionMnemonic::new("stop"),    // Stop (low power mode)
        InstructionMnemonic::new("bgnd"),    // Background debug mode entry
        InstructionMnemonic::new("nop"),     // No operation
        // === Extended addressing / paged instructions ===
        InstructionMnemonic::new("gldaa"),   // Global load A (using GPAGE)
        InstructionMnemonic::new("gldab"),   // Global load B
        InstructionMnemonic::new("gldd"),    // Global load D
        InstructionMnemonic::new("gldx"),    // Global load X
        InstructionMnemonic::new("gldy"),    // Global load Y
        InstructionMnemonic::new("gstaa"),   // Global store A
        InstructionMnemonic::new("gstab"),   // Global store B
        InstructionMnemonic::new("gstd"),    // Global store D
        InstructionMnemonic::new("gstx"),    // Global store X
        InstructionMnemonic::new("gsty"),    // Global store Y
        // === Fuzzy logic instructions (HCS12) ===
        InstructionMnemonic::new("mem"),     // Membership evaluation
        InstructionMnemonic::new("rev"),     // Rule evaluation
        InstructionMnemonic::new("revw"),    // Rule evaluation (weighted)
        InstructionMnemonic::new("wav"),     // Weighted average
        // === MAX/MIN instructions (HCS12) ===
        InstructionMnemonic::new("emaxm"),   // Extended max (unsigned 16-bit)
        InstructionMnemonic::new("emaxd"),   // Extended max D
        InstructionMnemonic::new("emaxmd"),  // Extended max in memory
        InstructionMnemonic::new("eminm"),   // Extended min (unsigned 16-bit)
        InstructionMnemonic::new("emind"),   // Extended min D
        InstructionMnemonic::new("eminmd"),  // Extended min in memory
        InstructionMnemonic::new("maxa"),    // Max A (unsigned 8-bit)
        InstructionMnemonic::new("maxm"),    // Max memory
        InstructionMnemonic::new("mina"),    // Min A
        InstructionMnemonic::new("minm"),    // Min memory
        // === Table lookup ===
        InstructionMnemonic::new("tbl"),     // Table lookup and interpolate
        InstructionMnemonic::new("etbl"),    // Extended table lookup and interpolate
    ]
}

impl ProcessorModule for Hcs12Processor {
    fn name() -> &'static str {
        "Freescale HCS12 / MC9S12"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "hcs12:BE:16:default",
                "HC12 / HCS12 / MC9S12 (16-bit, big-endian)",
                "default",
                Endian::Big,
                16,
            ),
            Language::new(
                "hcs12:BE:16:XGATE",
                "HCS12X / MC9S12X with XGATE (16-bit, big-endian)",
                "XGATE",
                Endian::Big,
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
    fn test_hcs12_name() {
        assert_eq!(Hcs12Processor::name(), "Freescale HCS12 / MC9S12");
    }

    #[test]
    fn test_hcs12_registers() {
        let bank = Hcs12Processor::registers();
        assert!(bank.len() > 20, "Expected registers, got {}", bank.len());
        // Core
        assert!(bank.get("A").is_some());
        assert!(bank.get("B").is_some());
        assert!(bank.get("D").is_some());
        assert!(bank.get("X").is_some());
        assert!(bank.get("Y").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("CCR").is_some());
        // CCR bits
        assert!(bank.get("C").is_some());
        assert!(bank.get("V").is_some());
        assert!(bank.get("Z").is_some());
        assert!(bank.get("N").is_some());
        assert!(bank.get("I").is_some());
        assert!(bank.get("H").is_some());
        assert!(bank.get("X").is_some());
        assert!(bank.get("S").is_some());
        // Paging
        assert!(bank.get("PPAGE").is_some());
        assert!(bank.get("RPAGE").is_some());
        assert!(bank.get("EPAGE").is_some());
        assert!(bank.get("GPAGE").is_some());
    }

    #[test]
    fn test_hcs12_register_bits() {
        let bank = Hcs12Processor::registers();
        assert_eq!(bank.get("A").unwrap().bit_size, 8);
        assert_eq!(bank.get("B").unwrap().bit_size, 8);
        assert_eq!(bank.get("D").unwrap().bit_size, 16);
        assert_eq!(bank.get("X").unwrap().bit_size, 16);
        assert_eq!(bank.get("Y").unwrap().bit_size, 16);
        assert_eq!(bank.get("SP").unwrap().bit_size, 16);
        assert_eq!(bank.get("PC").unwrap().bit_size, 16);
        assert_eq!(bank.get("CCR").unwrap().bit_size, 8);
        assert_eq!(bank.get("C").unwrap().bit_size, 1);
    }

    #[test]
    fn test_hcs12_ccr_bits() {
        let bank = Hcs12Processor::registers();
        let c = bank.get("C").unwrap();
        assert_eq!(c.parent.as_deref(), Some("CCR"));
        assert_eq!(c.lsb, 0);

        let v = bank.get("V").unwrap();
        assert_eq!(v.parent.as_deref(), Some("CCR"));
        assert_eq!(v.lsb, 1);

        let z = bank.get("Z").unwrap();
        assert_eq!(z.parent.as_deref(), Some("CCR"));
        assert_eq!(z.lsb, 2);

        let s = bank.get("S").unwrap();
        assert_eq!(s.parent.as_deref(), Some("CCR"));
        assert_eq!(s.lsb, 7);
    }

    #[test]
    fn test_hcs12_languages() {
        let langs = Hcs12Processor::languages();
        assert!(langs.len() >= 1);
        assert!(langs.iter().any(|l| l.id == "hcs12:BE:16:default"));
        assert!(langs.iter().all(|l| l.endian == Endian::Big));
    }

    #[test]
    fn test_hcs12_instructions() {
        let insts = Hcs12Processor::instructions();
        assert!(insts.len() > 60);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"ldaa"));
        assert!(texts.contains(&"ldd"));
        assert!(texts.contains(&"staa"));
        assert!(texts.contains(&"adda"));
        assert!(texts.contains(&"suba"));
        assert!(texts.contains(&"mul"));
        assert!(texts.contains(&"idiv"));
        assert!(texts.contains(&"psha"));
        assert!(texts.contains(&"pula"));
        assert!(texts.contains(&"bra"));
        assert!(texts.contains(&"beq"));
        assert!(texts.contains(&"bne"));
        assert!(texts.contains(&"bcc"));
        assert!(texts.contains(&"bcs"));
        assert!(texts.contains(&"jmp"));
        assert!(texts.contains(&"jsr"));
        assert!(texts.contains(&"rts"));
        assert!(texts.contains(&"rti"));
        assert!(texts.contains(&"swi"));
        assert!(texts.contains(&"bclr"));
        assert!(texts.contains(&"bset"));
        assert!(texts.contains(&"call"));
        assert!(texts.contains(&"nop"));
    }
}
