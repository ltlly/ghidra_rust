//! Zilog Z80 + Game Boy LR35902 Processor Module
//!
//! Supports the Zilog Z80 and the Sharp LR35902 (Game Boy CPU, Z80-derived).
//!
//! The Z80 is an 8-bit CISC microprocessor introduced in 1976 as a binary-
//! compatible extension of the Intel 8080. It was used in the ZX Spectrum,
//! TRS-80, MSX, CP/M machines, Game Boy (modified), TI calculators, and
//! countless embedded systems. The LR35902 is a member of the Z80 family
//! with Game Boy-specific modifications.
//!
//! ## Register space layout
//!
//! ### Main register set
//! - A (Accumulator):              0x0000  (8-bit)
//! - F (Flags):                    0x0001  (8-bit)
//! - B, C:                         0x0002, 0x0003 (8-bit each, or BC pair 16-bit)
//! - D, E:                         0x0004, 0x0005 (8-bit each, or DE pair 16-bit)
//! - H, L:                         0x0006, 0x0007 (8-bit each, or HL pair 16-bit)
//!
//! ### Alternate register set (Z80)
//! - A', F':                       0x0008, 0x0009 (8-bit each)
//! - B', C':                       0x000A, 0x000B (8-bit each)
//! - D', E':                       0x000C, 0x000D (8-bit each)
//! - H', L':                       0x000E, 0x000F (8-bit each)
//!
//! ### Index registers
//! - IX (Index X):                 0x0010  (16-bit, Z80)
//! - IY (Index Y):                 0x0012  (16-bit, Z80)
//! - SP (Stack Pointer):           0x0014  (16-bit)
//! - PC (Program Counter):         0x0016  (16-bit)
//! - IXH, IXL (IX halves):        0x0010, 0x0011 (8-bit each, undocumented/HD64180)
//! - IYH, IYL (IY halves):        0x0012, 0x0013 (8-bit each, undocumented/HD64180)
//!
//! ### Special registers
//! - I (Interrupt Vector):         0x0018  (8-bit, Z80)
//! - R (Refresh counter):          0x0019  (8-bit, Z80, 8-bit wrap-around)
//!
//! ### Shadow/internal only
//! - WZ (Internal temp register):  0x001A  (16-bit)
//! - IM (Interrupt Mode):          0x001C  (2-bit, Z80)
//! - IFF1 (Interrupt Flip-Flop):   0x001D  (1-bit, Z80)
//! - IFF2 (IFF save):              0x001E  (1-bit, Z80)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Z80 processor struct.
pub struct Z80Processor;

/// Build the complete Z80 register bank (includes Game Boy LR35902).
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- Main register set (8-bit) ----
    bank.add(Register::new("A", 8, 0x0000)); // Accumulator
    bank.add(Register::new("F", 8, 0x0001)); // Flags

    // Flag bit fields
    bank.add(Register::sub_register("S", 1, 0x0001, "F", 7)); // Sign Flag
    bank.add(Register::sub_register("Z", 1, 0x0001, "F", 6)); // Zero Flag
    bank.add(Register::sub_register("HALF_CARRY", 1, 0x0001, "F", 4)); // Half Carry Flag
    bank.add(Register::sub_register("P_V", 1, 0x0001, "F", 2)); // Parity/Overflow Flag
    bank.add(Register::sub_register("N", 1, 0x0001, "F", 1)); // Add/Subtract Flag
    bank.add(Register::sub_register("C", 1, 0x0001, "F", 0)); // Carry Flag
    // Undocumented flag bits
    bank.add(Register::sub_register("F5", 1, 0x0001, "F", 5)); // Undocumented bit 5
    bank.add(Register::sub_register("F3", 1, 0x0001, "F", 3)); // Undocumented bit 3

    bank.add(Register::new("B", 8, 0x0002));
    bank.add(Register::new("C", 8, 0x0003));
    bank.add(Register::new("D", 8, 0x0004));
    bank.add(Register::new("E", 8, 0x0005));
    bank.add(Register::new("H", 8, 0x0006));
    bank.add(Register::new("L", 8, 0x0007));

    // 16-bit register pairs (aliases spanning two 8-bit registers)
    bank.add(Register::sub_register("AF", 16, 0x0000, "A", 0)); // AF pair (A high, F low)
    bank.add(Register::sub_register("BC", 16, 0x0002, "B", 0)); // BC pair
    bank.add(Register::sub_register("DE", 16, 0x0004, "D", 0)); // DE pair
    bank.add(Register::sub_register("HL", 16, 0x0006, "H", 0)); // HL pair

    // ---- Alternate register set (Z80 only, not LR35902) ----
    bank.add(Register::new("A_PRIME", 8, 0x0008));
    bank.add(Register::new("F_PRIME", 8, 0x0009));
    bank.add(Register::new("B_PRIME", 8, 0x000A));
    bank.add(Register::new("C_PRIME", 8, 0x000B));
    bank.add(Register::new("D_PRIME", 8, 0x000C));
    bank.add(Register::new("E_PRIME", 8, 0x000D));
    bank.add(Register::new("H_PRIME", 8, 0x000E));
    bank.add(Register::new("L_PRIME", 8, 0x000F));

    // Alternate 16-bit pairs
    bank.add(Register::sub_register("AF_PRIME", 16, 0x0008, "A_PRIME", 0));
    bank.add(Register::sub_register("BC_PRIME", 16, 0x000A, "B_PRIME", 0));
    bank.add(Register::sub_register("DE_PRIME", 16, 0x000C, "D_PRIME", 0));
    bank.add(Register::sub_register("HL_PRIME", 16, 0x000E, "H_PRIME", 0));

    // ---- Index registers (16-bit, Z80) ----
    bank.add(Register::new("IX", 16, 0x0010)); // Index X
    bank.add(Register::sub_register("IXH", 8, 0x0010, "IX", 8)); // IX high byte
    bank.add(Register::sub_register("IXL", 8, 0x0010, "IX", 0)); // IX low byte

    bank.add(Register::new("IY", 16, 0x0012)); // Index Y
    bank.add(Register::sub_register("IYH", 8, 0x0012, "IY", 8)); // IY high byte
    bank.add(Register::sub_register("IYL", 8, 0x0012, "IY", 0)); // IY low byte

    // ---- Stack Pointer and Program Counter (16-bit) ----
    bank.add(Register::new("SP", 16, 0x0014));
    bank.add(Register::new("PC", 16, 0x0016));

    // ---- Special registers ----
    bank.add(Register::new("I", 8, 0x0018)); // Interrupt Vector Register (Z80)
    bank.add(Register::new("R", 8, 0x0019)); // Memory Refresh Register (Z80, 7-bit wraps)

    // ---- Internal / shadow registers ----
    bank.add(Register::new("WZ", 16, 0x001A)); // Internal temporary (W and Z)
    bank.add(Register::new("W", 8, 0x001A)); // W temp (high byte)
    bank.add(Register::sub_register("Z_INT", 8, 0x001A, "WZ", 0)); // Z temp (alias, low byte)

    bank.add(Register::new("IM", 2, 0x001C)); // Interrupt Mode (0, 1, or 2)
    bank.add(Register::new("IFF1", 1, 0x001D)); // Interrupt Flip-Flop 1
    bank.add(Register::new("IFF2", 1, 0x001E)); // Interrupt Flip-Flop 2 (saved during NMI)

    // ---- MEMPTR (internal; Game Boy uses WZ-like temporarily) ----
    bank.add(Register::new("MEMPTR", 16, 0x0020)); // Memory pointer (internal temp)

    // ---- Game Boy LR35902 specific registers ----
    // The LR35902 lacks the alternate register set and IX/IY, but adds:
    // - LCD/PPU mapped registers (not CPU registers per se, addressed in I/O space)
    // - No IM 2 mode (only IM 0 and IM 1)
    // - HALT bug
    // These are typically represented in the memory map, not as CPU registers.

    // Game Boy-specific: Speed control (GBC double-speed mode)
    bank.add(Register::new("KEY1", 8, 0x0030)); // GBC speed switch (bit 7 = current, bit 0 = prepare)
    bank.add(Register::new("VBK", 8, 0x0031)); // GBC VRAM Bank select
    bank.add(Register::new("SVBK", 8, 0x0032)); // GBC WRAM Bank select
    bank.add(Register::new("HDMA1", 8, 0x0034)); // GBC HDMA source high
    bank.add(Register::new("HDMA2", 8, 0x0035)); // GBC HDMA source low
    bank.add(Register::new("HDMA3", 8, 0x0036)); // GBC HDMA dest high
    bank.add(Register::new("HDMA4", 8, 0x0037)); // GBC HDMA dest low
    bank.add(Register::new("HDMA5", 8, 0x0038)); // GBC HDMA length/mode/start

    bank
}

/// Build the Z80 instruction mnemonics (includes Game Boy-specific extensions).
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === 8-bit Load ===
        InstructionMnemonic::new("ld"),
        InstructionMnemonic::new("ld_a_i"),  // LD A, I
        InstructionMnemonic::new("ld_a_r"),  // LD A, R
        InstructionMnemonic::new("ld_i_a"),  // LD I, A
        InstructionMnemonic::new("ld_r_a"),  // LD R, A
        InstructionMnemonic::new("ldi"),     // LoaD and Increment (HL)
        InstructionMnemonic::new("ldd"),     // LoaD and Decrement (HL)
        InstructionMnemonic::new("ldir"),    // LoaD, Increment, Repeat
        InstructionMnemonic::new("lddr"),    // LoaD, Decrement, Repeat
        // === 16-bit Load ===
        InstructionMnemonic::new("ld_bc_nn"),
        InstructionMnemonic::new("ld_de_nn"),
        InstructionMnemonic::new("ld_hl_nn"),
        InstructionMnemonic::new("ld_sp_nn"),
        InstructionMnemonic::new("ld_ix_nn"),
        InstructionMnemonic::new("ld_iy_nn"),
        InstructionMnemonic::new("ld_sp_hl"),
        InstructionMnemonic::new("ld_sp_ix"),
        InstructionMnemonic::new("ld_sp_iy"),
        // === Stack operations ===
        InstructionMnemonic::new("push"),
        InstructionMnemonic::new("pop"),
        InstructionMnemonic::new("push_af"),
        InstructionMnemonic::new("push_bc"),
        InstructionMnemonic::new("push_de"),
        InstructionMnemonic::new("push_hl"),
        InstructionMnemonic::new("push_ix"),
        InstructionMnemonic::new("push_iy"),
        InstructionMnemonic::new("pop_af"),
        InstructionMnemonic::new("pop_bc"),
        InstructionMnemonic::new("pop_de"),
        InstructionMnemonic::new("pop_hl"),
        InstructionMnemonic::new("pop_ix"),
        InstructionMnemonic::new("pop_iy"),
        // === Exchange ===
        InstructionMnemonic::new("ex_de_hl"),   // EX DE, HL
        InstructionMnemonic::new("ex_af_afp"),   // EX AF, AF'
        InstructionMnemonic::new("exx"),         // EX BC,DE,HL with BC',DE',HL'
        InstructionMnemonic::new("ex_sp_hl"),    // EX (SP), HL
        InstructionMnemonic::new("ex_sp_ix"),    // EX (SP), IX
        InstructionMnemonic::new("ex_sp_iy"),    // EX (SP), IY
        // === 8-bit Arithmetic ===
        InstructionMnemonic::new("add_a"),
        InstructionMnemonic::new("adc"),
        InstructionMnemonic::new("sub"),
        InstructionMnemonic::new("sbc"),
        InstructionMnemonic::new("and"),
        InstructionMnemonic::new("or"),
        InstructionMnemonic::new("xor"),
        InstructionMnemonic::new("cp"),          // ComPare
        InstructionMnemonic::new("inc"),
        InstructionMnemonic::new("dec"),
        // === 16-bit Arithmetic ===
        InstructionMnemonic::new("add_hl"),
        InstructionMnemonic::new("adc_hl"),
        InstructionMnemonic::new("sbc_hl"),
        InstructionMnemonic::new("add_ix"),
        InstructionMnemonic::new("add_iy"),
        // === General-purpose Arithmetic and Control ===
        InstructionMnemonic::new("daa"),  // Decimal Adjust Accumulator
        InstructionMnemonic::new("cpl"),  // ComPLement accumulator
        InstructionMnemonic::new("neg"),  // NEGate accumulator (2's complement)
        InstructionMnemonic::new("ccf"),  // Complement Carry Flag
        InstructionMnemonic::new("scf"),  // Set Carry Flag
        InstructionMnemonic::new("nop"),  // No OPeration
        InstructionMnemonic::new("halt"), // HALT (wait for interrupt)
        InstructionMnemonic::new("stop"), // STOP (Game Boy: low-power, Z80: similar)
        InstructionMnemonic::new("di"),   // Disable Interrupts
        InstructionMnemonic::new("ei"),   // Enable Interrupts
        InstructionMnemonic::new("im"),   // Interrupt Mode (Z80: IM 0/1/2)
        // === Rotate and Shift ===
        InstructionMnemonic::new("rlca"),  // Rotate Left Circular A
        InstructionMnemonic::new("rla"),   // Rotate Left through carry A
        InstructionMnemonic::new("rrca"),  // Rotate Right Circular A
        InstructionMnemonic::new("rra"),   // Rotate Right through carry A
        InstructionMnemonic::new("rlc"),   // Rotate Left Circular (any reg)
        InstructionMnemonic::new("rl"),    // Rotate Left through carry
        InstructionMnemonic::new("rrc"),   // Rotate Right Circular
        InstructionMnemonic::new("rr"),    // Rotate Right through carry
        InstructionMnemonic::new("sla"),   // Shift Left Arithmetic
        InstructionMnemonic::new("sra"),   // Shift Right Arithmetic
        InstructionMnemonic::new("sll"),   // Shift Left Logical (undocumented)
        InstructionMnemonic::new("srl"),   // Shift Right Logical
        InstructionMnemonic::new("rld"),   // Rotate Left Digit (BCD, A with (HL))
        InstructionMnemonic::new("rrd"),   // Rotate Right Digit (BCD, A with (HL))
        // === Bit Operations ===
        InstructionMnemonic::new("bit"),   // BIT test
        InstructionMnemonic::new("set"),   // SET bit
        InstructionMnemonic::new("res"),   // RESet bit
        // === Jump ===
        InstructionMnemonic::new("jp"),
        InstructionMnemonic::new("jp_c"),
        InstructionMnemonic::new("jp_nc"),
        InstructionMnemonic::new("jp_z"),
        InstructionMnemonic::new("jp_nz"),
        InstructionMnemonic::new("jp_pe"), // Jump if Parity Even
        InstructionMnemonic::new("jp_po"), // Jump if Parity Odd
        InstructionMnemonic::new("jp_p"),  // Jump if Plus (sign positive)
        InstructionMnemonic::new("jp_m"),  // Jump if Minus (sign negative)
        InstructionMnemonic::new("jp_hl"), // JP (HL)
        InstructionMnemonic::new("jp_ix"), // JP (IX)
        InstructionMnemonic::new("jp_iy"), // JP (IY)
        InstructionMnemonic::new("jr"),    // Relative Jump (unconditional)
        InstructionMnemonic::new("jr_c"),  // Relative Jump if Carry
        InstructionMnemonic::new("jr_nc"), // Relative Jump if No Carry
        InstructionMnemonic::new("jr_z"),  // Relative Jump if Zero
        InstructionMnemonic::new("jr_nz"), // Relative Jump if Not Zero
        InstructionMnemonic::new("djnz"),  // Decrement B and Jump if Non Zero
        // === Call / Return ===
        InstructionMnemonic::new("call"),
        InstructionMnemonic::new("call_c"),
        InstructionMnemonic::new("call_nc"),
        InstructionMnemonic::new("call_z"),
        InstructionMnemonic::new("call_nz"),
        InstructionMnemonic::new("call_pe"),
        InstructionMnemonic::new("call_po"),
        InstructionMnemonic::new("call_p"),
        InstructionMnemonic::new("call_m"),
        InstructionMnemonic::new("ret"),
        InstructionMnemonic::new("ret_c"),
        InstructionMnemonic::new("ret_nc"),
        InstructionMnemonic::new("ret_z"),
        InstructionMnemonic::new("ret_nz"),
        InstructionMnemonic::new("ret_pe"),
        InstructionMnemonic::new("ret_po"),
        InstructionMnemonic::new("ret_p"),
        InstructionMnemonic::new("ret_m"),
        InstructionMnemonic::new("reti"), // RETurn from Interrupt
        InstructionMnemonic::new("retn"), // RETurn from Nmi
        InstructionMnemonic::new("rst"),  // ReSTart (8 fixed vectors)
        // === I/O ===
        InstructionMnemonic::new("in"),
        InstructionMnemonic::new("ini"),
        InstructionMnemonic::new("inir"),
        InstructionMnemonic::new("ind"),
        InstructionMnemonic::new("indr"),
        InstructionMnemonic::new("out"),
        InstructionMnemonic::new("outi"),
        InstructionMnemonic::new("otir"), // Z80 mnemonics: OTIR, not OUTIR
        InstructionMnemonic::new("outd"),
        InstructionMnemonic::new("otdr"), // OTDR
        // === Block Transfer and Search ===
        InstructionMnemonic::new("cpi"),  // ComPare and Increment
        InstructionMnemonic::new("cpir"), // ComPare, Increment, Repeat
        InstructionMnemonic::new("cpd"),  // ComPare and Decrement
        InstructionMnemonic::new("cpdr"), // ComPare, Decrement, Repeat
        // === Game Boy (LR35902) specific instructions (not on standard Z80) ===
        InstructionMnemonic::new("ldh_a8_a"),    // LDH ($FF00+n), A
        InstructionMnemonic::new("ldh_a_a8"),    // LDH A, ($FF00+n)
        InstructionMnemonic::new("ldh_c_a"),     // LDH ($FF00+C), A
        InstructionMnemonic::new("ldh_a_c"),     // LDH A, ($FF00+C)
        InstructionMnemonic::new("ld_hl_spd"),   // LD HL, SP+d8 (unsigned offset)
        InstructionMnemonic::new("ld_sp_hl_gb"), // LD SP, HL (Game Boy specific encoding)
        InstructionMnemonic::new("add_sp_d"),    // ADD SP, d8
        InstructionMnemonic::new("swap"),        // SWAP nibbles (Game Boy / Z180)
        // === Game Boy Color (GBC) specific instructions ===
        // These are GBC/Game Boy only, not Z80:
        // HDMA (General Purpose DMA) is memory-mapped, not a CPU instruction
        // The "STOP speed" instruction toggles GBC double-speed mode
        InstructionMnemonic::new("stop_speed"),  // STOP (GBC: double-speed toggle)
    ]
}

impl ProcessorModule for Z80Processor {
    fn name() -> &'static str {
        "Zilog Z80 / Game Boy LR35902"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "z80:LE:8:default",
                "Zilog Z80 (8-bit, little-endian)",
                "Z80",
                Endian::Little,
                16,
            ),
            Language::new(
                "z80:BE:8:default",
                "Zilog Z80 (8-bit, big-endian, for big-endian Z80 systems)",
                "Z80",
                Endian::Big,
                16,
            ),
            Language::new(
                "gb:LE:8:LR35902",
                "Game Boy / Game Boy Color (Sharp LR35902, Z80-derived)",
                "LR35902",
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
    fn test_z80_name() {
        assert_eq!(Z80Processor::name(), "Zilog Z80 / Game Boy LR35902");
    }

    #[test]
    fn test_z80_registers() {
        let bank = Z80Processor::registers();
        assert!(bank.len() > 40, "Expected many registers, got {}", bank.len());
        // Main set
        assert!(bank.get("A").is_some());
        assert!(bank.get("F").is_some());
        assert!(bank.get("B").is_some());
        assert!(bank.get("C").is_some());
        assert!(bank.get("D").is_some());
        assert!(bank.get("E").is_some());
        assert!(bank.get("H").is_some());
        assert!(bank.get("L").is_some());
        // Alternate set
        assert!(bank.get("A_PRIME").is_some());
        assert!(bank.get("F_PRIME").is_some());
        assert!(bank.get("B_PRIME").is_some());
        assert!(bank.get("H_PRIME").is_some());
        // Index registers
        assert!(bank.get("IX").is_some());
        assert!(bank.get("IY").is_some());
        assert!(bank.get("IXH").is_some());
        assert!(bank.get("IXL").is_some());
        assert!(bank.get("IYH").is_some());
        assert!(bank.get("IYL").is_some());
        // Special
        assert!(bank.get("SP").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("I").is_some());
        assert!(bank.get("R").is_some());
        // Internal
        assert!(bank.get("IM").is_some());
        assert!(bank.get("IFF1").is_some());
        assert!(bank.get("IFF2").is_some());
    }

    #[test]
    fn test_z80_register_pairs() {
        let bank = Z80Processor::registers();
        assert!(bank.get("AF").is_some());
        assert!(bank.get("BC").is_some());
        assert!(bank.get("DE").is_some());
        assert!(bank.get("HL").is_some());
        // Alternate pairs
        assert!(bank.get("AF_PRIME").is_some());
        assert!(bank.get("BC_PRIME").is_some());
        assert!(bank.get("HL_PRIME").is_some());
    }

    #[test]
    fn test_z80_flag_bits() {
        let bank = Z80Processor::registers();
        let s = bank.get("S").unwrap();
        assert_eq!(s.parent.as_deref(), Some("F"));
        assert_eq!(s.lsb, 7);
        assert_eq!(s.bit_size, 1);

        let z = bank.get("Z").unwrap();
        assert_eq!(z.lsb, 6);
        assert_eq!(z.bit_size, 1);

        let h = bank.get("HALF_CARRY").unwrap();
        assert_eq!(h.lsb, 4);

        let pv = bank.get("P_V").unwrap();
        assert_eq!(pv.lsb, 2);

        let n = bank.get("N").unwrap();
        assert_eq!(n.lsb, 1);

        let c = bank.get("C").unwrap();
        assert_eq!(c.lsb, 0);
    }

    #[test]
    fn test_z80_index_sub_registers() {
        let bank = Z80Processor::registers();
        let ixh = bank.get("IXH").unwrap();
        assert_eq!(ixh.parent.as_deref(), Some("IX"));
        assert_eq!(ixh.lsb, 8);
        assert_eq!(ixh.bit_size, 8);

        let ixl = bank.get("IXL").unwrap();
        assert_eq!(ixl.parent.as_deref(), Some("IX"));
        assert_eq!(ixl.lsb, 0);
        assert_eq!(ixl.bit_size, 8);
    }

    #[test]
    fn test_z80_languages() {
        let langs = Z80Processor::languages();
        assert!(langs.len() >= 2);
        assert!(langs.iter().any(|l| l.id == "z80:LE:8:default"));
        assert!(langs.iter().any(|l| l.id == "gb:LE:8:LR35902"));
    }

    #[test]
    fn test_z80_instructions() {
        let insts = Z80Processor::instructions();
        assert!(insts.len() > 70);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"ld"));
        assert!(texts.contains(&"push"));
        assert!(texts.contains(&"pop"));
        assert!(texts.contains(&"add_a"));
        assert!(texts.contains(&"adc"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"cp"));
        assert!(texts.contains(&"jp"));
        assert!(texts.contains(&"jr_c"));
        assert!(texts.contains(&"call"));
        assert!(texts.contains(&"ret"));
        assert!(texts.contains(&"reti"));
        assert!(texts.contains(&"rst"));
        assert!(texts.contains(&"bit"));
        assert!(texts.contains(&"set"));
        assert!(texts.contains(&"res"));
        assert!(texts.contains(&"rlc"));
        assert!(texts.contains(&"rl"));
        assert!(texts.contains(&"sla"));
        assert!(texts.contains(&"srl"));
        assert!(texts.contains(&"halt"));
        assert!(texts.contains(&"di"));
        assert!(texts.contains(&"ei"));
    }
}
