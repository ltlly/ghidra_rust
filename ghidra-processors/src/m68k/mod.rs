//! Motorola 68000 Family Processor Module
//!
//! Supports the complete M68K family: 68000, 68010, 68020, 68030, 68040, 68060,
//! and ColdFire (V1-V5) variants.
//!
//! The Motorola 68000 is a 16/32-bit CISC architecture introduced in 1979. It
//! was used in the Apple Macintosh, Commodore Amiga, Atari ST, Sega Genesis
//! (Mega Drive), and countless embedded systems. ColdFire is a simplified,
//! enhanced derivative for embedded applications.
//!
//! ## Register space layout
//! - Data registers (D0-D7):         0x0000 - 0x001C  (32-bit each)
//! - Address registers (A0-A7):      0x0020 - 0x003C  (32-bit each)
//!   - A7 is the user stack pointer (USP)
//! - Program Counter (PC):           0x0040            (32-bit)
//! - Status Register (SR/CCR):       0x0048            (16-bit)
//!   - Condition Code Register (CCR): low 8 bits of SR
//! - Supervisor Stack Pointer (SSP): 0x0050            (32-bit, 68000+)
//! - Vector Base Register (VBR):     0x0058            (32-bit, 68010+)
//! - Source Function Code (SFC):     0x0060            (3-bit, 68020+)
//! - Destination Function Code (DFC):0x0064            (3-bit, 68020+)
//! - Cache Control Register (CACR):  0x0068            (32-bit, 68020+)
//! - Cache Address Register (CAAR):  0x0070            (32-bit, 68020+)
//! - User Stack Pointer (USP):       0x0078            (32-bit, alias of A7 in user mode)
//! - Interrupt Stack Pointer (ISP):  0x0080            (32-bit, 68020+)
//! - Master Stack Pointer (MSP):     0x0088            (32-bit, 68020+)
//! - FPU registers (FP0-FP7):       0x0100 - 0x0170  (80-bit extended, 68040+)
//! - FPU Status Register (FPSR):     0x0180            (32-bit, 68040+)
//! - FPU Control Register (FPCR):    0x0184            (32-bit, 68040+)
//! - FPU Instruction Address (FPIAR):0x0188            (32-bit, 68040+)
//! - MACSR (MAC Status Register):    0x0200            (32-bit, ColdFire)
//! - MASK (MAC Address Mask):        0x0208            (32-bit, ColdFire)
//! - ACC (MAC Accumulator):          0x0210            (32-bit, ColdFire)
//! - MACEXT (MAC Extractor):         0x0214            (32-bit, ColdFire)
//! - EMAC Accumulators (EMAC0-EMAC3):0x0220 - 0x023C  (32-bit each, ColdFire V4+)
//! - EMAC Status Register:           0x0240            (32-bit, ColdFire V4+)
//! - EMAC Accumulator MSB extension: 0x0248            (32-bit, ColdFire V4+)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Motorola 68000 processor struct.
pub struct M68kProcessor;

/// Build the complete M68K register bank (68060 + ColdFire).
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- Data registers D0-D7 (32-bit) ----
    for i in 0u32..8 {
        bank.add(Register::new(&format!("D{}", i), 32, (i as u64) * 4));
    }

    // ---- Address registers A0-A7 (32-bit) ----
    for i in 0u32..8 {
        bank.add(Register::new(&format!("A{}", i), 32, 0x0020 + (i as u64) * 4));
    }
    // A7 aliases
    bank.add(Register::sub_register("USP", 32, 0x0020 + 7 * 4, "A7", 0)); // User Stack Pointer = A7
    bank.add(Register::sub_register("SP", 32, 0x0020 + 7 * 4, "A7", 0)); // Stack Pointer = A7

    // ---- Program Counter (32-bit) ----
    bank.add(Register::new("PC", 32, 0x0040));

    // ---- Status Register (16-bit) with CCR alias ----
    bank.add(Register::new("SR", 16, 0x0048));
    bank.add(Register::sub_register("CCR", 8, 0x0048, "SR", 0)); // Condition Code Register (low byte)

    // SR / CCR bit fields
    bank.add(Register::sub_register("C", 1, 0x0048, "SR", 0)); // Carry
    bank.add(Register::sub_register("V", 1, 0x0048, "SR", 1)); // Overflow
    bank.add(Register::sub_register("Z", 1, 0x0048, "SR", 2)); // Zero
    bank.add(Register::sub_register("N", 1, 0x0048, "SR", 3)); // Negative
    bank.add(Register::sub_register("X", 1, 0x0048, "SR", 4)); // Extend
    bank.add(Register::sub_register("I0", 1, 0x0048, "SR", 8)); // Interrupt mask bit 0
    bank.add(Register::sub_register("I1", 1, 0x0048, "SR", 9)); // Interrupt mask bit 1
    bank.add(Register::sub_register("I2", 1, 0x0048, "SR", 10)); // Interrupt mask bit 2
    bank.add(Register::sub_register("S", 1, 0x0048, "SR", 13)); // Supervisor flag
    bank.add(Register::sub_register("T0", 1, 0x0048, "SR", 14)); // Trace 0 (68000 trace)
    bank.add(Register::sub_register("T1", 1, 0x0048, "SR", 15)); // Trace 1 (68020+ trace)

    // ---- Supervisor Stack Pointer (32-bit, 68000+) ----
    bank.add(Register::new("SSP", 32, 0x0050)); // Supervisor (A7') - also known as ISP
    bank.add(Register::sub_register("A7_PRIME", 32, 0x0050, "SSP", 0));

    // ---- Vector Base Register (32-bit, 68010+) ----
    bank.add(Register::new("VBR", 32, 0x0058));

    // ---- Alternate Function Code Registers (3-bit, 68020+) ----
    bank.add(Register::new("SFC", 3, 0x0060)); // Source Function Code
    bank.add(Register::new("DFC", 3, 0x0064)); // Destination Function Code

    // ---- Cache Control Register (32-bit, 68020+) ----
    bank.add(Register::new("CACR", 32, 0x0068));

    // ---- Cache Address Register (32-bit, 68020+) ----
    bank.add(Register::new("CAAR", 32, 0x0070));

    // ---- Interrupt Stack Pointer (32-bit, 68020+) ----
    bank.add(Register::new("ISP", 32, 0x0080));

    // ---- Master Stack Pointer (32-bit, 68020+) ----
    bank.add(Register::new("MSP", 32, 0x0088));

    // ---- Address Translation Control (32-bit, 68030+) ----
    bank.add(Register::new("TC", 32, 0x0090)); // Translation Control (68030 MMU)
    bank.add(Register::new("TT0", 32, 0x0094)); // Transparent Translation 0
    bank.add(Register::new("TT1", 32, 0x0098)); // Transparent Translation 1
    bank.add(Register::new("SRP", 64, 0x00A0)); // Supervisor Root Pointer
    bank.add(Register::new("CRP", 64, 0x00A8)); // CPU Root Pointer
    bank.add(Register::new("MMUSR", 16, 0x00B0)); // MMU Status Register (68030)

    // ---- Bus Control Registers (32-bit, 68040+) ----
    bank.add(Register::new("ITT0", 32, 0x00B8)); // Instruction Transparent Translation 0
    bank.add(Register::new("ITT1", 32, 0x00BC)); // Instruction Transparent Translation 1
    bank.add(Register::new("DTT0", 32, 0x00C0)); // Data Transparent Translation 0
    bank.add(Register::new("DTT1", 32, 0x00C4)); // Data Transparent Translation 1
    bank.add(Register::new("URP", 32, 0x00C8)); // User Root Pointer (68040)

    // ---- FPU registers FP0-FP7 (80-bit extended precision, 68040+ / 68881/68882 coprocessor) ----
    for i in 0u32..8 {
        bank.add(Register::new(
            &format!("FP{}", i),
            80,
            0x0100 + (i as u64) * 16,
        ));
    }

    // ---- FPU control/status registers (68040+ / 68881/68882) ----
    bank.add(Register::new("FPSR", 32, 0x0180)); // FPU Status Register
    bank.add(Register::new("FPCR", 32, 0x0184)); // FPU Control Register
    bank.add(Register::new("FPIAR", 32, 0x0188)); // FPU Instruction Address Register
    bank.add(Register::new("FPRES", 96, 0x0190)); // FPU Restore buffer

    // FPSR bit fields
    bank.add(Register::sub_register("FPCC", 4, 0x0180, "FPSR", 28)); // Floating-point condition code
    bank.add(Register::sub_register("FP_N", 1, 0x0180, "FPSR", 31)); // Negative
    bank.add(Register::sub_register("FP_Z", 1, 0x0180, "FPSR", 30)); // Zero
    bank.add(Register::sub_register("FP_INF", 1, 0x0180, "FPSR", 29)); // Infinity
    bank.add(Register::sub_register("FP_NAN", 1, 0x0180, "FPSR", 28)); // NaN
    bank.add(Register::sub_register("BSUN", 1, 0x0180, "FPSR", 7)); // Branch/Set on Unordered
    bank.add(Register::sub_register("SNAN", 1, 0x0180, "FPSR", 6)); // Signaling NaN
    bank.add(Register::sub_register("OPERR", 1, 0x0180, "FPSR", 5)); // Operand Error
    bank.add(Register::sub_register("OVFL", 1, 0x0180, "FPSR", 4)); // Overflow
    bank.add(Register::sub_register("UNFL", 1, 0x0180, "FPSR", 3)); // Underflow
    bank.add(Register::sub_register("DZ", 1, 0x0180, "FPSR", 2)); // Divide by Zero
    bank.add(Register::sub_register("INEX2", 1, 0x0180, "FPSR", 1)); // Inexact 2
    bank.add(Register::sub_register("INEX1", 1, 0x0180, "FPSR", 0)); // Inexact 1

    // FPCR bit fields
    bank.add(Register::sub_register("FPCR_RND", 2, 0x0184, "FPCR", 4)); // Rounding mode
    bank.add(Register::sub_register("FPCR_PREC", 3, 0x0184, "FPCR", 6)); // Precision

    // ---- ColdFire-specific registers ----
    // MAC registers (ColdFire V2+)
    bank.add(Register::new("MACSR", 32, 0x0200)); // MAC Status Register
    bank.add(Register::new("MASK", 32, 0x0208)); // MAC Address Mask
    bank.add(Register::new("ACC", 32, 0x0210)); // MAC Accumulator (signed 32-bit)
    bank.add(Register::new("MACEXT", 32, 0x0214)); // MAC Accumulator Extension

    // EMAC registers (ColdFire V4+)
    for i in 0u32..4 {
        bank.add(Register::new(
            &format!("EMAC{}", i),
            32,
            0x0220 + (i as u64) * 4,
        ));
    }
    bank.add(Register::new("EMAC_STATUS", 32, 0x0240)); // EMAC Status
    bank.add(Register::new("EMAC_EXT", 32, 0x0248)); // EMAC Extension MSB

    // ColdFire Version Register
    bank.add(Register::new("CCR_CF", 32, 0x0250)); // ColdFire Core Configuration Register

    // ColdFire RAM Base Address registers
    bank.add(Register::new("RAMBAR", 32, 0x0258)); // RAM Base Address Register
    bank.add(Register::new("RAMBAR0", 32, 0x0260)); // RAM Base Address 0
    bank.add(Register::new("RAMBAR1", 32, 0x0268)); // RAM Base Address 1 (ColdFire V3+)

    bank
}

/// Build the M68K instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Data Movement ===
        InstructionMnemonic::new("move"),
        InstructionMnemonic::new("movea"),
        InstructionMnemonic::new("moveq"), // MOVE Quick (sign-extended 8-bit immediate)
        InstructionMnemonic::new("movem"), // MOVE Multiple registers
        InstructionMnemonic::new("movep"), // MOVE Peripheral
        InstructionMnemonic::new("move16"), // MOVE16 (68040+) block transfer
        InstructionMnemonic::new("mov3q"), // MOVE 3-bit Quick (ColdFire)
        InstructionMnemonic::new("lea"),   // Load Effective Address
        InstructionMnemonic::new("pea"),   // Push Effective Address
        InstructionMnemonic::new("link"),  // Link stack frame
        InstructionMnemonic::new("unlk"),  // Unlink stack frame
        InstructionMnemonic::new("exg"),   // Exchange registers
        InstructionMnemonic::new("swap"),  // Swap words in data register
        // === Arithmetic ===
        InstructionMnemonic::new("add"),
        InstructionMnemonic::new("adda"),
        InstructionMnemonic::new("addi"),
        InstructionMnemonic::new("addq"),  // ADD Quick (3-bit)
        InstructionMnemonic::new("addx"),  // ADD with Extend
        InstructionMnemonic::new("sub"),
        InstructionMnemonic::new("suba"),
        InstructionMnemonic::new("subi"),
        InstructionMnemonic::new("subq"),  // SUBtract Quick
        InstructionMnemonic::new("subx"),  // SUBtract with Extend
        InstructionMnemonic::new("muls"),  // MULtiply Signed
        InstructionMnemonic::new("mulu"),  // MULtiply Unsigned
        InstructionMnemonic::new("divs"),  // DIVide Signed
        InstructionMnemonic::new("divu"),  // DIVide Unsigned
        InstructionMnemonic::new("divsl"), // 64/32 -> 32 Signed Divide (68020+)
        InstructionMnemonic::new("divul"), // 64/32 -> 32 Unsigned Divide (68020+)
        InstructionMnemonic::new("muls_l"),// 32*32 -> 32 Signed Multiply (long, 68020+)
        InstructionMnemonic::new("mulu_l"),// 32*32 -> 32 Unsigned Multiply (long, 68020+)
        InstructionMnemonic::new("neg"),
        InstructionMnemonic::new("negx"),  // NEGate with Extend
        InstructionMnemonic::new("clr"),   // CLeaR
        InstructionMnemonic::new("cmp"),
        InstructionMnemonic::new("cmpa"),
        InstructionMnemonic::new("cmpi"),
        InstructionMnemonic::new("cmp2"),  // CMP register bounds (68020+)
        InstructionMnemonic::new("cmpm"),  // CMP Memory-to-Memory
        InstructionMnemonic::new("tst"),   // TeST (compare with zero)
        InstructionMnemonic::new("tas"),   // Test And Set
        InstructionMnemonic::new("ext"),   // EXTend sign
        InstructionMnemonic::new("extb"),  // EXTend Byte to Long (68020+)
        // === Logical ===
        InstructionMnemonic::new("and"),
        InstructionMnemonic::new("andi"),
        InstructionMnemonic::new("andi_ccr"), // ANDI to CCR
        InstructionMnemonic::new("andi_sr"),  // ANDI to SR (privileged)
        InstructionMnemonic::new("or"),
        InstructionMnemonic::new("ori"),
        InstructionMnemonic::new("ori_ccr"),  // ORI to CCR
        InstructionMnemonic::new("ori_sr"),   // ORI to SR (privileged)
        InstructionMnemonic::new("eor"),      // Exclusive OR
        InstructionMnemonic::new("eori"),
        InstructionMnemonic::new("eori_ccr"), // EORI to CCR
        InstructionMnemonic::new("eori_sr"),  // EORI to SR (privileged)
        InstructionMnemonic::new("not"),
        // === Shift and Rotate ===
        InstructionMnemonic::new("asl"),  // Arithmetic Shift Left
        InstructionMnemonic::new("asr"),  // Arithmetic Shift Right
        InstructionMnemonic::new("lsl"),  // Logical Shift Left
        InstructionMnemonic::new("lsr"),  // Logical Shift Right
        InstructionMnemonic::new("rol"),  // ROtate Left
        InstructionMnemonic::new("ror"),  // ROtate Right
        InstructionMnemonic::new("roxl"), // ROtate with eXtend Left
        InstructionMnemonic::new("roxr"), // ROtate with eXtend Right
        // === Bit Manipulation (68020+) ===
        InstructionMnemonic::new("bfchg"), // Bit Field CHanGe
        InstructionMnemonic::new("bfclr"), // Bit Field CLeaR
        InstructionMnemonic::new("bfexts"),// Bit Field EXTract Signed
        InstructionMnemonic::new("bfextu"),// Bit Field EXTract Unsigned
        InstructionMnemonic::new("bfffo"), // Bit Field Find First One
        InstructionMnemonic::new("bfins"), // Bit Field INSert
        InstructionMnemonic::new("bfset"), // Bit Field SET
        InstructionMnemonic::new("bftst"), // Bit Field TeST
        // === Bit Operations ===
        InstructionMnemonic::new("bchg"),  // Bit test and CHanGe
        InstructionMnemonic::new("bclr"),  // Bit test and CLeaR
        InstructionMnemonic::new("bset"),  // Bit test and SET
        InstructionMnemonic::new("btst"),  // Bit TeST
        // === BCD Arithmetic ===
        InstructionMnemonic::new("abcd"),  // Add BCD
        InstructionMnemonic::new("sbcd"),  // Subtract BCD
        InstructionMnemonic::new("nbcd"),  // Negate BCD
        // === Branch ===
        InstructionMnemonic::new("bra"),   // BRAnch
        InstructionMnemonic::new("bsr"),   // Branch to SubRoutine
        InstructionMnemonic::new("beq"),   // Branch if EQual
        InstructionMnemonic::new("bne"),   // Branch if Not Equal
        InstructionMnemonic::new("bcs"),   // Branch if Carry Set
        InstructionMnemonic::new("bcc"),   // Branch if Carry Clear
        InstructionMnemonic::new("bhs"),   // Branch if Higher or Same (same as BCC)
        InstructionMnemonic::new("blo"),   // Branch if LOwer (same as BCS)
        InstructionMnemonic::new("bmi"),   // Branch if MInus
        InstructionMnemonic::new("bpl"),   // Branch if PLus
        InstructionMnemonic::new("bvs"),   // Branch if oVerflow Set
        InstructionMnemonic::new("bvc"),   // Branch if oVerflow Clear
        InstructionMnemonic::new("bhi"),   // Branch if HIgher (unsigned)
        InstructionMnemonic::new("bls"),   // Branch if Lower or Same (unsigned)
        InstructionMnemonic::new("bge"),   // Branch if Greater or Equal (signed)
        InstructionMnemonic::new("blt"),   // Branch if Less Than (signed)
        InstructionMnemonic::new("bgt"),   // Branch if Greater Than (signed)
        InstructionMnemonic::new("ble"),   // Branch if Less or Equal (signed)
        InstructionMnemonic::new("dbcc"),  // Decrement and Branch if Carry Clear
        InstructionMnemonic::new("dbcs"),  // Decrement and Branch if Carry Set
        InstructionMnemonic::new("dbeq"),  // Decrement and Branch if EQual
        InstructionMnemonic::new("dbne"),  // Decrement and Branch if Not Equal
        InstructionMnemonic::new("dbf"),   // Decrement and Branch, never true (F=never)
        InstructionMnemonic::new("dbt"),   // Decrement and Branch, always True
        InstructionMnemonic::new("dbhi"),  // Decrement and Branch if HIgher
        InstructionMnemonic::new("dbls"),  // Decrement and Branch if Lower or Same
        InstructionMnemonic::new("dbge"),  // Decrement and Branch if Greater or Equal
        InstructionMnemonic::new("dblt"),  // Decrement and Branch if Less Than
        InstructionMnemonic::new("dbgt"),  // Decrement and Branch if Greater Than
        InstructionMnemonic::new("dble"),  // Decrement and Branch if Less or Equal
        InstructionMnemonic::new("dbpl"),  // Decrement and Branch if PLus
        InstructionMnemonic::new("dbmi"),  // Decrement and Branch if MInus
        InstructionMnemonic::new("dbvc"),  // Decrement and Branch if oVerflow Clear
        InstructionMnemonic::new("dbvs"),  // Decrement and Branch if oVerflow Set
        InstructionMnemonic::new("jmp"),   // JuMP
        InstructionMnemonic::new("jsr"),   // Jump to SubRoutine
        InstructionMnemonic::new("rts"),   // ReTurn from Subroutine
        InstructionMnemonic::new("rtd"),   // ReTurn and Deallocate (68010+)
        InstructionMnemonic::new("rtr"),   // ReTurn and Restore codes
        // === Exception / System ===
        InstructionMnemonic::new("trap"),
        InstructionMnemonic::new("trapv"),  // TRAP on oVerflow
        InstructionMnemonic::new("trapcc"), // TRAP on Condition (68020+)
        InstructionMnemonic::new("bkpt"),   // BreaKPoinT
        InstructionMnemonic::new("chk"),    // CHecK register against bounds
        InstructionMnemonic::new("chk2"),   // CHecK register against bounds (2 operands, 68020+)
        InstructionMnemonic::new("rte"),    // ReTurn from Exception
        InstructionMnemonic::new("illegal"),// ILLEGAL instruction trap
        InstructionMnemonic::new("nop"),    // No OPeration
        InstructionMnemonic::new("reset"),  // RESET external devices
        InstructionMnemonic::new("stop"),   // STOP (load SR and halt)
        InstructionMnemonic::new("halt"),   // HALT (ColdFire)
        InstructionMnemonic::new("pulse"),  // PULSE (ColdFire)
        // === Privileged ===
        InstructionMnemonic::new("movec"),  // MOVE Control register (68010+)
        InstructionMnemonic::new("movem_sp"),// MOVEM to/from SP (ColdFire V4)
        InstructionMnemonic::new("moves"),  // MOVE from/to SFC/DFC address space (68020+)
        InstructionMnemonic::new("move_sr"),// MOVE to/from SR
        InstructionMnemonic::new("move_ccr"),// MOVE to/from CCR
        InstructionMnemonic::new("move_usp"),// MOVE to/from USP
        InstructionMnemonic::new("rte_ext"),// RTE extended (68060)
        InstructionMnemonic::new("wdebug"), // Write DEBuG (ColdFire)
        // === Cache Maintenance (68030+) ===
        InstructionMnemonic::new("cinva"),  // Cache Invalidate All
        InstructionMnemonic::new("cinvl"),  // Cache Invalidate Line
        InstructionMnemonic::new("cinvp"),  // Cache Invalidate Page
        InstructionMnemonic::new("cpusha"), // Cache Push All
        InstructionMnemonic::new("cpushl"), // Cache Push Line
        InstructionMnemonic::new("cpushp"), // Cache Push Page
        InstructionMnemonic::new("cpusha_ic"), // Cache Push All IC
        InstructionMnemonic::new("cpushl_ic"), // Cache Push Line IC
        InstructionMnemonic::new("cpushp_ic"), // Cache Push Page IC
        // === Pack/Unpack (68020+) ===
        InstructionMnemonic::new("pack"),   // PACK BCD
        InstructionMnemonic::new("unpk"),   // UNPacK BCD
        // === CAS/CAS2 (68020+) ===
        InstructionMnemonic::new("cas"),    // Compare And Swap
        InstructionMnemonic::new("cas2"),   // Compare And Swap (2 operands)
        // === ColdFire MAC instructions ===
        InstructionMnemonic::new("mac"),    // Multiply ACcumulate
        InstructionMnemonic::new("macw"),   // Multiply ACcumulate Word
        InstructionMnemonic::new("macl"),   // Multiply ACcumulate Long
        InstructionMnemonic::new("msac"),   // Multiply Subtract ACcumulate
        InstructionMnemonic::new("move_mac"),// MOVE to/from MAC registers
        InstructionMnemonic::new("clr_acc"),// CLeaR ACCumulator
        // === ColdFire EMAC instructions ===
        InstructionMnemonic::new("emac"),   // Enhanced Multiply ACcumulate
        InstructionMnemonic::new("emacw"),
        InstructionMnemonic::new("emsac"),
        InstructionMnemonic::new("emsacw"),
        // === ColdFire Other ===
        InstructionMnemonic::new("stldsr"), // Store Load Data Status Register
        InstructionMnemonic::new("byterev"), // Byte REVerse (ColdFire V4)
        InstructionMnemonic::new("ff1"),     // Find First 1 (ColdFire V4)
        InstructionMnemonic::new("sats"),    // SATurate Signed (ColdFire V4)
        InstructionMnemonic::new("bitrev"),  // BIT REVerse (ColdFire V4)
        // === Floating Point (68881/68882 / 68040+) ===
        InstructionMnemonic::new("fmove"),
        InstructionMnemonic::new("fmove_fpcr"),
        InstructionMnemonic::new("fmove_fpsr"),
        InstructionMnemonic::new("fmove_fpiar"),
        InstructionMnemonic::new("fadd"),
        InstructionMnemonic::new("fsub"),
        InstructionMnemonic::new("fmul"),
        InstructionMnemonic::new("fdiv"),
        InstructionMnemonic::new("fabs"),
        InstructionMnemonic::new("fneg"),
        InstructionMnemonic::new("fsqrt"),
        InstructionMnemonic::new("fsin"),
        InstructionMnemonic::new("fcos"),
        InstructionMnemonic::new("ftan"),
        InstructionMnemonic::new("fasin"),
        InstructionMnemonic::new("facos"),
        InstructionMnemonic::new("fatan"),
        InstructionMnemonic::new("fatanh"),
        InstructionMnemonic::new("fsinh"),
        InstructionMnemonic::new("fcosh"),
        InstructionMnemonic::new("ftanh"),
        InstructionMnemonic::new("fgetexp"),
        InstructionMnemonic::new("fgetman"),
        InstructionMnemonic::new("flog2"),
        InstructionMnemonic::new("flog10"),
        InstructionMnemonic::new("flogn"),
        InstructionMnemonic::new("flognp1"),
        InstructionMnemonic::new("fmod"),
        InstructionMnemonic::new("frem"),
        InstructionMnemonic::new("fscale"),
        InstructionMnemonic::new("fsglmul"),
        InstructionMnemonic::new("fsgldiv"),
        InstructionMnemonic::new("fcmp"),
        InstructionMnemonic::new("ftst"),
        InstructionMnemonic::new("fbeq"),
        InstructionMnemonic::new("fbne"),
        InstructionMnemonic::new("fbgt"),
        InstructionMnemonic::new("fbge"),
        InstructionMnemonic::new("fblt"),
        InstructionMnemonic::new("fble"),
        InstructionMnemonic::new("fbgl"),
        InstructionMnemonic::new("fbgle"),
        InstructionMnemonic::new("fbngl"),
        InstructionMnemonic::new("fbngle"),
        InstructionMnemonic::new("fbogt"),
        InstructionMnemonic::new("fboge"),
        InstructionMnemonic::new("fbolt"),
        InstructionMnemonic::new("fbole"),
        InstructionMnemonic::new("fbor"),
        InstructionMnemonic::new("fbun"),
        InstructionMnemonic::new("fbueq"),
        InstructionMnemonic::new("fbugt"),
        InstructionMnemonic::new("fbuge"),
        InstructionMnemonic::new("fbult"),
        InstructionMnemonic::new("fbule"),
        InstructionMnemonic::new("fbne_or"),
        InstructionMnemonic::new("fseq"),
        InstructionMnemonic::new("fsne"),
        InstructionMnemonic::new("fsgt"),
        InstructionMnemonic::new("fsge"),
        InstructionMnemonic::new("fslt"),
        InstructionMnemonic::new("fsle"),
        InstructionMnemonic::new("fsgl"),
        InstructionMnemonic::new("fsgle"),
        InstructionMnemonic::new("fsngl"),
        InstructionMnemonic::new("fsngle"),
        InstructionMnemonic::new("fsogt"),
        InstructionMnemonic::new("fsoge"),
        InstructionMnemonic::new("fsolt"),
        InstructionMnemonic::new("fsole"),
        InstructionMnemonic::new("fsor"),
        InstructionMnemonic::new("fsun"),
        InstructionMnemonic::new("fsueq"),
        InstructionMnemonic::new("fsugt"),
        InstructionMnemonic::new("fsuge"),
        InstructionMnemonic::new("fsult"),
        InstructionMnemonic::new("fsule"),
        InstructionMnemonic::new("fsne_or"),
        // FPU integer and conversion
        InstructionMnemonic::new("fint"),
        InstructionMnemonic::new("fintrz"),
        InstructionMnemonic::new("fsubb"),
        InstructionMnemonic::new("faddb"),
        InstructionMnemonic::new("fmulb"),
        InstructionMnemonic::new("fdivb"),
        InstructionMnemonic::new("fmul3"),
        InstructionMnemonic::new("fabsb"),
        InstructionMnemonic::new("fmove_b"),
        InstructionMnemonic::new("fmove_p"),
    ]
}

impl ProcessorModule for M68kProcessor {
    fn name() -> &'static str {
        "Motorola 68000 Family"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "m68k:BE:32:68000",
                "Motorola 68000 (32-bit, big-endian)",
                "68000",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68k:BE:32:68010",
                "Motorola 68010 (32-bit, big-endian, with VBR)",
                "68010",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68k:BE:32:68020",
                "Motorola 68020 (32-bit, big-endian, with bit fields + cache)",
                "68020",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68k:BE:32:68030",
                "Motorola 68030 (32-bit, big-endian, with MMU)",
                "68030",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68k:BE:32:68040",
                "Motorola 68040 (32-bit, big-endian, with integrated FPU + MMU)",
                "68040",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68k:BE:32:68060",
                "Motorola 68060 (32-bit, big-endian, superscalar + FPU)",
                "68060",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68k:BE:32:ColdFire",
                "Motorola ColdFire V1-V5 (32-bit, big-endian, embedded)",
                "ColdFire",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68k:BE:32:ColdFire_EMAC",
                "Motorola ColdFire V4-V5 with EMAC (32-bit, big-endian)",
                "ColdFire-EMAC",
                Endian::Big,
                32,
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
    fn test_m68k_name() {
        assert_eq!(M68kProcessor::name(), "Motorola 68000 Family");
    }

    #[test]
    fn test_m68k_registers() {
        let bank = M68kProcessor::registers();
        assert!(bank.len() > 80, "Expected many registers, got {}", bank.len());
        // Data registers
        for i in 0..8 {
            assert!(bank.get(&format!("D{}", i)).is_some());
        }
        // Address registers
        for i in 0..8 {
            assert!(bank.get(&format!("A{}", i)).is_some());
        }
        // Special
        assert!(bank.get("PC").is_some());
        assert!(bank.get("SR").is_some());
        assert!(bank.get("USP").is_some());
        assert!(bank.get("SSP").is_some());
        assert!(bank.get("VBR").is_some());
        // FPU
        assert!(bank.get("FP0").is_some());
        assert!(bank.get("FP7").is_some());
        assert!(bank.get("FPSR").is_some());
        assert!(bank.get("FPCR").is_some());
        assert!(bank.get("FPIAR").is_some());
        // ColdFire
        assert!(bank.get("MACSR").is_some());
        assert!(bank.get("MASK").is_some());
        assert!(bank.get("ACC").is_some());
        assert!(bank.get("MACEXT").is_some());
        assert!(bank.get("EMAC0").is_some());
        assert!(bank.get("EMAC3").is_some());
    }

    #[test]
    fn test_m68k_sr_flags() {
        let bank = M68kProcessor::registers();
        let c = bank.get("C").unwrap();
        assert_eq!(c.parent.as_deref(), Some("SR"));
        assert_eq!(c.lsb, 0);
        let n = bank.get("N").unwrap();
        assert_eq!(n.lsb, 3);
        let x = bank.get("X").unwrap();
        assert_eq!(x.lsb, 4);
        let s = bank.get("S").unwrap();
        assert_eq!(s.lsb, 13);
    }

    #[test]
    fn test_m68k_register_bits() {
        let bank = M68kProcessor::registers();
        assert_eq!(bank.get("D0").unwrap().bit_size, 32);
        assert_eq!(bank.get("SR").unwrap().bit_size, 16);
        assert_eq!(bank.get("CCR").unwrap().bit_size, 8);
        assert_eq!(bank.get("SFC").unwrap().bit_size, 3);
        assert_eq!(bank.get("FP0").unwrap().bit_size, 80);
    }

    #[test]
    fn test_m68k_languages() {
        let langs = M68kProcessor::languages();
        assert!(langs.len() >= 7);
        assert!(langs.iter().any(|l| l.id == "m68k:BE:32:68000"));
        assert!(langs.iter().any(|l| l.id == "m68k:BE:32:68060"));
        assert!(langs.iter().any(|l| l.id == "m68k:BE:32:ColdFire"));
        assert!(langs.iter().all(|l| matches!(l.endian, Endian::Big)));
    }

    #[test]
    fn test_m68k_instructions() {
        let insts = M68kProcessor::instructions();
        assert!(insts.len() > 120);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"move"));
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"bra"));
        assert!(texts.contains(&"bsr"));
        assert!(texts.contains(&"jmp"));
        assert!(texts.contains(&"jsr"));
        assert!(texts.contains(&"rts"));
        assert!(texts.contains(&"rte"));
        assert!(texts.contains(&"beq"));
        assert!(texts.contains(&"bne"));
        assert!(texts.contains(&"trap"));
        assert!(texts.contains(&"link"));
        assert!(texts.contains(&"unlk"));
        assert!(texts.contains(&"fadd"));
        assert!(texts.contains(&"fmul"));
        assert!(texts.contains(&"fdiv"));
        assert!(texts.contains(&"fsqrt"));
        assert!(texts.contains(&"mac"));
        assert!(texts.contains(&"emac"));
        assert!(texts.contains(&"cas"));
    }
}
