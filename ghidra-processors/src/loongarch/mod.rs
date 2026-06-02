//! LoongArch Processor Module
//!
//! Supports LoongArch 64-bit (LA64) and 32-bit (LA32) ISA variants.
//!
//! LoongArch is a RISC instruction set architecture developed by Loongson
//! Technology, designed as an alternative to MIPS, ARM, and RISC-V for
//! general-purpose computing.
//!
//! ## Architecture overview
//! - 32 general-purpose registers: GR0-GR31
//!   - GR0 = always zero
//!   - GR1 (RA) = return address
//!   - GR3 (SP) = stack pointer
//!   - GR22 (FP) = frame pointer
//! - 32 floating-point registers: F0-F31 (LA64) or F0-F31 (LA32)
//! - 8 condition flag registers: FCC0-FCC7
//! - Floating-point control/status: FCSR0-FCSR3
//! - Privileged/system control registers for exception handling, MMU, etc.
//!
//! ## Register space layout
//! - GPR (GR0-GR31):      0x0000 - 0x00F8  (64-bit on LA64, 32-bit on LA32)
//! - FPU (F0-F31):        0x0100 - 0x01F8  (64-bit / 32-bit)
//! - FCC (FCC0-FCC7):     0x0200 - 0x0207  (8-bit each)
//! - FCSR (FCSR0-FCSR3):  0x0210 - 0x021C  (32-bit each)
//! - Privileged:          0x0300 - 0x0400  (various widths)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// LoongArch processor struct.
pub struct LoongArchProcessor;

/// Build the complete LoongArch register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- General-purpose registers GR0-GR31 (64-bit on LA64) ----
    // GR0 = ZERO (hardwired to zero)
    // GR1 = RA (return address)
    // GR3 = SP (stack pointer)
    // GR22 = FP (frame pointer)
    for i in 0..32u32 {
        bank.add(Register::new(
            &format!("GR{}", i),
            64,
            (i as u64) * 8,
        ));
    }

    // Register aliases
    bank.add(Register::sub_register("ZERO", 64, 0 * 8, "GR0", 0));
    bank.add(Register::sub_register("RA", 64, 1 * 8, "GR1", 0));
    bank.add(Register::sub_register("TP", 64, 2 * 8, "GR2", 0)); // Thread pointer
    bank.add(Register::sub_register("SP", 64, 3 * 8, "GR3", 0));
    bank.add(Register::sub_register("A0", 64, 4 * 8, "GR4", 0)); // Argument 0
    bank.add(Register::sub_register("A1", 64, 5 * 8, "GR5", 0)); // Argument 1
    bank.add(Register::sub_register("A2", 64, 6 * 8, "GR6", 0));
    bank.add(Register::sub_register("A3", 64, 7 * 8, "GR7", 0));
    bank.add(Register::sub_register("A4", 64, 8 * 8, "GR8", 0));
    bank.add(Register::sub_register("A5", 64, 9 * 8, "GR9", 0));
    bank.add(Register::sub_register("A6", 64, 10 * 8, "GR10", 0));
    bank.add(Register::sub_register("A7", 64, 11 * 8, "GR11", 0));
    bank.add(Register::sub_register("T0", 64, 12 * 8, "GR12", 0)); // Temp 0
    bank.add(Register::sub_register("T1", 64, 13 * 8, "GR13", 0));
    bank.add(Register::sub_register("T2", 64, 14 * 8, "GR14", 0));
    bank.add(Register::sub_register("T3", 64, 15 * 8, "GR15", 0));
    bank.add(Register::sub_register("T4", 64, 16 * 8, "GR16", 0));
    bank.add(Register::sub_register("T5", 64, 17 * 8, "GR17", 0));
    bank.add(Register::sub_register("T6", 64, 18 * 8, "GR18", 0));
    bank.add(Register::sub_register("T7", 64, 19 * 8, "GR19", 0));
    bank.add(Register::sub_register("S0", 64, 23 * 8, "GR23", 0)); // Saved 0
    bank.add(Register::sub_register("S1", 64, 24 * 8, "GR24", 0));
    bank.add(Register::sub_register("S2", 64, 25 * 8, "GR25", 0));
    bank.add(Register::sub_register("S3", 64, 26 * 8, "GR26", 0));
    bank.add(Register::sub_register("S4", 64, 27 * 8, "GR27", 0));
    bank.add(Register::sub_register("S5", 64, 28 * 8, "GR28", 0));
    bank.add(Register::sub_register("S6", 64, 29 * 8, "GR29", 0));
    bank.add(Register::sub_register("S7", 64, 30 * 8, "GR30", 0));
    bank.add(Register::sub_register("S8", 64, 31 * 8, "GR31", 0));
    bank.add(Register::sub_register("FP", 64, 22 * 8, "GR22", 0)); // Frame pointer alias

    // Program Counter
    bank.add(Register::new("PC", 64, 0x0200));

    // ---- Floating-point registers F0-F31 (64-bit on LA64) ----
    for i in 0..32u32 {
        bank.add(Register::new(
            &format!("F{}", i),
            64,
            0x0100 + (i as u64) * 8,
        ));
    }

    // FPU aliases for argument/return
    bank.add(Register::sub_register("FA0", 64, 0x0100 + 0 * 8, "F0", 0));
    bank.add(Register::sub_register("FA1", 64, 0x0100 + 1 * 8, "F1", 0));
    bank.add(Register::sub_register("FA2", 64, 0x0100 + 2 * 8, "F2", 0));
    bank.add(Register::sub_register("FA3", 64, 0x0100 + 3 * 8, "F3", 0));
    bank.add(Register::sub_register("FA4", 64, 0x0100 + 4 * 8, "F4", 0));
    bank.add(Register::sub_register("FA5", 64, 0x0100 + 5 * 8, "F5", 0));
    bank.add(Register::sub_register("FA6", 64, 0x0100 + 6 * 8, "F6", 0));
    bank.add(Register::sub_register("FA7", 64, 0x0100 + 7 * 8, "F7", 0));
    bank.add(Register::sub_register("FT0", 64, 0x0100 + 8 * 8, "F8", 0));
    bank.add(Register::sub_register("FT1", 64, 0x0100 + 9 * 8, "F9", 0));
    bank.add(Register::sub_register("FT2", 64, 0x0100 + 10 * 8, "F10", 0));
    bank.add(Register::sub_register("FT3", 64, 0x0100 + 11 * 8, "F11", 0));
    bank.add(Register::sub_register("FT4", 64, 0x0100 + 12 * 8, "F12", 0));
    bank.add(Register::sub_register("FT5", 64, 0x0100 + 13 * 8, "F13", 0));
    bank.add(Register::sub_register("FT6", 64, 0x0100 + 14 * 8, "F14", 0));
    bank.add(Register::sub_register("FT7", 64, 0x0100 + 15 * 8, "F15", 0));
    bank.add(Register::sub_register("FS0", 64, 0x0100 + 24 * 8, "F24", 0));
    bank.add(Register::sub_register("FS1", 64, 0x0100 + 25 * 8, "F25", 0));
    bank.add(Register::sub_register("FS2", 64, 0x0100 + 26 * 8, "F26", 0));
    bank.add(Register::sub_register("FS3", 64, 0x0100 + 27 * 8, "F27", 0));
    bank.add(Register::sub_register("FS4", 64, 0x0100 + 28 * 8, "F28", 0));
    bank.add(Register::sub_register("FS5", 64, 0x0100 + 29 * 8, "F29", 0));
    bank.add(Register::sub_register("FS6", 64, 0x0100 + 30 * 8, "F30", 0));
    bank.add(Register::sub_register("FS7", 64, 0x0100 + 31 * 8, "F31", 0));

    // ---- Condition flag registers FCC0-FCC7 ----
    for i in 0..8u32 {
        bank.add(Register::new(
            &format!("FCC{}", i),
            8,
            0x0208 + (i as u64),
        ));
    }

    // ---- Floating-point control/status registers ----
    for i in 0..4u32 {
        bank.add(Register::new(
            &format!("FCSR{}", i),
            32,
            0x0210 + (i as u64) * 4,
        ));
    }

    // ---- Privileged / System registers ----
    bank.add(Register::new("CRMD", 32, 0x0300));    // Current mode
    bank.add(Register::new("PRMD", 32, 0x0304));    // Previous mode
    bank.add(Register::new("EUEN", 32, 0x0308));    // Extended unit enable
    bank.add(Register::new("ECFG", 32, 0x030C));    // Exception configuration
    bank.add(Register::new("ESTAT", 32, 0x0310));   // Exception status
    bank.add(Register::new("ERA", 64, 0x0318));     // Exception return address
    bank.add(Register::new("BADV", 64, 0x0320));    // Bad virtual address
    bank.add(Register::new("BADI", 32, 0x0328));    // Bad instruction
    bank.add(Register::new("EENTRY", 64, 0x0330));  // Exception entry point
    bank.add(Register::new("TLBIDX", 32, 0x0338));  // TLB index
    bank.add(Register::new("TLBEHI", 64, 0x0340));  // TLB entry high
    bank.add(Register::new("TLBELO0", 64, 0x0348)); // TLB entry low 0
    bank.add(Register::new("TLBELO1", 64, 0x0350)); // TLB entry low 1
    bank.add(Register::new("ASID", 16, 0x0358));    // Address space ID
    bank.add(Register::new("PGDL", 64, 0x0360));    // Page global directory (low)
    bank.add(Register::new("PGDH", 64, 0x0368));    // Page global directory (high)
    bank.add(Register::new("PGD", 64, 0x0370));     // Page global directory
    bank.add(Register::new("PWCL", 32, 0x0378));    // Page walk config (low)
    bank.add(Register::new("PWCH", 32, 0x037C));    // Page walk config (high)
    bank.add(Register::new("STLBPGSIZE", 8, 0x0380)); // STLB page size
    bank.add(Register::new("RVA", 64, 0x0388));     // Reduced virtual address
    bank.add(Register::new("CPUID", 32, 0x0390));   // CPU ID
    bank.add(Register::new("PRCFG1", 32, 0x03A0));  // Processor config 1
    bank.add(Register::new("PRCFG2", 32, 0x03A4));  // Processor config 2
    bank.add(Register::new("PRCFG3", 32, 0x03A8));  // Processor config 3
    bank.add(Register::new("SAVE0", 64, 0x03B0));   // Data save 0
    bank.add(Register::new("SAVE1", 64, 0x03B8));   // Data save 1
    bank.add(Register::new("SAVE2", 64, 0x03C0));   // Data save 2
    bank.add(Register::new("SAVE3", 64, 0x03C8));   // Data save 3
    bank.add(Register::new("SAVE4", 64, 0x03D0));   // Data save 4
    bank.add(Register::new("SAVE5", 64, 0x03D8));   // Data save 5
    bank.add(Register::new("SAVE6", 64, 0x03E0));   // Data save 6
    bank.add(Register::new("SAVE7", 64, 0x03E8));   // Data save 7
    bank.add(Register::new("TID", 32, 0x03F0));     // Thread ID
    bank.add(Register::new("TCFG", 32, 0x03F4));    // Timer configuration
    bank.add(Register::new("TVAL", 32, 0x03F8));    // Timer value
    bank.add(Register::new("TICLR", 32, 0x03FC));   // Timer interrupt clear
    bank.add(Register::new("LLBCTL", 32, 0x0400));  // LLBit control
    bank.add(Register::new("DMW0", 64, 0x0408));    // Direct map window 0
    bank.add(Register::new("DMW1", 64, 0x0410));    // Direct map window 1
    bank.add(Register::new("DMW2", 64, 0x0418));    // Direct map window 2
    bank.add(Register::new("DMW3", 64, 0x0420));    // Direct map window 3

    bank
}

/// Build the LoongArch instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Integer arithmetic ===
        InstructionMnemonic::new("add_w"),     // Add word
        InstructionMnemonic::new("add_d"),     // Add double-word
        InstructionMnemonic::new("addi_w"),    // Add immediate word
        InstructionMnemonic::new("addi_d"),    // Add immediate double-word
        InstructionMnemonic::new("sub_w"),     // Subtract word
        InstructionMnemonic::new("sub_d"),     // Subtract double-word
        InstructionMnemonic::new("mul_w"),     // Multiply word
        InstructionMnemonic::new("mul_d"),     // Multiply double-word
        InstructionMnemonic::new("mulh_w"),    // Multiply high word (signed)
        InstructionMnemonic::new("mulh_wu"),   // Multiply high word (unsigned)
        InstructionMnemonic::new("mulh_d"),    // Multiply high double-word (signed)
        InstructionMnemonic::new("mulh_du"),   // Multiply high double-word (unsigned)
        InstructionMnemonic::new("div_w"),     // Divide word (signed)
        InstructionMnemonic::new("div_wu"),    // Divide word (unsigned)
        InstructionMnemonic::new("div_d"),     // Divide double-word (signed)
        InstructionMnemonic::new("div_du"),    // Divide double-word (unsigned)
        InstructionMnemonic::new("mod_w"),     // Remainder word (signed)
        InstructionMnemonic::new("mod_wu"),    // Remainder word (unsigned)
        InstructionMnemonic::new("mod_d"),     // Remainder double-word (signed)
        InstructionMnemonic::new("mod_du"),    // Remainder double-word (unsigned)
        InstructionMnemonic::new("neg_w"),     // Negate word
        InstructionMnemonic::new("neg_d"),     // Negate double-word
        // === Logical / bitwise ===
        InstructionMnemonic::new("and"),       // Bitwise AND
        InstructionMnemonic::new("andi"),      // Bitwise AND immediate
        InstructionMnemonic::new("or"),        // Bitwise OR
        InstructionMnemonic::new("ori"),       // Bitwise OR immediate
        InstructionMnemonic::new("xor"),       // Bitwise XOR
        InstructionMnemonic::new("xori"),      // Bitwise XOR immediate
        InstructionMnemonic::new("nor"),       // Bitwise NOR
        InstructionMnemonic::new("andn"),      // Bitwise AND NOT
        InstructionMnemonic::new("orn"),       // Bitwise OR NOT
        InstructionMnemonic::new("not"),       // Bitwise NOT
        // === Shift ===
        InstructionMnemonic::new("sll_w"),     // Shift left logical word
        InstructionMnemonic::new("sll_d"),     // Shift left logical double-word
        InstructionMnemonic::new("slli_w"),    // Shift left logical immediate word
        InstructionMnemonic::new("slli_d"),    // Shift left logical immediate double-word
        InstructionMnemonic::new("srl_w"),     // Shift right logical word
        InstructionMnemonic::new("srl_d"),     // Shift right logical double-word
        InstructionMnemonic::new("srli_w"),    // Shift right logical immediate word
        InstructionMnemonic::new("srli_d"),    // Shift right logical immediate double-word
        InstructionMnemonic::new("sra_w"),     // Shift right arithmetic word
        InstructionMnemonic::new("sra_d"),     // Shift right arithmetic double-word
        InstructionMnemonic::new("srai_w"),    // Shift right arithmetic immediate word
        InstructionMnemonic::new("srai_d"),    // Shift right arithmetic immediate double-word
        InstructionMnemonic::new("rotri_w"),   // Rotate right immediate word
        InstructionMnemonic::new("rotri_d"),   // Rotate right immediate double-word
        // === Bit manipulation ===
        InstructionMnemonic::new("bstrins_w"), // Bit string insert word
        InstructionMnemonic::new("bstrins_d"), // Bit string insert double-word
        InstructionMnemonic::new("bstrpick_w"),// Bit string pick word
        InstructionMnemonic::new("bstrpick_d"),// Bit string pick double-word
        InstructionMnemonic::new("clz_w"),     // Count leading zeros word
        InstructionMnemonic::new("clz_d"),     // Count leading zeros double-word
        InstructionMnemonic::new("ctz_w"),     // Count trailing zeros word
        InstructionMnemonic::new("ctz_d"),     // Count trailing zeros double-word
        InstructionMnemonic::new("bytepick_w"),// Byte pick word
        InstructionMnemonic::new("bytepick_d"),// Byte pick double-word
        // === Byte / sign extension ===
        InstructionMnemonic::new("ext_w_b"),   // Sign-extend byte to word
        InstructionMnemonic::new("ext_w_h"),   // Sign-extend halfword to word
        InstructionMnemonic::new("lu12i_w"),   // Load upper 12 bits word (immediate)
        InstructionMnemonic::new("lu32i_d"),   // Load upper 32 bits double-word
        InstructionMnemonic::new("lu52i_d"),   // Load upper 52 bits double-word
        // === Compare ===
        InstructionMnemonic::new("slt"),       // Set if less than (signed)
        InstructionMnemonic::new("sltu"),      // Set if less than (unsigned)
        InstructionMnemonic::new("slti"),      // Set if less than immediate (signed)
        InstructionMnemonic::new("sltui"),     // Set if less than immediate (unsigned)
        InstructionMnemonic::new("maskeqz"),   // Mask if equal to zero
        InstructionMnemonic::new("masknez"),   // Mask if not equal to zero
        // === Conditional moves ===
        InstructionMnemonic::new("moveqz"),    // Move if equal to zero
        InstructionMnemonic::new("movnez"),    // Move if not equal to zero
        // === Branch ===
        InstructionMnemonic::new("beqz"),      // Branch if equal to zero
        InstructionMnemonic::new("bnez"),      // Branch if not equal to zero
        InstructionMnemonic::new("bceqz"),     // Branch if condition equal zero
        InstructionMnemonic::new("bcnez"),     // Branch if condition not equal zero
        InstructionMnemonic::new("beq"),       // Branch if equal
        InstructionMnemonic::new("bne"),       // Branch if not equal
        InstructionMnemonic::new("blt"),       // Branch if less than (signed)
        InstructionMnemonic::new("bge"),       // Branch if greater or equal (signed)
        InstructionMnemonic::new("bltu"),      // Branch if less than (unsigned)
        InstructionMnemonic::new("bgeu"),      // Branch if greater or equal (unsigned)
        InstructionMnemonic::new("b"),         // Branch unconditional
        InstructionMnemonic::new("bl"),        // Branch and link
        // === Jump ===
        InstructionMnemonic::new("jirl"),      // Jump indirect and link register
        // === Load / Store ===
        InstructionMnemonic::new("ld_b"),      // Load byte
        InstructionMnemonic::new("ld_h"),      // Load half-word
        InstructionMnemonic::new("ld_w"),      // Load word
        InstructionMnemonic::new("ld_d"),      // Load double-word
        InstructionMnemonic::new("ld_bu"),     // Load byte unsigned
        InstructionMnemonic::new("ld_hu"),     // Load half-word unsigned
        InstructionMnemonic::new("ld_wu"),     // Load word unsigned (LA64 only)
        InstructionMnemonic::new("st_b"),      // Store byte
        InstructionMnemonic::new("st_h"),      // Store half-word
        InstructionMnemonic::new("st_w"),      // Store word
        InstructionMnemonic::new("st_d"),      // Store double-word
        InstructionMnemonic::new("ldx_b"),     // Load byte indexed
        InstructionMnemonic::new("ldx_h"),     // Load half-word indexed
        InstructionMnemonic::new("ldx_w"),     // Load word indexed
        InstructionMnemonic::new("ldx_d"),     // Load double-word indexed
        InstructionMnemonic::new("ldx_bu"),    // Load byte unsigned indexed
        InstructionMnemonic::new("ldx_hu"),    // Load half-word unsigned indexed
        InstructionMnemonic::new("ldx_wu"),    // Load word unsigned indexed
        InstructionMnemonic::new("stx_b"),     // Store byte indexed
        InstructionMnemonic::new("stx_h"),     // Store half-word indexed
        InstructionMnemonic::new("stx_w"),     // Store word indexed
        InstructionMnemonic::new("stx_d"),     // Store double-word indexed
        // Prefix load instructions
        InstructionMnemonic::new("preld"),     // Prefetch for load
        // === Atomic ===
        InstructionMnemonic::new("amswap_w"),     // Atomic swap word
        InstructionMnemonic::new("amswap_d"),     // Atomic swap double-word
        InstructionMnemonic::new("amadd_w"),      // Atomic add word
        InstructionMnemonic::new("amadd_d"),      // Atomic add double-word
        InstructionMnemonic::new("amand_w"),      // Atomic AND word
        InstructionMnemonic::new("amand_d"),      // Atomic AND double-word
        InstructionMnemonic::new("amor_w"),       // Atomic OR word
        InstructionMnemonic::new("amor_d"),       // Atomic OR double-word
        InstructionMnemonic::new("amxor_w"),      // Atomic XOR word
        InstructionMnemonic::new("amxor_d"),      // Atomic XOR double-word
        InstructionMnemonic::new("ammax_w"),      // Atomic max word (signed)
        InstructionMnemonic::new("ammax_d"),      // Atomic max double-word (signed)
        InstructionMnemonic::new("ammax_wu"),     // Atomic max word (unsigned)
        InstructionMnemonic::new("ammax_du"),     // Atomic max double-word (unsigned)
        InstructionMnemonic::new("ammin_w"),      // Atomic min word (signed)
        InstructionMnemonic::new("ammin_d"),      // Atomic min double-word (signed)
        InstructionMnemonic::new("ammin_wu"),     // Atomic min word (unsigned)
        InstructionMnemonic::new("ammin_du"),     // Atomic min double-word (unsigned)
        InstructionMnemonic::new("amcas_w"),      // Atomic compare-and-swap word
        InstructionMnemonic::new("amcas_d"),      // Atomic compare-and-swap double-word
        // === LL/SC (Load-Linked / Store-Conditional) ===
        InstructionMnemonic::new("ll_w"),      // Load linked word
        InstructionMnemonic::new("ll_d"),      // Load linked double-word
        InstructionMnemonic::new("sc_w"),      // Store conditional word
        InstructionMnemonic::new("sc_d"),      // Store conditional double-word
        // === Barriers ===
        InstructionMnemonic::new("dbar"),      // Data barrier
        InstructionMnemonic::new("ibar"),      // Instruction barrier
        // === System ===
        InstructionMnemonic::new("syscall"),   // System call
        InstructionMnemonic::new("break"),     // Breakpoint
        InstructionMnemonic::new("ertn"),      // Exception return
        InstructionMnemonic::new("idle"),      // Wait for interrupt / idle
        InstructionMnemonic::new("csrrd"),     // CSR read
        InstructionMnemonic::new("csrwr"),     // CSR write
        InstructionMnemonic::new("csrxchg"),   // CSR exchange
        InstructionMnemonic::new("iocsrrd_b"), // IO CSR read byte
        InstructionMnemonic::new("iocsrrd_h"), // IO CSR read half-word
        InstructionMnemonic::new("iocsrrd_w"), // IO CSR read word
        InstructionMnemonic::new("iocsrrd_d"), // IO CSR read double-word
        InstructionMnemonic::new("iocsrwr_b"), // IO CSR write byte
        InstructionMnemonic::new("iocsrwr_h"), // IO CSR write half-word
        InstructionMnemonic::new("iocsrwr_w"), // IO CSR write word
        InstructionMnemonic::new("iocsrwr_d"), // IO CSR write double-word
        InstructionMnemonic::new("tlbsrch"),   // TLB search
        InstructionMnemonic::new("tlbrd"),     // TLB read
        InstructionMnemonic::new("tlbwr"),     // TLB write
        InstructionMnemonic::new("tlbfill"),   // TLB fill
        InstructionMnemonic::new("invtlb"),    // Invalidate TLB
        // === FPU ===
        InstructionMnemonic::new("fadd_s"),    // FP add single
        InstructionMnemonic::new("fadd_d"),    // FP add double
        InstructionMnemonic::new("fsub_s"),    // FP subtract single
        InstructionMnemonic::new("fsub_d"),    // FP subtract double
        InstructionMnemonic::new("fmul_s"),    // FP multiply single
        InstructionMnemonic::new("fmul_d"),    // FP multiply double
        InstructionMnemonic::new("fdiv_s"),    // FP divide single
        InstructionMnemonic::new("fdiv_d"),    // FP divide double
        InstructionMnemonic::new("fmadd_s"),   // FP fused multiply-add single
        InstructionMnemonic::new("fmadd_d"),   // FP fused multiply-add double
        InstructionMnemonic::new("fmsub_s"),   // FP fused multiply-sub single
        InstructionMnemonic::new("fmsub_d"),   // FP fused multiply-sub double
        InstructionMnemonic::new("fnmadd_s"),  // FP negated multiply-add single
        InstructionMnemonic::new("fnmadd_d"),  // FP negated multiply-add double
        InstructionMnemonic::new("fnmsub_s"),  // FP negated multiply-sub single
        InstructionMnemonic::new("fnmsub_d"),  // FP negated multiply-sub double
        InstructionMnemonic::new("fmax_s"),    // FP max single
        InstructionMnemonic::new("fmax_d"),    // FP max double
        InstructionMnemonic::new("fmin_s"),    // FP min single
        InstructionMnemonic::new("fmin_d"),    // FP min double
        InstructionMnemonic::new("fmaxa_s"),   // FP max absolute single
        InstructionMnemonic::new("fmaxa_d"),   // FP max absolute double
        InstructionMnemonic::new("fmina_s"),   // FP min absolute single
        InstructionMnemonic::new("fmina_d"),   // FP min absolute double
        InstructionMnemonic::new("fabs_s"),    // FP absolute single
        InstructionMnemonic::new("fabs_d"),    // FP absolute double
        InstructionMnemonic::new("fneg_s"),    // FP negate single
        InstructionMnemonic::new("fneg_d"),    // FP negate double
        InstructionMnemonic::new("fsqrt_s"),   // FP square root single
        InstructionMnemonic::new("fsqrt_d"),   // FP square root double
        InstructionMnemonic::new("frecip_s"),  // FP reciprocal single (approximate)
        InstructionMnemonic::new("frecip_d"),  // FP reciprocal double (approximate)
        InstructionMnemonic::new("frsqrt_s"),  // FP reciprocal sqrt single (approximate)
        InstructionMnemonic::new("frsqrt_d"),  // FP reciprocal sqrt double (approximate)
        InstructionMnemonic::new("fscaleb_s"), // FP scale-by-exponent single
        InstructionMnemonic::new("fscaleb_d"), // FP scale-by-exponent double
        InstructionMnemonic::new("flogb_s"),   // FP log base-2 single
        InstructionMnemonic::new("flogb_d"),   // FP log base-2 double
        InstructionMnemonic::new("fcopysign_s"),// FP copy sign single
        InstructionMnemonic::new("fcopysign_d"),// FP copy sign double
        InstructionMnemonic::new("fclass_s"),  // FP classify single
        InstructionMnemonic::new("fclass_d"),  // FP classify double
        // FP compare
        InstructionMnemonic::new("fcmp_caf_s"),// Compare: quiet and flag (single)
        InstructionMnemonic::new("fcmp_caf_d"),// Compare: quiet and flag (double)
        InstructionMnemonic::new("fcmp_saf_s"),// Compare: signaling and flag (single)
        InstructionMnemonic::new("fcmp_saf_d"),// Compare: signaling and flag (double)
        InstructionMnemonic::new("fcmp_clt_s"),// Compare: quiet less-than (single)
        InstructionMnemonic::new("fcmp_clt_d"),// Compare: quiet less-than (double)
        InstructionMnemonic::new("fcmp_slt_s"),// Compare: signaling less-than (single)
        InstructionMnemonic::new("fcmp_slt_d"),// Compare: signaling less-than (double)
        InstructionMnemonic::new("fcmp_ceq_s"),// Compare: quiet equal (single)
        InstructionMnemonic::new("fcmp_ceq_d"),// Compare: quiet equal (double)
        InstructionMnemonic::new("fcmp_seq_s"),// Compare: signaling equal (single)
        InstructionMnemonic::new("fcmp_seq_d"),// Compare: signaling equal (double)
        InstructionMnemonic::new("fcmp_cle_s"),// Compare: quiet less-or-equal (single)
        InstructionMnemonic::new("fcmp_cle_d"),// Compare: quiet less-or-equal (double)
        InstructionMnemonic::new("fcmp_sle_s"),// Compare: signaling less-or-equal (single)
        InstructionMnemonic::new("fcmp_sle_d"),// Compare: signaling less-or-equal (double)
        InstructionMnemonic::new("fcmp_cun_s"),// Compare: quiet unordered (single)
        InstructionMnemonic::new("fcmp_cun_d"),// Compare: quiet unordered (double)
        InstructionMnemonic::new("fcmp_sun_s"),// Compare: signaling unordered (single)
        InstructionMnemonic::new("fcmp_sun_d"),// Compare: signaling unordered (double)
        InstructionMnemonic::new("fcmp_cueq_s"),// Compare: quiet unordered-or-equal (single)
        InstructionMnemonic::new("fcmp_cueq_d"),// Compare: quiet unordered-or-equal (double)
        InstructionMnemonic::new("fcmp_sueq_s"),// Compare: signaling unordered-or-equal (single)
        InstructionMnemonic::new("fcmp_sueq_d"),// Compare: signaling unordered-or-equal (double)
        // FP move / convert
        InstructionMnemonic::new("fmov_s"),    // FP move single
        InstructionMnemonic::new("fmov_d"),    // FP move double
        InstructionMnemonic::new("fcvt_s_d"),  // Convert double to single
        InstructionMnemonic::new("fcvt_d_s"),  // Convert single to double
        InstructionMnemonic::new("ftint_w_s"), // FP to int word (round toward zero) single
        InstructionMnemonic::new("ftint_w_d"), // FP to int word (round toward zero) double
        InstructionMnemonic::new("ftint_l_s"), // FP to int long (round toward zero) single
        InstructionMnemonic::new("ftint_l_d"), // FP to int long (round toward zero) double
        InstructionMnemonic::new("ffint_s_w"), // Int word to FP single
        InstructionMnemonic::new("ffint_s_l"), // Int long to FP single
        InstructionMnemonic::new("ffint_d_w"), // Int word to FP double
        InstructionMnemonic::new("ffint_d_l"), // Int long to FP double
        InstructionMnemonic::new("frint_s"),   // FP round to integer single
        InstructionMnemonic::new("frint_d"),   // FP round to integer double
        // FP load/store
        InstructionMnemonic::new("fld_s"),     // FP load single
        InstructionMnemonic::new("fld_d"),     // FP load double
        InstructionMnemonic::new("fst_s"),     // FP store single
        InstructionMnemonic::new("fst_d"),     // FP store double
        InstructionMnemonic::new("fldx_s"),    // FP load single indexed
        InstructionMnemonic::new("fldx_d"),    // FP load double indexed
        InstructionMnemonic::new("fstx_s"),    // FP store single indexed
        InstructionMnemonic::new("fstx_d"),    // FP store double indexed
        // === PC-relative address generation ===
        InstructionMnemonic::new("pcaddi"),    // PC-relative add immediate
        InstructionMnemonic::new("pcaddu12i"), // PC-relative add upper 12 immediate
        InstructionMnemonic::new("pcaddu18i"), // PC-relative add upper 18 immediate
        InstructionMnemonic::new("pcalau12i"), // PC-relative add lower 12 immediate
        // === Misc ===
        InstructionMnemonic::new("nop"),       // No operation
        InstructionMnemonic::new("rdtimel_w"), // Read timer (low) word
        InstructionMnemonic::new("rdtimeh_w"), // Read timer (high) word
        InstructionMnemonic::new("rdtime_d"),  // Read timer double-word
        InstructionMnemonic::new("crc_w_b_w"), // CRC byte
        InstructionMnemonic::new("crc_w_h_w"), // CRC half-word
        InstructionMnemonic::new("crc_w_w_w"), // CRC word
        InstructionMnemonic::new("crc_w_d_w"), // CRC double-word
        InstructionMnemonic::new("crcc_w_b_w"),// CRC checksum byte
        InstructionMnemonic::new("crcc_w_h_w"),// CRC checksum half-word
        InstructionMnemonic::new("crcc_w_w_w"),// CRC checksum word
        InstructionMnemonic::new("crcc_w_d_w"),// CRC checksum double-word
        InstructionMnemonic::new("cpucfg"),    // CPU configuration
    ]
}

impl ProcessorModule for LoongArchProcessor {
    fn name() -> &'static str {
        "LoongArch"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "Loongarch:LE:32:LA32",
                "LoongArch LA32 (32-bit, little-endian)",
                "LA32",
                Endian::Little,
                32,
            ),
            Language::new(
                "Loongarch:LE:64:LA64",
                "LoongArch LA64 (64-bit, little-endian)",
                "LA64",
                Endian::Little,
                64,
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
    fn test_loongarch_name() {
        assert_eq!(LoongArchProcessor::name(), "LoongArch");
    }

    #[test]
    fn test_loongarch_registers() {
        let bank = LoongArchProcessor::registers();
        assert!(bank.len() > 50, "Expected many registers, got {}", bank.len());
        // GPRs
        for i in 0..32u32 {
            assert!(bank.get(&format!("GR{}", i)).is_some());
        }
        assert!(bank.get("ZERO").is_some());
        assert!(bank.get("RA").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("FP").is_some());
        assert!(bank.get("PC").is_some());
        // FPU
        for i in 0..32u32 {
            assert!(bank.get(&format!("F{}", i)).is_some());
        }
        assert!(bank.get("FCSR0").is_some());
        assert!(bank.get("FCSR3").is_some());
        // Privileged
        assert!(bank.get("CRMD").is_some());
        assert!(bank.get("ERA").is_some());
        assert!(bank.get("EENTRY").is_some());
        assert!(bank.get("TLBIDX").is_some());
        assert!(bank.get("CPUID").is_some());
    }

    #[test]
    fn test_loongarch_aliases() {
        let bank = LoongArchProcessor::registers();
        assert_eq!(bank.get("ZERO").unwrap().parent.as_deref(), Some("GR0"));
        assert_eq!(bank.get("RA").unwrap().parent.as_deref(), Some("GR1"));
        assert_eq!(bank.get("SP").unwrap().parent.as_deref(), Some("GR3"));
        assert_eq!(bank.get("FP").unwrap().parent.as_deref(), Some("GR22"));
        assert_eq!(bank.get("A0").unwrap().parent.as_deref(), Some("GR4"));
        assert_eq!(bank.get("FA0").unwrap().parent.as_deref(), Some("F0"));
    }

    #[test]
    fn test_loongarch_register_bits() {
        let bank = LoongArchProcessor::registers();
        assert_eq!(bank.get("GR0").unwrap().bit_size, 64);
        assert_eq!(bank.get("PC").unwrap().bit_size, 64);
        assert_eq!(bank.get("F0").unwrap().bit_size, 64);
        assert_eq!(bank.get("FCC0").unwrap().bit_size, 8);
        assert_eq!(bank.get("CRMD").unwrap().bit_size, 32);
        assert_eq!(bank.get("ERA").unwrap().bit_size, 64);
    }

    #[test]
    fn test_loongarch_languages() {
        let langs = LoongArchProcessor::languages();
        assert!(langs.len() >= 2);
        assert!(langs.iter().any(|l| l.id == "Loongarch:LE:32:LA32"));
        assert!(langs.iter().any(|l| l.id == "Loongarch:LE:64:LA64"));
        assert!(langs.iter().all(|l| l.endian == Endian::Little));
    }

    #[test]
    fn test_loongarch_instructions() {
        let insts = LoongArchProcessor::instructions();
        assert!(insts.len() > 80);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"add_w"));
        assert!(texts.contains(&"add_d"));
        assert!(texts.contains(&"ld_w"));
        assert!(texts.contains(&"st_d"));
        assert!(texts.contains(&"beqz"));
        assert!(texts.contains(&"jirl"));
        assert!(texts.contains(&"fadd_s"));
        assert!(texts.contains(&"fdiv_d"));
        assert!(texts.contains(&"amswap_w"));
        assert!(texts.contains(&"ll_w"));
        assert!(texts.contains(&"sc_w"));
        assert!(texts.contains(&"dbar"));
        assert!(texts.contains(&"syscall"));
        assert!(texts.contains(&"ertn"));
    }
}
