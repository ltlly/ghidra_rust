//! Renesas SuperH SH-4 Processor Module
//!
//! Supports the Renesas SuperH SH-4 (SH7750 series) 32-bit RISC
//! microprocessor.
//!
//! ## Architecture overview
//! - 16 general-purpose 32-bit registers r0-r15
//! - r15 is the stack pointer (banked)
//! - Banked registers R0_BANK-R7_BANK for fast interrupt response
//! - 32-bit multiply registers MACH, MACL
//! - 32-bit procedure register PR
//! - 32-bit program counter PC
//! - Status register SR with T flag
//! - Floating-point registers fr0-fr15 (32-bit single precision)
//! - Double-precision pairs dr0-dr14 (64-bit)
//! - Extended floating-point bank xf0-xf15
//! - Double-precision extended pairs xd0-xd14
//! - 4-register float vectors fv0, fv4, fv8, fv12
//! - Control registers: GBR, VBR, SSR, SPC, SGR, DBR
//! - FPSCR, FPUL for FPU control
//!
//! ## Register space layout
//! - General Purpose (r0-r15):       0x00-0x3C  (32-bit each)
//! - Banked (R0_BANK-R7_BANK):      0x20-0x3C  (32-bit each)
//! - FPU Single (fr0-fr15):         0x200+  (32-bit each)
//! - FPU Extended (xf0-xf15):       0x200+  (32-bit each)
//! - FPU Double (dr0-dr14):         0x200+  (64-bit pairs)
//! - FPU Vector (fv0,fv4,fv8,fv12): 0x200+  (128-bit)
//! - Control (GBR, SR, etc.):       0x400+  (32-bit each)
//! - SR flags (T, S, Q, M, etc.):   0x600  (8-bit each)
//! - System (MACH, MACL, PR, PC):   0x800+  (32-bit each)
//! - FPSCR flags:                   0xA00  (8-bit each)

pub mod language_provider;

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// SuperH SH-4 processor struct.
pub struct SuperH4Processor;

/// Build the complete SuperH4 register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- General-purpose registers (r0-r15) ----
    for i in 0..16u64 {
        let name = format!("r{}", i);
        bank.add(Register::new(&name, 32, i * 4)
            .with_description(format!("General-purpose register r{}", i))
            .with_group("General Purpose"));
    }

    // ---- Banked registers (R0_BANK-R7_BANK) ----
    for i in 0..8u64 {
        let name = format!("R{}_BANK", i);
        bank.add(Register::new(&name, 32, 0x20 + i * 4)
            .with_description(format!("Banked register R{}_BANK", i))
            .with_group("Banked"));
    }

    // ---- FPU single-precision registers (fr0-fr15) ----
    for i in 0..16u64 {
        let name = format!("fr{}", i);
        bank.add(Register::new(&name, 32, 0x200 + i * 4)
            .with_description(format!("FPU register fr{} (single precision)", i))
            .with_group("FPU Single"));
    }

    // ---- FPU extended registers (xf0-xf15) ----
    for i in 0..16u64 {
        let name = format!("xf{}", i);
        bank.add(Register::new(&name, 32, 0x200 + i * 4)
            .with_description(format!("FPU extended register xf{}", i))
            .with_group("FPU Extended"));
    }

    // ---- FPU double-precision pairs (dr0-dr14, even only) ----
    for i in (0..=14).step_by(2) {
        let name = format!("dr{}", i);
        bank.add(Register::new(&name, 64, 0x200 + i * 4)
            .with_description(format!("FPU double register dr{} (fr{}:fr{})", i, i + 1, i))
            .with_group("FPU Double"));
    }

    // ---- FPU extended double-precision pairs (xd0-xd14) ----
    for i in (0..=14).step_by(2) {
        let name = format!("xd{}", i);
        bank.add(Register::new(&name, 64, 0x200 + i * 4)
            .with_description(format!("FPU extended double register xd{}", i))
            .with_group("FPU Extended Double"));
    }

    // ---- FPU vector registers (fv0, fv4, fv8, fv12) ----
    for i in (0..=12).step_by(4) {
        let name = format!("fv{}", i);
        bank.add(Register::new(&name, 128, 0x200 + i * 4)
            .with_description(format!("FPU vector register fv{}", i))
            .with_group("FPU Vector"));
    }

    // ---- Control registers ----
    bank.add(Register::new("GBR", 32, 0x0400)
        .with_description("Global base register")
        .with_group("Control"));
    bank.add(Register::new("SR", 32, 0x0404)
        .with_description("Status register")
        .with_group("Control"));
    bank.add(Register::new("SSR", 32, 0x0408)
        .with_description("Saved status register")
        .with_group("Control"));
    bank.add(Register::new("SPC", 32, 0x040C)
        .with_description("Saved program counter")
        .with_group("Control"));
    bank.add(Register::new("VBR", 32, 0x0410)
        .with_description("Vector base register")
        .with_group("Control"));
    bank.add(Register::new("SGR", 32, 0x0414)
        .with_description("Saved general register (r15)")
        .with_group("Control"));
    bank.add(Register::new("DBR", 32, 0x0418)
        .with_description("Debug base register")
        .with_group("Control"));

    // ---- SR component fields ----
    bank.add(Register::new("T", 1, 0x0600)
        .with_description("T flag (condition/overflow)")
        .with_group("SR Flags"));
    bank.add(Register::new("S", 1, 0x0601)
        .with_description("S flag (MAC saturation)")
        .with_group("SR Flags"));
    bank.add(Register::new("IMASK", 4, 0x0602)
        .with_description("Interrupt mask")
        .with_group("SR Flags"));
    bank.add(Register::new("Q", 1, 0x0606)
        .with_description("Q flag (division)")
        .with_group("SR Flags"));
    bank.add(Register::new("M", 1, 0x0607)
        .with_description("M flag (division)")
        .with_group("SR Flags"));
    bank.add(Register::new("FD", 1, 0x0608)
        .with_description("FPU disable flag")
        .with_group("SR Flags"));
    bank.add(Register::new("BL", 1, 0x0609)
        .with_description("Exception/interrupt block flag")
        .with_group("SR Flags"));
    bank.add(Register::new("RB", 1, 0x060A)
        .with_description("Register bank flag")
        .with_group("SR Flags"));
    bank.add(Register::new("MD", 1, 0x060B)
        .with_description("Mode flag (privileged/user)")
        .with_group("SR Flags"));

    // ---- System registers ----
    bank.add(Register::new("MACH", 32, 0x0800)
        .with_description("Multiply-accumulate high")
        .with_group("System"));
    bank.add(Register::new("MACL", 32, 0x0804)
        .with_description("Multiply-accumulate low")
        .with_group("System"));
    bank.add(Register::new("PR", 32, 0x0808)
        .with_description("Procedure register (return address)")
        .with_group("System"));
    bank.add(Register::new("PC", 32, 0x080C)
        .with_type(crate::common::RegisterType::PC)
        .with_description("Program counter")
        .with_group("System"));
    bank.add(Register::new("FPSCR", 32, 0x0810)
        .with_description("FPU status/control register")
        .with_group("FPU Control"));
    bank.add(Register::new("FPUL", 32, 0x0814)
        .with_description("FPU communication register")
        .with_group("FPU Control"));

    // ---- FPSCR component fields ----
    bank.add(Register::new("FPSCR_RM", 1, 0x0A00)
        .with_description("FPSCR rounding mode")
        .with_group("FPSCR Flags"));
    bank.add(Register::new("FPSCR_FLAG", 5, 0x0A01)
        .with_description("FPSCR exception flag")
        .with_group("FPSCR Flags"));
    bank.add(Register::new("FPSCR_ENABLE", 5, 0x0A06)
        .with_description("FPSCR exception enable")
        .with_group("FPSCR Flags"));
    bank.add(Register::new("FPSCR_CAUSE", 5, 0x0A0B)
        .with_description("FPSCR exception cause")
        .with_group("FPSCR Flags"));
    bank.add(Register::new("FPSCR_DN", 1, 0x0A10)
        .with_description("FPSCR denormalization mode")
        .with_group("FPSCR Flags"));
    bank.add(Register::new("FPSCR_PR", 1, 0x0A11)
        .with_description("FPSCR precision (0=single, 1=double)")
        .with_group("FPSCR Flags"));
    bank.add(Register::new("FPSCR_SZ", 1, 0x0A12)
        .with_description("FPSCR transfer size (0=32-bit, 1=64-bit)")
        .with_group("FPSCR Flags"));
    bank.add(Register::new("FPSCR_FR", 1, 0x0A13)
        .with_description("FPSCR register bank flag")
        .with_group("FPSCR Flags"));

    bank
}

/// Build the SuperH4 instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Data transfer (integer) ===
        InstructionMnemonic::new("mov"),     // Move register
        InstructionMnemonic::new("mov.b"),   // Move byte
        InstructionMnemonic::new("mov.w"),   // Move word
        InstructionMnemonic::new("mov.l"),   // Move longword
        InstructionMnemonic::new("movua.l"), // Move unaligned longword
        // === Load immediate ===
        InstructionMnemonic::new("movi"),    // Move immediate (8-bit sign-extended)
        InstructionMnemonic::new("movw"),    // Move word (PC-relative load)
        InstructionMnemonic::new("movl"),    // Move long (PC-relative load)
        // === Load effective address ===
        InstructionMnemonic::new("mova"),    // Move effective address
        // === Swap ===
        InstructionMnemonic::new("swap.b"),  // Swap bytes
        InstructionMnemonic::new("swap.w"),  // Swap words
        InstructionMnemonic::new("xtrct"),   // Extract (concatenate halves)
        // === Arithmetic ===
        InstructionMnemonic::new("add"),     // Add
        InstructionMnemonic::new("addc"),    // Add with carry
        InstructionMnemonic::new("addv"),    // Add with overflow check
        InstructionMnemonic::new("sub"),     // Subtract
        InstructionMnemonic::new("subc"),    // Subtract with carry
        InstructionMnemonic::new("subv"),    // Subtract with overflow check
        InstructionMnemonic::new("negc"),    // Negate with carry
        InstructionMnemonic::new("neg"),     // Negate
        InstructionMnemonic::new("dt"),      // Decrement and test
        InstructionMnemonic::new("exts.b"),  // Sign-extend byte
        InstructionMnemonic::new("exts.w"),  // Sign-extend word
        InstructionMnemonic::new("extu.b"),  // Zero-extend byte
        InstructionMnemonic::new("extu.w"),  // Zero-extend word
        // === Multiply ===
        InstructionMnemonic::new("mul.l"),   // Multiply long (32x32->64 MACL)
        InstructionMnemonic::new("muls.w"),  // Multiply signed word
        InstructionMnemonic::new("mulu.w"),  // Multiply unsigned word
        InstructionMnemonic::new("dmuls.l"), // Double-precision multiply signed
        InstructionMnemonic::new("dmulu.l"), // Double-precision multiply unsigned
        InstructionMnemonic::new("mac.l"),   // Multiply-accumulate long
        InstructionMnemonic::new("mac.w"),   // Multiply-accumulate word
        // === Divide ===
        InstructionMnemonic::new("div1"),    // Divide step (1-bit)
        InstructionMnemonic::new("div0s"),   // Divide step 0 (signed)
        InstructionMnemonic::new("div0u"),   // Divide step 0 (unsigned)
        InstructionMnemonic::new("divcl"),   // Divide (software loop helper)
        // === Logical ===
        InstructionMnemonic::new("and"),     // Bitwise AND
        InstructionMnemonic::new("and.b"),   // Bitwise AND byte (immediate)
        InstructionMnemonic::new("or"),      // Bitwise OR
        InstructionMnemonic::new("or.b"),    // Bitwise OR byte (immediate)
        InstructionMnemonic::new("xor"),     // Bitwise XOR
        InstructionMnemonic::new("xor.b"),   // Bitwise XOR byte (immediate)
        InstructionMnemonic::new("not"),     // Bitwise NOT
        InstructionMnemonic::new("tst"),     // Test (AND, set T)
        InstructionMnemonic::new("tst.b"),   // Test byte (immediate)
        // === Shift ===
        InstructionMnemonic::new("shll"),    // Shift logical left (1 bit)
        InstructionMnemonic::new("shll2"),   // Shift logical left (2 bits)
        InstructionMnemonic::new("shll8"),   // Shift logical left (8 bits)
        InstructionMnemonic::new("shll16"),  // Shift logical left (16 bits)
        InstructionMnemonic::new("shlr"),    // Shift logical right (1 bit)
        InstructionMnemonic::new("shlr2"),   // Shift logical right (2 bits)
        InstructionMnemonic::new("shlr8"),   // Shift logical right (8 bits)
        InstructionMnemonic::new("shlr16"),  // Shift logical right (16 bits)
        InstructionMnemonic::new("shar"),    // Shift arithmetic right (1 bit)
        InstructionMnemonic::new("shar2"),   // Shift arithmetic right (2 bits)
        InstructionMnemonic::new("shar8"),   // Shift arithmetic right (8 bits)
        InstructionMnemonic::new("shar16"),  // Shift arithmetic right (16 bits)
        InstructionMnemonic::new("shld"),    // Shift logical (by register)
        InstructionMnemonic::new("shad"),    // Shift arithmetic (by register)
        InstructionMnemonic::new("rotcl"),   // Rotate left through carry
        InstructionMnemonic::new("rotcr"),   // Rotate right through carry
        InstructionMnemonic::new("rotl"),    // Rotate left
        InstructionMnemonic::new("rotr"),    // Rotate right
        // === Compare ===
        InstructionMnemonic::new("cmp/eq"),  // Compare equal
        InstructionMnemonic::new("cmp/hs"),  // Compare higher or same (unsigned)
        InstructionMnemonic::new("cmp/ge"),  // Compare greater or equal (signed)
        InstructionMnemonic::new("cmp/hi"),  // Compare higher (unsigned)
        InstructionMnemonic::new("cmp/gt"),  // Compare greater than (signed)
        InstructionMnemonic::new("cmp/pl"),  // Compare plus
        InstructionMnemonic::new("cmp/pz"),  // Compare plus or zero
        InstructionMnemonic::new("cmp/str"), // Compare equal (byte string)
        InstructionMnemonic::new("cmp/eq"),  // Compare immediate equal
        InstructionMnemonic::new("tst"),     // Test (AND, set T if zero)
        // === Branch ===
        InstructionMnemonic::new("bt"),      // Branch if T=1
        InstructionMnemonic::new("bf"),      // Branch if T=0
        InstructionMnemonic::new("bt/s"),    // Branch if T=1 (delayed)
        InstructionMnemonic::new("bf/s"),    // Branch if T=0 (delayed)
        InstructionMnemonic::new("bra"),     // Branch unconditional
        InstructionMnemonic::new("braf"),    // Branch far (register)
        InstructionMnemonic::new("bsr"),     // Branch to subroutine
        InstructionMnemonic::new("bsrf"),    // Branch to subroutine far (register)
        InstructionMnemonic::new("jmp"),     // Jump
        InstructionMnemonic::new("jsr"),     // Jump to subroutine
        InstructionMnemonic::new("rts"),     // Return from subroutine
        // === System ===
        InstructionMnemonic::new("trapa"),   // Trap always
        InstructionMnemonic::new("nop"),     // No operation
        InstructionMnemonic::new("rte"),     // Return from exception
        InstructionMnemonic::new("sett"),    // Set T flag
        InstructionMnemonic::new("clrt"),    // Clear T flag
        InstructionMnemonic::new("ldc"),     // Load to control register
        InstructionMnemonic::new("ldc.l"),   // Load to control register (memory)
        InstructionMnemonic::new("sts"),     // Store from system register
        InstructionMnemonic::new("sts.l"),   // Store from system register (memory)
        InstructionMnemonic::new("stc"),     // Store from control register
        InstructionMnemonic::new("stc.l"),   // Store from control register (memory)
        // === FPU data transfer ===
        InstructionMnemonic::new("fmov"),    // Move FPU register
        InstructionMnemonic::new("fmov.s"),  // Move single-precision
        InstructionMnemonic::new("fldi0"),   // Load 0.0 to FPU
        InstructionMnemonic::new("fldi1"),   // Load 1.0 to FPU
        InstructionMnemonic::new("fsts"),    // Store FPUL to FPU
        InstructionMnemonic::new("flds"),    // Load FPU to FPUL
        InstructionMnemonic::new("fabs"),    // FPU absolute value
        InstructionMnemonic::new("fneg"),    // FPU negate
        // === FPU arithmetic ===
        InstructionMnemonic::new("fadd"),    // FPU add
        InstructionMnemonic::new("fsub"),    // FPU subtract
        InstructionMnemonic::new("fmul"),    // FPU multiply
        InstructionMnemonic::new("fmac"),    // FPU multiply-accumulate
        InstructionMnemonic::new("fdiv"),    // FPU divide
        InstructionMnemonic::new("fsqrt"),   // FPU square root
        InstructionMnemonic::new("fcmp/eq"), // FPU compare equal
        InstructionMnemonic::new("fcmp/gt"), // FPU compare greater
        // === FPU conversion ===
        InstructionMnemonic::new("float"),   // Convert integer to float
        InstructionMnemonic::new("ftrc"),    // Convert float to integer (truncate)
        InstructionMnemonic::new("fcnvds"),  // Convert double to single (FPUL)
        InstructionMnemonic::new("fcnvsd"),  // Convert single to double (FPUL)
        // === FPU status ===
        InstructionMnemonic::new("fschg"),   // Toggle FPSCR.FR (register bank)
        InstructionMnemonic::new("frchg"),   // Toggle FPSCR.FR (register bank)
        InstructionMnemonic::new("fenv"),    // Set FPU environment
        // === Cache/Prefetch ===
        InstructionMnemonic::new("ocbi"),    // Operand cache block invalidate
        InstructionMnemonic::new("ocbp"),    // Operand cache block purge
        InstructionMnemonic::new("ocbwb"),   // Operand cache block write-back
        InstructionMnemonic::new("pref"),    // Prefetch
        InstructionMnemonic::new("icbi"),    // Instruction cache block invalidate
        // === TLB ===
        InstructionMnemonic::new("ldtlb"),   // Load TLB entry
        InstructionMnemonic::new("ldrc"),    // Load register from context
        // === Sleep ===
        InstructionMnemonic::new("sleep"),   // Sleep / standby
    ]
}

impl ProcessorModule for SuperH4Processor {
    fn name() -> &'static str {
        "SuperH-4"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "SuperH4:LE:32:default",
                "SuperH-4(a) (SH4) little endian",
                "default",
                Endian::Little,
                32,
            )
            .with_instruction_alignment(2)
            .with_pc_register("PC"),
            Language::new(
                "SuperH4:BE:32:default",
                "SuperH-4(a) (SH4) big endian",
                "default",
                Endian::Big,
                32,
            )
            .with_instruction_alignment(2)
            .with_pc_register("PC"),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> {
        build_instructions()
    }

    fn description() -> &'static str {
        "Renesas SuperH SH-4 (SH7750) 32-bit RISC microprocessor"
    }

    fn family() -> &'static str {
        "SuperH"
    }

    fn default_pointer_size() -> u32 {
        32
    }

    fn default_endian() -> Endian {
        Endian::Little
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_superh4_name() {
        assert_eq!(SuperH4Processor::name(), "SuperH-4");
    }

    #[test]
    fn test_superh4_registers() {
        let bank = SuperH4Processor::registers();
        assert!(bank.len() >= 60, "Expected at least 60 registers, got {}", bank.len());
        // General purpose
        assert!(bank.get("r0").is_some());
        assert!(bank.get("r1").is_some());
        assert!(bank.get("r15").is_some());
        // Banked
        assert!(bank.get("R0_BANK").is_some());
        assert!(bank.get("R7_BANK").is_some());
        // FPU
        assert!(bank.get("fr0").is_some());
        assert!(bank.get("fr15").is_some());
        assert!(bank.get("xf0").is_some());
        assert!(bank.get("xf15").is_some());
        assert!(bank.get("dr0").is_some());
        assert!(bank.get("dr14").is_some());
        assert!(bank.get("fv0").is_some());
        assert!(bank.get("fv12").is_some());
        // Control
        assert!(bank.get("GBR").is_some());
        assert!(bank.get("SR").is_some());
        assert!(bank.get("VBR").is_some());
        // System
        assert!(bank.get("MACH").is_some());
        assert!(bank.get("MACL").is_some());
        assert!(bank.get("PR").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("FPSCR").is_some());
        assert!(bank.get("FPUL").is_some());
        // SR flags
        assert!(bank.get("T").is_some());
        assert!(bank.get("S").is_some());
        assert!(bank.get("Q").is_some());
        assert!(bank.get("M").is_some());
        assert!(bank.get("BL").is_some());
        assert!(bank.get("RB").is_some());
    }

    #[test]
    fn test_superh4_register_bits() {
        let bank = SuperH4Processor::registers();
        assert_eq!(bank.get("r0").unwrap().bit_size, 32);
        assert_eq!(bank.get("r15").unwrap().bit_size, 32);
        assert_eq!(bank.get("fr0").unwrap().bit_size, 32);
        assert_eq!(bank.get("dr0").unwrap().bit_size, 64);
        assert_eq!(bank.get("fv0").unwrap().bit_size, 128);
        assert_eq!(bank.get("GBR").unwrap().bit_size, 32);
        assert_eq!(bank.get("SR").unwrap().bit_size, 32);
        assert_eq!(bank.get("PC").unwrap().bit_size, 32);
        assert_eq!(bank.get("T").unwrap().bit_size, 1);
    }

    #[test]
    fn test_superh4_languages() {
        let langs = SuperH4Processor::languages();
        assert!(langs.len() >= 2);
        assert!(langs.iter().any(|l| l.id == "SuperH4:LE:32:default"));
        assert!(langs.iter().any(|l| l.id == "SuperH4:BE:32:default"));
    }

    #[test]
    fn test_superh4_instructions() {
        let insts = SuperH4Processor::instructions();
        assert!(insts.len() > 100);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        // Data transfer
        assert!(texts.contains(&"mov"));
        assert!(texts.contains(&"mov.b"));
        assert!(texts.contains(&"mov.w"));
        assert!(texts.contains(&"mov.l"));
        // Arithmetic
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"addc"));
        assert!(texts.contains(&"addv"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"subc"));
        assert!(texts.contains(&"dt"));
        assert!(texts.contains(&"exts.b"));
        assert!(texts.contains(&"extu.b"));
        // Multiply/Divide
        assert!(texts.contains(&"mul.l"));
        assert!(texts.contains(&"muls.w"));
        assert!(texts.contains(&"mulu.w"));
        assert!(texts.contains(&"dmuls.l"));
        assert!(texts.contains(&"div1"));
        assert!(texts.contains(&"div0s"));
        assert!(texts.contains(&"div0u"));
        // Logical
        assert!(texts.contains(&"and"));
        assert!(texts.contains(&"or"));
        assert!(texts.contains(&"xor"));
        assert!(texts.contains(&"not"));
        assert!(texts.contains(&"tst"));
        // Shift
        assert!(texts.contains(&"shll"));
        assert!(texts.contains(&"shlr"));
        assert!(texts.contains(&"shar"));
        assert!(texts.contains(&"shld"));
        assert!(texts.contains(&"shad"));
        assert!(texts.contains(&"rotcl"));
        assert!(texts.contains(&"rotcr"));
        // Compare
        assert!(texts.contains(&"cmp/eq"));
        assert!(texts.contains(&"cmp/hs"));
        assert!(texts.contains(&"cmp/ge"));
        assert!(texts.contains(&"cmp/hi"));
        assert!(texts.contains(&"cmp/gt"));
        assert!(texts.contains(&"cmp/pl"));
        assert!(texts.contains(&"cmp/pz"));
        // Branch
        assert!(texts.contains(&"bt"));
        assert!(texts.contains(&"bf"));
        assert!(texts.contains(&"bt/s"));
        assert!(texts.contains(&"bf/s"));
        assert!(texts.contains(&"bra"));
        assert!(texts.contains(&"bsr"));
        assert!(texts.contains(&"jmp"));
        assert!(texts.contains(&"jsr"));
        assert!(texts.contains(&"rts"));
        // System
        assert!(texts.contains(&"nop"));
        assert!(texts.contains(&"rte"));
        assert!(texts.contains(&"trapa"));
        assert!(texts.contains(&"sleep"));
        assert!(texts.contains(&"ldc"));
        assert!(texts.contains(&"sts"));
        assert!(texts.contains(&"stc"));
        // FPU
        assert!(texts.contains(&"fmov"));
        assert!(texts.contains(&"fmov.s"));
        assert!(texts.contains(&"fadd"));
        assert!(texts.contains(&"fsub"));
        assert!(texts.contains(&"fmul"));
        assert!(texts.contains(&"fdiv"));
        assert!(texts.contains(&"fsqrt"));
        assert!(texts.contains(&"fcmp/eq"));
        assert!(texts.contains(&"fcmp/gt"));
        assert!(texts.contains(&"float"));
        assert!(texts.contains(&"ftrc"));
    }

    #[test]
    fn test_superh4_metadata() {
        assert_eq!(SuperH4Processor::family(), "SuperH");
        assert_eq!(SuperH4Processor::default_pointer_size(), 32);
        assert_eq!(SuperH4Processor::default_endian(), Endian::Little);
    }
}
