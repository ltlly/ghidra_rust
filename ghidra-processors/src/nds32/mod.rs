//! Andes NDS32 (AndeStar V3) Processor Module
//!
//! Supports the NDS32 architecture developed by Andes Technology, a 32-bit
//! RISC ISA used extensively in embedded systems, IoT, and microcontroller
//! applications.
//!
//! ## Architecture overview
//! - 32 general-purpose registers: GR0-GR31
//!   - GR0 (ZERO) = hardwired to zero
//!   - GR1 (TA) = temporary for assembler
//!   - GR28 (FP) = frame pointer
//!   - GR29 (SP) = stack pointer
//!   - GR30 (LP) = link pointer
//!   - GR31 (PC) = program counter
//! - FPU: 16 double-precision (FD0-FD15) and 32 single-precision (FS0-FS31)
//! - DSP: D0-D3 (64-bit), WR0-WR3 (various widths)
//! - System registers: IPC, IPSW, P_P0, O_MD, P_P1, ISB, MSC_CFG, etc.
//!
//! ## Register space layout
//! - GPR (GR0-GR31):      0x0000 - 0x007C  (32-bit each)
//! - FPU double (FD0-FD15): 0x0100 - 0x0178  (64-bit each)
//! - FPU single (FS0-FS31): 0x0200 - 0x027C  (32-bit each)
//! - DSP (D0-D3, WR0-WR3):  0x0300 - 0x034F
//! - System:                0x0400 - 0x04FF

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Andes NDS32 processor struct.
pub struct Nds32Processor;

/// Build the complete NDS32 register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- General-purpose registers GR0-GR31 (32-bit) ----
    for i in 0..32u32 {
        bank.add(Register::new(
            &format!("GR{}", i),
            32,
            (i as u64) * 4,
        ));
    }

    // Register aliases
    bank.add(Register::sub_register("ZERO", 32, 0 * 4, "GR0", 0));
    bank.add(Register::sub_register("TA", 32, 1 * 4, "GR1", 0)); // Temp assembler
    bank.add(Register::sub_register("SP", 32, 29 * 4, "GR29", 0));
    bank.add(Register::sub_register("FP", 32, 28 * 4, "GR28", 0));
    bank.add(Register::sub_register("LP", 32, 30 * 4, "GR30", 0)); // Link pointer
    bank.add(Register::sub_register("PC", 32, 31 * 4, "GR31", 0));
    // Calling convention aliases
    bank.add(Register::sub_register("R0", 32, 0 * 4, "GR0", 0));
    bank.add(Register::sub_register("R1", 32, 1 * 4, "GR1", 0));
    bank.add(Register::sub_register("R2", 32, 2 * 4, "GR2", 0));
    bank.add(Register::sub_register("R3", 32, 3 * 4, "GR3", 0));
    bank.add(Register::sub_register("R4", 32, 4 * 4, "GR4", 0));
    bank.add(Register::sub_register("R5", 32, 5 * 4, "GR5", 0));
    bank.add(Register::sub_register("R6", 32, 6 * 4, "GR6", 0));
    bank.add(Register::sub_register("R7", 32, 7 * 4, "GR7", 0));
    bank.add(Register::sub_register("R8", 32, 8 * 4, "GR8", 0));
    bank.add(Register::sub_register("R9", 32, 9 * 4, "GR9", 0));
    bank.add(Register::sub_register("R10", 32, 10 * 4, "GR10", 0));
    bank.add(Register::sub_register("R11", 32, 11 * 4, "GR11", 0));
    bank.add(Register::sub_register("R12", 32, 12 * 4, "GR12", 0));
    bank.add(Register::sub_register("R13", 32, 13 * 4, "GR13", 0));
    bank.add(Register::sub_register("R14", 32, 14 * 4, "GR14", 0));
    bank.add(Register::sub_register("R15", 32, 15 * 4, "GR15", 0));

    // ---- FPU double-precision registers FD0-FD15 (64-bit) ----
    for i in 0..16u32 {
        bank.add(Register::new(
            &format!("FD{}", i),
            64,
            0x0100 + (i as u64) * 8,
        ));
    }

    // ---- FPU single-precision registers FS0-FS31 (32-bit) ----
    for i in 0..32u32 {
        bank.add(Register::new(
            &format!("FS{}", i),
            32,
            0x0200 + (i as u64) * 4,
        ));
    }

    // ---- DSP accumulator registers D0-D3 (64-bit) ----
    bank.add(Register::new("D0", 64, 0x0300));
    bank.add(Register::new("D0_LO", 32, 0x0300)); // D0 low 32 bits
    bank.add(Register::new("D0_HI", 32, 0x0304)); // D0 high 32 bits
    bank.add(Register::new("D1", 64, 0x0308));
    bank.add(Register::new("D1_LO", 32, 0x0308));
    bank.add(Register::new("D1_HI", 32, 0x030C));
    bank.add(Register::new("D2", 64, 0x0310));
    bank.add(Register::new("D2_LO", 32, 0x0310));
    bank.add(Register::new("D2_HI", 32, 0x0314));
    bank.add(Register::new("D3", 64, 0x0318));
    bank.add(Register::new("D3_LO", 32, 0x0318));
    bank.add(Register::new("D3_HI", 32, 0x031C));

    // ---- DSP working registers WR0-WR3 ----
    bank.add(Register::new("WR0", 32, 0x0320));
    bank.add(Register::new("WR1", 32, 0x0324));
    bank.add(Register::new("WR2", 32, 0x0328));
    bank.add(Register::new("WR3", 32, 0x032C));

    // ---- System registers ----
    bank.add(Register::new("IPC", 32, 0x0400));       // Interrupt PC
    bank.add(Register::new("IPSW", 32, 0x0404));      // Interrupt PSW
    bank.add(Register::new("P_P0", 32, 0x0408));      // Pending interrupt P0
    bank.add(Register::new("O_MD", 32, 0x040C));      // Operation mode
    bank.add(Register::new("P_P1", 32, 0x0410));      // Pending interrupt P1
    bank.add(Register::new("ISB", 32, 0x0414));       // Instruction stream buffer
    bank.add(Register::new("MSC_CFG", 32, 0x0418));   // Misc configuration
    bank.add(Register::new("MSC_LOW", 32, 0x041C));   // Misc low
    bank.add(Register::new("MSC_HIGH", 32, 0x0420));  // Misc high
    bank.add(Register::new("IR0", 32, 0x0424));       // Interrupt request 0
    bank.add(Register::new("IR1", 32, 0x0428));       // Interrupt request 1
    bank.add(Register::new("IR2", 32, 0x042C));       // Interrupt request 2
    bank.add(Register::new("IR3", 32, 0x0430));       // Interrupt request 3
    bank.add(Register::new("IMR", 32, 0x0434));       // Interrupt mask register
    bank.add(Register::new("ISR", 32, 0x0438));       // Interrupt status register
    bank.add(Register::new("IVA", 32, 0x043C));       // Interrupt vector address
    bank.add(Register::new("DMA_CFG", 32, 0x0440));   // DMA configuration
    bank.add(Register::new("CCTL_CFG", 32, 0x0444));  // Cache control config
    bank.add(Register::new("MMU_CFG", 32, 0x0448));   // MMU configuration
    bank.add(Register::new("PSW", 32, 0x044C));       // Program status word
    bank.add(Register::new("ITB", 32, 0x0450));       // Instruction TLB base
    bank.add(Register::new("DTB", 32, 0x0454));       // Data TLB base
    bank.add(Register::new("EVA", 32, 0x0458));       // Exception vector address
    bank.add(Register::new("ITYPE", 32, 0x045C));     // Instruction type / ITYPE
    bank.add(Register::new("IPSW2", 32, 0x0460));     // Interrupt PSW 2
    bank.add(Register::new("IPC2", 32, 0x0464));      // Interrupt PC 2
    bank.add(Register::new("EDM_CFG", 32, 0x0468));   // EDM configuration
    bank.add(Register::new("DEBUG_CFG", 32, 0x046C)); // Debug config
    bank.add(Register::new("BPC0", 32, 0x0470));      // Breakpoint PC 0
    bank.add(Register::new("BPC1", 32, 0x0474));      // Breakpoint PC 1
    bank.add(Register::new("BPC2", 32, 0x0478));      // Breakpoint PC 2
    bank.add(Register::new("BPC3", 32, 0x047C));      // Breakpoint PC 3
    bank.add(Register::new("BPA0", 32, 0x0480));      // Breakpoint address 0
    bank.add(Register::new("BPA1", 32, 0x0484));      // Breakpoint address 1
    bank.add(Register::new("BPA2", 32, 0x0488));      // Breakpoint address 2
    bank.add(Register::new("BPA3", 32, 0x048C));      // Breakpoint address 3
    bank.add(Register::new("BPAM0", 32, 0x0490));     // Breakpoint address mask 0
    bank.add(Register::new("BPAM1", 32, 0x0494));     // Breakpoint address mask 1
    bank.add(Register::new("BPAM2", 32, 0x0498));     // Breakpoint address mask 2
    bank.add(Register::new("BPAM3", 32, 0x049C));     // Breakpoint address mask 3
    bank.add(Register::new("BPV0", 32, 0x04A0));      // Breakpoint value 0
    bank.add(Register::new("BPV1", 32, 0x04A4));      // Breakpoint value 1
    bank.add(Register::new("BPV2", 32, 0x04A8));      // Breakpoint value 2
    bank.add(Register::new("BPV3", 32, 0x04AC));      // Breakpoint value 3
    bank.add(Register::new("BPCID0", 32, 0x04B0));    // Breakpoint config ID 0
    bank.add(Register::new("BPCID1", 32, 0x04B4));    // Breakpoint config ID 1
    bank.add(Register::new("BPCID2", 32, 0x04B8));    // Breakpoint config ID 2
    bank.add(Register::new("BPCID3", 32, 0x04BC));    // Breakpoint config ID 3
    bank.add(Register::new("PFMC0", 32, 0x04C0));     // Performance monitor counter 0
    bank.add(Register::new("PFMC1", 32, 0x04C4));     // Performance monitor counter 1
    bank.add(Register::new("PFM_CTL", 32, 0x04C8));   // Performance monitor control
    bank.add(Register::new("FUCOP_CTL", 32, 0x04D0)); // FPU coprocessor control

    bank
}

/// Build the NDS32 instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Move ===
        InstructionMnemonic::new("movi"),      // Move immediate
        InstructionMnemonic::new("movhi"),     // Move high immediate
        InstructionMnemonic::new("mfsr"),      // Move from system register
        InstructionMnemonic::new("mtsr"),      // Move to system register
        InstructionMnemonic::new("mov"),       // Move register
        InstructionMnemonic::new("mov55"),     // Move for AndeStar V2/V3
        // === Arithmetic ===
        InstructionMnemonic::new("add"),       // Add
        InstructionMnemonic::new("addi"),      // Add immediate
        InstructionMnemonic::new("add_slli"),  // Add with shift left
        InstructionMnemonic::new("sub"),       // Subtract
        InstructionMnemonic::new("subi"),      // Subtract immediate
        InstructionMnemonic::new("mul"),       // Multiply
        InstructionMnemonic::new("muls"),      // Multiply signed
        InstructionMnemonic::new("mulu"),      // Multiply unsigned
        InstructionMnemonic::new("mulr64"),    // Multiply (64-bit result)
        InstructionMnemonic::new("maddr32"),   // Multiply-add
        InstructionMnemonic::new("msubr32"),   // Multiply-subtract
        InstructionMnemonic::new("div"),       // Divide signed
        InstructionMnemonic::new("divr"),      // Divide signed (reverse)
        InstructionMnemonic::new("divs"),      // Divide signed fast
        InstructionMnemonic::new("rem"),       // Remainder signed
        InstructionMnemonic::new("rems"),      // Remainder signed fast
        InstructionMnemonic::new("ave"),       // Average
        InstructionMnemonic::new("abs"),       // Absolute value
        InstructionMnemonic::new("max"),       // Maximum
        InstructionMnemonic::new("min"),       // Minimum
        // === Logical ===
        InstructionMnemonic::new("and"),       // Bitwise AND
        InstructionMnemonic::new("andi"),      // Bitwise AND immediate
        InstructionMnemonic::new("or"),        // Bitwise OR
        InstructionMnemonic::new("ori"),       // Bitwise OR immediate
        InstructionMnemonic::new("xor"),       // Bitwise XOR
        InstructionMnemonic::new("xori"),      // Bitwise XOR immediate
        InstructionMnemonic::new("nor"),       // Bitwise NOR
        InstructionMnemonic::new("not"),       // Bitwise NOT
        // === Shift / Rotate ===
        InstructionMnemonic::new("sll"),       // Shift left logical
        InstructionMnemonic::new("slli"),      // Shift left logical immediate
        InstructionMnemonic::new("srl"),       // Shift right logical
        InstructionMnemonic::new("srli"),      // Shift right logical immediate
        InstructionMnemonic::new("sra"),       // Shift right arithmetic
        InstructionMnemonic::new("srai"),      // Shift right arithmetic immediate
        InstructionMnemonic::new("rotl"),      // Rotate left
        InstructionMnemonic::new("rotr"),      // Rotate right
        InstructionMnemonic::new("rotri"),     // Rotate right immediate
        // === Bit manipulation ===
        InstructionMnemonic::new("bse"),       // Bit set
        InstructionMnemonic::new("bclr"),      // Bit clear
        InstructionMnemonic::new("btgl"),      // Bit toggle
        InstructionMnemonic::new("btst"),      // Bit test
        InstructionMnemonic::new("bswp"),      // Byte swap
        InstructionMnemonic::new("wsbh"),      // Word swap bytes within half-words
        InstructionMnemonic::new("ffb"),       // Find first bit
        InstructionMnemonic::new("ffbi"),      // Find first bit immediate
        InstructionMnemonic::new("ffmism"),    // Find first mismatch
        InstructionMnemonic::new("flmism"),    // Find last mismatch
        InstructionMnemonic::new("clz"),       // Count leading zeros
        // === Compare ===
        InstructionMnemonic::new("cmpeq"),     // Compare equal
        InstructionMnemonic::new("cmpne"),     // Compare not equal
        InstructionMnemonic::new("cmpgt"),     // Compare greater than (signed)
        InstructionMnemonic::new("cmpge"),     // Compare greater equal (signed)
        InstructionMnemonic::new("cmplt"),     // Compare less than (signed)
        InstructionMnemonic::new("cmple"),     // Compare less equal (signed)
        InstructionMnemonic::new("cmpugt"),    // Compare greater than (unsigned)
        InstructionMnemonic::new("cmpuge"),    // Compare greater equal (unsigned)
        InstructionMnemonic::new("cmpult"),    // Compare less than (unsigned)
        InstructionMnemonic::new("cmpule"),    // Compare less equal (unsigned)
        // === Branch ===
        InstructionMnemonic::new("beq"),       // Branch if equal
        InstructionMnemonic::new("bne"),       // Branch if not equal
        InstructionMnemonic::new("bgez"),      // Branch if greater equal zero
        InstructionMnemonic::new("bgtz"),      // Branch if greater than zero
        InstructionMnemonic::new("blez"),      // Branch if less equal zero
        InstructionMnemonic::new("bltz"),      // Branch if less than zero
        InstructionMnemonic::new("bgezal"),    // Branch if >= zero and link
        InstructionMnemonic::new("bltzal"),    // Branch if < zero and link
        InstructionMnemonic::new("beqz"),      // Branch if equal to zero
        InstructionMnemonic::new("bnez"),      // Branch if not equal to zero
        InstructionMnemonic::new("j"),         // Jump
        InstructionMnemonic::new("jal"),       // Jump and link
        InstructionMnemonic::new("jr"),        // Jump register
        InstructionMnemonic::new("jral"),      // Jump register and link
        InstructionMnemonic::new("jrnez"),     // Jump register if not equal zero
        InstructionMnemonic::new("jralnez"),   // Jump register and link if not zero
        InstructionMnemonic::new("ret"),       // Return (jr LP)
        // === Load / Store ===
        InstructionMnemonic::new("lbi"),       // Load byte immediate (signed)
        InstructionMnemonic::new("lhi"),       // Load half-word immediate (signed)
        InstructionMnemonic::new("lwi"),       // Load word immediate
        InstructionMnemonic::new("lbiu"),      // Load byte unsigned immediate
        InstructionMnemonic::new("lhiu"),      // Load half-word unsigned immediate
        InstructionMnemonic::new("lb"),        // Load byte
        InstructionMnemonic::new("lh"),        // Load half-word
        InstructionMnemonic::new("lw"),        // Load word
        InstructionMnemonic::new("lbu"),       // Load byte unsigned
        InstructionMnemonic::new("lhu"),       // Load half-word unsigned
        InstructionMnemonic::new("sbi"),       // Store byte immediate
        InstructionMnemonic::new("shi"),       // Store half-word immediate
        InstructionMnemonic::new("swi"),       // Store word immediate
        InstructionMnemonic::new("sb"),        // Store byte
        InstructionMnemonic::new("sh"),        // Store half-word
        InstructionMnemonic::new("sw"),        // Store word
        InstructionMnemonic::new("pop25"),     // POP multiple (16-bit encoding)
        InstructionMnemonic::new("push25"),    // PUSH multiple (16-bit encoding)
        InstructionMnemonic::new("lmw"),       // Load multiple words
        InstructionMnemonic::new("smw"),       // Store multiple words
        InstructionMnemonic::new("lmwbi"),     // Load multiple words base immediate
        InstructionMnemonic::new("smwbi"),     // Store multiple words base immediate
        // Atomic
        InstructionMnemonic::new("llw"),       // Load linked word
        InstructionMnemonic::new("scw"),       // Store conditional word
        InstructionMnemonic::new("llex"),      // Load linked exclusive
        InstructionMnemonic::new("scex"),      // Store conditional exclusive
        // === System / Privileged ===
        InstructionMnemonic::new("trap"),      // Trap
        InstructionMnemonic::new("teqz"),      // Trap if equal zero
        InstructionMnemonic::new("tnez"),      // Trap if not equal zero
        InstructionMnemonic::new("syscall"),   // System call
        InstructionMnemonic::new("break"),     // Breakpoint
        InstructionMnemonic::new("iret"),      // Interrupt return
        InstructionMnemonic::new("setend_l"),  // Set endianness little
        InstructionMnemonic::new("setend_b"),  // Set endianness big
        InstructionMnemonic::new("setgie_en"), // Set global interrupt enable
        InstructionMnemonic::new("setgie_dis"),// Set global interrupt disable
        InstructionMnemonic::new("dsb"),       // Data synchronization barrier
        InstructionMnemonic::new("isb"),       // Instruction sync barrier
        InstructionMnemonic::new("msync"),     // Memory sync
        InstructionMnemonic::new("isync"),     // Instruction sync
        InstructionMnemonic::new("standby"),   // Standby mode
        InstructionMnemonic::new("cctl"),      // Cache control
        InstructionMnemonic::new("tlbop"),     // TLB operation
        InstructionMnemonic::new("read_implid"),// Read implementation ID
        // === FPU ===
        InstructionMnemonic::new("fadds"),     // FP add single
        InstructionMnemonic::new("faddd"),     // FP add double
        InstructionMnemonic::new("fsubs"),     // FP subtract single
        InstructionMnemonic::new("fsubd"),     // FP subtract double
        InstructionMnemonic::new("fmuls"),     // FP multiply single
        InstructionMnemonic::new("fmuld"),     // FP multiply double
        InstructionMnemonic::new("fdivs"),     // FP divide single
        InstructionMnemonic::new("fdivd"),     // FP divide double
        InstructionMnemonic::new("fmadds"),    // FP fused multiply-add single
        InstructionMnemonic::new("fmaddd"),    // FP fused multiply-add double
        InstructionMnemonic::new("fmsubs"),    // FP fused multiply-sub single
        InstructionMnemonic::new("fmsubd"),    // FP fused multiply-sub double
        InstructionMnemonic::new("fcpynss"),   // FP copy negate sign single
        InstructionMnemonic::new("fcpynsd"),   // FP copy negate sign double
        InstructionMnemonic::new("fabss"),     // FP absolute single
        InstructionMnemonic::new("fabsd"),     // FP absolute double
        InstructionMnemonic::new("fnegs"),     // FP negate single
        InstructionMnemonic::new("fnegd"),     // FP negate double
        InstructionMnemonic::new("fsqrts"),    // FP square root single
        InstructionMnemonic::new("fsqrtd"),    // FP square root double
        InstructionMnemonic::new("fcmpeqs"),   // FP compare equal single
        InstructionMnemonic::new("fcmpeqd"),   // FP compare equal double
        InstructionMnemonic::new("fcmpequs"),  // FP compare equal unordered single
        InstructionMnemonic::new("fcmpequd"),  // FP compare equal unordered double
        InstructionMnemonic::new("fcmplts"),   // FP compare less-than single
        InstructionMnemonic::new("fcmpltd"),   // FP compare less-than double
        InstructionMnemonic::new("fcmpltus"),  // FP compare less-than unord single
        InstructionMnemonic::new("fcmpltud"),  // FP compare less-than unord double
        InstructionMnemonic::new("fcmples"),   // FP compare less-equal single
        InstructionMnemonic::new("fcmpled"),   // FP compare less-equal double
        InstructionMnemonic::new("fcmpleus"),  // FP compare less-equal unord single
        InstructionMnemonic::new("fcmpleud"),  // FP compare less-equal unord double
        InstructionMnemonic::new("fcpyss"),    // FP copy sign single
        InstructionMnemonic::new("fcpysd"),    // FP copy sign double
        InstructionMnemonic::new("fs2d"),      // FP single to double
        InstructionMnemonic::new("fd2s"),      // FP double to single
        InstructionMnemonic::new("fs2si"),     // FP single to signed int
        InstructionMnemonic::new("fd2si"),     // FP double to signed int
        InstructionMnemonic::new("fsi2s"),     // Signed int to FP single
        InstructionMnemonic::new("fsi2d"),     // Signed int to FP double
        InstructionMnemonic::new("fui2s"),     // Unsigned int to FP single
        InstructionMnemonic::new("fui2d"),     // Unsigned int to FP double
        InstructionMnemonic::new("fs2ui"),     // FP single to unsigned int
        InstructionMnemonic::new("fd2ui"),     // FP double to unsigned int
        InstructionMnemonic::new("flts"),      // FP load single
        InstructionMnemonic::new("fltd"),      // FP load double
        InstructionMnemonic::new("fsts"),      // FP store single
        InstructionMnemonic::new("fstd"),      // FP store double
        // FP conditional moves
        InstructionMnemonic::new("fcmovs"),    // FP conditional move single
        InstructionMnemonic::new("fcmovd"),    // FP conditional move double
        // === DSP instructions ===
        InstructionMnemonic::new("smmul"),     // Signed fractional multiply
        InstructionMnemonic::new("smmulu"),    // Signed fractional multiply unsigned
        InstructionMnemonic::new("smmwb"),     // Signed fractional multiply word x half
        InstructionMnemonic::new("smmwbu"),    // Signed fractional multiply word x half unsigned
        InstructionMnemonic::new("smmls"),     // Signed fractional multiply-subtract
        InstructionMnemonic::new("smmlsu"),    // Signed fractional multiply-subtract unsigned
        InstructionMnemonic::new("smmla"),     // Signed fractional multiply-accumulate
        InstructionMnemonic::new("kaddw"),     // Saturating add word
        InstructionMnemonic::new("ksubw"),     // Saturating sub word
        InstructionMnemonic::new("khmul"),     // Saturating half multiply
        InstructionMnemonic::new("kslraw"),    // Saturating shift left right arithmetic word
        InstructionMnemonic::new("rdov"),      // Read overflow flag
        InstructionMnemonic::new("clrov"),     // Clear overflow flag
        // === Performance / Micro-architecture ===
        InstructionMnemonic::new("nop"),       // No operation
        InstructionMnemonic::new("nop16"),     // 16-bit no operation
        InstructionMnemonic::new("dret"),      // Debug return
    ]
}

impl ProcessorModule for Nds32Processor {
    fn name() -> &'static str {
        "Andes NDS32 (AndeStar V3)"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "nds32:LE:32:V2",
                "Andes NDS32 AndeStar V2 (32-bit, little-endian)",
                "V2",
                Endian::Little,
                32,
            ),
            Language::new(
                "nds32:LE:32:V3",
                "Andes NDS32 AndeStar V3 (32-bit, little-endian)",
                "V3",
                Endian::Little,
                32,
            ),
            Language::new(
                "nds32:LE:32:V3M",
                "Andes NDS32 AndeStar V3m (32-bit, little-endian, with MAC)",
                "V3m",
                Endian::Little,
                32,
            ),
            Language::new(
                "nds32:LE:32:V3F",
                "Andes NDS32 AndeStar V3f (32-bit, little-endian, with FPU)",
                "V3f",
                Endian::Little,
                32,
            ),
            Language::new(
                "nds32:BE:32:V3",
                "Andes NDS32 AndeStar V3 (32-bit, big-endian)",
                "V3",
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
    fn test_nds32_name() {
        assert_eq!(Nds32Processor::name(), "Andes NDS32 (AndeStar V3)");
    }

    #[test]
    fn test_nds32_registers() {
        let bank = Nds32Processor::registers();
        assert!(bank.len() > 60, "Expected many registers, got {}", bank.len());
        // GPRs
        for i in 0..32u32 {
            assert!(bank.get(&format!("GR{}", i)).is_some());
        }
        assert!(bank.get("ZERO").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("FP").is_some());
        assert!(bank.get("LP").is_some());
        assert!(bank.get("PC").is_some());
        // FPU
        for i in 0..16u32 {
            assert!(bank.get(&format!("FD{}", i)).is_some());
        }
        for i in 0..32u32 {
            assert!(bank.get(&format!("FS{}", i)).is_some());
        }
        // DSP
        assert!(bank.get("D0").is_some());
        assert!(bank.get("D3").is_some());
        assert!(bank.get("WR0").is_some());
        assert!(bank.get("WR3").is_some());
        // System
        assert!(bank.get("IPC").is_some());
        assert!(bank.get("IPSW").is_some());
        assert!(bank.get("P_P0").is_some());
        assert!(bank.get("O_MD").is_some());
        assert!(bank.get("ISB").is_some());
        assert!(bank.get("MSC_CFG").is_some());
        assert!(bank.get("PSW").is_some());
    }

    #[test]
    fn test_nds32_register_bits() {
        let bank = Nds32Processor::registers();
        assert_eq!(bank.get("GR0").unwrap().bit_size, 32);
        assert_eq!(bank.get("IPC").unwrap().bit_size, 32);
        assert_eq!(bank.get("FD0").unwrap().bit_size, 64);
        assert_eq!(bank.get("FS0").unwrap().bit_size, 32);
        assert_eq!(bank.get("D0").unwrap().bit_size, 64);
        assert_eq!(bank.get("WR0").unwrap().bit_size, 32);
    }

    #[test]
    fn test_nds32_aliases() {
        let bank = Nds32Processor::registers();
        assert_eq!(bank.get("ZERO").unwrap().parent.as_deref(), Some("GR0"));
        assert_eq!(bank.get("SP").unwrap().parent.as_deref(), Some("GR29"));
        assert_eq!(bank.get("FP").unwrap().parent.as_deref(), Some("GR28"));
        assert_eq!(bank.get("LP").unwrap().parent.as_deref(), Some("GR30"));
        assert_eq!(bank.get("PC").unwrap().parent.as_deref(), Some("GR31"));
    }

    #[test]
    fn test_nds32_languages() {
        let langs = Nds32Processor::languages();
        assert!(langs.len() >= 3);
        assert!(langs.iter().any(|l| l.id == "nds32:LE:32:V3"));
        assert!(langs.iter().any(|l| l.id == "nds32:LE:32:V3F"));
        assert!(langs.iter().any(|l| l.id == "nds32:BE:32:V3" && l.endian == Endian::Big));
    }

    #[test]
    fn test_nds32_instructions() {
        let insts = Nds32Processor::instructions();
        assert!(insts.len() > 80);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"mul"));
        assert!(texts.contains(&"div"));
        assert!(texts.contains(&"lw"));
        assert!(texts.contains(&"sw"));
        assert!(texts.contains(&"beq"));
        assert!(texts.contains(&"bne"));
        assert!(texts.contains(&"j"));
        assert!(texts.contains(&"jal"));
        assert!(texts.contains(&"ret"));
        assert!(texts.contains(&"fadds"));
        assert!(texts.contains(&"fdivd"));
        assert!(texts.contains(&"iret"));
        assert!(texts.contains(&"syscall"));
        assert!(texts.contains(&"smmul"));
        assert!(texts.contains(&"llw"));
        assert!(texts.contains(&"scw"));
    }
}
