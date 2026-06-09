//! Microchip PIC Processor Module
//!
//! Supports PIC16, PIC18, PIC24, and dsPIC33 families.
//!
//! The Microchip PIC (Peripheral Interface Controller) is an 8/16-bit RISC
//! microcontroller family ranging from the 8-bit PIC12/PIC16/PIC18 up to the
//! 16-bit PIC24/dsPIC33 with DSP extensions. Known for its Harvard
//! architecture, banked register files, and single-instruction cycle execution.
//!
//! ## Register space layout
//!
//! ### PIC16 (8-bit baseline/mid-range)
//! - WREG (Working register):        0x0000  (8-bit)
//! - STATUS register:                0x0001  (8-bit)
//! - FSR (File Select Register):     0x0002  (8-bit)
//! - INDF (INDirect File):           0x0003  (8-bit, pseudo-register)
//! - PCL (Program Counter Low):      0x0004  (8-bit)
//! - PCLATH (PC Latch High):         0x0005  (8-bit)
//! - Banked GPR file:                0x0010 - 0x00FF
//!
//! ### PIC18 (8-bit high-end)
//! - As PIC16 plus:
//! - WREG, STATUS (same)
//! - BSR (Bank Select Register):     0x0006  (8-bit)
//! - FSR0-H/L, FSR1-H/L, FSR2-H/L:  0x0008 - 0x000F (each 12 or 16-bit)
//! - PC (Program Counter):           0x0010 (21-bit)
//! - TOS (Top-of-Stack):             0x0014 (21-bit)
//! - PRODH/PRODL (Multiply):         0x0018 (16-bit product)
//! - TABLAT (Table Latch):           0x001A (8-bit)
//!
//! ### PIC24 / dsPIC33 (16-bit)
//! - W0-W15 (16 x 16-bit GP registers): 0x0020 - 0x003F
//!   - W0-W13: general-purpose
//!   - W14: Stack Frame Pointer
//!   - W15: Stack Pointer
//! - SR (CPU Status Register, 16-bit): 0x0040
//! - SPLIM (Stack Pointer Limit):      0x0042
//! - PCL/PCH (Program Counter):        0x0044
//! - TBLPAG (Table Page):             0x0046
//! - PSVPAG (Program Space Visibility):0x0048
//! - RCOUNT (REPEAT loop counter):     0x004A
//! - DCOUNT (DO loop counter):         0x004C
//! - DOSTART (DO loop start):          0x004E
//! - DOEND (DO loop end):             0x0052
//! - CORCON (Core Control):           0x0056
//!
//! ### dsPIC DSP accumulator registers
//! - ACCA (40-bit accumulator A):     0x0060
//! - ACCAH/ACCAL:                     0x0060/0x0062
//! - ACCB (40-bit accumulator B):     0x0068
//! - ACCBH/ACCBL:                     0x0068/0x006A

pub mod language_provider;

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Microchip PIC processor struct.
pub struct PicProcessor;

/// Build the complete PIC register bank (PIC24/dsPIC33 as default).
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ========================================================================
    // PIC16 / PIC18 registers (8-bit era)
    // ========================================================================

    // Core working register
    bank.add(Register::new("WREG", 8, 0x0000)); // Working register

    // STATUS register
    bank.add(Register::new("STATUS", 8, 0x0001));
    bank.add(Register::sub_register("C", 1, 0x0001, "STATUS", 0)); // Carry / Borrow
    bank.add(Register::sub_register("DC", 1, 0x0001, "STATUS", 1)); // Digit Carry
    bank.add(Register::sub_register("Z", 1, 0x0001, "STATUS", 2)); // Zero
    bank.add(Register::sub_register("N", 1, 0x0001, "STATUS", 3)); // Negative (PIC18)
    bank.add(Register::sub_register("OV", 1, 0x0001, "STATUS", 4)); // Overflow (PIC18)
    bank.add(Register::sub_register("RP0", 1, 0x0001, "STATUS", 5)); // Register Bank bit 0 (PIC16)
    bank.add(Register::sub_register("RP1", 1, 0x0001, "STATUS", 6)); // Register Bank bit 1 (PIC16)
    bank.add(Register::sub_register("IRP", 1, 0x0001, "STATUS", 7)); // Indirect addressing bank

    // File Select Register + Indirect
    bank.add(Register::new("FSR", 8, 0x0002)); // File Select Register
    bank.add(Register::new("INDF", 8, 0x0003)); // Indirect File (not a physical register)

    // Program Counter and latch
    bank.add(Register::new("PCL", 8, 0x0004)); // Program Counter Low
    bank.add(Register::new("PCLATH", 8, 0x0005)); // Program Counter Latch High

    // ---- PIC18 extensions ----
    bank.add(Register::new("BSR", 8, 0x0006)); // Bank Select Register (PIC18)

    // PIC18: FSR0, FSR1, FSR2 (each with high/low byte)
    bank.add(Register::new("FSR0H", 8, 0x0008));
    bank.add(Register::new("FSR0L", 8, 0x0009));
    bank.add(Register::new("FSR0", 16, 0x0008)); // Combined
    bank.add(Register::new("FSR1H", 8, 0x000A));
    bank.add(Register::new("FSR1L", 8, 0x000B));
    bank.add(Register::new("FSR1", 16, 0x000A)); // Combined
    bank.add(Register::new("FSR2H", 8, 0x000C));
    bank.add(Register::new("FSR2L", 8, 0x000D));
    bank.add(Register::new("FSR2", 16, 0x000C)); // Combined

    // PIC18 indirect file registers
    bank.add(Register::new("INDF0", 8, 0x0010)); // Indirect through FSR0
    bank.add(Register::new("POSTINC0", 8, 0x0011)); // Post-increment through FSR0
    bank.add(Register::new("POSTDEC0", 8, 0x0012)); // Post-decrement through FSR0
    bank.add(Register::new("PREINC0", 8, 0x0013)); // Pre-increment through FSR0
    bank.add(Register::new("PLUSW0", 8, 0x0014)); // FSR0 + WREG indirect

    bank.add(Register::new("INDF1", 8, 0x0015)); // Indirect through FSR1
    bank.add(Register::new("POSTINC1", 8, 0x0016));
    bank.add(Register::new("POSTDEC1", 8, 0x0017));
    bank.add(Register::new("PREINC1", 8, 0x0018));
    bank.add(Register::new("PLUSW1", 8, 0x0019));

    bank.add(Register::new("INDF2", 8, 0x001A));
    bank.add(Register::new("POSTINC2", 8, 0x001B));
    bank.add(Register::new("POSTDEC2", 8, 0x001C));
    bank.add(Register::new("PREINC2", 8, 0x001D));
    bank.add(Register::new("PLUSW2", 8, 0x001E));

    // PIC18: Full program counter (21-bit)
    bank.add(Register::new("PC", 21, 0x0020));
    bank.add(Register::new("TOS", 21, 0x0024)); // Top Of Stack
    bank.add(Register::new("TOSH", 8, 0x0024));
    bank.add(Register::new("TOSL", 8, 0x0025));
    bank.add(Register::new("TOSU", 8, 0x0026));

    // PIC18: Multiply product (PROD)
    bank.add(Register::new("PRODL", 8, 0x0028));
    bank.add(Register::new("PRODH", 8, 0x0029));
    bank.add(Register::new("PROD", 16, 0x0028)); // Combined product

    // PIC18: Table Latch
    bank.add(Register::new("TABLAT", 8, 0x002A));

    // PIC18: Stack pointer
    bank.add(Register::new("STKPTR", 5, 0x002C));

    // ========================================================================
    // PIC24 / dsPIC33 registers (16-bit era)
    // ========================================================================

    // Working registers W0-W15 (16-bit each)
    for i in 0u32..16 {
        let offset = 0x0030 + (i as u64) * 2;
        let name = format!("W{}", i);
        bank.add(Register::new(&name, 16, offset));
    }

    // Register aliases
    bank.add(Register::sub_register("WREG_24", 16, 0x0030, "W0", 0)); // W0 = WREG on PIC24

    // Corcon (always W0) aliases on 8-bit PIC
    // W14 and W15 have special names on PIC24
    bank.add(Register::sub_register("FP", 16, 0x0030 + 14 * 2, "W14", 0)); // Frame Pointer
    bank.add(Register::sub_register("SP", 16, 0x0030 + 15 * 2, "W15", 0)); // Stack Pointer

    // CPU Status Register (lower 16-bit)
    bank.add(Register::new("SR", 16, 0x0050)); // CPU Status Register

    // SR bit fields (PIC24/dsPIC33)
    bank.add(Register::sub_register("C_SR", 1, 0x0050, "SR", 0)); // Carry
    bank.add(Register::sub_register("Z_SR", 1, 0x0050, "SR", 1)); // Zero
    bank.add(Register::sub_register("OV_SR", 1, 0x0050, "SR", 2)); // Overflow
    bank.add(Register::sub_register("N_SR", 1, 0x0050, "SR", 3)); // Negative
    bank.add(Register::sub_register("RA", 1, 0x0050, "SR", 4)); // Repeat Active
    bank.add(Register::sub_register("DC_SR", 1, 0x0050, "SR", 8)); // Digit Carry
    bank.add(Register::sub_register("DA", 1, 0x0050, "SR", 9)); // DO Loop Active
    bank.add(Register::sub_register("IPL", 3, 0x0050, "SR", 5)); // Interrupt Priority Level

    // CPU Status Register Upper
    bank.add(Register::new("CORCON", 16, 0x0052)); // Core Control Register (lower SR bits)

    // CORCON bit fields
    bank.add(Register::sub_register("PSV", 1, 0x0052, "CORCON", 2)); // Program Space Visibility
    bank.add(Register::sub_register("SATA", 1, 0x0052, "CORCON", 4)); // ACCA Saturation
    bank.add(Register::sub_register("SATB", 1, 0x0052, "CORCON", 5)); // ACCB Saturation
    bank.add(Register::sub_register("SATDW", 1, 0x0052, "CORCON", 6)); // Data Space Write Saturation
    bank.add(Register::sub_register("IF", 1, 0x0052, "CORCON", 0)); // Integer/Fractional mode (dsPIC)
    bank.add(Register::sub_register("US", 1, 0x0052, "CORCON", 12)); // DSP Multiply Unsigned/Signed
    bank.add(Register::sub_register("EDT", 1, 0x0052, "CORCON", 11)); // Early DO termination

    // Stack Pointer Limit
    bank.add(Register::new("SPLIM", 16, 0x0054));

    // Program Counter
    bank.add(Register::new("PCL_24", 16, 0x0056)); // Program Counter Low
    bank.add(Register::new("PCH_24", 8, 0x0058)); // Program Counter High (upper 8 bits)
    bank.add(Register::new("PC_24", 24, 0x0056)); // Combined 24-bit PC

    // Program Space Visibility Page (PIC24)
    bank.add(Register::new("TBLPAG", 8, 0x005A)); // Table Page
    bank.add(Register::new("PSVPAG", 8, 0x005B)); // PSV Page

    // DO loop registers
    bank.add(Register::new("RCOUNT", 14, 0x0060)); // REPEAT Count
    bank.add(Register::new("DCOUNT", 14, 0x0062)); // DO Count
    bank.add(Register::new("DOSTARTL", 16, 0x0064)); // DO loop start (low)
    bank.add(Register::new("DOENDL", 16, 0x0068)); // DO loop end (low)

    // ========================================================================
    // dsPIC DSP accumulator registers
    // ========================================================================
    // ACCA - 40-bit accumulator A
    bank.add(Register::new("ACCA", 40, 0x0080));
    bank.add(Register::new("ACCAL", 16, 0x0080)); // Lower 16 bits
    bank.add(Register::new("ACCAH", 16, 0x0082)); // Upper 16 bits
    bank.add(Register::new("ACCAU", 8, 0x0084)); // Guard bits (upper 8)

    // ACCB - 40-bit accumulator B
    bank.add(Register::new("ACCB", 40, 0x0088));
    bank.add(Register::new("ACCBL", 16, 0x0088)); // Lower 16 bits
    bank.add(Register::new("ACCBH", 16, 0x008A)); // Upper 16 bits
    bank.add(Register::new("ACCBU", 8, 0x008C)); // Guard bits (upper 8)

    bank
}

/// Build the PIC instruction mnemonics (PIC16 + PIC18 + PIC24 + dsPIC).
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === PIC16 Baseline/Mid-range ===
        // Byte-oriented file register operations
        InstructionMnemonic::new("addwf"),    // ADD W and f
        InstructionMnemonic::new("andwf"),    // AND W with f
        InstructionMnemonic::new("clrf"),     // CLeaR f
        InstructionMnemonic::new("clrw"),     // CLeaR W
        InstructionMnemonic::new("comf"),     // COMplement f
        InstructionMnemonic::new("decf"),     // DECrement f
        InstructionMnemonic::new("decfsz"),   // DECrement f, Skip if 0
        InstructionMnemonic::new("incf"),     // INCrement f
        InstructionMnemonic::new("incfsz"),   // INCrement f, Skip if 0
        InstructionMnemonic::new("iorwf"),    // Inclusive OR W with f
        InstructionMnemonic::new("movf"),     // MOVe f
        InstructionMnemonic::new("movwf"),    // MOVe W to f
        InstructionMnemonic::new("nop"),      // No OPeration
        InstructionMnemonic::new("rlf"),      // Rotate Left f through Carry
        InstructionMnemonic::new("rrf"),      // Rotate Right f through Carry
        InstructionMnemonic::new("subwf"),    // SUBtract W from f
        InstructionMnemonic::new("swapf"),    // SWAP nibbles in f
        InstructionMnemonic::new("xorwf"),    // eXclusive OR W with f
        // Bit-oriented
        InstructionMnemonic::new("bcf"),      // Bit Clear f
        InstructionMnemonic::new("bsf"),      // Bit Set f
        InstructionMnemonic::new("btfsc"),    // Bit Test f, Skip if Clear
        InstructionMnemonic::new("btfss"),    // Bit Test f, Skip if Set
        // Literal/control
        InstructionMnemonic::new("addlw"),    // ADD Literal to W
        InstructionMnemonic::new("andlw"),    // AND Literal with W
        InstructionMnemonic::new("call"),     // CALL subroutine
        InstructionMnemonic::new("clrwdt"),   // CLeaR WatchDog Timer
        InstructionMnemonic::new("goto"),     // GOTO address
        InstructionMnemonic::new("iorlw"),    // Inclusive OR Literal with W
        InstructionMnemonic::new("movlw"),    // MOVe Literal to W
        InstructionMnemonic::new("retfie"),   // RETurn From Interrupt and Enable
        InstructionMnemonic::new("retlw"),    // RETurn with Literal in W
        InstructionMnemonic::new("return"),   // RETurn from subroutine
        InstructionMnemonic::new("sleep"),    // SLEEP (go into standby)
        InstructionMnemonic::new("sublw"),    // SUBtract Literal from W
        InstructionMnemonic::new("xorlw"),    // eXclusive OR Literal with W
        // === PIC18 Extended Instructions ===
        InstructionMnemonic::new("addwfc"),   // ADD W and f with Carry
        InstructionMnemonic::new("addfsr"),   // ADD literal to FSR
        InstructionMnemonic::new("bc"),       // Branch if Carry
        InstructionMnemonic::new("bcf_b"),    // BCF (PIC18 encoding)
        InstructionMnemonic::new("bn"),       // Branch if Negative
        InstructionMnemonic::new("bnc"),      // Branch if Not Carry
        InstructionMnemonic::new("bnn"),      // Branch if Not Negative
        InstructionMnemonic::new("bnov"),     // Branch if Not Overflow
        InstructionMnemonic::new("bnz"),      // Branch if Not Zero
        InstructionMnemonic::new("bov"),      // Branch if Overflow
        InstructionMnemonic::new("bra"),      // BRAnch (unconditional)
        InstructionMnemonic::new("bz"),       // Branch if Zero
        InstructionMnemonic::new("cpfseq"),   // ComPare f with W, Skip if EQual
        InstructionMnemonic::new("cpfsgt"),   // ComPare f with W, Skip if Greater Than
        InstructionMnemonic::new("cpfslt"),   // ComPare f with W, Skip if Less Than
        InstructionMnemonic::new("daw"),      // Decimal Adjust Wreg (PIC18)
        InstructionMnemonic::new("infsnz"),   // INCrement f, Skip if Not Zero
        InstructionMnemonic::new("lfsr"),     // Load FSR with literal
        InstructionMnemonic::new("movff"),    // MOVe f to f (two-address)
        InstructionMnemonic::new("movlb"),    // MOVe Literal to BSR
        InstructionMnemonic::new("mulwf"),    // MULtiply W with f (PIC18)
        InstructionMnemonic::new("negf"),     // NEGate f
        InstructionMnemonic::new("push_pic"), // PUSH (PIC18)
        InstructionMnemonic::new("pop_pic"),  // POP (PIC18)
        InstructionMnemonic::new("rcall"),    // Relative CALL (PIC18)
        InstructionMnemonic::new("reset_pic"),// RESET (PIC18)
        InstructionMnemonic::new("setf"),     // SET f to all ones
        InstructionMnemonic::new("subfwb"),   // SUBtract f from W with Borrow
        InstructionMnemonic::new("subwfb"),   // SUBtract W from f with Borrow
        InstructionMnemonic::new("tblrd"),    // TaBLe ReaD (PIC18)
        InstructionMnemonic::new("tblrd_postinc"), // Table Read with post-increment
        InstructionMnemonic::new("tblrd_postdec"), // Table Read with post-decrement
        InstructionMnemonic::new("tblrd_preinc"),  // Table Read with pre-increment
        InstructionMnemonic::new("tblwt"),    // TaBLe WriTe (PIC18)
        InstructionMnemonic::new("tblwt_postinc"), // Table Write with post-increment
        InstructionMnemonic::new("tblwt_postdec"), // Table Write with post-decrement
        InstructionMnemonic::new("tblwt_preinc"),  // Table Write with pre-increment
        InstructionMnemonic::new("tstfsz"),   // TeST f, Skip if Zero
        // === PIC24 / dsPIC33 (16-bit) ===
        // Data movement
        InstructionMnemonic::new("mov"),
        InstructionMnemonic::new("mov_b"),
        InstructionMnemonic::new("mov_w"),
        InstructionMnemonic::new("mov_mapped"), // MOV to/from mapped SFR
        InstructionMnemonic::new("mov_r"),       // MOV register (PIC24 encoding)
        InstructionMnemonic::new("swap"),         // SWAP bytes in register
        // Arithmetic
        InstructionMnemonic::new("add"),
        InstructionMnemonic::new("addc"),
        InstructionMnemonic::new("add_wb"),      // ADD with byte access
        InstructionMnemonic::new("sub"),
        InstructionMnemonic::new("subb"),
        InstructionMnemonic::new("subr"),        // SUBtract f from W (reversed)
        InstructionMnemonic::new("subbr"),       // SUBtract f from W with Borrow (reversed)
        InstructionMnemonic::new("mul"),          // MULtiply (unsigned)
        InstructionMnemonic::new("mul_ss"),       // MULtiply Signed*Signed
        InstructionMnemonic::new("mul_su"),       // MULtiply Signed*Unsigned
        InstructionMnemonic::new("mul_uu"),       // MULtiply Unsigned*Unsigned
        InstructionMnemonic::new("div_16"),       // DIVide (16/16 -> 16:16)
        InstructionMnemonic::new("div_s"),        // DIVide Signed
        InstructionMnemonic::new("div_u"),        // DIVide Unsigned
        InstructionMnemonic::new("inc"),
        InstructionMnemonic::new("inc2"),
        InstructionMnemonic::new("dec"),
        InstructionMnemonic::new("dec2"),
        InstructionMnemonic::new("neg"),
        InstructionMnemonic::new("com"),
        InstructionMnemonic::new("se"),          // Sign Extend
        InstructionMnemonic::new("ze"),          // Zero Extend
        // Logical
        InstructionMnemonic::new("and"),
        InstructionMnemonic::new("ior"),
        InstructionMnemonic::new("xor"),
        // Shift/Rotate
        InstructionMnemonic::new("sl"),          // Shift Left
        InstructionMnemonic::new("lsr"),         // Logical Shift Right (PIC24)
        InstructionMnemonic::new("asr"),         // Arithmetic Shift Right
        InstructionMnemonic::new("rlc"),         // Rotate Left through Carry
        InstructionMnemonic::new("rrc"),         // Rotate Right through Carry
        InstructionMnemonic::new("rlnc"),        // Rotate Left (No Carry)
        InstructionMnemonic::new("rrnc"),        // Rotate Right (No Carry)
        // Bit operations
        InstructionMnemonic::new("bclr"),
        InstructionMnemonic::new("bset"),
        InstructionMnemonic::new("btg"),         // Bit Toggle
        InstructionMnemonic::new("btst"),        // Bit Test
        InstructionMnemonic::new("btsc"),        // Bit Test and Skip if Clear
        InstructionMnemonic::new("btss"),        // Bit Test and Skip if Set
        InstructionMnemonic::new("ff1l"),        // Find First 1 from Left
        InstructionMnemonic::new("ff1r"),        // Find First 1 from Right
        InstructionMnemonic::new("fbc"),         // Find Bit Changed
        InstructionMnemonic::new("fbcl"),        // Find Bit Changed from Left
        // Branch
        InstructionMnemonic::new("bra_c"),       // Carry set
        InstructionMnemonic::new("bra_nc"),      // Carry clear
        InstructionMnemonic::new("bra_z"),       // Zero set
        InstructionMnemonic::new("bra_nz"),      // Zero clear
        InstructionMnemonic::new("bra_n"),       // Negative
        InstructionMnemonic::new("bra_nn"),      // Not negative
        InstructionMnemonic::new("bra_ov"),      // Overflow
        InstructionMnemonic::new("bra_nov"),     // No overflow
        InstructionMnemonic::new("bra_ge"),      // Greater or Equal (signed)
        InstructionMnemonic::new("bra_lt"),      // Less Than (signed)
        InstructionMnemonic::new("bra_gt"),      // Greater Than (signed)
        InstructionMnemonic::new("bra_le"),      // Less or Equal (signed)
        InstructionMnemonic::new("bra_geu"),     // Greater or Equal Unsigned
        InstructionMnemonic::new("bra_ltu"),     // Less Than Unsigned
        InstructionMnemonic::new("bra_gtu"),     // Greater Than Unsigned
        InstructionMnemonic::new("bra_leu"),     // Less or Equal Unsigned
        InstructionMnemonic::new("bra_w"),       // Unconditional (PIC24 wide)
        InstructionMnemonic::new("goto_24"),     // GOTO (PIC24)
        InstructionMnemonic::new("call_24"),     // CALL (PIC24)
        // Conditional executions
        InstructionMnemonic::new("cp"),           // ComPare
        InstructionMnemonic::new("cp0"),          // ComPare with 0
        InstructionMnemonic::new("cpb"),          // ComPare f with W (byte)
        InstructionMnemonic::new("cpseq"),        // ComPare and Skip if EQual
        InstructionMnemonic::new("cpsne"),        // ComPare and Skip if Not Equal
        InstructionMnemonic::new("cpsgt"),        // ComPare and Skip if Greater Than
        InstructionMnemonic::new("cpslt"),        // ComPare and Skip if Less Than
        // Subroutine / Control
        InstructionMnemonic::new("rcall_24"),     // Relative CALL (PIC24)
        InstructionMnemonic::new("retfie_24"),    // Return from interrupt
        InstructionMnemonic::new("retlw_24"),     // Return with literal
        InstructionMnemonic::new("return_24"),    // Return
        InstructionMnemonic::new("nop_24"),       // NOP
        InstructionMnemonic::new("nopr"),         // NOP register (PIC24 extended NOP)
        InstructionMnemonic::new("pwrsav"),       // Enter Power Save
        InstructionMnemonic::new("disi"),         // DISable Interrupts temporarily
        InstructionMnemonic::new("repeat"),       // REPEAT next instruction
        InstructionMnemonic::new("do"),           // DO loop
        // DSP (dsPIC33)
        InstructionMnemonic::new("mac"),          // Multiply ACcumulate
        InstructionMnemonic::new("msc"),          // Multiply and Subtract from ACCumulator
        InstructionMnemonic::new("mpy"),          // MultiPlY
        InstructionMnemonic::new("mpy_n"),        // MPY with null destination
        InstructionMnemonic::new("ed"),           // Euclidean Distance
        InstructionMnemonic::new("edac"),         // Euclidean Distance and Accumulate
        InstructionMnemonic::new("clr_acc"),      // CLeaR ACCumulator
        InstructionMnemonic::new("lac"),          // Load ACCumulator
        InstructionMnemonic::new("sac"),          // Store ACCumulator
        InstructionMnemonic::new("sac_r"),        // Store ACCumulator Rounded
        InstructionMnemonic::new("sftac"),        // ShifT ACCumulator
    ]
}

impl ProcessorModule for PicProcessor {
    fn name() -> &'static str {
        "Microchip PIC"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "pic:LE:8:PIC16",
                "Microchip PIC16 (8-bit, little-endian, mid-range)",
                "PIC16",
                Endian::Little,
                16,
            ),
            Language::new(
                "pic:LE:8:PIC18",
                "Microchip PIC18 (8-bit, little-endian, high-end)",
                "PIC18",
                Endian::Little,
                16,
            ),
            Language::new(
                "pic:LE:16:PIC24",
                "Microchip PIC24 (16-bit, little-endian, MCU)",
                "PIC24",
                Endian::Little,
                24,
            ),
            Language::new(
                "pic:LE:16:dsPIC33",
                "Microchip dsPIC33 (16-bit, little-endian, DSP)",
                "dsPIC33",
                Endian::Little,
                24,
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
    fn test_pic_name() {
        assert_eq!(PicProcessor::name(), "Microchip PIC");
    }

    #[test]
    fn test_pic_registers() {
        let bank = PicProcessor::registers();
        assert!(bank.len() > 60, "Expected many registers, got {}", bank.len());
        // PIC16 core
        assert!(bank.get("WREG").is_some());
        assert!(bank.get("STATUS").is_some());
        assert!(bank.get("FSR").is_some());
        assert!(bank.get("PCL").is_some());
        assert!(bank.get("PCLATH").is_some());
        // PIC18
        assert!(bank.get("BSR").is_some());
        assert!(bank.get("FSR0").is_some());
        assert!(bank.get("FSR1").is_some());
        assert!(bank.get("FSR2").is_some());
        assert!(bank.get("PROD").is_some());
        assert!(bank.get("TABLAT").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("TOS").is_some());
        // PIC24/33
        assert!(bank.get("W0").is_some());
        assert!(bank.get("W15").is_some());
        assert!(bank.get("FP").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("SR").is_some());
        assert!(bank.get("CORCON").is_some());
        assert!(bank.get("SPLIM").is_some());
        assert!(bank.get("TBLPAG").is_some());
        // DSP
        assert!(bank.get("ACCA").is_some());
        assert!(bank.get("ACCB").is_some());
    }

    #[test]
    fn test_pic_status_flags() {
        let bank = PicProcessor::registers();
        let c = bank.get("C").unwrap();
        assert_eq!(c.parent.as_deref(), Some("STATUS"));
        assert_eq!(c.lsb, 0);

        let dc = bank.get("DC").unwrap();
        assert_eq!(dc.lsb, 1);

        let z = bank.get("Z").unwrap();
        assert_eq!(z.lsb, 2);
    }

    #[test]
    fn test_pic24_sr_flags() {
        let bank = PicProcessor::registers();
        let z_sr = bank.get("Z_SR").unwrap();
        assert_eq!(z_sr.parent.as_deref(), Some("SR"));
        assert_eq!(z_sr.lsb, 1);
    }

    #[test]
    fn test_pic_corcon_flags() {
        let bank = PicProcessor::registers();
        let if_bit = bank.get("IF").unwrap();
        assert_eq!(if_bit.parent.as_deref(), Some("CORCON"));
        assert_eq!(if_bit.lsb, 0);

        let us = bank.get("US").unwrap();
        assert_eq!(us.lsb, 12);
    }

    #[test]
    fn test_pic_register_bits() {
        let bank = PicProcessor::registers();
        assert_eq!(bank.get("W0").unwrap().bit_size, 16);
        assert_eq!(bank.get("WREG").unwrap().bit_size, 8);
        assert_eq!(bank.get("ACCA").unwrap().bit_size, 40);
        assert_eq!(bank.get("PC_24").unwrap().bit_size, 24);
    }

    #[test]
    fn test_pic_languages() {
        let langs = PicProcessor::languages();
        assert!(langs.len() >= 4);
        assert!(langs.iter().any(|l| l.id == "pic:LE:8:PIC16"));
        assert!(langs.iter().any(|l| l.id == "pic:LE:8:PIC18"));
        assert!(langs.iter().any(|l| l.id == "pic:LE:16:PIC24"));
        assert!(langs.iter().any(|l| l.id == "pic:LE:16:dsPIC33"));
    }

    #[test]
    fn test_pic_instructions() {
        let insts = PicProcessor::instructions();
        assert!(insts.len() > 80);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        // PIC16
        assert!(texts.contains(&"addwf"));
        assert!(texts.contains(&"movwf"));
        assert!(texts.contains(&"bcf"));
        assert!(texts.contains(&"bsf"));
        assert!(texts.contains(&"call"));
        assert!(texts.contains(&"goto"));
        assert!(texts.contains(&"retlw"));
        assert!(texts.contains(&"retfie"));
        assert!(texts.contains(&"nop"));
        // PIC18
        assert!(texts.contains(&"movff"));
        assert!(texts.contains(&"lfsr"));
        assert!(texts.contains(&"tblrd"));
        assert!(texts.contains(&"tblwt"));
        assert!(texts.contains(&"rcall"));
        assert!(texts.contains(&"bra"));
        // PIC24
        assert!(texts.contains(&"mov"));
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"mul"));
        assert!(texts.contains(&"repeat"));
        // dsPIC
        assert!(texts.contains(&"mac"));
        assert!(texts.contains(&"msc"));
        assert!(texts.contains(&"mpy"));
        assert!(texts.contains(&"lac"));
        assert!(texts.contains(&"sac"));
    }
}
