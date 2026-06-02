//! Intel 8051 (MCS-51) Processor Module
//!
//! Supports the classic Intel 8051 microcontroller family and derivatives.
//!
//! The Intel 8051 (MCS-51) is an 8-bit microcontroller architecture introduced
//! in 1980. It features a Harvard architecture with separate code and data
//! memory spaces, four register banks, bit-addressable RAM, and a rich set of
//! on-chip peripherals. Used extensively in embedded systems, automotive
//! electronics, and consumer devices.
//!
//! ## Register space layout
//!
//! ### Core registers
//! - ACC (Accumulator):             0x0000  (8-bit)
//! - B (Multiplier/Divider):        0x0001  (8-bit)
//! - PSW (Program Status Word):     0x0002  (8-bit)
//! - SP (Stack Pointer):            0x0003  (8-bit, internal RAM only)
//! - DPH (Data Pointer High):       0x0004  (8-bit)
//! - DPL (Data Pointer Low):        0x0005  (8-bit)
//! - PC (Program Counter):          0x0008  (16-bit)
//!
//! ### Register banks (R0-R7, four banks at 0x00-0x1F in internal RAM)
//! - R0-R7 (Bank 0):               0x0020 - 0x0027
//! - R0-R7 (Bank 1):               0x0028 - 0x002F
//! - R0-R7 (Bank 2):               0x0030 - 0x0037
//! - R0-R7 (Bank 3):               0x0038 - 0x003F
//!
//! ### PSW flags
//! - C / CY  (Carry):              bit 7 of PSW
//! - AC      (Auxiliary Carry):     bit 6 of PSW
//! - F0      (User Flag 0):        bit 5 of PSW
//! - RS1     (Register Bank Select):bit 4 of PSW
//! - RS0     (Register Bank Select):bit 3 of PSW
//! - OV      (Overflow):           bit 2 of PSW
//! - F1      (User Flag 1):        bit 1 of PSW (reserved/8052)
//! - P       (Parity):             bit 0 of PSW (read-only)
//!
//! ### SFR (Special Function Registers) space at 0x80-0xFF in internal RAM
//! - P0, P1, P2, P3 (I/O ports)
//! - SCON, SBUF (Serial port)
//! - TCON, TMOD, TL0, TH0, TL1, TH1 (Timers)
//! - IE, IP (Interrupt enable/priority)
//! - PCON (Power control)
//! - DPH0/DPL0, DPH1/DPL1 (dual DPTRs, 8052+)
//! - AUXR, AUXR1 (Auxiliary registers, extended variants)
//! - SADDR, SADEN (SFR address recognition, 8052+)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Intel 8051 processor struct.
pub struct M8051Processor;

/// Build the complete 8051 register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- Core registers ----
    bank.add(Register::new("ACC", 8, 0x0000)); // Accumulator (also SFR at 0xE0)
    bank.add(Register::new("B", 8, 0x0001));   // B register (multiply/divide, also SFR at 0xF0)
    bank.add(Register::new("PSW", 8, 0x0002)); // Program Status Word (also SFR at 0xD0)

    // PSW flag bit fields
    bank.add(Register::sub_register("CY", 1, 0x0002, "PSW", 7)); // Carry flag
    bank.add(Register::sub_register("AC", 1, 0x0002, "PSW", 6)); // Auxiliary Carry
    bank.add(Register::sub_register("F0", 1, 0x0002, "PSW", 5)); // User flag 0 (general purpose)
    bank.add(Register::sub_register("RS1", 1, 0x0002, "PSW", 4)); // Register Bank Select 1
    bank.add(Register::sub_register("RS0", 1, 0x0002, "PSW", 3)); // Register Bank Select 0
    bank.add(Register::sub_register("OV", 1, 0x0002, "PSW", 2)); // Overflow flag
    bank.add(Register::sub_register("F1", 1, 0x0002, "PSW", 1)); // User flag 1
    bank.add(Register::sub_register("P", 1, 0x0002, "PSW", 0));  // Parity (always read-only)

    bank.add(Register::new("SP", 8, 0x0003));   // Stack Pointer (also SFR at 0x81)
    bank.add(Register::new("DPH", 8, 0x0004));  // Data Pointer High (also SFR at 0x83)
    bank.add(Register::new("DPL", 8, 0x0005));  // Data Pointer Low (also SFR at 0x82)
    bank.add(Register::new("DPTR", 16, 0x0004));// Combined DPTR

    bank.add(Register::new("PC", 16, 0x0008));  // Program Counter (not SFR-mapped)

    // ---- Register Banks (R0-R7, four banks) ----
    // Bank 0 (RS1=0, RS0=0) -- default
    bank.add(Register::new("R0_BANK0", 8, 0x0020));
    bank.add(Register::new("R1_BANK0", 8, 0x0021));
    bank.add(Register::new("R2_BANK0", 8, 0x0022));
    bank.add(Register::new("R3_BANK0", 8, 0x0023));
    bank.add(Register::new("R4_BANK0", 8, 0x0024));
    bank.add(Register::new("R5_BANK0", 8, 0x0025));
    bank.add(Register::new("R6_BANK0", 8, 0x0026));
    bank.add(Register::new("R7_BANK0", 8, 0x0027));

    // Bank 1 (RS1=0, RS0=1)
    bank.add(Register::new("R0_BANK1", 8, 0x0028));
    bank.add(Register::new("R1_BANK1", 8, 0x0029));
    bank.add(Register::new("R2_BANK1", 8, 0x002A));
    bank.add(Register::new("R3_BANK1", 8, 0x002B));
    bank.add(Register::new("R4_BANK1", 8, 0x002C));
    bank.add(Register::new("R5_BANK1", 8, 0x002D));
    bank.add(Register::new("R6_BANK1", 8, 0x002E));
    bank.add(Register::new("R7_BANK1", 8, 0x002F));

    // Bank 2 (RS1=1, RS0=0)
    bank.add(Register::new("R0_BANK2", 8, 0x0030));
    bank.add(Register::new("R1_BANK2", 8, 0x0031));
    bank.add(Register::new("R2_BANK2", 8, 0x0032));
    bank.add(Register::new("R3_BANK2", 8, 0x0033));
    bank.add(Register::new("R4_BANK2", 8, 0x0034));
    bank.add(Register::new("R5_BANK2", 8, 0x0035));
    bank.add(Register::new("R6_BANK2", 8, 0x0036));
    bank.add(Register::new("R7_BANK2", 8, 0x0037));

    // Bank 3 (RS1=1, RS0=1)
    bank.add(Register::new("R0_BANK3", 8, 0x0038));
    bank.add(Register::new("R1_BANK3", 8, 0x0039));
    bank.add(Register::new("R2_BANK3", 8, 0x003A));
    bank.add(Register::new("R3_BANK3", 8, 0x003B));
    bank.add(Register::new("R4_BANK3", 8, 0x003C));
    bank.add(Register::new("R5_BANK3", 8, 0x003D));
    bank.add(Register::new("R6_BANK3", 8, 0x003E));
    bank.add(Register::new("R7_BANK3", 8, 0x003F));

    // ---- SFR space (0x80-0xFF in internal direct RAM) ----
    // Port registers
    bank.add(Register::new("P0", 8, 0x0080)); // Port 0 (SFR 0x80)
    bank.add(Register::new("P1", 8, 0x0090)); // Port 1 (SFR 0x90)
    bank.add(Register::new("P2", 8, 0x00A0)); // Port 2 (SFR 0xA0)
    bank.add(Register::new("P3", 8, 0x00B0)); // Port 3 (SFR 0xB0)

    // Serial port
    bank.add(Register::new("SCON", 8, 0x0098)); // Serial Control (SFR 0x98)
    bank.add(Register::new("SBUF", 8, 0x0099)); // Serial Buffer (SFR 0x99)

    // Timer 0
    bank.add(Register::new("TL0", 8, 0x008A));  // Timer 0 Low (SFR 0x8A)
    bank.add(Register::new("TH0", 8, 0x008C));  // Timer 0 High (SFR 0x8C)

    // Timer 1
    bank.add(Register::new("TL1", 8, 0x008B));  // Timer 1 Low (SFR 0x8B)
    bank.add(Register::new("TH1", 8, 0x008D));  // Timer 1 High (SFR 0x8D)

    // Timer control
    bank.add(Register::new("TCON", 8, 0x0088)); // Timer Control (SFR 0x88)
    bank.add(Register::new("TMOD", 8, 0x0089)); // Timer Mode (SFR 0x89)

    // TCON bit fields
    bank.add(Register::sub_register("TF1", 1, 0x0088, "TCON", 7)); // Timer 1 overflow flag
    bank.add(Register::sub_register("TR1", 1, 0x0088, "TCON", 6)); // Timer 1 run control
    bank.add(Register::sub_register("TF0", 1, 0x0088, "TCON", 5)); // Timer 0 overflow flag
    bank.add(Register::sub_register("TR0", 1, 0x0088, "TCON", 4)); // Timer 0 run control
    bank.add(Register::sub_register("IE1", 1, 0x0088, "TCON", 3)); // External interrupt 1 edge flag
    bank.add(Register::sub_register("IT1", 1, 0x0088, "TCON", 2)); // External interrupt 1 type
    bank.add(Register::sub_register("IE0", 1, 0x0088, "TCON", 1)); // External interrupt 0 edge flag
    bank.add(Register::sub_register("IT0", 1, 0x0088, "TCON", 0)); // External interrupt 0 type

    // Interrupt
    bank.add(Register::new("IE", 8, 0x00A8));  // Interrupt Enable (SFR 0xA8)
    bank.add(Register::sub_register("EA", 1, 0x00A8, "IE", 7));  // Enable All interrupts
    bank.add(Register::sub_register("ES", 1, 0x00A8, "IE", 4));  // Enable Serial interrupt
    bank.add(Register::sub_register("ET1", 1, 0x00A8, "IE", 3)); // Enable Timer 1 interrupt
    bank.add(Register::sub_register("EX1", 1, 0x00A8, "IE", 2)); // Enable External 1 interrupt
    bank.add(Register::sub_register("ET0", 1, 0x00A8, "IE", 1)); // Enable Timer 0 interrupt
    bank.add(Register::sub_register("EX0", 1, 0x00A8, "IE", 0)); // Enable External 0 interrupt
    bank.add(Register::new("IP", 8, 0x00B8));  // Interrupt Priority (SFR 0xB8)

    // Interrupt Priority bit fields
    bank.add(Register::sub_register("PS", 1, 0x00B8, "IP", 4));  // Serial priority
    bank.add(Register::sub_register("PT1", 1, 0x00B8, "IP", 3)); // Timer 1 priority
    bank.add(Register::sub_register("PX1", 1, 0x00B8, "IP", 2)); // External 1 priority
    bank.add(Register::sub_register("PT0", 1, 0x00B8, "IP", 1)); // Timer 0 priority
    bank.add(Register::sub_register("PX0", 1, 0x00B8, "IP", 0)); // External 0 priority

    // Power control
    bank.add(Register::new("PCON", 8, 0x0087)); // Power Control (SFR 0x87)
    bank.add(Register::sub_register("SMOD", 1, 0x0087, "PCON", 7)); // Serial baud rate double
    bank.add(Register::sub_register("GF1", 1, 0x0087, "PCON", 3));  // General-purpose flag 1
    bank.add(Register::sub_register("GF0", 1, 0x0087, "PCON", 2));  // General-purpose flag 0
    bank.add(Register::sub_register("PD", 1, 0x0087, "PCON", 1));   // Power Down mode
    bank.add(Register::sub_register("IDL", 1, 0x0087, "PCON", 0));  // Idle mode

    // ---- 8052 / Extended SFRs ----
    // Timer 2 (8052+)
    bank.add(Register::new("TL2", 8, 0x00CC));  // Timer 2 Low (SFR 0xCC)
    bank.add(Register::new("TH2", 8, 0x00CD));  // Timer 2 High (SFR 0xCD)
    bank.add(Register::new("RCAP2L", 8, 0x00CA)); // Timer 2 Reload/Capture Low (SFR 0xCA)
    bank.add(Register::new("RCAP2H", 8, 0x00CB)); // Timer 2 Reload/Capture High (SFR 0xCB)
    bank.add(Register::new("T2CON", 8, 0x00C8)); // Timer 2 Control (SFR 0xC8)

    // T2CON bit fields
    bank.add(Register::sub_register("TF2", 1, 0x00C8, "T2CON", 7)); // Timer 2 overflow
    bank.add(Register::sub_register("EXF2", 1, 0x00C8, "T2CON", 6)); // Timer 2 external flag
    bank.add(Register::sub_register("RCLK", 1, 0x00C8, "T2CON", 5)); // Receive clock flag
    bank.add(Register::sub_register("TCLK", 1, 0x00C8, "T2CON", 4)); // Transmit clock flag
    bank.add(Register::sub_register("EXEN2", 1, 0x00C8, "T2CON", 3)); // Timer 2 external enable
    bank.add(Register::sub_register("TR2", 1, 0x00C8, "T2CON", 2)); // Timer 2 run control
    bank.add(Register::sub_register("C_T2", 1, 0x00C8, "T2CON", 1)); // Counter/Timer select
    bank.add(Register::sub_register("CP_RL2", 1, 0x00C8, "T2CON", 0)); // Capture/Reload select

    // Interrupt enable 2 (8052+)
    bank.add(Register::new("IE2", 8, 0x00E8)); // Not part of standard SFR, extended

    // Dual DPTR registers (some 8051 variants)
    bank.add(Register::new("DPH1", 8, 0x0085)); // Data Pointer 1 High
    bank.add(Register::new("DPL1", 8, 0x0084)); // Data Pointer 1 Low
    bank.add(Register::new("DPTR1", 16, 0x0084)); // Combined DPTR1

    // DPTR select (AUXR1.0 selects active DPTR)
    bank.add(Register::new("AUXR1", 8, 0x00A2)); // Auxiliary Register 1
    bank.add(Register::sub_register("DPS", 1, 0x00A2, "AUXR1", 0)); // DPTR Select

    // Auxiliary Register
    bank.add(Register::new("AUXR", 8, 0x008E)); // Auxiliary Register
    bank.add(Register::sub_register("EXTRAM", 1, 0x008E, "AUXR", 1)); // External RAM access

    // Watchdog (some variants)
    bank.add(Register::new("WDTRST", 8, 0x00A6)); // Watchdog Reset
    bank.add(Register::new("WDTPRG", 8, 0x00A7)); // Watchdog Prescaler

    // ---- Address recognition for multiprocessor comm (8052+) ----
    bank.add(Register::new("SADDR", 8, 0x00A9)); // Serial Address (SFR 0xA9)
    bank.add(Register::new("SADEN", 8, 0x00B9)); // Serial Address Enable (SFR 0xB9)

    bank
}

/// Build the 8051 instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Arithmetic ===
        InstructionMnemonic::new("add_a_rn"),       // ADD A, Rn
        InstructionMnemonic::new("add_a_direct"),   // ADD A, direct
        InstructionMnemonic::new("add_a_ri"),       // ADD A, @Ri
        InstructionMnemonic::new("add_a_data"),     // ADD A, #data
        InstructionMnemonic::new("addc_a_rn"),      // ADDC A, Rn
        InstructionMnemonic::new("addc_a_direct"),  // ADDC A, direct
        InstructionMnemonic::new("addc_a_ri"),      // ADDC A, @Ri
        InstructionMnemonic::new("addc_a_data"),    // ADDC A, #data
        InstructionMnemonic::new("subb_a_rn"),      // SUBB A, Rn
        InstructionMnemonic::new("subb_a_direct"),  // SUBB A, direct
        InstructionMnemonic::new("subb_a_ri"),      // SUBB A, @Ri
        InstructionMnemonic::new("subb_a_data"),    // SUBB A, #data
        InstructionMnemonic::new("inc_a"),           // INC A
        InstructionMnemonic::new("inc_rn"),          // INC Rn
        InstructionMnemonic::new("inc_direct"),      // INC direct
        InstructionMnemonic::new("inc_ri"),          // INC @Ri
        InstructionMnemonic::new("inc_dptr"),        // INC DPTR
        InstructionMnemonic::new("dec_a"),           // DEC A
        InstructionMnemonic::new("dec_rn"),          // DEC Rn
        InstructionMnemonic::new("dec_direct"),      // DEC direct
        InstructionMnemonic::new("dec_ri"),          // DEC @Ri
        InstructionMnemonic::new("mul_ab"),          // MUL AB
        InstructionMnemonic::new("div_ab"),          // DIV AB
        InstructionMnemonic::new("da_a"),            // DA A (Decimal Adjust)
        // === Logical ===
        InstructionMnemonic::new("anl_a_rn"),        // ANL A, Rn
        InstructionMnemonic::new("anl_a_direct"),    // ANL A, direct
        InstructionMnemonic::new("anl_a_ri"),        // ANL A, @Ri
        InstructionMnemonic::new("anl_a_data"),      // ANL A, #data
        InstructionMnemonic::new("anl_direct_a"),    // ANL direct, A
        InstructionMnemonic::new("anl_direct_data"), // ANL direct, #data
        InstructionMnemonic::new("orl_a_rn"),        // ORL A, Rn
        InstructionMnemonic::new("orl_a_direct"),    // ORL A, direct
        InstructionMnemonic::new("orl_a_ri"),        // ORL A, @Ri
        InstructionMnemonic::new("orl_a_data"),      // ORL A, #data
        InstructionMnemonic::new("orl_direct_a"),    // ORL direct, A
        InstructionMnemonic::new("orl_direct_data"), // ORL direct, #data
        InstructionMnemonic::new("xrl_a_rn"),        // XRL A, Rn
        InstructionMnemonic::new("xrl_a_direct"),    // XRL A, direct
        InstructionMnemonic::new("xrl_a_ri"),        // XRL A, @Ri
        InstructionMnemonic::new("xrl_a_data"),      // XRL A, #data
        InstructionMnemonic::new("xrl_direct_a"),    // XRL direct, A
        InstructionMnemonic::new("xrl_direct_data"), // XRL direct, #data
        InstructionMnemonic::new("clr_a"),           // CLR A
        InstructionMnemonic::new("cpl_a"),           // CPL A
        InstructionMnemonic::new("rl_a"),            // RL A (Rotate Left)
        InstructionMnemonic::new("rlc_a"),           // RLC A (Rotate Left through Carry)
        InstructionMnemonic::new("rr_a"),            // RR A (Rotate Right)
        InstructionMnemonic::new("rrc_a"),           // RRC A (Rotate Right through Carry)
        InstructionMnemonic::new("swap_a"),          // SWAP A (swap nibbles)
        // === Data Transfer ===
        InstructionMnemonic::new("mov_a_rn"),        // MOV A, Rn
        InstructionMnemonic::new("mov_a_direct"),    // MOV A, direct
        InstructionMnemonic::new("mov_a_ri"),        // MOV A, @Ri
        InstructionMnemonic::new("mov_a_data"),      // MOV A, #data
        InstructionMnemonic::new("mov_rn_a"),        // MOV Rn, A
        InstructionMnemonic::new("mov_rn_direct"),   // MOV Rn, direct
        InstructionMnemonic::new("mov_rn_data"),     // MOV Rn, #data
        InstructionMnemonic::new("mov_direct_a"),    // MOV direct, A
        InstructionMnemonic::new("mov_direct_rn"),   // MOV direct, Rn
        InstructionMnemonic::new("mov_direct_direct"),// MOV direct, direct
        InstructionMnemonic::new("mov_direct_ri"),   // MOV direct, @Ri
        InstructionMnemonic::new("mov_direct_data"), // MOV direct, #data
        InstructionMnemonic::new("mov_ri_a"),        // MOV @Ri, A
        InstructionMnemonic::new("mov_ri_direct"),   // MOV @Ri, direct
        InstructionMnemonic::new("mov_ri_data"),     // MOV @Ri, #data
        InstructionMnemonic::new("mov_dptr_data"),   // MOV DPTR, #data16
        // === External RAM (MOVX) ===
        InstructionMnemonic::new("movx_a_dptr"),     // MOVX A, @DPTR
        InstructionMnemonic::new("movx_a_ri"),       // MOVX A, @Ri
        InstructionMnemonic::new("movx_dptr_a"),     // MOVX @DPTR, A
        InstructionMnemonic::new("movx_ri_a"),       // MOVX @Ri, A
        // === Code Memory (MOVC) ===
        InstructionMnemonic::new("movc_a_a_pc"),     // MOVC A, @A+PC
        InstructionMnemonic::new("movc_a_a_dptr"),   // MOVC A, @A+DPTR
        // === Stack ===
        InstructionMnemonic::new("push"),             // PUSH direct
        InstructionMnemonic::new("pop"),              // POP direct
        // === Exchange ===
        InstructionMnemonic::new("xch_a_rn"),         // XCH A, Rn
        InstructionMnemonic::new("xch_a_direct"),     // XCH A, direct
        InstructionMnemonic::new("xch_a_ri"),         // XCH A, @Ri
        InstructionMnemonic::new("xchd_a_ri"),        // XCHD A, @Ri (exchange low nibbles)
        // === Boolean / Bit Operations ===
        InstructionMnemonic::new("clr_c"),            // CLR C (clear carry)
        InstructionMnemonic::new("clr_bit"),          // CLR bit
        InstructionMnemonic::new("setb_c"),           // SETB C (set carry)
        InstructionMnemonic::new("setb_bit"),         // SETB bit
        InstructionMnemonic::new("cpl_c"),            // CPL C (complement carry)
        InstructionMnemonic::new("cpl_bit"),          // CPL bit
        InstructionMnemonic::new("anl_c_bit"),        // ANL C, bit
        InstructionMnemonic::new("anl_c_not_bit"),    // ANL C, /bit
        InstructionMnemonic::new("orl_c_bit"),        // ORL C, bit
        InstructionMnemonic::new("orl_c_not_bit"),    // ORL C, /bit
        InstructionMnemonic::new("mov_c_bit"),        // MOV C, bit
        InstructionMnemonic::new("mov_bit_c"),        // MOV bit, C
        InstructionMnemonic::new("jc"),               // JC rel (jump if carry)
        InstructionMnemonic::new("jnc"),              // JNC rel (jump if not carry)
        InstructionMnemonic::new("jb"),               // JB bit, rel (jump if bit set)
        InstructionMnemonic::new("jnb"),              // JNB bit, rel (jump if bit not set)
        InstructionMnemonic::new("jbc"),              // JBC bit, rel (jump if bit set, then clear)
        // === Jump ===
        InstructionMnemonic::new("ajmp"),             // Absolute Jump (11-bit address)
        InstructionMnemonic::new("ljmp"),             // Long Jump (16-bit address)
        InstructionMnemonic::new("sjmp"),             // Short Jump (relative)
        InstructionMnemonic::new("jmp_a_dptr"),       // JMP @A+DPTR
        InstructionMnemonic::new("jz"),               // JZ rel (jump if A = 0)
        InstructionMnemonic::new("jnz"),              // JNZ rel (jump if A != 0)
        InstructionMnemonic::new("cjne_a_direct"),    // CJNE A, direct, rel
        InstructionMnemonic::new("cjne_a_data"),      // CJNE A, #data, rel
        InstructionMnemonic::new("cjne_rn_data"),     // CJNE Rn, #data, rel
        InstructionMnemonic::new("cjne_ri_data"),     // CJNE @Ri, #data, rel
        InstructionMnemonic::new("djnz_rn"),          // DJNZ Rn, rel
        InstructionMnemonic::new("djnz_direct"),      // DJNZ direct, rel
        InstructionMnemonic::new("nop"),              // NOP
        // === Subroutine ===
        InstructionMnemonic::new("acall"),            // Absolute Call (11-bit)
        InstructionMnemonic::new("lcall"),            // Long Call (16-bit)
        InstructionMnemonic::new("ret"),              // RET
        InstructionMnemonic::new("reti"),             // RETI (return from interrupt)
    ]
}

impl ProcessorModule for M8051Processor {
    fn name() -> &'static str {
        "Intel 8051 (MCS-51)"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "8051:LE:8:default",
                "Intel 8051 (8-bit, little-endian, MCS-51 architecture)",
                "8051",
                Endian::Little,
                16,
            ),
            Language::new(
                "8051:LE:8:8052",
                "Intel 8052 (8-bit, little-endian, MCS-51 + Timer 2)",
                "8052",
                Endian::Little,
                16,
            ),
            Language::new(
                "8051:LE:8:DS80C320",
                "Dallas/Maxim DS80C320 (8051-compatible, fast)",
                "DS80C320",
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
    fn test_m8051_name() {
        assert_eq!(M8051Processor::name(), "Intel 8051 (MCS-51)");
    }

    #[test]
    fn test_m8051_registers() {
        let bank = M8051Processor::registers();
        assert!(bank.len() > 50, "Expected many registers, got {}", bank.len());
        // Core
        assert!(bank.get("ACC").is_some());
        assert!(bank.get("B").is_some());
        assert!(bank.get("PSW").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("DPH").is_some());
        assert!(bank.get("DPL").is_some());
        assert!(bank.get("DPTR").is_some());
        assert!(bank.get("PC").is_some());
        // Register banks
        assert!(bank.get("R0_BANK0").is_some());
        assert!(bank.get("R7_BANK0").is_some());
        assert!(bank.get("R0_BANK1").is_some());
        assert!(bank.get("R7_BANK1").is_some());
        assert!(bank.get("R0_BANK3").is_some());
        assert!(bank.get("R7_BANK3").is_some());
        // SFRs
        assert!(bank.get("P0").is_some());
        assert!(bank.get("P1").is_some());
        assert!(bank.get("P2").is_some());
        assert!(bank.get("P3").is_some());
        assert!(bank.get("SCON").is_some());
        assert!(bank.get("SBUF").is_some());
        assert!(bank.get("TCON").is_some());
        assert!(bank.get("TMOD").is_some());
        assert!(bank.get("IE").is_some());
        assert!(bank.get("IP").is_some());
        assert!(bank.get("PCON").is_some());
        // 8052
        assert!(bank.get("TL2").is_some());
        assert!(bank.get("TH2").is_some());
        assert!(bank.get("T2CON").is_some());
    }

    #[test]
    fn test_m8051_psw_flags() {
        let bank = M8051Processor::registers();
        let cy = bank.get("CY").unwrap();
        assert_eq!(cy.parent.as_deref(), Some("PSW"));
        assert_eq!(cy.lsb, 7);
        let ac = bank.get("AC").unwrap();
        assert_eq!(ac.lsb, 6);
        let ov = bank.get("OV").unwrap();
        assert_eq!(ov.lsb, 2);
        let p = bank.get("P").unwrap();
        assert_eq!(p.lsb, 0);
    }

    #[test]
    fn test_m8051_tcon_flags() {
        let bank = M8051Processor::registers();
        let tf0 = bank.get("TF0").unwrap();
        assert_eq!(tf0.parent.as_deref(), Some("TCON"));
        assert_eq!(tf0.lsb, 5);
        let tr0 = bank.get("TR0").unwrap();
        assert_eq!(tr0.lsb, 4);
    }

    #[test]
    fn test_m8051_register_bits() {
        let bank = M8051Processor::registers();
        assert_eq!(bank.get("ACC").unwrap().bit_size, 8);
        assert_eq!(bank.get("PC").unwrap().bit_size, 16);
        assert_eq!(bank.get("DPTR").unwrap().bit_size, 16);
    }

    #[test]
    fn test_m8051_languages() {
        let langs = M8051Processor::languages();
        assert!(langs.len() >= 2);
        assert!(langs.iter().any(|l| l.id == "8051:LE:8:default"));
        assert!(langs.iter().any(|l| l.id == "8051:LE:8:8052"));
    }

    #[test]
    fn test_m8051_instructions() {
        let insts = M8051Processor::instructions();
        assert!(insts.len() > 60);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"mov_a_rn"));
        assert!(texts.contains(&"add_a_rn"));
        assert!(texts.contains(&"subb_a_rn"));
        assert!(texts.contains(&"mul_ab"));
        assert!(texts.contains(&"div_ab"));
        assert!(texts.contains(&"ajmp"));
        assert!(texts.contains(&"ljmp"));
        assert!(texts.contains(&"acall"));
        assert!(texts.contains(&"lcall"));
        assert!(texts.contains(&"ret"));
        assert!(texts.contains(&"reti"));
        assert!(texts.contains(&"push"));
        assert!(texts.contains(&"pop"));
        assert!(texts.contains(&"clr_c"));
        assert!(texts.contains(&"setb_c"));
        assert!(texts.contains(&"nop"));
    }
}
