//! Texas Instruments MSP430 Processor Module
//!
//! Supports the MSP430 and MSP430X (20-bit extended) families.
//!
//! The Texas Instruments MSP430 is a 16-bit ultra-low-power RISC
//! microcontroller introduced in the 1990s. It features 16 registers
//! (R0-R15), a compact instruction set, and on-chip analog peripherals.
//! The MSP430X extends addressing to 20 bits. Used in low-power wireless
//! sensor nodes, medical devices, and industrial instrumentation.
//!
//! ## Register space layout
//!
//! - R0 (PC):  Program Counter
//! - R1 (SP):  Stack Pointer
//! - R2 (SR/CG1): Status Register (also used as constant generator 1)
//! - R3 (CG2): Constant Generator 2
//! - R4-R15: General-purpose registers
//!
//! ### Status Register (SR) bits (R2):
//! - V (Overflow):              bit 8
//! - SCG1 (System Clock Gen 1):  bit 7
//! - SCG0 (System Clock Gen 0):  bit 6
//! - OSCOFF (Oscillator Off):    bit 5
//! - CPUOFF (CPU Off):           bit 4
//! - GIE (Global Interrupt En):  bit 3
//! - N (Negative):               bit 2
//! - Z (Zero):                   bit 1
//! - C (Carry):                  bit 0

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// TI MSP430 processor struct.
pub struct Msp430Processor;

/// Build the complete MSP430 register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- CPU Registers R0-R15 (16-bit each) ----
    bank.add(Register::new("R0", 16, 0x0000));
    bank.add(Register::sub_register("PC", 16, 0x0000, "R0", 0)); // R0 = Program Counter

    bank.add(Register::new("R1", 16, 0x0002));
    bank.add(Register::sub_register("SP", 16, 0x0002, "R1", 0)); // R1 = Stack Pointer

    bank.add(Register::new("R2", 16, 0x0004));
    bank.add(Register::sub_register("SR", 16, 0x0004, "R2", 0)); // R2 = Status Register
    bank.add(Register::sub_register("CG1", 16, 0x0004, "R2", 0)); // R2 = Constant Generator 1

    bank.add(Register::new("R3", 16, 0x0006));
    bank.add(Register::sub_register("CG2", 16, 0x0006, "R3", 0)); // R3 = Constant Generator 2

    // General-purpose registers R4-R15
    for i in 4u32..16 {
        bank.add(Register::new(&format!("R{}", i), 16, 0x0008 + (i as u64 - 4) * 2));
    }

    // ---- Status Register (SR / R2) bit fields ----
    bank.add(Register::sub_register("C", 1, 0x0004, "R2", 0)); // Carry
    bank.add(Register::sub_register("Z", 1, 0x0004, "R2", 1)); // Zero
    bank.add(Register::sub_register("N", 1, 0x0004, "R2", 2)); // Negative
    bank.add(Register::sub_register("GIE", 1, 0x0004, "R2", 3)); // General Interrupt Enable
    bank.add(Register::sub_register("CPUOFF", 1, 0x0004, "R2", 4)); // CPU Off
    bank.add(Register::sub_register("OSCOFF", 1, 0x0004, "R2", 5)); // Oscillator Off
    bank.add(Register::sub_register("SCG0", 1, 0x0004, "R2", 6)); // System Clock Generator 0
    bank.add(Register::sub_register("SCG1", 1, 0x0004, "R2", 7)); // System Clock Generator 1
    bank.add(Register::sub_register("V", 1, 0x0004, "R2", 8)); // Overflow

    // ---- MSP430X Extended Registers (20-bit) ----
    // In MSP430X, PC/SR become 20-bit, and R0-R15 preserve the lower 16-bit identity
    // but full values are 20-bit.
    bank.add(Register::new("PCX", 20, 0x0020)); // 20-bit Program Counter (MSP430X)
    bank.add(Register::new("SRX", 20, 0x0024)); // 20-bit Status Register (MSP430X)
    bank.add(Register::new("SPX", 20, 0x0028)); // 20-bit Stack Pointer (MSP430X)

    // ---- MSP430X Registers R0-R15 (20-bit) ----
    for i in 0u32..16 {
        bank.add(Register::new(
            &format!("R{}X", i),
            20,
            0x0030 + (i as u64) * 4,
        ));
    }

    // ---- Constant Generator values (virtual, embedded in instruction encoding) ----
    // In MSP430, the CG1 (R2) and CG2 (R3) registers generate constants when used
    // with specific addressing modes (As). These are not physical registers but
    // are effectively part of the instruction set:
    //
    // CG1 (R2): As=00: register R2; As=01: [R2]; As=10: #4; As=11: #8
    // CG2 (R3): As=00: register R3; As=01: [R3]; As=10: #2; As=11: #-1 (0xFFFF)
    //
    // Representing them as named constants aids disassembly accuracy.
    bank.add(Register::new("CG1_CONST4", 16, 0x0040)); // Constant 4 from CG1
    bank.add(Register::new("CG1_CONST8", 16, 0x0042)); // Constant 8 from CG1
    bank.add(Register::new("CG2_CONST2", 16, 0x0044)); // Constant 2 from CG2
    bank.add(Register::new("CG2_CONST1", 16, 0x0046)); // Constant -1 (0xFFFF) from CG2

    // ---- Peripheral registers mapped to common MSP430 devices ----

    // Watchdog Timer
    bank.add(Register::new("WDTCTL", 16, 0x0120)); // Watchdog Timer Control

    // Basic Clock Module
    bank.add(Register::new("DCOCTL", 8, 0x0056)); // DCO Control
    bank.add(Register::new("BCSCTL1", 8, 0x0057)); // Basic Clock System Control 1
    bank.add(Register::new("BCSCTL2", 8, 0x0058)); // Basic Clock System Control 2
    bank.add(Register::new("BCSCTL3", 8, 0x0053)); // Basic Clock System Control 3 (FLL+ devices)

    // Unified Clock System (MSP430F5xx/F6xx)
    bank.add(Register::new("UCSCTL0", 16, 0x0160));
    bank.add(Register::new("UCSCTL1", 16, 0x0162));
    bank.add(Register::new("UCSCTL2", 16, 0x0164));
    bank.add(Register::new("UCSCTL3", 16, 0x0166));
    bank.add(Register::new("UCSCTL4", 16, 0x0168));
    bank.add(Register::new("UCSCTL5", 16, 0x016A));
    bank.add(Register::new("UCSCTL6", 16, 0x016C));
    bank.add(Register::new("UCSCTL7", 16, 0x016E));
    bank.add(Register::new("UCSCTL8", 16, 0x0170));

    // Timer A
    bank.add(Register::new("TA0CTL", 16, 0x0160)); // Timer A0 Control
    bank.add(Register::new("TA0CCTL0", 16, 0x0162)); // Capture/Compare Control 0
    bank.add(Register::new("TA0CCTL1", 16, 0x0164));
    bank.add(Register::new("TA0CCTL2", 16, 0x0166));
    bank.add(Register::new("TA0R", 16, 0x0170)); // Timer A0 Count
    bank.add(Register::new("TA0CCR0", 16, 0x0172)); // Capture/Compare 0
    bank.add(Register::new("TA0CCR1", 16, 0x0174)); // Capture/Compare 1
    bank.add(Register::new("TA0CCR2", 16, 0x0176)); // Capture/Compare 2
    bank.add(Register::new("TA0IV", 16, 0x017E)); // Timer A0 Interrupt Vector

    // Timer B
    bank.add(Register::new("TB0CTL", 16, 0x0180));
    bank.add(Register::new("TB0CCTL0", 16, 0x0182));
    bank.add(Register::new("TB0R", 16, 0x0190));
    bank.add(Register::new("TB0CCR0", 16, 0x0192));
    bank.add(Register::new("TB0IV", 16, 0x019E));

    // Port 1 & 2 (common to almost all MSP430 devices)
    bank.add(Register::new("P1IN", 8, 0x0020)); // Port 1 Input
    bank.add(Register::new("P1OUT", 8, 0x0021)); // Port 1 Output
    bank.add(Register::new("P1DIR", 8, 0x0022)); // Port 1 Direction
    bank.add(Register::new("P1IFG", 8, 0x0023)); // Port 1 Interrupt Flag
    bank.add(Register::new("P1IES", 8, 0x0024)); // Port 1 Interrupt Edge Select
    bank.add(Register::new("P1IE", 8, 0x0025)); // Port 1 Interrupt Enable
    bank.add(Register::new("P1SEL", 8, 0x0026)); // Port 1 Select
    bank.add(Register::new("P1REN", 8, 0x0027)); // Port 1 Resistor Enable

    bank.add(Register::new("P2IN", 8, 0x0028));
    bank.add(Register::new("P2OUT", 8, 0x0029));
    bank.add(Register::new("P2DIR", 8, 0x002A));
    bank.add(Register::new("P2IFG", 8, 0x002B));
    bank.add(Register::new("P2IES", 8, 0x002C));
    bank.add(Register::new("P2IE", 8, 0x002D));
    bank.add(Register::new("P2SEL", 8, 0x002E));
    bank.add(Register::new("P2REN", 8, 0x002F));

    // Port 3 & 4 (optional, depends on device)
    bank.add(Register::new("P3IN", 8, 0x0018));
    bank.add(Register::new("P3OUT", 8, 0x0019));
    bank.add(Register::new("P3DIR", 8, 0x001A));

    bank.add(Register::new("P4IN", 8, 0x001C));
    bank.add(Register::new("P4OUT", 8, 0x001D));
    bank.add(Register::new("P4DIR", 8, 0x001E));

    // ADC10 / ADC12 (common MSP430 analog peripheral)
    bank.add(Register::new("ADC10CTL0", 16, 0x01B0)); // ADC10 Control 0
    bank.add(Register::new("ADC10CTL1", 16, 0x01B2)); // ADC10 Control 1
    bank.add(Register::new("ADC10MEM", 16, 0x01B4)); // ADC10 Memory
    bank.add(Register::new("ADC10MCTL0", 8, 0x01B6)); // ADC10 Memory Control
    bank.add(Register::new("ADC10AE0", 8, 0x004A)); // ADC10 Analog Enable

    bank.add(Register::new("ADC12CTL0", 16, 0x01C0)); // ADC12 Control 0
    bank.add(Register::new("ADC12CTL1", 16, 0x01C2)); // ADC12 Control 1
    bank.add(Register::new("ADC12MEM0", 16, 0x01C8)); // ADC12 Memory 0

    // Comparator A+
    bank.add(Register::new("CACTL1", 8, 0x0059));
    bank.add(Register::new("CACTL2", 8, 0x005A));
    bank.add(Register::new("CAPD", 8, 0x005B));

    // USCI (Universal Serial Communication Interface, MSP430F5xx)
    bank.add(Register::new("UCA0CTLW0", 16, 0x05C0)); // USCI A Control Word 0
    bank.add(Register::new("UCA0BRW", 16, 0x05C6)); // USCI A Baud Rate
    bank.add(Register::new("UCA0MCTLW", 16, 0x05C8)); // USCI A Modulation Control
    bank.add(Register::new("UCA0RXBUF", 8, 0x05CC)); // USCI A Receive Buffer
    bank.add(Register::new("UCA0TXBUF", 8, 0x05CE)); // USCI A Transmit Buffer
    bank.add(Register::new("UCA0STAT", 8, 0x05D0)); // USCI A Status
    bank.add(Register::new("UCA0IE", 8, 0x05DC)); // USCI A Interrupt Enable
    bank.add(Register::new("UCA0IFG", 8, 0x05DD)); // USCI A Interrupt Flag

    bank.add(Register::new("UCB0CTLW0", 16, 0x05E0)); // USCI B (SPI/I2C)
    bank.add(Register::new("UCB0BRW", 16, 0x05E6));
    bank.add(Register::new("UCB0RXBUF", 8, 0x05EC));
    bank.add(Register::new("UCB0TXBUF", 8, 0x05EE));

    // Flash Controller
    bank.add(Register::new("FCTL1", 16, 0x0128)); // Flash Control 1
    bank.add(Register::new("FCTL2", 16, 0x012A)); // Flash Control 2
    bank.add(Register::new("FCTL3", 16, 0x012C)); // Flash Control 3
    bank.add(Register::new("FCTL4", 16, 0x012E)); // Flash Control 4 (MSP430X)

    // Special function / interrupt
    bank.add(Register::new("SFRIE1", 8, 0x0100)); // Special Function Interrupt Enable 1
    bank.add(Register::new("SFRIFG1", 8, 0x0102)); // Special Function Interrupt Flag 1
    bank.add(Register::new("SFRRPCR", 8, 0x0104)); // Special Function Reset Pin Control
    bank.add(Register::new("PM5CTL0", 16, 0x0110)); // Power Management 5 Control 0

    // RTC
    bank.add(Register::new("RTCCTL", 16, 0x0400)); // Real-Time Clock Control
    bank.add(Register::new("RTCNT1", 8, 0x0404)); // RTC Counter 1
    bank.add(Register::new("RTCDAY", 8, 0x0406)); // RTC Day

    // CRC16
    bank.add(Register::new("CRC16DI", 16, 0x0150)); // CRC16 Data In
    bank.add(Register::new("CRCINIRES", 16, 0x0152)); // CRC Init / Result

    // Multiplier (common on many MSP430 devices)
    bank.add(Register::new("MPY", 16, 0x0130)); // Multiplier Operand 1
    bank.add(Register::new("MPYS", 16, 0x0132)); // Signed Multiply operand
    bank.add(Register::new("MAC", 16, 0x0134)); // MAC operand
    bank.add(Register::new("MACS", 16, 0x0136)); // Signed MAC operand
    bank.add(Register::new("OP2", 16, 0x0138)); // Operand 2
    bank.add(Register::new("RESLO", 16, 0x013A)); // Result Low
    bank.add(Register::new("RESHI", 16, 0x013C)); // Result High
    bank.add(Register::new("SUMEXT", 16, 0x013E)); // Sum Extension

    bank
}

/// Build the MSP430 instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Double-Operand (Format I) ===
        InstructionMnemonic::new("mov"),
        InstructionMnemonic::new("add"),
        InstructionMnemonic::new("addc"),    // ADD with Carry
        InstructionMnemonic::new("subc"),    // SUBtract with Carry
        InstructionMnemonic::new("sub"),     // SUBtract
        InstructionMnemonic::new("cmp"),     // CoMPare
        InstructionMnemonic::new("dadd"),    // Decimal ADD (BCD)
        InstructionMnemonic::new("bit"),     // BIT test (AND, discard result)
        InstructionMnemonic::new("bic"),     // BIt Clear
        InstructionMnemonic::new("bis"),     // BIt Set
        InstructionMnemonic::new("xor"),
        InstructionMnemonic::new("and"),     // Logical AND
        // === Single-Operand (Format II) ===
        InstructionMnemonic::new("rrc"),     // Rotate Right through Carry
        InstructionMnemonic::new("rra"),     // Rotate Right Arithmetic (sign extend)
        InstructionMnemonic::new("swpb"),    // SWaP Bytes
        InstructionMnemonic::new("sxt"),     // Sign eXTend
        InstructionMnemonic::new("call"),
        InstructionMnemonic::new("reti"),    // RETurn from Interrupt
        // Emulated instructions from single-operand encodings
        InstructionMnemonic::new("push"),
        InstructionMnemonic::new("ret"),     // RETurn from subroutine (MOV @SP+,PC)
        InstructionMnemonic::new("pop"),
        // === Program Flow Control (Jumps) ===
        InstructionMnemonic::new("jmp"),     // Unconditional jump (JMP label)
        // Conditional jumps (based on SR bits)
        InstructionMnemonic::new("jne"),     // Jump if Not Equal (Z=0)
        InstructionMnemonic::new("jnz"),     // Jump if Not Zero (alias for JNE)
        InstructionMnemonic::new("jeq"),     // Jump if EQual (Z=1)
        InstructionMnemonic::new("jz"),      // Jump if Zero (alias for JEQ)
        InstructionMnemonic::new("jnc"),     // Jump if No Carry (C=0)
        InstructionMnemonic::new("jlo"),     // Jump if LOwer (alias for JNC, unsigned)
        InstructionMnemonic::new("jc"),      // Jump if Carry (C=1)
        InstructionMnemonic::new("jhs"),     // Jump if Higher or Same (alias for JC)
        InstructionMnemonic::new("jn"),      // Jump if Negative (N=1)
        InstructionMnemonic::new("jge"),     // Jump if Greater or Equal, signed (N==V)
        InstructionMnemonic::new("jl"),      // Jump if Less, signed (N!=V)
        InstructionMnemonic::new("jmp_rel"), // Unconditional JMP (relative)
        // MSP430X 20-bit jumps
        InstructionMnemonic::new("bra"),     // BRAnch (MSP430X, 20-bit CALLA)
        InstructionMnemonic::new("calla"),   // CALL Absolute (MSP430X, 20-bit)
        // === Emulated Instructions ===
        InstructionMnemonic::new("clr"),     // CLeaR destination (MOV #0, dst)
        InstructionMnemonic::new("clrc"),    // CLeaR Carry (BIC #1, SR)
        InstructionMnemonic::new("clrz"),    // CLeaR Zero (BIC #2, SR)
        InstructionMnemonic::new("clrn"),    // CLeaR Negative (BIC #4, SR)
        InstructionMnemonic::new("setc"),    // SET Carry (BIS #1, SR)
        InstructionMnemonic::new("setz"),    // SET Zero (BIS #2, SR)
        InstructionMnemonic::new("setn"),    // SET Negative (BIS #4, SR)
        InstructionMnemonic::new("dint"),    // Disable INTerrupts (BIC #8, SR)
        InstructionMnemonic::new("eint"),    // Enable INTerrupts (BIS #8, SR)
        InstructionMnemonic::new("nop"),     // No OPeration (MOV #0, R3)
        InstructionMnemonic::new("tst"),     // TeST (CMP #0, dst)
        InstructionMnemonic::new("inc"),     // INCrement (ADD #1, dst)
        InstructionMnemonic::new("incd"),    // INCrement Double (ADDC #2, dst)
        InstructionMnemonic::new("dec"),     // DECrement (SUB #1, dst)
        InstructionMnemonic::new("decd"),    // DECrement Double (SUBC #2, dst)
        InstructionMnemonic::new("adc"),     // ADd Carry to destination
        InstructionMnemonic::new("dadc"),    // Decimal ADd Carry
        InstructionMnemonic::new("rlc"),     // Rotate Left through Carry (ADDC dst)
        InstructionMnemonic::new("inv"),     // INVert (XOR #-1, dst)
        // === MSP430X Extended Instructions ===
        InstructionMnemonic::new("movx"),    // MOV extended (20-bit addressing)
        InstructionMnemonic::new("addx"),    // ADD extended
        InstructionMnemonic::new("subx"),    // SUB extended
        InstructionMnemonic::new("cmpx"),    // CMP extended
        InstructionMnemonic::new("callx"),   // CALL extended (20-bit CALLA encoding)
        InstructionMnemonic::new("pushx"),   // PUSH extended (PUSHX.A)
        InstructionMnemonic::new("popx"),    // POP extended (POPX.A)
        InstructionMnemonic::new("mova"),    // MOV Address (20-bit, MSP430X)
        InstructionMnemonic::new("cmpa"),    // CMP Address (20-bit)
        InstructionMnemonic::new("adda"),    // ADD Address (20-bit)
        InstructionMnemonic::new("suba"),    // SUB Address (20-bit)
        InstructionMnemonic::new("rrax"),    // RRA 20-bit (MSP430X)
        InstructionMnemonic::new("rrcx"),    // RRC 20-bit (MSP430X)
        InstructionMnemonic::new("pushma"),  // PUSH Multiple registers (MSP430X)
        InstructionMnemonic::new("popma"),   // POP Multiple registers (MSP430X)
    ]
}

impl ProcessorModule for Msp430Processor {
    fn name() -> &'static str {
        "Texas Instruments MSP430"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "msp430:LE:16:default",
                "TI MSP430 (16-bit, little-endian)",
                "MSP430",
                Endian::Little,
                16,
            ),
            Language::new(
                "msp430:LE:20:MSP430X",
                "TI MSP430X (20-bit, little-endian, extended addressing)",
                "MSP430X",
                Endian::Little,
                20,
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
    fn test_msp430_name() {
        assert_eq!(Msp430Processor::name(), "Texas Instruments MSP430");
    }

    #[test]
    fn test_msp430_registers() {
        let bank = Msp430Processor::registers();
        assert!(bank.len() > 60, "Expected many registers, got {}", bank.len());
        // CPU registers
        for i in 0..16 {
            assert!(bank.get(&format!("R{}", i)).is_some());
        }
        // Aliases
        assert!(bank.get("PC").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("SR").is_some());
        assert!(bank.get("CG1").is_some());
        assert!(bank.get("CG2").is_some());
        // MSP430X registers
        assert!(bank.get("PCX").is_some());
        assert!(bank.get("SRX").is_some());
        assert!(bank.get("SPX").is_some());
        assert!(bank.get("R0X").is_some());
        assert!(bank.get("R15X").is_some());
        // Constant generators
        assert!(bank.get("CG1_CONST4").is_some());
        assert!(bank.get("CG2_CONST1").is_some());
        // Port registers
        assert!(bank.get("P1IN").is_some());
        assert!(bank.get("P1OUT").is_some());
        assert!(bank.get("P1DIR").is_some());
        assert!(bank.get("P2IN").is_some());
        assert!(bank.get("P2OUT").is_some());
        // Timers
        assert!(bank.get("TA0CTL").is_some());
        assert!(bank.get("TA0R").is_some());
        assert!(bank.get("TA0CCR0").is_some());
        // ADC
        assert!(bank.get("ADC10CTL0").is_some());
        assert!(bank.get("ADC10MEM").is_some());
        // USCI
        assert!(bank.get("UCA0CTLW0").is_some());
        assert!(bank.get("UCA0RXBUF").is_some());
        assert!(bank.get("UCA0TXBUF").is_some());
        // Clock
        assert!(bank.get("DCOCTL").is_some());
        assert!(bank.get("BCSCTL1").is_some());
        // Watchdog
        assert!(bank.get("WDTCTL").is_some());
        // Flash
        assert!(bank.get("FCTL1").is_some());
        assert!(bank.get("FCTL3").is_some());
        // Multiplier
        assert!(bank.get("MPY").is_some());
        assert!(bank.get("RESLO").is_some());
        assert!(bank.get("RESHI").is_some());
    }

    #[test]
    fn test_msp430_sr_flags() {
        let bank = Msp430Processor::registers();
        let c = bank.get("C").unwrap();
        assert_eq!(c.parent.as_deref(), Some("R2"));
        assert_eq!(c.lsb, 0);
        assert_eq!(c.bit_size, 1);

        let z = bank.get("Z").unwrap();
        assert_eq!(z.lsb, 1);

        let n = bank.get("N").unwrap();
        assert_eq!(n.lsb, 2);

        let gie = bank.get("GIE").unwrap();
        assert_eq!(gie.lsb, 3);

        let cpuoff = bank.get("CPUOFF").unwrap();
        assert_eq!(cpuoff.lsb, 4);

        let oscoff = bank.get("OSCOFF").unwrap();
        assert_eq!(oscoff.lsb, 5);

        let scg0 = bank.get("SCG0").unwrap();
        assert_eq!(scg0.lsb, 6);

        let scg1 = bank.get("SCG1").unwrap();
        assert_eq!(scg1.lsb, 7);

        let v = bank.get("V").unwrap();
        assert_eq!(v.lsb, 8);
    }

    #[test]
    fn test_msp430_register_aliases() {
        let bank = Msp430Processor::registers();
        let pc = bank.get("PC").unwrap();
        assert_eq!(pc.parent.as_deref(), Some("R0"));
        assert_eq!(pc.bit_size, 16);

        let sp = bank.get("SP").unwrap();
        assert_eq!(sp.parent.as_deref(), Some("R1"));

        let sr = bank.get("SR").unwrap();
        assert_eq!(sr.parent.as_deref(), Some("R2"));

        let cg2 = bank.get("CG2").unwrap();
        assert_eq!(cg2.parent.as_deref(), Some("R3"));
    }

    #[test]
    fn test_msp430_register_bits() {
        let bank = Msp430Processor::registers();
        assert_eq!(bank.get("R0").unwrap().bit_size, 16);
        assert_eq!(bank.get("PC").unwrap().bit_size, 16);
        assert_eq!(bank.get("PCX").unwrap().bit_size, 20);
        assert_eq!(bank.get("SPX").unwrap().bit_size, 20);
        assert_eq!(bank.get("R15X").unwrap().bit_size, 20);
    }

    #[test]
    fn test_msp430_languages() {
        let langs = Msp430Processor::languages();
        assert!(langs.len() >= 2);
        assert!(langs.iter().any(|l| l.id == "msp430:LE:16:default"));
        assert!(langs.iter().any(|l| l.id == "msp430:LE:20:MSP430X"));
        assert!(langs.iter().all(|l| matches!(l.endian, Endian::Little)));
    }

    #[test]
    fn test_msp430_instructions() {
        let insts = Msp430Processor::instructions();
        assert!(insts.len() > 40);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        // Core double-operand
        assert!(texts.contains(&"mov"));
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"cmp"));
        assert!(texts.contains(&"and"));
        assert!(texts.contains(&"xor"));
        assert!(texts.contains(&"bic"));
        assert!(texts.contains(&"bis"));
        // Single-operand
        assert!(texts.contains(&"rrc"));
        assert!(texts.contains(&"rra"));
        assert!(texts.contains(&"swpb"));
        assert!(texts.contains(&"sxt"));
        assert!(texts.contains(&"call"));
        assert!(texts.contains(&"reti"));
        // Emulated
        assert!(texts.contains(&"push"));
        assert!(texts.contains(&"pop"));
        assert!(texts.contains(&"ret"));
        assert!(texts.contains(&"clr"));
        assert!(texts.contains(&"nop"));
        assert!(texts.contains(&"tst"));
        assert!(texts.contains(&"inc"));
        assert!(texts.contains(&"dec"));
        // Conditional jumps
        assert!(texts.contains(&"jne"));
        assert!(texts.contains(&"jnz"));
        assert!(texts.contains(&"jeq"));
        assert!(texts.contains(&"jz"));
        assert!(texts.contains(&"jc"));
        assert!(texts.contains(&"jnc"));
        assert!(texts.contains(&"jn"));
        assert!(texts.contains(&"jge"));
        assert!(texts.contains(&"jl"));
        // Bit manipulation
        assert!(texts.contains(&"setc"));
        assert!(texts.contains(&"clrc"));
        assert!(texts.contains(&"eint"));
        assert!(texts.contains(&"dint"));
        // MSP430X
        assert!(texts.contains(&"movx"));
        assert!(texts.contains(&"mova"));
        assert!(texts.contains(&"callx"));
    }
}
