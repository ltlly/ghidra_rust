//! Atmel AVR Processor Module
//!
//! Supports Atmel/Microchip AVR (ATmega, ATtiny, ATxmega, AVR32).
//!
//! The Atmel AVR is an 8-bit RISC microcontroller family introduced in 1996.
//! Features: 32 general-purpose working registers, Harvard architecture,
//! single-cycle execution for most instructions, and an extensive I/O register
//! file. Used in Arduino (ATmega328P), embedded systems, and automotive.
//!
//! ## Register space layout
//!
//! - Registers R0-R31:           0x0000 - 0x001F  (8-bit each)
//!   - R26:R27 = X pointer
//!   - R28:R29 = Y pointer
//!   - R30:R31 = Z pointer
//! - Status Register (SREG):     0x0020  (8-bit)
//!   - I (Global Interrupt Enable)
//!   - T (Bit Copy Storage)
//!   - H (Half Carry)
//!   - S (Sign, N ^ V)
//!   - V (Overflow)
//!   - N (Negative)
//!   - Z (Zero)
//!   - C (Carry)
//! - Stack Pointer (SP):         0x0022  (16-bit)
//!   - SPH: high byte
//!   - SPL: low byte
//! - Program Counter (PC):       0x0024  (22-bit max on large devices)
//! - RAMPX, RAMPY, RAMPZ:        0x0028 - 0x002A  (8-bit each, extended addressing)
//! - EIND (Extended Indirect):   0x002C  (8-bit, ATmega2560+)
//! - RAMPD (RAM Page D):         0x002D  (8-bit, ATxmega)
//! - EIMSK, EIFR (interrupt):    0x0030 - 0x0031 (8-bit each)

pub mod language_provider;

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Atmel AVR processor struct.
pub struct AvrProcessor;

/// Build the complete AVR register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- General Purpose Registers R0-R31 (8-bit each) ----
    for i in 0u32..32 {
        bank.add(Register::new(&format!("R{}", i), 8, i as u64));
    }

    // ---- Register Pairs (16-bit aliases) ----
    // Standard pairs (even-odd)
    for i in (0u32..32).step_by(2) {
        let pair_name = format!("R{}R{}", i, i + 1);
        bank.add(Register::new(&pair_name, 16, i as u64));
    }

    // ---- Pointer aliases (R26:R27 = X, R28:R29 = Y, R30:R31 = Z) ----
    bank.add(Register::sub_register("XL", 8, 26, "R26", 0));
    bank.add(Register::sub_register("XH", 8, 27, "R27", 0));
    bank.add(Register::sub_register("X", 16, 26, "R26", 0)); // X = R27:R26

    bank.add(Register::sub_register("YL", 8, 28, "R28", 0));
    bank.add(Register::sub_register("YH", 8, 29, "R29", 0));
    bank.add(Register::sub_register("Y", 16, 28, "R28", 0)); // Y = R29:R28

    bank.add(Register::sub_register("ZL", 8, 30, "R30", 0));
    bank.add(Register::sub_register("ZH", 8, 31, "R31", 0));
    bank.add(Register::sub_register("Z", 16, 30, "R30", 0)); // Z = R31:R30

    // ---- Status Register SREG (8-bit) ----
    bank.add(Register::new("SREG", 8, 0x0020));

    // SREG bit fields
    bank.add(Register::sub_register("C", 1, 0x0020, "SREG", 0)); // Carry Flag
    bank.add(Register::sub_register("Z_FLAG", 1, 0x0020, "SREG", 1)); // Zero Flag
    bank.add(Register::sub_register("N", 1, 0x0020, "SREG", 2)); // Negative Flag
    bank.add(Register::sub_register("V", 1, 0x0020, "SREG", 3)); // Two's Complement Overflow Flag
    bank.add(Register::sub_register("S", 1, 0x0020, "SREG", 4)); // Sign Flag (N xor V)
    bank.add(Register::sub_register("H", 1, 0x0020, "SREG", 5)); // Half Carry Flag
    bank.add(Register::sub_register("T", 1, 0x0020, "SREG", 6)); // Bit Copy Storage
    bank.add(Register::sub_register("I", 1, 0x0020, "SREG", 7)); // Global Interrupt Enable

    // ---- Stack Pointer (16-bit) ----
    bank.add(Register::new("SP", 16, 0x0022)); // Stack Pointer (16-bit)
    bank.add(Register::sub_register("SPL", 8, 0x0022, "SP", 0)); // SP low byte
    bank.add(Register::sub_register("SPH", 8, 0x0022, "SP", 8)); // SP high byte

    // ---- Program Counter (up to 22-bit for large devices) ----
    bank.add(Register::new("PC", 22, 0x0024)); // Program Counter
    bank.add(Register::sub_register("PCL", 8, 0x0024, "PC", 0));
    bank.add(Register::sub_register("PCH", 14, 0x0024, "PC", 8)); // Upper 14 bits

    // ---- Extended Addressing Registers (ATmega256 / ATxmega) ----
    bank.add(Register::new("RAMPX", 8, 0x0028)); // RAM Page X (extends X pointer)
    bank.add(Register::new("RAMPY", 8, 0x0029)); // RAM Page Y (extends Y pointer)
    bank.add(Register::new("RAMPZ", 8, 0x002A)); // RAM Page Z (extends Z pointer)

    // Extended pointer aliases (24-bit with RAMP)
    bank.add(Register::new("X_24", 24, 0x0028)); // RAMPX:R27:R26
    bank.add(Register::new("Y_24", 24, 0x0029)); // RAMPY:R29:R28
    bank.add(Register::new("Z_24", 24, 0x002A)); // RAMPZ:R31:R30

    // ---- Extended Indirect Register (ATmega2560+) ----
    bank.add(Register::new("EIND", 8, 0x002C)); // Extended Indirect

    // ---- RAM Page D (ATxmega) ----
    bank.add(Register::new("RAMPD", 8, 0x002D)); // RAM Page D

    // ---- Special pointer (ELPM/Z extended LPM) ----
    bank.add(Register::new("EIND_PC", 24, 0x002E)); // EIND:PC (combined for EIJMP/EICALL)

    // ---- CPU Control Registers ----
    bank.add(Register::new("MCUCR", 8, 0x0035)); // MCU Control Register
    bank.add(Register::sub_register("PUD", 1, 0x0035, "MCUCR", 4)); // Pull-up Disable
    bank.add(Register::sub_register("IVSEL", 1, 0x0035, "MCUCR", 1)); // Interrupt Vector Select
    bank.add(Register::sub_register("IVCE", 1, 0x0035, "MCUCR", 0)); // Interrupt Vector Change Enable

    bank.add(Register::new("MCUSR", 8, 0x0036)); // MCU Status Register
    bank.add(Register::sub_register("WDRF", 1, 0x0036, "MCUSR", 3)); // Watchdog Reset Flag
    bank.add(Register::sub_register("BORF", 1, 0x0036, "MCUSR", 2)); // Brown-Out Reset Flag
    bank.add(Register::sub_register("EXTRF", 1, 0x0036, "MCUSR", 1)); // External Reset Flag
    bank.add(Register::sub_register("PORF", 1, 0x0036, "MCUSR", 0)); // Power-On Reset Flag

    // ---- GPIOR (General Purpose I/O Registers) ----
    bank.add(Register::new("GPIOR0", 8, 0x0038));
    bank.add(Register::new("GPIOR1", 8, 0x0039));
    bank.add(Register::new("GPIOR2", 8, 0x003A));

    // ---- External Interrupt Registers ----
    bank.add(Register::new("EIMSK", 8, 0x003D)); // External Interrupt Mask
    bank.add(Register::new("EIFR", 8, 0x003E)); // External Interrupt Flag Register
    bank.add(Register::new("PCMSK0", 8, 0x003F)); // Pin Change Mask 0
    bank.add(Register::new("PCMSK1", 8, 0x0040)); // Pin Change Mask 1
    bank.add(Register::new("PCMSK2", 8, 0x0041)); // Pin Change Mask 2
    bank.add(Register::new("PCIFR", 8, 0x0042)); // Pin Change Interrupt Flag
    bank.add(Register::new("PCICR", 8, 0x0043)); // Pin Change Interrupt Control

    // ---- Standard I/O space (64 registers at 0x20-0x5F in I/O space) ----
    // These are the most common I/O-mapped registers

    // Timer/Counter 0
    bank.add(Register::new("TCCR0A", 8, 0x0044)); // Timer/Counter 0 Control A
    bank.add(Register::new("TCCR0B", 8, 0x0045)); // Timer/Counter 0 Control B
    bank.add(Register::new("TCNT0", 8, 0x0046)); // Timer/Counter 0 count
    bank.add(Register::new("OCR0A", 8, 0x0047)); // Output Compare 0A
    bank.add(Register::new("OCR0B", 8, 0x0048)); // Output Compare 0B

    // Timer/Counter 1 (16-bit)
    bank.add(Register::new("TCCR1A", 8, 0x0049));
    bank.add(Register::new("TCCR1B", 8, 0x004A));
    bank.add(Register::new("TCCR1C", 8, 0x004B)); // ATmega328P+
    bank.add(Register::new("TCNT1", 16, 0x004C)); // Timer/Counter 1
    bank.add(Register::sub_register("TCNT1L", 8, 0x004C, "TCNT1", 0));
    bank.add(Register::sub_register("TCNT1H", 8, 0x004C, "TCNT1", 8));
    bank.add(Register::new("OCR1A", 16, 0x004E)); // Output Compare 1A
    bank.add(Register::new("OCR1B", 16, 0x0050)); // Output Compare 1B
    bank.add(Register::new("ICR1", 16, 0x0052)); // Input Capture 1

    // Timer/Counter 2
    bank.add(Register::new("TCCR2A", 8, 0x0054));
    bank.add(Register::new("TCCR2B", 8, 0x0055));
    bank.add(Register::new("TCNT2", 8, 0x0056));
    bank.add(Register::new("OCR2A", 8, 0x0057));
    bank.add(Register::new("OCR2B", 8, 0x0058));

    // ADC
    bank.add(Register::new("ADMUX", 8, 0x0059)); // ADC Multiplexer
    bank.add(Register::new("ADCSRA", 8, 0x005A)); // ADC Control/Status A
    bank.add(Register::new("ADCSRB", 8, 0x005B)); // ADC Control/Status B
    bank.add(Register::new("ADCH", 8, 0x005C)); // ADC Data High
    bank.add(Register::new("ADCL", 8, 0x005D)); // ADC Data Low

    // USART
    bank.add(Register::new("UDR0", 8, 0x005E)); // USART Data Register
    bank.add(Register::new("UCSR0A", 8, 0x005F)); // USART Control/Status A
    bank.add(Register::new("UCSR0B", 8, 0x0060)); // USART Control/Status B
    bank.add(Register::new("UCSR0C", 8, 0x0061)); // USART Control/Status C
    bank.add(Register::new("UBRR0", 16, 0x0062)); // USART Baud Rate

    // SPI
    bank.add(Register::new("SPCR", 8, 0x0064)); // SPI Control
    bank.add(Register::new("SPSR", 8, 0x0065)); // SPI Status
    bank.add(Register::new("SPDR", 8, 0x0066)); // SPI Data

    // Port registers
    bank.add(Register::new("PORTB", 8, 0x0068));
    bank.add(Register::new("DDRB", 8, 0x0069)); // Data Direction B
    bank.add(Register::new("PINB", 8, 0x006A)); // Pin Input B

    bank.add(Register::new("PORTC", 8, 0x006B));
    bank.add(Register::new("DDRC", 8, 0x006C));
    bank.add(Register::new("PINC", 8, 0x006D));

    bank.add(Register::new("PORTD", 8, 0x006E));
    bank.add(Register::new("DDRD", 8, 0x006F));
    bank.add(Register::new("PIND", 8, 0x0070));

    // Watchdog
    bank.add(Register::new("WDTCSR", 8, 0x0071)); // Watchdog Timer Control

    // EEPROM
    bank.add(Register::new("EEAR", 16, 0x0072)); // EEPROM Address Register
    bank.add(Register::new("EEDR", 8, 0x0074)); // EEPROM Data Register
    bank.add(Register::new("EECR", 8, 0x0075)); // EEPROM Control Register

    // ---- ATxmega extensions ----
    bank.add(Register::new("CPU_CCP", 8, 0x0078)); // Configuration Change Protection
    bank.add(Register::new("OSC_CTRL", 8, 0x0079)); // Oscillator Control
    bank.add(Register::new("OSC_STATUS", 8, 0x007A)); // Oscillator Status
    bank.add(Register::new("CLK_CTRL", 8, 0x007B)); // System Clock Control
    bank.add(Register::new("CLK_PSCTRL", 8, 0x007C)); // Clock Prescaler Control

    bank
}

/// Build the AVR instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Arithmetic and Logic ===
        InstructionMnemonic::new("add"),
        InstructionMnemonic::new("adc"),
        InstructionMnemonic::new("adiw"),   // Add Immediate to Word
        InstructionMnemonic::new("sub"),
        InstructionMnemonic::new("sbc"),
        InstructionMnemonic::new("sbiw"),   // Subtract Immediate from Word
        InstructionMnemonic::new("and"),
        InstructionMnemonic::new("andi"),
        InstructionMnemonic::new("or"),
        InstructionMnemonic::new("ori"),
        InstructionMnemonic::new("eor"),    // Exclusive OR
        InstructionMnemonic::new("com"),    // One's Complement
        InstructionMnemonic::new("neg"),    // Two's Complement
        InstructionMnemonic::new("inc"),
        InstructionMnemonic::new("dec"),
        InstructionMnemonic::new("mul"),    // Unsigned Multiply
        InstructionMnemonic::new("muls"),   // Signed Multiply
        InstructionMnemonic::new("mulsu"),  // Signed with Unsigned Multiply
        InstructionMnemonic::new("fmul"),   // Fractional Multiply Unsigned
        InstructionMnemonic::new("fmuls"),  // Fractional Multiply Signed
        InstructionMnemonic::new("fmulsu"), // Fractional Multiply Signed*Unsigned
        InstructionMnemonic::new("des"),    // Data Encryption Standard (ATxmega)
        // === Compare ===
        InstructionMnemonic::new("cp"),
        InstructionMnemonic::new("cpc"),
        InstructionMnemonic::new("cpi"),
        InstructionMnemonic::new("cpse"),   // Compare, Skip if Equal
        // === Branch ===
        InstructionMnemonic::new("rjmp"),   // Relative Jump
        InstructionMnemonic::new("ijmp"),   // Indirect Jump (to Z)
        InstructionMnemonic::new("eijmp"),  // Extended Indirect Jump (ATmega256x)
        InstructionMnemonic::new("jmp"),    // Jump (4 words, < 8K devices use RJMP)
        InstructionMnemonic::new("rcall"),  // Relative Call
        InstructionMnemonic::new("icall"),  // Indirect Call (to Z)
        InstructionMnemonic::new("eicall"), // Extended Indirect Call (ATmega256x)
        InstructionMnemonic::new("call"),   // Call (4 words)
        InstructionMnemonic::new("ret"),    // Return
        InstructionMnemonic::new("reti"),   // Return from Interrupt
        // === Conditional Branch ===
        InstructionMnemonic::new("breq"),   // Branch if Equal (Z=1)
        InstructionMnemonic::new("brne"),   // Branch if Not Equal (Z=0)
        InstructionMnemonic::new("brcs"),   // Branch if Carry Set
        InstructionMnemonic::new("brcc"),   // Branch if Carry Cleared
        InstructionMnemonic::new("brsh"),   // Branch if Same or Higher (C=0) [BRSH = BRCC]
        InstructionMnemonic::new("brlo"),   // Branch if Lower (C=1)
        InstructionMnemonic::new("brmi"),   // Branch if Minus (N=1)
        InstructionMnemonic::new("brpl"),   // Branch if Plus (N=0)
        InstructionMnemonic::new("brge"),   // Branch if Greater or Equal, signed (S=0)
        InstructionMnemonic::new("brlt"),   // Branch if Less Than, signed (S=1)
        InstructionMnemonic::new("brhs"),   // Branch if Half Carry Set (H=1)
        InstructionMnemonic::new("brhc"),   // Branch if Half Carry Clear (H=0)
        InstructionMnemonic::new("brts"),   // Branch if T Flag Set
        InstructionMnemonic::new("brtc"),   // Branch if T Flag Cleared
        InstructionMnemonic::new("brvs"),   // Branch if Overflow Set
        InstructionMnemonic::new("brvc"),   // Branch if Overflow Cleared
        InstructionMnemonic::new("brie"),   // Branch if Interrupt Enabled (I=1)
        InstructionMnemonic::new("brid"),   // Branch if Interrupt Disabled (I=0)
        // === Skip if Bit ===
        InstructionMnemonic::new("sbrc"),   // Skip if Bit in Register Cleared
        InstructionMnemonic::new("sbrs"),   // Skip if Bit in Register Set
        InstructionMnemonic::new("sbic"),   // Skip if Bit in I/O Cleared
        InstructionMnemonic::new("sbis"),   // Skip if Bit in I/O Set
        // === Data Transfer ===
        InstructionMnemonic::new("mov"),
        InstructionMnemonic::new("movw"),   // Copy Register Word (pair)
        InstructionMnemonic::new("ldi"),    // Load Immediate
        InstructionMnemonic::new("ld"),     // Load Indirect
        InstructionMnemonic::new("lds"),    // Load Direct from SRAM (16-bit address)
        InstructionMnemonic::new("ldd"),    // Load Indirect with Displacement
        // Post-increment/pre-decrement variants
        InstructionMnemonic::new("ld_x"),        // LD Rd, X
        InstructionMnemonic::new("ld_x_plus"),   // LD Rd, X+
        InstructionMnemonic::new("ld_minus_x"),  // LD Rd, -X
        InstructionMnemonic::new("ld_y"),        // LD Rd, Y
        InstructionMnemonic::new("ld_y_plus"),   // LD Rd, Y+
        InstructionMnemonic::new("ld_minus_y"),  // LD Rd, -Y
        InstructionMnemonic::new("ld_z"),        // LD Rd, Z
        InstructionMnemonic::new("ld_z_plus"),   // LD Rd, Z+
        InstructionMnemonic::new("ld_minus_z"),  // LD Rd, -Z
        // Store variants
        InstructionMnemonic::new("st"),     // Store Indirect
        InstructionMnemonic::new("sts"),    // Store Direct to SRAM
        InstructionMnemonic::new("std"),    // Store Indirect with Displacement
        InstructionMnemonic::new("st_x"),        // ST X, Rr
        InstructionMnemonic::new("st_x_plus"),   // ST X+, Rr
        InstructionMnemonic::new("st_minus_x"),  // ST -X, Rr
        InstructionMnemonic::new("st_y"),        // ST Y, Rr
        InstructionMnemonic::new("st_y_plus"),   // ST Y+, Rr
        InstructionMnemonic::new("st_minus_y"),  // ST -Y, Rr
        InstructionMnemonic::new("st_z"),        // ST Z, Rr
        InstructionMnemonic::new("st_z_plus"),   // ST Z+, Rr
        InstructionMnemonic::new("st_minus_z"),  // ST -Z, Rr
        // === Program Memory ===
        InstructionMnemonic::new("lpm"),    // Load Program Memory
        InstructionMnemonic::new("lpm_z"),       // LPM Rd, Z
        InstructionMnemonic::new("lpm_z_plus"),  // LPM Rd, Z+
        InstructionMnemonic::new("elpm"),   // Extended LPM (with RAMPZ)
        InstructionMnemonic::new("elpm_z"),
        InstructionMnemonic::new("elpm_z_plus"),
        InstructionMnemonic::new("spm"),    // Store Program Memory
        InstructionMnemonic::new("spm_z_plus"),  // SPM Z+ (page erase/write)
        // === Stack ===
        InstructionMnemonic::new("push"),
        InstructionMnemonic::new("pop"),
        // === I/O ===
        InstructionMnemonic::new("in"),
        InstructionMnemonic::new("out"),
        // === Bit and Bit-Test ===
        InstructionMnemonic::new("sbi"),     // Set Bit in I/O
        InstructionMnemonic::new("cbi"),     // Clear Bit in I/O
        InstructionMnemonic::new("lsl"),     // Logical Shift Left
        InstructionMnemonic::new("lsr"),     // Logical Shift Right
        InstructionMnemonic::new("rol"),     // Rotate Left through Carry
        InstructionMnemonic::new("ror"),     // Rotate Right through Carry
        InstructionMnemonic::new("asr"),     // Arithmetic Shift Right
        InstructionMnemonic::new("swap"),    // Swap Nibbles
        // Bit set/clear in SREG
        InstructionMnemonic::new("bset"),    // Bit Set in SREG
        InstructionMnemonic::new("bclr"),    // Bit Clear in SREG
        // Specific SREG bit mnemonics
        InstructionMnemonic::new("sec"),     // Set Carry
        InstructionMnemonic::new("clc"),     // Clear Carry
        InstructionMnemonic::new("sen"),     // Set Negative
        InstructionMnemonic::new("cln"),     // Clear Negative
        InstructionMnemonic::new("sez"),     // Set Zero
        InstructionMnemonic::new("clz"),     // Clear Zero
        InstructionMnemonic::new("sei"),     // Set Global Interrupt
        InstructionMnemonic::new("cli"),     // Clear Global Interrupt
        InstructionMnemonic::new("ses"),     // Set Signed
        InstructionMnemonic::new("cls"),     // Clear Signed
        InstructionMnemonic::new("sev"),     // Set Overflow
        InstructionMnemonic::new("clv"),     // Clear Overflow
        InstructionMnemonic::new("set"),     // Set T flag
        InstructionMnemonic::new("clt"),     // Clear T flag
        InstructionMnemonic::new("seh"),     // Set Half-carry
        InstructionMnemonic::new("clh"),     // Clear Half-carry
        // === Misc / Control ===
        InstructionMnemonic::new("nop"),
        InstructionMnemonic::new("sleep"),
        InstructionMnemonic::new("wdr"),     // Watchdog Reset
        InstructionMnemonic::new("break"),   // BREAK (debug)
        InstructionMnemonic::new("xch"),     // EXCHange (ATxmega)
        InstructionMnemonic::new("las"),     // Load And Set (ATxmega)
        InstructionMnemonic::new("lac"),     // Load And Clear (ATxmega)
        InstructionMnemonic::new("lat"),     // Load And Toggle (ATxmega)
    ]
}

impl ProcessorModule for AvrProcessor {
    fn name() -> &'static str {
        "Atmel AVR"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "avr:LE:8:default",
                "Atmel AVR (8-bit, ATmega/ATtiny baseline)",
                "AVR",
                Endian::Little,
                16,
            ),
            Language::new(
                "avr:LE:8:ATmega",
                "Atmel ATmega (8-bit, classic AVR core)",
                "ATmega",
                Endian::Little,
                16,
            ),
            Language::new(
                "avr:LE:8:ATtiny",
                "Atmel ATtiny (8-bit, reduced AVR core)",
                "ATtiny",
                Endian::Little,
                16,
            ),
            Language::new(
                "avr:LE:8:ATxmega",
                "Atmel ATxmega (8-bit, enhanced AVR core)",
                "ATxmega",
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
    fn test_avr_name() {
        assert_eq!(AvrProcessor::name(), "Atmel AVR");
    }

    #[test]
    fn test_avr_registers() {
        let bank = AvrProcessor::registers();
        assert!(bank.len() > 80, "Expected many registers, got {}", bank.len());
        // General-purpose registers
        for i in 0..32 {
            assert!(bank.get(&format!("R{}", i)).is_some());
        }
        // Pointer aliases
        assert!(bank.get("X").is_some());
        assert!(bank.get("XL").is_some());
        assert!(bank.get("XH").is_some());
        assert!(bank.get("Y").is_some());
        assert!(bank.get("YL").is_some());
        assert!(bank.get("YH").is_some());
        assert!(bank.get("Z").is_some());
        assert!(bank.get("ZL").is_some());
        assert!(bank.get("ZH").is_some());
        // Status/Control
        assert!(bank.get("SREG").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("PC").is_some());
        // Extended addressing
        assert!(bank.get("RAMPX").is_some());
        assert!(bank.get("RAMPY").is_some());
        assert!(bank.get("RAMPZ").is_some());
        assert!(bank.get("EIND").is_some());
        // CPU control
        assert!(bank.get("MCUCR").is_some());
        assert!(bank.get("MCUSR").is_some());
        // IO
        assert!(bank.get("PORTB").is_some());
        assert!(bank.get("DDRB").is_some());
        assert!(bank.get("PINB").is_some());
        assert!(bank.get("PORTC").is_some());
        assert!(bank.get("PORTD").is_some());
        // Timers
        assert!(bank.get("TCCR0A").is_some());
        assert!(bank.get("TCNT0").is_some());
        assert!(bank.get("TCNT1").is_some());
        assert!(bank.get("OCR1A").is_some());
        // ADC
        assert!(bank.get("ADMUX").is_some());
        assert!(bank.get("ADCH").is_some());
        assert!(bank.get("ADCL").is_some());
        // USART
        assert!(bank.get("UDR0").is_some());
        assert!(bank.get("UCSR0A").is_some());
        // SPI
        assert!(bank.get("SPCR").is_some());
        assert!(bank.get("SPDR").is_some());
        // EEPROM
        assert!(bank.get("EEAR").is_some());
        assert!(bank.get("EEDR").is_some());
        assert!(bank.get("EECR").is_some());
    }

    #[test]
    fn test_avr_sreg_flags() {
        let bank = AvrProcessor::registers();
        let c = bank.get("C").unwrap();
        assert_eq!(c.parent.as_deref(), Some("SREG"));
        assert_eq!(c.lsb, 0);
        assert_eq!(c.bit_size, 1);

        let z = bank.get("Z_FLAG").unwrap();
        assert_eq!(z.lsb, 1);

        let n = bank.get("N").unwrap();
        assert_eq!(n.lsb, 2);

        let v = bank.get("V").unwrap();
        assert_eq!(v.lsb, 3);

        let h = bank.get("H").unwrap();
        assert_eq!(h.lsb, 5);

        let t = bank.get("T").unwrap();
        assert_eq!(t.lsb, 6);

        let i = bank.get("I").unwrap();
        assert_eq!(i.lsb, 7);
    }

    #[test]
    fn test_avr_pointer_aliases() {
        let bank = AvrProcessor::registers();
        let x = bank.get("X").unwrap();
        assert_eq!(x.bit_size, 16);
        assert_eq!(x.parent.as_deref(), Some("R26"));
        assert_eq!(x.lsb, 0);

        let xh = bank.get("XH").unwrap();
        assert_eq!(xh.parent.as_deref(), Some("R27"));
        assert_eq!(xh.bit_size, 8);

        let y = bank.get("Y").unwrap();
        assert_eq!(y.parent.as_deref(), Some("R28"));

        let z = bank.get("Z").unwrap();
        assert_eq!(z.parent.as_deref(), Some("R30"));
    }

    #[test]
    fn test_avr_register_bits() {
        let bank = AvrProcessor::registers();
        assert_eq!(bank.get("R0").unwrap().bit_size, 8);
        assert_eq!(bank.get("SP").unwrap().bit_size, 16);
        assert_eq!(bank.get("PC").unwrap().bit_size, 22);
        assert_eq!(bank.get("X_24").unwrap().bit_size, 24);
    }

    #[test]
    fn test_avr_languages() {
        let langs = AvrProcessor::languages();
        assert!(langs.len() >= 4);
        assert!(langs.iter().any(|l| l.id == "avr:LE:8:default"));
        assert!(langs.iter().any(|l| l.id == "avr:LE:8:ATmega"));
        assert!(langs.iter().any(|l| l.id == "avr:LE:8:ATtiny"));
        assert!(langs.iter().any(|l| l.id == "avr:LE:8:ATxmega"));
    }

    #[test]
    fn test_avr_instructions() {
        let insts = AvrProcessor::instructions();
        assert!(insts.len() > 80);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"adc"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"sbc"));
        assert!(texts.contains(&"mul"));
        assert!(texts.contains(&"rjmp"));
        assert!(texts.contains(&"ijmp"));
        assert!(texts.contains(&"rcall"));
        assert!(texts.contains(&"icall"));
        assert!(texts.contains(&"ret"));
        assert!(texts.contains(&"reti"));
        assert!(texts.contains(&"breq"));
        assert!(texts.contains(&"brne"));
        assert!(texts.contains(&"brcs"));
        assert!(texts.contains(&"brcc"));
        assert!(texts.contains(&"mov"));
        assert!(texts.contains(&"ldi"));
        assert!(texts.contains(&"ld"));
        assert!(texts.contains(&"st"));
        assert!(texts.contains(&"push"));
        assert!(texts.contains(&"pop"));
        assert!(texts.contains(&"in"));
        assert!(texts.contains(&"out"));
        assert!(texts.contains(&"sbi"));
        assert!(texts.contains(&"cbi"));
        assert!(texts.contains(&"nop"));
        assert!(texts.contains(&"sei"));
        assert!(texts.contains(&"cli"));
        assert!(texts.contains(&"sec"));
        assert!(texts.contains(&"clc"));
    }
}
