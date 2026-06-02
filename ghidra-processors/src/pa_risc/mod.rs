//! HP PA-RISC Processor Module
//!
//! Supports Hewlett-Packard Precision Architecture RISC (PA-RISC) ISA variants
//! including PA-RISC 1.0, 1.1, and 2.0 in both 32-bit (narrow) and 64-bit
//! (wide) modes.
//!
//! ## Architecture overview
//! - 32 general-purpose registers: GR0-GR31
//!   - GR0 = always zero
//!   - GR1 = addil target (linkage table pointer)
//!   - GR2 = return pointer (RP)
//!   - GR30 = stack pointer (SP)
//! - 8 space registers: SR0-SR7
//! - 32 control registers: CR0-CR31 (some privileged)
//! - 32 floating-point registers: FR0-FR31 (64-bit in PA 2.0 wide mode)
//! - Condition nullification with each instruction
//! - Wide (64-bit) vs narrow (32-bit) mode
//!
//! ## Register space layout
//! - GPR (GR0-GR31):       0x0000 - 0x00F8  (64-bit in wide, 32-bit in narrow)
//! - Space reg (SR0-SR7):  0x0100 - 0x011C  (32-bit each, space IDs)
//! - Control reg (CR0-31): 0x0200 - 0x02FC  (32-bit each)
//! - FPU (FR0-FR31):       0x0300 - 0x03F8  (64-bit each)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// HP PA-RISC processor struct.
pub struct PaRiscProcessor;

/// Build the complete PA-RISC register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- General-purpose registers GR0-GR31 (32-bit narrow / 64-bit wide) ----
    // GR0: hardwired to zero
    // GR1: target of ADDL instruction (linkage table pointer in PIC code)
    // GR2: return pointer (RP) - holds return address for BLE
    // GR3-GR18: general-purpose / parameter passing
    // GR19: linkage table pointer (shared library)
    // GR20-GR22: general
    // GR23: argument pointer (AP) / arg3
    // GR24: arg2
    // GR25: arg1
    // GR26: arg0
    // GR27: data pointer (DP) / global pointer
    // GR28: return value (ret0)
    // GR29: return value (ret1)
    // GR30: stack pointer (SP)
    // GR31: millicode return pointer (MRP)
    for i in 0..32u32 {
        bank.add(Register::new(
            &format!("GR{}", i),
            64,
            (i as u64) * 8,
        ));
    }

    // Register aliases for conventional usage
    bank.add(Register::sub_register("ZERO", 64, 0 * 8, "GR0", 0));
    bank.add(Register::sub_register("RP", 64, 2 * 8, "GR2", 0));
    bank.add(Register::sub_register("AP", 64, 23 * 8, "GR23", 0)); // Argument pointer
    bank.add(Register::sub_register("ARG0", 64, 26 * 8, "GR26", 0));
    bank.add(Register::sub_register("ARG1", 64, 25 * 8, "GR25", 0));
    bank.add(Register::sub_register("ARG2", 64, 24 * 8, "GR24", 0));
    bank.add(Register::sub_register("ARG3", 64, 23 * 8, "GR23", 0));
    bank.add(Register::sub_register("DP", 64, 27 * 8, "GR27", 0)); // Data pointer
    bank.add(Register::sub_register("RET0", 64, 28 * 8, "GR28", 0)); // Return value 0
    bank.add(Register::sub_register("RET1", 64, 29 * 8, "GR29", 0)); // Return value 1
    bank.add(Register::sub_register("SP", 64, 30 * 8, "GR30", 0));
    bank.add(Register::sub_register("MRP", 64, 31 * 8, "GR31", 0)); // Millicode return ptr
    bank.add(Register::sub_register("LTP", 64, 19 * 8, "GR19", 0)); // Linkage table ptr

    // ---- Program counter ----
    bank.add(Register::new("PC", 64, 0x0100));

    // ---- Space registers SR0-SR7 (32-bit) ----
    for i in 0..8u32 {
        bank.add(Register::new(
            &format!("SR{}", i),
            32,
            0x0200 + (i as u64) * 4,
        ));
    }

    // Space register conventional usage
    bank.add(Register::sub_register("SR_USER", 32, 0x0200 + 0 * 4, "SR0", 0));
    bank.add(Register::sub_register("SR_KERN", 32, 0x0200 + 4 * 4, "SR4", 0)); // Kernel space
    bank.add(Register::sub_register("SR_KERN2", 32, 0x0200 + 5 * 4, "SR5", 0));

    // ---- Control registers CR0-CR31 (32-bit) ----
    // CR0: null (recovery counter on PA 1.X)
    bank.add(Register::new("CR0", 32, 0x0300));
    bank.add(Register::new("CR1", 32, 0x0304)); // Interval timer
    bank.add(Register::new("CR2", 32, 0x0308)); // Interval timer
    bank.add(Register::new("CR3", 32, 0x030C)); // Interval timer
    bank.add(Register::new("CR4", 32, 0x0310)); // Interval timer
    bank.add(Register::new("CR5", 32, 0x0314)); // Interval timer
    bank.add(Register::new("CR6", 32, 0x0318)); // Interval timer
    bank.add(Register::new("CR7", 32, 0x031C)); // Interval timer
    bank.add(Register::new("CR8", 32, 0x0320)); // Protection ID 1
    bank.add(Register::new("CR9", 32, 0x0324)); // Protection ID 2
    bank.add(Register::new("CR10", 32, 0x0328)); // Coprocessor CCB
    bank.add(Register::new("CR11", 32, 0x032C)); // SAR - shift amount register
    bank.add(Register::new("CR12", 32, 0x0330)); // Coprocessor CCB
    bank.add(Register::new("CR13", 32, 0x0334)); // Coprocessor CCB
    bank.add(Register::new("CR14", 32, 0x0338)); // Interrupt vector address / EIRR
    bank.add(Register::new("CR15", 32, 0x033C)); // EIEM (external interrupt enable mask)
    bank.add(Register::new("CR16", 32, 0x0340)); // ITMR (interval timer match)
    bank.add(Register::new("CR17", 32, 0x0344)); // PCSQ front (previous code space queue)
    bank.add(Register::new("CR18", 32, 0x0348)); // PCSQ back
    bank.add(Register::new("CR19", 32, 0x034C)); // IOR (interrupt queue)
    bank.add(Register::new("CR20", 32, 0x0350)); // ISR (interrupt stack register)
    bank.add(Register::new("CR21", 32, 0x0354)); // IOR (interrupt offset register)
    bank.add(Register::new("CR22", 32, 0x0358)); // IPSW (interrupt PSW)
    bank.add(Register::new("CR23", 32, 0x035C)); // EIRR (ext interrupt request)
    bank.add(Register::new("CR24", 32, 0x0360)); // TR breakpoint reg 0
    bank.add(Register::new("CR25", 32, 0x0364)); // TR breakpoint reg 1
    bank.add(Register::new("CR26", 32, 0x0368)); // TR breakpoint reg 2
    bank.add(Register::new("CR27", 32, 0x036C)); // TR breakpoint reg 3
    bank.add(Register::new("CR28", 32, 0x0370)); // TR0 (translation reg 0)
    bank.add(Register::new("CR29", 32, 0x0374)); // TR1
    bank.add(Register::new("CR30", 32, 0x0378)); // TR2
    bank.add(Register::new("CR31", 32, 0x037C)); // TR3

    // Aliases for commonly-referenced control registers
    bank.add(Register::new("SAR", 32, 0x032C)); // Explicit SAR alias
    bank.add(Register::new("EIEM", 32, 0x033C)); // Explicit EIEM alias
    bank.add(Register::new("ITMR", 32, 0x0340)); // Explicit ITMR alias
    bank.add(Register::new("PCSQ_F", 32, 0x0344)); // Explicit PCSQ front
    bank.add(Register::new("PCSQ_B", 32, 0x0348)); // Explicit PCSQ back
    bank.add(Register::new("IPSW", 32, 0x0358)); // Explicit IPSW alias

    // ---- Processor Status Word (PSW) flags ----
    bank.add(Register::new("PSW", 32, 0x0400));
    // Individual PSW bit fields
    bank.add(Register::sub_register("PSW_E", 1, 0x0400, "PSW", 0));  // Little-endian data refs
    bank.add(Register::sub_register("PSW_T", 1, 0x0400, "PSW", 1));  // Taken branch trace
    bank.add(Register::sub_register("PSW_H", 1, 0x0400, "PSW", 2));  // Higher-privilege transfer
    bank.add(Register::sub_register("PSW_L", 1, 0x0400, "PSW", 3));  // Lower-privilege transfer
    bank.add(Register::sub_register("PSW_N", 1, 0x0400, "PSW", 4));  // Nullify
    bank.add(Register::sub_register("PSW_X", 1, 0x0400, "PSW", 5));  // Data memory protect disable
    bank.add(Register::sub_register("PSW_B", 1, 0x0400, "PSW", 6));  // Taken branch
    bank.add(Register::sub_register("PSW_C", 1, 0x0400, "PSW", 7));  // Code translation disabled
    bank.add(Register::sub_register("PSW_V", 1, 0x0400, "PSW", 8));  // Divide step correction
    bank.add(Register::sub_register("PSW_M", 1, 0x0400, "PSW", 9));  // High-priority machine check
    bank.add(Register::sub_register("PSW_F", 1, 0x0400, "PSW", 10)); // Floating-point coprocessor
    bank.add(Register::sub_register("PSW_R", 1, 0x0400, "PSW", 11)); // Recovery counter
    bank.add(Register::sub_register("PSW_Q", 1, 0x0400, "PSW", 12)); // Interrupt collection
    bank.add(Register::sub_register("PSW_P", 1, 0x0400, "PSW", 13)); // Protection ID check
    bank.add(Register::sub_register("PSW_D", 1, 0x0400, "PSW", 14)); // Data address translation
    bank.add(Register::sub_register("PSW_I", 1, 0x0400, "PSW", 15)); // External/IO interrupt mask
    bank.add(Register::sub_register("PSW_G", 1, 0x0400, "PSW", 16)); // Debug
    bank.add(Register::sub_register("PSW_W", 1, 0x0400, "PSW", 17)); // Wide mode (64-bit)
    bank.add(Register::sub_register("PSW_Y", 1, 0x0400, "PSW", 18)); // (PA 2.0)
    bank.add(Register::sub_register("PSW_Z", 1, 0x0400, "PSW", 19)); // (PA 2.0)
    // Flags as sub-registers
    bank.add(Register::sub_register("PSW_CB", 8, 0x0400, "PSW", 28)); // Carry/borrow bits

    // ---- Floating-point registers FR0-FR31 (64-bit) ----
    for i in 0..32u32 {
        bank.add(Register::new(
            &format!("FR{}", i),
            64,
            0x0500 + (i as u64) * 8,
        ));
    }

    // FPU aliases
    bank.add(Register::sub_register("FR_FULL", 64, 0x0500 + 0 * 8, "FR0", 0));
    bank.add(Register::sub_register("FR_L", 32, 0x0500 + 0 * 8, "FR0", 0)); // Left half (MSB) of FR
    bank.add(Register::sub_register("FR_R", 32, 0x0500 + 0 * 8, "FR0", 32)); // Right half (LSB) of FR

    // FP status register
    bank.add(Register::new("FPSR", 32, 0x0600)); // Floating-point status register
    bank.add(Register::sub_register("FP_C", 1, 0x0600, "FPSR", 0));

    // ---- Multiply / Divide step register ----
    bank.add(Register::new("MDSR", 32, 0x0700)); // Multiply/divide step register

    bank
}

/// Build the PA-RISC instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === ALU / arithmetic ===
        InstructionMnemonic::new("add"),       // Add
        InstructionMnemonic::new("addl"),      // Add logical (32-bit)
        InstructionMnemonic::new("addo"),      // Add with overflow trap
        InstructionMnemonic::new("addi"),      // Add immediate
        InstructionMnemonic::new("addil"),     // Add immediate left (load offset high 21 bits)
        InstructionMnemonic::new("sub"),       // Subtract
        InstructionMnemonic::new("subo"),      // Subtract with overflow trap
        InstructionMnemonic::new("subi"),      // Subtract immediate
        InstructionMnemonic::new("sh1add"),    // Shift left 1 + add (index*2+base)
        InstructionMnemonic::new("sh2add"),    // Shift left 2 + add (index*4+base)
        InstructionMnemonic::new("sh3add"),    // Shift left 3 + add (index*8+base)
        InstructionMnemonic::new("sh1addl"),   // Shift left 1 + add logical
        InstructionMnemonic::new("sh2addl"),   // Shift left 2 + add logical
        InstructionMnemonic::new("sh3addl"),   // Shift left 3 + add logical
        // === Logical ===
        InstructionMnemonic::new("and"),       // Bitwise AND
        InstructionMnemonic::new("andcm"),     // Complement source then AND
        InstructionMnemonic::new("or"),        // Bitwise OR
        InstructionMnemonic::new("xor"),       // Bitwise XOR
        // === Shift / Extract / Deposit ===
        InstructionMnemonic::new("vshd"),      // Variable shift double (64-bit shift/rotate)
        InstructionMnemonic::new("shd"),       // Shift double
        InstructionMnemonic::new("extrw"),     // Extract word (right-justified)
        InstructionMnemonic::new("extrw_s"),   // Extract word with sign extend
        InstructionMnemonic::new("extru"),     // Extract unsigned (bit-field extract)
        InstructionMnemonic::new("extrs"),     // Extract signed (bit-field extract signed)
        InstructionMnemonic::new("depw"),      // Deposit word
        InstructionMnemonic::new("depwi"),     // Deposit word immediate
        InstructionMnemonic::new("dep"),       // Deposit bit-field
        InstructionMnemonic::new("depi"),      // Deposit bit-field immediate
        InstructionMnemonic::new("zvdep"),     // Zero-var deposit (parallel)
        InstructionMnemonic::new("zvdepi"),    // Zero-var deposit immediate
        InstructionMnemonic::new("vextru"),    // Variable extract unsigned
        InstructionMnemonic::new("vextrs"),    // Variable extract signed
        // === Branch ===
        InstructionMnemonic::new("b"),         // Branch (unconditional, PC-relative)
        InstructionMnemonic::new("bl"),        // Branch and link (save RP=GR2)
        InstructionMnemonic::new("ble"),       // Branch and link external (inter-space)
        InstructionMnemonic::new("bv"),        // Branch vectored (register target)
        InstructionMnemonic::new("bve"),       // Branch vectored external
        InstructionMnemonic::new("be"),        // Branch external (privileged)
        InstructionMnemonic::new("blr"),       // Branch and link register
        InstructionMnemonic::new("gate"),      // Gate (inter-space, privileged)
        // === Compare / condition ===
        InstructionMnemonic::new("combt"),     // Compare and branch (true)
        InstructionMnemonic::new("combf"),     // Compare and branch (false)
        InstructionMnemonic::new("comibt"),    // Compare immediate and branch (true)
        InstructionMnemonic::new("comibf"),    // Compare immediate and branch (false)
        InstructionMnemonic::new("comclr"),    // Compare and clear (true)
        InstructionMnemonic::new("comiclr"),   // Compare immediate and clear
        InstructionMnemonic::new("addbt"),     // Add and branch (true)
        InstructionMnemonic::new("addbf"),     // Add and branch (false)
        InstructionMnemonic::new("addibt"),    // Add immediate and branch (true)
        InstructionMnemonic::new("addibf"),    // Add immediate and branch (false)
        InstructionMnemonic::new("movb"),      // Move and branch (true)
        InstructionMnemonic::new("movib"),     // Move immediate and branch
        InstructionMnemonic::new("bb"),        // Branch on bit (in register)
        // Condition codes used for nullification
        InstructionMnemonic::new("cmpb"),      // Compare (used with combt/bf)
        InstructionMnemonic::new("cmpib"),     // Compare immediate
        // === Load / Store ===
        InstructionMnemonic::new("ldw"),       // Load word
        InstructionMnemonic::new("ldh"),       // Load half-word
        InstructionMnemonic::new("ldb"),       // Load byte
        InstructionMnemonic::new("ldwm"),      // Load word, modify index
        InstructionMnemonic::new("std"),       // Store double-word
        InstructionMnemonic::new("stw"),       // Store word
        InstructionMnemonic::new("sth"),       // Store half-word
        InstructionMnemonic::new("stb"),       // Store byte
        InstructionMnemonic::new("stwm"),      // Store word, modify index
        InstructionMnemonic::new("ldd"),       // Load double-word
        InstructionMnemonic::new("ldda"),      // Load double-word, modify index
        InstructionMnemonic::new("ldwa"),      // Load word absolute
        InstructionMnemonic::new("ldcw"),      // Load and clear word (semaphore)
        InstructionMnemonic::new("ldcws"),     // Load and clear word short
        InstructionMnemonic::new("stbys"),     // Store bytes (partial-word store)
        InstructionMnemonic::new("ldsid"),     // Load space ID
        InstructionMnemonic::new("mtsp"),      // Move to space register
        InstructionMnemonic::new("mfsp"),      // Move from space register
        InstructionMnemonic::new("ldil"),      // Load immediate left (21 bits)
        InstructionMnemonic::new("ldo"),       // Load offset (ldo offset(base), dest)
        InstructionMnemonic::new("ldsid"),     // Load space identifier
        // === Multiply / Divide ===
        InstructionMnemonic::new("xmpyu"),     // Extended multiply unsigned (32x32 -> 64)
        InstructionMnemonic::new("ds"),        // Divide step
        // === System / Privileged ===
        InstructionMnemonic::new("break"),     // Break (debug)
        InstructionMnemonic::new("sync"),      // Memory synchronization
        InstructionMnemonic::new("syncdma"),   // Sync DMA
        InstructionMnemonic::new("rfi"),       // Return from interrupt
        InstructionMnemonic::new("rfir"),      // Return from interrupt (recovery)
        InstructionMnemonic::new("ssm"),       // Set system mask
        InstructionMnemonic::new("rsm"),       // Reset system mask
        InstructionMnemonic::new("mtsm"),      // Move to system mask
        InstructionMnemonic::new("lci"),       // Load cache instruction
        InstructionMnemonic::new("diag"),      // Diagnose
        InstructionMnemonic::new("prob"),      // Probe access
        InstructionMnemonic::new("prober"),    // Probe read access
        InstructionMnemonic::new("probew"),    // Probe write access
        InstructionMnemonic::new("lpa"),       // Load physical address
        InstructionMnemonic::new("pdtlb"),     // Purge data TLB
        InstructionMnemonic::new("pitlb"),     // Purge instruction TLB
        InstructionMnemonic::new("pdtlbe"),    // Purge data TLB entry
        InstructionMnemonic::new("pitlbe"),    // Purge instruction TLB entry
        InstructionMnemonic::new("idtlbt"),    // Insert data TLB
        InstructionMnemonic::new("iitlbt"),    // Insert instruction TLB
        InstructionMnemonic::new("lha"),       // Load hash address
        InstructionMnemonic::new("lci"),       // Load cache instruction
        InstructionMnemonic::new("pdc"),       // Purge data cache
        InstructionMnemonic::new("fic"),       // Flush instruction cache
        InstructionMnemonic::new("fdc"),       // Flush data cache
        InstructionMnemonic::new("fdce"),      // Flush data cache entry
        InstructionMnemonic::new("fice"),      // Flush instruction cache entry
        // === Control register move ===
        InstructionMnemonic::new("mtctl"),     // Move to control register
        InstructionMnemonic::new("mfctl"),     // Move from control register
        // === FPU instructions ===
        InstructionMnemonic::new("fadd"),      // FP add (single/double)
        InstructionMnemonic::new("fsub"),      // FP subtract
        InstructionMnemonic::new("fmpy"),      // FP multiply
        InstructionMnemonic::new("fdiv"),      // FP divide
        InstructionMnemonic::new("fsqrt"),     // FP square root
        InstructionMnemonic::new("fabs"),      // FP absolute value
        InstructionMnemonic::new("frnd"),      // FP round
        InstructionMnemonic::new("fcpy"),      // FP copy
        InstructionMnemonic::new("fcmp"),      // FP compare
        InstructionMnemonic::new("ftest"),     // FP test
        InstructionMnemonic::new("fcnv"),      // FP convert
        InstructionMnemonic::new("fcnvff"),    // FP convert format
        InstructionMnemonic::new("fcnvxf"),    // Convert integer to FP
        InstructionMnemonic::new("fcnvfx"),    // Convert FP to integer (truncate)
        InstructionMnemonic::new("fcnvfxt"),   // Convert FP to integer (round toward -inf)
        InstructionMnemonic::new("fldw"),      // FP load word
        InstructionMnemonic::new("fstw"),      // FP store word
        InstructionMnemonic::new("fldd"),      // FP load double
        InstructionMnemonic::new("fstd"),      // FP store double
        InstructionMnemonic::new("fldwx"),     // FP load word, modify index
        InstructionMnemonic::new("fstwx"),     // FP store word, modify index
        InstructionMnemonic::new("flddx"),     // FP load double, modify index
        InstructionMnemonic::new("fstdx"),     // FP store double, modify index
        // FP fused multiply-add (PA-RISC 2.0)
        InstructionMnemonic::new("fmpyfadd"),  // FP multiply + FP add (fused)
        InstructionMnemonic::new("fmpynfadd"), // FP multiply negated + FP add (fused)
        InstructionMnemonic::new("fneg"),      // FP negate (without absolute)
        InstructionMnemonic::new("fnegabs"),   // FP negate absolute
        // === Copy / Move (PA-RISC 2.0) ===
        InstructionMnemonic::new("copy"),      // Copy register (pseudo: OR with zero)
        // === NOP ===
        InstructionMnemonic::new("nop"),       // No operation (OR GR0,GR0,GR0)
        InstructionMnemonic::new("mtsar"),     // Move to SAR (shift amount register)
    ]
}

impl ProcessorModule for PaRiscProcessor {
    fn name() -> &'static str {
        "HP PA-RISC"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "pa-risc:BE:32:default",
                "PA-RISC 1.x (32-bit narrow mode, big-endian)",
                "1.x",
                Endian::Big,
                32,
            ),
            Language::new(
                "pa-risc:BE:64:2.0",
                "PA-RISC 2.0 (64-bit wide mode, big-endian)",
                "2.0",
                Endian::Big,
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
    fn test_pa_risc_name() {
        assert_eq!(PaRiscProcessor::name(), "HP PA-RISC");
    }

    #[test]
    fn test_pa_risc_registers() {
        let bank = PaRiscProcessor::registers();
        assert!(bank.len() > 60, "Expected many registers, got {}", bank.len());
        // GPRs
        for i in 0..32u32 {
            assert!(bank.get(&format!("GR{}", i)).is_some());
        }
        assert!(bank.get("ZERO").is_some());
        assert!(bank.get("RP").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("ARG0").is_some());
        assert!(bank.get("RET0").is_some());
        assert!(bank.get("MRP").is_some());
        assert!(bank.get("PC").is_some());
        // Space registers
        for i in 0..8u32 {
            assert!(bank.get(&format!("SR{}", i)).is_some());
        }
        // Control registers (sample)
        assert!(bank.get("CR0").is_some());
        assert!(bank.get("CR11").is_some());
        assert!(bank.get("CR22").is_some());
        assert!(bank.get("CR31").is_some());
        assert!(bank.get("SAR").is_some());
        // PSW
        assert!(bank.get("PSW").is_some());
        assert!(bank.get("PSW_W").is_some()); // Wide mode bit
        // FPU
        for i in 0..32u32 {
            assert!(bank.get(&format!("FR{}", i)).is_some());
        }
        assert!(bank.get("FPSR").is_some());
    }

    #[test]
    fn test_pa_risc_aliases() {
        let bank = PaRiscProcessor::registers();
        assert_eq!(bank.get("ZERO").unwrap().parent.as_deref(), Some("GR0"));
        assert_eq!(bank.get("RP").unwrap().parent.as_deref(), Some("GR2"));
        assert_eq!(bank.get("SP").unwrap().parent.as_deref(), Some("GR30"));
        assert_eq!(bank.get("ARG0").unwrap().parent.as_deref(), Some("GR26"));
        assert_eq!(bank.get("RET0").unwrap().parent.as_deref(), Some("GR28"));
    }

    #[test]
    fn test_pa_risc_register_bits() {
        let bank = PaRiscProcessor::registers();
        assert_eq!(bank.get("GR0").unwrap().bit_size, 64);
        assert_eq!(bank.get("PC").unwrap().bit_size, 64);
        assert_eq!(bank.get("SR0").unwrap().bit_size, 32);
        assert_eq!(bank.get("CR11").unwrap().bit_size, 32);
        assert_eq!(bank.get("PSW").unwrap().bit_size, 32);
        assert_eq!(bank.get("PSW_W").unwrap().bit_size, 1);
        assert_eq!(bank.get("FR0").unwrap().bit_size, 64);
        assert_eq!(bank.get("FPSR").unwrap().bit_size, 32);
    }

    #[test]
    fn test_pa_risc_psw_bits() {
        let bank = PaRiscProcessor::registers();
        let e = bank.get("PSW_E").unwrap();
        assert_eq!(e.parent.as_deref(), Some("PSW"));
        assert_eq!(e.lsb, 0);

        let w = bank.get("PSW_W").unwrap();
        assert_eq!(w.parent.as_deref(), Some("PSW"));
        assert_eq!(w.lsb, 17); // Wide mode
    }

    #[test]
    fn test_pa_risc_languages() {
        let langs = PaRiscProcessor::languages();
        assert!(langs.len() >= 2);
        assert!(langs.iter().any(|l| l.id == "pa-risc:BE:32:default"));
        assert!(langs.iter().any(|l| l.id == "pa-risc:BE:64:2.0"));
        assert!(langs.iter().all(|l| l.endian == Endian::Big));
    }

    #[test]
    fn test_pa_risc_instructions() {
        let insts = PaRiscProcessor::instructions();
        assert!(insts.len() > 60);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"sh1add"));
        assert!(texts.contains(&"sh2add"));
        assert!(texts.contains(&"sh3add"));
        assert!(texts.contains(&"and"));
        assert!(texts.contains(&"or"));
        assert!(texts.contains(&"xor"));
        assert!(texts.contains(&"extrw"));
        assert!(texts.contains(&"depw"));
        assert!(texts.contains(&"b"));
        assert!(texts.contains(&"bl"));
        assert!(texts.contains(&"ble"));
        assert!(texts.contains(&"ldw"));
        assert!(texts.contains(&"stw"));
        assert!(texts.contains(&"ldb"));
        assert!(texts.contains(&"stb"));
        assert!(texts.contains(&"ldcw"));
        assert!(texts.contains(&"mtctl"));
        assert!(texts.contains(&"mfctl"));
        assert!(texts.contains(&"fadd"));
        assert!(texts.contains(&"fsub"));
        assert!(texts.contains(&"fmpy"));
        assert!(texts.contains(&"fdiv"));
        assert!(texts.contains(&"break"));
        assert!(texts.contains(&"rfi"));
        assert!(texts.contains(&"nop"));
    }
}
