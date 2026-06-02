//! eBPF (extended Berkeley Packet Filter) Processor Module
//!
//! Supports the eBPF instruction set architecture used in the Linux kernel
//! for in-kernel programmability (networking, tracing, security, observability).
//!
//! ## Architecture overview
//! - 11 general-purpose 64-bit registers: R0-R10, with R11 as PC
//! - R0: return value from helper functions and programs
//! - R1-R5: function call arguments (caller-saved)
//! - R6-R9: callee-saved registers
//! - R10: stack frame pointer (read-only, points to 512-byte stack)
//! - Instruction set: ALU (32/64-bit), jumps, loads/stores, calls
//! - Atomic operations, endian conversion
//!
//! ## Instruction classes
//! - ALU64: 64-bit arithmetic and logic (BPF_ALU64, class 0x07)
//! - ALU32: 32-bit arithmetic and logic (BPF_ALU, class 0x04)
//! - LD:   load instructions (BPF_LD, class 0x00)
//! - LDX:  load register indirect (BPF_LDX, class 0x01)
//! - ST:   store immediate (BPF_ST, class 0x02)
//! - STX:  store register (BPF_STX, class 0x03)
//! - JMP:  jump operations (BPF_JMP, class 0x05), including
//!         conditional jumps (32/64-bit), unconditional JA, CALL, EXIT
//! - JMP32: 32-bit conditional jump operations (BPF_JMP32, class 0x06)
//!
//! ## Register space layout
//! - General-purpose (R0-R10):   0x0000 - 0x0050  (64-bit each)
//! - R0 Lo/Hi (R0L/R0H):        0x0000 / 0x0004    (32-bit halves)
//! - Frame pointer (FP) alias:   0x0050 (alias for R10)
//! - Program counter (R11/PC):   0x0058 (64-bit)
//!
//! ## eBPF verifier constraints
//! - Programs are statically verified before loading
//! - Maximum 512-byte stack (accessed via R10 + offset)
//! - Bounded loops only (back-edges must be provably finite)
//! - All memory accesses must be within valid bounds
//! - Helper function calls have strict argument type checking

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// eBPF processor struct.
pub struct EbpfProcessor;

/// Build the complete eBPF register bank.
///
/// eBPF has 11 general-purpose 64-bit registers (R0-R10) plus R11 as the
/// program counter. Each register has a defined role in the eBPF ABI:
///
/// - R0:  Return value from helper functions, exit code for programs
/// - R1:  First function argument (caller-saved)
/// - R2:  Second function argument (caller-saved)
/// - R3:  Third function argument (caller-saved)
/// - R4:  Fourth function argument (caller-saved)
/// - R5:  Fifth function argument (caller-saved)
/// - R6:  Callee-saved register 1
/// - R7:  Callee-saved register 2
/// - R8:  Callee-saved register 3
/// - R9:  Callee-saved register 4
/// - R10: Stack frame pointer (read-only, points to 512-byte stack)
/// - R11: Program counter (pseudo-register, not directly accessible)
///
/// The 32-bit sub-registers (R0L-R10L) hold the lower 32 bits and are used
/// by the ALU32 class of operations, which zero-extend the upper 32 bits.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- General-purpose registers R0-R10 (64-bit) ----
    let descriptions = [
        ("R0", "Return value / exit code"),
        ("R1", "Function argument 1 (caller-saved)"),
        ("R2", "Function argument 2 (caller-saved)"),
        ("R3", "Function argument 3 (caller-saved)"),
        ("R4", "Function argument 4 (caller-saved)"),
        ("R5", "Function argument 5 (caller-saved)"),
        ("R6", "Callee-saved register 1"),
        ("R7", "Callee-saved register 2"),
        ("R8", "Callee-saved register 3"),
        ("R9", "Callee-saved register 4"),
        ("R10", "Stack frame pointer (read-only)"),
    ];

    for (i, &(name, _desc)) in descriptions.iter().enumerate() {
        bank.add(Register::new(name, 64, (i as u64) * 8));
    }

    // ---- 32-bit sub-registers for ALU32 operations ----
    // ALU32 instructions operate on the lower 32 bits and zero-extend the
    // upper 32 bits of the destination register.
    for i in 0..11u32 {
        let name_lo = format!("R{}L", i);
        let parent = format!("R{}", i);
        bank.add(Register::sub_register(&name_lo, 32, (i as u64) * 8, &parent, 0));
    }

    // ---- 32-bit high halves (upper 32 bits of 64-bit registers) ----
    for i in 0..11u32 {
        let name_hi = format!("R{}H", i);
        let parent = format!("R{}", i);
        bank.add(Register::sub_register(&name_hi, 32, (i as u64) * 8, &parent, 32));
    }

    // ---- Register aliases for ABI roles ----
    bank.add(Register::sub_register("RA", 64, 0 * 8, "R0", 0));    // Return value alias
    bank.add(Register::sub_register("ARG1", 64, 1 * 8, "R1", 0));  // Argument 1
    bank.add(Register::sub_register("ARG2", 64, 2 * 8, "R2", 0));  // Argument 2
    bank.add(Register::sub_register("ARG3", 64, 3 * 8, "R3", 0));  // Argument 3
    bank.add(Register::sub_register("ARG4", 64, 4 * 8, "R4", 0));  // Argument 4
    bank.add(Register::sub_register("ARG5", 64, 5 * 8, "R5", 0));  // Argument 5
    bank.add(Register::sub_register("FP", 64, 10 * 8, "R10", 0));  // Frame pointer alias

    // ---- Program counter R11 (PC) ----
    // R11/PC is a pseudo-register representing the current instruction address.
    // It is not directly accessible from eBPF bytecode but is modelled for
    // disassembly and analysis purposes.
    bank.add(Register::new("R11", 64, 0x0058));
    bank.add(Register::sub_register("PC", 64, 0x0058, "R11", 0));
    // 32-bit subs of R11
    bank.add(Register::sub_register("R11L", 32, 0x0058, "R11", 0));
    bank.add(Register::sub_register("R11H", 32, 0x0058, "R11", 32));
    // PC sub-registers
    bank.add(Register::sub_register("PCL", 32, 0x0058, "R11", 0));
    bank.add(Register::sub_register("PCH", 32, 0x0058, "R11", 32));

    // ---- Stack pointer shadow (for disassembly context) ----
    // The eBPF stack is fixed-size (512 bytes) at R10 + offset.
    // R10 itself is read-only; the effective stack pointer tracks the
    // current offset within the stack frame.
    bank.add(Register::new("SP", 64, 0x0060));  // Stack offset within frame

    // ---- Map file descriptor register (pseudo) ----
    // eBPF maps are identified by file descriptors loaded into registers
    // via the BPF_LD | BPF_DW | BPF_LD_MAP instruction. The map pointer
    // is then passed to helper functions. This pseudo-register represents
    // the map pointer for analysis.
    bank.add(Register::new("MAP_PTR", 64, 0x0068));

    // ---- Return code register (alias) ----
    // R0 holds the program exit code. This alias makes the semantic
    // role explicit for disassembly output.
    bank.add(Register::sub_register("EXIT_CODE", 64, 0x0000, "R0", 0));

    // ---- Context/ctx register (alias for R1) ----
    // R1 holds the pointer to the program context (e.g., __sk_buff* for
    // networking, pt_regs* for tracing) on program entry.
    bank.add(Register::sub_register("CTX", 64, 1 * 8, "R1", 0));

    bank
}

/// Build the complete eBPF instruction mnemonic list.
///
/// Covers all eBPF instruction classes (v1.0+) including:
/// - ALU64: 64-bit arithmetic, logical, shift, endian, move operations
/// - ALU32: 32-bit arithmetic, logical, shift, endian, move operations
/// - LD/LDX: memory load instructions (immediate, indirect, absolute)
/// - ST/STX: memory store instructions (immediate, register)
/// - JMP:   conditional/unconditional jumps, function call, program exit
/// - JMP32: 32-bit comparison jump operations
/// - Atomic operations (fetch-and-add, exchange, compare-and-swap)
/// - Pseudo instructions for convenience
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // ====================================================================
        // ALU64 (class 0x07) - 64-bit arithmetic and logic
        // ====================================================================
        InstructionMnemonic::new("add"),      // dst += src    (64-bit)
        InstructionMnemonic::new("add_imm"),  // dst += imm    (64-bit immediate)
        InstructionMnemonic::new("sub"),      // dst -= src    (64-bit)
        InstructionMnemonic::new("sub_imm"),  // dst -= imm    (64-bit immediate)
        InstructionMnemonic::new("mul"),      // dst *= src    (64-bit)
        InstructionMnemonic::new("mul_imm"),  // dst *= imm    (64-bit immediate)
        InstructionMnemonic::new("div"),      // dst /= src    (64-bit unsigned)
        InstructionMnemonic::new("div_imm"),  // dst /= imm    (64-bit unsigned imm)
        InstructionMnemonic::new("or"),       // dst |= src    (64-bit)
        InstructionMnemonic::new("or_imm"),   // dst |= imm    (64-bit immediate)
        InstructionMnemonic::new("and"),      // dst &= src    (64-bit)
        InstructionMnemonic::new("and_imm"),  // dst &= imm    (64-bit immediate)
        InstructionMnemonic::new("lsh"),      // dst <<= src   (64-bit)
        InstructionMnemonic::new("lsh_imm"),  // dst <<= imm   (64-bit immediate)
        InstructionMnemonic::new("rsh"),      // dst >>= src   (64-bit logical)
        InstructionMnemonic::new("rsh_imm"),  // dst >>= imm   (64-bit logical imm)
        InstructionMnemonic::new("neg"),      // dst = -dst    (64-bit)
        InstructionMnemonic::new("mod"),      // dst %= src    (64-bit unsigned)
        InstructionMnemonic::new("mod_imm"),  // dst %= imm    (64-bit unsigned imm)
        InstructionMnemonic::new("xor"),      // dst ^= src    (64-bit)
        InstructionMnemonic::new("xor_imm"),  // dst ^= imm    (64-bit immediate)
        InstructionMnemonic::new("mov"),      // dst = src     (64-bit)
        InstructionMnemonic::new("mov_imm"),  // dst = imm     (64-bit immediate)
        InstructionMnemonic::new("arsh"),     // dst >>= src   (64-bit arithmetic)
        InstructionMnemonic::new("arsh_imm"), // dst >>= imm   (64-bit arithmetic imm)

        // ====================================================================
        // ALU32 (class 0x04) - 32-bit arithmetic and logic
        // Upper 32 bits of destination are zero-extended.
        // ====================================================================
        InstructionMnemonic::new("add32"),     // dst += src    (32-bit)
        InstructionMnemonic::new("add32_imm"), // dst += imm    (32-bit immediate)
        InstructionMnemonic::new("sub32"),     // dst -= src    (32-bit)
        InstructionMnemonic::new("sub32_imm"), // dst -= imm    (32-bit immediate)
        InstructionMnemonic::new("mul32"),     // dst *= src    (32-bit)
        InstructionMnemonic::new("mul32_imm"), // dst *= imm    (32-bit immediate)
        InstructionMnemonic::new("div32"),     // dst /= src    (32-bit unsigned)
        InstructionMnemonic::new("div32_imm"), // dst /= imm    (32-bit unsigned imm)
        InstructionMnemonic::new("or32"),      // dst |= src    (32-bit)
        InstructionMnemonic::new("or32_imm"),  // dst |= imm    (32-bit immediate)
        InstructionMnemonic::new("and32"),     // dst &= src    (32-bit)
        InstructionMnemonic::new("and32_imm"), // dst &= imm    (32-bit immediate)
        InstructionMnemonic::new("lsh32"),     // dst <<= src   (32-bit)
        InstructionMnemonic::new("lsh32_imm"), // dst <<= imm   (32-bit immediate)
        InstructionMnemonic::new("rsh32"),     // dst >>= src   (32-bit logical)
        InstructionMnemonic::new("rsh32_imm"), // dst >>= imm   (32-bit logical imm)
        InstructionMnemonic::new("neg32"),     // dst = -dst    (32-bit)
        InstructionMnemonic::new("mod32"),     // dst %= src    (32-bit unsigned)
        InstructionMnemonic::new("mod32_imm"), // dst %= imm    (32-bit unsigned imm)
        InstructionMnemonic::new("xor32"),     // dst ^= src    (32-bit)
        InstructionMnemonic::new("xor32_imm"), // dst ^= imm    (32-bit immediate)
        InstructionMnemonic::new("mov32"),     // dst = src     (32-bit)
        InstructionMnemonic::new("mov32_imm"), // dst = imm     (32-bit immediate)
        InstructionMnemonic::new("arsh32"),    // dst >>= src   (32-bit arithmetic)
        InstructionMnemonic::new("arsh32_imm"),// dst >>= imm   (32-bit arithmetic imm)

        // ====================================================================
        // Endian conversion (ALU64 class with special source field)
        // ====================================================================
        InstructionMnemonic::new("le16"),  // Convert 16-bit to little-endian
        InstructionMnemonic::new("le32"),  // Convert 32-bit to little-endian
        InstructionMnemonic::new("le64"),  // Convert 64-bit to little-endian
        InstructionMnemonic::new("be16"),  // Convert 16-bit to big-endian
        InstructionMnemonic::new("be32"),  // Convert 32-bit to big-endian
        InstructionMnemonic::new("be64"),  // Convert 64-bit to big-endian

        // ====================================================================
        // Memory loads - BPF_LD (class 0x00)
        // ====================================================================
        InstructionMnemonic::new("lddw"),      // Load 64-bit immediate (double-width)
        InstructionMnemonic::new("ldabsw"),    // Load absolute word (deprecated)
        InstructionMnemonic::new("ldabsdw"),   // Load absolute double-word (deprecated)
        InstructionMnemonic::new("ldindw"),    // Load indirect word (deprecated)
        InstructionMnemonic::new("ldinddw"),   // Load indirect double-word (deprecated)
        InstructionMnemonic::new("ld_map_fd"), // Load map file descriptor (pseudo)

        // ====================================================================
        // Memory loads - BPF_LDX (class 0x01) - indexed loads
        // ====================================================================
        InstructionMnemonic::new("ldxb"),      // Load byte from src + offset
        InstructionMnemonic::new("ldxh"),      // Load half-word (16-bit) from src + offset
        InstructionMnemonic::new("ldxw"),      // Load word (32-bit) from src + offset
        InstructionMnemonic::new("ldxdw"),     // Load double-word (64-bit) from src + offset

        // ====================================================================
        // Memory stores - BPF_ST (class 0x02) - immediate stores
        // ====================================================================
        InstructionMnemonic::new("stb"),       // Store byte immediate to dst + offset
        InstructionMnemonic::new("sth"),       // Store half-word immediate to dst + offset
        InstructionMnemonic::new("stw"),       // Store word immediate to dst + offset
        InstructionMnemonic::new("stdw"),      // Store double-word immediate to dst + offset

        // ====================================================================
        // Memory stores - BPF_STX (class 0x03) - register stores
        // ====================================================================
        InstructionMnemonic::new("stxb"),      // Store byte from reg to dst + offset
        InstructionMnemonic::new("stxh"),      // Store half-word from reg to dst + offset
        InstructionMnemonic::new("stxw"),      // Store word from reg to dst + offset
        InstructionMnemonic::new("stxdw"),     // Store double-word from reg to dst + offset

        // ====================================================================
        // Branch instructions - BPF_JMP (class 0x05) - 64-bit comparisons
        // ====================================================================
        InstructionMnemonic::new("ja"),        // Jump always (unconditional)
        InstructionMnemonic::new("jeq"),       // Jump if dst == src     (64-bit)
        InstructionMnemonic::new("jeq_imm"),   // Jump if dst == imm     (64-bit)
        InstructionMnemonic::new("jgt"),       // Jump if dst >  src     (64-bit unsigned)
        InstructionMnemonic::new("jgt_imm"),   // Jump if dst >  imm     (64-bit unsigned)
        InstructionMnemonic::new("jge"),       // Jump if dst >= src     (64-bit unsigned)
        InstructionMnemonic::new("jge_imm"),   // Jump if dst >= imm     (64-bit unsigned)
        InstructionMnemonic::new("jlt"),       // Jump if dst <  src     (64-bit unsigned)
        InstructionMnemonic::new("jlt_imm"),   // Jump if dst <  imm     (64-bit unsigned)
        InstructionMnemonic::new("jle"),       // Jump if dst <= src     (64-bit unsigned)
        InstructionMnemonic::new("jle_imm"),   // Jump if dst <= imm     (64-bit unsigned)
        InstructionMnemonic::new("jset"),      // Jump if dst & src != 0  (64-bit)
        InstructionMnemonic::new("jset_imm"),  // Jump if dst & imm != 0  (64-bit)
        InstructionMnemonic::new("jne"),       // Jump if dst != src     (64-bit)
        InstructionMnemonic::new("jne_imm"),   // Jump if dst != imm     (64-bit)
        InstructionMnemonic::new("jsgt"),      // Jump if dst >  src     (64-bit signed)
        InstructionMnemonic::new("jsgt_imm"),  // Jump if dst >  imm     (64-bit signed)
        InstructionMnemonic::new("jsge"),      // Jump if dst >= src     (64-bit signed)
        InstructionMnemonic::new("jsge_imm"),  // Jump if dst >= imm     (64-bit signed)
        InstructionMnemonic::new("jslt"),      // Jump if dst <  src     (64-bit signed)
        InstructionMnemonic::new("jslt_imm"),  // Jump if dst <  imm     (64-bit signed)
        InstructionMnemonic::new("jsle"),      // Jump if dst <= src     (64-bit signed)
        InstructionMnemonic::new("jsle_imm"),  // Jump if dst <= imm     (64-bit signed)

        // ====================================================================
        // Branch instructions - BPF_JMP32 (class 0x06) - 32-bit comparisons
        // ====================================================================
        InstructionMnemonic::new("jeq32"),      // Jump if dst == src     (32-bit)
        InstructionMnemonic::new("jeq32_imm"),  // Jump if dst == imm     (32-bit)
        InstructionMnemonic::new("jgt32"),      // Jump if dst >  src     (32-bit unsigned)
        InstructionMnemonic::new("jgt32_imm"),  // Jump if dst >  imm     (32-bit unsigned)
        InstructionMnemonic::new("jge32"),      // Jump if dst >= src     (32-bit unsigned)
        InstructionMnemonic::new("jge32_imm"),  // Jump if dst >= imm     (32-bit unsigned)
        InstructionMnemonic::new("jlt32"),      // Jump if dst <  src     (32-bit unsigned)
        InstructionMnemonic::new("jlt32_imm"),  // Jump if dst <  imm     (32-bit unsigned)
        InstructionMnemonic::new("jle32"),      // Jump if dst <= src     (32-bit unsigned)
        InstructionMnemonic::new("jle32_imm"),  // Jump if dst <= imm     (32-bit unsigned)
        InstructionMnemonic::new("jset32"),     // Jump if dst & src != 0  (32-bit)
        InstructionMnemonic::new("jset32_imm"), // Jump if dst & imm != 0  (32-bit)
        InstructionMnemonic::new("jne32"),      // Jump if dst != src     (32-bit)
        InstructionMnemonic::new("jne32_imm"),  // Jump if dst != imm     (32-bit)
        InstructionMnemonic::new("jsgt32"),     // Jump if dst >  src     (32-bit signed)
        InstructionMnemonic::new("jsgt32_imm"), // Jump if dst >  imm     (32-bit signed)
        InstructionMnemonic::new("jsge32"),     // Jump if dst >= src     (32-bit signed)
        InstructionMnemonic::new("jsge32_imm"), // Jump if dst >= imm     (32-bit signed)
        InstructionMnemonic::new("jslt32"),     // Jump if dst <  src     (32-bit signed)
        InstructionMnemonic::new("jslt32_imm"), // Jump if dst <  imm     (32-bit signed)
        InstructionMnemonic::new("jsle32"),     // Jump if dst <= src     (32-bit signed)
        InstructionMnemonic::new("jsle32_imm"), // Jump if dst <= imm     (32-bit signed)

        // ====================================================================
        // Function calls (BPF_JMP class with special opcodes)
        // ====================================================================
        InstructionMnemonic::new("call"),        // Call helper function by ID (imm)
        InstructionMnemonic::new("callx"),       // Call helper function by register
        InstructionMnemonic::new("call_pseudo"), // Pseudo call (BPF-to-BPF function call)
        InstructionMnemonic::new("exit"),        // Exit from eBPF program (return R0)

        // ====================================================================
        // 64-bit immediate load (double-width pseudo-instruction)
        // ====================================================================
        InstructionMnemonic::new("ldimm64"),     // Load 64-bit immediate (occupies 2 slots)
        InstructionMnemonic::new("ld_map_ptr"),  // Load map pointer (pseudo)

        // ====================================================================
        // Atomic operations (BPF_STX + special atomic mode field)
        // ====================================================================
        InstructionMnemonic::new("xadd"),       // Atomic fetch-and-add (64-bit)
        InstructionMnemonic::new("xaddw"),      // Atomic fetch-and-add word (32-bit)
        InstructionMnemonic::new("xadddw"),     // Atomic fetch-and-add double-word (64-bit)
        InstructionMnemonic::new("xchg"),       // Atomic exchange / swap (64-bit)
        InstructionMnemonic::new("xchgw"),      // Atomic exchange word (32-bit)
        InstructionMnemonic::new("xchgdw"),     // Atomic exchange double-word (64-bit)
        InstructionMnemonic::new("cmpxchg"),    // Atomic compare-and-exchange (64-bit)
        InstructionMnemonic::new("cmpxchgw"),   // Atomic compare-and-exchange word (32-bit)
        InstructionMnemonic::new("cmpxchgdw"),  // Atomic compare-and-exchange dword (64-bit)

        // Additional atomic variants
        InstructionMnemonic::new("atomic_add"),     // Atomic add (from BPF v1.1+ atomic extension)
        InstructionMnemonic::new("atomic_add32"),   // Atomic add 32-bit
        InstructionMnemonic::new("atomic_and"),     // Atomic AND
        InstructionMnemonic::new("atomic_and32"),   // Atomic AND 32-bit
        InstructionMnemonic::new("atomic_or"),      // Atomic OR
        InstructionMnemonic::new("atomic_or32"),    // Atomic OR 32-bit
        InstructionMnemonic::new("atomic_xor"),     // Atomic XOR
        InstructionMnemonic::new("atomic_xor32"),   // Atomic XOR 32-bit

        // ====================================================================
        // Pseudo / meta instructions
        // ====================================================================
        InstructionMnemonic::new("nop"),        // No operation
        InstructionMnemonic::new("undef"),      // Undefined (trap / invalid)

        // ====================================================================
        // eBPF v1.1+ extended instruction aliases
        // ====================================================================
        InstructionMnemonic::new("sdiv"),        // Signed divide (64-bit)
        InstructionMnemonic::new("sdiv32"),      // Signed divide (32-bit)
        InstructionMnemonic::new("smod"),        // Signed remainder (64-bit)
        InstructionMnemonic::new("smod32"),      // Signed remainder (32-bit)
        InstructionMnemonic::new("movsx8"),      // Sign-extend 8-bit to 64-bit
        InstructionMnemonic::new("movsx8_32"),   // Sign-extend 8-bit to 32-bit
        InstructionMnemonic::new("movsx16"),     // Sign-extend 16-bit to 64-bit
        InstructionMnemonic::new("movsx16_32"),  // Sign-extend 16-bit to 32-bit
        InstructionMnemonic::new("movsx32"),     // Sign-extend 32-bit to 64-bit
    ]
}

impl ProcessorModule for EbpfProcessor {
    fn name() -> &'static str {
        "eBPF (extended Berkeley Packet Filter)"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "ebpf:LE:64:default",
                "eBPF (64-bit, little-endian, Linux kernel verifier)",
                "v1.0",
                Endian::Little,
                64,
            ),
            Language::new(
                "ebpf:LE:64:v1_1",
                "eBPF (64-bit, little-endian, BPF v1.1+ with atomic extensions)",
                "v1.1",
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
    fn test_ebpf_name() {
        assert_eq!(
            EbpfProcessor::name(),
            "eBPF (extended Berkeley Packet Filter)"
        );
    }

    #[test]
    fn test_ebpf_registers() {
        let bank = EbpfProcessor::registers();
        assert!(bank.len() > 30, "Expected many registers, got {}", bank.len());
        // All GPRs R0-R11
        for i in 0..=11u32 {
            assert!(
                bank.get(&format!("R{}", i)).is_some(),
                "Missing register R{}",
                i
            );
        }
        // 32-bit sub-registers
        for i in 0..=11u32 {
            assert!(
                bank.get(&format!("R{}L", i)).is_some(),
                "Missing register R{}L",
                i
            );
            assert!(
                bank.get(&format!("R{}H", i)).is_some(),
                "Missing register R{}H",
                i
            );
        }
        assert!(bank.get("FP").is_some());
        assert!(bank.get("PC").is_some());
        assert!(bank.get("RA").is_some());
        assert!(bank.get("ARG1").is_some());
        assert!(bank.get("ARG5").is_some());
        assert!(bank.get("CTX").is_some());
        assert!(bank.get("EXIT_CODE").is_some());
        assert!(bank.get("SP").is_some());
        assert!(bank.get("MAP_PTR").is_some());
    }

    #[test]
    fn test_ebpf_aliases() {
        let bank = EbpfProcessor::registers();
        assert_eq!(bank.get("FP").unwrap().parent.as_deref(), Some("R10"));
        assert_eq!(bank.get("PC").unwrap().parent.as_deref(), Some("R11"));
        assert_eq!(bank.get("RA").unwrap().parent.as_deref(), Some("R0"));
        assert_eq!(bank.get("ARG1").unwrap().parent.as_deref(), Some("R1"));
        assert_eq!(bank.get("CTX").unwrap().parent.as_deref(), Some("R1"));
        assert_eq!(bank.get("EXIT_CODE").unwrap().parent.as_deref(), Some("R0"));
    }

    #[test]
    fn test_ebpf_sub_registers() {
        let bank = EbpfProcessor::registers();
        // Verify 32-bit halves reference correct parent
        let r0l = bank.get("R0L").unwrap();
        assert_eq!(r0l.parent.as_deref(), Some("R0"));
        assert_eq!(r0l.bit_size, 32);
        assert_eq!(r0l.lsb, 0);

        let r0h = bank.get("R0H").unwrap();
        assert_eq!(r0h.parent.as_deref(), Some("R0"));
        assert_eq!(r0h.bit_size, 32);
        assert_eq!(r0h.lsb, 32);

        let r10l = bank.get("R10L").unwrap();
        assert_eq!(r10l.parent.as_deref(), Some("R10"));
        assert_eq!(r10l.bit_size, 32);

        let pcl = bank.get("PCL").unwrap();
        assert_eq!(pcl.parent.as_deref(), Some("R11"));
        assert_eq!(pcl.bit_size, 32);
        assert_eq!(pcl.lsb, 0);

        let pch = bank.get("PCH").unwrap();
        assert_eq!(pch.parent.as_deref(), Some("R11"));
        assert_eq!(pch.bit_size, 32);
        assert_eq!(pch.lsb, 32);
    }

    #[test]
    fn test_ebpf_register_bits() {
        let bank = EbpfProcessor::registers();
        for i in 0..=11u32 {
            assert_eq!(bank.get(&format!("R{}", i)).unwrap().bit_size, 64);
            assert_eq!(bank.get(&format!("R{}L", i)).unwrap().bit_size, 32);
            assert_eq!(bank.get(&format!("R{}H", i)).unwrap().bit_size, 32);
        }
        assert_eq!(bank.get("SP").unwrap().bit_size, 64);
        assert_eq!(bank.get("MAP_PTR").unwrap().bit_size, 64);
    }

    #[test]
    fn test_ebpf_languages() {
        let langs = EbpfProcessor::languages();
        assert_eq!(langs.len(), 2);
        assert_eq!(langs[0].id, "ebpf:LE:64:default");
        assert_eq!(langs[0].endian, Endian::Little);
        assert_eq!(langs[0].pointer_size, 64);
        assert_eq!(langs[1].id, "ebpf:LE:64:v1_1");
        assert_eq!(langs[1].pointer_size, 64);
    }

    #[test]
    fn test_ebpf_instructions_alu64() {
        let insts = EbpfProcessor::instructions();
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"add"));
        assert!(texts.contains(&"sub"));
        assert!(texts.contains(&"mul"));
        assert!(texts.contains(&"div"));
        assert!(texts.contains(&"or"));
        assert!(texts.contains(&"and"));
        assert!(texts.contains(&"lsh"));
        assert!(texts.contains(&"rsh"));
        assert!(texts.contains(&"neg"));
        assert!(texts.contains(&"mod"));
        assert!(texts.contains(&"xor"));
        assert!(texts.contains(&"mov"));
        assert!(texts.contains(&"arsh"));
    }

    #[test]
    fn test_ebpf_instructions_alu32() {
        let insts = EbpfProcessor::instructions();
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"add32"));
        assert!(texts.contains(&"sub32"));
        assert!(texts.contains(&"mul32"));
        assert!(texts.contains(&"div32"));
        assert!(texts.contains(&"or32"));
        assert!(texts.contains(&"and32"));
        assert!(texts.contains(&"lsh32"));
        assert!(texts.contains(&"rsh32"));
        assert!(texts.contains(&"neg32"));
        assert!(texts.contains(&"mod32"));
        assert!(texts.contains(&"xor32"));
        assert!(texts.contains(&"mov32"));
        assert!(texts.contains(&"arsh32"));
    }

    #[test]
    fn test_ebpf_instructions_endian() {
        let insts = EbpfProcessor::instructions();
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"le16"));
        assert!(texts.contains(&"le32"));
        assert!(texts.contains(&"le64"));
        assert!(texts.contains(&"be16"));
        assert!(texts.contains(&"be32"));
        assert!(texts.contains(&"be64"));
    }

    #[test]
    fn test_ebpf_instructions_load_store() {
        let insts = EbpfProcessor::instructions();
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"lddw"));
        assert!(texts.contains(&"ldxdw"));
        assert!(texts.contains(&"stdw"));
        assert!(texts.contains(&"stb"));
        assert!(texts.contains(&"sth"));
        assert!(texts.contains(&"stw"));
        assert!(texts.contains(&"stdw"));
    }

    #[test]
    fn test_ebpf_instructions_jumps() {
        let insts = EbpfProcessor::instructions();
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"ja"));
        assert!(texts.contains(&"jeq"));
        assert!(texts.contains(&"jgt"));
        assert!(texts.contains(&"jge"));
        assert!(texts.contains(&"jlt"));
        assert!(texts.contains(&"jle"));
        assert!(texts.contains(&"jset"));
        assert!(texts.contains(&"jne"));
        assert!(texts.contains(&"jsgt"));
        assert!(texts.contains(&"jsge"));
        assert!(texts.contains(&"jslt"));
        assert!(texts.contains(&"jsle"));
        // 32-bit variants
        assert!(texts.contains(&"jeq32"));
        assert!(texts.contains(&"jgt32"));
        assert!(texts.contains(&"jge32"));
        assert!(texts.contains(&"jlt32"));
        assert!(texts.contains(&"jle32"));
        assert!(texts.contains(&"jset32"));
        assert!(texts.contains(&"jne32"));
        assert!(texts.contains(&"jsgt32"));
        assert!(texts.contains(&"jsge32"));
        assert!(texts.contains(&"jslt32"));
        assert!(texts.contains(&"jsle32"));
    }

    #[test]
    fn test_ebpf_instructions_calls() {
        let insts = EbpfProcessor::instructions();
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"call"));
        assert!(texts.contains(&"callx"));
        assert!(texts.contains(&"exit"));
    }

    #[test]
    fn test_ebpf_instructions_atomic() {
        let insts = EbpfProcessor::instructions();
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"xadd"));
        assert!(texts.contains(&"xaddw"));
        assert!(texts.contains(&"xadddw"));
        assert!(texts.contains(&"xchg"));
        assert!(texts.contains(&"xchgw"));
        assert!(texts.contains(&"xchgdw"));
        assert!(texts.contains(&"cmpxchg"));
        assert!(texts.contains(&"cmpxchgw"));
        assert!(texts.contains(&"cmpxchgdw"));
        assert!(texts.contains(&"atomic_add"));
        assert!(texts.contains(&"atomic_and"));
        assert!(texts.contains(&"atomic_or"));
        assert!(texts.contains(&"atomic_xor"));
    }

    #[test]
    fn test_ebpf_instructions_signed_div() {
        let insts = EbpfProcessor::instructions();
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        assert!(texts.contains(&"sdiv"));
        assert!(texts.contains(&"sdiv32"));
        assert!(texts.contains(&"smod"));
        assert!(texts.contains(&"smod32"));
        assert!(texts.contains(&"movsx8"));
        assert!(texts.contains(&"movsx16"));
        assert!(texts.contains(&"movsx32"));
    }

    #[test]
    fn test_ebpf_total_instruction_count() {
        let insts = EbpfProcessor::instructions();
        assert!(
            insts.len() >= 90,
            "Expected at least 90 instructions, got {}",
            insts.len()
        );
    }
}
