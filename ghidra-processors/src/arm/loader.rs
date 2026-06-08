//! ARM Binary Image Loader and Instruction Mode Detection
//!
//! Handles loading ARM/Thumb binaries, detecting ARM vs Thumb instruction
//! mode, identifying function boundaries via prologue/epilogue patterns,
//! and detecting calling conventions.

use crate::arm::instructions::ArmMnemonic;
use crate::arm::registers::ArmRegisterBank;

// ========================================================================
// Binary Format Detection for ARM
// ========================================================================

/// Supported executable formats for ARM32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmBinaryFormat {
    /// 32-bit ELF (ARM)
    ELF32,
    /// Raw binary (flat binary, boot sector, firmware)
    Raw,
    /// SREC / Motorola S-record
    SREC,
    /// Intel HEX
    IntelHex,
    /// Unknown format
    Unknown,
}

impl ArmBinaryFormat {
    /// Detect the binary format from magic bytes.
    pub fn detect(data: &[u8]) -> Self {
        if data.len() < 4 {
            return ArmBinaryFormat::Unknown;
        }
        match &data[0..4] {
            [0x7F, 0x45, 0x4C, 0x46] => {
                // ELF magic. Check class in byte 4.
                if data.len() >= 5 && data[4] == 1 {
                    // ELFCLASS32 - check machine type in e_machine field
                    if data.len() >= 20 {
                        let machine = u16::from_le_bytes([data[18], data[19]]);
                        if machine == 0x28 {
                            return ArmBinaryFormat::ELF32;
                        }
                    }
                    ArmBinaryFormat::ELF32
                } else {
                    ArmBinaryFormat::Unknown
                }
            }
            [b'S', b'0', ..] => ArmBinaryFormat::SREC,
            [b':', ..] => ArmBinaryFormat::IntelHex,
            _ => ArmBinaryFormat::Raw,
        }
    }

    /// Returns the default instruction mode for this format.
    pub fn default_mode(&self) -> ArmExecutionMode {
        match self {
            ArmBinaryFormat::ELF32 => ArmExecutionMode::Arm,
            ArmBinaryFormat::Raw => ArmExecutionMode::Arm,
            _ => ArmExecutionMode::Arm,
        }
    }
}

// ========================================================================
// ARM Execution Mode (ARM vs Thumb)
// ========================================================================

/// ARM32 execution mode for instruction decoding.
///
/// ARM processors can execute instructions in two modes:
/// - ARM mode: 32-bit fixed-width instructions
/// - Thumb mode: 16-bit (Thumb) or mixed 16/32-bit (Thumb-2) instructions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmExecutionMode {
    /// Standard ARM mode (32-bit instructions, word-aligned)
    Arm,
    /// Thumb mode (16-bit instructions, halfword-aligned)
    Thumb,
    /// Thumb-2 mode (mixed 16-bit and 32-bit instructions)
    Thumb2,
}

impl ArmExecutionMode {
    /// Returns true if this mode uses halfword-aligned instructions.
    pub fn is_thumb(&self) -> bool {
        matches!(self, ArmExecutionMode::Thumb | ArmExecutionMode::Thumb2)
    }

    /// Returns the instruction alignment in bytes.
    pub fn alignment(&self) -> u32 {
        match self {
            ArmExecutionMode::Arm => 4,
            ArmExecutionMode::Thumb | ArmExecutionMode::Thumb2 => 2,
        }
    }

    /// Minimum instruction size in bytes.
    pub fn min_instruction_size(&self) -> u32 {
        match self {
            ArmExecutionMode::Arm => 4,
            ArmExecutionMode::Thumb => 2,
            ArmExecutionMode::Thumb2 => 2,
        }
    }

    /// Maximum instruction size in bytes.
    pub fn max_instruction_size(&self) -> u32 {
        match self {
            ArmExecutionMode::Arm => 4,
            ArmExecutionMode::Thumb => 2,
            ArmExecutionMode::Thumb2 => 4,
        }
    }
}

// ========================================================================
// Thumb/ARM Mode Detection
// ========================================================================

/// ARM vs Thumb mode detection utilities.
pub struct ArmModeDetector;

impl ArmModeDetector {
    /// Detect whether a sequence at the given address is ARM or Thumb code.
    ///
    /// Thumb bit: The LSB of branch target addresses indicates mode:
    /// - LSB = 0: ARM mode (target address & 0xFFFFFFFE for actual address)
    /// - LSB = 1: Thumb mode (target address & 0xFFFFFFFE for actual address)
    pub fn detect_mode_at(target_address: u32) -> ArmExecutionMode {
        if target_address & 1 == 1 {
            ArmExecutionMode::Thumb
        } else {
            ArmExecutionMode::Arm
        }
    }

    /// Get the actual aligned target address (clear bit 0 for Thumb interwork).
    pub fn aligned_target(target_address: u32) -> u32 {
        target_address & !1
    }

    /// Try to detect the instruction mode by analyzing the initial bytes.
    ///
    /// Heuristic: ARM-mode prologues typically begin with `STMFD SP!, {..., LR}`
    /// or `MOV IP, SP`, while Thumb prologues typically begin with `PUSH {..., LR}`
    /// or `SUB SP, SP, #imm`.
    pub fn detect_mode_from_bytes(data: &[u8]) -> Option<ArmExecutionMode> {
        if data.len() < 2 {
            return None;
        }

        // Check for common Thumb-mode instruction signatures first (2 bytes)
        // Thumb PUSH {..., LR} = 0xB5xx
        // Thumb SUB SP, SP, #imm = 0xB08x
        let thumb_half = u16::from_le_bytes([data[0], data[1]]);
        if (thumb_half & 0xFF00) == 0xB500 || (thumb_half & 0xFF80) == 0xB080 {
            return Some(ArmExecutionMode::Thumb);
        }

        // Check for common ARM-mode instruction signatures (requires 4 bytes)
        if data.len() < 4 {
            return None;
        }

        // STMFD SP!, {R4-R11, LR} = 0xE92D 4FF0 (typical prologue)
        // MOV R12, SP = 0xE1A0 C00D
        // STMFD SP!, {R4-R7, LR} = 0xE92D 40F0
        let arm_word = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let arm_cond = (arm_word >> 28) & 0xF;

        // ARM instructions typically have cond != 0xF (NV), and bits 27-25
        // distinguish data processing / load-store / branch.
        if arm_cond != 0xF {
            let op_type = (arm_word >> 25) & 0x7;
            if op_type == 0b100 || op_type == 0b010 || op_type == 0b101 {
                return Some(ArmExecutionMode::Arm);
            }
        }

        None
    }

    /// Classify a branch target as an interwork branch (arm<->thumb transition).
    pub fn is_interwork_branch(mnemonic: ArmMnemonic) -> bool {
        matches!(mnemonic, ArmMnemonic::BX | ArmMnemonic::BLX)
    }
}

// ========================================================================
// ARM Calling Convention
// ========================================================================

/// ARM calling conventions.
///
/// Derived from Ghidra's cspec definitions:
/// - ARM.cspec (AAPCS default, AAPCS with VFP, SoftFP)
/// - ARM_apcs.cspec (deprecated APCS/ATPCS from gcc -mabi=apcs-gnu / -mabi=atpcs)
/// - ARM_win.cspec (Visual Studio / Windows ARM)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArmCallingConvention {
    /// ARM standard (AAPCS): r0-r3 args, r0-r1 return, r4-r11 preserved,
    /// s0-s15/d0-d7 for float args. Default for Linux/GCC/Clang.
    AAPCS,
    /// ARM standard with VFP (hard-float): r0-r3 + s0-s15/d0-d7 args.
    /// Floats passed in VFP registers, aggregates may use HFA rules.
    AAPCSVfp,
    /// Soft-float ABI (-mfloat-abi=soft / softfp): no VFP register usage
    /// for parameter passing; floats passed in r0-r3 / stack.
    SoftFP,
    /// Deprecated ARM Procedure Call Standard (gcc -mabi=apcs-gnu / -mabi=atpcs).
    /// Similar to AAPCS but structs returned by pointer (hidden return).
    APCS,
    /// Thumb calling convention (same register usage as AAPCS).
    TPCS,
    /// Windows ARM calling convention (Visual Studio).
    /// r0-r3 args, r0 return, r4-r11 preserved, r12 is scratch.
    /// Same register usage as AAPCS but with Windows-specific struct rules.
    Windows,
    /// Bare-metal / interrupt handler (minimal convention).
    BareMetal,
}

impl ArmCallingConvention {
    /// Return the argument registers for this convention.
    pub fn arg_registers(&self) -> &[&str] {
        match self {
            ArmCallingConvention::AAPCS
            | ArmCallingConvention::AAPCSVfp
            | ArmCallingConvention::SoftFP
            | ArmCallingConvention::APCS
            | ArmCallingConvention::TPCS
            | ArmCallingConvention::Windows => &["R0", "R1", "R2", "R3"],
            ArmCallingConvention::BareMetal => &["R0"],
        }
    }

    /// Return the return value register.
    pub fn return_register(&self) -> &str {
        "R0"
    }

    /// Return the second return value register (for 64-bit values in r0:r1).
    pub fn return_register_pair_high(&self) -> &str {
        "R1"
    }

    /// Return the callee-saved (preserved/unaffected) registers.
    pub fn callee_saved(&self) -> &[&str] {
        &["R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "SP"]
    }

    /// Return the caller-saved (scratch/killed-by-call) registers.
    pub fn caller_saved(&self) -> &[&str] {
        match self {
            ArmCallingConvention::AAPCSVfp => &[
                "R0", "R1", "R2", "R3", "R12", "LR",
                "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7",
            ],
            _ => &["R0", "R1", "R2", "R3", "R12", "LR"],
        }
    }

    /// Return the VFP argument registers (AAPCS with VFP only).
    pub fn vfp_arg_registers(&self) -> &[&str] {
        match self {
            ArmCallingConvention::AAPCS | ArmCallingConvention::AAPCSVfp => {
                &["S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7",
                  "S8", "S9", "S10", "S11", "S12", "S13", "S14", "S15"]
            }
            _ => &[],
        }
    }

    /// Return the VFP callee-saved registers.
    pub fn vfp_callee_saved(&self) -> &[&str] {
        &["D8", "D9", "D10", "D11", "D12", "D13", "D14", "D15"]
    }

    /// Return the hidden return register (struct return pointer).
    pub fn hidden_return_register(&self) -> Option<&str> {
        // AAPCS uses r0 for small struct returns; Windows also uses r0
        None // No dedicated hidden return register in ARM AAPCS
    }

    /// Detect the likely calling convention from symbol/function name.
    pub fn detect_from_name(name: &str) -> Self {
        if name.starts_with("__aeabi_") || name.starts_with("__gnu_") {
            ArmCallingConvention::AAPCS
        } else if name.starts_with("__hardfp_") {
            ArmCallingConvention::AAPCSVfp
        } else if name.starts_with("isr_")
            || name.starts_with("__irq_")
            || name.starts_with("__fiq_")
        {
            ArmCallingConvention::BareMetal
        } else if name.starts_with("__rt_") || name.starts_with("__cpp_") {
            // ARM RealView / RVCT naming
            ArmCallingConvention::APCS
        } else {
            ArmCallingConvention::AAPCS
        }
    }

    /// Returns the compiler spec ID used in Ghidra's cspec definitions.
    pub fn compiler_spec_id(&self) -> &'static str {
        match self {
            ArmCallingConvention::AAPCS
            | ArmCallingConvention::AAPCSVfp
            | ArmCallingConvention::SoftFP
            | ArmCallingConvention::TPCS => "default",
            ArmCallingConvention::APCS => "apcs",
            ArmCallingConvention::Windows => "windows",
            ArmCallingConvention::BareMetal => "default",
        }
    }
}

// ========================================================================
// Function Boundary Detection
// ========================================================================

/// Prologue/epilogue pattern types for ARM functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProloguePattern {
    /// STMFD SP!, {R4-R11, LR} - Full save
    SaveRegsAndLr,
    /// STMFD SP!, {R4-R7, LR} - Partial save
    SaveFewRegsAndLr,
    /// STMFD SP!, {LR} - Link register only
    SaveLrOnly,
    /// SUB SP, SP, #imm - Stack frame allocation
    StackAlloc,
    /// MOV R12, SP (IP = SP)
    MovIpSp,
    /// PUSH {R4-R7, LR} - Thumb full save
    ThumbPushLr,
    /// Thumb SUB SP, SP, #imm
    ThumbStackAlloc,
}

/// Detected function boundary with type and offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionBoundary {
    /// Offset into the binary where this boundary was detected
    pub offset: u64,
    /// Whether this is a function start or end
    pub boundary_type: BoundaryType,
    /// The detected execution mode at this boundary
    pub execution_mode: ArmExecutionMode,
    /// The detected pattern type
    pub pattern: Option<ProloguePattern>,
}

/// Type of function boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryType {
    /// Function entry (prologue)
    FunctionStart,
    /// Function exit (epilogue)
    FunctionEnd,
    /// Potential function start (lower confidence)
    PossibleStart,
}

// ========================================================================
// ARM Binary Image
// ========================================================================

/// A loaded ARM binary image with associated metadata.
#[derive(Debug, Clone)]
pub struct ArmBinaryImage {
    /// The raw binary data.
    pub data: Vec<u8>,
    /// Load base address.
    pub base_address: u64,
    /// Entry point address.
    pub entry_point: u64,
    /// Detected binary format.
    pub format: ArmBinaryFormat,
    /// Default execution mode.
    pub execution_mode: ArmExecutionMode,
    /// Detected function boundaries.
    pub function_boundaries: Vec<FunctionBoundary>,
    /// Associated register bank (for reference).
    pub registers: ArmRegisterBank,
    /// Sections found in the binary.
    pub sections: Vec<Section>,
}

/// A section in the ARM binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub offset: u64,
    pub size: u64,
    pub is_executable: bool,
    pub is_writable: bool,
    pub data: Vec<u8>,
}

impl ArmBinaryImage {
    /// Create a new ARM binary image from raw data.
    pub fn new(data: Vec<u8>, base_address: u64, entry_point: u64) -> Self {
        let format = ArmBinaryFormat::detect(&data);
        ArmBinaryImage {
            data,
            base_address,
            entry_point,
            format,
            execution_mode: ArmExecutionMode::Arm,
            function_boundaries: Vec::new(),
            registers: ArmRegisterBank::new_armv7a(),
            sections: Vec::new(),
        }
    }

    /// Load a binary from raw data and auto-detect parameters.
    pub fn load(data: Vec<u8>, base_address: u64) -> Self {
        let format = ArmBinaryFormat::detect(&data);
        let mode = if let Some(mode) = ArmModeDetector::detect_mode_from_bytes(&data) {
            mode
        } else {
            format.default_mode()
        };

        ArmBinaryImage {
            data,
            base_address,
            entry_point: base_address,
            format,
            execution_mode: mode,
            function_boundaries: Vec::new(),
            registers: ArmRegisterBank::new_armv7a(),
            sections: Vec::new(),
        }
    }

    /// Read a 32-bit word at the given offset (little-endian).
    pub fn read_word(&self, offset: u64) -> Option<u32> {
        let off = offset as usize;
        if off + 4 <= self.data.len() {
            Some(u32::from_le_bytes([
                self.data[off],
                self.data[off + 1],
                self.data[off + 2],
                self.data[off + 3],
            ]))
        } else {
            None
        }
    }

    /// Read a 16-bit halfword at the given offset (little-endian).
    pub fn read_halfword(&self, offset: u64) -> Option<u16> {
        let off = offset as usize;
        if off + 2 <= self.data.len() {
            Some(u16::from_le_bytes([self.data[off], self.data[off + 1]]))
        } else {
            None
        }
    }

    /// Read a byte at the given offset.
    pub fn read_byte(&self, offset: u64) -> Option<u8> {
        let off = offset as usize;
        if off < self.data.len() {
            Some(self.data[off])
        } else {
            None
        }
    }

    /// Detect all function boundaries in the binary.
    pub fn detect_function_boundaries(&mut self) {
        self.function_boundaries =
            detect_function_boundaries(&self.data, self.base_address, self.execution_mode);
    }
}

// ========================================================================
// Function Boundary Detection (Implementation)
// ========================================================================

/// Detect function boundaries in raw ARM/Thumb binary data.
pub fn detect_function_boundaries(
    data: &[u8],
    base_address: u64,
    mode: ArmExecutionMode,
) -> Vec<FunctionBoundary> {
    let mut boundaries = Vec::new();
    let min_size = mode.min_instruction_size() as usize;

    if data.len() < min_size {
        return boundaries;
    }

    let mut offset = 0;

    while offset + 3 < data.len() {
        let word = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        // Check for ARM-mode prologue patterns
        if (word & 0xFFFF_0000) == 0xE92D_0000 {
            // STMFD SP!, {reglist} - potential function prologue
            let reglist = word & 0xFFFF;
            // Check if LR (bit 14) is saved
            if reglist & (1 << 14) != 0 {
                boundaries.push(FunctionBoundary {
                    offset: base_address + offset as u64,
                    boundary_type: BoundaryType::FunctionStart,
                    execution_mode: ArmExecutionMode::Arm,
                    pattern: if (reglist & 0x4FF0) == 0x4FF0 {
                        Some(ProloguePattern::SaveRegsAndLr)
                    } else if reglist & 0x4000 != 0 {
                        Some(ProloguePattern::SaveFewRegsAndLr)
                    } else {
                        Some(ProloguePattern::SaveLrOnly)
                    },
                });
            }
        }
        // MOV IP, SP (MOV R12, SP) = 0xE1A0C00D
        else if word == 0xE1A0_C00D {
            boundaries.push(FunctionBoundary {
                offset: base_address + offset as u64,
                boundary_type: BoundaryType::FunctionStart,
                execution_mode: ArmExecutionMode::Arm,
                pattern: Some(ProloguePattern::MovIpSp),
            });
        }
        // SUB SP, SP, #imm
        else if (word & 0xFFFF_F000) == 0xE24D_D000 {
            boundaries.push(FunctionBoundary {
                offset: base_address + offset as u64,
                boundary_type: BoundaryType::FunctionStart,
                execution_mode: ArmExecutionMode::Arm,
                pattern: Some(ProloguePattern::StackAlloc),
            });
        }

        // Check for Thumb-mode prologue (halfword at a time)
        if offset + 1 < data.len() {
            let half = u16::from_le_bytes([data[offset], data[offset + 1]]);
            if (half & 0xFF00) == 0xB500 {
                // PUSH {..., LR}
                boundaries.push(FunctionBoundary {
                    offset: base_address + offset as u64,
                    boundary_type: BoundaryType::FunctionStart,
                    execution_mode: ArmExecutionMode::Thumb,
                    pattern: Some(ProloguePattern::ThumbPushLr),
                });
            } else if (half & 0xFF80) == 0xB080 {
                // SUB SP, SP, #imm
                boundaries.push(FunctionBoundary {
                    offset: base_address + offset as u64,
                    boundary_type: BoundaryType::FunctionStart,
                    execution_mode: ArmExecutionMode::Thumb,
                    pattern: Some(ProloguePattern::ThumbStackAlloc),
                });
            }
        }

        // Detect epilogue: LDMFD SP!, {reglist, PC} - function return
        if (word & 0xFFFF_0000) == 0xE8BD_0000 {
            let reglist = word & 0xFFFF;
            if reglist & (1 << 15) != 0 {
                // PC popped = function return
                boundaries.push(FunctionBoundary {
                    offset: base_address + offset as u64,
                    boundary_type: BoundaryType::FunctionEnd,
                    execution_mode: ArmExecutionMode::Arm,
                    pattern: None,
                });
            }
        }

        // BX LR (0xE12FFF1E) = unconditional function return
        if word == 0xE12F_FF1E {
            boundaries.push(FunctionBoundary {
                offset: base_address + offset as u64,
                boundary_type: BoundaryType::FunctionEnd,
                execution_mode: ArmExecutionMode::Arm,
                pattern: None,
            });
        }

        offset += min_size;
    }

    boundaries
}

// ========================================================================
// Prologue Detection
// ========================================================================

/// Detect a function prologue at the given offset.
pub fn detect_prologue(data: &[u8], mode: ArmExecutionMode) -> Option<ProloguePattern> {
    let min_size = mode.min_instruction_size() as usize;
    if data.len() < min_size {
        return None;
    }

    match mode {
        ArmExecutionMode::Arm => {
            let word = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if word == 0xE1A0_C00D {
                return Some(ProloguePattern::MovIpSp);
            }
            if (word & 0xFFFF_0000) == 0xE92D_0000 {
                let reglist = word & 0xFFFF;
                if (reglist & 0x4FF0) == 0x4FF0 {
                    return Some(ProloguePattern::SaveRegsAndLr);
                } else if reglist & 0x4000 != 0 {
                    return Some(ProloguePattern::SaveFewRegsAndLr);
                } else {
                    return Some(ProloguePattern::SaveLrOnly);
                }
            }
            if (word & 0xFFFF_F000) == 0xE24D_D000 {
                return Some(ProloguePattern::StackAlloc);
            }
            None
        }
        ArmExecutionMode::Thumb | ArmExecutionMode::Thumb2 => {
            let half = u16::from_le_bytes([data[0], data[1]]);
            if (half & 0xFF00) == 0xB500 {
                Some(ProloguePattern::ThumbPushLr)
            } else if (half & 0xFF80) == 0xB080 {
                Some(ProloguePattern::ThumbStackAlloc)
            } else {
                None
            }
        }
    }
}

// ========================================================================
// Epilogue Detection
// ========================================================================

/// Detect a function epilogue at the given offset.
pub fn detect_epilogue(data: &[u8], mode: ArmExecutionMode) -> bool {
    let min_size = mode.min_instruction_size() as usize;
    if data.len() < min_size {
        return false;
    }

    match mode {
        ArmExecutionMode::Arm => {
            let word = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            // LDMFD SP!, {..., PC}
            if (word & 0xFFFF_0000) == 0xE8BD_0000 {
                let reglist = word & 0xFFFF;
                reglist & (1 << 15) != 0
            }
            // BX LR
            else if word == 0xE12F_FF1E {
                true
            }
            // MOV PC, LR (return via mov)
            else if word == 0xE1A0_F00E {
                true
            } else {
                false
            }
        }
        ArmExecutionMode::Thumb | ArmExecutionMode::Thumb2 => {
            // Thumb POP {..., PC}
            let half = u16::from_le_bytes([data[0], data[1]]);
            (half & 0xFF00) == 0xBD00
                // Thumb BX LR
                || half == 0x4770
        }
    }
}

// ========================================================================
// Tests
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_format_detection_elf() {
        // Minimal ELF32 header with ARM machine type
        let mut elf_data = vec![0u8; 52];
        elf_data[0..4].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
        elf_data[4] = 1; // ELFCLASS32
        elf_data[18..20].copy_from_slice(&[0x28, 0x00]); // EM_ARM = 0x28
        let fmt = ArmBinaryFormat::detect(&elf_data);
        assert_eq!(fmt, ArmBinaryFormat::ELF32);
    }

    #[test]
    fn test_binary_format_detection_raw() {
        let data = vec![0x00, 0x00, 0xA0, 0xE1]; // MOV R0, R0
        let fmt = ArmBinaryFormat::detect(&data);
        assert_eq!(fmt, ArmBinaryFormat::Raw);
    }

    #[test]
    fn test_thumb_mode_detection() {
        assert_eq!(
            ArmModeDetector::detect_mode_at(0x8001),
            ArmExecutionMode::Thumb
        );
        assert_eq!(
            ArmModeDetector::detect_mode_at(0x8000),
            ArmExecutionMode::Arm
        );
        assert_eq!(ArmModeDetector::aligned_target(0x8001), 0x8000);
        assert_eq!(ArmModeDetector::aligned_target(0x8000), 0x8000);
    }

    #[test]
    fn test_arm_execution_mode_properties() {
        assert!(ArmExecutionMode::Arm.alignment() == 4);
        assert!(ArmExecutionMode::Thumb.alignment() == 2);
        assert!(ArmExecutionMode::Arm.min_instruction_size() == 4);
        assert!(ArmExecutionMode::Thumb.min_instruction_size() == 2);
        assert!(ArmExecutionMode::Arm.max_instruction_size() == 4);
        assert!(ArmExecutionMode::Thumb2.max_instruction_size() == 4);
    }

    #[test]
    fn test_detect_prologue_arm() {
        // STMFD SP!, {R4-R11, LR} = 0xE92D4FF0
        let data = [0xF0, 0x4F, 0x2D, 0xE9];
        let result = detect_prologue(&data, ArmExecutionMode::Arm);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), ProloguePattern::SaveRegsAndLr);
    }

    #[test]
    fn test_detect_prologue_thumb() {
        // PUSH {R4-R7, LR} = 0xB5F0
        let data = [0xF0, 0xB5];
        let result = detect_prologue(&data, ArmExecutionMode::Thumb);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), ProloguePattern::ThumbPushLr);
    }

    #[test]
    fn test_detect_epilogue_arm_bx_lr() {
        // BX LR = 0xE12FFF1E
        let data = [0x1E, 0xFF, 0x2F, 0xE1];
        assert!(detect_epilogue(&data, ArmExecutionMode::Arm));
    }

    #[test]
    fn test_detect_epilogue_thumb_bx_lr() {
        // BX LR = 0x4770
        let data = [0x70, 0x47];
        assert!(detect_epilogue(&data, ArmExecutionMode::Thumb));
    }

    #[test]
    fn test_detect_epilogue_arm_ldmfd_pc() {
        // LDMFD SP!, {R4-R11, PC} = 0xE8BD8FF0
        let data = [0xF0, 0x8F, 0xBD, 0xE8];
        assert!(detect_epilogue(&data, ArmExecutionMode::Arm));
    }

    #[test]
    fn test_calling_convention_args() {
        let cc = ArmCallingConvention::AAPCS;
        assert_eq!(cc.arg_registers(), &["R0", "R1", "R2", "R3"]);
        assert_eq!(cc.return_register(), "R0");
    }

    #[test]
    fn test_calling_convention_detect() {
        assert_eq!(
            ArmCallingConvention::detect_from_name("__aeabi_memcpy"),
            ArmCallingConvention::AAPCS
        );
        assert_eq!(
            ArmCallingConvention::detect_from_name("isr_timer"),
            ArmCallingConvention::BareMetal
        );
    }

    #[test]
    fn test_arm_binary_image_load() {
        let data = vec![0xF0, 0x4F, 0x2D, 0xE9]; // STMFD SP!, {R4-R11, LR}
        let image = ArmBinaryImage::load(data.clone(), 0x10000);
        assert_eq!(image.base_address, 0x10000);
        assert_eq!(image.format, ArmBinaryFormat::Raw);
        assert!(!image.registers.is_empty());
    }

    #[test]
    fn test_function_boundary_detection() {
        // ARM prologue + some code + epilogue
        let data = vec![
            0xF0, 0x4F, 0x2D, 0xE9, // STMFD SP!, {R4-R11, LR}
            0x00, 0x00, 0xA0, 0xE1, // MOV R0, R0 (NOP)
            0x02, 0x10, 0xA0, 0xE1, // MOV R1, R2
            0x1E, 0xFF, 0x2F, 0xE1, // BX LR
        ];
        let boundaries = detect_function_boundaries(&data, 0x8000, ArmExecutionMode::Arm);
        assert!(!boundaries.is_empty());

        let starts: Vec<_> = boundaries
            .iter()
            .filter(|b| b.boundary_type == BoundaryType::FunctionStart)
            .collect();
        assert!(!starts.is_empty());
    }

    #[test]
    fn test_arm_interwork_detection() {
        assert!(ArmModeDetector::is_interwork_branch(ArmMnemonic::BX));
        assert!(ArmModeDetector::is_interwork_branch(ArmMnemonic::BLX));
        assert!(!ArmModeDetector::is_interwork_branch(ArmMnemonic::B));
    }

    #[test]
    fn test_mode_detect_from_arm_bytes() {
        // ARM STMFD SP!, {R4,LR} = 0xE92D4010
        let data = [0x10, 0x40, 0x2D, 0xE9];
        let mode = ArmModeDetector::detect_mode_from_bytes(&data);
        assert_eq!(mode, Some(ArmExecutionMode::Arm));
    }

    #[test]
    fn test_mode_detect_from_thumb_bytes() {
        // Thumb PUSH {R4, LR} = 0xB510
        let data = [0x10, 0xB5];
        let mode = ArmModeDetector::detect_mode_from_bytes(&data);
        assert_eq!(mode, Some(ArmExecutionMode::Thumb));
    }
}
