//! AArch64 Binary Image Loader and Calling Convention Support
//!
//! Handles loading AArch64 binaries, detecting calling conventions,
//! identifying function boundaries via prologue/epilogue patterns,
//! and binary format detection.

// ========================================================================
// Binary Format Detection for AArch64
// ========================================================================

/// Supported executable formats for AArch64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aarch64BinaryFormat {
    /// 64-bit ELF (AArch64)
    ELF64,
    /// 32-bit ELF with ILP32 ABI (AArch64)
    ELF32ILP32,
    /// PE/COFF (AArch64 Windows)
    PE,
    /// Mach-O (macOS/iOS ARM64)
    MachO,
    /// Raw binary
    Raw,
    /// Unknown format
    Unknown,
}

impl Aarch64BinaryFormat {
    /// Detect the binary format from magic bytes.
    pub fn detect(data: &[u8]) -> Self {
        if data.len() < 4 {
            return Aarch64BinaryFormat::Unknown;
        }
        match &data[0..4] {
            [0x7F, 0x45, 0x4C, 0x46] => {
                // ELF magic. Check class in byte 4.
                if data.len() >= 5 && data[4] == 2 {
                    // ELFCLASS64
                    Aarch64BinaryFormat::ELF64
                } else if data.len() >= 5 && data[4] == 1 {
                    // ELFCLASS32 - might be ILP32
                    if data.len() >= 20 {
                        let machine = u16::from_le_bytes([data[18], data[19]]);
                        if machine == 0xB7 {
                            return Aarch64BinaryFormat::ELF32ILP32;
                        }
                    }
                    Aarch64BinaryFormat::ELF32ILP32
                } else {
                    Aarch64BinaryFormat::Unknown
                }
            }
            [0x4D, 0x5A, ..] => Aarch64BinaryFormat::PE, // MZ (PE)
            // Mach-O: little-endian 64-bit
            [0xCF, 0xFA, 0xED, 0xFE] => Aarch64BinaryFormat::MachO,
            // Mach-O: big-endian 64-bit
            [0xFE, 0xED, 0xFA, 0xCF] => Aarch64BinaryFormat::MachO,
            _ => Aarch64BinaryFormat::Raw,
        }
    }
}

// ========================================================================
// AArch64 Calling Conventions
// ========================================================================

/// AArch64 calling conventions.
///
/// Derived from Ghidra's cspec definitions:
/// - AARCH64.cspec (AAPCS64 default for Linux/GCC/Clang)
/// - AARCH64_win.cspec (Windows ARM64 ABI)
/// - AARCH64_ilp32.cspec (ILP32 variant)
/// - AARCH64_apple.cspec (Apple Silicon macOS/iOS)
/// - AARCH64_golang.cspec (Go runtime ABI)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Aarch64CallingConvention {
    /// AAPCS64 (standard for Linux, Android, GCC/Clang).
    /// x0-x7 args, x0-x1 return, x19-x28 preserved, d8-d15 preserved.
    AAPCS64,
    /// Windows ARM64 ABI.
    /// x0-x7 args, x0-x1 return, x19-x28 preserved, d8-d15 preserved.
    /// Differences from AAPCS64: LLP64 data model, different struct rules,
    /// x18 is reserved (TIB pointer), long is 4 bytes.
    Windows,
    /// Apple Silicon (macOS/iOS) calling convention.
    /// Similar to AAPCS64 but with Apple-specific extensions (PAC, etc.)
    AppleSilicon,
    /// Go runtime calling convention.
    /// x0-x15 args (more than AAPCS64), Go-specific register usage.
    Go,
    /// Bare-metal / interrupt handler.
    BareMetal,
}

impl Aarch64CallingConvention {
    /// Return the integer argument registers.
    pub fn arg_registers(&self) -> &[&str] {
        &["X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7"]
    }

    /// Return the integer return value registers.
    pub fn return_registers(&self) -> &[&str] {
        &["X0", "X1"]
    }

    /// Return the primary return value register.
    pub fn return_register(&self) -> &str {
        "X0"
    }

    /// Return the hidden return (indirect result location) register.
    ///
    /// In AAPCS64, x8 is used as the indirect result location register
    /// when a return value is too large to fit in x0-x1.
    pub fn hidden_return_register(&self) -> &str {
        "X8"
    }

    /// Return the callee-saved (preserved/unaffected) integer registers.
    pub fn callee_saved(&self) -> &[&str] {
        &["X19", "X20", "X21", "X22", "X23", "X24", "X25", "X26",
          "X27", "X28", "X29", "X30", "SP"]
    }

    /// Return the caller-saved (scratch/killed-by-call) integer registers.
    pub fn caller_saved(&self) -> &[&str] {
        &["X0", "X1", "X8", "X9", "X10", "X11", "X12", "X13",
          "X14", "X15", "X16", "X17", "X18"]
    }

    /// Return the callee-saved (preserved) SIMD/FP registers (double-precision view).
    pub fn vfp_callee_saved(&self) -> &[&str] {
        &["D8", "D9", "D10", "D11", "D12", "D13", "D14", "D15"]
    }

    /// Return the caller-saved (scratch) SIMD/FP registers (double-precision view).
    pub fn vfp_caller_saved(&self) -> &[&str] {
        &["D16", "D17", "D18", "D19", "D20", "D21", "D22", "D23",
          "D24", "D25", "D26", "D27", "D28", "D29", "D30", "D31"]
    }

    /// Return the SIMD/FP argument registers (quad-precision view).
    pub fn fp_arg_registers(&self) -> &[&str] {
        &["Q0", "Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7"]
    }

    /// Return the platform register (if reserved).
    pub fn platform_register(&self) -> Option<&str> {
        match self {
            Aarch64CallingConvention::Windows => Some("X18"),
            Aarch64CallingConvention::AppleSilicon => Some("X18"),
            _ => None,
        }
    }

    /// Detect the likely calling convention from symbol/function name.
    pub fn detect_from_name(name: &str) -> Self {
        if name.starts_with("isr_") || name.starts_with("__irq_") {
            Aarch64CallingConvention::BareMetal
        } else if name.starts_with("runtime.") || name.starts_with("go.") {
            Aarch64CallingConvention::Go
        } else {
            Aarch64CallingConvention::AAPCS64
        }
    }

    /// Returns the compiler spec ID used in Ghidra's cspec definitions.
    pub fn compiler_spec_id(&self) -> &'static str {
        match self {
            Aarch64CallingConvention::AAPCS64
            | Aarch64CallingConvention::BareMetal => "default",
            Aarch64CallingConvention::Windows => "windows",
            Aarch64CallingConvention::AppleSilicon => "default",
            Aarch64CallingConvention::Go => "golang",
        }
    }
}

// ========================================================================
// Function Boundary Detection
// ========================================================================

/// Prologue/epilogue pattern types for AArch64 functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aarch64ProloguePattern {
    /// STP x29, x30, [sp, #-N]! -- Save frame pointer and link register
    SaveFpLr,
    /// STP x29, x30, [sp, #N] -- Save FP/LR without pre-decrement
    SaveFpLrOffset,
    /// SUB sp, sp, #N -- Stack frame allocation
    StackAlloc,
    /// PACIASP -- Pointer authentication (ARMv8.3-A+)
    PacSign,
    /// MOV x29, sp -- Set up frame pointer
    SetUpFp,
}

/// Detected function boundary with type and offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aarch64FunctionBoundary {
    /// Address where this boundary was detected
    pub address: u64,
    /// Whether this is a function start or end
    pub boundary_type: Aarch64BoundaryType,
    /// The detected pattern type
    pub pattern: Option<Aarch64ProloguePattern>,
}

/// Type of function boundary for AArch64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aarch64BoundaryType {
    /// Function entry (prologue)
    FunctionStart,
    /// Function exit (epilogue)
    FunctionEnd,
    /// Potential function start (lower confidence)
    PossibleStart,
}

// ========================================================================
// AArch64 Binary Image
// ========================================================================

/// A loaded AArch64 binary image with associated metadata.
#[derive(Debug, Clone)]
pub struct Aarch64BinaryImage {
    /// The raw binary data.
    pub data: Vec<u8>,
    /// Load base address.
    pub base_address: u64,
    /// Entry point address.
    pub entry_point: u64,
    /// Detected binary format.
    pub format: Aarch64BinaryFormat,
    /// Detected function boundaries.
    pub function_boundaries: Vec<Aarch64FunctionBoundary>,
    /// Sections found in the binary.
    pub sections: Vec<Aarch64Section>,
}

/// A section in the AArch64 binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aarch64Section {
    pub name: String,
    pub virtual_address: u64,
    pub offset: u64,
    pub size: u64,
    pub is_executable: bool,
    pub is_writable: bool,
    pub data: Vec<u8>,
}

impl Aarch64BinaryImage {
    /// Create a new AArch64 binary image from raw data.
    pub fn new(data: Vec<u8>, base_address: u64, entry_point: u64) -> Self {
        let format = Aarch64BinaryFormat::detect(&data);
        Aarch64BinaryImage {
            data,
            base_address,
            entry_point,
            format,
            function_boundaries: Vec::new(),
            sections: Vec::new(),
        }
    }

    /// Load a binary from raw data and auto-detect parameters.
    pub fn load(data: Vec<u8>, base_address: u64) -> Self {
        let format = Aarch64BinaryFormat::detect(&data);
        Aarch64BinaryImage {
            data,
            base_address,
            entry_point: base_address,
            format,
            function_boundaries: Vec::new(),
            sections: Vec::new(),
        }
    }

    /// Read a 32-bit word at the given address (little-endian).
    pub fn read_word(&self, address: u64) -> Option<u32> {
        let off = (address - self.base_address) as usize;
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

    /// Read a 16-bit halfword at the given address (little-endian).
    pub fn read_halfword(&self, address: u64) -> Option<u16> {
        let off = (address - self.base_address) as usize;
        if off + 2 <= self.data.len() {
            Some(u16::from_le_bytes([self.data[off], self.data[off + 1]]))
        } else {
            None
        }
    }

    /// Read a byte at the given address.
    pub fn read_byte(&self, address: u64) -> Option<u8> {
        let off = (address - self.base_address) as usize;
        if off < self.data.len() {
            Some(self.data[off])
        } else {
            None
        }
    }

    /// Detect all function boundaries in the binary.
    pub fn detect_function_boundaries(&mut self) {
        self.function_boundaries =
            detect_aarch64_function_boundaries(&self.data, self.base_address);
    }
}

// ========================================================================
// Function Boundary Detection (Implementation)
// ========================================================================

/// Detect function boundaries in raw AArch64 binary data.
pub fn detect_aarch64_function_boundaries(
    data: &[u8],
    base_address: u64,
) -> Vec<Aarch64FunctionBoundary> {
    let mut boundaries = Vec::new();

    if data.len() < 4 {
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

        // STP x29, x30, [sp, #-N]!  (pre-indexed decrement)
        // Encoding: 0xA9xx7BFD where xx is the scaled imm7
        if (word & 0xFFC0_7FFF) == 0xA980_7BFD {
            boundaries.push(Aarch64FunctionBoundary {
                address: base_address + offset as u64,
                boundary_type: Aarch64BoundaryType::FunctionStart,
                pattern: Some(Aarch64ProloguePattern::SaveFpLr),
            });
        }
        // STP x29, x30, [sp, #N]  (signed offset)
        // Encoding: 0xA9xx7BFD with various immediate patterns
        else if (word & 0x7FC0_7FFF) == 0x2900_7BFD || (word & 0xFFC0_7FFF) == 0xA900_7BFD {
            // Could be STP with positive offset (non-pre-index)
            let rt1 = word & 0x1F;
            let rt2 = (word >> 10) & 0x1F;
            if rt1 == 29 && rt2 == 30 {
                boundaries.push(Aarch64FunctionBoundary {
                    address: base_address + offset as u64,
                    boundary_type: Aarch64BoundaryType::PossibleStart,
                    pattern: Some(Aarch64ProloguePattern::SaveFpLrOffset),
                });
            }
        }
        // SUB sp, sp, #imm  (stack allocation)
        // Encoding: 0xD100_03FF where 0x3FF is sp
        else if (word & 0xFF00_03FF) == 0xD100_03FF {
            boundaries.push(Aarch64FunctionBoundary {
                address: base_address + offset as u64,
                boundary_type: Aarch64BoundaryType::FunctionStart,
                pattern: Some(Aarch64ProloguePattern::StackAlloc),
            });
        }
        // PACIASP (Pointer Authentication)
        // Encoding: 0xD503_233F
        else if word == 0xD503_233F {
            boundaries.push(Aarch64FunctionBoundary {
                address: base_address + offset as u64,
                boundary_type: Aarch64BoundaryType::FunctionStart,
                pattern: Some(Aarch64ProloguePattern::PacSign),
            });
        }

        // Epilogue: RET (0xD65F_03C0) or LDP x29, x30, [sp], #N followed by RET
        if word == 0xD65F_03C0 {
            // RET
            boundaries.push(Aarch64FunctionBoundary {
                address: base_address + offset as u64,
                boundary_type: Aarch64BoundaryType::FunctionEnd,
                pattern: None,
            });
        } else if (word & 0xFFC0_7FFF) == 0xA8C0_7BFD {
            // LDP x29, x30, [sp], #N (post-increment restore) - likely epilogue
            boundaries.push(Aarch64FunctionBoundary {
                address: base_address + offset as u64,
                boundary_type: Aarch64BoundaryType::FunctionEnd,
                pattern: None,
            });
        }
        // AUTIASP (Pointer Authentication epilogue)
        else if word == 0xD503_23BF {
            boundaries.push(Aarch64FunctionBoundary {
                address: base_address + offset as u64,
                boundary_type: Aarch64BoundaryType::FunctionEnd,
                pattern: None,
            });
        }

        offset += 4; // AArch64 instructions are always 4 bytes
    }

    boundaries
}

/// Detect a function prologue at the given offset in AArch64 binary data.
pub fn detect_prologue(data: &[u8]) -> Option<Aarch64ProloguePattern> {
    if data.len() < 4 {
        return None;
    }

    let word = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    // PACIASP
    if word == 0xD503_233F {
        return Some(Aarch64ProloguePattern::PacSign);
    }
    // STP x29, x30, [sp, #-N]!
    if (word & 0xFFC0_7FFF) == 0xA980_7BFD {
        return Some(Aarch64ProloguePattern::SaveFpLr);
    }
    // SUB sp, sp, #imm
    if (word & 0xFF00_03FF) == 0xD100_03FF {
        let rd = word & 0x1F;
        if rd == 31 {
            // SP
            return Some(Aarch64ProloguePattern::StackAlloc);
        }
    }

    None
}

/// Detect a function epilogue at the given offset in AArch64 binary data.
pub fn detect_epilogue(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    let word = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    // RET
    word == 0xD65F_03C0
    // AUTIASP
    || word == 0xD503_23BF
    // LDP x29, x30, [sp], #N (post-increment, epilogue restore)
    || (word & 0xFFC0_7FFF) == 0xA8C0_7BFD
}

// ========================================================================
// Tests
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_format_detection_elf64() {
        let mut elf_data = vec![0u8; 64];
        elf_data[0..4].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
        elf_data[4] = 2; // ELFCLASS64
        elf_data[18..20].copy_from_slice(&[0xB7, 0x00]); // EM_AARCH64 = 0xB7
        let fmt = Aarch64BinaryFormat::detect(&elf_data);
        assert_eq!(fmt, Aarch64BinaryFormat::ELF64);
    }

    #[test]
    fn test_binary_format_detection_pe() {
        let mut pe_data = vec![0u8; 64];
        pe_data[0] = 0x4D; // 'M'
        pe_data[1] = 0x5A; // 'Z'
        let fmt = Aarch64BinaryFormat::detect(&pe_data);
        assert_eq!(fmt, Aarch64BinaryFormat::PE);
    }

    #[test]
    fn test_binary_format_detection_macho() {
        let mut data = vec![0u8; 32];
        // LE Mach-O 64-bit
        data[0] = 0xCF;
        data[1] = 0xFA;
        data[2] = 0xED;
        data[3] = 0xFE;
        let fmt = Aarch64BinaryFormat::detect(&data);
        assert_eq!(fmt, Aarch64BinaryFormat::MachO);
    }

    #[test]
    fn test_binary_format_detection_raw() {
        let data = vec![0x00, 0x00, 0x00, 0xD5]; // NOP
        let fmt = Aarch64BinaryFormat::detect(&data);
        assert_eq!(fmt, Aarch64BinaryFormat::Raw);
    }

    #[test]
    fn test_aapcs64_convention() {
        let cc = Aarch64CallingConvention::AAPCS64;
        assert_eq!(cc.arg_registers(), &["X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7"]);
        assert_eq!(cc.return_register(), "X0");
        assert_eq!(cc.hidden_return_register(), "X8");
        assert!(cc.callee_saved().contains(&"X19"));
        assert!(cc.callee_saved().contains(&"SP"));
        assert_eq!(cc.platform_register(), None);
        assert_eq!(cc.compiler_spec_id(), "default");
    }

    #[test]
    fn test_windows_convention() {
        let cc = Aarch64CallingConvention::Windows;
        assert_eq!(cc.platform_register(), Some("X18"));
        assert_eq!(cc.compiler_spec_id(), "windows");
    }

    #[test]
    fn test_apple_silicon_convention() {
        let cc = Aarch64CallingConvention::AppleSilicon;
        assert_eq!(cc.platform_register(), Some("X18"));
    }

    #[test]
    fn test_go_convention() {
        let cc = Aarch64CallingConvention::Go;
        assert_eq!(cc.compiler_spec_id(), "golang");
    }

    #[test]
    fn test_convention_detection() {
        assert_eq!(
            Aarch64CallingConvention::detect_from_name("runtime.malloc"),
            Aarch64CallingConvention::Go
        );
        assert_eq!(
            Aarch64CallingConvention::detect_from_name("isr_timer"),
            Aarch64CallingConvention::BareMetal
        );
        assert_eq!(
            Aarch64CallingConvention::detect_from_name("main"),
            Aarch64CallingConvention::AAPCS64
        );
    }

    #[test]
    fn test_fp_arg_registers() {
        let cc = Aarch64CallingConvention::AAPCS64;
        assert_eq!(cc.fp_arg_registers().len(), 8);
        assert_eq!(cc.fp_arg_registers()[0], "Q0");
    }

    #[test]
    fn test_detect_ret_epilogue() {
        // RET = 0xD65F03C0 (LE bytes: C0 03 5F D6)
        let data = [0xC0, 0x03, 0x5F, 0xD6];
        assert!(detect_epilogue(&data));
    }

    #[test]
    fn test_detect_prologue_paciasp() {
        // PACIASP = 0xD503233F (LE bytes: 3F 23 03 D5)
        let data = [0x3F, 0x23, 0x03, 0xD5];
        let result = detect_prologue(&data);
        assert_eq!(result, Some(Aarch64ProloguePattern::PacSign));
    }

    #[test]
    fn test_detect_prologue_stp_fp_lr() {
        // STP x29, x30, [sp, #-0x10]! = 0xA9BF7BFD (LE: FD 7B BF A9)
        let data = [0xFD, 0x7B, 0xBF, 0xA9];
        let result = detect_prologue(&data);
        assert_eq!(result, Some(Aarch64ProloguePattern::SaveFpLr));
    }

    #[test]
    fn test_aarch64_binary_image() {
        let data = vec![0xC0, 0x03, 0x5F, 0xD6]; // RET
        let image = Aarch64BinaryImage::new(data, 0x400000, 0x400000);
        assert_eq!(image.base_address, 0x400000);
        assert_eq!(image.format, Aarch64BinaryFormat::Raw);
    }

    #[test]
    fn test_function_boundary_detection() {
        // PACIASP + STP + ... + RET
        let data = vec![
            0x3F, 0x23, 0x03, 0xD5, // PACIASP
            0xFD, 0x7B, 0xBF, 0xA9, // STP x29, x30, [sp, #-0x10]!
            0xC0, 0x03, 0x5F, 0xD6, // RET
        ];
        let boundaries = detect_aarch64_function_boundaries(&data, 0x10000);
        assert!(!boundaries.is_empty());
        let starts: Vec<_> = boundaries
            .iter()
            .filter(|b| b.boundary_type == Aarch64BoundaryType::FunctionStart)
            .collect();
        assert!(!starts.is_empty());
    }
}
