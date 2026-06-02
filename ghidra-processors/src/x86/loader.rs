//! x86 Binary Image Loader and Instruction Decoder
//!
//! Handles loading x86/x86-64 binaries (PE, ELF, Mach-O), decoding
//! individual instructions, detecting function prologues/epilogues,
//! and identifying calling conventions.

use crate::x86::instructions::{
    ConditionCode, DecodedInstruction, ModRM, Operand, PrefixInfo, X86Mnemonic, REX, SIB,
};
use crate::x86::registers::X86RegisterBank;

// ========================================================================
// Binary Format Detection
// ========================================================================

/// Supported executable formats for x86.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    PE32,     // 32-bit Portable Executable
    PE32Plus, // 64-bit Portable Executable
    ELF32,    // 32-bit ELF
    ELF64,    // 64-bit ELF
    MachO32,  // 32-bit Mach-O
    MachO64,  // 64-bit Mach-O
    Raw,      // Raw binary (flat binary, boot sector, etc.)
    Unknown,
}

impl BinaryFormat {
    /// Detect the binary format from magic bytes.
    pub fn detect(data: &[u8]) -> Self {
        if data.len() < 4 {
            return BinaryFormat::Unknown;
        }
        match &data[0..4] {
            [0x4D, 0x5A, ..] => {
                // MZ header -> PE or DOS. Check for PE signature at offset in MZ header.
                if data.len() >= 0x40 {
                    let pe_offset =
                        u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]])
                            as usize;
                    if data.len() >= pe_offset + 6 {
                        match &data[pe_offset..pe_offset + 4] {
                            [0x50, 0x45, 0x00, 0x00] => {
                                // PE\0\0 — check machine type in COFF header
                                let machine =
                                    u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);
                                match machine {
                                    0x8664 => BinaryFormat::PE32Plus,
                                    _ => BinaryFormat::PE32,
                                }
                            }
                            _ => BinaryFormat::Unknown,
                        }
                    } else {
                        BinaryFormat::Raw // DOS-only or truncated
                    }
                } else {
                    BinaryFormat::Raw
                }
            }
            [0x7F, 0x45, 0x4C, 0x46] => {
                // ELF magic
                if data.len() >= 5 {
                    match data[4] {
                        1 => BinaryFormat::ELF32, // ELFCLASS32
                        2 => BinaryFormat::ELF64, // ELFCLASS64
                        _ => BinaryFormat::Unknown,
                    }
                } else {
                    BinaryFormat::Unknown
                }
            }
            // Mach-O magic
            [0xFE, 0xED, 0xFA, 0xCE] | [0xCE, 0xFA, 0xED, 0xFE] => BinaryFormat::MachO32,
            [0xFE, 0xED, 0xFA, 0xCF] | [0xCF, 0xFA, 0xED, 0xFE] => BinaryFormat::MachO64,
            _ => BinaryFormat::Raw,
        }
    }

    /// Returns true if this is a 64-bit binary format.
    pub fn is_64bit(&self) -> bool {
        matches!(
            self,
            BinaryFormat::PE32Plus | BinaryFormat::ELF64 | BinaryFormat::MachO64
        )
    }

    /// Returns the default code pointer size for this format.
    pub fn pointer_size(&self) -> u8 {
        if self.is_64bit() {
            8
        } else {
            4
        }
    }
}

// ========================================================================
// Calling Convention Detection
// ========================================================================

/// x86 calling conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// cdecl: caller cleans stack, parameters pushed right-to-left.
    Cdecl,
    /// stdcall: callee cleans stack, parameters pushed right-to-left.
    Stdcall,
    /// fastcall: first 2 params in ECX, EDX; rest on stack.
    Fastcall,
    /// thiscall: 'this' pointer in ECX; rest on stack (MSVC variant).
    Thiscall,
    /// x86-64 System V ABI: RDI, RSI, RDX, RCX, R8, R9; rest on stack.
    SystemV64,
    /// x86-64 Microsoft ABI: RCX, RDX, R8, R9; rest on stack.
    Windows64,
    /// vectorcall: fastcall with XMM registers for FP args.
    Vectorcall,
    /// Unknown / could not determine.
    Unknown,
}

impl CallingConvention {
    /// Identify the calling convention from the binary format and function
    /// characteristics.
    ///
    /// Heuristics:
    /// - 64-bit PE -> Windows x64
    /// - 64-bit ELF / MachO -> System V AMD64
    /// - 32-bit with stdcall decoration (@N suffix) -> stdcall
    /// - 32-bit with 'this' pointer in ECX -> thiscall
    /// - 32-bit default -> cdecl
    /// - SIMD-heavy with XMM params -> vectorcall
    pub fn detect(
        format: BinaryFormat,
        symbol_name: Option<&str>,
        args_passed_in_regs: Option<&[&str]>,
    ) -> Self {
        match format {
            BinaryFormat::PE32Plus => {
                // 64-bit Windows: always the MS x64 ABI
                CallingConvention::Windows64
            }
            BinaryFormat::ELF64 | BinaryFormat::MachO64 => {
                // 64-bit Unix: always System V AMD64
                CallingConvention::SystemV64
            }
            _ => {
                // 32-bit: inspect symbol name and register usage
                if let Some(name) = symbol_name {
                    // Check for stdcall decoration: _name@N
                    if name.starts_with('_') && name.contains('@') {
                        return CallingConvention::Stdcall;
                    }
                }
                if let Some(regs) = args_passed_in_regs {
                    // Check register usage pattern
                    if !regs.is_empty() && regs[0] == "ECX" {
                        if regs.len() >= 2 && regs[1] == "EDX" {
                            return CallingConvention::Fastcall;
                        }
                        return CallingConvention::Thiscall;
                    }
                }
                CallingConvention::Cdecl
            }
        }
    }

    /// Return the registers used for passing arguments, in order.
    pub fn argument_registers(&self) -> &'static [&'static str] {
        match self {
            CallingConvention::Cdecl => &[],   // all on stack
            CallingConvention::Stdcall => &[], // all on stack
            CallingConvention::Fastcall => &["ECX", "EDX"],
            CallingConvention::Thiscall => &["ECX"],
            CallingConvention::SystemV64 => &["RDI", "RSI", "RDX", "RCX", "R8", "R9"],
            CallingConvention::Windows64 => &["RCX", "RDX", "R8", "R9"],
            CallingConvention::Vectorcall => {
                &["RCX", "RDX", "R8", "R9", "XMM0", "XMM1", "XMM2", "XMM3"]
            }
            CallingConvention::Unknown => &[],
        }
    }

    /// Return the register used for the return value.
    pub fn return_register(&self) -> &'static str {
        match self {
            CallingConvention::Cdecl
            | CallingConvention::Stdcall
            | CallingConvention::Fastcall
            | CallingConvention::Thiscall => "EAX",
            CallingConvention::SystemV64
            | CallingConvention::Windows64
            | CallingConvention::Vectorcall => "RAX",
            CallingConvention::Unknown => "RAX",
        }
    }

    /// Does the callee clean up the stack?
    pub fn callee_cleans_stack(&self) -> bool {
        matches!(
            self,
            CallingConvention::Stdcall | CallingConvention::Fastcall
        )
    }

    /// The human-readable name of this convention.
    pub fn name(&self) -> &'static str {
        match self {
            CallingConvention::Cdecl => "cdecl",
            CallingConvention::Stdcall => "stdcall",
            CallingConvention::Fastcall => "fastcall",
            CallingConvention::Thiscall => "thiscall",
            CallingConvention::SystemV64 => "System V AMD64 ABI",
            CallingConvention::Windows64 => "Microsoft x64",
            CallingConvention::Vectorcall => "vectorcall",
            CallingConvention::Unknown => "unknown",
        }
    }
}

// ========================================================================
// Function Prologue / Epilogue Detection
// ========================================================================

/// Patterns that identify function entry points (prologues).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProloguePattern {
    /// Standard: `push rbp; mov rbp, rsp` (or 32-bit `push ebp; mov ebp, esp`)
    StandardFrame,
    /// `push rbp; push rbx; sub rsp, N`
    SaveNonVolatile,
    /// `mov edi, edi` (hot-patch point, 5-byte NOP prefix)
    HotPatchPoint,
    /// Only `sub rsp, N` (leaf function without frame pointer)
    LeafFunction,
    /// `push reg` sequence followed by entry (no frame pointer)
    PushOnly,
    /// `endbr64` / `endbr32` CET landing pad
    CetLandingPad,
}

/// Recognised function epilogue patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpiloguePattern {
    /// `leave; ret N` or `leave; ret`
    LeaveRet,
    /// `pop rbp; ret` or `add rsp, N; pop rbp; ret`
    PopRet,
    /// `ret N` (stdcall cleanup)
    RetImm,
    /// Simple `ret` (no cleanup)
    Ret,
    /// `jmp` to another function (tail call)
    TailCall,
    /// `ud2` or interrupt (unreachable / abort)
    Unreachable,
}

/// Information about a detected function prologue or epilogue.
#[derive(Debug, Clone)]
pub struct FunctionBoundary {
    /// Address where the boundary was detected.
    pub address: u64,
    /// Type of boundary (prologue or epilogue).
    pub boundary_type: BoundaryType,
    /// Bytes that matched the pattern.
    pub matched_bytes: Vec<u8>,
    /// Size of the stack frame being set up or torn down, if known.
    pub frame_size: Option<i64>,
    /// Which pattern was recognised.
    pub pattern: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryType {
    Prologue,
    Epilogue,
}

/// Detect function prologue at the given address in the byte stream.
///
/// Recognises common patterns:
/// - `push rbp; mov rbp, rsp`  (standard frame pointer setup)
/// - `push rbp; push rbx; sub rsp, N`  (save non-volatile + alloc)
/// - `sub rsp, N`  (leaf function)
/// - `mov edi, edi`  (hot-patch point in Windows x64)
pub fn detect_prologue(data: &[u8], address: u64, is_64bit: bool) -> Option<FunctionBoundary> {
    let len = data.len();
    if len < 1 {
        return None;
    }

    let (push_rbp, _push_ebp, mov_rbp_rsp, _mov_ebp_esp, sub_rsp, _sub_esp) = if is_64bit {
        // 64-bit patterns
        (
            &[0x55u8][..],           // push rbp
            &[0x55u8][..],           // N/A
            &[0x48, 0x89, 0xE5][..], // mov rbp, rsp
            &[0x48, 0x89, 0xE5][..], // N/A
            &[0x48, 0x83, 0xEC][..], // sub rsp, imm8
            &[0x48, 0x83, 0xEC][..], // N/A
        )
    } else {
        // 32-bit patterns
        (
            &[0x55u8][..],     // push ebp
            &[0x55u8][..],     // push ebp
            &[0x89, 0xE5][..], // mov ebp, esp
            &[0x89, 0xE5][..], // mov ebp, esp
            &[0x83, 0xEC][..], // sub esp, imm8
            &[0x83, 0xEC][..], // sub esp, imm8
        )
    };

    // Pattern: push rbp; mov rbp, rsp
    if len >= 3 && data[..1] == push_rbp[..1] {
        // Check for frame pointer pattern
        if len >= 4 && data[1..].starts_with(mov_rbp_rsp) {
            return Some(FunctionBoundary {
                address,
                boundary_type: BoundaryType::Prologue,
                matched_bytes: data[..4].to_vec(),
                frame_size: Some(0),
                pattern: "push rbp; mov rbp, rsp".to_string(),
            });
        }
        // push rbp alone may be partial
        return Some(FunctionBoundary {
            address,
            boundary_type: BoundaryType::Prologue,
            matched_bytes: data[..1].to_vec(),
            frame_size: None,
            pattern: "push rbp".to_string(),
        });
    }

    // Pattern: sub rsp, N  (leaf function or after frame pointer setup)
    if len >= 4 && data.starts_with(sub_rsp) {
        let frame_size = data[2] as i64;
        return Some(FunctionBoundary {
            address,
            boundary_type: BoundaryType::Prologue,
            matched_bytes: data[..4].to_vec(),
            frame_size: Some(frame_size),
            pattern: format!("sub rsp, {}", frame_size),
        });
    }

    // Pattern: push rbx (common second instruction after push rbp)
    if len >= 1 && data[0] == 0x53 {
        return Some(FunctionBoundary {
            address,
            boundary_type: BoundaryType::Prologue,
            matched_bytes: data[..1].to_vec(),
            frame_size: None,
            pattern: "push rbx".to_string(),
        });
    }

    // Hot-patch point (mov edi, edi in Windows x64: 8B FF or 89 FF)
    if len >= 2 && ((data[0] == 0x8B && data[1] == 0xFF) || (data[0] == 0x89 && data[1] == 0xFF)) {
        return Some(FunctionBoundary {
            address,
            boundary_type: BoundaryType::Prologue,
            matched_bytes: data[..2].to_vec(),
            frame_size: None,
            pattern: "mov edi, edi (hot-patch)".to_string(),
        });
    }

    // CET endbr64 (F3 0F 1E FA) / endbr32 (F3 0F 1E FB)
    if len >= 4
        && data[0] == 0xF3
        && data[1] == 0x0F
        && data[2] == 0x1E
        && (data[3] == 0xFA || data[3] == 0xFB)
    {
        return Some(FunctionBoundary {
            address,
            boundary_type: BoundaryType::Prologue,
            matched_bytes: data[..4].to_vec(),
            frame_size: None,
            pattern: if data[3] == 0xFA {
                "endbr64"
            } else {
                "endbr32"
            }
            .to_string(),
        });
    }

    None
}

/// Detect function epilogue at the given address.
///
/// Recognised patterns:
/// - `leave; ret`  (C9 C3)
/// - `pop rbp; ret`  (5D C3)
/// - `ret N`  (C2 N 00)
/// - `ret`  (C3)
/// - `jmp` to external symbol (tail call)
pub fn detect_epilogue(data: &[u8], address: u64) -> Option<FunctionBoundary> {
    let len = data.len();
    if len < 1 {
        return None;
    }

    match data[0] {
        // ret (C3)
        0xC3 => Some(FunctionBoundary {
            address,
            boundary_type: BoundaryType::Epilogue,
            matched_bytes: data[..1].to_vec(),
            frame_size: None,
            pattern: "ret".to_string(),
        }),
        // ret imm16 (C2)
        0xC2 if len >= 3 => {
            let pop_bytes = u16::from_le_bytes([data[1], data[2]]) as i64;
            Some(FunctionBoundary {
                address,
                boundary_type: BoundaryType::Epilogue,
                matched_bytes: data[..3].to_vec(),
                frame_size: Some(pop_bytes),
                pattern: format!("ret {}", pop_bytes),
            })
        }
        // leave (C9)
        0xC9 => Some(FunctionBoundary {
            address,
            boundary_type: BoundaryType::Epilogue,
            matched_bytes: data[..1].to_vec(),
            frame_size: None,
            pattern: "leave".to_string(),
        }),
        // pop rbp (5D)
        0x5D => Some(FunctionBoundary {
            address,
            boundary_type: BoundaryType::Epilogue,
            matched_bytes: data[..1].to_vec(),
            frame_size: None,
            pattern: "pop rbp".to_string(),
        }),
        // Near jump (E9) — potential tail call
        0xE9 => Some(FunctionBoundary {
            address,
            boundary_type: BoundaryType::Epilogue,
            matched_bytes: data[..1].to_vec(),
            frame_size: None,
            pattern: "jmp (tail call)".to_string(),
        }),
        _ => None,
    }
}

// ========================================================================
// Basic Instruction Decoder
// ========================================================================

/// A minimal x86 instruction decoder.
///
/// This is a skeletal implementation that decodes common patterns
/// for analysis purposes. A complete decoder would handle every
/// opcode and prefix combination; this version targets the
/// instructions most relevant to static analysis (control flow,
/// function boundaries, stack manipulation, data references).
pub struct X86InstructionDecoder {
    /// 64-bit mode flag
    pub is_64bit: bool,
    /// Register bank for operand resolution
    pub registers: X86RegisterBank,
    /// Current decode position in the byte stream
    pos: usize,
    /// The byte stream being decoded
    data: Vec<u8>,
    /// Base address for relative offset calculations
    base_address: u64,
}

impl X86InstructionDecoder {
    /// Create a new decoder for the given byte slice and base address.
    pub fn new(data: &[u8], base_address: u64, is_64bit: bool) -> Self {
        X86InstructionDecoder {
            is_64bit,
            registers: X86RegisterBank::new_x86_64(),
            pos: 0,
            data: data.to_vec(),
            base_address,
        }
    }

    /// Peek at the next byte without advancing.
    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Consume the next byte.
    fn next_byte(&mut self) -> Option<u8> {
        let b = self.peek();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    /// Consume `n` bytes as a little-endian value.
    fn next_bytes_le(&mut self, n: usize) -> Option<u64> {
        let mut value: u64 = 0;
        for i in 0..n {
            let b = self.next_byte()?;
            value |= (b as u64) << (i * 8);
        }
        Some(value)
    }

    /// Skip `n` bytes.
    fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.data.len());
    }

    /// True if there are more bytes to decode.
    pub fn has_more(&self) -> bool {
        self.pos < self.data.len()
    }

    /// Current position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Set the position.
    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos.min(self.data.len());
    }

    /// Decode the next instruction.
    pub fn decode_next(&mut self) -> Option<DecodedInstruction> {
        let start = self.pos;
        let address = self.base_address + start as u64;

        // --- Prefix bytes ---
        let mut prefixes: Vec<PrefixInfo> = Vec::new();
        let mut operand_size_16 = false;
        let mut address_size_16 = false;
        let mut has_rex = false;
        let mut rex_byte = 0u8;
        let mut segment_override: Option<PrefixInfo> = None;
        let mut has_lock = false;
        let mut has_rep = false;
        let mut has_repne = false;

        loop {
            let b = self.peek()?;
            match b {
                0xF0 => {
                    has_lock = true;
                    prefixes.push(PrefixInfo::Lock);
                    self.next_byte();
                }
                0xF2 => {
                    has_repne = true;
                    prefixes.push(PrefixInfo::Repne);
                    self.next_byte();
                }
                0xF3 => {
                    has_rep = true;
                    prefixes.push(PrefixInfo::Rep);
                    self.next_byte();
                }
                0x26 => {
                    segment_override = Some(PrefixInfo::SegmentOverride(
                        crate::x86::instructions::SegmentRegister::ES,
                    ));
                    prefixes.push(segment_override.unwrap());
                    self.next_byte();
                }
                0x2E => {
                    segment_override = Some(PrefixInfo::SegmentOverride(
                        crate::x86::instructions::SegmentRegister::CS,
                    ));
                    prefixes.push(segment_override.unwrap());
                    self.next_byte();
                }
                0x36 => {
                    segment_override = Some(PrefixInfo::SegmentOverride(
                        crate::x86::instructions::SegmentRegister::SS,
                    ));
                    prefixes.push(segment_override.unwrap());
                    self.next_byte();
                }
                0x3E => {
                    segment_override = Some(PrefixInfo::SegmentOverride(
                        crate::x86::instructions::SegmentRegister::DS,
                    ));
                    prefixes.push(segment_override.unwrap());
                    self.next_byte();
                }
                0x64 => {
                    segment_override = Some(PrefixInfo::SegmentOverride(
                        crate::x86::instructions::SegmentRegister::FS,
                    ));
                    prefixes.push(segment_override.unwrap());
                    self.next_byte();
                }
                0x65 => {
                    segment_override = Some(PrefixInfo::SegmentOverride(
                        crate::x86::instructions::SegmentRegister::GS,
                    ));
                    prefixes.push(segment_override.unwrap());
                    self.next_byte();
                }
                0x66 => {
                    operand_size_16 = true;
                    prefixes.push(PrefixInfo::OperandSizeOverride);
                    self.next_byte();
                }
                0x67 => {
                    address_size_16 = true;
                    prefixes.push(PrefixInfo::AddressSizeOverride);
                    self.next_byte();
                }
                n if REX::is_rex(n) => {
                    has_rex = true;
                    rex_byte = n;
                    prefixes.push(PrefixInfo::Rex(REX::new(n)));
                    self.next_byte();
                }
                _ => break,
            }
        }

        // --- Opcode ---
        let opcode_byte = self.next_byte()?;

        // Determine operand sizes
        let operand_size: u8 = if self.is_64bit {
            if has_rex && (rex_byte & 0b1000) != 0 {
                64
            } else if operand_size_16 {
                16
            } else {
                32
            }
        } else {
            if operand_size_16 {
                16
            } else {
                32
            }
        };

        let address_size: u8 = if self.is_64bit {
            if address_size_16 {
                32
            } else {
                64
            }
        } else {
            if address_size_16 {
                16
            } else {
                32
            }
        };

        // --- Decode mnemonic and operands ---
        let (mnemonic, operands, is_branch, branch_target, is_terminator) =
            self.decode_opcode(opcode_byte, operand_size, address_size, address);

        let end = self.pos;
        let bytes = self.data[start..end].to_vec();

        Some(DecodedInstruction {
            mnemonic,
            operands,
            address,
            length: (end - start) as u8,
            operand_size,
            address_size,
            prefixes,
            is_branch,
            branch_target,
            is_terminator,
            raw_bytes: bytes,
        })
    }

    /// Decode primary opcode into mnemonic + operands.
    fn decode_opcode(
        &mut self,
        opcode: u8,
        operand_size: u8,
        _address_size: u8,
        current_address: u64,
    ) -> (X86Mnemonic, Vec<Operand>, bool, Option<u64>, bool) {
        let mut operands = Vec::new();
        let mut is_branch = false;
        let mut branch_target = None;
        let mut is_terminator = false;

        match opcode {
            // --- MOV r/m8, r8 ---
            0x88 | 0x8A => {
                let modrm = self.next_byte().map(ModRM::new).unwrap_or(ModRM::new(0));
                operands.push(self.decode_modrm_operand(&modrm, operand_size));
                let reg = self.gp_register_name(modrm.reg(), 8);
                operands.push(Operand::Reg(reg));
                if opcode == 0x8A {
                    operands.reverse();
                }
                (X86Mnemonic::MOV, operands, false, None, false)
            }

            // --- MOV r/m, r (full width) ---
            0x89 | 0x8B => {
                let modrm = self.next_byte().map(ModRM::new).unwrap_or(ModRM::new(0));
                operands.push(self.decode_modrm_operand(&modrm, operand_size));
                let reg = self.gp_register_name(modrm.reg(), operand_size as u32);
                operands.push(Operand::Reg(reg));
                if opcode == 0x8B {
                    operands.reverse();
                }
                (X86Mnemonic::MOV, operands, false, None, false)
            }

            // --- MOV r, imm ---
            0xB8..=0xBF => {
                let reg_idx = (opcode - 0xB8) & 0x7;
                let reg = self.gp_register_name(reg_idx, operand_size as u32);
                operands.push(Operand::Reg(reg));
                let imm = self.next_bytes_le(operand_size as usize / 8).unwrap_or(0) as i64;
                operands.push(Operand::Imm(imm));
                (X86Mnemonic::MOV, operands, false, None, false)
            }

            // --- PUSH r ---
            0x50..=0x57 => {
                let reg_idx = opcode - 0x50;
                let reg = self.gp_register_name(reg_idx, operand_size as u32);
                operands.push(Operand::Reg(reg));
                (X86Mnemonic::PUSH, operands, false, None, false)
            }

            // --- POP r ---
            0x58..=0x5F => {
                let reg_idx = opcode - 0x58;
                let reg = self.gp_register_name(reg_idx, operand_size as u32);
                operands.push(Operand::Reg(reg));
                (X86Mnemonic::POP, operands, false, None, false)
            }

            // --- PUSH imm8 ---
            0x6A => {
                let imm = self.next_byte().map(|b| b as i8 as i64).unwrap_or(0);
                operands.push(Operand::Imm(imm));
                (X86Mnemonic::PUSH, operands, false, None, false)
            }

            // --- PUSH imm32 ---
            0x68 => {
                let imm = self.next_bytes_le(4).unwrap_or(0) as i64;
                operands.push(Operand::Imm(imm));
                (X86Mnemonic::PUSH, operands, false, None, false)
            }

            // --- Conditional jumps (70-7F) ---
            0x70..=0x7F => {
                let cc_code = opcode & 0x0F;
                let cc = short_jump_condition(cc_code);
                let offset = self.next_byte().map(|b| b as i8 as i64).unwrap_or(0);
                let target = ((current_address as i64) + 2 + offset) as u64;
                operands.push(Operand::AbsAddr(target));
                is_branch = true;
                branch_target = Some(target);
                (X86Mnemonic::Jcc(cc), operands, true, Some(target), false)
            }

            // --- ADD/ADC/SUB/SBB/AND/OR/XOR/CMP/TEST r/m, r ---
            0x01 | 0x03 | 0x09 | 0x0B | 0x11 | 0x19 | 0x1B | 0x21 | 0x23 | 0x29 | 0x2B | 0x31
            | 0x33 | 0x39 | 0x3B | 0x85 => {
                let modrm = self.next_byte().map(ModRM::new).unwrap_or(ModRM::new(0));
                operands.push(self.decode_modrm_operand(&modrm, operand_size));
                let reg = self.gp_register_name(modrm.reg(), operand_size as u32);
                operands.push(Operand::Reg(reg));
                let mnem = match opcode {
                    0x01 | 0x03 => X86Mnemonic::ADD,
                    0x11 | 0x13 => X86Mnemonic::ADC,
                    0x29 | 0x2B => X86Mnemonic::SUB,
                    0x19 | 0x1B => X86Mnemonic::SBB,
                    0x21 | 0x23 => X86Mnemonic::AND,
                    0x09 | 0x0B => X86Mnemonic::OR,
                    0x31 | 0x33 => X86Mnemonic::XOR,
                    0x39 | 0x3B => X86Mnemonic::CMP,
                    0x85 => X86Mnemonic::TEST,
                    _ => X86Mnemonic::NOP,
                };
                (mnem, operands, false, None, false)
            }

            // --- MOV r/m, imm (0xC7 with reg=0 in ModRM) ---
            0xC7 => {
                let modrm = self.next_byte().map(ModRM::new).unwrap_or(ModRM::new(0));
                operands.push(self.decode_modrm_operand(&modrm, operand_size));
                let imm = self.next_bytes_le(operand_size as usize / 8).unwrap_or(0) as i64;
                operands.push(Operand::Imm(imm));
                (X86Mnemonic::MOV, operands, false, None, false)
            }

            // --- RET near ---
            0xC3 => (X86Mnemonic::RET, vec![], true, None, true),

            // --- RET imm16 ---
            0xC2 => {
                let imm = self.next_bytes_le(2).unwrap_or(0) as i64;
                operands.push(Operand::Imm(imm));
                (X86Mnemonic::RET, operands, true, None, true)
            }

            // --- LEAVE ---
            0xC9 => (X86Mnemonic::LEAVE, vec![], false, None, false),

            // --- INT3 ---
            0xCC => (X86Mnemonic::INT3, vec![], true, None, true),

            // --- INT imm8 ---
            0xCD => {
                let imm = self.next_byte().map(|b| b as i64).unwrap_or(0);
                operands.push(Operand::Imm(imm));
                (X86Mnemonic::INT, operands, true, None, true)
            }

            // --- CALL rel32 ---
            0xE8 => {
                let offset = self.next_bytes_le(4).unwrap_or(0) as i32 as i64;
                let target = ((current_address as i64) + 5 + offset) as u64;
                operands.push(Operand::AbsAddr(target));
                is_branch = true;
                branch_target = Some(target);
                (X86Mnemonic::CALL, operands, true, Some(target), false)
            }

            // --- JMP rel32 ---
            0xE9 => {
                let offset = self.next_bytes_le(4).unwrap_or(0) as i32 as i64;
                let target = ((current_address as i64) + 5 + offset) as u64;
                operands.push(Operand::AbsAddr(target));
                is_branch = true;
                branch_target = Some(target);
                is_terminator = true;
                (X86Mnemonic::JMP, operands, true, Some(target), true)
            }

            // --- JMP rel8 (short) ---
            0xEB => {
                let offset = self.next_byte().map(|b| b as i8 as i64).unwrap_or(0);
                let target = ((current_address as i64) + 2 + offset) as u64;
                operands.push(Operand::AbsAddr(target));
                is_branch = true;
                branch_target = Some(target);
                is_terminator = true;
                (X86Mnemonic::JMP, operands, true, Some(target), true)
            }

            // --- NOP ---
            0x90 => (X86Mnemonic::NOP, vec![], false, None, false),

            // --- HLT ---
            0xF4 => (X86Mnemonic::HLT, vec![], false, None, true),

            // --- INC/DEC r/m ---
            0xFE | 0xFF => {
                let modrm = self.next_byte().map(ModRM::new).unwrap_or(ModRM::new(0));
                operands.push(self.decode_modrm_operand(&modrm, operand_size));
                let mnem = if opcode == 0xFE {
                    match modrm.reg() {
                        0 => X86Mnemonic::INC,
                        1 => X86Mnemonic::DEC,
                        _ => X86Mnemonic::NOP,
                    }
                } else {
                    match modrm.reg() {
                        0 => X86Mnemonic::INC,
                        1 => X86Mnemonic::DEC,
                        2 => {
                            is_branch = true;
                            is_terminator = true;
                            X86Mnemonic::CALL
                        }
                        3 => {
                            is_branch = true;
                            is_terminator = true;
                            X86Mnemonic::CALL // far call
                        }
                        4 => {
                            is_branch = true;
                            is_terminator = true;
                            X86Mnemonic::JMP
                        }
                        5 => {
                            is_branch = true;
                            is_terminator = true;
                            X86Mnemonic::JMP // far jmp
                        }
                        6 => X86Mnemonic::PUSH,
                        _ => X86Mnemonic::NOP,
                    }
                };
                (mnem, operands, is_branch, branch_target, is_terminator)
            }

            // --- IN / OUT ---
            0xE4 => {
                let port = self.next_byte().unwrap_or(0);
                operands.push(Operand::Imm(port as i64));
                operands.push(Operand::Reg("AL".to_string()));
                (X86Mnemonic::IN, operands, false, None, false)
            }
            0xE6 => {
                let port = self.next_byte().unwrap_or(0);
                operands.push(Operand::Imm(port as i64));
                operands.push(Operand::Reg("AL".to_string()));
                (X86Mnemonic::OUT, operands, false, None, false)
            }

            // --- LEA ---
            0x8D => {
                let modrm = self.next_byte().map(ModRM::new).unwrap_or(ModRM::new(0));
                let reg = self.gp_register_name(modrm.reg(), operand_size as u32);
                operands.push(Operand::Reg(reg));
                operands.push(self.decode_modrm_operand(&modrm, operand_size));
                (X86Mnemonic::LEA, operands, false, None, false)
            }

            // XOR r/m, imm8
            0x83 => {
                let modrm = self.next_byte().map(ModRM::new).unwrap_or(ModRM::new(0));
                operands.push(self.decode_modrm_operand(&modrm, operand_size));
                let imm = self.next_byte().map(|b| b as i8 as i64).unwrap_or(0);
                operands.push(Operand::Imm(imm));
                let mnem = match modrm.reg() {
                    0 => X86Mnemonic::ADD,
                    1 => X86Mnemonic::OR,
                    2 => X86Mnemonic::ADC,
                    3 => X86Mnemonic::SBB,
                    4 => X86Mnemonic::AND,
                    5 => X86Mnemonic::SUB,
                    6 => X86Mnemonic::XOR,
                    7 => X86Mnemonic::CMP,
                    _ => X86Mnemonic::NOP,
                };
                (mnem, operands, false, None, false)
            }

            // XOR r/m, imm (32/16)
            0x81 => {
                let modrm = self.next_byte().map(ModRM::new).unwrap_or(ModRM::new(0));
                operands.push(self.decode_modrm_operand(&modrm, operand_size));
                let imm = self.next_bytes_le(operand_size as usize / 8).unwrap_or(0) as i64;
                operands.push(Operand::Imm(imm));
                let mnem = match modrm.reg() {
                    0 => X86Mnemonic::ADD,
                    1 => X86Mnemonic::OR,
                    2 => X86Mnemonic::ADC,
                    3 => X86Mnemonic::SBB,
                    4 => X86Mnemonic::AND,
                    5 => X86Mnemonic::SUB,
                    6 => X86Mnemonic::XOR,
                    7 => X86Mnemonic::CMP,
                    _ => X86Mnemonic::NOP,
                };
                (mnem, operands, false, None, false)
            }

            // --- SHL/SHR/SAL/SAR/ROL/ROR/RCL/RCR r/m, imm8 ---
            0xC0 | 0xC1 | 0xD0 | 0xD1 | 0xD2 | 0xD3 => {
                let modrm = self.next_byte().map(ModRM::new).unwrap_or(ModRM::new(0));
                operands.push(self.decode_modrm_operand(&modrm, operand_size));
                let shift_mnem = match modrm.reg() {
                    0 => X86Mnemonic::ROL,
                    1 => X86Mnemonic::ROR,
                    2 => X86Mnemonic::RCL,
                    3 => X86Mnemonic::RCR,
                    4 | 6 => X86Mnemonic::SHL, // SHL and SAL are the same op
                    5 => X86Mnemonic::SHR,
                    7 => X86Mnemonic::SAR,
                    _ => X86Mnemonic::NOP,
                };
                // imm8 or CL
                if matches!(opcode, 0xC0 | 0xC1) {
                    let imm = self.next_byte().unwrap_or(1);
                    operands.push(Operand::Imm(imm as i64));
                } else {
                    operands.push(Operand::Reg("CL".to_string()));
                }
                (shift_mnem, operands, false, None, false)
            }

            // --- TEST r/m, r ---
            0x84 | 0x85 => {
                let modrm = self.next_byte().map(ModRM::new).unwrap_or(ModRM::new(0));
                operands.push(self.decode_modrm_operand(&modrm, operand_size));
                let reg = self.gp_register_name(modrm.reg(), operand_size as u32);
                operands.push(Operand::Reg(reg));
                (X86Mnemonic::TEST, operands, false, None, false)
            }

            // --- XCHG r, AX/EAX/RAX ---
            0x90..=0x97 if opcode != 0x90 => {
                let reg_idx = opcode - 0x90;
                let acc = self.gp_register_name(0, operand_size as u32);
                let other = self.gp_register_name(reg_idx, operand_size as u32);
                operands.push(Operand::Reg(acc));
                operands.push(Operand::Reg(other));
                (X86Mnemonic::XCHG, operands, false, None, false)
            }

            // --- MOVSX / MOVZX (0F BE / 0F B6) ---
            // Handled via 0x0F two-byte opcode path (see default below)
            // --- CMOVcc (0F 4x) ---
            // --- SETcc (0F 9x) ---
            // --- Conditional jumps near (0F 8x) ---

            // --- SYSCALL (0F 05) ---
            // --- CPUID (0F A2) ---
            // --- RDTSC (0F 31) ---
            // --- IMUL (0F AF) ---

            // --- Default: unrecognised opcode ---
            _ => {
                // Try to consume a ModR/M byte if the instruction likely has one.
                // This is a heuristic: most x86 instructions use ModR/M unless they
                // are fixed-register forms (like PUSH r, INC/DEC r, B8+ MOV).
                // We attempt to stay aligned by peeking ModR/M for opcodes >= 0x40.
                if opcode >= 0x40 {
                    // Just advance past an estimated 2 bytes (ModR/M + optional SIB + displacement)
                    // so the decoder can keep making progress.
                    let consumed = self.consume_modrm(opcode);
                    self.skip(consumed as usize);
                }
                (X86Mnemonic::NOP, vec![], false, None, false)
            }
        }
    }

    /// Consume ModR/M and following SIB + displacement bytes; return total extra bytes consumed.
    fn consume_modrm(&mut self, opcode: u8) -> u32 {
        let modrm_byte = match self.next_byte() {
            Some(b) => b,
            None => return 0,
        };
        let modrm = ModRM::new(modrm_byte);

        let mut consumed: u32 = 1;

        // SIB if needed
        if modrm.has_sib() {
            let _sib_byte = self.next_byte();
            consumed += 1;
        }

        // Displacement
        let disp_size = match modrm.mod_bits() {
            0b01 => 1,
            0b10 => 2, // or 4 in 32/64-bit mode
            _ => 0,
        };
        for _ in 0..disp_size {
            self.next_byte();
            consumed += 1;
        }

        // Immediate for opcodes 0x80-0x83
        if matches!(opcode, 0x80 | 0x81 | 0x82 | 0x83) {
            let imm_size = if opcode == 0x80 || opcode == 0x82 || opcode == 0x83 {
                1
            } else {
                2
            };
            for _ in 0..imm_size {
                self.next_byte();
                consumed += 1;
            }
        }

        consumed
    }

    /// Get a general-purpose register name by index and size.
    fn gp_register_name(&self, idx: u8, size: u32) -> String {
        let base = match size {
            8 => [
                "AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH", "R8B", "R9B", "R10B", "R11B",
                "R12B", "R13B", "R14B", "R15B",
            ],
            16 => [
                "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8W", "R9W", "R10W", "R11W",
                "R12W", "R13W", "R14W", "R15W",
            ],
            32 => [
                "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "R8D", "R9D", "R10D",
                "R11D", "R12D", "R13D", "R14D", "R15D",
            ],
            _ => [
                "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11",
                "R12", "R13", "R14", "R15",
            ],
        };
        base.get(idx as usize)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("R{}", idx))
    }

    /// Decode a ModR/M operand into an Operand.
    fn decode_modrm_operand(&mut self, modrm: &ModRM, operand_size: u8) -> Operand {
        if modrm.is_register() {
            return Operand::Reg(self.gp_register_name(modrm.rm(), operand_size as u32));
        }

        // Memory operand
        let mut mem_op = crate::x86::instructions::MemoryOperand {
            segment: None,
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            size: operand_size,
        };

        let mod_bits = modrm.mod_bits();
        let rm = modrm.rm();

        // Compute displacement
        let disp: i64 = match (mod_bits, rm) {
            (0b00, 0b101) => {
                // RIP-relative (64-bit) or direct address (32-bit)
                if self.is_64bit {
                    self.next_bytes_le(4).unwrap_or(0) as i32 as i64
                } else {
                    self.next_bytes_le(4).unwrap_or(0) as i64
                }
            }
            (0b01, _) => self.next_byte().map(|b| b as i8 as i64).unwrap_or(0),
            (0b10, _) => self.next_bytes_le(4).unwrap_or(0) as i32 as i64,
            _ => 0,
        };
        mem_op.displacement = disp;

        if modrm.has_sib() {
            let sib_byte = self.next_byte().unwrap_or(0);
            let sib = SIB::new(sib_byte);
            mem_op.scale = sib.scale_multiplier();

            if !sib.no_index() {
                mem_op.index = Some(self.gp_register_name(sib.index(), operand_size as u32));
            }

            if mod_bits == 0b00 && sib.base() == 0b101 {
                // [index*scale + disp32]
                mem_op.base = None;
            } else {
                mem_op.base = Some(self.gp_register_name(sib.base(), operand_size as u32));
            }
        } else {
            // 16-bit or 32-bit direct addressing (no SIB)
            match (mod_bits, rm) {
                (0b00, 0b101) => {
                    // Direct address (no base register)
                    mem_op.base = None;
                }
                _ => {
                    mem_op.base = Some(self.gp_register_name(rm, operand_size as u32));
                }
            }
        }

        Operand::Mem(Box::new(mem_op))
    }
}

// ========================================================================
// Instruction Stream Decoder
// ========================================================================

/// Decode all instructions in a byte range, returning a vector of decoded
/// instructions. Stops at the first unrecognised or terminating instruction.
pub fn decode_instructions(
    data: &[u8],
    base_address: u64,
    is_64bit: bool,
    max_instructions: usize,
) -> Vec<DecodedInstruction> {
    let mut decoder = X86InstructionDecoder::new(data, base_address, is_64bit);
    let mut result = Vec::with_capacity(max_instructions.min(data.len()));
    while decoder.has_more() && result.len() < max_instructions {
        if let Some(inst) = decoder.decode_next() {
            let is_terminator = inst.is_terminator;
            result.push(inst);
            if is_terminator {
                break;
            }
        } else {
            // Advance by one byte and retry (resync)
            decoder.set_position(decoder.position() + 1);
        }
    }
    result
}

// ========================================================================
// Binary Image Loader
// ========================================================================

/// A loaded x86 binary image ready for disassembly and analysis.
#[derive(Debug, Clone)]
pub struct X86BinaryImage {
    /// The raw bytes of the image.
    pub data: Vec<u8>,
    /// Binary format detected.
    pub format: BinaryFormat,
    /// Base address where the image is loaded.
    pub base_address: u64,
    /// Entry point address.
    pub entry_point: u64,
    /// Sections in the binary.
    pub sections: Vec<Section>,
    /// Import symbols.
    pub imports: Vec<ImportSymbol>,
    /// Export symbols.
    pub exports: Vec<ExportSymbol>,
    /// Whether this is a 64-bit binary.
    pub is_64bit: bool,
    /// Calling convention used (best guess).
    pub calling_convention: CallingConvention,
    /// Register bank for this image.
    pub registers: X86RegisterBank,
}

/// A section in the loaded binary.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub characteristics: u32, // section flags
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
}

/// An imported function or data symbol.
#[derive(Debug, Clone)]
pub struct ImportSymbol {
    pub name: String,
    pub module_name: Option<String>,
    pub address: u64, // IAT address or import stub address
    pub is_function: bool,
    pub ordinal: Option<u32>,
}

/// An exported function or data symbol.
#[derive(Debug, Clone)]
pub struct ExportSymbol {
    pub name: String,
    pub address: u64,
    pub ordinal: u32,
    pub is_function: bool,
}

impl X86BinaryImage {
    /// Load a binary from raw bytes. Detects format and populates basic metadata.
    pub fn load(data: Vec<u8>, base_address: u64) -> Self {
        let format = BinaryFormat::detect(&data);
        let is_64bit = format.is_64bit();
        let registers = if is_64bit {
            X86RegisterBank::new_x86_64()
        } else {
            X86RegisterBank::new_x86_64() // 32-bit uses the same bank
        };
        let calling_convention = CallingConvention::detect(format, None, None);

        X86BinaryImage {
            data,
            format,
            base_address,
            entry_point: base_address, // will be updated by format-specific parsers
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            is_64bit,
            calling_convention,
            registers,
        }
    }

    /// Scan for function boundaries using prologue/epilogue detection.
    pub fn scan_function_boundaries(&self) -> Vec<FunctionBoundary> {
        let mut boundaries = Vec::new();
        let data = &self.data;

        // Scan executable sections only
        for section in &self.sections {
            if !section.is_executable {
                continue;
            }
            let start = section.raw_offset as usize;
            let end = (section.raw_offset + section.raw_size).min(data.len() as u64) as usize;
            let section_data = &data[start..end];
            let section_addr = section.virtual_address;

            let mut offset = 0usize;
            while offset < section_data.len() {
                let addr = section_addr + offset as u64;
                if let Some(boundary) =
                    detect_prologue(&section_data[offset..], addr, self.is_64bit)
                {
                    boundaries.push(boundary);
                }
                if let Some(boundary) = detect_epilogue(&section_data[offset..], addr) {
                    boundaries.push(boundary);
                }
                offset += 1; // scan every byte (basic linear sweep)
            }
        }

        boundaries
    }

    /// Decode the instruction at a given virtual address.
    pub fn decode_at(&self, address: u64) -> Option<DecodedInstruction> {
        if let Some(offset) = self.va_to_offset(address) {
            let slice = &self.data[offset..];
            let mut decoder = X86InstructionDecoder::new(slice, address, self.is_64bit);
            decoder.decode_next()
        } else {
            None
        }
    }

    /// Convert a virtual address to a file offset.
    pub fn va_to_offset(&self, va: u64) -> Option<usize> {
        // Check sections first
        for section in &self.sections {
            if va >= section.virtual_address && va < section.virtual_address + section.virtual_size
            {
                let offset = (va - section.virtual_address + section.raw_offset) as usize;
                if offset < self.data.len() {
                    return Some(offset);
                }
            }
        }
        // Fallback: raw offset within data bounds
        if (va as usize) < self.data.len() {
            Some(va as usize)
        } else {
            None
        }
    }

    /// Total size of the image in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

// ========================================================================
// Helpers
// ========================================================================

/// Map a 4-bit condition code from short jump opcodes (70-7F) to ConditionCode.
fn short_jump_condition(code: u8) -> ConditionCode {
    match code {
        0x0 => ConditionCode::O,
        0x1 => ConditionCode::NO,
        0x2 => ConditionCode::C,
        0x3 => ConditionCode::NC,
        0x4 => ConditionCode::Z,
        0x5 => ConditionCode::NZ,
        0x6 => ConditionCode::BE,
        0x7 => ConditionCode::A,
        0x8 => ConditionCode::S,
        0x9 => ConditionCode::NS,
        0xA => ConditionCode::PE,
        0xB => ConditionCode::PO,
        0xC => ConditionCode::L,
        0xD => ConditionCode::GE,
        0xE => ConditionCode::LE,
        0xF => ConditionCode::G,
        _ => ConditionCode::O,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection_pe32() {
        // Minimal MZ + PE header
        let mut data = vec![0u8; 0x100];
        data[0] = 0x4D; // M
        data[1] = 0x5A; // Z
        data[0x3C] = 0x80; // PE header at offset 0x80
        data[0x80] = 0x50; // P
        data[0x81] = 0x45; // E
        data[0x84] = 0x4C; // Machine = 0x014C (i386)
        data[0x85] = 0x01;
        assert_eq!(BinaryFormat::detect(&data), BinaryFormat::PE32);
    }

    #[test]
    fn test_format_detection_elf64() {
        let data = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        assert_eq!(BinaryFormat::detect(&data), BinaryFormat::ELF64);
    }

    #[test]
    fn test_format_detection_raw() {
        let data = vec![0x31, 0xC0, 0x40, 0xCD, 0x10]; // random x86 code
        assert_eq!(BinaryFormat::detect(&data), BinaryFormat::Raw);
    }

    #[test]
    fn test_detect_standard_prologue() {
        // push rbp; mov rbp, rsp  =>  0x55 0x48 0x89 0xE5
        let data = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20];
        let result = detect_prologue(&data, 0x401000, true);
        assert!(result.is_some());
        let f = result.unwrap();
        assert_eq!(f.pattern, "push rbp; mov rbp, rsp");
    }

    #[test]
    fn test_detect_ret_epilogue() {
        let data = [0xC3, 0x90, 0x90];
        let result = detect_epilogue(&data, 0x401050);
        assert!(result.is_some());
        let f = result.unwrap();
        assert_eq!(f.pattern, "ret");
    }

    #[test]
    fn test_detect_cet_landing_pad() {
        let data = [0xF3, 0x0F, 0x1E, 0xFA]; // endbr64
        let result = detect_prologue(&data, 0x401000, true);
        assert!(result.is_some());
        assert_eq!(result.unwrap().pattern, "endbr64");
    }

    #[test]
    fn test_calling_convention_detect() {
        let cc = CallingConvention::detect(BinaryFormat::PE32Plus, None, None);
        assert_eq!(cc, CallingConvention::Windows64);

        let cc = CallingConvention::detect(BinaryFormat::ELF64, None, None);
        assert_eq!(cc, CallingConvention::SystemV64);

        let cc = CallingConvention::detect(BinaryFormat::PE32, Some("_MyFunc@16"), None);
        assert_eq!(cc, CallingConvention::Stdcall);
    }

    #[test]
    fn test_decode_push_ret() {
        // push rbp; mov rbp,rsp; pop rbp; ret
        let data = [0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3];
        let mut decoder = X86InstructionDecoder::new(&data, 0x401000, true);

        let inst1 = decoder.decode_next().unwrap();
        assert_eq!(inst1.mnemonic, X86Mnemonic::PUSH);

        let inst2 = decoder.decode_next().unwrap();
        assert_eq!(inst2.mnemonic, X86Mnemonic::MOV);

        let inst3 = decoder.decode_next().unwrap();
        assert_eq!(inst3.mnemonic, X86Mnemonic::POP);

        let inst4 = decoder.decode_next().unwrap();
        assert_eq!(inst4.mnemonic, X86Mnemonic::RET);
        assert!(inst4.is_terminator);
    }

    #[test]
    fn test_decode_nop_int3() {
        let data = [0x90, 0xCC];
        let mut decoder = X86InstructionDecoder::new(&data, 0x401000, true);

        let inst1 = decoder.decode_next().unwrap();
        assert_eq!(inst1.mnemonic, X86Mnemonic::NOP);

        let inst2 = decoder.decode_next().unwrap();
        assert_eq!(inst2.mnemonic, X86Mnemonic::INT3);
    }
}
