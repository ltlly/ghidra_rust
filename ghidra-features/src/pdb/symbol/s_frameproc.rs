//! S_FRAMEPROC -- Frame procedure information symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ExtraFrameAndProcedureInformationMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// Register name for explicitly encoded base pointer fields.
///
/// The 2-bit fields in `S_FRAMEPROC` flags for `local_base_pointer_register`
/// and `parameter_pointer_register` encode a register index. This enum
/// provides a human-readable name matching the PDB register numbering.
///
/// The mapping follows the x86 register numbering from the CodeView spec:
/// - 0 = None (no explicitly encoded register)
/// - 1 = al / ax / eax
/// - 2 = cl / cx / ecx
/// - 3 = dl / dx / edx
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FramePointerRegister(pub u8);

impl FramePointerRegister {
    /// Return the register name string for x86/x64.
    pub fn name(&self) -> &'static str {
        match self.0 {
            0 => "None",
            1 => "ax",
            2 => "cx",
            3 => "dx",
            _ => "???",
        }
    }
}

impl fmt::Display for FramePointerRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A frame procedure information symbol (`S_FRAMEPROC`).
///
/// This symbol contains detailed information about a function's stack frame
/// layout, exception handling configuration, and compiler optimization flags.
/// It is emitted by the linker/compiler alongside procedure symbols to enable
/// accurate stack unwinding and security analysis.
///
/// # PDB Binary Layout
///
/// ```text
/// total_frame_len     : u32
/// padding_frame_len   : u32
/// offset_of_padding   : u32
/// callee_save_reg_size: u32
/// exception_handler_off: u32
/// exception_handler_sect: u16
/// (padding)           : u16
/// flags               : u32
/// ```
///
/// The `flags` field is a bitfield encoding numerous boolean properties
/// (see [`FrameProcFlags`]).
///
/// This corresponds to `S_FRAMEPROC` (0x1012) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SFrameProc {
    /// Total size in bytes of the procedure's stack frame.
    pub total_frame_length: u32,

    /// Size in bytes of the padding portion of the frame.
    pub padding_frame_length: u32,

    /// Offset within the frame where padding begins.
    pub offset_of_padding: u32,

    /// Number of bytes occupied by callee-saved register spills.
    pub callee_save_registers_byte_count: u32,

    /// Offset of the exception handler entry point (within its section).
    pub exception_handler_offset: u32,

    /// Section index containing the exception handler.
    pub exception_handler_section_id: u16,

    /// Raw flags bitfield.
    pub flags: u32,

    /// Parsed flag values from the `flags` bitfield.
    pub frame_flags: FrameProcFlags,
}

/// Parsed boolean flags from the `S_FRAMEPROC` flags bitfield.
///
/// Each flag is decoded from a specific bit position in the 32-bit `flags`
/// field. The layout follows the Microsoft CodeView specification and
/// Ghidra's Java implementation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FrameProcFlags {
    /// Function uses `alloca()`.
    pub uses_alloca: bool,
    /// Function uses `setjmp()`.
    pub uses_setjmp: bool,
    /// Function uses `longjmp()`.
    pub uses_longjmp: bool,
    /// Function contains inline assembly.
    pub uses_inline_asm: bool,
    /// Function has exception handling states.
    pub has_exception_handling_states: bool,
    /// Function was marked with an inline specification.
    pub was_inline_specified: bool,
    /// Function uses structured exception handling (SEH).
    pub was_structured_exception_handling: bool,
    /// Function is `__declspec(naked)`.
    pub is_declspec_naked: bool,
    /// Function has `/GS` buffer security checks.
    pub has_gs_buffer_security_check: bool,
    /// Function was compiled with `/EHa` (async exception handling).
    pub compiled_with_async_exception_handling: bool,
    /// Stack ordering could not be performed despite `/GS` checks.
    pub could_not_do_stack_ordering_with_gs: bool,
    /// Function was inlined within another function.
    pub was_inlined_within_another_function: bool,
    /// Function is `__declspec(strict_gs_check)`.
    pub is_declspec_strict_gs_check: bool,
    /// Function is `__declspec(safebuffers)`.
    pub is_declspec_safebuffers: bool,
    /// Bits 14-15: explicitly encoded local base pointer register (2 bits).
    pub local_base_pointer_register: FramePointerRegister,
    /// Bits 16-17: explicitly encoded parameter pointer register (2 bits).
    pub parameter_pointer_register: FramePointerRegister,
    /// Function was compiled with PGO/PGU (Profile Guided Optimization).
    pub compiled_with_pgo_pgu: bool,
    /// PGO/PGU counts are valid.
    pub has_valid_pogo_counts: bool,
    /// Function was optimized for speed (vs. size).
    pub optimized_for_speed: bool,
    /// Function contains Control Flow Guard checks but no write checks.
    pub contains_cfg_checks_no_write_checks: bool,
    /// Function contains Control Flow Guard write checks and/or instrumentation.
    pub contains_cfw_checks_or_instrumentation: bool,
    /// Remaining high bits (padding / reserved).
    pub padding: u16,
}

impl FrameProcFlags {
    /// Decode flags from a raw 32-bit value.
    pub fn from_u32(raw: u32) -> Self {
        let mut f = raw;
        let uses_alloca = (f & 0x01) != 0;
        f >>= 1;
        let uses_setjmp = (f & 0x01) != 0;
        f >>= 1;
        let uses_longjmp = (f & 0x01) != 0;
        f >>= 1;
        let uses_inline_asm = (f & 0x01) != 0;
        f >>= 1;
        let has_exception_handling_states = (f & 0x01) != 0;
        f >>= 1;
        let was_inline_specified = (f & 0x01) != 0;
        f >>= 1;
        let was_structured_exception_handling = (f & 0x01) != 0;
        f >>= 1;
        let is_declspec_naked = (f & 0x01) != 0;
        f >>= 1;
        let has_gs_buffer_security_check = (f & 0x01) != 0;
        f >>= 1;
        let compiled_with_async_exception_handling = (f & 0x01) != 0;
        f >>= 1;
        let could_not_do_stack_ordering_with_gs = (f & 0x01) != 0;
        f >>= 1;
        let was_inlined_within_another_function = (f & 0x01) != 0;
        f >>= 1;
        let is_declspec_strict_gs_check = (f & 0x01) != 0;
        f >>= 1;
        let is_declspec_safebuffers = (f & 0x01) != 0;
        f >>= 1;
        let local_base_pointer_register = FramePointerRegister((f & 0x03) as u8);
        f >>= 2;
        let parameter_pointer_register = FramePointerRegister((f & 0x03) as u8);
        f >>= 2;
        let compiled_with_pgo_pgu = (f & 0x01) != 0;
        f >>= 1;
        let has_valid_pogo_counts = (f & 0x01) != 0;
        f >>= 1;
        let optimized_for_speed = (f & 0x01) != 0;
        f >>= 1;
        let contains_cfg_checks_no_write_checks = (f & 0x01) != 0;
        f >>= 1;
        let contains_cfw_checks_or_instrumentation = (f & 0x01) != 0;
        f >>= 1;
        let padding = (f & 0x01FF) as u16;

        Self {
            uses_alloca,
            uses_setjmp,
            uses_longjmp,
            uses_inline_asm,
            has_exception_handling_states,
            was_inline_specified,
            was_structured_exception_handling,
            is_declspec_naked,
            has_gs_buffer_security_check,
            compiled_with_async_exception_handling,
            could_not_do_stack_ordering_with_gs,
            was_inlined_within_another_function,
            is_declspec_strict_gs_check,
            is_declspec_safebuffers,
            local_base_pointer_register,
            parameter_pointer_register,
            compiled_with_pgo_pgu,
            has_valid_pogo_counts,
            optimized_for_speed,
            contains_cfg_checks_no_write_checks,
            contains_cfw_checks_or_instrumentation,
            padding,
        }
    }
}

impl SFrameProc {
    /// Create a new frame procedure symbol.
    pub fn new(
        total_frame_length: u32,
        padding_frame_length: u32,
        offset_of_padding: u32,
        callee_save_registers_byte_count: u32,
        exception_handler_offset: u32,
        exception_handler_section_id: u16,
        flags: u32,
    ) -> Self {
        Self {
            total_frame_length,
            padding_frame_length,
            offset_of_padding,
            callee_save_registers_byte_count,
            exception_handler_offset,
            exception_handler_section_id,
            flags,
            frame_flags: FrameProcFlags::from_u32(flags),
        }
    }

    /// Parse an S_FRAMEPROC symbol from a byte slice.
    ///
    /// Expects the layout:
    /// ```text
    /// total_frame_len(u32) + padding_frame_len(u32) + offset_of_padding(u32)
    /// + callee_save_reg_size(u32) + exception_handler_off(u32)
    /// + exception_handler_sect(u16) + padding(u16) + flags(u32)
    /// ```
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 28 {
            return None;
        }
        let total_frame_length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let padding_frame_length = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let offset_of_padding = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let callee_save_registers_byte_count =
            u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let exception_handler_offset =
            u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let exception_handler_section_id = u16::from_le_bytes([data[20], data[21]]);
        // data[22..24] is padding
        let flags = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        Some(Self {
            total_frame_length,
            padding_frame_length,
            offset_of_padding,
            callee_save_registers_byte_count,
            exception_handler_offset,
            exception_handler_section_id,
            flags,
            frame_flags: FrameProcFlags::from_u32(flags),
        })
    }
}

impl AbstractMsSymbol for SFrameProc {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_FRAMEPROC
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_FRAMEPROC"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "FrameProc:")?;
        writeln!(
            f,
            "   Frame size = {:08X} bytes",
            self.total_frame_length
        )?;
        writeln!(
            f,
            "   Pad size = {:08X} bytes",
            self.padding_frame_length
        )?;
        writeln!(f, "   Offset of pad in frame = {:08X}", self.offset_of_padding)?;
        writeln!(
            f,
            "   Size of callee save registers = {:08X}",
            self.callee_save_registers_byte_count
        )?;
        write!(
            f,
            "   Address of exception handler = {:04X}:{:08X}",
            self.exception_handler_section_id, self.exception_handler_offset
        )?;

        // Emit flag hints
        let ff = &self.frame_flags;
        let mut hints = Vec::new();
        if ff.uses_alloca { hints.push("alloca"); }
        if ff.uses_setjmp { hints.push("setjmp"); }
        if ff.uses_longjmp { hints.push("longjmp"); }
        if ff.uses_inline_asm { hints.push("inlasm"); }
        if ff.has_exception_handling_states { hints.push("eh"); }
        if ff.was_inline_specified { hints.push("inl_specified"); }
        if ff.was_structured_exception_handling { hints.push("seh"); }
        if ff.is_declspec_naked { hints.push("naked"); }
        if ff.has_gs_buffer_security_check { hints.push("gschecks"); }
        if ff.compiled_with_async_exception_handling { hints.push("asynceh"); }
        if ff.could_not_do_stack_ordering_with_gs { hints.push("gsnostackordering"); }
        if ff.was_inlined_within_another_function { hints.push("wasinlined"); }
        if ff.is_declspec_strict_gs_check { hints.push("strict_gs_check"); }
        if ff.is_declspec_safebuffers { hints.push("safebuffers"); }
        if ff.compiled_with_pgo_pgu { hints.push("pgo_on"); }
        if ff.has_valid_pogo_counts { hints.push("valid_pgo_counts"); } else { hints.push("invalid_pgo_counts"); }
        if ff.optimized_for_speed { hints.push("opt_for_speed"); }

        if !hints.is_empty() {
            write!(f, "\n   Function info: {}", hints.join(" "))?;
        }

        write!(
            f,
            " Local={} Param={} {} {} ({:08X})",
            ff.local_base_pointer_register,
            ff.parameter_pointer_register,
            if ff.contains_cfg_checks_no_write_checks { "guardcf" } else { "" },
            if ff.contains_cfw_checks_or_instrumentation { "guardcfw" } else { "" },
            self.flags,
        )
    }
}

impl fmt::Display for SFrameProc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frameproc_bytes(
        total: u32,
        pad: u32,
        pad_off: u32,
        callee: u32,
        eh_off: u32,
        eh_sect: u16,
        flags: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&total.to_le_bytes());
        data.extend_from_slice(&pad.to_le_bytes());
        data.extend_from_slice(&pad_off.to_le_bytes());
        data.extend_from_slice(&callee.to_le_bytes());
        data.extend_from_slice(&eh_off.to_le_bytes());
        data.extend_from_slice(&eh_sect.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // padding
        data.extend_from_slice(&flags.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_frameproc_bytes(0x100, 0x10, 0x80, 0x20, 0x500, 1, 0x0001);
        let sym = SFrameProc::parse(&data).unwrap();
        assert_eq!(sym.total_frame_length, 0x100);
        assert_eq!(sym.padding_frame_length, 0x10);
        assert_eq!(sym.offset_of_padding, 0x80);
        assert_eq!(sym.callee_save_registers_byte_count, 0x20);
        assert_eq!(sym.exception_handler_offset, 0x500);
        assert_eq!(sym.exception_handler_section_id, 1);
        assert_eq!(sym.flags, 0x0001);
        assert!(sym.frame_flags.uses_alloca);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00; 20]; // too short
        assert!(SFrameProc::parse(&data).is_none());
    }

    #[test]
    fn test_flags_alloca() {
        let flags = 0x0001; // bit 0
        let data = make_frameproc_bytes(0, 0, 0, 0, 0, 0, flags);
        let sym = SFrameProc::parse(&data).unwrap();
        assert!(sym.frame_flags.uses_alloca);
        assert!(!sym.frame_flags.uses_setjmp);
    }

    #[test]
    fn test_flags_setjmp() {
        let flags = 0x0002; // bit 1
        let data = make_frameproc_bytes(0, 0, 0, 0, 0, 0, flags);
        let sym = SFrameProc::parse(&data).unwrap();
        assert!(!sym.frame_flags.uses_alloca);
        assert!(sym.frame_flags.uses_setjmp);
    }

    #[test]
    fn test_flags_seh() {
        // SEH is bit 6 (0x0040)
        let flags = 0x0040;
        let data = make_frameproc_bytes(0, 0, 0, 0, 0, 0, flags);
        let sym = SFrameProc::parse(&data).unwrap();
        assert!(sym.frame_flags.was_structured_exception_handling);
    }

    #[test]
    fn test_flags_gs_check() {
        // GS check is bit 8 (0x0100)
        let flags = 0x0100;
        let data = make_frameproc_bytes(0, 0, 0, 0, 0, 0, flags);
        let sym = SFrameProc::parse(&data).unwrap();
        assert!(sym.frame_flags.has_gs_buffer_security_check);
    }

    #[test]
    fn test_flags_register_fields() {
        // local_base_pointer_register is bits 14-15
        // parameter_pointer_register is bits 16-17
        // local=3 (bits 14-15 = 0b11 << 14 = 0x0000C000)
        // param=2 (bits 16-17 = 0b10 << 16 = 0x00020000)
        let flags = 0x0002C000u32;
        let data = make_frameproc_bytes(0, 0, 0, 0, 0, 0, flags);
        let sym = SFrameProc::parse(&data).unwrap();
        assert_eq!(sym.frame_flags.local_base_pointer_register, FramePointerRegister(3));
        assert_eq!(sym.frame_flags.parameter_pointer_register, FramePointerRegister(2));
        assert_eq!(sym.frame_flags.local_base_pointer_register.name(), "dx");
        assert_eq!(sym.frame_flags.parameter_pointer_register.name(), "cx");
    }

    #[test]
    fn test_flags_multiple() {
        // alloca + seh + gschecks = 0x01 | 0x40 | 0x100 = 0x0141
        let flags = 0x0141u32;
        let data = make_frameproc_bytes(0, 0, 0, 0, 0, 0, flags);
        let sym = SFrameProc::parse(&data).unwrap();
        assert!(sym.frame_flags.uses_alloca);
        assert!(sym.frame_flags.was_structured_exception_handling);
        assert!(sym.frame_flags.has_gs_buffer_security_check);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SFrameProc::new(0x200, 0x20, 0x100, 0x40, 0x800, 2, 0x03);
        assert_eq!(sym.pdb_id(), 0x1012);
        assert_eq!(sym.symbol_type_name(), "S_FRAMEPROC");
    }

    #[test]
    fn test_display() {
        let sym = SFrameProc::new(0x100, 0x10, 0x80, 0x20, 0x500, 1, 0x0001);
        let s = format!("{}", sym);
        assert!(s.contains("FrameProc"));
        assert!(s.contains("alloca"));
    }

    #[test]
    fn test_zero_flags() {
        let data = make_frameproc_bytes(0, 0, 0, 0, 0, 0, 0);
        let sym = SFrameProc::parse(&data).unwrap();
        assert!(!sym.frame_flags.uses_alloca);
        assert!(!sym.frame_flags.uses_setjmp);
        assert!(!sym.frame_flags.uses_longjmp);
        assert!(!sym.frame_flags.uses_inline_asm);
        assert!(!sym.frame_flags.has_exception_handling_states);
        assert_eq!(sym.frame_flags.local_base_pointer_register, FramePointerRegister(0));
        assert_eq!(sym.frame_flags.parameter_pointer_register, FramePointerRegister(0));
    }

    #[test]
    fn test_default_frame_flags() {
        let ff = FrameProcFlags::default();
        assert!(!ff.uses_alloca);
        assert!(!ff.optimized_for_speed);
        assert_eq!(ff.local_base_pointer_register, FramePointerRegister(0));
    }

    #[test]
    fn test_register_name_display() {
        assert_eq!(format!("{}", FramePointerRegister(0)), "None");
        assert_eq!(format!("{}", FramePointerRegister(1)), "ax");
        assert_eq!(format!("{}", FramePointerRegister(2)), "cx");
        assert_eq!(format!("{}", FramePointerRegister(3)), "dx");
    }
}
