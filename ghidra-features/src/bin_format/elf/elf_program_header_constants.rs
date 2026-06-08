//! ELF program header constants ported from Ghidra's `ElfProgramHeaderConstants.java`.
//!
//! Provides constants for:
//! - Segment type values (PT_NULL through PT_TLS)
//! - GNU-specific segment types (PT_GNU_EH_FRAME, PT_GNU_STACK, PT_GNU_RELRO)
//! - Sun-specific segment types
//! - Segment flag bits (PF_X, PF_W, PF_R)

// ---------------------------------------------------------------------------
// Segment Types (p_type values)
// ---------------------------------------------------------------------------

/// Unused/Undefined segment.
pub const PT_NULL: u32 = 0;
/// Loadable segment.
pub const PT_LOAD: u32 = 1;
/// Dynamic linking information (.dynamic section).
pub const PT_DYNAMIC: u32 = 2;
/// Interpreter path name.
pub const PT_INTERP: u32 = 3;
/// Auxiliary information location.
pub const PT_NOTE: u32 = 4;
/// Unused.
pub const PT_SHLIB: u32 = 5;
/// Program header table.
pub const PT_PHDR: u32 = 6;
/// Thread-local storage segment.
pub const PT_TLS: u32 = 7;

// ---------------------------------------------------------------------------
// GNU-Specific Segment Types
// ---------------------------------------------------------------------------

/// GCC `.eh_frame_hdr` segment.
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
/// Indicates stack executability.
pub const PT_GNU_STACK: u32 = 0x6474e551;
/// Specifies segments which may be read-only after relocation.
pub const PT_GNU_RELRO: u32 = 0x6474e552;

// ---------------------------------------------------------------------------
// Sun-Specific Segment Types
// ---------------------------------------------------------------------------

/// Sun-specific `.SUNW_bss` segment.
pub const PT_SUNWBSS: u32 = 0x6ffffffa;
/// Sun-specific stack segment.
pub const PT_SUNWSTACK: u32 = 0x6ffffffb;

// ---------------------------------------------------------------------------
// Segment Flag Bits (p_flags values)
// ---------------------------------------------------------------------------

/// Segment is executable.
pub const PF_X: u32 = 1 << 0;
/// Segment is writable.
pub const PF_W: u32 = 1 << 1;
/// Segment is readable.
pub const PF_R: u32 = 1 << 2;
/// OS-specific.
pub const PF_MASKOS: u32 = 0x0ff00000;
/// Processor-specific.
pub const PF_MASKPROC: u32 = 0xf0000000;

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Returns a human-readable name for the given program header type.
///
/// # Arguments
///
/// * `p_type` - The `p_type` value from the program header.
///
/// # Returns
///
/// A static string slice with the type name (e.g., `"PT_LOAD"`).
pub fn program_header_type_name(p_type: u32) -> &'static str {
    match p_type {
        PT_NULL => "PT_NULL",
        PT_LOAD => "PT_LOAD",
        PT_DYNAMIC => "PT_DYNAMIC",
        PT_INTERP => "PT_INTERP",
        PT_NOTE => "PT_NOTE",
        PT_SHLIB => "PT_SHLIB",
        PT_PHDR => "PT_PHDR",
        PT_TLS => "PT_TLS",
        PT_GNU_EH_FRAME => "PT_GNU_EH_FRAME",
        PT_GNU_STACK => "PT_GNU_STACK",
        PT_GNU_RELRO => "PT_GNU_RELRO",
        PT_SUNWBSS => "PT_SUNWBSS",
        PT_SUNWSTACK => "PT_SUNWSTACK",
        _ => "PT_UNKNOWN",
    }
}

/// Returns a human-readable string describing the segment flags.
///
/// # Arguments
///
/// * `flags` - The `p_flags` value from the program header.
///
/// # Returns
///
/// A string like `"R-X"`, `"RW-"`, `"R--"`, etc. where each position
/// represents read, write, and execute permissions respectively.
pub fn program_header_flags_string(flags: u32) -> String {
    let r = if flags & PF_R != 0 { 'R' } else { '-' };
    let w = if flags & PF_W != 0 { 'W' } else { '-' };
    let x = if flags & PF_X != 0 { 'X' } else { '-' };
    format!("{}{}{}", r, w, x)
}

/// Returns `true` if the given program header type represents a loadable segment.
///
/// # Arguments
///
/// * `p_type` - The `p_type` value from the program header.
pub fn is_loadable_segment(p_type: u32) -> bool {
    p_type == PT_LOAD
}

/// Returns `true` if the given program header type is in the OS-specific range.
///
/// # Arguments
///
/// * `p_type` - The `p_type` value from the program header.
pub fn is_os_specific_segment(p_type: u32) -> bool {
    p_type >= 0x60000000 && p_type <= 0x6fffffff
}

/// Returns `true` if the given program header type is in the processor-specific range.
///
/// # Arguments
///
/// * `p_type` - The `p_type` value from the program header.
pub fn is_processor_specific_segment(p_type: u32) -> bool {
    p_type >= 0x70000000 && p_type <= 0x7fffffff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_type_constants() {
        assert_eq!(PT_NULL, 0);
        assert_eq!(PT_LOAD, 1);
        assert_eq!(PT_DYNAMIC, 2);
        assert_eq!(PT_INTERP, 3);
        assert_eq!(PT_NOTE, 4);
        assert_eq!(PT_SHLIB, 5);
        assert_eq!(PT_PHDR, 6);
        assert_eq!(PT_TLS, 7);
    }

    #[test]
    fn test_gnu_segment_types() {
        assert_eq!(PT_GNU_EH_FRAME, 0x6474e550);
        assert_eq!(PT_GNU_STACK, 0x6474e551);
        assert_eq!(PT_GNU_RELRO, 0x6474e552);
    }

    #[test]
    fn test_sun_segment_types() {
        assert_eq!(PT_SUNWBSS, 0x6ffffffa);
        assert_eq!(PT_SUNWSTACK, 0x6ffffffb);
    }

    #[test]
    fn test_segment_flags() {
        assert_eq!(PF_X, 1);
        assert_eq!(PF_W, 2);
        assert_eq!(PF_R, 4);
        assert_eq!(PF_MASKOS, 0x0ff00000);
        assert_eq!(PF_MASKPROC, 0xf0000000);
    }

    #[test]
    fn test_program_header_type_name() {
        assert_eq!(program_header_type_name(PT_NULL), "PT_NULL");
        assert_eq!(program_header_type_name(PT_LOAD), "PT_LOAD");
        assert_eq!(program_header_type_name(PT_DYNAMIC), "PT_DYNAMIC");
        assert_eq!(program_header_type_name(PT_INTERP), "PT_INTERP");
        assert_eq!(program_header_type_name(PT_GNU_STACK), "PT_GNU_STACK");
        assert_eq!(program_header_type_name(0xFFFFFFFF), "PT_UNKNOWN");
    }

    #[test]
    fn test_program_header_flags_string() {
        assert_eq!(program_header_flags_string(PF_R), "R--");
        assert_eq!(program_header_flags_string(PF_R | PF_W), "RW-");
        assert_eq!(program_header_flags_string(PF_R | PF_X), "R-X");
        assert_eq!(program_header_flags_string(PF_R | PF_W | PF_X), "RWX");
        assert_eq!(program_header_flags_string(0), "---");
    }

    #[test]
    fn test_is_loadable_segment() {
        assert!(is_loadable_segment(PT_LOAD));
        assert!(!is_loadable_segment(PT_DYNAMIC));
        assert!(!is_loadable_segment(PT_NULL));
    }

    #[test]
    fn test_is_os_specific_segment() {
        assert!(is_os_specific_segment(PT_GNU_EH_FRAME));
        assert!(is_os_specific_segment(PT_GNU_STACK));
        assert!(is_os_specific_segment(PT_SUNWBSS));
        assert!(!is_os_specific_segment(PT_LOAD));
        assert!(!is_os_specific_segment(0x70000000));
    }

    #[test]
    fn test_is_processor_specific_segment() {
        assert!(is_processor_specific_segment(0x70000000));
        assert!(is_processor_specific_segment(0x7fffffff));
        assert!(!is_processor_specific_segment(PT_LOAD));
        assert!(!is_processor_specific_segment(0x60000000));
    }
}
