//! ELF program header type registry ported from Ghidra's `ElfProgramHeaderType.java`.
//!
//! Provides:
//! - [`ElfProgramHeaderType`] -- a named program header type with its numeric value
//!   and description
//! - Default program header type instances (PT_NULL through PT_TLS)
//! - GNU-specific program header types
//! - Sun-specific program header types
//! - A registry for looking up program header types by value
//! - Helper functions for type classification

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

use super::elf_program_header_constants;

// ---------------------------------------------------------------------------
// ElfProgramHeaderType
// ---------------------------------------------------------------------------

/// A named ELF program header type.
///
/// Each instance pairs a numeric `value` (the `p_type` constant), a `name`
/// (e.g. `"PT_LOAD"`), and a human-readable `description`.
#[derive(Debug, Clone)]
pub struct ElfProgramHeaderType {
    /// The numeric program header type value (e.g. `1` for PT_LOAD).
    pub value: u32,
    /// The symbolic name (e.g. `"PT_LOAD"`).
    pub name: &'static str,
    /// A human-readable description.
    pub description: &'static str,
}

impl ElfProgramHeaderType {
    /// Create a new program header type entry.
    pub const fn new(value: u32, name: &'static str, description: &'static str) -> Self {
        Self {
            value,
            name,
            description,
        }
    }
}

impl fmt::Display for ElfProgramHeaderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(0x{:08x})", self.name, self.value)
    }
}

// ---------------------------------------------------------------------------
// Standard Program Header Types (PT_*)
// ---------------------------------------------------------------------------

/// Unused/Undefined segment.
pub const PT_NULL_TYPE: ElfProgramHeaderType = ElfProgramHeaderType::new(
    elf_program_header_constants::PT_NULL,
    "PT_NULL",
    "Unused/Undefined segment",
);
/// Loadable segment.
pub const PT_LOAD_TYPE: ElfProgramHeaderType = ElfProgramHeaderType::new(
    elf_program_header_constants::PT_LOAD,
    "PT_LOAD",
    "Loadable segment",
);
/// Dynamic linking information.
pub const PT_DYNAMIC_TYPE: ElfProgramHeaderType = ElfProgramHeaderType::new(
    elf_program_header_constants::PT_DYNAMIC,
    "PT_DYNAMIC",
    "Dynamic linking information",
);
/// Interpreter path name.
pub const PT_INTERP_TYPE: ElfProgramHeaderType = ElfProgramHeaderType::new(
    elf_program_header_constants::PT_INTERP,
    "PT_INTERP",
    "Interpreter path name",
);
/// Auxiliary information location.
pub const PT_NOTE_TYPE: ElfProgramHeaderType = ElfProgramHeaderType::new(
    elf_program_header_constants::PT_NOTE,
    "PT_NOTE",
    "Auxiliary information location",
);
/// Unused.
pub const PT_SHLIB_TYPE: ElfProgramHeaderType = ElfProgramHeaderType::new(
    elf_program_header_constants::PT_SHLIB,
    "PT_SHLIB",
    "",
);
/// Program header table.
pub const PT_PHDR_TYPE: ElfProgramHeaderType = ElfProgramHeaderType::new(
    elf_program_header_constants::PT_PHDR,
    "PT_PHDR",
    "Program header table",
);
/// Thread-local storage template.
pub const PT_TLS_TYPE: ElfProgramHeaderType = ElfProgramHeaderType::new(
    elf_program_header_constants::PT_TLS,
    "PT_TLS",
    "Thread-Local Storage template",
);

// ---------------------------------------------------------------------------
// GNU-Specific Program Header Types
// ---------------------------------------------------------------------------

/// GCC `.eh_frame_hdr` segment.
pub const PT_GNU_EH_FRAME_TYPE: ElfProgramHeaderType = ElfProgramHeaderType::new(
    elf_program_header_constants::PT_GNU_EH_FRAME,
    "PT_GNU_EH_FRAME",
    "GCC .eh_frame_hdr segment",
);
/// Indicates stack executability.
pub const PT_GNU_STACK_TYPE: ElfProgramHeaderType = ElfProgramHeaderType::new(
    elf_program_header_constants::PT_GNU_STACK,
    "PT_GNU_STACK",
    "Indicates stack executability",
);
/// Specifies segments which may be read-only after relocation.
pub const PT_GNU_RELRO_TYPE: ElfProgramHeaderType = ElfProgramHeaderType::new(
    elf_program_header_constants::PT_GNU_RELRO,
    "PT_GNU_RELRO",
    "Specifies segments which may be read-only post-relocation",
);

// ---------------------------------------------------------------------------
// Sun-Specific Program Header Types
// ---------------------------------------------------------------------------

/// Sun-specific `.SUNW_bss` segment.
pub const PT_SUNWBSS_TYPE: ElfProgramHeaderType = ElfProgramHeaderType::new(
    elf_program_header_constants::PT_SUNWBSS,
    "PT_SUNWBSS",
    "Sun Specific segment",
);
/// Sun-specific stack segment.
pub const PT_SUNWSTACK_TYPE: ElfProgramHeaderType = ElfProgramHeaderType::new(
    elf_program_header_constants::PT_SUNWSTACK,
    "PT_SUNWSTACK",
    "Stack segment",
);

// ---------------------------------------------------------------------------
// Registry / Lookup
// ---------------------------------------------------------------------------

/// Build the default program header type registry (all standard PT_* types).
fn build_default_program_header_types() -> HashMap<u32, &'static ElfProgramHeaderType> {
    let mut map = HashMap::new();
    let types: &[&ElfProgramHeaderType] = &[
        // Standard types
        &PT_NULL_TYPE,
        &PT_LOAD_TYPE,
        &PT_DYNAMIC_TYPE,
        &PT_INTERP_TYPE,
        &PT_NOTE_TYPE,
        &PT_SHLIB_TYPE,
        &PT_PHDR_TYPE,
        &PT_TLS_TYPE,
        // GNU-specific
        &PT_GNU_EH_FRAME_TYPE,
        &PT_GNU_STACK_TYPE,
        &PT_GNU_RELRO_TYPE,
        // Sun-specific
        &PT_SUNWBSS_TYPE,
        &PT_SUNWSTACK_TYPE,
    ];
    for t in types {
        map.insert(t.value, *t);
    }
    map
}

/// Look up a program header type by its numeric value.
///
/// Returns a reference to the [`ElfProgramHeaderType`] if the value is a known
/// program header type, or `None` for unknown/processor-specific types
/// not in the default registry.
pub fn lookup_program_header_type(value: u32) -> Option<&'static ElfProgramHeaderType> {
    static REGISTRY: OnceLock<HashMap<u32, &'static ElfProgramHeaderType>> = OnceLock::new();
    let map = REGISTRY.get_or_init(build_default_program_header_types);
    map.get(&value).copied()
}

/// Returns a human-readable name for the given program header type value.
///
/// For known types returns the PT_* name; for unknown values returns `"PT_UNKNOWN"`.
pub fn program_header_type_name(value: u32) -> &'static str {
    lookup_program_header_type(value)
        .map(|t| t.name)
        .unwrap_or("PT_UNKNOWN")
}

/// Returns `true` if the given program header type represents a loadable segment.
pub fn is_loadable_type(p_type: u32) -> bool {
    p_type == elf_program_header_constants::PT_LOAD
}

/// Returns `true` if the given program header type represents a dynamic segment.
pub fn is_dynamic_type(p_type: u32) -> bool {
    p_type == elf_program_header_constants::PT_DYNAMIC
}

/// Returns `true` if the given program header type represents an interpreter segment.
pub fn is_interp_type(p_type: u32) -> bool {
    p_type == elf_program_header_constants::PT_INTERP
}

/// Returns `true` if the given program header type represents a note segment.
pub fn is_note_type(p_type: u32) -> bool {
    p_type == elf_program_header_constants::PT_NOTE
}

/// Returns `true` if the given program header type represents a TLS segment.
pub fn is_tls_type(p_type: u32) -> bool {
    p_type == elf_program_header_constants::PT_TLS
}

/// Returns `true` if the given program header type is in the OS-specific range
/// (0x60000000 - 0x6fffffff).
pub fn is_os_specific_type(p_type: u32) -> bool {
    p_type >= 0x60000000 && p_type <= 0x6fffffff
}

/// Returns `true` if the given program header type is in the processor-specific range
/// (0x70000000 - 0x7fffffff).
pub fn is_processor_specific_type(p_type: u32) -> bool {
    p_type >= 0x70000000 && p_type <= 0x7fffffff
}

/// Returns `true` if the given program header type is a GNU-specific type.
pub fn is_gnu_type(p_type: u32) -> bool {
    matches!(
        p_type,
        elf_program_header_constants::PT_GNU_EH_FRAME
            | elf_program_header_constants::PT_GNU_STACK
            | elf_program_header_constants::PT_GNU_RELRO
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_program_header_types() {
        assert_eq!(PT_NULL_TYPE.value, 0);
        assert_eq!(PT_LOAD_TYPE.value, 1);
        assert_eq!(PT_DYNAMIC_TYPE.value, 2);
        assert_eq!(PT_INTERP_TYPE.value, 3);
        assert_eq!(PT_NOTE_TYPE.value, 4);
        assert_eq!(PT_SHLIB_TYPE.value, 5);
        assert_eq!(PT_PHDR_TYPE.value, 6);
        assert_eq!(PT_TLS_TYPE.value, 7);
    }

    #[test]
    fn test_program_header_type_display() {
        let s = format!("{}", PT_LOAD_TYPE);
        assert!(s.contains("PT_LOAD"));
        assert!(s.contains("0x00000001"));
    }

    #[test]
    fn test_lookup_program_header_type() {
        let t = lookup_program_header_type(1);
        assert!(t.is_some());
        assert_eq!(t.unwrap().name, "PT_LOAD");
        assert_eq!(t.unwrap().description, "Loadable segment");
    }

    #[test]
    fn test_lookup_unknown() {
        assert!(lookup_program_header_type(9999).is_none());
    }

    #[test]
    fn test_program_header_type_name_fn() {
        assert_eq!(program_header_type_name(0), "PT_NULL");
        assert_eq!(program_header_type_name(1), "PT_LOAD");
        assert_eq!(program_header_type_name(2), "PT_DYNAMIC");
        assert_eq!(program_header_type_name(0x6474e551), "PT_GNU_STACK");
        assert_eq!(program_header_type_name(9999), "PT_UNKNOWN");
    }

    #[test]
    fn test_is_loadable_type() {
        assert!(is_loadable_type(elf_program_header_constants::PT_LOAD));
        assert!(!is_loadable_type(elf_program_header_constants::PT_DYNAMIC));
        assert!(!is_loadable_type(elf_program_header_constants::PT_NULL));
    }

    #[test]
    fn test_is_dynamic_type() {
        assert!(is_dynamic_type(elf_program_header_constants::PT_DYNAMIC));
        assert!(!is_dynamic_type(elf_program_header_constants::PT_LOAD));
    }

    #[test]
    fn test_is_interp_type() {
        assert!(is_interp_type(elf_program_header_constants::PT_INTERP));
        assert!(!is_interp_type(elf_program_header_constants::PT_LOAD));
    }

    #[test]
    fn test_is_note_type() {
        assert!(is_note_type(elf_program_header_constants::PT_NOTE));
        assert!(!is_note_type(elf_program_header_constants::PT_LOAD));
    }

    #[test]
    fn test_is_tls_type() {
        assert!(is_tls_type(elf_program_header_constants::PT_TLS));
        assert!(!is_tls_type(elf_program_header_constants::PT_LOAD));
    }

    #[test]
    fn test_is_os_specific_type() {
        assert!(is_os_specific_type(elf_program_header_constants::PT_GNU_EH_FRAME));
        assert!(is_os_specific_type(elf_program_header_constants::PT_GNU_STACK));
        assert!(is_os_specific_type(elf_program_header_constants::PT_SUNWBSS));
        assert!(!is_os_specific_type(elf_program_header_constants::PT_LOAD));
        assert!(!is_os_specific_type(0x70000000));
    }

    #[test]
    fn test_is_processor_specific_type() {
        assert!(is_processor_specific_type(0x70000000));
        assert!(is_processor_specific_type(0x7fffffff));
        assert!(!is_processor_specific_type(elf_program_header_constants::PT_LOAD));
        assert!(!is_processor_specific_type(0x60000000));
    }

    #[test]
    fn test_is_gnu_type() {
        assert!(is_gnu_type(elf_program_header_constants::PT_GNU_EH_FRAME));
        assert!(is_gnu_type(elf_program_header_constants::PT_GNU_STACK));
        assert!(is_gnu_type(elf_program_header_constants::PT_GNU_RELRO));
        assert!(!is_gnu_type(elf_program_header_constants::PT_LOAD));
        assert!(!is_gnu_type(elf_program_header_constants::PT_SUNWBSS));
    }

    #[test]
    fn test_gnu_types() {
        assert_eq!(PT_GNU_EH_FRAME_TYPE.value, 0x6474e550);
        assert_eq!(PT_GNU_STACK_TYPE.value, 0x6474e551);
        assert_eq!(PT_GNU_RELRO_TYPE.value, 0x6474e552);
    }

    #[test]
    fn test_sun_types() {
        assert_eq!(PT_SUNWBSS_TYPE.value, 0x6ffffffa);
        assert_eq!(PT_SUNWSTACK_TYPE.value, 0x6ffffffb);
    }

    #[test]
    fn test_lookup_gnu_types() {
        let t = lookup_program_header_type(0x6474e551);
        assert!(t.is_some());
        assert_eq!(t.unwrap().name, "PT_GNU_STACK");
    }

    #[test]
    fn test_lookup_sun_types() {
        let t = lookup_program_header_type(0x6ffffffa);
        assert!(t.is_some());
        assert_eq!(t.unwrap().name, "PT_SUNWBSS");
    }
}
