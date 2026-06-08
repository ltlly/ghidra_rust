//! SOM constant values ported from Ghidra's `SomConstants.java`.
//!
//! HP PA-RISC System Object Module (SOM) format constants.
//!
//! Reference: [The 32-bit PA-RISC Run-time Architecture Document](https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf)

/// SOM constant values.
pub struct SomConstants;

impl SomConstants {
    // -----------------------------------------------------------------------
    // System IDs
    // -----------------------------------------------------------------------

    /// PA-RISC 1.0 system.
    pub const SYSTEM_PA_RISC_1_0: u16 = 0x20b;
    /// PA-RISC 1.1 system.
    pub const SYSTEM_PA_RISC_1_1: u16 = 0x210;
    /// PA-RISC 2.0 system.
    pub const SYSTEM_PA_RISC_2_0: u16 = 0x214;

    // -----------------------------------------------------------------------
    // Magic numbers
    // -----------------------------------------------------------------------

    /// Library archive.
    pub const MAGIC_LIBRARY: u16 = 0x104;
    /// Relocatable object.
    pub const MAGIC_RELOCATABLE: u16 = 0x106;
    /// Non-shareable executable.
    pub const MAGIC_NON_SHAREABLE_EXE: u16 = 0x107;
    /// Shareable executable.
    pub const MAGIC_SHAREABLE_EXE: u16 = 0x108;
    /// Sharable demand-loadable executable.
    pub const MAGIC_SHARABLE_DEMAND_LOADABLE_EXE: u16 = 0x10b;
    /// Dynamic load library.
    pub const MAGIC_DYNAMIC_LOAD_LIBRARY: u16 = 0x10d;
    /// Shared library.
    pub const MAGIC_SHARED_LIBRARY: u16 = 0x10e;
    /// Relocatable library.
    pub const MAGIC_RELOCATABLE_LIBRARY: u16 = 0x0619;

    // -----------------------------------------------------------------------
    // Version IDs
    // -----------------------------------------------------------------------

    /// Old version ID (YYMMDDHH = 85082112).
    pub const VERSION_OLD: u32 = 0x85082112;
    /// New version ID (YYMMDDHH = 87102412).
    pub const VERSION_NEW: u32 = 0x87102412;

    // -----------------------------------------------------------------------
    // Auxiliary header types
    // -----------------------------------------------------------------------

    /// Null auxiliary header type.
    pub const TYPE_NULL: u16 = 0;
    /// Linker footprint.
    pub const LINKER_FOOTPRINT: u16 = 1;
    /// MEP/iX program.
    pub const MEP_IX_PROGRAM: u16 = 2;
    /// Debugger footprint.
    pub const DEBUGGER_FOOTPRINT: u16 = 3;
    /// Executable auxiliary header.
    pub const EXEC_AUXILIARY_HEADER: u16 = 4;
    /// IPL auxiliary header.
    pub const IPL_AUXILIARY_HEADER: u16 = 5;
    /// Version string.
    pub const VERSION_STRING: u16 = 6;
    /// MPE/iX program.
    pub const MPE_IX_PROGRAM: u16 = 7;
    /// MPE/iX SOM.
    pub const MPE_IX_SOM: u16 = 8;
    /// Copyright.
    pub const COPYRIGHT: u16 = 9;
    /// Shared library version information.
    pub const SHARED_LIBRARY_VERSION_INFORMATION: u16 = 10;
    /// Product specifics.
    pub const PRODUCT_SPECIFICS: u16 = 11;
    /// NetWare loadable module.
    pub const NETWARE_LOADABLE_MODULE: u16 = 12;

    // -----------------------------------------------------------------------
    // Symbol types
    // -----------------------------------------------------------------------

    /// Null symbol.
    pub const SYMBOL_NULL: u8 = 0;
    /// Absolute symbol.
    pub const SYMBOL_ABSOLUTE: u8 = 1;
    /// Data symbol.
    pub const SYMBOL_DATA: u8 = 2;
    /// Code symbol.
    pub const SYMBOL_CODE: u8 = 3;
    /// Primary program.
    pub const SYMBOL_PRI_PROG: u8 = 4;
    /// Secondary program.
    pub const SYMBOL_SEC_PROG: u8 = 5;
    /// Entry point.
    pub const SYMBOL_ENTRY: u8 = 6;
    /// Storage.
    pub const SYMBOL_STORAGE: u8 = 7;
    /// Stub.
    pub const SYMBOL_STUB: u8 = 8;
    /// Module.
    pub const SYMBOL_MODULE: u8 = 9;
    /// Symbol extension.
    pub const SYMBOL_SYM_EXT: u8 = 10;
    /// Argument extension.
    pub const SYMBOL_ARG_EXT: u8 = 11;
    /// Millicode.
    pub const SYMBOL_MILLICODE: u8 = 12;
    /// Procedure label.
    pub const SYMBOL_PLABEL: u8 = 13;
    /// Octet disassembler.
    pub const SYMBOL_OCT_DIS: u8 = 14;
    /// Millicode extension.
    pub const SYMBOL_MILLI_EXT: u8 = 15;
    /// Thread storage.
    pub const SYMBOL_TSTORAGE: u8 = 16;
    /// COMDAT.
    pub const SYMBOL_COMDAT: u8 = 17;

    // -----------------------------------------------------------------------
    // Symbol scopes
    // -----------------------------------------------------------------------

    /// Unsatisfied scope.
    pub const SYMBOL_SCOPE_UNSAT: u8 = 0;
    /// External scope.
    pub const SYMBOL_SCOPE_EXTERNAL: u8 = 1;
    /// Local scope.
    pub const SYMBOL_SCOPE_LOCAL: u8 = 2;
    /// Universal scope.
    pub const SYMBOL_SCOPE_UNIVERSAL: u8 = 3;

    // -----------------------------------------------------------------------
    // Dynamic relocation types
    // -----------------------------------------------------------------------

    /// External procedure label relocation.
    pub const DR_PLABEL_EXT: u8 = 1;
    /// Internal procedure label relocation.
    pub const DR_PLABEL_INT: u8 = 2;
    /// External data relocation.
    pub const DR_DATA_EXT: u8 = 3;
    /// Internal data relocation.
    pub const DR_DATA_INT: u8 = 4;
    /// Propagate relocation.
    pub const DR_PROPAGATE: u8 = 5;
    /// Invoke relocation.
    pub const DR_INVOKE: u8 = 6;
    /// Internal text relocation.
    pub const DR_TEXT_INT: u8 = 7;
}

/// Returns true if the given magic number is a valid SOM magic.
pub fn is_valid_som_magic(magic: u16) -> bool {
    matches!(
        magic,
        SomConstants::MAGIC_LIBRARY
            | SomConstants::MAGIC_RELOCATABLE
            | SomConstants::MAGIC_NON_SHAREABLE_EXE
            | SomConstants::MAGIC_SHAREABLE_EXE
            | SomConstants::MAGIC_SHARABLE_DEMAND_LOADABLE_EXE
            | SomConstants::MAGIC_DYNAMIC_LOAD_LIBRARY
            | SomConstants::MAGIC_SHARED_LIBRARY
            | SomConstants::MAGIC_RELOCATABLE_LIBRARY
    )
}

/// Returns true if the given version ID is valid.
pub fn is_valid_version_id(version_id: u32) -> bool {
    version_id == SomConstants::VERSION_OLD || version_id == SomConstants::VERSION_NEW
}

/// Returns a human-readable name for a SOM magic value.
pub fn magic_name(magic: u16) -> &'static str {
    match magic {
        SomConstants::MAGIC_LIBRARY => "Library",
        SomConstants::MAGIC_RELOCATABLE => "Relocatable",
        SomConstants::MAGIC_NON_SHAREABLE_EXE => "Non-Shareable Executable",
        SomConstants::MAGIC_SHAREABLE_EXE => "Shareable Executable",
        SomConstants::MAGIC_SHARABLE_DEMAND_LOADABLE_EXE => "Sharable Demand-Loadable Executable",
        SomConstants::MAGIC_DYNAMIC_LOAD_LIBRARY => "Dynamic Load Library",
        SomConstants::MAGIC_SHARED_LIBRARY => "Shared Library",
        SomConstants::MAGIC_RELOCATABLE_LIBRARY => "Relocatable Library",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for a symbol type.
pub fn symbol_type_name(symbol_type: u8) -> &'static str {
    match symbol_type {
        SomConstants::SYMBOL_NULL => "Null",
        SomConstants::SYMBOL_ABSOLUTE => "Absolute",
        SomConstants::SYMBOL_DATA => "Data",
        SomConstants::SYMBOL_CODE => "Code",
        SomConstants::SYMBOL_PRI_PROG => "Primary Program",
        SomConstants::SYMBOL_SEC_PROG => "Secondary Program",
        SomConstants::SYMBOL_ENTRY => "Entry",
        SomConstants::SYMBOL_STORAGE => "Storage",
        SomConstants::SYMBOL_STUB => "Stub",
        SomConstants::SYMBOL_MODULE => "Module",
        SomConstants::SYMBOL_SYM_EXT => "Symbol Extension",
        SomConstants::SYMBOL_ARG_EXT => "Argument Extension",
        SomConstants::SYMBOL_MILLICODE => "Millicode",
        SomConstants::SYMBOL_PLABEL => "Procedure Label",
        SomConstants::SYMBOL_OCT_DIS => "Octet Disassembler",
        SomConstants::SYMBOL_MILLI_EXT => "Millicode Extension",
        SomConstants::SYMBOL_TSTORAGE => "Thread Storage",
        SomConstants::SYMBOL_COMDAT => "COMDAT",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for a symbol scope.
pub fn symbol_scope_name(symbol_scope: u8) -> &'static str {
    match symbol_scope {
        SomConstants::SYMBOL_SCOPE_UNSAT => "Unsatisfied",
        SomConstants::SYMBOL_SCOPE_EXTERNAL => "External",
        SomConstants::SYMBOL_SCOPE_LOCAL => "Local",
        SomConstants::SYMBOL_SCOPE_UNIVERSAL => "Universal",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for a dynamic relocation type.
pub fn dr_type_name(dr_type: u8) -> &'static str {
    match dr_type {
        SomConstants::DR_PLABEL_EXT => "PLABEL_EXT",
        SomConstants::DR_PLABEL_INT => "PLABEL_INT",
        SomConstants::DR_DATA_EXT => "DATA_EXT",
        SomConstants::DR_DATA_INT => "DATA_INT",
        SomConstants::DR_PROPAGATE => "PROPAGATE",
        SomConstants::DR_INVOKE => "INVOKE",
        SomConstants::DR_TEXT_INT => "TEXT_INT",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_magic() {
        assert!(is_valid_som_magic(SomConstants::MAGIC_LIBRARY));
        assert!(is_valid_som_magic(SomConstants::MAGIC_SHARED_LIBRARY));
        assert!(is_valid_som_magic(SomConstants::MAGIC_RELOCATABLE));
        assert!(!is_valid_som_magic(0x0000));
        assert!(!is_valid_som_magic(0xFFFF));
    }

    #[test]
    fn test_valid_version_id() {
        assert!(is_valid_version_id(SomConstants::VERSION_OLD));
        assert!(is_valid_version_id(SomConstants::VERSION_NEW));
        assert!(!is_valid_version_id(0x00000000));
        assert!(!is_valid_version_id(0x12345678));
    }

    #[test]
    fn test_magic_name() {
        assert_eq!(magic_name(SomConstants::MAGIC_LIBRARY), "Library");
        assert_eq!(magic_name(SomConstants::MAGIC_SHARED_LIBRARY), "Shared Library");
        assert_eq!(magic_name(0xFFFF), "Unknown");
    }

    #[test]
    fn test_symbol_type_name() {
        assert_eq!(symbol_type_name(SomConstants::SYMBOL_CODE), "Code");
        assert_eq!(symbol_type_name(SomConstants::SYMBOL_DATA), "Data");
        assert_eq!(symbol_type_name(0xFF), "Unknown");
    }

    #[test]
    fn test_symbol_scope_name() {
        assert_eq!(symbol_scope_name(SomConstants::SYMBOL_SCOPE_LOCAL), "Local");
        assert_eq!(symbol_scope_name(SomConstants::SYMBOL_SCOPE_EXTERNAL), "External");
        assert_eq!(symbol_scope_name(0xFF), "Unknown");
    }

    #[test]
    fn test_dr_type_name() {
        assert_eq!(dr_type_name(SomConstants::DR_PLABEL_EXT), "PLABEL_EXT");
        assert_eq!(dr_type_name(SomConstants::DR_DATA_INT), "DATA_INT");
        assert_eq!(dr_type_name(0xFF), "Unknown");
    }

    #[test]
    fn test_system_ids() {
        assert_eq!(SomConstants::SYSTEM_PA_RISC_1_0, 0x20b);
        assert_eq!(SomConstants::SYSTEM_PA_RISC_1_1, 0x210);
        assert_eq!(SomConstants::SYSTEM_PA_RISC_2_0, 0x214);
    }

    #[test]
    fn test_aux_header_types() {
        assert_eq!(SomConstants::EXEC_AUXILIARY_HEADER, 4);
        assert_eq!(SomConstants::LINKER_FOOTPRINT, 1);
        assert_eq!(SomConstants::PRODUCT_SPECIFICS, 11);
    }
}
