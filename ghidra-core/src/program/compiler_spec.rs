//! Compiler specification definitions.
//!
//! This module re-exports the [`CompilerSpec`] and [`CompilerSpecID`] types
//! from the parent `lang` module, providing a dedicated access path for
//! compiler specification functionality.
//!
//! # Correspondence to Ghidra
//!
//! This is a direct translation of:
//! - `ghidra.program.model.lang.CompilerSpec` — ABI / compiler specification
//! - `ghidra.program.model.lang.CompilerSpecID` — compiler spec identifier
//! - `ghidra.program.model.lang.CompilerSpecDescription` — compiler spec metadata

// Re-export from the parent lang module.
pub use super::lang::{
    BasicCompilerSpecDescription, CompilerSpec, CompilerSpecDescription, CompilerSpecID,
};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::lang::LanguageID;
    use crate::data::DataOrganization;

    #[test]
    fn test_compiler_spec_id_new() {
        let id = CompilerSpecID::new("default");
        assert_eq!(id.as_string(), "default");
    }

    #[test]
    fn test_compiler_spec_id_display() {
        let id = CompilerSpecID::new("gcc");
        assert_eq!(format!("{}", id), "gcc");
    }

    #[test]
    fn test_compiler_spec_id_equality() {
        let id1 = CompilerSpecID::new("default");
        let id2 = CompilerSpecID::new("default");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_compiler_spec_id_inequality() {
        let id1 = CompilerSpecID::new("default");
        let id2 = CompilerSpecID::new("gcc");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_compiler_spec_new() {
        let spec_id = CompilerSpecID::new("default");
        let lang_id = LanguageID::x86_64();
        let data_org = DataOrganization::default_64bit_le();
        let spec = CompilerSpec::new(spec_id, lang_id, "Default", data_org);
        assert_eq!(spec.id.as_string(), "default");
        assert_eq!(spec.name, "Default");
    }

    #[test]
    fn test_basic_compiler_spec_description() {
        let spec_id = CompilerSpecID::new("default");
        let desc = BasicCompilerSpecDescription::new(spec_id, "Default");
        assert_eq!(desc.id.as_string(), "default");
        assert_eq!(desc.name, "Default");
    }
}
