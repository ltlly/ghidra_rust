//! Language descriptor for processor languages.
//!
//! This module re-exports the [`Language`] struct and related types from
//! the parent `lang` module, providing a dedicated access path for
//! language functionality.
//!
//! # Correspondence to Ghidra
//!
//! This is a direct translation of `ghidra.program.model.lang.Language`
//! (interface). A [`Language`] bundles the language identity with version
//! metadata, the register manager, available compiler specifications,
//! an address factory, and segment register mappings.

// Re-export from the parent lang module.
pub use super::lang::{
    BasicLanguageDescription, Language, LanguageCompilerSpecPair, LanguageCompilerSpecQuery,
    LanguageDescription, LanguageNotFoundException, LanguageService,
};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::lang::LanguageID;
    use crate::addr::AddressFactory;

    #[test]
    fn test_language_new() {
        let id = LanguageID::x86_64();
        let af = AddressFactory::default();
        let lang = Language::new(
            id.clone(),
            "x86/little/64",
            "1.0",
            0,
            "x86 64-bit little-endian",
            af,
        );
        assert_eq!(lang.id, id);
        assert_eq!(lang.name, "x86/little/64");
    }

    #[test]
    fn test_language_id_accessors() {
        let id = LanguageID::x86_64();
        let af = AddressFactory::default();
        let lang = Language::new(id, "test", "1.0", 0, "test description", af);
        assert_eq!(lang.get_language_id().to_string(), "x86:LE:64:default");
        assert_eq!(lang.name, "test");
    }

    #[test]
    fn test_language_display() {
        let id = LanguageID::x86_64();
        let af = AddressFactory::default();
        let lang = Language::new(id, "test", "1.0", 0, "test description", af);
        assert_eq!(format!("{}", lang), "test v1.0 (x86:LE:64:default)");
    }
}
