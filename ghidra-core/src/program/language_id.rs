//! Language identifier for Ghidra processor languages.
//!
//! This module re-exports the [`LanguageID`] struct from the parent `lang`
//! module, providing a dedicated access path for language identification
//! functionality.
//!
//! # Correspondence to Ghidra
//!
//! This is a direct translation of `ghidra.program.model.lang.LanguageID`.
//! The Java version wraps a raw string; this Rust version parses it into
//! structured fields for type-safe access while retaining the ability to
//! round-trip through the canonical string form.
//!
//! A `LanguageID` takes the form `processor:endian:size:variant[:qualifier]`,
//! e.g. `"x86:LE:64:default"` or `"ARM:LE:32:v7"`.

// Re-export from the parent lang module.
pub use super::lang::LanguageID;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let id = LanguageID::new("x86", "LE", 64, "default");
        assert_eq!(id.processor, "x86");
        assert_eq!(id.endian, "LE");
        assert_eq!(id.size, 64);
        assert_eq!(id.variant, "default");
        assert!(id.qualifier.is_none());
    }

    #[test]
    fn test_with_qualifier() {
        let id = LanguageID::new("x86", "LE", 64, "default").with_qualifier("windows");
        assert_eq!(id.qualifier, Some("windows".to_string()));
    }

    #[test]
    fn test_parse() {
        let id = LanguageID::parse("x86:LE:64:default").unwrap();
        assert_eq!(id.processor, "x86");
        assert_eq!(id.endian, "LE");
        assert_eq!(id.size, 64);
        assert_eq!(id.variant, "default");
    }

    #[test]
    fn test_parse_with_qualifier() {
        let id = LanguageID::parse("ARM:LE:32:v7:windows").unwrap();
        assert_eq!(id.qualifier, Some("windows".to_string()));
    }

    #[test]
    fn test_parse_invalid() {
        assert!(LanguageID::parse("x86:LE").is_none());
        assert!(LanguageID::parse("x86:LE:notanumber:default").is_none());
    }

    #[test]
    fn test_to_string() {
        let id = LanguageID::new("x86", "LE", 64, "default");
        assert_eq!(id.to_string(), "x86:LE:64:default");
    }

    #[test]
    fn test_to_string_with_qualifier() {
        let id = LanguageID::new("x86", "LE", 64, "default").with_qualifier("gcc");
        assert_eq!(id.to_string(), "x86:LE:64:default:gcc");
    }

    #[test]
    fn test_is_big_endian() {
        let id = LanguageID::new("MIPS", "BE", 32, "default");
        assert!(id.is_big_endian());
        assert!(!id.is_little_endian());
    }

    #[test]
    fn test_is_little_endian() {
        let id = LanguageID::new("x86", "LE", 64, "default");
        assert!(id.is_little_endian());
        assert!(!id.is_big_endian());
    }

    #[test]
    fn test_convenience_constructors() {
        let x64 = LanguageID::x86_64();
        assert_eq!(x64.to_string(), "x86:LE:64:default");

        let x32 = LanguageID::x86_32();
        assert_eq!(x32.to_string(), "x86:LE:32:default");

        let arm = LanguageID::arm_v7();
        assert_eq!(arm.to_string(), "ARM:LE:32:v7");

        let aarch = LanguageID::aarch64();
        assert_eq!(aarch.to_string(), "AARCH64:LE:64:v8");

        let mips = LanguageID::mips32_be();
        assert_eq!(mips.to_string(), "MIPS:BE:32:default");
    }

    #[test]
    fn test_equality() {
        let id1 = LanguageID::new("x86", "LE", 64, "default");
        let id2 = LanguageID::parse("x86:LE:64:default").unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_ordering() {
        let a = LanguageID::new("ARM", "LE", 32, "v7");
        let z = LanguageID::new("x86", "LE", 64, "default");
        assert!(a < z);
    }

    #[test]
    fn test_display() {
        let id = LanguageID::new("x86", "LE", 64, "default");
        assert_eq!(format!("{}", id), "x86:LE:64:default");
    }

    #[test]
    fn test_as_string() {
        let id = LanguageID::new("x86", "LE", 64, "default");
        assert_eq!(id.as_string(), "x86:LE:64:default");
    }
}
