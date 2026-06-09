//! MIPS Language Provider
//!
//! Provides the [`MipsLanguageProvider`] which implements the [`LanguageProvider`]
//! trait for MIPS processor languages.
//!
//! ## Supported Languages
//!
//! Covers MIPS32 and MIPS64 in big-endian and little-endian configurations,
//! including default, mips16e, microMIPS, and R6 variants, plus 64-bit with
//! 32-bit addressing modes.

use crate::common::{
    CompilerSpecDescription, Endian, Language, LanguageDescription, LanguageID, LanguageProvider,
    Processor,
};

/// Language provider for MIPS processors.
///
/// Migrates the Java `MIPS` processor language definitions into Rust.
pub struct MipsLanguageProvider;

impl MipsLanguageProvider {
    /// The processor name constant.
    pub const PROCESSOR_NAME: &'static str = "MIPS";

    /// Processor family.
    pub const FAMILY: &'static str = "MIPS";

    /// All language IDs supported by this provider.
    pub const LANGUAGE_IDS: [&'static str; 22] = [
        "MIPS:BE:32:default",
        "MIPS:LE:32:default",
        "MIPS:BE:32:16e",
        "MIPS:LE:32:16e",
        "MIPS:BE:32:micro",
        "MIPS:LE:32:micro",
        "MIPS:BE:32:R6",
        "MIPS:LE:32:R6",
        "MIPS:BE:64:default",
        "MIPS:LE:64:default",
        "MIPS:BE:64:16e",
        "MIPS:LE:64:16e",
        "MIPS:BE:64:micro",
        "MIPS:LE:64:micro",
        "MIPS:BE:64:R6",
        "MIPS:LE:64:R6",
        "MIPS:BE:64:64-32addr",
        "MIPS:LE:64:64-32addr",
        "MIPS:BE:64:micro64-32addr",
        "MIPS:LE:64:micro64-32addr",
        "MIPS:BE:64:64-32R6addr",
        "MIPS:LE:64:64-32R6addr",
    ];

    fn build_languages() -> Vec<Language> {
        vec![
            // -- 32-bit default (mips16e mode) --
            Language::new("MIPS:BE:32:default", "MIPS32 32-bit addresses, big endian, with mips16e", "1.9", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("MIPS:LE:32:default", "MIPS32 32-bit addresses, little endian, with mips16e", "1.9", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- 32-bit mips16e --
            Language::new("MIPS:BE:32:16e", "MIPS32 32-bit addresses, big endian, in mips16e mode", "1.9", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("MIPS:LE:32:16e", "MIPS32 32-bit addresses, little endian, in mips16e mode", "1.9", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- 32-bit microMIPS --
            Language::new("MIPS:BE:32:micro", "MIPS32 32-bit addresses, big endian, with microMIPS", "1.9", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("MIPS:LE:32:micro", "MIPS32 32-bit addresses, little endian, with microMIPS", "1.9", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- 32-bit R6 --
            Language::new("MIPS:BE:32:R6", "MIPS32 Release-6 32-bit addresses, big endian, with microMIPS", "1.9", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("MIPS:LE:32:R6", "MIPS32 Release-6 32-bit addresses, little endian, with microMIPS", "1.9", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- 64-bit default (mips16e mode) --
            Language::new("MIPS:BE:64:default", "MIPS64 64-bit addresses, big endian, with mips16e", "1.9", Endian::Big, 64)
                .with_pc_register("PC"),
            Language::new("MIPS:LE:64:default", "MIPS64 64-bit addresses, little endian, with mips16e", "1.9", Endian::Little, 64)
                .with_pc_register("PC"),
            // -- 64-bit mips16e --
            Language::new("MIPS:BE:64:16e", "MIPS64 64-bit addresses, big endian, in mips16e mode", "1.9", Endian::Big, 64)
                .with_pc_register("PC"),
            Language::new("MIPS:LE:64:16e", "MIPS64 64-bit addresses, little endian, in mips16e mode", "1.9", Endian::Little, 64)
                .with_pc_register("PC"),
            // -- 64-bit microMIPS --
            Language::new("MIPS:BE:64:micro", "MIPS64 64-bit addresses, big endian, with microMIPS", "1.9", Endian::Big, 64)
                .with_pc_register("PC"),
            Language::new("MIPS:LE:64:micro", "MIPS64 64-bit addresses, little endian, with microMIPS", "1.9", Endian::Little, 64)
                .with_pc_register("PC"),
            // -- 64-bit R6 --
            Language::new("MIPS:BE:64:R6", "MIPS64 Release-6 64-bit addresses, big endian, with microMIPS", "1.9", Endian::Big, 64)
                .with_pc_register("PC"),
            Language::new("MIPS:LE:64:R6", "MIPS64 Release-6 64-bit addresses, little endian, with microMIPS", "1.9", Endian::Little, 64)
                .with_pc_register("PC"),
            // -- 64-bit with 32-bit addressing --
            Language::new("MIPS:BE:64:64-32addr", "MIPS64 32-bit addresses, big endian, with mips16e", "1.9", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("MIPS:LE:64:64-32addr", "MIPS64 32-bit addresses, little endian, with mips16e", "1.9", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- 64-bit microMIPS with 32-bit addressing --
            Language::new("MIPS:BE:64:micro64-32addr", "MIPS64 32-bit addresses, big endian, with microMIPS", "1.9", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("MIPS:LE:64:micro64-32addr", "MIPS64 32-bit addresses, little endian, with microMIPS", "1.9", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- 64-bit R6 with 32-bit addressing --
            Language::new("MIPS:BE:64:64-32R6addr", "MIPS64 Release-6 big endian with 32 bit addressing and microMIPS", "1.9", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("MIPS:LE:64:64-32R6addr", "MIPS64 Release-6 with 32-bit addresses, little endian, with microMIPS", "1.9", Endian::Little, 32)
                .with_pc_register("PC"),
        ]
    }

    fn build_language_descriptions() -> Vec<LanguageDescription> {
        let proc = Processor::new(
            Self::PROCESSOR_NAME,
            "MIPS processor family (32/64-bit) including CP0, FPU, MSA, DSP, microMIPS, MIPS16e, and VZ",
            Self::FAMILY,
        );
        let default_cs = CompilerSpecDescription::default_spec("default");

        Self::build_languages()
            .into_iter()
            .map(|lang| {
                LanguageDescription::new(
                    LanguageID::new(&lang.id),
                    proc.clone(),
                    lang.endian,
                    lang.pointer_size,
                    &lang.version,
                    &lang.description,
                )
                .with_compiler_spec(default_cs.clone())
            })
            .collect()
    }
}

impl LanguageProvider for MipsLanguageProvider {
    fn processor_name() -> &'static str {
        Self::PROCESSOR_NAME
    }

    fn processor_description() -> &'static str {
        "MIPS processor family (32/64-bit) including CP0, FPU, MSA, DSP, microMIPS, MIPS16e, and VZ"
    }

    fn family() -> &'static str {
        Self::FAMILY
    }

    fn language_descriptions() -> Vec<LanguageDescription> {
        Self::build_language_descriptions()
    }

    fn languages() -> Vec<Language> {
        Self::build_languages()
    }

    fn get_language(language_id: &str) -> Option<Language> {
        Self::build_languages().into_iter().find(|l| l.id == language_id)
    }

    fn is_language_loaded(language_id: &str) -> bool {
        Self::LANGUAGE_IDS.contains(&language_id)
    }

    fn default_language() -> Language {
        Language::new(
            "MIPS:BE:32:default",
            "MIPS32 32-bit addresses, big endian, with mips16e",
            "1.9",
            Endian::Big,
            32,
        )
        .with_pc_register("PC")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_name() {
        assert_eq!(MipsLanguageProvider::processor_name(), "MIPS");
    }

    #[test]
    fn test_language_count() {
        let langs = MipsLanguageProvider::languages();
        assert_eq!(langs.len(), 22);
    }

    #[test]
    fn test_language_description_count() {
        let descs = MipsLanguageProvider::language_descriptions();
        assert_eq!(descs.len(), 22);
    }

    #[test]
    fn test_get_language_found() {
        let lang = MipsLanguageProvider::get_language("MIPS:BE:64:default");
        assert!(lang.is_some());
        let lang = lang.unwrap();
        assert_eq!(lang.pointer_size, 64);
        assert_eq!(lang.endian, Endian::Big);
    }

    #[test]
    fn test_get_language_not_found() {
        assert!(MipsLanguageProvider::get_language("nonexistent:LE:32:default").is_none());
    }

    #[test]
    fn test_is_language_loaded() {
        assert!(MipsLanguageProvider::is_language_loaded("MIPS:BE:32:default"));
        assert!(MipsLanguageProvider::is_language_loaded("MIPS:LE:64:R6"));
        assert!(!MipsLanguageProvider::is_language_loaded("nonexistent:LE:32:default"));
    }

    #[test]
    fn test_default_language() {
        let lang = MipsLanguageProvider::default_language();
        assert_eq!(lang.id, "MIPS:BE:32:default");
        assert_eq!(lang.pointer_size, 32);
        assert_eq!(lang.endian, Endian::Big);
    }

    #[test]
    fn test_mips64_languages() {
        let mips64: Vec<_> = MipsLanguageProvider::languages()
            .into_iter()
            .filter(|l| l.id.contains("64") && !l.id.contains("32addr"))
            .collect();
        assert!(mips64.len() >= 8, "Expected >= 8 MIPS64 languages, got {}", mips64.len());
    }

    #[test]
    fn test_variant_types_present() {
        let ids: Vec<&str> = MipsLanguageProvider::LANGUAGE_IDS.to_vec();
        // mips16e variants
        assert!(ids.iter().any(|id| id.contains("16e")));
        // microMIPS variants
        assert!(ids.iter().any(|id| id.contains("micro")));
        // R6 variants
        assert!(ids.iter().any(|id| id.contains("R6")));
        // 64-32addr variants
        assert!(ids.iter().any(|id| id.contains("64-32addr")));
    }

    #[test]
    fn test_language_descriptions_have_processor() {
        for desc in MipsLanguageProvider::language_descriptions() {
            assert_eq!(desc.processor.name(), "MIPS");
            assert_eq!(desc.processor.family(), "MIPS");
        }
    }
}
