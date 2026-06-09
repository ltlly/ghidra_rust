//! SPARC Language Provider
//!
//! Provides the [`SparcLanguageProvider`] which implements the [`LanguageProvider`]
//! trait for SPARC processor languages.
//!
//! ## Supported Languages
//!
//! Covers SPARC V7 through V9 with VIS 1/2/3 extensions,
//! in both 32-bit and 64-bit configurations (all big-endian).

use crate::common::{
    CompilerSpecDescription, Endian, Language, LanguageDescription, LanguageID, LanguageProvider,
    Processor,
};

/// Language provider for SPARC processors.
pub struct SparcLanguageProvider;

impl SparcLanguageProvider {
    /// The processor name constant.
    pub const PROCESSOR_NAME: &'static str = "SPARC";

    /// Processor family.
    pub const FAMILY: &'static str = "SPARC";

    /// All language IDs supported by this provider.
    pub const LANGUAGE_IDS: [&'static str; 9] = [
        "sparc:BE:32:default",
        "sparc:BE:64:default",
        "sparc:BE:32:V7",
        "sparc:BE:32:V8",
        "sparc:BE:32:V8+",
        "sparc:BE:64:V9",
        "sparc:BE:64:V9_VIS1",
        "sparc:BE:64:V9_VIS2",
        "sparc:BE:64:V9_VIS3",
    ];

    fn build_languages() -> Vec<Language> {
        vec![
            Language::new(
                "sparc:BE:32:default",
                "Sparc V9 32-bit",
                "1.5",
                Endian::Big,
                32,
            ),
            Language::new(
                "sparc:BE:64:default",
                "Sparc V9 64-bit",
                "1.5",
                Endian::Big,
                64,
            ),
            Language::new(
                "sparc:BE:32:V7",
                "SPARC V7 32-bit Big Endian",
                "V7",
                Endian::Big,
                32,
            ),
            Language::new(
                "sparc:BE:32:V8",
                "SPARC V8 32-bit Big Endian",
                "V8",
                Endian::Big,
                32,
            ),
            Language::new(
                "sparc:BE:32:V8+",
                "SPARC V8+ 32-bit Big Endian",
                "V8+",
                Endian::Big,
                32,
            ),
            Language::new(
                "sparc:BE:64:V9",
                "SPARC V9 64-bit Big Endian",
                "V9",
                Endian::Big,
                64,
            ),
            Language::new(
                "sparc:BE:64:V9_VIS1",
                "SPARC V9 64-bit Big Endian with VIS 1",
                "V9+VIS1",
                Endian::Big,
                64,
            ),
            Language::new(
                "sparc:BE:64:V9_VIS2",
                "SPARC V9 64-bit Big Endian with VIS 2",
                "V9+VIS2",
                Endian::Big,
                64,
            ),
            Language::new(
                "sparc:BE:64:V9_VIS3",
                "SPARC V9 64-bit Big Endian with VIS 3",
                "V9+VIS3",
                Endian::Big,
                64,
            ),
        ]
    }

    fn build_language_descriptions() -> Vec<LanguageDescription> {
        let proc = Processor::new(
            Self::PROCESSOR_NAME,
            "SPARC V8/V9 processor family with register windows, FPU, and VIS SIMD extensions",
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

impl LanguageProvider for SparcLanguageProvider {
    fn processor_name() -> &'static str {
        Self::PROCESSOR_NAME
    }

    fn processor_description() -> &'static str {
        "SPARC V8/V9 processor family with register windows, FPU, and VIS SIMD extensions"
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
            "sparc:BE:64:default",
            "Sparc V9 64-bit",
            "1.5",
            Endian::Big,
            64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_name() {
        assert_eq!(SparcLanguageProvider::processor_name(), "SPARC");
    }

    #[test]
    fn test_language_count() {
        let langs = SparcLanguageProvider::languages();
        assert_eq!(langs.len(), 9);
    }

    #[test]
    fn test_language_description_count() {
        let descs = SparcLanguageProvider::language_descriptions();
        assert_eq!(descs.len(), 9);
    }

    #[test]
    fn test_get_language_found() {
        let lang = SparcLanguageProvider::get_language("sparc:BE:64:V9");
        assert!(lang.is_some());
        let lang = lang.unwrap();
        assert_eq!(lang.pointer_size, 64);
        assert_eq!(lang.endian, Endian::Big);
    }

    #[test]
    fn test_get_language_not_found() {
        assert!(SparcLanguageProvider::get_language("nonexistent:LE:32:default").is_none());
    }

    #[test]
    fn test_is_language_loaded() {
        assert!(SparcLanguageProvider::is_language_loaded("sparc:BE:32:default"));
        assert!(SparcLanguageProvider::is_language_loaded("sparc:BE:64:V9_VIS3"));
        assert!(!SparcLanguageProvider::is_language_loaded("nonexistent:LE:32:default"));
    }

    #[test]
    fn test_default_language() {
        let lang = SparcLanguageProvider::default_language();
        assert_eq!(lang.id, "sparc:BE:64:default");
        assert_eq!(lang.pointer_size, 64);
        assert_eq!(lang.endian, Endian::Big);
    }

    #[test]
    fn test_all_big_endian() {
        for lang in SparcLanguageProvider::languages() {
            assert_eq!(lang.endian, Endian::Big, "SPARC should be big-endian: {}", lang.id);
        }
    }

    #[test]
    fn test_language_descriptions_have_processor() {
        for desc in SparcLanguageProvider::language_descriptions() {
            assert_eq!(desc.processor.name(), "SPARC");
            assert_eq!(desc.processor.family(), "SPARC");
        }
    }
}
