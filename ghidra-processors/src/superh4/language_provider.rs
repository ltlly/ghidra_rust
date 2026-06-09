//! SuperH-4 Language Provider
//!
//! Provides the [`SuperH4LanguageProvider`] which implements the [`LanguageProvider`]
//! trait for Renesas SuperH SH-4 processor languages.
//!
//! ## Supported Languages
//!
//! Covers the SuperH SH-4 in both little-endian and big-endian
//! configurations, 32-bit with 2-byte instruction alignment.

use crate::common::{
    CompilerSpecDescription, Endian, Language, LanguageDescription, LanguageID, LanguageProvider,
    Processor,
};

/// Language provider for SuperH SH-4 processors.
pub struct SuperH4LanguageProvider;

impl SuperH4LanguageProvider {
    /// The processor name constant.
    pub const PROCESSOR_NAME: &'static str = "SuperH-4";

    /// Processor family.
    pub const FAMILY: &'static str = "SuperH";

    /// All language IDs supported by this provider.
    pub const LANGUAGE_IDS: [&'static str; 2] = [
        "SuperH4:LE:32:default",
        "SuperH4:BE:32:default",
    ];

    fn build_languages() -> Vec<Language> {
        vec![
            Language::new(
                "SuperH4:LE:32:default",
                "SuperH-4(a) (SH4) little endian",
                "default",
                Endian::Little,
                32,
            )
            .with_instruction_alignment(2)
            .with_pc_register("PC"),
            Language::new(
                "SuperH4:BE:32:default",
                "SuperH-4(a) (SH4) big endian",
                "default",
                Endian::Big,
                32,
            )
            .with_instruction_alignment(2)
            .with_pc_register("PC"),
        ]
    }

    fn build_language_descriptions() -> Vec<LanguageDescription> {
        let proc = Processor::new(
            Self::PROCESSOR_NAME,
            "Renesas SuperH SH-4 (SH7750) 32-bit RISC microprocessor",
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

impl LanguageProvider for SuperH4LanguageProvider {
    fn processor_name() -> &'static str {
        Self::PROCESSOR_NAME
    }

    fn processor_description() -> &'static str {
        "Renesas SuperH SH-4 (SH7750) 32-bit RISC microprocessor"
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
            "SuperH4:LE:32:default",
            "SuperH-4(a) (SH4) little endian",
            "default",
            Endian::Little,
            32,
        )
        .with_instruction_alignment(2)
        .with_pc_register("PC")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_name() {
        assert_eq!(SuperH4LanguageProvider::processor_name(), "SuperH-4");
    }

    #[test]
    fn test_language_count() {
        let langs = SuperH4LanguageProvider::languages();
        assert_eq!(langs.len(), 2);
    }

    #[test]
    fn test_language_description_count() {
        let descs = SuperH4LanguageProvider::language_descriptions();
        assert_eq!(descs.len(), 2);
    }

    #[test]
    fn test_get_language_found() {
        let lang = SuperH4LanguageProvider::get_language("SuperH4:LE:32:default");
        assert!(lang.is_some());
        let lang = lang.unwrap();
        assert_eq!(lang.pointer_size, 32);
        assert_eq!(lang.endian, Endian::Little);
    }

    #[test]
    fn test_get_language_not_found() {
        assert!(SuperH4LanguageProvider::get_language("nonexistent:LE:32:default").is_none());
    }

    #[test]
    fn test_is_language_loaded() {
        assert!(SuperH4LanguageProvider::is_language_loaded("SuperH4:LE:32:default"));
        assert!(SuperH4LanguageProvider::is_language_loaded("SuperH4:BE:32:default"));
        assert!(!SuperH4LanguageProvider::is_language_loaded("nonexistent:LE:32:default"));
    }

    #[test]
    fn test_default_language() {
        let lang = SuperH4LanguageProvider::default_language();
        assert_eq!(lang.id, "SuperH4:LE:32:default");
        assert_eq!(lang.pointer_size, 32);
        assert_eq!(lang.instruction_alignment, 2);
    }

    #[test]
    fn test_le_and_be_variants() {
        let langs = SuperH4LanguageProvider::languages();
        assert!(langs.iter().any(|l| l.endian == Endian::Little));
        assert!(langs.iter().any(|l| l.endian == Endian::Big));
    }

    #[test]
    fn test_language_descriptions_have_processor() {
        for desc in SuperH4LanguageProvider::language_descriptions() {
            assert_eq!(desc.processor.name(), "SuperH-4");
            assert_eq!(desc.processor.family(), "SuperH");
        }
    }
}
