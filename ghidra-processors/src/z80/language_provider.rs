//! Z80 / Game Boy Language Provider
//!
//! Provides the [`Z80LanguageProvider`] which implements the [`LanguageProvider`]
//! trait for Zilog Z80 and Game Boy LR35902 processor languages.
//!
//! ## Supported Languages
//!
//! Covers the Z80 in little-endian and big-endian configurations,
//! plus the Game Boy / Game Boy Color (Sharp LR35902) variant.

use crate::common::{
    CompilerSpecDescription, Endian, Language, LanguageDescription, LanguageID, LanguageProvider,
    Processor,
};

/// Language provider for Z80 / Game Boy processors.
pub struct Z80LanguageProvider;

impl Z80LanguageProvider {
    /// The processor name constant.
    pub const PROCESSOR_NAME: &'static str = "Zilog Z80 / Game Boy LR35902";

    /// Processor family.
    pub const FAMILY: &'static str = "Z80";

    /// All language IDs supported by this provider.
    pub const LANGUAGE_IDS: [&'static str; 3] = [
        "z80:LE:8:default",
        "z80:BE:8:default",
        "gb:LE:8:LR35902",
    ];

    fn build_languages() -> Vec<Language> {
        vec![
            Language::new(
                "z80:LE:8:default",
                "Zilog Z80 (8-bit, little-endian)",
                "Z80",
                Endian::Little,
                16,
            ),
            Language::new(
                "z80:BE:8:default",
                "Zilog Z80 (8-bit, big-endian, for big-endian Z80 systems)",
                "Z80",
                Endian::Big,
                16,
            ),
            Language::new(
                "gb:LE:8:LR35902",
                "Game Boy / Game Boy Color (Sharp LR35902, Z80-derived)",
                "LR35902",
                Endian::Little,
                16,
            ),
        ]
    }

    fn build_language_descriptions() -> Vec<LanguageDescription> {
        let proc = Processor::new(
            Self::PROCESSOR_NAME,
            "Zilog Z80 8-bit microprocessor and Game Boy LR35902",
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

impl LanguageProvider for Z80LanguageProvider {
    fn processor_name() -> &'static str {
        Self::PROCESSOR_NAME
    }

    fn processor_description() -> &'static str {
        "Zilog Z80 8-bit microprocessor and Game Boy LR35902"
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
            "z80:LE:8:default",
            "Zilog Z80 (8-bit, little-endian)",
            "Z80",
            Endian::Little,
            16,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_name() {
        assert_eq!(Z80LanguageProvider::processor_name(), "Zilog Z80 / Game Boy LR35902");
    }

    #[test]
    fn test_language_count() {
        let langs = Z80LanguageProvider::languages();
        assert_eq!(langs.len(), 3);
    }

    #[test]
    fn test_language_description_count() {
        let descs = Z80LanguageProvider::language_descriptions();
        assert_eq!(descs.len(), 3);
    }

    #[test]
    fn test_get_language_found() {
        let lang = Z80LanguageProvider::get_language("gb:LE:8:LR35902");
        assert!(lang.is_some());
        let lang = lang.unwrap();
        assert_eq!(lang.pointer_size, 16);
        assert_eq!(lang.endian, Endian::Little);
    }

    #[test]
    fn test_get_language_not_found() {
        assert!(Z80LanguageProvider::get_language("nonexistent:LE:32:default").is_none());
    }

    #[test]
    fn test_is_language_loaded() {
        assert!(Z80LanguageProvider::is_language_loaded("z80:LE:8:default"));
        assert!(Z80LanguageProvider::is_language_loaded("gb:LE:8:LR35902"));
        assert!(!Z80LanguageProvider::is_language_loaded("nonexistent:LE:32:default"));
    }

    #[test]
    fn test_default_language() {
        let lang = Z80LanguageProvider::default_language();
        assert_eq!(lang.id, "z80:LE:8:default");
        assert_eq!(lang.pointer_size, 16);
    }

    #[test]
    fn test_gameboy_language_exists() {
        let lang = Z80LanguageProvider::get_language("gb:LE:8:LR35902");
        assert!(lang.is_some());
    }

    #[test]
    fn test_language_descriptions_have_processor() {
        for desc in Z80LanguageProvider::language_descriptions() {
            assert_eq!(desc.processor.name(), "Zilog Z80 / Game Boy LR35902");
            assert_eq!(desc.processor.family(), "Z80");
        }
    }
}
