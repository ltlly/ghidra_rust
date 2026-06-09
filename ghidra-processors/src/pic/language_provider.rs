//! Microchip PIC Language Provider
//!
//! Provides the [`PicLanguageProvider`] which implements the [`LanguageProvider`]
//! trait for Microchip PIC processor languages.
//!
//! ## Supported Languages
//!
//! Covers PIC16, PIC18 (8-bit), PIC24, and dsPIC33 (16-bit DSP),
//! all little-endian.

use crate::common::{
    CompilerSpecDescription, Endian, Language, LanguageDescription, LanguageID, LanguageProvider,
    Processor,
};

/// Language provider for Microchip PIC processors.
pub struct PicLanguageProvider;

impl PicLanguageProvider {
    /// The processor name constant.
    pub const PROCESSOR_NAME: &'static str = "Microchip PIC";

    /// Processor family.
    pub const FAMILY: &'static str = "PIC";

    /// All language IDs supported by this provider.
    pub const LANGUAGE_IDS: [&'static str; 4] = [
        "pic:LE:8:PIC16",
        "pic:LE:8:PIC18",
        "pic:LE:16:PIC24",
        "pic:LE:16:dsPIC33",
    ];

    fn build_languages() -> Vec<Language> {
        vec![
            Language::new(
                "pic:LE:8:PIC16",
                "Microchip PIC16 (8-bit, little-endian, mid-range)",
                "PIC16",
                Endian::Little,
                16,
            ),
            Language::new(
                "pic:LE:8:PIC18",
                "Microchip PIC18 (8-bit, little-endian, high-end)",
                "PIC18",
                Endian::Little,
                16,
            ),
            Language::new(
                "pic:LE:16:PIC24",
                "Microchip PIC24 (16-bit, little-endian, MCU)",
                "PIC24",
                Endian::Little,
                24,
            ),
            Language::new(
                "pic:LE:16:dsPIC33",
                "Microchip dsPIC33 (16-bit, little-endian, DSP)",
                "dsPIC33",
                Endian::Little,
                24,
            ),
        ]
    }

    fn build_language_descriptions() -> Vec<LanguageDescription> {
        let proc = Processor::new(
            Self::PROCESSOR_NAME,
            "Microchip PIC 8/16-bit microcontroller family (PIC16, PIC18, PIC24, dsPIC33)",
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

impl LanguageProvider for PicLanguageProvider {
    fn processor_name() -> &'static str {
        Self::PROCESSOR_NAME
    }

    fn processor_description() -> &'static str {
        "Microchip PIC 8/16-bit microcontroller family (PIC16, PIC18, PIC24, dsPIC33)"
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
            "pic:LE:16:PIC24",
            "Microchip PIC24 (16-bit, little-endian, MCU)",
            "PIC24",
            Endian::Little,
            24,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_name() {
        assert_eq!(PicLanguageProvider::processor_name(), "Microchip PIC");
    }

    #[test]
    fn test_language_count() {
        let langs = PicLanguageProvider::languages();
        assert_eq!(langs.len(), 4);
    }

    #[test]
    fn test_language_description_count() {
        let descs = PicLanguageProvider::language_descriptions();
        assert_eq!(descs.len(), 4);
    }

    #[test]
    fn test_get_language_found() {
        let lang = PicLanguageProvider::get_language("pic:LE:16:dsPIC33");
        assert!(lang.is_some());
        let lang = lang.unwrap();
        assert_eq!(lang.pointer_size, 24);
        assert_eq!(lang.endian, Endian::Little);
    }

    #[test]
    fn test_get_language_not_found() {
        assert!(PicLanguageProvider::get_language("nonexistent:LE:32:default").is_none());
    }

    #[test]
    fn test_is_language_loaded() {
        assert!(PicLanguageProvider::is_language_loaded("pic:LE:8:PIC16"));
        assert!(PicLanguageProvider::is_language_loaded("pic:LE:16:PIC24"));
        assert!(!PicLanguageProvider::is_language_loaded("nonexistent:LE:32:default"));
    }

    #[test]
    fn test_default_language() {
        let lang = PicLanguageProvider::default_language();
        assert_eq!(lang.id, "pic:LE:16:PIC24");
        assert_eq!(lang.pointer_size, 24);
    }

    #[test]
    fn test_8bit_and_16bit_variants() {
        let langs = PicLanguageProvider::languages();
        let pic16_langs: Vec<_> = langs.iter().filter(|l| l.id.contains("PIC16") || l.id.contains("PIC18")).collect();
        let pic24_langs: Vec<_> = langs.iter().filter(|l| l.id.contains("PIC24") || l.id.contains("dsPIC33")).collect();
        assert_eq!(pic16_langs.len(), 2);
        assert_eq!(pic24_langs.len(), 2);
    }

    #[test]
    fn test_language_descriptions_have_processor() {
        for desc in PicLanguageProvider::language_descriptions() {
            assert_eq!(desc.processor.name(), "Microchip PIC");
            assert_eq!(desc.processor.family(), "PIC");
        }
    }
}
