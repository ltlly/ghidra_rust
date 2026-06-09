//! Atmel AVR Language Provider
//!
//! Provides the [`AvrLanguageProvider`] which implements the [`LanguageProvider`]
//! trait for Atmel/Microchip AVR processor languages.
//!
//! ## Supported Languages
//!
//! Covers the baseline AVR, ATmega, ATtiny, and ATxmega variants,
//! all little-endian 8-bit with 16-bit pointers.

use crate::common::{
    CompilerSpecDescription, Endian, Language, LanguageDescription, LanguageID, LanguageProvider,
    Processor,
};

/// Language provider for Atmel AVR processors.
pub struct AvrLanguageProvider;

impl AvrLanguageProvider {
    /// The processor name constant.
    pub const PROCESSOR_NAME: &'static str = "Atmel AVR";

    /// Processor family.
    pub const FAMILY: &'static str = "AVR";

    /// All language IDs supported by this provider.
    pub const LANGUAGE_IDS: [&'static str; 4] = [
        "avr:LE:8:default",
        "avr:LE:8:ATmega",
        "avr:LE:8:ATtiny",
        "avr:LE:8:ATxmega",
    ];

    fn build_languages() -> Vec<Language> {
        vec![
            Language::new(
                "avr:LE:8:default",
                "Atmel AVR (8-bit, ATmega/ATtiny baseline)",
                "AVR",
                Endian::Little,
                16,
            ),
            Language::new(
                "avr:LE:8:ATmega",
                "Atmel ATmega (8-bit, classic AVR core)",
                "ATmega",
                Endian::Little,
                16,
            ),
            Language::new(
                "avr:LE:8:ATtiny",
                "Atmel ATtiny (8-bit, reduced AVR core)",
                "ATtiny",
                Endian::Little,
                16,
            ),
            Language::new(
                "avr:LE:8:ATxmega",
                "Atmel ATxmega (8-bit, enhanced AVR core)",
                "ATxmega",
                Endian::Little,
                16,
            ),
        ]
    }

    fn build_language_descriptions() -> Vec<LanguageDescription> {
        let proc = Processor::new(
            Self::PROCESSOR_NAME,
            "Atmel AVR 8-bit RISC microcontroller family (ATmega, ATtiny, ATxmega)",
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

impl LanguageProvider for AvrLanguageProvider {
    fn processor_name() -> &'static str {
        Self::PROCESSOR_NAME
    }

    fn processor_description() -> &'static str {
        "Atmel AVR 8-bit RISC microcontroller family (ATmega, ATtiny, ATxmega)"
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
            "avr:LE:8:default",
            "Atmel AVR (8-bit, ATmega/ATtiny baseline)",
            "AVR",
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
        assert_eq!(AvrLanguageProvider::processor_name(), "Atmel AVR");
    }

    #[test]
    fn test_language_count() {
        let langs = AvrLanguageProvider::languages();
        assert_eq!(langs.len(), 4);
    }

    #[test]
    fn test_language_description_count() {
        let descs = AvrLanguageProvider::language_descriptions();
        assert_eq!(descs.len(), 4);
    }

    #[test]
    fn test_get_language_found() {
        let lang = AvrLanguageProvider::get_language("avr:LE:8:ATmega");
        assert!(lang.is_some());
        let lang = lang.unwrap();
        assert_eq!(lang.pointer_size, 16);
        assert_eq!(lang.endian, Endian::Little);
    }

    #[test]
    fn test_get_language_not_found() {
        assert!(AvrLanguageProvider::get_language("nonexistent:LE:32:default").is_none());
    }

    #[test]
    fn test_is_language_loaded() {
        assert!(AvrLanguageProvider::is_language_loaded("avr:LE:8:default"));
        assert!(AvrLanguageProvider::is_language_loaded("avr:LE:8:ATtiny"));
        assert!(!AvrLanguageProvider::is_language_loaded("nonexistent:LE:32:default"));
    }

    #[test]
    fn test_default_language() {
        let lang = AvrLanguageProvider::default_language();
        assert_eq!(lang.id, "avr:LE:8:default");
        assert_eq!(lang.pointer_size, 16);
    }

    #[test]
    fn test_all_little_endian() {
        for lang in AvrLanguageProvider::languages() {
            assert_eq!(lang.endian, Endian::Little, "AVR should be little-endian: {}", lang.id);
        }
    }

    #[test]
    fn test_language_descriptions_have_processor() {
        for desc in AvrLanguageProvider::language_descriptions() {
            assert_eq!(desc.processor.name(), "Atmel AVR");
            assert_eq!(desc.processor.family(), "AVR");
        }
    }
}
