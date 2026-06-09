//! BPF Language Provider
//!
//! Provides the [`BpfLanguageProvider`] which implements the [`LanguageProvider`]
//! trait for Berkeley Packet Filter processor languages.
//!
//! ## Supported Languages
//!
//! Single 32-bit little-endian BPF virtual machine language.

use crate::common::{
    CompilerSpecDescription, Endian, Language, LanguageDescription, LanguageID, LanguageProvider,
    Processor,
};

/// Language provider for BPF processors.
pub struct BpfLanguageProvider;

impl BpfLanguageProvider {
    /// The processor name constant.
    pub const PROCESSOR_NAME: &'static str = "BPF (Berkeley Packet Filter)";

    /// Processor family.
    pub const FAMILY: &'static str = "BPF";

    /// All language IDs supported by this provider.
    pub const LANGUAGE_IDS: [&'static str; 1] = [
        "BPF:LE:32:default",
    ];

    fn build_languages() -> Vec<Language> {
        vec![
            Language::new(
                "BPF:LE:32:default",
                "BPF processor 32-bit little-endian",
                "default",
                Endian::Little,
                32,
            )
            .with_instruction_alignment(1)
            .with_pc_register("PC"),
        ]
    }

    fn build_language_descriptions() -> Vec<LanguageDescription> {
        let proc = Processor::new(
            Self::PROCESSOR_NAME,
            "Berkeley Packet Filter (BPF) virtual machine",
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

impl LanguageProvider for BpfLanguageProvider {
    fn processor_name() -> &'static str {
        Self::PROCESSOR_NAME
    }

    fn processor_description() -> &'static str {
        "Berkeley Packet Filter (BPF) virtual machine"
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
            "BPF:LE:32:default",
            "BPF processor 32-bit little-endian",
            "default",
            Endian::Little,
            32,
        )
        .with_instruction_alignment(1)
        .with_pc_register("PC")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_name() {
        assert_eq!(BpfLanguageProvider::processor_name(), "BPF (Berkeley Packet Filter)");
    }

    #[test]
    fn test_language_count() {
        let langs = BpfLanguageProvider::languages();
        assert_eq!(langs.len(), 1);
    }

    #[test]
    fn test_language_description_count() {
        let descs = BpfLanguageProvider::language_descriptions();
        assert_eq!(descs.len(), 1);
    }

    #[test]
    fn test_get_language_found() {
        let lang = BpfLanguageProvider::get_language("BPF:LE:32:default");
        assert!(lang.is_some());
        let lang = lang.unwrap();
        assert_eq!(lang.pointer_size, 32);
        assert_eq!(lang.endian, Endian::Little);
    }

    #[test]
    fn test_get_language_not_found() {
        assert!(BpfLanguageProvider::get_language("nonexistent:LE:32:default").is_none());
    }

    #[test]
    fn test_is_language_loaded() {
        assert!(BpfLanguageProvider::is_language_loaded("BPF:LE:32:default"));
        assert!(!BpfLanguageProvider::is_language_loaded("nonexistent:LE:32:default"));
    }

    #[test]
    fn test_default_language() {
        let lang = BpfLanguageProvider::default_language();
        assert_eq!(lang.id, "BPF:LE:32:default");
        assert_eq!(lang.pointer_size, 32);
    }

    #[test]
    fn test_language_descriptions_have_processor() {
        for desc in BpfLanguageProvider::language_descriptions() {
            assert_eq!(desc.processor.name(), "BPF (Berkeley Packet Filter)");
            assert_eq!(desc.processor.family(), "BPF");
        }
    }
}
