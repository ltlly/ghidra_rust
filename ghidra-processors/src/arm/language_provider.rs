//! ARM32 Language Provider
//!
//! Provides the [`ArmLanguageProvider`] which implements the [`LanguageProvider`]
//! trait for ARM (AArch32) processor languages.
//!
//! ## Supported Languages
//!
//! Covers ARMv4 through ARMv8 in both little-endian and big-endian
//! configurations, including Thumb, Cortex, and v8-m variants.

use crate::common::{
    CompilerSpecDescription, Endian, Language, LanguageDescription, LanguageID, LanguageProvider,
    Processor,
};

/// Language provider for ARM32 (AArch32) processors.
///
/// Migrates the Java `ARM` processor language definitions into Rust.
pub struct ArmLanguageProvider;

impl ArmLanguageProvider {
    /// The processor name constant.
    pub const PROCESSOR_NAME: &'static str = "ARM";

    /// Processor family.
    pub const FAMILY: &'static str = "ARM";

    /// All language IDs supported by this provider.
    pub const LANGUAGE_IDS: [&'static str; 20] = [
        "ARM:LE:32:v8",
        "ARM:LE:32:v8T",
        "ARM:BE:32:v8",
        "ARM:BE:32:v8T",
        "ARM:LEBE:32:v8LEInstruction",
        "ARM:LE:32:v7",
        "ARM:BE:32:v7",
        "ARM:LEBE:32:v7LEInstruction",
        "ARM:LE:32:Cortex",
        "ARM:BE:32:Cortex",
        "ARM:LE:32:v8-m",
        "ARM:BE:32:v8-m",
        "ARM:LE:32:v6",
        "ARM:BE:32:v6",
        "ARM:LE:32:v5t",
        "ARM:BE:32:v5t",
        "ARM:LE:32:v5",
        "ARM:BE:32:v5",
        "ARM:LE:32:v4t",
        "ARM:BE:32:v4t",
    ];

    fn build_languages() -> Vec<Language> {
        vec![
            // --- v8 ---
            Language::new(
                "ARM:LE:32:v8", "Generic ARM/Thumb v8 little endian", "v8",
                Endian::Little, 32,
            ),
            Language::new(
                "ARM:LE:32:v8T", "Generic ARM/Thumb v8 little endian (Thumb is default)", "v8T",
                Endian::Little, 32,
            ),
            Language::new(
                "ARM:BE:32:v8", "Generic ARM/Thumb v8 big endian", "v8",
                Endian::Big, 32,
            ),
            Language::new(
                "ARM:BE:32:v8T", "Generic ARM/Thumb v8 big endian (Thumb is default)", "v8T",
                Endian::Big, 32,
            ),
            Language::new(
                "ARM:LEBE:32:v8LEInstruction",
                "Generic ARM/Thumb v8 little endian instructions and big endian data",
                "v8LEInstruction", Endian::Big, 32,
            ),
            // --- v7 ---
            Language::new(
                "ARM:LE:32:v7", "Generic ARM/Thumb v7 little endian", "v7",
                Endian::Little, 32,
            ),
            Language::new(
                "ARM:BE:32:v7", "Generic ARM/Thumb v7 big endian", "v7",
                Endian::Big, 32,
            ),
            Language::new(
                "ARM:LEBE:32:v7LEInstruction",
                "Generic ARM/Thumb v7 little endian instructions and big endian data",
                "v7LEInstruction", Endian::Big, 32,
            ),
            // --- Cortex ---
            Language::new(
                "ARM:LE:32:Cortex", "ARM Cortex / Thumb little endian", "Cortex",
                Endian::Little, 32,
            ),
            Language::new(
                "ARM:BE:32:Cortex", "ARM Cortex / Thumb big endian", "Cortex",
                Endian::Big, 32,
            ),
            // --- v8-m ---
            Language::new(
                "ARM:LE:32:v8-m", "ARM Cortex v8-m little endian", "v8-m",
                Endian::Little, 32,
            ),
            Language::new(
                "ARM:BE:32:v8-m", "ARM Cortex v8-m big endian", "v8-m",
                Endian::Big, 32,
            ),
            // --- v6 ---
            Language::new(
                "ARM:LE:32:v6", "Generic ARM/Thumb v6 little endian", "v6",
                Endian::Little, 32,
            ),
            Language::new(
                "ARM:BE:32:v6", "Generic ARM/Thumb v6 big endian", "v6",
                Endian::Big, 32,
            ),
            // --- v5t ---
            Language::new(
                "ARM:LE:32:v5t", "Generic ARM/Thumb v5 little endian (T-variant)", "v5t",
                Endian::Little, 32,
            ),
            Language::new(
                "ARM:BE:32:v5t", "Generic ARM/Thumb v5 big endian (T-variant)", "v5t",
                Endian::Big, 32,
            ),
            // --- v5 (no Thumb) ---
            Language::new(
                "ARM:LE:32:v5", "Generic ARM v5 little endian", "v5",
                Endian::Little, 32,
            ),
            Language::new(
                "ARM:BE:32:v5", "Generic ARM v5 big endian", "v5",
                Endian::Big, 32,
            ),
            // --- v4t ---
            Language::new(
                "ARM:LE:32:v4t", "Generic ARM/Thumb v4 little endian (T-variant)", "v4t",
                Endian::Little, 32,
            ),
            Language::new(
                "ARM:BE:32:v4t", "Generic ARM/Thumb v4 big endian (T-variant)", "v4t",
                Endian::Big, 32,
            ),
        ]
    }

    fn build_language_descriptions() -> Vec<LanguageDescription> {
        let proc = Processor::new(
            Self::PROCESSOR_NAME,
            "ARM 32-bit processor family (AArch32), including Thumb, VFP, and NEON",
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

impl LanguageProvider for ArmLanguageProvider {
    fn processor_name() -> &'static str {
        Self::PROCESSOR_NAME
    }

    fn processor_description() -> &'static str {
        "ARM 32-bit processor family (AArch32), including Thumb, VFP, and NEON"
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
            "ARM:LE:32:v8",
            "Generic ARM/Thumb v8 little endian",
            "v8",
            Endian::Little,
            32,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_name() {
        assert_eq!(ArmLanguageProvider::processor_name(), "ARM");
    }

    #[test]
    fn test_language_count() {
        let langs = ArmLanguageProvider::languages();
        assert_eq!(langs.len(), 20);
    }

    #[test]
    fn test_language_description_count() {
        let descs = ArmLanguageProvider::language_descriptions();
        assert_eq!(descs.len(), 20);
    }

    #[test]
    fn test_get_language_found() {
        let lang = ArmLanguageProvider::get_language("ARM:LE:32:v8");
        assert!(lang.is_some());
        let lang = lang.unwrap();
        assert_eq!(lang.pointer_size, 32);
        assert_eq!(lang.endian, Endian::Little);
    }

    #[test]
    fn test_get_language_not_found() {
        assert!(ArmLanguageProvider::get_language("nonexistent:LE:32:default").is_none());
    }

    #[test]
    fn test_is_language_loaded() {
        assert!(ArmLanguageProvider::is_language_loaded("ARM:LE:32:v8"));
        assert!(ArmLanguageProvider::is_language_loaded("ARM:BE:32:v7"));
        assert!(ArmLanguageProvider::is_language_loaded("ARM:LE:32:Cortex"));
        assert!(!ArmLanguageProvider::is_language_loaded("nonexistent:LE:32:default"));
    }

    #[test]
    fn test_default_language() {
        let lang = ArmLanguageProvider::default_language();
        assert_eq!(lang.id, "ARM:LE:32:v8");
        assert_eq!(lang.pointer_size, 32);
    }

    #[test]
    fn test_be_languages_exist() {
        let be_langs: Vec<_> = ArmLanguageProvider::languages()
            .into_iter()
            .filter(|l| l.endian == Endian::Big)
            .collect();
        assert!(!be_langs.is_empty(), "Expected big-endian ARM languages");
    }

    #[test]
    fn test_language_descriptions_have_processor() {
        for desc in ArmLanguageProvider::language_descriptions() {
            assert_eq!(desc.processor.name(), "ARM");
            assert_eq!(desc.processor.family(), "ARM");
        }
    }
}
