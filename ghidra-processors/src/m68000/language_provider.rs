//! Motorola 68000 Family Language Provider
//!
//! Provides the [`M68000LanguageProvider`] which implements the [`LanguageProvider`]
//! trait for Motorola 68000 family processor languages.
//!
//! ## Supported Languages
//!
//! Covers MC68000 through MC68060, ColdFire V1-V5, and CPU32,
//! all big-endian 32-bit.

use crate::common::{
    CompilerSpecDescription, Endian, Language, LanguageDescription, LanguageID, LanguageProvider,
    Processor,
};

/// Language provider for Motorola 68000 family processors.
pub struct M68000LanguageProvider;

impl M68000LanguageProvider {
    /// The processor name constant.
    pub const PROCESSOR_NAME: &'static str = "Motorola 68000 Family";

    /// Processor family.
    pub const FAMILY: &'static str = "68000";

    /// All language IDs supported by this provider.
    pub const LANGUAGE_IDS: [&'static str; 12] = [
        "m68000:BE:32:68000",
        "m68000:BE:32:68010",
        "m68000:BE:32:68020",
        "m68000:BE:32:68030",
        "m68000:BE:32:68040",
        "m68000:BE:32:68060",
        "m68000:BE:32:ColdFire_V1",
        "m68000:BE:32:ColdFire_V2",
        "m68000:BE:32:ColdFire_V3",
        "m68000:BE:32:ColdFire_V4",
        "m68000:BE:32:ColdFire_V5",
        "m68000:BE:32:CPU32",
    ];

    fn build_languages() -> Vec<Language> {
        vec![
            Language::new(
                "m68000:BE:32:68000",
                "Motorola 68000",
                "68000",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68000:BE:32:68010",
                "Motorola 68010",
                "68010",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68000:BE:32:68020",
                "Motorola 68020",
                "68020",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68000:BE:32:68030",
                "Motorola 68030 (MMU)",
                "68030",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68000:BE:32:68040",
                "Motorola 68040 (FPU+MMU)",
                "68040",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68000:BE:32:68060",
                "Motorola 68060 (Superscalar)",
                "68060",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68000:BE:32:ColdFire_V1",
                "ColdFire V1",
                "CFv1",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68000:BE:32:ColdFire_V2",
                "ColdFire V2 (MAC)",
                "CFv2",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68000:BE:32:ColdFire_V3",
                "ColdFire V3",
                "CFv3",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68000:BE:32:ColdFire_V4",
                "ColdFire V4 (EMAC)",
                "CFv4",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68000:BE:32:ColdFire_V5",
                "ColdFire V5",
                "CFv5",
                Endian::Big,
                32,
            ),
            Language::new(
                "m68000:BE:32:CPU32",
                "CPU32 (68300 family)",
                "CPU32",
                Endian::Big,
                32,
            ),
        ]
    }

    fn build_language_descriptions() -> Vec<LanguageDescription> {
        let proc = Processor::new(
            Self::PROCESSOR_NAME,
            "Motorola 68000 processor family from 68000 through 68060 and ColdFire",
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

impl LanguageProvider for M68000LanguageProvider {
    fn processor_name() -> &'static str {
        Self::PROCESSOR_NAME
    }

    fn processor_description() -> &'static str {
        "Motorola 68000 processor family from 68000 through 68060 and ColdFire"
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
            "m68000:BE:32:68000",
            "Motorola 68000",
            "68000",
            Endian::Big,
            32,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_name() {
        assert_eq!(M68000LanguageProvider::processor_name(), "Motorola 68000 Family");
    }

    #[test]
    fn test_language_count() {
        let langs = M68000LanguageProvider::languages();
        assert_eq!(langs.len(), 12);
    }

    #[test]
    fn test_language_description_count() {
        let descs = M68000LanguageProvider::language_descriptions();
        assert_eq!(descs.len(), 12);
    }

    #[test]
    fn test_get_language_found() {
        let lang = M68000LanguageProvider::get_language("m68000:BE:32:68040");
        assert!(lang.is_some());
        let lang = lang.unwrap();
        assert_eq!(lang.pointer_size, 32);
        assert_eq!(lang.endian, Endian::Big);
    }

    #[test]
    fn test_get_language_not_found() {
        assert!(M68000LanguageProvider::get_language("nonexistent:LE:32:default").is_none());
    }

    #[test]
    fn test_is_language_loaded() {
        assert!(M68000LanguageProvider::is_language_loaded("m68000:BE:32:68000"));
        assert!(M68000LanguageProvider::is_language_loaded("m68000:BE:32:ColdFire_V4"));
        assert!(!M68000LanguageProvider::is_language_loaded("nonexistent:LE:32:default"));
    }

    #[test]
    fn test_default_language() {
        let lang = M68000LanguageProvider::default_language();
        assert_eq!(lang.id, "m68000:BE:32:68000");
        assert_eq!(lang.pointer_size, 32);
        assert_eq!(lang.endian, Endian::Big);
    }

    #[test]
    fn test_all_big_endian() {
        for lang in M68000LanguageProvider::languages() {
            assert_eq!(lang.endian, Endian::Big, "M68000 should be big-endian: {}", lang.id);
        }
    }

    #[test]
    fn test_coldfire_variants() {
        let cf_langs: Vec<_> = M68000LanguageProvider::languages()
            .into_iter()
            .filter(|l| l.id.contains("ColdFire"))
            .collect();
        assert_eq!(cf_langs.len(), 5);
    }

    #[test]
    fn test_language_descriptions_have_processor() {
        for desc in M68000LanguageProvider::language_descriptions() {
            assert_eq!(desc.processor.name(), "Motorola 68000 Family");
            assert_eq!(desc.processor.family(), "68000");
        }
    }
}
