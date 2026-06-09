//! PowerPC Language Provider
//!
//! Provides the [`PowerPcLanguageProvider`] which implements the [`LanguageProvider`]
//! trait for PowerPC processor languages.
//!
//! ## Supported Languages
//!
//! Covers PowerPC 32-bit and 64-bit in big-endian and little-endian
//! configurations, including 4xx embedded, QUICC, e500, e500mc, Power ISA A2,
//! and VLE variants.

use crate::common::{
    CompilerSpecDescription, Endian, Language, LanguageDescription, LanguageID, LanguageProvider,
    Processor,
};

/// Language provider for PowerPC processors.
///
/// Migrates the Java `PowerPC` processor language definitions into Rust.
pub struct PowerPcLanguageProvider;

impl PowerPcLanguageProvider {
    /// The processor name constant.
    pub const PROCESSOR_NAME: &'static str = "PowerPC";

    /// Processor family.
    pub const FAMILY: &'static str = "PowerPC";

    /// All language IDs supported by this provider.
    pub const LANGUAGE_IDS: [&'static str; 23] = [
        "PowerPC:BE:32:default",
        "PowerPC:LE:32:default",
        "PowerPC:BE:64:default",
        "PowerPC:LE:64:default",
        "PowerPC:BE:64:64-32addr",
        "PowerPC:LE:64:64-32addr",
        "PowerPC:BE:32:4xx",
        "PowerPC:LE:32:4xx",
        "PowerPC:BE:32:MPC8270",
        "PowerPC:BE:32:QUICC",
        "PowerPC:LE:32:QUICC",
        "PowerPC:BE:32:e500",
        "PowerPC:LE:32:e500",
        "PowerPC:BE:32:e500mc",
        "PowerPC:LE:32:e500mc",
        "PowerPC:BE:64:A2-32addr",
        "PowerPC:LE:64:A2-32addr",
        "PowerPC:BE:64:A2ALT-32addr",
        "PowerPC:LE:64:A2ALT-32addr",
        "PowerPC:BE:64:A2ALT",
        "PowerPC:LE:64:A2ALT",
        "PowerPC:BE:64:VLE-32addr",
        "PowerPC:BE:64:VLEALT-32addr",
    ];

    fn build_languages() -> Vec<Language> {
        vec![
            // -- 32-bit default --
            Language::new("PowerPC:BE:32:default", "PowerPC 32-bit big endian w/Altivec, G2", "1.7", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("PowerPC:LE:32:default", "PowerPC 32-bit little endian w/Altivec, G2", "1.7", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- 64-bit default --
            Language::new("PowerPC:BE:64:default", "PowerPC 64-bit big endian w/Altivec, G2", "1.7", Endian::Big, 64)
                .with_pc_register("PC"),
            Language::new("PowerPC:LE:64:default", "PowerPC 64-bit little endian w/Altivec, G2", "1.7", Endian::Little, 64)
                .with_pc_register("PC"),
            // -- 64-bit with 32-bit addressing --
            Language::new("PowerPC:BE:64:64-32addr", "PowerPC 64-bit big endian w/Altivec and 32 bit addressing, G2", "1.7", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("PowerPC:LE:64:64-32addr", "PowerPC 64-bit little endian w/Altivec and 32 bit addressing, G2", "1.7", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- 4xx embedded --
            Language::new("PowerPC:BE:32:4xx", "PowerPC 4xx 32-bit big endian embedded core", "1.7", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("PowerPC:LE:32:4xx", "PowerPC 4xx 32-bit little endian embedded core", "1.7", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- MPC8270 --
            Language::new("PowerPC:BE:32:MPC8270", "Freescale MPC8280 32-bit big endian family (PowerQUICC-III)", "1.7", Endian::Big, 32)
                .with_pc_register("PC"),
            // -- PowerQUICC-III --
            Language::new("PowerPC:BE:32:QUICC", "PowerQUICC-III 32-bit big endian family", "1.7", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("PowerPC:LE:32:QUICC", "PowerQUICC-III 32-bit little endian family", "1.7", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- e500 --
            Language::new("PowerPC:BE:32:e500", "PowerQUICC-III e500 32-bit big-endian family", "1.7", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("PowerPC:LE:32:e500", "PowerQUICC-III e500 32-bit little-endian family", "1.7", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- e500mc --
            Language::new("PowerPC:BE:32:e500mc", "PowerQUICC-III e500mc 32-bit big-endian family", "1.7", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("PowerPC:LE:32:e500mc", "PowerQUICC-III e500mc 32-bit little-endian family", "1.7", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- Power ISA A2 (EVX, 32-bit addressing) --
            Language::new("PowerPC:BE:64:A2-32addr", "Power ISA 3.0 Big Endian w/EVX and 32-bit Addressing", "1.7", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("PowerPC:LE:64:A2-32addr", "Power ISA 3.0 Little Endian w/EVX and 32-bit Addressing", "1.7", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- Power ISA A2+Altivec (32-bit addressing) --
            Language::new("PowerPC:BE:64:A2ALT-32addr", "Power ISA 3.0 Big Endian w/Altivec and 32-bit Addressing", "1.7", Endian::Big, 32)
                .with_pc_register("PC"),
            Language::new("PowerPC:LE:64:A2ALT-32addr", "Power ISA 3.0 Little Endian w/Altivec and 32-bit Addressing", "1.7", Endian::Little, 32)
                .with_pc_register("PC"),
            // -- Power ISA A2+Altivec (64-bit) --
            Language::new("PowerPC:BE:64:A2ALT", "Power ISA 3.0 Big Endian w/Altivec", "1.7", Endian::Big, 64)
                .with_pc_register("PC"),
            Language::new("PowerPC:LE:64:A2ALT", "Power ISA 3.0 Little Endian w/Altivec", "1.7", Endian::Little, 64)
                .with_pc_register("PC"),
            // -- Power ISA VLE (32-bit addressing) --
            Language::new("PowerPC:BE:64:VLE-32addr", "Power ISA 3.0 Big Endian w/VLE, EVX and 32-bit Addressing", "1.7", Endian::Big, 32)
                .with_pc_register("PC"),
            // -- Power ISA VLE+Altivec (32-bit addressing) --
            Language::new("PowerPC:BE:64:VLEALT-32addr", "Power ISA 3.0 Big Endian w/VLE, Altivec and 32-bit Addressing", "1.7", Endian::Big, 32)
                .with_pc_register("PC"),
        ]
    }

    fn build_language_descriptions() -> Vec<LanguageDescription> {
        let proc = Processor::new(
            Self::PROCESSOR_NAME,
            "PowerPC 32/64-bit processor family including VMX/Altivec, VSX, VLE, DFP, and EABI",
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

impl LanguageProvider for PowerPcLanguageProvider {
    fn processor_name() -> &'static str {
        Self::PROCESSOR_NAME
    }

    fn processor_description() -> &'static str {
        "PowerPC 32/64-bit processor family including VMX/Altivec, VSX, VLE, DFP, and EABI"
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
            "PowerPC:BE:32:default",
            "PowerPC 32-bit big endian w/Altivec, G2",
            "1.7",
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
        assert_eq!(PowerPcLanguageProvider::processor_name(), "PowerPC");
    }

    #[test]
    fn test_language_count() {
        let langs = PowerPcLanguageProvider::languages();
        assert_eq!(langs.len(), 23);
    }

    #[test]
    fn test_language_description_count() {
        let descs = PowerPcLanguageProvider::language_descriptions();
        assert_eq!(descs.len(), 23);
    }

    #[test]
    fn test_get_language_found() {
        let lang = PowerPcLanguageProvider::get_language("PowerPC:BE:64:default");
        assert!(lang.is_some());
        let lang = lang.unwrap();
        assert_eq!(lang.pointer_size, 64);
        assert_eq!(lang.endian, Endian::Big);
    }

    #[test]
    fn test_get_language_not_found() {
        assert!(PowerPcLanguageProvider::get_language("nonexistent:BE:32:default").is_none());
    }

    #[test]
    fn test_is_language_loaded() {
        assert!(PowerPcLanguageProvider::is_language_loaded("PowerPC:BE:32:default"));
        assert!(PowerPcLanguageProvider::is_language_loaded("PowerPC:LE:64:default"));
        assert!(PowerPcLanguageProvider::is_language_loaded("PowerPC:BE:32:e500"));
        assert!(!PowerPcLanguageProvider::is_language_loaded("nonexistent:BE:32:default"));
    }

    #[test]
    fn test_default_language() {
        let lang = PowerPcLanguageProvider::default_language();
        assert_eq!(lang.id, "PowerPC:BE:32:default");
        assert_eq!(lang.pointer_size, 32);
        assert_eq!(lang.endian, Endian::Big);
    }

    #[test]
    fn test_variant_types_present() {
        let ids: Vec<&str> = PowerPcLanguageProvider::LANGUAGE_IDS.to_vec();
        // 4xx embedded
        assert!(ids.iter().any(|id| id.contains("4xx")));
        // QUICC
        assert!(ids.iter().any(|id| id.contains("QUICC")));
        // e500
        assert!(ids.iter().any(|id| id.contains("e500")));
        // A2
        assert!(ids.iter().any(|id| id.contains("A2")));
        // VLE
        assert!(ids.iter().any(|id| id.contains("VLE")));
    }

    #[test]
    fn test_be_le_pairs() {
        // Check that most variants have both BE and LE versions
        let be_count = PowerPcLanguageProvider::languages()
            .iter()
            .filter(|l| l.endian == Endian::Big)
            .count();
        let le_count = PowerPcLanguageProvider::languages()
            .iter()
            .filter(|l| l.endian == Endian::Little)
            .count();
        assert!(be_count > 0, "Expected big-endian PowerPC languages");
        assert!(le_count > 0, "Expected little-endian PowerPC languages");
    }

    #[test]
    fn test_language_descriptions_have_processor() {
        for desc in PowerPcLanguageProvider::language_descriptions() {
            assert_eq!(desc.processor.name(), "PowerPC");
            assert_eq!(desc.processor.family(), "PowerPC");
        }
    }
}
