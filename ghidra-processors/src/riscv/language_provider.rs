//! RISC-V Language Provider
//!
//! Provides the [`RiscVLanguageProvider`] which implements the [`LanguageProvider`]
//! trait for RISC-V processor languages.
//!
//! ## Supported Languages
//!
//! Covers RV32 and RV64 with multiple extension combinations
//! including I, M, A, F, D, C, Zba, Zbb, and V.

use crate::common::{
    CompilerSpecDescription, Endian, Language, LanguageDescription, LanguageID, LanguageProvider,
    Processor,
};

/// Language provider for RISC-V processors.
pub struct RiscVLanguageProvider;

impl RiscVLanguageProvider {
    /// The processor name constant.
    pub const PROCESSOR_NAME: &'static str = "RISC-V";

    /// Processor family.
    pub const FAMILY: &'static str = "RISC-V";

    /// All language IDs supported by this provider.
    pub const LANGUAGE_IDS: [&'static str; 12] = [
        "RISCV:LE:64:default",
        "RISCV:LE:32:default",
        "RISCV:LE:32:RV32I",
        "RISCV:LE:32:RV32IMAC",
        "RISCV:LE:32:RV32G",
        "RISCV:LE:32:RV32GC",
        "RISCV:LE:64:RV64I",
        "RISCV:LE:64:RV64IMAC",
        "RISCV:LE:64:RV64G",
        "RISCV:LE:64:RV64GC",
        "RISCV:LE:64:RV64GC_Zba_Zbb",
        "RISCV:LE:64:RV64GCV",
    ];

    fn build_languages() -> Vec<Language> {
        vec![
            Language::new(
                "RISCV:LE:64:default",
                "RISC-V 64 little default",
                "1.4",
                Endian::Little,
                64,
            )
            .with_pc_register("pc"),
            Language::new(
                "RISCV:LE:32:default",
                "RISC-V 32 little default",
                "1.4",
                Endian::Little,
                32,
            )
            .with_pc_register("pc"),
            Language::new(
                "RISCV:LE:32:RV32I",
                "RISC-V 32-bit RV32I (Little Endian)",
                "RV32I",
                Endian::Little,
                32,
            )
            .with_pc_register("pc"),
            Language::new(
                "RISCV:LE:32:RV32IMAC",
                "RISC-V 32-bit RV32IMAC (Little Endian)",
                "RV32IMAC",
                Endian::Little,
                32,
            )
            .with_pc_register("pc"),
            Language::new(
                "RISCV:LE:32:RV32G",
                "RISC-V 32-bit RV32G (Little Endian)",
                "RV32G",
                Endian::Little,
                32,
            )
            .with_pc_register("pc"),
            Language::new(
                "RISCV:LE:32:RV32GC",
                "RISC-V 32-bit RV32GC (Little Endian)",
                "RV32GC",
                Endian::Little,
                32,
            )
            .with_pc_register("pc"),
            Language::new(
                "RISCV:LE:64:RV64I",
                "RISC-V 64-bit RV64I (Little Endian)",
                "RV64I",
                Endian::Little,
                64,
            )
            .with_pc_register("pc"),
            Language::new(
                "RISCV:LE:64:RV64IMAC",
                "RISC-V 64-bit RV64IMAC (Little Endian)",
                "RV64IMAC",
                Endian::Little,
                64,
            )
            .with_pc_register("pc"),
            Language::new(
                "RISCV:LE:64:RV64G",
                "RISC-V 64-bit RV64G (Little Endian)",
                "RV64G",
                Endian::Little,
                64,
            )
            .with_pc_register("pc"),
            Language::new(
                "RISCV:LE:64:RV64GC",
                "RISC-V 64-bit RV64GC (Little Endian)",
                "RV64GC",
                Endian::Little,
                64,
            )
            .with_pc_register("pc"),
            Language::new(
                "RISCV:LE:64:RV64GC_Zba_Zbb",
                "RISC-V 64-bit RV64GC+Zba+Zbb (Little Endian)",
                "RV64GCB",
                Endian::Little,
                64,
            )
            .with_pc_register("pc"),
            Language::new(
                "RISCV:LE:64:RV64GCV",
                "RISC-V 64-bit RV64GC+V (Little Endian)",
                "RV64GCV",
                Endian::Little,
                64,
            )
            .with_pc_register("pc"),
        ]
    }

    fn build_language_descriptions() -> Vec<LanguageDescription> {
        let proc = Processor::new(
            Self::PROCESSOR_NAME,
            "RISC-V 32/64-bit processor family including extensions RV32I, RV64I, M, A, F, D, C, Zicsr, V",
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

impl LanguageProvider for RiscVLanguageProvider {
    fn processor_name() -> &'static str {
        Self::PROCESSOR_NAME
    }

    fn processor_description() -> &'static str {
        "RISC-V 32/64-bit processor family including extensions RV32I, RV64I, M, A, F, D, C, Zicsr, V"
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
            "RISCV:LE:64:default",
            "RISC-V 64 little default",
            "1.4",
            Endian::Little,
            64,
        )
        .with_pc_register("pc")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_name() {
        assert_eq!(RiscVLanguageProvider::processor_name(), "RISC-V");
    }

    #[test]
    fn test_language_count() {
        let langs = RiscVLanguageProvider::languages();
        assert_eq!(langs.len(), 12);
    }

    #[test]
    fn test_language_description_count() {
        let descs = RiscVLanguageProvider::language_descriptions();
        assert_eq!(descs.len(), 12);
    }

    #[test]
    fn test_get_language_found() {
        let lang = RiscVLanguageProvider::get_language("RISCV:LE:64:RV64GC");
        assert!(lang.is_some());
        let lang = lang.unwrap();
        assert_eq!(lang.pointer_size, 64);
        assert_eq!(lang.endian, Endian::Little);
    }

    #[test]
    fn test_get_language_not_found() {
        assert!(RiscVLanguageProvider::get_language("nonexistent:LE:32:default").is_none());
    }

    #[test]
    fn test_is_language_loaded() {
        assert!(RiscVLanguageProvider::is_language_loaded("RISCV:LE:64:default"));
        assert!(RiscVLanguageProvider::is_language_loaded("RISCV:LE:32:RV32I"));
        assert!(RiscVLanguageProvider::is_language_loaded("RISCV:LE:64:RV64GCV"));
        assert!(!RiscVLanguageProvider::is_language_loaded("nonexistent:LE:32:default"));
    }

    #[test]
    fn test_default_language() {
        let lang = RiscVLanguageProvider::default_language();
        assert_eq!(lang.id, "RISCV:LE:64:default");
        assert_eq!(lang.pointer_size, 64);
    }

    #[test]
    fn test_language_descriptions_have_processor() {
        for desc in RiscVLanguageProvider::language_descriptions() {
            assert_eq!(desc.processor.name(), "RISC-V");
            assert_eq!(desc.processor.family(), "RISC-V");
        }
    }

    #[test]
    fn test_32bit_languages_exist() {
        let lang32: Vec<_> = RiscVLanguageProvider::languages()
            .into_iter()
            .filter(|l| l.pointer_size == 32)
            .collect();
        assert!(!lang32.is_empty(), "Expected 32-bit RISC-V languages");
    }
}
