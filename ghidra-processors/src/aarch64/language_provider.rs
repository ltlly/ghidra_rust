//! AARCH64 Language Provider
//!
//! Provides the [`Aarch64LanguageProvider`] which implements the [`LanguageProvider`]
//! trait for ARM 64-bit (AArch64) processor languages.
//!
//! ## Supported Languages
//!
//! | Language ID                        | Description                               |
//! |------------------------------------|-------------------------------------------|
//! | `AARCH64:LE:64:v8A`               | Generic ARM64 v8.5-A LE                   |
//! | `AARCH64:BE:64:v8A`               | Generic ARM64 v8.5-A BE data              |
//! | `AARCH64:LE:32:ilp32`             | ARM64 v8.5-A LE ilp32 (32-bit pointers)   |
//! | `AARCH64:BE:32:ilp32`             | ARM64 v8.5-A BE ilp32 (32-bit pointers)   |
//! | `AARCH64:LE:64:AppleSilicon`      | Apple Silicon ARM v8.5-A with AMX         |

use crate::common::{
    CompilerSpecDescription, Endian, Language, LanguageDescription, LanguageID, LanguageProvider,
    Processor,
};

/// Language provider for AARCH64 (ARM 64-bit) processors.
///
/// Migrates the Java `AARCH64` processor language definitions into Rust.
pub struct Aarch64LanguageProvider;

impl Aarch64LanguageProvider {
    /// The processor name constant.
    pub const PROCESSOR_NAME: &'static str = "AARCH64";

    /// Processor family.
    pub const FAMILY: &'static str = "ARM";

    /// All language IDs supported by this provider.
    pub const LANGUAGE_IDS: [&'static str; 5] = [
        "AARCH64:LE:64:v8A",
        "AARCH64:BE:64:v8A",
        "AARCH64:LE:32:ilp32",
        "AARCH64:BE:32:ilp32",
        "AARCH64:LE:64:AppleSilicon",
    ];

    fn build_languages() -> Vec<Language> {
        vec![
            // --- v8A (primary 64-bit) ---
            Language::new(
                "AARCH64:LE:64:v8A",
                "Generic ARM64 v8.5-A LE instructions, LE data",
                "v8A",
                Endian::Little,
                64,
            )
            .with_pc_register("PC")
            .with_instruction_alignment(4),
            // Big-endian data, little-endian instructions
            Language::new(
                "AARCH64:BE:64:v8A",
                "Generic ARM64 v8.5-A LE instructions, BE data",
                "v8A",
                Endian::Big,
                64,
            )
            .with_pc_register("PC")
            .with_instruction_alignment(4),
            // --- ILP32 (32-bit pointers) ---
            Language::new(
                "AARCH64:LE:32:ilp32",
                "Generic ARM64 v8.5-A LE instructions, LE data, ilp32",
                "ilp32",
                Endian::Little,
                32,
            )
            .with_pc_register("PC")
            .with_instruction_alignment(4),
            Language::new(
                "AARCH64:BE:32:ilp32",
                "Generic ARM64 v8.5-A LE instructions, BE data, ilp32",
                "ilp32",
                Endian::Big,
                32,
            )
            .with_pc_register("PC")
            .with_instruction_alignment(4),
            // --- Apple Silicon ---
            Language::new(
                "AARCH64:LE:64:AppleSilicon",
                "AppleSilicon ARM v8.5-A LE instructions, LE data, AMX extensions",
                "AppleSilicon",
                Endian::Little,
                64,
            )
            .with_pc_register("PC")
            .with_instruction_alignment(4),
        ]
    }

    fn build_language_descriptions() -> Vec<LanguageDescription> {
        let proc = Processor::new(
            Self::PROCESSOR_NAME,
            "ARM 64-bit processor family (AArch64), including SIMD/FP and cryptographic extensions",
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

impl LanguageProvider for Aarch64LanguageProvider {
    fn processor_name() -> &'static str {
        Self::PROCESSOR_NAME
    }

    fn processor_description() -> &'static str {
        "ARM 64-bit processor family (AArch64), including SIMD/FP and cryptographic extensions"
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
            "AARCH64:LE:64:v8A",
            "Generic ARM64 v8.5-A LE instructions, LE data",
            "v8A",
            Endian::Little,
            64,
        )
        .with_pc_register("PC")
        .with_instruction_alignment(4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_name() {
        assert_eq!(Aarch64LanguageProvider::processor_name(), "AARCH64");
    }

    #[test]
    fn test_language_count() {
        let langs = Aarch64LanguageProvider::languages();
        assert_eq!(langs.len(), 5);
    }

    #[test]
    fn test_language_description_count() {
        let descs = Aarch64LanguageProvider::language_descriptions();
        assert_eq!(descs.len(), 5);
    }

    #[test]
    fn test_get_language_found() {
        let lang = Aarch64LanguageProvider::get_language("AARCH64:LE:64:v8A");
        assert!(lang.is_some());
        let lang = lang.unwrap();
        assert_eq!(lang.pointer_size, 64);
        assert_eq!(lang.endian, Endian::Little);
        assert_eq!(lang.program_counter, "PC");
    }

    #[test]
    fn test_get_language_not_found() {
        assert!(Aarch64LanguageProvider::get_language("nonexistent:LE:64:default").is_none());
    }

    #[test]
    fn test_is_language_loaded() {
        assert!(Aarch64LanguageProvider::is_language_loaded("AARCH64:LE:64:v8A"));
        assert!(Aarch64LanguageProvider::is_language_loaded("AARCH64:LE:32:ilp32"));
        assert!(Aarch64LanguageProvider::is_language_loaded("AARCH64:LE:64:AppleSilicon"));
        assert!(!Aarch64LanguageProvider::is_language_loaded("nonexistent:LE:64:default"));
    }

    #[test]
    fn test_default_language() {
        let lang = Aarch64LanguageProvider::default_language();
        assert_eq!(lang.id, "AARCH64:LE:64:v8A");
        assert_eq!(lang.pointer_size, 64);
        assert_eq!(lang.instruction_alignment, 4);
    }

    #[test]
    fn test_ilp32_languages() {
        let ilp32 = Aarch64LanguageProvider::get_language("AARCH64:LE:32:ilp32").unwrap();
        assert_eq!(ilp32.pointer_size, 32);
    }

    #[test]
    fn test_all_languages_have_4byte_alignment() {
        for lang in Aarch64LanguageProvider::languages() {
            assert_eq!(
                lang.instruction_alignment, 4,
                "Expected 4-byte alignment for {}",
                lang.id
            );
        }
    }

    #[test]
    fn test_language_descriptions_have_processor() {
        for desc in Aarch64LanguageProvider::language_descriptions() {
            assert_eq!(desc.processor.name(), "AARCH64");
        }
    }
}
