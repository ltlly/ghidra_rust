//! x86 Language Provider
//!
//! Provides the [`X86LanguageProvider`] which implements the [`LanguageProvider`]
//! trait for x86/x86-64 processor languages.
//!
//! ## Supported Languages
//!
//! | Language ID                   | Description                              |
//! |-------------------------------|------------------------------------------|
//! | `x86:LE:16:RealMode`          | 16-bit real mode (8086)                  |
//! | `x86:LE:32:default`           | 32-bit protected mode                    |
//! | `x86:LE:32:Protected`         | 32-bit protected mode (detailed)         |
//! | `x86:LE:32:SystemManagement`  | 32-bit system management mode            |
//! | `x86:LE:64:default`           | 64-bit long mode                         |
//! | `x86:LE:64:LongMode`          | 64-bit long mode (detailed)              |

use crate::common::{
    CompilerSpecDescription, Endian, Language, LanguageDescription, LanguageID, LanguageProvider,
    Processor,
};

/// Language provider for x86/x86-64 processors.
///
/// Migrates the Java `x86` processor language definitions into Rust.
pub struct X86LanguageProvider;

impl X86LanguageProvider {
    /// The processor name constant.
    pub const PROCESSOR_NAME: &'static str = "x86";

    /// Processor family.
    pub const FAMILY: &'static str = "x86";

    /// All language IDs supported by this provider.
    pub const LANGUAGE_IDS: [&'static str; 6] = [
        "x86:LE:16:RealMode",
        "x86:LE:32:default",
        "x86:LE:32:Protected",
        "x86:LE:32:SystemManagement",
        "x86:LE:64:default",
        "x86:LE:64:LongMode",
    ];

    fn build_languages() -> Vec<Language> {
        vec![
            Language::new(
                "x86:LE:16:RealMode",
                "x86 16-bit Real Mode (8086)",
                "RealMode",
                Endian::Little,
                16,
            ),
            Language::new(
                "x86:LE:32:default",
                "x86 32-bit Protected Mode",
                "default",
                Endian::Little,
                32,
            )
            .with_pc_register("EIP")
            .with_instruction_alignment(1),
            Language::new(
                "x86:LE:32:Protected",
                "x86 32-bit Protected Mode (detailed)",
                "Protected",
                Endian::Little,
                32,
            )
            .with_pc_register("EIP")
            .with_instruction_alignment(1),
            Language::new(
                "x86:LE:32:SystemManagement",
                "x86 32-bit System Management Mode",
                "SystemManagement",
                Endian::Little,
                32,
            )
            .with_pc_register("EIP")
            .with_instruction_alignment(1),
            Language::new(
                "x86:LE:64:default",
                "x86-64 Long Mode",
                "default",
                Endian::Little,
                64,
            )
            .with_pc_register("RIP")
            .with_instruction_alignment(1),
            Language::new(
                "x86:LE:64:LongMode",
                "x86-64 Long Mode (detailed)",
                "LongMode",
                Endian::Little,
                64,
            )
            .with_pc_register("RIP")
            .with_instruction_alignment(1),
        ]
    }

    fn build_language_descriptions() -> Vec<LanguageDescription> {
        let proc = Processor::new(
            Self::PROCESSOR_NAME,
            "Intel/AMD x86 and x86-64 processor family",
            Self::FAMILY,
        );
        let default_cs = CompilerSpecDescription::default_spec("gcc");

        vec![
            LanguageDescription::new(
                LanguageID::new("x86:LE:16:RealMode"),
                proc.clone(),
                Endian::Little,
                16,
                "RealMode",
                "x86 16-bit Real Mode (8086)",
            )
            .with_compiler_spec(default_cs.clone()),
            LanguageDescription::new(
                LanguageID::new("x86:LE:32:default"),
                proc.clone(),
                Endian::Little,
                32,
                "default",
                "x86 32-bit Protected Mode",
            )
            .with_compiler_spec(default_cs.clone()),
            LanguageDescription::new(
                LanguageID::new("x86:LE:32:Protected"),
                proc.clone(),
                Endian::Little,
                32,
                "Protected",
                "x86 32-bit Protected Mode (detailed)",
            )
            .with_compiler_spec(default_cs.clone()),
            LanguageDescription::new(
                LanguageID::new("x86:LE:32:SystemManagement"),
                proc.clone(),
                Endian::Little,
                32,
                "SystemManagement",
                "x86 32-bit System Management Mode",
            )
            .with_compiler_spec(default_cs.clone()),
            LanguageDescription::new(
                LanguageID::new("x86:LE:64:default"),
                proc.clone(),
                Endian::Little,
                64,
                "default",
                "x86-64 Long Mode",
            )
            .with_compiler_spec(default_cs.clone()),
            LanguageDescription::new(
                LanguageID::new("x86:LE:64:LongMode"),
                proc.clone(),
                Endian::Little,
                64,
                "LongMode",
                "x86-64 Long Mode (detailed)",
            )
            .with_compiler_spec(default_cs.clone()),
        ]
    }
}

impl LanguageProvider for X86LanguageProvider {
    fn processor_name() -> &'static str {
        Self::PROCESSOR_NAME
    }

    fn processor_description() -> &'static str {
        "Intel/AMD x86 and x86-64 processor family"
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
            "x86:LE:64:default",
            "x86-64 Long Mode",
            "default",
            Endian::Little,
        64,
        )
        .with_pc_register("RIP")
        .with_instruction_alignment(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_name() {
        assert_eq!(X86LanguageProvider::processor_name(), "x86");
    }

    #[test]
    fn test_language_count() {
        let langs = X86LanguageProvider::languages();
        assert_eq!(langs.len(), 6);
    }

    #[test]
    fn test_language_description_count() {
        let descs = X86LanguageProvider::language_descriptions();
        assert_eq!(descs.len(), 6);
    }

    #[test]
    fn test_get_language_found() {
        let lang = X86LanguageProvider::get_language("x86:LE:64:default");
        assert!(lang.is_some());
        let lang = lang.unwrap();
        assert_eq!(lang.pointer_size, 64);
        assert_eq!(lang.endian, Endian::Little);
        assert_eq!(lang.program_counter, "RIP");
    }

    #[test]
    fn test_get_language_not_found() {
        let lang = X86LanguageProvider::get_language("nonexistent:LE:32:default");
        assert!(lang.is_none());
    }

    #[test]
    fn test_is_language_loaded() {
        assert!(X86LanguageProvider::is_language_loaded("x86:LE:64:default"));
        assert!(X86LanguageProvider::is_language_loaded("x86:LE:32:default"));
        assert!(X86LanguageProvider::is_language_loaded("x86:LE:16:RealMode"));
        assert!(!X86LanguageProvider::is_language_loaded("nonexistent:LE:32:default"));
    }

    #[test]
    fn test_default_language() {
        let lang = X86LanguageProvider::default_language();
        assert_eq!(lang.id, "x86:LE:64:default");
        assert_eq!(lang.pointer_size, 64);
    }

    #[test]
    fn test_all_languages_little_endian() {
        for lang in X86LanguageProvider::languages() {
            assert_eq!(lang.endian, Endian::Little, "Expected LE for {}", lang.id);
        }
    }

    #[test]
    fn test_language_descriptions_have_processor() {
        for desc in X86LanguageProvider::language_descriptions() {
            assert_eq!(desc.processor.name(), "x86");
            assert_eq!(desc.processor.family(), "x86");
        }
    }
}
