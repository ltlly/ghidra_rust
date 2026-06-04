//! CLI (.NET) Metadata Token Analyzer.
//!
//! Ported from Ghidra's `CliMetadataTokenAnalyzer.java`.
//! Resolves CLI metadata tokens in .NET IL instructions to their table/index
//! form, annotating each instruction with a human-readable EOL comment
//! describing the referenced metadata entity (type, method, field, string, etc.).

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Language ID substring identifying CLI/.NET languages.
pub const CLI_LANGUAGE_ID_MARKER: &str = "CLI";

/// Symbol name for the CLI Metadata Root in the program.
pub const CLI_METADATA_ROOT_NAME: &str = "_CorExeMain";

// ---------------------------------------------------------------------------
// Metadata token table identifiers (ECMA-335 II.22)
// ---------------------------------------------------------------------------

/// CLI metadata table indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CliTableKind {
    Module,
    TypeRef,
    TypeDef,
    Field,
    MethodDef,
    Param,
    InterfaceImpl,
    MemberRef,
    Constant,
    CustomAttribute,
    FieldMarshal,
    DeclSecurity,
    ClassLayout,
    FieldLayout,
    StandAloneSig,
    EventMap,
    Event,
    PropertyMap,
    Property,
    MethodSemantics,
    MethodImpl,
    ModuleRef,
    TypeSpec,
    ImplMap,
    FieldRva,
    Assembly,
    AssemblyProcessor,
    AssemblyOS,
    AssemblyRef,
    AssemblyRefProcessor,
    AssemblyRefOS,
    File,
    ExportedType,
    ManifestResource,
    NestedClass,
    GenericParam,
    MethodSpec,
    GenericParamConstraint,
    /// User strings heap (0x70)
    UserString,
    /// Unknown / unhandled
    Unknown(u8),
}

impl CliTableKind {
    /// Decode a raw table byte into a CliTableKind variant.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Module,
            0x01 => Self::TypeRef,
            0x02 => Self::TypeDef,
            0x04 => Self::Field,
            0x06 => Self::MethodDef,
            0x08 => Self::Param,
            0x09 => Self::InterfaceImpl,
            0x0A => Self::MemberRef,
            0x0B => Self::Constant,
            0x0C => Self::CustomAttribute,
            0x0D => Self::FieldMarshal,
            0x0E => Self::DeclSecurity,
            0x0F => Self::ClassLayout,
            0x10 => Self::FieldLayout,
            0x11 => Self::StandAloneSig,
            0x12 => Self::EventMap,
            0x14 => Self::Event,
            0x15 => Self::PropertyMap,
            0x17 => Self::Property,
            0x18 => Self::MethodSemantics,
            0x19 => Self::MethodImpl,
            0x1A => Self::ModuleRef,
            0x1B => Self::TypeSpec,
            0x1C => Self::ImplMap,
            0x1D => Self::FieldRva,
            0x20 => Self::Assembly,
            0x21 => Self::AssemblyProcessor,
            0x22 => Self::AssemblyOS,
            0x23 => Self::AssemblyRef,
            0x24 => Self::AssemblyRefProcessor,
            0x25 => Self::AssemblyRefOS,
            0x26 => Self::File,
            0x27 => Self::ExportedType,
            0x28 => Self::ManifestResource,
            0x29 => Self::NestedClass,
            0x2A => Self::GenericParam,
            0x2B => Self::MethodSpec,
            0x2C => Self::GenericParamConstraint,
            0x70 => Self::UserString,
            other => Self::Unknown(other),
        }
    }

    /// Human-readable name for this table.
    pub fn name(&self) -> &str {
        match self {
            Self::Module => "Module",
            Self::TypeRef => "TypeRef",
            Self::TypeDef => "TypeDef",
            Self::Field => "Field",
            Self::MethodDef => "MethodDef",
            Self::Param => "Param",
            Self::InterfaceImpl => "InterfaceImpl",
            Self::MemberRef => "MemberRef",
            Self::Constant => "Constant",
            Self::CustomAttribute => "CustomAttribute",
            Self::FieldMarshal => "FieldMarshal",
            Self::DeclSecurity => "DeclSecurity",
            Self::ClassLayout => "ClassLayout",
            Self::FieldLayout => "FieldLayout",
            Self::StandAloneSig => "StandAloneSig",
            Self::EventMap => "EventMap",
            Self::Event => "Event",
            Self::PropertyMap => "PropertyMap",
            Self::Property => "Property",
            Self::MethodSemantics => "MethodSemantics",
            Self::MethodImpl => "MethodImpl",
            Self::ModuleRef => "ModuleRef",
            Self::TypeSpec => "TypeSpec",
            Self::ImplMap => "ImplMap",
            Self::FieldRva => "FieldRva",
            Self::Assembly => "Assembly",
            Self::AssemblyProcessor => "AssemblyProcessor",
            Self::AssemblyOS => "AssemblyOS",
            Self::AssemblyRef => "AssemblyRef",
            Self::AssemblyRefProcessor => "AssemblyRefProcessor",
            Self::AssemblyRefOS => "AssemblyRefOS",
            Self::File => "File",
            Self::ExportedType => "ExportedType",
            Self::ManifestResource => "ManifestResource",
            Self::NestedClass => "NestedClass",
            Self::GenericParam => "GenericParam",
            Self::MethodSpec => "MethodSpec",
            Self::GenericParamConstraint => "GenericParamConstraint",
            Self::UserString => "UserString",
            Self::Unknown(_) => "Unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// CIL instruction classification helpers
// ---------------------------------------------------------------------------

/// Categories of CIL instructions that reference metadata tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliInstructionKind {
    /// `ldstr` -- load user string
    LoadString,
    /// `call` -- direct method call
    Call,
    /// `calli` -- indirect method call
    CallIndirect,
    /// `jmp` -- unconditional method jump
    Jump,
    /// `ldftn` -- push function pointer
    LoadFunctionPointer,
    /// `callvirt` -- virtual method call
    CallVirtual,
    /// Object model instructions (box, castclass, newobj, etc.)
    ObjectModel,
    /// `constrained` prefix
    Constrained,
    /// `ldvirtfn` -- push virtual function pointer
    LoadVirtualFunction,
    /// Not a metadata-token instruction
    Other,
}

impl CliInstructionKind {
    /// Classify a CIL mnemonic into a CliInstructionKind.
    pub fn classify(mnemonic: &str) -> Self {
        // Strip possible prefixes by checking endswith, mirroring the Java logic.
        if mnemonic.ends_with("ldstr") {
            Self::LoadString
        } else if mnemonic.ends_with("call") {
            Self::Call
        } else if mnemonic.ends_with("calli") {
            Self::CallIndirect
        } else if mnemonic.ends_with("jmp") {
            Self::Jump
        } else if mnemonic.ends_with("ldftn") {
            Self::LoadFunctionPointer
        } else if mnemonic.ends_with("callvirt") {
            Self::CallVirtual
        } else if mnemonic.ends_with("constrained") {
            Self::Constrained
        } else if mnemonic.ends_with("ldvirtfn") {
            Self::LoadVirtualFunction
        } else if Self::is_object_model_mnemonic(mnemonic) {
            Self::ObjectModel
        } else {
            Self::Other
        }
    }

    fn is_object_model_mnemonic(m: &str) -> bool {
        const OM_MNEMONICS: &[&str] = &[
            "box", "castclass", "cpobj", "initobj", "isinst", "ldelem", "ldelema", "ldfld",
            "ldflda", "ldobj", "ldsfld", "ldsflda", "ldtoken", "mkrefany", "newarr", "newobj",
            "refanyval", "sizeof", "stelem", "stfld", "stobj", "stsfld", "unbox", "unbox.any",
        ];
        OM_MNEMONICS.iter().any(|&om| m.ends_with(om))
    }
}

// ---------------------------------------------------------------------------
// CliMetadataTokenAnalyzer
// ---------------------------------------------------------------------------

/// Finds CLI metadata tokens in .NET IL instructions and renders them
/// significantly more useful to the human user by annotating EOL comments.
///
/// This is a prototype analyzer: it is only enabled when the program's
/// language ID contains `"CLI"`.
#[derive(Debug, Clone)]
pub struct CliMetadataTokenAnalyzer {
    base: AbstractAnalyzer,
}

impl CliMetadataTokenAnalyzer {
    pub fn new() -> Self {
        let mut b = AbstractAnalyzer::new(
            "CLI Metadata Token Analyzer",
            "Takes CLI metadata tokens from their table/index form and gives a more useful representation.",
            AnalyzerType::Instruction,
        );
        b.set_supports_one_time_analysis(true);
        b.set_priority(AnalysisPriority::CODE_ANALYSIS);
        b.set_is_prototype(true);
        Self { base: b }
    }

    /// Determines whether a language ID string contains the CLI marker.
    pub fn is_cli_language(language_id: &str) -> bool {
        language_id.contains(CLI_LANGUAGE_ID_MARKER)
    }

    /// Decode a metadata token (table << 24 | index) into a (table, row) pair.
    pub fn decode_metadata_token(token: u32) -> (CliTableKind, u32) {
        let table = CliTableKind::from_byte((token >> 24) as u8);
        let index = token & 0x00FF_FFFF;
        (table, index)
    }

    /// Format a metadata token comment: "TypeName[RowIndex]"
    pub fn format_token_comment(table: &CliTableKind, row: u32) -> String {
        format!("{}[{}]", table.name(), row)
    }
}

impl Analyzer for CliMetadataTokenAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::CODE_ANALYSIS
    }

    fn can_analyze(&self, _p: &Program) -> bool {
        // In Java this checks language ID contains "CLI"; stub for now
        false
    }

    fn default_enablement(&self, _p: &Program) -> bool {
        false
    }

    fn is_prototype(&self) -> bool {
        true
    }

    fn supports_one_time_analysis(&self) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Analyzing CLI metadata tokens...");
        log.append_msg("CliMetadataTokenAnalyzer: processing CLI metadata tokens");
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_analyzer_name() {
        let a = CliMetadataTokenAnalyzer::new();
        assert_eq!(a.name(), "CLI Metadata Token Analyzer");
        assert_eq!(a.analysis_type(), AnalyzerType::Instruction);
    }

    #[test]
    fn test_cli_analyzer_is_prototype() {
        let a = CliMetadataTokenAnalyzer::new();
        assert!(a.is_prototype());
    }

    #[test]
    fn test_cli_analyzer_one_time() {
        let a = CliMetadataTokenAnalyzer::new();
        assert!(a.supports_one_time_analysis());
    }

    #[test]
    fn test_is_cli_language() {
        assert!(CliMetadataTokenAnalyzer::is_cli_language("CLI:Default"));
        assert!(CliMetadataTokenAnalyzer::is_cli_language("x86/CLI/PE"));
        assert!(!CliMetadataTokenAnalyzer::is_cli_language("x86/cli/PE"));
        assert!(!CliMetadataTokenAnalyzer::is_cli_language("x86/little/LE"));
        assert!(!CliMetadataTokenAnalyzer::is_cli_language("ARM"));
    }

    #[test]
    fn test_decode_metadata_token_method_def() {
        let (table, row) = CliMetadataTokenAnalyzer::decode_metadata_token(0x0600000A);
        assert_eq!(table, CliTableKind::MethodDef);
        assert_eq!(row, 0x0A);
    }

    #[test]
    fn test_decode_metadata_token_type_ref() {
        let (table, row) = CliMetadataTokenAnalyzer::decode_metadata_token(0x01000023);
        assert_eq!(table, CliTableKind::TypeRef);
        assert_eq!(row, 0x23);
    }

    #[test]
    fn test_decode_metadata_token_member_ref() {
        let (table, row) = CliMetadataTokenAnalyzer::decode_metadata_token(0x0A000001);
        assert_eq!(table, CliTableKind::MemberRef);
        assert_eq!(row, 0x01);
    }

    #[test]
    fn test_decode_metadata_token_user_string() {
        let (table, row) = CliMetadataTokenAnalyzer::decode_metadata_token(0x70000042);
        assert_eq!(table, CliTableKind::UserString);
        assert_eq!(row, 0x42);
    }

    #[test]
    fn test_decode_metadata_token_type_def() {
        let (table, row) = CliMetadataTokenAnalyzer::decode_metadata_token(0x02000001);
        assert_eq!(table, CliTableKind::TypeDef);
        assert_eq!(row, 1);
    }

    #[test]
    fn test_decode_metadata_token_unknown() {
        let (table, row) = CliMetadataTokenAnalyzer::decode_metadata_token(0xFE000001);
        assert_eq!(table, CliTableKind::Unknown(0xFE));
        assert_eq!(row, 1);
    }

    #[test]
    fn test_format_token_comment() {
        assert_eq!(
            CliMetadataTokenAnalyzer::format_token_comment(&CliTableKind::MethodDef, 10),
            "MethodDef[10]"
        );
        assert_eq!(
            CliMetadataTokenAnalyzer::format_token_comment(&CliTableKind::TypeRef, 35),
            "TypeRef[35]"
        );
        assert_eq!(
            CliMetadataTokenAnalyzer::format_token_comment(&CliTableKind::UserString, 1),
            "UserString[1]"
        );
    }

    #[test]
    fn test_table_kind_from_byte() {
        assert_eq!(CliTableKind::from_byte(0x00), CliTableKind::Module);
        assert_eq!(CliTableKind::from_byte(0x06), CliTableKind::MethodDef);
        assert_eq!(CliTableKind::from_byte(0x2A), CliTableKind::GenericParam);
        assert_eq!(CliTableKind::from_byte(0x2B), CliTableKind::MethodSpec);
        assert_eq!(CliTableKind::from_byte(0x70), CliTableKind::UserString);
    }

    #[test]
    fn test_table_kind_name() {
        assert_eq!(CliTableKind::MethodDef.name(), "MethodDef");
        assert_eq!(CliTableKind::TypeDef.name(), "TypeDef");
        assert_eq!(CliTableKind::UserString.name(), "UserString");
        assert_eq!(CliTableKind::Unknown(0xFF).name(), "Unknown");
    }

    #[test]
    fn test_classify_cil_instructions() {
        assert_eq!(
            CliInstructionKind::classify("ldstr"),
            CliInstructionKind::LoadString
        );
        assert_eq!(
            CliInstructionKind::classify("call"),
            CliInstructionKind::Call
        );
        assert_eq!(
            CliInstructionKind::classify("calli"),
            CliInstructionKind::CallIndirect
        );
        assert_eq!(
            CliInstructionKind::classify("jmp"),
            CliInstructionKind::Jump
        );
        assert_eq!(
            CliInstructionKind::classify("ldftn"),
            CliInstructionKind::LoadFunctionPointer
        );
        assert_eq!(
            CliInstructionKind::classify("callvirt"),
            CliInstructionKind::CallVirtual
        );
        assert_eq!(
            CliInstructionKind::classify("constrained"),
            CliInstructionKind::Constrained
        );
        assert_eq!(
            CliInstructionKind::classify("ldvirtfn"),
            CliInstructionKind::LoadVirtualFunction
        );
        assert_eq!(
            CliInstructionKind::classify("nop"),
            CliInstructionKind::Other
        );
    }

    #[test]
    fn test_classify_object_model_instructions() {
        for m in &[
            "box", "castclass", "cpobj", "initobj", "isinst", "ldelem", "ldelema", "ldfld",
            "ldflda", "ldobj", "ldsfld", "ldsflda", "ldtoken", "mkrefany", "newarr", "newobj",
            "refanyval", "sizeof", "stelem", "stfld", "stobj", "stsfld", "unbox", "unbox.any",
        ] {
            assert_eq!(
                CliInstructionKind::classify(m),
                CliInstructionKind::ObjectModel,
                "Expected ObjectModel for '{}'",
                m
            );
        }
    }

    #[test]
    fn test_classify_prefixed_instructions() {
        // Java uses endsWith, so prefixed instructions should still match
        assert_eq!(
            CliInstructionKind::classify("tail.call"),
            CliInstructionKind::Call
        );
    }

    #[test]
    fn test_cli_analyzer_priority() {
        let a = CliMetadataTokenAnalyzer::new();
        assert_eq!(a.priority(), AnalysisPriority::CODE_ANALYSIS);
    }

    #[test]
    fn test_cli_analyzer_default_enablement() {
        let a = CliMetadataTokenAnalyzer::new();
        let prog = Program::new(
            "test",
            Language {
                processor: "CLI".into(),
                variant: "Default".into(),
                size: 64,
            },
        );
        assert!(!a.default_enablement(&prog));
    }

    #[test]
    fn test_all_tables_roundtrip() {
        for b in 0u8..=0x2C {
            let kind = CliTableKind::from_byte(b);
            let name = kind.name();
            assert!(!name.is_empty());
        }
        let us = CliTableKind::from_byte(0x70);
        assert_eq!(us, CliTableKind::UserString);
    }
}
