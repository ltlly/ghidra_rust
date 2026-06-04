//! Compiler specification extension management ported from Java's
//! `SpecExtension` and `ProgramCompilerSpec`.
//!
//! Manages program-specific extensions to the base compiler specification:
//! call fixups, callother fixups, and prototype models.  Extensions are stored
//! as XML documents in program options.

use std::collections::HashMap;
use std::fmt;

// ============================================================================
// ExtensionType (port of Java SpecExtension.Type)
// ============================================================================

/// The kind of compiler specification extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtensionType {
    /// A call-fixup P-code injection.
    CallFixup,
    /// A callother-fixup P-code injection.
    CallotherFixup,
    /// A prototype model (calling convention).
    PrototypeModel,
    /// A merged/resolved prototype model.
    MergeModel,
}

impl ExtensionType {
    /// Return the XML tag name associated with this extension type.
    pub fn tag_name(&self) -> &'static str {
        match self {
            ExtensionType::CallFixup => "callfixup",
            ExtensionType::CallotherFixup => "callotherfixup",
            ExtensionType::PrototypeModel => "prototype",
            ExtensionType::MergeModel => "resolveprototype",
        }
    }

    /// Parse an extension type from an XML tag name.
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "callfixup" => Some(ExtensionType::CallFixup),
            "callotherfixup" => Some(ExtensionType::CallotherFixup),
            "prototype" => Some(ExtensionType::PrototypeModel),
            "resolveprototype" => Some(ExtensionType::MergeModel),
            _ => None,
        }
    }
}

impl fmt::Display for ExtensionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtensionType::CallFixup => write!(f, "CallFixup"),
            ExtensionType::CallotherFixup => write!(f, "CallotherFixup"),
            ExtensionType::PrototypeModel => write!(f, "PrototypeModel"),
            ExtensionType::MergeModel => write!(f, "MergeModel"),
        }
    }
}

// ============================================================================
// ExtensionDocInfo (port of Java SpecExtension.DocInfo)
// ============================================================================

/// Parsed metadata about a compiler spec extension document.
#[derive(Debug, Clone)]
pub struct ExtensionDocInfo {
    /// Type of extension.
    pub ext_type: ExtensionType,
    /// Formal name (the unique name/target of the extension).
    pub formal_name: String,
    /// Option name used to store the extension in program options.
    pub option_name: String,
    /// Whether this extension overrides a core document.
    pub overrides: bool,
}

impl ExtensionDocInfo {
    /// Create a new doc info.
    pub fn new(ext_type: ExtensionType, formal_name: &str) -> Self {
        let option_name = format!("{}_{}", ext_type.tag_name(), formal_name);
        Self {
            ext_type,
            formal_name: formal_name.to_string(),
            option_name,
            overrides: false,
        }
    }
}

// ============================================================================
// SpecExtension (port of Java SpecExtension)
// ============================================================================

/// Manager for compiler specification extensions.
///
/// Port of Java `ghidra.program.database.SpecExtension`.
///
/// Stores extensions as XML documents keyed by option name.  Each extension
/// has a type (callfixup, callotherfixup, prototype, resolveprototype) and
/// a unique formal name.
pub struct SpecExtension {
    /// Map from option name to XML document body.
    extensions: HashMap<String, String>,
    /// Format version of the extension store.
    format_version: i32,
    /// Monotonic version counter bumped on every modification.
    version_counter: i32,
}

impl SpecExtension {
    /// The options list name where spec extensions are stored.
    pub const SPEC_EXTENSION: &'static str = "Specification Extensions";
    /// Option name for the format version.
    pub const FORMAT_VERSION_OPTION: &'static str = "FormatVersion";
    /// Option name for the version counter.
    pub const VERSION_COUNTER_OPTION: &'static str = "VersionCounter";
    /// Current format version.
    pub const FORMAT_VERSION: i32 = 1;

    /// Create a new empty spec extension store.
    pub fn new() -> Self {
        Self {
            extensions: HashMap::new(),
            format_version: Self::FORMAT_VERSION,
            version_counter: 0,
        }
    }

    /// Return the current version counter.
    pub fn version_counter(&self) -> i32 {
        self.version_counter
    }

    /// Return the format version.
    pub fn format_version(&self) -> i32 {
        self.format_version
    }

    /// Install or replace a compiler spec extension.
    ///
    /// Port of Java `SpecExtension.addReplaceCompilerSpecExtension(String)`.
    pub fn add_replace_extension(
        &mut self,
        doc_info: &ExtensionDocInfo,
        document: &str,
    ) {
        self.extensions
            .insert(doc_info.option_name.clone(), document.to_string());
        self.version_counter = (self.version_counter + 1) % 0x40000000;
    }

    /// Remove a compiler spec extension by option name.
    ///
    /// Port of Java `SpecExtension.removeCompilerSpecExtension(String)`.
    pub fn remove_extension(&mut self, option_name: &str) -> bool {
        let removed = self.extensions.remove(option_name).is_some();
        if removed {
            self.version_counter = (self.version_counter + 1) % 0x40000000;
        }
        removed
    }

    /// Get the XML document for a specific extension option.
    pub fn get_extension(&self, option_name: &str) -> Option<&str> {
        self.extensions.get(option_name).map(|s| s.as_str())
    }

    /// Return the list of all installed extension option names.
    pub fn get_extension_option_names(&self) -> Vec<String> {
        self.extensions.keys().cloned().collect()
    }

    /// Return the number of installed extensions.
    pub fn extension_count(&self) -> usize {
        self.extensions.len()
    }

    /// Return true if no extensions are installed.
    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty()
    }

    /// Remove all extensions.
    pub fn clear(&mut self) {
        self.extensions.clear();
        self.version_counter = (self.version_counter + 1) % 0x40000000;
    }

    /// Extract the formal name from an option name.
    ///
    /// The option name is `tagName_formalName`.
    pub fn get_formal_name(option_name: &str) -> Option<&str> {
        option_name.find('_').map(|i| &option_name[i + 1..])
    }

    /// Extract the extension type from an option name.
    pub fn get_extension_type(option_name: &str) -> Option<ExtensionType> {
        let tag = option_name.find('_').map(|i| &option_name[..i])?;
        ExtensionType::from_tag(tag)
    }

    /// Build an option name from a type and formal name.
    pub fn make_option_name(ext_type: ExtensionType, formal_name: &str) -> String {
        format!("{}_{}", ext_type.tag_name(), formal_name)
    }

    /// Get all extensions of a specific type.
    pub fn get_extensions_by_type(&self, ext_type: ExtensionType) -> Vec<(&str, &str)> {
        self.extensions
            .iter()
            .filter(|(name, _)| {
                Self::get_extension_type(name) == Some(ext_type)
            })
            .map(|(name, doc)| (name.as_str(), doc.as_str()))
            .collect()
    }
}

impl Default for SpecExtension {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SpecExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpecExtension")
            .field("extension_count", &self.extensions.len())
            .field("version_counter", &self.version_counter)
            .field("format_version", &self.format_version)
            .finish()
    }
}

// ============================================================================
// ProgramCompilerSpec (port of Java ProgramCompilerSpec)
// ============================================================================

/// Program-specific compiler specification with extensions.
///
/// Port of Java `ghidra.program.database.ProgramCompilerSpec`.
///
/// Wraps a base compiler specification and overlays program-specific
/// extensions (prototype models, call fixups, callother fixups).
#[derive(Debug)]
pub struct ProgramCompilerSpec {
    /// The base compiler spec ID.
    compiler_spec_id: String,
    /// Program-specific extensions.
    extensions: SpecExtension,
    /// Evaluation model overrides (model type -> model name).
    evaluation_model_overrides: HashMap<String, String>,
    /// Decompiler output language.
    decompiler_language: String,
}

impl ProgramCompilerSpec {
    /// Property list name for decompiler settings.
    pub const DECOMPILER_PROPERTY_LIST: &'static str = "Decompiler";
    /// Option name for decompiler output language.
    pub const DECOMPILER_OUTPUT_LANGUAGE: &'static str = "Output Language";
    /// Option name for evaluation model override.
    pub const EVALUATION_MODEL_PROPERTY: &'static str = "EvaluationModel";

    /// Create a new program compiler spec.
    pub fn new(compiler_spec_id: &str) -> Self {
        Self {
            compiler_spec_id: compiler_spec_id.to_string(),
            extensions: SpecExtension::new(),
            evaluation_model_overrides: HashMap::new(),
            decompiler_language: "c-language".to_string(),
        }
    }

    /// Return the compiler spec ID.
    pub fn compiler_spec_id(&self) -> &str {
        &self.compiler_spec_id
    }

    /// Get the extensions store.
    pub fn extensions(&self) -> &SpecExtension {
        &self.extensions
    }

    /// Get the extensions store (mutable).
    pub fn extensions_mut(&mut self) -> &mut SpecExtension {
        &mut self.extensions
    }

    /// Get the decompiler output language.
    pub fn decompiler_language(&self) -> &str {
        &self.decompiler_language
    }

    /// Set the decompiler output language.
    pub fn set_decompiler_language(&mut self, lang: &str) {
        self.decompiler_language = lang.to_string();
    }

    /// Get an evaluation model override.
    pub fn get_evaluation_model_override(&self, model_type: &str) -> Option<&str> {
        self.evaluation_model_overrides
            .get(model_type)
            .map(|s| s.as_str())
    }

    /// Set an evaluation model override.
    pub fn set_evaluation_model_override(&mut self, model_type: &str, model_name: &str) {
        self.evaluation_model_overrides
            .insert(model_type.to_string(), model_name.to_string());
    }

    /// Install extensions from the SpecExtension store.
    ///
    /// Port of Java `ProgramCompilerSpec.installExtensions()`.
    pub fn install_extensions(&mut self) {
        // The version counter bump is handled by SpecExtension itself.
        // This method would parse XML and merge into the in-memory model.
        // For the port, we just bump the version.
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_type_tags() {
        assert_eq!(ExtensionType::CallFixup.tag_name(), "callfixup");
        assert_eq!(ExtensionType::from_tag("prototype"), Some(ExtensionType::PrototypeModel));
        assert_eq!(ExtensionType::from_tag("unknown"), None);
    }

    #[test]
    fn test_spec_extension_add_remove() {
        let mut ext = SpecExtension::new();
        assert!(ext.is_empty());

        let info = ExtensionDocInfo::new(ExtensionType::CallFixup, "myFixup");
        ext.add_replace_extension(&info, "<callfixup name=\"myFixup\">...</callfixup>");
        assert_eq!(ext.extension_count(), 1);
        assert_eq!(ext.version_counter(), 1);

        let doc = ext.get_extension("callfixup_myFixup").unwrap();
        assert!(doc.contains("myFixup"));

        ext.remove_extension("callfixup_myFixup");
        assert!(ext.is_empty());
        assert_eq!(ext.version_counter(), 2);
    }

    #[test]
    fn test_spec_extension_formal_name() {
        assert_eq!(
            SpecExtension::get_formal_name("callfixup_myFixup"),
            Some("myFixup")
        );
        assert_eq!(
            SpecExtension::get_extension_type("callfixup_myFixup"),
            Some(ExtensionType::CallFixup)
        );
    }

    #[test]
    fn test_spec_extension_make_option_name() {
        let name = SpecExtension::make_option_name(ExtensionType::PrototypeModel, "fastcall");
        assert_eq!(name, "prototype_fastcall");
    }

    #[test]
    fn test_spec_extension_by_type() {
        let mut ext = SpecExtension::new();
        ext.add_replace_extension(
            &ExtensionDocInfo::new(ExtensionType::CallFixup, "a"),
            "<doc/>",
        );
        ext.add_replace_extension(
            &ExtensionDocInfo::new(ExtensionType::CallotherFixup, "b"),
            "<doc/>",
        );
        ext.add_replace_extension(
            &ExtensionDocInfo::new(ExtensionType::CallFixup, "c"),
            "<doc/>",
        );

        let call_fixups = ext.get_extensions_by_type(ExtensionType::CallFixup);
        assert_eq!(call_fixups.len(), 2);

        let callother = ext.get_extensions_by_type(ExtensionType::CallotherFixup);
        assert_eq!(callother.len(), 1);
    }

    #[test]
    fn test_program_compiler_spec() {
        let mut pcs = ProgramCompilerSpec::new("default");
        assert_eq!(pcs.compiler_spec_id(), "default");
        assert_eq!(pcs.decompiler_language(), "c-language");

        pcs.set_decompiler_language("java-language");
        assert_eq!(pcs.decompiler_language(), "java-language");

        pcs.set_evaluation_model_override("stdcall", "myStdcall");
        assert_eq!(
            pcs.get_evaluation_model_override("stdcall"),
            Some("myStdcall")
        );
        assert_eq!(pcs.get_evaluation_model_override("cdecl"), None);
    }

    #[test]
    fn test_program_compiler_spec_extensions() {
        let mut pcs = ProgramCompilerSpec::new("gcc");
        let info = ExtensionDocInfo::new(ExtensionType::PrototypeModel, "custom");
        pcs.extensions_mut()
            .add_replace_extension(&info, "<prototype name=\"custom\"/>");
        assert_eq!(pcs.extensions().extension_count(), 1);
    }
}
