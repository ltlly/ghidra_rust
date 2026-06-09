//! Language specification types for Ghidra's build infrastructure.
//!
//! Port of Ghidra's `ghidra.program.model.lang.LanguageDescription`,
//! `BasicLanguageDescription`, `CompilerSpecDescription`, and related types
//! from the SoftwareModeling framework.
//!
//! A [`LanguageSpec`] describes a processor language as declared in a `.ldefs`
//! XML file. It captures the language identity, processor family, endianness,
//! address size, variant, versioning, compatible compiler specifications,
//! external tool names, and optional truncation rules.

use std::collections::HashMap;
use std::fmt;

// ============================================================================
// Endian
// ============================================================================

/// Processor endianness.
///
/// Corresponds to `ghidra.program.model.lang.Endian`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    /// Parse an endianness string ("LE" / "BE" / "little" / "big").
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "LE" | "LITTLE" | "LITTLEENDIAN" => Some(Self::Little),
            "BE" | "BIG" | "BIGENDIAN" => Some(Self::Big),
            _ => None,
        }
    }

    /// Returns true if this is little-endian.
    pub fn is_little(self) -> bool {
        matches!(self, Self::Little)
    }

    /// Returns true if this is big-endian.
    pub fn is_big(self) -> bool {
        matches!(self, Self::Big)
    }
}

impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Little => write!(f, "LE"),
            Self::Big => write!(f, "BE"),
        }
    }
}

// ============================================================================
// LanguageSpecID
// ============================================================================

/// Uniquely identifies a language specification.
///
/// Corresponds to `ghidra.program.model.lang.LanguageID`. Takes the form
/// `processor:endian:size:variant`, e.g. `"x86:LE:64:default"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LanguageSpecID {
    /// The processor family (e.g., "x86", "ARM", "MIPS").
    pub processor: String,
    /// The endianness.
    pub endian: Endian,
    /// Address size in bits.
    pub size: usize,
    /// Variant name (e.g., "default", "v7").
    pub variant: String,
}

impl LanguageSpecID {
    /// Create a new language spec ID.
    pub fn new(
        processor: impl Into<String>,
        endian: Endian,
        size: usize,
        variant: impl Into<String>,
    ) -> Self {
        Self {
            processor: processor.into(),
            endian,
            size,
            variant: variant.into(),
        }
    }

    /// Parse from the canonical `processor:endian:size:variant` string.
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 4 {
            return None;
        }
        let endian = Endian::parse(parts[1])?;
        let size: usize = parts[2].parse().ok()?;
        Some(Self::new(parts[0], endian, size, parts[3]))
    }

    /// Convenience: x86 64-bit little-endian default.
    pub fn x86_64() -> Self {
        Self::new("x86", Endian::Little, 64, "default")
    }

    /// Convenience: x86 32-bit little-endian default.
    pub fn x86_32() -> Self {
        Self::new("x86", Endian::Little, 32, "default")
    }

    /// Convenience: ARM 32-bit little-endian v7.
    pub fn arm_v7() -> Self {
        Self::new("ARM", Endian::Little, 32, "v7")
    }

    /// Convenience: AARCH64 64-bit little-endian default.
    pub fn aarch64() -> Self {
        Self::new("AARCH64", Endian::Little, 64, "default")
    }
}

impl fmt::Display for LanguageSpecID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}:{}", self.processor, self.endian, self.size, self.variant)
    }
}

// ============================================================================
// CompilerSpecID
// ============================================================================

/// Identifies a compiler specification within a language.
///
/// Corresponds to `ghidra.program.model.lang.CompilerSpecID`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CompilerSpecID(pub String);

impl CompilerSpecID {
    /// Create a new compiler spec ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The default GCC compiler spec.
    pub fn default_gcc() -> Self {
        Self("default".to_string())
    }

    /// The Windows compiler spec.
    pub fn windows() -> Self {
        Self("windows".to_string())
    }
}

impl fmt::Display for CompilerSpecID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for CompilerSpecID {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<&str> for CompilerSpecID {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for CompilerSpecID {
    fn from(s: String) -> Self {
        Self(s)
    }
}

// ============================================================================
// CompilerSpecDescription
// ============================================================================

/// Description of a compatible compiler specification.
///
/// Corresponds to `ghidra.program.model.lang.CompilerSpecDescription`.
/// Each entry in a `.ldefs` `<compiler>` element maps to one of these.
#[derive(Debug, Clone)]
pub struct CompilerSpecDescription {
    /// The compiler spec identifier.
    pub id: CompilerSpecID,
    /// Human-readable name (e.g., "default", "Visual Studio").
    pub name: String,
    /// Path to the `.cspec` file (relative to the language directory).
    pub spec_file: String,
}

impl CompilerSpecDescription {
    /// Create a new compiler spec description.
    pub fn new(
        id: impl Into<CompilerSpecID>,
        name: impl Into<String>,
        spec_file: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            spec_file: spec_file.into(),
        }
    }
}

// ============================================================================
// TruncateSpace
// ============================================================================

/// A truncation rule for an address space.
///
/// Corresponds to `<truncate_space>` entries in `.ldefs` files.
#[derive(Debug, Clone)]
pub struct TruncateSpace {
    /// The address space name.
    pub space: String,
    /// The truncated size in bytes.
    pub size: usize,
}

// ============================================================================
// LanguageSpec
// ============================================================================

/// A language specification loaded from a `.ldefs` file.
///
/// Corresponds to a combination of `LanguageDescription` (interface) and
/// `BasicLanguageDescription` (concrete class) from Ghidra's Java source.
///
/// Each `<language>` element in a `.ldefs` XML file produces one `LanguageSpec`.
#[derive(Debug, Clone)]
pub struct LanguageSpec {
    /// The language identifier (e.g., "x86:LE:64:default").
    pub id: LanguageSpecID,
    /// The processor family name.
    pub processor: String,
    /// The data endianness.
    pub endian: Endian,
    /// The instruction endianness (may differ from data endian for some ISAs).
    pub instruction_endian: Endian,
    /// Address size in bits.
    pub size: usize,
    /// The variant name.
    pub variant: String,
    /// Human-readable description.
    pub description: String,
    /// Major version number.
    pub version: u32,
    /// Minor version number.
    pub minor_version: u32,
    /// Whether this language is deprecated.
    pub deprecated: bool,
    /// Whether this language is hidden (only visible in development mode).
    pub hidden: bool,
    /// The `.sla` (Sleigh assembly) file name.
    pub sla_file: String,
    /// The processor spec (`.pspec`) file name.
    pub processor_spec: String,
    /// The manual index file name (if any).
    pub manual_index_file: Option<String>,
    /// Compatible compiler specifications.
    pub compiler_specs: Vec<CompilerSpecDescription>,
    /// External tool name mappings (tool name -> list of names).
    pub external_names: HashMap<String, Vec<String>>,
    /// Address space truncation rules.
    pub truncate_spaces: Vec<TruncateSpace>,
}

impl LanguageSpec {
    /// Create a new language specification.
    pub fn new(
        id: LanguageSpecID,
        description: impl Into<String>,
        version: u32,
        minor_version: u32,
        sla_file: impl Into<String>,
        processor_spec: impl Into<String>,
    ) -> Self {
        let processor = id.processor.clone();
        let endian = id.endian;
        let size = id.size;
        let variant = id.variant.clone();
        Self {
            id,
            processor,
            endian,
            instruction_endian: endian,
            size,
            variant,
            description: description.into(),
            version,
            minor_version,
            deprecated: false,
            hidden: false,
            sla_file: sla_file.into(),
            processor_spec: processor_spec.into(),
            manual_index_file: None,
            compiler_specs: Vec::new(),
            external_names: HashMap::new(),
            truncate_spaces: Vec::new(),
        }
    }

    /// Set the instruction endianness (if different from data endian).
    pub fn with_instruction_endian(mut self, ie: Endian) -> Self {
        self.instruction_endian = ie;
        self
    }

    /// Mark this language as deprecated.
    pub fn with_deprecated(mut self, deprecated: bool) -> Self {
        self.deprecated = deprecated;
        self
    }

    /// Mark this language as hidden.
    pub fn with_hidden(mut self, hidden: bool) -> Self {
        self.hidden = hidden;
        self
    }

    /// Set the manual index file.
    pub fn with_manual_index(mut self, file: impl Into<String>) -> Self {
        self.manual_index_file = Some(file.into());
        self
    }

    /// Add a compiler spec description.
    pub fn add_compiler_spec(&mut self, cs: CompilerSpecDescription) {
        self.compiler_specs.push(cs);
    }

    /// Add an external name mapping.
    pub fn add_external_name(&mut self, tool: impl Into<String>, name: impl Into<String>) {
        self.external_names
            .entry(tool.into())
            .or_default()
            .push(name.into());
    }

    /// Add a truncation rule.
    pub fn add_truncate_space(&mut self, space: impl Into<String>, size: usize) {
        self.truncate_spaces.push(TruncateSpace {
            space: space.into(),
            size,
        });
    }

    /// Get the default compiler spec description (first in the list).
    pub fn default_compiler_spec(&self) -> Option<&CompilerSpecDescription> {
        self.compiler_specs.first()
    }

    /// Find a compiler spec by ID.
    pub fn get_compiler_spec(&self, id: &CompilerSpecID) -> Option<&CompilerSpecDescription> {
        self.compiler_specs.iter().find(|cs| cs.id == *id)
    }

    /// Get external names for a specific tool.
    pub fn get_external_names(&self, tool: &str) -> Option<&Vec<String>> {
        self.external_names.get(tool)
    }

    /// Returns true if this language uses big-endian byte order.
    pub fn is_big_endian(&self) -> bool {
        self.endian.is_big()
    }

    /// Returns the full version string (e.g., "1.0").
    pub fn version_string(&self) -> String {
        format!("{}.{}", self.version, self.minor_version)
    }
}

impl fmt::Display for LanguageSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} v{}.{} ({})", self.description, self.version, self.minor_version, self.id)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endian_parse() {
        assert_eq!(Endian::parse("LE"), Some(Endian::Little));
        assert_eq!(Endian::parse("BE"), Some(Endian::Big));
        assert_eq!(Endian::parse("little"), Some(Endian::Little));
        assert_eq!(Endian::parse("big"), Some(Endian::Big));
        assert_eq!(Endian::parse("unknown"), None);
    }

    #[test]
    fn test_endian_display() {
        assert_eq!(Endian::Little.to_string(), "LE");
        assert_eq!(Endian::Big.to_string(), "BE");
    }

    #[test]
    fn test_endian_checks() {
        assert!(Endian::Little.is_little());
        assert!(!Endian::Little.is_big());
        assert!(Endian::Big.is_big());
        assert!(!Endian::Big.is_little());
    }

    #[test]
    fn test_language_spec_id_new() {
        let id = LanguageSpecID::new("x86", Endian::Little, 64, "default");
        assert_eq!(id.processor, "x86");
        assert_eq!(id.endian, Endian::Little);
        assert_eq!(id.size, 64);
        assert_eq!(id.variant, "default");
    }

    #[test]
    fn test_language_spec_id_parse() {
        let id = LanguageSpecID::parse("x86:LE:64:default").unwrap();
        assert_eq!(id.processor, "x86");
        assert_eq!(id.endian, Endian::Little);
        assert_eq!(id.size, 64);
        assert_eq!(id.variant, "default");
    }

    #[test]
    fn test_language_spec_id_parse_invalid() {
        assert!(LanguageSpecID::parse("x86:LE").is_none());
        assert!(LanguageSpecID::parse("x86:LE:notanumber:default").is_none());
    }

    #[test]
    fn test_language_spec_id_to_string() {
        let id = LanguageSpecID::new("ARM", Endian::Big, 32, "v7");
        assert_eq!(id.to_string(), "ARM:BE:32:v7");
    }

    #[test]
    fn test_language_spec_id_convenience() {
        assert_eq!(LanguageSpecID::x86_64().to_string(), "x86:LE:64:default");
        assert_eq!(LanguageSpecID::x86_32().to_string(), "x86:LE:32:default");
        assert_eq!(LanguageSpecID::arm_v7().to_string(), "ARM:LE:32:v7");
        assert_eq!(LanguageSpecID::aarch64().to_string(), "AARCH64:LE:64:default");
    }

    #[test]
    fn test_compiler_spec_id() {
        let id = CompilerSpecID::new("default");
        assert_eq!(id.to_string(), "default");
        assert_eq!(id.as_ref(), "default");
        assert_eq!(CompilerSpecID::default_gcc().0, "default");
        assert_eq!(CompilerSpecID::windows().0, "windows");
    }

    #[test]
    fn test_compiler_spec_description() {
        let cs = CompilerSpecDescription::new("default", "default", "default.cspec");
        assert_eq!(cs.id.0, "default");
        assert_eq!(cs.name, "default");
        assert_eq!(cs.spec_file, "default.cspec");
    }

    #[test]
    fn test_language_spec_new() {
        let id = LanguageSpecID::x86_64();
        let spec = LanguageSpec::new(id, "x86 64-bit little-endian", 1, 0, "x86.sla", "x86.pspec");
        assert_eq!(spec.id.to_string(), "x86:LE:64:default");
        assert_eq!(spec.description, "x86 64-bit little-endian");
        assert_eq!(spec.version, 1);
        assert_eq!(spec.minor_version, 0);
        assert_eq!(spec.sla_file, "x86.sla");
        assert_eq!(spec.processor_spec, "x86.pspec");
        assert!(!spec.deprecated);
        assert!(!spec.hidden);
        assert!(spec.compiler_specs.is_empty());
    }

    #[test]
    fn test_language_spec_builder_methods() {
        let id = LanguageSpecID::new("MIPS", Endian::Big, 32, "default");
        let spec = LanguageSpec::new(id, "MIPS 32-bit", 1, 0, "mips.sla", "mips.pspec")
            .with_instruction_endian(Endian::Big)
            .with_deprecated(false)
            .with_hidden(false)
            .with_manual_index("mips_manual.idx");
        assert_eq!(spec.instruction_endian, Endian::Big);
        assert!(!spec.deprecated);
        assert!(spec.manual_index_file.is_some());
    }

    #[test]
    fn test_language_spec_compiler_specs() {
        let id = LanguageSpecID::x86_64();
        let mut spec = LanguageSpec::new(id, "x86-64", 1, 0, "x86.sla", "x86.pspec");
        spec.add_compiler_spec(CompilerSpecDescription::new("default", "default", "default.cspec"));
        spec.add_compiler_spec(CompilerSpecDescription::new("windows", "windows", "windows.cspec"));

        assert_eq!(spec.compiler_specs.len(), 2);
        assert_eq!(spec.default_compiler_spec().unwrap().id.0, "default");
        assert_eq!(
            spec.get_compiler_spec(&CompilerSpecID::new("windows")).unwrap().name,
            "windows"
        );
        assert!(spec.get_compiler_spec(&CompilerSpecID::new("missing")).is_none());
    }

    #[test]
    fn test_language_spec_external_names() {
        let id = LanguageSpecID::x86_64();
        let mut spec = LanguageSpec::new(id, "x86-64", 1, 0, "x86.sla", "x86.pspec");
        spec.add_external_name("IDA-PRO", "metapc");
        spec.add_external_name("IDA-PRO", "pc");
        spec.add_external_name("Radare2", "x86");

        let ida = spec.get_external_names("IDA-PRO").unwrap();
        assert_eq!(ida.len(), 2);
        assert_eq!(ida[0], "metapc");
        assert!(spec.get_external_names("nonexistent").is_none());
    }

    #[test]
    fn test_language_spec_truncate_spaces() {
        let id = LanguageSpecID::x86_64();
        let mut spec = LanguageSpec::new(id, "x86-64", 1, 0, "x86.sla", "x86.pspec");
        spec.add_truncate_space("ram", 32);
        assert_eq!(spec.truncate_spaces.len(), 1);
        assert_eq!(spec.truncate_spaces[0].space, "ram");
        assert_eq!(spec.truncate_spaces[0].size, 32);
    }

    #[test]
    fn test_language_spec_endian_checks() {
        let id = LanguageSpecID::new("MIPS", Endian::Big, 32, "default");
        let spec = LanguageSpec::new(id, "MIPS", 1, 0, "m.sla", "m.pspec");
        assert!(spec.is_big_endian());

        let id2 = LanguageSpecID::x86_64();
        let spec2 = LanguageSpec::new(id2, "x86", 1, 0, "x.sla", "x.pspec");
        assert!(!spec2.is_big_endian());
    }

    #[test]
    fn test_language_spec_version_string() {
        let id = LanguageSpecID::x86_64();
        let spec = LanguageSpec::new(id, "x86", 2, 3, "x.sla", "x.pspec");
        assert_eq!(spec.version_string(), "2.3");
    }

    #[test]
    fn test_language_spec_display() {
        let id = LanguageSpecID::x86_64();
        let spec = LanguageSpec::new(id, "x86 64-bit LE", 1, 0, "x.sla", "x.pspec");
        let s = format!("{}", spec);
        assert!(s.contains("x86 64-bit LE"));
        assert!(s.contains("x86:LE:64:default"));
    }

    #[test]
    fn test_truncate_space() {
        let ts = TruncateSpace {
            space: "register".to_string(),
            size: 4,
        };
        assert_eq!(ts.space, "register");
        assert_eq!(ts.size, 4);
    }
}
