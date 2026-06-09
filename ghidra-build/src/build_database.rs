//! Build database for Ghidra language and compiler specifications.
//!
//! Port of Ghidra's `DefaultLanguageService` and `SleighLanguageProvider`
//! registry pattern from `ghidra.program.model.lang` and
//! `ghidra.app.plugin.processors.sleigh`.
//!
//! The [`BuildDatabase`] acts as a central registry of all known language
//! specifications, compiler specifications, and processor definitions
//! available in a Ghidra installation. It is populated from `.ldefs` files
//! by [`BuildDatabaseFactory`](super::build_database_factory::BuildDatabaseFactory).

use std::collections::HashMap;
use std::fmt;

use super::language_spec::{CompilerSpecDescription, CompilerSpecID, Endian, LanguageSpec};

// ============================================================================
// Processor
// ============================================================================

/// A processor family (ISA grouping).
///
/// Corresponds to `ghidra.program.model.lang.Processor`.
///
/// Processors group related language variants. For example, "x86" covers
/// both 32-bit and 64-bit x86 languages, and "ARM" covers ARM and Thumb modes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Processor {
    /// The processor name (e.g., "x86", "ARM", "MIPS").
    name: String,
}

impl Processor {
    /// Create a new processor.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Get the processor name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// x86 processor family.
    pub fn x86() -> Self {
        Self::new("x86")
    }

    /// ARM processor family.
    pub fn arm() -> Self {
        Self::new("ARM")
    }

    /// AARCH64 (ARM 64-bit) processor family.
    pub fn aarch64() -> Self {
        Self::new("AARCH64")
    }

    /// MIPS processor family.
    pub fn mips() -> Self {
        Self::new("MIPS")
    }

    /// PowerPC processor family.
    pub fn powerpc() -> Self {
        Self::new("PowerPC")
    }

    /// RISC-V processor family.
    pub fn riscv() -> Self {
        Self::new("RISC-V")
    }
}

impl fmt::Display for Processor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl AsRef<str> for Processor {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

// ============================================================================
// LanguageService (trait)
// ============================================================================

/// Service interface for querying languages.
///
/// Corresponds to `ghidra.program.model.lang.LanguageService`.
pub trait LanguageService {
    /// Get a language spec by its ID string.
    fn get_language_spec(&self, id: &str) -> Option<&LanguageSpec>;

    /// Get the default language for a processor.
    fn get_default_language(&self, processor: &str) -> Option<&LanguageSpec>;

    /// Get all language specs.
    fn get_all_language_specs(&self) -> &[LanguageSpec];

    /// Get all non-deprecated language specs.
    fn get_active_language_specs(&self) -> Vec<&LanguageSpec>;

    /// Find language specs matching the given criteria.
    /// `None` values are treated as wildcards.
    fn find_language_specs(
        &self,
        processor: Option<&str>,
        endian: Option<Endian>,
        size: Option<usize>,
        variant: Option<&str>,
    ) -> Vec<&LanguageSpec>;

    /// Get all known processors.
    fn get_processors(&self) -> Vec<&Processor>;
}

// ============================================================================
// BuildDatabase
// ============================================================================

/// Central registry of language and compiler specifications.
///
/// Corresponds to the combined functionality of Ghidra's
/// `DefaultLanguageService` and `SleighLanguageProvider`.
///
/// The `BuildDatabase` stores all loaded [`LanguageSpec`] instances and
/// provides lookup methods for finding languages by ID, processor, or
/// other criteria. It also maintains a registry of known [`Processor`]s.
///
/// # Example
///
/// ```
/// use ghidra_build::build_database::BuildDatabase;
/// use ghidra_build::language_spec::{LanguageSpec, LanguageSpecID, Endian};
///
/// let mut db = BuildDatabase::new();
/// let spec = LanguageSpec::new(
///     LanguageSpecID::x86_64(),
///     "x86 64-bit",
///     1, 0,
///     "x86.sla",
///     "x86.pspec",
/// );
/// db.add_language_spec(spec);
///
/// assert!(db.get_language_spec("x86:LE:64:default").is_some());
/// assert_eq!(db.language_count(), 1);
/// ```
#[derive(Debug, Default)]
pub struct BuildDatabase {
    /// Language specs indexed by their string ID.
    specs: HashMap<String, LanguageSpec>,
    /// Known processors, indexed by name.
    processors: HashMap<String, Processor>,
    /// Ordered list of language IDs (preserves insertion order).
    ordered_ids: Vec<String>,
}

impl BuildDatabase {
    /// Create a new empty build database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a language specification to the database.
    ///
    /// If a language with the same ID already exists, it is replaced.
    pub fn add_language_spec(&mut self, spec: LanguageSpec) {
        let id_str = spec.id.to_string();

        // Register the processor if not already known
        self.processors
            .entry(spec.id.processor.clone())
            .or_insert_with(|| Processor::new(&spec.id.processor));

        if !self.specs.contains_key(&id_str) {
            self.ordered_ids.push(id_str.clone());
        }
        self.specs.insert(id_str, spec);
    }

    /// Remove a language specification by ID string.
    pub fn remove_language_spec(&mut self, id: &str) -> Option<LanguageSpec> {
        self.ordered_ids.retain(|x| x != id);
        self.specs.remove(id)
    }

    /// Get a language spec by its ID string.
    pub fn get_language_spec(&self, id: &str) -> Option<&LanguageSpec> {
        self.specs.get(id)
    }

    /// Get a mutable reference to a language spec by ID string.
    pub fn get_language_spec_mut(&mut self, id: &str) -> Option<&mut LanguageSpec> {
        self.specs.get_mut(id)
    }

    /// Get all language specs in insertion order.
    pub fn all_language_specs(&self) -> Vec<&LanguageSpec> {
        self.ordered_ids
            .iter()
            .filter_map(|id| self.specs.get(id))
            .collect()
    }

    /// Get all non-deprecated language specs.
    pub fn active_language_specs(&self) -> Vec<&LanguageSpec> {
        self.ordered_ids
            .iter()
            .filter_map(|id| self.specs.get(id))
            .filter(|s| !s.deprecated)
            .collect()
    }

    /// Get all deprecated language specs.
    pub fn deprecated_language_specs(&self) -> Vec<&LanguageSpec> {
        self.ordered_ids
            .iter()
            .filter_map(|id| self.specs.get(id))
            .filter(|s| s.deprecated)
            .collect()
    }

    /// Find language specs matching the given criteria.
    /// `None` values act as wildcards.
    pub fn find_language_specs(
        &self,
        processor: Option<&str>,
        endian: Option<Endian>,
        size: Option<usize>,
        variant: Option<&str>,
    ) -> Vec<&LanguageSpec> {
        self.ordered_ids
            .iter()
            .filter_map(|id| self.specs.get(id))
            .filter(|s| {
                processor.map_or(true, |p| s.processor == p)
                    && endian.map_or(true, |e| s.endian == e)
                    && size.map_or(true, |sz| s.size == sz)
                    && variant.map_or(true, |v| s.variant == v)
            })
            .collect()
    }

    /// Get all language specs for a given processor.
    pub fn get_languages_for_processor(&self, processor: &str) -> Vec<&LanguageSpec> {
        self.find_language_specs(Some(processor), None, None, None)
    }

    /// Get the default language for a processor.
    ///
    /// Returns the first non-deprecated language for the processor whose
    /// variant is "default", or the first non-deprecated language if no
    /// "default" variant exists.
    pub fn get_default_language(&self, processor: &str) -> Option<&LanguageSpec> {
        let specs = self.get_languages_for_processor(processor);
        // Prefer non-deprecated with "default" variant
        specs
            .iter()
            .find(|s| !s.deprecated && s.variant == "default")
            .or_else(|| specs.iter().find(|s| !s.deprecated))
            .copied()
    }

    /// Register a processor explicitly.
    pub fn register_processor(&mut self, processor: Processor) {
        self.processors
            .entry(processor.name().to_string())
            .or_insert(processor);
    }

    /// Get a processor by name.
    pub fn get_processor(&self, name: &str) -> Option<&Processor> {
        self.processors.get(name)
    }

    /// Get all known processors.
    pub fn get_all_processors(&self) -> Vec<&Processor> {
        self.processors.values().collect()
    }

    /// Get the number of loaded language specs.
    pub fn language_count(&self) -> usize {
        self.specs.len()
    }

    /// Get the number of known processors.
    pub fn processor_count(&self) -> usize {
        self.processors.len()
    }

    /// Returns true if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }

    /// Returns true if a language with the given ID exists.
    pub fn contains_language(&self, id: &str) -> bool {
        self.specs.contains_key(id)
    }

    /// Get all compiler spec IDs across all languages.
    ///
    /// Returns pairs of (language_id_string, compiler_spec_id).
    pub fn all_compiler_spec_ids(&self) -> Vec<(String, &CompilerSpecID)> {
        self.specs
            .values()
            .flat_map(|s| {
                let lang_id = s.id.to_string();
                s.compiler_specs
                    .iter()
                    .map(move |cs| (lang_id.clone(), &cs.id))
            })
            .collect()
    }

    /// Find the compiler spec description for a given language + compiler spec pair.
    pub fn get_compiler_spec(
        &self,
        language_id: &str,
        compiler_spec_id: &CompilerSpecID,
    ) -> Option<&CompilerSpecDescription> {
        self.specs
            .get(language_id)
            .and_then(|s| s.get_compiler_spec(compiler_spec_id))
    }
}

impl LanguageService for BuildDatabase {
    fn get_language_spec(&self, id: &str) -> Option<&LanguageSpec> {
        self.get_language_spec(id)
    }

    fn get_default_language(&self, processor: &str) -> Option<&LanguageSpec> {
        self.get_default_language(processor)
    }

    fn get_all_language_specs(&self) -> &[LanguageSpec] {
        // Note: this returns specs in HashMap iteration order, not insertion order.
        // For ordered access, use all_language_specs() instead.
        // This is a limitation of the trait returning a slice.
        // We work around it by using the ordered_ids approach in the direct methods.
        unimplemented!("Use all_language_specs() for ordered access")
    }

    fn get_active_language_specs(&self) -> Vec<&LanguageSpec> {
        self.active_language_specs()
    }

    fn find_language_specs(
        &self,
        processor: Option<&str>,
        endian: Option<Endian>,
        size: Option<usize>,
        variant: Option<&str>,
    ) -> Vec<&LanguageSpec> {
        self.find_language_specs(processor, endian, size, variant)
    }

    fn get_processors(&self) -> Vec<&Processor> {
        self.get_all_processors()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language_spec::{CompilerSpecDescription, LanguageSpec, LanguageSpecID};

    fn make_x86_64_spec() -> LanguageSpec {
        let id = LanguageSpecID::x86_64();
        let mut spec = LanguageSpec::new(id, "x86 64-bit LE", 1, 0, "x86.sla", "x86.pspec");
        spec.add_compiler_spec(CompilerSpecDescription::new("default", "default", "default.cspec"));
        spec.add_compiler_spec(CompilerSpecDescription::new("windows", "windows", "windows.cspec"));
        spec
    }

    fn make_x86_32_spec() -> LanguageSpec {
        let id = LanguageSpecID::x86_32();
        let mut spec = LanguageSpec::new(id, "x86 32-bit LE", 1, 0, "x86.sla", "x86.pspec");
        spec.add_compiler_spec(CompilerSpecDescription::new("default", "default", "default.cspec"));
        spec
    }

    fn make_arm_v7_spec() -> LanguageSpec {
        let id = LanguageSpecID::arm_v7();
        let mut spec = LanguageSpec::new(id, "ARM v7 LE", 1, 0, "arm.sla", "arm.pspec");
        spec.add_compiler_spec(CompilerSpecDescription::new("default", "default", "default.cspec"));
        spec
    }

    fn make_deprecated_spec() -> LanguageSpec {
        let id = LanguageSpecID::new("x86", Endian::Little, 16, "default");
        let spec = LanguageSpec::new(id, "x86 16-bit (deprecated)", 1, 0, "x86-16.sla", "x86-16.pspec")
            .with_deprecated(true);
        spec
    }

    #[test]
    fn test_build_database_new() {
        let db = BuildDatabase::new();
        assert!(db.is_empty());
        assert_eq!(db.language_count(), 0);
        assert_eq!(db.processor_count(), 0);
    }

    #[test]
    fn test_add_language_spec() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        assert_eq!(db.language_count(), 1);
        assert_eq!(db.processor_count(), 1);
        assert!(db.contains_language("x86:LE:64:default"));
    }

    #[test]
    fn test_get_language_spec() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        let spec = db.get_language_spec("x86:LE:64:default").unwrap();
        assert_eq!(spec.description, "x86 64-bit LE");
        assert!(db.get_language_spec("nonexistent").is_none());
    }

    #[test]
    fn test_remove_language_spec() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        assert_eq!(db.language_count(), 1);
        let removed = db.remove_language_spec("x86:LE:64:default");
        assert!(removed.is_some());
        assert!(db.is_empty());
        assert!(db.remove_language_spec("nonexistent").is_none());
    }

    #[test]
    fn test_get_language_spec_mut() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        let spec = db.get_language_spec_mut("x86:LE:64:default").unwrap();
        spec.description = "modified".to_string();
        assert_eq!(db.get_language_spec("x86:LE:64:default").unwrap().description, "modified");
    }

    #[test]
    fn test_all_language_specs_ordering() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_arm_v7_spec());
        db.add_language_spec(make_x86_64_spec());
        db.add_language_spec(make_x86_32_spec());
        let all = db.all_language_specs();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].id.to_string(), "ARM:LE:32:v7");
        assert_eq!(all[1].id.to_string(), "x86:LE:64:default");
        assert_eq!(all[2].id.to_string(), "x86:LE:32:default");
    }

    #[test]
    fn test_active_vs_deprecated() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        db.add_language_spec(make_deprecated_spec());
        assert_eq!(db.language_count(), 2);
        assert_eq!(db.active_language_specs().len(), 1);
        assert_eq!(db.deprecated_language_specs().len(), 1);
    }

    #[test]
    fn test_find_by_processor() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        db.add_language_spec(make_x86_32_spec());
        db.add_language_spec(make_arm_v7_spec());

        let x86 = db.find_language_specs(Some("x86"), None, None, None);
        assert_eq!(x86.len(), 2);
        let arm = db.find_language_specs(Some("ARM"), None, None, None);
        assert_eq!(arm.len(), 1);
    }

    #[test]
    fn test_find_by_endian_and_size() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        db.add_language_spec(make_x86_32_spec());
        db.add_language_spec(make_arm_v7_spec());

        let le64 = db.find_language_specs(None, Some(Endian::Little), Some(64), None);
        assert_eq!(le64.len(), 1);
        assert_eq!(le64[0].id.to_string(), "x86:LE:64:default");

        let le32 = db.find_language_specs(None, Some(Endian::Little), Some(32), None);
        assert_eq!(le32.len(), 2); // x86:32 and ARM:32
    }

    #[test]
    fn test_find_by_variant() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        db.add_language_spec(make_arm_v7_spec());

        let v7 = db.find_language_specs(None, None, None, Some("v7"));
        assert_eq!(v7.len(), 1);
        assert_eq!(v7[0].id.to_string(), "ARM:LE:32:v7");
    }

    #[test]
    fn test_find_wildcards() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        db.add_language_spec(make_arm_v7_spec());

        // All wildcards returns everything
        let all = db.find_language_specs(None, None, None, None);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_get_languages_for_processor() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        db.add_language_spec(make_x86_32_spec());
        db.add_language_spec(make_arm_v7_spec());

        let x86 = db.get_languages_for_processor("x86");
        assert_eq!(x86.len(), 2);
    }

    #[test]
    fn test_get_default_language() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        db.add_language_spec(make_x86_32_spec());

        let default = db.get_default_language("x86").unwrap();
        // Should prefer non-deprecated "default" variant
        assert_eq!(default.variant, "default");
        assert!(!default.deprecated);
    }

    #[test]
    fn test_get_default_language_missing() {
        let db = BuildDatabase::new();
        assert!(db.get_default_language("nonexistent").is_none());
    }

    #[test]
    fn test_processor_registration() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        // Processor auto-registered from language spec
        assert!(db.get_processor("x86").is_some());

        // Manual registration
        db.register_processor(Processor::riscv());
        assert!(db.get_processor("RISC-V").is_some());
    }

    #[test]
    fn test_get_all_processors() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        db.add_language_spec(make_arm_v7_spec());
        let procs = db.get_all_processors();
        assert_eq!(procs.len(), 2);
    }

    #[test]
    fn test_get_compiler_spec() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());

        let cs = db
            .get_compiler_spec("x86:LE:64:default", &CompilerSpecID::new("default"))
            .unwrap();
        assert_eq!(cs.name, "default");

        let win = db
            .get_compiler_spec("x86:LE:64:default", &CompilerSpecID::new("windows"))
            .unwrap();
        assert_eq!(win.name, "windows");

        assert!(db
            .get_compiler_spec("x86:LE:64:default", &CompilerSpecID::new("missing"))
            .is_none());
    }

    #[test]
    fn test_replace_existing_spec() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());
        assert_eq!(db.language_count(), 1);

        // Add a new version of the same language
        let id = LanguageSpecID::x86_64();
        let spec2 = LanguageSpec::new(id, "x86 64-bit v2", 2, 0, "x86.sla", "x86.pspec");
        db.add_language_spec(spec2);
        assert_eq!(db.language_count(), 1); // still 1, replaced
        assert_eq!(
            db.get_language_spec("x86:LE:64:default").unwrap().description,
            "x86 64-bit v2"
        );
    }

    #[test]
    fn test_processor_display() {
        assert_eq!(Processor::x86().to_string(), "x86");
        assert_eq!(Processor::arm().to_string(), "ARM");
        assert_eq!(Processor::riscv().to_string(), "RISC-V");
    }

    #[test]
    fn test_processor_as_ref() {
        let p = Processor::new("test");
        let s: &str = p.as_ref();
        assert_eq!(s, "test");
    }

    #[test]
    fn test_processor_convenience_constructors() {
        assert_eq!(Processor::x86().name(), "x86");
        assert_eq!(Processor::arm().name(), "ARM");
        assert_eq!(Processor::aarch64().name(), "AARCH64");
        assert_eq!(Processor::mips().name(), "MIPS");
        assert_eq!(Processor::powerpc().name(), "PowerPC");
        assert_eq!(Processor::riscv().name(), "RISC-V");
    }

    #[test]
    fn test_mutable_language_spec_in_db() {
        let mut db = BuildDatabase::new();
        db.add_language_spec(make_x86_64_spec());

        // Modify through mutable reference
        if let Some(spec) = db.get_language_spec_mut("x86:LE:64:default") {
            spec.add_compiler_spec(CompilerSpecDescription::new(
                "gcc",
                "GCC custom",
                "gcc.cspec",
            ));
        }

        let spec = db.get_language_spec("x86:LE:64:default").unwrap();
        assert_eq!(spec.compiler_specs.len(), 3);
    }
}
