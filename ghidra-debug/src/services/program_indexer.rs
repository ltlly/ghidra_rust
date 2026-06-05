//! Program module indexer for static mapping.
//!
//! Ported from Ghidra's `ProgramModuleIndexer` and `ModuleRegionMatcher`.
//!
//! Indexes modules and sections from a program for use in static mapping
//! proposals. Provides matching logic for correlating program modules
//! with trace modules.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::Lifespan;

/// A section within a program module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedSection {
    /// The section name (e.g., ".text", ".data").
    pub name: String,
    /// The start address of the section.
    pub start_address: u64,
    /// The end address of the section (inclusive).
    pub end_address: u64,
    /// Whether the section is executable.
    pub executable: bool,
    /// Whether the section is writable.
    pub writable: bool,
    /// Whether the section is readable.
    pub readable: bool,
}

impl IndexedSection {
    /// Create a new indexed section.
    pub fn new(
        name: impl Into<String>,
        start_address: u64,
        end_address: u64,
    ) -> Self {
        Self {
            name: name.into(),
            start_address,
            end_address,
            executable: false,
            writable: false,
            readable: true,
        }
    }

    /// Mark this section as executable.
    pub fn executable(mut self) -> Self {
        self.executable = true;
        self
    }

    /// Mark this section as writable.
    pub fn writable(mut self) -> Self {
        self.writable = true;
        self
    }

    /// Get the size of this section in bytes.
    pub fn size(&self) -> u64 {
        self.end_address.saturating_sub(self.start_address) + 1
    }

    /// Check if this section overlaps with a given address range.
    pub fn overlaps(&self, min: u64, max: u64) -> bool {
        self.start_address <= max && self.end_address >= min
    }

    /// Check if this section contains the given address.
    pub fn contains_address(&self, addr: u64) -> bool {
        addr >= self.start_address && addr <= self.end_address
    }
}

/// A module (library, executable) indexed from a program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedModule {
    /// The module name (e.g., "libc.so.6", "app.exe").
    pub name: String,
    /// The module file path.
    pub path: String,
    /// The base load address.
    pub base_address: u64,
    /// The length of the module in memory.
    pub length: u64,
    /// Sections within this module, keyed by section name.
    pub sections: BTreeMap<String, IndexedSection>,
}

impl IndexedModule {
    /// Create a new indexed module.
    pub fn new(
        name: impl Into<String>,
        path: impl Into<String>,
        base_address: u64,
        length: u64,
    ) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            base_address,
            length,
            sections: BTreeMap::new(),
        }
    }

    /// Add a section to this module.
    pub fn add_section(&mut self, section: IndexedSection) {
        self.sections.insert(section.name.clone(), section);
    }

    /// Get the end address of this module.
    pub fn end_address(&self) -> u64 {
        self.base_address + self.length
    }

    /// Check if this module overlaps with a given address range.
    pub fn overlaps(&self, min: u64, max: u64) -> bool {
        self.base_address <= max && self.end_address() >= min
    }

    /// Find the section containing the given address, if any.
    pub fn section_at(&self, addr: u64) -> Option<&IndexedSection> {
        self.sections
            .values()
            .find(|s| s.contains_address(addr))
    }

    /// Get all section names.
    pub fn section_names(&self) -> Vec<&str> {
        self.sections.keys().map(|s| s.as_str()).collect()
    }
}

/// Indexes modules and sections from a program for static mapping.
///
/// This is the Rust equivalent of Ghidra's `ProgramModuleIndexer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramModuleIndexer {
    /// Indexed modules, keyed by module name.
    pub modules: BTreeMap<String, IndexedModule>,
    /// The program URL.
    pub program_url: String,
    /// The language ID.
    pub language_id: String,
}

impl ProgramModuleIndexer {
    /// Create a new program module indexer.
    pub fn new(program_url: impl Into<String>, language_id: impl Into<String>) -> Self {
        Self {
            modules: BTreeMap::new(),
            program_url: program_url.into(),
            language_id: language_id.into(),
        }
    }

    /// Add a module to the index.
    pub fn add_module(&mut self, module: IndexedModule) {
        self.modules.insert(module.name.clone(), module);
    }

    /// Get a module by name.
    pub fn get_module(&self, name: &str) -> Option<&IndexedModule> {
        self.modules.get(name)
    }

    /// Get the total number of indexed modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Find the module containing the given address.
    pub fn module_at(&self, addr: u64) -> Option<&IndexedModule> {
        self.modules.values().find(|m| m.overlaps(addr, addr))
    }

    /// Get all modules that overlap with the given range.
    pub fn modules_overlapping(&self, min: u64, max: u64) -> Vec<&IndexedModule> {
        self.modules
            .values()
            .filter(|m| m.overlaps(min, max))
            .collect()
    }
}

/// Matches program modules to trace modules for static mapping.
///
/// Ported from Ghidra's `ModuleRegionMatcher`.
#[derive(Debug, Clone)]
pub struct ModuleRegionMatcher {
    /// The indexed program modules.
    pub program_index: ProgramModuleIndexer,
    /// Confidence threshold for matching (0.0 - 1.0).
    pub confidence_threshold: f64,
}

/// A match result between a program module and a trace module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMatchResult {
    /// The program module name.
    pub program_module: String,
    /// The trace module name.
    pub trace_module: String,
    /// The matching confidence (0.0 - 1.0).
    pub confidence: f64,
    /// The reason for the match.
    pub reason: String,
    /// Whether the match was by name.
    pub name_match: bool,
    /// Whether the match was by address range.
    pub address_match: bool,
}

impl ModuleRegionMatcher {
    /// Create a new module region matcher.
    pub fn new(program_index: ProgramModuleIndexer) -> Self {
        Self {
            program_index,
            confidence_threshold: 0.5,
        }
    }

    /// Set the confidence threshold.
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.confidence_threshold = threshold;
        self
    }

    /// Match a program module name against trace module names.
    ///
    /// Returns match candidates sorted by confidence (highest first).
    pub fn match_by_name(
        &self,
        program_module: &str,
        trace_modules: &[&str],
    ) -> Vec<ModuleMatchResult> {
        let mut results = Vec::new();

        let prog_lower = program_module.to_lowercase();

        for &trace_module in trace_modules {
            let trace_lower = trace_module.to_lowercase();
            let mut confidence = 0.0;
            let mut reason = String::new();

            // Exact name match
            if prog_lower == trace_lower {
                confidence = 1.0;
                reason = "Exact name match".to_string();
            }
            // One name is a suffix of the other
            else if prog_lower.ends_with(&trace_lower) || trace_lower.ends_with(&prog_lower) {
                confidence = 0.8;
                reason = "Name suffix match".to_string();
            }
            // One name starts with the other (e.g., "libc.so.6" vs "libc.so.6-extra")
            else if trace_lower.starts_with(&prog_lower) || prog_lower.starts_with(&trace_lower) {
                let common_len = prog_lower.len().min(trace_lower.len());
                let max_len = prog_lower.len().max(trace_lower.len());
                confidence = (common_len as f64 / max_len as f64).max(0.6);
                reason = format!("Name prefix match ({} of {} chars)", common_len, max_len);
            }
            // Shared prefix with library name heuristic
            else {
                let prefix_len = prog_lower
                    .chars()
                    .zip(trace_lower.chars())
                    .take_while(|(a, b)| a == b)
                    .count();
                // Extract base library name (before .so, -, or .)
                let extract_base = |name: &str| -> String {
                    let stripped = name
                        .split(".so")
                        .next()
                        .unwrap_or(name);
                    stripped
                        .split('-')
                        .next()
                        .unwrap_or(stripped)
                        .to_string()
                };
                let prog_base = extract_base(&prog_lower);
                let trace_base = extract_base(&trace_lower);
                if prog_base == trace_base && prog_base.len() >= 3 {
                    confidence = 0.6;
                    reason = format!("Shared base name '{}'", prog_base);
                } else if prefix_len > 3 {
                    confidence = (prefix_len as f64 / prog_lower.len().max(trace_lower.len()) as f64) * 0.9;
                    reason = format!("Common prefix ({} chars)", prefix_len);
                }
            }

            if confidence >= self.confidence_threshold {
                results.push(ModuleMatchResult {
                    program_module: program_module.to_string(),
                    trace_module: trace_module.to_string(),
                    confidence,
                    reason,
                    name_match: true,
                    address_match: false,
                });
            }
        }

        results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indexed_section() {
        let section = IndexedSection::new(".text", 0x1000, 0x2000)
            .executable();
        assert_eq!(section.name, ".text");
        assert_eq!(section.size(), 0x1001);
        assert!(section.executable);
        assert!(!section.writable);
        assert!(section.contains_address(0x1500));
        assert!(!section.contains_address(0x2001));
        assert!(section.overlaps(0x500, 0x1500));
        assert!(!section.overlaps(0x3000, 0x4000));
    }

    #[test]
    fn test_indexed_module() {
        let mut module = IndexedModule::new("libc.so.6", "/usr/lib/libc.so.6", 0x7f000000, 0x20000);
        module.add_section(IndexedSection::new(".text", 0x7f001000, 0x7f010000).executable());
        module.add_section(IndexedSection::new(".data", 0x7f011000, 0x7f018000).writable());
        module.add_section(IndexedSection::new(".bss", 0x7f019000, 0x7f020000));

        assert_eq!(module.name, "libc.so.6");
        assert_eq!(module.end_address(), 0x7f020000);
        assert_eq!(module.sections.len(), 3);
        assert!(module.overlaps(0x7f005000, 0x7f006000));
        assert!(!module.overlaps(0x80000000, 0x80001000));

        let section = module.section_at(0x7f005000);
        assert!(section.is_some());
        assert_eq!(section.unwrap().name, ".text");

        let names = module.section_names();
        assert_eq!(names, vec![".bss", ".data", ".text"]);
    }

    #[test]
    fn test_program_module_indexer() {
        let mut indexer = ProgramModuleIndexer::new("file:///app", "x86:LE:64:default");

        let mut libc = IndexedModule::new("libc.so.6", "/usr/lib/libc.so.6", 0x7f000000, 0x20000);
        libc.add_section(IndexedSection::new(".text", 0x7f001000, 0x7f010000));
        indexer.add_module(libc);

        let mut app = IndexedModule::new("app", "/bin/app", 0x400000, 0x10000);
        app.add_section(IndexedSection::new(".text", 0x401000, 0x409000));
        indexer.add_module(app);

        assert_eq!(indexer.module_count(), 2);
        assert!(indexer.get_module("libc.so.6").is_some());
        assert!(indexer.get_module("nonexistent").is_none());

        let module = indexer.module_at(0x7f005000);
        assert!(module.is_some());
        assert_eq!(module.unwrap().name, "libc.so.6");

        let overlapping = indexer.modules_overlapping(0x400000, 0x410000);
        assert_eq!(overlapping.len(), 1);
        assert_eq!(overlapping[0].name, "app");
    }

    #[test]
    fn test_module_region_matcher() {
        let mut indexer = ProgramModuleIndexer::new("file:///app", "x86:LE:64:default");
        indexer.add_module(IndexedModule::new("libc.so.6", "/usr/lib/libc.so.6", 0x7f000000, 0x20000));
        indexer.add_module(IndexedModule::new("libpthread.so.0", "/usr/lib/libpthread.so.0", 0x7f030000, 0x10000));

        let matcher = ModuleRegionMatcher::new(indexer);

        let trace_modules = vec![
            "libc-2.31.so",
            "libpthread-2.31.so",
            "app",
        ];

        // Exact name match for libc.so.6 vs libc-2.31.so won't be exact but prefix match
        let results = matcher.match_by_name("libc.so.6", &trace_modules);
        // Should find at least one match
        assert!(!results.is_empty());

        // Try exact match
        let results_exact = matcher.match_by_name("app", &vec!["app", "other"]);
        assert!(!results_exact.is_empty());
        assert!(results_exact[0].confidence > 0.9);
    }

    #[test]
    fn test_module_match_by_name_exact() {
        let indexer = ProgramModuleIndexer::new("file:///app", "x86:LE:64:default");
        let matcher = ModuleRegionMatcher::new(indexer);

        let results = matcher.match_by_name("libc.so.6", &vec!["libc.so.6", "other.so"]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].confidence, 1.0);
        assert!(results[0].name_match);
    }

    #[test]
    fn test_module_match_by_name_suffix() {
        let indexer = ProgramModuleIndexer::new("file:///app", "x86:LE:64:default");
        let matcher = ModuleRegionMatcher::new(indexer);

        let results = matcher.match_by_name("libc.so.6", &vec!["libc.so.6-extra", "libpthread"]);
        assert!(!results.is_empty());
        assert!(results[0].confidence > 0.5);
    }

    #[test]
    fn test_module_match_by_name_no_match() {
        let indexer = ProgramModuleIndexer::new("file:///app", "x86:LE:64:default");
        let matcher = ModuleRegionMatcher::new(indexer);

        let results = matcher.match_by_name("libc.so.6", &vec!["libpthread", "libm"]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_module_match_threshold() {
        let indexer = ProgramModuleIndexer::new("file:///app", "x86:LE:64:default");
        let matcher = ModuleRegionMatcher::new(indexer).with_threshold(0.9);

        // Suffix match has confidence 0.8, below 0.9 threshold
        let results = matcher.match_by_name("libc.so.6", &vec!["libc.so.6-extra"]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_section_permissions() {
        let section = IndexedSection::new(".data", 0x2000, 0x3000)
            .writable();
        assert!(section.writable);
        assert!(!section.executable);
        assert!(section.readable);
    }

    #[test]
    fn test_section_serialization() {
        let section = IndexedSection::new(".text", 0x1000, 0x2000);
        let json = serde_json::to_string(&section).unwrap();
        let deserialized: IndexedSection = serde_json::from_str(&json).unwrap();
        assert_eq!(section.name, deserialized.name);
        assert_eq!(section.start_address, deserialized.start_address);
    }

    #[test]
    fn test_module_empty_sections() {
        let module = IndexedModule::new("empty", "/dev/null", 0, 0);
        assert!(module.sections.is_empty());
        assert!(module.section_names().is_empty());
        assert!(module.section_at(0).is_none());
    }

    #[test]
    fn test_indexer_no_modules() {
        let indexer = ProgramModuleIndexer::new("file:///empty", "x86:LE:64:default");
        assert_eq!(indexer.module_count(), 0);
        assert!(indexer.module_at(0).is_none());
        assert!(indexer.modules_overlapping(0, 0).is_empty());
    }

    #[test]
    fn test_module_match_result_serialization() {
        let result = ModuleMatchResult {
            program_module: "libc.so.6".to_string(),
            trace_module: "libc-2.31.so".to_string(),
            confidence: 0.85,
            reason: "Name suffix match".to_string(),
            name_match: true,
            address_match: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ModuleMatchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.confidence, deserialized.confidence);
    }
}
