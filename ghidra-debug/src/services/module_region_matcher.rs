//! Module-region matching for auto-mapping ported from Java.
//!
//! Ported from `ModuleRegionMatcher` in the Debugger module.
//! Matches loaded modules from a debug target to sections/regions
//! in a static program for automatic address mapping.

use std::collections::HashMap;

/// A loaded module from a debug target.
#[derive(Debug, Clone)]
pub struct LoadedModule {
    /// Module name (e.g., "libc.so").
    pub name: String,
    /// Base address where the module is loaded.
    pub base_address: u64,
    /// Size of the module in bytes.
    pub size: u64,
    /// Path to the module file.
    pub file_path: String,
}

/// A region (section) from a static program.
#[derive(Debug, Clone)]
pub struct ProgramRegion {
    /// Region name (e.g., ".text").
    pub name: String,
    /// Start address in the program.
    pub start_address: u64,
    /// Size of the region.
    pub size: u64,
    /// Whether the region is executable.
    pub is_executable: bool,
    /// Whether the region is writable.
    pub is_writable: bool,
}

/// A match between a loaded module and a program region.
#[derive(Debug, Clone)]
pub struct ModuleRegionMatch {
    /// The loaded module.
    pub module: LoadedModule,
    /// The matching program region.
    pub region: ProgramRegion,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Computed offset from program address to trace address.
    pub offset: i64,
}

/// Matches loaded modules to program regions for auto-mapping.
#[derive(Debug)]
pub struct ModuleRegionMatcher {
    /// Minimum name similarity score to consider a match.
    min_name_similarity: f64,
    /// Indexed modules from the program.
    #[allow(dead_code)]
    modules: Vec<super::program_indexer::IndexedModule>,
}

impl Default for ModuleRegionMatcher {
    fn default() -> Self {
        Self {
            min_name_similarity: 0.3,
            modules: Vec::new(),
        }
    }
}

impl ModuleRegionMatcher {
    /// Create a new matcher with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a matcher with an indexed program.
    pub fn with_indexer(indexer: super::program_indexer::ProgramModuleIndexer) -> Self {
        Self {
            min_name_similarity: 0.3,
            modules: indexer.modules,
        }
    }

    /// Create a matcher with a custom name similarity threshold.
    pub fn with_threshold(threshold: f64) -> Self {
        Self {
            min_name_similarity: threshold,
            modules: Vec::new(),
        }
    }

    /// Match a module name against a list of candidate names.
    pub fn match_by_name(&self, module_name: &str, candidates: &[&str]) -> Vec<ModuleRegionMatch> {
        let mut results = Vec::new();
        for candidate in candidates {
            let score = Self::name_similarity(module_name, candidate);
            if score >= self.min_name_similarity {
                results.push(ModuleRegionMatch {
                    module: LoadedModule {
                        name: module_name.to_string(),
                        base_address: 0,
                        size: 0,
                        file_path: String::new(),
                    },
                    region: ProgramRegion {
                        name: candidate.to_string(),
                        start_address: 0,
                        size: 0,
                        is_executable: false,
                        is_writable: false,
                    },
                    confidence: score,
                    offset: 0,
                });
            }
        }
        results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        results
    }

    /// Compute a simple name similarity score between two strings.
    pub fn name_similarity(a: &str, b: &str) -> f64 {
        let a_lower = a.to_lowercase();
        let b_lower = b.to_lowercase();

        if a_lower == b_lower {
            return 1.0;
        }

        // Check if one contains the other
        if a_lower.contains(&b_lower) || b_lower.contains(&a_lower) {
            return 0.8;
        }

        // Check common extensions/stems
        let a_stem = Self::extract_stem(&a_lower);
        let b_stem = Self::extract_stem(&b_lower);
        if a_stem == b_stem {
            return 0.6;
        }

        // Only return character overlap if it's very high (different names
        // sharing many characters like "libc.so" and "libm" should not match)
        let common = a_lower.chars().filter(|c| b_lower.contains(*c)).count();
        let total = a_lower.len().max(b_lower.len());
        if total == 0 {
            return 0.0;
        }
        let ratio = (common as f64) / (total as f64);
        // Only consider it a match if the ratio is very high
        if ratio >= 0.7 { ratio } else { 0.0 }
    }

    /// Extract the stem of a filename (remove extension, path, and common prefixes).
    fn extract_stem<'a>(name: &'a str) -> String {
        let base = name.rsplit('/').next().unwrap_or(name);
        // Strip "lib" prefix
        let base = base.trim_start_matches("lib");
        // Take the first segment before '.', '-', or '_'
        let stem = base.split(&['.', '-', '_'][..]).next().unwrap_or(base);
        stem.to_string()
    }

    /// Match loaded modules to program regions.
    pub fn match_modules(
        &self,
        modules: &[LoadedModule],
        regions: &[ProgramRegion],
    ) -> Vec<ModuleRegionMatch> {
        let mut matches = Vec::new();

        for module in modules {
            for region in regions {
                let name_score = Self::name_similarity(&module.name, &region.name);
                if name_score < self.min_name_similarity {
                    continue;
                }

                let size_score = if module.size > 0 && region.size > 0 {
                    let ratio = (module.size.min(region.size) as f64)
                        / (module.size.max(region.size) as f64);
                    ratio
                } else {
                    0.5
                };

                let confidence = name_score * 0.6 + size_score * 0.4;
                let offset = module.base_address as i64 - region.start_address as i64;

                matches.push(ModuleRegionMatch {
                    module: module.clone(),
                    region: region.clone(),
                    confidence,
                    offset,
                });
            }
        }

        // Sort by confidence descending
        matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        matches
    }

    /// Deduplicate matches, keeping only the best match for each module.
    pub fn deduplicate(matches: &[ModuleRegionMatch]) -> Vec<&ModuleRegionMatch> {
        let mut seen_modules = HashMap::new();
        let mut result = Vec::new();

        for m in matches {
            let entry = seen_modules
                .entry(m.module.name.clone())
                .or_insert(m);
            if m.confidence > entry.confidence {
                *entry = m;
            }
        }

        for m in seen_modules.values() {
            result.push(*m);
        }
        result.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_module(name: &str, base: u64, size: u64) -> LoadedModule {
        LoadedModule {
            name: name.to_string(),
            base_address: base,
            size,
            file_path: format!("/usr/lib/{}", name),
        }
    }

    fn make_region(name: &str, start: u64, size: u64) -> ProgramRegion {
        ProgramRegion {
            name: name.to_string(),
            start_address: start,
            size,
            is_executable: true,
            is_writable: false,
        }
    }

    #[test]
    fn test_exact_name_match() {
        assert_eq!(ModuleRegionMatcher::name_similarity("libc", "libc"), 1.0);
    }

    #[test]
    fn test_partial_name_match() {
        let score = ModuleRegionMatcher::name_similarity("libc.so.6", "libc");
        assert!(score > 0.5);
    }

    #[test]
    fn test_match_modules() {
        let matcher = ModuleRegionMatcher::new();
        let modules = vec![
            make_module("libc.so", 0x7f000000, 0x100000),
            make_module("libpthread.so", 0x7f100000, 0x80000),
        ];
        let regions = vec![
            make_region("libc", 0x400000, 0x100000),
            make_region("libpthread", 0x500000, 0x80000),
        ];

        let matches = matcher.match_modules(&modules, &regions);
        assert!(!matches.is_empty());

        // Best match should be libc with libc
        let best = &matches[0];
        assert!(best.confidence > 0.5);
    }

    #[test]
    fn test_name_similarity_different() {
        let score = ModuleRegionMatcher::name_similarity("libfoo", "libbar");
        assert!(score < 0.8);
    }
}
