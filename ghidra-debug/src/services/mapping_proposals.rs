//! Default mapping proposal implementations for modules, sections, and regions.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.modules` package.
//!
//! Provides the concrete mapping proposal classes that compute scores and
//! generate map entries for:
//! - Module-to-program mapping (`DefaultModuleMapProposal`)
//! - Section-to-block mapping (`DefaultSectionMapProposal`)
//! - Region-to-block mapping (`DefaultRegionMapProposal`)
//!
//! Also includes `ModuleRegionMatcher` and `ProgramModuleIndexer`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// Abstract base types
// ---------------------------------------------------------------------------

/// A mapping entry pairing a trace-side object with a program-side object.
///
/// Ported from Ghidra's `AbstractMapEntry<T, P>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractMapEntry {
    /// The trace ID.
    pub trace_id: String,
    /// The "from" object descriptor (module name, section name, etc.).
    pub from_name: String,
    /// The trace address range start.
    pub from_min: u64,
    /// The trace address range end (inclusive).
    pub from_max: u64,
    /// The snap at which this mapping was computed.
    pub snap: i64,
    /// The "to" object descriptor (program name, block name, etc.).
    pub to_name: String,
    /// The program address range start.
    pub to_min: u64,
    /// The program address range end (inclusive).
    pub to_max: u64,
    /// Whether to memorize (persist) this mapping.
    pub memorize: bool,
}

impl AbstractMapEntry {
    /// Create a new abstract map entry.
    pub fn new(
        trace_id: impl Into<String>,
        from_name: impl Into<String>,
        from_min: u64,
        from_max: u64,
        snap: i64,
        to_name: impl Into<String>,
        to_min: u64,
        to_max: u64,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            from_name: from_name.into(),
            from_min,
            from_max,
            snap,
            to_name: to_name.into(),
            to_min,
            to_max,
            memorize: false,
        }
    }

    /// The length of the mapping (minimum of from and to ranges).
    pub fn mapping_length(&self) -> u64 {
        let from_len = self.from_max - self.from_min + 1;
        let to_len = self.to_max - self.to_min + 1;
        from_len.min(to_len)
    }

    /// Translate a "from" address to a "to" address.
    pub fn translate_from_to(&self, addr: u64) -> Option<u64> {
        if addr >= self.from_min && addr <= self.from_max {
            let offset = addr - self.from_min;
            Some(self.to_min + offset)
        } else {
            None
        }
    }

    /// Translate a "to" address to a "from" address.
    pub fn translate_to_from(&self, addr: u64) -> Option<u64> {
        if addr >= self.to_min && addr <= self.to_max {
            let offset = addr - self.to_min;
            Some(self.from_min + offset)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Matcher utilities
// ---------------------------------------------------------------------------

/// Utility for matching program blocks to trace regions by offset.
///
/// Ported from Ghidra's `ModuleRegionMatcher`.
#[derive(Debug, Clone)]
pub struct ModuleRegionMatcher {
    /// The snap at which this matcher was computed.
    pub snap: i64,
    /// The program block range, if matched.
    pub block_min: Option<u64>,
    /// The program block max address.
    pub block_max: Option<u64>,
    /// The program block size.
    pub block_size: Option<u64>,
    /// The trace region range, if matched.
    pub region_min: Option<u64>,
    /// The trace region max address.
    pub region_max: Option<u64>,
    /// The trace region length.
    pub region_length: Option<u64>,
}

impl ModuleRegionMatcher {
    /// Create a new matcher for a given snap.
    pub fn new(snap: i64) -> Self {
        Self {
            snap,
            block_min: None,
            block_max: None,
            block_size: None,
            region_min: None,
            region_max: None,
            region_length: None,
        }
    }

    /// Set program block info.
    pub fn with_block(mut self, min: u64, max: u64, size: u64) -> Self {
        self.block_min = Some(min);
        self.block_max = Some(max);
        self.block_size = Some(size);
        self
    }

    /// Set trace region info.
    pub fn with_region(mut self, min: u64, max: u64, length: u64) -> Self {
        self.region_min = Some(min);
        self.region_max = Some(max);
        self.region_length = Some(length);
        self
    }

    /// Compute a matching score.
    ///
    /// Returns 0 if either side is unmatched, otherwise returns a base
    /// score of 3 for the matching offset, plus 10 if the sizes match exactly.
    pub fn score(&self) -> i32 {
        if self.block_min.is_none() || self.region_min.is_none() {
            return 0;
        }
        let mut score = 3; // For the matching offset
        if self.block_size == self.region_length {
            score += 10;
        }
        score
    }
}

// ---------------------------------------------------------------------------
// Quantize utility
// ---------------------------------------------------------------------------

/// Quantize an address range to 4096-byte block boundaries.
///
/// This is used to make module/program comparisons more resilient to
/// minor address differences.
pub fn quantize_range(min: u64, max: u64) -> (u64, u64) {
    const BLOCK_BITS: u32 = 12;
    const BLOCK_MASK: u64 = !((1u64 << BLOCK_BITS) - 1);
    const INV_BLOCK_MASK: u64 = (1u64 << BLOCK_BITS) - 1;
    let q_min = min & BLOCK_MASK;
    let q_max = max | INV_BLOCK_MASK;
    (q_min, q_max)
}

// ---------------------------------------------------------------------------
// DefaultModuleMapProposal
// ---------------------------------------------------------------------------

/// A proposed module-to-program mapping.
///
/// Ported from Ghidra's `DefaultModuleMapProposal`.
///
/// Matches a loaded module to a static program by comparing the
/// sizes and offsets of memory blocks vs. memory regions.
#[derive(Debug, Clone)]
pub struct DefaultModuleMapProposal {
    /// The trace ID.
    pub trace_id: String,
    /// The module name.
    pub module_name: String,
    /// The module base address in the trace.
    pub module_base: u64,
    /// The module range: (quantized_min, quantized_max).
    pub module_range: (u64, u64),
    /// The snap at which this proposal was computed.
    pub snap: i64,
    /// The program name / URL.
    pub program_name: String,
    /// The program image range: (quantized_min, quantized_max).
    pub image_range: (u64, u64),
    /// Indexed matchers by offset from module/image base.
    pub matchers: BTreeMap<u64, ModuleRegionMatcher>,
}

impl DefaultModuleMapProposal {
    /// Create a new module map proposal.
    pub fn new(
        trace_id: impl Into<String>,
        module_name: impl Into<String>,
        module_base: u64,
        module_max: u64,
        snap: i64,
        program_name: impl Into<String>,
        program_image_min: u64,
        program_image_max: u64,
    ) -> Self {
        let module_range = quantize_range(module_base, module_max);
        let image_range = quantize_range(program_image_min, program_image_max);
        Self {
            trace_id: trace_id.into(),
            module_name: module_name.into(),
            module_base,
            module_range,
            snap,
            program_name: program_name.into(),
            image_range,
            matchers: BTreeMap::new(),
        }
    }

    /// Add a program block at the given offset from the program image base.
    pub fn add_program_block(&mut self, offset: u64, block_min: u64, block_max: u64, block_size: u64) {
        let matcher = self.matchers.entry(offset).or_insert_with(|| ModuleRegionMatcher::new(self.snap));
        matcher.block_min = Some(block_min);
        matcher.block_max = Some(block_max);
        matcher.block_size = Some(block_size);
    }

    /// Add a trace region at the given offset from the module base.
    pub fn add_trace_region(&mut self, offset: u64, region_min: u64, region_max: u64, region_length: u64) {
        let matcher = self.matchers.entry(offset).or_insert_with(|| ModuleRegionMatcher::new(self.snap));
        matcher.region_min = Some(region_min);
        matcher.region_max = Some(region_max);
        matcher.region_length = Some(region_length);
    }

    /// Compute a score for this proposal (average of matchers).
    pub fn compute_score(&self) -> f64 {
        if self.matchers.is_empty() {
            return 0.0;
        }
        let total: i32 = self.matchers.values().map(|m| m.score()).sum();
        total as f64 / self.matchers.len() as f64
    }

    /// Compute the mapping entries.
    pub fn compute_entries(&self) -> Vec<AbstractMapEntry> {
        self.matchers
            .values()
            .filter(|m| m.block_min.is_some() && m.region_min.is_some())
            .map(|m| {
                AbstractMapEntry::new(
                    &self.trace_id,
                    &self.module_name,
                    m.region_min.unwrap(),
                    m.region_max.unwrap(),
                    self.snap,
                    &self.program_name,
                    m.block_min.unwrap(),
                    m.block_max.unwrap(),
                )
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// DefaultSectionMapProposal
// ---------------------------------------------------------------------------

/// A section-to-block matcher entry.
#[derive(Debug, Clone)]
pub struct SectionBlockMatcher {
    /// The section name.
    pub section_name: String,
    /// The section range in the trace: (min, max).
    pub section_range: (u64, u64),
    /// The matched block name.
    pub block_name: Option<String>,
    /// The matched block range in the program: (min, max).
    pub block_range: Option<(u64, u64)>,
    /// The matching score.
    pub score: f64,
}

impl SectionBlockMatcher {
    /// Create a new section-block matcher.
    pub fn new(
        section_name: impl Into<String>,
        section_min: u64,
        section_max: u64,
    ) -> Self {
        Self {
            section_name: section_name.into(),
            section_range: (section_min, section_max),
            block_name: None,
            block_range: None,
            score: 0.0,
        }
    }

    /// Try to match with a program block (by name similarity and size).
    pub fn try_match_block(
        &mut self,
        block_name: &str,
        block_min: u64,
        block_max: u64,
    ) {
        let sec_len = self.section_range.1 - self.section_range.0 + 1;
        let blk_len = block_max - block_min + 1;

        let name_score = compute_name_score(&self.section_name, block_name);
        let size_score = compute_size_score(sec_len, blk_len);
        let total_score = name_score + size_score;

        if total_score > self.score {
            self.score = total_score;
            self.block_name = Some(block_name.to_string());
            self.block_range = Some((block_min, block_max));
        }
    }
}

/// A proposed section-to-program mapping.
///
/// Ported from Ghidra's `DefaultSectionMapProposal`.
#[derive(Debug, Clone)]
pub struct DefaultSectionMapProposal {
    /// The trace ID.
    pub trace_id: String,
    /// The module name.
    pub module_name: String,
    /// The snap.
    pub snap: i64,
    /// The program name.
    pub program_name: String,
    /// The section matchers.
    pub matchers: Vec<SectionBlockMatcher>,
}

impl DefaultSectionMapProposal {
    /// Create a new section map proposal.
    pub fn new(
        trace_id: impl Into<String>,
        module_name: impl Into<String>,
        snap: i64,
        program_name: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            module_name: module_name.into(),
            snap,
            program_name: program_name.into(),
            matchers: Vec::new(),
        }
    }

    /// Add a section to match.
    pub fn add_section(
        &mut self,
        section_name: impl Into<String>,
        section_min: u64,
        section_max: u64,
    ) {
        self.matchers.push(SectionBlockMatcher::new(section_name, section_min, section_max));
    }

    /// Try to match all sections with the given program blocks.
    pub fn match_blocks(&mut self, blocks: &[(String, u64, u64)]) {
        for matcher in &mut self.matchers {
            for (block_name, block_min, block_max) in blocks {
                matcher.try_match_block(block_name, *block_min, *block_max);
            }
        }
    }

    /// Compute a score for this proposal (average of matcher scores).
    pub fn compute_score(&self) -> f64 {
        if self.matchers.is_empty() {
            return 0.0;
        }
        let total: f64 = self.matchers.iter().map(|m| m.score).sum();
        total / self.matchers.len() as f64
    }

    /// Compute the mapping entries.
    pub fn compute_entries(&self) -> Vec<AbstractMapEntry> {
        self.matchers
            .iter()
            .filter(|m| m.block_range.is_some())
            .map(|m| {
                let (blk_min, blk_max) = m.block_range.unwrap();
                AbstractMapEntry::new(
                    &self.trace_id,
                    &m.section_name,
                    m.section_range.0,
                    m.section_range.1,
                    self.snap,
                    &self.program_name,
                    blk_min,
                    blk_max,
                )
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// DefaultRegionMapProposal
// ---------------------------------------------------------------------------

/// A proposed region-to-program mapping.
///
/// Ported from Ghidra's `DefaultRegionMapProposal`.
#[derive(Debug, Clone)]
pub struct DefaultRegionMapProposal {
    /// The trace ID.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
    /// The program name.
    pub program_name: String,
    /// The program image base.
    pub program_base: u64,
    /// The trace regions: (name, min, max).
    pub regions: Vec<(String, u64, u64)>,
    /// The trace regions sorted by min address.
    pub from_base: Option<u64>,
    /// Matchers per region, keyed by offset from from_base.
    pub matchers: BTreeMap<u64, SectionBlockMatcher>,
    /// Program blocks: (name, min, max).
    pub blocks: Vec<(String, u64, u64)>,
}

impl DefaultRegionMapProposal {
    /// Create a new region map proposal.
    pub fn new(
        trace_id: impl Into<String>,
        snap: i64,
        program_name: impl Into<String>,
        program_base: u64,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            program_name: program_name.into(),
            program_base,
            regions: Vec::new(),
            from_base: None,
            matchers: BTreeMap::new(),
            blocks: Vec::new(),
        }
    }

    /// Add a trace region.
    pub fn add_region(&mut self, name: impl Into<String>, min: u64, max: u64) {
        let name_str = name.into();
        if self.from_base.is_none() || min < self.from_base.unwrap() {
            self.from_base = Some(min);
        }
        self.regions.push((name_str, min, max));
    }

    /// Add a program block.
    pub fn add_block(&mut self, name: impl Into<String>, min: u64, max: u64) {
        self.blocks.push((name.into(), min, max));
    }

    /// Process regions and blocks to compute matches.
    pub fn process(&mut self) {
        let from_base = match self.from_base {
            Some(b) => b,
            None => return,
        };

        // Build matchers keyed by offset from base
        for (name, min, max) in &self.regions {
            let offset = min.wrapping_sub(from_base);
            self.matchers.insert(
                offset,
                SectionBlockMatcher::new(name, *min, *max),
            );
        }

        // Try to match each block
        for (block_name, block_min, block_max) in &self.blocks {
            let block_offset = block_min.wrapping_sub(self.program_base);
            if let Some(matcher) = self.matchers.get_mut(&block_offset) {
                matcher.try_match_block(block_name, *block_min, *block_max);
            }
        }
    }

    /// Compute a score for this proposal.
    pub fn compute_score(&self) -> f64 {
        if self.matchers.is_empty() {
            return 0.0;
        }
        let total: f64 = self.matchers.values().map(|m| m.score).sum();
        total / self.matchers.len() as f64
    }

    /// Compute the mapping entries.
    pub fn compute_entries(&self) -> Vec<AbstractMapEntry> {
        self.matchers
            .values()
            .filter(|m| m.block_range.is_some())
            .map(|m| {
                let (blk_min, blk_max) = m.block_range.unwrap();
                AbstractMapEntry::new(
                    &self.trace_id,
                    &m.section_name,
                    m.section_range.0,
                    m.section_range.1,
                    self.snap,
                    &self.program_name,
                    blk_min,
                    blk_max,
                )
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Name and size scoring utilities
// ---------------------------------------------------------------------------

/// Compute a name similarity score between two names.
///
/// Returns a score in [0.0, 10.0] based on name matching heuristics.
pub fn compute_name_score(a: &str, b: &str) -> f64 {
    let a_lower = a.to_lowercase();
    let b_lower = b.to_lowercase();

    if a_lower == b_lower {
        return 10.0;
    }
    // Strip common prefix (. / _)
    let a_stripped = a_lower.trim_start_matches(|c: char| c == '.' || c == '_');
    let b_stripped = b_lower.trim_start_matches(|c: char| c == '.' || c == '_');
    if a_stripped == b_stripped {
        return 9.0;
    }
    if a_stripped.starts_with(b_stripped) || b_stripped.starts_with(a_stripped) {
        return 7.0;
    }
    if a_lower.contains(&b_lower) || b_lower.contains(&a_lower) {
        return 5.0;
    }
    // Check for common substrings
    let common = longest_common_substring(&a_lower, &b_lower);
    let max_len = a_lower.len().max(b_lower.len());
    if max_len > 0 {
        (common as f64 / max_len as f64) * 5.0
    } else {
        0.0
    }
}

/// Compute a size similarity score.
///
/// Returns a score in [0.0, 10.0] based on how close the two sizes are.
pub fn compute_size_score(a: u64, b: u64) -> f64 {
    if a == b {
        return 10.0;
    }
    if a == 0 || b == 0 {
        return 0.0;
    }
    let (smaller, larger) = if a < b { (a, b) } else { (b, a) };
    let ratio = smaller as f64 / larger as f64;
    ratio * 10.0
}

/// Find the length of the longest common substring.
fn longest_common_substring(a: &str, b: &str) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut prev = vec![0usize; b_bytes.len() + 1];
    let mut max_len = 0;

    for i in 0..a_bytes.len() {
        let mut curr = vec![0usize; b_bytes.len() + 1];
        for j in 0..b_bytes.len() {
            if a_bytes[i] == b_bytes[j] {
                curr[j + 1] = prev[j] + 1;
                if curr[j + 1] > max_len {
                    max_len = curr[j + 1];
                }
            }
        }
        prev = curr;
    }
    max_len
}

// ---------------------------------------------------------------------------
// ProgramModuleIndexer
// ---------------------------------------------------------------------------

/// Indexer for mapping program modules and sections to trace modules.
///
/// Ported from Ghidra's `ProgramModuleIndexer`.
///
/// Provides precomputed lookups to quickly find matching program modules
/// for trace modules based on name, base address, and section layout.
#[derive(Debug, Clone)]
pub struct ProgramModuleIndex {
    /// Program name.
    pub program_name: String,
    /// Module names indexed by lowercase name.
    pub by_name: BTreeMap<String, ProgramModuleEntry>,
    /// Module entries indexed by base address.
    pub by_base: BTreeMap<u64, Vec<String>>,
}

/// An entry in the program module index.
#[derive(Debug, Clone)]
pub struct ProgramModuleEntry {
    /// The module name.
    pub name: String,
    /// The base address.
    pub base: u64,
    /// The size.
    pub size: u64,
    /// Section names and their ranges.
    pub sections: Vec<(String, u64, u64)>,
}

impl ProgramModuleEntry {
    /// Create a new program module entry.
    pub fn new(name: impl Into<String>, base: u64, size: u64) -> Self {
        Self {
            name: name.into(),
            base,
            size,
            sections: Vec::new(),
        }
    }

    /// Add a section.
    pub fn add_section(&mut self, name: impl Into<String>, min: u64, max: u64) {
        self.sections.push((name.into(), min, max));
    }
}

impl ProgramModuleIndex {
    /// Create a new program module index.
    pub fn new(program_name: impl Into<String>) -> Self {
        Self {
            program_name: program_name.into(),
            by_name: BTreeMap::new(),
            by_base: BTreeMap::new(),
        }
    }

    /// Add a module entry.
    pub fn add_module(&mut self, entry: ProgramModuleEntry) {
        let name_key = entry.name.to_lowercase();
        self.by_base.entry(entry.base).or_default().push(entry.name.clone());
        self.by_name.insert(name_key, entry);
    }

    /// Find a module by name.
    pub fn find_by_name(&self, name: &str) -> Option<&ProgramModuleEntry> {
        self.by_name.get(&name.to_lowercase())
    }

    /// Find modules by base address.
    pub fn find_by_base(&self, base: u64) -> Vec<&ProgramModuleEntry> {
        self.by_base
            .get(&base)
            .map(|names| {
                names
                    .iter()
                    .filter_map(|n| self.by_name.get(&n.to_lowercase()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find the best module match for a trace module name and base.
    pub fn find_best_match(&self, name: &str, base: u64) -> Option<&ProgramModuleEntry> {
        // First try exact name match
        if let Some(entry) = self.find_by_name(name) {
            return Some(entry);
        }
        // Then try base address match
        let base_matches = self.find_by_base(base);
        if base_matches.len() == 1 {
            return Some(base_matches[0]);
        }
        // Try partial name match
        let name_lower = name.to_lowercase();
        self.by_name
            .values()
            .find(|e| {
                let e_lower = e.name.to_lowercase();
                e_lower.contains(&name_lower) || name_lower.contains(&e_lower)
            })
    }

    /// Number of indexed modules.
    pub fn module_count(&self) -> usize {
        self.by_name.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantize_range() {
        let (min, max) = quantize_range(0x401234, 0x403456);
        assert_eq!(min, 0x401000);
        assert_eq!(max, 0x403fff);
    }

    #[test]
    fn test_module_region_matcher_score() {
        let matcher = ModuleRegionMatcher::new(0)
            .with_block(0x401000, 0x401fff, 0x1000)
            .with_region(0x7fff1000, 0x7fff1fff, 0x1000);
        assert_eq!(matcher.score(), 13); // 3 + 10 (sizes match)

        let unmatched = ModuleRegionMatcher::new(0)
            .with_block(0x401000, 0x401fff, 0x1000);
        assert_eq!(unmatched.score(), 0);
    }

    #[test]
    fn test_default_module_map_proposal() {
        let mut proposal = DefaultModuleMapProposal::new(
            "trace1", "main.elf", 0x400000, 0x410000, 0, "main.elf", 0x400000, 0x410000,
        );
        proposal.add_program_block(0, 0x400000, 0x400fff, 0x1000);
        proposal.add_trace_region(0, 0x400000, 0x400fff, 0x1000);

        let score = proposal.compute_score();
        assert!(score > 0.0);

        let entries = proposal.compute_entries();
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_default_section_map_proposal() {
        let mut proposal = DefaultSectionMapProposal::new(
            "trace1", "main.elf", 0, "main.elf",
        );
        proposal.add_section(".text", 0x401000, 0x401fff);
        proposal.add_section(".data", 0x403000, 0x403fff);

        let blocks = vec![
            (".text".into(), 0x401000u64, 0x401fffu64),
            (".data".into(), 0x403000u64, 0x403fffu64),
            (".bss".into(), 0x404000u64, 0x404fffu64),
        ];
        proposal.match_blocks(&blocks);

        let score = proposal.compute_score();
        assert!(score > 0.0);

        let entries = proposal.compute_entries();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_default_region_map_proposal() {
        let mut proposal = DefaultRegionMapProposal::new(
            "trace1", 0, "main.elf", 0x400000,
        );
        // from_base = 0x7fff0000 (first region min)
        // region offset = 0x7fff1000 - 0x7fff0000 = 0x1000
        // program_base = 0x400000
        // block offset = 0x401000 - 0x400000 = 0x1000
        // Both offsets = 0x1000, so they match.
        proposal.add_region(".text", 0x7fff0000, 0x7fff0fff);
        proposal.add_region(".text2", 0x7fff1000, 0x7fff1fff);
        proposal.add_block(".text", 0x400000, 0x400fff);
        proposal.add_block(".text2", 0x401000, 0x401fff);

        proposal.process();
        let score = proposal.compute_score();
        assert!(score > 0.0, "score was {}", score);

        let entries = proposal.compute_entries();
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_name_score_exact() {
        assert_eq!(compute_name_score(".text", ".text"), 10.0);
    }

    #[test]
    fn test_name_score_stripped() {
        let score = compute_name_score(".text", "text");
        assert!((score - 9.0).abs() < 0.01);
    }

    #[test]
    fn test_name_score_contains() {
        let score = compute_name_score(".text_segment", ".text");
        assert!(score > 0.0);
    }

    #[test]
    fn test_name_score_no_match() {
        let score = compute_name_score(".text", ".data");
        assert!(score < 5.0);
    }

    #[test]
    fn test_size_score_exact() {
        assert_eq!(compute_size_score(0x1000, 0x1000), 10.0);
    }

    #[test]
    fn test_size_score_ratio() {
        let score = compute_size_score(0x1000, 0x2000);
        assert!((score - 5.0).abs() < 0.01);
    }

    #[test]
    fn test_size_score_zero() {
        assert_eq!(compute_size_score(0, 0x1000), 0.0);
    }

    #[test]
    fn test_abstract_map_entry_translation() {
        let entry = AbstractMapEntry::new("t1", "mod", 0x400000, 0x400fff, 0, "prog", 0x1000, 0x1fff);
        assert_eq!(entry.translate_from_to(0x400000), Some(0x1000));
        assert_eq!(entry.translate_from_to(0x400100), Some(0x1100));
        assert_eq!(entry.translate_from_to(0x500000), None);

        assert_eq!(entry.translate_to_from(0x1000), Some(0x400000));
        assert_eq!(entry.translate_to_from(0x2000), None);
    }

    #[test]
    fn test_abstract_map_entry_length() {
        let entry = AbstractMapEntry::new("t1", "mod", 0x400000, 0x400fff, 0, "prog", 0x1000, 0x10ff);
        assert_eq!(entry.mapping_length(), 0x100); // min(0x1000, 0x100)
    }

    #[test]
    fn test_program_module_index() {
        let mut index = ProgramModuleIndex::new("test.exe");
        let mut entry1 = ProgramModuleEntry::new("main.elf", 0x400000, 0x10000);
        entry1.add_section(".text", 0x401000, 0x401fff);
        entry1.add_section(".data", 0x403000, 0x403fff);
        index.add_module(entry1);

        let mut entry2 = ProgramModuleEntry::new("libc.so", 0x7f000000, 0x200000);
        entry2.add_section(".text", 0x7f001000, 0x7f050000);
        index.add_module(entry2);

        assert_eq!(index.module_count(), 2);
        assert!(index.find_by_name("main.elf").is_some());
        assert!(index.find_by_name("MAIN.ELF").is_some()); // case-insensitive
        assert!(index.find_by_name("missing").is_none());
        assert_eq!(index.find_by_base(0x400000).len(), 1);
    }

    #[test]
    fn test_program_module_index_best_match() {
        let mut index = ProgramModuleIndex::new("test.exe");
        index.add_module(ProgramModuleEntry::new("main.elf", 0x400000, 0x10000));
        index.add_module(ProgramModuleEntry::new("libc.so", 0x7f000000, 0x200000));

        // Exact name match
        assert!(index.find_best_match("main.elf", 0x400000).is_some());
        // Base address match
        assert!(index.find_best_match("unknown", 0x7f000000).is_some());
        // Partial name match
        assert!(index.find_best_match("libc", 0).is_some());
    }

    #[test]
    fn test_section_block_matcher() {
        let mut matcher = SectionBlockMatcher::new(".text", 0x401000, 0x401fff);
        assert_eq!(matcher.score, 0.0);

        matcher.try_match_block(".text", 0x401000, 0x401fff);
        assert!(matcher.score > 0.0);
        assert_eq!(matcher.block_name.as_deref(), Some(".text"));
    }
}
