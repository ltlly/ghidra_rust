//! Auto-mapping service implementation.
//!
//! Ported from Ghidra's `DebuggerAutoMappingServicePlugin` and related classes.
//!
//! Provides automatic mapping of program modules/sections to trace memory
//! regions for synchronized static-dynamic analysis.

use std::collections::HashMap;

use crate::model::Lifespan;
use crate::services::{AutoMappingService, MappingProposal};

/// Information about a program for auto-mapping purposes.
#[derive(Debug, Clone)]
pub struct ProgramInfo {
    /// The program URL/key.
    pub url: String,
    /// The program name.
    pub name: String,
    /// Program regions: (name, min_addr, max_addr).
    pub regions: Vec<(String, u64, u64)>,
    /// Program sections: (name, min_addr, max_addr).
    pub sections: Vec<(String, u64, u64)>,
    /// The preferred base address for loading.
    pub preferred_base: u64,
}

/// Information about a trace's memory map for auto-mapping purposes.
#[derive(Debug, Clone)]
pub struct TraceMappingInfo {
    /// Memory regions: (name, min_addr, max_addr).
    pub regions: Vec<(String, u64, u64)>,
    /// Known module base addresses.
    pub module_bases: Vec<u64>,
    /// Whether the trace has ASLR applied.
    pub has_aslr: bool,
}

/// A candidate mapping between a program section and a trace region.
#[derive(Debug, Clone)]
pub struct MapCandidate {
    /// The program section name.
    pub section_name: String,
    /// The program section range.
    pub program_min: u64,
    pub program_max: u64,
    /// The matching trace region range.
    pub trace_min: u64,
    pub trace_max: u64,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
}

/// Implementation of the auto-mapping service.
///
/// Analyzes program and trace information to propose mappings that
/// synchronize static analysis data with the dynamic trace.
pub struct AutoMapServiceImpl {
    /// Cached program information.
    programs: HashMap<String, ProgramInfo>,
    /// Cached trace mapping information.
    trace_info: HashMap<i64, TraceMappingInfo>,
    /// Whether auto-mapping is enabled.
    enabled: bool,
}

impl AutoMapServiceImpl {
    /// Create a new auto-mapping service.
    pub fn new() -> Self {
        Self {
            programs: HashMap::new(),
            trace_info: HashMap::new(),
            enabled: true,
        }
    }

    /// Register program information for mapping.
    pub fn register_program(&mut self, info: ProgramInfo) {
        self.programs.insert(info.url.clone(), info);
    }

    /// Register trace mapping information.
    pub fn register_trace_info(&mut self, trace_key: i64, info: TraceMappingInfo) {
        self.trace_info.insert(trace_key, info);
    }

    /// Enable or disable auto-mapping.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if auto-mapping is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Find candidates for mapping a program to a trace.
    pub fn find_candidates(
        &self,
        program_url: &str,
        trace_key: i64,
    ) -> Vec<MapCandidate> {
        let program = match self.programs.get(program_url) {
            Some(p) => p,
            None => return Vec::new(),
        };
        let trace = match self.trace_info.get(&trace_key) {
            Some(t) => t,
            None => return Vec::new(),
        };

        let mut candidates = Vec::new();

        for (section_name, sec_min, sec_max) in &program.sections {
            for (region_name, reg_min, reg_max) in &trace.regions {
                let sec_size = sec_max - sec_min;
                let reg_size = reg_max - reg_min;

                // If sizes match exactly, high confidence
                if sec_size == reg_size {
                    candidates.push(MapCandidate {
                        section_name: section_name.clone(),
                        program_min: *sec_min,
                        program_max: *sec_max,
                        trace_min: *reg_min,
                        trace_max: *reg_max,
                        confidence: 0.99,
                    });
                }
                // If sizes are close (within 10%), medium confidence
                else if sec_size > 0 && reg_size > 0 {
                    let ratio = (sec_size as f64) / (reg_size as f64);
                    if (0.9..=1.1).contains(&ratio) {
                        candidates.push(MapCandidate {
                            section_name: section_name.clone(),
                            program_min: *sec_min,
                            program_max: *sec_max,
                            trace_min: *reg_min,
                            trace_max: *reg_max,
                            confidence: 0.7,
                        });
                    }
                }
            }
        }

        candidates
    }
}

impl Default for AutoMapServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl AutoMappingService for AutoMapServiceImpl {
    fn auto_map(
        &mut self,
        program_url: &str,
        trace_key: i64,
        lifespan: Lifespan,
    ) -> Result<(), String> {
        if !self.enabled {
            return Err("Auto-mapping is disabled".into());
        }

        let candidates = self.find_candidates(program_url, trace_key);
        if candidates.is_empty() {
            return Err("No mapping candidates found".into());
        }

        // In a real implementation, this would create actual mappings
        // through the StaticMappingService. Here we just validate the candidates.
        let best = candidates
            .iter()
            .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap())
            .unwrap();

        log::info!(
            "Auto-mapped {} section '{}' to trace [{:#x}..{:#x}] with confidence {}",
            program_url,
            best.section_name,
            best.trace_min,
            best.trace_max,
            best.confidence
        );

        Ok(())
    }

    fn propose_mapping(
        &self,
        program_url: &str,
        trace_key: i64,
    ) -> Vec<MappingProposal> {
        self.find_candidates(program_url, trace_key)
            .into_iter()
            .map(|c| MappingProposal {
                program_min: c.program_min,
                program_max: c.program_max,
                trace_min: c.trace_min,
                trace_max: c.trace_max,
                confidence: c.confidence,
            })
            .collect()
    }
}

/// Utility for matching program sections to trace regions.
pub struct SectionMatcher;

impl SectionMatcher {
    /// Match sections by name similarity.
    pub fn match_by_name(
        program_sections: &[(String, u64, u64)],
        trace_regions: &[(String, u64, u64)],
    ) -> Vec<(usize, usize)> {
        let mut matches = Vec::new();
        for (i, (sec_name, _, _)) in program_sections.iter().enumerate() {
            for (j, (reg_name, _, _)) in trace_regions.iter().enumerate() {
                if Self::names_similar(sec_name, reg_name) {
                    matches.push((i, j));
                }
            }
        }
        matches
    }

    /// Check if two names are similar enough to be a match.
    fn names_similar(a: &str, b: &str) -> bool {
        let a_lower = a.to_lowercase();
        let b_lower = b.to_lowercase();
        a_lower == b_lower
            || a_lower.starts_with(&b_lower)
            || b_lower.starts_with(&a_lower)
            || a_lower.contains(&b_lower)
            || b_lower.contains(&a_lower)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program(url: &str) -> ProgramInfo {
        ProgramInfo {
            url: url.into(),
            name: "test.exe".into(),
            regions: vec![("ram".into(), 0x400000, 0x500000)],
            sections: vec![
                (".text".into(), 0x401000, 0x402000),
                (".data".into(), 0x403000, 0x404000),
            ],
            preferred_base: 0x400000,
        }
    }

    fn make_trace_info() -> TraceMappingInfo {
        TraceMappingInfo {
            regions: vec![
                ("ram".into(), 0x401000, 0x402000),
                ("ram".into(), 0x503000, 0x504000),
            ],
            module_bases: vec![0x400000],
            has_aslr: false,
        }
    }

    #[test]
    fn test_auto_map_candidates() {
        let mut svc = AutoMapServiceImpl::new();
        svc.register_program(make_program("test.exe"));
        svc.register_trace_info(1, make_trace_info());

        let candidates = svc.find_candidates("test.exe", 1);
        assert!(!candidates.is_empty());

        // .text section (size 0x1000) should match first trace region (size 0x1000)
        let text_match = candidates.iter().find(|c| c.section_name == ".text");
        assert!(text_match.is_some());
        assert_eq!(text_match.unwrap().confidence, 0.99);
    }

    #[test]
    fn test_auto_map_service() {
        let mut svc = AutoMapServiceImpl::new();
        svc.register_program(make_program("test.exe"));
        svc.register_trace_info(1, make_trace_info());

        let proposals = svc.propose_mapping("test.exe", 1);
        assert!(!proposals.is_empty());

        let result = svc.auto_map("test.exe", 1, Lifespan::at(0));
        assert!(result.is_ok());
    }

    #[test]
    fn test_auto_map_disabled() {
        let mut svc = AutoMapServiceImpl::new();
        svc.set_enabled(false);
        assert!(!svc.is_enabled());

        let result = svc.auto_map("test.exe", 1, Lifespan::at(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_section_matcher() {
        let program = vec![
            (".text".into(), 0x401000, 0x402000),
            (".data".into(), 0x403000, 0x404000),
        ];
        let trace = vec![
            ("text".into(), 0x501000, 0x502000),
            ("data".into(), 0x503000, 0x504000),
            ("heap".into(), 0x600000, 0x700000),
        ];

        let matches = SectionMatcher::match_by_name(&program, &trace);
        // ".text" should match "text", ".data" should match "data"
        assert!(matches.len() >= 2);
    }
}
