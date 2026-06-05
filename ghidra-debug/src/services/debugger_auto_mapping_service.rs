//! DebuggerAutoMappingService - service for automatic program-to-trace mapping.
//!
//! Ported from Ghidra's `ghidra.app.services.DebuggerAutoMappingService`.

use crate::model::Lifespan;
use serde::{Deserialize, Serialize};

/// A proposal for automatically mapping a program to a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoMappingProposal {
    /// The program URL.
    pub program_url: String,
    /// The trace key.
    pub trace_key: i64,
    /// Proposed address mappings.
    pub entries: Vec<AutoMappingEntry>,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
}

/// A single entry in an auto-mapping proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoMappingEntry {
    /// Program address range start.
    pub program_min: u64,
    /// Program address range end.
    pub program_max: u64,
    /// Trace address range start.
    pub trace_min: u64,
    /// Trace address range end.
    pub trace_max: u64,
    /// The snap range for this mapping.
    pub lifespan: Lifespan,
    /// The matched module/section name, if any.
    pub matched_name: Option<String>,
}

/// Service interface for automatic mapping between programs and traces.
pub trait DebuggerAutoMappingServiceExt {
    /// Propose automatic mappings for a program.
    fn propose_mappings(
        &self,
        program_url: &str,
        trace_key: i64,
    ) -> Vec<AutoMappingProposal>;

    /// Execute a mapping proposal.
    fn execute_mapping(&mut self, proposal: &AutoMappingProposal) -> Result<(), String>;

    /// Auto-map all open programs to a trace.
    fn auto_map_all(&mut self, trace_key: i64) -> Result<Vec<AutoMappingProposal>, String>;

    /// Get the current auto-map mode.
    fn auto_map_mode(&self) -> AutoMapMode;

    /// Set the auto-map mode.
    fn set_auto_map_mode(&mut self, mode: AutoMapMode);
}

/// Auto-mapping mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AutoMapMode {
    /// No automatic mapping.
    None,
    /// Map by module name.
    ByModule,
    /// Map by section name.
    BySection,
    /// Map by region.
    ByRegion,
    /// One-to-one mapping.
    OneToOne,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_mapping_entry() {
        let entry = AutoMappingEntry {
            program_min: 0,
            program_max: 0x1000,
            trace_min: 0x400000,
            trace_max: 0x401000,
            lifespan: Lifespan::span(0, i64::MAX),
            matched_name: Some(".text".into()),
        };
        assert_eq!(entry.matched_name.as_deref(), Some(".text"));
    }

    #[test]
    fn test_auto_map_modes() {
        assert_ne!(AutoMapMode::None, AutoMapMode::ByModule);
        assert_ne!(AutoMapMode::BySection, AutoMapMode::OneToOne);
    }

    #[test]
    fn test_proposal() {
        let proposal = AutoMappingProposal {
            program_url: "file:///test".into(),
            trace_key: 1,
            entries: vec![],
            confidence: 0.95,
        };
        assert_eq!(proposal.confidence, 0.95);
    }
}
