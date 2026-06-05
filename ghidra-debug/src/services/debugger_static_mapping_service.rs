//! DebuggerStaticMappingService - service for managing static mappings.
//!
//! Ported from Ghidra's `ghidra.app.services.DebuggerStaticMappingService`.

use crate::model::Lifespan;
use serde::{Deserialize, Serialize};

/// A static mapping between a program address range and a trace address range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMappingEntry {
    /// Program URL.
    pub program_url: String,
    /// Program address range start.
    pub program_min: u64,
    /// Program address range end.
    pub program_max: u64,
    /// Trace address range start.
    pub trace_min: u64,
    /// Trace address range end.
    pub trace_max: u64,
    /// The snap range.
    pub lifespan: Lifespan,
    /// The module name in the trace, if mapped by module.
    pub trace_module_path: Option<String>,
}

/// Service interface for managing static mappings.
pub trait DebuggerStaticMappingServiceExt {
    /// Add a mapping.
    fn add_mapping(&mut self, entry: StaticMappingEntry) -> Result<(), String>;

    /// Remove a mapping by program URL and address range.
    fn remove_mapping(
        &mut self,
        program_url: &str,
        program_min: u64,
        program_max: u64,
    ) -> Result<(), String>;

    /// Get all mappings for a program.
    fn get_mappings_for_program(&self, program_url: &str) -> Vec<&StaticMappingEntry>;

    /// Get all mappings for a trace.
    fn get_mappings_for_trace(&self, trace_key: i64) -> Vec<&StaticMappingEntry>;

    /// Translate a program address to a trace address.
    fn translate_to_trace(
        &self,
        program_url: &str,
        program_addr: u64,
        snap: i64,
    ) -> Option<(u64, String)>;

    /// Translate a trace address to a program address.
    fn translate_to_program(
        &self,
        trace_addr: u64,
        snap: i64,
    ) -> Option<(String, u64)>;

    /// Get all mapping entries.
    fn all_entries(&self) -> Vec<&StaticMappingEntry>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_mapping_entry() {
        let entry = StaticMappingEntry {
            program_url: "file:///test".into(),
            program_min: 0,
            program_max: 0x1000,
            trace_min: 0x400000,
            trace_max: 0x401000,
            lifespan: Lifespan::new(0, i64::MAX),
            trace_module_path: Some("/modules/libc.so".into()),
        };
        assert_eq!(entry.program_url, "file:///test");
        assert_eq!(entry.trace_module_path.as_deref(), Some("/modules/libc.so"));
    }
}
