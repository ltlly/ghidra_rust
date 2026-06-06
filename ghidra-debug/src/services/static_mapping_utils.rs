//! Static mapping utilities ported from Java.
//!
//! Ported from `DebuggerStaticMappingUtils` in the Debugger module.
//! Provides utility functions for managing static mappings between
//! programs and traces, including auto-mapping proposals.

use crate::model::Lifespan;
use crate::model::map_proposal::{
    ModuleMapProposal, RegionMapProposal, SectionMapProposal, SectionMapping,
};

/// Utility functions for static mapping operations.
pub struct StaticMappingUtils;

impl StaticMappingUtils {
    /// Create a default module-level map proposal.
    pub fn create_module_proposal(
        module_name: &str,
        program_base: u64,
        trace_base: u64,
        length: u64,
    ) -> ModuleMapProposal {
        ModuleMapProposal::new(module_name, trace_base, program_base, length, Lifespan::ALL)
    }

    /// Create a default region-level map proposal.
    pub fn create_region_proposal(
        region_name: &str,
        program_start: u64,
        program_end: u64,
        trace_start: u64,
        trace_end: u64,
    ) -> RegionMapProposal {
        RegionMapProposal {
            region_name: region_name.to_string(),
            trace_start,
            trace_end,
            program_start,
            program_end,
            lifespan: Lifespan::ALL,
            permissions: crate::model::map_proposal::RegionPermissions::READ,
        }
    }

    /// Create a default section-level map proposal.
    pub fn create_section_proposal(
        module_name: &str,
        section_name: &str,
        program_start: u64,
        program_end: u64,
        trace_start: u64,
        trace_end: u64,
    ) -> SectionMapProposal {
        SectionMapProposal {
            module_name: module_name.to_string(),
            sections: vec![SectionMapping {
                name: section_name.to_string(),
                trace_start,
                trace_end,
                program_start,
                program_end,
                executable: true,
                writable: false,
                readable: true,
            }],
            lifespan: Lifespan::ALL,
        }
    }

    /// Compute the overlap between two address ranges.
    pub fn compute_overlap(
        (min1, max1): (u64, u64),
        (min2, max2): (u64, u64),
    ) -> Option<(u64, u64)> {
        let overlap_min = min1.max(min2);
        let overlap_max = max1.min(max2);
        if overlap_min <= overlap_max {
            Some((overlap_min, overlap_max))
        } else {
            None
        }
    }

    /// Translate an address from program space to trace space using a mapping.
    pub fn translate_address(
        program_addr: u64,
        program_min: u64,
        trace_min: u64,
        length: u64,
    ) -> Option<u64> {
        if program_addr >= program_min && program_addr < program_min + length {
            let offset = program_addr - program_min;
            Some(trace_min + offset)
        } else {
            None
        }
    }

    /// Reverse-translate an address from trace space to program space.
    pub fn reverse_translate(
        trace_addr: u64,
        program_min: u64,
        trace_min: u64,
        length: u64,
    ) -> Option<u64> {
        if trace_addr >= trace_min && trace_addr < trace_min + length {
            let offset = trace_addr - trace_min;
            Some(program_min + offset)
        } else {
            None
        }
    }

    /// Check if two mapping ranges are compatible for merging.
    pub fn are_compatible(
        prog_min1: u64, trace_min1: u64, _len1: u64,
        prog_min2: u64, trace_min2: u64, _len2: u64,
    ) -> bool {
        // Check that the relative offsets are consistent
        let offset1 = trace_min1.wrapping_sub(prog_min1);
        let offset2 = trace_min2.wrapping_sub(prog_min2);
        offset1 == offset2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_address() {
        // Program range [0x1000, 0x2000) maps to trace range [0x400000, 0x401000)
        assert_eq!(
            StaticMappingUtils::translate_address(0x1500, 0x1000, 0x400000, 0x1000),
            Some(0x400500)
        );
        assert_eq!(
            StaticMappingUtils::translate_address(0x2000, 0x1000, 0x400000, 0x1000),
            None
        );
    }

    #[test]
    fn test_reverse_translate() {
        assert_eq!(
            StaticMappingUtils::reverse_translate(0x400500, 0x1000, 0x400000, 0x1000),
            Some(0x1500)
        );
    }

    #[test]
    fn test_compute_overlap() {
        assert_eq!(
            StaticMappingUtils::compute_overlap((0, 100), (50, 150)),
            Some((50, 100))
        );
        assert_eq!(
            StaticMappingUtils::compute_overlap((0, 10), (20, 30)),
            None
        );
    }

    #[test]
    fn test_compatible_mappings() {
        assert!(StaticMappingUtils::are_compatible(
            0x1000, 0x400000, 0x1000,
            0x2000, 0x401000, 0x1000
        ));
        assert!(!StaticMappingUtils::are_compatible(
            0x1000, 0x400000, 0x1000,
            0x2000, 0x500000, 0x1000
        ));
    }

    #[test]
    fn test_create_proposals() {
        let mp = StaticMappingUtils::create_module_proposal("libc", 0, 0x400000, 0x1000);
        assert_eq!(mp.module_name, "libc");

        let rp = StaticMappingUtils::create_region_proposal(".text", 0, 0x1000, 0x400000, 0x401000);
        assert_eq!(rp.region_name, ".text");
    }
}
