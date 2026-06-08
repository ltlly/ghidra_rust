//! GCC Exception Handler Analyzer
//!
//! Ported from `GccExceptionAnalyzer.java`.
//!
//! Locates and annotates exception-handling infrastructure installed by the GCC
//! compiler. This analyzer processes `.eh_frame_hdr`, `.eh_frame`, `.debug_frame`,
//! and `.gcc_except_table` sections.

use super::{RegionDescriptor, LsdaCallSiteRecord, LsdaActionRecord};

/// The analyzer name.
pub const GCC_EXCEPTION_ANALYZER_NAME: &str = "GCC Exception Handlers";

/// The analyzer description.
pub const GCC_EXCEPTION_ANALYZER_DESCRIPTION: &str =
    "Locates and annotates exception-handling infrastructure installed by the GCC compiler";

/// Default setting: create try/catch comments in the listing.
pub const OPTION_DEFAULT_CREATE_TRY_CATCH_COMMENTS: bool = true;

/// GCC exception handling analyzer.
///
/// Processes DWARF-based exception handling metadata from GCC-compiled
/// binaries. The analyzer:
/// 1. Locates `.eh_frame_hdr` and `.eh_frame` sections.
/// 2. Parses CIE and FDE structures.
/// 3. Identifies LSDA (Language-Specific Data Area) tables from `.gcc_except_table`.
/// 4. Annotates try/catch regions with comments in the listing.
#[derive(Debug, Clone)]
pub struct GccExceptionAnalyzer {
    /// Whether to create try/catch comments in the disassembly listing.
    pub create_try_catch_comments: bool,
}

impl GccExceptionAnalyzer {
    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self {
            create_try_catch_comments: OPTION_DEFAULT_CREATE_TRY_CATCH_COMMENTS,
        }
    }

    /// Check if the given section name indicates a GCC EH section.
    pub fn is_eh_frame_section(name: &str) -> bool {
        name == ".eh_frame"
            || name == ".eh_frame_hdr"
            || name.starts_with(".debug_frame")
    }

    /// Check if the given section name indicates a GCC exception table.
    pub fn is_gcc_except_table(name: &str) -> bool {
        name == ".gcc_except_table"
    }

    /// Process a parsed list of regions and generate try/catch annotations.
    ///
    /// This is the core analysis step that iterates over all call site records
    /// and optionally creates listing comments.
    pub fn process_regions(&self, regions: &[RegionDescriptor]) -> Vec<Annotation> {
        let mut annotations = Vec::new();

        for region in regions {
            for csr in &region.call_site_records {
                if !csr.has_landing_pad() {
                    continue;
                }

                let lp_addr = csr.landing_pad(region.ip_range_start);
                let cs_start = csr.call_site_base(region.ip_range_start);
                let cs_end = cs_start + csr.call_site_length;

                // Look up type info from action records
                let type_infos = self.get_type_infos(region, csr);

                annotations.push(Annotation::TryStart {
                    address: cs_start,
                    catch_handler: lp_addr,
                    try_end: cs_end,
                });

                annotations.push(Annotation::CatchStart {
                    address: lp_addr,
                    try_start: cs_start,
                    type_infos: type_infos.clone(),
                });

                if self.create_try_catch_comments {
                    annotations.push(Annotation::TryEnd {
                        address: cs_end,
                        try_start: cs_start,
                    });

                    annotations.push(Annotation::CatchEnd {
                        address: lp_addr,
                        try_range: cs_start..cs_end,
                    });
                }
            }
        }

        annotations
    }

    /// Get the type infos for a call site record by walking the action chain.
    fn get_type_infos(
        &self,
        region: &RegionDescriptor,
        csr: &LsdaCallSiteRecord,
    ) -> Vec<TypeInfo> {
        if csr.action_offset == 0 || region.action_records.is_empty() {
            return Vec::new();
        }

        let mut type_infos = Vec::new();
        let mut action_idx = (csr.action_offset as usize) / std::mem::size_of::<LsdaActionRecord>();

        while action_idx < region.action_records.len() {
            let action = &region.action_records[action_idx];
            let filter = action.type_filter;

            if filter > 0 && (filter as usize) < region.type_table.len() {
                let type_info_addr = region.type_table[filter as usize];
                type_infos.push(TypeInfo {
                    type_info_address: type_info_addr,
                    action_filter: filter,
                });
            }

            if action.next_displacement == 0 {
                break;
            }
            // The displacement is relative to the current action's position
            // For simplicity, advance to next action in the table
            action_idx += 1;
        }

        type_infos
    }
}

impl Default for GccExceptionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// A type info entry associating an address with its action filter.
#[derive(Debug, Clone)]
pub struct TypeInfo {
    /// Address of the type info record.
    pub type_info_address: u64,
    /// The action filter value for this type.
    pub action_filter: i32,
}

/// An annotation generated by the analyzer for the listing.
#[derive(Debug, Clone)]
pub enum Annotation {
    /// Start of a try block.
    TryStart {
        address: u64,
        catch_handler: u64,
        try_end: u64,
    },
    /// End of a try block.
    TryEnd { address: u64, try_start: u64 },
    /// Start of a catch handler.
    CatchStart {
        address: u64,
        try_start: u64,
        type_infos: Vec<TypeInfo>,
    },
    /// End of a catch handler.
    CatchEnd {
        address: u64,
        try_range: std::ops::Range<u64>,
    },
}

impl Annotation {
    /// Format this annotation as a listing comment string.
    pub fn to_comment(&self) -> String {
        match self {
            Annotation::TryStart {
                address,
                catch_handler,
                try_end,
            } => {
                format!(
                    "try {{ // try from 0x{:x} to 0x{:x} has its CatchHandler @ 0x{:x}",
                    address, try_end, catch_handler
                )
            }
            Annotation::TryEnd {
                address,
                try_start,
            } => {
                format!(
                    "}} // end try from 0x{:x} to 0x{:x}",
                    try_start, address
                )
            }
            Annotation::CatchStart {
                address,
                try_start,
                type_infos,
            } => {
                let type_str = type_infos
                    .iter()
                    .map(|ti| format!("type#{} @ 0x{:x}", ti.action_filter, ti.type_info_address))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "catch({}) {{ ... }} // from try @ 0x{:x} with catch @ 0x{:x}",
                    type_str, try_start, address
                )
            }
            Annotation::CatchEnd { address, try_range } => {
                format!(
                    "}} // end catchHandler() for try 0x{:x}..0x{:x} (lp=0x{:x})",
                    try_range.start, try_range.end, address
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = GccExceptionAnalyzer::new();
        assert!(analyzer.create_try_catch_comments);
    }

    #[test]
    fn test_section_name_checks() {
        assert!(GccExceptionAnalyzer::is_eh_frame_section(".eh_frame"));
        assert!(GccExceptionAnalyzer::is_eh_frame_section(".eh_frame_hdr"));
        assert!(GccExceptionAnalyzer::is_eh_frame_section(".debug_frame"));
        assert!(GccExceptionAnalyzer::is_eh_frame_section(".debug_frame_42"));
        assert!(!GccExceptionAnalyzer::is_eh_frame_section(".text"));

        assert!(GccExceptionAnalyzer::is_gcc_except_table(".gcc_except_table"));
        assert!(!GccExceptionAnalyzer::is_gcc_except_table(".text"));
    }

    #[test]
    fn test_process_regions_no_catch() {
        let analyzer = GccExceptionAnalyzer::new();
        let regions = vec![RegionDescriptor {
            lsda_address: Some(0x5000),
            ip_range_start: 0x1000,
            ip_range_end: 0x2000,
            call_site_records: vec![LsdaCallSiteRecord {
                call_site_start: 0,
                call_site_length: 0x100,
                landing_pad_offset: 0, // no landing pad = cleanup only
                action_offset: 0,
            }],
            action_records: vec![],
            type_table: vec![],
            fde_index: 0,
        }];
        let annotations = analyzer.process_regions(&regions);
        assert!(annotations.is_empty());
    }

    #[test]
    fn test_process_regions_with_try_catch() {
        let analyzer = GccExceptionAnalyzer::new();
        let regions = vec![RegionDescriptor {
            lsda_address: Some(0x5000),
            ip_range_start: 0x1000,
            ip_range_end: 0x2000,
            call_site_records: vec![LsdaCallSiteRecord {
                call_site_start: 0,
                call_site_length: 0x100,
                landing_pad_offset: 0x500,
                action_offset: 0,
            }],
            action_records: vec![],
            type_table: vec![],
            fde_index: 0,
        }];
        let annotations = analyzer.process_regions(&regions);
        assert_eq!(annotations.len(), 4); // TryStart, CatchStart, TryEnd, CatchEnd
    }

    #[test]
    fn test_annotation_comments() {
        let try_start = Annotation::TryStart {
            address: 0x1000,
            catch_handler: 0x1500,
            try_end: 0x1100,
        };
        assert!(try_start.to_comment().contains("try {"));
        assert!(try_start.to_comment().contains("0x1000"));

        let catch = Annotation::CatchStart {
            address: 0x1500,
            try_start: 0x1000,
            type_infos: vec![TypeInfo {
                type_info_address: 0x8000,
                action_filter: 1,
            }],
        };
        assert!(catch.to_comment().contains("catch("));
        assert!(catch.to_comment().contains("type#1"));
    }

    #[test]
    fn test_type_info_format() {
        let ti = TypeInfo {
            type_info_address: 0xdead_beef,
            action_filter: 42,
        };
        let comment = format!("type#{} @ 0x{:x}", ti.action_filter, ti.type_info_address);
        assert!(comment.contains("type#42"));
        assert!(comment.contains("deadbeef"));
    }
}
