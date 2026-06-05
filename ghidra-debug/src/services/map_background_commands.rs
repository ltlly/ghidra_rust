//! Background mapping commands ported from Java.
//!
//! Ported from `MapModulesBackgroundCommand`, `MapRegionsBackgroundCommand`,
//! `MapSectionsBackgroundCommand` in the Debugger module. These are
//! the execution primitives for applying mapping proposals in the background.

use crate::model::Lifespan;
use crate::model::map_proposal::{
    MapProposal, ModuleMapProposal, ProposedMapping, RegionMapProposal, SectionMapProposal,
};
use super::module_region_matcher::{LoadedModule, ModuleRegionMatch, ProgramRegion};

/// The result of a background mapping operation.
#[derive(Debug, Clone)]
pub struct MapCommandResult {
    /// Number of mappings successfully applied.
    pub applied_count: usize,
    /// Number of mappings that failed.
    pub failed_count: usize,
    /// Error messages for failed mappings.
    pub errors: Vec<String>,
    /// The proposed mappings that were applied.
    pub applied_mappings: Vec<ProposedMapping>,
}

impl MapCommandResult {
    /// Create an empty result.
    pub fn new() -> Self {
        Self {
            applied_count: 0,
            failed_count: 0,
            errors: Vec::new(),
            applied_mappings: Vec::new(),
        }
    }

    /// Whether all mappings succeeded.
    pub fn is_success(&self) -> bool {
        self.failed_count == 0
    }

    /// Total number of mappings attempted.
    pub fn total(&self) -> usize {
        self.applied_count + self.failed_count
    }
}

/// Command to map modules from a trace to a program.
///
/// Iterates over loaded modules and applies address mappings using
/// module name matching and base address offsets.
pub struct MapModulesCommand {
    modules: Vec<LoadedModule>,
    program_regions: Vec<ProgramRegion>,
    lifespan: Lifespan,
}

impl MapModulesCommand {
    /// Create a new command.
    pub fn new(
        modules: Vec<LoadedModule>,
        program_regions: Vec<ProgramRegion>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            modules,
            program_regions,
            lifespan,
        }
    }

    /// Execute the mapping command, returning proposed mappings.
    pub fn execute(&self) -> MapCommandResult {
        let matcher = super::module_region_matcher::ModuleRegionMatcher::new();
        let matches = matcher.match_modules(&self.modules, &self.program_regions);
        let deduped = super::module_region_matcher::ModuleRegionMatcher::deduplicate(&matches);

        let mut result = MapCommandResult::new();
        for m in deduped {
            let length = m.region.size;
            let proposed = ProposedMapping {
                name: m.module.name.clone(),
                program_min: m.region.start_address,
                program_max: m.region.start_address + m.region.size,
                trace_min: m.module.base_address,
                trace_max: m.module.base_address + m.module.size,
                length,
                lifespan: self.lifespan,
                read_only: false,
                section_name: None,
                module_name: Some(m.module.name.clone()),
            };
            result.applied_mappings.push(proposed);
            result.applied_count += 1;
        }
        result
    }
}

/// Command to map memory regions from a trace to a program.
pub struct MapRegionsCommand {
    trace_regions: Vec<LoadedModule>,
    program_regions: Vec<ProgramRegion>,
    lifespan: Lifespan,
}

impl MapRegionsCommand {
    /// Create a new regions mapping command.
    pub fn new(
        trace_regions: Vec<LoadedModule>,
        program_regions: Vec<ProgramRegion>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            trace_regions,
            program_regions,
            lifespan,
        }
    }

    /// Execute the regions mapping.
    pub fn execute(&self) -> MapCommandResult {
        let matcher = super::module_region_matcher::ModuleRegionMatcher::new();
        let matches = matcher.match_modules(&self.trace_regions, &self.program_regions);

        let mut result = MapCommandResult::new();
        for m in &matches {
            if m.confidence >= 0.5 {
                let length = m.region.size;
                let proposed = ProposedMapping {
                    name: m.module.name.clone(),
                    program_min: m.region.start_address,
                    program_max: m.region.start_address + m.region.size,
                    trace_min: m.module.base_address,
                    trace_max: m.module.base_address + m.module.size,
                    length,
                    lifespan: self.lifespan,
                    read_only: false,
                    section_name: None,
                    module_name: Some(m.module.name.clone()),
                };
                result.applied_mappings.push(proposed);
                result.applied_count += 1;
            } else {
                result.failed_count += 1;
                result.errors.push(format!(
                    "Low confidence ({:.2}) for region '{}'",
                    m.confidence, m.region.name
                ));
            }
        }
        result
    }
}

/// Command to map sections from a trace to a program.
pub struct MapSectionsCommand {
    sections: Vec<LoadedModule>,
    program_sections: Vec<ProgramRegion>,
    lifespan: Lifespan,
}

impl MapSectionsCommand {
    /// Create a new sections mapping command.
    pub fn new(
        sections: Vec<LoadedModule>,
        program_sections: Vec<ProgramRegion>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            sections,
            program_sections,
            lifespan,
        }
    }

    /// Execute the sections mapping.
    pub fn execute(&self) -> MapCommandResult {
        let matcher = super::module_region_matcher::ModuleRegionMatcher::new();
        let matches = matcher.match_modules(&self.sections, &self.program_sections);

        let mut result = MapCommandResult::new();
        for m in &matches {
            let length = m.region.size;
            let proposed = ProposedMapping {
                name: m.module.name.clone(),
                program_min: m.region.start_address,
                program_max: m.region.start_address + m.region.size,
                trace_min: m.module.base_address,
                trace_max: m.module.base_address + m.module.size,
                length,
                lifespan: self.lifespan,
                read_only: false,
                section_name: None,
                module_name: Some(m.module.name.clone()),
            };
            result.applied_mappings.push(proposed);
            result.applied_count += 1;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Lifespan;

    #[test]
    fn test_map_modules_command() {
        let modules = vec![
            LoadedModule {
                name: "libc.so".into(),
                base_address: 0x7f000000,
                size: 0x100000,
                file_path: "/usr/lib/libc.so".into(),
            },
        ];
        let regions = vec![
            ProgramRegion {
                name: "libc".into(),
                start_address: 0x400000,
                size: 0x100000,
                is_executable: true,
                is_writable: false,
            },
        ];

        let cmd = MapModulesCommand::new(modules, regions, Lifespan::span(0, 100));
        let result = cmd.execute();
        assert_eq!(result.applied_count, 1);
        assert!(result.is_success());
    }

    #[test]
    fn test_map_command_result() {
        let result = MapCommandResult::new();
        assert_eq!(result.total(), 0);
        assert!(result.is_success());
    }
}
