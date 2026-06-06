//! Breakpoint time overview color service.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.timeoverview.breakpoint`
//! package.
//!
//! Provides the `CellType` enum for activity-cell classification and the
//! `BreakpointTimeOverviewColorService` that maps cells to colors.

use serde::{Deserialize, Serialize};

/// The kind of activity recorded at a cell in the breakpoint overview.
///
/// Ported from `CellType.java`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CellType {
    /// An instruction was executed at this cell.
    InstructionExecuted,
    /// Memory was read.
    MemoryRead,
    /// Memory was written.
    MemoryWritten,
    /// The current execution location.
    CurrentLocation,
}

impl CellType {
    /// Return a human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::InstructionExecuted => "Instruction Executed",
            Self::MemoryRead => "Memory Read",
            Self::MemoryWritten => "Memory Written",
            Self::CurrentLocation => "Current Location",
        }
    }

    /// Return the default ARGB color.
    pub fn default_color_rgba(&self) -> u32 {
        match self {
            Self::InstructionExecuted => 0xFF_40_40_80,
            Self::MemoryRead => 0xFF_40_80_40,
            Self::MemoryWritten => 0xFF_80_40_40,
            Self::CurrentLocation => 0xFF_00_FF_00,
        }
    }

    /// Return the default color key.
    pub fn default_color_key(&self) -> &'static str {
        match self {
            Self::InstructionExecuted => {
                "color.debugger.plugin.timeoverview.box.type.instructions"
            }
            Self::MemoryRead => "color.debugger.plugin.timeoverview.box.type.read.memory",
            Self::MemoryWritten => "color.debugger.plugin.timeoverview.box.type.write.memory",
            Self::CurrentLocation => "color.palette.green",
        }
    }

    /// All known cell types.
    pub fn all() -> &'static [CellType] {
        &[
            Self::InstructionExecuted,
            Self::MemoryRead,
            Self::MemoryWritten,
            Self::CurrentLocation,
        ]
    }
}

impl std::fmt::Display for CellType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.description())
    }
}

/// Configuration for the breakpoint time overview color service.
///
/// Ported from `BreakpointTimeOverviewColorService.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointTimeOverviewColorService {
    /// Colors for each cell type (ARGB).
    pub cell_colors: std::collections::HashMap<CellType, u32>,
    /// Color for cells with no activity.
    pub inactive_color: u32,
    /// Color for the address bar separator.
    pub separator_color: u32,
    /// Whether to show the legend.
    pub show_legend: bool,
    /// The reference type filter (if any).
    pub ref_type_filter: Option<String>,
    /// Address ranges of interest.
    pub address_ranges: Vec<AddressRange>,
}

/// An address range for breakpoint overview filtering.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressRange {
    /// Start address (inclusive).
    pub min: u64,
    /// End address (inclusive).
    pub max: u64,
    /// The address space name.
    pub space: String,
}

impl Default for BreakpointTimeOverviewColorService {
    fn default() -> Self {
        let mut cell_colors = std::collections::HashMap::new();
        for &ct in CellType::all() {
            cell_colors.insert(ct, ct.default_color_rgba());
        }
        Self {
            cell_colors,
            inactive_color: 0xFF_E0_E0_E0,
            separator_color: 0xFF_40_40_40,
            show_legend: true,
            ref_type_filter: None,
            address_ranges: Vec::new(),
        }
    }
}

impl BreakpointTimeOverviewColorService {
    /// Get the color for a cell type.
    pub fn color_for_cell(&self, ct: CellType) -> u32 {
        self.cell_colors
            .get(&ct)
            .copied()
            .unwrap_or(ct.default_color_rgba())
    }

    /// Override the color for a cell type.
    pub fn set_color(&mut self, ct: CellType, color: u32) {
        self.cell_colors.insert(ct, color);
    }

    /// Classify the dominant activity at a cell given a list of observed types.
    pub fn classify_cell(&self, activities: &[CellType]) -> Option<CellType> {
        let priority = [
            CellType::CurrentLocation,
            CellType::InstructionExecuted,
            CellType::MemoryRead,
            CellType::MemoryWritten,
        ];
        for &p in &priority {
            if activities.contains(&p) {
                return Some(p);
            }
        }
        None
    }

    /// Compute the color for a cell given observed activities.
    pub fn compute_cell_color(&self, activities: &[CellType]) -> u32 {
        self.classify_cell(activities)
            .map(|ct| self.color_for_cell(ct))
            .unwrap_or(self.inactive_color)
    }

    /// Add an address range to the filter.
    pub fn add_address_range(&mut self, range: AddressRange) {
        self.address_ranges.push(range);
    }

    /// Clear all address ranges.
    pub fn clear_address_ranges(&mut self) {
        self.address_ranges.clear();
    }
}

/// A legend entry for the breakpoint overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointLegendEntry {
    /// The cell type.
    pub cell_type: CellType,
    /// The display label.
    pub label: String,
    /// The ARGB color.
    pub color: u32,
}

impl BreakpointLegendEntry {
    /// Build the full legend.
    pub fn build_legend(service: &BreakpointTimeOverviewColorService) -> Vec<Self> {
        CellType::all()
            .iter()
            .map(|&ct| Self {
                cell_type: ct,
                label: ct.description().to_string(),
                color: service.color_for_cell(ct),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_type_descriptions() {
        assert_eq!(
            CellType::InstructionExecuted.description(),
            "Instruction Executed"
        );
        assert_eq!(CellType::MemoryRead.description(), "Memory Read");
        assert_eq!(CellType::CurrentLocation.description(), "Current Location");
    }

    #[test]
    fn test_cell_type_display() {
        assert_eq!(
            format!("{}", CellType::MemoryWritten),
            "Memory Written"
        );
    }

    #[test]
    fn test_cell_type_all() {
        assert_eq!(CellType::all().len(), 4);
    }

    #[test]
    fn test_color_service_default() {
        let svc = BreakpointTimeOverviewColorService::default();
        assert_eq!(svc.cell_colors.len(), 4);
        assert!(svc.show_legend);
    }

    #[test]
    fn test_color_service_override() {
        let mut svc = BreakpointTimeOverviewColorService::default();
        let custom = 0xFF_11_22_33;
        svc.set_color(CellType::InstructionExecuted, custom);
        assert_eq!(svc.color_for_cell(CellType::InstructionExecuted), custom);
    }

    #[test]
    fn test_classify_cell_priority() {
        let svc = BreakpointTimeOverviewColorService::default();
        let activities = vec![CellType::MemoryRead, CellType::CurrentLocation];
        assert_eq!(
            svc.classify_cell(&activities),
            Some(CellType::CurrentLocation)
        );
    }

    #[test]
    fn test_classify_cell_empty() {
        let svc = BreakpointTimeOverviewColorService::default();
        assert!(svc.classify_cell(&[]).is_none());
    }

    #[test]
    fn test_compute_cell_color_inactive() {
        let svc = BreakpointTimeOverviewColorService::default();
        assert_eq!(svc.compute_cell_color(&[]), svc.inactive_color);
    }

    #[test]
    fn test_address_ranges() {
        let mut svc = BreakpointTimeOverviewColorService::default();
        svc.add_address_range(AddressRange {
            min: 0x400000,
            max: 0x401000,
            space: "ram".into(),
        });
        assert_eq!(svc.address_ranges.len(), 1);
        svc.clear_address_ranges();
        assert!(svc.address_ranges.is_empty());
    }

    #[test]
    fn test_legend_entry_build() {
        let svc = BreakpointTimeOverviewColorService::default();
        let legend = BreakpointLegendEntry::build_legend(&svc);
        assert_eq!(legend.len(), 4);
        assert_eq!(legend[0].label, "Instruction Executed");
    }

    #[test]
    fn test_ref_type_filter() {
        let mut svc = BreakpointTimeOverviewColorService::default();
        assert!(svc.ref_type_filter.is_none());
        svc.ref_type_filter = Some("read".into());
        assert_eq!(svc.ref_type_filter.as_deref(), Some("read"));
    }
}
