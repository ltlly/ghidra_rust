//! Time-type overview color service.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.timeoverview.timetype`
//! package.
//!
//! Provides the `TimeType` enum that labels the kind of change that occurred
//! at each snapshot, and the `TimeTypeOverviewColorService` that maps those
//! types to colors for the time overview bar.

use serde::{Deserialize, Serialize};

/// The kind of trace change at a snapshot.
///
/// Ported from `TimeType.java`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimeType {
    /// A thread was added.
    ThreadAdded,
    /// A thread was removed.
    ThreadRemoved,
    /// A thread property changed.
    ThreadChanged,
    /// A module (loaded image) was added.
    ModuleAdded,
    /// A module was removed.
    ModuleRemoved,
    /// A module property changed.
    ModuleChanged,
    /// A memory region was added.
    MemoryAdded,
    /// A memory region was removed.
    MemoryRemoved,
    /// A memory region property changed.
    MemoryChanged,
    /// A breakpoint was added.
    BreakpointAdded,
    /// A breakpoint was removed.
    BreakpointRemoved,
    /// A breakpoint property changed.
    BreakpointChanged,
    /// The current execution location.
    CurrentLocation,
}

impl TimeType {
    /// Return the short label used in the overview legend.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ThreadAdded => "+T",
            Self::ThreadRemoved => "-T",
            Self::ThreadChanged => "*T",
            Self::ModuleAdded => "+M",
            Self::ModuleRemoved => "-M",
            Self::ModuleChanged => "*M",
            Self::MemoryAdded => "+Mem",
            Self::MemoryRemoved => "-Mem",
            Self::MemoryChanged => "*Mem",
            Self::BreakpointAdded => "+B",
            Self::BreakpointRemoved => "-B",
            Self::BreakpointChanged => "*B",
            Self::CurrentLocation => "Now",
        }
    }

    /// Return the full description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::ThreadAdded => "Thread Added",
            Self::ThreadRemoved => "Thread Removed",
            Self::ThreadChanged => "Thread Changed",
            Self::ModuleAdded => "Module Added",
            Self::ModuleRemoved => "Module Removed",
            Self::ModuleChanged => "Module Changed",
            Self::MemoryAdded => "Memory Added",
            Self::MemoryRemoved => "Memory Removed",
            Self::MemoryChanged => "Memory Changed",
            Self::BreakpointAdded => "Breakpoint Added",
            Self::BreakpointRemoved => "Breakpoint Removed",
            Self::BreakpointChanged => "Breakpoint Changed",
            Self::CurrentLocation => "Current Location",
        }
    }

    /// Return the default color key (a CSS-like color identifier).
    pub fn default_color_key(&self) -> &'static str {
        match self {
            Self::ThreadAdded => "color.debugger.plugin.timeoverview.box.type.thread.added",
            Self::ThreadRemoved => "color.debugger.plugin.timeoverview.box.type.thread.removed",
            Self::ThreadChanged => "color.debugger.plugin.timeoverview.box.type.thread.changed",
            Self::ModuleAdded => "color.debugger.plugin.timeoverview.box.type.module.added",
            Self::ModuleRemoved => "color.debugger.plugin.timeoverview.box.type.module.removed",
            Self::ModuleChanged => "color.debugger.plugin.timeoverview.box.type.module.changed",
            Self::MemoryAdded => "color.debugger.plugin.timeoverview.box.type.memory.added",
            Self::MemoryRemoved => "color.debugger.plugin.timeoverview.box.type.memory.removed",
            Self::MemoryChanged => "color.debugger.plugin.timeoverview.box.type.memory.changed",
            Self::BreakpointAdded => "color.debugger.plugin.timeoverview.box.type.breakpoint.added",
            Self::BreakpointRemoved => {
                "color.debugger.plugin.timeoverview.box.type.breakpoint.removed"
            }
            Self::BreakpointChanged => {
                "color.debugger.plugin.timeoverview.box.type.breakpoint.changed"
            }
            Self::CurrentLocation => "color.palette.green",
        }
    }

    /// Return a default ARGB color for this type.
    pub fn default_color_rgba(&self) -> u32 {
        match self {
            Self::ThreadAdded => 0xFF_00_80_00,
            Self::ThreadRemoved => 0xFF_FF_00_00,
            Self::ThreadChanged => 0xFF_FF_FF_00,
            Self::ModuleAdded => 0xFF_00_00_FF,
            Self::ModuleRemoved => 0xFF_80_00_00,
            Self::ModuleChanged => 0xFF_80_80_00,
            Self::MemoryAdded => 0xFF_00_80_80,
            Self::MemoryRemoved => 0xFF_80_00_80,
            Self::MemoryChanged => 0xFF_00_FF_FF,
            Self::BreakpointAdded => 0xFF_FF_80_00,
            Self::BreakpointRemoved => 0xFF_80_00_40,
            Self::BreakpointChanged => 0xFF_FF_80_80,
            Self::CurrentLocation => 0xFF_00_FF_00,
        }
    }

    /// All known time types.
    pub fn all() -> &'static [TimeType] {
        &[
            Self::ThreadAdded,
            Self::ThreadRemoved,
            Self::ThreadChanged,
            Self::ModuleAdded,
            Self::ModuleRemoved,
            Self::ModuleChanged,
            Self::MemoryAdded,
            Self::MemoryRemoved,
            Self::MemoryChanged,
            Self::BreakpointAdded,
            Self::BreakpointRemoved,
            Self::BreakpointChanged,
            Self::CurrentLocation,
        ]
    }
}

impl std::fmt::Display for TimeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Configuration for the time-type overview color service.
///
/// Ported from `TimeTypeOverviewColorService.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeTypeOverviewColorService {
    /// The colors for each time type (ARGB).
    pub type_colors: std::collections::HashMap<TimeType, u32>,
    /// The color for undefined/uninitialized snap.
    pub undefined_color: u32,
    /// The color for uninitialized memory.
    pub uninitialized_color: u32,
    /// Whether to show the legend.
    pub show_legend: bool,
    /// The radix for snap display.
    pub snap_radix: u32,
}

impl Default for TimeTypeOverviewColorService {
    fn default() -> Self {
        let mut type_colors = std::collections::HashMap::new();
        for &tt in TimeType::all() {
            type_colors.insert(tt, tt.default_color_rgba());
        }
        Self {
            type_colors,
            undefined_color: 0xFF_C0_C0_C0,     // light gray
            uninitialized_color: 0xFF_80_80_80,   // gray
            show_legend: true,
            snap_radix: 10,
        }
    }
}

impl TimeTypeOverviewColorService {
    /// Get the color for a time type.
    pub fn color_for_type(&self, tt: TimeType) -> u32 {
        self.type_colors
            .get(&tt)
            .copied()
            .unwrap_or(tt.default_color_rgba())
    }

    /// Override the color for a time type.
    pub fn set_color(&mut self, tt: TimeType, color: u32) {
        self.type_colors.insert(tt, color);
    }

    /// Compute the dominant time type for a snapshot given a set of change flags.
    pub fn classify_snapshot(&self, changes: &[TimeType]) -> Option<TimeType> {
        // Priority: CurrentLocation > Thread > Module > Memory > Breakpoint
        let priority = [
            TimeType::CurrentLocation,
            TimeType::ThreadAdded,
            TimeType::ThreadRemoved,
            TimeType::ThreadChanged,
            TimeType::ModuleAdded,
            TimeType::ModuleRemoved,
            TimeType::ModuleChanged,
            TimeType::MemoryAdded,
            TimeType::MemoryRemoved,
            TimeType::MemoryChanged,
            TimeType::BreakpointAdded,
            TimeType::BreakpointRemoved,
            TimeType::BreakpointChanged,
        ];
        for &p in &priority {
            if changes.contains(&p) {
                return Some(p);
            }
        }
        None
    }
}

/// A legend entry for the time-type overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeTypeLegendEntry {
    /// The time type.
    pub time_type: TimeType,
    /// The display label.
    pub label: String,
    /// The ARGB color.
    pub color: u32,
}

impl TimeTypeLegendEntry {
    /// Build the full legend for the service.
    pub fn build_legend(service: &TimeTypeOverviewColorService) -> Vec<Self> {
        TimeType::all()
            .iter()
            .map(|&tt| Self {
                time_type: tt,
                label: format!("{}: {}", tt.label(), tt.description()),
                color: service.color_for_type(tt),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_type_labels() {
        assert_eq!(TimeType::ThreadAdded.label(), "+T");
        assert_eq!(TimeType::ModuleRemoved.label(), "-M");
        assert_eq!(TimeType::CurrentLocation.label(), "Now");
    }

    #[test]
    fn test_time_type_display() {
        assert_eq!(format!("{}", TimeType::ThreadChanged), "*T");
    }

    #[test]
    fn test_time_type_all() {
        assert_eq!(TimeType::all().len(), 13);
    }

    #[test]
    fn test_time_type_description() {
        assert_eq!(TimeType::BreakpointAdded.description(), "Breakpoint Added");
        assert_eq!(
            TimeType::MemoryChanged.description(),
            "Memory Changed"
        );
    }

    #[test]
    fn test_color_service_default() {
        let svc = TimeTypeOverviewColorService::default();
        assert_eq!(svc.type_colors.len(), 13);
        assert!(svc.show_legend);
    }

    #[test]
    fn test_color_service_override() {
        let mut svc = TimeTypeOverviewColorService::default();
        let new_color = 0xFF_AA_BB_CC;
        svc.set_color(TimeType::ThreadAdded, new_color);
        assert_eq!(svc.color_for_type(TimeType::ThreadAdded), new_color);
    }

    #[test]
    fn test_classify_snapshot_priority() {
        let svc = TimeTypeOverviewColorService::default();
        let changes = vec![
            TimeType::BreakpointAdded,
            TimeType::ThreadRemoved,
            TimeType::MemoryChanged,
        ];
        assert_eq!(
            svc.classify_snapshot(&changes),
            Some(TimeType::ThreadRemoved)
        );
    }

    #[test]
    fn test_classify_snapshot_empty() {
        let svc = TimeTypeOverviewColorService::default();
        assert!(svc.classify_snapshot(&[]).is_none());
    }

    #[test]
    fn test_legend_entry_build() {
        let svc = TimeTypeOverviewColorService::default();
        let legend = TimeTypeLegendEntry::build_legend(&svc);
        assert_eq!(legend.len(), 13);
        assert!(legend[0].label.contains("+T"));
    }

    #[test]
    fn test_default_color_keys() {
        assert!(
            TimeType::ThreadAdded
                .default_color_key()
                .contains("thread.added")
        );
        assert!(
            TimeType::CurrentLocation
                .default_color_key()
                .contains("palette")
        );
    }
}
