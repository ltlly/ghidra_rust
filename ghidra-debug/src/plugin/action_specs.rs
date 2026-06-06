//! Concrete action specifications for auto-mapping, location tracking,
//! and auto-read memory.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.action` package.
//!
//! This module provides the concrete implementations of the action spec
//! interfaces:
//!
//! **Auto-map specs** (how to map dynamic trace memory to static programs):
//! - `ByModuleAutoMapSpec`: Maps by matching loaded modules and regions.
//! - `ByRegionAutoMapSpec`: Maps by matching memory regions.
//! - `BySectionAutoMapSpec`: Maps by matching individual sections.
//! - `OneToOneAutoMapSpec`: Creates a single identity mapping.
//! - `NoneAutoMapSpec`: Disables auto-mapping.
//!
//! **Location tracking specs** (how to navigate the listing to the current state):
//! - `PcLocationTrackingSpec`: Tracks the program counter (PC/RIP).
//! - `SpLocationTrackingSpec`: Tracks the stack pointer (SP/RSP).
//! - `RegisterLocationTrackingSpec`: Tracks an arbitrary register.
//! - `WatchLocationTrackingSpec`: Tracks a watch expression.
//! - `NoneLocationTrackingSpec`: Disables location tracking.
//!
//! **Auto-read memory specs** (how to automatically read target memory):
//! - `BasicAutoReadMemorySpec`: Reads visible memory regions.
//! - `NoneAutoReadMemorySpec`: Disables auto-read.

use serde::{Deserialize, Serialize};

// Re-export the base types used by all specs.
use crate::api::action::{
    AutoMapSpec, AutoReadMemorySpec, LocationTracker, LocationTrackingSpec,
    TrackingEvent,
};

// ---------------------------------------------------------------------------
// Auto-map specifications
// ---------------------------------------------------------------------------

/// Maps trace modules and memory regions to static programs.
///
/// This is the most commonly used auto-map strategy. It proposes
/// mappings for loaded modules and memory regions at the given snap.
/// Ported from Ghidra's `ByModuleAutoMapSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByModuleAutoMapSpec {
    pub config_name: String,
    pub menu_name: String,
}

impl Default for ByModuleAutoMapSpec {
    fn default() -> Self {
        Self {
            config_name: "1_MAP_BY_MODULE".into(),
            menu_name: "Auto-Map by Module".into(),
        }
    }
}

impl ByModuleAutoMapSpec {
    /// Create a new ByModule spec.
    pub fn new() -> Self {
        Self::default()
    }
}

impl From<ByModuleAutoMapSpec> for AutoMapSpec {
    fn from(s: ByModuleAutoMapSpec) -> Self {
        AutoMapSpec::new(
            s.config_name,
            s.menu_name,
            "Map trace modules and regions to static programs",
        )
    }
}

/// Maps by matching memory regions between trace and program.
///
/// Uses region permissions (read/write/execute) and addresses to
/// propose mappings.
/// Ported from Ghidra's `ByRegionAutoMapSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByRegionAutoMapSpec {
    pub config_name: String,
    pub menu_name: String,
}

impl Default for ByRegionAutoMapSpec {
    fn default() -> Self {
        Self {
            config_name: "2_MAP_BY_REGION".into(),
            menu_name: "Auto-Map by Region".into(),
        }
    }
}

impl ByRegionAutoMapSpec {
    /// Create a new ByRegion spec.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get info string describing the regions at a given snap.
    pub fn get_info_for_regions(trace_snap: i64, region_count: usize) -> String {
        format!("snap={},{}regions", trace_snap, region_count)
    }
}

impl From<ByRegionAutoMapSpec> for AutoMapSpec {
    fn from(s: ByRegionAutoMapSpec) -> Self {
        AutoMapSpec::new(
            s.config_name,
            s.menu_name,
            "Map trace memory regions to program memory",
        )
    }
}

/// Maps by matching individual sections within modules.
///
/// Uses section names and offsets to propose mappings.
/// Ported from Ghidra's `BySectionAutoMapSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BySectionAutoMapSpec {
    pub config_name: String,
    pub menu_name: String,
}

impl Default for BySectionAutoMapSpec {
    fn default() -> Self {
        Self {
            config_name: "3_MAP_BY_SECTION".into(),
            menu_name: "Auto-Map by Section".into(),
        }
    }
}

impl BySectionAutoMapSpec {
    /// Create a new BySection spec.
    pub fn new() -> Self {
        Self::default()
    }
}

impl From<BySectionAutoMapSpec> for AutoMapSpec {
    fn from(s: BySectionAutoMapSpec) -> Self {
        AutoMapSpec::new(
            s.config_name,
            s.menu_name,
            "Map trace sections to program sections",
        )
    }
}

/// Creates a single identity mapping (trace address == program address).
///
/// Useful for simple firmware images where the load address is known.
/// Ported from Ghidra's `OneToOneAutoMapSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneToOneAutoMapSpec {
    pub config_name: String,
    pub menu_name: String,
}

impl Default for OneToOneAutoMapSpec {
    fn default() -> Self {
        Self {
            config_name: "4_MAP_ONE_TO_ONE".into(),
            menu_name: "Auto-Map One-to-One".into(),
        }
    }
}

impl OneToOneAutoMapSpec {
    /// Create a new OneToOne spec.
    pub fn new() -> Self {
        Self::default()
    }
}

impl From<OneToOneAutoMapSpec> for AutoMapSpec {
    fn from(s: OneToOneAutoMapSpec) -> Self {
        AutoMapSpec::new(
            s.config_name,
            s.menu_name,
            "Create a single identity mapping",
        )
    }
}

/// Disables auto-mapping entirely.
///
/// Ported from Ghidra's `NoneAutoMapSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoneAutoMapSpec {
    pub config_name: String,
    pub menu_name: String,
}

impl Default for NoneAutoMapSpec {
    fn default() -> Self {
        Self {
            config_name: "0_MAP_NONE".into(),
            menu_name: "Do Not Auto-Map".into(),
        }
    }
}

impl NoneAutoMapSpec {
    /// Create a new None spec.
    pub fn new() -> Self {
        Self::default()
    }
}

impl From<NoneAutoMapSpec> for AutoMapSpec {
    fn from(s: NoneAutoMapSpec) -> Self {
        let mut spec = AutoMapSpec::new(s.config_name, s.menu_name, "Disable auto-mapping");
        spec.has_task = false;
        spec
    }
}

// ---------------------------------------------------------------------------
// Location tracking specifications
// ---------------------------------------------------------------------------

/// Tracks the program counter (PC).
///
/// This is the default location tracking spec. It delegates to the
/// register-based and stack-based PC trackers. At a "snap-only" time
/// (no particular frame), it tries the stack-based tracker first, then
/// falls back to the register-based tracker.
/// Ported from Ghidra's `PCLocationTrackingSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcLocationTrackingSpec {
    pub config_name: String,
}

impl Default for PcLocationTrackingSpec {
    fn default() -> Self {
        Self {
            config_name: "TRACK_PC".into(),
        }
    }
}

impl PcLocationTrackingSpec {
    /// Create a new PC tracking spec.
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert to a `LocationTrackingSpec`.
    pub fn to_spec(&self) -> LocationTrackingSpec {
        LocationTrackingSpec::new("Auto PC", "register", true)
            .with_trigger(TrackingEvent::ValueChanged)
            .with_trigger(TrackingEvent::StackChanged)
            .with_trigger(TrackingEvent::SnapChanged)
    }

    /// Convert to a `LocationTracker`.
    pub fn to_tracker(&self) -> LocationTracker {
        LocationTracker::new(&self.config_name).with_goto_expression("RIP")
    }

    /// Compute the trace address by delegating to register and stack trackers.
    ///
    /// In "snap-only" mode, tries the stack-based tracker first, then
    /// falls back to register-based.
    pub fn compute_trace_address(
        &self,
        by_reg_offset: Option<u64>,
        by_stack_offset: Option<u64>,
        snap_only: bool,
    ) -> Option<u64> {
        if snap_only {
            if let Some(pc) = by_stack_offset {
                return Some(pc);
            }
        }
        by_reg_offset
    }
}

/// Tracks the stack pointer (SP).
///
/// Used for navigating the listing to the current stack location.
/// Ported from Ghidra's `SPLocationTrackingSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpLocationTrackingSpec {
    pub config_name: String,
}

impl Default for SpLocationTrackingSpec {
    fn default() -> Self {
        Self {
            config_name: "TRACK_SP".into(),
        }
    }
}

impl SpLocationTrackingSpec {
    /// Create a new SP tracking spec.
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert to a `LocationTrackingSpec`.
    pub fn to_spec(&self) -> LocationTrackingSpec {
        LocationTrackingSpec::new("Auto SP", "register", false)
            .with_trigger(TrackingEvent::ValueChanged)
            .with_trigger(TrackingEvent::StackChanged)
            .with_trigger(TrackingEvent::SnapChanged)
    }

    /// Convert to a `LocationTracker`.
    pub fn to_tracker(&self) -> LocationTracker {
        LocationTracker::new(&self.config_name).with_goto_expression("RSP")
    }
}

/// Tracks an arbitrary register by name.
///
/// The register name is taken from a Sleigh expression.
/// Ported from Ghidra's `RegisterLocationTrackingSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterLocationTrackingSpec {
    pub config_name: String,
    /// The register name being tracked (e.g., "RAX", "RIP").
    pub register_name: String,
}

impl RegisterLocationTrackingSpec {
    /// Create a new register tracking spec.
    pub fn new(register_name: impl Into<String>) -> Self {
        let name = register_name.into();
        Self {
            config_name: format!("TRACK_REG_{}", name),
            register_name: name,
        }
    }

    /// Convert to a `LocationTrackingSpec`.
    pub fn to_spec(&self) -> LocationTrackingSpec {
        LocationTrackingSpec::new(
            format!("Track {}", self.register_name),
            "register",
            false,
        )
        .with_trigger(TrackingEvent::ValueChanged)
        .with_trigger(TrackingEvent::SnapChanged)
    }

    /// Convert to a `LocationTracker`.
    pub fn to_tracker(&self) -> LocationTracker {
        LocationTracker::new(&self.config_name)
            .with_goto_expression(&self.register_name)
    }
}

/// Tracks the program counter using only register reads (no stack).
///
/// This is the sub-tracker used by `PcLocationTrackingSpec` when the
/// stack-based tracker is not applicable.
/// Ported from Ghidra's `PCByRegisterLocationTrackingSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcByRegisterLocationTrackingSpec {
    pub config_name: String,
}

impl Default for PcByRegisterLocationTrackingSpec {
    fn default() -> Self {
        Self {
            config_name: "TRACK_PC_BY_REG".into(),
        }
    }
}

impl PcByRegisterLocationTrackingSpec {
    /// Create a new spec.
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert to a `LocationTracker`.
    pub fn to_tracker(&self) -> LocationTracker {
        LocationTracker::new(&self.config_name).with_goto_expression("RIP")
    }
}

/// Tracks the program counter using stack frame analysis.
///
/// Falls back to reading the return address from the stack frame when
/// the register-based tracker is not applicable.
/// Ported from Ghidra's `PCByStackLocationTrackingSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcByStackLocationTrackingSpec {
    pub config_name: String,
}

impl Default for PcByStackLocationTrackingSpec {
    fn default() -> Self {
        Self {
            config_name: "TRACK_PC_BY_STACK".into(),
        }
    }
}

impl PcByStackLocationTrackingSpec {
    /// Create a new spec.
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert to a `LocationTracker`.
    pub fn to_tracker(&self) -> LocationTracker {
        LocationTracker::new(&self.config_name).with_goto_expression("RIP")
    }
}

/// Tracks a watch expression for location navigation.
///
/// Watch expressions allow arbitrary Sleigh expressions to be evaluated
/// for the tracked address.
/// Ported from Ghidra's `WatchLocationTrackingSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchLocationTrackingSpec {
    pub config_name: String,
    /// The watch expression to evaluate.
    pub expression: String,
}

impl WatchLocationTrackingSpec {
    /// Create a new watch tracking spec.
    pub fn new(expression: impl Into<String>) -> Self {
        Self {
            config_name: "TRACK_WATCH".into(),
            expression: expression.into(),
        }
    }

    /// Convert to a `LocationTrackingSpec`.
    pub fn to_spec(&self) -> LocationTrackingSpec {
        LocationTrackingSpec::new(
            format!("Watch: {}", self.expression),
            "register",
            false,
        )
        .with_trigger(TrackingEvent::ValueChanged)
        .with_trigger(TrackingEvent::SnapChanged)
    }

    /// Convert to a `LocationTracker`.
    pub fn to_tracker(&self) -> LocationTracker {
        LocationTracker::new(&self.config_name)
            .with_goto_expression(&self.expression)
    }
}

/// Disables location tracking entirely.
///
/// Ported from Ghidra's `NoneLocationTrackingSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoneLocationTrackingSpec {
    pub config_name: String,
}

impl Default for NoneLocationTrackingSpec {
    fn default() -> Self {
        Self {
            config_name: "TRACK_NONE".into(),
        }
    }
}

impl NoneLocationTrackingSpec {
    /// Create a new None spec.
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert to a `LocationTrackingSpec`.
    pub fn to_spec(&self) -> LocationTrackingSpec {
        LocationTrackingSpec::new("None", "register", false)
    }
}

// ---------------------------------------------------------------------------
// Auto-read memory specifications
// ---------------------------------------------------------------------------

/// Reads visible memory regions from the target.
///
/// This is the default auto-read strategy: when a memory provider becomes
/// visible, the debugger reads the displayed address range.
/// Ported from Ghidra's `BasicAutoReadMemorySpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAutoReadMemorySpec {
    pub config_name: String,
    pub menu_name: String,
    /// Maximum number of bytes to read per chunk.
    pub chunk_size: usize,
}

impl Default for BasicAutoReadMemorySpec {
    fn default() -> Self {
        Self {
            config_name: "BASIC_READ".into(),
            menu_name: "Auto-Read Visible Memory".into(),
            chunk_size: 0x10000, // 64 KiB
        }
    }
}

impl BasicAutoReadMemorySpec {
    /// Create a new BasicAutoReadMemorySpec.
    pub fn new() -> Self {
        Self::default()
    }
}

impl From<BasicAutoReadMemorySpec> for AutoReadMemorySpec {
    fn from(s: BasicAutoReadMemorySpec) -> Self {
        AutoReadMemorySpec::new(s.config_name, s.menu_name, "Read visible memory regions")
    }
}

/// Disables auto-read memory entirely.
///
/// Ported from Ghidra's `NoneAutoReadMemorySpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoneAutoReadMemorySpec {
    pub config_name: String,
    pub menu_name: String,
}

impl Default for NoneAutoReadMemorySpec {
    fn default() -> Self {
        Self {
            config_name: "NONE_READ".into(),
            menu_name: "Do Not Auto-Read".into(),
        }
    }
}

impl NoneAutoReadMemorySpec {
    /// Create a new None spec.
    pub fn new() -> Self {
        Self::default()
    }
}

impl From<NoneAutoReadMemorySpec> for AutoReadMemorySpec {
    fn from(s: NoneAutoReadMemorySpec) -> Self {
        let mut spec = AutoReadMemorySpec::new(s.config_name, s.menu_name, "Disable auto-read");
        spec.enabled = false;
        spec
    }
}

// ---------------------------------------------------------------------------
// Built-in spec registries
// ---------------------------------------------------------------------------

/// Register all built-in auto-map specs into the given registry.
pub fn register_builtin_auto_map_specs(registry: &mut crate::api::action::AutoMapSpecRegistry) {
    registry.register(NoneAutoMapSpec::default().into());
    registry.register(ByModuleAutoMapSpec::default().into());
    registry.register(ByRegionAutoMapSpec::default().into());
    registry.register(BySectionAutoMapSpec::default().into());
    registry.register(OneToOneAutoMapSpec::default().into());
}

/// Register all built-in auto-read memory specs into the given registry.
pub fn register_builtin_auto_read_specs(
    registry: &mut crate::api::action::AutoReadMemorySpecRegistry,
) {
    registry.register(NoneAutoReadMemorySpec::default().into());
    registry.register(BasicAutoReadMemorySpec::default().into());
}

/// Create all built-in location tracking specs.
pub fn builtin_location_tracking_specs() -> Vec<LocationTrackingSpec> {
    vec![
        PcLocationTrackingSpec::default().to_spec(),
        SpLocationTrackingSpec::default().to_spec(),
        NoneLocationTrackingSpec::default().to_spec(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Auto-map specs --

    #[test]
    fn test_by_module_auto_map_spec() {
        let spec = ByModuleAutoMapSpec::new();
        let auto: AutoMapSpec = spec.into();
        assert_eq!(auto.config_name, "1_MAP_BY_MODULE");
        assert_eq!(auto.menu_name, "Auto-Map by Module");
        assert!(auto.has_task);
    }

    #[test]
    fn test_by_region_auto_map_spec() {
        let spec = ByRegionAutoMapSpec::new();
        let auto: AutoMapSpec = spec.into();
        assert_eq!(auto.config_name, "2_MAP_BY_REGION");
    }

    #[test]
    fn test_by_section_auto_map_spec() {
        let spec = BySectionAutoMapSpec::new();
        let auto: AutoMapSpec = spec.into();
        assert_eq!(auto.config_name, "3_MAP_BY_SECTION");
    }

    #[test]
    fn test_one_to_one_auto_map_spec() {
        let spec = OneToOneAutoMapSpec::new();
        let auto: AutoMapSpec = spec.into();
        assert_eq!(auto.config_name, "4_MAP_ONE_TO_ONE");
    }

    #[test]
    fn test_none_auto_map_spec() {
        let spec = NoneAutoMapSpec::new();
        let auto: AutoMapSpec = spec.into();
        assert_eq!(auto.config_name, "0_MAP_NONE");
        assert!(!auto.has_task);
    }

    #[test]
    fn test_by_region_info() {
        let info = ByRegionAutoMapSpec::get_info_for_regions(10, 3);
        assert!(info.contains("snap=10"));
        assert!(info.contains("3regions"));
    }

    #[test]
    fn test_register_builtin_auto_map_specs() {
        let mut reg = crate::api::action::AutoMapSpecRegistry::new();
        register_builtin_auto_map_specs(&mut reg);
        assert_eq!(reg.len(), 5);
        assert!(reg.get("0_MAP_NONE").is_some());
        assert!(reg.get("1_MAP_BY_MODULE").is_some());
        assert!(reg.get("2_MAP_BY_REGION").is_some());
        assert!(reg.get("3_MAP_BY_SECTION").is_some());
        assert!(reg.get("4_MAP_ONE_TO_ONE").is_some());
    }

    // -- Location tracking specs --

    #[test]
    fn test_pc_location_tracking_spec() {
        let spec = PcLocationTrackingSpec::new();
        assert_eq!(spec.config_name, "TRACK_PC");

        let lt = spec.to_spec();
        assert_eq!(lt.name, "Auto PC");
        assert!(lt.should_disassemble);

        let tracker = spec.to_tracker();
        assert_eq!(tracker.spec_name, "TRACK_PC");
        assert_eq!(tracker.goto_expression, "RIP");
    }

    #[test]
    fn test_pc_compute_address_snap_only() {
        let spec = PcLocationTrackingSpec::new();
        // In snap-only mode, prefer stack-based offset
        let addr = spec.compute_trace_address(Some(0x400000), Some(0x401000), true);
        assert_eq!(addr, Some(0x401000));
    }

    #[test]
    fn test_pc_compute_address_no_stack() {
        let spec = PcLocationTrackingSpec::new();
        // In snap-only mode, fall back to register offset if no stack offset
        let addr = spec.compute_trace_address(Some(0x400000), None, true);
        assert_eq!(addr, Some(0x400000));
    }

    #[test]
    fn test_pc_compute_address_frame_mode() {
        let spec = PcLocationTrackingSpec::new();
        // In frame mode, use register-based offset
        let addr = spec.compute_trace_address(Some(0x400000), Some(0x401000), false);
        assert_eq!(addr, Some(0x400000));
    }

    #[test]
    fn test_sp_location_tracking_spec() {
        let spec = SpLocationTrackingSpec::new();
        assert_eq!(spec.config_name, "TRACK_SP");

        let lt = spec.to_spec();
        assert_eq!(lt.name, "Auto SP");
        assert!(!lt.should_disassemble);

        let tracker = spec.to_tracker();
        assert_eq!(tracker.goto_expression, "RSP");
    }

    #[test]
    fn test_register_location_tracking_spec() {
        let spec = RegisterLocationTrackingSpec::new("RAX");
        assert_eq!(spec.config_name, "TRACK_REG_RAX");

        let lt = spec.to_spec();
        assert!(lt.name.contains("RAX"));

        let tracker = spec.to_tracker();
        assert_eq!(tracker.goto_expression, "RAX");
    }

    #[test]
    fn test_pc_by_register_spec() {
        let spec = PcByRegisterLocationTrackingSpec::new();
        let tracker = spec.to_tracker();
        assert_eq!(tracker.spec_name, "TRACK_PC_BY_REG");
        assert_eq!(tracker.goto_expression, "RIP");
    }

    #[test]
    fn test_pc_by_stack_spec() {
        let spec = PcByStackLocationTrackingSpec::new();
        let tracker = spec.to_tracker();
        assert_eq!(tracker.spec_name, "TRACK_PC_BY_STACK");
        assert_eq!(tracker.goto_expression, "RIP");
    }

    #[test]
    fn test_watch_location_tracking_spec() {
        let spec = WatchLocationTrackingSpec::new("RAX + 8");
        assert_eq!(spec.config_name, "TRACK_WATCH");
        assert_eq!(spec.expression, "RAX + 8");

        let lt = spec.to_spec();
        assert!(lt.name.contains("RAX + 8"));

        let tracker = spec.to_tracker();
        assert_eq!(tracker.goto_expression, "RAX + 8");
    }

    #[test]
    fn test_none_location_tracking_spec() {
        let spec = NoneLocationTrackingSpec::new();
        assert_eq!(spec.config_name, "TRACK_NONE");

        let lt = spec.to_spec();
        assert_eq!(lt.name, "None");
    }

    #[test]
    fn test_builtin_location_tracking_specs() {
        let specs = builtin_location_tracking_specs();
        assert_eq!(specs.len(), 3);
        assert!(specs.iter().any(|s| s.name == "Auto PC"));
        assert!(specs.iter().any(|s| s.name == "Auto SP"));
        assert!(specs.iter().any(|s| s.name == "None"));
    }

    // -- Auto-read memory specs --

    #[test]
    fn test_basic_auto_read_memory_spec() {
        let spec = BasicAutoReadMemorySpec::new();
        assert_eq!(spec.config_name, "BASIC_READ");
        assert_eq!(spec.chunk_size, 0x10000);

        let auto: AutoReadMemorySpec = spec.into();
        assert!(auto.enabled);
    }

    #[test]
    fn test_none_auto_read_memory_spec() {
        let spec = NoneAutoReadMemorySpec::new();
        assert_eq!(spec.config_name, "NONE_READ");

        let auto: AutoReadMemorySpec = spec.into();
        assert!(!auto.enabled);
    }

    #[test]
    fn test_register_builtin_auto_read_specs() {
        let mut reg = crate::api::action::AutoReadMemorySpecRegistry::new();
        register_builtin_auto_read_specs(&mut reg);
        assert_eq!(reg.len(), 2);
        assert!(reg.get("NONE_READ").is_some());
        assert!(reg.get("BASIC_READ").is_some());
    }

    // -- Serialization roundtrips --

    #[test]
    fn test_by_module_serde() {
        let spec = ByModuleAutoMapSpec::new();
        let json = serde_json::to_string(&spec).unwrap();
        let back: ByModuleAutoMapSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.config_name, "1_MAP_BY_MODULE");
    }

    #[test]
    fn test_pc_tracking_serde() {
        let spec = PcLocationTrackingSpec::new();
        let json = serde_json::to_string(&spec).unwrap();
        let back: PcLocationTrackingSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.config_name, "TRACK_PC");
    }

    #[test]
    fn test_register_tracking_serde() {
        let spec = RegisterLocationTrackingSpec::new("RAX");
        let json = serde_json::to_string(&spec).unwrap();
        let back: RegisterLocationTrackingSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.register_name, "RAX");
    }

    #[test]
    fn test_basic_read_serde() {
        let spec = BasicAutoReadMemorySpec::new();
        let json = serde_json::to_string(&spec).unwrap();
        let back: BasicAutoReadMemorySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.chunk_size, 0x10000);
    }
}
