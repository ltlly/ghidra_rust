//! Location tracking specifications for automatic navigation.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.action` package.
//! Each specification tracks a particular register or stack-based location
//! (e.g., PC, SP) and provides the address for the listing to follow.

use serde::{Deserialize, Serialize};

use crate::api::action::{LocationTrackingSpec, TrackingEvent};
use crate::api::tracemgr::DebuggerCoordinates;

/// A register-based location tracking specification.
///
/// Ported from Ghidra's `RegisterLocationTrackingSpec`.
/// Computes a register from the current coordinates and reads its value
/// to determine the address to track.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterTrackingSpec {
    /// The base tracking spec metadata.
    pub spec: LocationTrackingSpec,
    /// The register name to track (e.g., "PC", "RIP", "LR").
    pub register_name: String,
    /// The default address space when the register is not available.
    pub default_space: Option<String>,
}

impl RegisterTrackingSpec {
    /// Create a new register tracking specification.
    pub fn new(
        _config_name: impl Into<String>,
        menu_name: impl Into<String>,
        register_name: impl Into<String>,
        should_disassemble: bool,
    ) -> Self {
        let register_name = register_name.into();
        Self {
            spec: LocationTrackingSpec::new(menu_name, "register", should_disassemble)
                .with_trigger(TrackingEvent::ValueChanged)
                .with_trigger(TrackingEvent::SnapChanged),
            register_name,
            default_space: None,
        }
    }

    /// Set the default address space.
    pub fn with_default_space(mut self, space: impl Into<String>) -> Self {
        self.default_space = Some(space.into());
        self
    }
}

/// PC (Program Counter) location tracking specification.
///
/// Ported from Ghidra's `PCLocationTrackingSpec`. Tracks the program counter
/// register of the current thread. When snap-only time is used, it first
/// tries to read PC from the stack trace, then falls back to the register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcLocationTrackingSpec {
    /// The register-based tracking for PC.
    pub register: RegisterTrackingSpec,
    /// The stack-based tracking for PC (fallback).
    pub stack: StackTrackingSpec,
}

impl PcLocationTrackingSpec {
    /// Create a new PC tracking specification.
    pub fn new() -> Self {
        Self {
            register: RegisterTrackingSpec::new(
                "TRACK_PC",
                "Auto PC",
                "PC",
                true,
            ),
            stack: StackTrackingSpec::new(),
        }
    }

    /// Compute the trace address for the current coordinates.
    ///
    /// First tries stack-based PC, then falls back to register-based.
    pub fn compute_trace_address(&self, coordinates: &DebuggerCoordinates) -> Option<u64> {
        if let Some(addr) = self.stack.compute_trace_address(coordinates) {
            return Some(addr);
        }
        self.register.compute_trace_address(coordinates)
    }
}

impl Default for PcLocationTrackingSpec {
    fn default() -> Self {
        Self::new()
    }
}

/// SP (Stack Pointer) location tracking specification.
///
/// Ported from Ghidra's `SPLocationTrackingSpec`. Tracks the stack pointer
/// register of the current thread. This is typically used to follow the
/// stack frame during debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpLocationTrackingSpec {
    /// The register-based tracking for SP.
    pub register: RegisterTrackingSpec,
}

impl SpLocationTrackingSpec {
    /// Create a new SP tracking specification.
    pub fn new() -> Self {
        Self {
            register: RegisterTrackingSpec::new(
                "TRACK_SP",
                "Auto SP",
                "SP",
                false,
            ),
        }
    }

    /// Compute the trace address for the current coordinates.
    pub fn compute_trace_address(&self, coordinates: &DebuggerCoordinates) -> Option<u64> {
        self.register.compute_trace_address(coordinates)
    }
}

impl Default for SpLocationTrackingSpec {
    fn default() -> Self {
        Self::new()
    }
}

/// PC-by-register location tracking specification.
///
/// Ported from Ghidra's `PCByRegisterLocationTrackingSpec`.
/// Reads the PC register directly from the register space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcByRegisterLocationTrackingSpec {
    /// The register-based tracking.
    pub register: RegisterTrackingSpec,
}

impl PcByRegisterLocationTrackingSpec {
    /// Create a new PC-by-register tracking specification.
    pub fn new() -> Self {
        Self {
            register: RegisterTrackingSpec::new(
                "TRACK_PC_BY_REG",
                "Auto PC (Register)",
                "PC",
                true,
            ),
        }
    }

    /// Compute the trace address for the current coordinates.
    pub fn compute_trace_address(&self, coordinates: &DebuggerCoordinates) -> Option<u64> {
        self.register.compute_trace_address(coordinates)
    }
}

impl Default for PcByRegisterLocationTrackingSpec {
    fn default() -> Self {
        Self::new()
    }
}

/// PC-by-stack location tracking specification.
///
/// Ported from Ghidra's `PCByStackLocationTrackingSpec`.
/// Reads the return address from the stack to determine the PC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcByStackLocationTrackingSpec {
    /// The stack-based tracking.
    pub stack: StackTrackingSpec,
}

impl PcByStackLocationTrackingSpec {
    /// Create a new PC-by-stack tracking specification.
    pub fn new() -> Self {
        Self {
            stack: StackTrackingSpec::new(),
        }
    }

    /// Compute the trace address for the current coordinates.
    pub fn compute_trace_address(&self, coordinates: &DebuggerCoordinates) -> Option<u64> {
        self.stack.compute_trace_address(coordinates)
    }
}

impl Default for PcByStackLocationTrackingSpec {
    fn default() -> Self {
        Self::new()
    }
}

/// Stack-based location tracking specification.
///
/// Ported from Ghidra's `PCByStackLocationTrackingSpec`.
/// Uses the stack trace to determine the return address of the current frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackTrackingSpec {
    /// Configuration name.
    pub config_name: String,
}

impl StackTrackingSpec {
    /// Create a new stack tracking specification.
    pub fn new() -> Self {
        Self {
            config_name: "TRACK_STACK".into(),
        }
    }

    /// Compute the trace address from the stack.
    ///
    /// In a full implementation, this would walk the stack frames and
    /// extract the return address of the current frame.
    pub fn compute_trace_address(&self, coordinates: &DebuggerCoordinates) -> Option<u64> {
        // Placeholder: stack-based PC resolution would read from the
        // stack frame's return address register. The actual implementation
        // depends on the platform's calling convention.
        let _ = coordinates;
        None
    }
}

impl Default for StackTrackingSpec {
    fn default() -> Self {
        Self::new()
    }
}

/// Factory for creating location tracking specifications.
///
/// Ported from Ghidra's `LocationTrackingSpecFactory`.
#[derive(Debug, Clone, Default)]
pub struct LocationTrackingSpecFactory {
    specs: Vec<LocationTrackingSpecEntry>,
}

/// An entry in the location tracking spec factory.
#[derive(Debug, Clone)]
pub struct LocationTrackingSpecEntry {
    /// The configuration name.
    pub config_name: String,
    /// The tracking specification type.
    pub spec_type: TrackingSpecType,
}

/// The type of location tracking specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackingSpecType {
    /// Track the Program Counter.
    PC,
    /// Track the Stack Pointer.
    SP,
    /// Track PC via register.
    PcByRegister,
    /// Track PC via stack.
    PcByStack,
    /// Track a named register.
    Register(String),
    /// Track nothing.
    None,
}

impl LocationTrackingSpecFactory {
    /// Create a new factory with all built-in specs.
    pub fn new() -> Self {
        let specs = vec![
            LocationTrackingSpecEntry {
                config_name: "TRACK_PC".into(),
                spec_type: TrackingSpecType::PC,
            },
            LocationTrackingSpecEntry {
                config_name: "TRACK_SP".into(),
                spec_type: TrackingSpecType::SP,
            },
            LocationTrackingSpecEntry {
                config_name: "TRACK_PC_BY_REG".into(),
                spec_type: TrackingSpecType::PcByRegister,
            },
            LocationTrackingSpecEntry {
                config_name: "TRACK_PC_BY_STACK".into(),
                spec_type: TrackingSpecType::PcByStack,
            },
            LocationTrackingSpecEntry {
                config_name: "TRACK_NONE".into(),
                spec_type: TrackingSpecType::None,
            },
        ];
        Self { specs }
    }

    /// Get a spec type by configuration name.
    pub fn from_config_name(&self, name: &str) -> Option<&TrackingSpecType> {
        self.specs
            .iter()
            .find(|s| s.config_name == name)
            .map(|s| &s.spec_type)
    }

    /// Get all registered spec entries.
    pub fn all_specs(&self) -> &[LocationTrackingSpecEntry] {
        &self.specs
    }

    /// Register a custom tracking spec.
    pub fn register(&mut self, config_name: impl Into<String>, spec_type: TrackingSpecType) {
        self.specs.push(LocationTrackingSpecEntry {
            config_name: config_name.into(),
            spec_type,
        });
    }
}

/// A no-op location tracking specification.
///
/// Ported from Ghidra's `NoneLocationTrackingSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoneLocationTrackingSpec {
    /// The base spec.
    pub spec: LocationTrackingSpec,
}

impl NoneLocationTrackingSpec {
    /// Create a new no-op tracking spec.
    pub fn new() -> Self {
        Self {
            spec: LocationTrackingSpec::new("No Tracking", "none", false),
        }
    }
}

impl Default for NoneLocationTrackingSpec {
    fn default() -> Self {
        Self::new()
    }
}

// Helper: compute trace address for a register-based spec.
impl RegisterTrackingSpec {
    /// Compute the trace address by reading the register value.
    ///
    /// This is a placeholder that returns None. In a full implementation,
    /// it would read the register value from the trace at the given
    /// coordinates and interpret it as an address.
    pub fn compute_trace_address(&self, coordinates: &DebuggerCoordinates) -> Option<u64> {
        let _ = coordinates;
        // Placeholder: actual implementation reads the register value
        // from the trace and converts it to an address.
        None
    }

    /// Check if a change in the given address space affects this tracking.
    pub fn affected_by_bytes_change(
        &self,
        space_name: &str,
        snap: i64,
        coordinates: &DebuggerCoordinates,
    ) -> bool {
        // Check if the change is in a memory space or the register container
        // and if the snap is within the lifespan of the change.
        let is_memory = space_name.contains("ram") || space_name.contains("mem");
        let is_register = space_name.contains("register") || space_name.contains("reg");
        (is_memory || is_register) && snap <= coordinates.snap.unwrap_or(0)
    }

    /// Check if a stack change affects this tracking.
    pub fn affected_by_stack_change(&self, coordinates: &DebuggerCoordinates) -> bool {
        let _ = coordinates;
        // SP tracking is affected by stack changes, PC tracking is not.
        self.register_name == "SP"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tracemgr::DebuggerCoordinates;

    fn make_coordinates() -> DebuggerCoordinates {
        DebuggerCoordinates::none()
    }

    #[test]
    fn test_pc_tracking_spec() {
        let spec = PcLocationTrackingSpec::new();
        assert_eq!(spec.register.register_name, "PC");
        assert!(spec.register.spec.should_disassemble);
    }

    #[test]
    fn test_sp_tracking_spec() {
        let spec = SpLocationTrackingSpec::new();
        assert_eq!(spec.register.register_name, "SP");
        assert!(!spec.register.spec.should_disassemble);
    }

    #[test]
    fn test_pc_by_register() {
        let spec = PcByRegisterLocationTrackingSpec::new();
        assert_eq!(spec.register.register_name, "PC");
    }

    #[test]
    fn test_pc_by_stack() {
        let spec = PcByStackLocationTrackingSpec::new();
        assert_eq!(spec.stack.config_name, "TRACK_STACK");
    }

    #[test]
    fn test_none_tracking_spec() {
        let spec = NoneLocationTrackingSpec::new();
        assert_eq!(spec.spec.name, "No Tracking");
        assert!(!spec.spec.should_disassemble);
    }

    #[test]
    fn test_tracking_factory() {
        let factory = LocationTrackingSpecFactory::new();
        assert!(factory.from_config_name("TRACK_PC").is_some());
        assert!(factory.from_config_name("TRACK_SP").is_some());
        assert!(factory.from_config_name("missing").is_none());
    }

    #[test]
    fn test_register_tracking_affected_by_bytes() {
        let spec = RegisterTrackingSpec::new("test", "Test", "PC", true);
        let coords = make_coordinates();
        assert!(spec.affected_by_bytes_change("ram", 0, &coords));
        assert!(spec.affected_by_bytes_change("register", 0, &coords));
        assert!(!spec.affected_by_bytes_change("some_other", 0, &coords));
    }

    #[test]
    fn test_register_tracking_affected_by_stack() {
        let sp_spec = RegisterTrackingSpec::new("test", "Test", "SP", false);
        let pc_spec = RegisterTrackingSpec::new("test", "Test", "PC", true);
        let coords = make_coordinates();
        assert!(sp_spec.affected_by_stack_change(&coords));
        assert!(!pc_spec.affected_by_stack_change(&coords));
    }

    #[test]
    fn test_pc_tracking_compute_address() {
        let spec = PcLocationTrackingSpec::new();
        let coords = make_coordinates();
        // Placeholder returns None
        assert!(spec.compute_trace_address(&coords).is_none());
    }

    #[test]
    fn test_sp_tracking_compute_address() {
        let spec = SpLocationTrackingSpec::new();
        let coords = make_coordinates();
        assert!(spec.compute_trace_address(&coords).is_none());
    }

    #[test]
    fn test_factory_register_custom() {
        let mut factory = LocationTrackingSpecFactory::new();
        let initial_count = factory.all_specs().len();
        factory.register("CUSTOM_REG", TrackingSpecType::Register("R15".into()));
        assert_eq!(factory.all_specs().len(), initial_count + 1);
    }
}
