//! Location tracking specifications for the debugger.
//!
//! Ported from Ghidra's `ghidra.debug.api.action` package:
//! - `LocationTrackingSpec`: Defines how to track a specific register or
//!   address during debugging (e.g., track the program counter, stack pointer).
//! - `TrackingEvent`: Events that trigger location tracking updates.
//! - `AutoMapSpec`: Specifications for automatic mapping between trace and program.
//! - `AutoReadMemorySpec`: Specifications for automatically reading memory.
//! - `GoToInput`: Input for goto operations in the debugger.
//!
//! These types allow the debugger UI to follow execution by automatically
//! updating the listing view to show the code at the current PC, the
//! current stack frame, etc.

use serde::{Deserialize, Serialize};

/// A specification for tracking a register or address.
///
/// Ported from Ghidra's `LocationTrackingSpec`. Defines what register
/// to track and how to present it in the listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationTrackingSpec {
    /// The name of this tracking specification.
    pub name: String,
    /// The register name to track (e.g., "PC", "SP", "LR").
    pub register_name: String,
    /// Whether this tracking spec is enabled.
    pub enabled: bool,
    /// The display order (lower = shown first).
    pub order: i32,
    /// Whether to follow the tracked address into subroutines.
    pub follow_calls: bool,
    /// The short display label.
    pub label: String,
}

impl LocationTrackingSpec {
    /// Create a new location tracking spec.
    pub fn new(
        name: impl Into<String>,
        register_name: impl Into<String>,
        label: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            register_name: register_name.into(),
            enabled: true,
            order: 0,
            follow_calls: false,
            label: label.into(),
        }
    }

    /// Disable this tracking spec.
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Set the display order.
    pub fn with_order(mut self, order: i32) -> Self {
        self.order = order;
        self
    }

    /// Enable call following.
    pub fn follow_calls(mut self) -> Self {
        self.follow_calls = true;
        self
    }
}

/// Built-in tracking specifications.
pub mod builtin_specs {
    use super::LocationTrackingSpec;

    /// Track the program counter (PC).
    pub fn pc() -> LocationTrackingSpec {
        LocationTrackingSpec::new("PC Tracking", "PC", "PC")
            .with_order(0)
            .follow_calls()
    }

    /// Track the stack pointer (SP).
    pub fn sp() -> LocationTrackingSpec {
        LocationTrackingSpec::new("SP Tracking", "SP", "SP").with_order(1)
    }

    /// Track the link register (LR) on ARM.
    pub fn lr() -> LocationTrackingSpec {
        LocationTrackingSpec::new("LR Tracking", "LR", "LR").with_order(2)
    }

    /// Get all built-in tracking specs.
    pub fn all() -> Vec<LocationTrackingSpec> {
        vec![pc(), sp(), lr()]
    }
}

/// An event that triggers a location tracking update.
///
/// Ported from Ghidra's `TrackingEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrackingEvent {
    /// A step (instruction or pcode op) completed.
    Step,
    /// A breakpoint was hit.
    BreakpointHit,
    /// A signal was received.
    Signal,
    /// The user changed focus.
    FocusChanged,
    /// A thread was selected.
    ThreadSelected,
    /// Execution resumed.
    Resume,
}

impl std::fmt::Display for TrackingEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Step => write!(f, "step"),
            Self::BreakpointHit => write!(f, "breakpoint-hit"),
            Self::Signal => write!(f, "signal"),
            Self::FocusChanged => write!(f, "focus-changed"),
            Self::ThreadSelected => write!(f, "thread-selected"),
            Self::Resume => write!(f, "resume"),
        }
    }
}

/// Specification for automatic memory mapping.
///
/// Ported from Ghidra's `AutoMapSpec`. Defines when and how to automatically
/// map trace memory to a static program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoMapSpec {
    /// The name of this auto-map specification.
    pub name: String,
    /// Whether this spec is enabled.
    pub enabled: bool,
    /// Whether to map on module load.
    pub on_module_load: bool,
    /// Whether to map on section discovery.
    pub on_section_discovery: bool,
    /// The match strategy.
    pub match_strategy: AutoMapMatchStrategy,
}

/// Strategy for matching modules to programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AutoMapMatchStrategy {
    /// Match by module path.
    ByPath,
    /// Match by module name.
    ByName,
    /// Match by module hash.
    ByHash,
    /// Match by heuristics (name similarity, size, etc.).
    Heuristic,
}

impl std::fmt::Display for AutoMapMatchStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ByPath => write!(f, "path"),
            Self::ByName => write!(f, "name"),
            Self::ByHash => write!(f, "hash"),
            Self::Heuristic => write!(f, "heuristic"),
        }
    }
}

impl AutoMapSpec {
    /// Create a new auto-map spec.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            on_module_load: true,
            on_section_discovery: false,
            match_strategy: AutoMapMatchStrategy::ByName,
        }
    }

    /// Disable this spec.
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Enable mapping on section discovery.
    pub fn on_sections(mut self) -> Self {
        self.on_section_discovery = true;
        self
    }

    /// Set the match strategy.
    pub fn with_strategy(mut self, strategy: AutoMapMatchStrategy) -> Self {
        self.match_strategy = strategy;
        self
    }
}

/// Built-in auto-map specifications.
pub mod builtin_auto_map {
    use super::{AutoMapMatchStrategy, AutoMapSpec};

    /// The default auto-map spec.
    pub fn default_spec() -> AutoMapSpec {
        AutoMapSpec::new("Default Auto-Map")
            .on_sections()
            .with_strategy(AutoMapMatchStrategy::ByName)
    }

    /// Auto-map by module path.
    pub fn by_path() -> AutoMapSpec {
        AutoMapSpec::new("Auto-Map by Path")
            .with_strategy(AutoMapMatchStrategy::ByPath)
    }

    /// Get all built-in auto-map specs.
    pub fn all() -> Vec<AutoMapSpec> {
        vec![default_spec(), by_path()]
    }
}

/// Specification for automatically reading memory.
///
/// Ported from Ghidra's `AutoReadMemorySpec`. Defines what memory to
/// automatically read when a breakpoint is hit or execution stops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoReadMemorySpec {
    /// The name of this spec.
    pub name: String,
    /// The register whose value defines the read address.
    pub address_register: String,
    /// The number of bytes to read.
    pub length: usize,
    /// Whether this spec is enabled.
    pub enabled: bool,
}

impl AutoReadMemorySpec {
    /// Create a new auto-read memory spec.
    pub fn new(
        name: impl Into<String>,
        address_register: impl Into<String>,
        length: usize,
    ) -> Self {
        Self {
            name: name.into(),
            address_register: address_register.into(),
            length,
            enabled: true,
        }
    }

    /// Disable this spec.
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// Input for goto operations in the debugger.
///
/// Ported from Ghidra's `GoToInput`. Encapsulates the different kinds
/// of goto targets (address, register, symbol name, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GoToInput {
    /// Go to a specific address.
    Address(u64),
    /// Go to the value of a register.
    Register(String),
    /// Go to a named symbol.
    Symbol(String),
    /// Go to the value at a memory address (dereference).
    Dereference(u64),
    /// Go to a relative offset from the current PC.
    RelativeOffset(i64),
}

impl GoToInput {
    /// Whether this input represents an address.
    pub fn is_address(&self) -> bool {
        matches!(self, Self::Address(_))
    }

    /// Whether this input represents a register.
    pub fn is_register(&self) -> bool {
        matches!(self, Self::Register(_))
    }

    /// Whether this input represents a symbol.
    pub fn is_symbol(&self) -> bool {
        matches!(self, Self::Symbol(_))
    }

    /// If this is an address, return it.
    pub fn as_address(&self) -> Option<u64> {
        match self {
            Self::Address(a) => Some(*a),
            _ => None,
        }
    }

    /// If this is a register name, return it.
    pub fn as_register(&self) -> Option<&str> {
        match self {
            Self::Register(r) => Some(r),
            _ => None,
        }
    }
}

impl std::fmt::Display for GoToInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address(a) => write!(f, "0x{:x}", a),
            Self::Register(r) => write!(f, "{}", r),
            Self::Symbol(s) => write!(f, "{}", s),
            Self::Dereference(a) => write!(f, "[0x{:x}]", a),
            Self::RelativeOffset(o) => {
                if *o >= 0 {
                    write!(f, "+{}", o)
                } else {
                    write!(f, "{}", o)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_location_tracking_spec() {
        let spec = LocationTrackingSpec::new("PC", "RIP", "Program Counter")
            .with_order(0)
            .follow_calls();
        assert_eq!(spec.name, "PC");
        assert_eq!(spec.register_name, "RIP");
        assert!(spec.enabled);
        assert!(spec.follow_calls);
        assert_eq!(spec.order, 0);
    }

    #[test]
    fn test_location_tracking_spec_disabled() {
        let spec = LocationTrackingSpec::new("X", "X", "X").disabled();
        assert!(!spec.enabled);
    }

    #[test]
    fn test_builtin_specs() {
        let pc = builtin_specs::pc();
        assert_eq!(pc.register_name, "PC");
        assert!(pc.follow_calls);

        let sp = builtin_specs::sp();
        assert_eq!(sp.register_name, "SP");
        assert!(!sp.follow_calls);

        let all = builtin_specs::all();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_tracking_event_display() {
        assert_eq!(TrackingEvent::Step.to_string(), "step");
        assert_eq!(TrackingEvent::BreakpointHit.to_string(), "breakpoint-hit");
        assert_eq!(TrackingEvent::Signal.to_string(), "signal");
    }

    #[test]
    fn test_auto_map_spec() {
        let spec = AutoMapSpec::new("Test")
            .on_sections()
            .with_strategy(AutoMapMatchStrategy::ByPath);
        assert!(spec.enabled);
        assert!(spec.on_section_discovery);
        assert_eq!(spec.match_strategy, AutoMapMatchStrategy::ByPath);
    }

    #[test]
    fn test_auto_map_spec_disabled() {
        let spec = AutoMapSpec::new("X").disabled();
        assert!(!spec.enabled);
    }

    #[test]
    fn test_auto_map_strategy_display() {
        assert_eq!(AutoMapMatchStrategy::ByPath.to_string(), "path");
        assert_eq!(AutoMapMatchStrategy::ByName.to_string(), "name");
        assert_eq!(AutoMapMatchStrategy::ByHash.to_string(), "hash");
    }

    #[test]
    fn test_builtin_auto_map() {
        let def = builtin_auto_map::default_spec();
        assert!(def.on_section_discovery);
        assert_eq!(def.match_strategy, AutoMapMatchStrategy::ByName);

        let by_path = builtin_auto_map::by_path();
        assert_eq!(by_path.match_strategy, AutoMapMatchStrategy::ByPath);

        let all = builtin_auto_map::all();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_auto_read_memory_spec() {
        let spec = AutoReadMemorySpec::new("Stack", "RSP", 256);
        assert_eq!(spec.address_register, "RSP");
        assert_eq!(spec.length, 256);
        assert!(spec.enabled);
    }

    #[test]
    fn test_auto_read_memory_spec_disabled() {
        let spec = AutoReadMemorySpec::new("X", "X", 0).disabled();
        assert!(!spec.enabled);
    }

    #[test]
    fn test_go_to_input_address() {
        let input = GoToInput::Address(0x401000);
        assert!(input.is_address());
        assert!(!input.is_register());
        assert_eq!(input.as_address(), Some(0x401000));
        assert_eq!(input.to_string(), "0x401000");
    }

    #[test]
    fn test_go_to_input_register() {
        let input = GoToInput::Register("RIP".into());
        assert!(input.is_register());
        assert!(!input.is_address());
        assert_eq!(input.as_register(), Some("RIP"));
        assert_eq!(input.to_string(), "RIP");
    }

    #[test]
    fn test_go_to_input_symbol() {
        let input = GoToInput::Symbol("main".into());
        assert!(input.is_symbol());
        assert_eq!(input.to_string(), "main");
    }

    #[test]
    fn test_go_to_input_dereference() {
        let input = GoToInput::Dereference(0x7fff0000);
        assert_eq!(input.to_string(), "[0x7fff0000]");
    }

    #[test]
    fn test_go_to_input_relative_offset() {
        let positive = GoToInput::RelativeOffset(16);
        assert_eq!(positive.to_string(), "+16");

        let negative = GoToInput::RelativeOffset(-8);
        assert_eq!(negative.to_string(), "-8");
    }

    #[test]
    fn test_go_to_input_as_address_none() {
        let input = GoToInput::Register("RIP".into());
        assert_eq!(input.as_address(), None);
    }

    #[test]
    fn test_go_to_input_as_register_none() {
        let input = GoToInput::Address(0x401000);
        assert_eq!(input.as_register(), None);
    }

    #[test]
    fn test_tracking_event_equality() {
        assert_eq!(TrackingEvent::Step, TrackingEvent::Step);
        assert_ne!(TrackingEvent::Step, TrackingEvent::BreakpointHit);
    }

    #[test]
    fn test_auto_map_strategy_equality() {
        assert_eq!(AutoMapMatchStrategy::ByPath, AutoMapMatchStrategy::ByPath);
        assert_ne!(AutoMapMatchStrategy::ByPath, AutoMapMatchStrategy::ByName);
    }

    #[test]
    fn test_location_tracking_spec_serde() {
        let spec = LocationTrackingSpec::new("PC", "RIP", "PC");
        let json = serde_json::to_string(&spec).unwrap();
        let back: LocationTrackingSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "PC");
    }

    #[test]
    fn test_go_to_input_serde() {
        let input = GoToInput::Address(0x401000);
        let json = serde_json::to_string(&input).unwrap();
        let back: GoToInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_address(), Some(0x401000));
    }
}
