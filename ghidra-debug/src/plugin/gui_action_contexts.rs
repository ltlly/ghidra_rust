//! GUI action context types for the debugger plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui` package.
//!
//! These represent the data contexts that drive debugger UI actions.
//! In Ghidra, each UI component has an "action context" that carries
//! the information needed for context-sensitive actions. In Rust,
//! these become data-only types without Swing dependencies.

use serde::{Deserialize, Serialize};

use crate::api::action_name::ActionName;
use crate::model::breakpoint::TraceBreakpointKind;
use crate::model::module::TraceStaticMapping;
use crate::util::coordinates::DebuggerCoordinates;
use super::debugger_regions::RegionPermissions;

// ── Debugger Provider Model ──────────────────────────────────────────

/// The base type for a debugger provider's data model.
///
/// Ported from Ghidra's `DebuggerProvider`. In the Java version,
/// this is a Swing component that provides the docking behavior
/// for debugger panels. In Rust, this is the data model portion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerProviderModel {
    /// The title of the provider panel.
    pub title: String,
    /// The unique window group this provider belongs to.
    pub window_group: Option<String>,
    /// Whether the provider is currently visible.
    pub visible: bool,
    /// Whether the provider supports multiple instances.
    pub supports_multiple: bool,
}

impl DebuggerProviderModel {
    /// Create a new provider model with the given title.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            window_group: None,
            visible: false,
            supports_multiple: false,
        }
    }

    /// Set the window group.
    pub fn with_window_group(mut self, group: impl Into<String>) -> Self {
        self.window_group = Some(group.into());
        self
    }

    /// Make the provider support multiple instances.
    pub fn with_multiple(mut self) -> Self {
        self.supports_multiple = true;
        self
    }
}

// ── Debugger Snap Action Context ─────────────────────────────────────

/// The action context for snap-level debugger operations.
///
/// Ported from Ghidra's `DebuggerSnapActionContext`. This context
/// carries the current snapshot information needed for snap-related
/// actions (go to snap, create snapshot, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerSnapActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The snap value being acted upon.
    pub snap: i64,
    /// Whether this is a scratch snap.
    pub scratch: bool,
}

impl DebuggerSnapActionContext {
    /// Create a new snap action context.
    pub fn new(coordinates: DebuggerCoordinates, snap: i64) -> Self {
        Self {
            coordinates,
            snap,
            scratch: false,
        }
    }

    /// Mark this context as being for a scratch snap.
    pub fn with_scratch(mut self, scratch: bool) -> Self {
        self.scratch = scratch;
        self
    }
}

// ── Listing Action Context ───────────────────────────────────────────

/// The action context for operations on the debugger listing.
///
/// Ported from Ghidra's `DebuggerListingActionContext`. Carries the
/// information needed for context-sensitive actions in the code listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerListingActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The address at the cursor, if any.
    pub address: Option<u64>,
    /// The address space name, if known.
    pub space_name: Option<String>,
    /// Whether the context is in a scratch (unsaved) snapshot.
    pub scratch: bool,
    /// Whether the current position has known memory state.
    pub known_memory: bool,
}

impl DebuggerListingActionContext {
    /// Create a new listing action context.
    pub fn new(coordinates: DebuggerCoordinates) -> Self {
        Self {
            coordinates,
            address: None,
            space_name: None,
            scratch: false,
            known_memory: false,
        }
    }

    /// Set the address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Set the address space name.
    pub fn with_space(mut self, space: impl Into<String>) -> Self {
        self.space_name = Some(space.into());
        self
    }
}

// ── Breakpoint Location Action Context ───────────────────────────────

/// Action context for breakpoint location operations.
///
/// Ported from Ghidra's `DebuggerBreakpointLocationsActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointLocationsActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The breakpoint location addresses.
    pub locations: Vec<BreakpointLocationEntry>,
    /// Whether all selected locations are enabled.
    pub all_enabled: bool,
    /// Whether any selected locations have pending changes.
    pub has_pending: bool,
}

/// A breakpoint location entry in the locations table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointLocationEntry {
    /// The location address.
    pub address: u64,
    /// The address space name.
    pub space_name: String,
    /// The length in bytes of the breakpoint.
    pub length: u64,
    /// Whether this location is enabled.
    pub enabled: bool,
    /// The breakpoint kinds.
    pub kinds: Vec<TraceBreakpointKind>,
    /// The expression (if any).
    pub expression: Option<String>,
}

// ── Logical Breakpoint Action Context ────────────────────────────────

/// Action context for logical breakpoint operations.
///
/// Ported from Ghidra's `DebuggerLogicalBreakpointsActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalBreakpointsActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The selected logical breakpoints.
    pub breakpoints: Vec<LogicalBreakpointEntry>,
    /// Whether all selected breakpoints are enabled.
    pub all_enabled: bool,
    /// Whether any selected breakpoints are effective.
    pub any_effective: bool,
}

/// A logical breakpoint entry for the action context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalBreakpointEntry {
    /// The logical breakpoint ID.
    pub id: i64,
    /// The address (if known).
    pub address: Option<u64>,
    /// The expression (if any).
    pub expression: Option<String>,
    /// Whether this breakpoint is enabled.
    pub enabled: bool,
    /// Whether this breakpoint is effective on the target.
    pub effective: bool,
    /// The number of associated trace breakpoints.
    pub trace_breakpoint_count: usize,
    /// The number of associated emulator breakpoints.
    pub emu_breakpoint_count: usize,
}

// ── Module Action Context ────────────────────────────────────────────

/// Action context for module operations in the debugger.
///
/// Ported from Ghidra's `DebuggerModuleActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerModuleActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The selected module entries.
    pub modules: Vec<ModuleActionEntry>,
    /// Whether mapping proposals are available.
    pub has_proposals: bool,
}

/// A module entry for the action context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleActionEntry {
    /// The module name.
    pub name: String,
    /// The module base address.
    pub base: u64,
    /// The module length.
    pub length: u64,
    /// The mapped program path (if mapped).
    pub mapped_program: Option<String>,
    /// The static mapping (if any).
    pub mapping: Option<TraceStaticMapping>,
}

// ── Section Action Context ───────────────────────────────────────────

/// Action context for section operations in the debugger.
///
/// Ported from Ghidra's `DebuggerSectionActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerSectionActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The selected section entries.
    pub sections: Vec<SectionActionEntry>,
}

/// A section entry for the action context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionActionEntry {
    /// The parent module name.
    pub module_name: String,
    /// The section name.
    pub name: String,
    /// The section start address.
    pub start: u64,
    /// The section length.
    pub length: u64,
    /// Whether this section is mapped.
    pub mapped: bool,
}

// ── Static Mapping Action Context ────────────────────────────────────

/// Action context for static mapping operations.
///
/// Ported from Ghidra's `DebuggerStaticMappingActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerStaticMappingActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The selected mappings.
    pub mappings: Vec<StaticMappingActionEntry>,
}

/// A static mapping entry for the action context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMappingActionEntry {
    /// The trace address range (start).
    pub trace_start: u64,
    /// The trace address range (length).
    pub trace_length: u64,
    /// The program address range (start).
    pub program_start: u64,
    /// The program address range (length).
    pub program_length: u64,
    /// The lifespan snap range (start).
    pub snap_from: i64,
    /// The lifespan snap range (end).
    pub snap_to: i64,
}

// ── Watch Action Context ─────────────────────────────────────────────

/// Action context for watch expression operations.
///
/// Ported from Ghidra's `DebuggerWatchActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerWatchActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The selected watch expression rows.
    pub watches: Vec<WatchActionEntry>,
    /// Whether any selected watch has an error.
    pub any_errors: bool,
}

/// A watch entry for the action context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchActionEntry {
    /// The expression string.
    pub expression: String,
    /// The value bytes (if resolved).
    pub value: Option<Vec<u8>>,
    /// The error message (if evaluation failed).
    pub error: Option<String>,
    /// Whether the value is editable.
    pub editable: bool,
}

// ── Trace File Action Context ────────────────────────────────────────

/// Action context for operations on trace files.
///
/// Ported from Ghidra's `DebuggerTraceFileActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerTraceFileActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The trace file path.
    pub file_path: Option<String>,
    /// Whether the trace has unsaved changes.
    pub dirty: bool,
    /// Whether the trace is a "pure emulation" trace.
    pub emulated: bool,
}

// ── Register Action Context ──────────────────────────────────────────

/// Action context for register operations in the debugger.
///
/// Ported from Ghidra's `DebuggerRegisterActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerRegisterActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The selected register entries.
    pub registers: Vec<RegisterActionEntry>,
}

/// A register entry for the action context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterActionEntry {
    /// The register name.
    pub name: String,
    /// The register value (if known).
    pub value: Option<Vec<u8>>,
    /// Whether the value has changed since the last snapshot.
    pub changed: bool,
    /// Whether the value is editable.
    pub editable: bool,
}

/// Action context for the "available registers" dialog.
///
/// Ported from Ghidra's `DebuggerAvailableRegistersActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerAvailableRegistersActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// All available registers.
    pub available_registers: Vec<AvailableRegisterEntry>,
}

/// An available register entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableRegisterEntry {
    /// The register name.
    pub name: String,
    /// The register size in bits.
    pub bit_size: u32,
    /// Whether this register is currently displayed.
    pub displayed: bool,
    /// The register group (e.g., "General", "Floating Point").
    pub group: Option<String>,
}

// ── Memory Action Contexts ───────────────────────────────────────────

/// Action context for memory bytes operations.
///
/// Ported from Ghidra's `DebuggerMemoryBytesActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerMemoryBytesActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The address at the cursor.
    pub address: u64,
    /// The selected byte range.
    pub selection: Option<(u64, u64)>,
    /// Whether the selected bytes have known state.
    pub known: bool,
}

/// Action context for memory region operations.
///
/// Ported from Ghidra's `DebuggerRegionActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerRegionActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The selected memory regions.
    pub regions: Vec<RegionActionEntry>,
}

/// A memory region entry for the action context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionActionEntry {
    /// The region name.
    pub name: String,
    /// The region start address.
    pub start: u64,
    /// The region length.
    pub length: u64,
    /// The region permissions.
    pub permissions: RegionPermissions,
}

/// Permissions for a memory region in an action context.
///
/// Re-uses the `RegionPermissions` from `debugger_regions` module.

// ── Trace Call Tree Context ──────────────────────────────────────────

/// Action context for trace call tree operations.
///
/// Ported from Ghidra's `TraceCallTreeActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCallTreeActionContext {
    /// The current debugger coordinates.
    pub coordinates: DebuggerCoordinates,
    /// The selected call tree nodes.
    pub nodes: Vec<CallTreeActionNode>,
}

/// A call tree node for the action context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTreeActionNode {
    /// The function name.
    pub function_name: String,
    /// The call address.
    pub call_address: u64,
    /// The return address.
    pub return_address: Option<u64>,
    /// The node kind.
    pub kind: CallTreeActionNodeKind,
    /// The depth in the call tree.
    pub depth: usize,
}

/// The kind of call tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallTreeActionNodeKind {
    /// A regular call.
    Call,
    /// A tail call.
    TailCall,
    /// A return.
    Return,
    /// An external function.
    External,
    /// A log entry.
    LogEntry,
}

// ── Multi Provider Save Behavior (Action-Level) ─────────────────────

/// How save actions should behave for the action context system.
///
/// This is the action-context view of save behavior. The data-model
/// view is in `gui_panel_models::MultiProviderSaveBehavior`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SaveBehavior {
    /// Save is not applicable (provider has no saveable state).
    NotApplicable,
    /// Save all providers at once.
    SaveAll,
    /// Save only the current provider.
    SaveCurrent,
    /// Prompt the user for each provider.
    PromptEach,
}

impl Default for SaveBehavior {
    fn default() -> Self {
        Self::NotApplicable
    }
}

// ── Invoke Action Entry ──────────────────────────────────────────────

/// An entry in the invoke action list.
///
/// Ported from Ghidra's `InvokeActionEntryAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeActionEntry {
    /// The action name.
    pub action: ActionName,
    /// The display name.
    pub display_name: String,
    /// The description.
    pub description: String,
    /// Whether this action is enabled.
    pub enabled: bool,
    /// The keyboard shortcut, if any.
    pub shortcut: Option<String>,
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_model() {
        let model = DebuggerProviderModel::new("Test Panel")
            .with_window_group("debugger_group")
            .with_multiple();
        assert_eq!(model.title, "Test Panel");
        assert_eq!(model.window_group.as_deref(), Some("debugger_group"));
        assert!(model.supports_multiple);
        assert!(!model.visible);
    }

    #[test]
    fn test_snap_action_context() {
        let coords = DebuggerCoordinates::default();
        let ctx = DebuggerSnapActionContext::new(coords, 42).with_scratch(true);
        assert_eq!(ctx.snap, 42);
        assert!(ctx.scratch);
    }

    #[test]
    fn test_listing_action_context() {
        let coords = DebuggerCoordinates::default();
        let ctx = DebuggerListingActionContext::new(coords)
            .with_address(0x1000)
            .with_space("ram");
        assert_eq!(ctx.address, Some(0x1000));
        assert_eq!(ctx.space_name.as_deref(), Some("ram"));
    }

    #[test]
    fn test_region_permissions() {
        let all = RegionPermissions::all();
        assert!(all.read);
        assert!(all.write);
        assert!(all.execute);

        let ro = RegionPermissions::read_only();
        assert!(ro.read);
        assert!(!ro.write);
        assert!(!ro.execute);
    }

    #[test]
    fn test_module_action_context() {
        let coords = DebuggerCoordinates::default();
        let modules = vec![ModuleActionEntry {
            name: "libc.so".to_string(),
            base: 0x7fff0000,
            length: 0x200000,
            mapped_program: None,
            mapping: None,
        }];
        let ctx = DebuggerModuleActionContext {
            coordinates: coords,
            modules,
            has_proposals: true,
        };
        assert_eq!(ctx.modules.len(), 1);
        assert_eq!(ctx.modules[0].name, "libc.so");
        assert!(ctx.has_proposals);
    }

    #[test]
    fn test_call_tree_action_context() {
        let coords = DebuggerCoordinates::default();
        let nodes = vec![
            CallTreeActionNode {
                function_name: "main".to_string(),
                call_address: 0x401000,
                return_address: Some(0x401050),
                kind: CallTreeActionNodeKind::Call,
                depth: 0,
            },
            CallTreeActionNode {
                function_name: "printf".to_string(),
                call_address: 0x401020,
                return_address: Some(0x401028),
                kind: CallTreeActionNodeKind::External,
                depth: 1,
            },
        ];
        let ctx = TraceCallTreeActionContext {
            coordinates: coords,
            nodes,
        };
        assert_eq!(ctx.nodes.len(), 2);
        assert_eq!(ctx.nodes[0].kind, CallTreeActionNodeKind::Call);
        assert_eq!(ctx.nodes[1].kind, CallTreeActionNodeKind::External);
    }

    #[test]
    fn test_save_behavior() {
        assert_eq!(SaveBehavior::default(), SaveBehavior::NotApplicable);

        let behaviors = [
            SaveBehavior::NotApplicable,
            SaveBehavior::SaveAll,
            SaveBehavior::SaveCurrent,
            SaveBehavior::PromptEach,
        ];
        assert_eq!(behaviors.len(), 4);
    }

    #[test]
    fn test_invoke_action_entry() {
        let entry = InvokeActionEntry {
            action: ActionName::StepInto,
            display_name: "Step Into".to_string(),
            description: "Step into the current instruction".to_string(),
            enabled: true,
            shortcut: Some("F7".to_string()),
        };
        assert!(entry.enabled);
        assert_eq!(entry.shortcut.as_deref(), Some("F7"));
    }

    #[test]
    fn test_breakpoint_location_entry() {
        let entry = BreakpointLocationEntry {
            address: 0x401000,
            space_name: "ram".to_string(),
            length: 1,
            enabled: true,
            kinds: vec![TraceBreakpointKind::SwExecute],
            expression: None,
        };
        assert_eq!(entry.address, 0x401000);
        assert!(entry.enabled);
    }

    #[test]
    fn test_static_mapping_action_entry() {
        let entry = StaticMappingActionEntry {
            trace_start: 0x7fff0000,
            trace_length: 0x1000,
            program_start: 0x401000,
            program_length: 0x1000,
            snap_from: 0,
            snap_to: i64::MAX,
        };
        assert_eq!(entry.snap_from, 0);
        assert_eq!(entry.snap_to, i64::MAX);
    }

    #[test]
    fn test_watch_action_context() {
        let coords = DebuggerCoordinates::default();
        let watches = vec![
            WatchActionEntry {
                expression: "RAX".to_string(),
                value: Some(vec![0x42; 8]),
                error: None,
                editable: true,
            },
            WatchActionEntry {
                expression: "invalid_expr".to_string(),
                value: None,
                error: Some("Syntax error".to_string()),
                editable: false,
            },
        ];
        let ctx = DebuggerWatchActionContext {
            coordinates: coords,
            watches,
            any_errors: true,
        };
        assert!(ctx.any_errors);
        assert!(ctx.watches[0].error.is_none());
        assert!(ctx.watches[1].error.is_some());
    }

    #[test]
    fn test_trace_file_action_context() {
        let coords = DebuggerCoordinates::default();
        let ctx = DebuggerTraceFileActionContext {
            coordinates: coords,
            file_path: Some("/tmp/trace.db".to_string()),
            dirty: true,
            emulated: false,
        };
        assert!(ctx.dirty);
        assert!(!ctx.emulated);
    }

    #[test]
    fn test_register_action_entry() {
        let entry = RegisterActionEntry {
            name: "RAX".to_string(),
            value: Some(vec![0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00]),
            changed: true,
            editable: true,
        };
        assert!(entry.changed);
        assert_eq!(entry.value.as_ref().unwrap().len(), 8);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let ctx = DebuggerMemoryBytesActionContext {
            coordinates: DebuggerCoordinates::default(),
            address: 0x401000,
            selection: Some((0x401000, 0x4010ff)),
            known: true,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let deserialized: DebuggerMemoryBytesActionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.address, 0x401000);
        assert!(deserialized.known);
    }

    #[test]
    fn test_region_action_entry() {
        let entry = RegionActionEntry {
            name: ".text".to_string(),
            start: 0x401000,
            length: 0x5000,
            permissions: RegionPermissions {
                read: true, write: false, execute: true,
            },
        };
        assert_eq!(entry.name, ".text");
        assert!(entry.permissions.read);
        assert!(entry.permissions.execute);
        assert!(!entry.permissions.write);
    }
}
