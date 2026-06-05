//! Processor-specific disassembly actions -- ported from
//! `ghidra.app.plugin.core.disassembler`.
//!
//! Provides action definitions for processor-specific disassembly modes
//! (ARM Thumb, MIPS16, PPC VLE, x86 32-bit mode, HCS12 XGATE).

/// A processor-specific disassembly action.
///
/// Models the various `*DisassembleAction` classes in Ghidra's disassembler package.
#[derive(Debug, Clone)]
pub struct ProcessorDisassembleAction {
    /// The action name.
    pub name: String,
    /// The processor this action applies to.
    pub processor: ProcessorFamily,
    /// The specific disassembly mode.
    pub mode: ProcessorDisassemblyMode,
    /// Popup menu path.
    pub popup_menu_path: Vec<String>,
    /// Key binding (if any).
    pub key_binding: Option<String>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

/// Processor families with special disassembly modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessorFamily {
    /// ARM (including Thumb mode).
    ARM,
    /// MIPS (including MIPS16 mode).
    MIPS,
    /// PowerPC (including VLE mode).
    PowerPC,
    /// x86 / x86-64 (32-bit compatibility mode).
    X86,
    /// Freescale HCS12 (XGATE mode).
    HCS12,
}

/// Processor-specific disassembly modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessorDisassemblyMode {
    /// ARM normal (32-bit) mode.
    ArmNormal,
    /// ARM Thumb (16-bit) mode.
    ArmThumb,
    /// MIPS normal mode.
    MipsNormal,
    /// MIPS16 mode.
    Mips16,
    /// PowerPC normal mode.
    PpcNormal,
    /// PowerPC VLE (Variable Length Encoding) mode.
    PpcVle,
    /// x86-64 in 64-bit mode.
    X86_64,
    /// x86-64 in 32-bit (legacy) mode.
    X86_32,
    /// HCS12 normal mode.
    Hcs12Normal,
    /// HCS12 XGATE mode.
    Hcs12Xgate,
}

impl ProcessorDisassemblyMode {
    /// The display name for this mode.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::ArmNormal => "ARM",
            Self::ArmThumb => "ARM Thumb",
            Self::MipsNormal => "MIPS",
            Self::Mips16 => "MIPS16",
            Self::PpcNormal => "PowerPC",
            Self::PpcVle => "PowerPC VLE",
            Self::X86_64 => "x86-64",
            Self::X86_32 => "x86 (32-bit)",
            Self::Hcs12Normal => "HCS12",
            Self::Hcs12Xgate => "HCS12 XGATE",
        }
    }

    /// The popup menu label for this mode.
    pub fn menu_label(&self) -> String {
        format!("Disassemble ({})", self.display_name())
    }

    /// Whether this is a non-default mode (e.g. Thumb, MIPS16, VLE).
    pub fn is_non_default(&self) -> bool {
        matches!(
            self,
            Self::ArmThumb
                | Self::Mips16
                | Self::PpcVle
                | Self::X86_32
                | Self::Hcs12Xgate
        )
    }
}

impl ProcessorDisassembleAction {
    /// Create a new processor-specific disassembly action.
    pub fn new(
        name: impl Into<String>,
        processor: ProcessorFamily,
        mode: ProcessorDisassemblyMode,
    ) -> Self {
        let name_str = name.into();
        Self {
            name: name_str,
            processor,
            mode,
            popup_menu_path: vec!["Disassemble".into(), mode.menu_label()],
            key_binding: None,
            enabled: true,
        }
    }

    /// Create all standard processor-specific actions.
    pub fn all_standard_actions() -> Vec<Self> {
        vec![
            Self::new("Disassemble ARM Thumb", ProcessorFamily::ARM, ProcessorDisassemblyMode::ArmThumb),
            Self::new("Disassemble MIPS16", ProcessorFamily::MIPS, ProcessorDisassemblyMode::Mips16),
            Self::new("Disassemble PPC VLE", ProcessorFamily::PowerPC, ProcessorDisassemblyMode::PpcVle),
            Self::new(
                "Disassemble x86-64 (32-bit mode)",
                ProcessorFamily::X86,
                ProcessorDisassemblyMode::X86_32,
            ),
            Self::new(
                "Disassemble HCS12 XGATE",
                ProcessorFamily::HCS12,
                ProcessorDisassemblyMode::Hcs12Xgate,
            ),
        ]
    }
}

/// Context register state for disassembly.
///
/// Models `ProcessorStateDialog` and the context register management.
#[derive(Debug, Clone, Default)]
pub struct ProcessorState {
    /// Context register values (register name -> value).
    pub context_values: std::collections::HashMap<String, u64>,
    /// Whether any values have been modified.
    pub dirty: bool,
}

impl ProcessorState {
    /// Create a new empty processor state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a context register value.
    pub fn set_register(&mut self, name: impl Into<String>, value: u64) {
        self.context_values.insert(name.into(), value);
        self.dirty = true;
    }

    /// Get a context register value.
    pub fn get_register(&self, name: &str) -> Option<u64> {
        self.context_values.get(name).copied()
    }

    /// Whether the processor has any context registers set.
    pub fn has_context_registers(&self) -> bool {
        !self.context_values.is_empty()
    }

    /// Clear the dirty flag.
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// Reset all registers to default.
    pub fn reset(&mut self) {
        self.context_values.clear();
        self.dirty = true;
    }
}

// ---------------------------------------------------------------------------
// SetFlowOverrideAction
// ---------------------------------------------------------------------------

/// Types of flow overrides that can be applied to instructions.
///
/// Ported from `ghidra.app.plugin.core.disassembler.SetFlowOverrideAction`
/// and `SetFlowOverrideDialog`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOverrideType {
    /// No override (default flow).
    None,
    /// Override to call.
    Call,
    /// Override to call-return.
    CallReturn,
    /// Override to jump.
    Jump,
    /// Override to return.
    Return,
}

impl FlowOverrideType {
    /// Display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::None => "Default",
            Self::Call => "Call Override",
            Self::CallReturn => "Call-Return Override",
            Self::Jump => "Jump Override",
            Self::Return => "Return Override",
        }
    }

    /// All available override types.
    pub fn all() -> &'static [FlowOverrideType] {
        &[
            Self::None,
            Self::Call,
            Self::CallReturn,
            Self::Jump,
            Self::Return,
        ]
    }
}

/// Action for setting flow overrides on instructions.
///
/// Ported from `ghidra.app.plugin.core.disassembler.SetFlowOverrideAction`.
#[derive(Debug, Clone)]
pub struct SetFlowOverrideAction {
    /// The display name.
    pub name: String,
    /// The override type.
    pub override_type: FlowOverrideType,
    /// Popup menu path.
    pub popup_menu_path: Vec<String>,
    /// Whether enabled.
    pub enabled: bool,
}

impl SetFlowOverrideAction {
    /// Create all flow override actions.
    pub fn all_actions() -> Vec<Self> {
        FlowOverrideType::all()
            .iter()
            .map(|&override_type| Self {
                name: format!("Set Flow: {}", override_type.display_name()),
                override_type,
                popup_menu_path: vec![
                    "Disassemble".into(),
                    "Flow Override".into(),
                    override_type.display_name().into(),
                ],
                enabled: override_type != FlowOverrideType::None,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Restricted Disassembly
// ---------------------------------------------------------------------------

/// Options for restricted disassembly.
///
/// Ported from `ghidra.app.plugin.core.disassembler.RestrictedDisassembleAction`.
#[derive(Debug, Clone)]
pub struct RestrictedDisassembleOptions {
    /// The address to disassemble at.
    pub address: u64,
    /// Whether to restrict to the current selection.
    pub restrict_to_selection: bool,
    /// Whether to follow data pointers.
    pub follow_data_pointers: bool,
    /// Maximum depth for pointer following.
    pub max_pointer_depth: usize,
    /// Whether to disassemble into external memory.
    pub follow_externals: bool,
}

impl RestrictedDisassembleOptions {
    /// Create default options for an address.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            restrict_to_selection: false,
            follow_data_pointers: true,
            max_pointer_depth: 1,
            follow_externals: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_disassemble_action_new() {
        let action = ProcessorDisassembleAction::new(
            "Disassemble ARM Thumb",
            ProcessorFamily::ARM,
            ProcessorDisassemblyMode::ArmThumb,
        );
        assert_eq!(action.name, "Disassemble ARM Thumb");
        assert_eq!(action.processor, ProcessorFamily::ARM);
        assert_eq!(action.mode, ProcessorDisassemblyMode::ArmThumb);
        assert!(action.enabled);
    }

    #[test]
    fn test_all_standard_actions() {
        let actions = ProcessorDisassembleAction::all_standard_actions();
        assert_eq!(actions.len(), 5);
        // All non-default modes
        for action in &actions {
            assert!(action.mode.is_non_default());
        }
    }

    #[test]
    fn test_processor_disassembly_mode_display() {
        assert_eq!(ProcessorDisassemblyMode::ArmThumb.display_name(), "ARM Thumb");
        assert_eq!(ProcessorDisassemblyMode::Mips16.display_name(), "MIPS16");
        assert_eq!(ProcessorDisassemblyMode::PpcVle.display_name(), "PowerPC VLE");
    }

    #[test]
    fn test_processor_disassembly_mode_is_non_default() {
        assert!(ProcessorDisassemblyMode::ArmThumb.is_non_default());
        assert!(!ProcessorDisassemblyMode::ArmNormal.is_non_default());
        assert!(!ProcessorDisassemblyMode::MipsNormal.is_non_default());
        assert!(ProcessorDisassemblyMode::X86_32.is_non_default());
    }

    #[test]
    fn test_processor_state() {
        let mut state = ProcessorState::new();
        assert!(!state.has_context_registers());
        state.set_register("TMode", 1);
        assert!(state.has_context_registers());
        assert_eq!(state.get_register("TMode"), Some(1));
        assert!(state.dirty);
        state.clear_dirty();
        assert!(!state.dirty);
        state.reset();
        assert!(!state.has_context_registers());
    }

    #[test]
    fn test_flow_override_type() {
        assert_eq!(FlowOverrideType::Call.display_name(), "Call Override");
        assert_eq!(FlowOverrideType::all().len(), 5);
    }

    #[test]
    fn test_set_flow_override_actions() {
        let actions = SetFlowOverrideAction::all_actions();
        assert_eq!(actions.len(), 5);
        // First action (None) is disabled by default
        assert!(!actions[0].enabled);
        assert!(actions[1].enabled);
    }

    #[test]
    fn test_restricted_disassemble_options() {
        let opts = RestrictedDisassembleOptions::new(0x1000);
        assert_eq!(opts.address, 0x1000);
        assert!(!opts.restrict_to_selection);
        assert!(opts.follow_data_pointers);
        assert_eq!(opts.max_pointer_depth, 1);
        assert!(!opts.follow_externals);
    }

    #[test]
    fn test_menu_label() {
        assert_eq!(
            ProcessorDisassemblyMode::ArmThumb.menu_label(),
            "Disassemble (ARM Thumb)"
        );
    }
}
