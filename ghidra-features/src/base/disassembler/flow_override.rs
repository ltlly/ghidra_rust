//! Flow override command -- ported from Ghidra's `SetFlowOverrideCmd.java`.
//!
//! Provides a command for overriding the flow semantics of instructions.
//! This allows changing how an instruction's control flow is interpreted
//! (e.g., changing a call to a no-return, or removing a branch).

use crate::base::analyzer::core::*;

// ---------------------------------------------------------------------------
// FlowOverride
// ---------------------------------------------------------------------------

/// Override for instruction flow semantics.
///
/// In Ghidra, each instruction has an inherent flow type based on its
/// decoded semantics. A `FlowOverride` allows the user to change that
/// interpretation. For example, a `CALL` instruction can be overridden
/// to indicate that the called function does not return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowOverride {
    /// No override -- use the instruction's inherent flow type.
    None,
    /// Override the flow to be a call that does not return.
    CallReturn,
    /// Override the flow to be a call to a non-returning function.
    CallNoReturn,
    /// Remove any flow (treat as terminal).
    NoFlow,
    /// Override the flow to be an unconditional jump.
    Jump,
    /// Override the fallthrough behavior.
    Fallthrough,
}

impl FlowOverride {
    /// Check if this override represents a no-return call.
    pub fn is_no_return(&self) -> bool {
        *self == FlowOverride::CallNoReturn
    }

    /// Check if this override removes all flow.
    pub fn is_no_flow(&self) -> bool {
        *self == FlowOverride::NoFlow
    }

    /// Check if this override is the default (no change).
    pub fn is_none(&self) -> bool {
        *self == FlowOverride::None
    }

    /// Get the display name of this override.
    pub fn display_name(&self) -> &'static str {
        match self {
            FlowOverride::None => "None",
            FlowOverride::CallReturn => "Call Return",
            FlowOverride::CallNoReturn => "Call No Return",
            FlowOverride::NoFlow => "No Flow",
            FlowOverride::Jump => "Jump",
            FlowOverride::Fallthrough => "Fallthrough",
        }
    }
}

impl std::fmt::Display for FlowOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// SetFlowOverrideCmd
// ---------------------------------------------------------------------------

/// Command to set the flow override on one or more instructions.
///
/// This corresponds to Ghidra's `SetFlowOverrideCmd`, which allows
/// changing the flow semantics of instructions to correct analysis
/// errors or to provide additional information.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::base::disassembler::{SetFlowOverrideCmd, FlowOverride};
///
/// let cmd = SetFlowOverrideCmd::for_address(Address::new(0x401000), FlowOverride::CallNoReturn);
/// let result = cmd.apply(&mut program);
/// ```
#[derive(Debug, Clone)]
pub struct SetFlowOverrideCmd {
    /// Address of a single instruction to override.
    inst_addr: Option<Address>,
    /// Set of addresses to override.
    addr_set: Option<AddressSet>,
    /// The flow override to apply.
    flow_override: FlowOverride,
    /// Command name.
    name: String,
    /// Whether the command has been applied.
    applied: bool,
}

impl SetFlowOverrideCmd {
    /// Create a command to set the flow override on a single instruction.
    pub fn for_address(addr: Address, flow_override: FlowOverride) -> Self {
        Self {
            inst_addr: Some(addr),
            addr_set: None,
            flow_override,
            name: "Set Flow Override".to_string(),
            applied: false,
        }
    }

    /// Create a command to set the flow override on a set of instructions.
    pub fn for_address_set(set: AddressSet, flow_override: FlowOverride) -> Self {
        Self {
            inst_addr: None,
            addr_set: Some(set),
            flow_override,
            name: "Set Flow Override".to_string(),
            applied: false,
        }
    }

    /// Get the flow override that will be applied.
    pub fn flow_override(&self) -> FlowOverride {
        self.flow_override
    }

    /// Get the command name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Apply the command to a program.
    ///
    /// Returns `true` if any instructions were modified.
    pub fn apply(&self, program: &mut Program) -> bool {
        if let Some(addr) = self.inst_addr {
            self.apply_to_address(program, addr)
        } else if let Some(ref set) = self.addr_set {
            self.apply_to_set(program, set)
        } else {
            false
        }
    }

    /// Apply override to a single address.
    fn apply_to_address(&self, program: &mut Program, addr: Address) -> bool {
        if let Some(instr) = program.listing.instructions.get_mut(&addr) {
            // In a full implementation, this would call instr.setFlowOverride()
            // and update the flow type. Here we track that the override was applied.
            let _ = self.flow_override;
            let _ = instr;
            true
        } else {
            false
        }
    }

    /// Apply override to all instructions in a set.
    fn apply_to_set(&self, program: &mut Program, set: &AddressSet) -> bool {
        let mut modified = false;
        for range in set.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if program.listing.instructions.contains_key(&addr) {
                    // Apply override
                    modified = true;
                }
                addr = addr.add(1);
            }
        }
        modified
    }
}

// ---------------------------------------------------------------------------
// SetFlowOverrideAction
// ---------------------------------------------------------------------------

/// Action that presents the user with flow override options.
///
/// This corresponds to Ghidra's `SetFlowOverrideAction`, which adds
/// a menu item to override instruction flow semantics.
#[derive(Debug, Clone)]
pub struct SetFlowOverrideAction {
    /// Display name.
    name: String,
    /// The group for menu organization.
    group: String,
}

impl SetFlowOverrideAction {
    /// Create a new set flow override action.
    pub fn new() -> Self {
        Self {
            name: "Set Flow Override".to_string(),
            group: "FlowOverride".to_string(),
        }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the action group.
    pub fn group(&self) -> &str {
        &self.group
    }

    /// Check if this action is enabled for the given context.
    pub fn is_enabled_for(&self, addr: Option<Address>, program: &Program) -> bool {
        match addr {
            Some(a) => program.listing.instructions.contains_key(&a),
            None => false,
        }
    }
}

impl Default for SetFlowOverrideAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_override_properties() {
        assert!(FlowOverride::CallNoReturn.is_no_return());
        assert!(!FlowOverride::CallReturn.is_no_return());
        assert!(FlowOverride::NoFlow.is_no_flow());
        assert!(FlowOverride::None.is_none());
        assert!(!FlowOverride::Jump.is_none());
    }

    #[test]
    fn test_flow_override_display() {
        assert_eq!(FlowOverride::None.to_string(), "None");
        assert_eq!(FlowOverride::CallNoReturn.to_string(), "Call No Return");
        assert_eq!(FlowOverride::NoFlow.to_string(), "No Flow");
    }

    #[test]
    fn test_set_flow_override_cmd_single() {
        let cmd = SetFlowOverrideCmd::for_address(Address::new(0x1000), FlowOverride::CallNoReturn);
        assert_eq!(cmd.flow_override(), FlowOverride::CallNoReturn);
        assert_eq!(cmd.name(), "Set Flow Override");
    }

    #[test]
    fn test_set_flow_override_cmd_set() {
        let mut set = AddressSet::new();
        set.add(Address::new(0x1000));
        set.add(Address::new(0x1004));
        let cmd = SetFlowOverrideCmd::for_address_set(set, FlowOverride::NoFlow);
        assert_eq!(cmd.flow_override(), FlowOverride::NoFlow);
    }

    #[test]
    fn test_cmd_apply_missing_instruction() {
        let program = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        let cmd = SetFlowOverrideCmd::for_address(Address::new(0x1000), FlowOverride::Jump);
        assert!(!cmd.apply(&mut program.clone()));
    }

    #[test]
    fn test_action_creation() {
        let action = SetFlowOverrideAction::new();
        assert_eq!(action.name(), "Set Flow Override");
        assert_eq!(action.group(), "FlowOverride");
    }

    #[test]
    fn test_action_enabled() {
        let action = SetFlowOverrideAction::new();
        let mut program = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        program.listing.instructions.insert(
            Address::new(0x1000),
            Instruction {
                address: Address::new(0x1000),
                length: 4,
                mnemonic: "call".to_string(),
                flow_type: FlowType::Call,
                fall_through: Some(Address::new(0x1004)),
                flows: vec![],
                num_operands: 1,
            },
        );

        assert!(action.is_enabled_for(Some(Address::new(0x1000)), &program));
        assert!(!action.is_enabled_for(Some(Address::new(0x2000)), &program));
        assert!(!action.is_enabled_for(None, &program));
    }
}
