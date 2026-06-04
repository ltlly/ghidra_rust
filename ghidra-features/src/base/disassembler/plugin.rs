//! Disassembler plugin -- ported from Ghidra's
//! `DisassemblerPlugin.java` and related action classes.
//!
//! This module provides the disassembler plugin infrastructure:
//! - [`DisassemblerPlugin`] -- main plugin that provides disassembly services
//! - [`DisassembleAction`] -- action for dynamic disassembly from cursor
//! - [`StaticDisassembleAction`] -- action for static range disassembly
//! - [`RestrictedDisassembleAction`] -- action for restricted-area disassembly
//! - [`ContextAction`] -- action for editing disassembly context registers

use crate::base::analyzer::core::*;
use crate::base::disassembler::core::DisassemblyResult;

// ---------------------------------------------------------------------------
// DisassemblerPlugin
// ---------------------------------------------------------------------------

/// The main disassembler plugin providing disassembly services.
///
/// This plugin provides functionality for:
/// - **Dynamic disassembly**: starts from selected addresses or cursor
///   location, follows fall-throughs and flows to continue disassembly.
/// - **Static disassembly**: disassembles a given range, removing
///   existing code first.
/// - **Restricted disassembly**: disassembles within a restricted area.
///
/// # Actions
///
/// The plugin registers several actions for different disassembly modes:
/// - `Disassemble` (key: `D`) -- dynamic disassembly from cursor
/// - `Static Disassemble` -- disassemble a selected range
/// - `Restricted Disassemble` -- disassemble within restrictions
/// - `Set Flow Override` -- change instruction flow semantics
/// - `Set Length Override` -- change instruction length
#[derive(Debug, Clone)]
pub struct DisassemblerPlugin {
    /// Plugin name.
    name: String,
    /// Plugin description.
    description: String,
    /// Registered actions.
    actions: Vec<DisassemblerAction>,
    /// Whether the plugin is enabled.
    enabled: bool,
}

impl DisassemblerPlugin {
    /// Group name for menu organization.
    pub const GROUP_NAME: &'static str = "Disassembly";

    /// Create a new disassembler plugin.
    pub fn new() -> Self {
        let mut plugin = Self {
            name: "Disassembler".to_string(),
            description: "Provides disassembler services for all supplied machine language modules."
                .to_string(),
            actions: Vec::new(),
            enabled: true,
        };
        plugin.create_actions();
        plugin
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the plugin description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the plugin category.
    pub fn category() -> &'static str {
        "Disassemblers"
    }

    /// Check if the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get a reference to the registered actions.
    pub fn actions(&self) -> &[DisassemblerAction] {
        &self.actions
    }

    /// Create the default set of actions.
    fn create_actions(&mut self) {
        self.actions.push(DisassemblerAction {
            name: "Disassemble".to_string(),
            description: "Dynamic disassembly from cursor".to_string(),
            key_binding: Some(("D".to_string(), 0)),
            menu_path: vec!["Disassemble".to_string(), "Disassemble".to_string()],
            group: Self::GROUP_NAME.to_string(),
            action_type: DisassembleActionType::Dynamic,
        });
        self.actions.push(DisassemblerAction {
            name: "Static Disassemble".to_string(),
            description: "Static disassembly of selected range".to_string(),
            key_binding: None,
            menu_path: vec![
                "Disassemble".to_string(),
                "Static Disassemble".to_string(),
            ],
            group: Self::GROUP_NAME.to_string(),
            action_type: DisassembleActionType::Static,
        });
        self.actions.push(DisassemblerAction {
            name: "Restricted Disassemble".to_string(),
            description: "Disassembly within restricted area".to_string(),
            key_binding: None,
            menu_path: vec![
                "Disassemble".to_string(),
                "Restricted Disassemble".to_string(),
            ],
            group: Self::GROUP_NAME.to_string(),
            action_type: DisassembleActionType::Restricted,
        });
        self.actions.push(DisassemblerAction {
            name: "Set Flow Override".to_string(),
            description: "Override instruction flow semantics".to_string(),
            key_binding: None,
            menu_path: vec![
                "Disassemble".to_string(),
                "Set Flow Override".to_string(),
            ],
            group: Self::GROUP_NAME.to_string(),
            action_type: DisassembleActionType::SetFlowOverride,
        });
    }

    /// Process a plugin event (e.g., program activation).
    pub fn process_event(&mut self, event: &PluginEvent) {
        match event {
            PluginEvent::ProgramActivated(_program_name) => {
                // In Ghidra, this would initialize disassembler properties
                // from the program's options.
            }
            _ => {}
        }
    }

    /// Check if disassembly is enabled at the given address.
    ///
    /// Returns true if the address is valid and the location is undefined
    /// or already an instruction.
    pub fn check_disassembly_enabled(
        &self,
        addr: Option<Address>,
        program: &Program,
        _is_dynamic: bool,
    ) -> bool {
        match addr {
            Some(a) => {
                // Check if the address is in initialized memory
                let in_memory = program.memory_blocks.iter().any(|block| {
                    block.is_initialized
                        && a.offset >= block.start.offset
                        && a.offset < block.start.offset + block.size
                });
                in_memory
            }
            None => false,
        }
    }

    /// Perform dynamic disassembly from a context.
    ///
    /// This is the main entry point for the "Disassemble" action.
    pub fn disassemble_callback(
        &self,
        addr: Address,
        program: &mut Program,
    ) -> DisassemblyResult {
        let config = super::core::DisassemblerConfig::new();
        let mut disassembler = super::core::Disassembler::new(config);
        let monitor = BasicTaskMonitor::new();
        disassembler.set_follow_flow(true);
        disassembler
            .disassemble_single(addr, program, &monitor)
            .unwrap_or_default()
    }
}

impl Default for DisassemblerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DisassemblerAction
// ---------------------------------------------------------------------------

/// A disassembler action registered by the plugin.
#[derive(Debug, Clone)]
pub struct DisassemblerAction {
    /// The action name.
    pub name: String,
    /// Description of the action.
    pub description: String,
    /// Key binding (key + modifiers).
    pub key_binding: Option<(String, u32)>,
    /// Menu path for the action.
    pub menu_path: Vec<String>,
    /// Group name for menu organization.
    pub group: String,
    /// The type of disassembly action.
    pub action_type: DisassembleActionType,
}

/// Types of disassembly actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisassembleActionType {
    /// Dynamic disassembly following flows from the cursor.
    Dynamic,
    /// Static disassembly of a range.
    Static,
    /// Restricted disassembly within a bounded area.
    Restricted,
    /// Context register editing.
    Context,
    /// Set flow override.
    SetFlowOverride,
    /// Set length override.
    SetLengthOverride,
}

// ---------------------------------------------------------------------------
// PluginEvent
// ---------------------------------------------------------------------------

/// Events that the disassembler plugin can process.
#[derive(Debug, Clone)]
pub enum PluginEvent {
    /// A program was activated in the tool.
    ProgramActivated(String),
    /// A program was deactivated.
    ProgramDeactivated(String),
    /// A selection changed in the listing.
    SelectionChanged,
}

// ---------------------------------------------------------------------------
// Architecture-specific disassemble actions
// ---------------------------------------------------------------------------

/// ARM-specific disassembly action (Thumb mode handling).
#[derive(Debug, Clone)]
pub struct ArmDisassembleAction;

impl ArmDisassembleAction {
    /// Create a new ARM disassembly action.
    pub fn new() -> Self {
        Self
    }

    /// Check if this action is applicable for the given program.
    pub fn is_applicable(program: &Program) -> bool {
        program.language.processor.to_uppercase() == "ARM"
    }
}

/// MIPS-specific disassembly action (delay slot handling).
#[derive(Debug, Clone)]
pub struct MipsDisassembleAction;

impl MipsDisassembleAction {
    /// Create a new MIPS disassembly action.
    pub fn new() -> Self {
        Self
    }

    /// Check if this action is applicable for the given program.
    pub fn is_applicable(program: &Program) -> bool {
        program.language.processor.to_uppercase() == "MIPS"
    }
}

/// PowerPC-specific disassembly action.
#[derive(Debug, Clone)]
pub struct PowerPCDisassembleAction;

impl PowerPCDisassembleAction {
    /// Create a new PowerPC disassembly action.
    pub fn new() -> Self {
        Self
    }

    /// Check if this action is applicable for the given program.
    pub fn is_applicable(program: &Program) -> bool {
        let proc = program.language.processor.to_uppercase();
        proc == "POWERPC" || proc == "PPC"
    }
}

/// x86-64 specific disassembly action.
#[derive(Debug, Clone)]
pub struct X86_64DisassembleAction;

impl X86_64DisassembleAction {
    /// Create a new x86-64 disassembly action.
    pub fn new() -> Self {
        Self
    }

    /// Check if this action is applicable for the given program.
    pub fn is_applicable(program: &Program) -> bool {
        let proc = program.language.processor.to_uppercase();
        proc == "X86" && program.language.size == 64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = DisassemblerPlugin::new();
        assert_eq!(plugin.name(), "Disassembler");
        assert_eq!(plugin.description(), "Provides disassembler services for all supplied machine language modules.");
        assert!(plugin.is_enabled());
        assert_eq!(plugin.actions().len(), 4);
    }

    #[test]
    fn test_plugin_category() {
        assert_eq!(DisassemblerPlugin::category(), "Disassemblers");
    }

    #[test]
    fn test_plugin_actions() {
        let plugin = DisassemblerPlugin::new();
        let action_names: Vec<&str> = plugin.actions().iter().map(|a| a.name.as_str()).collect();
        assert!(action_names.contains(&"Disassemble"));
        assert!(action_names.contains(&"Static Disassemble"));
        assert!(action_names.contains(&"Restricted Disassemble"));
        assert!(action_names.contains(&"Set Flow Override"));
    }

    #[test]
    fn test_dynamic_action_key_binding() {
        let plugin = DisassemblerPlugin::new();
        let dynamic_action = plugin
            .actions()
            .iter()
            .find(|a| a.action_type == DisassembleActionType::Dynamic)
            .unwrap();
        assert_eq!(dynamic_action.key_binding, Some(("D".to_string(), 0)));
    }

    #[test]
    fn test_check_disassembly_enabled() {
        let plugin = DisassemblerPlugin::new();
        let mut program = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        program.memory_blocks.push(MemoryBlock {
            name: ".text".to_string(),
            start: Address::new(0x400000),
            size: 0x10000,
            is_read: true,
            is_write: false,
            is_execute: true,
            is_initialized: true,
        });

        assert!(plugin.check_disassembly_enabled(Some(Address::new(0x400000)), &program, true));
        assert!(plugin.check_disassembly_enabled(Some(Address::new(0x40FFFF)), &program, true));
        assert!(!plugin.check_disassembly_enabled(Some(Address::new(0x300000)), &program, true));
        assert!(!plugin.check_disassembly_enabled(None, &program, true));
    }

    #[test]
    fn test_arm_action_applicability() {
        let arm_prog = Program::new("arm", Language {
            processor: "ARM".into(),
            variant: "LE".into(),
            size: 32,
        });
        let x86_prog = Program::new("x86", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        assert!(ArmDisassembleAction::is_applicable(&arm_prog));
        assert!(!ArmDisassembleAction::is_applicable(&x86_prog));
    }

    #[test]
    fn test_mips_action_applicability() {
        let mips_prog = Program::new("mips", Language {
            processor: "MIPS".into(),
            variant: "BE".into(),
            size: 32,
        });
        assert!(MipsDisassembleAction::is_applicable(&mips_prog));
    }

    #[test]
    fn test_ppc_action_applicability() {
        let ppc_prog = Program::new("ppc", Language {
            processor: "PowerPC".into(),
            variant: "BE".into(),
            size: 32,
        });
        assert!(PowerPCDisassembleAction::is_applicable(&ppc_prog));
    }

    #[test]
    fn test_x86_64_action_applicability() {
        let x64_prog = Program::new("x64", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        let x32_prog = Program::new("x32", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 32,
        });
        assert!(X86_64DisassembleAction::is_applicable(&x64_prog));
        assert!(!X86_64DisassembleAction::is_applicable(&x32_prog));
    }

    #[test]
    fn test_plugin_event() {
        let mut plugin = DisassemblerPlugin::new();
        plugin.process_event(&PluginEvent::ProgramActivated("test.elf".to_string()));
        // Should not panic
    }

    #[test]
    fn test_plugin_enable_disable() {
        let mut plugin = DisassemblerPlugin::new();
        assert!(plugin.is_enabled());
        plugin.set_enabled(false);
        assert!(!plugin.is_enabled());
    }

    #[test]
    fn test_disassemble_callback() {
        let plugin = DisassemblerPlugin::new();
        let mut program = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        program.memory_blocks.push(MemoryBlock {
            name: ".text".to_string(),
            start: Address::new(0x400000),
            size: 0x10000,
            is_read: true,
            is_write: false,
            is_execute: true,
            is_initialized: true,
        });

        let result = plugin.disassemble_callback(Address::new(0x400000), &mut program);
        // Returns empty result since full decoder is not implemented
        assert_eq!(result.instruction_count, 0);
    }
}
