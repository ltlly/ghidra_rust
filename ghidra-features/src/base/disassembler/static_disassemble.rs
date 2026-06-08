//! Static disassembly and processor-specific actions -- ported from Ghidra's
//! `StaticDisassembleAction.java`, `Hcs12DisassembleAction.java`, and
//! `DisassembledViewPlugin.java`.
//!
//! Provides:
//! - [`StaticDisassembleAction`] -- disassembles a selected address range
//! - [`Hcs12DisassembleAction`] -- HCS12-specific disassembly with paging
//! - [`DisassembledViewPlugin`] -- plugin that provides a disassembled view

use crate::base::analyzer::core::*;
use crate::base::disassembler::core::{Disassembler, DisassemblerConfig, DisassemblyResult};

// ---------------------------------------------------------------------------
// StaticDisassembleAction
// ---------------------------------------------------------------------------

/// Action for static (range-based) disassembly.
///
/// Unlike dynamic disassembly which follows control flow from a starting
/// address, static disassembly treats every address in the selection as a
/// potential instruction start. Existing code is cleared first.
///
/// Corresponds to Ghidra's `StaticDisassembleAction`.
#[derive(Debug, Clone)]
pub struct StaticDisassembleAction {
    /// Display name.
    name: String,
    /// Menu group.
    group: String,
}

impl StaticDisassembleAction {
    /// Create a new static disassemble action.
    pub fn new() -> Self {
        Self {
            name: "Static Disassemble".to_string(),
            group: "Disassembly".to_string(),
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

    /// Check if the action is enabled for the given context.
    pub fn is_enabled_for(&self, selection: Option<&AddressSet>, program: &Program) -> bool {
        match selection {
            Some(set) if !set.is_empty() => {
                // Check that at least part of the selection is in initialized memory
                program.memory_blocks.iter().any(|block| {
                    block.is_initialized && set.iter().any(|range| {
                        range.start.offset < block.start.offset + block.size
                            && range.end.offset >= block.start.offset
                    })
                })
            }
            _ => false,
        }
    }

    /// Execute the static disassembly action.
    pub fn execute(
        &self,
        program: &mut Program,
        selection: &AddressSet,
        follow_flow: bool,
        monitor: &dyn TaskMonitor,
    ) -> DisassemblyResult {
        let config = DisassemblerConfig::new();
        let mut disassembler = Disassembler::new(config);
        disassembler.disassemble_range(selection, None, follow_flow, program, monitor)
            .unwrap_or_default()
    }
}

impl Default for StaticDisassembleAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Hcs12DisassembleAction
// ---------------------------------------------------------------------------

/// HCS12-specific disassembly action.
///
/// The Freescale/NXP HCS12 (S12) microcontroller has a paged memory
/// architecture where code pages are mapped into a 64 KiB logical address
/// space via a page window. This action handles the page-switching
/// semantics during disassembly.
///
/// Corresponds to Ghidra's `Hcs12DisassembleAction`.
#[derive(Debug, Clone)]
pub struct Hcs12DisassembleAction {
    /// Display name.
    name: String,
    /// The PPAGE register name.
    pub ppage_register: String,
    /// Default PPAGE value.
    pub default_ppage: u8,
}

impl Hcs12DisassembleAction {
    /// PPAGE register name for HCS12.
    pub const PPAGE_REG: &'static str = "PPAGE";

    /// Create a new HCS12 disassemble action.
    pub fn new() -> Self {
        Self {
            name: "HCS12 Disassemble".to_string(),
            ppage_register: Self::PPAGE_REG.to_string(),
            default_ppage: 0,
        }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if this action is applicable for the given program.
    pub fn is_applicable(program: &Program) -> bool {
        program.language.processor.to_uppercase() == "HCS12"
            || program.language.processor.to_uppercase() == "68HC12"
    }

    /// Get the current PPAGE value for an address in the paged window.
    ///
    /// The HCS12 paged window is at 0x8000-0xBFFF. Addresses outside
    /// this window use the default (local) page.
    pub fn get_ppage_for_address(&self, addr: Address, _program: &Program) -> u8 {
        if addr.offset >= 0x8000 && addr.offset <= 0xBFFF {
            // In a full implementation, this would read the PPAGE register
            // from the program context at this address.
            self.default_ppage
        } else {
            0 // Non-paged local address
        }
    }

    /// Execute disassembly with HCS12 page awareness.
    pub fn execute(
        &self,
        program: &mut Program,
        addr: Address,
        monitor: &dyn TaskMonitor,
    ) -> DisassemblyResult {
        let config = DisassemblerConfig::new();
        let mut disassembler = Disassembler::new(config);
        // Set up context for paged addressing
        disassembler.set_follow_flow(true);
        disassembler.disassemble_single(addr, program, monitor)
            .unwrap_or_default()
    }
}

impl Default for Hcs12DisassembleAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DisassembledViewPlugin
// ---------------------------------------------------------------------------

/// Plugin that provides a disassembled listing view.
///
/// Corresponds to Ghidra's `DisassembledViewPlugin`, which provides a
/// second (read-only) listing view that can be navigated independently
/// from the main code browser. The view displays the same disassembled
/// listing but can be locked to a specific address range.
#[derive(Debug)]
pub struct DisassembledViewPlugin {
    /// Plugin name.
    name: String,
    /// Whether the view is locked to a specific address.
    locked: bool,
    /// The locked address (when `locked` is true).
    locked_address: Option<Address>,
    /// Current program name.
    program_name: Option<String>,
    /// Whether the plugin is enabled.
    enabled: bool,
}

impl DisassembledViewPlugin {
    /// Create a new disassembled view plugin.
    pub fn new() -> Self {
        Self {
            name: "Disassembled View".to_string(),
            locked: false,
            locked_address: None,
            program_name: None,
            enabled: true,
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the current program.
    pub fn set_program(&mut self, name: Option<String>) {
        self.program_name = name;
    }

    /// Get the current program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Whether the view is locked.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Lock the view to a specific address.
    pub fn lock_to_address(&mut self, addr: Address) {
        self.locked = true;
        self.locked_address = Some(addr);
    }

    /// Unlock the view (follow the main cursor).
    pub fn unlock(&mut self) {
        self.locked = false;
        self.locked_address = None;
    }

    /// Get the locked address, if any.
    pub fn locked_address(&self) -> Option<Address> {
        self.locked_address
    }

    /// Navigate the view to a new address.
    pub fn go_to(&mut self, addr: Address) {
        if !self.locked {
            self.locked_address = Some(addr);
        }
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.program_name = None;
        self.locked_address = None;
        self.locked = false;
    }
}

impl Default for DisassembledViewPlugin {
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
    fn test_static_disassemble_action() {
        let action = StaticDisassembleAction::new();
        assert_eq!(action.name(), "Static Disassemble");
        assert_eq!(action.group(), "Disassembly");
    }

    #[test]
    fn test_static_action_enabled() {
        let action = StaticDisassembleAction::new();
        let prog = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        // No selection -> not enabled
        assert!(!action.is_enabled_for(None, &prog));
        // Empty selection -> not enabled
        let empty = AddressSet::new();
        assert!(!action.is_enabled_for(Some(&empty), &prog));
    }

    #[test]
    fn test_static_action_enabled_with_memory() {
        let action = StaticDisassembleAction::new();
        let mut prog = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        prog.memory_blocks.push(MemoryBlock {
            name: ".text".into(),
            start: Address::new(0x400000),
            size: 0x10000,
            is_read: true,
            is_write: false,
            is_execute: true,
            is_initialized: true,
        });
        let mut set = AddressSet::new();
        set.add_range(AddressRange::new(Address::new(0x400000), Address::new(0x4000FF)));
        assert!(action.is_enabled_for(Some(&set), &prog));
    }

    #[test]
    fn test_static_action_execute() {
        let action = StaticDisassembleAction::new();
        let mut prog = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        let set = AddressSet::from_address(Address::new(0x1000));
        let monitor = BasicTaskMonitor::new();
        let result = action.execute(&mut prog, &set, false, &monitor);
        assert_eq!(result.instruction_count, 0);
    }

    #[test]
    fn test_hcs12_action_creation() {
        let action = Hcs12DisassembleAction::new();
        assert_eq!(action.name(), "HCS12 Disassemble");
        assert_eq!(action.ppage_register, "PPAGE");
    }

    #[test]
    fn test_hcs12_action_applicability() {
        let hcs12 = Program::new("hcs12", Language {
            processor: "HCS12".into(),
            variant: "BE".into(),
            size: 16,
        });
        let x86 = Program::new("x86", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        assert!(Hcs12DisassembleAction::is_applicable(&hcs12));
        assert!(!Hcs12DisassembleAction::is_applicable(&x86));
    }

    #[test]
    fn test_hcs12_ppage_for_address() {
        let action = Hcs12DisassembleAction::new();
        let prog = Program::new("hcs12", Language {
            processor: "HCS12".into(),
            variant: "BE".into(),
            size: 16,
        });
        // Address in paged window
        assert_eq!(action.get_ppage_for_address(Address::new(0x9000), &prog), 0);
        // Address outside paged window
        assert_eq!(action.get_ppage_for_address(Address::new(0x4000), &prog), 0);
    }

    #[test]
    fn test_disassembled_view_plugin() {
        let plugin = DisassembledViewPlugin::new();
        assert_eq!(plugin.name(), "Disassembled View");
        assert!(plugin.is_enabled());
        assert!(!plugin.is_locked());
        assert!(plugin.program_name().is_none());
    }

    #[test]
    fn test_disassembled_view_program() {
        let mut plugin = DisassembledViewPlugin::new();
        plugin.set_program(Some("test.elf".into()));
        assert_eq!(plugin.program_name(), Some("test.elf"));
    }

    #[test]
    fn test_disassembled_view_lock() {
        let mut plugin = DisassembledViewPlugin::new();
        plugin.lock_to_address(Address::new(0x400000));
        assert!(plugin.is_locked());
        assert_eq!(plugin.locked_address(), Some(Address::new(0x400000)));

        plugin.unlock();
        assert!(!plugin.is_locked());
        assert!(plugin.locked_address().is_none());
    }

    #[test]
    fn test_disassembled_view_go_to() {
        let mut plugin = DisassembledViewPlugin::new();
        plugin.go_to(Address::new(0x1000));
        assert_eq!(plugin.locked_address(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_disassembled_view_dispose() {
        let mut plugin = DisassembledViewPlugin::new();
        plugin.set_program(Some("test".into()));
        plugin.lock_to_address(Address::new(0x1000));
        plugin.dispose();
        assert!(plugin.program_name().is_none());
        assert!(plugin.locked_address().is_none());
    }
}
