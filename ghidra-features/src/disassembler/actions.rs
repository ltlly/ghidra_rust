//! Disassembler actions -- ported from Ghidra's
//! `ghidra.app.plugin.core.disassembler` Java package.
//!
//! Action-level types for triggering disassembly from the UI:
//! [`DisassembleAction`] variants, [`DisassembleDialog`] options,
//! and [`FlowOverride`] for controlling instruction flow.

use ghidra_core::Address;

/// Disassembly action identifiers matching Ghidra action names.
///
/// Ported from `ghidra.app.plugin.core.disassembler.DisassembleActionPlugin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisassembleActionId {
    /// Disassemble at the current cursor position.
    Disassemble,
    /// Disassemble the selection using the chosen strategy.
    DisassembleSelection,
    /// Apply a flow override to an instruction.
    ApplyFlowOverride,
    /// Remove the flow override from an instruction.
    RemoveFlowOverride,
    /// Disassemble at an address typed in a dialog.
    DisassembleAtAddress,
    /// Remove disassembly from the current selection.
    RemoveDisassembly,
}

impl DisassembleActionId {
    /// Human-readable name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Disassemble => "Disassemble",
            Self::DisassembleSelection => "Disassemble Selection",
            Self::ApplyFlowOverride => "Apply Flow Override",
            Self::RemoveFlowOverride => "Remove Flow Override",
            Self::DisassembleAtAddress => "Disassemble at Address",
            Self::RemoveDisassembly => "Remove Disassembly",
        }
    }

    /// The menu group this action belongs to.
    pub fn menu_group(&self) -> &'static str {
        match self {
            Self::Disassemble | Self::DisassembleSelection | Self::DisassembleAtAddress => {
                "Disassemble"
            }
            Self::ApplyFlowOverride | Self::RemoveFlowOverride => "FlowOverride",
            Self::RemoveDisassembly => "Disassemble",
        }
    }
}

impl std::fmt::Display for DisassembleActionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

// ---------------------------------------------------------------------------
// FlowOverride
// ---------------------------------------------------------------------------

/// Override for the flow type of an instruction.
///
/// When an instruction's flow is overridden, the decompiler will use the
/// specified flow behavior instead of the one determined by analysis.
///
/// Ported from `ghidra.program.model.listing.FlowOverride`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowOverride {
    /// No override -- use the default analysis.
    None,
    /// Treat the instruction as a call (push return address and branch).
    Call,
    /// Treat the instruction as a call-return (call, but also auto-return).
    CallReturn,
    /// Treat the instruction as a jump (no return address pushed).
    Jump,
    /// Treat the instruction as a return.
    Return,
}

impl FlowOverride {
    /// Display name for the flow override.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::None => "Default",
            Self::Call => "Call Override",
            Self::CallReturn => "Call-Return Override",
            Self::Jump => "Jump Override",
            Self::Return => "Return Override",
        }
    }

    /// Whether this is an actual override (not None).
    pub fn is_override(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether this override causes a call.
    pub fn is_call(&self) -> bool {
        matches!(self, Self::Call | Self::CallReturn)
    }

    /// Whether this override causes a return.
    pub fn is_return(&self) -> bool {
        matches!(self, Self::Return | Self::CallReturn)
    }

    /// Whether this override causes a jump.
    pub fn is_jump(&self) -> bool {
        matches!(self, Self::Jump)
    }
}

impl Default for FlowOverride {
    fn default() -> Self {
        Self::None
    }
}

impl std::fmt::Display for FlowOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

// ---------------------------------------------------------------------------
// DisassembleDialog
// ---------------------------------------------------------------------------

/// Options collected from the "Disassemble at Address" dialog.
///
/// Ported from `ghidra.app.plugin.core.disassembler.DisassembleDialog`.
#[derive(Debug, Clone)]
pub struct DisassembleDialogOptions {
    /// The target address to disassemble.
    pub address: Address,
    /// Whether to follow flows from this address.
    pub follow_flows: bool,
    /// Whether to apply to the entire selection or just this address.
    pub apply_to_selection: bool,
    /// Maximum depth for recursive descent.
    pub max_depth: usize,
    /// Maximum number of instructions to disassemble.
    pub max_instructions: usize,
    /// The flow override to apply (if any).
    pub flow_override: FlowOverride,
    /// Whether to overwrite existing instructions.
    pub overwrite: bool,
}

impl DisassembleDialogOptions {
    /// Create default options for an address.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            follow_flows: true,
            apply_to_selection: false,
            max_depth: 1000,
            max_instructions: 100_000,
            flow_override: FlowOverride::None,
            overwrite: true,
        }
    }
}

// ---------------------------------------------------------------------------
// DisassemblyContext
// ---------------------------------------------------------------------------

/// Context information passed to the disassembler during operation.
///
/// Ported from `ghidra.app.plugin.core.disassembler.DisassemblerContext`.
#[derive(Debug, Clone)]
pub struct DisassemblyContext {
    /// Whether analysis is currently running.
    pub analysis_active: bool,
    /// The address set to restrict disassembly to.
    pub restrict_to: Vec<(u64, u64)>,
    /// Whether to disassemble into external programs.
    pub follow_externals: bool,
    /// Whether to disassemble through computed jumps.
    pub follow_computed_jumps: bool,
    /// Whether to clear existing code before disassembling.
    pub clear_before_disassemble: bool,
}

impl Default for DisassemblyContext {
    fn default() -> Self {
        Self {
            analysis_active: false,
            restrict_to: Vec::new(),
            follow_externals: false,
            follow_computed_jumps: true,
            clear_before_disassemble: false,
        }
    }
}

impl DisassemblyContext {
    /// Create a new disassembly context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if an address is within the restricted range.
    pub fn is_address_allowed(&self, address: u64) -> bool {
        if self.restrict_to.is_empty() {
            return true;
        }
        self.restrict_to
            .iter()
            .any(|&(start, end)| address >= start && address <= end)
    }
}

// ---------------------------------------------------------------------------
// AddressTableEntry
// ---------------------------------------------------------------------------

/// An entry in an address table found during disassembly.
///
/// Ported from `ghidra.app.plugin.core.disassembler.AddressTable`.
#[derive(Debug, Clone)]
pub struct AddressTableEntry {
    /// The base address of the address table.
    pub table_address: Address,
    /// The entries in the table (addresses pointed to).
    pub entries: Vec<Address>,
    /// Whether the table entries are relative (offsets) or absolute.
    pub is_relative: bool,
    /// The pointer size in bytes (e.g., 4 for 32-bit, 8 for 64-bit).
    pub pointer_size: u8,
}

impl AddressTableEntry {
    /// Create a new address table entry.
    pub fn new(table_address: Address, pointer_size: u8) -> Self {
        Self {
            table_address,
            entries: Vec::new(),
            is_relative: false,
            pointer_size,
        }
    }

    /// Number of entries in the table.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// The end address of the table (exclusive).
    pub fn end_address(&self) -> u64 {
        self.table_address.offset
            + (self.entries.len() as u64) * (self.pointer_size as u64)
    }

    /// Whether the table has entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add an entry to the table.
    pub fn add_entry(&mut self, address: Address) {
        self.entries.push(address);
    }

    /// Resolve a table entry to an absolute address.
    ///
    /// For relative tables, the entry is relative to the table base.
    /// For absolute tables, the entry is used as-is.
    pub fn resolve_entry(&self, index: usize) -> Option<Address> {
        self.entries.get(index).map(|entry| {
            if self.is_relative {
                Address::new(self.table_address.offset.wrapping_add(entry.offset))
            } else {
                *entry
            }
        })
    }
}

// ---------------------------------------------------------------------------
// CallFixup
// ---------------------------------------------------------------------------

/// A call fixup annotation attached to a function.
///
/// Ported from `ghidra.app.plugin.core.disassembler.CallFixupInfo`.
#[derive(Debug, Clone)]
pub struct CallFixup {
    /// The name of the call fixup.
    pub name: String,
    /// The p-code snippet to inline at call sites.
    pub pcode_snippet: String,
    /// Whether this is a callee fixup (applied at the callee) or caller fixup.
    pub is_callee_fixup: bool,
}

impl CallFixup {
    /// Create a new call fixup.
    pub fn new(name: impl Into<String>, pcode_snippet: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pcode_snippet: pcode_snippet.into(),
            is_callee_fixup: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------

/// An entry point for recursive descent disassembly.
///
/// Ported from `ghidra.app.plugin.core.disassembler.EntryPointInfo`.
#[derive(Debug, Clone)]
pub struct EntryPointInfo {
    /// The address of the entry point.
    pub address: Address,
    /// The source that identified this entry point (e.g., "Symbol", "ELF header").
    pub source: String,
    /// Priority of this entry point (lower = higher priority).
    pub priority: u32,
    /// Whether this entry point has already been processed.
    pub processed: bool,
}

impl EntryPointInfo {
    /// Create a new entry point.
    pub fn new(address: Address, source: impl Into<String>, priority: u32) -> Self {
        Self {
            address,
            source: source.into(),
            priority,
            processed: false,
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
    fn test_disassemble_action_id_display() {
        assert_eq!(
            DisassembleActionId::Disassemble.display_name(),
            "Disassemble"
        );
        assert_eq!(
            DisassembleActionId::DisassembleSelection.display_name(),
            "Disassemble Selection"
        );
    }

    #[test]
    fn test_flow_override_is_override() {
        assert!(!FlowOverride::None.is_override());
        assert!(FlowOverride::Call.is_override());
        assert!(FlowOverride::Jump.is_override());
        assert!(FlowOverride::Return.is_override());
    }

    #[test]
    fn test_flow_override_is_call() {
        assert!(FlowOverride::Call.is_call());
        assert!(FlowOverride::CallReturn.is_call());
        assert!(!FlowOverride::Jump.is_call());
        assert!(!FlowOverride::Return.is_call());
    }

    #[test]
    fn test_flow_override_is_return() {
        assert!(FlowOverride::Return.is_return());
        assert!(FlowOverride::CallReturn.is_return());
        assert!(!FlowOverride::Call.is_return());
        assert!(!FlowOverride::Jump.is_return());
    }

    #[test]
    fn test_flow_override_display() {
        assert_eq!(FlowOverride::None.display_name(), "Default");
        assert_eq!(FlowOverride::CallReturn.display_name(), "Call-Return Override");
    }

    #[test]
    fn test_flow_override_default() {
        assert_eq!(FlowOverride::default(), FlowOverride::None);
    }

    #[test]
    fn test_disassemble_dialog_options() {
        let opts = DisassembleDialogOptions::new(Address::new(0x1000));
        assert_eq!(opts.address, Address::new(0x1000));
        assert!(opts.follow_flows);
        assert!(!opts.apply_to_selection);
        assert_eq!(opts.max_depth, 1000);
        assert_eq!(opts.max_instructions, 100_000);
        assert_eq!(opts.flow_override, FlowOverride::None);
        assert!(opts.overwrite);
    }

    #[test]
    fn test_disassembly_context_default() {
        let ctx = DisassemblyContext::default();
        assert!(!ctx.analysis_active);
        assert!(ctx.is_address_allowed(0x1000)); // no restriction = all allowed
        assert!(!ctx.follow_externals);
        assert!(ctx.follow_computed_jumps);
        assert!(!ctx.clear_before_disassemble);
    }

    #[test]
    fn test_disassembly_context_restricted() {
        let mut ctx = DisassemblyContext::new();
        ctx.restrict_to = vec![(0x1000, 0x2000)];
        assert!(ctx.is_address_allowed(0x1500));
        assert!(!ctx.is_address_allowed(0x3000));
    }

    #[test]
    fn test_address_table_entry() {
        let mut table = AddressTableEntry::new(Address::new(0x4000), 4);
        assert_eq!(table.entry_count(), 0);
        assert!(table.is_empty());

        table.add_entry(Address::new(0x1000));
        table.add_entry(Address::new(0x2000));
        assert_eq!(table.entry_count(), 2);
        assert_eq!(table.end_address(), 0x4008);
    }

    #[test]
    fn test_address_table_entry_resolve_absolute() {
        let mut table = AddressTableEntry::new(Address::new(0x4000), 4);
        table.add_entry(Address::new(0x8000));
        assert_eq!(table.resolve_entry(0), Some(Address::new(0x8000)));
    }

    #[test]
    fn test_address_table_entry_resolve_relative() {
        let mut table = AddressTableEntry::new(Address::new(0x4000), 4);
        table.is_relative = true;
        table.add_entry(Address::new(0x100));
        assert_eq!(table.resolve_entry(0), Some(Address::new(0x4100)));
    }

    #[test]
    fn test_address_table_entry_resolve_out_of_bounds() {
        let table = AddressTableEntry::new(Address::new(0x4000), 4);
        assert_eq!(table.resolve_entry(0), None);
    }

    #[test]
    fn test_call_fixup() {
        let fixup = CallFixup::new("memcpy", "pcode...");
        assert_eq!(fixup.name, "memcpy");
        assert!(fixup.is_callee_fixup);
    }

    #[test]
    fn test_entry_point_info() {
        let ep = EntryPointInfo::new(Address::new(0x400000), "ELF header", 10);
        assert_eq!(ep.address, Address::new(0x400000));
        assert_eq!(ep.source, "ELF header");
        assert_eq!(ep.priority, 10);
        assert!(!ep.processed);
    }
}
