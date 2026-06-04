//! Clear plugin -- manages clear operations and provides the user-facing API.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.clear.ClearPlugin`.
//!
//! The `ClearPlugin` is the entry point for all clear operations. It
//! provides methods to:
//!
//! - Clear code bytes at the current location (key binding: C)
//! - Show the "Clear With Options" dialog
//! - Show the "Clear Flow and Repair" dialog
//! - Clear internal parts of a data structure

use super::cmd::ClearCmd;
use super::flow_cmd::ClearFlowAndRepairCmd;
use super::options::{ClearOptions, ClearType};
use ghidra_core::addr::{Address, AddressSet};
use serde::{Deserialize, Serialize};

/// The menu group name for clear actions.
pub const CLEAR_MENU: &str = "Clear";

/// Display name for "Clear With Options" action.
pub const CLEAR_WITH_OPTIONS_NAME: &str = "Clear With Options";

/// Display name for "Clear Code Bytes" action.
pub const CLEAR_CODE_BYTES_NAME: &str = "Clear Code Bytes";

/// Display name for "Clear Flow and Repair" action.
pub const CLEAR_FLOW_AND_REPAIR: &str = "Clear Flow and Repair";

/// Represents a selection state at the time of a clear operation.
///
/// This mirrors the relevant parts of Ghidra's `ProgramSelection` and
/// `ProgramLocation` that are used to determine what to clear.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearContext {
    /// The address at the cursor location.
    pub address: Option<Address>,
    /// The selected address range (if any).
    pub selection: Option<AddressSet>,
    /// Whether the selection is an interior (data structure) selection.
    pub is_interior_selection: bool,
    /// Component path for data structure selections.
    pub component_path: Vec<i32>,
}

impl ClearContext {
    /// Creates a context from a cursor address (no selection).
    pub fn from_cursor(address: Address) -> Self {
        Self {
            address: Some(address),
            selection: None,
            is_interior_selection: false,
            component_path: Vec::new(),
        }
    }

    /// Creates a context from a selection.
    pub fn from_selection(selection: AddressSet) -> Self {
        Self {
            address: None,
            selection: Some(selection),
            is_interior_selection: false,
            component_path: Vec::new(),
        }
    }

    /// Creates a context for an interior (structure) selection.
    pub fn interior(address: Address, component_path: Vec<i32>) -> Self {
        Self {
            address: Some(address),
            selection: None,
            is_interior_selection: true,
            component_path,
        }
    }

    /// Returns `true` if this context has a selection.
    pub fn has_selection(&self) -> bool {
        self.selection.as_ref().map_or(false, |s| !s.is_empty())
    }

    /// Returns the address set to use for the clear operation.
    ///
    /// If there is a selection, returns it. Otherwise, returns a singleton
    /// set containing the cursor address.
    pub fn get_address_set(&self) -> AddressSet {
        if let Some(ref sel) = self.selection {
            if !sel.is_empty() {
                return sel.clone();
            }
        }
        if let Some(addr) = self.address {
            AddressSet::from_range(addr, addr)
        } else {
            AddressSet::new()
        }
    }
}

/// The clear plugin, managing all clear-related actions.
///
/// This corresponds to Ghidra's `ClearPlugin`. In this Rust port it
/// serves as the controller that dispatches clear commands based on
/// the current context and selected options.
///
/// # Architecture
///
/// The plugin holds no mutable state itself. Each clear operation
/// creates and returns a command object that the caller is responsible
/// for executing. This avoids shared mutable state and allows the
/// caller to integrate the commands into their own execution framework.
#[derive(Debug, Clone, Default)]
pub struct ClearPlugin;

impl ClearPlugin {
    /// Creates a new clear plugin.
    pub fn new() -> Self {
        Self
    }

    /// Creates a "Clear Code Bytes" command for the given context.
    ///
    /// This clears instructions, data, and all reference types over the
    /// selected address range (or the code unit at the cursor).
    ///
    /// Returns `None` if the context has no valid address.
    pub fn clear_code_bytes(&self, ctx: &ClearContext) -> Option<ClearCmd> {
        let mut options = ClearOptions::new(false);
        options.set_should_clear(ClearType::Instructions, true);
        options.set_should_clear(ClearType::Data, true);
        options.set_should_clear(ClearType::UserReferences, true);
        options.set_should_clear(ClearType::AnalysisReferences, true);
        options.set_should_clear(ClearType::ImportReferences, true);
        options.set_should_clear(ClearType::DefaultReferences, true);

        if ctx.has_selection() {
            Some(ClearCmd::new(ctx.get_address_set(), options))
        } else if let Some(addr) = ctx.address {
            Some(ClearCmd::for_code_unit(addr, addr, options))
        } else {
            None
        }
    }

    /// Creates a "Clear With Options" command for the given context.
    ///
    /// If no clear types are selected in the options, returns `None`.
    /// For interior (data structure) selections, returns `None` since
    /// structure clearing is handled separately.
    pub fn clear_with_options(
        &self,
        options: &ClearOptions,
        ctx: &ClearContext,
    ) -> Option<ClearCmd> {
        if !options.clear_any() {
            return None;
        }

        // Interior selection is handled by clear_structure
        if ctx.is_interior_selection {
            return None;
        }

        let addrs = ctx.get_address_set();
        Some(ClearCmd::new(addrs, options.clone()))
    }

    /// Creates a "Clear Flow and Repair" command for the given context.
    pub fn clear_flow_and_repair(
        &self,
        ctx: &ClearContext,
        clear_labels: bool,
        clear_data: bool,
        repair: bool,
    ) -> ClearFlowAndRepairCmd {
        if let Some(ref sel) = ctx.selection {
            if !sel.is_empty() {
                return ClearFlowAndRepairCmd::new(
                    sel.clone(),
                    None,
                    clear_data,
                    clear_labels,
                    repair,
                );
            }
        }

        ClearFlowAndRepairCmd::from_address(
            ctx.address.unwrap_or(Address::new(0)),
            clear_data,
            clear_labels,
            repair,
        )
    }

    /// Returns `true` if the "Clear Code Bytes" action should be enabled.
    ///
    /// Mirrors `ClearPlugin.isClearCodeBytesEnabled`:
    /// - Must have a non-empty selection, OR
    /// - Must be on a code unit location
    pub fn is_clear_code_bytes_enabled(&self, ctx: &ClearContext) -> bool {
        if ctx.has_selection() {
            return true;
        }
        ctx.address.is_some()
    }

    /// Describes what "clear structure" would do for the given context.
    ///
    /// When the user clears inside a data structure (composite type),
    /// Ghidra clears the component rather than the address range. This
    /// method returns a description of the operation.
    ///
    /// Returns `None` if the context is not a structure selection.
    pub fn describe_clear_structure(&self, ctx: &ClearContext) -> Option<StructureClearInfo> {
        if !ctx.is_interior_selection || ctx.component_path.is_empty() {
            return None;
        }
        let start_index = *ctx.component_path.last()?;
        Some(StructureClearInfo {
            address: ctx.address?,
            component_path: ctx.component_path.clone(),
            start_component_index: start_index,
            end_component_index: start_index,
        })
    }
}

/// Information about a structure component clear operation.
///
/// When the user selects components inside a data structure, Ghidra
/// clears those components rather than the raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructureClearInfo {
    /// The address of the containing data structure.
    pub address: Address,
    /// The full component path to the selection.
    pub component_path: Vec<i32>,
    /// The first component index to clear.
    pub start_component_index: i32,
    /// The last component index to clear.
    pub end_component_index: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clear_code_bytes_with_selection() {
        let plugin = ClearPlugin::new();
        let mut sel = AddressSet::new();
        sel.add_range(Address::new(0x1000), Address::new(0x1100));
        let ctx = ClearContext::from_selection(sel);

        let cmd = plugin.clear_code_bytes(&ctx).unwrap();
        assert_eq!(cmd.view().num_addresses(), 0x101);
        assert!(cmd.options().should_clear(ClearType::Instructions));
        assert!(cmd.options().should_clear(ClearType::Data));
    }

    #[test]
    fn test_clear_code_bytes_at_cursor() {
        let plugin = ClearPlugin::new();
        let ctx = ClearContext::from_cursor(Address::new(0x1000));

        let cmd = plugin.clear_code_bytes(&ctx).unwrap();
        assert_eq!(cmd.view().num_addresses(), 1);
    }

    #[test]
    fn test_clear_code_bytes_no_address() {
        let plugin = ClearPlugin::new();
        let ctx = ClearContext {
            address: None,
            selection: None,
            is_interior_selection: false,
            component_path: Vec::new(),
        };
        assert!(plugin.clear_code_bytes(&ctx).is_none());
    }

    #[test]
    fn test_clear_with_options_empty() {
        let plugin = ClearPlugin::new();
        let opts = ClearOptions::new(false);
        let ctx = ClearContext::from_cursor(Address::new(0x1000));

        // No types enabled -> returns None
        assert!(plugin.clear_with_options(&opts, &ctx).is_none());
    }

    #[test]
    fn test_clear_with_options_interior() {
        let plugin = ClearPlugin::new();
        let opts = ClearOptions::all();
        let ctx = ClearContext::interior(Address::new(0x1000), vec![0, 1]);

        // Interior selection -> returns None (handled by clear_structure)
        assert!(plugin.clear_with_options(&opts, &ctx).is_none());
    }

    #[test]
    fn test_clear_with_options_normal() {
        let plugin = ClearPlugin::new();
        let mut opts = ClearOptions::new(false);
        opts.set_should_clear(ClearType::Symbols, true);
        let ctx = ClearContext::from_cursor(Address::new(0x1000));

        let cmd = plugin.clear_with_options(&opts, &ctx).unwrap();
        assert!(cmd.options().should_clear(ClearType::Symbols));
    }

    #[test]
    fn test_clear_flow_and_repair_with_selection() {
        let plugin = ClearPlugin::new();
        let mut sel = AddressSet::new();
        sel.add_range(Address::new(0x401000), Address::new(0x401FFF));
        let ctx = ClearContext::from_selection(sel);

        let cmd = plugin.clear_flow_and_repair(&ctx, true, false, true);
        assert!(cmd.start_addrs().contains(&Address::new(0x401000)));
        assert!(cmd.clears_labels());
        assert!(!cmd.clears_data());
        assert!(cmd.repairs());
    }

    #[test]
    fn test_clear_flow_and_repair_at_cursor() {
        let plugin = ClearPlugin::new();
        let ctx = ClearContext::from_cursor(Address::new(0x401000));

        let cmd = plugin.clear_flow_and_repair(&ctx, false, true, false);
        assert!(cmd.start_addrs().contains(&Address::new(0x401000)));
        assert!(!cmd.clears_labels());
        assert!(cmd.clears_data());
    }

    #[test]
    fn test_is_clear_code_bytes_enabled() {
        let plugin = ClearPlugin::new();

        // With selection
        let mut sel = AddressSet::new();
        sel.add_range(Address::new(0x1000), Address::new(0x1100));
        let ctx = ClearContext::from_selection(sel);
        assert!(plugin.is_clear_code_bytes_enabled(&ctx));

        // At cursor
        let ctx = ClearContext::from_cursor(Address::new(0x1000));
        assert!(plugin.is_clear_code_bytes_enabled(&ctx));

        // No address
        let ctx = ClearContext {
            address: None,
            selection: None,
            is_interior_selection: false,
            component_path: Vec::new(),
        };
        assert!(!plugin.is_clear_code_bytes_enabled(&ctx));
    }

    #[test]
    fn test_describe_clear_structure() {
        let plugin = ClearPlugin::new();
        let ctx = ClearContext::interior(Address::new(0x1000), vec![0, 2, 3]);

        let info = plugin.describe_clear_structure(&ctx).unwrap();
        assert_eq!(info.address, Address::new(0x1000));
        assert_eq!(info.component_path, vec![0, 2, 3]);
        assert_eq!(info.start_component_index, 3);
        assert_eq!(info.end_component_index, 3);
    }

    #[test]
    fn test_describe_clear_structure_no_interior() {
        let plugin = ClearPlugin::new();
        let ctx = ClearContext::from_cursor(Address::new(0x1000));
        assert!(plugin.describe_clear_structure(&ctx).is_none());
    }

    #[test]
    fn test_clear_context_has_selection() {
        let ctx = ClearContext::from_cursor(Address::new(0x1000));
        assert!(!ctx.has_selection());

        let mut sel = AddressSet::new();
        sel.add_range(Address::new(0x1000), Address::new(0x1100));
        let ctx = ClearContext::from_selection(sel);
        assert!(ctx.has_selection());
    }

    #[test]
    fn test_clear_context_get_address_set() {
        let ctx = ClearContext::from_cursor(Address::new(0x1000));
        let addrs = ctx.get_address_set();
        assert_eq!(addrs.num_addresses(), 1);
        assert!(addrs.contains(&Address::new(0x1000)));
    }

    #[test]
    fn test_menu_constants() {
        assert_eq!(CLEAR_MENU, "Clear");
        assert_eq!(CLEAR_WITH_OPTIONS_NAME, "Clear With Options");
        assert_eq!(CLEAR_CODE_BYTES_NAME, "Clear Code Bytes");
        assert_eq!(CLEAR_FLOW_AND_REPAIR, "Clear Flow and Repair");
    }
}
