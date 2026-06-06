//! Register management subsystem.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.register` Java package.
//!
//! This module provides:
//! - [`RegisterManager`] — manages register value display, selection, and modification
//! - [`RegisterValueRange`] — represents a range of addresses with a specific register value
//! - [`RegisterTree`] — hierarchical tree of registers organized by group
//! - [`RegisterValuesPanel`] — panel for displaying and editing register value ranges
//! - [`RegisterValueDialogModel`] — validation model for the register value dialog
//! - [`SetRegisterValueCmd`] — command to set or clear register values over an address range

mod commands;
mod dialog;
mod manager;
pub mod plugin;
mod tree;
mod value_range;
mod values_panel;

pub use commands::{RegisterCommand, SetRegisterValueCmd};
pub use dialog::{RegisterDialogError, RegisterDialogMode, RegisterValueDialogModel};
pub use manager::RegisterManager;
pub use plugin::{
    RegisterActionType, RegisterManagerContext, RegisterPluginAction, RegisterPluginModel,
    RegisterTransitionInfo,
};
pub use tree::{RegisterGroupNode, RegisterNode, RegisterTree};
pub use value_range::RegisterValueRange;
pub use values_panel::{RegisterValuesPanel, SortDirection};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use ghidra_core::addr::Address;

    #[test]
    fn test_register_value_range_basics() {
        let range = RegisterValueRange::new(
            Address::new(0x1000),
            Address::new(0x2000),
            0xFF,
            false,
        );
        assert_eq!(range.start_address(), Address::new(0x1000));
        assert_eq!(range.end_address(), Address::new(0x2000));
        assert_eq!(range.value(), 0xFF);
        assert!(!range.is_default());
        assert!(range.contains(&Address::new(0x1500)));
        assert!(!range.contains(&Address::new(0x3000)));
        assert_eq!(range.size(), 0x1001);
    }

    #[test]
    fn test_register_value_range_default() {
        let range = RegisterValueRange::default_range(
            Address::new(0x0),
            Address::new(0xFFFF),
            0,
        );
        assert!(range.is_default());
        assert_eq!(range.value(), 0);
    }

    #[test]
    fn test_register_value_range_adjacency() {
        let r1 = RegisterValueRange::from_range(Address::new(0x1000), Address::new(0x1FFF), 0xAA);
        let r2 = RegisterValueRange::from_range(Address::new(0x2000), Address::new(0x2FFF), 0xAA);
        let r3 = RegisterValueRange::from_range(Address::new(0x3000), Address::new(0x3FFF), 0xBB);

        assert!(r1.is_adjacent_to(&r2));
        assert!(!r1.is_adjacent_to(&r3));
        assert!(r1.can_merge_with(&r2)); // same value
        assert!(!r1.can_merge_with(&r3)); // different value
    }

    #[test]
    fn test_register_value_range_merge() {
        let mut ranges = vec![
            RegisterValueRange::from_range(Address::new(0x1000), Address::new(0x1FFF), 0xAA),
            RegisterValueRange::from_range(Address::new(0x2000), Address::new(0x2FFF), 0xAA),
            RegisterValueRange::from_range(Address::new(0x4000), Address::new(0x4FFF), 0xBB),
        ];
        value_range::merge_adjacent_ranges(&mut ranges);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start_address(), Address::new(0x1000));
        assert_eq!(ranges[0].end_address(), Address::new(0x2FFF));
        assert_eq!(ranges[1].start_address(), Address::new(0x4000));
    }

    #[test]
    fn test_register_plugin_model_integration() {
        let mut model = plugin::RegisterPluginModel::new();
        assert!(model.registers().is_empty());

        model.set_registers(vec![
            "RAX".to_string(),
            "RBX".to_string(),
            "RCX".to_string(),
        ]);
        assert_eq!(model.registers().len(), 3);

        // Toggle provider visibility
        assert!(!model.is_provider_visible());
        model.show_provider();
        assert!(model.is_provider_visible());
        model.toggle_provider();
        assert!(!model.is_provider_visible());
    }

    #[test]
    fn test_register_plugin_actions_integration() {
        let model = plugin::RegisterPluginModel::new();

        // All actions should be enabled by default
        assert!(model.set_register_action.enabled);
        assert!(model.delete_range_action.enabled);
        assert!(model.delete_at_function_action.enabled);
        assert!(model.clear_register_action.enabled);

        // Key bindings should be correct for set register action
        let kb = model.set_register_action.key_binding.as_ref().unwrap();
        assert_eq!(kb.key_code, 0x52); // VK_R
    }

    #[test]
    fn test_register_plugin_action_context_types() {
        use crate::base::function::actions::ActionContext;

        let set_action = plugin::RegisterPluginAction::new(plugin::RegisterActionType::SetRegisterValues);

        // Enabled at any listing address
        let ctx = ActionContext::listing_at(Address::new(0x401000));
        assert!(set_action.is_enabled_for_context(&ctx));

        // Disabled for symbol context
        let ctx = ActionContext::Symbol(crate::base::function::actions::SymbolContext {
            symbols: vec![],
        });
        assert!(!set_action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_register_transition_info_delta() {
        let info = plugin::RegisterTransitionInfo::with_old_value(
            0x401000, "RIP", 0x1000, 0x1010, 8,
        );
        assert_eq!(info.delta(), Some(0x10));

        let info_no_old = plugin::RegisterTransitionInfo::new(0x401000, "RIP", 0x1010, 8);
        assert!(info_no_old.delta().is_none());
    }

    #[test]
    fn test_register_dialog_model_set_mode() {
        let mut model = dialog::RegisterValueDialogModel::new(
            dialog::RegisterDialogMode::SetValue,
        );
        assert_eq!(model.mode(), dialog::RegisterDialogMode::SetValue);
        assert!(model.register().is_none());

        // Set value
        model.set_value(0xFF);
        assert_eq!(model.value(), Some(0xFF));
    }

    #[test]
    fn test_register_dialog_model_clear_mode() {
        let model = dialog::RegisterValueDialogModel::new(
            dialog::RegisterDialogMode::ClearValue,
        );
        assert_eq!(model.mode(), dialog::RegisterDialogMode::ClearValue);
    }

    #[test]
    fn test_register_dialog_model_summary() {
        let model = dialog::RegisterValueDialogModel::new(
            dialog::RegisterDialogMode::SetValue,
        );
        let summary = model.summary();
        assert!(!summary.is_empty());
    }

    #[test]
    fn test_register_command_set_value() {
        let cmd = commands::SetRegisterValueCmd::new(
            "RAX",
            Address::new(0x1000),
            Address::new(0x2000),
            Some(0xFF),
        );
        let display = format!("{}", cmd);
        assert!(display.contains("RAX"));
        assert!(display.contains("0x1000"));
        assert_eq!(cmd.register_name(), "RAX");
        assert_eq!(cmd.start(), Address::new(0x1000));
        assert_eq!(cmd.end(), Address::new(0x2000));
        assert_eq!(cmd.value(), Some(0xFF));
    }

    #[test]
    fn test_register_command_clear_value() {
        let cmd = commands::SetRegisterValueCmd::clear(
            "RAX",
            Address::new(0x1000),
            Address::new(0x2000),
        );
        let display = format!("{}", cmd);
        assert!(display.contains("RAX"));
        assert!(cmd.value().is_none());
    }

    #[test]
    fn test_compound_register_command() {
        let mut compound = commands::CompoundRegisterCmd::new("Batch Set");
        compound.add(commands::SetRegisterValueCmd::new(
            "RAX", Address::new(0x1000), Address::new(0x2000), Some(0x42),
        ));
        compound.add(commands::SetRegisterValueCmd::new(
            "RBX", Address::new(0x1000), Address::new(0x2000), Some(0x43),
        ));
        assert_eq!(compound.len(), 2);
        assert!(!compound.is_empty());
        assert_eq!(compound.commands().len(), 2);
    }

    #[test]
    fn test_register_manager_lifecycle() {
        let mut mgr = RegisterManager::new();
        assert!(mgr.selected_register().is_none());
        assert!(mgr.value_ranges().is_empty());

        mgr.select_register("RAX");
        assert_eq!(mgr.selected_register(), Some("RAX"));

        // Set location
        mgr.set_location(Some("RAX"), Address::new(0x1000));

        // Include default values
        assert!(!mgr.include_default_values());
    }

    #[test]
    fn test_register_manager_showing() {
        let mut mgr = RegisterManager::new();
        mgr.set_is_showing(true);
        mgr.set_is_showing(false);
    }

    #[test]
    fn test_register_tree_empty() {
        let tree = RegisterTree::new(&[]);
        assert!(tree.groups().is_empty());
        assert!(tree.ungrouped().is_empty());
        assert!(tree.all_registers().is_empty());
        assert!(!tree.is_filtered());
    }

    #[test]
    fn test_register_tree_with_registers() {
        let regs = vec![
            ghidra_core::program::lang::Register::new("RAX", 64, "register", 0),
            ghidra_core::program::lang::Register::new("RBX", 64, "register", 8),
            ghidra_core::program::lang::Register::new("RCX", 64, "register", 16),
        ];
        let tree = RegisterTree::new(&regs);
        assert_eq!(tree.all_registers().len(), 3);

        // Find by name
        assert!(tree.find_register("RAX").is_some());
        assert!(tree.find_register("NOPE").is_none());

        // Find node
        assert!(tree.find_node("RAX").is_some());
    }

    #[test]
    fn test_register_tree_update() {
        let regs1 = vec![
            ghidra_core::program::lang::Register::new("RAX", 64, "register", 0),
        ];
        let mut tree = RegisterTree::new(&regs1);
        assert_eq!(tree.all_registers().len(), 1);

        let regs2 = vec![
            ghidra_core::program::lang::Register::new("RAX", 64, "register", 0),
            ghidra_core::program::lang::Register::new("RBX", 64, "register", 8),
        ];
        tree.update_registers(&regs2);
        assert_eq!(tree.all_registers().len(), 2);
    }

    #[test]
    fn test_register_node_basics() {
        let reg = ghidra_core::program::lang::Register::new("RAX", 64, "register", 0);
        let all_regs = vec![ghidra_core::program::lang::Register::new("RAX", 64, "register", 0)];
        let node = RegisterNode::new(reg, &all_regs);
        assert_eq!(node.name(), "RAX");
        assert_eq!(node.bit_length(), 64);
        assert!(!node.has_children());
        assert!(node.children().is_empty());
    }

    #[test]
    fn test_register_values_panel_basics() {
        let panel = RegisterValuesPanel::new();
        assert_eq!(panel.row_count(), 0);
        assert!(panel.display_ranges().is_empty());
        assert_eq!(panel.sort_direction(), SortDirection::Ascending);
        assert!(panel.selected_register().is_none());
        assert!(panel.selected_row().is_none());
        assert!(!panel.shows_defaults());
    }

    #[test]
    fn test_in_memory_register_context() {
        let mut ctx = commands::InMemoryRegisterContext::new();
        ctx.set_default_value("RAX", 0);
        ctx.set_default_value("RBX", 0xFF);
    }
}
