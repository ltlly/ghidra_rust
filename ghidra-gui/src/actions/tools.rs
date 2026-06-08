//! Built-in Tools actions for the Ghidra GUI.
//!
//! Provides program differences, function call graph, data type manager,
//! memory map, register manager, and script manager actions.

use crate::actions::commands::{enqueue, ActionCommand, CommandQueue};
use crate::docking::{
    ActionCallback, DockingAction, Key, KeyBinding,
};

/// Create all Tools-menu docking actions.
pub fn create_tools_actions(queue: &CommandQueue) -> Vec<DockingAction> {
    vec![
        program_differences_action(queue),
        function_graph_action(queue),
        data_type_manager_action(queue),
        memory_map_action(queue),
        register_manager_action(queue),
        script_manager_action(queue),
    ]
}

// ── Program Differences ──────────────────────────────────────────────────────

pub fn program_differences_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("program-differences", "Program Differences...")
        .with_description("Compare two programs and display side-by-side differences")
        .with_key_binding(KeyBinding::ctrl(Key::D))
        .with_menu_path(vec!["Tools".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::ProgramDifferences)
        }))
}

// ── Function Graph ───────────────────────────────────────────────────────────

pub fn function_graph_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("function-graph", "Function Graph")
        .with_description("Display the control-flow graph for the function at the cursor")
        .with_key_binding(KeyBinding::ctrl_shift(Key::F))
        .with_menu_path(vec!["Tools".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::FunctionGraph)
        }))
}

// ── Data Type Manager ────────────────────────────────────────────────────────

pub fn data_type_manager_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("data-type-manager", "Data Type Manager")
        .with_description(
            "Open or focus the Data Type Manager panel for browsing and editing data types",
        )
        .with_key_binding(KeyBinding::ctrl(Key::Num0)) // placeholder
        .with_menu_path(vec!["Tools".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::DataTypeManager)
        }))
}

// ── Memory Map ───────────────────────────────────────────────────────────────

pub fn memory_map_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("memory-map", "Memory Map")
        .with_description("View and edit the program's memory layout (sections, permissions)")
        .with_key_binding(KeyBinding::ctrl(Key::M))
        .with_menu_path(vec!["Tools".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::MemoryMap)
        }))
}

// ── Register Manager ─────────────────────────────────────────────────────────

pub fn register_manager_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("register-manager", "Register Manager")
        .with_description("View and edit register definitions and values")
        .with_key_binding(KeyBinding::ctrl_shift(Key::R))
        .with_menu_path(vec!["Tools".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::RegisterManager)
        }))
}

// ── Script Manager ───────────────────────────────────────────────────────────

pub fn script_manager_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("script-manager", "Script Manager")
        .with_description("Browse, run, and manage Ghidra scripts (Python, Java, etc.)")
        .with_key_binding(KeyBinding::ctrl(Key::J))
        .with_menu_path(vec!["Tools".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::ScriptManager)
        }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tools_actions_count() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_tools_actions(&q);
        assert_eq!(actions.len(), 6);
    }

    #[test]
    fn test_all_have_keybindings() {
        let q = crate::actions::commands::new_command_queue();
        for action in &create_tools_actions(&q) {
            assert!(
                action.key_binding.is_some(),
                "{} missing keybinding",
                action.name
            );
        }
    }

    #[test]
    fn test_function_graph_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = function_graph_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::FunctionGraph]);
    }

    #[test]
    fn test_memory_map_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = memory_map_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::MemoryMap]);
    }

    #[test]
    fn test_all_tools_commands_distinct() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_tools_actions(&q);
        let mut seen = std::collections::HashSet::new();
        for action in &actions {
            assert!(
                seen.insert(action.name.clone()),
                "duplicate action name: {}",
                action.name
            );
        }
        assert_eq!(seen.len(), actions.len());
    }

    #[test]
    fn test_all_descriptions_not_empty() {
        let q = crate::actions::commands::new_command_queue();
        for action in &create_tools_actions(&q) {
            assert!(
                !action.description.is_empty(),
                "{} has empty description",
                action.name
            );
        }
    }
}
