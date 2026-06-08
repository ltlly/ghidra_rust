//! Built-in Analysis actions for the Ghidra GUI.
//!
//! Provides auto-analysis, one-shot analysis, disassembly, function creation,
//! data definition, labelling, commenting, and register operations.

use crate::actions::commands::{enqueue, ActionCommand, CommandQueue};
use crate::docking::{
    ActionCallback, DockingAction, Key, KeyBinding, Modifiers,
};

/// Create all Analysis-menu docking actions.
pub fn create_analysis_actions(queue: &CommandQueue) -> Vec<DockingAction> {
    vec![
        auto_analyze_action(queue),
        analyze_one_shot_action(queue),
        disassemble_action(queue),
        create_function_action(queue),
        create_data_action(queue),
        create_label_action(queue),
        create_comment_action(queue),
        clear_code_bytes_action(queue),
        define_data_action(queue),
        edit_function_signature_action(queue),
        rename_variable_action(queue),
        set_register_value_action(queue),
    ]
}

// ── Auto Analyze ─────────────────────────────────────────────────────────────

pub fn auto_analyze_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("auto-analyze", "Auto Analyze...")
        .with_description("Run all enabled analyzers on the entire program")
        .with_key_binding(KeyBinding::plain(Key::A))
        .with_menu_path(vec!["Analysis".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::AutoAnalyze)
        }))
}

// ── Analyze One Shot ─────────────────────────────────────────────────────────

pub fn analyze_one_shot_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("analyze-one-shot", "One Shot Analysis...")
        .with_description("Run a single analyser pass on demand")
        .with_key_binding(KeyBinding::ctrl_shift(Key::A))
        .with_menu_path(vec!["Analysis".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::AnalyzeOneShot)
        }))
}

// ── Disassemble ──────────────────────────────────────────────────────────────

pub fn disassemble_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("disassemble", "Disassemble")
        .with_description("Disassemble bytes starting at the current cursor address")
        .with_key_binding(KeyBinding::plain(Key::D))
        .with_menu_path(vec!["Analysis".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::Disassemble)
        }))
}

// ── Create Function ──────────────────────────────────────────────────────────

pub fn create_function_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("create-function", "Create Function")
        .with_description("Define a new function at the current address")
        .with_key_binding(KeyBinding::plain(Key::F))
        .with_menu_path(vec!["Analysis".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::CreateFunction)
        }))
}

// ── Create Data ──────────────────────────────────────────────────────────────

pub fn create_data_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("create-data", "Create Data")
        .with_description("Define a data item at the current address")
        .with_key_binding(KeyBinding::plain(Key::B))
        .with_menu_path(vec!["Analysis".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::CreateData)
        }))
}

// ── Create Label ─────────────────────────────────────────────────────────────

pub fn create_label_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("create-label", "Create Label")
        .with_description("Create a label (symbol name) at the current address")
        .with_key_binding(KeyBinding::plain(Key::L))
        .with_menu_path(vec!["Analysis".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::CreateLabel)
        }))
}

// ── Create Comment ───────────────────────────────────────────────────────────

pub fn create_comment_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("create-comment", "Create Comment")
        .with_description("Add or edit a comment at the current address")
        .with_key_binding(KeyBinding::new(Modifiers::NONE, Key::Semicolon))
        .with_menu_path(vec!["Analysis".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::CreateComment)
        }))
}

// ── Clear Code Bytes ─────────────────────────────────────────────────────────

pub fn clear_code_bytes_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("clear-code-bytes", "Clear Code Bytes")
        .with_description("Undefine the code/data at the current address, reverting to raw bytes")
        .with_key_binding(KeyBinding::plain(Key::C))
        .with_menu_path(vec!["Analysis".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::ClearCodeBytes)
        }))
}

// ── Define Data ──────────────────────────────────────────────────────────────

pub fn define_data_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("define-data", "Define Data Type...")
        .with_description(
            "Choose a specific data type to apply at the cursor (byte, word, dword, string, etc.)",
        )
        .with_key_binding(KeyBinding::ctrl(Key::T))
        .with_menu_path(vec!["Analysis".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::DefineData(String::new()))
        }))
}

// ── Edit Function Signature ──────────────────────────────────────────────────

pub fn edit_function_signature_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("edit-function-signature", "Edit Function Signature...")
        .with_description(
            "Edit the signature (return type, parameters, calling convention) of the function at the cursor",
        )
        .with_key_binding(KeyBinding::ctrl_shift(Key::S))
        .with_menu_path(vec!["Analysis".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::EditFunctionSignature)
        }))
}

// ── Rename Variable ──────────────────────────────────────────────────────────

pub fn rename_variable_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("rename-variable", "Rename Variable...")
        .with_description("Rename a local variable in the current function's stack frame")
        .with_key_binding(KeyBinding::ctrl(Key::R))
        .with_menu_path(vec!["Analysis".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::RenameVariable)
        }))
}

// ── Set Register Value ───────────────────────────────────────────────────────

pub fn set_register_value_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("set-register-value", "Set Register Value...")
        .with_description("Set a register to a specific value at the current address")
        .with_key_binding(KeyBinding::ctrl_shift(Key::R))
        .with_menu_path(vec!["Analysis".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::SetRegisterValue)
        }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_actions_count() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_analysis_actions(&q);
        assert_eq!(actions.len(), 12);
    }

    #[test]
    fn test_all_have_keybindings() {
        let q = crate::actions::commands::new_command_queue();
        for action in &create_analysis_actions(&q) {
            assert!(
                action.key_binding.is_some(),
                "{} missing keybinding",
                action.name
            );
        }
    }

    #[test]
    fn test_disassemble_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = disassemble_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::Disassemble]);
    }

    #[test]
    fn test_create_function_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = create_function_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::CreateFunction]);
    }

    #[test]
    fn test_auto_analyze_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = auto_analyze_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::AutoAnalyze]);
    }

    #[test]
    fn test_all_analysis_commands_distinct() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_analysis_actions(&q);
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
    fn test_action_descriptions_not_empty() {
        let q = crate::actions::commands::new_command_queue();
        for action in &create_analysis_actions(&q) {
            assert!(
                !action.description.is_empty(),
                "{} has empty description",
                action.name
            );
        }
    }
}
