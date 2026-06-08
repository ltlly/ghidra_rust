//! Built-in Navigation actions for the Ghidra GUI.
//!
//! Provides go-to, history, function/instruction navigation, label/reference
//! traversal, and entry-point jumping.

use crate::actions::commands::{enqueue, ActionCommand, CommandQueue};
use crate::docking::{
    ActionCallback, DockingAction, Key, KeyBinding,
};

/// Create all Navigation-menu docking actions.
pub fn create_navigation_actions(queue: &CommandQueue) -> Vec<DockingAction> {
    vec![
        go_to_action(queue),
        back_action(queue),
        forward_action(queue),
        next_function_action(queue),
        previous_function_action(queue),
        next_instruction_action(queue),
        previous_instruction_action(queue),
        next_label_action(queue),
        next_reference_action(queue),
        go_to_entry_point_action(queue),
        go_to_external_location_action(queue),
    ]
}

// ── Go To ────────────────────────────────────────────────────────────────────

pub fn go_to_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("go-to", "Go To...")
        .with_description("Navigate to an arbitrary address")
        .with_key_binding(KeyBinding::ctrl(Key::G))
        .with_menu_path(vec!["Navigation".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::GoTo)
        }))
}

// ── Back ─────────────────────────────────────────────────────────────────────

pub fn back_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("back", "Back")
        .with_description("Navigate backward in the location history")
        .with_key_binding(KeyBinding::alt(Key::Left))
        .with_menu_path(vec!["Navigation".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::Back)
        }))
}

// ── Forward ──────────────────────────────────────────────────────────────────

pub fn forward_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("forward", "Forward")
        .with_description("Navigate forward in the location history")
        .with_key_binding(KeyBinding::alt(Key::Right))
        .with_menu_path(vec!["Navigation".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::Forward)
        }))
}

// ── Next Function ────────────────────────────────────────────────────────────

pub fn next_function_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("next-function", "Next Function")
        .with_description("Move the cursor to the next function definition")
        .with_key_binding(KeyBinding::ctrl(Key::Down))
        .with_menu_path(vec!["Navigation".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::NextFunction)
        }))
}

// ── Previous Function ────────────────────────────────────────────────────────

pub fn previous_function_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("previous-function", "Previous Function")
        .with_description("Move the cursor to the previous function definition")
        .with_key_binding(KeyBinding::ctrl(Key::Up))
        .with_menu_path(vec!["Navigation".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::PreviousFunction)
        }))
}

// ── Next Instruction ─────────────────────────────────────────────────────────

pub fn next_instruction_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("next-instruction", "Next Instruction")
        .with_description("Move the cursor to the next instruction")
        .with_key_binding(KeyBinding::plain(Key::Down))
        .with_menu_path(vec!["Navigation".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::NextInstruction)
        }))
}

// ── Previous Instruction ─────────────────────────────────────────────────────

pub fn previous_instruction_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("previous-instruction", "Previous Instruction")
        .with_description("Move the cursor to the previous instruction")
        .with_key_binding(KeyBinding::plain(Key::Up))
        .with_menu_path(vec!["Navigation".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::PreviousInstruction)
        }))
}

// ── Next Label ───────────────────────────────────────────────────────────────

pub fn next_label_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("next-label", "Next Label")
        .with_description("Navigate to the next labelled address")
        .with_key_binding(KeyBinding::ctrl(Key::L))
        .with_menu_path(vec!["Navigation".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::NextLabel)
        }))
}

// ── Next Reference ───────────────────────────────────────────────────────────

pub fn next_reference_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("next-reference", "Next Reference")
        .with_description("Navigate to the next cross-reference")
        .with_key_binding(KeyBinding::ctrl_shift(Key::F))
        .with_menu_path(vec!["Navigation".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::NextReference)
        }))
}

// ── Go To Entry Point ────────────────────────────────────────────────────────

pub fn go_to_entry_point_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("go-to-entry", "Go To Entry Point")
        .with_description("Navigate to the program's main entry point")
        .with_key_binding(KeyBinding::ctrl(Key::E))
        .with_menu_path(vec!["Navigation".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::GoToEntryPoint)
        }))
}

// ── Go To External Location ──────────────────────────────────────────────────

pub fn go_to_external_location_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("go-to-external", "Go To External Location...")
        .with_description("Navigate to a location outside the current program (e.g. a library)")
        .with_key_binding(KeyBinding::ctrl_shift(Key::G))
        .with_menu_path(vec!["Navigation".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::GoToExternalLocation)
        }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_navigation_actions_count() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_navigation_actions(&q);
        assert_eq!(actions.len(), 11);
    }

    #[test]
    fn test_all_have_keybindings() {
        let q = crate::actions::commands::new_command_queue();
        for action in &create_navigation_actions(&q) {
            assert!(
                action.key_binding.is_some(),
                "{} missing keybinding",
                action.name
            );
        }
    }

    #[test]
    fn test_go_to_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = go_to_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::GoTo]);
    }

    #[test]
    fn test_all_navigation_commands_distinct() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_navigation_actions(&q);
        let mut seen = std::collections::HashSet::new();
        for action in &actions {
            seen.insert(action.name.clone());
        }
        assert_eq!(seen.len(), actions.len());
    }
}
