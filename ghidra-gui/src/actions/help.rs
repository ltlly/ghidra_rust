//! Built-in Help actions for the Ghidra GUI.
//!
//! Provides About, Key Bindings reference, help search, and help contents.

use crate::actions::commands::{enqueue, ActionCommand, CommandQueue};
use crate::docking::{
    ActionCallback, DockingAction, Key, KeyBinding,
};

/// Create all Help-menu docking actions.
pub fn create_help_actions(queue: &CommandQueue) -> Vec<DockingAction> {
    vec![
        about_action(queue),
        key_bindings_action(queue),
        search_help_action(queue),
        ghidra_help_action(queue),
    ]
}

// ── About ────────────────────────────────────────────────────────────────────

pub fn about_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("about", "About Ghidra Rust")
        .with_description("Display version, license, and contributor information")
        .with_menu_path(vec!["Help".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::About)
        }))
}

// ── Key Bindings ─────────────────────────────────────────────────────────────

pub fn key_bindings_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("key-bindings", "Key Bindings")
        .with_description("Display a reference of all keyboard shortcuts")
        .with_key_binding(KeyBinding::ctrl(Key::F1))
        .with_menu_path(vec!["Help".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::KeyBindings)
        }))
}

// ── Search Help ──────────────────────────────────────────────────────────────

pub fn search_help_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("search-help", "Search Help...")
        .with_description("Search the Ghidra help system for a topic")
        .with_key_binding(KeyBinding::ctrl_shift(Key::F1))
        .with_menu_path(vec!["Help".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::SearchHelp)
        }))
}

// ── Ghidra Help ──────────────────────────────────────────────────────────────

pub fn ghidra_help_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("ghidra-help", "Ghidra Help")
        .with_description("Open the Ghidra help system table of contents")
        .with_key_binding(KeyBinding::plain(Key::F1))
        .with_menu_path(vec!["Help".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::GhidraHelp)
        }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_actions_count() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_help_actions(&q);
        assert_eq!(actions.len(), 4);
    }

    #[test]
    fn test_about_has_no_keybinding() {
        let q = crate::actions::commands::new_command_queue();
        let action = about_action(&q);
        assert!(action.key_binding.is_none());
    }

    #[test]
    fn test_ghidra_help_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = ghidra_help_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::GhidraHelp]);
    }

    #[test]
    fn test_about_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = about_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::About]);
    }

    #[test]
    fn test_all_help_commands_distinct() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_help_actions(&q);
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
        for action in &create_help_actions(&q) {
            assert!(
                !action.description.is_empty(),
                "{} has empty description",
                action.name
            );
        }
    }
}
