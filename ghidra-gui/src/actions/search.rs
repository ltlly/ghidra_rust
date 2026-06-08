//! Built-in Search actions for the Ghidra GUI.
//!
//! Provides memory search, program text search, string search, reference
//! search, instruction pattern search, address table search, and search
//! result navigation.

use crate::actions::commands::{enqueue, ActionCommand, CommandQueue};
use crate::docking::{
    ActionCallback, DockingAction, Key, KeyBinding,
};

/// Create all Search-menu docking actions.
pub fn create_search_actions(queue: &CommandQueue) -> Vec<DockingAction> {
    vec![
        search_memory_action(queue),
        search_program_text_action(queue),
        search_for_strings_action(queue),
        search_for_direct_references_action(queue),
        search_for_instruction_patterns_action(queue),
        search_for_address_tables_action(queue),
        search_next_action(queue),
        search_previous_action(queue),
    ]
}

// ── Search Memory ────────────────────────────────────────────────────────────

pub fn search_memory_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("search-memory", "Search Memory...")
        .with_description("Search program memory for a hex or byte pattern")
        .with_key_binding(KeyBinding::ctrl_shift(Key::M))
        .with_menu_path(vec!["Search".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::SearchMemory)
        }))
}

// ── Search Program Text ──────────────────────────────────────────────────────

pub fn search_program_text_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("search-program-text", "Search Program Text...")
        .with_description("Search disassembly text, labels, and comments for a string")
        .with_key_binding(KeyBinding::ctrl(Key::F))
        .with_menu_path(vec!["Search".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::SearchProgramText)
        }))
}

// ── Search For Strings ───────────────────────────────────────────────────────

pub fn search_for_strings_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("search-for-strings", "Search For Strings...")
        .with_description("Scan memory for printable ASCII and Unicode strings")
        .with_key_binding(KeyBinding::ctrl_shift(Key::S))
        .with_menu_path(vec!["Search".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::SearchForStrings)
        }))
}

// ── Search For Direct References ─────────────────────────────────────────────

pub fn search_for_direct_references_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new(
        "search-for-direct-references",
        "Search For Direct References...",
    )
    .with_description("Find all instructions that directly reference a given address or value")
    .with_key_binding(KeyBinding::ctrl_shift(Key::D))
    .with_menu_path(vec!["Search".into()])
    .with_callback(ActionCallback::new(move || {
        enqueue(&q, ActionCommand::SearchForDirectReferences)
    }))
}

// ── Search For Instruction Patterns ──────────────────────────────────────────

pub fn search_for_instruction_patterns_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new(
        "search-for-instruction-patterns",
        "Search For Instruction Patterns...",
    )
    .with_description(
        "Search for sequences of instructions matching a given pattern (masked bytes)",
    )
    .with_key_binding(KeyBinding::ctrl_shift(Key::I))
    .with_menu_path(vec!["Search".into()])
    .with_callback(ActionCallback::new(move || {
        enqueue(&q, ActionCommand::SearchForInstructionPatterns)
    }))
}

// ── Search For Address Tables ────────────────────────────────────────────────

pub fn search_for_address_tables_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("search-for-address-tables", "Search For Address Tables...")
        .with_description(
            "Scan memory for arrays of pointer-aligned addresses (jump tables, v-tables, etc.)",
        )
        .with_key_binding(KeyBinding::ctrl_shift(Key::T))
        .with_menu_path(vec!["Search".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::SearchForAddressTables)
        }))
}

// ── Search Next ──────────────────────────────────────────────────────────────

pub fn search_next_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("search-next", "Search Next")
        .with_description("Jump to the next search result")
        .with_key_binding(KeyBinding::plain(Key::F3))
        .with_menu_path(vec!["Search".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::SearchNext)
        }))
}

// ── Search Previous ──────────────────────────────────────────────────────────

pub fn search_previous_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("search-previous", "Search Previous")
        .with_description("Jump to the previous search result")
        .with_key_binding(KeyBinding::shift(Key::F3))
        .with_menu_path(vec!["Search".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::SearchPrevious)
        }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_actions_count() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_search_actions(&q);
        assert_eq!(actions.len(), 8);
    }

    #[test]
    fn test_all_have_keybindings() {
        let q = crate::actions::commands::new_command_queue();
        for action in &create_search_actions(&q) {
            assert!(
                action.key_binding.is_some(),
                "{} missing keybinding",
                action.name
            );
        }
    }

    #[test]
    fn test_search_memory_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = search_memory_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::SearchMemory]);
    }

    #[test]
    fn test_search_next_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = search_next_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::SearchNext]);
    }

    #[test]
    fn test_all_search_commands_distinct() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_search_actions(&q);
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
        for action in &create_search_actions(&q) {
            assert!(
                !action.description.is_empty(),
                "{} has empty description",
                action.name
            );
        }
    }
}
