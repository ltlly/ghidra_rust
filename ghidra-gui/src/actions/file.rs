//! Built-in File actions for the Ghidra GUI.
//!
//! Provides open, close, save, save-as, export, and import operations.

use crate::actions::commands::{enqueue, ActionCommand, CommandQueue};
use crate::docking::{ActionCallback, DockingAction, Key, KeyBinding};

/// Create all File-menu docking actions.
pub fn create_file_actions(queue: &CommandQueue) -> Vec<DockingAction> {
    vec![
        open_file_action(queue),
        close_file_action(queue),
        save_file_action(queue),
        save_file_as_action(queue),
        export_program_action(queue),
        import_program_action(queue),
    ]
}

// ── Open File ────────────────────────────────────────────────────────────────

pub fn open_file_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("open-file", "Open...")
        .with_description("Open an existing program file for analysis")
        .with_key_binding(KeyBinding::ctrl(Key::O))
        .with_menu_path(vec!["File".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::OpenFile)
        }))
}

// ── Close File ───────────────────────────────────────────────────────────────

pub fn close_file_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("close-file", "Close")
        .with_description("Close the current program")
        .with_key_binding(KeyBinding::ctrl(Key::W))
        .with_menu_path(vec!["File".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::CloseFile)
        }))
}

// ── Save File ────────────────────────────────────────────────────────────────

pub fn save_file_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("save-file", "Save")
        .with_description("Save the current program to disk")
        .with_key_binding(KeyBinding::ctrl(Key::S))
        .with_menu_path(vec!["File".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::SaveFile)
        }))
}

// ── Save File As ─────────────────────────────────────────────────────────────

pub fn save_file_as_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("save-file-as", "Save As...")
        .with_description("Save the current program to a new file or project location")
        .with_key_binding(KeyBinding::ctrl_shift(Key::S))
        .with_menu_path(vec!["File".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::SaveFileAs)
        }))
}

// ── Export Program ───────────────────────────────────────────────────────────

pub fn export_program_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("export-program", "Export Program...")
        .with_description(
            "Export the current program to an external format (ELF, PE, binary, etc.)",
        )
        .with_menu_path(vec!["File".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::ExportProgram)
        }))
}

// ── Import Program ───────────────────────────────────────────────────────────

pub fn import_program_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("import-program", "Import...")
        .with_description("Import a new program into the current project")
        .with_key_binding(KeyBinding::ctrl(Key::I))
        .with_menu_path(vec!["File".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::ImportProgram)
        }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_actions_count() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_file_actions(&q);
        assert_eq!(actions.len(), 6);
    }

    #[test]
    fn test_all_have_keybindings_or_are_export() {
        let q = crate::actions::commands::new_command_queue();
        for action in &create_file_actions(&q) {
            if action.name == "export-program" {
                continue;
            }
            assert!(
                action.key_binding.is_some(),
                "{} missing keybinding",
                action.name
            );
        }
    }

    #[test]
    fn test_open_file_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = open_file_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::OpenFile]);
    }

    #[test]
    fn test_save_file_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = save_file_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::SaveFile]);
    }

    #[test]
    fn test_all_file_commands_distinct() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_file_actions(&q);
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
        for action in &create_file_actions(&q) {
            assert!(
                !action.description.is_empty(),
                "{} has empty description",
                action.name
            );
        }
    }
}
