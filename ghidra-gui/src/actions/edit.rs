//! Built-in Edit actions for the Ghidra GUI.
//!
//! Provides undo/redo, clipboard operations, selection, and find/replace.

use crate::actions::commands::{enqueue, ActionCommand, CommandQueue};
use crate::docking::{
    ActionCallback, ActionContext, ActionType, DockingAction, Key, KeyBinding, Modifiers,
};

/// Create all Edit-menu docking actions.
///
/// Returns a vector of [`DockingAction`] instances, each wired to push the
/// appropriate [`ActionCommand`] into the shared `queue`.
pub fn create_edit_actions(queue: &CommandQueue) -> Vec<DockingAction> {
    vec![
        undo_action(queue),
        redo_action(queue),
        cut_action(queue),
        copy_action(queue),
        paste_action(queue),
        delete_action(queue),
        select_all_action(queue),
        find_action(queue),
        replace_action(queue),
    ]
}

// ── Undo ─────────────────────────────────────────────────────────────────────

pub fn undo_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("undo", "Undo")
        .with_description("Undo the last operation")
        .with_key_binding(KeyBinding::ctrl(Key::Z))
        .with_menu_path(vec!["Edit".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::Undo)
        }))
}

// ── Redo ─────────────────────────────────────────────────────────────────────

pub fn redo_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("redo", "Redo")
        .with_description("Redo the previously undone operation")
        .with_key_binding(KeyBinding::ctrl_shift(Key::Z))
        .with_menu_path(vec!["Edit".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::Redo)
        }))
}

// ── Cut ──────────────────────────────────────────────────────────────────────

pub fn cut_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("cut", "Cut")
        .with_description("Cut the selected text/data to the clipboard")
        .with_key_binding(KeyBinding::ctrl(Key::X))
        .with_menu_path(vec!["Edit".into()])
        .with_callback(ActionCallback::new(move || enqueue(&q, ActionCommand::Cut)))
}

// ── Copy ─────────────────────────────────────────────────────────────────────

pub fn copy_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("copy", "Copy")
        .with_description("Copy the selected text/data to the clipboard")
        .with_key_binding(KeyBinding::ctrl(Key::C))
        .with_menu_path(vec!["Edit".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::Copy)
        }))
}

// ── Paste ────────────────────────────────────────────────────────────────────

pub fn paste_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("paste", "Paste")
        .with_description("Paste clipboard contents at the current cursor position")
        .with_key_binding(KeyBinding::ctrl(Key::V))
        .with_menu_path(vec!["Edit".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::Paste)
        }))
}

// ── Delete ───────────────────────────────────────────────────────────────────

pub fn delete_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("delete", "Delete")
        .with_description("Delete the current selection")
        .with_key_binding(KeyBinding::new(Modifiers::NONE, Key::Delete))
        .with_menu_path(vec!["Edit".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::Delete)
        }))
}

// ── Select All ───────────────────────────────────────────────────────────────

pub fn select_all_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("select-all", "Select All")
        .with_description("Select all items in the active view")
        .with_key_binding(KeyBinding::ctrl(Key::A))
        .with_menu_path(vec!["Edit".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::SelectAll)
        }))
}

// ── Find ─────────────────────────────────────────────────────────────────────

pub fn find_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("find", "Find...")
        .with_description("Search for text or bytes in the program")
        .with_key_binding(KeyBinding::ctrl(Key::F))
        .with_menu_path(vec!["Edit".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::Find)
        }))
}

// ── Replace ──────────────────────────────────────────────────────────────────

pub fn replace_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("replace", "Replace...")
        .with_description("Search for text and replace with new text")
        .with_key_binding(KeyBinding::ctrl(Key::H))
        .with_menu_path(vec!["Edit".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::Replace)
        }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn action_names(actions: &[DockingAction]) -> Vec<&str> {
        actions.iter().map(|a| a.name.as_str()).collect()
    }

    #[test]
    fn test_edit_actions_count() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_edit_actions(&q);
        assert_eq!(actions.len(), 9);
    }

    #[test]
    fn test_edit_action_names() {
        let q = crate::actions::commands::new_command_queue();
        let names = action_names(&create_edit_actions(&q));
        assert!(names.contains(&"undo"));
        assert!(names.contains(&"redo"));
        assert!(names.contains(&"cut"));
        assert!(names.contains(&"copy"));
        assert!(names.contains(&"paste"));
        assert!(names.contains(&"delete"));
        assert!(names.contains(&"select-all"));
        assert!(names.contains(&"find"));
        assert!(names.contains(&"replace"));
    }

    #[test]
    fn test_undo_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = undo_action(&q);
        assert_eq!(action.name, "undo");
        assert!(action.key_binding.is_some());
        // Trigger the callback.
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::Undo]);
    }

    #[test]
    fn test_copy_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = copy_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::Copy]);
    }

    #[test]
    fn test_builder_properties() {
        let q = crate::actions::commands::new_command_queue();
        let action = undo_action(&q);
        assert_eq!(action.display_name, "Undo");
        assert!(!action.description.is_empty());
        assert_eq!(action.menu_path, vec!["Edit"]);
        assert!(action.is_applicable(&ActionContext::Any));
    }
}
