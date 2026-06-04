//! Built-in Window actions for the Ghidra GUI.
//!
//! Provides new tool, close tool, tile windows vertically, and tile
//! windows horizontally.  Mirrors Ghidra's Window menu.

use crate::actions::commands::{enqueue, ActionCommand, CommandQueue};
use crate::docking::{ActionCallback, DockingAction, Key, KeyBinding};

/// Create all Window-menu docking actions.
pub fn create_window_actions(queue: &CommandQueue) -> Vec<DockingAction> {
    vec![
        new_tool_action(queue),
        close_tool_action(queue),
        tile_windows_vertically_action(queue),
        tile_windows_horizontally_action(queue),
    ]
}

// ── New Tool ─────────────────────────────────────────────────────────────────

pub fn new_tool_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("new-tool", "New Tool...")
        .with_description("Open a new Ghidra tool window with its own set of plugins and layout")
        .with_menu_path(vec!["Window".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::NewTool)
        }))
}

// ── Close Tool ───────────────────────────────────────────────────────────────

pub fn close_tool_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("close-tool", "Close Tool")
        .with_description("Close the current tool window and all its plugins")
        .with_key_binding(KeyBinding::ctrl(Key::W))
        .with_menu_path(vec!["Window".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::CloseTool)
        }))
}

// ── Tile Windows Vertically ──────────────────────────────────────────────────

pub fn tile_windows_vertically_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("tile-windows-vertically", "Tile Windows Vertically")
        .with_description("Arrange all open windows side by side in the current tool")
        .with_menu_path(vec!["Window".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::TileWindowsVertically)
        }))
}

// ── Tile Windows Horizontally ────────────────────────────────────────────────

pub fn tile_windows_horizontally_action(queue: &CommandQueue) -> DockingAction {
    let q = queue.clone();
    DockingAction::new("tile-windows-horizontally", "Tile Windows Horizontally")
        .with_description("Arrange all open windows stacked vertically in the current tool")
        .with_menu_path(vec!["Window".into()])
        .with_callback(ActionCallback::new(move || {
            enqueue(&q, ActionCommand::TileWindowsHorizontally)
        }))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_actions_count() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_window_actions(&q);
        assert_eq!(actions.len(), 4);
    }

    #[test]
    fn test_new_tool_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = new_tool_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::NewTool]);
    }

    #[test]
    fn test_tile_vertically_triggers_command() {
        let q = crate::actions::commands::new_command_queue();
        let action = tile_windows_vertically_action(&q);
        action.callback.as_ref().unwrap().call();
        let cmds = crate::actions::commands::drain(&q);
        assert_eq!(cmds, vec![ActionCommand::TileWindowsVertically]);
    }

    #[test]
    fn test_all_window_commands_distinct() {
        let q = crate::actions::commands::new_command_queue();
        let actions = create_window_actions(&q);
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
        for action in &create_window_actions(&q) {
            assert!(
                !action.description.is_empty(),
                "{} has empty description",
                action.name
            );
        }
    }
}
