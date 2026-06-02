//! Built-in DockingAction factories for the Ghidra Rust GUI.
//!
//! Each sub-module produces a `Vec<DockingAction>` wired to push typed
//! [`commands::ActionCommand`] values into a shared [`commands::CommandQueue`].
//! The application loop drains the queue each frame and executes the
//! corresponding logic.
//!
//! # Usage
//!
//! ```ignore
//! use ghidra_gui::actions::{self, commands::new_command_queue};
//!
//! let queue = new_command_queue();
//! let all_actions = actions::build_all_actions(&queue);
//!
//! // Register with the DockingTool
//! tool.add_actions(all_actions);
//!
//! // Each frame, drain and handle the queue
//! for cmd in commands::drain(&queue) {
//!     my_app.handle_command(cmd);
//! }
//! ```

pub mod analysis;
pub mod commands;
pub mod edit;
pub mod help;
pub mod navigation;
pub mod search;
pub mod tools;

use crate::docking::DockingAction;
use commands::CommandQueue;

/// Convenience: build all built-in actions across every module and return
/// them as a single flat vector.
pub fn build_all_actions(queue: &CommandQueue) -> Vec<DockingAction> {
    let mut all = Vec::new();
    all.extend(edit::create_edit_actions(queue));
    all.extend(navigation::create_navigation_actions(queue));
    all.extend(analysis::create_analysis_actions(queue));
    all.extend(search::create_search_actions(queue));
    all.extend(tools::create_tools_actions(queue));
    all.extend(help::create_help_actions(queue));
    all
}

/// Returns the number of built-in actions across all modules.
pub fn builtin_action_count() -> usize {
    build_all_actions(&commands::new_command_queue()).len()
}

// ── Integration test ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_all_actions() {
        let q = commands::new_command_queue();
        let actions = build_all_actions(&q);
        // 9 edit + 11 navigation + 12 analysis + 8 search + 6 tools + 4 help = 50
        assert_eq!(actions.len(), 50);
    }

    #[test]
    fn test_all_actions_have_callbacks() {
        let q = commands::new_command_queue();
        let actions = build_all_actions(&q);
        let missing: Vec<_> = actions
            .iter()
            .filter(|a| a.callback.is_none())
            .map(|a| a.name.clone())
            .collect();
        assert!(
            missing.is_empty(),
            "Actions missing callbacks: {:?}",
            missing
        );
    }

    #[test]
    fn test_all_action_names_unique() {
        let q = commands::new_command_queue();
        let actions = build_all_actions(&q);
        let mut seen = std::collections::HashSet::new();
        for action in &actions {
            assert!(
                seen.insert(action.name.clone()),
                "Duplicate action name: {}",
                action.name
            );
        }
    }

    #[test]
    fn test_each_action_triggers_command() {
        let q = commands::new_command_queue();
        let actions = build_all_actions(&q);

        for action in &actions {
            let cb = action.callback.as_ref().expect("missing callback");
            cb.call();
            let cmds = commands::drain(&q);
            assert_eq!(
                cmds.len(),
                1,
                "Action '{}' should enqueue exactly one command, got {:?}",
                action.name,
                cmds
            );
        }
    }

    #[test]
    fn test_command_queue_drain_clears() {
        let q = commands::new_command_queue();
        commands::enqueue(&q, commands::ActionCommand::Undo);
        commands::enqueue(&q, commands::ActionCommand::Redo);
        assert_eq!(commands::drain(&q).len(), 2);
        assert!(commands::drain(&q).is_empty());
    }
}
