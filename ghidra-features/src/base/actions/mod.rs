//! Application-level actions.
//!
//! Ported from Ghidra's `ghidra.app.actions` Java package.

/// Action for selecting all code in the current view.
#[derive(Debug)]
pub struct SelectAllAction {
    name: String,
    owner: String,
}

impl SelectAllAction {
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }
}

/// Action for toggling the connected state of a navigatable.
#[derive(Debug)]
pub struct ToggleConnectAction {
    name: String,
    owner: String,
}

impl ToggleConnectAction {
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_all_action() {
        let action = SelectAllAction::new("Select All", "CodeBrowser");
        assert_eq!(action.name(), "Select All");
        assert_eq!(action.owner(), "CodeBrowser");
    }

    #[test]
    fn test_toggle_connect_action() {
        let action = ToggleConnectAction::new("Toggle Connect", "CodeBrowser");
        assert_eq!(action.name(), "Toggle Connect");
    }
}
