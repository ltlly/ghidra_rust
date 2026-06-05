//! BSim search dialog types.
//!
//! Ports `ghidra.features.bsim.gui.search` from Ghidra's Java source.

pub mod dialog;
pub mod results;

/// BSim search state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BSimSearchState {
    /// Not started.
    Idle,
    /// Search in progress.
    Searching,
    /// Search completed successfully.
    Complete,
    /// Search failed.
    Failed(String),
}

impl Default for BSimSearchState {
    fn default() -> Self {
        BSimSearchState::Idle
    }
}

impl BSimSearchState {
    /// Whether the search is in progress.
    pub fn is_searching(&self) -> bool {
        matches!(self, BSimSearchState::Searching)
    }

    /// Whether the search completed successfully.
    pub fn is_complete(&self) -> bool {
        matches!(self, BSimSearchState::Complete)
    }

    /// Whether the search failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, BSimSearchState::Failed(_))
    }

    /// Get the error message if failed.
    pub fn error_message(&self) -> Option<&str> {
        match self {
            BSimSearchState::Failed(msg) => Some(msg),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_state_default() {
        assert_eq!(BSimSearchState::default(), BSimSearchState::Idle);
    }

    #[test]
    fn test_search_state_idle() {
        let state = BSimSearchState::Idle;
        assert!(!state.is_searching());
        assert!(!state.is_complete());
        assert!(!state.is_failed());
        assert!(state.error_message().is_none());
    }

    #[test]
    fn test_search_state_searching() {
        let state = BSimSearchState::Searching;
        assert!(state.is_searching());
        assert!(!state.is_complete());
        assert!(!state.is_failed());
    }

    #[test]
    fn test_search_state_complete() {
        let state = BSimSearchState::Complete;
        assert!(!state.is_searching());
        assert!(state.is_complete());
        assert!(!state.is_failed());
    }

    #[test]
    fn test_search_state_failed() {
        let state = BSimSearchState::Failed("connection timeout".into());
        assert!(!state.is_searching());
        assert!(!state.is_complete());
        assert!(state.is_failed());
        assert_eq!(state.error_message(), Some("connection timeout"));
    }
}
