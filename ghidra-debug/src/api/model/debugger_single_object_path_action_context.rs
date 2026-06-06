//! Action context carrying a single object path for scripting.

use crate::model::target_path::KeyPath;

/// Action context carrying a single object path.
#[derive(Debug, Clone)]
pub struct DebuggerSingleObjectPathActionContext {
    /// The path to the target object.
    pub path: KeyPath,
    /// Provider name.
    pub provider_name: String,
}

impl DebuggerSingleObjectPathActionContext {
    /// Create a new context with the given path.
    pub fn new(path: KeyPath, provider_name: impl Into<String>) -> Self {
        Self { path, provider_name: provider_name.into() }
    }
    /// Get the path.
    pub fn path(&self) -> &KeyPath { &self.path }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_single_path_context() {
        let path = KeyPath::from_vec(vec!["root".into(), "child".into()]);
        let ctx = DebuggerSingleObjectPathActionContext::new(path, "Script");
        assert_eq!(ctx.path().size(), 2);
    }
}
