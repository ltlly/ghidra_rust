//! Port of `RenameTask`.
use std::collections::HashMap;
/// Struct porting `RenameTask`.
#[derive(Debug, Clone)]
pub struct RenameTask {
    /// newName
    pub new_name: String,
    /// oldName
    pub old_name: String,
    /// errorMsg
    pub error_msg: String,
    /// tool
    pub tool: String,
    /// program
    pub program: String,
    /// provider
    pub provider: String,
}
impl RenameTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RenameTask {
    fn default() -> Self {
        Self {
            new_name: String::new(),
            old_name: String::new(),
            error_msg: String::new(),
            tool: String::new(),
            program: String::new(),
            provider: String::new()
        }
    }


}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rename_task_new() { let _ = RenameTask::new(); }
}
