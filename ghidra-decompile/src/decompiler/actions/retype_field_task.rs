//! Port of `RetypeFieldTask`.
use std::collections::HashMap;
/// Struct porting `RetypeFieldTask`.
#[derive(Debug, Clone)]
pub struct RetypeFieldTask {
    /// composite
    pub composite: String,
    /// newType
    pub new_type: String,
    /// oldType
    pub old_type: String,
    /// errorMsg
    pub error_msg: String,
    /// tool
    pub tool: String,
    /// program
    pub program: String,
}
impl RetypeFieldTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RetypeFieldTask {
    fn default() -> Self {
        Self {
            composite: String::new(),
            new_type: String::new(),
            old_type: String::new(),
            error_msg: String::new(),
            tool: String::new(),
            program: String::new()
        }
    }


}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_retype_field_task_new() { let _ = RetypeFieldTask::new(); }
}
