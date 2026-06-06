//! Port of `Task`.
use std::collections::HashMap;
/// Struct porting `Task`.
#[derive(Debug, Clone)]
pub struct Task {
    /// wait_for_task_completed.
    pub wait_for_task_completed: bool,
    /// task_monitor.
    pub task_monitor: String,
}

impl Task {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for Task {
    fn default() -> Self {
        Self {
            wait_for_task_completed: false,
            task_monitor: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_task_new() { let _ = Task::new(); }
}
