//! Port of `UnknownProgressWrappingTaskMonitor`.
use std::collections::HashMap;
/// Struct porting `UnknownProgressWrappingTaskMonitor`.
#[derive(Debug, Clone)]
pub struct UnknownProgressWrappingTaskMonitor {
    _phantom: std::marker::PhantomData<()>,
}
impl UnknownProgressWrappingTaskMonitor {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for UnknownProgressWrappingTaskMonitor {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_unknown_progress_wrapping_task_monitor_new() { let _ = UnknownProgressWrappingTaskMonitor::new(); }
}
