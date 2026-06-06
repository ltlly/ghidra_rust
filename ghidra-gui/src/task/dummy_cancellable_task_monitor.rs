//! Port of `DummyCancellableTaskMonitor`.
use std::collections::HashMap;
/// Struct porting `DummyCancellableTaskMonitor`.
#[derive(Debug, Clone)]
pub struct DummyCancellableTaskMonitor {
    _phantom: std::marker::PhantomData<()>,
}
impl DummyCancellableTaskMonitor {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DummyCancellableTaskMonitor {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_dummy_cancellable_task_monitor_new() { let _ = DummyCancellableTaskMonitor::new(); }
}
