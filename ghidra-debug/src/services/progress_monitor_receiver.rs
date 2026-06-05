//! Progress monitor receiver implementation.
//!
//! Ported from Ghidra's `DefaultMonitorReceiver` in
//! `ghidra.app.plugin.core.debug.service.progress`.

use super::progress_closeable_monitor::CloseableTaskMonitor;

/// A receiver for progress events from task monitors.
///
/// Forwards progress events from remote sessions to the local UI.
#[derive(Debug)]
pub struct ProgressMonitorReceiver {
    monitor: CloseableTaskMonitor,
    name: String,
}

impl ProgressMonitorReceiver {
    /// Create a new receiver.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            monitor: CloseableTaskMonitor::new(),
            name: name.into(),
        }
    }

    /// Get the name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get a reference to the monitor.
    pub fn monitor(&self) -> &CloseableTaskMonitor {
        &self.monitor
    }

    /// Get a mutable reference to the monitor.
    pub fn monitor_mut(&mut self) -> &mut CloseableTaskMonitor {
        &mut self.monitor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receiver_new() {
        let r = ProgressMonitorReceiver::new("test");
        assert_eq!(r.name(), "test");
        assert!(!r.monitor().is_cancelled());
    }
}
