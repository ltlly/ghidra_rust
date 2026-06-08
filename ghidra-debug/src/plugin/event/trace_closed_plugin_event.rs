//! Trace closed event.

/// Trace closed event.
#[derive(Debug, Clone)]
pub struct TraceClosedPluginEvent {
    /// trace_name
    pub trace_name: String,
    /// trace_id
    pub trace_id: u64,
}

impl TraceClosedPluginEvent {
    /// Create a new TraceClosedPluginEvent.
    pub fn new(trace_name: String, trace_id: u64) -> Self {
        Self { trace_name, trace_id }
    }

    /// trace_name
    pub fn trace_name(&self) -> &String {
        &self.trace_name
    }

    /// trace_id
    pub fn trace_id(&self) -> &u64 {
        &self.trace_id
    }
}

impl Default for TraceClosedPluginEvent {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = TraceClosedPluginEvent::new("test".to_string(), 0);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = TraceClosedPluginEvent::default();
    }
}
