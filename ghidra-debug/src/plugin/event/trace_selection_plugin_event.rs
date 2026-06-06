//! Trace selection event.

/// Trace selection event.
#[derive(Debug, Clone)]
pub struct TraceSelectionPluginEvent {
    /// trace_name
    pub trace_name: Option<String>,
    /// trace_id
    pub trace_id: Option<u64>,
}

impl TraceSelectionPluginEvent {
    /// Create a new TraceSelectionPluginEvent.
    pub fn new(trace_name: Option<String>, trace_id: Option<u64>) -> Self {
        Self { trace_name, trace_id }
    }

    /// trace_name
    pub fn trace_name(&self) -> Option<&str> {
        self.trace_name.as_deref()
    }

    /// trace_id
    pub fn trace_id(&self) -> &Option<u64> {
        &self.trace_id
    }
}

impl Default for TraceSelectionPluginEvent {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = TraceSelectionPluginEvent::new(None, None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = TraceSelectionPluginEvent::default();
    }
}
