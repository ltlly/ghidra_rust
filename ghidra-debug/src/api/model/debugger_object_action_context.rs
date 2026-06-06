//! Action context carrying trace object values.

use crate::model::target_value::TraceObjectValue;

/// Action context for debugger object operations.
#[derive(Debug, Clone)]
pub struct DebuggerObjectActionContext {
    /// The object values involved in this action.
    pub object_values: Vec<TraceObjectValue>,
    /// The snap (time) at which this action was performed.
    pub snap: i64,
    /// The provider name for this context.
    pub provider_name: String,
}

impl DebuggerObjectActionContext {
    /// Create a new action context.
    pub fn new(object_values: Vec<TraceObjectValue>, snap: i64, provider_name: impl Into<String>) -> Self {
        Self { object_values, snap, provider_name: provider_name.into() }
    }
    /// Get the object values.
    pub fn object_values(&self) -> &[TraceObjectValue] { &self.object_values }
    /// Get the snap.
    pub fn snap(&self) -> i64 { self.snap }
    /// Get the object count.
    pub fn object_count(&self) -> usize { self.object_values.len() }
}

impl Default for DebuggerObjectActionContext {
    fn default() -> Self { Self::new(vec![], 0, "") }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_creation() {
        let ctx = DebuggerObjectActionContext::new(vec![], 42, "TestProvider");
        assert_eq!(ctx.snap(), 42);
        assert_eq!(ctx.object_count(), 0);
    }
}
