//! Debugger color config.

/// Debugger color config.
#[derive(Debug, Clone)]
pub struct DebuggerColors {
    /// trace_color_map
    pub trace_color_map: std::collections::HashMap<String, [u8; 3]>,
}

impl DebuggerColors {
    /// Create a new DebuggerColors.
    pub fn new(trace_color_map: std::collections::HashMap<String, [u8; 3]>) -> Self {
        Self { trace_color_map }
    }

    /// trace_color_map
    pub fn trace_color_map(&self) -> &std::collections::HashMap<String, [u8; 3]> {
        &self.trace_color_map
    }
}

impl Default for DebuggerColors {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DebuggerColors::new(Default::default());
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerColors::default();
    }
}
