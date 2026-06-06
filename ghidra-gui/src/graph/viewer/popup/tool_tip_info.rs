//! Port of `ToolTipInfo`.
use std::collections::HashMap;
/// Struct porting `ToolTipInfo`.
#[derive(Debug, Clone)]
pub struct ToolTipInfo {
    /// event.
    pub event: String,
    /// graph_object.
    pub graph_object: String,
}

impl ToolTipInfo {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ToolTipInfo {
    fn default() -> Self {
        Self {
            event: String::new(),
            graph_object: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_tool_tip_info_new() { let _ = ToolTipInfo::new(); }
}
