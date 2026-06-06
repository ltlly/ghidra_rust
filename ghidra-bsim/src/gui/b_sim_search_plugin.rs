//! Port of `BSimSearchPlugin`.
use std::collections::HashMap;
/// Struct porting `BSimSearchPlugin`.
#[derive(Debug, Clone)]
pub struct BSimSearchPlugin {
    /// help_topic.
    pub help_topic: String,
}

impl BSimSearchPlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for BSimSearchPlugin {
    fn default() -> Self {
        Self {
            help_topic: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_search_plugin_new() { let _ = BSimSearchPlugin::new(); }
}
