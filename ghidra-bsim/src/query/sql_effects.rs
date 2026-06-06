//! Port of `SQLEffects`.
use std::collections::HashMap;
/// Struct porting `SQLEffects`.
#[derive(Debug, Clone)]
pub struct SQLEffects {
    /// tableclause.
    pub tableclause: String,
    /// whereclause.
    pub whereclause: String,
}

impl SQLEffects {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for SQLEffects {
    fn default() -> Self {
        Self {
            tableclause: String::new(),
            whereclause: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sql_effects_new() { let _ = SQLEffects::new(); }
}
