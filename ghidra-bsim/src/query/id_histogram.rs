//! Port of `IdHistogram`.
use std::collections::HashMap;
/// Struct porting `IdHistogram`.
#[derive(Debug, Clone)]
pub struct IdHistogram {
    /// id.
    pub id: i64,
    /// count.
    pub count: i32,
    /// vec.
    pub vec: String,
}

impl IdHistogram {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for IdHistogram {
    fn default() -> Self {
        Self {
            id: 0,
            count: 0,
            vec: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_id_histogram_new() { let _ = IdHistogram::new(); }
}
