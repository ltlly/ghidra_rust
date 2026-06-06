//! Port of `ResponseChildren`.
use std::collections::HashMap;
/// Struct porting `ResponseChildren`.
#[derive(Debug, Clone)]
pub struct ResponseChildren {
    /// manage.
    pub manage: String,
    /// correspond.
    pub correspond: String,
    /// qchild.
    pub qchild: String,
}

impl ResponseChildren {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseChildren {
    fn default() -> Self {
        Self {
            manage: String::new(),
            correspond: String::new(),
            qchild: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_children_new() { let _ = ResponseChildren::new(); }
}
