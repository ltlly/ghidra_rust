//! Port of `AbstractBSimSearchDialog`.
use std::collections::HashMap;
/// Struct porting `AbstractBSimSearchDialog`.
#[derive(Debug, Clone)]
pub struct AbstractBSimSearchDialog {
    /// search_service.
    pub search_service: String,
    /// tool.
    pub tool: String,
    /// similarity_field.
    pub similarity_field: String,
    /// confidence_field.
    pub confidence_field: String,
    /// server_cache.
    pub server_cache: String,
    /// error_exception.
    pub error_exception: String,
}

impl AbstractBSimSearchDialog {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for AbstractBSimSearchDialog {
    fn default() -> Self {
        Self {
            search_service: String::new(),
            tool: String::new(),
            similarity_field: String::new(),
            confidence_field: String::new(),
            server_cache: String::new(),
            error_exception: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_abstract_b_sim_search_dialog_new() { let _ = AbstractBSimSearchDialog::new(); }
}
