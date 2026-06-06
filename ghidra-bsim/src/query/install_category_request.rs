//! Port of `InstallCategoryRequest`.
use std::collections::HashMap;
/// Struct porting `InstallCategoryRequest`.
#[derive(Debug, Clone)]
pub struct InstallCategoryRequest {
    /// type_name.
    pub type_name: String,
    /// isdatecolumn.
    pub isdatecolumn: bool,
    /// installresponse.
    pub installresponse: String,
}

impl InstallCategoryRequest {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for InstallCategoryRequest {
    fn default() -> Self {
        Self {
            type_name: String::new(),
            isdatecolumn: false,
            installresponse: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_install_category_request_new() { let _ = InstallCategoryRequest::new(); }
}
