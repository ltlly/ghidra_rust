//! Port of `InstallTagRequest`.
use std::collections::HashMap;
/// Struct porting `InstallTagRequest`.
#[derive(Debug, Clone)]
pub struct InstallTagRequest {
    /// tag_name.
    pub tag_name: String,
    /// installresponse.
    pub installresponse: String,
}

impl InstallTagRequest {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for InstallTagRequest {
    fn default() -> Self {
        Self {
            tag_name: String::new(),
            installresponse: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_install_tag_request_new() { let _ = InstallTagRequest::new(); }
}
