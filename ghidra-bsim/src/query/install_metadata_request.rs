//! Port of `InstallMetadataRequest`.
use std::collections::HashMap;
/// Struct porting `InstallMetadataRequest`.
#[derive(Debug, Clone)]
pub struct InstallMetadataRequest {
    /// dbname.
    pub dbname: String,
    /// owner.
    pub owner: String,
    /// description.
    pub description: String,
    /// installresponse.
    pub installresponse: String,
}

impl InstallMetadataRequest {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for InstallMetadataRequest {
    fn default() -> Self {
        Self {
            dbname: String::new(),
            owner: String::new(),
            description: String::new(),
            installresponse: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_install_metadata_request_new() { let _ = InstallMetadataRequest::new(); }
}
