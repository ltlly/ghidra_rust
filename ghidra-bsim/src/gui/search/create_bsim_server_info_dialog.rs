//! Port of `CreateBsimServerInfoDialog`.
use std::collections::HashMap;
/// Struct porting `CreateBsimServerInfoDialog`.
#[derive(Debug, Clone)]
pub struct CreateBsimServerInfoDialog {
    /// file_db_ext.
    pub file_db_ext: String,
}

impl CreateBsimServerInfoDialog {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for CreateBsimServerInfoDialog {
    fn default() -> Self {
        Self {
            file_db_ext: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_create_bsim_server_info_dialog_new() { let _ = CreateBsimServerInfoDialog::new(); }
}
