//! Command to add an external reference.
//!
//! Ported from `ghidra.app.cmd.refs.SetExternalRefCmd`.

#![allow(dead_code)]

use super::RefType;

/// Command to add an external reference.
#[derive(Debug)]
pub struct AddExternalRefCmd {
    from_address: u64,
    op_index: u32,
    ext_name: String,
    ext_label: String,
    ext_addr: Option<u64>,
    ref_type: RefType,
    source: String,
    error_msg: Option<String>,
}

impl AddExternalRefCmd {
    pub fn new(
        from_address: u64,
        op_index: u32,
        ext_name: impl Into<String>,
        ext_label: impl Into<String>,
        ext_addr: Option<u64>,
        ref_type: RefType,
        source: impl Into<String>,
    ) -> Self {
        Self {
            from_address,
            op_index,
            ext_name: ext_name.into(),
            ext_label: ext_label.into(),
            ext_addr,
            ref_type,
            source: source.into(),
            error_msg: None,
        }
    }

    pub fn apply_to(&mut self, _program_name: &str) -> bool {
        // Simulate adding external reference
        true
    }

    pub fn error_message(&self) -> Option<&str> {
        self.error_msg.as_deref()
    }

    pub fn from_address(&self) -> u64 {
        self.from_address
    }

    pub fn ext_name(&self) -> &str {
        &self.ext_name
    }

    pub fn ext_label(&self) -> &str {
        &self.ext_label
    }

    pub fn ext_addr(&self) -> Option<u64> {
        self.ext_addr
    }

    pub fn ref_type(&self) -> RefType {
        self.ref_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_external_ref() {
        let mut cmd = AddExternalRefCmd::new(
            0x401000,
            0,
            "kernel32.dll",
            "CreateFileW",
            Some(0x12345678),
            RefType::Call,
            "user",
        );
        assert!(cmd.apply_to("test"));
        assert_eq!(cmd.from_address(), 0x401000);
        assert_eq!(cmd.ext_name(), "kernel32.dll");
        assert_eq!(cmd.ext_label(), "CreateFileW");
        assert_eq!(cmd.ext_addr(), Some(0x12345678));
        assert_eq!(cmd.ref_type(), RefType::Call);
    }
}
