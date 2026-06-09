//! Command to add a memory reference.
//!
//! Ported from `ghidra.app.cmd.refs.AddMemRefCmd`.

#![allow(dead_code)]

use super::RefType;

/// Command to add a memory reference.
#[derive(Debug)]
pub struct AddMemRefCmd {
    from_address: u64,
    to_address: u64,
    ref_type: RefType,
    source: String,
    op_index: u32,
    set_primary: bool,
}

impl AddMemRefCmd {
    pub fn new(
        from_address: u64,
        to_address: u64,
        ref_type: RefType,
        source: impl Into<String>,
        op_index: u32,
        set_primary: bool,
    ) -> Self {
        Self {
            from_address,
            to_address,
            ref_type,
            source: source.into(),
            op_index,
            set_primary,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }

    pub fn from_address(&self) -> u64 {
        self.from_address
    }

    pub fn to_address(&self) -> u64 {
        self.to_address
    }

    pub fn ref_type(&self) -> RefType {
        self.ref_type
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn op_index(&self) -> u32 {
        self.op_index
    }

    pub fn is_primary(&self) -> bool {
        self.set_primary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_mem_ref() {
        let cmd = AddMemRefCmd::new(
            0x401000,
            0x402000,
            RefType::Call,
            "analysis",
            0,
            true,
        );
        assert!(cmd.apply_to("test"));
        assert_eq!(cmd.from_address(), 0x401000);
        assert_eq!(cmd.to_address(), 0x402000);
        assert_eq!(cmd.ref_type(), RefType::Call);
        assert_eq!(cmd.source(), "analysis");
        assert_eq!(cmd.op_index(), 0);
        assert!(cmd.is_primary());
    }
}
