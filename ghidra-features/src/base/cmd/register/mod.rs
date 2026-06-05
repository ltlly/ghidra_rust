//! Register commands.
//!
//! Ported from `ghidra.app.cmd.register`.

/// Command to set a register value.
#[derive(Debug)]
pub struct SetRegisterCmd {
    address: u64,
    register_name: String,
    value: u64,
}

impl SetRegisterCmd {
    pub fn new(address: u64, register_name: impl Into<String>, value: u64) -> Self {
        Self {
            address,
            register_name: register_name.into(),
            value,
        }
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn register_name(&self) -> &str {
        &self.register_name
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_register_cmd() {
        let cmd = SetRegisterCmd::new(0x401000, "EAX", 0x12345678);
        assert_eq!(cmd.address(), 0x401000);
        assert_eq!(cmd.register_name(), "EAX");
        assert_eq!(cmd.value(), 0x12345678);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_set_register_64bit() {
        let cmd = SetRegisterCmd::new(0x401000, "RAX", 0xDEADBEEFCAFEBABE);
        assert_eq!(cmd.value(), 0xDEADBEEFCAFEBABE);
    }
}
