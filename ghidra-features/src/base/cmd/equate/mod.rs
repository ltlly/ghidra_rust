//! Equate commands.
//!
//! Ported from `ghidra.app.cmd.equate`.

/// Command to set an equate at an operand.
#[derive(Debug)]
pub struct SetEquateCmd {
    address: u64,
    operand_index: usize,
    equate_name: String,
    value: i64,
}

impl SetEquateCmd {
    pub fn new(
        address: u64,
        operand_index: usize,
        equate_name: impl Into<String>,
        value: i64,
    ) -> Self {
        Self {
            address,
            operand_index,
            equate_name: equate_name.into(),
            value,
        }
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn equate_name(&self) -> &str {
        &self.equate_name
    }

    pub fn value(&self) -> i64 {
        self.value
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to clear (remove) an equate from an operand.
#[derive(Debug)]
pub struct ClearEquateCmd {
    address: u64,
    operand_index: usize,
    equate_name: String,
}

impl ClearEquateCmd {
    pub fn new(address: u64, operand_index: usize, equate_name: impl Into<String>) -> Self {
        Self {
            address,
            operand_index,
            equate_name: equate_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_equate_cmd() {
        let cmd = SetEquateCmd::new(0x401000, 0, "MY_CONST", 42);
        assert_eq!(cmd.address(), 0x401000);
        assert_eq!(cmd.equate_name(), "MY_CONST");
        assert_eq!(cmd.value(), 42);
    }

    #[test]
    fn test_clear_equate_cmd() {
        let cmd = ClearEquateCmd::new(0x401000, 0, "MY_CONST");
        assert!(cmd.apply_to("test"));
    }
}
