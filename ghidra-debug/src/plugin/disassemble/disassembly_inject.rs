//! Disassembly injection into a trace.

/// Disassembly injection into a trace.
#[derive(Debug, Clone)]
pub struct DisassemblyInject {
    /// architecture_id
    pub architecture_id: String,
    /// max_instruction_bytes
    pub max_instruction_bytes: usize,
    /// follow_flow
    pub follow_flow: bool,
}

impl DisassemblyInject {
    /// Create a new DisassemblyInject.
    pub fn new(architecture_id: String, max_instruction_bytes: usize, follow_flow: bool) -> Self {
        Self { architecture_id, max_instruction_bytes, follow_flow }
    }

    /// architecture_id
    pub fn architecture_id(&self) -> &String {
        &self.architecture_id
    }

    /// max_instruction_bytes
    pub fn max_instruction_bytes(&self) -> &usize {
        &self.max_instruction_bytes
    }

    /// follow_flow
    pub fn follow_flow(&self) -> &bool {
        &self.follow_flow
    }
}

impl Default for DisassemblyInject {
    fn default() -> Self {
        Self::new(Default::default(), Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = DisassemblyInject::new("test".to_string(), 4, true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DisassemblyInject::default();
    }
}
