//! P-code program representation.
//!
//! Ported from Java: `ghidra.pcode.exec.PcodeProgram`.
//!
//! A `PcodeProgram` is a list of P-code operations together with a map of
//! expected userops. It can be executed by a `PcodeExecutor`.

use std::collections::HashMap;

use ghidra_decompile::pcode::PcodeOperation;

/// A P-code program to be executed.
///
/// Contains the list of P-code operations and a mapping of userop numbers to names.
#[derive(Debug, Clone)]
pub struct PcodeProgram {
    /// The P-code operations in this program.
    code: Vec<PcodeOperation>,

    /// Map of userop numbers to their names.
    userop_names: HashMap<u32, String>,

    /// Description of this program (for display purposes).
    description: String,
}

impl PcodeProgram {
    /// Create a new P-code program with the given operations.
    pub fn new(code: Vec<PcodeOperation>) -> Self {
        Self {
            code,
            userop_names: HashMap::new(),
            description: String::new(),
        }
    }

    /// Create a new P-code program with operations and userop names.
    pub fn with_userops(
        code: Vec<PcodeOperation>,
        userop_names: HashMap<u32, String>,
    ) -> Self {
        Self {
            code,
            userop_names,
            description: String::new(),
        }
    }

    /// Set the description of this program.
    pub fn set_description(&mut self, desc: impl Into<String>) {
        self.description = desc.into();
    }

    /// Get the description of this program.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the P-code operations.
    pub fn code(&self) -> &[PcodeOperation] {
        &self.code
    }

    /// Get the userop names map.
    pub fn userop_names(&self) -> &HashMap<u32, String> {
        &self.userop_names
    }

    /// Get the name of a userop by number.
    pub fn get_userop_name(&self, op_no: u32) -> Option<&str> {
        self.userop_names.get(&op_no).map(|s| s.as_str())
    }

    /// Get the userop number for a given name.
    ///
    /// This exhaustively searches the userop names.
    pub fn get_userop_number(&self, name: &str) -> Option<u32> {
        for (&num, op_name) in &self.userop_names {
            if op_name == name {
                return Some(num);
            }
        }
        None
    }

    /// Get the number of operations in this program.
    pub fn len(&self) -> usize {
        self.code.len()
    }

    /// Check if this program is empty.
    pub fn is_empty(&self) -> bool {
        self.code.is_empty()
    }

    /// Get the operation at the given index.
    pub fn get(&self, index: usize) -> Option<&PcodeOperation> {
        self.code.get(index)
    }

    /// Format this program as a human-readable string.
    pub fn format(&self) -> String {
        let mut result = format!("PcodeProgram ({} ops):\n", self.code.len());
        for (i, op) in self.code.iter().enumerate() {
            result.push_str(&format!("  {}: {:?}\n", i, op));
        }
        result
    }
}

impl std::fmt::Display for PcodeProgram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.format())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_decompile::pcode::{OpCode, PcodeOperation, Varnode};

    fn make_test_ops() -> Vec<PcodeOperation> {
        vec![
            PcodeOperation::new_unannotated(
                OpCode::COPY,
                Some(Varnode::constant(0, 8)),
                vec![Varnode::constant(42, 8)],
            ),
            PcodeOperation::new_unannotated(
                OpCode::INT_ADD,
                Some(Varnode::constant(0, 8)),
                vec![Varnode::constant(0, 8), Varnode::constant(8, 8)],
            ),
        ]
    }

    #[test]
    fn test_program_creation() {
        let ops = make_test_ops();
        let prog = PcodeProgram::new(ops);
        assert_eq!(prog.len(), 2);
        assert!(!prog.is_empty());
    }

    #[test]
    fn test_program_with_userops() {
        let ops = make_test_ops();
        let mut userops = HashMap::new();
        userops.insert(0, "my_userop".to_string());
        let prog = PcodeProgram::with_userops(ops, userops);
        assert_eq!(prog.get_userop_name(0), Some("my_userop"));
        assert_eq!(prog.get_userop_number("my_userop"), Some(0));
    }

    #[test]
    fn test_program_get() {
        let ops = make_test_ops();
        let prog = PcodeProgram::new(ops);
        assert!(prog.get(0).is_some());
        assert!(prog.get(99).is_none());
    }

    #[test]
    fn test_program_format() {
        let ops = make_test_ops();
        let prog = PcodeProgram::new(ops);
        let formatted = prog.format();
        assert!(formatted.contains("2 ops"));
    }
}
