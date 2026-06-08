//! Register dropdown selection data model.
//!
//! Ported from `RegisterDropDownSelectionDataModel.java` in
//! `ghidra.app.plugin.core.function.editor`.
//!
//! Provides a data model for a dropdown text field that allows the user
//! to select a register by name.  The model supports prefix-based
//! search filtering.

use std::fmt;

/// A simplified register descriptor for the dropdown model.
///
/// In Ghidra this is `ghidra.program.model.lang.Register`.
/// Here we keep only the fields needed for display and search.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegisterDescriptor {
    /// The register name (e.g., "RAX", "EAX", "XMM0").
    name: String,
    /// The register size in bytes.
    size: usize,
    /// The parent register name, if this is a sub-register.
    parent: Option<String>,
    /// The bit offset within the parent register.
    bit_offset: usize,
}

impl RegisterDescriptor {
    /// Creates a new register descriptor.
    pub fn new(name: impl Into<String>, size: usize) -> Self {
        Self {
            name: name.into(),
            size,
            parent: None,
            bit_offset: 0,
        }
    }

    /// Creates a sub-register descriptor.
    pub fn sub_register(
        name: impl Into<String>,
        size: usize,
        parent: impl Into<String>,
        bit_offset: usize,
    ) -> Self {
        Self {
            name: name.into(),
            size,
            parent: Some(parent.into()),
            bit_offset,
        }
    }

    /// Returns the register name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the register size in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the parent register name.
    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    /// Returns the bit offset within the parent register.
    pub fn bit_offset(&self) -> usize {
        self.bit_offset
    }

    /// Whether this is a sub-register.
    pub fn is_sub_register(&self) -> bool {
        self.parent.is_some()
    }
}

impl fmt::Display for RegisterDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Search mode for the dropdown data model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchMode {
    /// Match entries that start with the search text.
    StartsWith,
    /// Match entries that contain the search text.
    Contains,
}

/// Data model for a register dropdown selection text field.
///
/// Ported from `RegisterDropDownSelectionDataModel.java`.  Provides
/// prefix-based search over a list of registers, returning matching
/// entries for display in a dropdown.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::editor::register_dropdown::*;
///
/// let registers = vec![
///     RegisterDescriptor::new("RAX", 8),
///     RegisterDescriptor::new("RBX", 8),
///     RegisterDescriptor::new("RCX", 8),
///     RegisterDescriptor::new("EAX", 4),
/// ];
/// let model = RegisterDropDownModel::new(registers);
///
/// let matches = model.get_matching("RA", SearchMode::StartsWith);
/// assert_eq!(matches.len(), 1);
/// assert_eq!(matches[0].name(), "RAX");
/// ```
#[derive(Debug, Clone)]
pub struct RegisterDropDownModel {
    /// The full list of registers.
    registers: Vec<RegisterDescriptor>,
}

impl RegisterDropDownModel {
    /// Creates a new model with the given registers.
    pub fn new(registers: Vec<RegisterDescriptor>) -> Self {
        Self { registers }
    }

    /// Returns the total number of registers.
    pub fn register_count(&self) -> usize {
        self.registers.len()
    }

    /// Returns all registers.
    pub fn registers(&self) -> &[RegisterDescriptor] {
        &self.registers
    }

    /// Returns the display text for a register.
    pub fn display_text(reg: &RegisterDescriptor) -> &str {
        &reg.name
    }

    /// Returns registers matching the given search text.
    ///
    /// If the search text is blank, all registers are returned.
    pub fn get_matching(&self, search_text: &str, mode: SearchMode) -> Vec<&RegisterDescriptor> {
        if search_text.trim().is_empty() {
            return self.registers.iter().collect();
        }

        let lower = search_text.to_lowercase();
        self.registers
            .iter()
            .filter(|reg| {
                let reg_lower = reg.name.to_lowercase();
                match mode {
                    SearchMode::StartsWith => reg_lower.starts_with(&lower),
                    SearchMode::Contains => reg_lower.contains(&lower),
                }
            })
            .collect()
    }

    /// Returns the index of the first register whose name starts with
    /// the given search text.
    ///
    /// Returns 0 if no match is found.
    pub fn get_index_of_first_match(&self, data: &[RegisterDescriptor], search_text: &str) -> usize {
        let lower = search_text.to_lowercase();
        data.iter()
            .position(|reg| reg.name.to_lowercase().starts_with(&lower))
            .unwrap_or(0)
    }

    /// Returns a register by name (case-insensitive exact match).
    pub fn find_by_name(&self, name: &str) -> Option<&RegisterDescriptor> {
        let lower = name.to_lowercase();
        self.registers.iter().find(|r| r.name.to_lowercase() == lower)
    }

    /// Returns all registers that are sub-registers of the given parent.
    pub fn sub_registers_of(&self, parent_name: &str) -> Vec<&RegisterDescriptor> {
        self.registers
            .iter()
            .filter(|r| r.parent.as_deref() == Some(parent_name))
            .collect()
    }
}

impl Default for RegisterDropDownModel {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

/// Creates a standard x86-64 register set.
pub fn x86_64_registers() -> Vec<RegisterDescriptor> {
    vec![
        // 64-bit general purpose
        RegisterDescriptor::new("RAX", 8),
        RegisterDescriptor::new("RBX", 8),
        RegisterDescriptor::new("RCX", 8),
        RegisterDescriptor::new("RDX", 8),
        RegisterDescriptor::new("RSI", 8),
        RegisterDescriptor::new("RDI", 8),
        RegisterDescriptor::new("RBP", 8),
        RegisterDescriptor::new("RSP", 8),
        RegisterDescriptor::new("R8", 8),
        RegisterDescriptor::new("R9", 8),
        RegisterDescriptor::new("R10", 8),
        RegisterDescriptor::new("R11", 8),
        RegisterDescriptor::new("R12", 8),
        RegisterDescriptor::new("R13", 8),
        RegisterDescriptor::new("R14", 8),
        RegisterDescriptor::new("R15", 8),
        // 32-bit sub-registers
        RegisterDescriptor::sub_register("EAX", 4, "RAX", 0),
        RegisterDescriptor::sub_register("EBX", 4, "RBX", 0),
        RegisterDescriptor::sub_register("ECX", 4, "RCX", 0),
        RegisterDescriptor::sub_register("EDX", 4, "RDX", 0),
        RegisterDescriptor::sub_register("ESI", 4, "RSI", 0),
        RegisterDescriptor::sub_register("EDI", 4, "RDI", 0),
        RegisterDescriptor::sub_register("EBP", 4, "RBP", 0),
        RegisterDescriptor::sub_register("ESP", 4, "RSP", 0),
        // 16-bit sub-registers
        RegisterDescriptor::sub_register("AX", 2, "RAX", 0),
        RegisterDescriptor::sub_register("BX", 2, "RBX", 0),
        RegisterDescriptor::sub_register("CX", 2, "RCX", 0),
        RegisterDescriptor::sub_register("DX", 2, "RDX", 0),
        // 8-bit sub-registers
        RegisterDescriptor::sub_register("AL", 1, "RAX", 0),
        RegisterDescriptor::sub_register("BL", 1, "RBX", 0),
        RegisterDescriptor::sub_register("CL", 1, "RCX", 0),
        RegisterDescriptor::sub_register("DL", 1, "RDX", 0),
    ]
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_registers() -> Vec<RegisterDescriptor> {
        vec![
            RegisterDescriptor::new("RAX", 8),
            RegisterDescriptor::new("RBX", 8),
            RegisterDescriptor::new("RCX", 8),
            RegisterDescriptor::new("EAX", 4),
            RegisterDescriptor::new("EBX", 4),
        ]
    }

    #[test]
    fn test_model_creation() {
        let model = RegisterDropDownModel::new(sample_registers());
        assert_eq!(model.register_count(), 5);
    }

    #[test]
    fn test_get_matching_starts_with() {
        let model = RegisterDropDownModel::new(sample_registers());
        let matches = model.get_matching("RA", SearchMode::StartsWith);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name(), "RAX");
    }

    #[test]
    fn test_get_matching_starts_with_case_insensitive() {
        let model = RegisterDropDownModel::new(sample_registers());
        let matches = model.get_matching("rax", SearchMode::StartsWith);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name(), "RAX");
    }

    #[test]
    fn test_get_matching_contains() {
        let model = RegisterDropDownModel::new(sample_registers());
        let matches = model.get_matching("AX", SearchMode::Contains);
        assert_eq!(matches.len(), 2); // RAX and EAX
    }

    #[test]
    fn test_get_matching_empty() {
        let model = RegisterDropDownModel::new(sample_registers());
        let matches = model.get_matching("", SearchMode::StartsWith);
        assert_eq!(matches.len(), 5);
    }

    #[test]
    fn test_get_matching_no_match() {
        let model = RegisterDropDownModel::new(sample_registers());
        let matches = model.get_matching("XYZ", SearchMode::StartsWith);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_find_by_name() {
        let model = RegisterDropDownModel::new(sample_registers());
        assert!(model.find_by_name("RAX").is_some());
        assert!(model.find_by_name("rax").is_some());
        assert!(model.find_by_name("MISSING").is_none());
    }

    #[test]
    fn test_sub_registers_of() {
        let regs = x86_64_registers();
        let model = RegisterDropDownModel::new(regs);
        let eax_subs = model.sub_registers_of("RAX");
        // EAX and AX and AL are sub-registers of RAX
        assert!(!eax_subs.is_empty());
    }

    #[test]
    fn test_display_text() {
        let reg = RegisterDescriptor::new("RAX", 8);
        assert_eq!(RegisterDropDownModel::display_text(&reg), "RAX");
    }

    #[test]
    fn test_register_descriptor() {
        let reg = RegisterDescriptor::new("RAX", 8);
        assert_eq!(reg.name(), "RAX");
        assert_eq!(reg.size(), 8);
        assert!(!reg.is_sub_register());
        assert!(reg.parent().is_none());
    }

    #[test]
    fn test_sub_register_descriptor() {
        let reg = RegisterDescriptor::sub_register("EAX", 4, "RAX", 0);
        assert_eq!(reg.name(), "EAX");
        assert_eq!(reg.size(), 4);
        assert!(reg.is_sub_register());
        assert_eq!(reg.parent(), Some("RAX"));
        assert_eq!(reg.bit_offset(), 0);
    }

    #[test]
    fn test_register_display() {
        let reg = RegisterDescriptor::new("RAX", 8);
        assert_eq!(format!("{}", reg), "RAX");
    }

    #[test]
    fn test_get_index_of_first_match() {
        let model = RegisterDropDownModel::new(sample_registers());
        let regs = sample_registers();
        assert_eq!(model.get_index_of_first_match(&regs, "RBX"), 1);
        assert_eq!(model.get_index_of_first_match(&regs, "EAX"), 3);
        assert_eq!(model.get_index_of_first_match(&regs, "ZZZ"), 0);
    }

    #[test]
    fn test_x86_64_registers() {
        let regs = x86_64_registers();
        assert!(regs.len() > 20);
        let model = RegisterDropDownModel::new(regs);
        assert!(model.find_by_name("RAX").is_some());
        assert!(model.find_by_name("EAX").is_some());
        assert!(model.find_by_name("AL").is_some());
    }

    #[test]
    fn test_default_model() {
        let model = RegisterDropDownModel::default();
        assert_eq!(model.register_count(), 0);
    }

    #[test]
    fn test_search_mode_partial_prefix() {
        let model = RegisterDropDownModel::new(sample_registers());
        let matches = model.get_matching("E", SearchMode::StartsWith);
        assert_eq!(matches.len(), 2); // EAX, EBX
    }
}
