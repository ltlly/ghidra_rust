//! Symbolic Z3 GUI components.
//!
//! Ported from the `ghidra.symz3.gui` package in the SymbolicSummaryZ3
//! extension.
//!
//! Provides display field factories for showing symbolic Z3 values
//! in the Ghidra listing and debugger register views.

use super::model::SymValueZ3;
use std::fmt;

/// A field location for displaying symbolic values.
///
/// Ported from `SymZ3FieldLocation.java`.
///
/// Represents a location in the listing where a symbolic value
/// is displayed, combining an address with the symbolic expression.
#[derive(Debug, Clone)]
pub struct SymZ3FieldLocation {
    /// The address this field applies to.
    pub address: u64,
    /// The symbolic value at this location.
    pub value: SymValueZ3,
    /// Display column index.
    pub column: usize,
}

impl SymZ3FieldLocation {
    /// Create a new symbolic field location.
    pub fn new(address: u64, value: SymValueZ3, column: usize) -> Self {
        Self {
            address,
            value,
            column,
        }
    }

    /// Get the display text for this field.
    pub fn display_text(&self) -> String {
        self.value.to_string()
    }
}

impl fmt::Display for SymZ3FieldLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}: {}", self.address, self.value)
    }
}

/// A factory for creating symbolic value display fields.
///
/// Ported from `SymZ3FieldFactory.java`.
///
/// In the Ghidra listing, symbolic values from the Z3 emulator are
/// displayed in a custom column alongside the disassembly. This factory
/// manages the creation and rendering of these fields.
#[derive(Debug)]
pub struct SymZ3FieldFactory {
    /// The field name.
    pub name: String,
    /// Width of the field in characters.
    pub width: u32,
    /// Whether the factory is enabled.
    pub enabled: bool,
}

impl SymZ3FieldFactory {
    /// Create a new symbolic field factory.
    pub fn new() -> Self {
        Self {
            name: "SymZ3".to_string(),
            width: 40,
            enabled: true,
        }
    }

    /// Format a symbolic value for display.
    ///
    /// Truncates long expressions to fit within the configured width.
    pub fn format_value(&self, value: &SymValueZ3) -> String {
        let text = value.to_string();
        if text.len() > self.width as usize {
            format!("{}...", &text[..self.width as usize - 3])
        } else {
            text
        }
    }

    /// Check if the factory is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the factory.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Default for SymZ3FieldFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// Column factory for displaying Z3 symbolic register values.
///
/// Ported from `SymZ3DebuggerRegisterColumnFactory.java`.
///
/// Provides columns in the debugger register view that show the
/// symbolic expression associated with each register.
#[derive(Debug)]
pub struct SymZ3DebuggerRegisterColumnFactory {
    /// Column name.
    pub name: String,
    /// Whether to show the raw Z3 expression.
    pub show_raw_expression: bool,
}

impl SymZ3DebuggerRegisterColumnFactory {
    /// Create a new register column factory.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            show_raw_expression: false,
        }
    }

    /// Format a register value for display.
    pub fn format_register_value(&self, value: &SymValueZ3) -> String {
        if self.show_raw_expression {
            value.to_string()
        } else {
            // Simplified display: show a human-readable summary
            value.simplified_string()
        }
    }
}

/// Panel for displaying Z3 summary information.
///
/// Ported from `Z3SummaryInformationPanel.java`.
///
/// Shows a summary of the symbolic execution state including
/// register and memory constraints.
#[derive(Debug)]
pub struct Z3SummaryInformationPanel {
    /// Panel title.
    pub title: String,
    /// Registered register summaries (register_name -> expression).
    pub register_summaries: Vec<(String, String)>,
    /// Memory constraint count.
    pub memory_constraints: usize,
}

impl Z3SummaryInformationPanel {
    /// Create a new summary panel.
    pub fn new() -> Self {
        Self {
            title: "Z3 Symbolic Summary".to_string(),
            register_summaries: Vec::new(),
            memory_constraints: 0,
        }
    }

    /// Add a register summary entry.
    pub fn add_register_summary(
        &mut self,
        register: impl Into<String>,
        expression: impl Into<String>,
    ) {
        self.register_summaries
            .push((register.into(), expression.into()));
    }

    /// Set the memory constraint count.
    pub fn set_memory_constraints(&mut self, count: usize) {
        self.memory_constraints = count;
    }

    /// Generate a text summary of the panel contents.
    pub fn summary_text(&self) -> String {
        let mut text = format!("{}\n", self.title);
        text.push_str(&format!(
            "Register constraints: {}\n",
            self.register_summaries.len()
        ));
        text.push_str(&format!(
            "Memory constraints: {}\n",
            self.memory_constraints
        ));
        text.push('\n');
        for (reg, expr) in &self.register_summaries {
            text.push_str(&format!("  {reg} = {expr}\n"));
        }
        text
    }
}

impl Default for Z3SummaryInformationPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// Panel for displaying the p-code execution log with symbolic annotations.
///
/// Ported from `Z3SummaryPcodeLogPanel.java`.
#[derive(Debug)]
pub struct Z3SummaryPcodeLogPanel {
    /// Log entries: (address, pcode_op_description, symbolic_state).
    pub entries: Vec<(u64, String, String)>,
}

impl Z3SummaryPcodeLogPanel {
    /// Create a new p-code log panel.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a log entry.
    pub fn add_entry(
        &mut self,
        address: u64,
        pcode_op: impl Into<String>,
        symbolic_state: impl Into<String>,
    ) {
        self.entries
            .push((address, pcode_op.into(), symbolic_state.into()));
    }

    /// Get the number of log entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Generate a text representation of the log.
    pub fn to_text(&self) -> String {
        self.entries
            .iter()
            .map(|(addr, op, state)| format!("0x{addr:08x}: {op} | {state}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for Z3SummaryPcodeLogPanel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_location() {
        let loc = SymZ3FieldLocation::new(0x1000, SymValueZ3::from_bitvec("RAX"), 0);
        assert_eq!(loc.address, 0x1000);
        assert!(loc.display_text().contains("RAX"));
        assert!(loc.to_string().contains("0x1000"));
    }

    #[test]
    fn test_field_factory_format() {
        let factory = SymZ3FieldFactory::new();
        let val = SymValueZ3::from_bitvec("x");
        let text = factory.format_value(&val);
        assert!(text.contains("x"));
    }

    #[test]
    fn test_field_factory_truncation() {
        let mut factory = SymZ3FieldFactory::new();
        factory.width = 10;
        let long_expr = "a_very_long_symbolic_expression_that_exceeds_width";
        let val = SymValueZ3::from_bitvec(long_expr);
        let text = factory.format_value(&val);
        assert!(text.len() <= 10);
        assert!(text.ends_with("..."));
    }

    #[test]
    fn test_field_factory_enabled() {
        let mut factory = SymZ3FieldFactory::new();
        assert!(factory.is_enabled());
        factory.set_enabled(false);
        assert!(!factory.is_enabled());
    }

    #[test]
    fn test_debugger_register_column() {
        let factory = SymZ3DebuggerRegisterColumnFactory::new("RAX");
        let val = SymValueZ3::from_bitvec("bv_add(RAX_init, 0x10)");
        let display = factory.format_register_value(&val);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_summary_panel() {
        let mut panel = Z3SummaryInformationPanel::new();
        panel.add_register_summary("RAX", "bv_add(RAX_init, 1)");
        panel.add_register_summary("RBX", "RBX_init");
        panel.set_memory_constraints(42);
        let text = panel.summary_text();
        assert!(text.contains("RAX"));
        assert!(text.contains("42"));
    }

    #[test]
    fn test_pcode_log_panel() {
        let mut panel = Z3SummaryPcodeLogPanel::new();
        assert!(panel.is_empty());
        panel.add_entry(0x1000, "COPY RAX, 0x42", "RAX = 0x42");
        panel.add_entry(0x1004, "ADD RAX, RBX", "RAX = bv_add(0x42, RBX)");
        assert_eq!(panel.len(), 2);
        let text = panel.to_text();
        assert!(text.contains("0x00001000"));
        assert!(text.contains("COPY"));
    }
}
