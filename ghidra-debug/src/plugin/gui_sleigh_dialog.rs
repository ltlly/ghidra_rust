//! Sleigh expression input dialog data models.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.breakpoint` package.
//!
//! These types model the data structures used by the Sleigh expression
//! input dialogs for placing breakpoints and editing semantic breakpoints.

use serde::{Deserialize, Serialize};

/// The type of Sleigh expression input.
///
/// Ported from Ghidra's `AbstractDebuggerSleighInputDialog`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SleighInputType {
    /// A breakpoint address expression.
    BreakpointExpression,
    /// A semantic breakpoint condition.
    SemanticCondition,
    /// A register watch expression.
    RegisterWatch,
    /// A memory access expression.
    MemoryAccess,
}

impl Default for SleighInputType {
    fn default() -> Self {
        Self::BreakpointExpression
    }
}

impl std::fmt::Display for SleighInputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BreakpointExpression => write!(f, "Breakpoint Expression"),
            Self::SemanticCondition => write!(f, "Semantic Condition"),
            Self::RegisterWatch => write!(f, "Register Watch"),
            Self::MemoryAccess => write!(f, "Memory Access"),
        }
    }
}

/// The result of a Sleigh expression input dialog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SleighInputResult {
    /// The expression entered by the user.
    pub expression: String,
    /// The type of input.
    pub input_type: SleighInputType,
    /// Whether the expression was validated.
    pub validated: bool,
    /// Validation error message, if any.
    pub validation_error: Option<String>,
}

impl SleighInputResult {
    /// Create a new Sleigh input result.
    pub fn new(expression: impl Into<String>, input_type: SleighInputType) -> Self {
        Self {
            expression: expression.into(),
            input_type,
            validated: false,
            validation_error: None,
        }
    }

    /// Mark the result as successfully validated.
    pub fn with_validated(mut self) -> Self {
        self.validated = true;
        self.validation_error = None;
        self
    }

    /// Mark the result as having a validation error.
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.validated = false;
        self.validation_error = Some(error.into());
        self
    }
}

/// Configuration for a Sleigh expression input dialog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SleighInputConfig {
    /// The title of the dialog.
    pub title: String,
    /// The prompt message.
    pub prompt: String,
    /// The type of input expected.
    pub input_type: SleighInputType,
    /// The default expression value.
    pub default_value: Option<String>,
    /// Whether to show a preview/evaluation result.
    pub show_preview: bool,
    /// Help anchor for the dialog.
    pub help_anchor: Option<String>,
}

impl SleighInputConfig {
    /// Create a new config for a breakpoint expression dialog.
    pub fn breakpoint_expression(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            prompt: "Enter breakpoint expression:".to_string(),
            input_type: SleighInputType::BreakpointExpression,
            default_value: None,
            show_preview: true,
            help_anchor: Some("breakpoint_expression".to_string()),
        }
    }

    /// Create a new config for a semantic condition dialog.
    pub fn semantic_condition(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            prompt: "Enter semantic condition:".to_string(),
            input_type: SleighInputType::SemanticCondition,
            default_value: None,
            show_preview: true,
            help_anchor: Some("semantic_condition".to_string()),
        }
    }

    /// Set the default value.
    pub fn with_default(mut self, value: impl Into<String>) -> Self {
        self.default_value = Some(value.into());
        self
    }
}

/// A place breakpoint dialog result.
///
/// Ported from Ghidra's `DebuggerPlaceBreakpointDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceBreakpointDialogResult {
    /// The breakpoint address expression.
    pub address_expression: String,
    /// Whether this is a software breakpoint.
    pub software: bool,
    /// Whether this is a hardware breakpoint.
    pub hardware: bool,
    /// Whether this is a read watchpoint.
    pub read_watchpoint: bool,
    /// Whether this is a write watchpoint.
    pub write_watchpoint: bool,
    /// Whether this is an access watchpoint.
    pub access_watchpoint: bool,
    /// The size of the breakpoint in bytes.
    pub size: u64,
    /// The condition expression, if any.
    pub condition: Option<String>,
    /// The command to execute when hit, if any.
    pub hit_command: Option<String>,
}

impl PlaceBreakpointDialogResult {
    /// Create a new result with a software breakpoint at the given expression.
    pub fn software(expression: impl Into<String>) -> Self {
        Self {
            address_expression: expression.into(),
            software: true,
            hardware: false,
            read_watchpoint: false,
            write_watchpoint: false,
            access_watchpoint: false,
            size: 1,
            condition: None,
            hit_command: None,
        }
    }

    /// Create a new result with a hardware breakpoint at the given expression.
    pub fn hardware(expression: impl Into<String>) -> Self {
        Self {
            address_expression: expression.into(),
            software: false,
            hardware: true,
            read_watchpoint: false,
            write_watchpoint: false,
            access_watchpoint: false,
            size: 1,
            condition: None,
            hit_command: None,
        }
    }

    /// Set the breakpoint size.
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// Set the condition expression.
    pub fn with_condition(mut self, condition: impl Into<String>) -> Self {
        self.condition = Some(condition.into());
        self
    }

    /// Get the breakpoint kinds as a bitfield.
    pub fn kind_flags(&self) -> u32 {
        let mut flags = 0u32;
        if self.software { flags |= 0x01; }
        if self.hardware { flags |= 0x02; }
        if self.read_watchpoint { flags |= 0x04; }
        if self.write_watchpoint { flags |= 0x08; }
        if self.access_watchpoint { flags |= 0x10; }
        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sleigh_input_type_display() {
        assert_eq!(SleighInputType::BreakpointExpression.to_string(), "Breakpoint Expression");
        assert_eq!(SleighInputType::SemanticCondition.to_string(), "Semantic Condition");
        assert_eq!(SleighInputType::RegisterWatch.to_string(), "Register Watch");
        assert_eq!(SleighInputType::MemoryAccess.to_string(), "Memory Access");
    }

    #[test]
    fn test_sleigh_input_result() {
        let result = SleighInputResult::new("RAX == 0x42", SleighInputType::BreakpointExpression)
            .with_validated();
        assert!(result.validated);
        assert!(result.validation_error.is_none());
        assert_eq!(result.expression, "RAX == 0x42");
    }

    #[test]
    fn test_sleigh_input_result_with_error() {
        let result = SleighInputResult::new("bad expr", SleighInputType::SemanticCondition)
            .with_error("Syntax error at position 4");
        assert!(!result.validated);
        assert_eq!(result.validation_error.as_deref(), Some("Syntax error at position 4"));
    }

    #[test]
    fn test_sleigh_input_config() {
        let config = SleighInputConfig::breakpoint_expression("Add Breakpoint")
            .with_default("0x401000");
        assert_eq!(config.title, "Add Breakpoint");
        assert_eq!(config.input_type, SleighInputType::BreakpointExpression);
        assert_eq!(config.default_value.as_deref(), Some("0x401000"));
        assert!(config.show_preview);
    }

    #[test]
    fn test_place_breakpoint_dialog_result() {
        let result = PlaceBreakpointDialogResult::software("0x401000")
            .with_size(4)
            .with_condition("RAX == 0");
        assert!(result.software);
        assert!(!result.hardware);
        assert_eq!(result.size, 4);
        assert_eq!(result.condition.as_deref(), Some("RAX == 0"));
    }

    #[test]
    fn test_place_breakpoint_kind_flags() {
        let sw = PlaceBreakpointDialogResult::software("0x401000");
        assert_eq!(sw.kind_flags(), 0x01);

        let hw = PlaceBreakpointDialogResult::hardware("0x401000");
        assert_eq!(hw.kind_flags(), 0x02);

        let mut multi = PlaceBreakpointDialogResult::software("0x401000");
        multi.write_watchpoint = true;
        assert_eq!(multi.kind_flags(), 0x01 | 0x08);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let config = SleighInputConfig::semantic_condition("Edit Condition")
            .with_default("true");
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SleighInputConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.title, "Edit Condition");
    }
}
