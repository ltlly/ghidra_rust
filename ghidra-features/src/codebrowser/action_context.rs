//! Action context types for the code browser.
//!
//! Ports `ghidra.app.plugin.core.codebrowser.CodeViewerActionContext` and
//! `ghidra.app.plugin.core.codebrowser.OtherPanelContext`.

use std::fmt;

/// The action context when the user interacts with the code viewer listing.
///
/// Carries the address, program, function, and selection state that an
/// action needs to operate within the code browser.
///
/// Ported from Ghidra's `CodeViewerActionContext`.
#[derive(Debug, Clone, Default)]
pub struct CodeViewerActionContext {
    /// The program name/path.
    pub program: Option<String>,
    /// The address under the cursor (hex string, e.g. "0x100000").
    pub address: Option<String>,
    /// The name of the containing function, if any.
    pub function_name: Option<String>,
    /// Whether the user has made a selection (non-empty address set).
    pub has_selection: bool,
    /// Start address of the selection (if any).
    pub selection_start: Option<String>,
    /// End address of the selection (if any).
    pub selection_end: Option<String>,
    /// The name of the component that owns this context.
    pub provider_name: String,
}

impl CodeViewerActionContext {
    /// Create a new action context.
    pub fn new(provider_name: impl Into<String>) -> Self {
        Self {
            provider_name: provider_name.into(),
            ..Default::default()
        }
    }

    /// Builder: set the program.
    pub fn with_program(mut self, program: impl Into<String>) -> Self {
        self.program = Some(program.into());
        self
    }

    /// Builder: set the address.
    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.address = Some(address.into());
        self
    }

    /// Builder: set the function name.
    pub fn with_function(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }

    /// Builder: set the selection range.
    pub fn with_selection(mut self, start: impl Into<String>, end: impl Into<String>) -> Self {
        self.has_selection = true;
        self.selection_start = Some(start.into());
        self.selection_end = Some(end.into());
        self
    }

    /// Whether there is an active program context.
    pub fn has_program(&self) -> bool {
        self.program.is_some()
    }

    /// Whether there is an address context.
    pub fn has_address(&self) -> bool {
        self.address.is_some()
    }

    /// Whether there is a function context.
    pub fn has_function(&self) -> bool {
        self.function_name.is_some()
    }

    /// Whether a selection is active.
    pub fn has_selection(&self) -> bool {
        self.has_selection
    }
}

impl fmt::Display for CodeViewerActionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CodeViewerActionContext(addr={:?}, program={:?}, func={:?})",
            self.address, self.program, self.function_name
        )
    }
}

/// Context used when an action is invoked from the "other" (secondary) panel
/// in a dual-listing layout.
///
/// Ported from Ghidra's `OtherPanelContext`.
#[derive(Debug, Clone, Default)]
pub struct OtherPanelContext {
    /// The program name shown in the other panel.
    pub program: Option<String>,
    /// The address under the cursor in the other panel.
    pub address: Option<String>,
}

impl OtherPanelContext {
    /// Create a new other-panel context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set the program.
    pub fn with_program(mut self, program: impl Into<String>) -> Self {
        self.program = Some(program.into());
        self
    }

    /// Builder: set the address.
    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.address = Some(address.into());
        self
    }
}

impl fmt::Display for OtherPanelContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OtherPanelContext(addr={:?}, program={:?})",
            self.address, self.program
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_viewer_action_context_builder() {
        let ctx = CodeViewerActionContext::new("CodeBrowser")
            .with_program("test.exe")
            .with_address("0x100000")
            .with_function("main");

        assert_eq!(ctx.provider_name, "CodeBrowser");
        assert!(ctx.has_program());
        assert!(ctx.has_address());
        assert!(ctx.has_function());
        assert!(!ctx.has_selection());
    }

    #[test]
    fn test_code_viewer_action_context_with_selection() {
        let ctx = CodeViewerActionContext::new("CodeBrowser")
            .with_selection("0x100000", "0x100100");

        assert!(ctx.has_selection());
        assert_eq!(ctx.selection_start.as_deref(), Some("0x100000"));
        assert_eq!(ctx.selection_end.as_deref(), Some("0x100100"));
    }

    #[test]
    fn test_code_viewer_action_context_default() {
        let ctx = CodeViewerActionContext::default();
        assert!(!ctx.has_program());
        assert!(!ctx.has_address());
        assert!(!ctx.has_function());
        assert!(!ctx.has_selection());
    }

    #[test]
    fn test_other_panel_context() {
        let ctx = OtherPanelContext::new()
            .with_program("other.exe")
            .with_address("0x200000");

        assert_eq!(ctx.program.as_deref(), Some("other.exe"));
        assert_eq!(ctx.address.as_deref(), Some("0x200000"));
    }

    #[test]
    fn test_display() {
        let ctx = CodeViewerActionContext::new("Viewer")
            .with_address("0xDEAD");
        let display = format!("{}", ctx);
        assert!(display.contains("0xDEAD"));
    }
}
