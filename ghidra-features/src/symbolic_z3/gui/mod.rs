//! GUI components for the Symbolic Summary Z3 extension.
//!
//! Provides panel and plugin types for viewing symbolic execution
//! summaries in Ghidra's UI.

// ---------------------------------------------------------------------------
// Z3SummaryPlugin
// ---------------------------------------------------------------------------

/// Plugin for viewing Z3 symbolic summaries.
///
/// Ported from `Z3SummaryPlugin.java`. Provides a dockable panel
/// that displays symbolic execution results including register
/// valuations, memory writes, and path conditions.
#[derive(Debug)]
pub struct Z3SummaryPlugin {
    /// Plugin name.
    name: String,
    /// Whether the plugin is enabled.
    enabled: bool,
    /// Summary text content.
    summary_text: String,
    /// Instruction log entries.
    instruction_log: Vec<String>,
    /// P-code log entries.
    pcode_log: Vec<String>,
}

impl Z3SummaryPlugin {
    /// Create a new Z3 summary plugin.
    pub fn new() -> Self {
        Self {
            name: "Z3 Summary".to_string(),
            enabled: true,
            summary_text: String::new(),
            instruction_log: Vec::new(),
            pcode_log: Vec::new(),
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the summary text.
    pub fn set_summary_text(&mut self, text: impl Into<String>) {
        self.summary_text = text.into();
    }

    /// Get the summary text.
    pub fn summary_text(&self) -> &str {
        &self.summary_text
    }

    /// Add an instruction log entry.
    pub fn add_instruction_log(&mut self, entry: impl Into<String>) {
        self.instruction_log.push(entry.into());
    }

    /// Get the instruction log.
    pub fn instruction_log(&self) -> &[String] {
        &self.instruction_log
    }

    /// Add a p-code log entry.
    pub fn add_pcode_log(&mut self, entry: impl Into<String>) {
        self.pcode_log.push(entry.into());
    }

    /// Get the p-code log.
    pub fn pcode_log(&self) -> &[String] {
        &self.pcode_log
    }

    /// Clear all logs and summary text.
    pub fn clear(&mut self) {
        self.summary_text.clear();
        self.instruction_log.clear();
        self.pcode_log.clear();
    }
}

impl Default for Z3SummaryPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Z3SummaryProvider
// ---------------------------------------------------------------------------

/// Provider for the Z3 summary panel.
///
/// Ported from `Z3SummaryProvider.java`. Manages the component that
/// displays symbolic execution results.
#[derive(Debug)]
pub struct Z3SummaryProvider {
    /// Provider name.
    name: String,
    /// Whether the panel is visible.
    visible: bool,
}

impl Z3SummaryProvider {
    /// Create a new summary provider.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            visible: false,
        }
    }

    /// Get the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the panel is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the panel visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Show the panel.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the panel.
    pub fn hide(&mut self) {
        self.visible = false;
    }
}

// ---------------------------------------------------------------------------
// SymZ3FieldFactory
// ---------------------------------------------------------------------------

/// Field factory for displaying symbolic values in the listing.
///
/// Ported from `SymZ3FieldFactory.java`. Creates field elements that
/// render symbolic Z3 expressions in the Ghidra listing view.
#[derive(Debug)]
pub struct SymZ3FieldFactory {
    /// Field name.
    name: String,
    /// Display width in characters.
    width: u32,
}

impl SymZ3FieldFactory {
    /// The field name constant.
    pub const FIELD_NAME: &'static str = "SymZ3";

    /// Create a new field factory.
    pub fn new() -> Self {
        Self {
            name: Self::FIELD_NAME.to_string(),
            width: 32,
        }
    }

    /// Get the field name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the display width.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Set the display width.
    pub fn set_width(&mut self, width: u32) {
        self.width = width;
    }

    /// Format a symbolic value for display.
    pub fn format_value(expr: &str, max_width: usize) -> String {
        if expr.len() <= max_width {
            expr.to_string()
        } else {
            format!("{}...", &expr[..max_width.saturating_sub(3)])
        }
    }
}

impl Default for SymZ3FieldFactory {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SymZ3FieldLocation
// ---------------------------------------------------------------------------

/// A location in the SymZ3 field.
///
/// Ported from `SymZ3FieldLocation.java`. Represents a position
/// within a symbolic value field in the listing.
#[derive(Debug, Clone)]
pub struct SymZ3FieldLocation {
    /// The program address.
    pub address: u64,
    /// Character offset within the field.
    pub char_offset: usize,
}

impl SymZ3FieldLocation {
    /// Create a new field location.
    pub fn new(address: u64, char_offset: usize) -> Self {
        Self {
            address,
            char_offset,
        }
    }
}

// ---------------------------------------------------------------------------
// HtmlCellRenderer (stub)
// ---------------------------------------------------------------------------

/// Renders HTML content in table cells.
///
/// Ported from `HtmlCellRenderer.java`.
#[derive(Debug)]
pub struct HtmlCellRenderer;

impl HtmlCellRenderer {
    /// Render a value as HTML.
    pub fn render_html(value: &str) -> String {
        format!("<html><body><pre>{value}</pre></body></html>")
    }
}

// ---------------------------------------------------------------------------
// MonospaceCellRenderer (stub)
// ---------------------------------------------------------------------------

/// Renders monospace text in table cells.
///
/// Ported from `MonospaceCellRenderer.java`.
#[derive(Debug)]
pub struct MonospaceCellRenderer;

impl MonospaceCellRenderer {
    /// Render a value in monospace format.
    pub fn render_monospace(value: &str) -> String {
        format!("<pre>{value}</pre>")
    }
}

// ---------------------------------------------------------------------------
// Z3SummaryInformationPanel
// ---------------------------------------------------------------------------

/// Panel displaying summary information.
///
/// Ported from `Z3SummaryInformationPanel.java`.
#[derive(Debug)]
pub struct Z3SummaryInformationPanel {
    /// Summary text content.
    content: String,
}

impl Z3SummaryInformationPanel {
    /// Create a new information panel.
    pub fn new() -> Self {
        Self {
            content: String::new(),
        }
    }

    /// Set the content.
    pub fn set_content(&mut self, content: impl Into<String>) {
        self.content = content.into();
    }

    /// Get the content.
    pub fn content(&self) -> &str {
        &self.content
    }
}

impl Default for Z3SummaryInformationPanel {
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
    fn test_z3_summary_plugin() {
        let mut plugin = Z3SummaryPlugin::new();
        assert_eq!(plugin.name(), "Z3 Summary");
        assert!(plugin.is_enabled());
        assert!(plugin.summary_text().is_empty());

        plugin.set_summary_text("RAX = #x42");
        assert_eq!(plugin.summary_text(), "RAX = #x42");

        plugin.add_instruction_log("0x401000: MOV RAX, 42");
        plugin.add_pcode_log("INT_ADD(RAX, RBX) -> RCX");
        assert_eq!(plugin.instruction_log().len(), 1);
        assert_eq!(plugin.pcode_log().len(), 1);

        plugin.clear();
        assert!(plugin.summary_text().is_empty());
        assert!(plugin.instruction_log().is_empty());
        assert!(plugin.pcode_log().is_empty());
    }

    #[test]
    fn test_z3_summary_provider() {
        let mut provider = Z3SummaryProvider::new("TestProvider");
        assert_eq!(provider.name(), "TestProvider");
        assert!(!provider.is_visible());

        provider.show();
        assert!(provider.is_visible());

        provider.hide();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_symz3_field_factory() {
        let factory = SymZ3FieldFactory::new();
        assert_eq!(factory.name(), "SymZ3");
        assert_eq!(factory.width(), 32);

        // Short value
        assert_eq!(SymZ3FieldFactory::format_value("RAX", 32), "RAX");

        // Long value gets truncated
        let long_expr = "A".repeat(50);
        let formatted = SymZ3FieldFactory::format_value(&long_expr, 10);
        assert!(formatted.len() <= 10);
        assert!(formatted.ends_with("..."));
    }

    #[test]
    fn test_symz3_field_location() {
        let loc = SymZ3FieldLocation::new(0x401000, 5);
        assert_eq!(loc.address, 0x401000);
        assert_eq!(loc.char_offset, 5);
    }

    #[test]
    fn test_html_cell_renderer() {
        let html = HtmlCellRenderer::render_html("test value");
        assert!(html.contains("<html>"));
        assert!(html.contains("test value"));
    }

    #[test]
    fn test_monospace_cell_renderer() {
        let text = MonospaceCellRenderer::render_monospace("RAX = 42");
        assert!(text.contains("<pre>"));
        assert!(text.contains("RAX = 42"));
    }

    #[test]
    fn test_information_panel() {
        let mut panel = Z3SummaryInformationPanel::new();
        assert!(panel.content().is_empty());

        panel.set_content("Symbolic summary text");
        assert_eq!(panel.content(), "Symbolic summary text");
    }
}
