//! Exporter Plugin
//!
//! Ported from `ghidra.app.plugin.core.exporter`.
//!
//! Provides the plugin and dialog for exporting a Ghidra program to an
//! external file in one of the supported export formats (e.g., GZF, XML,
//! binary, ELF, etc.).

use std::path::PathBuf;

/// The Exporter Plugin.
///
/// Registers actions for exporting programs from both the front-end
/// project tree and the code browser tool.
#[derive(Debug, Clone)]
pub struct ExporterPlugin {
    /// Plugin name.
    pub name: String,
    /// The last-used exporter name.
    pub last_used_exporter: String,
}

impl ExporterPlugin {
    /// Create a new exporter plugin.
    pub fn new() -> Self {
        Self {
            name: "Export Program/Datatype Archives".to_string(),
            last_used_exporter: "GZF".to_string(),
        }
    }

    /// Get the action names this plugin registers.
    pub fn actions(&self) -> Vec<&str> {
        vec!["Export Program", "Export"]
    }
}

impl Default for ExporterPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// An export format option.
#[derive(Debug, Clone)]
pub struct ExporterInfo {
    /// The display name of the exporter (e.g., "GZF", "XML", "Binary").
    pub name: String,
    /// The default file extension.
    pub file_extension: String,
    /// Whether this exporter supports selection-only export.
    pub supports_selection: bool,
    /// A brief description.
    pub description: String,
}

impl ExporterInfo {
    /// Create a new exporter info.
    pub fn new(name: &str, extension: &str, supports_selection: bool, description: &str) -> Self {
        Self {
            name: name.to_string(),
            file_extension: extension.to_string(),
            supports_selection,
            description: description.to_string(),
        }
    }

    /// Append the file extension to a path if not already present.
    pub fn append_extension(&self, path: &str) -> String {
        if self.file_extension.is_empty() {
            return path.to_string();
        }
        let ext_with_dot = format!(".{}", self.file_extension);
        if path.to_lowercase().ends_with(&ext_with_dot.to_lowercase()) {
            path.to_string()
        } else {
            format!("{}{}", path, ext_with_dot)
        }
    }
}

/// The Exporter Dialog state.
///
/// Manages the state for the export dialog including format selection,
/// output file path, and selection-only option.
#[derive(Debug, Clone)]
pub struct ExporterDialog {
    /// The program/domain file name being exported.
    pub file_name: String,
    /// Available exporters.
    pub exporters: Vec<ExporterInfo>,
    /// Currently selected exporter index.
    pub selected_exporter: usize,
    /// The output file path.
    pub output_path: PathBuf,
    /// Whether to export only the selection.
    pub selection_only: bool,
    /// Whether a selection exists to export.
    pub has_selection: bool,
    /// Whether this is running in the front-end (no code viewer).
    pub is_front_end: bool,
    /// Validation status message.
    pub status_text: String,
    /// Whether the dialog is valid for OK.
    pub ok_enabled: bool,
    /// Export options for the current format.
    pub options: Vec<ExportOption>,
}

impl ExporterDialog {
    /// Create a new exporter dialog.
    pub fn new(file_name: &str, is_front_end: bool) -> Self {
        let exporters = Self::default_exporters();
        let output_path = PathBuf::from(format!("{}.gzf", file_name));

        let mut dialog = Self {
            file_name: file_name.to_string(),
            exporters,
            selected_exporter: 0,
            output_path,
            selection_only: false,
            has_selection: false,
            is_front_end,
            status_text: String::new(),
            ok_enabled: false,
            options: Vec::new(),
        };
        dialog.validate();
        dialog
    }

    /// Get the default list of exporters.
    fn default_exporters() -> Vec<ExporterInfo> {
        vec![
            ExporterInfo::new("GZF", "gzf", false, "Ghidra Zip Format"),
            ExporterInfo::new("XML", "xml", true, "Ghidra XML export"),
            ExporterInfo::new("Binary", "bin", true, "Raw binary export"),
            ExporterInfo::new("ELF", "elf", false, "ELF executable export"),
            ExporterInfo::new("SARIF", "sarif", true, "SARIF results export"),
        ]
    }

    /// Select an exporter by index.
    pub fn select_exporter(&mut self, index: usize) {
        if index < self.exporters.len() {
            self.selected_exporter = index;
            let ext = &self.exporters[index].file_extension;
            if !ext.is_empty() {
                let stem = self
                    .output_path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let parent = self
                    .output_path
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| PathBuf::from("."));
                self.output_path = parent.join(format!("{}.{}", stem, ext));
            }
            self.validate();
        }
    }

    /// Get the currently selected exporter.
    pub fn selected_exporter(&self) -> Option<&ExporterInfo> {
        self.exporters.get(self.selected_exporter)
    }

    /// Set the output file path.
    pub fn set_output_path(&mut self, path: PathBuf) {
        self.output_path = path;
        self.validate();
    }

    /// Validate the dialog state.
    pub fn validate(&mut self) {
        self.ok_enabled = false;
        self.status_text.clear();

        if self.exporters.is_empty() {
            self.status_text = "No available exporters for content type".to_string();
            return;
        }

        let exporter = &self.exporters[self.selected_exporter];

        if self.output_path.as_os_str().is_empty() {
            self.status_text = "Please enter a destination file.".to_string();
            return;
        }

        if self.output_path.is_dir() {
            self.status_text = "The specified output file is a directory.".to_string();
            return;
        }

        if self.output_path.exists() {
            // File exists, will need overwrite confirmation
        }

        // Show warnings for lossy formats
        if exporter.name.contains("XML") {
            self.status_text = "Warning: XML is lossy. GZF is recommended for saving.".to_string();
        }
        if exporter.name.contains("SARIF") {
            self.status_text = "Warning: SARIF is lossy. GZF is recommended for saving.".to_string();
        }

        self.ok_enabled = true;
    }

    /// Check whether there are no applicable exporters.
    pub fn has_no_applicable_exporter(&self) -> bool {
        self.exporters.is_empty()
    }

    /// Whether the selection checkbox should be enabled.
    pub fn should_enable_selection_checkbox(&self) -> bool {
        if !self.has_selection {
            return false;
        }
        if let Some(exporter) = self.selected_exporter() {
            exporter.supports_selection
        } else {
            false
        }
    }

    /// Get the current file path with the exporter extension appended.
    pub fn get_output_file(&self) -> PathBuf {
        if let Some(exporter) = self.selected_exporter() {
            let path_str = self.output_path.to_string_lossy().to_string();
            PathBuf::from(exporter.append_extension(&path_str))
        } else {
            self.output_path.clone()
        }
    }
}

/// An export option (name/value pair).
#[derive(Debug, Clone)]
pub struct ExportOption {
    /// Option name.
    pub name: String,
    /// Option description.
    pub description: String,
    /// Current value as a string.
    pub value: String,
    /// Default value.
    pub default_value: String,
}

impl ExportOption {
    /// Create a new export option.
    pub fn new(name: &str, description: &str, default: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            value: default.to_string(),
            default_value: default.to_string(),
        }
    }

    /// Whether the value differs from the default.
    pub fn is_modified(&self) -> bool {
        self.value != self.default_value
    }

    /// Reset to the default value.
    pub fn reset(&mut self) {
        self.value = self.default_value.clone();
    }
}

/// Export result summary.
#[derive(Debug, Clone)]
pub struct ExportResult {
    /// The destination file path.
    pub output_file: PathBuf,
    /// The output file size in bytes.
    pub file_size: u64,
    /// The exporter format name.
    pub format_name: String,
    /// Any warning/error messages.
    pub messages: Vec<String>,
    /// Whether the export was successful.
    pub success: bool,
}

impl ExportResult {
    /// Format the result as a summary string.
    pub fn format_summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "Destination file:       {}",
            self.output_file.display()
        ));
        lines.push(String::new());
        lines.push(format!("Destination file Size:  {}", self.file_size));
        lines.push(format!("Format:                 {}", self.format_name));
        lines.push(String::new());
        if !self.messages.is_empty() {
            lines.extend(self.messages.iter().cloned());
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exporter_plugin() {
        let plugin = ExporterPlugin::new();
        assert_eq!(plugin.actions().len(), 2);
        assert_eq!(plugin.last_used_exporter, "GZF");
    }

    #[test]
    fn test_exporter_info() {
        let info = ExporterInfo::new("GZF", "gzf", false, "Ghidra Zip Format");
        assert_eq!(info.append_extension("test"), "test.gzf");
        assert_eq!(info.append_extension("test.gzf"), "test.gzf");
        assert_eq!(info.append_extension("test.GZF"), "test.GZF");
    }

    #[test]
    fn test_exporter_info_no_extension() {
        let info = ExporterInfo::new("Raw", "", true, "Raw binary");
        assert_eq!(info.append_extension("test"), "test");
    }

    #[test]
    fn test_exporter_dialog_creation() {
        let dialog = ExporterDialog::new("my_program", false);
        assert_eq!(dialog.file_name, "my_program");
        assert!(!dialog.is_front_end);
        assert!(!dialog.exporters.is_empty());
        assert!(dialog.ok_enabled); // should validate OK since we have a valid path
    }

    #[test]
    fn test_exporter_dialog_select_format() {
        let mut dialog = ExporterDialog::new("test", false);
        dialog.select_exporter(1); // XML
        let exporter = dialog.selected_exporter().unwrap();
        assert_eq!(exporter.name, "XML");
        assert!(dialog.output_path.to_string_lossy().contains(".xml"));
    }

    #[test]
    fn test_exporter_dialog_no_exporters() {
        let mut dialog = ExporterDialog::new("test", true);
        dialog.exporters.clear();
        dialog.validate();
        assert!(!dialog.ok_enabled);
        assert!(dialog.has_no_applicable_exporter());
    }

    #[test]
    fn test_exporter_dialog_empty_path() {
        let mut dialog = ExporterDialog::new("test", false);
        dialog.output_path = PathBuf::new();
        dialog.validate();
        assert!(!dialog.ok_enabled);
        assert!(dialog.status_text.contains("destination file"));
    }

    #[test]
    fn test_exporter_dialog_xml_warning() {
        let mut dialog = ExporterDialog::new("test", false);
        dialog.select_exporter(1); // XML
        assert!(dialog.status_text.contains("XML"));
    }

    #[test]
    fn test_selection_checkbox() {
        let mut dialog = ExporterDialog::new("test", false);
        assert!(!dialog.should_enable_selection_checkbox());
        dialog.has_selection = true;
        dialog.select_exporter(1); // XML (supports_selection = true)
        assert!(dialog.should_enable_selection_checkbox());
    }

    #[test]
    fn test_export_option() {
        let mut opt = ExportOption::new("include_headers", "Include headers", "true");
        assert!(!opt.is_modified());
        opt.value = "false".to_string();
        assert!(opt.is_modified());
        opt.reset();
        assert!(!opt.is_modified());
    }

    #[test]
    fn test_export_result_summary() {
        let result = ExportResult {
            output_file: PathBuf::from("/tmp/output.gzf"),
            file_size: 1024,
            format_name: "GZF".to_string(),
            messages: vec!["OK".to_string()],
            success: true,
        };
        let summary = result.format_summary();
        assert!(summary.contains("/tmp/output.gzf"));
        assert!(summary.contains("1024"));
        assert!(summary.contains("GZF"));
        assert!(summary.contains("OK"));
    }

    #[test]
    fn test_get_output_file() {
        let mut dialog = ExporterDialog::new("program", false);
        dialog.output_path = PathBuf::from("/tmp/program");
        dialog.select_exporter(0); // GZF
        let file = dialog.get_output_file();
        assert!(file.to_string_lossy().contains(".gzf"));
    }
}
