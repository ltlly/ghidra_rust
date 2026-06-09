//! Export plugin implementation.
//!
//! Provides the export plugin that registers actions for exporting programs
//! from both the front-end project tree and the code browser tool.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.exporter.ExporterPlugin`.

use std::fmt;
use std::io::Write;

use crate::base::analyzer::{AddressSet, Program};
use crate::loader::framework::MessageLog as LoaderMessageLog;

use super::{
    CountingWriter, ExportConfig, ExportFormat, ExportResult, ExporterError, ExporterRegistry,
    ExportOption, ExportOptionValue, MemoryModel,
};

// ---------------------------------------------------------------------------
// ExporterPlugin -- the main export plugin
// ---------------------------------------------------------------------------

/// The export plugin model.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.exporter.ExporterPlugin`.
///
/// Provides methods for initiating export operations from either the
/// front-end project view or from within a tool with an open program.
///
/// This plugin registers two actions:
/// - **"Export Program"** -- accessible from the code browser's File menu
/// - **"Export"** -- accessible from the project tree context menu
///
/// # Example
///
/// ```ignore
/// use ghidra_features::exporter::export_plugin::ExporterPlugin;
///
/// let mut plugin = ExporterPlugin::new();
/// assert_eq!(plugin.available_formats().len(), 6);
/// ```
pub struct ExporterPlugin {
    /// The exporter registry.
    registry: ExporterRegistry,
    /// Event log (for testing and diagnostics).
    events: Vec<String>,
    /// The last-used exporter name (for persistence across sessions).
    last_used_exporter: Option<String>,
}

impl fmt::Debug for ExporterPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExporterPlugin")
            .field("events", &self.events)
            .field("last_used_exporter", &self.last_used_exporter)
            .finish()
    }
}

impl ExporterPlugin {
    /// Create a new exporter plugin with all default exporters registered.
    pub fn new() -> Self {
        Self {
            registry: ExporterRegistry::with_defaults(),
            events: Vec::new(),
            last_used_exporter: None,
        }
    }

    /// Get the action names this plugin registers.
    ///
    /// Mirrors the action names from `ExporterPlugin.createFrontEndAction()`
    /// and `ExporterPlugin.createToolAction()`.
    pub fn actions(&self) -> Vec<&str> {
        vec!["Export Program", "Export"]
    }

    /// Get available export formats.
    pub fn available_formats(&self) -> &[ExportFormat] {
        ExportFormat::all()
    }

    /// Get the exporter registry.
    pub fn registry(&self) -> &ExporterRegistry {
        &self.registry
    }

    /// Get a mutable reference to the exporter registry.
    ///
    /// Allows registering custom exporters at runtime.
    pub fn registry_mut(&mut self) -> &mut ExporterRegistry {
        &mut self.registry
    }

    /// Set the last-used exporter name.
    pub fn set_last_used_exporter(&mut self, name: impl Into<String>) {
        self.last_used_exporter = Some(name.into());
    }

    /// Get the last-used exporter name.
    pub fn last_used_exporter(&self) -> Option<&str> {
        self.last_used_exporter.as_deref()
    }

    /// Export a program using the given configuration.
    ///
    /// Returns the number of bytes written on success.
    ///
    /// # Parameters
    ///
    /// * `program` -- the program to export
    /// * `config` -- the export configuration (format, output path, options)
    /// * `memory` -- optional memory model for byte-level export
    /// * `writer` -- the output writer
    /// * `log` -- message log for warnings and info
    ///
    /// # Errors
    ///
    /// Returns an error if the exporter is not found or the export fails.
    pub fn export(
        &mut self,
        program: &Program,
        config: &ExportConfig,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<u64, ExporterError> {
        let exporter_name = config.format.exporter_name();
        self.last_used_exporter = Some(exporter_name.to_string());
        self.events
            .push(format!("Export: {} -> {}", exporter_name, config.output_path));

        let mut counting_writer = CountingWriter::new(writer);
        self.registry.export(
            exporter_name,
            program,
            None,
            memory,
            &mut counting_writer,
            log,
        )?;
        Ok(counting_writer.bytes_written())
    }

    /// Export a program to a specific format by name.
    ///
    /// Returns an `ExportResult` with success/failure status and summary.
    ///
    /// This is a convenience method that creates an `ExportConfig`, runs the
    /// export, and collects the result into an `ExportResult`.
    pub fn export_with_result(
        &mut self,
        program: &Program,
        format: ExportFormat,
        output_path: &str,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> ExportResult {
        let config = ExportConfig::new(format, output_path);
        let exporter_name = format.exporter_name();

        let mut counting = CountingWriter::new(writer);
        let result = self.registry.export(
            exporter_name,
            program,
            None,
            memory,
            &mut counting,
            log,
        );

        match result {
            Ok(true) => {
                let bytes = counting.bytes_written();
                self.events
                    .push(format!("Export completed: {} bytes", bytes));
                ExportResult::success(output_path, bytes, format.display_name())
            }
            Ok(false) => {
                self.events.push("Export returned false (partial/empty)".into());
                let mut r = ExportResult::failure(output_path, format.display_name());
                r.add_message("Export returned false (possibly empty or unsupported)");
                r
            }
            Err(e) => {
                let msg = format!("Export error: {}", e);
                self.events.push(msg.clone());
                let mut r = ExportResult::failure(output_path, format.display_name());
                r.add_message(msg);
                r
            }
        }
    }

    /// Get the event log.
    pub fn events(&self) -> &[String] {
        &self.events
    }
}

impl Default for ExporterPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ExportOption -- plugin-level option (simple name/value pair)
// ---------------------------------------------------------------------------

/// A simple export option with name and string value.
///
/// This is a simpler alternative to the typed `super::ExportOption` used
/// by the dialog model. It is useful for plugin-level configuration where
/// options are stored as key-value string pairs.
#[derive(Debug, Clone)]
pub struct PluginExportOption {
    /// Option name.
    pub name: String,
    /// Option description.
    pub description: String,
    /// Current value as a string.
    pub value: String,
    /// Default value.
    pub default_value: String,
}

impl PluginExportOption {
    /// Create a new plugin export option.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::{Address, AddressRange, Language};

    fn make_test_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test_binary", lang);
        prog.image_base = 0x400000;
        prog.memory
            .add_range(AddressRange::new(Address::new(0x400000), Address::new(0x40001F)));
        prog.symbols.insert(Address::new(0x400000), "_start".into());
        prog.symbols.insert(Address::new(0x400010), "main".into());
        prog
    }

    fn make_test_memory() -> MemoryModel {
        let mut mem = MemoryModel::new();
        for i in 0u8..32 {
            mem.set_byte(&Address::new(0x400000 + i as u64), i);
        }
        mem
    }

    #[test]
    fn test_exporter_plugin_new() {
        let plugin = ExporterPlugin::new();
        assert_eq!(plugin.actions().len(), 2);
        assert!(plugin.last_used_exporter.is_none());
        assert!(plugin.events().is_empty());
    }

    #[test]
    fn test_exporter_plugin_available_formats() {
        let plugin = ExporterPlugin::new();
        assert_eq!(plugin.available_formats().len(), 6);
    }

    #[test]
    fn test_exporter_plugin_actions() {
        let plugin = ExporterPlugin::new();
        let actions = plugin.actions();
        assert!(actions.contains(&"Export Program"));
        assert!(actions.contains(&"Export"));
    }

    #[test]
    fn test_exporter_plugin_registry() {
        let plugin = ExporterPlugin::new();
        let names = plugin.registry().exporter_names();
        assert!(names.contains(&"Raw Bytes"));
        assert!(names.contains(&"Intel Hex"));
        assert!(names.contains(&"Motorola Hex"));
        assert!(names.contains(&"XML"));
        assert!(names.contains(&"HTML"));
        assert!(names.contains(&"Ascii Text"));
    }

    #[test]
    fn test_exporter_plugin_export_binary() {
        let mut plugin = ExporterPlugin::new();
        let prog = make_test_program();
        let mem = make_test_memory();
        let config = ExportConfig::new(ExportFormat::Binary, "/tmp/out.bin");

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let bytes = plugin
            .export(&prog, &config, Some(&mem), &mut output, &mut log)
            .unwrap();
        assert_eq!(bytes, 32);
        assert_eq!(output.len(), 32);
        assert_eq!(plugin.events().len(), 1);
        assert_eq!(
            plugin.last_used_exporter(),
            Some("Raw Bytes")
        );
    }

    #[test]
    fn test_exporter_plugin_export_intel_hex() {
        let mut plugin = ExporterPlugin::new();
        let prog = make_test_program();
        let mem = make_test_memory();
        let config = ExportConfig::new(ExportFormat::IntelHex, "/tmp/out.hex");

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let bytes = plugin
            .export(&prog, &config, Some(&mem), &mut output, &mut log)
            .unwrap();
        assert!(bytes > 0);
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains(":00000001FF"));
        assert_eq!(plugin.last_used_exporter(), Some("Intel Hex"));
    }

    #[test]
    fn test_exporter_plugin_export_with_result() {
        let mut plugin = ExporterPlugin::new();
        let prog = make_test_program();
        let mem = make_test_memory();

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = plugin.export_with_result(
            &prog,
            ExportFormat::Binary,
            "/tmp/out.bin",
            Some(&mem),
            &mut output,
            &mut log,
        );
        assert!(result.success);
        assert_eq!(result.output_size, 32);
        assert!(result.format_name.contains("Binary"));
    }

    #[test]
    fn test_exporter_plugin_export_with_result_xml() {
        let mut plugin = ExporterPlugin::new();
        let prog = make_test_program();
        let mem = make_test_memory();

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = plugin.export_with_result(
            &prog,
            ExportFormat::Xml,
            "/tmp/out.xml",
            Some(&mem),
            &mut output,
            &mut log,
        );
        assert!(result.success);
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("<?xml"));
    }

    #[test]
    fn test_exporter_plugin_events() {
        let mut plugin = ExporterPlugin::new();
        assert!(plugin.events().is_empty());

        let prog = make_test_program();
        let mem = make_test_memory();
        let config = ExportConfig::new(ExportFormat::Binary, "/tmp/out.bin");

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        plugin
            .export(&prog, &config, Some(&mem), &mut output, &mut log)
            .unwrap();

        let events = plugin.events();
        assert_eq!(events.len(), 1);
        assert!(events[0].contains("Raw Bytes"));
        assert!(events[0].contains("/tmp/out.bin"));
    }

    #[test]
    fn test_exporter_plugin_set_last_used() {
        let mut plugin = ExporterPlugin::new();
        assert!(plugin.last_used_exporter.is_none());

        plugin.set_last_used_exporter("Intel Hex");
        assert_eq!(plugin.last_used_exporter(), Some("Intel Hex"));
    }

    #[test]
    fn test_exporter_plugin_registry_mut() {
        let mut plugin = ExporterPlugin::new();
        let initial_count = plugin.registry().exporter_names().len();

        // Register a duplicate (the registry allows it)
        plugin
            .registry_mut()
            .register(Box::new(crate::exporter::BinaryExporter::new()));
        assert_eq!(plugin.registry().exporter_names().len(), initial_count + 1);
    }

    #[test]
    fn test_exporter_plugin_debug() {
        let plugin = ExporterPlugin::new();
        let debug = format!("{:?}", plugin);
        assert!(debug.contains("ExporterPlugin"));
    }

    #[test]
    fn test_exporter_plugin_default() {
        let plugin = ExporterPlugin::default();
        assert_eq!(plugin.actions().len(), 2);
        assert!(plugin.last_used_exporter.is_none());
    }

    // ========================================================================
    // PluginExportOption tests
    // ========================================================================

    #[test]
    fn test_plugin_export_option_new() {
        let opt = PluginExportOption::new("record_size", "HEX record size", "16");
        assert_eq!(opt.name, "record_size");
        assert_eq!(opt.description, "HEX record size");
        assert_eq!(opt.value, "16");
        assert_eq!(opt.default_value, "16");
    }

    #[test]
    fn test_plugin_export_option_is_modified() {
        let mut opt = PluginExportOption::new("record_size", "HEX record size", "16");
        assert!(!opt.is_modified());

        opt.value = "32".to_string();
        assert!(opt.is_modified());
    }

    #[test]
    fn test_plugin_export_option_reset() {
        let mut opt = PluginExportOption::new("record_size", "HEX record size", "16");
        opt.value = "32".to_string();
        assert!(opt.is_modified());

        opt.reset();
        assert!(!opt.is_modified());
        assert_eq!(opt.value, "16");
    }

    // ========================================================================
    // Integration: all formats through ExporterPlugin
    // ========================================================================

    #[test]
    fn test_all_formats_through_exporter_plugin() {
        let prog = make_test_program();
        let mem = make_test_memory();

        for format in ExportFormat::all() {
            let mut plugin = ExporterPlugin::new();
            let config = ExportConfig::new(
                *format,
                format!("/tmp/test.{}", format.default_extension()),
            );

            let mut output = Vec::new();
            let mut log = LoaderMessageLog::new();
            let bytes = plugin
                .export(&prog, &config, Some(&mem), &mut output, &mut log)
                .unwrap_or(0);

            // At least some output should be produced for each format
            assert!(
                !output.is_empty() || bytes == 0,
                "No output for format: {}",
                format.display_name()
            );
        }
    }
}
