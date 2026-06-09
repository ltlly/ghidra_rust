//! Export service implementation.
//!
//! Provides a service-layer API for export operations. This is the
//! service-oriented counterpart to the plugin, offering programmatic
//! format selection, validation, and batch export capabilities.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.exporter.ExporterPlugin`
//! service registration pattern.

use std::fmt;
use std::io::{self, Write};
use std::path::Path;

use crate::base::analyzer::{AddressSet, Program};
use crate::loader::framework::MessageLog as LoaderMessageLog;

use super::{
    ExportConfig, ExportFormat, ExportResult, ExporterError, ExporterRegistry, MemoryModel,
};

// ---------------------------------------------------------------------------
// ExportService
// ---------------------------------------------------------------------------

/// Service for programmatic export operations.
///
/// Ported from Ghidra's `ghidra.app.services.ExporterService` and the
/// service registration logic in `ExporterPlugin`.
///
/// While the [`ExporterPlugin`](super::export_plugin::ExporterPlugin) is
/// the UI-facing component, `ExportService` is the service-layer API
/// intended for use by other plugins and scripts that need to export
/// programs without presenting a dialog.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::exporter::export_service::ExportService;
/// use ghidra_features::exporter::ExportFormat;
///
/// let service = ExportService::new();
/// let formats = service.available_exporters();
/// assert!(!formats.is_empty());
/// ```
pub struct ExportService {
    /// The exporter registry.
    registry: ExporterRegistry,
    /// Whether the service is currently active.
    active: bool,
}

impl ExportService {
    /// Create a new export service with all default exporters.
    pub fn new() -> Self {
        Self {
            registry: ExporterRegistry::with_defaults(),
            active: true,
        }
    }

    /// Returns `true` if the service is active and ready to handle requests.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate the service.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Get the list of available exporter names.
    pub fn available_exporters(&self) -> Vec<&str> {
        self.registry.exporter_names()
    }

    /// Check whether an exporter with the given name is available.
    pub fn has_exporter(&self, name: &str) -> bool {
        self.registry.find_by_name(name).is_some()
    }

    /// Get exporters that can handle the given program.
    pub fn compatible_exporters(&self, program: &Program) -> Vec<&str> {
        self.registry
            .find_compatible(program)
            .iter()
            .map(|e| e.name())
            .collect()
    }

    /// Export a program to the given writer using the specified format.
    ///
    /// # Parameters
    ///
    /// * `program` -- the program to export
    /// * `format` -- the export format to use
    /// * `addr_set` -- optional address set to restrict the export
    /// * `memory` -- optional memory model for byte-level export
    /// * `writer` -- the output destination
    /// * `log` -- message log for warnings and info
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the export completed successfully, `Ok(false)` if the
    /// export was partial or empty.
    ///
    /// # Errors
    ///
    /// Returns `ExporterError` if the exporter is not found or the export
    /// fails due to I/O or memory access errors.
    pub fn export(
        &self,
        program: &Program,
        format: ExportFormat,
        addr_set: Option<&AddressSet>,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<bool, ExporterError> {
        if !self.active {
            return Err(ExporterError::Other("Export service is not active".into()));
        }

        let exporter_name = format.exporter_name();
        self.registry
            .export(exporter_name, program, addr_set, memory, writer, log)
    }

    /// Export a program using a configuration object.
    ///
    /// This is a convenience method that combines format lookup,
    /// validation, and export execution.
    pub fn export_with_config(
        &self,
        program: &Program,
        config: &ExportConfig,
        addr_set: Option<&AddressSet>,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<ExportResult, ExporterError> {
        if !self.active {
            return Err(ExporterError::Other("Export service is not active".into()));
        }

        let exporter_name = config.format.exporter_name();
        let mut counting = super::CountingWriter::new(writer);
        let result = self.registry.export(
            exporter_name,
            program,
            addr_set,
            memory,
            &mut counting,
            log,
        );

        match result {
            Ok(true) => {
                let bytes = counting.bytes_written();
                Ok(ExportResult::success(
                    &config.output_path,
                    bytes,
                    config.format.display_name(),
                ))
            }
            Ok(false) => {
                let mut r = ExportResult::failure(&config.output_path, config.format.display_name());
                r.add_message("Export returned false (possibly empty or unsupported address space)");
                Ok(r)
            }
            Err(e) => Err(e),
        }
    }

    /// Validate whether a given export configuration is usable.
    ///
    /// Returns `Ok(())` if the configuration can be used, or an error
    /// message describing the problem.
    pub fn validate_config(&self, config: &ExportConfig) -> Result<(), String> {
        if !self.active {
            return Err("Export service is not active".to_string());
        }

        let exporter_name = config.format.exporter_name();
        if !self.has_exporter(exporter_name) {
            return Err(format!("Unknown exporter: {}", exporter_name));
        }

        if config.output_path.trim().is_empty() {
            return Err("No output path specified".to_string());
        }

        // Check if output path is a directory
        let path = Path::new(config.output_path.trim());
        if path.exists() && path.is_dir() {
            return Err("Output path is a directory".to_string());
        }

        Ok(())
    }

    /// Export a program and write to a byte buffer, returning the result.
    ///
    /// This is a convenience method for programmatic use where the caller
    /// wants to capture the exported bytes in memory rather than writing
    /// to a file.
    pub fn export_to_vec(
        &self,
        program: &Program,
        format: ExportFormat,
        memory: Option<&MemoryModel>,
        log: &mut LoaderMessageLog,
    ) -> Result<Vec<u8>, ExporterError> {
        let mut buf = Vec::new();
        self.export(program, format, None, memory, &mut buf, log)?;
        Ok(buf)
    }

    /// Get a reference to the exporter registry.
    pub fn registry(&self) -> &ExporterRegistry {
        &self.registry
    }

    /// Get a mutable reference to the exporter registry.
    ///
    /// Allows registering custom exporters at runtime.
    pub fn registry_mut(&mut self) -> &mut ExporterRegistry {
        &mut self.registry
    }
}

impl Default for ExportService {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ExportService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportService")
            .field("active", &self.active)
            .field("exporters", &self.registry.exporter_names())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ExportBatchItem -- batch export request
// ---------------------------------------------------------------------------

/// A single item in a batch export request.
///
/// Ported from Ghidra's batch export patterns used in the project manager.
#[derive(Debug, Clone)]
pub struct ExportBatchItem {
    /// The program to export.
    pub program_name: String,
    /// The export format.
    pub format: ExportFormat,
    /// The output path.
    pub output_path: String,
    /// Whether to export only the selection.
    pub selection_only: bool,
}

impl ExportBatchItem {
    /// Create a new batch export item.
    pub fn new(
        program_name: impl Into<String>,
        format: ExportFormat,
        output_path: impl Into<String>,
    ) -> Self {
        Self {
            program_name: program_name.into(),
            format,
            output_path: output_path.into(),
            selection_only: false,
        }
    }

    /// Set whether to export only the selection.
    pub fn with_selection_only(mut self, selection_only: bool) -> Self {
        self.selection_only = selection_only;
        self
    }
}

/// Result of a batch export operation.
#[derive(Debug, Clone)]
pub struct ExportBatchResult {
    /// Per-item results.
    pub items: Vec<ExportBatchItemResult>,
    /// Total bytes written across all items.
    pub total_bytes: u64,
    /// Number of successful exports.
    pub success_count: usize,
    /// Number of failed exports.
    pub failure_count: usize,
}

/// Result of a single batch export item.
#[derive(Debug, Clone)]
pub struct ExportBatchItemResult {
    /// The program name.
    pub program_name: String,
    /// The output path.
    pub output_path: String,
    /// Whether this item succeeded.
    pub success: bool,
    /// The number of bytes written (0 if failed).
    pub bytes_written: u64,
    /// Error message, if any.
    pub error: Option<String>,
}

impl ExportBatchResult {
    /// Create a new empty batch result.
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            total_bytes: 0,
            success_count: 0,
            failure_count: 0,
        }
    }

    /// Add a successful item result.
    pub fn add_success(&mut self, program_name: &str, output_path: &str, bytes: u64) {
        self.items.push(ExportBatchItemResult {
            program_name: program_name.to_string(),
            output_path: output_path.to_string(),
            success: true,
            bytes_written: bytes,
            error: None,
        });
        self.total_bytes += bytes;
        self.success_count += 1;
    }

    /// Add a failed item result.
    pub fn add_failure(&mut self, program_name: &str, output_path: &str, error: &str) {
        self.items.push(ExportBatchItemResult {
            program_name: program_name.to_string(),
            output_path: output_path.to_string(),
            success: false,
            bytes_written: 0,
            error: Some(error.to_string()),
        });
        self.failure_count += 1;
    }

    /// Returns `true` if all items succeeded.
    pub fn all_succeeded(&self) -> bool {
        self.failure_count == 0
    }

    /// Generate a summary string for the batch result.
    pub fn summary(&self) -> String {
        let mut buf = String::new();
        buf.push_str(&format!(
            "Batch export: {} succeeded, {} failed\n",
            self.success_count, self.failure_count
        ));
        buf.push_str(&format!("Total bytes: {}\n\n", self.total_bytes));
        for item in &self.items {
            let status = if item.success { "OK" } else { "FAILED" };
            buf.push_str(&format!(
                "  [{}] {} -> {} ({} bytes)",
                status, item.program_name, item.output_path, item.bytes_written
            ));
            if let Some(ref err) = item.error {
                buf.push_str(&format!(" -- {}", err));
            }
            buf.push('\n');
        }
        buf
    }
}

impl Default for ExportBatchResult {
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

    // ========================================================================
    // ExportService tests
    // ========================================================================

    #[test]
    fn test_export_service_new() {
        let service = ExportService::new();
        assert!(service.is_active());
        assert!(!service.available_exporters().is_empty());
    }

    #[test]
    fn test_export_service_default() {
        let service = ExportService::default();
        assert!(service.is_active());
    }

    #[test]
    fn test_export_service_debug() {
        let service = ExportService::new();
        let debug = format!("{:?}", service);
        assert!(debug.contains("ExportService"));
        assert!(debug.contains("active"));
    }

    #[test]
    fn test_export_service_available_exporters() {
        let service = ExportService::new();
        let exporters = service.available_exporters();
        assert!(exporters.contains(&"Raw Bytes"));
        assert!(exporters.contains(&"Intel Hex"));
        assert!(exporters.contains(&"Motorola Hex"));
        assert!(exporters.contains(&"XML"));
        assert!(exporters.contains(&"HTML"));
        assert!(exporters.contains(&"Ascii Text"));
    }

    #[test]
    fn test_export_service_has_exporter() {
        let service = ExportService::new();
        assert!(service.has_exporter("Raw Bytes"));
        assert!(service.has_exporter("Intel Hex"));
        assert!(!service.has_exporter("Nonexistent"));
    }

    #[test]
    fn test_export_service_compatible_exporters() {
        let service = ExportService::new();
        let prog = make_test_program();
        let compatible = service.compatible_exporters(&prog);
        assert!(!compatible.is_empty());
        assert!(compatible.contains(&"Raw Bytes"));
    }

    #[test]
    fn test_export_service_export_binary() {
        let service = ExportService::new();
        let prog = make_test_program();
        let mem = make_test_memory();

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = service.export(
            &prog,
            ExportFormat::Binary,
            None,
            Some(&mem),
            &mut output,
            &mut log,
        );
        assert!(result.is_ok());
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_export_service_export_intel_hex() {
        let service = ExportService::new();
        let prog = make_test_program();
        let mem = make_test_memory();

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = service.export(
            &prog,
            ExportFormat::IntelHex,
            None,
            Some(&mem),
            &mut output,
            &mut log,
        );
        assert!(result.is_ok());
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains(":00000001FF"));
    }

    #[test]
    fn test_export_service_export_with_config() {
        let service = ExportService::new();
        let prog = make_test_program();
        let mem = make_test_memory();
        let config = ExportConfig::new(ExportFormat::Binary, "/tmp/out.bin");

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = service
            .export_with_config(&prog, &config, None, Some(&mem), &mut output, &mut log)
            .unwrap();
        assert!(result.success);
        assert_eq!(result.output_size, 32);
    }

    #[test]
    fn test_export_service_export_to_vec() {
        let service = ExportService::new();
        let prog = make_test_program();
        let mem = make_test_memory();
        let mut log = LoaderMessageLog::new();

        let data = service
            .export_to_vec(&prog, ExportFormat::Binary, Some(&mem), &mut log)
            .unwrap();
        assert_eq!(data.len(), 32);
        assert_eq!(data[0], 0);
        assert_eq!(data[31], 31);
    }

    #[test]
    fn test_export_service_deactivated() {
        let mut service = ExportService::new();
        assert!(service.is_active());

        service.deactivate();
        assert!(!service.is_active());

        let prog = make_test_program();
        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = service.export(
            &prog,
            ExportFormat::Binary,
            None,
            None,
            &mut output,
            &mut log,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not active"));
    }

    #[test]
    fn test_export_service_validate_config() {
        let service = ExportService::new();

        // Valid config
        let config = ExportConfig::new(ExportFormat::Binary, "/tmp/out.bin");
        assert!(service.validate_config(&config).is_ok());

        // Empty output path
        let config = ExportConfig::new(ExportFormat::Binary, "");
        assert!(service.validate_config(&config).is_err());
        assert!(service
            .validate_config(&config)
            .unwrap_err()
            .contains("No output path"));

        // Whitespace-only output path
        let config = ExportConfig::new(ExportFormat::Binary, "   ");
        assert!(service.validate_config(&config).is_err());
    }

    #[test]
    fn test_export_service_validate_config_inactive() {
        let mut service = ExportService::new();
        service.deactivate();

        let config = ExportConfig::new(ExportFormat::Binary, "/tmp/out.bin");
        let result = service.validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not active"));
    }

    #[test]
    fn test_export_service_registry_access() {
        let service = ExportService::new();
        let names = service.registry().exporter_names();
        assert!(names.contains(&"Raw Bytes"));
    }

    #[test]
    fn test_export_service_registry_mut() {
        let mut service = ExportService::new();
        let initial_count = service.registry().exporter_names().len();

        service
            .registry_mut()
            .register(Box::new(crate::exporter::BinaryExporter::new()));
        assert_eq!(service.registry().exporter_names().len(), initial_count + 1);
    }

    // ========================================================================
    // ExportBatchItem tests
    // ========================================================================

    #[test]
    fn test_export_batch_item_new() {
        let item = ExportBatchItem::new("program.exe", ExportFormat::Binary, "/tmp/out.bin");
        assert_eq!(item.program_name, "program.exe");
        assert_eq!(item.format, ExportFormat::Binary);
        assert_eq!(item.output_path, "/tmp/out.bin");
        assert!(!item.selection_only);
    }

    #[test]
    fn test_export_batch_item_with_selection_only() {
        let item = ExportBatchItem::new("test", ExportFormat::Xml, "/tmp/out.xml")
            .with_selection_only(true);
        assert!(item.selection_only);
    }

    // ========================================================================
    // ExportBatchResult tests
    // ========================================================================

    #[test]
    fn test_export_batch_result_new() {
        let result = ExportBatchResult::new();
        assert!(result.items.is_empty());
        assert_eq!(result.total_bytes, 0);
        assert_eq!(result.success_count, 0);
        assert_eq!(result.failure_count, 0);
        assert!(result.all_succeeded());
    }

    #[test]
    fn test_export_batch_result_default() {
        let result = ExportBatchResult::default();
        assert!(result.items.is_empty());
    }

    #[test]
    fn test_export_batch_result_add_success() {
        let mut result = ExportBatchResult::new();
        result.add_success("prog1", "/tmp/p1.bin", 1024);
        result.add_success("prog2", "/tmp/p2.bin", 2048);

        assert_eq!(result.items.len(), 2);
        assert_eq!(result.total_bytes, 3072);
        assert_eq!(result.success_count, 2);
        assert_eq!(result.failure_count, 0);
        assert!(result.all_succeeded());
    }

    #[test]
    fn test_export_batch_result_add_failure() {
        let mut result = ExportBatchResult::new();
        result.add_success("prog1", "/tmp/p1.bin", 1024);
        result.add_failure("prog2", "/tmp/p2.bin", "Disk full");

        assert_eq!(result.items.len(), 2);
        assert_eq!(result.total_bytes, 1024);
        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 1);
        assert!(!result.all_succeeded());
    }

    #[test]
    fn test_export_batch_result_summary() {
        let mut result = ExportBatchResult::new();
        result.add_success("program1", "/tmp/p1.bin", 1024);
        result.add_failure("program2", "/tmp/p2.bin", "Export error");

        let summary = result.summary();
        assert!(summary.contains("1 succeeded, 1 failed"));
        assert!(summary.contains("Total bytes: 1024"));
        assert!(summary.contains("[OK] program1"));
        assert!(summary.contains("[FAILED] program2"));
        assert!(summary.contains("Export error"));
    }

    #[test]
    fn test_export_batch_result_summary_all_success() {
        let mut result = ExportBatchResult::new();
        result.add_success("a", "/tmp/a.bin", 100);
        result.add_success("b", "/tmp/b.bin", 200);

        let summary = result.summary();
        assert!(summary.contains("2 succeeded, 0 failed"));
        assert!(summary.contains("Total bytes: 300"));
    }

    // ========================================================================
    // Integration: all formats through ExportService
    // ========================================================================

    #[test]
    fn test_all_formats_through_export_service() {
        let service = ExportService::new();
        let prog = make_test_program();
        let mem = make_test_memory();

        for format in ExportFormat::all() {
            let mut output = Vec::new();
            let mut log = LoaderMessageLog::new();
            let result = service.export(
                &prog,
                *format,
                None,
                Some(&mem),
                &mut output,
                &mut log,
            );
            assert!(
                result.is_ok(),
                "Export failed for format {}: {:?}",
                format.display_name(),
                result.err()
            );
        }
    }

    #[test]
    fn test_all_formats_export_to_vec() {
        let service = ExportService::new();
        let prog = make_test_program();
        let mem = make_test_memory();

        for format in ExportFormat::all() {
            let mut log = LoaderMessageLog::new();
            let data = service
                .export_to_vec(&prog, *format, Some(&mem), &mut log)
                .unwrap_or_default();
            assert!(
                !data.is_empty(),
                "Empty output for format: {}",
                format.display_name()
            );
        }
    }
}
