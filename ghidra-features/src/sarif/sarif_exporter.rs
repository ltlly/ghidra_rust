//! SARIF exporter, loader, and writer task.
//!
//! Ported from Ghidra's Java sources:
//! - `SarifExporter.java` -- `Exporter` subclass for writing SARIF files
//! - `SarifLoader.java` -- `AbstractProgramLoader` subclass for reading SARIF
//! - `SarifWriterTask.java` -- background task for SARIF export
//! - `SarifUtils.java` -- address/location utilities (subset for export)
//! - `ProgramSarifMgr.java` -- read/write orchestration

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::sarif_plugin::SarifProgramOptions;
use super::{
    GhidraBookmark, GhidraComment, GhidraData, GhidraEntryPoint, GhidraEquate, GhidraFunction,
    GhidraFunctionParam, GhidraFunctionRegVar, GhidraFunctionStack, GhidraFunctionStackVar,
    GhidraMemoryBlock, GhidraProgramExport, GhidraReference, GhidraReferenceType, GhidraRelocation,
    GhidraSymbol, SarifArtifact, SarifArtifactLocation, SarifExporter, SarifInvocation, SarifLevel,
    SarifLocation, SarifLog, SarifMessage, SarifPhysicalLocation, SarifRegion, SarifReportingDescriptor,
    SarifResult, SarifRun, SarifTool, SarifToolComponent,
};

// ---------------------------------------------------------------------------
// SarifWriteOptions -- export options wrapper
// ---------------------------------------------------------------------------

/// Options controlling SARIF export.
///
/// Combines program-level options with export-specific settings.
/// Ported from the option handling in `SarifExporter.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifWriteOptions {
    /// Program options controlling what to export.
    pub program_options: SarifProgramOptions,
    /// Whether to include memory byte contents.
    pub include_memory_contents: bool,
    /// Whether to include function details (parameters, stack, registers).
    pub include_function_details: bool,
    /// Whether to include cross-references.
    pub include_references: bool,
    /// Whether to include relocation entries.
    pub include_relocations: bool,
    /// The tool name to report in the SARIF log.
    pub tool_name: String,
    /// The tool version to report in the SARIF log.
    pub tool_version: Option<String>,
    /// Whether to pretty-print the JSON output.
    pub pretty_print: bool,
}

impl Default for SarifWriteOptions {
    fn default() -> Self {
        Self {
            program_options: SarifProgramOptions::default(),
            include_memory_contents: true,
            include_function_details: true,
            include_references: true,
            include_relocations: true,
            tool_name: "Ghidra Rust".to_string(),
            tool_version: Some("0.1.0".to_string()),
            pretty_print: true,
        }
    }
}

// ---------------------------------------------------------------------------
// SarifWriterTask -- background export task
// ---------------------------------------------------------------------------

/// Status of a SARIF write task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SarifTaskStatus {
    /// Task has not started.
    NotStarted,
    /// Task is currently running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled.
    Cancelled,
    /// Task failed with an error.
    Failed,
}

impl Default for SarifTaskStatus {
    fn default() -> Self {
        Self::NotStarted
    }
}

/// A progress callback for tracking export/import progress.
pub type ProgressCallback = Box<dyn Fn(u64, u64, &str) + Send + Sync>;

/// Background task for writing a SARIF export.
///
/// Orchestrates the creation of a SARIF log from a Ghidra program's
/// analysis data. Each category of data (functions, symbols, comments,
/// etc.) is written by a dedicated sub-writer.
///
/// Ported from `SarifWriterTask.java`.
#[derive(Debug)]
pub struct SarifWriterTask {
    /// Task name (for display).
    pub name: String,
    /// Current status.
    status: SarifTaskStatus,
    /// Progress (0.0 to 1.0).
    progress: f64,
    /// Current phase description.
    phase: String,
    /// Number of items processed.
    items_processed: u64,
    /// Total items to process.
    items_total: u64,
    /// Accumulated messages.
    messages: Vec<String>,
}

impl SarifWriterTask {
    /// Create a new writer task.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: SarifTaskStatus::NotStarted,
            progress: 0.0,
            phase: String::new(),
            items_processed: 0,
            items_total: 0,
            messages: Vec::new(),
        }
    }

    /// Get the current task status.
    pub fn status(&self) -> SarifTaskStatus {
        self.status
    }

    /// Get the current progress (0.0 to 1.0).
    pub fn progress(&self) -> f64 {
        self.progress
    }

    /// Get the current phase description.
    pub fn phase(&self) -> &str {
        &self.phase
    }

    /// Get accumulated messages.
    pub fn messages(&self) -> &[String] {
        &self.messages
    }

    /// Start the export task with the given program data.
    pub fn execute(
        &mut self,
        export: &GhidraProgramExport,
        options: &SarifWriteOptions,
        path: &Path,
    ) -> io::Result<()> {
        self.status = SarifTaskStatus::Running;
        self.phase = "Building SARIF log".to_string();
        self.progress = 0.0;

        let mut exporter = SarifExporter::new(options.tool_name.clone());
        if let Some(version) = &options.tool_version {
            exporter.set_version(version);
        }

        // Add invocation record
        let invocation = SarifInvocation::new(true);
        exporter.add_invocation(invocation);

        // Export functions
        if options.program_options.functions {
            self.phase = "Exporting functions".to_string();
            self.export_functions(&mut exporter, export, options);
        }

        // Export symbols
        if options.program_options.symbols {
            self.phase = "Exporting symbols".to_string();
            self.export_symbols(&mut exporter, export);
        }

        // Export entry points
        if options.program_options.entry_points {
            self.phase = "Exporting entry points".to_string();
            self.export_entry_points(&mut exporter, export);
        }

        // Export data items
        if options.program_options.data {
            self.phase = "Exporting data".to_string();
            self.export_data(&mut exporter, export);
        }

        // Export comments
        if options.program_options.comments {
            self.phase = "Exporting comments".to_string();
            self.export_comments(&mut exporter, export);
        }

        // Export equates
        if options.program_options.equates {
            self.phase = "Exporting equates".to_string();
            self.export_equates(&mut exporter, export);
        }

        // Export relocations
        if options.program_options.relocation_table && options.include_relocations {
            self.phase = "Exporting relocations".to_string();
            self.export_relocations(&mut exporter, export);
        }

        self.phase = "Writing SARIF file".to_string();
        self.progress = 0.9;

        exporter
            .write_to_file(path)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("SARIF write failed: {e}")))?;

        self.status = SarifTaskStatus::Completed;
        self.progress = 1.0;
        self.phase = "Done".to_string();

        Ok(())
    }

    fn export_functions(
        &mut self,
        exporter: &mut SarifExporter,
        export: &GhidraProgramExport,
        options: &SarifWriteOptions,
    ) {
        for (i, func) in export.functions.iter().enumerate() {
            let addr = func.location.as_deref().unwrap_or("0x0");
            let name = func.name.as_deref().unwrap_or("<unknown>");

            // Create a descriptive message with function details
            let mut msg_parts = vec![format!("Function: {name}")];
            if let Some(ns) = &func.namespace {
                msg_parts.push(format!("namespace: {ns}"));
            }
            if let Some(cc) = &func.calling_convention {
                msg_parts.push(format!("cc: {cc}"));
            }
            if options.include_function_details {
                if let Some(params) = &func.params {
                    let param_strs: Vec<String> = params
                        .iter()
                        .map(|p| {
                            let pname = p.name.as_deref().unwrap_or("?");
                            let ptype = p.data_type.as_deref().unwrap_or("?");
                            format!("{ptype} {pname}")
                        })
                        .collect();
                    if !param_strs.is_empty() {
                        msg_parts.push(format!("params: ({})", param_strs.join(", ")));
                    }
                }
            }

            exporter.add_result(
                "GhidraFunction".into(),
                msg_parts.join(" | "),
                SarifLevel::None,
                addr.to_string(),
            );

            // Add artifact for the function
            exporter.add_artifact(SarifArtifact::file(name));
        }
    }

    fn export_symbols(&mut self, exporter: &mut SarifExporter, export: &GhidraProgramExport) {
        for sym in &export.symbols {
            let addr = sym.address.as_deref().unwrap_or("0x0");
            let name = sym.name.as_deref().unwrap_or("<unknown>");
            let sym_type = sym.symbol_type.as_deref().unwrap_or("Label");
            exporter.add_result(
                "GhidraSymbol".into(),
                format!("Symbol: {name} ({sym_type})"),
                SarifLevel::None,
                addr.to_string(),
            );
        }
    }

    fn export_entry_points(&mut self, exporter: &mut SarifExporter, export: &GhidraProgramExport) {
        for ep in &export.entry_points {
            let addr = ep.address.as_deref().unwrap_or("0x0");
            exporter.add_result(
                "GhidraEntryPoint".into(),
                format!("Entry point: {addr}"),
                SarifLevel::None,
                addr.to_string(),
            );
        }
    }

    fn export_data(&mut self, exporter: &mut SarifExporter, export: &GhidraProgramExport) {
        for data in &export.data {
            let addr = data.address.as_deref().unwrap_or("0x0");
            let type_name = data.type_name.as_deref().unwrap_or("unknown");
            exporter.add_result(
                "GhidraData".into(),
                format!("Data: {type_name} at {addr}"),
                SarifLevel::None,
                addr.to_string(),
            );
        }
    }

    fn export_comments(&mut self, exporter: &mut SarifExporter, export: &GhidraProgramExport) {
        // Comments are associated with addresses via the results they appear in
        for comment in &export.comments {
            let kind = comment.kind.as_deref().unwrap_or("eol");
            let value = comment.value.as_deref().unwrap_or("");
            // Comments don't have their own address, they're attached to code units
            // For now we create informational results
            exporter.add_result(
                "GhidraComment".into(),
                format!("[{kind}] {value}"),
                SarifLevel::None,
                "0x0".to_string(),
            );
        }
    }

    fn export_equates(&mut self, exporter: &mut SarifExporter, export: &GhidraProgramExport) {
        for equate in &export.equates {
            let name = equate.name.as_deref().unwrap_or("?");
            let value = equate.value.unwrap_or(0);
            exporter.add_result(
                "GhidraEquate".into(),
                format!("Equate: {name} = {value}"),
                SarifLevel::None,
                "0x0".to_string(),
            );
        }
    }

    fn export_relocations(
        &mut self,
        exporter: &mut SarifExporter,
        export: &GhidraProgramExport,
    ) {
        for reloc in &export.relocations {
            let addr = reloc.address.as_deref().unwrap_or("0x0");
            let symbol = reloc.symbol_name.as_deref().unwrap_or("?");
            let rtype = reloc.relocation_type.as_deref().unwrap_or("?");
            exporter.add_result(
                "GhidraRelocation".into(),
                format!("Relocation: {rtype} -> {symbol}"),
                SarifLevel::None,
                addr.to_string(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramSarifMgr -- orchestrates read/write of SARIF
// ---------------------------------------------------------------------------

/// Manager for reading and writing SARIF data for a Ghidra program.
///
/// This is the primary orchestrator for SARIF import/export. It holds
/// references to the program data and coordinates the various sub-managers
/// (functions, symbols, comments, etc.).
///
/// Ported from `ProgramSarifMgr.java`.
#[derive(Debug)]
pub struct ProgramSarifMgr {
    /// Write options.
    options: SarifWriteOptions,
    /// Accumulated messages/errors.
    messages: Vec<String>,
    /// The current program export data (for writing).
    export: GhidraProgramExport,
    /// The current SARIF log (for reading).
    current_log: Option<SarifLog>,
}

impl ProgramSarifMgr {
    /// Create a new program SARIF manager for writing.
    pub fn for_write(tool_name: impl Into<String>) -> Self {
        Self {
            options: SarifWriteOptions {
                tool_name: tool_name.into(),
                ..Default::default()
            },
            messages: Vec::new(),
            export: GhidraProgramExport::new(),
            current_log: None,
        }
    }

    /// Create a new program SARIF manager for reading from a file.
    pub fn for_read(path: &Path) -> io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let log: SarifLog =
            serde_json::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Self {
            options: SarifWriteOptions::default(),
            messages: Vec::new(),
            export: GhidraProgramExport::new(),
            current_log: Some(log),
        })
    }

    /// Create a new program SARIF manager for reading from a string.
    pub fn for_read_string(json: &str) -> io::Result<Self> {
        let log: SarifLog = serde_json::from_str(json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Self {
            options: SarifWriteOptions::default(),
            messages: Vec::new(),
            export: GhidraProgramExport::new(),
            current_log: Some(log),
        })
    }

    /// Set the write options.
    pub fn set_options(&mut self, options: SarifWriteOptions) {
        self.options = options;
    }

    /// Set program options from a `SarifProgramOptions`.
    pub fn set_program_options(&mut self, opts: SarifProgramOptions) {
        self.options.program_options = opts;
    }

    /// Get the accumulated messages.
    pub fn messages(&self) -> &[String] {
        &self.messages
    }

    /// Add a message.
    pub fn add_message(&mut self, msg: impl Into<String>) {
        self.messages.push(msg.into());
    }

    /// Get a reference to the program export data.
    pub fn export(&self) -> &GhidraProgramExport {
        &self.export
    }

    /// Get a mutable reference to the program export data.
    pub fn export_mut(&mut self) -> &mut GhidraProgramExport {
        &mut self.export
    }

    /// Get the current SARIF log (if reading).
    pub fn current_log(&self) -> Option<&SarifLog> {
        self.current_log.as_ref()
    }

    /// Get program info from the loaded SARIF (for import).
    ///
    /// Extracts the target language, compiler spec, and image base from
    /// the SARIF run's tool information and properties.
    pub fn get_program_info(&self) -> Option<SarifProgramInfo> {
        let log = self.current_log.as_ref()?;
        let run = log.runs.first()?;

        // Extract language info from tool properties or extensions
        let mut info = SarifProgramInfo::default();

        // Check tool properties for language ID
        if let Some(props) = &run.tool.driver.properties {
            if let Some(tags) = &props.tags {
                for tag in tags {
                    if let Some(lang) = tag.strip_prefix("language:") {
                        info.language_id = Some(lang.to_string());
                    } else if let Some(compiler) = tag.strip_prefix("compiler:") {
                        info.compiler_spec_id = Some(compiler.to_string());
                    }
                }
            }
        }

        // Check default source language
        info.language = run.default_source_language.clone();

        Some(info)
    }

    /// Write the accumulated program data to a SARIF file.
    pub fn write(&mut self, path: &Path) -> io::Result<()> {
        let mut task = SarifWriterTask::new("SARIF Export");
        task.execute(&self.export, &self.options, path)?;
        self.messages.extend(task.messages().iter().cloned());
        Ok(())
    }

    /// Read SARIF data and populate the program export.
    pub fn read(&mut self) -> io::Result<()> {
        let log = self
            .current_log
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No SARIF log loaded"))?;

        for run in &log.runs {
            if let Some(results) = &run.results {
                for result in results {
                    self.process_result(result);
                }
            }
        }

        Ok(())
    }

    fn process_result(&mut self, result: &SarifResult) {
        match result.rule_id.as_str() {
            "GhidraFunction" => {
                if let Some(locations) = &result.locations {
                    for loc in locations {
                        if let Some(phys) = &loc.physical_location {
                            if let Some(addr_obj) = &phys.address {
                                if let Some(addr) = &addr_obj.absolute_address {
                                    let text = result
                                        .message
                                        .text
                                        .as_deref()
                                        .unwrap_or("");
                                    let name = text
                                        .strip_prefix("Function: ")
                                        .unwrap_or(text);
                                    // Parse function name from message
                                    let func_name = name
                                        .split(" | ")
                                        .next()
                                        .unwrap_or(name);
                                    self.export.add_function(GhidraFunction::new(
                                        func_name,
                                        addr,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            "GhidraSymbol" => {
                if let Some(locations) = &result.locations {
                    for loc in locations {
                        if let Some(phys) = &loc.physical_location {
                            if let Some(addr_obj) = &phys.address {
                                if let Some(addr) = &addr_obj.absolute_address {
                                    let text = result
                                        .message
                                        .text
                                        .as_deref()
                                        .unwrap_or("");
                                    let name = text
                                        .strip_prefix("Symbol: ")
                                        .unwrap_or(text)
                                        .split(" (")
                                        .next()
                                        .unwrap_or(text);
                                    self.export.add_symbol(GhidraSymbol::new(name, addr));
                                }
                            }
                        }
                    }
                }
            }
            "GhidraEntryPoint" => {
                if let Some(locations) = &result.locations {
                    for loc in locations {
                        if let Some(phys) = &loc.physical_location {
                            if let Some(addr_obj) = &phys.address {
                                if let Some(addr) = &addr_obj.absolute_address {
                                    self.export
                                        .add_entry_point(GhidraEntryPoint::new(addr));
                                }
                            }
                        }
                    }
                }
            }
            "GhidraEquate" => {
                let text = result.message.text.as_deref().unwrap_or("");
                if let Some(rest) = text.strip_prefix("Equate: ") {
                    let parts: Vec<&str> = rest.split(" = ").collect();
                    if parts.len() == 2 {
                        let name = parts[0];
                        if let Ok(value) = parts[1].parse::<i64>() {
                            self.export.add_equate(GhidraEquate::new(name, value));
                        }
                    }
                }
            }
            _ => {
                // Unknown rule -- skip
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SarifProgramInfo -- program metadata from SARIF
// ---------------------------------------------------------------------------

/// Program information extracted from a SARIF log for import.
///
/// Used by the SARIF loader to determine the target language, compiler
/// spec, and other metadata needed to create or update a Ghidra program.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SarifProgramInfo {
    /// The Ghidra language ID (e.g., "x86:LE:64:default").
    pub language_id: Option<String>,
    /// The compiler spec ID (e.g., "default", "windows").
    pub compiler_spec_id: Option<String>,
    /// The processor name (e.g., "x86", "ARM").
    pub processor_name: Option<String>,
    /// The target language (from SARIF defaultSourceLanguage).
    pub language: Option<String>,
    /// The image base address.
    pub image_base: Option<String>,
    /// The address model (e.g., "64-bit").
    pub address_model: Option<String>,
    /// The endianness ("little" or "big").
    pub endian: Option<String>,
    /// The external tool name.
    pub external_tool_name: Option<String>,
}

impl SarifProgramInfo {
    /// Get the normalized external tool name.
    pub fn get_normalized_external_tool_name(&self) -> &str {
        self.external_tool_name.as_deref().unwrap_or("default")
    }
}

// ---------------------------------------------------------------------------
// SarifLoader -- binary loader for SARIF files
// ---------------------------------------------------------------------------

/// Loader for importing SARIF files into a Ghidra program.
///
/// This loader reads a `.sarif` (or `.json`) file, extracts the program
/// metadata and analysis data, and populates a Ghidra program with the
/// imported information.
///
/// Ported from `SarifLoader.java`.
#[derive(Debug)]
pub struct SarifLoader {
    /// Loader name.
    pub name: String,
    /// Whether the loader supports loading into an existing program.
    pub supports_load_into: bool,
}

impl SarifLoader {
    /// SARIF file extension.
    pub const SARIF_EXTENSION: &'static str = ".sarif";
    /// JSON file extension (also accepted).
    pub const JSON_EXTENSION: &'static str = ".json";
    /// Loader source name.
    pub const SARIF_SRC_NAME: &'static str = "SARIF Input Format";

    /// Create a new SARIF loader.
    pub fn new() -> Self {
        Self {
            name: Self::SARIF_SRC_NAME.to_string(),
            supports_load_into: true,
        }
    }

    /// Check if the given file extension is supported.
    pub fn supports_extension(ext: &str) -> bool {
        ext.eq_ignore_ascii_case(Self::SARIF_EXTENSION)
            || ext.eq_ignore_ascii_case(Self::JSON_EXTENSION)
    }

    /// Check if the data at the beginning of a file looks like SARIF JSON.
    ///
    /// Looks for the `"version"` and `"$schema"` keys that are required
    /// in a SARIF 2.1.0 log.
    pub fn can_load(data: &[u8]) -> bool {
        let text = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // Quick heuristic: must contain SARIF version and schema
        text.contains("\"version\"")
            && text.contains("\"2.1.0\"")
            && (text.contains("sarif") || text.contains("$schema"))
    }

    /// Parse a SARIF file and extract program info.
    pub fn parse(&self, data: &[u8]) -> io::Result<(SarifLog, SarifProgramInfo)> {
        let text = std::str::from_utf8(data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let log: SarifLog = serde_json::from_str(text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mgr = ProgramSarifMgr {
            options: SarifWriteOptions::default(),
            messages: Vec::new(),
            export: GhidraProgramExport::new(),
            current_log: Some(log.clone()),
        };

        let info = mgr.get_program_info().unwrap_or_default();
        Ok((log, info))
    }

    /// Load SARIF data and return the program export.
    pub fn load(&self, data: &[u8], options: &SarifProgramOptions) -> io::Result<ProgramSarifMgr> {
        let text = std::str::from_utf8(data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut mgr = ProgramSarifMgr::for_read_string(text)?;
        mgr.set_program_options(options.clone());
        mgr.read()?;
        Ok(mgr)
    }

    /// Load a SARIF file from disk.
    pub fn load_file(
        &self,
        path: &Path,
        options: &SarifProgramOptions,
    ) -> io::Result<ProgramSarifMgr> {
        let data = std::fs::read(path)?;
        self.load(&data, options)
    }

    /// Get the preferred file name (strip .sarif/.json extension).
    pub fn preferred_file_name<'a>(&self, name: &'a str) -> &'a str {
        if name.to_lowercase().ends_with(Self::SARIF_EXTENSION) {
            &name[..name.len() - Self::SARIF_EXTENSION.len()]
        } else if name.to_lowercase().ends_with(Self::JSON_EXTENSION) {
            &name[..name.len() - Self::JSON_EXTENSION.len()]
        } else {
            name
        }
    }
}

impl Default for SarifLoader {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AbstractSarifWriter -- trait for sub-writers
// ---------------------------------------------------------------------------

/// Trait for individual category writers that contribute results to a
/// SARIF export.
///
/// Ported from `AbstractExtWriter.java`.
pub trait AbstractSarifWriter: Send + Sync {
    /// The name of this writer (e.g., "Functions", "Symbols").
    fn name(&self) -> &str;

    /// The rule ID prefix for results produced by this writer.
    fn rule_id_prefix(&self) -> &str;

    /// Write results for the given program export into the SARIF exporter.
    fn write(&self, export: &GhidraProgramExport, exporter: &mut SarifExporter);
}

/// Writer for function data.
#[derive(Debug)]
pub struct SarifFunctionWriter;

impl AbstractSarifWriter for SarifFunctionWriter {
    fn name(&self) -> &str {
        "Functions"
    }

    fn rule_id_prefix(&self) -> &str {
        "GhidraFunction"
    }

    fn write(&self, export: &GhidraProgramExport, exporter: &mut SarifExporter) {
        for func in &export.functions {
            let addr = func.location.as_deref().unwrap_or("0x0");
            let name = func.name.as_deref().unwrap_or("<unknown>");
            exporter.add_result(
                "GhidraFunction".into(),
                format!("Function: {name}"),
                SarifLevel::None,
                addr.to_string(),
            );
        }
    }
}

/// Writer for symbol data.
#[derive(Debug)]
pub struct SarifSymbolWriter;

impl AbstractSarifWriter for SarifSymbolWriter {
    fn name(&self) -> &str {
        "Symbols"
    }

    fn rule_id_prefix(&self) -> &str {
        "GhidraSymbol"
    }

    fn write(&self, export: &GhidraProgramExport, exporter: &mut SarifExporter) {
        for sym in &export.symbols {
            let addr = sym.address.as_deref().unwrap_or("0x0");
            let name = sym.name.as_deref().unwrap_or("<unknown>");
            exporter.add_result(
                "GhidraSymbol".into(),
                format!("Symbol: {name}"),
                SarifLevel::None,
                addr.to_string(),
            );
        }
    }
}

/// Writer for memory block data.
#[derive(Debug)]
pub struct SarifMemoryMapWriter;

impl AbstractSarifWriter for SarifMemoryMapWriter {
    fn name(&self) -> &str {
        "MemoryMap"
    }

    fn rule_id_prefix(&self) -> &str {
        "GhidraMemoryBlock"
    }

    fn write(&self, export: &GhidraProgramExport, exporter: &mut SarifExporter) {
        for block in &export.memory_blocks {
            let name = block.name.as_deref().unwrap_or("?");
            let start = block.start_address.as_deref().unwrap_or("0x0");
            let end = block.end_address.as_deref().unwrap_or("0x0");
            exporter.add_result(
                "GhidraMemoryBlock".into(),
                format!("Memory: {name} [{start} - {end}]"),
                SarifLevel::None,
                start.to_string(),
            );
        }
    }
}

/// Writer for bookmark data.
#[derive(Debug)]
pub struct SarifBookmarkWriter;

impl AbstractSarifWriter for SarifBookmarkWriter {
    fn name(&self) -> &str {
        "Bookmarks"
    }

    fn rule_id_prefix(&self) -> &str {
        "GhidraBookmark"
    }

    fn write(&self, export: &GhidraProgramExport, exporter: &mut SarifExporter) {
        for bm in &export.bookmarks {
            let kind = bm.kind.as_deref().unwrap_or("?");
            let comment = bm.comment.as_deref().unwrap_or("");
            exporter.add_result(
                "GhidraBookmark".into(),
                format!("Bookmark [{kind}]: {comment}"),
                SarifLevel::None,
                "0x0".to_string(),
            );
        }
    }
}

/// Writer for relocation data.
#[derive(Debug)]
pub struct SarifRelocationWriter;

impl AbstractSarifWriter for SarifRelocationWriter {
    fn name(&self) -> &str {
        "Relocations"
    }

    fn rule_id_prefix(&self) -> &str {
        "GhidraRelocation"
    }

    fn write(&self, export: &GhidraProgramExport, exporter: &mut SarifExporter) {
        for reloc in &export.relocations {
            let addr = reloc.address.as_deref().unwrap_or("0x0");
            let symbol = reloc.symbol_name.as_deref().unwrap_or("?");
            let rtype = reloc.relocation_type.as_deref().unwrap_or("?");
            exporter.add_result(
                "GhidraRelocation".into(),
                format!("Relocation: {rtype} -> {symbol}"),
                SarifLevel::None,
                addr.to_string(),
            );
        }
    }
}

/// Writer for equate data.
#[derive(Debug)]
pub struct SarifEquateWriter;

impl AbstractSarifWriter for SarifEquateWriter {
    fn name(&self) -> &str {
        "Equates"
    }

    fn rule_id_prefix(&self) -> &str {
        "GhidraEquate"
    }

    fn write(&self, export: &GhidraProgramExport, exporter: &mut SarifExporter) {
        for equate in &export.equates {
            let name = equate.name.as_deref().unwrap_or("?");
            let value = equate.value.unwrap_or(0);
            exporter.add_result(
                "GhidraEquate".into(),
                format!("Equate: {name} = {value}"),
                SarifLevel::None,
                "0x0".to_string(),
            );
        }
    }
}

/// Writer for entry point data.
#[derive(Debug)]
pub struct SarifEntryPointWriter;

impl AbstractSarifWriter for SarifEntryPointWriter {
    fn name(&self) -> &str {
        "EntryPoints"
    }

    fn rule_id_prefix(&self) -> &str {
        "GhidraEntryPoint"
    }

    fn write(&self, export: &GhidraProgramExport, exporter: &mut SarifExporter) {
        for ep in &export.entry_points {
            let addr = ep.address.as_deref().unwrap_or("0x0");
            exporter.add_result(
                "GhidraEntryPoint".into(),
                format!("Entry point: {addr}"),
                SarifLevel::None,
                addr.to_string(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif_write_options_default() {
        let opts = SarifWriteOptions::default();
        assert_eq!(opts.tool_name, "Ghidra Rust");
        assert!(opts.include_function_details);
        assert!(opts.pretty_print);
    }

    #[test]
    fn test_sarif_writer_task_lifecycle() {
        let mut task = SarifWriterTask::new("Test Export");
        assert_eq!(task.status(), SarifTaskStatus::NotStarted);

        let export = GhidraProgramExport::new();
        let options = SarifWriteOptions::default();
        let tmp = std::env::temp_dir().join("test_sarif_writer_task.sarif");

        task.execute(&export, &options, &tmp).unwrap();
        assert_eq!(task.status(), SarifTaskStatus::Completed);
        assert_eq!(task.progress(), 1.0);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_sarif_writer_task_with_data() {
        let mut export = GhidraProgramExport::new();
        export.add_function(GhidraFunction::new("main", "0x401000"));
        export.add_symbol(GhidraSymbol::new("printf", "0x402000"));
        export.add_entry_point(GhidraEntryPoint::new("0x401000"));

        let options = SarifWriteOptions::default();
        let tmp = std::env::temp_dir().join("test_sarif_writer_data.sarif");

        let mut task = SarifWriterTask::new("Data Export");
        task.execute(&export, &options, &tmp).unwrap();

        assert_eq!(task.status(), SarifTaskStatus::Completed);

        // Verify file was written and contains expected data
        let content = std::fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("GhidraFunction"));
        assert!(content.contains("GhidraSymbol"));
        assert!(content.contains("GhidraEntryPoint"));
        assert!(content.contains("main"));
        assert!(content.contains("printf"));

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_program_sarif_mgr_write() {
        let mut mgr = ProgramSarifMgr::for_write("TestTool");
        mgr.export_mut()
            .add_function(GhidraFunction::new("test_fn", "0x500000"));

        let tmp = std::env::temp_dir().join("test_mgr_write.sarif");
        mgr.write(&tmp).unwrap();

        let content = std::fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("test_fn"));
        assert!(content.contains("0x500000"));

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_program_sarif_mgr_read() {
        let json = r#"{
            "version": "2.1.0",
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "TestTool"}},
                "results": [{
                    "ruleId": "GhidraFunction",
                    "message": {"text": "Function: my_func | namespace: NS"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "my_func"},
                            "address": {"absoluteAddress": "0x401000"}
                        }
                    }]
                }, {
                    "ruleId": "GhidraSymbol",
                    "message": {"text": "Symbol: puts (Function)"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "puts"},
                            "address": {"absoluteAddress": "0x402000"}
                        }
                    }]
                }]
            }]
        }"#;

        let mut mgr = ProgramSarifMgr::for_read_string(json).unwrap();
        mgr.read().unwrap();

        assert_eq!(mgr.export().functions.len(), 1);
        assert_eq!(mgr.export().functions[0].name, Some("my_func".into()));
        assert_eq!(mgr.export().functions[0].location, Some("0x401000".into()));
        assert_eq!(mgr.export().symbols.len(), 1);
        assert_eq!(mgr.export().symbols[0].name, Some("puts".into()));
    }

    #[test]
    fn test_sarif_loader() {
        let loader = SarifLoader::new();
        assert_eq!(loader.name, "SARIF Input Format");
        assert!(loader.supports_load_into);
    }

    #[test]
    fn test_sarif_loader_can_load() {
        let sarif_data = br#"{
            "version": "2.1.0",
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
            "runs": []
        }"#;
        assert!(SarifLoader::can_load(sarif_data));

        let not_sarif = b"this is not sarif";
        assert!(!SarifLoader::can_load(not_sarif));
    }

    #[test]
    fn test_sarif_loader_supports_extension() {
        assert!(SarifLoader::supports_extension(".sarif"));
        assert!(SarifLoader::supports_extension(".SARIF"));
        assert!(SarifLoader::supports_extension(".json"));
        assert!(!SarifLoader::supports_extension(".xml"));
    }

    #[test]
    fn test_sarif_loader_preferred_file_name() {
        let loader = SarifLoader::new();
        assert_eq!(loader.preferred_file_name("test.sarif"), "test");
        assert_eq!(loader.preferred_file_name("test.json"), "test");
        assert_eq!(loader.preferred_file_name("test.SARIF"), "test");
        assert_eq!(loader.preferred_file_name("test.txt"), "test.txt");
    }

    #[test]
    fn test_sarif_loader_parse() {
        let json = br#"{
            "version": "2.1.0",
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "TestTool"}},
                "results": []
            }]
        }"#;

        let loader = SarifLoader::new();
        let (log, _info) = loader.parse(json).unwrap();
        assert_eq!(log.version, "2.1.0");
    }

    #[test]
    fn test_sarif_program_info() {
        let info = SarifProgramInfo {
            language_id: Some("x86:LE:64:default".into()),
            compiler_spec_id: Some("default".into()),
            ..Default::default()
        };
        assert_eq!(info.language_id.as_deref(), Some("x86:LE:64:default"));
        assert_eq!(info.get_normalized_external_tool_name(), "default");
    }

    #[test]
    fn test_sub_writers() {
        let mut export = GhidraProgramExport::new();
        export.add_function(GhidraFunction::new("fn1", "0x1000"));
        export.add_symbol(GhidraSymbol::new("sym1", "0x2000"));
        export.add_memory_block(GhidraMemoryBlock::new(".text", "0x1000", "0x5000"));
        export.add_bookmark(GhidraBookmark::new("Warning"));
        export.add_equate(GhidraEquate::new("NULL", 0));
        export.add_entry_point(GhidraEntryPoint::new("0x1000"));
        export.add_relocation(GhidraRelocation::new("0x3000", "printf", "R_X86_64_PC32"));

        let mut exporter = SarifExporter::new("SubWriterTest".to_string());

        SarifFunctionWriter.write(&export, &mut exporter);
        SarifSymbolWriter.write(&export, &mut exporter);
        SarifMemoryMapWriter.write(&export, &mut exporter);
        SarifBookmarkWriter.write(&export, &mut exporter);
        SarifEquateWriter.write(&export, &mut exporter);
        SarifEntryPointWriter.write(&export, &mut exporter);
        SarifRelocationWriter.write(&export, &mut exporter);

        let json = exporter.to_json().unwrap();
        assert!(json.contains("GhidraFunction"));
        assert!(json.contains("GhidraSymbol"));
        assert!(json.contains("GhidraMemoryBlock"));
        assert!(json.contains("GhidraBookmark"));
        assert!(json.contains("GhidraEquate"));
        assert!(json.contains("GhidraEntryPoint"));
        assert!(json.contains("GhidraRelocation"));
    }

    #[test]
    fn test_task_status_display() {
        let mut task = SarifWriterTask::new("Test");
        assert_eq!(task.status(), SarifTaskStatus::NotStarted);
        assert_eq!(task.progress(), 0.0);
        assert_eq!(task.phase(), "");
    }

    #[test]
    fn test_sarif_loader_file_roundtrip() {
        let mut export = GhidraProgramExport::new();
        export.add_function(GhidraFunction::new("roundtrip_fn", "0x800000"));
        export.add_symbol(GhidraSymbol::new("roundtrip_sym", "0x801000"));
        export.add_equate(GhidraEquate::new("MY_CONST", 42));

        let tmp = std::env::temp_dir().join("test_roundtrip.sarif");
        let mut mgr = ProgramSarifMgr::for_write("RoundTripTool");
        *mgr.export_mut() = export;
        mgr.write(&tmp).unwrap();

        // Read it back
        let loader = SarifLoader::new();
        let read_mgr = loader.load_file(&tmp, &SarifProgramOptions::default()).unwrap();
        assert_eq!(read_mgr.export().functions.len(), 1);
        assert_eq!(read_mgr.export().symbols.len(), 1);
        assert_eq!(read_mgr.export().equates.len(), 1);
        assert_eq!(read_mgr.export().equates[0].name, Some("MY_CONST".into()));
        assert_eq!(read_mgr.export().equates[0].value, Some(42));

        let _ = std::fs::remove_file(&tmp);
    }
}
