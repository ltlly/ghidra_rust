//! Default PDB Applicator -- main orchestrator for applying PDB data to a program.
//!
//! Ports Ghidra's `ghidra.app.util.pdb.pdbapplicator.DefaultPdbApplicator`.
//!
//! This is the top-level coordinator that drives the entire PDB application
//! process. It manages the lifecycle of type application, symbol application,
//! and debug information application through the dedicated factory modules.
//!
//! # Responsibilities
//!
//! - Parsing the PDB and building the reader context.
//! - Orchestrating type application via [`TypeApplierFactory`].
//! - Orchestrating symbol application via [`SymbolApplierFactory`].
//! - Managing metrics and options across the application pipeline.
//! - Providing cancellation support for long-running operations.

use std::collections::{HashMap, HashSet};
use std::fmt;

use super::super::pdb_applicator_metrics::PdbApplicatorMetrics;
use super::super::pdb_applicator_options::{PdbApplicatorControl, PdbApplicatorOptions};
use super::super::abstract_pdb::{AbstractPdb, PdbReaderContext};
use super::super::pdb_exception::PdbException;
use super::super::{
    MsfFile, PdbFile, PdbInfoStream, TpiStream, IpiStream, DbiStream,
    TypeRecord, SymbolRecord, SymbolStream,
    parse_msf, parse_pdb_info_stream, parse_tpi_stream, parse_ipi_stream, parse_dbi_stream,
};

use super::symbol_applier_factory::{SymbolApplierFactory, SymbolApplyError};
use super::type_applier_factory::{TypeApplierFactory, TypeApplyError};

// =============================================================================
// Errors
// =============================================================================

/// Errors specific to the default PDB applicator.
#[derive(Debug, Clone)]
pub enum DefaultPdbApplicatorError {
    /// The PDB could not be parsed.
    PdbParseError(String),
    /// A required stream was missing.
    MissingStream(&'static str),
    /// Application was cancelled by the user or a timeout.
    Cancelled,
    /// An internal error occurred during application.
    InternalError(String),
    /// The applicator is in an invalid state.
    InvalidState(String),
}

impl fmt::Display for DefaultPdbApplicatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PdbParseError(msg) => write!(f, "PDB parse error: {}", msg),
            Self::MissingStream(name) => write!(f, "Missing PDB stream: {}", name),
            Self::Cancelled => write!(f, "PDB application cancelled"),
            Self::InternalError(msg) => write!(f, "Internal applicator error: {}", msg),
            Self::InvalidState(msg) => write!(f, "Invalid applicator state: {}", msg),
        }
    }
}

impl std::error::Error for DefaultPdbApplicatorError {}

impl From<PdbException> for DefaultPdbApplicatorError {
    fn from(e: PdbException) -> Self {
        Self::PdbParseError(e.to_string())
    }
}

// =============================================================================
// Application Phase
// =============================================================================

/// Tracks which phase of PDB application is currently in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicatorPhase {
    /// No application has started yet.
    NotStarted,
    /// Parsing the PDB file.
    ParsingPdb,
    /// Applying type information from TPI/IPI streams.
    ApplyingTypes,
    /// Applying symbol records from DBI module streams.
    ApplyingSymbols,
    /// Applying debug information (line numbers, source files).
    ApplyingDebugInfo,
    /// Application completed successfully.
    Completed,
    /// Application encountered an error.
    Error,
}

impl ApplicatorPhase {
    /// Get a human-readable label for this phase.
    pub fn label(&self) -> &'static str {
        match self {
            Self::NotStarted => "Not Started",
            Self::ParsingPdb => "Parsing PDB",
            Self::ApplyingTypes => "Applying Types",
            Self::ApplyingSymbols => "Applying Symbols",
            Self::ApplyingDebugInfo => "Applying Debug Info",
            Self::Completed => "Completed",
            Self::Error => "Error",
        }
    }
}

impl fmt::Display for ApplicatorPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// =============================================================================
// DefaultPdbApplicator
// =============================================================================

/// The main orchestrator for applying PDB data to a Ghidra program.
///
/// This struct coordinates the full PDB application pipeline:
///
/// 1. Parse the PDB file into a [`PdbReaderContext`].
/// 2. Apply types from TPI/IPI via [`TypeApplierFactory`].
/// 3. Apply symbols from DBI module streams via [`SymbolApplierFactory`].
/// 4. Apply debug information (line numbers, source file checksums).
///
/// Mirrors Ghidra's `DefaultPdbApplicator` Java class which is the primary
/// entry point invoked by the PDB analyzer plugin.
pub struct DefaultPdbApplicator {
    /// Configuration options.
    options: PdbApplicatorOptions,
    /// The PDB reader context (populated after parsing).
    reader_context: Option<PdbReaderContext>,
    /// The type applier factory.
    type_factory: TypeApplierFactory,
    /// The symbol applier factory.
    symbol_factory: SymbolApplierFactory,
    /// Metrics collected during application.
    metrics: PdbApplicatorMetrics,
    /// Current application phase.
    phase: ApplicatorPhase,
    /// Set of processed type indices to avoid re-processing.
    processed_types: HashSet<u32>,
    /// Set of processed symbol names to track coverage.
    processed_symbols: HashSet<String>,
    /// Whether a cancellation has been requested.
    cancelled: bool,
    /// Errors encountered during application (non-fatal).
    warnings: Vec<String>,
}

impl DefaultPdbApplicator {
    /// Create a new applicator with default options.
    pub fn new() -> Self {
        Self {
            options: PdbApplicatorOptions::default(),
            reader_context: None,
            type_factory: TypeApplierFactory::new(),
            symbol_factory: SymbolApplierFactory::new(),
            metrics: PdbApplicatorMetrics::new(),
            phase: ApplicatorPhase::NotStarted,
            processed_types: HashSet::new(),
            processed_symbols: HashSet::new(),
            cancelled: false,
            warnings: Vec::new(),
        }
    }

    /// Create a new applicator with custom options.
    pub fn with_options(options: PdbApplicatorOptions) -> Self {
        Self {
            options,
            ..Self::new()
        }
    }

    // =========================================================================
    // Configuration
    // =========================================================================

    /// Get the current options.
    pub fn options(&self) -> &PdbApplicatorOptions {
        &self.options
    }

    /// Get mutable access to the options.
    pub fn options_mut(&mut self) -> &mut PdbApplicatorOptions {
        &mut self.options
    }

    /// Set new options.
    pub fn set_options(&mut self, options: PdbApplicatorOptions) {
        self.options = options;
    }

    // =========================================================================
    // State queries
    // =========================================================================

    /// Get the current application phase.
    pub fn phase(&self) -> ApplicatorPhase {
        self.phase
    }

    /// Get the collected metrics.
    pub fn metrics(&self) -> &PdbApplicatorMetrics {
        &self.metrics
    }

    /// Get the PDB reader context, if a PDB has been parsed.
    pub fn reader_context(&self) -> Option<&PdbReaderContext> {
        self.reader_context.as_ref()
    }

    /// Get the type applier factory.
    pub fn type_factory(&self) -> &TypeApplierFactory {
        &self.type_factory
    }

    /// Get the symbol applier factory.
    pub fn symbol_factory(&self) -> &SymbolApplierFactory {
        &self.symbol_factory
    }

    /// Get the number of types that have been processed.
    pub fn processed_type_count(&self) -> usize {
        self.processed_types.len()
    }

    /// Get the number of symbols that have been processed.
    pub fn processed_symbol_count(&self) -> usize {
        self.processed_symbols.len()
    }

    /// Get any warnings collected during application.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Check whether application has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    // =========================================================================
    // Control
    // =========================================================================

    /// Request cancellation of the current application.
    ///
    /// The application will stop at the next cancellation check point.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Reset the applicator state for a fresh application.
    pub fn reset(&mut self) {
        self.reader_context = None;
        self.type_factory = TypeApplierFactory::new();
        self.symbol_factory = SymbolApplierFactory::new();
        self.metrics = PdbApplicatorMetrics::new();
        self.phase = ApplicatorPhase::NotStarted;
        self.processed_types.clear();
        self.processed_symbols.clear();
        self.cancelled = false;
        self.warnings.clear();
    }

    // =========================================================================
    // Main application pipeline
    // =========================================================================

    /// Apply PDB data from raw bytes.
    ///
    /// This is the main entry point. It parses the PDB and then applies
    /// types, symbols, and debug information based on the current options.
    pub fn apply_bytes(&mut self, data: &[u8]) -> Result<(), DefaultPdbApplicatorError> {
        self.phase = ApplicatorPhase::ParsingPdb;

        let context = PdbReaderContext::parse(data)?;
        self.reader_context = Some(context);

        self.apply_from_context()
    }

    /// Apply PDB data from a pre-parsed PDB file.
    pub fn apply_pdb_file(&mut self, pdb: PdbFile) -> Result<(), DefaultPdbApplicatorError> {
        self.phase = ApplicatorPhase::ParsingPdb;

        // Convert PdbFile into PdbReaderContext
        let msf = pdb.msf;
        let info = pdb.info;
        let tpi = pdb.tpi;
        let dbi = pdb.dbi;
        let ipi = pdb.ipi;

        let type_names = Self::build_type_name_cache_static(&tpi);

        let context = PdbReaderContext {
            msf,
            info,
            tpi,
            dbi,
            ipi,
            type_names,
        };
        self.reader_context = Some(context);

        self.apply_from_context()
    }

    /// Apply PDB data from an already-constructed reader context.
    fn apply_from_context(&mut self) -> Result<(), DefaultPdbApplicatorError> {
        let control = self.options.control();

        // Phase 1: Apply types
        if control == PdbApplicatorControl::All || control == PdbApplicatorControl::DataTypesOnly {
            if self.cancelled {
                self.phase = ApplicatorPhase::Error;
                return Err(DefaultPdbApplicatorError::Cancelled);
            }
            self.phase = ApplicatorPhase::ApplyingTypes;
            self.apply_types()?;
        }

        // Phase 2: Apply symbols
        if control == PdbApplicatorControl::All || control == PdbApplicatorControl::PublicSymbolsOnly {
            if self.cancelled {
                self.phase = ApplicatorPhase::Error;
                return Err(DefaultPdbApplicatorError::Cancelled);
            }
            self.phase = ApplicatorPhase::ApplyingSymbols;
            self.apply_symbols()?;
        }

        // Phase 3: Apply debug info
        if control == PdbApplicatorControl::All && self.options.apply_source_line_numbers() {
            if self.cancelled {
                self.phase = ApplicatorPhase::Error;
                return Err(DefaultPdbApplicatorError::Cancelled);
            }
            self.phase = ApplicatorPhase::ApplyingDebugInfo;
            self.apply_debug_info()?;
        }

        self.phase = ApplicatorPhase::Completed;
        Ok(())
    }

    /// Apply type records using the type applier factory.
    fn apply_types(&mut self) -> Result<(), DefaultPdbApplicatorError> {
        let context = self.reader_context.as_ref()
            .ok_or_else(|| DefaultPdbApplicatorError::InvalidState("No PDB parsed".into()))?;

        // Process TPI types
        if let Some(ref tpi) = context.tpi {
            let base_index = tpi.type_index_begin;
            for (i, record) in tpi.types.iter().enumerate() {
                if self.cancelled {
                    return Err(DefaultPdbApplicatorError::Cancelled);
                }

                let type_index = base_index + i as u32;
                if self.processed_types.contains(&type_index) {
                    continue;
                }

                self.metrics.inc_types_processed();

                match self.type_factory.apply_type(record, type_index, context) {
                    Ok(_applied) => {
                        self.processed_types.insert(type_index);
                        self.metrics.inc_types_applied();
                    }
                    Err(TypeApplyError::Unsupported) => {
                        // Record unsupported type but continue
                        let name = format!("type_0x{:04X}", type_index);
                        self.metrics.witness_cannot_apply_type(&name);
                    }
                    Err(TypeApplyError::Cancelled) => {
                        return Err(DefaultPdbApplicatorError::Cancelled);
                    }
                    Err(e) => {
                        self.warnings.push(format!(
                            "Error applying type 0x{:04X}: {}", type_index, e
                        ));
                    }
                }
            }
        }

        // Process IPI items
        if let Some(ref ipi) = context.ipi {
            let base_index = ipi.type_index_begin;
            for (i, record) in ipi.items.iter().enumerate() {
                if self.cancelled {
                    return Err(DefaultPdbApplicatorError::Cancelled);
                }

                let type_index = base_index + i as u32;
                if self.processed_types.contains(&type_index) {
                    continue;
                }

                self.metrics.inc_types_processed();

                match self.type_factory.apply_type(record, type_index, context) {
                    Ok(_applied) => {
                        self.processed_types.insert(type_index);
                        self.metrics.inc_types_applied();
                    }
                    Err(TypeApplyError::Unsupported) => {
                        let name = format!("item_0x{:04X}", type_index);
                        self.metrics.witness_cannot_apply_type(&name);
                    }
                    Err(TypeApplyError::Cancelled) => {
                        return Err(DefaultPdbApplicatorError::Cancelled);
                    }
                    Err(e) => {
                        self.warnings.push(format!(
                            "Error applying IPI item 0x{:04X}: {}", type_index, e
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Apply symbol records using the symbol applier factory.
    fn apply_symbols(&mut self) -> Result<(), DefaultPdbApplicatorError> {
        // Collect the stream data we need before entering mutable borrows.
        // This avoids holding an immutable borrow on self.reader_context
        // while calling self.apply_symbol_stream (which needs &mut self).
        let streams_to_process: Vec<(Vec<u8>, String)> = {
            let context = self.reader_context.as_ref()
                .ok_or_else(|| DefaultPdbApplicatorError::InvalidState("No PDB parsed".into()))?;

            let mut streams = Vec::new();

            if let Some(ref dbi) = context.dbi {
                // Global symbols
                let gsi_index = dbi.gsi as u32;
                if let Some(gsi_data) = context.msf.read_stream(gsi_index) {
                    streams.push((gsi_data, "global".to_string()));
                }

                // Public symbols
                let psi_index = dbi.psi as u32;
                if let Some(psi_data) = context.msf.read_stream(psi_index) {
                    streams.push((psi_data, "public".to_string()));
                }

                // Per-module symbols
                for module in &dbi.modules {
                    if module.module_sym_stream > 0 {
                        if let Some(sym_data) = context.msf.read_stream(module.module_sym_stream as u32) {
                            streams.push((sym_data, module.module_name.clone()));
                        }
                    }
                }
            }

            streams
        };

        // Now process each stream with mutable access to self
        for (data, label) in &streams_to_process {
            if self.cancelled {
                return Err(DefaultPdbApplicatorError::Cancelled);
            }
            self.apply_symbol_stream(data, label)?;
        }

        Ok(())
    }

    /// Apply all symbols from a single symbol stream.
    fn apply_symbol_stream(
        &mut self,
        data: &[u8],
        stream_label: &str,
    ) -> Result<(), DefaultPdbApplicatorError> {
        let stream = SymbolStream::new(data);
        for symbol in stream {
            if self.cancelled {
                return Err(DefaultPdbApplicatorError::Cancelled);
            }

            self.metrics.inc_symbols_processed();

            match self.symbol_factory.apply_symbol(&symbol, self.reader_context.as_ref()) {
                Ok(applied) => {
                    if applied {
                        self.metrics.inc_symbols_applied();
                    }
                }
                Err(SymbolApplyError::Unsupported) => {
                    // Unsupported symbols are expected
                }
                Err(SymbolApplyError::Cancelled) => {
                    return Err(DefaultPdbApplicatorError::Cancelled);
                }
                Err(e) => {
                    self.warnings.push(format!(
                        "Error applying symbol in {}: {}", stream_label, e
                    ));
                }
            }
        }

        Ok(())
    }

    /// Apply debug information (line numbers, source files).
    fn apply_debug_info(&mut self) -> Result<(), DefaultPdbApplicatorError> {
        let context = self.reader_context.as_ref()
            .ok_or_else(|| DefaultPdbApplicatorError::InvalidState("No PDB parsed".into()))?;

        if let Some(ref dbi) = context.dbi {
            for module in &dbi.modules {
                if self.cancelled {
                    return Err(DefaultPdbApplicatorError::Cancelled);
                }

                // In a full implementation, this would parse C13 subsection
                // streams from each module to apply line number and file
                // checksum information.
                if module.module_sym_stream > 0 {
                    // Placeholder for C13 line info parsing
                }
            }
        }

        Ok(())
    }

    /// Build a type index to name mapping from the TPI stream.
    fn build_type_name_cache_static(tpi: &Option<TpiStream>) -> HashMap<u32, String> {
        let mut map = HashMap::new();
        if let Some(ref tpi) = tpi {
            let base_index = tpi.type_index_begin;
            for (i, rec) in tpi.types.iter().enumerate() {
                let ti = base_index + i as u32;
                if let Some(name) = Self::type_record_name_static(rec) {
                    map.insert(ti, name);
                }
            }
        }
        map
    }

    /// Extract the name from a type record.
    fn type_record_name_static(record: &TypeRecord) -> Option<String> {
        match record {
            TypeRecord::Class(c) => Some(c.name.clone()),
            TypeRecord::Structure(s) => Some(s.name.clone()),
            TypeRecord::Union(u) => Some(u.name.clone()),
            TypeRecord::Enum(e) => Some(e.name.clone()),
            TypeRecord::Array(a) => Some(a.name.clone()),
            _ => None,
        }
    }

    // =========================================================================
    // Query helpers
    // =========================================================================

    /// Look up a type record by index from the parsed context.
    pub fn get_type_record(&self, type_index: u32) -> Option<&TypeRecord> {
        self.reader_context.as_ref().and_then(|ctx| ctx.get_type(type_index))
    }

    /// Get the name of a type by its index.
    pub fn get_type_name(&self, type_index: u32) -> Option<&str> {
        self.reader_context.as_ref().and_then(|ctx| ctx.get_type_name(type_index))
    }

    /// Get the total number of types in the TPI stream.
    pub fn tpi_type_count(&self) -> usize {
        self.reader_context.as_ref().map(|ctx| ctx.type_count()).unwrap_or(0)
    }

    /// Check if the PDB has debug information.
    pub fn has_debug_info(&self) -> bool {
        self.reader_context.as_ref().map(|ctx| ctx.has_debug_info()).unwrap_or(false)
    }

    /// Generate a summary report of the application.
    pub fn summary_report(&self) -> String {
        let mut report = String::new();
        report.push_str(&format!("Phase: {}\n", self.phase));
        report.push_str(&format!("Types processed: {}\n", self.processed_types.len()));
        report.push_str(&format!("Symbols processed: {}\n", self.processed_symbols.len()));
        report.push_str(&format!("Warnings: {}\n", self.warnings.len()));
        report.push_str(&self.metrics.report());
        report
    }
}

impl Default for DefaultPdbApplicator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DefaultPdbApplicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultPdbApplicator")
            .field("phase", &self.phase)
            .field("options", &self.options)
            .field("processed_types", &self.processed_types.len())
            .field("processed_symbols", &self.processed_symbols.len())
            .field("warnings", &self.warnings.len())
            .field("cancelled", &self.cancelled)
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_applicator_default() {
        let app = DefaultPdbApplicator::new();
        assert_eq!(app.phase(), ApplicatorPhase::NotStarted);
        assert!(!app.is_cancelled());
        assert_eq!(app.processed_type_count(), 0);
        assert_eq!(app.processed_symbol_count(), 0);
        assert!(app.reader_context().is_none());
        assert!(app.warnings().is_empty());
    }

    #[test]
    fn test_applicator_with_options() {
        let mut opts = PdbApplicatorOptions::default();
        opts.set_apply_source_line_numbers(false);
        let app = DefaultPdbApplicator::with_options(opts);
        assert!(!app.options().apply_source_line_numbers());
    }

    #[test]
    fn test_phase_display() {
        assert_eq!(format!("{}", ApplicatorPhase::NotStarted), "Not Started");
        assert_eq!(format!("{}", ApplicatorPhase::ApplyingTypes), "Applying Types");
        assert_eq!(format!("{}", ApplicatorPhase::Completed), "Completed");
    }

    #[test]
    fn test_cancel() {
        let mut app = DefaultPdbApplicator::new();
        assert!(!app.is_cancelled());
        app.cancel();
        assert!(app.is_cancelled());
    }

    #[test]
    fn test_reset() {
        let mut app = DefaultPdbApplicator::new();
        app.cancel();
        app.warnings.push("test warning".to_string());
        app.reset();
        assert!(!app.is_cancelled());
        assert!(app.warnings().is_empty());
        assert_eq!(app.phase(), ApplicatorPhase::NotStarted);
    }

    #[test]
    fn test_error_display() {
        let err = DefaultPdbApplicatorError::MissingStream("TPI");
        assert!(format!("{}", err).contains("TPI"));

        let err = DefaultPdbApplicatorError::Cancelled;
        assert!(format!("{}", err).contains("cancelled"));

        let err = DefaultPdbApplicatorError::InternalError("oops".into());
        assert!(format!("{}", err).contains("oops"));
    }

    #[test]
    fn test_error_from_pdb_exception() {
        let pdb_err = PdbException::IoError("test".to_string());
        let err = DefaultPdbApplicatorError::from(pdb_err);
        assert!(matches!(err, DefaultPdbApplicatorError::PdbParseError(_)));
    }

    #[test]
    fn test_summary_report() {
        let app = DefaultPdbApplicator::new();
        let report = app.summary_report();
        assert!(report.contains("Phase: Not Started"));
        assert!(report.contains("Types processed: 0"));
    }

    #[test]
    fn test_debug_format() {
        let app = DefaultPdbApplicator::new();
        let dbg = format!("{:?}", app);
        assert!(dbg.contains("DefaultPdbApplicator"));
        assert!(dbg.contains("phase"));
    }

    #[test]
    fn test_get_type_record_none() {
        let app = DefaultPdbApplicator::new();
        assert!(app.get_type_record(0x1000).is_none());
    }

    #[test]
    fn test_has_debug_info_default() {
        let app = DefaultPdbApplicator::new();
        assert!(!app.has_debug_info());
    }
}
