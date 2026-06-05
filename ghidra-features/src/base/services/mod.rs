//! Service interfaces for Ghidra's plugin framework.
//!
//! Ported from Ghidra's `ghidra.app.services` Java package. These traits
//! define the contract between service providers (plugins) and service
//! consumers (other plugins). Each trait corresponds to a Java interface
//! annotated with `@ServiceInfo`.

use std::fmt;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Placeholder types
// ---------------------------------------------------------------------------

/// Placeholder for a Ghidra Program.
#[derive(Debug, Clone)]
pub struct Program {
    pub name: String,
}

/// Placeholder for a program address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub u64);

/// Placeholder for a program location.
#[derive(Debug, Clone)]
pub struct ProgramLocation {
    pub address: Address,
}

/// Placeholder for a program selection.
#[derive(Debug, Clone, Default)]
pub struct ProgramSelection {
    pub ranges: Vec<(Address, Address)>,
}

/// Placeholder for a Navigatable.
pub trait Navigatable: fmt::Debug + Send + Sync {
    fn get_program(&self) -> Option<Arc<Program>>;
    fn go_to(&self, program: &Program, location: &ProgramLocation) -> bool;
}

/// Placeholder for TaskMonitor.
pub trait TaskMonitor: fmt::Debug + Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn set_progress(&self, value: u64);
    fn set_message(&self, msg: &str);
}

/// Placeholder for ExternalLocation.
#[derive(Debug, Clone)]
pub struct ExternalLocation {
    pub library_name: String,
    pub label: String,
    pub address: Option<Address>,
}

/// Placeholder for DomainFile.
#[derive(Debug, Clone)]
pub struct DomainFile {
    pub pathname: String,
}

/// Placeholder for QueryData.
#[derive(Debug, Clone)]
pub struct QueryData {
    pub query: String,
    pub is_case_sensitive: bool,
}

impl QueryData {
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            is_case_sensitive: false,
        }
    }

    pub fn with_case_sensitive(mut self, yes: bool) -> Self {
        self.is_case_sensitive = yes;
        self
    }
}

// ---------------------------------------------------------------------------
// AnalysisPriority
// ---------------------------------------------------------------------------

/// Priority levels for analyzers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnalysisPriority {
    /// Lowest priority -- runs after everything else.
    Lowest,
    /// Low priority.
    Low,
    /// Medium priority (default).
    Medium,
    /// High priority.
    High,
    /// Highest priority -- runs before everything else.
    Highest,
}

impl AnalysisPriority {
    /// Numeric value for sorting (higher = runs first).
    pub fn value(&self) -> u32 {
        match self {
            Self::Lowest => 1,
            Self::Low => 25,
            Self::Medium => 50,
            Self::High => 75,
            Self::Highest => 100,
        }
    }
}

impl Default for AnalysisPriority {
    fn default() -> Self {
        Self::Medium
    }
}

// ---------------------------------------------------------------------------
// GoToService
// ---------------------------------------------------------------------------

/// Trait for the GoTo navigation service.
///
/// Provides methods for navigating to addresses, locations, and
/// performing queries that resolve to locations.
pub trait GoToService: fmt::Debug + Send + Sync {
    /// Valid characters in GoTo queries (typically library delimiters).
    const VALID_GOTO_CHARS: &'static [char] = &['.', ':', '*'];

    /// Navigate to a program location.
    fn go_to_location(&self, loc: &ProgramLocation) -> bool;

    /// Navigate to a program location within a specific program.
    fn go_to_location_in_program(&self, loc: &ProgramLocation, program: &Program) -> bool;

    /// Navigate to a location using a specific navigatable.
    fn go_to_navigatable(
        &self,
        navigatable: &dyn Navigatable,
        loc: &ProgramLocation,
        program: &Program,
    ) -> bool;

    /// Navigate from one address to another.
    fn go_to_address(&self, from: Address, to: Address) -> bool;

    /// Navigate to an address using a navigatable.
    fn go_to_address_navigatable(
        &self,
        navigatable: &dyn Navigatable,
        to: Address,
    ) -> bool;

    /// Navigate to an address within a program.
    fn go_to_address_in_program(&self, to: Address, program: &Program) -> bool;

    /// Navigate to an external location.
    fn go_to_external_location(
        &self,
        ext_loc: &ExternalLocation,
        check_navigation_option: bool,
    ) -> bool;

    /// Perform a GoTo query.
    fn go_to_query(
        &self,
        from_addr: Address,
        query: &QueryData,
        monitor: &dyn TaskMonitor,
    ) -> bool;

    /// Get the default navigatable.
    fn get_default_navigatable(&self) -> &dyn Navigatable;
}

// ---------------------------------------------------------------------------
// GoToServiceListener
// ---------------------------------------------------------------------------

/// Listener for GoTo query completion.
pub trait GoToServiceListener: fmt::Debug + Send + Sync {
    /// Called when the query completes.
    fn query_completed(&self, success: bool, result_count: usize);
}

// ---------------------------------------------------------------------------
// ProgramManager
// ---------------------------------------------------------------------------

/// Open modes for programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramOpenMode {
    /// Open in hidden state.
    Hidden = 0,
    /// Open as the currently active program.
    Current = 1,
    /// Open visible but do not change the active program.
    Visible = 2,
}

/// Service for managing open programs.
pub trait ProgramManager: fmt::Debug + Send + Sync {
    /// Get the currently active program.
    fn get_current_program(&self) -> Option<Arc<Program>>;

    /// Check if a program is visible.
    fn is_visible(&self, program: &Program) -> bool;

    /// Close the currently active program.
    fn close_program(&self) -> bool;

    /// Open a program from a domain file.
    fn open_program(&self, file: &DomainFile, mode: ProgramOpenMode) -> Option<Arc<Program>>;

    /// Save the given program.
    fn save_program(&self, program: &Program) -> bool;

    /// Save all open programs.
    fn save_all(&self) -> bool;

    /// Get all open programs.
    fn get_all_open_programs(&self) -> Vec<Arc<Program>>;

    /// Get all visible programs.
    fn get_visible_programs(&self) -> Vec<Arc<Program>>;

    /// Set the active program.
    fn set_active_program(&self, program: &Program);

    /// Release a program (remove from the manager).
    fn release_program(&self, program: &Program);
}

// ---------------------------------------------------------------------------
// ConsoleService
// ---------------------------------------------------------------------------

/// Console message levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConsoleLevel {
    Info,
    Warn,
    Error,
}

/// Service for interacting with the scripting console.
pub trait ConsoleService: fmt::Debug + Send + Sync {
    /// Print a message to the console.
    fn println(&self, msg: &str);

    /// Print an error message to the console.
    fn print_error(&self, msg: &str);

    /// Print a warning message to the console.
    fn print_warning(&self, msg: &str);

    /// Add a message with a specific level.
    fn add_message(&self, level: ConsoleLevel, msg: &str);

    /// Clear the console.
    fn clear(&self);
}

// ---------------------------------------------------------------------------
// CodeViewerService
// ---------------------------------------------------------------------------

/// Service providing access to the code viewer (listing).
pub trait CodeViewerService: fmt::Debug + Send + Sync {
    /// Get the current program location.
    fn get_current_location(&self) -> Option<ProgramLocation>;

    /// Get the current program.
    fn get_current_program(&self) -> Option<Arc<Program>>;

    /// Get the current selection.
    fn get_selection(&self) -> ProgramSelection;

    /// Set the cursor to the given address.
    fn set_cursor_position(&self, addr: Address);
}

// ---------------------------------------------------------------------------
// HoverService
// ---------------------------------------------------------------------------

/// Service for providing hover (tooltip) information.
pub trait HoverService: fmt::Debug + Send + Sync {
    /// Get the hover text for the given location.
    fn get_hover_text(&self, program: &Program, location: &ProgramLocation) -> Option<String>;
}

// ---------------------------------------------------------------------------
// ClipboardService
// ---------------------------------------------------------------------------

/// Service for clipboard operations.
pub trait ClipboardService: fmt::Debug + Send + Sync {
    /// Copy text to the system clipboard.
    fn copy_to_clipboard(&self, text: &str);

    /// Get text from the system clipboard.
    fn get_from_clipboard(&self) -> Option<String>;

    /// Check if the clipboard has text content.
    fn has_text(&self) -> bool;
}

// ---------------------------------------------------------------------------
// BlockModelService
// ---------------------------------------------------------------------------

/// Service for block model management.
pub trait BlockModelService: fmt::Debug + Send + Sync {
    /// Get the default code block model name.
    fn get_default_model_name(&self) -> &str;

    /// Get all available model names.
    fn get_model_names(&self) -> Vec<String>;
}

/// Listener for block model changes.
pub trait BlockModelServiceListener: fmt::Debug + Send + Sync {
    fn model_changed(&self, model_name: &str);
}

// ---------------------------------------------------------------------------
// NavigationHistoryService
// ---------------------------------------------------------------------------

/// Service for navigation history (back/forward).
pub trait NavigationHistoryService: fmt::Debug + Send + Sync {
    /// Go back in the history.
    fn go_back(&self) -> bool;

    /// Go forward in the history.
    fn go_forward(&self) -> bool;

    /// Check if going back is possible.
    fn can_go_back(&self) -> bool;

    /// Check if going forward is possible.
    fn go_forward_possible(&self) -> bool;
}

// ---------------------------------------------------------------------------
// MemorySearchService
// ---------------------------------------------------------------------------

/// Service for searching memory.
pub trait MemorySearchService: fmt::Debug + Send + Sync {
    /// Search for a byte pattern.
    fn search_bytes(&self, program: &Program, pattern: &[u8]) -> Vec<Address>;

    /// Search for a string.
    fn search_string(&self, program: &Program, query: &str) -> Vec<Address>;
}

// ---------------------------------------------------------------------------
// GhidraScriptService
// ---------------------------------------------------------------------------

/// Service for Ghidra scripting.
pub trait GhidraScriptService: fmt::Debug + Send + Sync {
    /// Run a script by name.
    fn run_script(&self, script_name: &str) -> bool;

    /// Get the list of available scripts.
    fn get_script_names(&self) -> Vec<String>;
}

// ---------------------------------------------------------------------------
// DataTypeQueryService
// ---------------------------------------------------------------------------

/// Service for querying data types.
pub trait DataTypeQueryService: fmt::Debug + Send + Sync {
    /// Get all data type names.
    fn get_data_type_names(&self) -> Vec<String>;
}

// ---------------------------------------------------------------------------
// DataTypeArchiveService
// ---------------------------------------------------------------------------

/// Service for managing data type archives.
pub trait DataTypeArchiveService: fmt::Debug + Send + Sync {
    /// Get the names of all open archives.
    fn get_archive_names(&self) -> Vec<String>;
}

// ---------------------------------------------------------------------------
// FunctionComparisonService
// ---------------------------------------------------------------------------

/// Service for comparing functions.
pub trait FunctionComparisonService: fmt::Debug + Send + Sync {
    /// Compare two functions and return a similarity score (0.0 - 1.0).
    fn compare(&self, addr_a: Address, addr_b: Address, program: &Program) -> f64;
}

// ---------------------------------------------------------------------------
// StringTranslationService
// ---------------------------------------------------------------------------

/// Service for translating strings found in programs.
pub trait StringTranslationService: fmt::Debug + Send + Sync {
    /// Attempt to translate a string.
    fn translate(&self, text: &str) -> Option<String>;
}

// ---------------------------------------------------------------------------
// StringValidatorQuery
// ---------------------------------------------------------------------------

/// Query for validating strings.
#[derive(Debug, Clone)]
pub struct StringValidatorQuery {
    pub text: String,
    pub min_length: usize,
    pub max_length: usize,
}

/// Score result for string validity.
#[derive(Debug, Clone)]
pub struct StringValidityScore {
    pub score: f64,
    pub is_valid: bool,
}

// ---------------------------------------------------------------------------
// EclipseIntegrationService
// ---------------------------------------------------------------------------

/// Service for Eclipse IDE integration.
pub trait EclipseIntegrationService: fmt::Debug + Send + Sync {
    /// Check if running inside Eclipse.
    fn is_eclipse_environment(&self) -> bool;
}

// ---------------------------------------------------------------------------
// VSCodeIntegrationService
// ---------------------------------------------------------------------------

/// Service for VS Code integration.
pub trait VSCodeIntegrationService: fmt::Debug + Send + Sync {
    /// Check if VS Code integration is available.
    fn is_available(&self) -> bool;
}

// ---------------------------------------------------------------------------
// ListingMarginProviderService
// ---------------------------------------------------------------------------

/// Service for providing margin annotations in the listing.
pub trait ListingMarginProviderService: fmt::Debug + Send + Sync {
    /// Register a margin provider.
    fn register_provider(&self, provider_name: &str);

    /// Unregister a margin provider.
    fn unregister_provider(&self, provider_name: &str);
}

// ---------------------------------------------------------------------------
// FieldMouseHandlerService
// ---------------------------------------------------------------------------

/// Service for handling mouse events in listing fields.
pub trait FieldMouseHandlerService: fmt::Debug + Send + Sync {
    /// Handle a mouse click at the given location.
    fn handle_mouse_click(&self, location: &ProgramLocation) -> bool;
}

// ---------------------------------------------------------------------------
// TerminalService
// ---------------------------------------------------------------------------

/// Service for interacting with a terminal.
pub trait TerminalService: fmt::Debug + Send + Sync {
    /// Write a line to the terminal.
    fn write_line(&self, line: &str);

    /// Read a line from the terminal.
    fn read_line(&self) -> Option<String>;
}

// ---------------------------------------------------------------------------
// ProgramLocationPair
// ---------------------------------------------------------------------------

/// A pair of (program, location) for service operations.
#[derive(Debug, Clone)]
pub struct ProgramLocationPair {
    pub program: Arc<Program>,
    pub location: ProgramLocation,
}

impl ProgramLocationPair {
    pub fn new(program: Arc<Program>, location: ProgramLocation) -> Self {
        Self { program, location }
    }
}

// ---------------------------------------------------------------------------
// AnalyzerAdapter / AbstractAnalyzer (minimal interfaces)
// ---------------------------------------------------------------------------

/// Adapter for analyzer service notifications.
pub trait AnalyzerAdapter: fmt::Debug + Send + Sync {
    fn analysis_started(&self, program: &Program);
    fn analysis_ended(&self, program: &Program);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_priority_ordering() {
        assert!(AnalysisPriority::Highest > AnalysisPriority::High);
        assert!(AnalysisPriority::Low < AnalysisPriority::Medium);
        assert_eq!(AnalysisPriority::default(), AnalysisPriority::Medium);
    }

    #[test]
    fn test_analysis_priority_values() {
        assert_eq!(AnalysisPriority::Lowest.value(), 1);
        assert_eq!(AnalysisPriority::Low.value(), 25);
        assert_eq!(AnalysisPriority::Medium.value(), 50);
        assert_eq!(AnalysisPriority::High.value(), 75);
        assert_eq!(AnalysisPriority::Highest.value(), 100);
    }

    #[test]
    fn test_query_data() {
        let q = QueryData::new("test").with_case_sensitive(true);
        assert_eq!(q.query, "test");
        assert!(q.is_case_sensitive);
    }

    #[test]
    fn test_program_open_mode() {
        assert_eq!(ProgramOpenMode::Hidden as u32, 0);
        assert_eq!(ProgramOpenMode::Current as u32, 1);
        assert_eq!(ProgramOpenMode::Visible as u32, 2);
    }

    #[test]
    fn test_console_level_ordering() {
        assert!(ConsoleLevel::Info < ConsoleLevel::Warn);
        assert!(ConsoleLevel::Warn < ConsoleLevel::Error);
    }

    #[test]
    fn test_string_validator_query() {
        let q = StringValidatorQuery {
            text: "hello".into(),
            min_length: 1,
            max_length: 100,
        };
        assert_eq!(q.text, "hello");
    }

    #[test]
    fn test_string_validity_score() {
        let s = StringValidityScore {
            score: 0.95,
            is_valid: true,
        };
        assert!(s.score > 0.9);
        assert!(s.is_valid);
    }

    #[test]
    fn test_program_location_pair() {
        let program = Arc::new(Program {
            name: "test.exe".into(),
        });
        let loc = ProgramLocation {
            address: Address(0x401000),
        };
        let pair = ProgramLocationPair::new(program, loc);
        assert_eq!(pair.program.name, "test.exe");
        assert_eq!(pair.location.address, Address(0x401000));
    }

    #[test]
    fn test_external_location() {
        let ext = ExternalLocation {
            library_name: "kernel32.dll".into(),
            label: "CreateFileW".into(),
            address: Some(Address(0x7FF00000)),
        };
        assert_eq!(ext.library_name, "kernel32.dll");
        assert_eq!(ext.label, "CreateFileW");
    }
}
