//! SARIF plugin, service interface, controller, and program options.
//!
//! Ported from Ghidra's Java sources:
//! - `SarifPlugin.java` -- plugin registration, menu actions, option management
//! - `SarifService.java` -- service interface for loading and displaying SARIF
//! - `SarifController.java` -- controller bridging SARIF data to Ghidra UI
//! - `SarifGraphDisplayListener.java` -- graph display event listener
//! - `SarifProgramOptions.java` -- import/export option flags
//! - `SarifUtils.java` -- address resolution, logical location helpers

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::sarif_exporter::SarifWriteOptions;
use super::{
    GhidraProgramExport, SarifArtifact, SarifCodeFlow, SarifInvocation, SarifLevel, SarifLocation,
    SarifLogicalLocation, SarifLog, SarifMessage, SarifRegion, SarifResult, SarifRun,
    SarifThreadFlow, SarifThreadFlowLocation,
};

// ---------------------------------------------------------------------------
// SarifProgramOptions -- import/export option flags
// ---------------------------------------------------------------------------

/// Flags controlling which Ghidra program elements are read/written during
/// SARIF import or export.
///
/// Ported from `SarifProgramOptions.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifProgramOptions {
    /// Import/export memory blocks.
    pub memory_blocks: bool,
    /// Import/export memory contents.
    pub memory_contents: bool,
    /// Import/export instructions.
    pub instructions: bool,
    /// Import/export data items.
    pub data: bool,
    /// Import/export symbols.
    pub symbols: bool,
    /// Import/export equates (named constants).
    pub equates: bool,
    /// Import/export comments.
    pub comments: bool,
    /// Import/export properties.
    pub properties: bool,
    /// Import/export program trees.
    pub trees: bool,
    /// Import/export references (xrefs).
    pub references: bool,
    /// Import/export functions.
    pub functions: bool,
    /// Import/export register values.
    pub registers: bool,
    /// Import/export relocation table.
    pub relocation_table: bool,
    /// Import/export entry points.
    pub entry_points: bool,
    /// Import/export external libraries.
    pub external_libraries: bool,
    /// Import/export bookmarks.
    pub bookmarks: bool,
    /// Overwrite existing memory blocks on conflict.
    pub overwrite_memory_conflicts: bool,
    /// Overwrite existing data on conflict.
    pub overwrite_data_conflicts: bool,
    /// Overwrite existing symbols on conflict.
    pub overwrite_symbol_conflicts: bool,
    /// Overwrite existing properties on conflict.
    pub overwrite_property_conflicts: bool,
    /// Overwrite existing bookmarks on conflict.
    pub overwrite_bookmark_conflicts: bool,
    /// Overwrite existing references on conflict.
    pub overwrite_reference_conflicts: bool,
    /// Apply processor-defined labels.
    pub apply_proc_defined_labels: bool,
    /// Anchor processor-defined labels.
    pub anchor_proc_defined_labels: bool,
}

impl Default for SarifProgramOptions {
    fn default() -> Self {
        Self {
            memory_blocks: true,
            memory_contents: true,
            instructions: true,
            data: true,
            symbols: true,
            equates: true,
            comments: true,
            properties: true,
            trees: true,
            references: true,
            functions: true,
            registers: true,
            relocation_table: true,
            entry_points: true,
            external_libraries: true,
            bookmarks: true,
            overwrite_memory_conflicts: false,
            overwrite_data_conflicts: true,
            overwrite_symbol_conflicts: true,
            overwrite_property_conflicts: true,
            overwrite_bookmark_conflicts: true,
            overwrite_reference_conflicts: true,
            apply_proc_defined_labels: false,
            anchor_proc_defined_labels: true,
        }
    }
}

impl SarifProgramOptions {
    /// Create options with all features enabled.
    pub fn all_enabled() -> Self {
        Self {
            memory_blocks: true,
            memory_contents: true,
            instructions: true,
            data: true,
            symbols: true,
            equates: true,
            comments: true,
            properties: true,
            trees: true,
            references: true,
            functions: true,
            registers: true,
            relocation_table: true,
            entry_points: true,
            external_libraries: true,
            bookmarks: true,
            overwrite_memory_conflicts: true,
            overwrite_data_conflicts: true,
            overwrite_symbol_conflicts: true,
            overwrite_property_conflicts: true,
            overwrite_bookmark_conflicts: true,
            overwrite_reference_conflicts: true,
            apply_proc_defined_labels: true,
            anchor_proc_defined_labels: true,
        }
    }

    /// Set an option by name. Returns `Err` for unknown option names.
    pub fn set_option(&mut self, name: &str, value: bool) -> Result<(), String> {
        match name {
            "Memory Blocks" => self.memory_blocks = value,
            "Memory Contents" => self.memory_contents = value,
            "Instructions" => self.instructions = value,
            "Data" => self.data = value,
            "Symbols" => self.symbols = value,
            "Equates" => self.equates = value,
            "Comments" => self.comments = value,
            "Properties" => self.properties = value,
            "Bookmarks" => self.bookmarks = value,
            "Trees" => self.trees = value,
            "References" => self.references = value,
            "Functions" => self.functions = value,
            "Registers" => self.registers = value,
            "Relocation Table" => self.relocation_table = value,
            "Entry Points" => self.entry_points = value,
            "External Libraries" => self.external_libraries = value,
            "Overwrite Memory Conflicts" => self.overwrite_memory_conflicts = value,
            "Overwrite Data Conflicts" => self.overwrite_data_conflicts = value,
            "Overwrite Symbol Conflicts" => self.overwrite_symbol_conflicts = value,
            "Overwrite Property Conflicts" => self.overwrite_property_conflicts = value,
            "Overwrite Bookmark Conflicts" => self.overwrite_bookmark_conflicts = value,
            "Overwrite Reference Conflicts" => self.overwrite_reference_conflicts = value,
            "Apply Processor Defined Labels" => self.apply_proc_defined_labels = value,
            "Anchor Processor Defined Labels" => self.anchor_proc_defined_labels = value,
            other => return Err(format!("Unknown option: {other}")),
        }
        Ok(())
    }

    /// Get the list of option names and their current boolean values.
    pub fn option_list(&self) -> Vec<(&str, bool)> {
        vec![
            ("Memory Blocks", self.memory_blocks),
            ("Memory Contents", self.memory_contents),
            ("Instructions", self.instructions),
            ("Data", self.data),
            ("Symbols", self.symbols),
            ("Equates", self.equates),
            ("Comments", self.comments),
            ("Properties", self.properties),
            ("Bookmarks", self.bookmarks),
            ("Trees", self.trees),
            ("References", self.references),
            ("Functions", self.functions),
            ("Registers", self.registers),
            ("Relocation Table", self.relocation_table),
            ("Entry Points", self.entry_points),
            ("External Libraries", self.external_libraries),
        ]
    }

    /// Get the list of overwrite option names and their current boolean values.
    pub fn overwrite_option_list(&self) -> Vec<(&str, bool)> {
        vec![
            ("Overwrite Memory Conflicts", self.overwrite_memory_conflicts),
            ("Overwrite Data Conflicts", self.overwrite_data_conflicts),
            ("Overwrite Symbol Conflicts", self.overwrite_symbol_conflicts),
            ("Overwrite Property Conflicts", self.overwrite_property_conflicts),
            ("Overwrite Bookmark Conflicts", self.overwrite_bookmark_conflicts),
            ("Overwrite Reference Conflicts", self.overwrite_reference_conflicts),
        ]
    }
}

// ---------------------------------------------------------------------------
// SarifPluginOptions -- plugin-level display options
// ---------------------------------------------------------------------------

/// Plugin-level display options for the SARIF plugin.
///
/// Ported from `SarifPlugin.java` option handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPluginOptions {
    /// Display image artifacts by default.
    pub display_artifacts: bool,
    /// Display graphs by default.
    pub display_graphs: bool,
    /// Maximum number of nodes per graph.
    pub max_graph_size: usize,
    /// Append to the current graph instead of replacing.
    pub append_to_graph: bool,
}

impl Default for SarifPluginOptions {
    fn default() -> Self {
        Self {
            display_artifacts: false,
            display_graphs: false,
            max_graph_size: 1000,
            append_to_graph: false,
        }
    }
}

/// A single named option for display in an options panel.
#[derive(Debug, Clone)]
pub struct SarifOptionEntry {
    /// Display name of the option.
    pub name: String,
    /// Current boolean value.
    pub value: bool,
    /// Help text.
    pub help: String,
}

// ---------------------------------------------------------------------------
// SarifService -- service interface
// ---------------------------------------------------------------------------

/// Service interface for loading and displaying SARIF data.
///
/// Plugins obtain a reference to this service to read SARIF files or blobs
/// and display the parsed results in the Ghidra UI.
///
/// Ported from `SarifService.java`.
pub trait SarifService: Send + Sync {
    /// Read a SARIF file from disk.
    fn read_sarif_file(&self, path: &Path) -> io::Result<SarifLog>;

    /// Read a SARIF JSON string.
    fn read_sarif_string(&self, sarif: &str) -> io::Result<SarifLog>;

    /// Display a parsed SARIF log with the given display name.
    fn show_sarif(&self, log_name: &str, sarif: &SarifLog);

    /// Get the current controller.
    fn get_controller(&self) -> Option<&dyn SarifControllerOps>;
}

// ---------------------------------------------------------------------------
// SarifController -- controller for SARIF interactions
// ---------------------------------------------------------------------------

/// Operations supported by a SARIF controller.
///
/// The controller manages the mapping between SARIF results and the Ghidra
/// program. It handles result selection, graph display, address resolution,
/// and listing actions (comments, highlights, bookmarks).
///
/// Ported from `SarifController.java`.
pub trait SarifControllerOps: Send + Sync {
    /// Dispose of all UI providers and resources.
    fn dispose(&mut self);

    /// Show or hide the results table.
    fn set_table_visible(&mut self, visible: bool);

    /// Display a SARIF log in a results table with the given name.
    fn show_table(&mut self, log_name: &str, sarif: &SarifLog);

    /// Show an image artifact.
    fn show_image(&self, key: &str, image_data: &[u8]);

    /// Show a graph in the graph display.
    fn show_graph(&self, graph_name: &str, graph_data: &SarifGraphData);

    /// Handle a listing action (set comment, highlight, bookmark) at
    /// addresses derived from the SARIF result.
    fn handle_listing_action(&self, action: &str, value: &str, addresses: &[u64]);

    /// Get addresses from a SARIF result's locations.
    fn get_listing_addresses(&self, result: &SarifResult) -> Vec<u64>;

    /// Set the address selection in the listing view.
    fn make_selection(&self, addresses: &[u64]);

    /// Set background color for an address range.
    fn color_background(&self, start: u64, end: u64, r: u8, g: u8, b: u8);
}

// ---------------------------------------------------------------------------
// SarifGraphData -- graph data for display
// ---------------------------------------------------------------------------

/// Simplified graph data for display in the Ghidra graph viewer.
///
/// Represents a directed attributed graph that can be displayed using
/// Ghidra's graph display framework.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SarifGraphData {
    /// The graph name/title.
    pub name: String,
    /// Graph nodes, keyed by node ID.
    pub nodes: HashMap<String, SarifGraphNode>,
    /// Graph edges.
    pub edges: Vec<SarifGraphEdge>,
}

/// A node in a SARIF graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SarifGraphNode {
    /// The node ID.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Address associated with this node (hex string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Additional attributes.
    pub attributes: HashMap<String, String>,
}

/// An edge in a SARIF graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SarifGraphEdge {
    /// Edge ID.
    pub id: String,
    /// Source node ID.
    pub source: String,
    /// Target node ID.
    pub target: String,
    /// Edge label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

// ---------------------------------------------------------------------------
// SarifPlugin -- plugin implementation
// ---------------------------------------------------------------------------

/// The main SARIF plugin.
///
/// Manages SARIF file reading, controller lifecycle, plugin options, and
/// menu action registration. Each open program gets its own
/// [`SarifControllerState`] to manage SARIF data independently.
///
/// Ported from `SarifPlugin.java`.
#[derive(Debug)]
pub struct SarifPlugin {
    /// Plugin name.
    pub name: String,
    /// Per-program controller states.
    controllers: HashMap<String, SarifControllerState>,
    /// Plugin-level display options.
    pub options: SarifPluginOptions,
    /// Whether the plugin has been initialized.
    initialized: bool,
}

/// Per-program controller state.
#[derive(Debug)]
pub struct SarifControllerState {
    /// Program identifier (e.g., file path or name).
    pub program_id: String,
    /// Current SARIF log, if loaded.
    pub current_log: Option<SarifLog>,
    /// Display name of the current log.
    pub log_name: Option<String>,
    /// Active result indices (selected rows in the table).
    pub selected_results: Vec<usize>,
    /// Graph displays associated with this program.
    pub graphs: Vec<SarifGraphData>,
    /// Whether the results table is visible.
    pub table_visible: bool,
}

impl SarifControllerState {
    /// Create a new controller state for a program.
    pub fn new(program_id: impl Into<String>) -> Self {
        Self {
            program_id: program_id.into(),
            current_log: None,
            log_name: None,
            selected_results: Vec::new(),
            graphs: Vec::new(),
            table_visible: true,
        }
    }

    /// Load a SARIF log into this controller.
    pub fn load_log(&mut self, log_name: impl Into<String>, log: SarifLog) {
        self.log_name = Some(log_name.into());
        self.current_log = Some(log);
        self.selected_results.clear();
    }

    /// Get the number of results in the current log.
    pub fn result_count(&self) -> usize {
        self.current_log
            .as_ref()
            .map(|log| {
                log.runs
                    .iter()
                    .map(|r| r.results.as_ref().map_or(0, |res| res.len()))
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Select results by index.
    pub fn select_results(&mut self, indices: Vec<usize>) {
        self.selected_results = indices;
    }

    /// Get all addresses from selected results.
    pub fn get_selected_addresses(&self) -> Vec<String> {
        let mut addresses = Vec::new();
        if let Some(log) = &self.current_log {
            for run in &log.runs {
                if let Some(results) = &run.results {
                    for result in results {
                        if let Some(locations) = &result.locations {
                            for loc in locations {
                                if let Some(phys) = &loc.physical_location {
                                    if let Some(addr) = &phys.address {
                                        if let Some(abs) = &addr.absolute_address {
                                            addresses.push(abs.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        addresses
    }
}

impl SarifPlugin {
    /// Plugin name constant.
    pub const NAME: &'static str = "Sarif";

    /// Create a new SARIF plugin.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
            controllers: HashMap::new(),
            options: SarifPluginOptions::default(),
            initialized: false,
        }
    }

    /// Initialize the plugin (create actions, load options).
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
    }

    /// Read and display a SARIF file for the given program.
    pub fn read_file(&mut self, program_id: &str, path: &Path) -> io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let log: SarifLog =
            serde_json::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "SARIF".to_string());
        self.show_sarif(program_id, &file_name, log);
        Ok(())
    }

    /// Read and display a SARIF JSON string for the given program.
    pub fn read_string(&mut self, program_id: &str, sarif_json: &str) -> io::Result<()> {
        let log: SarifLog = serde_json::from_str(sarif_json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.show_sarif(program_id, "SARIF", log);
        Ok(())
    }

    /// Display a parsed SARIF log for the given program.
    pub fn show_sarif(&mut self, program_id: &str, log_name: &str, log: SarifLog) {
        let controller = self.get_or_create_controller(program_id);
        let result_count = log
            .runs
            .iter()
            .map(|r| r.results.as_ref().map_or(0, |res| res.len()))
            .sum::<usize>();

        let display_name = if result_count > 0 {
            format!("{log_name}  [{result_count}]")
        } else {
            log_name.to_string()
        };

        controller.load_log(display_name, log);
    }

    /// Get or create a controller state for a program.
    pub fn get_or_create_controller(&mut self, program_id: &str) -> &mut SarifControllerState {
        if !self.controllers.contains_key(program_id) {
            self.controllers
                .insert(program_id.to_string(), SarifControllerState::new(program_id));
        }
        self.controllers.get_mut(program_id).unwrap()
    }

    /// Get a reference to a controller state.
    pub fn get_controller(&self, program_id: &str) -> Option<&SarifControllerState> {
        self.controllers.get(program_id)
    }

    /// Get a mutable reference to a controller state.
    pub fn get_controller_mut(&mut self, program_id: &str) -> Option<&mut SarifControllerState> {
        self.controllers.get_mut(program_id)
    }

    /// Dispose of a program's controller state.
    pub fn dispose_controller(&mut self, program_id: &str) {
        self.controllers.remove(program_id);
    }

    /// Set table visibility for a program's controller.
    pub fn set_table_visible(&mut self, program_id: &str, visible: bool) {
        if let Some(controller) = self.controllers.get_mut(program_id) {
            controller.table_visible = visible;
        }
    }

    /// Get plugin options as a list of (name, value, help) tuples.
    pub fn get_option_entries(&self) -> Vec<SarifOptionEntry> {
        vec![
            SarifOptionEntry {
                name: "Display Artifacts".to_string(),
                value: self.options.display_artifacts,
                help: "Display artifacts by default".to_string(),
            },
            SarifOptionEntry {
                name: "Display Graphs".to_string(),
                value: self.options.display_graphs,
                help: "Display graphs by default".to_string(),
            },
            SarifOptionEntry {
                name: "Max Graph Size".to_string(),
                value: false, // integer, shown differently in UI
                help: format!("Maximum number of nodes per graph ({})", self.options.max_graph_size),
            },
            SarifOptionEntry {
                name: "Append Graphs".to_string(),
                value: self.options.append_to_graph,
                help: "Append to existing graph".to_string(),
            },
        ]
    }

    /// Load plugin options from a key-value map.
    pub fn load_options(&mut self, options: &HashMap<String, SarifOptionValue>) {
        if let Some(v) = options.get("Display Artifacts").and_then(|v| v.as_bool()) {
            self.options.display_artifacts = v;
        }
        if let Some(v) = options.get("Display Graphs").and_then(|v| v.as_bool()) {
            self.options.display_graphs = v;
        }
        if let Some(v) = options.get("Max Graph Size").and_then(|v| v.as_int()) {
            self.options.max_graph_size = v as usize;
        }
        if let Some(v) = options.get("Append Graphs").and_then(|v| v.as_bool()) {
            self.options.append_to_graph = v;
        }
    }

    /// Get the list of registered program IDs.
    pub fn program_ids(&self) -> Vec<&str> {
        self.controllers.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for SarifPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// A dynamic option value used when loading plugin options.
#[derive(Debug, Clone)]
pub enum SarifOptionValue {
    /// Boolean option.
    Bool(bool),
    /// Integer option.
    Int(i64),
    /// String option.
    String(String),
}

impl SarifOptionValue {
    /// Extract a boolean value, if this is a Bool variant.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Extract an integer value, if this is an Int variant.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            Self::Bool(v) => Some(if *v { 1 } else { 0 }),
            Self::String(s) => s.parse().ok(),
        }
    }
}

// ---------------------------------------------------------------------------
// SarifGraphDisplayListener -- graph event listener
// ---------------------------------------------------------------------------

/// Listener for graph display events that maps graph vertex selections
/// to program address selections.
///
/// Ported from `SarifGraphDisplayListener.java`.
#[derive(Debug)]
pub struct SarifGraphDisplayListener {
    /// Map from address to vertex IDs at that address.
    address_to_vertices: HashMap<u64, HashSet<String>>,
    /// Map from vertex ID to address.
    vertex_to_address: HashMap<String, u64>,
    /// Currently selected vertex IDs.
    selected_vertices: HashSet<String>,
}

impl SarifGraphDisplayListener {
    /// Create a new listener from a graph data structure.
    ///
    /// Builds the address-to-vertex mapping from node attributes.
    pub fn new(graph: &SarifGraphData) -> Self {
        let mut address_to_vertices: HashMap<u64, HashSet<String>> = HashMap::new();
        let mut vertex_to_address: HashMap<String, u64> = HashMap::new();

        for node in graph.nodes.values() {
            if let Some(addr_str) = &node.address {
                if let Ok(addr) = parse_hex_address(addr_str) {
                    address_to_vertices
                        .entry(addr)
                        .or_default()
                        .insert(node.id.clone());
                    vertex_to_address.insert(node.id.clone(), addr);
                }
            }
        }

        Self {
            address_to_vertices,
            vertex_to_address,
            selected_vertices: HashSet::new(),
        }
    }

    /// Handle a program location change -- select vertices at the address.
    pub fn on_location_changed(&mut self, address: u64) -> Vec<String> {
        if let Some(vertices) = self.address_to_vertices.get(&address) {
            self.selected_vertices = vertices.clone();
            vertices.iter().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Handle a vertex selection change -- return the associated addresses.
    pub fn on_vertices_selected(&mut self, vertex_ids: &[String]) -> Vec<u64> {
        self.selected_vertices = vertex_ids.iter().cloned().collect();
        vertex_ids
            .iter()
            .filter_map(|id| self.vertex_to_address.get(id).copied())
            .collect()
    }

    /// Get vertices within an address set.
    pub fn get_vertices_in_range(&self, start: u64, end: u64) -> Vec<String> {
        let mut vertices = Vec::new();
        for (addr, vertex_set) in &self.address_to_vertices {
            if *addr >= start && *addr <= end {
                vertices.extend(vertex_set.iter().cloned());
            }
        }
        vertices
    }

    /// Get the address for a vertex.
    pub fn get_address(&self, vertex_id: &str) -> Option<u64> {
        self.vertex_to_address.get(vertex_id).copied()
    }

    /// Check if an address is valid (has vertices mapped to it).
    pub fn is_valid_address(&self, addr: u64) -> bool {
        self.address_to_vertices.contains_key(&addr)
    }

    /// Get the currently selected vertex IDs.
    pub fn selected_vertices(&self) -> &HashSet<String> {
        &self.selected_vertices
    }
}

// ---------------------------------------------------------------------------
// SarifUtils -- address and location utilities
// ---------------------------------------------------------------------------

/// Utility functions for SARIF address and location resolution.
///
/// Ported from `SarifUtils.java`.
pub struct SarifUtils;

impl SarifUtils {
    /// Convert a SARIF location to an absolute address.
    ///
    /// Resolves the physical location's `absoluteAddress` field. Returns
    /// `None` if the location has no physical location or address.
    pub fn location_to_address(location: &SarifLocation) -> Option<u64> {
        let phys = location.physical_location.as_ref()?;
        let addr = phys.address.as_ref()?;
        let abs = addr.absolute_address.as_ref()?;
        parse_hex_address(abs).ok()
    }

    /// Convert a SARIF location to a (start, length) address range.
    ///
    /// Returns `(absolute_address, length)` if the location has both
    /// an address and a length.
    pub fn location_to_range(location: &SarifLocation) -> Option<(u64, u64)> {
        let phys = location.physical_location.as_ref()?;
        let addr = phys.address.as_ref()?;
        let abs = addr.absolute_address.as_ref()?;
        let offset = parse_hex_address(abs).ok()?;
        let length = addr.length.unwrap_or(0) as u64;
        Some((offset, length))
    }

    /// Get all addresses from a SARIF result's locations.
    pub fn get_result_addresses(result: &SarifResult) -> Vec<u64> {
        let mut addresses = Vec::new();
        if let Some(locations) = &result.locations {
            for loc in locations {
                if let Some(addr) = Self::location_to_address(loc) {
                    addresses.push(addr);
                }
            }
        }
        addresses
    }

    /// Get all addresses from a SARIF result's locations as an address set
    /// (start, end) pairs.
    pub fn get_result_address_ranges(result: &SarifResult) -> Vec<(u64, u64)> {
        let mut ranges = Vec::new();
        if let Some(locations) = &result.locations {
            for loc in locations {
                if let Some((start, length)) = Self::location_to_range(loc) {
                    if length > 0 {
                        ranges.push((start, start + length - 1));
                    } else {
                        ranges.push((start, start));
                    }
                }
            }
        }
        ranges
    }

    /// Extract the function name from a fully qualified logical location name.
    ///
    /// Logical location FQNs use `@` as a delimiter: `funcName@addr:insnAddr`.
    /// This extracts the function name (the part before `@`).
    pub fn extract_fqn_function(fqname: &str) -> &str {
        fqname.split('@').next().unwrap_or("UNKNOWN")
    }

    /// Extract the function entry address from a fully qualified logical
    /// location name.
    ///
    /// Format: `funcName@addr:insnAddr` or `funcName@EXTERNAL:addr`.
    pub fn extract_fqn_entry_address(fqname: &str) -> Option<u64> {
        let parts: Vec<&str> = fqname.split('@').collect();
        if parts.len() <= 1 {
            return None;
        }
        let subparts: Vec<&str> = parts[1].split(':').collect();
        if subparts.is_empty() {
            return None;
        }
        if subparts[0] == "EXTERNAL" && subparts.len() > 1 {
            return parse_hex_address(subparts[1]).ok();
        }
        // Strip any `!` suffix (used for non-equality operators)
        let addr_str = subparts[0].split('!').next().unwrap_or(subparts[0]);
        parse_hex_address(addr_str).ok()
    }

    /// Extract a pair of addresses from a fully qualified logical location
    /// name: (function entry, instruction address).
    ///
    /// Format: `funcName@fnAddr:insnAddr`.
    pub fn extract_fqn_address_pair(fqname: &str) -> Vec<u64> {
        let parts: Vec<&str> = fqname.split('@').collect();
        if parts.len() <= 1 {
            return Vec::new();
        }
        let mut result = Vec::new();
        let subparts: Vec<&str> = parts[1].split(':').collect();
        if subparts.len() > 1 {
            if let Ok(fn_addr) = parse_hex_address(subparts[0]) {
                result.push(fn_addr);
            }
            if let Ok(insn_addr) = parse_hex_address(subparts[1]) {
                result.push(insn_addr);
            }
        } else {
            // Handle `!` delimiter
            let inner_parts: Vec<&str> = parts[1].split('!').collect();
            if let Ok(fn_addr) = parse_hex_address(inner_parts[0]) {
                result.push(fn_addr);
                result.push(fn_addr);
            }
        }
        result
    }

    /// Extract a display name from a logical location.
    ///
    /// If the name starts with "vn", combines the FQN prefix with the
    /// second colon-separated part. Otherwise combines the FQN prefix
    /// with the name.
    pub fn extract_display_name(
        name: Option<&str>,
        fully_qualified_name: Option<&str>,
    ) -> String {
        let name = name.unwrap_or("");
        let fqname = fully_qualified_name.unwrap_or("");

        if name.starts_with("vn") {
            let prefix = fqname.split('@').next().unwrap_or("");
            let after_colon = fqname.split(':').nth(1).unwrap_or("");
            format!("{prefix}:{after_colon}")
        } else {
            let prefix = fqname.split('@').next().unwrap_or("");
            format!("{prefix}:{name}")
        }
    }

    /// Get the list of taxonomy names from a SARIF run.
    pub fn get_taxonomy_names(run: &SarifRun) -> Vec<String> {
        // Taxonomies are stored in extensions if present
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// SarifIo -- file I/O for SARIF
// ---------------------------------------------------------------------------

/// SARIF file I/O handler.
///
/// Ported from `SarifGsonIO.java` / `SarifIO.java` / `SarifJacksonIO.java`.
pub struct SarifIo;

impl SarifIo {
    /// Read a SARIF log from a file.
    pub fn read_from_file(path: &Path) -> io::Result<SarifLog> {
        let content = std::fs::read_to_string(path)?;
        Self::read_from_string(&content)
    }

    /// Read a SARIF log from a JSON string.
    pub fn read_from_string(json: &str) -> io::Result<SarifLog> {
        serde_json::from_str(json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Write a SARIF log to a file.
    pub fn write_to_file(log: &SarifLog, path: &Path) -> io::Result<()> {
        let json = Self::write_to_string(log)?;
        std::fs::write(path, json)
    }

    /// Serialize a SARIF log to a JSON string.
    pub fn write_to_string(log: &SarifLog) -> io::Result<String> {
        serde_json::to_string_pretty(log)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a hex address string (with or without "0x" prefix) to u64.
fn parse_hex_address(s: &str) -> Result<u64, std::num::ParseIntError> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse::<u64>()
    }
}

// ---------------------------------------------------------------------------
// ListingAction -- actions that can be applied at addresses
// ---------------------------------------------------------------------------

/// An action to apply at a set of addresses in the listing view.
///
/// Ported from `SarifController.handleListingAction()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ListingAction {
    /// Set a plate comment at the address.
    Comment { text: String },
    /// Set a background highlight color.
    Highlight { r: u8, g: u8, b: u8 },
    /// Set a bookmark.
    Bookmark {
        category: String,
        comment: String,
    },
}

impl ListingAction {
    /// Apply this action at the given addresses using the controller.
    pub fn apply_at_addresses(&self, controller: &dyn SarifControllerOps, addresses: &[u64]) {
        match self {
            ListingAction::Comment { text } => {
                controller.handle_listing_action("comment", text, addresses);
            }
            ListingAction::Highlight { r, g, b } => {
                let color_str = format!("{r},{g},{b}");
                controller.handle_listing_action("highlight", &color_str, addresses);
            }
            ListingAction::Bookmark { category, comment } => {
                controller.handle_listing_action("bookmark", comment, addresses);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::SarifExporter;

    #[test]
    fn test_sarif_program_options_default() {
        let opts = SarifProgramOptions::default();
        assert!(opts.memory_blocks);
        assert!(opts.symbols);
        assert!(opts.functions);
        assert!(!opts.overwrite_memory_conflicts);
        assert!(opts.overwrite_symbol_conflicts);
    }

    #[test]
    fn test_sarif_program_options_set_option() {
        let mut opts = SarifProgramOptions::default();
        assert!(opts.memory_blocks);
        opts.set_option("Memory Blocks", false).unwrap();
        assert!(!opts.memory_blocks);

        let result = opts.set_option("Nonexistent Option", true);
        assert!(result.is_err());
    }

    #[test]
    fn test_sarif_program_options_all_enabled() {
        let opts = SarifProgramOptions::all_enabled();
        assert!(opts.memory_blocks);
        assert!(opts.overwrite_memory_conflicts);
        assert!(opts.apply_proc_defined_labels);
    }

    #[test]
    fn test_sarif_plugin_options_default() {
        let opts = SarifPluginOptions::default();
        assert!(!opts.display_artifacts);
        assert!(!opts.display_graphs);
        assert_eq!(opts.max_graph_size, 1000);
    }

    #[test]
    fn test_sarif_plugin_create() {
        let plugin = SarifPlugin::new();
        assert_eq!(plugin.name, "Sarif");
        assert!(!plugin.initialized);
    }

    #[test]
    fn test_sarif_plugin_init() {
        let mut plugin = SarifPlugin::new();
        plugin.init();
        assert!(plugin.initialized);
    }

    #[test]
    fn test_sarif_plugin_controller_lifecycle() {
        let mut plugin = SarifPlugin::new();
        plugin.init();

        // Create controller
        {
            let controller = plugin.get_or_create_controller("prog1");
            assert_eq!(controller.program_id, "prog1");
            assert!(controller.current_log.is_none());
        }

        // Show SARIF
        let mut exporter = SarifExporter::new("TestTool".to_string());
        exporter.add_result(
            "T001".into(),
            "Test finding".into(),
            SarifLevel::Warning,
            "0x401000".into(),
        );
        let log = exporter.build();
        plugin.show_sarif("prog1", "TestLog", log);

        let controller = plugin.get_controller("prog1").unwrap();
        assert!(controller.current_log.is_some());
        assert_eq!(controller.result_count(), 1);
        assert!(controller.log_name.as_ref().unwrap().contains("TestLog"));
    }

    #[test]
    fn test_sarif_plugin_dispose() {
        let mut plugin = SarifPlugin::new();
        plugin.get_or_create_controller("prog1");
        assert!(plugin.get_controller("prog1").is_some());

        plugin.dispose_controller("prog1");
        assert!(plugin.get_controller("prog1").is_none());
    }

    #[test]
    fn test_sarif_plugin_read_string() {
        let mut plugin = SarifPlugin::new();
        let json = r#"{
            "version": "2.1.0",
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "Test"}},
                "results": [{
                    "ruleId": "R1",
                    "message": {"text": "hello"}
                }]
            }]
        }"#;
        plugin.read_string("prog1", json).unwrap();
        let controller = plugin.get_controller("prog1").unwrap();
        assert_eq!(controller.result_count(), 1);
    }

    #[test]
    fn test_sarif_controller_state_selected_addresses() {
        let mut state = SarifControllerState::new("test");
        let mut exporter = SarifExporter::new("TestTool".to_string());
        exporter.add_result(
            "R1".into(),
            "msg".into(),
            SarifLevel::Error,
            "0x401000".into(),
        );
        let log = exporter.build();
        state.load_log("test log", log);

        let addrs = state.get_selected_addresses();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "0x401000");
    }

    #[test]
    fn test_sarif_graph_display_listener() {
        let mut graph = SarifGraphData::default();
        graph.nodes.insert(
            "n1".into(),
            SarifGraphNode {
                id: "n1".into(),
                label: "Node 1".into(),
                address: Some("0x401000".into()),
                attributes: HashMap::new(),
            },
        );
        graph.nodes.insert(
            "n2".into(),
            SarifGraphNode {
                id: "n2".into(),
                label: "Node 2".into(),
                address: Some("0x401050".into()),
                attributes: HashMap::new(),
            },
        );

        let mut listener = SarifGraphDisplayListener::new(&graph);
        assert!(listener.is_valid_address(0x401000));
        assert!(!listener.is_valid_address(0x500000));

        let selected = listener.on_location_changed(0x401000);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], "n1");

        let addrs = listener.on_vertices_selected(&["n2".into()]);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], 0x401050);
    }

    #[test]
    fn test_sarif_utils_location_to_address() {
        let location = SarifLocation::at_address("0x401000");
        let addr = SarifUtils::location_to_address(&location);
        assert_eq!(addr, Some(0x401000));
    }

    #[test]
    fn test_sarif_utils_location_to_range() {
        let mut location = SarifLocation::at_address("0x401000");
        if let Some(ref mut phys) = location.physical_location {
            if let Some(ref mut addr) = phys.address {
                addr.length = Some(64);
            }
        }
        let range = SarifUtils::location_to_range(&location);
        assert_eq!(range, Some((0x401000, 64)));
    }

    #[test]
    fn test_sarif_utils_extract_fqn_function() {
        assert_eq!(SarifUtils::extract_fqn_function("main@0x401000"), "main");
        assert_eq!(
            SarifUtils::extract_fqn_function("Network::process@0x402000:0x402010"),
            "Network::process"
        );
        assert_eq!(SarifUtils::extract_fqn_function("standalone"), "standalone");
    }

    #[test]
    fn test_sarif_utils_extract_fqn_entry_address() {
        assert_eq!(
            SarifUtils::extract_fqn_entry_address("main@0x401000"),
            Some(0x401000)
        );
        assert_eq!(
            SarifUtils::extract_fqn_entry_address("func@0x402000:0x402010"),
            Some(0x402000)
        );
        assert_eq!(
            SarifUtils::extract_fqn_entry_address("ext@EXTERNAL:0x1000"),
            Some(0x1000)
        );
        assert_eq!(SarifUtils::extract_fqn_entry_address("no_at_sign"), None);
    }

    #[test]
    fn test_sarif_utils_extract_display_name() {
        let name = SarifUtils::extract_display_name(Some("main"), Some("main@0x401000"));
        assert_eq!(name, "main:main");

        let vn_name = SarifUtils::extract_display_name(Some("vn0"), Some("func@addr:type"));
        assert_eq!(vn_name, "func:type");
    }

    #[test]
    fn test_sarif_io_roundtrip() {
        let mut exporter = SarifExporter::new("IOTest".to_string());
        exporter.add_result(
            "IO001".into(),
            "IO test result".into(),
            SarifLevel::Note,
            "0x8000".into(),
        );
        let log = exporter.build();

        let json = SarifIo::write_to_string(&log).unwrap();
        let parsed = SarifIo::read_from_string(&json).unwrap();

        assert_eq!(parsed.version, "2.1.0");
        assert_eq!(parsed.runs.len(), 1);
        assert!(parsed.runs[0].results.is_some());
    }

    #[test]
    fn test_listing_action_comment() {
        let action = ListingAction::Comment {
            text: "test comment".to_string(),
        };
        // Just verify it serializes
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("Comment"));
        assert!(json.contains("test comment"));
    }

    #[test]
    fn test_parse_hex_address() {
        assert_eq!(parse_hex_address("0x401000").unwrap(), 0x401000);
        assert_eq!(parse_hex_address("0X401000").unwrap(), 0x401000);
        assert_eq!(parse_hex_address("401000").unwrap(), 401000); // decimal fallback
        assert_eq!(parse_hex_address("0xff").unwrap(), 0xff);
        assert!(parse_hex_address("invalid").is_err());
    }

    #[test]
    fn test_sarif_option_value() {
        let v = SarifOptionValue::Bool(true);
        assert_eq!(v.as_bool(), Some(true));
        assert_eq!(v.as_int(), Some(1));

        let v = SarifOptionValue::Int(42);
        assert_eq!(v.as_int(), Some(42));

        let v = SarifOptionValue::String("123".to_string());
        assert_eq!(v.as_int(), Some(123));
    }

    #[test]
    fn test_sarif_plugin_load_options() {
        let mut plugin = SarifPlugin::new();
        let mut opts = HashMap::new();
        opts.insert("Display Artifacts".to_string(), SarifOptionValue::Bool(true));
        opts.insert("Max Graph Size".to_string(), SarifOptionValue::Int(500));
        plugin.load_options(&opts);

        assert!(plugin.options.display_artifacts);
        assert_eq!(plugin.options.max_graph_size, 500);
    }

    #[test]
    fn test_program_ids() {
        let mut plugin = SarifPlugin::new();
        plugin.get_or_create_controller("prog1");
        plugin.get_or_create_controller("prog2");
        let ids = plugin.program_ids();
        assert_eq!(ids.len(), 2);
    }
}
