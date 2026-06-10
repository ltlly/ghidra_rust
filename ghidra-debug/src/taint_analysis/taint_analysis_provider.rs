//! Taint analysis provider.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.taint.TaintAnalysisProvider`.
//!
//! Provides the data model and display logic for a single taint analysis
//! results view.  Each provider corresponds to one panel in the debugger
//! UI that displays taint analysis output (tainted addresses, registers,
//! SARIF results, and engine status).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::gui::{TaintColumn, TaintFieldLocation};
use super::taint_analysis_plugin::TaintAnalysisJob;
use super::taint_states::{TaintEntry, TaintLevel};

// ---------------------------------------------------------------------------
// TaintAnalysisProviderConfig -- per-provider configuration
// ---------------------------------------------------------------------------

/// Configuration for a single taint analysis provider instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintAnalysisProviderConfig {
    /// The unique provider ID.
    pub provider_id: String,
    /// The window title for this provider.
    pub title: String,
    /// Whether to show clean (untainted) entries.
    pub show_clean: bool,
    /// Whether to show entries with unknown taint status.
    pub show_unknown: bool,
    /// The default number of results to display per page.
    pub page_size: usize,
    /// Whether to auto-scroll to new results.
    pub auto_scroll: bool,
    /// Column sort state.
    pub sort_column: Option<TaintColumn>,
    /// Sort ascending (true) or descending (false).
    pub sort_ascending: bool,
}

impl TaintAnalysisProviderConfig {
    /// Create a new provider config with the given ID.
    pub fn new(provider_id: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            title: "Taint Analysis".to_string(),
            show_clean: false,
            show_unknown: false,
            page_size: 100,
            auto_scroll: true,
            sort_column: None,
            sort_ascending: true,
        }
    }

    /// Set the title.
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Show clean entries.
    pub fn with_show_clean(mut self, show: bool) -> Self {
        self.show_clean = show;
        self
    }

    /// Show unknown entries.
    pub fn with_show_unknown(mut self, show: bool) -> Self {
        self.show_unknown = show;
        self
    }

    /// Set the page size.
    pub fn with_page_size(mut self, size: usize) -> Self {
        self.page_size = size;
        self
    }

    /// Set auto-scroll.
    pub fn with_auto_scroll(mut self, auto_scroll: bool) -> Self {
        self.auto_scroll = auto_scroll;
        self
    }

    /// Set sort column and direction.
    pub fn with_sort(mut self, column: TaintColumn, ascending: bool) -> Self {
        self.sort_column = Some(column);
        self.sort_ascending = ascending;
        self
    }
}

// ---------------------------------------------------------------------------
// TaintAnalysisDisplayRow -- a single row in the provider's table
// ---------------------------------------------------------------------------

/// A single display row in the taint analysis results table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintAnalysisDisplayRow {
    /// The address or register offset.
    pub address: u64,
    /// The taint level.
    pub level: TaintLevel,
    /// The size in bytes.
    pub size: u64,
    /// The taint source description.
    pub source: Option<String>,
    /// The register or space name (if applicable).
    pub label: Option<String>,
    /// The field location for GUI navigation.
    pub field_location: Option<TaintFieldLocation>,
}

impl TaintAnalysisDisplayRow {
    /// Create a display row from a `TaintEntry`.
    pub fn from_entry(entry: &TaintEntry) -> Self {
        Self {
            address: entry.address,
            level: entry.level,
            size: entry.size,
            source: entry.source.clone(),
            label: None,
            field_location: None,
        }
    }

    /// Create a display row for a register.
    pub fn register(
        address: u64,
        level: TaintLevel,
        size: u64,
        register_name: impl Into<String>,
    ) -> Self {
        Self {
            address,
            level,
            size,
            source: None,
            label: Some(register_name.into()),
            field_location: None,
        }
    }

    /// Whether this row should be displayed given the provider config.
    pub fn should_display(&self, config: &TaintAnalysisProviderConfig) -> bool {
        match self.level {
            TaintLevel::Clean => config.show_clean,
            TaintLevel::Unknown => config.show_unknown,
            _ => true,
        }
    }
}

// ---------------------------------------------------------------------------
// TaintAnalysisProviderState -- the provider's view state
// ---------------------------------------------------------------------------

/// The state of a taint analysis provider.
///
/// Maintains the current results, display configuration, selection, and
/// scroll position for one taint analysis panel.
#[derive(Debug)]
pub struct TaintAnalysisProviderState {
    /// The provider configuration.
    pub config: TaintAnalysisProviderConfig,
    /// The currently displayed rows.
    rows: Vec<TaintAnalysisDisplayRow>,
    /// The currently selected row index.
    selected_index: Option<usize>,
    /// The current page (zero-based).
    current_page: usize,
    /// Total number of tainted entries (before filtering).
    total_tainted: usize,
    /// Total number of entries (including clean).
    total_entries: usize,
    /// Whether the provider is visible.
    pub visible: bool,
    /// Currently associated job ID (if any).
    pub current_job_id: Option<u64>,
    /// Engine-specific display metadata.
    pub engine_metadata: BTreeMap<String, String>,
}

impl TaintAnalysisProviderState {
    /// Create a new provider state with the given config.
    pub fn new(config: TaintAnalysisProviderConfig) -> Self {
        Self {
            config,
            rows: Vec::new(),
            selected_index: None,
            current_page: 0,
            total_tainted: 0,
            total_entries: 0,
            visible: true,
            current_job_id: None,
            engine_metadata: BTreeMap::new(),
        }
    }

    /// Create a new provider state with a default config.
    pub fn with_id(provider_id: impl Into<String>) -> Self {
        Self::new(TaintAnalysisProviderConfig::new(provider_id))
    }

    /// Replace the displayed rows with a new set of taint entries.
    ///
    /// Applies the provider's display filter (show_clean, show_unknown).
    pub fn set_entries(&mut self, entries: &[TaintEntry]) {
        self.total_entries = entries.len();
        self.total_tainted = entries.iter().filter(|e| e.level.is_tainted()).count();

        let rows: Vec<TaintAnalysisDisplayRow> = entries
            .iter()
            .map(TaintAnalysisDisplayRow::from_entry)
            .filter(|r| r.should_display(&self.config))
            .collect();

        self.rows = rows;
        self.current_page = 0;
        self.selected_index = None;

        if self.config.sort_column.is_some() {
            self.sort_rows();
        }
    }

    /// Add entries to the existing display.
    pub fn append_entries(&mut self, entries: &[TaintEntry]) {
        self.total_entries += entries.len();
        self.total_tainted += entries.iter().filter(|e| e.level.is_tainted()).count();

        let new_rows: Vec<TaintAnalysisDisplayRow> = entries
            .iter()
            .map(TaintAnalysisDisplayRow::from_entry)
            .filter(|r| r.should_display(&self.config))
            .collect();

        self.rows.extend(new_rows);

        if self.config.sort_column.is_some() {
            self.sort_rows();
        }
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
        self.total_tainted = 0;
        self.total_entries = 0;
        self.current_page = 0;
        self.selected_index = None;
        self.current_job_id = None;
        self.engine_metadata.clear();
    }

    /// Get the current page of display rows.
    pub fn current_page_rows(&self) -> &[TaintAnalysisDisplayRow] {
        let start = self.current_page * self.config.page_size;
        let end = (start + self.config.page_size).min(self.rows.len());
        if start >= self.rows.len() {
            &[]
        } else {
            &self.rows[start..end]
        }
    }

    /// Get the total number of pages.
    pub fn total_pages(&self) -> usize {
        if self.config.page_size == 0 {
            return 0;
        }
        (self.rows.len() + self.config.page_size - 1) / self.config.page_size
    }

    /// Navigate to the next page.  Returns true if the page changed.
    pub fn next_page(&mut self) -> bool {
        if self.current_page + 1 < self.total_pages() {
            self.current_page += 1;
            self.selected_index = None;
            true
        } else {
            false
        }
    }

    /// Navigate to the previous page.  Returns true if the page changed.
    pub fn prev_page(&mut self) -> bool {
        if self.current_page > 0 {
            self.current_page -= 1;
            self.selected_index = None;
            true
        } else {
            false
        }
    }

    /// Navigate to a specific page.  Returns true if the page exists.
    pub fn goto_page(&mut self, page: usize) -> bool {
        if page < self.total_pages() {
            self.current_page = page;
            self.selected_index = None;
            true
        } else {
            false
        }
    }

    /// Get the current page index.
    pub fn current_page(&self) -> usize {
        self.current_page
    }

    /// Select a row by index within the current page.
    pub fn select(&mut self, index: Option<usize>) {
        if let Some(i) = index {
            let page_rows = self.current_page_rows().len();
            if i < page_rows {
                self.selected_index = Some(i);
            }
        } else {
            self.selected_index = None;
        }
    }

    /// Get the selected row.
    pub fn selected_row(&self) -> Option<&TaintAnalysisDisplayRow> {
        let page_start = self.current_page * self.config.page_size;
        self.selected_index
            .and_then(|i| self.rows.get(page_start + i))
    }

    /// Get the total number of tainted entries.
    pub fn total_tainted(&self) -> usize {
        self.total_tainted
    }

    /// Get the total number of entries.
    pub fn total_entries(&self) -> usize {
        self.total_entries
    }

    /// Get the total number of filtered rows.
    pub fn filtered_count(&self) -> usize {
        self.rows.len()
    }

    /// Get all rows (not paginated).
    pub fn all_rows(&self) -> &[TaintAnalysisDisplayRow] {
        &self.rows
    }

    /// Sort the rows by the configured sort column.
    pub fn sort_rows(&mut self) {
        let ascending = self.config.sort_ascending;
        match self.config.sort_column {
            Some(TaintColumn::RegisterName) => {
                self.rows.sort_by(|a, b| {
                    let cmp = a.label.as_deref().unwrap_or("").cmp(b.label.as_deref().unwrap_or(""));
                    if ascending { cmp } else { cmp.reverse() }
                });
            }
            Some(TaintColumn::TaintStatus) => {
                self.rows.sort_by(|a, b| {
                    let cmp = (a.level as u8).cmp(&(b.level as u8));
                    if ascending { cmp } else { cmp.reverse() }
                });
            }
            Some(TaintColumn::TaintMarks) => {
                self.rows.sort_by(|a, b| {
                    let cmp = a.source.as_deref().unwrap_or("").cmp(b.source.as_deref().unwrap_or(""));
                    if ascending { cmp } else { cmp.reverse() }
                });
            }
            _ => {}
        }
    }

    /// Update the sort column and re-sort.
    pub fn set_sort(&mut self, column: TaintColumn, ascending: bool) {
        self.config.sort_column = Some(column);
        self.config.sort_ascending = ascending;
        self.sort_rows();
    }

    /// Update the display from a completed job.
    pub fn update_from_job(&mut self, job: &TaintAnalysisJob) {
        self.current_job_id = Some(job.id);
        self.set_entries(&job.results);
    }

    /// Set engine metadata (e.g., engine name, version, timing).
    pub fn set_engine_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.engine_metadata.insert(key.into(), value.into());
    }

    /// Get engine metadata.
    pub fn engine_metadata(&self, key: &str) -> Option<&str> {
        self.engine_metadata.get(key).map(|s| s.as_str())
    }
}

// ---------------------------------------------------------------------------
// TaintAnalysisProvider -- the main provider type
// ---------------------------------------------------------------------------

/// The taint analysis provider.
///
/// Ported from Ghidra's `TaintAnalysisProvider`.  Manages a single
/// taint analysis results panel, including its display state and
/// interaction with the plugin's job system.
#[derive(Debug)]
pub struct TaintAnalysisProvider {
    /// The provider state.
    state: TaintAnalysisProviderState,
}

impl TaintAnalysisProvider {
    /// Create a new provider with the given ID.
    pub fn new(provider_id: impl Into<String>) -> Self {
        Self {
            state: TaintAnalysisProviderState::with_id(provider_id),
        }
    }

    /// Create a new provider with a custom config.
    pub fn with_config(config: TaintAnalysisProviderConfig) -> Self {
        Self {
            state: TaintAnalysisProviderState::new(config),
        }
    }

    /// Get the provider ID.
    pub fn provider_id(&self) -> &str {
        &self.state.config.provider_id
    }

    /// Get the provider title.
    pub fn title(&self) -> &str {
        &self.state.config.title
    }

    /// Whether the provider is visible.
    pub fn visible(&self) -> bool {
        self.state.visible
    }

    /// Set the visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.state.visible = visible;
    }

    /// Get a reference to the provider state.
    pub fn state(&self) -> &TaintAnalysisProviderState {
        &self.state
    }

    /// Get a mutable reference to the provider state.
    pub fn state_mut(&mut self) -> &mut TaintAnalysisProviderState {
        &mut self.state
    }

    /// Load results from a job.
    pub fn load_job(&mut self, job: &TaintAnalysisJob) {
        self.state.update_from_job(job);
    }

    /// Load raw taint entries.
    pub fn load_entries(&mut self, entries: &[TaintEntry]) {
        self.state.set_entries(entries);
    }

    /// Append entries.
    pub fn append_entries(&mut self, entries: &[TaintEntry]) {
        self.state.append_entries(entries);
    }

    /// Clear the provider's display.
    pub fn clear(&mut self) {
        self.state.clear();
    }

    /// Get the current page of display rows.
    pub fn current_rows(&self) -> &[TaintAnalysisDisplayRow] {
        self.state.current_page_rows()
    }

    /// Navigate to the next page.
    pub fn next_page(&mut self) -> bool {
        self.state.next_page()
    }

    /// Navigate to the previous page.
    pub fn prev_page(&mut self) -> bool {
        self.state.prev_page()
    }

    /// Select a row by index.
    pub fn select_row(&mut self, index: Option<usize>) {
        self.state.select(index);
    }

    /// Get the selected display row.
    pub fn selected_row(&self) -> Option<&TaintAnalysisDisplayRow> {
        self.state.selected_row()
    }

    /// Get summary statistics.
    pub fn summary(&self) -> TaintAnalysisSummary {
        TaintAnalysisSummary {
            total_entries: self.state.total_entries(),
            tainted_entries: self.state.total_tainted(),
            filtered_entries: self.state.filtered_count(),
            current_page: self.state.current_page(),
            total_pages: self.state.total_pages(),
            page_size: self.state.config.page_size,
            provider_id: self.state.config.provider_id.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// TaintAnalysisSummary -- statistics about the current provider state
// ---------------------------------------------------------------------------

/// Summary statistics for a taint analysis provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintAnalysisSummary {
    /// Total entries before filtering.
    pub total_entries: usize,
    /// Number of tainted entries.
    pub tainted_entries: usize,
    /// Number of entries after filtering.
    pub filtered_entries: usize,
    /// Current page (zero-based).
    pub current_page: usize,
    /// Total pages.
    pub total_pages: usize,
    /// Page size.
    pub page_size: usize,
    /// The provider ID.
    pub provider_id: String,
}

impl TaintAnalysisSummary {
    /// Whether there are any tainted entries.
    pub fn has_tainted(&self) -> bool {
        self.tainted_entries > 0
    }

    /// Whether there are multiple pages.
    pub fn is_paginated(&self) -> bool {
        self.total_pages > 1
    }

    /// The display range for the current page (1-based).
    pub fn page_range(&self) -> (usize, usize) {
        let start = self.current_page * self.page_size + 1;
        let end = ((self.current_page + 1) * self.page_size).min(self.filtered_entries);
        (start, end)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Config tests --

    #[test]
    fn test_provider_config_default() {
        let cfg = TaintAnalysisProviderConfig::new("test-provider");
        assert_eq!(cfg.provider_id, "test-provider");
        assert_eq!(cfg.title, "Taint Analysis");
        assert!(!cfg.show_clean);
        assert!(!cfg.show_unknown);
        assert_eq!(cfg.page_size, 100);
        assert!(cfg.auto_scroll);
        assert!(cfg.sort_column.is_none());
    }

    #[test]
    fn test_provider_config_builder() {
        let cfg = TaintAnalysisProviderConfig::new("p1")
            .with_title("Custom Title")
            .with_show_clean(true)
            .with_page_size(50)
            .with_sort(TaintColumn::TaintStatus, false);

        assert_eq!(cfg.title, "Custom Title");
        assert!(cfg.show_clean);
        assert_eq!(cfg.page_size, 50);
        assert!(cfg.sort_column.is_some());
        assert!(!cfg.sort_ascending);
    }

    // -- Display row tests --

    #[test]
    fn test_display_row_from_entry() {
        let entry = TaintEntry {
            address: 0x1000,
            level: TaintLevel::UserInput,
            size: 4,
            source: Some("stdin".to_string()),
        };
        let row = TaintAnalysisDisplayRow::from_entry(&entry);
        assert_eq!(row.address, 0x1000);
        assert_eq!(row.level, TaintLevel::UserInput);
        assert_eq!(row.source.as_deref(), Some("stdin"));
    }

    #[test]
    fn test_display_row_filter() {
        let clean = TaintAnalysisDisplayRow {
            address: 0,
            level: TaintLevel::Clean,
            size: 1,
            source: None,
            label: None,
            field_location: None,
        };
        let unknown = TaintAnalysisDisplayRow {
            address: 0,
            level: TaintLevel::Unknown,
            size: 1,
            source: None,
            label: None,
            field_location: None,
        };
        let tainted = TaintAnalysisDisplayRow {
            address: 0,
            level: TaintLevel::Network,
            size: 1,
            source: None,
            label: None,
            field_location: None,
        };

        let cfg = TaintAnalysisProviderConfig::new("test");
        assert!(!clean.should_display(&cfg));
        assert!(!unknown.should_display(&cfg));
        assert!(tainted.should_display(&cfg));

        let cfg = TaintAnalysisProviderConfig::new("test")
            .with_show_clean(true)
            .with_show_unknown(true);
        assert!(clean.should_display(&cfg));
        assert!(unknown.should_display(&cfg));
    }

    #[test]
    fn test_display_row_register() {
        let row = TaintAnalysisDisplayRow::register(
            0,
            TaintLevel::UserInput,
            8,
            "RAX",
        );
        assert_eq!(row.label.as_deref(), Some("RAX"));
        assert_eq!(row.size, 8);
    }

    // -- Provider state tests --

    #[test]
    fn test_provider_state_new() {
        let state = TaintAnalysisProviderState::with_id("test");
        assert_eq!(state.total_tainted(), 0);
        assert_eq!(state.total_entries(), 0);
        assert!(state.visible);
        assert!(state.current_page_rows().is_empty());
    }

    #[test]
    fn test_provider_state_set_entries() {
        let mut state = TaintAnalysisProviderState::with_id("test");
        let entries = vec![
            TaintEntry {
                address: 0x1000,
                level: TaintLevel::UserInput,
                size: 4,
                source: Some("a".into()),
            },
            TaintEntry {
                address: 0x2000,
                level: TaintLevel::Clean,
                size: 4,
                source: None,
            },
            TaintEntry {
                address: 0x3000,
                level: TaintLevel::Network,
                size: 8,
                source: Some("b".into()),
            },
        ];
        state.set_entries(&entries);
        assert_eq!(state.total_entries(), 3);
        assert_eq!(state.total_tainted(), 2);
        // Clean is not shown by default
        assert_eq!(state.filtered_count(), 2);
    }

    #[test]
    fn test_provider_state_pagination() {
        let config = TaintAnalysisProviderConfig::new("test").with_page_size(2);
        let mut state = TaintAnalysisProviderState::new(config);
        let entries: Vec<TaintEntry> = (0..5)
            .map(|i| TaintEntry {
                address: 0x1000 + i * 0x100,
                level: TaintLevel::UserInput,
                size: 1,
                source: None,
            })
            .collect();
        state.set_entries(&entries);
        assert_eq!(state.total_pages(), 3);
        assert_eq!(state.current_page_rows().len(), 2);

        assert!(state.next_page());
        assert_eq!(state.current_page(), 1);
        assert_eq!(state.current_page_rows().len(), 2);

        assert!(state.next_page());
        assert_eq!(state.current_page(), 2);
        assert_eq!(state.current_page_rows().len(), 1);

        assert!(!state.next_page()); // already at last page
    }

    #[test]
    fn test_provider_state_prev_page() {
        let config = TaintAnalysisProviderConfig::new("test").with_page_size(2);
        let mut state = TaintAnalysisProviderState::new(config);
        let entries: Vec<TaintEntry> = (0..5)
            .map(|i| TaintEntry {
                address: 0x1000 + i * 0x100,
                level: TaintLevel::UserInput,
                size: 1,
                source: None,
            })
            .collect();
        state.set_entries(&entries);
        state.next_page();
        state.next_page();

        assert!(state.prev_page());
        assert_eq!(state.current_page(), 1);
        assert!(state.prev_page());
        assert_eq!(state.current_page(), 0);
        assert!(!state.prev_page()); // already at first page
    }

    #[test]
    fn test_provider_state_goto_page() {
        let config = TaintAnalysisProviderConfig::new("test").with_page_size(2);
        let mut state = TaintAnalysisProviderState::new(config);
        let entries: Vec<TaintEntry> = (0..5)
            .map(|i| TaintEntry {
                address: 0x1000 + i * 0x100,
                level: TaintLevel::UserInput,
                size: 1,
                source: None,
            })
            .collect();
        state.set_entries(&entries);

        assert!(state.goto_page(2));
        assert_eq!(state.current_page(), 2);
        assert!(!state.goto_page(10)); // out of range
    }

    #[test]
    fn test_provider_state_select() {
        let mut state = TaintAnalysisProviderState::with_id("test");
        let entries = vec![
            TaintEntry {
                address: 0x1000,
                level: TaintLevel::UserInput,
                size: 4,
                source: None,
            },
            TaintEntry {
                address: 0x2000,
                level: TaintLevel::Network,
                size: 4,
                source: None,
            },
        ];
        state.set_entries(&entries);

        state.select(Some(0));
        let selected = state.selected_row().unwrap();
        assert_eq!(selected.address, 0x1000);

        state.select(Some(1));
        let selected = state.selected_row().unwrap();
        assert_eq!(selected.address, 0x2000);

        state.select(None);
        assert!(state.selected_row().is_none());
    }

    #[test]
    fn test_provider_state_append() {
        let mut state = TaintAnalysisProviderState::with_id("test");
        let e1 = vec![TaintEntry {
            address: 0x1000,
            level: TaintLevel::UserInput,
            size: 4,
            source: None,
        }];
        state.set_entries(&e1);
        assert_eq!(state.filtered_count(), 1);

        let e2 = vec![TaintEntry {
            address: 0x2000,
            level: TaintLevel::Network,
            size: 4,
            source: None,
        }];
        state.append_entries(&e2);
        assert_eq!(state.filtered_count(), 2);
        assert_eq!(state.total_tainted(), 2);
    }

    #[test]
    fn test_provider_state_sort() {
        let mut state = TaintAnalysisProviderState::with_id("test");
        let entries = vec![
            TaintEntry {
                address: 0x2000,
                level: TaintLevel::Network,
                size: 4,
                source: Some("b".into()),
            },
            TaintEntry {
                address: 0x1000,
                level: TaintLevel::UserInput,
                size: 4,
                source: Some("a".into()),
            },
        ];
        state.set_entries(&entries);

        // Sort ascending by source
        state.set_sort(TaintColumn::TaintMarks, true);
        let rows = state.all_rows();
        assert_eq!(rows[0].source.as_deref(), Some("a"));
        assert_eq!(rows[1].source.as_deref(), Some("b"));

        // Sort descending
        state.set_sort(TaintColumn::TaintMarks, false);
        let rows = state.all_rows();
        assert_eq!(rows[0].source.as_deref(), Some("b"));
        assert_eq!(rows[1].source.as_deref(), Some("a"));
    }

    #[test]
    fn test_provider_state_clear() {
        let mut state = TaintAnalysisProviderState::with_id("test");
        let entries = vec![TaintEntry {
            address: 0x1000,
            level: TaintLevel::UserInput,
            size: 4,
            source: None,
        }];
        state.set_entries(&entries);
        state.set_engine_metadata("engine", "angr");
        state.current_job_id = Some(1);

        state.clear();
        assert_eq!(state.total_entries(), 0);
        assert!(state.current_job_id.is_none());
        assert!(state.engine_metadata.is_empty());
    }

    #[test]
    fn test_provider_state_metadata() {
        let mut state = TaintAnalysisProviderState::with_id("test");
        state.set_engine_metadata("engine", "angr");
        state.set_engine_metadata("version", "1.0");
        assert_eq!(state.engine_metadata("engine"), Some("angr"));
        assert_eq!(state.engine_metadata("version"), Some("1.0"));
        assert!(state.engine_metadata("missing").is_none());
    }

    // -- Provider tests --

    #[test]
    fn test_provider_new() {
        let provider = TaintAnalysisProvider::new("main-taint");
        assert_eq!(provider.provider_id(), "main-taint");
        assert_eq!(provider.title(), "Taint Analysis");
        assert!(provider.visible());
    }

    #[test]
    fn test_provider_load_entries() {
        let mut provider = TaintAnalysisProvider::new("test");
        let entries = vec![
            TaintEntry {
                address: 0x1000,
                level: TaintLevel::UserInput,
                size: 4,
                source: Some("stdin".into()),
            },
            TaintEntry {
                address: 0x2000,
                level: TaintLevel::FileInput,
                size: 8,
                source: Some("read".into()),
            },
        ];
        provider.load_entries(&entries);

        assert_eq!(provider.state().total_tainted(), 2);
        assert_eq!(provider.current_rows().len(), 2);
    }

    #[test]
    fn test_provider_navigation() {
        let config = TaintAnalysisProviderConfig::new("test").with_page_size(2);
        let mut provider = TaintAnalysisProvider::with_config(config);
        let entries: Vec<TaintEntry> = (0..5)
            .map(|i| TaintEntry {
                address: 0x1000 + i * 0x100,
                level: TaintLevel::UserInput,
                size: 1,
                source: None,
            })
            .collect();
        provider.load_entries(&entries);

        assert_eq!(provider.current_rows().len(), 2);
        provider.next_page();
        assert_eq!(provider.current_rows().len(), 2);
        provider.next_page();
        assert_eq!(provider.current_rows().len(), 1);
    }

    #[test]
    fn test_provider_summary() {
        let mut provider = TaintAnalysisProvider::new("test");
        let entries = vec![
            TaintEntry {
                address: 0x1000,
                level: TaintLevel::UserInput,
                size: 4,
                source: None,
            },
            TaintEntry {
                address: 0x2000,
                level: TaintLevel::Clean,
                size: 4,
                source: None,
            },
        ];
        provider.load_entries(&entries);
        let summary = provider.summary();
        assert_eq!(summary.total_entries, 2);
        assert_eq!(summary.tainted_entries, 1);
        assert!(summary.has_tainted());
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = TaintAnalysisProvider::new("test");
        assert!(provider.visible());
        provider.set_visible(false);
        assert!(!provider.visible());
    }

    #[test]
    fn test_provider_clear() {
        let mut provider = TaintAnalysisProvider::new("test");
        let entries = vec![TaintEntry {
            address: 0x1000,
            level: TaintLevel::UserInput,
            size: 4,
            source: None,
        }];
        provider.load_entries(&entries);
        assert_eq!(provider.state().total_entries(), 1);

        provider.clear();
        assert_eq!(provider.state().total_entries(), 0);
    }

    #[test]
    fn test_summary_page_range() {
        let summary = TaintAnalysisSummary {
            total_entries: 100,
            tainted_entries: 80,
            filtered_entries: 80,
            current_page: 2,
            total_pages: 8,
            page_size: 10,
            provider_id: "test".into(),
        };
        let (start, end) = summary.page_range();
        assert_eq!(start, 21);
        assert_eq!(end, 30);
    }

    #[test]
    fn test_summary_is_paginated() {
        let single = TaintAnalysisSummary {
            total_entries: 5,
            tainted_entries: 5,
            filtered_entries: 5,
            current_page: 0,
            total_pages: 1,
            page_size: 10,
            provider_id: "test".into(),
        };
        assert!(!single.is_paginated());

        let multi = TaintAnalysisSummary {
            total_entries: 100,
            tainted_entries: 100,
            filtered_entries: 100,
            current_page: 0,
            total_pages: 10,
            page_size: 10,
            provider_id: "test".into(),
        };
        assert!(multi.is_paginated());
    }
}
