// ===========================================================================
// Search All Instructions Task -- ported from Ghidra's
// `ghidra.app.plugin.core.instructionsearch.ui.BytePatternSearchTask`.
//
// A background task that searches the entire program (or selection) for
// byte patterns discovered by the instruction search.
// ===========================================================================

use ghidra_core::Address;

use super::{SearchDirection, SearchOptions, SearchResult};

/// Status of the search task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchTaskStatus {
    /// Task has not started yet.
    Pending,
    /// Task is running.
    Running,
    /// Task completed.
    Completed,
    /// Task was cancelled.
    Cancelled,
}

impl Default for SearchTaskStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// A task that searches an address range for a byte pattern.
///
/// This is the concrete byte-level search implementation that operates
/// on raw memory. Distinct from [`super::search_task::BytePatternSearchTask`]
/// which uses the higher-level mask/value framework.
///
/// Ported from
/// `ghidra.app.plugin.core.instructionsearch.ui.BytePatternSearchTask`.
#[derive(Debug, Clone)]
pub struct BytePatternSearchTask {
    /// The search bytes.
    pub search_bytes: Vec<u8>,
    /// The mask bytes (0xFF = must match, 0x00 = wildcard).
    pub mask_bytes: Vec<u8>,
    /// The search options.
    pub options: SearchOptions,
    /// The start address for the search.
    pub start_address: Address,
    /// The end address (exclusive) for the search.
    pub end_address: Address,
    /// Current status.
    pub status: SearchTaskStatus,
    /// Discovered matches.
    pub results: Vec<SearchResult>,
    /// Number of bytes scanned so far.
    pub bytes_scanned: u64,
    /// Total bytes to scan.
    pub total_bytes: u64,
}

impl BytePatternSearchTask {
    /// Create a new search task.
    pub fn new(
        search_bytes: Vec<u8>,
        mask_bytes: Vec<u8>,
        start_address: Address,
        end_address: Address,
    ) -> Self {
        let total = end_address.offset.saturating_sub(start_address.offset);
        Self {
            search_bytes,
            mask_bytes,
            options: SearchOptions::default(),
            start_address,
            end_address,
            status: SearchTaskStatus::Pending,
            results: Vec::new(),
            bytes_scanned: 0,
            total_bytes: total,
        }
    }

    /// Start the search.
    pub fn start(&mut self) {
        self.status = SearchTaskStatus::Running;
    }

    /// Cancel the search.
    pub fn cancel(&mut self) {
        self.status = SearchTaskStatus::Cancelled;
    }

    /// Check if the search is done.
    pub fn is_done(&self) -> bool {
        matches!(
            self.status,
            SearchTaskStatus::Completed | SearchTaskStatus::Cancelled
        )
    }

    /// Get progress as a fraction (0.0 to 1.0).
    pub fn progress(&self) -> f64 {
        if self.total_bytes == 0 {
            return 1.0;
        }
        self.bytes_scanned as f64 / self.total_bytes as f64
    }

    /// Run the search over a byte slice.
    ///
    /// This is a simplified implementation that does a brute-force scan.
    pub fn search_in_bytes(&mut self, data: &[u8]) -> usize {
        self.status = SearchTaskStatus::Running;
        let pattern_len = self.search_bytes.len();

        if pattern_len == 0 || data.len() < pattern_len {
            self.status = SearchTaskStatus::Completed;
            return 0;
        }

        let mut found = 0;
        let start = if self.options.search_forward {
            0
        } else {
            data.len().saturating_sub(pattern_len)
        };

        let iter: Box<dyn Iterator<Item = usize>> = if self.options.search_forward {
            Box::new(0..=data.len().saturating_sub(pattern_len))
        } else {
            Box::new((0..=data.len().saturating_sub(pattern_len)).rev())
        };

        for i in iter {
            if self.status == SearchTaskStatus::Cancelled {
                break;
            }

            let mut matches = true;
            for j in 0..pattern_len {
                let mask = if j < self.mask_bytes.len() {
                    self.mask_bytes[j]
                } else {
                    0xFF
                };
                if (data[i + j] & mask) != (self.search_bytes[j] & mask) {
                    matches = false;
                    break;
                }
            }

            if matches {
                let addr = Address::new(self.start_address.offset + i as u64);
                self.results.push(SearchResult {
                    address: addr,
                    length: pattern_len,
                    matched_bytes: self.search_bytes[..pattern_len].to_vec(),
                    instruction: None,
                });
                found += 1;

                // If not searching for all occurrences, stop after first match.
                if !self.options.selection_only {
                    break;
                }
            }
        }

        self.bytes_scanned = data.len() as u64;
        self.status = SearchTaskStatus::Completed;
        found
    }

    /// Get the number of matches found.
    pub fn match_count(&self) -> usize {
        self.results.len()
    }
}

// ---------------------------------------------------------------------------
// InstructionSearchDialog
// ---------------------------------------------------------------------------

/// Dialog model for the instruction search feature.
///
/// Ported from
/// `ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog`.
#[derive(Debug, Clone)]
pub struct InstructionSearchDialog {
    /// Whether the dialog is open.
    pub is_open: bool,
    /// The current search pattern (raw bytes).
    pub search_bytes: Vec<u8>,
    /// The mask bytes.
    pub mask_bytes: Vec<u8>,
    /// Current search options.
    pub options: SearchOptions,
    /// The dialog title.
    pub title: String,
    /// Whether the search has been initiated.
    pub search_initiated: bool,
}

impl InstructionSearchDialog {
    /// Create a new dialog.
    pub fn new() -> Self {
        Self {
            is_open: false,
            search_bytes: Vec::new(),
            mask_bytes: Vec::new(),
            options: SearchOptions::default(),
            title: "Instruction Search".into(),
            search_initiated: false,
        }
    }

    /// Open the dialog.
    pub fn open(&mut self) {
        self.is_open = true;
    }

    /// Close the dialog.
    pub fn close(&mut self) {
        self.is_open = false;
    }

    /// Set the search pattern.
    pub fn set_pattern(&mut self, bytes: Vec<u8>, mask: Vec<u8>) {
        self.search_bytes = bytes;
        self.mask_bytes = mask;
    }

    /// Initiate the search.
    pub fn initiate_search(&mut self) -> bool {
        if self.search_bytes.is_empty() {
            return false;
        }
        self.search_initiated = true;
        true
    }

    /// Create a search task from the current dialog state.
    pub fn create_task(&self, start: Address, end: Address) -> Option<BytePatternSearchTask> {
        if self.search_bytes.is_empty() {
            return None;
        }
        Some(BytePatternSearchTask::new(
            self.search_bytes.clone(),
            self.mask_bytes.clone(),
            start,
            end,
        ))
    }
}

impl Default for InstructionSearchDialog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// InstructionSearchPlugin
// ---------------------------------------------------------------------------

/// Plugin that manages the instruction search feature.
///
/// Ported from
/// `ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin`.
#[derive(Debug, Clone)]
pub struct InstructionSearchPlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// The current dialog (if open).
    pub dialog: Option<InstructionSearchDialog>,
    /// Total number of searches performed.
    pub search_count: usize,
    /// Total matches found across all searches.
    pub total_matches: usize,
}

impl InstructionSearchPlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            name: "InstructionSearch".into(),
            enabled: true,
            dialog: None,
            search_count: 0,
            total_matches: 0,
        }
    }

    /// Open the search dialog.
    pub fn open_search(&mut self) {
        let mut dialog = InstructionSearchDialog::new();
        dialog.open();
        self.dialog = Some(dialog);
    }

    /// Close the search dialog.
    pub fn close_search(&mut self) {
        if let Some(dialog) = &mut self.dialog {
            dialog.close();
        }
        self.dialog = None;
    }

    /// Record a completed search.
    pub fn record_search(&mut self, match_count: usize) {
        self.search_count += 1;
        self.total_matches += match_count;
    }
}

impl Default for InstructionSearchPlugin {
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
    fn test_search_all_instructions_task_basic() {
        let mut task = BytePatternSearchTask::new(
            vec![0x90, 0xC3],
            vec![0xFF, 0xFF],
            Address::new(0x0),
            Address::new(0x100),
        );
        let data = vec![0x00, 0x00, 0x90, 0xC3, 0x00];
        let found = task.search_in_bytes(&data);
        assert_eq!(found, 1);
        assert_eq!(task.results[0].address, Address::new(0x2));
        assert_eq!(task.status, SearchTaskStatus::Completed);
    }

    #[test]
    fn test_search_with_mask() {
        let mut task = BytePatternSearchTask::new(
            vec![0x90, 0xC3],
            vec![0xFF, 0x00], // ignore second byte
            Address::new(0x0),
            Address::new(0x100),
        );
        let data = vec![0x90, 0xFF, 0x00, 0x90, 0x00];
        let found = task.search_in_bytes(&data);
        assert_eq!(found, 1); // Only first match (0x90,0xFF with mask 0xFF,0x00 = 0x90,0x00 = match)
    }

    #[test]
    fn test_search_task_progress() {
        let mut task = BytePatternSearchTask::new(
            vec![0x90],
            vec![0xFF],
            Address::new(0x0),
            Address::new(0x100),
        );
        assert_eq!(task.progress(), 0.0);
        task.bytes_scanned = 0x80;
        assert!((task.progress() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_search_task_cancel() {
        let mut task = BytePatternSearchTask::new(
            vec![0x90],
            vec![0xFF],
            Address::new(0x0),
            Address::new(0x100),
        );
        task.cancel();
        assert_eq!(task.status, SearchTaskStatus::Cancelled);
        assert!(task.is_done());
    }

    #[test]
    fn test_instruction_search_dialog() {
        let mut dialog = InstructionSearchDialog::new();
        assert!(!dialog.is_open);
        dialog.open();
        assert!(dialog.is_open);

        dialog.set_pattern(vec![0x90], vec![0xFF]);
        assert!(dialog.initiate_search());
        assert!(dialog.search_initiated);

        let task = dialog.create_task(Address::new(0x0), Address::new(0x100));
        assert!(task.is_some());

        dialog.close();
        assert!(!dialog.is_open);
    }

    #[test]
    fn test_instruction_search_dialog_empty_pattern() {
        let mut dialog = InstructionSearchDialog::new();
        assert!(!dialog.initiate_search());
        assert!(!dialog.search_initiated);
        assert!(dialog
            .create_task(Address::new(0x0), Address::new(0x100))
            .is_none());
    }

    #[test]
    fn test_instruction_search_plugin() {
        let mut plugin = InstructionSearchPlugin::new();
        assert_eq!(plugin.search_count, 0);

        plugin.open_search();
        assert!(plugin.dialog.is_some());

        plugin.record_search(5);
        plugin.record_search(3);
        assert_eq!(plugin.search_count, 2);
        assert_eq!(plugin.total_matches, 8);

        plugin.close_search();
        assert!(plugin.dialog.is_none());
    }

    #[test]
    fn test_search_backward() {
        let mut task = BytePatternSearchTask::new(
            vec![0x90],
            vec![0xFF],
            Address::new(0x0),
            Address::new(0x100),
        );
        task.options.search_forward = false;
        let data = vec![0x90, 0x00, 0x90];
        task.search_in_bytes(&data);
        // Should find the last occurrence first when searching backward.
        assert!(!task.results.is_empty());
        assert_eq!(task.results[0].address, Address::new(0x2));
    }
}
