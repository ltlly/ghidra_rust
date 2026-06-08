//! Label history dialog for displaying label changes at an address.
//!
//! Ported from Ghidra's `LabelHistoryDialog` (`LabelHistoryDialog.java`).
//!
//! This dialog displays a table of label history entries (add, remove, rename)
//! at a given address, or with a custom title for the "all history" view.
//! It implements the [`LabelHistoryListener`] trait to support address
//! navigation when a user clicks on a history row.

use std::fmt;

use ghidra_core::addr::Address;

use super::dialogs::LabelHistoryPanel;
use super::history::{LabelHistoryAction, LabelHistoryEntry, LabelHistoryTableModel};

// ---------------------------------------------------------------------------
// LabelHistoryDialog
// ---------------------------------------------------------------------------

/// Dialog that shows label history for an address or with a custom title.
///
/// Ported from Ghidra's `LabelHistoryDialog`. This dialog:
/// - Displays a table of label history entries via [`LabelHistoryPanel`]
/// - Implements [`LabelHistoryListener`] for address navigation
/// - Has a dismiss button (OK/Close)
/// - Has help location support
///
/// In Ghidra's Swing implementation, this extends `DialogComponentProvider`
/// and adds a `LabelHistoryPanel` as the work panel. In this Rust port,
/// we model the dialog state and behavior without Swing dependencies.
///
/// # Example
///
/// ```
/// use ghidra_features::base::label::{LabelHistoryDialog, LabelHistoryEntry, LabelHistoryAction};
/// use ghidra_core::addr::Address;
///
/// let entries = vec![
///     LabelHistoryEntry::new(
///         Address::new(0x1000),
///         LabelHistoryAction::Add,
///         "main",
///         "user1",
///         "2024-01-01",
///     ),
/// ];
///
/// // Create dialog for a specific address
/// let dialog = LabelHistoryDialog::for_address(Address::new(0x1000), entries.clone());
/// assert_eq!(dialog.title(), "Show Label History for 0x1000");
/// assert!(!dialog.is_dismissed());
///
/// // Create dialog with custom title
/// let dialog = LabelHistoryDialog::with_title("All Label History", entries);
/// assert_eq!(dialog.title(), "All Label History");
/// ```
pub struct LabelHistoryDialog {
    /// The dialog title.
    title: String,
    /// The address being shown (None for "all history" mode).
    address: Option<Address>,
    /// The history panel displaying the entries.
    panel: LabelHistoryPanel,
    /// Help location topic.
    help_topic: String,
    /// Help location anchor.
    help_anchor: String,
    /// Whether the dialog has been dismissed.
    dismissed: bool,
    /// The navigation callback target address (set when a row is clicked).
    navigated_address: Option<Address>,
}

impl LabelHistoryDialog {
    /// Creates a dialog showing label history for a specific address.
    ///
    /// Mirrors `LabelHistoryDialog(PluginTool tool, Program program,
    /// Address addr, List<LabelHistory> list)` in Java.
    ///
    /// The title is automatically set to "Show Label History for {address}".
    pub fn for_address(address: Address, entries: Vec<LabelHistoryEntry>) -> Self {
        let title = format!("Show Label History for 0x{:X}", address.offset);
        let mut panel = LabelHistoryPanel::for_address(address);
        panel.set_entries(entries);

        Self {
            title,
            address: Some(address),
            panel,
            help_topic: "Label".to_string(),
            help_anchor: "Show_Label_History".to_string(),
            dismissed: false,
            navigated_address: None,
        }
    }

    /// Creates a dialog with a custom title.
    ///
    /// Mirrors `LabelHistoryDialog(PluginTool tool, Program program,
    /// String title, List<LabelHistory> list)` in Java. This constructor
    /// is used for the "all history" view which shows a custom title
    /// like "All Label History" or "Label History Matching {pattern}".
    ///
    /// The panel shows the address column since it displays entries
    /// from multiple addresses.
    pub fn with_title(title: impl Into<String>, entries: Vec<LabelHistoryEntry>) -> Self {
        let mut panel = LabelHistoryPanel::show_all();
        panel.set_entries(entries);

        Self {
            title: title.into(),
            address: None,
            panel,
            help_topic: "Label".to_string(),
            help_anchor: "Show_All_History".to_string(),
            dismissed: false,
            navigated_address: None,
        }
    }

    /// Returns the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the address, if this is a single-address history dialog.
    pub fn address(&self) -> Option<Address> {
        self.address
    }

    /// Returns a reference to the history panel.
    pub fn panel(&self) -> &LabelHistoryPanel {
        &self.panel
    }

    /// Returns a mutable reference to the history panel.
    pub fn panel_mut(&mut self) -> &mut LabelHistoryPanel {
        &mut self.panel
    }

    /// Returns the table model for the displayed entries.
    pub fn table_model(&self) -> LabelHistoryTableModel {
        self.panel.table_model()
    }

    /// Returns the number of entries being displayed.
    pub fn entry_count(&self) -> usize {
        self.panel.entry_count()
    }

    /// Returns the entries being displayed.
    pub fn entries(&self) -> &[LabelHistoryEntry] {
        self.panel.entries()
    }

    /// Sets the help location.
    ///
    /// In Ghidra, this is `setHelpLocation(new HelpLocation(HelpTopics.LABEL, anchor))`.
    pub fn set_help_location(&mut self, topic: impl Into<String>, anchor: impl Into<String>) {
        self.help_topic = topic.into();
        self.help_anchor = anchor.into();
    }

    /// Returns the help topic.
    pub fn help_topic(&self) -> &str {
        &self.help_topic
    }

    /// Returns the help anchor.
    pub fn help_anchor(&self) -> &str {
        &self.help_anchor
    }

    /// Dismisses the dialog.
    ///
    /// Mirrors the dismiss/close behavior of the Java `DialogComponentProvider`.
    pub fn dismiss(&mut self) {
        self.dismissed = true;
    }

    /// Returns whether the dialog has been dismissed.
    pub fn is_dismissed(&self) -> bool {
        self.dismissed
    }

    /// Handles a row selection in the history table.
    ///
    /// When the user clicks on a history entry, this method is called
    /// to trigger address navigation. Returns the address to navigate to,
    /// if one was selected.
    pub fn handle_row_click(&mut self, row_index: usize) -> Option<Address> {
        if let Some(entry) = self.panel.entries().get(row_index) {
            let addr = entry.address;
            self.navigated_address = Some(addr);
            self.notify_address_selected(addr);
            Some(addr)
        } else {
            None
        }
    }

    /// Returns the address that was navigated to, if any.
    pub fn navigated_address(&self) -> Option<Address> {
        self.navigated_address
    }

    /// Notifies listeners that an address was selected.
    ///
    /// This is the Rust equivalent of the `LabelHistoryListener.addressSelected()`
    /// callback. In Ghidra, this triggers the `GoToService` to navigate
    /// to the address.
    fn notify_address_selected(&self, address: Address) {
        // In Ghidra, this calls:
        //   GoToService service = tool.getService(GoToService.class);
        //   if (service != null) {
        //       service.goTo(new CodeUnitLocation(program, addr, null, 0, 0, 0));
        //   }
        //
        // In our Rust port, the caller can observe `navigated_address()`.
    }

    /// Returns the display data for all visible rows and columns.
    ///
    /// This is a convenience method that returns the cell values for
    /// rendering the table.
    pub fn display_data(&self) -> Vec<Vec<String>> {
        let model = self.panel.table_model();
        let rows = model.row_count();
        let cols = model.column_count();

        (0..rows)
            .map(|row| {
                (0..cols)
                    .map(|col| model.get_value(row, col).unwrap_or_default())
                    .collect()
            })
            .collect()
    }

    /// Returns the column headers for the table.
    pub fn column_headers(&self) -> Vec<String> {
        let model = self.panel.table_model();
        (0..model.column_count())
            .map(|col| model.column_name(col).unwrap_or("").to_string())
            .collect()
    }

    /// Returns true if there are no entries to display.
    pub fn is_empty(&self) -> bool {
        self.panel.entry_count() == 0
    }

    /// Returns true if this dialog shows all addresses (not a single address).
    pub fn is_show_all(&self) -> bool {
        self.address.is_none()
    }
}

impl fmt::Debug for LabelHistoryDialog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LabelHistoryDialog")
            .field("title", &self.title)
            .field("address", &self.address)
            .field("entry_count", &self.entry_count())
            .field("dismissed", &self.dismissed)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn sample_entries() -> Vec<LabelHistoryEntry> {
        vec![
            LabelHistoryEntry::new(
                addr(0x1000),
                LabelHistoryAction::Add,
                "main",
                "user1",
                "2024-01-01",
            ),
            LabelHistoryEntry::new(
                addr(0x1000),
                LabelHistoryAction::Rename,
                "main_old",
                "user1",
                "2024-01-02",
            ),
            LabelHistoryEntry::new(
                addr(0x1000),
                LabelHistoryAction::Remove,
                "main_old",
                "user1",
                "2024-01-03",
            ),
        ]
    }

    fn multi_address_entries() -> Vec<LabelHistoryEntry> {
        vec![
            LabelHistoryEntry::new(
                addr(0x1000),
                LabelHistoryAction::Add,
                "main",
                "user1",
                "2024-01-01",
            ),
            LabelHistoryEntry::new(
                addr(0x2000),
                LabelHistoryAction::Add,
                "helper",
                "user2",
                "2024-01-02",
            ),
            LabelHistoryEntry::new(
                addr(0x3000),
                LabelHistoryAction::Add,
                "init",
                "user3",
                "2024-01-03",
            ),
        ]
    }

    // -- for_address constructor --

    #[test]
    fn test_for_address_title() {
        let dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        assert_eq!(dialog.title(), "Show Label History for 0x1000");
    }

    #[test]
    fn test_for_address_has_address() {
        let dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        assert_eq!(dialog.address(), Some(addr(0x1000)));
        assert!(!dialog.is_show_all());
    }

    #[test]
    fn test_for_address_entry_count() {
        let dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        assert_eq!(dialog.entry_count(), 3);
    }

    #[test]
    fn test_for_address_panel_shows_no_address_column() {
        let dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        // Single-address mode: Address column is hidden.
        let headers = dialog.column_headers();
        assert_eq!(headers.len(), 4);
        assert_eq!(headers[0], "Action");
        assert_eq!(headers[1], "Label");
    }

    // -- with_title constructor --

    #[test]
    fn test_with_title() {
        let dialog = LabelHistoryDialog::with_title("All Label History", multi_address_entries());
        assert_eq!(dialog.title(), "All Label History");
    }

    #[test]
    fn test_with_title_no_address() {
        let dialog = LabelHistoryDialog::with_title("All", multi_address_entries());
        assert!(dialog.address().is_none());
        assert!(dialog.is_show_all());
    }

    #[test]
    fn test_with_title_panel_shows_address_column() {
        let dialog = LabelHistoryDialog::with_title("All", multi_address_entries());
        let headers = dialog.column_headers();
        assert_eq!(headers.len(), 5);
        assert_eq!(headers[0], "Address");
        assert_eq!(headers[1], "Action");
    }

    #[test]
    fn test_with_matching_title() {
        let dialog =
            LabelHistoryDialog::with_title("Label History Matching main", sample_entries());
        assert_eq!(dialog.title(), "Label History Matching main");
    }

    // -- Dismiss behavior --

    #[test]
    fn test_not_dismissed_initially() {
        let dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        assert!(!dialog.is_dismissed());
    }

    #[test]
    fn test_dismiss() {
        let mut dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        dialog.dismiss();
        assert!(dialog.is_dismissed());
    }

    // -- Row click / navigation --

    #[test]
    fn test_handle_row_click() {
        let mut dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        let nav_addr = dialog.handle_row_click(0);
        assert_eq!(nav_addr, Some(addr(0x1000)));
        assert_eq!(dialog.navigated_address(), Some(addr(0x1000)));
    }

    #[test]
    fn test_handle_row_click_out_of_bounds() {
        let mut dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        let nav_addr = dialog.handle_row_click(99);
        assert!(nav_addr.is_none());
        assert!(dialog.navigated_address().is_none());
    }

    #[test]
    fn test_handle_multiple_clicks() {
        let mut dialog = LabelHistoryDialog::with_title("All", multi_address_entries());
        dialog.handle_row_click(0);
        assert_eq!(dialog.navigated_address(), Some(addr(0x1000)));
        dialog.handle_row_click(1);
        assert_eq!(dialog.navigated_address(), Some(addr(0x2000)));
    }

    // -- Help location --

    #[test]
    fn test_default_help_location() {
        let dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        assert_eq!(dialog.help_topic(), "Label");
        assert_eq!(dialog.help_anchor(), "Show_Label_History");
    }

    #[test]
    fn test_all_history_help_location() {
        let dialog = LabelHistoryDialog::with_title("All", sample_entries());
        assert_eq!(dialog.help_anchor(), "Show_All_History");
    }

    #[test]
    fn test_set_help_location() {
        let mut dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        dialog.set_help_location("CustomTopic", "CustomAnchor");
        assert_eq!(dialog.help_topic(), "CustomTopic");
        assert_eq!(dialog.help_anchor(), "CustomAnchor");
    }

    // -- Display data --

    #[test]
    fn test_display_data_single_address() {
        let dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        let data = dialog.display_data();
        assert_eq!(data.len(), 3);
        assert_eq!(data[0].len(), 4); // Action, Label, User, Date
        assert_eq!(data[0][0], "Add");
        assert_eq!(data[0][1], "main");
    }

    #[test]
    fn test_display_data_all_addresses() {
        let dialog = LabelHistoryDialog::with_title("All", multi_address_entries());
        let data = dialog.display_data();
        assert_eq!(data.len(), 3);
        assert_eq!(data[0].len(), 5); // Address, Action, Label, User, Date
        assert_eq!(data[0][0], "0x1000");
        assert_eq!(data[0][1], "Add");
    }

    // -- Column headers --

    #[test]
    fn test_column_headers_single_address() {
        let dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        let headers = dialog.column_headers();
        assert_eq!(
            headers,
            vec!["Action", "Label", "User", "Modification Date"]
        );
    }

    #[test]
    fn test_column_headers_all_addresses() {
        let dialog = LabelHistoryDialog::with_title("All", multi_address_entries());
        let headers = dialog.column_headers();
        assert_eq!(
            headers,
            vec!["Address", "Action", "Label", "User", "Modification Date"]
        );
    }

    // -- Empty dialog --

    #[test]
    fn test_empty_dialog() {
        let dialog = LabelHistoryDialog::for_address(addr(0x1000), vec![]);
        assert!(dialog.is_empty());
        assert_eq!(dialog.entry_count(), 0);
    }

    #[test]
    fn test_non_empty_dialog() {
        let dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        assert!(!dialog.is_empty());
    }

    // -- Panel access --

    #[test]
    fn test_panel_access() {
        let dialog = LabelHistoryDialog::for_address(addr(0x4000), sample_entries());
        assert_eq!(dialog.panel().focused_address(), Some(addr(0x4000)));
    }

    // -- Debug --

    #[test]
    fn test_debug_format() {
        let dialog = LabelHistoryDialog::for_address(addr(0x1000), sample_entries());
        let debug = format!("{:?}", dialog);
        assert!(debug.contains("LabelHistoryDialog"));
        assert!(debug.contains("0x1000"));
    }
}
