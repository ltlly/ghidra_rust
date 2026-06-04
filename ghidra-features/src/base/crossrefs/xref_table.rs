//! Cross-reference table model for display in the listing and table views.
//!
//! Ported from Ghidra's `XRefFieldFactory` display logic and the table
//! model used by the "Show References" pop-up (EditReferencesModel
//! displaying xrefs at a location).
//!
//! Provides:
//! - [`XRefTableModel`] -- tabular display of cross-references
//! - [`XRefColumn`] -- column identifiers
//! - [`ReferenceChangeEvent`] -- tracks reference additions/removals

use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::symbol::{RefType, Reference, ReferenceManager, SourceType};

use super::{ThunkReference, XRefDisplayRow, XRefEntry};

// ---------------------------------------------------------------------------
// XRefColumn -- column identifiers for xref tables
// ---------------------------------------------------------------------------

/// Column identifiers for cross-reference table display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XRefColumn {
    /// The "from" address.
    Address,
    /// The reference type label (e.g. "Call", "Jump", "Read").
    RefType,
    /// Symbol/label at the from address.
    Label,
    /// Whether this is the primary reference.
    Primary,
    /// The operand index.
    Operand,
}

impl XRefColumn {
    /// All columns in order.
    pub const ALL: [XRefColumn; 5] = [
        XRefColumn::Address,
        XRefColumn::RefType,
        XRefColumn::Label,
        XRefColumn::Primary,
        XRefColumn::Operand,
    ];

    /// Returns the column header name.
    pub fn display_name(self) -> &'static str {
        match self {
            XRefColumn::Address => "Address",
            XRefColumn::RefType => "Type",
            XRefColumn::Label => "Label",
            XRefColumn::Primary => "Primary",
            XRefColumn::Operand => "Op",
        }
    }

    /// Returns the column index.
    pub fn index(self) -> usize {
        self as usize
    }
}

impl fmt::Display for XRefColumn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// XRefTableModelRow -- a single row in the xref table
// ---------------------------------------------------------------------------

/// A row in the cross-reference table model.
#[derive(Debug, Clone)]
pub struct XRefTableModelRow {
    /// The from address.
    pub address: Address,
    /// Reference type display label.
    pub ref_type_label: String,
    /// Symbol name at the from address (if known).
    pub label: Option<String>,
    /// Whether this is the primary reference from that address.
    pub is_primary: bool,
    /// The operand index.
    pub operand_index: i32,
    /// Whether this is a thunk reference.
    pub is_thunk: bool,
    /// The original XRefEntry (for retrieval).
    pub entry: XRefEntry,
}

impl XRefTableModelRow {
    /// Creates a row from a regular reference.
    pub fn from_reference(ref_: &Reference, label: Option<String>) -> Self {
        Self {
            address: *ref_.get_from_address(),
            ref_type_label: ref_.get_reference_type().display_string().to_string(),
            label,
            is_primary: ref_.is_primary(),
            operand_index: ref_.get_operand_index(),
            is_thunk: false,
            entry: XRefEntry::Reference(ref_.clone()),
        }
    }

    /// Creates a row from a thunk reference.
    pub fn from_thunk(thunk: &ThunkReference, label: Option<String>) -> Self {
        Self {
            address: *thunk.get_from_address(),
            ref_type_label: "Thunk".to_string(),
            label,
            is_primary: false,
            operand_index: -1,
            is_thunk: true,
            entry: XRefEntry::Thunk(thunk.clone()),
        }
    }

    /// Returns the value for a specific column.
    pub fn get_column_value(&self, col: XRefColumn) -> String {
        match col {
            XRefColumn::Address => format!("0x{:X}", self.address.offset),
            XRefColumn::RefType => self.ref_type_label.clone(),
            XRefColumn::Label => self.label.clone().unwrap_or_default(),
            XRefColumn::Primary => {
                if self.is_primary {
                    "*".to_string()
                } else {
                    String::new()
                }
            }
            XRefColumn::Operand => {
                if self.operand_index >= 0 {
                    self.operand_index.to_string()
                } else {
                    String::new()
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// XRefTableModel
// ---------------------------------------------------------------------------

/// Tabular model for displaying cross-references.
///
/// Supports sorting by any column and optional label resolution.
/// This is the Rust equivalent of Ghidra's xref display in the
/// "Show References" panel.
#[derive(Debug)]
pub struct XRefTableModel {
    /// The rows in the table.
    rows: Vec<XRefTableModelRow>,
    /// Whether to include thunk references.
    include_thunks: bool,
    /// Current sort column.
    sort_column: XRefColumn,
    /// Whether sort is ascending.
    sort_ascending: bool,
}

impl XRefTableModel {
    /// Creates a new empty xref table model.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            include_thunks: true,
            sort_column: XRefColumn::Address,
            sort_ascending: true,
        }
    }

    /// Populates the model with references to the given address.
    pub fn populate_from_address(
        &mut self,
        ref_mgr: &ReferenceManager,
        to_addr: Address,
        thunk_entry_points: &[Address],
    ) {
        self.rows.clear();

        // Add regular references
        for ref_ in ref_mgr.get_references_to(to_addr) {
            self.rows
                .push(XRefTableModelRow::from_reference(&ref_, None));
        }

        // Add thunk references
        if self.include_thunks {
            for &entry_point in thunk_entry_points {
                self.rows.push(XRefTableModelRow::from_thunk(
                    &ThunkReference::new(entry_point, to_addr),
                    None,
                ));
            }
        }

        self.sort();
    }

    /// Populates from a list of XRefEntry values.
    pub fn populate_from_entries(&mut self, entries: &[XRefEntry]) {
        self.rows.clear();
        for entry in entries {
            let row = match entry {
                XRefEntry::Reference(r) => XRefTableModelRow::from_reference(r, None),
                XRefEntry::Thunk(t) => XRefTableModelRow::from_thunk(t, None),
            };
            self.rows.push(row);
        }
        self.sort();
    }

    /// Returns the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Returns the number of columns.
    pub fn column_count(&self) -> usize {
        XRefColumn::ALL.len()
    }

    /// Returns the column header name.
    pub fn column_name(&self, col: usize) -> Option<&'static str> {
        XRefColumn::ALL.get(col).map(|c| c.display_name())
    }

    /// Returns the value at a specific cell.
    pub fn get_value(&self, row: usize, col: usize) -> Option<String> {
        let r = self.rows.get(row)?;
        let c = XRefColumn::ALL.get(col)?;
        Some(r.get_column_value(*c))
    }

    /// Returns a reference to the row at the given index.
    pub fn get_row(&self, row: usize) -> Option<&XRefTableModelRow> {
        self.rows.get(row)
    }

    /// Returns all rows.
    pub fn rows(&self) -> &[XRefTableModelRow] {
        &self.rows
    }

    /// Returns true if the model is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Sets whether thunk references are included.
    pub fn set_include_thunks(&mut self, include: bool) {
        self.include_thunks = include;
    }

    /// Returns the number of direct (non-thunk) references.
    pub fn direct_reference_count(&self) -> usize {
        self.rows.iter().filter(|r| !r.is_thunk).count()
    }

    /// Returns the number of thunk references.
    pub fn thunk_count(&self) -> usize {
        self.rows.iter().filter(|r| r.is_thunk).count()
    }

    /// Sorts by the given column. Toggles direction if same column.
    pub fn sort_by(&mut self, col: XRefColumn) {
        if self.sort_column == col {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = col;
            self.sort_ascending = true;
        }
        self.sort();
    }

    fn sort(&mut self) {
        let asc = self.sort_ascending;
        match self.sort_column {
            XRefColumn::Address => {
                self.rows.sort_by(|a, b| {
                    let ord = a.address.offset.cmp(&b.address.offset);
                    if asc { ord } else { ord.reverse() }
                });
            }
            XRefColumn::RefType => {
                self.rows.sort_by(|a, b| {
                    let ord = a.ref_type_label.cmp(&b.ref_type_label);
                    if asc { ord } else { ord.reverse() }
                });
            }
            XRefColumn::Label => {
                self.rows.sort_by(|a, b| {
                    let la = a.label.as_deref().unwrap_or("");
                    let lb = b.label.as_deref().unwrap_or("");
                    let ord = la.cmp(lb);
                    if asc { ord } else { ord.reverse() }
                });
            }
            XRefColumn::Primary => {
                self.rows.sort_by(|a, b| {
                    let ord = a.is_primary.cmp(&b.is_primary);
                    if asc { ord } else { ord.reverse() }
                });
            }
            XRefColumn::Operand => {
                self.rows.sort_by(|a, b| {
                    let ord = a.operand_index.cmp(&b.operand_index);
                    if asc { ord } else { ord.reverse() }
                });
            }
        }
    }
}

impl Default for XRefTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ReferenceChangeEvent -- tracks reference mutations
// ---------------------------------------------------------------------------

/// Describes a change to the reference set.
///
/// Corresponds to Ghidra's `ReferenceManagerListener` events. Plugins
/// that need to keep UI in sync with reference changes can register
/// a listener for these events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceChangeEvent {
    /// A reference was added.
    Added(Reference),
    /// A reference was removed.
    Removed(Reference),
    /// A reference was replaced (old removed, new added).
    Replaced {
        /// The old reference.
        old: Reference,
        /// The new reference.
        new: Reference,
    },
    /// All references from an address were removed.
    AllRemovedFrom(Address),
    /// All references to an address were removed.
    AllRemovedTo(Address),
    /// A reference was set as primary.
    PrimarySet(Reference),
    /// All references in the manager were cleared.
    Cleared,
}

impl ReferenceChangeEvent {
    /// Returns the address most relevant to this event.
    pub fn primary_address(&self) -> Address {
        match self {
            ReferenceChangeEvent::Added(r) => *r.get_from_address(),
            ReferenceChangeEvent::Removed(r) => *r.get_from_address(),
            ReferenceChangeEvent::Replaced { new, .. } => *new.get_from_address(),
            ReferenceChangeEvent::AllRemovedFrom(addr) => *addr,
            ReferenceChangeEvent::AllRemovedTo(addr) => *addr,
            ReferenceChangeEvent::PrimarySet(r) => *r.get_from_address(),
            ReferenceChangeEvent::Cleared => Address::NULL,
        }
    }
}

impl fmt::Display for ReferenceChangeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReferenceChangeEvent::Added(r) => {
                write!(
                    f,
                    "Added: {} -> {}",
                    r.get_from_address(),
                    r.get_to_address()
                )
            }
            ReferenceChangeEvent::Removed(r) => {
                write!(
                    f,
                    "Removed: {} -> {}",
                    r.get_from_address(),
                    r.get_to_address()
                )
            }
            ReferenceChangeEvent::Replaced { old, new } => {
                write!(
                    f,
                    "Replaced: {}->{} with {}->{}",
                    old.get_from_address(),
                    old.get_to_address(),
                    new.get_from_address(),
                    new.get_to_address()
                )
            }
            ReferenceChangeEvent::AllRemovedFrom(addr) => {
                write!(f, "All removed from {}", addr)
            }
            ReferenceChangeEvent::AllRemovedTo(addr) => {
                write!(f, "All removed to {}", addr)
            }
            ReferenceChangeEvent::PrimarySet(r) => {
                write!(f, "Primary set: {} -> {}", r.get_from_address(), r.get_to_address())
            }
            ReferenceChangeEvent::Cleared => write!(f, "Cleared"),
        }
    }
}

// ---------------------------------------------------------------------------
// ReferenceChangeTracker -- accumulates reference change events
// ---------------------------------------------------------------------------

/// Tracks reference change events for batch processing or UI refresh.
///
/// In Ghidra, this logic is distributed across `ReferenceManagerListener`
/// implementations. This struct provides a simple accumulator that can be
/// queried after a batch of operations.
#[derive(Debug, Clone, Default)]
pub struct ReferenceChangeTracker {
    /// Accumulated events.
    events: Vec<ReferenceChangeEvent>,
}

impl ReferenceChangeTracker {
    /// Creates a new empty tracker.
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
        }
    }

    /// Records a change event.
    pub fn record(&mut self, event: ReferenceChangeEvent) {
        self.events.push(event);
    }

    /// Returns all recorded events.
    pub fn events(&self) -> &[ReferenceChangeEvent] {
        &self.events
    }

    /// Returns the number of events.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Returns true if no events have been recorded.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Clears all recorded events.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Returns the set of addresses affected by recorded events.
    pub fn affected_addresses(&self) -> Vec<Address> {
        let mut addrs: Vec<Address> = self.events.iter().map(|e| e.primary_address()).collect();
        addrs.sort_by_key(|a| a.offset);
        addrs.dedup();
        addrs
    }

    /// Returns the number of additions.
    pub fn addition_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, ReferenceChangeEvent::Added(_)))
            .count()
    }

    /// Returns the number of removals.
    pub fn removal_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, ReferenceChangeEvent::Removed(_)))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::symbol::DataRefType;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_ref(from: u64, to: u64, ref_type: RefType) -> Reference {
        Reference::new(addr(from), addr(to), ref_type, 0)
    }

    // ====================================================================
    // XRefColumn
    // ====================================================================

    #[test]
    fn test_xref_column_display() {
        assert_eq!(XRefColumn::Address.display_name(), "Address");
        assert_eq!(XRefColumn::RefType.display_name(), "Type");
        assert_eq!(XRefColumn::Label.display_name(), "Label");
        assert_eq!(XRefColumn::Primary.display_name(), "Primary");
        assert_eq!(XRefColumn::Operand.display_name(), "Op");
    }

    #[test]
    fn test_xref_column_index() {
        assert_eq!(XRefColumn::Address.index(), 0);
        assert_eq!(XRefColumn::RefType.index(), 1);
        assert_eq!(XRefColumn::Label.index(), 2);
        assert_eq!(XRefColumn::Primary.index(), 3);
        assert_eq!(XRefColumn::Operand.index(), 4);
    }

    // ====================================================================
    // XRefTableModelRow
    // ====================================================================

    #[test]
    fn test_row_from_reference() {
        let r = make_ref(0x1000, 0x2000, RefType::UNCONDITIONAL_CALL);
        let row = XRefTableModelRow::from_reference(&r, Some("main".to_string()));
        assert_eq!(row.address, addr(0x1000));
        assert_eq!(row.ref_type_label, "Call");
        assert_eq!(row.label, Some("main".to_string()));
        assert!(!row.is_thunk);
    }

    #[test]
    fn test_row_from_thunk() {
        let t = ThunkReference::new(addr(0x3000), addr(0x2000));
        let row = XRefTableModelRow::from_thunk(&t, None);
        assert_eq!(row.address, addr(0x3000));
        assert_eq!(row.ref_type_label, "Thunk");
        assert!(row.is_thunk);
        assert_eq!(row.operand_index, -1);
    }

    #[test]
    fn test_row_column_values() {
        let r = make_ref(0x1000, 0x2000, RefType::READ);
        let row = XRefTableModelRow::from_reference(&r, Some("sym".to_string()));
        assert_eq!(row.get_column_value(XRefColumn::Address), "0x1000");
        assert_eq!(row.get_column_value(XRefColumn::RefType), "Read");
        assert_eq!(row.get_column_value(XRefColumn::Label), "sym");
        assert_eq!(row.get_column_value(XRefColumn::Primary), "");
    }

    #[test]
    fn test_row_primary_indicator() {
        let mut r = Reference::new(addr(0x1000), addr(0x2000), RefType::READ, 0);
        r.set_primary(true);
        let row = XRefTableModelRow::from_reference(&r, None);
        assert_eq!(row.get_column_value(XRefColumn::Primary), "*");
    }

    // ====================================================================
    // XRefTableModel
    // ====================================================================

    #[test]
    fn test_model_new_empty() {
        let model = XRefTableModel::new();
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 5);
        assert!(model.is_empty());
    }

    #[test]
    fn test_model_populate_from_address() {
        let mut ref_mgr = ReferenceManager::new();
        ref_mgr
            .add_reference(make_ref(0x1000, 0x2000, RefType::READ))
            .unwrap();
        ref_mgr
            .add_reference(make_ref(0x1100, 0x2000, RefType::UNCONDITIONAL_CALL))
            .unwrap();
        ref_mgr
            .add_reference(make_ref(0x1200, 0x3000, RefType::WRITE))
            .unwrap();

        let mut model = XRefTableModel::new();
        model.populate_from_address(&ref_mgr, addr(0x2000), &[]);
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.direct_reference_count(), 2);
        assert_eq!(model.thunk_count(), 0);
    }

    #[test]
    fn test_model_populate_with_thunks() {
        let mut ref_mgr = ReferenceManager::new();
        ref_mgr
            .add_reference(make_ref(0x1000, 0x2000, RefType::READ))
            .unwrap();

        let mut model = XRefTableModel::new();
        model.populate_from_address(&ref_mgr, addr(0x2000), &[addr(0x3000)]);
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.direct_reference_count(), 1);
        assert_eq!(model.thunk_count(), 1);
    }

    #[test]
    fn test_model_exclude_thunks() {
        let mut ref_mgr = ReferenceManager::new();
        ref_mgr
            .add_reference(make_ref(0x1000, 0x2000, RefType::READ))
            .unwrap();

        let mut model = XRefTableModel::new();
        model.set_include_thunks(false);
        model.populate_from_address(&ref_mgr, addr(0x2000), &[addr(0x3000)]);
        assert_eq!(model.row_count(), 1);
        assert_eq!(model.thunk_count(), 0);
    }

    #[test]
    fn test_model_populate_from_entries() {
        let entries = vec![
            XRefEntry::Reference(make_ref(0x1000, 0x2000, RefType::READ)),
            XRefEntry::Thunk(ThunkReference::new(addr(0x3000), addr(0x2000))),
        ];
        let mut model = XRefTableModel::new();
        model.populate_from_entries(&entries);
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_model_get_value() {
        let entries = vec![XRefEntry::Reference(make_ref(
            0x1000,
            0x2000,
            RefType::UNCONDITIONAL_CALL,
        ))];
        let mut model = XRefTableModel::new();
        model.populate_from_entries(&entries);
        assert_eq!(model.get_value(0, 0), Some("0x1000".to_string()));
        assert_eq!(model.get_value(0, 1), Some("Call".to_string()));
        assert_eq!(model.get_value(0, 2), Some("".to_string())); // no label
        assert!(model.get_value(99, 0).is_none());
        assert!(model.get_value(0, 99).is_none());
    }

    #[test]
    fn test_model_sort_by_address() {
        let entries = vec![
            XRefEntry::Reference(make_ref(0x2000, 0x1000, RefType::READ)),
            XRefEntry::Reference(make_ref(0x1000, 0x1000, RefType::READ)),
        ];
        let mut model = XRefTableModel::new();
        model.populate_from_entries(&entries);
        // Default sort ascending by address
        assert_eq!(model.get_value(0, 0), Some("0x1000".to_string()));
        assert_eq!(model.get_value(1, 0), Some("0x2000".to_string()));
    }

    #[test]
    fn test_model_sort_toggle() {
        let entries = vec![
            XRefEntry::Reference(make_ref(0x2000, 0x1000, RefType::READ)),
            XRefEntry::Reference(make_ref(0x1000, 0x1000, RefType::UNCONDITIONAL_CALL)),
        ];
        let mut model = XRefTableModel::new();
        model.populate_from_entries(&entries);
        // Toggle address sort to descending
        model.sort_by(XRefColumn::Address);
        assert_eq!(model.get_value(0, 0), Some("0x2000".to_string()));
        assert_eq!(model.get_value(1, 0), Some("0x1000".to_string()));
    }

    #[test]
    fn test_model_sort_by_ref_type() {
        let entries = vec![
            XRefEntry::Reference(make_ref(0x1000, 0x2000, RefType::READ)),
            XRefEntry::Reference(make_ref(0x2000, 0x2000, RefType::UNCONDITIONAL_CALL)),
        ];
        let mut model = XRefTableModel::new();
        model.populate_from_entries(&entries);
        model.sort_by(XRefColumn::RefType);
        assert_eq!(model.get_value(0, 1), Some("Call".to_string()));
        assert_eq!(model.get_value(1, 1), Some("Read".to_string()));
    }

    #[test]
    fn test_model_column_names() {
        let model = XRefTableModel::new();
        assert_eq!(model.column_name(0), Some("Address"));
        assert_eq!(model.column_name(1), Some("Type"));
        assert_eq!(model.column_name(99), None);
    }

    // ====================================================================
    // ReferenceChangeEvent
    // ====================================================================

    #[test]
    fn test_ref_change_event_primary_address() {
        let r = make_ref(0x1000, 0x2000, RefType::READ);
        let event = ReferenceChangeEvent::Added(r.clone());
        assert_eq!(event.primary_address(), addr(0x1000));
    }

    #[test]
    fn test_ref_change_event_all_removed_from() {
        let event = ReferenceChangeEvent::AllRemovedFrom(addr(0x1000));
        assert_eq!(event.primary_address(), addr(0x1000));
    }

    #[test]
    fn test_ref_change_event_cleared() {
        let event = ReferenceChangeEvent::Cleared;
        assert_eq!(event.primary_address(), Address::NULL);
    }

    #[test]
    fn test_ref_change_event_display() {
        let r = make_ref(0x1000, 0x2000, RefType::READ);
        let event = ReferenceChangeEvent::Added(r);
        let display = format!("{}", event);
        assert!(display.contains("Added"));
        // Address Display uses "{:08x}" format: 0x1000 -> "00001000"
        assert!(display.contains("00001000"));
    }

    // ====================================================================
    // ReferenceChangeTracker
    // ====================================================================

    #[test]
    fn test_tracker_new_empty() {
        let tracker = ReferenceChangeTracker::new();
        assert!(tracker.is_empty());
        assert_eq!(tracker.event_count(), 0);
    }

    #[test]
    fn test_tracker_record_events() {
        let mut tracker = ReferenceChangeTracker::new();
        let r1 = make_ref(0x1000, 0x2000, RefType::READ);
        let r2 = make_ref(0x1100, 0x2000, RefType::WRITE);
        tracker.record(ReferenceChangeEvent::Added(r1));
        tracker.record(ReferenceChangeEvent::Removed(r2));
        assert_eq!(tracker.event_count(), 2);
        assert_eq!(tracker.addition_count(), 1);
        assert_eq!(tracker.removal_count(), 1);
    }

    #[test]
    fn test_tracker_affected_addresses() {
        let mut tracker = ReferenceChangeTracker::new();
        let r1 = make_ref(0x1000, 0x2000, RefType::READ);
        let r2 = make_ref(0x1000, 0x3000, RefType::WRITE);
        let r3 = make_ref(0x2000, 0x2000, RefType::READ);
        tracker.record(ReferenceChangeEvent::Added(r1));
        tracker.record(ReferenceChangeEvent::Added(r2));
        tracker.record(ReferenceChangeEvent::Added(r3));
        let addrs = tracker.affected_addresses();
        assert_eq!(addrs.len(), 2); // 0x1000, 0x2000
    }

    #[test]
    fn test_tracker_clear() {
        let mut tracker = ReferenceChangeTracker::new();
        let r = make_ref(0x1000, 0x2000, RefType::READ);
        tracker.record(ReferenceChangeEvent::Added(r));
        assert_eq!(tracker.event_count(), 1);
        tracker.clear();
        assert!(tracker.is_empty());
    }
}
