//! TransactionMonitor -- monitors the current transaction state.
//!
//! Ported from `ghidra.app.plugin.core.progmgr.TransactionMonitor`.
//!
//! In the Java version this is a Swing component that displays a "busy"
//! icon when a transaction is open.  In the Rust port we track the
//! transaction state only (no UI).

use std::fmt;

/// Information about an open transaction.
#[derive(Debug, Clone)]
pub struct TransactionInfo {
    /// Description of the transaction.
    pub description: String,
    /// ID of the transaction.
    pub id: i32,
    /// Nested sub-transactions.
    pub sub_transactions: Vec<String>,
}

impl TransactionInfo {
    /// Create a new TransactionInfo.
    pub fn new(id: i32, description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            id,
            sub_transactions: Vec::new(),
        }
    }
}

impl fmt::Display for TransactionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Transaction({}: {})", self.id, self.description)
    }
}

/// Monitors the transaction state of the active program.
///
/// Provides information about whether a transaction is currently open
/// and what it is doing.
#[derive(Debug, Default)]
pub struct TransactionMonitor {
    /// The currently open transaction, if any.
    current_transaction: Option<TransactionInfo>,
    /// The program name being monitored.
    program_name: Option<String>,
}

impl TransactionMonitor {
    /// Create a new TransactionMonitor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the program being monitored.
    pub fn set_program(&mut self, program_name: Option<String>) {
        self.program_name = program_name;
        self.current_transaction = None;
    }

    /// Returns the name of the program being monitored.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Called when a transaction starts.
    pub fn transaction_started(&mut self, tx: TransactionInfo) {
        self.current_transaction = Some(tx);
    }

    /// Called when a transaction ends.
    pub fn transaction_ended(&mut self) {
        self.current_transaction = None;
    }

    /// Returns `true` if a transaction is currently open.
    pub fn is_busy(&self) -> bool {
        self.current_transaction.is_some()
    }

    /// Returns the current transaction info, if any.
    pub fn current_transaction(&self) -> Option<&TransactionInfo> {
        self.current_transaction.as_ref()
    }

    /// Returns the tooltip text (lists open sub-transactions).
    pub fn tooltip_text(&self) -> Option<String> {
        self.current_transaction.as_ref().map(|tx| {
            if tx.sub_transactions.is_empty() {
                tx.description.clone()
            } else {
                tx.sub_transactions.join("\n")
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let mon = TransactionMonitor::new();
        assert!(!mon.is_busy());
        assert!(mon.current_transaction().is_none());
        assert!(mon.tooltip_text().is_none());
    }

    #[test]
    fn test_transaction_lifecycle() {
        let mut mon = TransactionMonitor::new();
        mon.set_program(Some("test.exe".into()));
        assert_eq!(mon.program_name(), Some("test.exe"));

        let tx = TransactionInfo::new(1, "Edit Labels");
        mon.transaction_started(tx);
        assert!(mon.is_busy());
        assert!(mon.current_transaction().is_some());

        mon.transaction_ended();
        assert!(!mon.is_busy());
    }

    #[test]
    fn test_tooltip_with_sub_transactions() {
        let mut mon = TransactionMonitor::new();
        let mut tx = TransactionInfo::new(1, "Main");
        tx.sub_transactions.push("Sub1".into());
        tx.sub_transactions.push("Sub2".into());
        mon.transaction_started(tx);

        let tooltip = mon.tooltip_text().unwrap();
        assert!(tooltip.contains("Sub1"));
        assert!(tooltip.contains("Sub2"));
    }

    #[test]
    fn test_set_program_resets_transaction() {
        let mut mon = TransactionMonitor::new();
        mon.transaction_started(TransactionInfo::new(1, "tx"));
        assert!(mon.is_busy());

        mon.set_program(Some("other.exe".into()));
        assert!(!mon.is_busy());
    }
}
