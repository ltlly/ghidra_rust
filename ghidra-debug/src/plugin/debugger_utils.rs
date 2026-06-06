//! Debugger utility types and helpers.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.utils` package.
//! Provides transaction coalescing, background command utilities,
//! program URL handling, and miscellaneous helpers.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use thiserror::Error;

/// Errors that can occur during debugger utility operations.
#[derive(Debug, Error)]
pub enum DebuggerUtilError {
    /// Operation was cancelled.
    #[error("Operation cancelled: {0}")]
    Cancelled(String),
    /// Background task execution error.
    #[error("Background task error: {0}")]
    BackgroundTask(String),
    /// Invalid program URL.
    #[error("Invalid program URL: {0}")]
    InvalidUrl(String),
    /// Transaction error.
    #[error("Transaction error: {0}")]
    Transaction(String),
}

// ---------------------------------------------------------------------------
// TransactionCoalescer
// ---------------------------------------------------------------------------

/// Trait for coalescing multiple small transactions into larger ones.
///
/// Ported from Ghidra's `TransactionCoalescer` interface.
/// Coalescing prevents excessive undo history entries from many small
/// database modifications.
pub trait TransactionCoalescer {
    /// Start a coalesced transaction with the given description.
    fn start(&self, description: &str) -> CoalescedTransaction;
}

/// A coalesced transaction handle that closes on drop.
#[derive(Debug)]
pub struct CoalescedTransaction {
    description: String,
    active: Arc<AtomicBool>,
    start_time: Instant,
}

impl CoalescedTransaction {
    /// Create a new coalesced transaction.
    pub fn new(description: &str, active: Arc<AtomicBool>) -> Self {
        active.store(true, Ordering::SeqCst);
        Self {
            description: description.to_string(),
            active,
            start_time: Instant::now(),
        }
    }

    /// Get the transaction description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the elapsed time since the transaction started.
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Check if the transaction is still active.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }
}

impl Drop for CoalescedTransaction {
    fn drop(&mut self) {
        self.active.store(false, Ordering::SeqCst);
    }
}

/// Default implementation of `TransactionCoalescer` with a minimum hold time.
#[derive(Debug, Clone)]
pub struct DefaultTransactionCoalescer {
    active: Arc<AtomicBool>,
    min_hold_ms: u64,
}

impl DefaultTransactionCoalescer {
    /// Create a new coalescer with the given minimum hold time in milliseconds.
    pub fn new(min_hold_ms: u64) -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            min_hold_ms,
        }
    }

    /// Get the minimum hold time.
    pub fn min_hold_ms(&self) -> u64 {
        self.min_hold_ms
    }
}

impl Default for DefaultTransactionCoalescer {
    fn default() -> Self {
        Self::new(100)
    }
}

impl TransactionCoalescer for DefaultTransactionCoalescer {
    fn start(&self, description: &str) -> CoalescedTransaction {
        CoalescedTransaction::new(description, self.active.clone())
    }
}

// ---------------------------------------------------------------------------
// BackgroundUtils
// ---------------------------------------------------------------------------

/// Status of a background command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackgroundCommandStatus {
    /// Command has not started.
    Pending,
    /// Command is running.
    Running,
    /// Command completed successfully.
    Completed,
    /// Command was cancelled.
    Cancelled,
    /// Command failed with an error message.
    Failed(String),
}

/// An async background command that runs against a domain object.
///
/// Ported from Ghidra's `BackgroundUtils.AsyncBackgroundCommand`.
#[derive(Debug)]
pub struct AsyncBackgroundCommand {
    /// Name of the command.
    pub name: String,
    /// Whether the command reports progress.
    pub has_progress: bool,
    /// Whether the command can be cancelled.
    pub can_cancel: bool,
    /// Whether the command is modal.
    pub is_modal: bool,
    status: Arc<Mutex<BackgroundCommandStatus>>,
    cancelled: Arc<AtomicBool>,
}

impl AsyncBackgroundCommand {
    /// Create a new async background command.
    pub fn new(
        name: impl Into<String>,
        has_progress: bool,
        can_cancel: bool,
        is_modal: bool,
    ) -> Self {
        Self {
            name: name.into(),
            has_progress,
            can_cancel,
            is_modal,
            status: Arc::new(Mutex::new(BackgroundCommandStatus::Pending)),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Request cancellation of this command.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Ok(mut status) = self.status.lock() {
            *status = BackgroundCommandStatus::Cancelled;
        }
    }

    /// Check if cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Get the current status.
    pub fn status(&self) -> BackgroundCommandStatus {
        self.status.lock().unwrap().clone()
    }

    /// Set the status.
    pub fn set_status(&self, status: BackgroundCommandStatus) {
        if let Ok(mut s) = self.status.lock() {
            *s = status;
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramURLUtils
// ---------------------------------------------------------------------------

/// Utilities for handling program URLs in the debugger.
///
/// Ported from Ghidra's `ProgramURLUtils`.
pub struct ProgramURLUtils;

impl ProgramURLUtils {
    /// Parse a Ghidra program URL into its components.
    ///
    /// A program URL has the form: `ghidra://host/path/to/program?query`
    pub fn parse_url(url: &str) -> Result<ProgramUrlParts, DebuggerUtilError> {
        if !url.starts_with("ghidra://") {
            return Err(DebuggerUtilError::InvalidUrl(format!(
                "Not a Ghidra URL: {}",
                url
            )));
        }

        let rest = &url[9..]; // skip "ghidra://"
        let (host, path) = match rest.find('/') {
            Some(pos) => (&rest[..pos], &rest[pos..]),
            None => (rest, "/"),
        };

        let (path_part, query) = match path.find('?') {
            Some(pos) => (&path[..pos], Some(&path[pos + 1..])),
            None => (path, None),
        };

        Ok(ProgramUrlParts {
            host: host.to_string(),
            path: path_part.to_string(),
            query: query.map(|s| s.to_string()),
        })
    }

    /// Construct a Ghidra program URL from components.
    pub fn build_url(host: &str, path: &str) -> String {
        format!("ghidra://{}{}", host, path)
    }

    /// Check if a URL is a valid Ghidra program URL.
    pub fn is_valid_url(url: &str) -> bool {
        url.starts_with("ghidra://") && url.len() > 9
    }
}

/// Parsed components of a Ghidra program URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramUrlParts {
    /// The host portion of the URL.
    pub host: String,
    /// The path portion.
    pub path: String,
    /// Optional query string.
    pub query: Option<String>,
}

// ---------------------------------------------------------------------------
// ManagedDomainObject
// ---------------------------------------------------------------------------

/// Trait representing a managed domain object in the debugger.
///
/// Ported from Ghidra's `ManagedDomainObject`.
pub trait ManagedDomainObject {
    /// Get the domain object ID.
    fn domain_object_id(&self) -> u64;

    /// Get the name of this domain object.
    fn name(&self) -> &str;

    /// Whether this object is ephemeral (not saved to disk).
    fn is_ephemeral(&self) -> bool;

    /// Whether this object has been modified.
    fn is_changed(&self) -> bool;

    /// Release resources held by this object.
    fn release(&mut self);
}

// ---------------------------------------------------------------------------
// ProgramLocationUtils
// ---------------------------------------------------------------------------

/// Utilities for program location handling in the debugger.
pub struct ProgramLocationUtils;

impl ProgramLocationUtils {
    /// Calculate the effective address from a base address and offset.
    pub fn effective_address(base: u64, offset: i64) -> u64 {
        base.wrapping_add(offset as u64)
    }

    /// Check if an address is within a given range.
    pub fn address_in_range(addr: u64, min: u64, max: u64) -> bool {
        addr >= min && addr <= max
    }

    /// Format an address as a hex string.
    pub fn format_address(addr: u64) -> String {
        format!("0x{:016x}", addr)
    }

    /// Parse a hex address string.
    pub fn parse_address(s: &str) -> Option<u64> {
        let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        u64::from_str_radix(s, 16).ok()
    }
}

// ---------------------------------------------------------------------------
// MiscellaneousUtils
// ---------------------------------------------------------------------------

/// Miscellaneous utility functions for the debugger.
pub struct MiscellaneousUtils;

impl MiscellaneousUtils {
    /// Truncate a string to the given maximum length, appending "..." if truncated.
    pub fn truncate_string(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len.saturating_sub(3)])
        }
    }

    /// Create an indented string representation of a nested structure.
    pub fn indent(text: &str, depth: usize) -> String {
        let prefix = "  ".repeat(depth);
        text.lines()
            .map(|line| format!("{}{}", prefix, line))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Null-safe string comparison.
    pub fn strings_equal(a: Option<&str>, b: Option<&str>) -> bool {
        match (a, b) {
            (Some(a), Some(b)) => a == b,
            (None, None) => true,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// AbstractMappedMemoryBytesVisitor
// ---------------------------------------------------------------------------

/// Visitor pattern for iterating over mapped memory bytes.
///
/// Ported from Ghidra's `AbstractMappedMemoryBytesVisitor`.
pub trait MappedMemoryBytesVisitor {
    /// Called for a contiguous region of known bytes.
    fn visit_known_bytes(&mut self, address: u64, bytes: &[u8]);

    /// Called for a region of unknown/uninitialized bytes.
    fn visit_unknown_bytes(&mut self, address: u64, length: u64);

    /// Called for a region of error bytes (e.g., read failure).
    fn visit_error_bytes(&mut self, address: u64, length: u64, error: &str);
}

/// Default implementation of `MappedMemoryBytesVisitor` that collects
/// all regions into a vector.
#[derive(Debug, Default)]
pub struct CollectingMemoryVisitor {
    /// Collected known byte regions.
    pub known_regions: Vec<(u64, Vec<u8>)>,
    /// Collected unknown byte regions.
    pub unknown_regions: Vec<(u64, u64)>,
    /// Collected error regions.
    pub error_regions: Vec<(u64, u64, String)>,
}

impl CollectingMemoryVisitor {
    /// Create a new collecting visitor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the total number of known bytes collected.
    pub fn total_known_bytes(&self) -> usize {
        self.known_regions.iter().map(|(_, b)| b.len()).sum()
    }
}

impl MappedMemoryBytesVisitor for CollectingMemoryVisitor {
    fn visit_known_bytes(&mut self, address: u64, bytes: &[u8]) {
        self.known_regions.push((address, bytes.to_vec()));
    }

    fn visit_unknown_bytes(&mut self, address: u64, length: u64) {
        self.unknown_regions.push((address, length));
    }

    fn visit_error_bytes(&mut self, address: u64, length: u64, error: &str) {
        self.error_regions.push((address, length, error.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_transaction_coalescer() {
        let coalescer = DefaultTransactionCoalescer::default();
        assert_eq!(coalescer.min_hold_ms(), 100);

        let tx = coalescer.start("test");
        assert!(tx.is_active());
        assert_eq!(tx.description(), "test");
        drop(tx);
    }

    #[test]
    fn test_coalesced_transaction_drop() {
        let active = Arc::new(AtomicBool::new(false));
        {
            let tx = CoalescedTransaction::new("test", active.clone());
            assert!(tx.is_active());
        }
        assert!(!active.load(Ordering::SeqCst));
    }

    #[test]
    fn test_async_background_command() {
        let cmd = AsyncBackgroundCommand::new("Test Command", true, true, false);
        assert_eq!(cmd.name, "Test Command");
        assert!(cmd.has_progress);
        assert!(cmd.can_cancel);
        assert!(!cmd.is_modal);
        assert!(!cmd.is_cancelled());

        cmd.cancel();
        assert!(cmd.is_cancelled());
        assert_eq!(cmd.status(), BackgroundCommandStatus::Cancelled);
    }

    #[test]
    fn test_program_url_parse() {
        let parts = ProgramURLUtils::parse_url("ghidra://localhost/path/to/prog").unwrap();
        assert_eq!(parts.host, "localhost");
        assert_eq!(parts.path, "/path/to/prog");
        assert!(parts.query.is_none());
    }

    #[test]
    fn test_program_url_with_query() {
        let parts = ProgramURLUtils::parse_url("ghidra://host/prog?key=value").unwrap();
        assert_eq!(parts.host, "host");
        assert_eq!(parts.path, "/prog");
        assert_eq!(parts.query.as_deref(), Some("key=value"));
    }

    #[test]
    fn test_program_url_invalid() {
        assert!(ProgramURLUtils::parse_url("http://example.com").is_err());
    }

    #[test]
    fn test_program_url_build() {
        let url = ProgramURLUtils::build_url("localhost", "/my/program");
        assert_eq!(url, "ghidra://localhost/my/program");
    }

    #[test]
    fn test_program_url_valid() {
        assert!(ProgramURLUtils::is_valid_url("ghidra://host/path"));
        assert!(!ProgramURLUtils::is_valid_url("ghidra://"));
        assert!(!ProgramURLUtils::is_valid_url("http://x"));
    }

    #[test]
    fn test_program_location_utils() {
        assert_eq!(ProgramLocationUtils::effective_address(0x1000, 0x10), 0x1010);
        assert!(ProgramLocationUtils::address_in_range(0x1005, 0x1000, 0x2000));
        assert!(!ProgramLocationUtils::address_in_range(0x3000, 0x1000, 0x2000));
        assert_eq!(ProgramLocationUtils::format_address(0x400000), "0x0000000000400000");
        assert_eq!(ProgramLocationUtils::parse_address("0x400000"), Some(0x400000));
        assert_eq!(ProgramLocationUtils::parse_address("400000"), Some(0x400000));
        assert_eq!(ProgramLocationUtils::parse_address("invalid"), None);
    }

    #[test]
    fn test_miscellaneous_utils() {
        assert_eq!(MiscellaneousUtils::truncate_string("hello", 10), "hello");
        assert_eq!(MiscellaneousUtils::truncate_string("hello world!", 8), "hello...");
        assert!(MiscellaneousUtils::strings_equal(Some("a"), Some("a")));
        assert!(MiscellaneousUtils::strings_equal(None, None));
        assert!(!MiscellaneousUtils::strings_equal(Some("a"), None));
    }

    #[test]
    fn test_indent() {
        let result = MiscellaneousUtils::indent("line1\nline2", 2);
        assert_eq!(result, "    line1\n    line2");
    }

    #[test]
    fn test_collecting_visitor() {
        let mut visitor = CollectingMemoryVisitor::new();
        visitor.visit_known_bytes(0x1000, &[0x90, 0xcc]);
        visitor.visit_unknown_bytes(0x2000, 0x100);
        visitor.visit_error_bytes(0x3000, 0x10, "read failed");

        assert_eq!(visitor.known_regions.len(), 1);
        assert_eq!(visitor.unknown_regions.len(), 1);
        assert_eq!(visitor.error_regions.len(), 1);
        assert_eq!(visitor.total_known_bytes(), 2);
    }
}
