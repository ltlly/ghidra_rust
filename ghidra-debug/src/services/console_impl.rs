//! Console, watch, listing, and auto-mapping service implementations.
//!
//! Ported from Ghidra's debugger service plugin implementations.

use std::collections::VecDeque;

use crate::model::Lifespan;
use crate::services::{
    AutoMappingService, ConsoleService, ListingService, MappingProposal, WatchService,
};

// ─── Console Service ─────────────────────────────────────────────────────

/// Severity of a console message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSeverity {
    /// Normal informational message.
    Info,
    /// Warning message.
    Warning,
    /// Error message.
    Error,
}

/// A console message with severity and timestamp.
#[derive(Debug, Clone)]
pub struct ConsoleMessage {
    /// The message text.
    pub message: String,
    /// The severity.
    pub severity: MessageSeverity,
    /// Monotonic sequence number.
    pub sequence: u64,
}

/// Default console service implementation.
#[derive(Debug)]
pub struct DefaultConsoleService {
    messages: VecDeque<ConsoleMessage>,
    max_messages: usize,
    next_seq: u64,
}

impl DefaultConsoleService {
    /// Create a new console service with the given message capacity.
    pub fn new(max_messages: usize) -> Self {
        Self {
            messages: VecDeque::new(),
            max_messages,
            next_seq: 0,
        }
    }

    /// Get all messages.
    pub fn messages(&self) -> &VecDeque<ConsoleMessage> {
        &self.messages
    }

    /// Get the last N messages.
    pub fn recent_messages(&self, n: usize) -> Vec<&ConsoleMessage> {
        self.messages.iter().rev().take(n).collect()
    }

    /// Clear all messages.
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// Get the number of messages.
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }
}

impl Default for DefaultConsoleService {
    fn default() -> Self {
        Self::new(10000)
    }
}

impl ConsoleService for DefaultConsoleService {
    fn print(&mut self, message: &str) {
        let msg = ConsoleMessage {
            message: message.to_string(),
            severity: MessageSeverity::Info,
            sequence: self.next_seq,
        };
        self.next_seq += 1;
        if self.messages.len() >= self.max_messages {
            self.messages.pop_front();
        }
        self.messages.push_back(msg);
    }

    fn print_error(&mut self, message: &str) {
        let msg = ConsoleMessage {
            message: message.to_string(),
            severity: MessageSeverity::Error,
            sequence: self.next_seq,
        };
        self.next_seq += 1;
        if self.messages.len() >= self.max_messages {
            self.messages.pop_front();
        }
        self.messages.push_back(msg);
    }
}

// ─── Watch Service ───────────────────────────────────────────────────────

/// Default watch service implementation.
#[derive(Debug, Default)]
pub struct DefaultWatchService {
    watches: Vec<String>,
}

impl DefaultWatchService {
    /// Create a new watch service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a specific watch expression.
    pub fn get(&self, index: usize) -> Option<&str> {
        self.watches.get(index).map(|s| s.as_str())
    }

    /// Clear all watches.
    pub fn clear(&mut self) {
        self.watches.clear();
    }
}

impl WatchService for DefaultWatchService {
    fn add_watch(&mut self, expression: String) {
        self.watches.push(expression);
    }

    fn remove_watch(&mut self, index: usize) {
        if index < self.watches.len() {
            self.watches.remove(index);
        }
    }

    fn watches(&self) -> &[String] {
        &self.watches
    }
}

// ─── Listing Service ─────────────────────────────────────────────────────

/// Default listing service implementation.
#[derive(Debug, Default)]
pub struct DefaultListingService {
    current_address: Option<u64>,
    history: Vec<u64>,
    history_index: usize,
}

impl DefaultListingService {
    /// Create a new listing service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Go back in history.
    pub fn go_back(&mut self) -> Option<u64> {
        if self.history_index > 0 {
            self.history_index -= 1;
            self.current_address = Some(self.history[self.history_index]);
            self.current_address
        } else {
            None
        }
    }

    /// Go forward in history.
    pub fn go_forward(&mut self) -> Option<u64> {
        if self.history_index < self.history.len().saturating_sub(1) {
            self.history_index += 1;
            self.current_address = Some(self.history[self.history_index]);
            self.current_address
        } else {
            None
        }
    }

    /// Get the navigation history.
    pub fn history(&self) -> &[u64] {
        &self.history
    }
}

impl ListingService for DefaultListingService {
    fn go_to(&mut self, offset: u64) {
        // Trim history forward of current position
        self.history.truncate(self.history_index + 1);
        self.history.push(offset);
        self.history_index = self.history.len() - 1;
        self.current_address = Some(offset);
    }

    fn current_address(&self) -> Option<u64> {
        self.current_address
    }
}

// ─── Auto-Mapping Service ───────────────────────────────────────────────

/// Default auto-mapping service implementation.
///
/// Proposes and applies static mappings between program address ranges
/// and trace address ranges based on module/section matching.
#[derive(Debug, Default)]
pub struct DefaultAutoMappingService {
    /// Stored proposals by (program_url, trace_key).
    proposals: Vec<(String, i64, Vec<MappingProposal>)>,
    /// Applied mappings.
    applied: Vec<AppliedMapping>,
}

/// A record of an applied mapping.
#[derive(Debug, Clone)]
pub struct AppliedMapping {
    /// Program URL.
    pub program_url: String,
    /// Trace key.
    pub trace_key: i64,
    /// The mapping proposal that was applied.
    pub proposal: MappingProposal,
    /// The lifespan during which this mapping is active.
    pub lifespan: Lifespan,
}

impl DefaultAutoMappingService {
    /// Create a new auto-mapping service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the stored proposals.
    pub fn proposals(&self) -> &[(String, i64, Vec<MappingProposal>)] {
        &self.proposals
    }

    /// Get the applied mappings.
    pub fn applied(&self) -> &[AppliedMapping] {
        &self.applied
    }

    /// Manually add a proposal.
    pub fn add_proposal(&mut self, program_url: &str, trace_key: i64, proposal: MappingProposal) {
        self.proposals
            .push((program_url.to_string(), trace_key, vec![proposal]));
    }
}

impl AutoMappingService for DefaultAutoMappingService {
    fn auto_map(
        &mut self,
        program_url: &str,
        trace_key: i64,
        lifespan: Lifespan,
    ) -> Result<(), String> {
        // Find proposals for this program/trace pair
        let proposals: Vec<MappingProposal> = self
            .proposals
            .iter()
            .filter(|(url, key, _)| url == program_url && *key == trace_key)
            .flat_map(|(_, _, p)| p.clone())
            .collect();

        if proposals.is_empty() {
            // Generate simple identity mapping
            let proposal = MappingProposal {
                program_min: 0,
                program_max: u64::MAX,
                trace_min: 0,
                trace_max: u64::MAX,
                confidence: 1.0,
            };
            self.applied.push(AppliedMapping {
                program_url: program_url.to_string(),
                trace_key,
                proposal,
                lifespan,
            });
        } else {
            for proposal in proposals {
                self.applied.push(AppliedMapping {
                    program_url: program_url.to_string(),
                    trace_key,
                    proposal,
                    lifespan: lifespan.clone(),
                });
            }
        }
        Ok(())
    }

    fn propose_mapping(
        &self,
        program_url: &str,
        trace_key: i64,
    ) -> Vec<MappingProposal> {
        self.proposals
            .iter()
            .filter(|(url, key, _)| url == program_url && *key == trace_key)
            .flat_map(|(_, _, p)| p.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_service() {
        let mut svc = DefaultConsoleService::new(100);
        svc.print("Hello");
        svc.print_error("Error!");
        assert_eq!(svc.message_count(), 2);
        assert_eq!(svc.messages()[0].severity, MessageSeverity::Info);
        assert_eq!(svc.messages()[1].severity, MessageSeverity::Error);
    }

    #[test]
    fn test_console_service_capacity() {
        let mut svc = DefaultConsoleService::new(3);
        svc.print("a");
        svc.print("b");
        svc.print("c");
        svc.print("d");
        assert_eq!(svc.message_count(), 3);
        assert_eq!(svc.messages()[0].message, "b");
    }

    #[test]
    fn test_watch_service() {
        let mut svc = DefaultWatchService::new();
        svc.add_watch("RAX".into());
        svc.add_watch("RBX".into());
        assert_eq!(svc.watches().len(), 2);
        assert_eq!(svc.get(0), Some("RAX"));
        svc.remove_watch(0);
        assert_eq!(svc.watches().len(), 1);
        assert_eq!(svc.get(0), Some("RBX"));
    }

    #[test]
    fn test_listing_service() {
        let mut svc = DefaultListingService::new();
        svc.go_to(0x400000);
        assert_eq!(svc.current_address(), Some(0x400000));
        svc.go_to(0x400010);
        assert_eq!(svc.current_address(), Some(0x400010));
        svc.go_back();
        assert_eq!(svc.current_address(), Some(0x400000));
        svc.go_forward();
        assert_eq!(svc.current_address(), Some(0x400010));
    }

    #[test]
    fn test_auto_mapping_service() {
        let mut svc = DefaultAutoMappingService::new();
        svc.add_proposal(
            "/path/to/prog",
            1,
            MappingProposal {
                program_min: 0,
                program_max: 0x1000,
                trace_min: 0x400000,
                trace_max: 0x401000,
                confidence: 0.95,
            },
        );

        let proposals = svc.propose_mapping("/path/to/prog", 1);
        assert_eq!(proposals.len(), 1);

        svc.auto_map("/path/to/prog", 1, Lifespan::now_on(0))
            .unwrap();
        assert_eq!(svc.applied().len(), 1);
    }
}
