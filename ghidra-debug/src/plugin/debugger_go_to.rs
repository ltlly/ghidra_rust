//! DebuggerGoTo - GoTo dialog model for address navigation.
//!
//! Ported from Ghidra's `DebuggerGoToDialog` and `DebuggerGoToTrait`
//! in `ghidra.app.plugin.core.debug.gui.action`.

use serde::{Deserialize, Serialize};

/// The type of address being navigated to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressKind {
    /// A raw address (hex or decimal).
    Address,
    /// A symbol name.
    Symbol,
    /// A label.
    Label,
    /// A register name.
    Register,
    /// A function entry.
    Function,
    /// A stack offset.
    StackOffset,
}

impl AddressKind {
    /// Whether this kind is navigable in the listing.
    pub fn is_navigable(&self) -> bool {
        matches!(
            self,
            Self::Address | Self::Symbol | Self::Label | Self::Function
        )
    }
}

/// A resolved address from a GoTo query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoToTarget {
    /// The resolved address.
    pub address: u64,
    /// The original query string.
    pub query: String,
    /// The type of address.
    pub kind: AddressKind,
    /// A display label for this target.
    pub label: String,
    /// Whether the target is in the current trace.
    pub in_current_trace: bool,
    /// The snap (time) at which this address is valid, if applicable.
    pub snap: Option<i64>,
}

impl GoToTarget {
    /// Create a new GoTo target.
    pub fn new(address: u64, query: impl Into<String>, kind: AddressKind) -> Self {
        let query = query.into();
        let label = match kind {
            AddressKind::Address => format!("0x{:x}", address),
            _ => query.clone(),
        };
        Self {
            address,
            query,
            kind,
            label,
            in_current_trace: true,
            snap: None,
        }
    }

    /// Set the display label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Set whether the target is in the current trace.
    pub fn with_in_current_trace(mut self, in_current: bool) -> Self {
        self.in_current_trace = in_current;
        self
    }

    /// Set the snap for this target.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.snap = Some(snap);
        self
    }
}

/// The result of a GoTo query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoToResult {
    /// The matched targets, sorted by relevance.
    pub targets: Vec<GoToTarget>,
    /// The original query.
    pub query: String,
    /// Whether an exact match was found.
    pub exact_match: bool,
}

impl GoToResult {
    /// Create a new result.
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            targets: Vec::new(),
            query: query.into(),
            exact_match: false,
        }
    }

    /// Add a target.
    pub fn add_target(&mut self, target: GoToTarget) {
        if self.targets.is_empty() {
            self.exact_match = target.query == self.query;
        }
        self.targets.push(target);
    }

    /// Get the best (first) target, if any.
    pub fn best_target(&self) -> Option<&GoToTarget> {
        self.targets.first()
    }

    /// Whether the query returned any results.
    pub fn has_results(&self) -> bool {
        !self.targets.is_empty()
    }

    /// Number of targets.
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    /// Whether there are no targets.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

/// Selection generation and translation utilities.
///
/// Ported from Ghidra's `SelectionGenerator` and `SelectionTranslator`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SelectionRange {
    /// Start address of the selection.
    pub start: u64,
    /// End address (inclusive) of the selection.
    pub end: u64,
}

impl SelectionRange {
    /// Create a new selection range.
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Create a single-address selection.
    pub fn single(address: u64) -> Self {
        Self {
            start: address,
            end: address,
        }
    }

    /// The size of the selection in bytes.
    pub fn size(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Check if an address is within this selection.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address <= self.end
    }

    /// Translate this selection from trace address space to program address space.
    pub fn translate_trace_to_program(&self, trace_base: u64, prog_base: u64) -> Option<Self> {
        if self.start < trace_base {
            return None;
        }
        let offset = self.start - trace_base;
        let translated_start = prog_base + offset;
        let translated_end = translated_start + (self.end - self.start);
        Some(Self::new(translated_start, translated_end))
    }

    /// Translate from program address space to trace address space.
    pub fn translate_program_to_trace(&self, prog_base: u64, trace_base: u64) -> Option<Self> {
        if self.start < prog_base {
            return None;
        }
        let offset = self.start - prog_base;
        let translated_start = trace_base + offset;
        let translated_end = translated_start + (self.end - self.start);
        Some(Self::new(translated_start, translated_end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_kind() {
        assert!(AddressKind::Address.is_navigable());
        assert!(AddressKind::Symbol.is_navigable());
        assert!(AddressKind::Function.is_navigable());
        assert!(!AddressKind::Register.is_navigable());
        assert!(!AddressKind::StackOffset.is_navigable());
    }

    #[test]
    fn test_go_to_target() {
        let target = GoToTarget::new(0x400000, "main", AddressKind::Function)
            .with_label("main()")
            .with_snap(5);
        assert_eq!(target.address, 0x400000);
        assert_eq!(target.label, "main()");
        assert_eq!(target.snap, Some(5));
    }

    #[test]
    fn test_go_to_result() {
        let mut result = GoToResult::new("main");
        result.add_target(GoToTarget::new(0x400000, "main", AddressKind::Function));
        result.add_target(GoToTarget::new(0x400100, "main_helper", AddressKind::Function));

        assert!(result.has_results());
        assert_eq!(result.len(), 2);
        assert!(result.exact_match);
        assert_eq!(result.best_target().unwrap().address, 0x400000);
    }

    #[test]
    fn test_go_to_result_empty() {
        let result = GoToResult::new("nonexistent");
        assert!(result.is_empty());
        assert!(!result.exact_match);
    }

    #[test]
    fn test_selection_range() {
        let sel = SelectionRange::new(0x1000, 0x100F);
        assert_eq!(sel.size(), 16);
        assert!(sel.contains(0x1005));
        assert!(!sel.contains(0x2000));
    }

    #[test]
    fn test_selection_single() {
        let sel = SelectionRange::single(0x400000);
        assert_eq!(sel.size(), 1);
        assert!(sel.contains(0x400000));
    }

    #[test]
    fn test_selection_translate() {
        let sel = SelectionRange::new(0x400000, 0x400FFF);
        let translated = sel.translate_trace_to_program(0x400000, 0x10000000);
        assert!(translated.is_some());
        let t = translated.unwrap();
        assert_eq!(t.start, 0x10000000);
        assert_eq!(t.end, 0x10000FFF);
    }

    #[test]
    fn test_selection_translate_reverse() {
        let sel = SelectionRange::new(0x10000000, 0x10000FFF);
        let translated = sel.translate_program_to_trace(0x10000000, 0x400000);
        assert!(translated.is_some());
        let t = translated.unwrap();
        assert_eq!(t.start, 0x400000);
        assert_eq!(t.end, 0x400FFF);
    }

    #[test]
    fn test_selection_translate_invalid() {
        let sel = SelectionRange::new(0x100, 0x1FF);
        assert!(sel.translate_trace_to_program(0x200, 0x10000000).is_none());
    }

    #[test]
    fn test_go_to_target_default_label() {
        let target = GoToTarget::new(0xDEAD, "0xDEAD", AddressKind::Address);
        assert_eq!(target.label, "0xdead");
    }
}
