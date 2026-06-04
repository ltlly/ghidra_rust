//! Clear command -- clears program annotations over an address set.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.clear.ClearCmd`.
//!
//! The `ClearCmd` is a background-capable command that iterates over an
//! address set and selectively removes instructions, data, symbols,
//! comments, properties, functions, registers, equates, references,
//! and bookmarks according to the provided [`ClearOptions`].

use super::options::{ClearOptions, ClearType};
use ghidra_core::addr::{Address, AddressRange, AddressSet};
use ghidra_core::symbol::SourceType;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Threshold for deciding whether to send individual program events.
///
/// When the number of addresses to clear is below this limit, individual
/// events are sent for each change. When above, events are batched.
pub const EVENT_LIMIT: u64 = 1000;

/// The chunk size for clearing code units in batches.
///
/// Ghidra clears code in chunks to allow the UI to remain responsive
/// and to manage database lock contention.
pub const CODE_CHUNK_SIZE: u64 = 10_000;

/// Maximum number of backward addresses to search for fallthrough repair.
pub const FALLTHROUGH_SEARCH_LIMIT: u32 = 12;

/// A background command that clears program annotations over an address range.
///
/// This corresponds to Ghidra's `ClearCmd` class. It operates on an
/// [`AddressSetView`](AddressSet) and selectively clears items based on
/// the provided [`ClearOptions`].
///
/// # Usage
///
/// ```rust
/// use ghidra_features::base::clear::{ClearCmd, ClearOptions, ClearType};
/// use ghidra_core::addr::{Address, AddressSet};
///
/// let opts = ClearOptions::all();
///
/// let mut addrs = AddressSet::new();
/// addrs.add_range(Address::new(0x1000), Address::new(0x1100));
///
/// let cmd = ClearCmd::new(addrs, opts);
/// assert_eq!(cmd.name(), "Clear with Options");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearCmd {
    /// The address set over which to clear.
    view: AddressSet,
    /// Options controlling what to clear.
    options: ClearOptions,
    /// Whether to send individual change events (for small ranges).
    send_individual_events: bool,
}

impl ClearCmd {
    /// Creates a new clear command for a single code unit address range.
    ///
    /// This is a convenience constructor that builds an `AddressSet` from the
    /// given start and end addresses.
    pub fn for_code_unit(start: Address, end: Address, options: ClearOptions) -> Self {
        let view = AddressSet::from_range(start, end);
        Self {
            view,
            options,
            send_individual_events: true,
        }
    }

    /// Creates a new clear command over the given address set with options.
    ///
    /// Individual events are sent if the address count is below
    /// [`EVENT_LIMIT`].
    pub fn new(view: AddressSet, options: ClearOptions) -> Self {
        let send_individual_events = view.num_addresses() < EVENT_LIMIT;
        Self {
            view,
            options,
            send_individual_events,
        }
    }

    /// Creates a code-only clear command (no options dialog).
    ///
    /// Clears instructions and data over the address set but does not
    /// touch other annotations.
    pub fn code_only(view: AddressSet) -> Self {
        let mut options = ClearOptions::new(false);
        options.set_should_clear(ClearType::Instructions, true);
        options.set_should_clear(ClearType::Data, true);
        let send_individual_events = view.num_addresses() < EVENT_LIMIT;
        Self {
            view,
            options,
            send_individual_events,
        }
    }

    /// Creates a full-clear command with all options enabled.
    pub fn full(view: AddressSet) -> Self {
        let send_individual_events = view.num_addresses() < EVENT_LIMIT;
        Self {
            view,
            options: ClearOptions::all(),
            send_individual_events,
        }
    }

    // -- Accessors --

    /// Returns the command name for display.
    pub fn name(&self) -> &str {
        if self.is_default_options() {
            "Clear code"
        } else {
            "Clear with Options"
        }
    }

    /// Returns a reference to the address set.
    pub fn view(&self) -> &AddressSet {
        &self.view
    }

    /// Returns a reference to the clear options.
    pub fn options(&self) -> &ClearOptions {
        &self.options
    }

    /// Returns whether individual events will be sent.
    pub fn sends_individual_events(&self) -> bool {
        self.send_individual_events
    }

    /// Returns `true` if the options are the default (code-only clear).
    fn is_default_options(&self) -> bool {
        !self.options.should_clear(ClearType::Symbols)
            && !self.options.should_clear(ClearType::Comments)
            && !self.options.should_clear(ClearType::Properties)
            && !self.options.should_clear(ClearType::Functions)
            && !self.options.should_clear(ClearType::Registers)
            && !self.options.should_clear(ClearType::Equates)
            && !self.options.should_clear(ClearType::Bookmarks)
    }

    // -- Execution helpers --

    /// Returns the list of clear operations to execute, in order.
    ///
    /// This mirrors the order of operations in Ghidra's `doApplyWithCancel`.
    pub fn operations(&self) -> Vec<ClearOperation> {
        let mut ops = Vec::new();

        if self.options.should_clear(ClearType::Equates) {
            ops.push(ClearOperation::Equates);
        }
        if self.options.should_clear(ClearType::Instructions)
            || self.options.should_clear(ClearType::Data)
        {
            ops.push(ClearOperation::InstructionsAndOrData {
                clear_instructions: self.options.should_clear(ClearType::Instructions),
                clear_data: self.options.should_clear(ClearType::Data),
            });
        }
        if self.options.should_clear(ClearType::Comments) {
            ops.push(ClearOperation::Comments);
        }
        if self.options.should_clear(ClearType::Functions) {
            ops.push(ClearOperation::Functions);
        }
        if self.options.should_clear(ClearType::Symbols) {
            ops.push(ClearOperation::Symbols);
        }
        if self.options.should_clear(ClearType::Properties) {
            ops.push(ClearOperation::Properties);
        }
        if self.options.should_clear(ClearType::Registers) {
            ops.push(ClearOperation::Registers);
        }
        if self.options.should_clear(ClearType::Bookmarks) {
            ops.push(ClearOperation::Bookmarks);
        }

        // Only clear references explicitly if NOT clearing both instructions and data.
        // (Clearing both instructions and data implicitly removes all references.)
        if !(self.options.should_clear(ClearType::Instructions)
            && self.options.should_clear(ClearType::Data))
        {
            let source_types = self.options.get_reference_source_types_to_clear();
            if !source_types.is_empty() {
                ops.push(ClearOperation::References { source_types });
            }
        }

        ops
    }

    /// Returns the progress message for the instructions/data clear step.
    pub fn code_clear_message(&self) -> &'static str {
        let clear_instr = self.options.should_clear(ClearType::Instructions);
        let clear_data = self.options.should_clear(ClearType::Data);
        match (clear_instr, clear_data) {
            (true, true) => "Clearing Instructions and Data...",
            (true, false) => "Clearing Instructions...",
            (false, true) => "Clearing Data...",
            (false, false) => "", // shouldn't be reached
        }
    }
}

/// Represents a single clear operation to be executed against a program.
///
/// The [`ClearCmd::operations`] method returns these in the correct
/// execution order. Each variant corresponds to a private method in
/// Ghidra's `ClearCmd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearOperation {
    /// Clear equates from operands in the address range.
    Equates,
    /// Clear instructions and/or data code units.
    InstructionsAndOrData {
        /// Whether to clear instructions.
        clear_instructions: bool,
        /// Whether to clear data.
        clear_data: bool,
    },
    /// Clear comments (pre, post, end-of-line, plate, repeatable).
    Comments,
    /// Remove functions whose entry points fall in the address range.
    Functions,
    /// Delete label symbols (non-pinned) in the address range.
    Symbols,
    /// Clear user-defined properties from code units.
    Properties,
    /// Clear register (context) values in the address range.
    Registers,
    /// Remove bookmarks in the address range.
    Bookmarks,
    /// Remove references of the given source types.
    References {
        /// The source types of references to clear.
        source_types: HashSet<SourceType>,
    },
}

/// Helper for chunking an address range into fixed-size pieces.
///
/// This mirrors Ghidra's `AddressRangeChunker` which breaks up large
/// ranges for progress reporting and UI responsiveness.
#[derive(Debug, Clone)]
pub struct AddressRangeChunker {
    /// The range to chunk.
    range: AddressRange,
    /// Maximum chunk size.
    chunk_size: u64,
}

impl AddressRangeChunker {
    /// Creates a new chunker for the given range and chunk size.
    pub fn new(range: AddressRange, chunk_size: u64) -> Self {
        Self { range, chunk_size }
    }

    /// Returns an iterator over the chunks.
    pub fn chunks(&self) -> AddressRangeChunkIter<'_> {
        AddressRangeChunkIter {
            chunker: self,
            current: self.range.start.offset,
        }
    }
}

/// Iterator over address range chunks.
#[derive(Debug)]
pub struct AddressRangeChunkIter<'a> {
    chunker: &'a AddressRangeChunker,
    current: u64,
}

impl<'a> Iterator for AddressRangeChunkIter<'a> {
    type Item = AddressRange;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current > self.chunker.range.end.offset {
            return None;
        }
        let chunk_end = (self.current + self.chunker.chunk_size - 1)
            .min(self.chunker.range.end.offset);
        let range = AddressRange::new(Address::new(self.current), Address::new(chunk_end));
        self.current = chunk_end + 1;
        Some(range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clear_cmd_code_only_name() {
        let cmd = ClearCmd::code_only(AddressSet::from_range(
            Address::new(0x1000),
            Address::new(0x1100),
        ));
        assert_eq!(cmd.name(), "Clear code");
    }

    #[test]
    fn test_clear_cmd_with_options_name() {
        let opts = ClearOptions::all();
        let cmd = ClearCmd::new(
            AddressSet::from_range(Address::new(0x1000), Address::new(0x1100)),
            opts,
        );
        assert_eq!(cmd.name(), "Clear with Options");
    }

    #[test]
    fn test_operations_code_only() {
        let cmd = ClearCmd::code_only(AddressSet::from_range(
            Address::new(0x1000),
            Address::new(0x1100),
        ));
        let ops = cmd.operations();
        // code_only only clears instructions and data -- no separate reference clearing
        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0],
            ClearOperation::InstructionsAndOrData {
                clear_instructions: true,
                clear_data: true,
            }
        );
    }

    #[test]
    fn test_operations_full() {
        let cmd = ClearCmd::full(AddressSet::from_range(
            Address::new(0x1000),
            Address::new(0x1100),
        ));
        let ops = cmd.operations();
        // Full clear: equates, instr+data, comments, functions, symbols, properties,
        // registers, bookmarks. References are implicitly cleared by clearing both
        // instructions and data.
        assert_eq!(ops.len(), 8);
        assert_eq!(ops[0], ClearOperation::Equates);
        assert_eq!(
            ops[1],
            ClearOperation::InstructionsAndOrData {
                clear_instructions: true,
                clear_data: true,
            }
        );
        assert_eq!(ops[2], ClearOperation::Comments);
        assert_eq!(ops[3], ClearOperation::Functions);
        assert_eq!(ops[4], ClearOperation::Symbols);
        assert_eq!(ops[5], ClearOperation::Properties);
        assert_eq!(ops[6], ClearOperation::Registers);
        assert_eq!(ops[7], ClearOperation::Bookmarks);
    }

    #[test]
    fn test_operations_partial_with_references() {
        let mut opts = ClearOptions::new(false);
        opts.set_should_clear(ClearType::Instructions, true);
        opts.set_should_clear(ClearType::UserReferences, true);
        opts.set_should_clear(ClearType::AnalysisReferences, true);

        let cmd = ClearCmd::new(
            AddressSet::from_range(Address::new(0x1000), Address::new(0x1100)),
            opts,
        );
        let ops = cmd.operations();
        // Instructions only (not data) + references
        assert_eq!(ops.len(), 2);
        assert_eq!(
            ops[0],
            ClearOperation::InstructionsAndOrData {
                clear_instructions: true,
                clear_data: false,
            }
        );
        match &ops[1] {
            ClearOperation::References { source_types } => {
                assert!(source_types.contains(&SourceType::UserDefined));
                assert!(source_types.contains(&SourceType::Analysis));
                assert_eq!(source_types.len(), 2);
            }
            _ => panic!("Expected References operation"),
        }
    }

    #[test]
    fn test_code_clear_message() {
        let cmd = ClearCmd::code_only(AddressSet::from_range(
            Address::new(0x1000),
            Address::new(0x1100),
        ));
        assert_eq!(cmd.code_clear_message(), "Clearing Instructions and Data...");
    }

    #[test]
    fn test_code_clear_message_instructions_only() {
        let mut opts = ClearOptions::new(false);
        opts.set_should_clear(ClearType::Instructions, true);
        let cmd = ClearCmd::new(
            AddressSet::from_range(Address::new(0x1000), Address::new(0x1100)),
            opts,
        );
        assert_eq!(cmd.code_clear_message(), "Clearing Instructions...");
    }

    #[test]
    fn test_address_range_chunker() {
        let range = AddressRange::new(Address::new(0x1000), Address::new(0x10FF));
        let chunker = AddressRangeChunker::new(range, 0x40);
        let chunks: Vec<AddressRange> = chunker.chunks().collect();
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].start, Address::new(0x1000));
        assert_eq!(chunks[0].end, Address::new(0x103F));
        assert_eq!(chunks[1].start, Address::new(0x1040));
        assert_eq!(chunks[1].end, Address::new(0x107F));
        assert_eq!(chunks[2].start, Address::new(0x1080));
        assert_eq!(chunks[2].end, Address::new(0x10BF));
        assert_eq!(chunks[3].start, Address::new(0x10C0));
        assert_eq!(chunks[3].end, Address::new(0x10FF));
    }

    #[test]
    fn test_address_range_chunker_single_chunk() {
        let range = AddressRange::new(Address::new(0x1000), Address::new(0x1005));
        let chunker = AddressRangeChunker::new(range, 0x10000);
        let chunks: Vec<AddressRange> = chunker.chunks().collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].start, Address::new(0x1000));
        assert_eq!(chunks[0].end, Address::new(0x1005));
    }

    #[test]
    fn test_send_individual_events_small() {
        let mut addrs = AddressSet::new();
        addrs.add_range(Address::new(0x1000), Address::new(0x1005));
        let cmd = ClearCmd::new(addrs, ClearOptions::all());
        assert!(cmd.sends_individual_events());
    }

    #[test]
    fn test_send_individual_events_large() {
        let mut addrs = AddressSet::new();
        addrs.add_range(Address::new(0x1000), Address::new(0x1FFF));
        let cmd = ClearCmd::new(addrs, ClearOptions::all());
        // 0x1000 = 4096 addresses > EVENT_LIMIT (1000)
        assert!(!cmd.sends_individual_events());
    }

    #[test]
    fn test_for_code_unit_convenience() {
        let cmd = ClearCmd::for_code_unit(
            Address::new(0x1000),
            Address::new(0x1004),
            ClearOptions::all(),
        );
        assert!(cmd.sends_individual_events());
        assert_eq!(cmd.view().num_addresses(), 5);
    }
}
