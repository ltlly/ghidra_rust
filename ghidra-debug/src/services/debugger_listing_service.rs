//! DebuggerListingService - service for listing (code view) integration.
//!
//! Ported from Ghidra's `ghidra.app.services.DebuggerListingService`.

/// Service interface for the listing (code view) integration.
pub trait DebuggerListingServiceExt {
    /// Go to the given address in the listing.
    fn go_to(&mut self, address: u64, space: &str);

    /// Go to the given trace location.
    fn go_to_location(&mut self, snap: i64, address: u64, space: &str);

    /// Get the current cursor address.
    fn current_address(&self) -> Option<u64>;

    /// Get the current cursor snap.
    fn current_snap(&self) -> Option<i64>;

    /// Set the address highlight.
    fn set_highlight(&mut self, address: Option<u64>);

    /// Get the highlighted address.
    fn highlight_address(&self) -> Option<u64>;

    /// Update the listing to reflect a new snap.
    fn update_snap(&mut self, snap: i64);

    /// Get the current code unit type at the cursor.
    fn current_code_unit_type(&self) -> Option<CodeUnitTypeAtCursor>;
}

/// The type of code unit at the cursor position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeUnitTypeAtCursor {
    /// An instruction.
    Instruction,
    /// Defined data.
    Data,
    /// Undefined data.
    Undefined,
    /// No code unit (empty space).
    None,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_unit_type_at_cursor() {
        assert_ne!(
            CodeUnitTypeAtCursor::Instruction,
            CodeUnitTypeAtCursor::Data
        );
    }
}
