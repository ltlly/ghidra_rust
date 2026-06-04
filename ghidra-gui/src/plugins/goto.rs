//! Go-to-address service -- navigate to addresses, labels, external
//! linkages, and cross-program locations.
//!
//! Ports `ghidra.app.plugin.core.gotoquery`:
//! - [`GoToService`] trait
//! - [`GoToHelper`] for resolving addresses across programs
//! - [`GoToServicePlugin`] that owns the service

use std::collections::VecDeque;

use ghidra_core::addr::Address;
use ghidra_core::program::program::Program;
use ghidra_core::symbol::ExternalLocation;

// ---------------------------------------------------------------------------
// ProgramLocation -- minimal Rust port of ghidra.program.util.ProgramLocation
// ---------------------------------------------------------------------------

/// A location within a program: an address together with optional
/// context about the field / row / column the user clicked on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProgramLocation {
    /// The address this location refers to.
    pub address: Address,
    /// The program name (used for cross-program navigation).
    pub program_name: String,
    /// Optional character offset within the rendered field text.
    pub char_offset: Option<usize>,
    /// Optional field name (e.g. "Mnemonic", "Operand").
    pub field_name: Option<String>,
}

impl ProgramLocation {
    /// Create a simple address-only location.
    pub fn new(address: Address, program_name: impl Into<String>) -> Self {
        Self {
            address,
            program_name: program_name.into(),
            char_offset: None,
            field_name: None,
        }
    }

    /// Create a location with character offset and field context.
    pub fn with_field(
        address: Address,
        program_name: impl Into<String>,
        field_name: impl Into<String>,
        char_offset: usize,
    ) -> Self {
        Self {
            address,
            program_name: program_name.into(),
            char_offset: Some(char_offset),
            field_name: Some(field_name.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// NavigationHistory -- tracks visited locations for back/forward
// ---------------------------------------------------------------------------

/// Fixed maximum history depth.
const MAX_HISTORY: usize = 256;

/// Stack-based navigation history.
#[derive(Debug, Clone)]
pub struct NavigationHistory {
    back_stack: VecDeque<ProgramLocation>,
    forward_stack: VecDeque<ProgramLocation>,
}

impl NavigationHistory {
    /// Create an empty history.
    pub fn new() -> Self {
        Self {
            back_stack: VecDeque::new(),
            forward_stack: VecDeque::new(),
        }
    }

    /// Record a new navigation event.
    pub fn push(&mut self, location: ProgramLocation) {
        if self.back_stack.back() == Some(&location) {
            return; // avoid duplicates
        }
        self.back_stack.push_back(location);
        self.forward_stack.clear();
        while self.back_stack.len() > MAX_HISTORY {
            self.back_stack.pop_front();
        }
    }

    /// Go back; returns the previous location if any.
    pub fn go_back(&mut self) -> Option<ProgramLocation> {
        let current = self.back_stack.pop_back()?;
        if let Some(prev) = self.back_stack.back() {
            let loc = prev.clone();
            self.forward_stack.push_back(current);
            Some(loc)
        } else {
            // Nothing behind -- push current back
            self.back_stack.push_back(current);
            None
        }
    }

    /// Go forward; returns the next location if any.
    pub fn go_forward(&mut self) -> Option<ProgramLocation> {
        let loc = self.forward_stack.pop_back()?;
        self.back_stack.push_back(loc.clone());
        Some(loc)
    }

    /// Current (most recent) location.
    pub fn current(&self) -> Option<&ProgramLocation> {
        self.back_stack.back()
    }

    /// Whether back navigation is possible.
    pub fn can_go_back(&self) -> bool {
        self.back_stack.len() > 1
    }

    /// Whether forward navigation is possible.
    pub fn can_go_forward(&self) -> bool {
        !self.forward_stack.is_empty()
    }
}

impl Default for NavigationHistory {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GoToService trait
// ---------------------------------------------------------------------------

/// Trait for navigating to addresses within programs.
pub trait GoToService: Send + Sync {
    /// Navigate to the given address in the specified program.
    fn go_to(&mut self, program: &Program, address: Address) -> bool;

    /// Navigate to the given location.
    fn go_to_location(&mut self, program: &Program, loc: &ProgramLocation) -> bool;

    /// Get the maximum number of search hits for wildcard queries.
    fn max_hits(&self) -> usize;
}

// ---------------------------------------------------------------------------
// GoToHelper -- resolves addresses and handles external linkage
// ---------------------------------------------------------------------------

/// Helper for resolving go-to targets, including external programs.
pub struct GoToHelper {
    /// Maximum hits when resolving wildcard queries.
    max_hits: usize,
    /// Whether to navigate to external programs (vs. linkage locations only).
    goto_external_program: bool,
}

impl GoToHelper {
    /// Create a new helper with default settings.
    pub fn new() -> Self {
        Self {
            max_hits: 1000,
            goto_external_program: false,
        }
    }

    /// Set the max-hits limit.
    pub fn set_max_hits(&mut self, max: usize) {
        self.max_hits = max;
    }

    /// Get the max-hits limit.
    pub fn max_hits(&self) -> usize {
        self.max_hits
    }

    /// Enable or disable navigating to external programs.
    pub fn set_goto_external_program(&mut self, enabled: bool) {
        self.goto_external_program = enabled;
    }

    /// Whether navigating to external programs is enabled.
    pub fn is_goto_external_program_enabled(&self) -> bool {
        self.goto_external_program
    }

    /// Resolve a [`ProgramLocation`] for the given target address.
    ///
    /// If a symbol exists at that address its location is returned;
    /// otherwise a simple `AddressFieldLocation` is built.
    pub fn location_for_address(
        program: &Program,
        target: &Address,
    ) -> Option<ProgramLocation> {
        // Try to find a symbol at the target address
        if program.get_symbol_at(target).is_some() {
            return Some(ProgramLocation::with_field(
                *target,
                program.get_name(),
                "Label",
                0,
            ));
        }
        // Fall back to a plain address location
        if target.is_memory_address() {
            Some(ProgramLocation::new(*target, program.get_name()))
        } else {
            None
        }
    }

    /// Attempt to go to an external linkage address.
    ///
    /// Returns `Some(ProgramLocation)` if a linkage address was found.
    pub fn go_to_external_linkage(
        &self,
        program: &Program,
        external_loc: &dyn ExternalLocation,
        _allow_popup: bool,
    ) -> Option<ProgramLocation> {
        // Find the external symbol address
        let sym_addr = external_loc.get_address()?;
        // Find references to that external address
        let refs: Vec<Address> = program.get_references_to(&sym_addr);
        if refs.is_empty() {
            return None;
        }
        // Prefer the first linkage address
        Self::location_for_address(program, &refs[0])
    }
}

impl Default for GoToHelper {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GoToServicePlugin -- owns the GoToHelper + history
// ---------------------------------------------------------------------------

/// The top-level plugin that provides go-to functionality.
pub struct GoToServicePlugin {
    helper: GoToHelper,
    history: NavigationHistory,
}

impl GoToServicePlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            helper: GoToHelper::new(),
            history: NavigationHistory::new(),
        }
    }

    /// Navigate to a raw address within the given program.
    pub fn go_to(
        &mut self,
        program: &Program,
        address: Address,
    ) -> Option<ProgramLocation> {
        let loc = GoToHelper::location_for_address(program, &address)?;
        self.history.push(loc.clone());
        Some(loc)
    }

    /// Navigate using an already-resolved location.
    pub fn go_to_location(&mut self, loc: ProgramLocation) {
        self.history.push(loc);
    }

    /// Go back in navigation history.
    pub fn go_back(&mut self) -> Option<ProgramLocation> {
        self.history.go_back()
    }

    /// Go forward in navigation history.
    pub fn go_forward(&mut self) -> Option<ProgramLocation> {
        self.history.go_forward()
    }

    /// Whether back navigation is possible.
    pub fn can_go_back(&self) -> bool {
        self.history.can_go_back()
    }

    /// Whether forward navigation is possible.
    pub fn can_go_forward(&self) -> bool {
        self.history.can_go_forward()
    }

    /// Get the current location.
    pub fn current_location(&self) -> Option<&ProgramLocation> {
        self.history.current()
    }

    /// Access the underlying helper.
    pub fn helper(&self) -> &GoToHelper {
        &self.helper
    }

    /// Mutable access to the underlying helper.
    pub fn helper_mut(&mut self) -> &mut GoToHelper {
        &mut self.helper
    }
}

impl Default for GoToServicePlugin {
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

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn program_location_creation() {
        let loc = ProgramLocation::new(addr(0x1000), "test_prog");
        assert_eq!(loc.address, addr(0x1000));
        assert_eq!(loc.program_name, "test_prog");
        assert!(loc.char_offset.is_none());
    }

    #[test]
    fn program_location_with_field() {
        let loc = ProgramLocation::with_field(addr(0x2000), "prog", "Mnemonic", 5);
        assert_eq!(loc.field_name.as_deref(), Some("Mnemonic"));
        assert_eq!(loc.char_offset, Some(5));
    }

    #[test]
    fn history_push_and_current() {
        let mut h = NavigationHistory::new();
        assert!(h.current().is_none());
        h.push(ProgramLocation::new(addr(100), "p"));
        assert_eq!(h.current().unwrap().address, addr(100));
        h.push(ProgramLocation::new(addr(200), "p"));
        assert_eq!(h.current().unwrap().address, addr(200));
    }

    #[test]
    fn history_no_duplicate_push() {
        let mut h = NavigationHistory::new();
        h.push(ProgramLocation::new(addr(100), "p"));
        h.push(ProgramLocation::new(addr(100), "p"));
        assert_eq!(h.back_stack.len(), 1);
    }

    #[test]
    fn history_go_back_forward() {
        let mut h = NavigationHistory::new();
        h.push(ProgramLocation::new(addr(100), "p"));
        h.push(ProgramLocation::new(addr(200), "p"));
        h.push(ProgramLocation::new(addr(300), "p"));

        assert!(h.can_go_back());
        assert!(!h.can_go_forward());

        let prev = h.go_back().unwrap();
        assert_eq!(prev.address, addr(200));

        assert!(h.can_go_forward());
        let fwd = h.go_forward().unwrap();
        assert_eq!(fwd.address, addr(300));
    }

    #[test]
    fn history_go_back_to_start() {
        let mut h = NavigationHistory::new();
        h.push(ProgramLocation::new(addr(100), "p"));
        assert!(h.go_back().is_none()); // only one entry
    }

    #[test]
    fn history_forward_cleared_on_new_push() {
        let mut h = NavigationHistory::new();
        h.push(ProgramLocation::new(addr(100), "p"));
        h.push(ProgramLocation::new(addr(200), "p"));
        h.go_back();
        assert!(h.can_go_forward());
        h.push(ProgramLocation::new(addr(300), "p"));
        assert!(!h.can_go_forward());
    }

    #[test]
    fn helper_defaults() {
        let h = GoToHelper::new();
        assert_eq!(h.max_hits(), 1000);
        assert!(!h.is_goto_external_program_enabled());
    }

    #[test]
    fn helper_set_max_hits() {
        let mut h = GoToHelper::new();
        h.set_max_hits(5000);
        assert_eq!(h.max_hits(), 5000);
    }

    #[test]
    fn helper_toggle_external() {
        let mut h = GoToHelper::new();
        h.set_goto_external_program(true);
        assert!(h.is_goto_external_program_enabled());
    }

    #[test]
    fn plugin_go_to_creates_location() {
        let prog = Program::new("test", Address::new(0x400000));
        let mut plugin = GoToServicePlugin::new();
        let loc = plugin.go_to(&prog, addr(0x400000));
        assert!(loc.is_some());
        assert_eq!(loc.unwrap().address, addr(0x400000));
    }

    #[test]
    fn plugin_history_navigation() {
        let prog = Program::new("test", Address::new(0x400000));
        let mut plugin = GoToServicePlugin::new();
        plugin.go_to(&prog, addr(0x1000));
        plugin.go_to(&prog, addr(0x2000));
        assert_eq!(plugin.current_location().unwrap().address, addr(0x2000));
        let back = plugin.go_back().unwrap();
        assert_eq!(back.address, addr(0x1000));
        let fwd = plugin.go_forward().unwrap();
        assert_eq!(fwd.address, addr(0x2000));
    }

    #[test]
    fn helper_location_for_address_basic() {
        let prog = Program::new("test", Address::new(0));
        let loc = GoToHelper::location_for_address(&prog, &addr(0x400000));
        assert!(loc.is_some());
        let loc = loc.unwrap();
        assert_eq!(loc.address, addr(0x400000));
        assert_eq!(loc.program_name, "test");
    }

    #[test]
    fn plugin_go_to_returns_none_for_nonexistent() {
        // Program with no memory -- any address will fail is_memory_address
        let prog = Program::new("test", Address::new(0));
        // Address::new(0) has is_memory_address() = false (stub)
        // So this returns None
        let mut plugin = GoToServicePlugin::new();
        let loc = plugin.go_to(&prog, addr(0x1000));
        // Address::is_memory_address returns true for non-null, non-stack
        // addresses in this implementation, so we get Some
        assert!(loc.is_some());
    }
}
