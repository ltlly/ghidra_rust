//! Navigation helpers -- location references, next/previous actions,
//! and reference descriptors.
//!
//! Ports `ghidra.app.plugin.core.navigation` and
//! `ghidra.app.plugin.core.navigation.locationreferences`:
//! - [`LocationReference`] (a single reference to something)
//! - [`LocationDescriptor`] (abstract description of a location)
//! - [`NavigationOptions`] (user-configurable navigation settings)
//! - Next/previous action patterns

use std::collections::BTreeSet;

use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// LocationReference -- a single reference to something
// ---------------------------------------------------------------------------

/// Search context qualifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SearchLocationContext {
    /// Human-readable context string (e.g. "Function Signature", "Variable Type").
    pub context: String,
}

impl SearchLocationContext {
    /// An empty / default context.
    pub fn empty() -> Self {
        Self::default()
    }
}

/// A single reference to an item being tracked.
///
/// For references, the address is the "from" address. For data types,
/// it is where the type is applied.
#[derive(Debug, Clone)]
pub struct LocationReference {
    /// The address where this item is used.
    location_of_use: Address,
    /// The type of reference (e.g. "READ", "WRITE", "CALL").
    ref_type: String,
    /// Whether this is an offcut reference (points into the middle of an item).
    is_offcut: bool,
    /// Additional context about the reference location.
    context: SearchLocationContext,
    /// Optional field name (e.g. "Mnemonic", "Operand 1").
    field_name: Option<String>,
}

impl LocationReference {
    /// Create a simple address-only reference.
    pub fn new(address: Address) -> Self {
        Self {
            location_of_use: address,
            ref_type: String::new(),
            is_offcut: false,
            context: SearchLocationContext::empty(),
            field_name: None,
        }
    }

    /// Create a reference with type information.
    pub fn with_type(address: Address, ref_type: impl Into<String>, is_offcut: bool) -> Self {
        Self {
            location_of_use: address,
            ref_type: ref_type.into(),
            is_offcut,
            context: SearchLocationContext::empty(),
            field_name: None,
        }
    }

    /// Create a reference with full context.
    pub fn with_context(
        address: Address,
        ref_type: impl Into<String>,
        is_offcut: bool,
        context: SearchLocationContext,
        field_name: Option<String>,
    ) -> Self {
        Self {
            location_of_use: address,
            ref_type: ref_type.into(),
            is_offcut,
            context,
            field_name,
        }
    }

    /// The address where this item is used.
    pub fn location_of_use(&self) -> &Address {
        &self.location_of_use
    }

    /// The reference type string.
    pub fn ref_type_string(&self) -> &str {
        &self.ref_type
    }

    /// Whether this is an offcut reference.
    pub fn is_offcut_reference(&self) -> bool {
        self.is_offcut
    }

    /// The search location context.
    pub fn context(&self) -> &SearchLocationContext {
        &self.context
    }

    /// Optional field name.
    pub fn field_name(&self) -> Option<&str> {
        self.field_name.as_deref()
    }
}

impl PartialEq for LocationReference {
    fn eq(&self, other: &Self) -> bool {
        self.location_of_use == other.location_of_use
            && self.ref_type == other.ref_type
            && self.is_offcut == other.is_offcut
    }
}

impl Eq for LocationReference {}

impl PartialOrd for LocationReference {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LocationReference {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.location_of_use.cmp(&other.location_of_use)
    }
}

// ---------------------------------------------------------------------------
// LocationDescriptor -- describes what the user is looking at
// ---------------------------------------------------------------------------

/// The kind of "thing" at a program location.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DescriptorKind {
    /// A symbol label.
    Label,
    /// A mnemonic field.
    Mnemonic,
    /// An operand field.
    Operand,
    /// A data type applied to a variable or data.
    DataType,
    /// A function signature component.
    FunctionSignature,
    /// A function parameter name.
    FunctionParameterName,
    /// A function parameter type.
    FunctionParameterType,
    /// A function return type.
    FunctionReturnType,
    /// A structure member.
    StructureMember,
    /// A union member.
    UnionMember,
    /// A variable name.
    VariableName,
    /// A variable type.
    VariableType,
    /// A cross-reference (XRef).
    XRef,
    /// An address.
    Address,
}

/// Describes the "thing" at a program location and knows how to find
/// all references to it.
///
/// Subclasses in the Java version implement `doGetReferences()` with
/// different strategies.  Here we model the descriptor as data plus a
/// pre-computed list of references.
#[derive(Debug, Clone)]
pub struct LocationDescriptor {
    /// What kind of thing is at this location.
    kind: DescriptorKind,
    /// The home address of the described item.
    home_address: Address,
    /// A human-readable label.
    label: String,
    /// Pre-loaded list of references (sorted by address).
    references: Vec<LocationReference>,
    /// Whether dynamic (runtime) searching is enabled.
    use_dynamic_searching: bool,
}

impl LocationDescriptor {
    /// Create a new descriptor.
    pub fn new(kind: DescriptorKind, home_address: Address, label: impl Into<String>) -> Self {
        Self {
            kind,
            home_address,
            label: label.into(),
            references: Vec::new(),
            use_dynamic_searching: true,
        }
    }

    /// The kind of descriptor.
    pub fn kind(&self) -> &DescriptorKind {
        &self.kind
    }

    /// The home address of the described item.
    pub fn home_address(&self) -> &Address {
        &self.home_address
    }

    /// The display label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Set the references list.
    pub fn set_references(&mut self, mut refs: Vec<LocationReference>) {
        refs.sort();
        refs.dedup();
        self.references = refs;
    }

    /// Get all references (sorted).
    pub fn references(&self) -> &[LocationReference] {
        &self.references
    }

    /// Whether the descriptor's reference list contains the given address.
    pub fn references_contain(&self, address: &Address) -> bool {
        self.references
            .binary_search_by(|r| r.location_of_use().cmp(address))
            .is_ok()
    }

    /// Remove all references from the given address.
    ///
    /// Returns `true` if any were removed.
    pub fn remove_references_from(&mut self, address: &Address) -> bool {
        let before = self.references.len();
        self.references
            .retain(|r| r.location_of_use() != address);
        self.references.len() != before
    }

    /// Whether the given address is the home address or in the references.
    pub fn is_in_addresses(&self, address: &Address) -> bool {
        &self.home_address == address || self.references_contain(address)
    }

    /// Set whether dynamic searching is enabled.
    pub fn set_use_dynamic_searching(&mut self, enabled: bool) {
        self.use_dynamic_searching = enabled;
    }

    /// Whether dynamic searching is enabled.
    pub fn use_dynamic_searching(&self) -> bool {
        self.use_dynamic_searching
    }

    /// Get a type name for display in a popup menu.
    pub fn type_name(&self) -> &str {
        &self.label
    }
}

impl PartialEq for LocationDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label && self.home_address == other.home_address && self.kind == other.kind
    }
}

impl Eq for LocationDescriptor {}

// ---------------------------------------------------------------------------
// NavigationOptions -- user-configurable settings
// ---------------------------------------------------------------------------

/// Options controlling navigation behavior.
#[derive(Debug, Clone)]
pub struct NavigationOptions {
    /// Whether to navigate to external programs on "Go To".
    goto_external_program: bool,
    /// Maximum number of search hits.
    max_search_hits: usize,
    /// Whether to use dynamic reference searching.
    use_dynamic_searching: bool,
}

impl NavigationOptions {
    /// Create options with default values.
    pub fn new() -> Self {
        Self {
            goto_external_program: false,
            max_search_hits: 1000,
            use_dynamic_searching: true,
        }
    }

    /// Whether navigating to external programs is enabled.
    pub fn is_goto_external_program_enabled(&self) -> bool {
        self.goto_external_program
    }

    /// Enable or disable external program navigation.
    pub fn set_goto_external_program(&mut self, enabled: bool) {
        self.goto_external_program = enabled;
    }

    /// Maximum search hits.
    pub fn max_search_hits(&self) -> usize {
        self.max_search_hits
    }

    /// Set max search hits.
    pub fn set_max_search_hits(&mut self, max: usize) {
        self.max_search_hits = max;
    }

    /// Whether dynamic searching is enabled.
    pub fn use_dynamic_searching(&self) -> bool {
        self.use_dynamic_searching
    }

    /// Set dynamic searching.
    pub fn set_use_dynamic_searching(&mut self, enabled: bool) {
        self.use_dynamic_searching = enabled;
    }
}

impl Default for NavigationOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NextPrevTracker -- tracks positions for next/previous actions
// ---------------------------------------------------------------------------

/// A generic next/previous tracker that moves through a sorted set of
/// addresses.
///
/// Used by the various `NextPrevious*Action` classes to jump between
/// bookmarks, functions, labels, instructions, etc.
#[derive(Debug, Clone)]
pub struct NextPrevTracker {
    /// Sorted set of target addresses.
    addresses: BTreeSet<Address>,
    /// Current position.
    current: Option<Address>,
}

impl NextPrevTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            addresses: BTreeSet::new(),
            current: None,
        }
    }

    /// Create a tracker from a collection of addresses.
    pub fn from_addresses(addrs: impl IntoIterator<Item = Address>) -> Self {
        let addresses: BTreeSet<Address> = addrs.into_iter().collect();
        Self {
            addresses,
            current: None,
        }
    }

    /// Set the current position.
    pub fn set_current(&mut self, addr: Address) {
        self.current = Some(addr);
    }

    /// Get the next address after the current position (wrapping around).
    pub fn next(&mut self) -> Option<Address> {
        if self.addresses.is_empty() {
            return None;
        }
        let current = self.current?;
        // Find the first address strictly greater than current
        let next = self
            .addresses
            .range(current.clone()..)
            .nth(1) // skip current itself
            .cloned()
            .or_else(|| self.addresses.iter().next().cloned()); // wrap
        if let Some(addr) = next {
            self.current = Some(addr.clone());
            Some(addr)
        } else {
            None
        }
    }

    /// Get the previous address before the current position (wrapping).
    pub fn previous(&mut self) -> Option<Address> {
        if self.addresses.is_empty() {
            return None;
        }
        let current = self.current?;
        // Collect all addresses less than current in reverse order
        let prev = self
            .addresses
            .range(..current.clone())
            .next_back()
            .cloned()
            .or_else(|| self.addresses.iter().next_back().cloned()); // wrap
        if let Some(addr) = prev {
            self.current = Some(addr.clone());
            Some(addr)
        } else {
            None
        }
    }

    /// Current address.
    pub fn current(&self) -> Option<&Address> {
        self.current.as_ref()
    }

    /// Number of tracked addresses.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Whether the tracker is empty.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Clear all addresses.
    pub fn clear(&mut self) {
        self.addresses.clear();
        self.current = None;
    }

    /// Replace the address set.
    pub fn set_addresses(&mut self, addrs: impl IntoIterator<Item = Address>) {
        self.addresses = addrs.into_iter().collect();
    }
}

impl Default for NextPrevTracker {
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

    // -- LocationReference tests --------------------------------------------

    #[test]
    fn location_reference_creation() {
        let lr = LocationReference::new(addr(0x1000));
        assert_eq!(*lr.location_of_use(), addr(0x1000));
        assert_eq!(lr.ref_type_string(), "");
        assert!(!lr.is_offcut_reference());
    }

    #[test]
    fn location_reference_with_type() {
        let lr = LocationReference::with_type(addr(0x2000), "READ", false);
        assert_eq!(lr.ref_type_string(), "READ");
    }

    #[test]
    fn location_reference_ordering() {
        let a = LocationReference::new(addr(0x100));
        let b = LocationReference::new(addr(0x200));
        assert!(a < b);
    }

    #[test]
    fn location_reference_equality() {
        let a = LocationReference::with_type(addr(0x100), "READ", false);
        let b = LocationReference::with_type(addr(0x100), "READ", false);
        let c = LocationReference::with_type(addr(0x100), "WRITE", false);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // -- LocationDescriptor tests -------------------------------------------

    #[test]
    fn descriptor_creation() {
        let d = LocationDescriptor::new(DescriptorKind::Label, addr(0x1000), "main");
        assert_eq!(*d.kind(), DescriptorKind::Label);
        assert_eq!(*d.home_address(), addr(0x1000));
        assert_eq!(d.label(), "main");
    }

    #[test]
    fn descriptor_set_references() {
        let mut d = LocationDescriptor::new(DescriptorKind::Mnemonic, addr(0x100), "mov");
        let refs = vec![
            LocationReference::new(addr(0x200)),
            LocationReference::new(addr(0x300)),
            LocationReference::new(addr(0x100)), // duplicate of address
        ];
        d.set_references(refs);
        // Sorted and deduped
        assert!(!d.references().is_empty());
    }

    #[test]
    fn descriptor_references_contain() {
        let mut d = LocationDescriptor::new(DescriptorKind::Label, addr(0x100), "x");
        d.set_references(vec![
            LocationReference::new(addr(0x200)),
            LocationReference::new(addr(0x300)),
        ]);
        assert!(d.references_contain(&addr(0x200)));
        assert!(!d.references_contain(&addr(0x500)));
    }

    #[test]
    fn descriptor_is_in_addresses() {
        let mut d = LocationDescriptor::new(DescriptorKind::Label, addr(0x100), "x");
        d.set_references(vec![LocationReference::new(addr(0x200))]);
        assert!(d.is_in_addresses(&addr(0x100))); // home
        assert!(d.is_in_addresses(&addr(0x200))); // ref
        assert!(!d.is_in_addresses(&addr(0x999)));
    }

    #[test]
    fn descriptor_remove_references() {
        let mut d = LocationDescriptor::new(DescriptorKind::Label, addr(0x100), "x");
        d.set_references(vec![
            LocationReference::new(addr(0x200)),
            LocationReference::new(addr(0x300)),
        ]);
        assert!(d.remove_references_from(&addr(0x200)));
        assert!(!d.references_contain(&addr(0x200)));
        assert!(d.references_contain(&addr(0x300)));
    }

    #[test]
    fn descriptor_remove_nonexistent() {
        let mut d = LocationDescriptor::new(DescriptorKind::Label, addr(0x100), "x");
        d.set_references(vec![LocationReference::new(addr(0x200))]);
        assert!(!d.remove_references_from(&addr(0x999)));
    }

    // -- NavigationOptions tests --------------------------------------------

    #[test]
    fn nav_options_defaults() {
        let opts = NavigationOptions::new();
        assert!(!opts.is_goto_external_program_enabled());
        assert_eq!(opts.max_search_hits(), 1000);
        assert!(opts.use_dynamic_searching());
    }

    #[test]
    fn nav_options_setters() {
        let mut opts = NavigationOptions::new();
        opts.set_goto_external_program(true);
        opts.set_max_search_hits(500);
        opts.set_use_dynamic_searching(false);
        assert!(opts.is_goto_external_program_enabled());
        assert_eq!(opts.max_search_hits(), 500);
        assert!(!opts.use_dynamic_searching());
    }

    // -- NextPrevTracker tests ----------------------------------------------

    #[test]
    fn tracker_empty() {
        let mut t = NextPrevTracker::new();
        assert!(t.is_empty());
        assert!(t.current().is_none());
        assert!(t.next().is_none());
    }

    #[test]
    fn tracker_from_addresses() {
        let t = NextPrevTracker::from_addresses(vec![addr(100), addr(200), addr(300)]);
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn tracker_next_wraps() {
        let mut t = NextPrevTracker::from_addresses(vec![addr(100), addr(200), addr(300)]);
        t.set_current(addr(300));
        let next = t.next().unwrap();
        assert_eq!(next, addr(100)); // wraps
    }

    #[test]
    fn tracker_next_advances() {
        let mut t = NextPrevTracker::from_addresses(vec![addr(100), addr(200), addr(300)]);
        t.set_current(addr(100));
        let next = t.next().unwrap();
        assert_eq!(next, addr(200));
    }

    #[test]
    fn tracker_previous_wraps() {
        let mut t = NextPrevTracker::from_addresses(vec![addr(100), addr(200), addr(300)]);
        t.set_current(addr(100));
        let prev = t.previous().unwrap();
        assert_eq!(prev, addr(300)); // wraps
    }

    #[test]
    fn tracker_previous_moves() {
        let mut t = NextPrevTracker::from_addresses(vec![addr(100), addr(200), addr(300)]);
        t.set_current(addr(300));
        let prev = t.previous().unwrap();
        assert_eq!(prev, addr(200));
    }

    #[test]
    fn tracker_clear() {
        let mut t = NextPrevTracker::from_addresses(vec![addr(100)]);
        t.set_current(addr(100));
        t.clear();
        assert!(t.is_empty());
        assert!(t.current().is_none());
    }

    #[test]
    fn tracker_set_addresses() {
        let mut t = NextPrevTracker::new();
        t.set_addresses(vec![addr(1), addr(2)]);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn tracker_single_element() {
        let mut t = NextPrevTracker::from_addresses(vec![addr(42)]);
        t.set_current(addr(42));
        // Next wraps to same
        assert_eq!(t.next(), Some(addr(42)));
        // Previous wraps to same
        assert_eq!(t.previous(), Some(addr(42)));
    }

    // -- SearchLocationContext tests ----------------------------------------

    #[test]
    fn context_empty() {
        let ctx = SearchLocationContext::empty();
        assert!(ctx.context.is_empty());
    }
}
