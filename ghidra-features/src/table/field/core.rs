//! Core data types for table columns.
//!
//! Ported from `ghidra.util.table.field`:
//! - `AddressBasedLocation` -- renderable address that handles memory, stack,
//!   register, external, and variable addresses.
//! - `ReferenceEndpoint` -- one end of a cross-reference.
//! - `IncomingReferenceEndpoint` / `OutgoingReferenceEndpoint` -- directional
//!   reference endpoints.
//! - `AddressPair` -- a (from, to) address pair for reference table models.

use ghidra_core::addr::Address;

use super::traits::{RefType, SourceType};

// ---------------------------------------------------------------------------
// AddressBasedLocation
// ---------------------------------------------------------------------------

/// A renderable address location that handles mixed address space types.
///
/// Ported from `ghidra.util.table.field.AddressBasedLocation`.  Provides
/// meaningful string rendering for memory, stack, register, external,
/// constant, and variable addresses, plus support for offset and shifted
/// references.
#[derive(Debug, Clone)]
pub struct AddressBasedLocation {
    address: Option<Address>,
    string_representation: String,
    reference_kind: ReferenceKind,
}

/// The kind of reference that produced this location (affects sort order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceKind {
    /// Not a reference destination.
    None,
    /// A normal memory reference.
    Normal,
    /// A shifted reference (address + shift).
    Shifted,
    /// An offset reference (base + offset).
    Offset,
}

impl AddressBasedLocation {
    /// Construct a null/unknown location.
    pub fn null() -> Self {
        Self {
            address: None,
            string_representation: "<NULL>".to_string(),
            reference_kind: ReferenceKind::None,
        }
    }

    /// Construct a location from an address with default rendering.
    pub fn from_address(address: Address) -> Self {
        let repr = Self::render_address(&address, ReferenceKind::None, 0);
        Self {
            address: Some(address),
            string_representation: repr,
            reference_kind: ReferenceKind::None,
        }
    }

    /// Construct a location from an address with an offset reference.
    pub fn from_offset_reference(base: Address, offset: i64) -> Self {
        let neg = offset < 0;
        let abs = if neg { -offset } else { offset } as u64;
        let sign = if neg { "-" } else { "+" };
        let repr = format!("0x{:x}{}0x{:x}", base.offset, sign, abs);
        Self {
            address: Some(base),
            string_representation: repr,
            reference_kind: ReferenceKind::Offset,
        }
    }

    /// Construct a location from a shifted reference.
    pub fn from_shifted_reference(address: Address, value: u64, shift: u32) -> Self {
        let repr = format!("0x{:x}(0x{:x}<<{})", address.offset, value, shift);
        Self {
            address: Some(address),
            string_representation: repr,
            reference_kind: ReferenceKind::Shifted,
        }
    }

    /// Construct a stack address location.
    pub fn from_stack(offset: i32) -> Self {
        let neg = offset < 0;
        let abs = if neg { -offset } else { offset } as u32;
        let sign = if neg { "-" } else { "+" };
        let repr = format!("Stack[{}0x{:x}]", sign, abs);
        Self {
            address: None,
            string_representation: repr,
            reference_kind: ReferenceKind::None,
        }
    }

    /// Construct an external address location.
    pub fn from_external(name: &str) -> Self {
        Self {
            address: None,
            string_representation: format!("External[{}]", name),
            reference_kind: ReferenceKind::None,
        }
    }

    /// Construct a register location.
    pub fn from_register(reg_name: &str) -> Self {
        Self {
            address: None,
            string_representation: format!("Register[{}]", reg_name),
            reference_kind: ReferenceKind::None,
        }
    }

    /// Construct a variable location.
    pub fn variable() -> Self {
        Self {
            address: None,
            string_representation: "<VARIABLE>".to_string(),
            reference_kind: ReferenceKind::None,
        }
    }

    /// Construct a constant address location.
    pub fn from_constant(offset: i32) -> Self {
        let neg = offset < 0;
        let abs = if neg { -offset } else { offset } as u32;
        let sign = if neg { "-" } else { "+" };
        let repr = format!("Constant[{}0x{:x}]", sign, abs);
        Self {
            address: None,
            string_representation: repr,
            reference_kind: ReferenceKind::None,
        }
    }

    /// Construct a location with explicit address and string representation.
    pub fn with_representation(address: Option<Address>, representation: impl Into<String>,
                               kind: ReferenceKind) -> Self {
        Self {
            address,
            string_representation: representation.into(),
            reference_kind: kind,
        }
    }

    /// Returns the underlying address, if any.
    pub fn address(&self) -> Option<Address> {
        self.address
    }

    /// Returns true if this location has a memory address.
    pub fn is_memory_location(&self) -> bool {
        self.address.is_some()
    }

    /// Returns true if this location corresponds to a shifted reference.
    pub fn is_shifted_address(&self) -> bool {
        self.reference_kind == ReferenceKind::Shifted
    }

    /// Returns true if this location corresponds to an offset reference.
    pub fn is_offset_address(&self) -> bool {
        self.reference_kind == ReferenceKind::Offset
    }

    /// Returns the reference kind.
    pub fn reference_kind(&self) -> ReferenceKind {
        self.reference_kind
    }

    fn render_address(address: &Address, _kind: ReferenceKind, _extra: u64) -> String {
        format!("0x{:x}", address.offset)
    }
}

impl std::fmt::Display for AddressBasedLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.string_representation)
    }
}

impl PartialEq for AddressBasedLocation {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
            && self.string_representation == other.string_representation
    }
}

impl Eq for AddressBasedLocation {}

impl PartialOrd for AddressBasedLocation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AddressBasedLocation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Null addresses sort first
        match (&self.address, &other.address) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(a), Some(b)) => {
                let rc = a.offset.cmp(&b.offset);
                if rc != std::cmp::Ordering::Equal {
                    return rc;
                }
                // Same address: sort by reference kind
                // Normal < Shifted < Offset
                let self_ord = match self.reference_kind {
                    ReferenceKind::None | ReferenceKind::Normal => 0,
                    ReferenceKind::Shifted => 1,
                    ReferenceKind::Offset => 2,
                };
                let other_ord = match other.reference_kind {
                    ReferenceKind::None | ReferenceKind::Normal => 0,
                    ReferenceKind::Shifted => 1,
                    ReferenceKind::Offset => 2,
                };
                self_ord.cmp(&other_ord)
                    .then_with(|| self.string_representation.cmp(&other.string_representation))
            }
        }
    }
}

impl std::hash::Hash for AddressBasedLocation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
        self.string_representation.hash(state);
    }
}

// ---------------------------------------------------------------------------
// ReferenceEndpoint
// ---------------------------------------------------------------------------

/// One end of a cross-reference, used in reference table models.
///
/// Ported from `ghidra.util.table.field.ReferenceEndpoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceEndpoint {
    address: Address,
    ref_type: RefType,
    is_offcut: bool,
    source: SourceType,
}

impl ReferenceEndpoint {
    /// Create a new reference endpoint.
    pub fn new(address: Address, ref_type: RefType, is_offcut: bool, source: SourceType) -> Self {
        Self { address, ref_type, is_offcut, source }
    }

    /// Returns the address of this endpoint.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns the reference type.
    pub fn reference_type(&self) -> RefType {
        self.ref_type
    }

    /// Returns true if this is an offcut (partial) reference.
    pub fn is_offcut(&self) -> bool {
        self.is_offcut
    }

    /// Returns the source of the reference.
    pub fn source(&self) -> SourceType {
        self.source
    }
}

// ---------------------------------------------------------------------------
// IncomingReferenceEndpoint
// ---------------------------------------------------------------------------

/// An incoming reference endpoint (the "from" side of a reference TO a target).
///
/// Ported from `ghidra.util.table.field.IncomingReferenceEndpoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingReferenceEndpoint {
    inner: ReferenceEndpoint,
}

impl IncomingReferenceEndpoint {
    /// Create a new incoming reference endpoint.
    pub fn new(address: Address, ref_type: RefType, is_offcut: bool, source: SourceType) -> Self {
        Self {
            inner: ReferenceEndpoint::new(address, ref_type, is_offcut, source),
        }
    }

    /// Returns the address of the source location.
    pub fn address(&self) -> Address {
        self.inner.address()
    }

    /// Returns the reference type.
    pub fn reference_type(&self) -> RefType {
        self.inner.reference_type()
    }

    /// Returns true if this is an offcut reference.
    pub fn is_offcut(&self) -> bool {
        self.inner.is_offcut()
    }

    /// Returns the source type.
    pub fn source(&self) -> SourceType {
        self.inner.source()
    }
}

impl AsRef<ReferenceEndpoint> for IncomingReferenceEndpoint {
    fn as_ref(&self) -> &ReferenceEndpoint {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// OutgoingReferenceEndpoint
// ---------------------------------------------------------------------------

/// An outgoing reference endpoint (the "to" side of a reference FROM a source).
///
/// Ported from `ghidra.util.table.field.OutgoingReferenceEndpoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingReferenceEndpoint {
    inner: ReferenceEndpoint,
}

impl OutgoingReferenceEndpoint {
    /// Create a new outgoing reference endpoint.
    pub fn new(address: Address, ref_type: RefType, is_offcut: bool, source: SourceType) -> Self {
        Self {
            inner: ReferenceEndpoint::new(address, ref_type, is_offcut, source),
        }
    }

    /// Returns the address of the destination location.
    pub fn address(&self) -> Address {
        self.inner.address()
    }

    /// Returns the reference type.
    pub fn reference_type(&self) -> RefType {
        self.inner.reference_type()
    }

    /// Returns true if this is an offcut reference.
    pub fn is_offcut(&self) -> bool {
        self.inner.is_offcut()
    }

    /// Returns the source type.
    pub fn source(&self) -> SourceType {
        self.inner.source()
    }
}

impl AsRef<ReferenceEndpoint> for OutgoingReferenceEndpoint {
    fn as_ref(&self) -> &ReferenceEndpoint {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// AddressPair / ReferenceAddressPair
// ---------------------------------------------------------------------------

/// A pair of (source, destination) addresses for reference table models.
///
/// Ported from `ghidra.app.plugin.core.analysis.ReferenceAddressPair`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReferenceAddressPair {
    source: Address,
    destination: Address,
}

impl ReferenceAddressPair {
    /// Create a new address pair.
    pub fn new(source: Address, destination: Address) -> Self {
        Self { source, destination }
    }

    /// Returns the source (from) address.
    pub fn source(&self) -> Address {
        self.source
    }

    /// Returns the destination (to) address.
    pub fn destination(&self) -> Address {
        self.destination
    }
}

// ---------------------------------------------------------------------------
// CodeUnitTableCellData
// ---------------------------------------------------------------------------

/// Data rendered in a code-unit table cell.
///
/// Ported from `ghidra.util.table.field.CodeUnitTableCellData`.
#[derive(Debug, Clone)]
pub struct CodeUnitTableCellData {
    /// The program location.
    pub address: Address,
    /// Number of code unit lines to display.
    pub line_count: usize,
    /// Byte offset from the code unit start.
    pub byte_offset: usize,
    /// The formatted code unit text.
    pub text: String,
}

impl CodeUnitTableCellData {
    /// Create new code unit cell data.
    pub fn new(address: Address, line_count: usize, byte_offset: usize, text: impl Into<String>) -> Self {
        Self { address, line_count, byte_offset, text: text.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_based_location_null() {
        let loc = AddressBasedLocation::null();
        assert_eq!(loc.to_string(), "<NULL>");
        assert!(loc.address().is_none());
        assert!(!loc.is_memory_location());
    }

    #[test]
    fn test_address_based_location_memory() {
        let loc = AddressBasedLocation::from_address(Address::new(0x1000));
        assert_eq!(loc.to_string(), "0x1000");
        assert!(loc.is_memory_location());
        assert_eq!(loc.address().unwrap().offset, 0x1000);
    }

    #[test]
    fn test_address_based_location_stack() {
        let loc = AddressBasedLocation::from_stack(-0x10);
        assert_eq!(loc.to_string(), "Stack[-0x10]");
    }

    #[test]
    fn test_address_based_location_external() {
        let loc = AddressBasedLocation::from_external("printf");
        assert_eq!(loc.to_string(), "External[printf]");
    }

    #[test]
    fn test_address_based_location_register() {
        let loc = AddressBasedLocation::from_register("RAX");
        assert_eq!(loc.to_string(), "Register[RAX]");
    }

    #[test]
    fn test_address_based_location_variable() {
        let loc = AddressBasedLocation::variable();
        assert_eq!(loc.to_string(), "<VARIABLE>");
    }

    #[test]
    fn test_address_based_location_constant() {
        let loc = AddressBasedLocation::from_constant(0x42);
        assert_eq!(loc.to_string(), "Constant[+0x42]");
    }

    #[test]
    fn test_address_based_location_offset_ref() {
        let loc = AddressBasedLocation::from_offset_reference(Address::new(0x1000), 0x10);
        assert_eq!(loc.to_string(), "0x1000+0x10");
        assert!(loc.is_offset_address());
    }

    #[test]
    fn test_address_based_location_shifted_ref() {
        let loc = AddressBasedLocation::from_shifted_reference(Address::new(0x2000), 0xFF, 8);
        assert_eq!(loc.to_string(), "0x2000(0xff<<8)");
        assert!(loc.is_shifted_address());
    }

    #[test]
    fn test_address_based_location_ordering() {
        let null = AddressBasedLocation::null();
        let low = AddressBasedLocation::from_address(Address::new(0x100));
        let high = AddressBasedLocation::from_address(Address::new(0x200));
        assert!(null < low);
        assert!(low < high);
    }

    #[test]
    fn test_address_based_location_same_addr_ref_ordering() {
        let normal = AddressBasedLocation::from_address(Address::new(0x1000));
        let shifted = AddressBasedLocation::from_shifted_reference(Address::new(0x1000), 0xFF, 4);
        let offset = AddressBasedLocation::from_offset_reference(Address::new(0x1000), 8);
        // Normal < Shifted < Offset
        assert!(normal < shifted);
        assert!(shifted < offset);
    }

    #[test]
    fn test_reference_endpoint() {
        let ep = ReferenceEndpoint::new(
            Address::new(0x100), RefType::Call, false, SourceType::Analysis);
        assert_eq!(ep.address().offset, 0x100);
        assert_eq!(ep.reference_type(), RefType::Call);
        assert!(!ep.is_offcut());
        assert_eq!(ep.source(), SourceType::Analysis);
    }

    #[test]
    fn test_incoming_reference_endpoint() {
        let ep = IncomingReferenceEndpoint::new(
            Address::new(0x200), RefType::Read, true, SourceType::UserDefined);
        assert_eq!(ep.address().offset, 0x200);
        assert!(ep.is_offcut());
        assert_eq!(ep.source(), SourceType::UserDefined);
    }

    #[test]
    fn test_outgoing_reference_endpoint() {
        let ep = OutgoingReferenceEndpoint::new(
            Address::new(0x300), RefType::Write, false, SourceType::Default);
        assert_eq!(ep.address().offset, 0x300);
        assert_eq!(ep.reference_type(), RefType::Write);
    }

    #[test]
    fn test_reference_address_pair() {
        let pair = ReferenceAddressPair::new(Address::new(0x100), Address::new(0x200));
        assert_eq!(pair.source().offset, 0x100);
        assert_eq!(pair.destination().offset, 0x200);
    }
}
