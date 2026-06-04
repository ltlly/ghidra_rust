//! Location references -- ported from Ghidra's
//! `ghidra.app.plugin.core.navigation.locationreferences` package.
//!
//! Provides the "Find References To" infrastructure: descriptors that
//! know how to identify and collect references to data types, addresses,
//! labels, mnemonics, operands, function parameters, etc.
//!
//! - [`LocationDescriptor`] -- base trait for all descriptors
//! - [`LocationReference`] -- a single reference (address + metadata)
//! - [`LocationReferencesPlugin`] -- plugin coordinating the feature
//!
//! The many Java subclasses (AddressLocationDescriptor, DataTypeLocationDescriptor,
//! etc.) are unified via the [`DescriptorKind`] enum.

use std::collections::HashSet;

use ghidra_core::Address;

// ---------------------------------------------------------------------------
// LocationReference
// ---------------------------------------------------------------------------

/// A reference to an item of interest at a specific address.
///
/// Contains the "from" address where the reference is used, optional
/// reference type metadata, and whether the reference is offcut (refers
/// to the interior of a code unit).
#[derive(Debug, Clone)]
pub struct LocationReference {
    /// The address where the referenced item is used (the "from" address).
    location_of_use: Address,
    /// Type of reference (e.g., "READ", "WRITE", "CALL").
    ref_type: String,
    /// Whether this is an offcut reference (interior of a code unit).
    is_offcut: bool,
    /// Optional field name.
    field_name: Option<String>,
    /// Optional context string (e.g., a code snippet or signature match).
    context: Option<String>,
    /// Cached hash code.
    hash: Option<u64>,
}

impl LocationReference {
    /// Create a new location reference with just an address.
    pub fn new(location_of_use: Address) -> Self {
        Self {
            location_of_use,
            ref_type: String::new(),
            is_offcut: false,
            field_name: None,
            context: None,
            hash: None,
        }
    }

    /// Create a reference with type information.
    pub fn with_ref_type(
        location_of_use: Address,
        ref_type: impl Into<String>,
        is_offcut: bool,
    ) -> Self {
        Self {
            location_of_use,
            ref_type: ref_type.into(),
            is_offcut,
            field_name: None,
            context: None,
            hash: None,
        }
    }

    /// Create a reference with a field name.
    pub fn with_field_name(
        location_of_use: Address,
        ref_type: impl Into<String>,
        is_offcut: bool,
        field_name: impl Into<String>,
    ) -> Self {
        Self {
            location_of_use,
            ref_type: ref_type.into(),
            is_offcut,
            field_name: Some(field_name.into()),
            context: None,
            hash: None,
        }
    }

    /// Create a reference with context.
    pub fn with_context(
        location_of_use: Address,
        context: impl Into<String>,
    ) -> Self {
        Self {
            location_of_use,
            ref_type: String::new(),
            is_offcut: false,
            field_name: None,
            context: Some(context.into()),
            hash: None,
        }
    }

    /// The address where the referenced item is used.
    pub fn location_of_use(&self) -> Address {
        self.location_of_use
    }

    /// The reference type string (empty if unknown).
    pub fn ref_type_string(&self) -> &str {
        &self.ref_type
    }

    /// Whether this is an offcut reference.
    pub fn is_offcut_reference(&self) -> bool {
        self.is_offcut
    }

    /// The optional field name.
    pub fn field_name(&self) -> Option<&str> {
        self.field_name.as_deref()
    }

    /// The optional context string.
    pub fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }
}

impl PartialEq for LocationReference {
    fn eq(&self, other: &Self) -> bool {
        self.location_of_use == other.location_of_use
            && self.ref_type == other.ref_type
            && self.is_offcut == other.is_offcut
            && self.context == other.context
    }
}

impl Eq for LocationReference {}

impl std::hash::Hash for LocationReference {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.location_of_use.hash(state);
        self.ref_type.hash(state);
    }
}

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

impl std::fmt::Display for LocationReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ address: {}", self.location_of_use)?;
        if !self.ref_type.is_empty() {
            write!(f, ", refType: {}", self.ref_type)?;
        }
        write!(f, ", isOffcut: {}", self.is_offcut)?;
        if let Some(ref ctx) = self.context {
            write!(f, ", context: {}", ctx)?;
        }
        write!(f, " }}")
    }
}

// ---------------------------------------------------------------------------
// DescriptorKind
// ---------------------------------------------------------------------------

/// The kind of item being described by a location descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DescriptorKind {
    /// References to an address.
    Address,
    /// References to a data type applied at locations.
    DataType,
    /// References to a label (symbol name).
    Label,
    /// References to a mnemonic (instruction or data).
    Mnemonic,
    /// References to an operand.
    Operand,
    /// References to a function signature field.
    FunctionSignature,
    /// References to a function parameter name.
    FunctionParameterName,
    /// References to a function parameter type.
    FunctionParameterType,
    /// References to a function return type.
    FunctionReturnType,
    /// References to a variable name.
    VariableName,
    /// References to a variable type.
    VariableType,
    /// Cross-references to a variable.
    VariableXRef,
    /// References to a structure member.
    StructureMember,
    /// References to a union member.
    UnionMember,
    /// References to a function definition.
    FunctionDefinition,
}

impl DescriptorKind {
    /// Human-readable name for display.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Address => "Address",
            Self::DataType => "Data Type",
            Self::Label => "Label",
            Self::Mnemonic => "Mnemonic",
            Self::Operand => "Operand",
            Self::FunctionSignature => "Function Signature",
            Self::FunctionParameterName => "Function Parameter Name",
            Self::FunctionParameterType => "Function Parameter Type",
            Self::FunctionReturnType => "Function Return Type",
            Self::VariableName => "Variable Name",
            Self::VariableType => "Variable Type",
            Self::VariableXRef => "Variable XRef",
            Self::StructureMember => "Structure Member",
            Self::UnionMember => "Union Member",
            Self::FunctionDefinition => "Function Definition",
        }
    }
}

impl std::fmt::Display for DescriptorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

// ---------------------------------------------------------------------------
// LocationDescriptor
// ---------------------------------------------------------------------------

/// Describes a "thing" at a program location and knows how to find
/// all references to that thing.
///
/// This is the core abstraction for the "Find References To" feature.
/// A descriptor is created from a [`ProgramLocation`] and a program,
/// then queried to collect all [`LocationReference`]s that point to
/// the same underlying entity.
#[derive(Debug, Clone)]
pub struct LocationDescriptor {
    /// The kind of entity being described.
    kind: DescriptorKind,
    /// The "home" address of the entity.
    home_address: Address,
    /// A human-readable label for the entity.
    label: String,
    /// The program name.
    program_name: String,
    /// Collected references (cached).
    references: Option<Vec<LocationReference>>,
    /// Whether to use dynamic searching (find potential references,
    /// not just existing ones).
    use_dynamic_searching: bool,
}

impl LocationDescriptor {
    /// Create a new location descriptor.
    pub fn new(
        kind: DescriptorKind,
        home_address: Address,
        label: impl Into<String>,
        program_name: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            home_address,
            label: label.into(),
            program_name: program_name.into(),
            references: None,
            use_dynamic_searching: true,
        }
    }

    /// The descriptor kind.
    pub fn kind(&self) -> &DescriptorKind {
        &self.kind
    }

    /// The home address of the entity being described.
    pub fn home_address(&self) -> Address {
        self.home_address
    }

    /// The label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Whether dynamic searching is enabled.
    pub fn use_dynamic_searching(&self) -> bool {
        self.use_dynamic_searching
    }

    /// Enable or disable dynamic searching.
    pub fn set_use_dynamic_searching(&mut self, use_dynamic: bool) {
        self.use_dynamic_searching = use_dynamic;
    }

    /// Set the references for this descriptor (manual population).
    pub fn set_references(&mut self, refs: Vec<LocationReference>) {
        // Sort by address for binary search
        let mut sorted = refs;
        sorted.sort();
        sorted.dedup();
        self.references = Some(sorted);
    }

    /// Get the references, if loaded.
    pub fn references(&self) -> Option<&[LocationReference]> {
        self.references.as_deref()
    }

    /// Check if a given address is among the references or the home address.
    pub fn contains_address(&self, address: &Address) -> bool {
        if *address == self.home_address {
            return true;
        }
        if let Some(ref refs) = self.references {
            refs.binary_search_by(|r| r.location_of_use().cmp(address)).is_ok()
        } else {
            false
        }
    }

    /// Remove references from a specific address (for live updates).
    pub fn remove_references_from_address(&mut self, address: &Address) -> bool {
        if let Some(ref mut refs) = self.references {
            let before = refs.len();
            refs.retain(|r| r.location_of_use() != *address);
            refs.len() < before
        } else {
            false
        }
    }

    /// The number of references (if loaded).
    pub fn reference_count(&self) -> usize {
        self.references.as_ref().map_or(0, |r| r.len())
    }

    /// Get all unique addresses that reference the described entity.
    pub fn unique_addresses(&self) -> HashSet<Address> {
        match &self.references {
            Some(refs) => refs.iter().map(|r| r.location_of_use()).collect(),
            None => HashSet::new(),
        }
    }
}

impl std::fmt::Display for LocationDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.label)
    }
}

// ---------------------------------------------------------------------------
// LocationReferencesPlugin
// ---------------------------------------------------------------------------

/// Plugin that provides "Find References To" functionality.
///
/// Collects references for the item at the current cursor position and
/// presents them in a table.
pub struct LocationReferencesPlugin {
    /// Plugin name.
    name: String,
    /// The current descriptor (if any).
    current_descriptor: Option<LocationDescriptor>,
    /// Current program name.
    current_program: Option<String>,
    /// Events.
    events: Vec<String>,
}

impl LocationReferencesPlugin {
    /// Create a new location references plugin.
    pub fn new() -> Self {
        Self {
            name: "LocationReferencesPlugin".to_string(),
            current_descriptor: None,
            current_program: None,
            events: Vec::new(),
        }
    }

    /// Plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.current_program = program;
    }

    /// Create a descriptor for finding references to a data type.
    pub fn find_references_to_data_type(
        &mut self,
        label: impl Into<String>,
        home_address: Address,
    ) -> Option<&LocationDescriptor> {
        let prog = self.current_program.as_deref()?;
        let descriptor = LocationDescriptor::new(
            DescriptorKind::DataType,
            home_address,
            label,
            prog,
        );
        self.current_descriptor = Some(descriptor);
        self.events.push("FindReferencesTo: DataType".to_string());
        self.current_descriptor.as_ref()
    }

    /// Create a descriptor for finding references to an address.
    pub fn find_references_to_address(
        &mut self,
        address: Address,
    ) -> Option<&LocationDescriptor> {
        let prog = self.current_program.as_deref()?;
        let label = format!("{}", address);
        let descriptor = LocationDescriptor::new(
            DescriptorKind::Address,
            address,
            label,
            prog,
        );
        self.current_descriptor = Some(descriptor);
        self.events.push("FindReferencesTo: Address".to_string());
        self.current_descriptor.as_ref()
    }

    /// Create a descriptor for finding references to a label.
    pub fn find_references_to_label(
        &mut self,
        label: impl Into<String>,
        home_address: Address,
    ) -> Option<&LocationDescriptor> {
        let prog = self.current_program.as_deref()?;
        let label_str = label.into();
        let descriptor = LocationDescriptor::new(
            DescriptorKind::Label,
            home_address,
            label_str,
            prog,
        );
        self.current_descriptor = Some(descriptor);
        self.events.push("FindReferencesTo: Label".to_string());
        self.current_descriptor.as_ref()
    }

    /// Get the current descriptor.
    pub fn current_descriptor(&self) -> Option<&LocationDescriptor> {
        self.current_descriptor.as_ref()
    }

    /// Get mutable access to the current descriptor.
    pub fn current_descriptor_mut(&mut self) -> Option<&mut LocationDescriptor> {
        self.current_descriptor.as_mut()
    }

    /// Clear the current descriptor.
    pub fn clear_descriptor(&mut self) {
        self.current_descriptor = None;
    }

    /// Get events.
    pub fn events(&self) -> &[String] {
        &self.events
    }
}

impl Default for LocationReferencesPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_location_reference_basic() {
        let lr = LocationReference::new(addr(0x1000));
        assert_eq!(lr.location_of_use(), addr(0x1000));
        assert_eq!(lr.ref_type_string(), "");
        assert!(!lr.is_offcut_reference());
        assert!(lr.field_name().is_none());
    }

    #[test]
    fn test_location_reference_with_ref_type() {
        let lr = LocationReference::with_ref_type(addr(0x1000), "READ", false);
        assert_eq!(lr.ref_type_string(), "READ");
    }

    #[test]
    fn test_location_reference_with_field_name() {
        let lr = LocationReference::with_field_name(addr(0x1000), "CALL", false, "operand1");
        assert_eq!(lr.field_name(), Some("operand1"));
    }

    #[test]
    fn test_location_reference_with_context() {
        let lr = LocationReference::with_context(addr(0x1000), "mov eax, [ebx+0x10]");
        assert_eq!(lr.context(), Some("mov eax, [ebx+0x10]"));
    }

    #[test]
    fn test_location_reference_ordering() {
        let mut refs = vec![
            LocationReference::new(addr(0x3000)),
            LocationReference::new(addr(0x1000)),
            LocationReference::new(addr(0x2000)),
        ];
        refs.sort();
        assert_eq!(refs[0].location_of_use(), addr(0x1000));
        assert_eq!(refs[1].location_of_use(), addr(0x2000));
        assert_eq!(refs[2].location_of_use(), addr(0x3000));
    }

    #[test]
    fn test_location_reference_display() {
        let lr = LocationReference::with_ref_type(addr(0x1000), "READ", false);
        let s = format!("{}", lr);
        assert!(s.contains("00001000"));
        assert!(s.contains("READ"));
    }

    #[test]
    fn test_descriptor_kind_display() {
        assert_eq!(DescriptorKind::Address.display_name(), "Address");
        assert_eq!(DescriptorKind::DataType.display_name(), "Data Type");
        assert_eq!(format!("{}", DescriptorKind::Label), "Label");
    }

    #[test]
    fn test_location_descriptor_basic() {
        let desc = LocationDescriptor::new(
            DescriptorKind::Address,
            addr(0x1000),
            "main",
            "test.exe",
        );
        assert_eq!(desc.kind(), &DescriptorKind::Address);
        assert_eq!(desc.home_address(), addr(0x1000));
        assert_eq!(desc.label(), "main");
        assert_eq!(desc.program_name(), "test.exe");
        assert!(desc.references().is_none());
        assert_eq!(desc.reference_count(), 0);
    }

    #[test]
    fn test_location_descriptor_set_references() {
        let mut desc = LocationDescriptor::new(
            DescriptorKind::Address,
            addr(0x1000),
            "main",
            "test.exe",
        );
        let refs = vec![
            LocationReference::new(addr(0x3000)),
            LocationReference::new(addr(0x1000)),
            LocationReference::new(addr(0x2000)),
        ];
        desc.set_references(refs);

        assert_eq!(desc.reference_count(), 3);
        // Should be sorted
        let addrs: Vec<_> = desc
            .references()
            .unwrap()
            .iter()
            .map(|r| r.location_of_use())
            .collect();
        assert_eq!(addrs, vec![addr(0x1000), addr(0x2000), addr(0x3000)]);
    }

    #[test]
    fn test_location_descriptor_contains_address() {
        let mut desc = LocationDescriptor::new(
            DescriptorKind::Address,
            addr(0x1000),
            "main",
            "test.exe",
        );
        let refs = vec![
            LocationReference::new(addr(0x2000)),
            LocationReference::new(addr(0x3000)),
        ];
        desc.set_references(refs);

        assert!(desc.contains_address(&addr(0x1000))); // home
        assert!(desc.contains_address(&addr(0x2000))); // in refs
        assert!(desc.contains_address(&addr(0x3000))); // in refs
        assert!(!desc.contains_address(&addr(0x4000))); // not found
    }

    #[test]
    fn test_location_descriptor_remove_references() {
        let mut desc = LocationDescriptor::new(
            DescriptorKind::Address,
            addr(0x1000),
            "main",
            "test.exe",
        );
        let refs = vec![
            LocationReference::new(addr(0x2000)),
            LocationReference::new(addr(0x3000)),
        ];
        desc.set_references(refs);

        assert!(desc.remove_references_from_address(&addr(0x2000)));
        assert_eq!(desc.reference_count(), 1);
        assert!(!desc.contains_address(&addr(0x2000)));
    }

    #[test]
    fn test_location_descriptor_unique_addresses() {
        let mut desc = LocationDescriptor::new(
            DescriptorKind::Label,
            addr(0x1000),
            "my_func",
            "test.exe",
        );
        let refs = vec![
            LocationReference::with_ref_type(addr(0x2000), "READ", false),
            LocationReference::with_ref_type(addr(0x2000), "WRITE", false), // same addr, different type
            LocationReference::new(addr(0x3000)),
        ];
        desc.set_references(refs);

        let unique = desc.unique_addresses();
        assert_eq!(unique.len(), 2);
        assert!(unique.contains(&addr(0x2000)));
        assert!(unique.contains(&addr(0x3000)));
    }

    #[test]
    fn test_location_descriptor_display() {
        let desc = LocationDescriptor::new(
            DescriptorKind::DataType,
            addr(0x1000),
            "int",
            "test.exe",
        );
        let s = format!("{}", desc);
        assert!(s.contains("Data Type"));
        assert!(s.contains("int"));
    }

    #[test]
    fn test_location_references_plugin_basic() {
        let mut plugin = LocationReferencesPlugin::new();
        assert_eq!(plugin.name(), "LocationReferencesPlugin");
        assert!(plugin.current_descriptor().is_none());
    }

    #[test]
    fn test_location_references_plugin_find_address() {
        let mut plugin = LocationReferencesPlugin::new();
        plugin.set_program(Some("test.exe".into()));

        let desc = plugin.find_references_to_address(addr(0x401000));
        assert!(desc.is_some());
        assert_eq!(desc.unwrap().kind(), &DescriptorKind::Address);
        assert_eq!(desc.unwrap().home_address(), addr(0x401000));
    }

    #[test]
    fn test_location_references_plugin_find_label() {
        let mut plugin = LocationReferencesPlugin::new();
        plugin.set_program(Some("test.exe".into()));

        let desc = plugin.find_references_to_label("main", addr(0x401000));
        assert!(desc.is_some());
        assert_eq!(desc.unwrap().kind(), &DescriptorKind::Label);
        assert_eq!(desc.unwrap().label(), "main");
    }

    #[test]
    fn test_location_references_plugin_find_data_type() {
        let mut plugin = LocationReferencesPlugin::new();
        plugin.set_program(Some("test.exe".into()));

        let desc = plugin.find_references_to_data_type("int", addr(0x1000));
        assert!(desc.is_some());
        assert_eq!(desc.unwrap().kind(), &DescriptorKind::DataType);
    }

    #[test]
    fn test_location_references_plugin_no_program() {
        let mut plugin = LocationReferencesPlugin::new();
        let desc = plugin.find_references_to_address(addr(0x401000));
        assert!(desc.is_none());
    }

    #[test]
    fn test_location_references_plugin_clear() {
        let mut plugin = LocationReferencesPlugin::new();
        plugin.set_program(Some("test.exe".into()));
        plugin.find_references_to_address(addr(0x401000));
        assert!(plugin.current_descriptor().is_some());

        plugin.clear_descriptor();
        assert!(plugin.current_descriptor().is_none());
    }

    #[test]
    fn test_location_references_plugin_events() {
        let mut plugin = LocationReferencesPlugin::new();
        plugin.set_program(Some("test.exe".into()));
        plugin.find_references_to_address(addr(0x401000));
        plugin.find_references_to_label("main", addr(0x401000));

        assert_eq!(plugin.events().len(), 2);
        assert!(plugin.events()[0].contains("Address"));
        assert!(plugin.events()[1].contains("Label"));
    }
}
