//! Address-type overview color service -- ported from Ghidra's
//! `ghidra.app.plugin.core.overview.addresstype` Java package.
//!
//! Maps each address in a program to a color based on the type of
//! content at that address: function, instruction, data, undefined,
//! uninitialized, or external reference.

use ghidra_core::Address;

use super::{OverviewColorService, RgbColor};

/// The different address types that have unique overview colors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    /// The address is the entry point of a function.
    Function,
    /// The address contains uninitialized memory.
    Uninitialized,
    /// The address is an external reference location.
    ExternalRef,
    /// The address contains an instruction.
    Instruction,
    /// The address contains defined data.
    Data,
    /// The address is undefined (neither code nor data).
    Undefined,
}

impl AddressType {
    /// Return a human-readable description of this address type.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Function => "Function",
            Self::Uninitialized => "Uninitialized",
            Self::ExternalRef => "External Reference",
            Self::Instruction => "Instruction",
            Self::Data => "Data",
            Self::Undefined => "Undefined",
        }
    }
}

impl std::fmt::Display for AddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.description())
    }
}

/// Color assigned to each address type in the overview bar.
pub fn color_for_type(at: AddressType) -> RgbColor {
    match at {
        AddressType::Function => RgbColor::new(0x00, 0x90, 0x00),      // green
        AddressType::Instruction => RgbColor::new(0xCC, 0xCC, 0xCC),   // light gray
        AddressType::Data => RgbColor::new(0x60, 0x60, 0xFF),          // blue
        AddressType::Undefined => RgbColor::new(0x80, 0x40, 0x00),     // brown
        AddressType::Uninitialized => RgbColor::new(0x40, 0x40, 0x40), // dark gray
        AddressType::ExternalRef => RgbColor::new(0xFF, 0xFF, 0x00),   // yellow
    }
}

/// Color service based on the type of content at each address.
///
/// Queries the listing to determine if each address is a function entry,
/// instruction, data, etc., and returns the corresponding color.
pub struct AddressTypeOverviewColorService {
    program_name: Option<String>,
    /// Mapping function: given an address, return its type.
    /// In a real Ghidra integration this would query the listing.
    type_resolver: Option<Box<dyn Fn(&Address) -> AddressType + Send + Sync>>,
}

impl AddressTypeOverviewColorService {
    /// Create a new service with no program loaded.
    pub fn new() -> Self {
        Self {
            program_name: None,
            type_resolver: None,
        }
    }

    /// Set a custom type resolver function.
    pub fn set_type_resolver(
        &mut self,
        resolver: Box<dyn Fn(&Address) -> AddressType + Send + Sync>,
    ) {
        self.type_resolver = Some(resolver);
    }

    /// Classify an address into its type using the resolver, defaulting
    /// to [`AddressType::Undefined`] if no resolver is set.
    pub fn classify(&self, address: &Address) -> AddressType {
        if let Some(ref resolver) = self.type_resolver {
            resolver(address)
        } else {
            AddressType::Undefined
        }
    }
}

impl Default for AddressTypeOverviewColorService {
    fn default() -> Self {
        Self::new()
    }
}

impl OverviewColorService for AddressTypeOverviewColorService {
    fn name(&self) -> &str {
        "Address Type"
    }

    fn get_color(&self, address: &Address) -> RgbColor {
        color_for_type(self.classify(address))
    }

    fn set_program(&mut self, program_name: Option<String>) {
        self.program_name = program_name;
    }

    fn get_program(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    fn get_tooltip_text(&self, address: &Address) -> String {
        let at = self.classify(address);
        format!("{}: {}", at.description(), address)
    }

    fn initialize(&mut self) {
        // No options to read for this service.
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_address_type_descriptions() {
        assert_eq!(AddressType::Function.description(), "Function");
        assert_eq!(AddressType::Instruction.description(), "Instruction");
        assert_eq!(AddressType::Data.description(), "Data");
        assert_eq!(AddressType::Undefined.description(), "Undefined");
        assert_eq!(AddressType::Uninitialized.description(), "Uninitialized");
        assert_eq!(AddressType::ExternalRef.description(), "External Reference");
    }

    #[test]
    fn test_address_type_display() {
        assert_eq!(format!("{}", AddressType::Function), "Function");
    }

    #[test]
    fn test_color_for_type_distinct() {
        let colors = [
            color_for_type(AddressType::Function),
            color_for_type(AddressType::Instruction),
            color_for_type(AddressType::Data),
            color_for_type(AddressType::Undefined),
            color_for_type(AddressType::Uninitialized),
            color_for_type(AddressType::ExternalRef),
        ];
        // All colors should be distinct
        for i in 0..colors.len() {
            for j in (i + 1)..colors.len() {
                assert_ne!(colors[i], colors[j], "colors[{}] == colors[{}]", i, j);
            }
        }
    }

    #[test]
    fn test_service_default_classification() {
        let svc = AddressTypeOverviewColorService::new();
        let addr = Address::new(0x401000);
        assert_eq!(svc.classify(&addr), AddressType::Undefined);
    }

    #[test]
    fn test_service_custom_resolver() {
        let mut svc = AddressTypeOverviewColorService::new();
        svc.set_type_resolver(Box::new(|addr| {
            if addr.offset < 0x1000 {
                AddressType::Function
            } else {
                AddressType::Instruction
            }
        }));
        let low = Address::new(0x100);
        let high = Address::new(0x2000);
        assert_eq!(svc.classify(&low), AddressType::Function);
        assert_eq!(svc.classify(&high), AddressType::Instruction);
    }

    #[test]
    fn test_service_trait_implementation() {
        let mut svc = AddressTypeOverviewColorService::new();
        assert_eq!(svc.name(), "Address Type");
        assert_eq!(svc.get_program(), None);

        svc.set_program(Some("test.exe".into()));
        assert_eq!(svc.get_program(), Some("test.exe"));

        svc.initialize(); // no-op, just ensure no panic

        let addr = Address::new(0x401000);
        let color = svc.get_color(&addr);
        assert_eq!(color, color_for_type(AddressType::Undefined));

        let tip = svc.get_tooltip_text(&addr);
        assert!(tip.contains("Undefined"));
        assert!(tip.contains("00401000"));
    }
}
