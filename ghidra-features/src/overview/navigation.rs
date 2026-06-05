//! Navigation-related overview color service.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.overview` package.
//!
//! Maps address types (defined code, defined data, undefined, functions)
//! to distinct colors for the overview bar.  This gives users a quick
//! visual sense of the program layout: code regions, data regions,
//! undefined areas, and function boundaries.

use ghidra_core::Address;

use super::{OverviewColorService, RgbColor};

// ---------------------------------------------------------------------------
// AddressType enum
// ---------------------------------------------------------------------------

/// The type of data at a given address.
///
/// Ported from the type classification logic in Ghidra's overview
/// address-type color service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    /// A defined instruction.
    Instruction,
    /// Defined data (non-instruction code unit).
    Data,
    /// An undefined byte.
    Undefined,
    /// The entry point of a function.
    FunctionEntry,
    /// Inside a function body (but not the entry point).
    FunctionBody,
}

impl AddressType {
    /// Get the color for this address type.
    pub fn color(&self) -> RgbColor {
        match self {
            Self::Instruction => RgbColor::new(0, 128, 0),       // green
            Self::Data => RgbColor::new(0, 0, 200),               // blue
            Self::Undefined => RgbColor::new(192, 192, 192),      // light gray
            Self::FunctionEntry => RgbColor::new(200, 0, 0),      // red
            Self::FunctionBody => RgbColor::new(100, 200, 100),   // light green
        }
    }

    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Instruction => "Instruction",
            Self::Data => "Defined Data",
            Self::FunctionEntry => "Function Entry",
            Self::FunctionBody => "Function Body",
            Self::Undefined => "Undefined",
        }
    }
}

// ---------------------------------------------------------------------------
// AddressTypeColorService
// ---------------------------------------------------------------------------

/// Color service that maps addresses to colors based on their type.
///
/// Ported from Ghidra's address-type overview color service.
///
/// # Address Type Mapping
///
/// | Address Type     | Color       |
/// |------------------|-------------|
/// | Instruction      | Green       |
/// | Data             | Blue        |
/// | Function Entry   | Red         |
/// | Function Body    | Light Green |
/// | Undefined        | Light Gray  |
#[derive(Debug)]
pub struct AddressTypeColorService {
    /// Current program name.
    program_name: Option<String>,
    /// Address-to-type mapping (simulated).
    address_types: Vec<(u64, u64, AddressType)>, // (start, end, type)
}

impl AddressTypeColorService {
    /// Create a new address-type color service.
    pub fn new() -> Self {
        Self {
            program_name: None,
            address_types: Vec::new(),
        }
    }

    /// Set the address type for a range.
    pub fn set_address_type(&mut self, start: u64, end: u64, addr_type: AddressType) {
        self.address_types.push((start, end, addr_type));
    }

    /// Clear all address type mappings.
    pub fn clear(&mut self) {
        self.address_types.clear();
    }

    /// Get the address type for a given address.
    pub fn get_address_type(&self, address: u64) -> AddressType {
        for &(start, end, addr_type) in &self.address_types {
            if address >= start && address < end {
                return addr_type;
            }
        }
        AddressType::Undefined
    }
}

impl Default for AddressTypeColorService {
    fn default() -> Self {
        Self::new()
    }
}

impl OverviewColorService for AddressTypeColorService {
    fn name(&self) -> &str {
        "Address Type"
    }

    fn get_color(&self, address: &Address) -> RgbColor {
        self.get_address_type(address.offset).color()
    }

    fn set_program(&mut self, program_name: Option<String>) {
        self.program_name = program_name;
        self.address_types.clear();
    }

    fn get_program(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    fn get_tooltip_text(&self, address: &Address) -> String {
        let addr_type = self.get_address_type(address.offset);
        format!("{}: 0x{:X} - {}", addr_type.description(), address.offset, addr_type.description())
    }

    fn initialize(&mut self) {
        // Nothing to initialize in the model-only port.
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_type_colors() {
        let instr = AddressType::Instruction.color();
        assert_eq!(instr, RgbColor::new(0, 128, 0));

        let data = AddressType::Data.color();
        assert_eq!(data, RgbColor::new(0, 0, 200));

        let undef = AddressType::Undefined.color();
        assert_eq!(undef, RgbColor::new(192, 192, 192));

        let entry = AddressType::FunctionEntry.color();
        assert_eq!(entry, RgbColor::new(200, 0, 0));

        let body = AddressType::FunctionBody.color();
        assert_eq!(body, RgbColor::new(100, 200, 100));
    }

    #[test]
    fn test_address_type_description() {
        assert_eq!(AddressType::Instruction.description(), "Instruction");
        assert_eq!(AddressType::Data.description(), "Defined Data");
        assert_eq!(AddressType::Undefined.description(), "Undefined");
        assert_eq!(AddressType::FunctionEntry.description(), "Function Entry");
        assert_eq!(AddressType::FunctionBody.description(), "Function Body");
    }

    #[test]
    fn test_address_type_color_service_default() {
        let service = AddressTypeColorService::new();
        assert!(service.get_program().is_none());
        assert_eq!(service.name(), "Address Type");
    }

    #[test]
    fn test_address_type_color_service_ranges() {
        let mut service = AddressTypeColorService::new();
        service.set_address_type(0x1000, 0x1100, AddressType::Instruction);
        service.set_address_type(0x2000, 0x2100, AddressType::Data);
        service.set_address_type(0x3000, 0x3100, AddressType::FunctionEntry);

        assert_eq!(service.get_address_type(0x1050), AddressType::Instruction);
        assert_eq!(service.get_address_type(0x2050), AddressType::Data);
        assert_eq!(service.get_address_type(0x3000), AddressType::FunctionEntry);
        // Undefined range
        assert_eq!(service.get_address_type(0x5000), AddressType::Undefined);
    }

    #[test]
    fn test_address_type_color_service_set_program() {
        let mut service = AddressTypeColorService::new();
        service.set_address_type(0x1000, 0x1100, AddressType::Instruction);
        service.set_program(Some("test.exe".to_string()));
        assert_eq!(service.get_program(), Some("test.exe"));
        // Ranges should be cleared
        assert_eq!(service.get_address_type(0x1050), AddressType::Undefined);
    }

    #[test]
    fn test_address_type_color_service_clear() {
        let mut service = AddressTypeColorService::new();
        service.set_address_type(0x1000, 0x1100, AddressType::Instruction);
        assert_ne!(service.get_address_type(0x1050), AddressType::Undefined);
        service.clear();
        assert_eq!(service.get_address_type(0x1050), AddressType::Undefined);
    }

    #[test]
    fn test_address_type_color_service_tooltip() {
        let mut service = AddressTypeColorService::new();
        service.set_address_type(0x1000, 0x1100, AddressType::Instruction);
        let addr = Address::new(0x1050);
        let tooltip = service.get_tooltip_text(&addr);
        assert!(tooltip.contains("Instruction"));
    }

    #[test]
    fn test_address_type_equality() {
        assert_eq!(AddressType::Instruction, AddressType::Instruction);
        assert_ne!(AddressType::Instruction, AddressType::Data);
    }

    #[test]
    fn test_overview_color_service_trait() {
        let mut service = AddressTypeColorService::new();
        service.set_address_type(0x1000, 0x1100, AddressType::FunctionEntry);
        service.set_address_type(0x1100, 0x1200, AddressType::FunctionBody);

        let addr_entry = Address::new(0x1000);
        let color = service.get_color(&addr_entry);
        assert_eq!(color, RgbColor::new(200, 0, 0));

        let addr_body = Address::new(0x1150);
        let color = service.get_color(&addr_body);
        assert_eq!(color, RgbColor::new(100, 200, 100));
    }
}
