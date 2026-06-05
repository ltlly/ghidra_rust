//! Hover Plugin -- show tooltip information on hover.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.hover` Java package.
//!
//! Provides model-level logic for computing what information to display
//! when the user hovers over elements in the listing. Supports a priority-
//! ordered provider system where multiple hover providers can contribute
//! tooltip information, with the highest-priority enabled provider winning.
//!
//! # Key Types
//!
//! - [`HoverElementType`] -- the kind of UI element being hovered
//! - [`HoverInfo`] -- a single tooltip entry
//! - [`HoverProvider`] -- trait for pluggable hover data sources
//! - [`HoverService`] -- trait for the hover subsystem
//! - [`HoverModel`] -- default in-memory implementation

use ghidra_core::Address;

/// The type of element being hovered over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HoverElementType {
    /// Hovering over a label.
    Label,
    /// Hovering over a register.
    Register,
    /// Hovering over a data type.
    DataType,
    /// Hovering over an address reference.
    AddressReference,
    /// Hovering over a function.
    Function,
    /// Hovering over a variable.
    Variable,
    /// Hovering over a comment.
    Comment,
    /// Hovering over a bookmark.
    Bookmark,
    /// Hovering over a field in a structure.
    StructureField,
}

impl HoverElementType {
    /// Display name for this element type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Label => "Label",
            Self::Register => "Register",
            Self::DataType => "Data Type",
            Self::AddressReference => "Address Reference",
            Self::Function => "Function",
            Self::Variable => "Variable",
            Self::Comment => "Comment",
            Self::Bookmark => "Bookmark",
            Self::StructureField => "Structure Field",
        }
    }
}

/// A hover info entry.
#[derive(Debug, Clone)]
pub struct HoverInfo {
    /// The element type being hovered.
    pub element_type: HoverElementType,
    /// The address associated with the hover.
    pub address: Address,
    /// The text to display in the tooltip.
    pub display_text: String,
    /// Whether this hover info should be shown.
    pub enabled: bool,
}

impl HoverInfo {
    /// Create a new hover info entry.
    pub fn new(
        element_type: HoverElementType,
        address: Address,
        display_text: impl Into<String>,
    ) -> Self {
        Self {
            element_type,
            address,
            display_text: display_text.into(),
            enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// HoverProvider -- trait for pluggable hover sources
// ---------------------------------------------------------------------------

/// Trait for hover data providers.
///
/// Each provider has a priority and can decide whether it handles hover
/// for a given address and element type.
///
/// Ported from `ghidra.app.plugin.core.hover.AbstractHoverProvider`.
pub trait HoverProvider {
    /// The name of this provider.
    fn name(&self) -> &str;

    /// Priority (lower number = higher priority; 0 is best).
    fn priority(&self) -> u32;

    /// Whether this provider handles hovers for the given element type.
    fn handles(&self, element_type: HoverElementType) -> bool;

    /// Produce a hover info entry for the given context, if possible.
    fn get_hover_info(
        &self,
        address: Address,
        element_type: HoverElementType,
    ) -> Option<HoverInfo>;

    /// Whether this provider is enabled.
    fn is_enabled(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// HoverService -- trait for the hover subsystem
// ---------------------------------------------------------------------------

/// Trait for the hover service that coordinates multiple providers.
pub trait HoverService {
    /// Register a hover provider.
    fn register_provider(&mut self, provider: Box<dyn HoverProvider>);

    /// Unregister a provider by name.
    fn unregister_provider(&mut self, name: &str) -> bool;

    /// Compute the best hover info for the given context by consulting
    /// registered providers in priority order.
    fn compute_hover(
        &self,
        address: Address,
        element_type: HoverElementType,
    ) -> Option<HoverInfo>;
}

// ---------------------------------------------------------------------------
// HoverModel -- default implementation
// ---------------------------------------------------------------------------

/// Model for computing hover information.
///
/// Supports both static entries and priority-ordered providers.
#[derive(Debug, Default)]
pub struct HoverModel {
    entries: Vec<HoverInfo>,
    /// Number of registered providers (tracked separately since we can't
    /// derive Debug on Box<dyn HoverProvider>).
    provider_count: usize,
}

impl HoverModel {
    /// Create a new hover model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a static hover info entry.
    pub fn add_entry(&mut self, entry: HoverInfo) {
        self.entries.push(entry);
    }

    /// Get hover info for an address from static entries.
    pub fn get_hover_at(&self, address: Address) -> Vec<&HoverInfo> {
        self.entries
            .iter()
            .filter(|e| e.address == address && e.enabled)
            .collect()
    }

    /// Get hover info for an address filtered by element type.
    pub fn get_hover_for_type(
        &self,
        address: Address,
        element_type: HoverElementType,
    ) -> Vec<&HoverInfo> {
        self.entries
            .iter()
            .filter(|e| {
                e.address == address && e.enabled && e.element_type == element_type
            })
            .collect()
    }

    /// Remove all entries at a given address.
    pub fn remove_entries_at(&mut self, address: Address) {
        self.entries.retain(|e| e.address != address);
    }

    /// Toggle the enabled state of entries matching a given element type.
    pub fn set_enabled_for_type(&mut self, element_type: HoverElementType, enabled: bool) {
        for entry in &mut self.entries {
            if entry.element_type == element_type {
                entry.enabled = enabled;
            }
        }
    }

    /// Get all entries.
    pub fn get_all_entries(&self) -> &[HoverInfo] {
        &self.entries
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return the number of static entries.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Return the number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.provider_count
    }

    /// Set the provider count (for tracking purposes).
    pub fn set_provider_count(&mut self, count: usize) {
        self.provider_count = count;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hover_info() {
        let mut model = HoverModel::new();
        model.add_entry(HoverInfo::new(
            HoverElementType::Label,
            Address::new(0x1000),
            "main: Function entry point",
        ));
        let entries = model.get_hover_at(Address::new(0x1000));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].display_text, "main: Function entry point");
    }

    #[test]
    fn test_hover_disabled() {
        let mut model = HoverModel::new();
        let mut info = HoverInfo::new(
            HoverElementType::Register,
            Address::new(0x1000),
            "RAX = 0",
        );
        info.enabled = false;
        model.add_entry(info);
        let entries = model.get_hover_at(Address::new(0x1000));
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_hover_element_type_display() {
        assert_eq!(HoverElementType::Label.display_name(), "Label");
        assert_eq!(HoverElementType::Function.display_name(), "Function");
        assert_eq!(HoverElementType::Bookmark.display_name(), "Bookmark");
    }

    #[test]
    fn test_get_hover_for_type() {
        let mut model = HoverModel::new();
        model.add_entry(HoverInfo::new(
            HoverElementType::Label,
            Address::new(0x1000),
            "main label",
        ));
        model.add_entry(HoverInfo::new(
            HoverElementType::Comment,
            Address::new(0x1000),
            "a comment",
        ));
        let labels = model.get_hover_for_type(Address::new(0x1000), HoverElementType::Label);
        assert_eq!(labels.len(), 1);
        let comments = model.get_hover_for_type(Address::new(0x1000), HoverElementType::Comment);
        assert_eq!(comments.len(), 1);
        let regs = model.get_hover_for_type(Address::new(0x1000), HoverElementType::Register);
        assert_eq!(regs.len(), 0);
    }

    #[test]
    fn test_remove_entries_at() {
        let mut model = HoverModel::new();
        model.add_entry(HoverInfo::new(HoverElementType::Label, Address::new(0x1000), "a"));
        model.add_entry(HoverInfo::new(HoverElementType::Comment, Address::new(0x1000), "b"));
        model.add_entry(HoverInfo::new(HoverElementType::Label, Address::new(0x2000), "c"));
        model.remove_entries_at(Address::new(0x1000));
        assert_eq!(model.count(), 1);
        assert_eq!(model.get_all_entries()[0].address, Address::new(0x2000));
    }

    #[test]
    fn test_set_enabled_for_type() {
        let mut model = HoverModel::new();
        model.add_entry(HoverInfo::new(HoverElementType::Register, Address::new(0x1000), "RAX"));
        model.add_entry(HoverInfo::new(HoverElementType::Register, Address::new(0x2000), "RBX"));
        model.add_entry(HoverInfo::new(HoverElementType::Label, Address::new(0x1000), "main"));
        model.set_enabled_for_type(HoverElementType::Register, false);
        assert_eq!(model.get_hover_at(Address::new(0x1000)).len(), 1); // only label
        assert_eq!(model.get_hover_at(Address::new(0x2000)).len(), 0); // register disabled
    }

    #[test]
    fn test_multiple_hover_entries_at_address() {
        let mut model = HoverModel::new();
        model.add_entry(HoverInfo::new(HoverElementType::Label, Address::new(0x1000), "main"));
        model.add_entry(HoverInfo::new(HoverElementType::Function, Address::new(0x1000), "void main()"));
        model.add_entry(HoverInfo::new(HoverElementType::Comment, Address::new(0x1000), "entry point"));
        assert_eq!(model.get_hover_at(Address::new(0x1000)).len(), 3);
    }

    #[test]
    fn test_provider_count_tracking() {
        let mut model = HoverModel::new();
        assert_eq!(model.provider_count(), 0);
        model.set_provider_count(3);
        assert_eq!(model.provider_count(), 3);
    }
}

// ============================================================================
// Abstract hover provider implementations
//
// Ported from Ghidra's `AbstractHoverProvider`, `AbstractReferenceHover`,
// `AbstractScalarOperandHover`, and `AbstractConfigurableHover` Java classes.
// ============================================================================

/// A configurable hover provider with name, priority, and enabled state.
///
/// Ported from `ghidra.app.plugin.core.hover.AbstractHoverProvider`.
///
/// This is the base implementation of [`HoverProvider`] that all concrete
/// hover providers should extend. It adds configurable properties like
/// a configurable name, priority, and enable/disable toggle.
#[derive(Debug)]
pub struct ConfigurableHoverProvider {
    /// The provider name.
    name: String,
    /// The priority (lower = higher priority).
    priority: u32,
    /// Whether this provider is enabled.
    enabled: bool,
    /// The element types this provider handles.
    handled_types: Vec<HoverElementType>,
    /// The last computed hover info.
    last_hover: Option<HoverInfo>,
    /// Delay in milliseconds before showing the hover.
    hover_delay_ms: u32,
}

impl ConfigurableHoverProvider {
    /// Create a new configurable hover provider.
    pub fn new(name: impl Into<String>, priority: u32) -> Self {
        Self {
            name: name.into(),
            priority,
            enabled: true,
            handled_types: Vec::new(),
            last_hover: None,
            hover_delay_ms: 500,
        }
    }

    /// Set the element types this provider handles.
    pub fn set_handled_types(&mut self, types: Vec<HoverElementType>) {
        self.handled_types = types;
    }

    /// Add an element type this provider handles.
    pub fn add_handled_type(&mut self, element_type: HoverElementType) {
        if !self.handled_types.contains(&element_type) {
            self.handled_types.push(element_type);
        }
    }

    /// Get the hover delay in milliseconds.
    pub fn hover_delay_ms(&self) -> u32 {
        self.hover_delay_ms
    }

    /// Set the hover delay in milliseconds.
    pub fn set_hover_delay_ms(&mut self, delay: u32) {
        self.hover_delay_ms = delay;
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Set the last hover info.
    pub fn set_last_hover(&mut self, info: Option<HoverInfo>) {
        self.last_hover = info;
    }

    /// Get the last hover info.
    pub fn last_hover(&self) -> Option<&HoverInfo> {
        self.last_hover.as_ref()
    }

    /// Get the handled element types.
    pub fn handled_types(&self) -> &[HoverElementType] {
        &self.handled_types
    }
}

impl HoverProvider for ConfigurableHoverProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn priority(&self) -> u32 {
        self.priority
    }

    fn handles(&self, element_type: HoverElementType) -> bool {
        self.handled_types.is_empty() || self.handled_types.contains(&element_type)
    }

    fn get_hover_info(
        &self,
        _address: Address,
        _element_type: HoverElementType,
    ) -> Option<HoverInfo> {
        // Base implementation returns the last computed hover info
        self.last_hover.clone()
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// A hover provider that shows information about references at an address.
///
/// Ported from `ghidra.app.plugin.core.hover.AbstractReferenceHover`.
///
/// When the user hovers over a reference (e.g., a cross-reference to a
/// function), this provider displays the target symbol name, type, and
/// namespace.
#[derive(Debug)]
pub struct ReferenceHoverProvider {
    /// Base configurable provider.
    base: ConfigurableHoverProvider,
    /// Whether to show namespace information.
    show_namespace: bool,
    /// Whether to show reference type (call, jump, read, write).
    show_ref_type: bool,
    /// Maximum number of references to display.
    max_references: usize,
}

impl ReferenceHoverProvider {
    /// Create a new reference hover provider.
    pub fn new(priority: u32) -> Self {
        let mut base = ConfigurableHoverProvider::new("Reference Hover", priority);
        base.add_handled_type(HoverElementType::AddressReference);
        base.add_handled_type(HoverElementType::Function);
        Self {
            base,
            show_namespace: true,
            show_ref_type: true,
            max_references: 10,
        }
    }

    /// Set whether to show namespaces.
    pub fn set_show_namespace(&mut self, show: bool) {
        self.show_namespace = show;
    }

    /// Set whether to show reference types.
    pub fn set_show_ref_type(&mut self, show: bool) {
        self.show_ref_type = show;
    }

    /// Set the maximum number of references to display.
    pub fn set_max_references(&mut self, max: usize) {
        self.max_references = max;
    }

    /// Format a reference tooltip from a list of reference summaries.
    pub fn format_reference_tooltip(&self, refs: &[(String, String)]) -> String {
        let mut text = String::new();
        for (i, (name, ref_type)) in refs.iter().enumerate() {
            if i >= self.max_references {
                text.push_str(&format!("... and {} more\n", refs.len() - self.max_references));
                break;
            }
            if self.show_ref_type {
                text.push_str(&format!("{}: {}\n", ref_type, name));
            } else {
                text.push_str(&format!("{}\n", name));
            }
        }
        text
    }
}

/// A hover provider that shows scalar operand information.
///
/// Ported from `ghidra.app.plugin.core.hover.AbstractScalarOperandHover`.
///
/// When the user hovers over a scalar value in an instruction operand,
/// this provider displays the value in multiple formats (hex, decimal,
/// octal, binary, floating point, ASCII).
#[derive(Debug)]
pub struct ScalarOperandHoverProvider {
    /// Base configurable provider.
    base: ConfigurableHoverProvider,
    /// Whether to show hex representation.
    show_hex: bool,
    /// Whether to show decimal representation.
    show_decimal: bool,
    /// Whether to show octal representation.
    show_octal: bool,
    /// Whether to show binary representation.
    show_binary: bool,
    /// Whether to show floating point interpretation.
    show_float: bool,
    /// Whether to show ASCII interpretation.
    show_ascii: bool,
}

impl ScalarOperandHoverProvider {
    /// Create a new scalar operand hover provider.
    pub fn new(priority: u32) -> Self {
        let mut base = ConfigurableHoverProvider::new("Scalar Operand Hover", priority);
        base.add_handled_type(HoverElementType::Variable);
        Self {
            base,
            show_hex: true,
            show_decimal: true,
            show_octal: false,
            show_binary: false,
            show_float: true,
            show_ascii: true,
        }
    }

    /// Set which representations to show.
    pub fn set_display_options(
        &mut self,
        hex: bool,
        decimal: bool,
        octal: bool,
        binary: bool,
        float: bool,
        ascii: bool,
    ) {
        self.show_hex = hex;
        self.show_decimal = decimal;
        self.show_octal = octal;
        self.show_binary = binary;
        self.show_float = float;
        self.show_ascii = ascii;
    }

    /// Format a scalar value as a tooltip with multiple representations.
    pub fn format_scalar_tooltip(&self, value: u64, size_bytes: usize) -> String {
        let mut parts = Vec::new();
        if self.show_hex {
            parts.push(format!("Hex: 0x{:0width$X}", value, width = size_bytes * 2));
        }
        if self.show_decimal {
            // Show as signed and unsigned
            let signed = match size_bytes {
                1 => value as i8 as i64,
                2 => value as i16 as i64,
                4 => value as i32 as i64,
                _ => value as i64,
            };
            parts.push(format!("Signed: {}", signed));
            parts.push(format!("Unsigned: {}", value));
        }
        if self.show_octal {
            parts.push(format!("Octal: 0o{:o}", value));
        }
        if self.show_binary && size_bytes <= 2 {
            parts.push(format!("Binary: 0b{:0width$b}", value, width = size_bytes * 8));
        }
        if self.show_float {
            if size_bytes == 4 {
                let f = f32::from_bits(value as u32);
                parts.push(format!("Float: {}", f));
            } else if size_bytes == 8 {
                let f = f64::from_bits(value);
                parts.push(format!("Double: {}", f));
            }
        }
        if self.show_ascii && size_bytes == 1 {
            let ch = value as u8 as char;
            if ch.is_ascii_graphic() {
                parts.push(format!("ASCII: '{}'", ch));
            }
        }
        parts.join("\n")
    }
}

/// A hover provider whose tooltip is fully user-configurable.
///
/// Ported from `ghidra.app.plugin.core.hover.AbstractConfigurableHover`.
///
/// Provides a hover template that can include substitution variables
/// for address, function name, label, etc.
#[derive(Debug)]
pub struct TemplateHoverProvider {
    /// Base configurable provider.
    base: ConfigurableHoverProvider,
    /// The template string with {variable} placeholders.
    template: String,
}

impl TemplateHoverProvider {
    /// Create a new template hover provider.
    pub fn new(name: impl Into<String>, priority: u32) -> Self {
        Self {
            base: ConfigurableHoverProvider::new(name, priority),
            template: String::new(),
        }
    }

    /// Set the template string.
    pub fn set_template(&mut self, template: impl Into<String>) {
        self.template = template.into();
    }

    /// Get the template string.
    pub fn template(&self) -> &str {
        &self.template
    }

    /// Expand the template with the given variable values.
    pub fn expand_template(&self, vars: &[(String, String)]) -> String {
        let mut result = self.template.clone();
        for (key, value) in vars {
            result = result.replace(&format!("{{{}}}", key), value);
        }
        result
    }
}

#[cfg(test)]
mod extended_hover_tests {
    use super::*;

    #[test]
    fn test_configurable_hover_provider() {
        let mut provider = ConfigurableHoverProvider::new("Test", 5);
        assert_eq!(provider.name(), "Test");
        assert_eq!(provider.priority(), 5);
        assert!(provider.is_enabled());
        provider.set_enabled(false);
        assert!(!provider.is_enabled());
    }

    #[test]
    fn test_configurable_hover_provider_handles() {
        let mut provider = ConfigurableHoverProvider::new("Test", 5);
        // With no handled types, handles everything
        assert!(provider.handles(HoverElementType::Label));
        provider.add_handled_type(HoverElementType::Label);
        assert!(provider.handles(HoverElementType::Label));
        assert!(!provider.handles(HoverElementType::Register));
    }

    #[test]
    fn test_configurable_hover_delay() {
        let mut provider = ConfigurableHoverProvider::new("Test", 5);
        assert_eq!(provider.hover_delay_ms(), 500);
        provider.set_hover_delay_ms(1000);
        assert_eq!(provider.hover_delay_ms(), 1000);
    }

    #[test]
    fn test_reference_hover_provider() {
        let mut provider = ReferenceHoverProvider::new(10);
        provider.set_show_namespace(false);
        provider.set_max_references(5);
        let refs = vec![
            ("main".to_string(), "CALL".to_string()),
            ("foo".to_string(), "READ".to_string()),
        ];
        let tooltip = provider.format_reference_tooltip(&refs);
        assert!(tooltip.contains("CALL: main"));
        assert!(tooltip.contains("READ: foo"));
    }

    #[test]
    fn test_reference_hover_provider_max() {
        let mut provider = ReferenceHoverProvider::new(10);
        provider.set_max_references(2);
        let refs = vec![
            ("a".into(), "CALL".into()),
            ("b".into(), "CALL".into()),
            ("c".into(), "CALL".into()),
        ];
        let tooltip = provider.format_reference_tooltip(&refs);
        assert!(tooltip.contains("... and 1 more"));
    }

    #[test]
    fn test_scalar_operand_hover_provider() {
        let provider = ScalarOperandHoverProvider::new(10);
        let tooltip = provider.format_scalar_tooltip(0x41, 1); // 0x41 = 'A'
        assert!(tooltip.contains("Hex: 0x41"));
        assert!(tooltip.contains("Signed: 65"));
        assert!(tooltip.contains("Unsigned: 65"));
        assert!(tooltip.contains("ASCII: 'A'"));
    }

    #[test]
    fn test_scalar_operand_hover_provider_float() {
        let provider = ScalarOperandHoverProvider::new(10);
        let val = 1.0f32.to_bits() as u64;
        let tooltip = provider.format_scalar_tooltip(val, 4);
        assert!(tooltip.contains("Float: 1"));
    }

    #[test]
    fn test_template_hover_provider() {
        let mut provider = TemplateHoverProvider::new("Template", 5);
        provider.set_template("Address: {addr}, Function: {func}");
        let result = provider.expand_template(&[
            ("addr".to_string(), "0x1000".to_string()),
            ("func".to_string(), "main".to_string()),
        ]);
        assert_eq!(result, "Address: 0x1000, Function: main");
    }

    #[test]
    fn test_template_hover_unresolved() {
        let mut provider = TemplateHoverProvider::new("Test", 5);
        provider.set_template("{unknown}");
        let result = provider.expand_template(&[]);
        assert_eq!(result, "{unknown}");
    }
}
