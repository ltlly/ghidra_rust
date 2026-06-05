//! Individual convert-to-format action implementations.
//!
//! Ported from Ghidra's 9 `ConvertTo*Action` classes in
//! `ghidra.app.plugin.core.equate`:
//!
//! - [`ConvertToBinaryAction`]
//! - [`ConvertToCharAction`]
//! - [`ConvertToSignedDecimalAction`]
//! - [`ConvertToUnsignedDecimalAction`]
//! - [`ConvertToOctalAction`]
//! - [`ConvertToSignedHexAction`]
//! - [`ConvertToUnsignedHexAction`]
//! - [`ConvertToFloatAction`]
//! - [`ConvertToDoubleAction`]
//!
//! Each action is a thin wrapper that pairs a [`ScalarFormat`] with
//! signedness and provides `name()`, `is_enabled()`, and `menu_label()`
//! methods.  The actual conversion logic lives in [`super::convert_cmd`].

use super::convert_cmd::ScalarFormat;
use super::Scalar;
use std::fmt;

// ============================================================================
// AbstractConvertActionModel -- base model for all convert actions
// ============================================================================

/// Base model for a scalar-format conversion action.
///
/// Corresponds to Ghidra's `AbstractConvertAction`.  Carries the format
/// target, signedness flag, and popup menu metadata.
#[derive(Debug, Clone)]
pub struct AbstractConvertActionModel {
    /// The target scalar format.
    pub format: ScalarFormat,
    /// Whether this conversion treats the operand as signed.
    pub is_signed: bool,
    /// The popup menu path (e.g., `["Convert", "Convert to Hex (Signed)"]`).
    pub menu_path: Vec<String>,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl AbstractConvertActionModel {
    /// Create a new convert action model.
    pub fn new(format: ScalarFormat, is_signed: bool) -> Self {
        let label = menu_label_for_format(format, is_signed);
        Self {
            format,
            is_signed,
            menu_path: vec!["Convert".to_string(), label],
            enabled: true,
        }
    }

    /// Check whether the action is applicable to the given scalar.
    ///
    /// The action is enabled when:
    /// - The format is valid for the scalar's bit-length, AND
    /// - The scalar's signedness matches (or the format is
    ///   sign-agnostic like Binary/Octal/Char).
    pub fn is_applicable(&self, scalar: &Scalar) -> bool {
        // Float and double require specific bit-lengths.
        match self.format {
            ScalarFormat::Float => scalar.bit_length() == 32,
            ScalarFormat::Double => scalar.bit_length() == 64,
            _ => true,
        }
    }

    /// Returns the menu item label including the current value preview.
    ///
    /// In Ghidra this would call `getMenuName()` which formats the
    /// scalar value using the target format and appends it to the menu
    /// label in parentheses.
    pub fn menu_label_with_value(&self, scalar: &Scalar) -> String {
        let formatted = super::convert_cmd::format_scalar_value(scalar, self.format);
        format!("{} ({})", self.menu_path.last().unwrap(), formatted)
    }
}

impl fmt::Display for AbstractConvertActionModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Convert to {}", self.format.name())
    }
}

// ============================================================================
// Concrete action structs
// ============================================================================

/// Convert to unsigned hexadecimal.
///
/// Ported from `ConvertToUnsignedHexAction.java`.
#[derive(Debug, Clone)]
pub struct ConvertToUnsignedHexAction {
    inner: AbstractConvertActionModel,
}

impl ConvertToUnsignedHexAction {
    pub fn new() -> Self {
        Self {
            inner: AbstractConvertActionModel::new(ScalarFormat::UnsignedHex, false),
        }
    }

    pub fn format(&self) -> ScalarFormat {
        self.inner.format
    }

    pub fn is_signed(&self) -> bool {
        self.inner.is_signed
    }

    pub fn menu_label(&self) -> &str {
        &self.inner.menu_path[1]
    }

    pub fn is_applicable(&self, scalar: &Scalar) -> bool {
        self.inner.is_applicable(scalar)
    }
}

impl Default for ConvertToUnsignedHexAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert to signed hexadecimal.
///
/// Ported from `ConvertToSignedHexAction.java`.
#[derive(Debug, Clone)]
pub struct ConvertToSignedHexAction {
    inner: AbstractConvertActionModel,
}

impl ConvertToSignedHexAction {
    pub fn new() -> Self {
        Self {
            inner: AbstractConvertActionModel::new(ScalarFormat::SignedHex, true),
        }
    }

    pub fn format(&self) -> ScalarFormat {
        self.inner.format
    }

    pub fn is_signed(&self) -> bool {
        self.inner.is_signed
    }

    pub fn menu_label(&self) -> &str {
        &self.inner.menu_path[1]
    }

    pub fn is_applicable(&self, scalar: &Scalar) -> bool {
        self.inner.is_applicable(scalar)
    }
}

impl Default for ConvertToSignedHexAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert to unsigned decimal.
///
/// Ported from `ConvertToUnsignedDecimalAction.java`.
#[derive(Debug, Clone)]
pub struct ConvertToUnsignedDecimalAction {
    inner: AbstractConvertActionModel,
}

impl ConvertToUnsignedDecimalAction {
    pub fn new() -> Self {
        Self {
            inner: AbstractConvertActionModel::new(ScalarFormat::UnsignedDecimal, false),
        }
    }

    pub fn format(&self) -> ScalarFormat {
        self.inner.format
    }

    pub fn is_signed(&self) -> bool {
        self.inner.is_signed
    }

    pub fn menu_label(&self) -> &str {
        &self.inner.menu_path[1]
    }

    pub fn is_applicable(&self, scalar: &Scalar) -> bool {
        self.inner.is_applicable(scalar)
    }
}

impl Default for ConvertToUnsignedDecimalAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert to signed decimal.
///
/// Ported from `ConvertToSignedDecimalAction.java`.
#[derive(Debug, Clone)]
pub struct ConvertToSignedDecimalAction {
    inner: AbstractConvertActionModel,
}

impl ConvertToSignedDecimalAction {
    pub fn new() -> Self {
        Self {
            inner: AbstractConvertActionModel::new(ScalarFormat::SignedDecimal, true),
        }
    }

    pub fn format(&self) -> ScalarFormat {
        self.inner.format
    }

    pub fn is_signed(&self) -> bool {
        self.inner.is_signed
    }

    pub fn menu_label(&self) -> &str {
        &self.inner.menu_path[1]
    }

    pub fn is_applicable(&self, scalar: &Scalar) -> bool {
        self.inner.is_applicable(scalar)
    }
}

impl Default for ConvertToSignedDecimalAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert to octal.
///
/// Ported from `ConvertToOctalAction.java`.
#[derive(Debug, Clone)]
pub struct ConvertToOctalAction {
    inner: AbstractConvertActionModel,
}

impl ConvertToOctalAction {
    pub fn new() -> Self {
        Self {
            inner: AbstractConvertActionModel::new(ScalarFormat::Octal, false),
        }
    }

    pub fn format(&self) -> ScalarFormat {
        self.inner.format
    }

    pub fn is_signed(&self) -> bool {
        self.inner.is_signed
    }

    pub fn menu_label(&self) -> &str {
        &self.inner.menu_path[1]
    }

    pub fn is_applicable(&self, scalar: &Scalar) -> bool {
        self.inner.is_applicable(scalar)
    }
}

impl Default for ConvertToOctalAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert to binary.
///
/// Ported from `ConvertToBinaryAction.java`.
#[derive(Debug, Clone)]
pub struct ConvertToBinaryAction {
    inner: AbstractConvertActionModel,
}

impl ConvertToBinaryAction {
    pub fn new() -> Self {
        Self {
            inner: AbstractConvertActionModel::new(ScalarFormat::Binary, false),
        }
    }

    pub fn format(&self) -> ScalarFormat {
        self.inner.format
    }

    pub fn is_signed(&self) -> bool {
        self.inner.is_signed
    }

    pub fn menu_label(&self) -> &str {
        &self.inner.menu_path[1]
    }

    pub fn is_applicable(&self, scalar: &Scalar) -> bool {
        self.inner.is_applicable(scalar)
    }
}

impl Default for ConvertToBinaryAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert to character.
///
/// Ported from `ConvertToCharAction.java`.
#[derive(Debug, Clone)]
pub struct ConvertToCharAction {
    inner: AbstractConvertActionModel,
}

impl ConvertToCharAction {
    pub fn new() -> Self {
        Self {
            inner: AbstractConvertActionModel::new(ScalarFormat::Char, false),
        }
    }

    pub fn format(&self) -> ScalarFormat {
        self.inner.format
    }

    pub fn is_signed(&self) -> bool {
        self.inner.is_signed
    }

    pub fn menu_label(&self) -> &str {
        &self.inner.menu_path[1]
    }

    pub fn is_applicable(&self, scalar: &Scalar) -> bool {
        // Char is only applicable to 8-bit scalars.
        scalar.bit_length() == 8
    }
}

impl Default for ConvertToCharAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert to float (IEEE 754 single-precision).
///
/// Ported from `ConvertToFloatAction.java`.
#[derive(Debug, Clone)]
pub struct ConvertToFloatAction {
    inner: AbstractConvertActionModel,
}

impl ConvertToFloatAction {
    pub fn new() -> Self {
        Self {
            inner: AbstractConvertActionModel::new(ScalarFormat::Float, false),
        }
    }

    pub fn format(&self) -> ScalarFormat {
        self.inner.format
    }

    pub fn is_signed(&self) -> bool {
        self.inner.is_signed
    }

    pub fn menu_label(&self) -> &str {
        &self.inner.menu_path[1]
    }

    pub fn is_applicable(&self, scalar: &Scalar) -> bool {
        scalar.bit_length() == 32
    }
}

impl Default for ConvertToFloatAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert to double (IEEE 754 double-precision).
///
/// Ported from `ConvertToDoubleAction.java`.
#[derive(Debug, Clone)]
pub struct ConvertToDoubleAction {
    inner: AbstractConvertActionModel,
}

impl ConvertToDoubleAction {
    pub fn new() -> Self {
        Self {
            inner: AbstractConvertActionModel::new(ScalarFormat::Double, false),
        }
    }

    pub fn format(&self) -> ScalarFormat {
        self.inner.format
    }

    pub fn is_signed(&self) -> bool {
        self.inner.is_signed
    }

    pub fn menu_label(&self) -> &str {
        &self.inner.menu_path[1]
    }

    pub fn is_applicable(&self, scalar: &Scalar) -> bool {
        scalar.bit_length() == 64
    }
}

impl Default for ConvertToDoubleAction {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// All convert actions as a collection
// ============================================================================

/// All 9 concrete convert actions, boxed for uniform iteration.
///
/// This mirrors Ghidra's pattern of registering all convert actions on
/// the `EquatePlugin`.
pub fn all_convert_action_models() -> Vec<AbstractConvertActionModel> {
    vec![
        ConvertToUnsignedHexAction::new().inner,
        ConvertToSignedHexAction::new().inner,
        ConvertToUnsignedDecimalAction::new().inner,
        ConvertToSignedDecimalAction::new().inner,
        ConvertToOctalAction::new().inner,
        ConvertToBinaryAction::new().inner,
        ConvertToCharAction::new().inner,
        ConvertToFloatAction::new().inner,
        ConvertToDoubleAction::new().inner,
    ]
}

/// Returns the menu label for a given format and signedness.
fn menu_label_for_format(format: ScalarFormat, is_signed: bool) -> String {
    match format {
        ScalarFormat::Binary => "Convert to Binary".to_string(),
        ScalarFormat::Char => "Convert to Char".to_string(),
        ScalarFormat::SignedDecimal => "Convert to Decimal (Signed)".to_string(),
        ScalarFormat::UnsignedDecimal => "Convert to Decimal (Unsigned)".to_string(),
        ScalarFormat::Octal => "Convert to Octal".to_string(),
        ScalarFormat::SignedHex => "Convert to Hex (Signed)".to_string(),
        ScalarFormat::UnsignedHex => "Convert to Hex (Unsigned)".to_string(),
        ScalarFormat::Float => "Convert to Float".to_string(),
        ScalarFormat::Double => "Convert to Double".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsigned_hex_action() {
        let action = ConvertToUnsignedHexAction::new();
        assert_eq!(action.format(), ScalarFormat::UnsignedHex);
        assert!(!action.is_signed());
        assert_eq!(action.menu_label(), "Convert to Hex (Unsigned)");
    }

    #[test]
    fn test_signed_hex_action() {
        let action = ConvertToSignedHexAction::new();
        assert_eq!(action.format(), ScalarFormat::SignedHex);
        assert!(action.is_signed());
        assert_eq!(action.menu_label(), "Convert to Hex (Signed)");
    }

    #[test]
    fn test_unsigned_decimal_action() {
        let action = ConvertToUnsignedDecimalAction::new();
        assert_eq!(action.format(), ScalarFormat::UnsignedDecimal);
        assert!(!action.is_signed());
    }

    #[test]
    fn test_signed_decimal_action() {
        let action = ConvertToSignedDecimalAction::new();
        assert_eq!(action.format(), ScalarFormat::SignedDecimal);
        assert!(action.is_signed());
    }

    #[test]
    fn test_octal_action() {
        let action = ConvertToOctalAction::new();
        assert_eq!(action.format(), ScalarFormat::Octal);
        assert!(!action.is_signed());
        assert_eq!(action.menu_label(), "Convert to Octal");
    }

    #[test]
    fn test_binary_action() {
        let action = ConvertToBinaryAction::new();
        assert_eq!(action.format(), ScalarFormat::Binary);
        assert!(!action.is_signed());
        assert_eq!(action.menu_label(), "Convert to Binary");
    }

    #[test]
    fn test_char_action_only_8bit() {
        let action = ConvertToCharAction::new();
        assert!(action.is_applicable(&Scalar::unsigned(8, 65))); // 'A'
        assert!(!action.is_applicable(&Scalar::unsigned(16, 65)));
    }

    #[test]
    fn test_float_action_only_32bit() {
        let action = ConvertToFloatAction::new();
        assert!(action.is_applicable(&Scalar::unsigned(32, 0x41200000)));
        assert!(!action.is_applicable(&Scalar::unsigned(64, 0x4024000000000000)));
    }

    #[test]
    fn test_double_action_only_64bit() {
        let action = ConvertToDoubleAction::new();
        assert!(action.is_applicable(&Scalar::unsigned(64, 0x4024000000000000)));
        assert!(!action.is_applicable(&Scalar::unsigned(32, 0x41200000)));
    }

    #[test]
    fn test_all_convert_action_models_count() {
        let models = all_convert_action_models();
        assert_eq!(models.len(), 9);
    }

    #[test]
    fn test_abstract_convert_action_model_display() {
        let model = AbstractConvertActionModel::new(ScalarFormat::UnsignedHex, false);
        let display = format!("{}", model);
        assert!(display.contains("Hex"));
    }

    #[test]
    fn test_abstract_convert_action_model_menu_path() {
        let model = AbstractConvertActionModel::new(ScalarFormat::Octal, false);
        assert_eq!(model.menu_path.len(), 2);
        assert_eq!(model.menu_path[0], "Convert");
        assert!(model.menu_path[1].contains("Octal"));
    }

    #[test]
    fn test_menu_label_for_format_all_variants() {
        assert!(menu_label_for_format(ScalarFormat::Binary, false).contains("Binary"));
        assert!(menu_label_for_format(ScalarFormat::Char, false).contains("Char"));
        assert!(menu_label_for_format(ScalarFormat::SignedDecimal, true).contains("Signed"));
        assert!(menu_label_for_format(ScalarFormat::UnsignedDecimal, false).contains("Unsigned"));
        assert!(menu_label_for_format(ScalarFormat::Octal, false).contains("Octal"));
        assert!(menu_label_for_format(ScalarFormat::SignedHex, true).contains("Signed"));
        assert!(menu_label_for_format(ScalarFormat::UnsignedHex, false).contains("Unsigned"));
        assert!(menu_label_for_format(ScalarFormat::Float, false).contains("Float"));
        assert!(menu_label_for_format(ScalarFormat::Double, false).contains("Double"));
    }

    #[test]
    fn test_abstract_convert_action_model_enabled_by_default() {
        let model = AbstractConvertActionModel::new(ScalarFormat::Binary, false);
        assert!(model.enabled);
    }
}
