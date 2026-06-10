//! LF_MODIFIER -- concrete Modifier type record.
//!
//! Ports Ghidra's `ModifierMsType` (PDB_ID = 0x1001),
//! `Modifier16MsType` (PDB_ID = 0x0001), and `AbstractModifierMsType`
//! Java classes.
//!
//! Represents a C/C++ type qualifier modifier (`const`, `volatile`,
//! `__unaligned`) applied to another type in the PDB type stream.
//!
//! # Binary Layout (LF_MODIFIER / 0x1001)
//!
//! ```text
//! +0  u32   modifiedType     Type index of the modified (underlying) type
//! +4  u16   attributes       Bitfield:
//!                               bit 0: isConst
//!                               bit 1: isVolatile
//!                               bit 2: isUnaligned
//! ```
//!
//! # Binary Layout (LF_MODIFIER_16 / 0x0001)
//!
//! ```text
//! +0  u16   attributes       Bitfield (same layout as above)
//! +2  u16   modifiedType     Type index of the modified (underlying) type
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Concrete PDB modifier type record (`LF_MODIFIER`).
///
/// This is the Rust equivalent of Ghidra's `ModifierMsType`.  It stores
/// the record number of the type being modified and the const/volatile/
/// unaligned qualifiers.
#[derive(Debug, Clone)]
pub struct LfModifier {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the type that this modifier modifies.
    pub modified_record_number: RecordNumber,
    /// Whether the modified type is `const`.
    pub is_const: bool,
    /// Whether the modified type is `volatile`.
    pub is_volatile: bool,
    /// Whether the modified type is `__unaligned`.
    pub is_unaligned: bool,
}

impl LfModifier {
    /// PDB ID for the 16-bit modifier variant.
    pub const PDB_ID_16: u32 = 0x0001;
    /// PDB ID for the 32-bit (MsType) modifier variant.
    pub const PDB_ID_32: u32 = 0x1001;

    /// Create a new modifier type record.
    pub fn new(
        modified_record_number: RecordNumber,
        is_const: bool,
        is_volatile: bool,
        is_unaligned: bool,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            modified_record_number,
            is_const,
            is_volatile,
            is_unaligned,
        }
    }

    /// Create from raw parsed field values.
    ///
    /// This is the typical constructor used after deserializing the binary
    /// PDB type record for the MsType (32-bit) variant.
    pub fn from_parsed(
        modified_type_index: u32,
        attributes: u16,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(modified_type_index),
            (attributes & 0x01) != 0,
            (attributes & 0x02) != 0,
            (attributes & 0x04) != 0,
        )
    }

    /// Create from raw parsed field values for the 16-bit variant.
    ///
    /// For the 16-bit variant (`Modifier16MsType`), the attribute byte is
    /// parsed first, then the 16-bit modified type index follows.
    pub fn from_parsed_16(
        modified_type_index: u16,
        attributes: u16,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(modified_type_index as u32),
            (attributes & 0x01) != 0,
            (attributes & 0x02) != 0,
            (attributes & 0x04) != 0,
        )
    }

    /// Create a `const` modifier on the given type.
    pub fn const_modifier(modified_type_index: u32) -> Self {
        Self::new(
            RecordNumber::type_record(modified_type_index),
            true,
            false,
            false,
        )
    }

    /// Create a `volatile` modifier on the given type.
    pub fn volatile_modifier(modified_type_index: u32) -> Self {
        Self::new(
            RecordNumber::type_record(modified_type_index),
            false,
            true,
            false,
        )
    }

    /// Create a `const volatile` modifier on the given type.
    pub fn const_volatile_modifier(modified_type_index: u32) -> Self {
        Self::new(
            RecordNumber::type_record(modified_type_index),
            true,
            true,
            false,
        )
    }

    /// Get the record number of the modified (underlying) type.
    ///
    /// Mirrors Java `AbstractModifierMsType.getModifiedRecordNumber()`.
    pub fn get_modified_record_number(&self) -> RecordNumber {
        self.modified_record_number
    }

    /// Get the raw attributes byte (for serialization).
    pub fn attributes_byte(&self) -> u16 {
        (self.is_const as u16)
            | ((self.is_volatile as u16) << 1)
            | ((self.is_unaligned as u16) << 2)
    }

    /// Whether any qualifier is applied.
    pub fn has_qualifiers(&self) -> bool {
        self.is_const || self.is_volatile || self.is_unaligned
    }

    /// Get the modifier qualifier string (e.g., "const volatile ").
    ///
    /// Returns a space-terminated string with all active qualifiers.
    /// If no qualifiers are set, returns an empty string.
    pub fn modifier_string(&self) -> String {
        let mut result = String::new();
        if self.is_const {
            result.push_str("const ");
        }
        if self.is_volatile {
            result.push_str("volatile ");
        }
        if self.is_unaligned {
            result.push_str("__unaligned ");
        }
        result
    }
}

impl AbstractMsType for LfModifier {
    fn pdb_id(&self) -> u32 {
        Self::PDB_ID_32 // LF_MODIFIER = 0x1001
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java AbstractModifierMsType.emit():
        //   modBuilder.append(isConst ? "const " : "");
        //   modBuilder.append(isVolatile ? "volatile " : "");
        //   modBuilder.append(isUnaligned ? "__unaligned " : "");
        //   modBuilder.append(getModifiedType());
        //   modBuilder.append(" ");
        //   builder.insert(0, modBuilder);
        let mut result = String::new();
        result.push_str(&self.modifier_string());
        result.push_str(&self.modified_record_number.to_string());
        result.push(' ');
        result
    }
}

impl fmt::Display for LfModifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

// =============================================================================
// ExtendedModifier -- individual modifier value in LF_MODIFIER_EX
// =============================================================================

/// Individual modifier values used in the `LF_MODIFIER_EX` (0x1518) type record.
///
/// Corresponds to the Java `ModifierExMsType.Modifier` enum. These include
/// standard C/C++ qualifiers as well as HLSL-specific modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ExtendedModifier {
    /// Invalid/unrecognized modifier.
    Invalid = 0,
    /// `const` qualifier.
    Const = 1,
    /// `volatile` qualifier.
    Volatile = 2,
    /// `__unaligned` qualifier.
    Unaligned = 3,
    // HLSL modifiers (0x0200 - 0x03ff)
    /// HLSL `uniform` modifier.
    HlslUniform = 0x0200,
    /// HLSL `line` modifier.
    HlslLine = 0x0201,
    /// HLSL `triangle` modifier.
    HlslTriangle = 0x0202,
    /// HLSL `lineadj` modifier.
    HlslLineAdj = 0x0203,
    /// HLSL `triangleadj` modifier.
    HlslTriangleAdj = 0x0204,
    /// HLSL `linear` modifier.
    HlslLinear = 0x0205,
    /// HLSL `centroid` modifier.
    HlslCentroid = 0x0206,
    /// HLSL `constinterp` modifier.
    HlslConstInterp = 0x0207,
    /// HLSL `noperspective` modifier.
    HlslNoPerspective = 0x0208,
    /// HLSL `sample` modifier.
    HlslSample = 0x0209,
    /// HLSL `center` modifier.
    HlslCenter = 0x020a,
    /// HLSL `snorm` modifier.
    HlslSnorm = 0x020b,
    /// HLSL `unorm` modifier.
    HlslUnorm = 0x020c,
    /// HLSL `precise` modifier.
    HlslPrecise = 0x020d,
    /// HLSL `uav_globally_coherent` modifier.
    HlslUavGloballyCoherent = 0x020e,
}

impl ExtendedModifier {
    /// Label string for this modifier (e.g., `"const "`).
    pub fn label(&self) -> &'static str {
        match self {
            Self::Invalid => "INVALID ",
            Self::Const => "const ",
            Self::Volatile => "volatile ",
            Self::Unaligned => "__unaligned ",
            Self::HlslUniform => "__uniform__ ",
            Self::HlslLine => "__line__ ",
            Self::HlslTriangle => "__triangle__ ",
            Self::HlslLineAdj => "__lineadj__ ",
            Self::HlslTriangleAdj => "__triangleadj__ ",
            Self::HlslLinear => "__linear__ ",
            Self::HlslCentroid => "__centroid__ ",
            Self::HlslConstInterp => "__constinterp__ ",
            Self::HlslNoPerspective => "__noperspective__ ",
            Self::HlslSample => "__sample__ ",
            Self::HlslCenter => "__center__ ",
            Self::HlslSnorm => "__snorm__ ",
            Self::HlslUnorm => "__unorm__ ",
            Self::HlslPrecise => "__precise__ ",
            Self::HlslUavGloballyCoherent => "__uav_globally_coherent__ ",
        }
    }

    /// Parse from a raw u16 value.
    ///
    /// Returns `Invalid` for unknown values.
    pub fn from_value(val: u16) -> Self {
        match val {
            0 => Self::Invalid,
            1 => Self::Const,
            2 => Self::Volatile,
            3 => Self::Unaligned,
            0x0200 => Self::HlslUniform,
            0x0201 => Self::HlslLine,
            0x0202 => Self::HlslTriangle,
            0x0203 => Self::HlslLineAdj,
            0x0204 => Self::HlslTriangleAdj,
            0x0205 => Self::HlslLinear,
            0x0206 => Self::HlslCentroid,
            0x0207 => Self::HlslConstInterp,
            0x0208 => Self::HlslNoPerspective,
            0x0209 => Self::HlslSample,
            0x020a => Self::HlslCenter,
            0x020b => Self::HlslSnorm,
            0x020c => Self::HlslUnorm,
            0x020d => Self::HlslPrecise,
            0x020e => Self::HlslUavGloballyCoherent,
            _ => Self::Invalid,
        }
    }

    /// Whether this is an HLSL-specific modifier.
    pub fn is_hlsl(&self) -> bool {
        (*self as u16) >= 0x0200
    }

    /// Whether this is a standard C/C++ qualifier.
    pub fn is_standard_qualifier(&self) -> bool {
        matches!(self, Self::Const | Self::Volatile | Self::Unaligned)
    }
}

impl fmt::Display for ExtendedModifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// =============================================================================
// LfModifierEx -- the extended modifier type record
// =============================================================================

/// Concrete PDB extended modifier type record (`LF_MODIFIER_EX`).
///
/// Ports Ghidra's `ModifierExMsType` (PDB_ID = 0x1518) Java class.
///
/// Unlike `LF_MODIFIER` which uses a bitmask for const/volatile/unaligned,
/// `LF_MODIFIER_EX` stores a list of [`ExtendedModifier`] values, supporting
/// both standard C/C++ qualifiers and HLSL-specific modifiers.
///
/// # Binary Layout (LF_MODIFIER_EX / 0x1518)
///
/// ```text
/// +0  u32   modifiedType     Type index of the modified (underlying) type
/// +4  u16   count            Number of modifiers
/// +6  u16[] modifiers        Array of modifier values
/// ```
#[derive(Debug, Clone)]
pub struct LfModifierEx {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the type that this modifier modifies.
    pub modified_record_number: RecordNumber,
    /// Ordered list of modifiers applied to the type.
    pub modifiers: Vec<ExtendedModifier>,
}

impl LfModifierEx {
    /// PDB ID for the extended modifier variant.
    pub const PDB_ID_32: u32 = 0x1518;

    /// Create a new extended modifier type record.
    pub fn new(
        modified_record_number: RecordNumber,
        modifiers: Vec<ExtendedModifier>,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            modified_record_number,
            modifiers,
        }
    }

    /// Create from raw parsed field values.
    pub fn from_parsed(
        modified_type_index: u32,
        modifier_values: Vec<u16>,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(modified_type_index),
            modifier_values
                .into_iter()
                .map(ExtendedModifier::from_value)
                .collect(),
        )
    }

    /// Get the record number of the modified (underlying) type.
    pub fn get_modified_record_number(&self) -> RecordNumber {
        self.modified_record_number
    }

    /// Check whether a specific modifier is present.
    ///
    /// Mirrors Java `ModifierExMsType.hasModifier(Modifier)`.
    pub fn has_modifier(&self, modifier: ExtendedModifier) -> bool {
        self.modifiers.contains(&modifier)
    }

    /// Whether the type has a `const` modifier.
    pub fn is_const(&self) -> bool {
        self.has_modifier(ExtendedModifier::Const)
    }

    /// Whether the type has a `volatile` modifier.
    pub fn is_volatile(&self) -> bool {
        self.has_modifier(ExtendedModifier::Volatile)
    }

    /// Whether the type has an `__unaligned` modifier.
    pub fn is_unaligned(&self) -> bool {
        self.has_modifier(ExtendedModifier::Unaligned)
    }

    /// Get the number of modifiers.
    pub fn num_modifiers(&self) -> usize {
        self.modifiers.len()
    }

    /// Whether this record contains any HLSL modifiers.
    pub fn has_hlsl_modifiers(&self) -> bool {
        self.modifiers.iter().any(|m| m.is_hlsl())
    }

    /// Build the combined modifier string.
    pub fn modifier_string(&self) -> String {
        let mut result = String::new();
        for modifier in &self.modifiers {
            result.push_str(modifier.label());
        }
        result
    }
}

impl AbstractMsType for LfModifierEx {
    fn pdb_id(&self) -> u32 {
        Self::PDB_ID_32 // LF_MODIFIER_EX = 0x1518
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java ModifierExMsType.emit():
        //   for (Modifier modifier : modifiers) {
        //     modBuilder.append(modifier);
        //   }
        //   modBuilder.append(pdb.getTypeRecord(modifiedRecordNumber));
        //   builder.insert(0, modBuilder);
        let mut result = String::new();
        for modifier in &self.modifiers {
            result.push_str(modifier.label());
        }
        result.push_str(&self.modified_record_number.to_string());
        result
    }
}

impl fmt::Display for LfModifierEx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modifier_const() {
        let m = LfModifier::const_modifier(0x0074);
        assert_eq!(m.pdb_id(), 0x1001);
        assert!(m.is_const);
        assert!(!m.is_volatile);
        assert!(!m.is_unaligned);
        assert_eq!(m.modified_record_number, RecordNumber::type_record(0x0074));
    }

    #[test]
    fn test_modifier_volatile() {
        let m = LfModifier::volatile_modifier(0x0074);
        assert!(!m.is_const);
        assert!(m.is_volatile);
        assert!(!m.is_unaligned);
    }

    #[test]
    fn test_modifier_const_volatile() {
        let m = LfModifier::const_volatile_modifier(0x0074);
        assert!(m.is_const);
        assert!(m.is_volatile);
        assert!(!m.is_unaligned);
    }

    #[test]
    fn test_modifier_new() {
        let m = LfModifier::new(
            RecordNumber::type_record(0x1000),
            true,
            false,
            true,
        );
        assert!(m.is_const);
        assert!(!m.is_volatile);
        assert!(m.is_unaligned);
    }

    #[test]
    fn test_modifier_from_parsed() {
        // attributes = 0x03 => bit 0 (const) + bit 1 (volatile)
        let m = LfModifier::from_parsed(0x0074, 0x03);
        assert!(m.is_const);
        assert!(m.is_volatile);
        assert!(!m.is_unaligned);
        assert_eq!(m.modified_record_number, RecordNumber::type_record(0x0074));
    }

    #[test]
    fn test_modifier_from_parsed_unaligned() {
        // attributes = 0x04 => bit 2 (unaligned)
        let m = LfModifier::from_parsed(0x0074, 0x04);
        assert!(!m.is_const);
        assert!(!m.is_volatile);
        assert!(m.is_unaligned);
    }

    #[test]
    fn test_modifier_from_parsed_all() {
        // attributes = 0x07 => all three bits set
        let m = LfModifier::from_parsed(0x0074, 0x07);
        assert!(m.is_const);
        assert!(m.is_volatile);
        assert!(m.is_unaligned);
    }

    #[test]
    fn test_modifier_attributes_byte() {
        let m = LfModifier::new(
            RecordNumber::type_record(0x0074),
            true,
            false,
            true,
        );
        assert_eq!(m.attributes_byte(), 0x05); // bit 0 + bit 2

        let m = LfModifier::const_volatile_modifier(0x0074);
        assert_eq!(m.attributes_byte(), 0x03);
    }

    #[test]
    fn test_modifier_emit_const() {
        let m = LfModifier::const_modifier(0x0074);
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.starts_with("const "));
        assert!(emitted.contains("0x0074"));
    }

    #[test]
    fn test_modifier_emit_volatile() {
        let m = LfModifier::volatile_modifier(0x0074);
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.starts_with("volatile "));
        assert!(emitted.contains("0x0074"));
    }

    #[test]
    fn test_modifier_emit_unaligned() {
        let m = LfModifier::new(
            RecordNumber::type_record(0x0074),
            false,
            false,
            true,
        );
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains("__unaligned"));
        assert!(emitted.contains("0x0074"));
    }

    #[test]
    fn test_modifier_emit_all() {
        let m = LfModifier::new(
            RecordNumber::type_record(0x0074),
            true,
            true,
            true,
        );
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains("const"));
        assert!(emitted.contains("volatile"));
        assert!(emitted.contains("__unaligned"));
    }

    #[test]
    fn test_modifier_emit_no_qualifiers() {
        let m = LfModifier::new(
            RecordNumber::type_record(0x0074),
            false,
            false,
            false,
        );
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains("0x0074"));
        assert!(!emitted.contains("const"));
        assert!(!emitted.contains("volatile"));
    }

    #[test]
    fn test_modifier_record_number() {
        let mut m = LfModifier::const_modifier(0x0074);
        assert!(m.record_number().is_no_type());
        m.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(m.record_number().index(), 0x2000);
    }

    #[test]
    fn test_modifier_display() {
        let m = LfModifier::const_modifier(0x0074);
        let display = format!("{}", m);
        assert!(display.contains("const"));
        assert!(display.contains("0x0074"));
    }

    #[test]
    fn test_modifier_from_parsed_16() {
        // 16-bit variant: attributes = 0x01 (const only)
        let m = LfModifier::from_parsed_16(0x0074, 0x01);
        assert!(m.is_const);
        assert!(!m.is_volatile);
        assert!(!m.is_unaligned);
        assert_eq!(m.modified_record_number, RecordNumber::type_record(0x0074));
    }

    #[test]
    fn test_modifier_from_parsed_16_all() {
        let m = LfModifier::from_parsed_16(0x1000, 0x07);
        assert!(m.is_const);
        assert!(m.is_volatile);
        assert!(m.is_unaligned);
    }

    #[test]
    fn test_modifier_get_modified_record_number() {
        let m = LfModifier::const_modifier(0x0074);
        assert_eq!(m.get_modified_record_number(), RecordNumber::type_record(0x0074));
    }

    #[test]
    fn test_modifier_has_qualifiers() {
        let m = LfModifier::new(
            RecordNumber::type_record(0x0074),
            false,
            false,
            false,
        );
        assert!(!m.has_qualifiers());

        let m = LfModifier::const_modifier(0x0074);
        assert!(m.has_qualifiers());
    }

    #[test]
    fn test_modifier_modifier_string_empty() {
        let m = LfModifier::new(
            RecordNumber::type_record(0x0074),
            false,
            false,
            false,
        );
        assert_eq!(m.modifier_string(), "");
    }

    #[test]
    fn test_modifier_modifier_string_const() {
        let m = LfModifier::const_modifier(0x0074);
        assert_eq!(m.modifier_string(), "const ");
    }

    #[test]
    fn test_modifier_modifier_string_volatile() {
        let m = LfModifier::volatile_modifier(0x0074);
        assert_eq!(m.modifier_string(), "volatile ");
    }

    #[test]
    fn test_modifier_modifier_string_all() {
        let m = LfModifier::new(
            RecordNumber::type_record(0x0074),
            true,
            true,
            true,
        );
        assert_eq!(m.modifier_string(), "const volatile __unaligned ");
    }

    #[test]
    fn test_modifier_pdb_id_constants() {
        assert_eq!(LfModifier::PDB_ID_16, 0x0001);
        assert_eq!(LfModifier::PDB_ID_32, 0x1001);
    }

    // =========================================================================
    // ExtendedModifier tests
    // =========================================================================

    #[test]
    fn test_extended_modifier_from_value() {
        assert_eq!(ExtendedModifier::from_value(0), ExtendedModifier::Invalid);
        assert_eq!(ExtendedModifier::from_value(1), ExtendedModifier::Const);
        assert_eq!(ExtendedModifier::from_value(2), ExtendedModifier::Volatile);
        assert_eq!(ExtendedModifier::from_value(3), ExtendedModifier::Unaligned);
    }

    #[test]
    fn test_extended_modifier_from_value_hlsl() {
        assert_eq!(
            ExtendedModifier::from_value(0x0200),
            ExtendedModifier::HlslUniform
        );
        assert_eq!(
            ExtendedModifier::from_value(0x020e),
            ExtendedModifier::HlslUavGloballyCoherent
        );
    }

    #[test]
    fn test_extended_modifier_from_value_unknown() {
        assert_eq!(ExtendedModifier::from_value(0x0100), ExtendedModifier::Invalid);
        assert_eq!(ExtendedModifier::from_value(0xFFFF), ExtendedModifier::Invalid);
    }

    #[test]
    fn test_extended_modifier_label() {
        assert_eq!(ExtendedModifier::Const.label(), "const ");
        assert_eq!(ExtendedModifier::Volatile.label(), "volatile ");
        assert_eq!(ExtendedModifier::Unaligned.label(), "__unaligned ");
        assert_eq!(ExtendedModifier::HlslUniform.label(), "__uniform__ ");
    }

    #[test]
    fn test_extended_modifier_is_hlsl() {
        assert!(!ExtendedModifier::Const.is_hlsl());
        assert!(!ExtendedModifier::Volatile.is_hlsl());
        assert!(ExtendedModifier::HlslUniform.is_hlsl());
        assert!(ExtendedModifier::HlslPrecise.is_hlsl());
    }

    #[test]
    fn test_extended_modifier_is_standard_qualifier() {
        assert!(ExtendedModifier::Const.is_standard_qualifier());
        assert!(ExtendedModifier::Volatile.is_standard_qualifier());
        assert!(ExtendedModifier::Unaligned.is_standard_qualifier());
        assert!(!ExtendedModifier::HlslUniform.is_standard_qualifier());
        assert!(!ExtendedModifier::Invalid.is_standard_qualifier());
    }

    #[test]
    fn test_extended_modifier_display() {
        assert_eq!(format!("{}", ExtendedModifier::Const), "const ");
        assert_eq!(format!("{}", ExtendedModifier::HlslLinear), "__linear__ ");
    }

    // =========================================================================
    // LfModifierEx tests
    // =========================================================================

    #[test]
    fn test_modifier_ex_basic() {
        let m = LfModifierEx::new(
            RecordNumber::type_record(0x0074),
            vec![ExtendedModifier::Const, ExtendedModifier::Volatile],
        );
        assert_eq!(m.pdb_id(), 0x1518);
        assert!(m.is_const());
        assert!(m.is_volatile());
        assert!(!m.is_unaligned());
        assert_eq!(m.num_modifiers(), 2);
    }

    #[test]
    fn test_modifier_ex_from_parsed() {
        let m = LfModifierEx::from_parsed(0x0074, vec![1, 2]); // const, volatile
        assert!(m.is_const());
        assert!(m.is_volatile());
        assert_eq!(
            m.modified_record_number,
            RecordNumber::type_record(0x0074)
        );
    }

    #[test]
    fn test_modifier_ex_from_parsed_empty() {
        let m = LfModifierEx::from_parsed(0x0074, vec![]);
        assert!(!m.is_const());
        assert!(!m.is_volatile());
        assert_eq!(m.num_modifiers(), 0);
    }

    #[test]
    fn test_modifier_ex_has_modifier() {
        let m = LfModifierEx::new(
            RecordNumber::type_record(0x0074),
            vec![ExtendedModifier::Const],
        );
        assert!(m.has_modifier(ExtendedModifier::Const));
        assert!(!m.has_modifier(ExtendedModifier::Volatile));
    }

    #[test]
    fn test_modifier_ex_emit() {
        let m = LfModifierEx::new(
            RecordNumber::type_record(0x0074),
            vec![ExtendedModifier::Const, ExtendedModifier::Volatile],
        );
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.starts_with("const volatile "));
        assert!(emitted.contains("0x0074"));
    }

    #[test]
    fn test_modifier_ex_emit_hlsl() {
        let m = LfModifierEx::new(
            RecordNumber::type_record(0x0074),
            vec![ExtendedModifier::HlslUniform, ExtendedModifier::Const],
        );
        let emitted = m.emit(Bind::NONE);
        assert!(emitted.contains("__uniform__"));
        assert!(emitted.contains("const "));
        assert!(emitted.contains("0x0074"));
    }

    #[test]
    fn test_modifier_ex_modifier_string() {
        let m = LfModifierEx::new(
            RecordNumber::type_record(0x0074),
            vec![
                ExtendedModifier::Const,
                ExtendedModifier::Volatile,
                ExtendedModifier::Unaligned,
            ],
        );
        assert_eq!(
            m.modifier_string(),
            "const volatile __unaligned "
        );
    }

    #[test]
    fn test_modifier_ex_modifier_string_empty() {
        let m = LfModifierEx::new(
            RecordNumber::type_record(0x0074),
            vec![],
        );
        assert_eq!(m.modifier_string(), "");
    }

    #[test]
    fn test_modifier_ex_has_hlsl_modifiers() {
        let m = LfModifierEx::new(
            RecordNumber::type_record(0x0074),
            vec![ExtendedModifier::Const],
        );
        assert!(!m.has_hlsl_modifiers());

        let m = LfModifierEx::new(
            RecordNumber::type_record(0x0074),
            vec![ExtendedModifier::Const, ExtendedModifier::HlslLinear],
        );
        assert!(m.has_hlsl_modifiers());
    }

    #[test]
    fn test_modifier_ex_record_number() {
        let mut m = LfModifierEx::new(
            RecordNumber::type_record(0x0074),
            vec![ExtendedModifier::Const],
        );
        assert!(m.record_number().is_no_type());
        m.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(m.record_number().index(), 0x2000);
    }

    #[test]
    fn test_modifier_ex_display() {
        let m = LfModifierEx::new(
            RecordNumber::type_record(0x0074),
            vec![ExtendedModifier::Const],
        );
        let display = format!("{}", m);
        assert!(display.contains("const"));
        assert!(display.contains("0x0074"));
    }

    #[test]
    fn test_modifier_ex_get_modified_record_number() {
        let m = LfModifierEx::new(
            RecordNumber::type_record(0x0074),
            vec![ExtendedModifier::Const],
        );
        assert_eq!(
            m.get_modified_record_number(),
            RecordNumber::type_record(0x0074)
        );
    }

    #[test]
    fn test_modifier_ex_pdb_id_constant() {
        assert_eq!(LfModifierEx::PDB_ID_32, 0x1518);
    }
}
