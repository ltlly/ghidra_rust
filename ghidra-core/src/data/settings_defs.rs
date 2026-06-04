//! Settings definitions ported from Ghidra's SettingsDefinition classes.
//!
//! Covers all settings definition types including:
//! - `EndianSettingsDefinition` (big/little endian)
//! - `MutabilitySettingsDefinition` (mutable/immutable)
//! - `TerminatedSettingsDefinition` (null-terminated strings)
//! - `CharsetSettingsDefinition` (character encoding)
//! - `RenderUnicodeSettingsDefinition` (unicode rendering)
//! - `TranslationSettingsDefinition` (address translation)
//! - `PointerTypeSettingsDefinition` (pointer type classification)
//! - `AddressSpaceSettingsDefinition` (target address space)
//! - `OffsetMaskSettingsDefinition` (pointer offset mask)
//! - `OffsetShiftSettingsDefinition` (pointer offset shift)
//! - `ComponentOffsetSettingsDefinition` (component offset)
//! - `PaddingSettingsDefinition` (structure padding)
//! - `DataTypeMnemonicSettingsDefinition` (mnemonic override)
//! - `RGB16EncodingSettingsDefinition` (RGB16 encoding)
//! - `RGB32EncodingSettingsDefinition` (RGB32 encoding)

use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// Endianness
// ============================================================================

/// Endianness setting. Port of Ghidra's `EndianSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EndianSetting {
    Big,
    Little,
    Dynamic,
}

impl Default for EndianSetting {
    fn default() -> Self { Self::Dynamic }
}

impl fmt::Display for EndianSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Big => write!(f, "Big Endian"),
            Self::Little => write!(f, "Little Endian"),
            Self::Dynamic => write!(f, "Dynamic"),
        }
    }
}

/// Endianness settings definition. Port of Ghidra's `EndianSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndianSettingsDefinition {
    pub setting: EndianSetting,
}

impl EndianSettingsDefinition {
    pub const NAME: &'static str = "Endian";

    pub fn new(setting: EndianSetting) -> Self {
        Self { setting }
    }
    pub fn is_big_endian(&self) -> bool { self.setting == EndianSetting::Big }
    pub fn is_little_endian(&self) -> bool { self.setting == EndianSetting::Little }
    pub fn is_dynamic(&self) -> bool { self.setting == EndianSetting::Dynamic }
}

impl Default for EndianSettingsDefinition {
    fn default() -> Self { Self { setting: EndianSetting::Dynamic } }
}

// ============================================================================
// Mutability
// ============================================================================

/// Mutability setting. Port of Ghidra's `MutabilitySettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MutabilitySetting {
    Immutable,
    Volatile,
    Constant,
}

impl Default for MutabilitySetting {
    fn default() -> Self { Self::Immutable }
}

impl fmt::Display for MutabilitySetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Immutable => write!(f, "Immutable"),
            Self::Volatile => write!(f, "Volatile"),
            Self::Constant => write!(f, "Constant"),
        }
    }
}

/// Mutability settings definition. Port of Ghidra's `MutabilitySettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutabilitySettingsDefinition {
    pub setting: MutabilitySetting,
}

impl MutabilitySettingsDefinition {
    pub const NAME: &'static str = "Mutability";

    pub fn new(setting: MutabilitySetting) -> Self {
        Self { setting }
    }
    pub fn is_volatile(&self) -> bool { self.setting == MutabilitySetting::Volatile }
    pub fn is_constant(&self) -> bool { self.setting == MutabilitySetting::Constant }
    pub fn is_immutable(&self) -> bool { self.setting == MutabilitySetting::Immutable }
}

impl Default for MutabilitySettingsDefinition {
    fn default() -> Self { Self { setting: MutabilitySetting::Immutable } }
}

// ============================================================================
// Terminated (for string types)
// ============================================================================

/// Terminated settings definition. Port of Ghidra's `TerminatedSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminatedSettingsDefinition {
    pub terminated: bool,
}

impl TerminatedSettingsDefinition {
    pub const NAME: &'static str = "Terminated";

    pub fn new(terminated: bool) -> Self {
        Self { terminated }
    }
}

impl Default for TerminatedSettingsDefinition {
    fn default() -> Self { Self { terminated: true } }
}

// ============================================================================
// Charset
// ============================================================================

/// Charset settings definition. Port of Ghidra's `CharsetSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharsetSettingsDefinition {
    pub charset_name: String,
}

impl CharsetSettingsDefinition {
    pub const NAME: &'static str = "Charset";

    pub fn new(charset_name: impl Into<String>) -> Self {
        Self { charset_name: charset_name.into() }
    }
    pub fn ascii() -> Self { Self::new("ASCII") }
    pub fn utf8() -> Self { Self::new("UTF-8") }
    pub fn utf16() -> Self { Self::new("UTF-16") }
}

impl Default for CharsetSettingsDefinition {
    fn default() -> Self { Self::ascii() }
}

// ============================================================================
// Render Unicode
// ============================================================================

/// Unicode rendering settings. Port of Ghidra's `RenderUnicodeSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnicodeRenderMode {
    /// Render as escape sequences (\uXXXX).
    EscapeSequence,
    /// Render as best-fit ASCII.
    BestFit,
}

impl Default for UnicodeRenderMode {
    fn default() -> Self { Self::EscapeSequence }
}

/// Render unicode settings definition. Port of Ghidra's `RenderUnicodeSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderUnicodeSettingsDefinition {
    pub mode: UnicodeRenderMode,
}

impl RenderUnicodeSettingsDefinition {
    pub const NAME: &'static str = "RenderUnicode";

    pub fn new(mode: UnicodeRenderMode) -> Self { Self { mode } }
}

impl Default for RenderUnicodeSettingsDefinition {
    fn default() -> Self { Self { mode: UnicodeRenderMode::EscapeSequence } }
}

// ============================================================================
// Translation
// ============================================================================

/// Translation settings definition. Port of Ghidra's `TranslationSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationSettingsDefinition {
    pub enabled: bool,
}

impl TranslationSettingsDefinition {
    pub const NAME: &'static str = "Translation";

    pub fn new(enabled: bool) -> Self { Self { enabled } }
}

impl Default for TranslationSettingsDefinition {
    fn default() -> Self { Self { enabled: false } }
}

// ============================================================================
// Pointer Type
// ============================================================================

/// Pointer type classification. Port of Ghidra's `PointerType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PointerType {
    Default,
    Near,
    Far,
    Segmented,
    Relative,
    ImageBaseRelative,
    FileOffset,
    HeapRelative,
}

impl Default for PointerType {
    fn default() -> Self { Self::Default }
}

impl fmt::Display for PointerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "Default"),
            Self::Near => write!(f, "Near"),
            Self::Far => write!(f, "Far"),
            Self::Segmented => write!(f, "Segmented"),
            Self::Relative => write!(f, "Relative"),
            Self::ImageBaseRelative => write!(f, "Image Base Relative"),
            Self::FileOffset => write!(f, "File Offset"),
            Self::HeapRelative => write!(f, "Heap Relative"),
        }
    }
}

/// Pointer type settings definition. Port of Ghidra's `PointerTypeSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerTypeSettingsDefinition {
    pub pointer_type: PointerType,
}

impl PointerTypeSettingsDefinition {
    pub const NAME: &'static str = "PointerType";

    pub fn new(pointer_type: PointerType) -> Self { Self { pointer_type } }
}

impl Default for PointerTypeSettingsDefinition {
    fn default() -> Self { Self { pointer_type: PointerType::Default } }
}

// ============================================================================
// Address Space
// ============================================================================

/// Address space settings definition. Port of Ghidra's `AddressSpaceSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressSpaceSettingsDefinition {
    pub space_name: String,
}

impl AddressSpaceSettingsDefinition {
    pub const NAME: &'static str = "AddressSpace";

    pub fn new(space_name: impl Into<String>) -> Self {
        Self { space_name: space_name.into() }
    }
}

impl Default for AddressSpaceSettingsDefinition {
    fn default() -> Self { Self { space_name: String::new() } }
}

// ============================================================================
// Offset Mask
// ============================================================================

/// Offset mask settings definition. Port of Ghidra's `OffsetMaskSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffsetMaskSettingsDefinition {
    pub mask: u64,
}

impl OffsetMaskSettingsDefinition {
    pub const NAME: &'static str = "OffsetMask";
    pub const DEFAULT: u64 = 0;

    pub fn new(mask: u64) -> Self { Self { mask } }
}

impl Default for OffsetMaskSettingsDefinition {
    fn default() -> Self { Self { mask: Self::DEFAULT } }
}

// ============================================================================
// Offset Shift
// ============================================================================

/// Offset shift settings definition. Port of Ghidra's `OffsetShiftSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffsetShiftSettingsDefinition {
    pub shift: i32,
}

impl OffsetShiftSettingsDefinition {
    pub const NAME: &'static str = "OffsetShift";
    pub const DEFAULT: i32 = 0;

    pub fn new(shift: i32) -> Self { Self { shift } }
}

impl Default for OffsetShiftSettingsDefinition {
    fn default() -> Self { Self { shift: Self::DEFAULT } }
}

// ============================================================================
// Component Offset
// ============================================================================

/// Component offset settings definition. Port of Ghidra's `ComponentOffsetSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentOffsetSettingsDefinition {
    pub offset: i64,
}

impl ComponentOffsetSettingsDefinition {
    pub const NAME: &'static str = "ComponentOffset";
    pub const DEFAULT: i64 = 0;

    pub fn new(offset: i64) -> Self { Self { offset } }
}

impl Default for ComponentOffsetSettingsDefinition {
    fn default() -> Self { Self { offset: Self::DEFAULT } }
}

// ============================================================================
// Padding
// ============================================================================

/// Padding settings definition. Port of Ghidra's `PaddingSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaddingSettingsDefinition {
    pub enabled: bool,
}

impl PaddingSettingsDefinition {
    pub const NAME: &'static str = "Padding";

    pub fn new(enabled: bool) -> Self { Self { enabled } }
}

impl Default for PaddingSettingsDefinition {
    fn default() -> Self { Self { enabled: true } }
}

// ============================================================================
// Data Type Mnemonic
// ============================================================================

/// Data type mnemonic settings. Port of Ghidra's `DataTypeMnemonicSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeMnemonicSettingsDefinition {
    pub mnemonic: String,
}

impl DataTypeMnemonicSettingsDefinition {
    pub const NAME: &'static str = "DataTypeMnemonic";

    pub fn new(mnemonic: impl Into<String>) -> Self {
        Self { mnemonic: mnemonic.into() }
    }
}

impl Default for DataTypeMnemonicSettingsDefinition {
    fn default() -> Self { Self { mnemonic: String::new() } }
}

// ============================================================================
// RGB16 Encoding
// ============================================================================

/// RGB16 encoding format. Port of Ghidra's `RGB16EncodingSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RGB16Encoding {
    /// 5-5-5 bit encoding.
    RGB555,
    /// 5-6-5 bit encoding.
    RGB565,
}

impl Default for RGB16Encoding {
    fn default() -> Self { Self::RGB555 }
}

/// RGB16 encoding settings. Port of Ghidra's `RGB16EncodingSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RGB16EncodingSettingsDefinition {
    pub encoding: RGB16Encoding,
}

impl RGB16EncodingSettingsDefinition {
    pub const NAME: &'static str = "RGB16Encoding";

    pub fn new(encoding: RGB16Encoding) -> Self { Self { encoding } }
}

impl Default for RGB16EncodingSettingsDefinition {
    fn default() -> Self { Self { encoding: RGB16Encoding::RGB555 } }
}

// ============================================================================
// RGB32 Encoding
// ============================================================================

/// RGB32 encoding format. Port of Ghidra's `RGB32EncodingSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RGB32Encoding {
    /// Standard 8-8-8 format.
    RGB888,
    /// Alpha-premultiplied format.
    ARGB8888,
}

impl Default for RGB32Encoding {
    fn default() -> Self { Self::RGB888 }
}

/// RGB32 encoding settings. Port of Ghidra's `RGB32EncodingSettingsDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RGB32EncodingSettingsDefinition {
    pub encoding: RGB32Encoding,
}

impl RGB32EncodingSettingsDefinition {
    pub const NAME: &'static str = "RGB32Encoding";

    pub fn new(encoding: RGB32Encoding) -> Self { Self { encoding } }
}

impl Default for RGB32EncodingSettingsDefinition {
    fn default() -> Self { Self { encoding: RGB32Encoding::RGB888 } }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endian_settings() {
        let big = EndianSettingsDefinition::new(EndianSetting::Big);
        assert!(big.is_big_endian());
        assert!(!big.is_little_endian());

        let little = EndianSettingsDefinition::new(EndianSetting::Little);
        assert!(!little.is_big_endian());
        assert!(little.is_little_endian());

        let dyn_s = EndianSettingsDefinition::default();
        assert!(dyn_s.is_dynamic());
    }

    #[test]
    fn test_mutability_settings() {
        let vol = MutabilitySettingsDefinition::new(MutabilitySetting::Volatile);
        assert!(vol.is_volatile());
        assert!(!vol.is_constant());

        let con = MutabilitySettingsDefinition::new(MutabilitySetting::Constant);
        assert!(con.is_constant());
        assert!(!con.is_immutable());

        let imm = MutabilitySettingsDefinition::default();
        assert!(imm.is_immutable());
    }

    #[test]
    fn test_terminated_settings() {
        let t = TerminatedSettingsDefinition::default();
        assert!(t.terminated);

        let f = TerminatedSettingsDefinition::new(false);
        assert!(!f.terminated);
    }

    #[test]
    fn test_charset_settings() {
        let ascii = CharsetSettingsDefinition::ascii();
        assert_eq!(ascii.charset_name, "ASCII");

        let utf8 = CharsetSettingsDefinition::utf8();
        assert_eq!(utf8.charset_name, "UTF-8");

        let utf16 = CharsetSettingsDefinition::utf16();
        assert_eq!(utf16.charset_name, "UTF-16");

        let custom = CharsetSettingsDefinition::new("Shift-JIS");
        assert_eq!(custom.charset_name, "Shift-JIS");
    }

    #[test]
    fn test_pointer_type_settings() {
        let default = PointerTypeSettingsDefinition::default();
        assert_eq!(default.pointer_type, PointerType::Default);

        let near = PointerTypeSettingsDefinition::new(PointerType::Near);
        assert_eq!(near.pointer_type, PointerType::Near);

        let rel = PointerTypeSettingsDefinition::new(PointerType::Relative);
        assert_eq!(rel.pointer_type, PointerType::Relative);
    }

    #[test]
    fn test_pointer_type_display() {
        assert_eq!(format!("{}", PointerType::Default), "Default");
        assert_eq!(format!("{}", PointerType::ImageBaseRelative), "Image Base Relative");
        assert_eq!(format!("{}", PointerType::HeapRelative), "Heap Relative");
    }

    #[test]
    fn test_address_space_settings() {
        let space = AddressSpaceSettingsDefinition::new("ram");
        assert_eq!(space.space_name, "ram");
    }

    #[test]
    fn test_offset_mask_settings() {
        let mask = OffsetMaskSettingsDefinition::new(0xFFFFFFFF);
        assert_eq!(mask.mask, 0xFFFFFFFF);
        assert_eq!(OffsetMaskSettingsDefinition::DEFAULT, 0);
    }

    #[test]
    fn test_offset_shift_settings() {
        let shift = OffsetShiftSettingsDefinition::new(2);
        assert_eq!(shift.shift, 2);
        assert_eq!(OffsetShiftSettingsDefinition::DEFAULT, 0);
    }

    #[test]
    fn test_rgb16_encoding() {
        let r555 = RGB16EncodingSettingsDefinition::default();
        assert_eq!(r555.encoding, RGB16Encoding::RGB555);

        let r565 = RGB16EncodingSettingsDefinition::new(RGB16Encoding::RGB565);
        assert_eq!(r565.encoding, RGB16Encoding::RGB565);
    }

    #[test]
    fn test_rgb32_encoding() {
        let r888 = RGB32EncodingSettingsDefinition::default();
        assert_eq!(r888.encoding, RGB32Encoding::RGB888);

        let argb = RGB32EncodingSettingsDefinition::new(RGB32Encoding::ARGB8888);
        assert_eq!(argb.encoding, RGB32Encoding::ARGB8888);
    }

    #[test]
    fn test_padding_settings() {
        let p = PaddingSettingsDefinition::default();
        assert!(p.enabled);
        let p2 = PaddingSettingsDefinition::new(false);
        assert!(!p2.enabled);
    }

    #[test]
    fn test_mnemonic_settings() {
        let m = DataTypeMnemonicSettingsDefinition::new("dw");
        assert_eq!(m.mnemonic, "dw");
    }

    #[test]
    fn test_render_unicode_settings() {
        let r = RenderUnicodeSettingsDefinition::default();
        assert_eq!(r.mode, UnicodeRenderMode::EscapeSequence);
        let r2 = RenderUnicodeSettingsDefinition::new(UnicodeRenderMode::BestFit);
        assert_eq!(r2.mode, UnicodeRenderMode::BestFit);
    }
}
