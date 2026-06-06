//! Settings definitions for table columns.
//!
//! Ported from `ghidra.util.table.field` settings definition classes.
//! Each settings definition controls how a column is displayed or
//! filtered, and provides enum-based or boolean choices.

use super::traits::Settings;

// ---------------------------------------------------------------------------
// SettingsDefinition trait
// ---------------------------------------------------------------------------

/// A single setting that can be applied to a table column.
///
/// Ported from `ghidra.docking.settings.SettingsDefinition`.
pub trait SettingsDefinition: Send + Sync {
    /// Returns the display name for this setting.
    fn name(&self) -> &str;

    /// Returns the storage key used to persist this setting.
    fn storage_key(&self) -> &str;

    /// Returns a human-readable description.
    fn description(&self) -> &str;

    /// Clears this setting from the given settings map.
    fn clear(&self, settings: &mut Settings) {
        settings.clear_setting(self.storage_key());
    }
}

// ---------------------------------------------------------------------------
// EnumSettingsDefinition
// ---------------------------------------------------------------------------

/// A settings definition with a fixed set of choices.
///
/// Ported from `ghidra.docking.settings.EnumSettingsDefinition`.
pub trait EnumSettingsDefinition: SettingsDefinition {
    /// Returns the current choice index.
    fn get_choice(&self, settings: &Settings) -> usize;

    /// Sets the current choice index.
    fn set_choice(&self, settings: &mut Settings, value: usize);

    /// Returns the display string for a choice index.
    fn display_choice(&self, value: usize) -> &str;

    /// Returns all available display choices.
    fn display_choices(&self) -> &[&str];

    /// Returns the display string for the current choice.
    fn get_display_value(&self, settings: &Settings) -> String {
        let idx = self.get_choice(settings);
        self.display_choice(idx).to_string()
    }
}

// ---------------------------------------------------------------------------
// BooleanSettingsDefinition
// ---------------------------------------------------------------------------

/// A settings definition that is either on or off.
///
/// Ported from `ghidra.docking.settings.BooleanSettingsDefinition`.
pub trait BooleanSettingsDefinition: SettingsDefinition {
    /// Returns the current boolean value.
    fn get_value(&self, settings: &Settings) -> bool;

    /// Sets the boolean value.
    fn set_value(&self, settings: &mut Settings, value: bool);
}

// ---------------------------------------------------------------------------
// AddressRangeEndpointSettingsDefinition
// ---------------------------------------------------------------------------

/// Selects whether to use the begin or end address of an address range
/// for table columns.
///
/// Ported from `ghidra.util.table.field.AddressRangeEndpointSettingsDefinition`.
#[derive(Debug)]
pub struct AddressRangeEndpointSettingsDefinition;

/// The singleton instance.
pub static ADDRESS_RANGE_ENDPOINT_DEF: AddressRangeEndpointSettingsDefinition =
    AddressRangeEndpointSettingsDefinition;

/// "Begin" choice index.
pub const BEGIN_CHOICE_INDEX: usize = 0;
/// "End" choice index.
pub const END_CHOICE_INDEX: usize = 1;

const ENDPOINT_CHOICES: [&str; 2] = ["Begin", "End"];

impl SettingsDefinition for AddressRangeEndpointSettingsDefinition {
    fn name(&self) -> &str { "Endpoint" }
    fn storage_key(&self) -> &str { "Address Range Endpoint" }
    fn description(&self) -> &str { "Selects the base address" }
}

impl EnumSettingsDefinition for AddressRangeEndpointSettingsDefinition {
    fn get_choice(&self, settings: &Settings) -> usize {
        settings.get_long(self.storage_key())
            .filter(|&v| v >= 0 && (v as usize) < ENDPOINT_CHOICES.len())
            .map(|v| v as usize)
            .unwrap_or(0)
    }

    fn set_choice(&self, settings: &mut Settings, value: usize) {
        settings.set_long(self.storage_key(), value as i64);
    }

    fn display_choice(&self, value: usize) -> &str {
        ENDPOINT_CHOICES.get(value).copied().unwrap_or("Begin")
    }

    fn display_choices(&self) -> &[&str] {
        &ENDPOINT_CHOICES
    }
}

// ---------------------------------------------------------------------------
// ByteCountSettingsDefinition
// ---------------------------------------------------------------------------

/// Controls how many bytes are displayed in a bytes column.
///
/// Ported from `ghidra.util.table.field.ByteCountSettingsDefinition`.
#[derive(Debug)]
pub struct ByteCountSettingsDefinition;

pub static BYTE_COUNT_DEF: ByteCountSettingsDefinition = ByteCountSettingsDefinition;

impl SettingsDefinition for ByteCountSettingsDefinition {
    fn name(&self) -> &str { "Byte Count" }
    fn storage_key(&self) -> &str { "Byte Count" }
    fn description(&self) -> &str { "Number of bytes to display" }
}

impl ByteCountSettingsDefinition {
    /// Returns the byte count setting, defaulting to 8.
    pub fn get_count(&self, settings: &Settings) -> usize {
        settings.get_long(self.storage_key())
            .filter(|&v| v > 0)
            .map(|v| v as usize)
            .unwrap_or(8)
    }
}

// ---------------------------------------------------------------------------
// CodeUnitCountSettingsDefinition
// ---------------------------------------------------------------------------

/// Controls how many code unit lines are displayed in a preview column.
///
/// Ported from `ghidra.util.table.field.CodeUnitCountSettingsDefinition`.
#[derive(Debug)]
pub struct CodeUnitCountSettingsDefinition;

pub static CODE_UNIT_COUNT_DEF: CodeUnitCountSettingsDefinition = CodeUnitCountSettingsDefinition;

impl SettingsDefinition for CodeUnitCountSettingsDefinition {
    fn name(&self) -> &str { "Code Unit Count" }
    fn storage_key(&self) -> &str { "Code Unit Count" }
    fn description(&self) -> &str { "Number of code units to display" }
}

impl CodeUnitCountSettingsDefinition {
    /// Returns the count, defaulting to 1.
    pub fn get_count(&self, settings: &Settings) -> usize {
        settings.get_long(self.storage_key())
            .filter(|&v| v > 0)
            .map(|v| v as usize)
            .unwrap_or(1)
    }
}

// ---------------------------------------------------------------------------
// CodeUnitOffsetSettingsDefinition
// ---------------------------------------------------------------------------

/// Controls the byte offset from the code unit start for preview columns.
///
/// Ported from `ghidra.util.table.field.CodeUnitOffsetSettingsDefinition`.
#[derive(Debug)]
pub struct CodeUnitOffsetSettingsDefinition;

pub static CODE_UNIT_OFFSET_DEF: CodeUnitOffsetSettingsDefinition =
    CodeUnitOffsetSettingsDefinition;

impl SettingsDefinition for CodeUnitOffsetSettingsDefinition {
    fn name(&self) -> &str { "Code Unit Offset" }
    fn storage_key(&self) -> &str { "Code Unit Offset" }
    fn description(&self) -> &str { "Byte offset from code unit start" }
}

impl CodeUnitOffsetSettingsDefinition {
    /// Returns the offset as a display string (e.g., "+2").
    pub fn get_display_value(&self, settings: &Settings) -> String {
        let offset = settings.get_long(self.storage_key()).unwrap_or(0);
        if offset == 0 {
            "0".to_string()
        } else if offset > 0 {
            format!("+{}", offset)
        } else {
            format!("{}", offset)
        }
    }

    /// Returns the offset value.
    pub fn get_offset(&self, settings: &Settings) -> usize {
        settings.get_long(self.storage_key())
            .filter(|&v| v >= 0)
            .map(|v| v as usize)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// MemoryOffsetSettingsDefinition
// ---------------------------------------------------------------------------

/// Controls offset display in memory section columns.
///
/// Ported from `ghidra.util.table.field.MemoryOffsetSettingsDefinition`.
#[derive(Debug)]
pub struct MemoryOffsetSettingsDefinition;

pub static MEMORY_OFFSET_DEF: MemoryOffsetSettingsDefinition = MemoryOffsetSettingsDefinition;

impl BooleanSettingsDefinition for MemoryOffsetSettingsDefinition {
    fn get_value(&self, settings: &Settings) -> bool {
        settings.get_bool(self.storage_key()).unwrap_or(false)
    }

    fn set_value(&self, settings: &mut Settings, value: bool) {
        settings.set_string(self.storage_key(), if value { "1" } else { "0" });
    }
}

impl SettingsDefinition for MemoryOffsetSettingsDefinition {
    fn name(&self) -> &str { "Show Memory Offset" }
    fn storage_key(&self) -> &str { "Memory Offset" }
    fn description(&self) -> &str { "Show offset from memory block start" }
}

// ---------------------------------------------------------------------------
// Function settings definitions
// ---------------------------------------------------------------------------

/// Controls whether "inline" annotation is shown in function signature columns.
///
/// Ported from `ghidra.util.table.field.FunctionInlineSettingsDefinition`.
#[derive(Debug)]
pub struct FunctionInlineSettingsDefinition;

pub static FUNCTION_INLINE_DEF: FunctionInlineSettingsDefinition =
    FunctionInlineSettingsDefinition;

impl BooleanSettingsDefinition for FunctionInlineSettingsDefinition {
    fn get_value(&self, settings: &Settings) -> bool {
        settings.get_bool(self.storage_key()).unwrap_or(true)
    }
    fn set_value(&self, settings: &mut Settings, value: bool) {
        settings.set_string(self.storage_key(), if value { "1" } else { "0" });
    }
}

impl SettingsDefinition for FunctionInlineSettingsDefinition {
    fn name(&self) -> &str { "Show Inline" }
    fn storage_key(&self) -> &str { "Function Inline" }
    fn description(&self) -> &str { "Show inline annotation for functions" }
}

/// Controls whether "thunk" annotation is shown.
///
/// Ported from `ghidra.util.table.field.FunctionThunkSettingsDefinition`.
#[derive(Debug)]
pub struct FunctionThunkSettingsDefinition;

pub static FUNCTION_THUNK_DEF: FunctionThunkSettingsDefinition = FunctionThunkSettingsDefinition;

impl BooleanSettingsDefinition for FunctionThunkSettingsDefinition {
    fn get_value(&self, settings: &Settings) -> bool {
        settings.get_bool(self.storage_key()).unwrap_or(true)
    }
    fn set_value(&self, settings: &mut Settings, value: bool) {
        settings.set_string(self.storage_key(), if value { "1" } else { "0" });
    }
}

impl SettingsDefinition for FunctionThunkSettingsDefinition {
    fn name(&self) -> &str { "Show Thunk" }
    fn storage_key(&self) -> &str { "Function Thunk" }
    fn description(&self) -> &str { "Show thunk annotation for functions" }
}

/// Controls whether "noreturn" annotation is shown.
///
/// Ported from `ghidra.util.table.field.FunctionNoReturnSettingsDefinition`.
#[derive(Debug)]
pub struct FunctionNoReturnSettingsDefinition;

pub static FUNCTION_NORETURN_DEF: FunctionNoReturnSettingsDefinition =
    FunctionNoReturnSettingsDefinition;

impl BooleanSettingsDefinition for FunctionNoReturnSettingsDefinition {
    fn get_value(&self, settings: &Settings) -> bool {
        settings.get_bool(self.storage_key()).unwrap_or(true)
    }
    fn set_value(&self, settings: &mut Settings, value: bool) {
        settings.set_string(self.storage_key(), if value { "1" } else { "0" });
    }
}

impl SettingsDefinition for FunctionNoReturnSettingsDefinition {
    fn name(&self) -> &str { "Show No Return" }
    fn storage_key(&self) -> &str { "Function NoReturn" }
    fn description(&self) -> &str { "Show noreturn annotation for functions" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_range_endpoint_default() {
        let s = Settings::new();
        assert_eq!(ADDRESS_RANGE_ENDPOINT_DEF.get_choice(&s), 0);
        assert_eq!(ADDRESS_RANGE_ENDPOINT_DEF.display_choice(0), "Begin");
        assert_eq!(ADDRESS_RANGE_ENDPOINT_DEF.display_choice(1), "End");
    }

    #[test]
    fn test_address_range_endpoint_set() {
        let mut s = Settings::new();
        ADDRESS_RANGE_ENDPOINT_DEF.set_choice(&mut s, END_CHOICE_INDEX);
        assert_eq!(ADDRESS_RANGE_ENDPOINT_DEF.get_choice(&s), 1);
        assert_eq!(ADDRESS_RANGE_ENDPOINT_DEF.get_display_value(&s), "End");
    }

    #[test]
    fn test_byte_count_default() {
        let s = Settings::new();
        assert_eq!(BYTE_COUNT_DEF.get_count(&s), 8);
    }

    #[test]
    fn test_byte_count_custom() {
        let mut s = Settings::new();
        s.set_long("Byte Count", 16);
        assert_eq!(BYTE_COUNT_DEF.get_count(&s), 16);
    }

    #[test]
    fn test_code_unit_count_default() {
        let s = Settings::new();
        assert_eq!(CODE_UNIT_COUNT_DEF.get_count(&s), 1);
    }

    #[test]
    fn test_code_unit_offset_default() {
        let s = Settings::new();
        assert_eq!(CODE_UNIT_OFFSET_DEF.get_offset(&s), 0);
        assert_eq!(CODE_UNIT_OFFSET_DEF.get_display_value(&s), "0");
    }

    #[test]
    fn test_code_unit_offset_positive() {
        let mut s = Settings::new();
        s.set_long("Code Unit Offset", 3);
        assert_eq!(CODE_UNIT_OFFSET_DEF.get_display_value(&s), "+3");
        assert_eq!(CODE_UNIT_OFFSET_DEF.get_offset(&s), 3);
    }

    #[test]
    fn test_function_inline_default() {
        let s = Settings::new();
        assert!(FUNCTION_INLINE_DEF.get_value(&s));
    }

    #[test]
    fn test_function_thunk_default() {
        let s = Settings::new();
        assert!(FUNCTION_THUNK_DEF.get_value(&s));
    }

    #[test]
    fn test_function_noreturn_default() {
        let s = Settings::new();
        assert!(FUNCTION_NORETURN_DEF.get_value(&s));
    }

    #[test]
    fn test_memory_offset_default() {
        let s = Settings::new();
        assert!(!MEMORY_OFFSET_DEF.get_value(&s));
    }

    #[test]
    fn test_settings_definition_names() {
        assert_eq!(ADDRESS_RANGE_ENDPOINT_DEF.name(), "Endpoint");
        assert_eq!(BYTE_COUNT_DEF.name(), "Byte Count");
        assert_eq!(CODE_UNIT_COUNT_DEF.name(), "Code Unit Count");
        assert_eq!(FUNCTION_INLINE_DEF.name(), "Show Inline");
        assert_eq!(FUNCTION_THUNK_DEF.name(), "Show Thunk");
        assert_eq!(FUNCTION_NORETURN_DEF.name(), "Show No Return");
    }
}
