//! Factory for creating EditorState objects for option types.
//!
//! Ports `ghidra.framework.options.EditorStateFactory`.

use super::editor_state::EditorState;
use super::option_type::OptionType;
use super::option_value::OptionValue;

/// Factory that creates EditorState objects for different option types.
///
/// This is used by the options dialog to create the appropriate
/// editing widget for each option type.
#[derive(Debug, Clone)]
pub struct EditorStateFactory {
    /// Whether to use compact layout.
    pub compact: bool,
}

impl EditorStateFactory {
    /// Create a new EditorStateFactory.
    pub fn new() -> Self {
        Self { compact: false }
    }

    /// Create with compact mode.
    pub fn compact() -> Self {
        Self { compact: true }
    }

    /// Create an EditorState for the given option type and name.
    pub fn create(&self, option_type: OptionType, name: &str) -> EditorState {
        let default_value = match option_type {
            OptionType::IntType => OptionValue::Int(0),
            OptionType::LongType => OptionValue::Long(0),
            OptionType::StringType => OptionValue::String(String::new()),
            OptionType::DoubleType => OptionValue::Double(0.0),
            OptionType::BooleanType => OptionValue::Boolean(false),
            OptionType::FloatType => OptionValue::Float(0.0),
            OptionType::EnumType => OptionValue::Enum(String::new()),
            OptionType::ByteArrayType => OptionValue::ByteArray(Vec::new()),
            OptionType::FileType => OptionValue::File(std::path::PathBuf::new()),
            OptionType::DateType => OptionValue::Date(String::new()),
            OptionType::CustomType => OptionValue::Custom(String::new()),
            _ => OptionValue::None,
        };
        EditorState::new(name, default_value)
    }
}

impl Default for EditorStateFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factory_create() {
        let factory = EditorStateFactory::new();
        let state = factory.create(OptionType::BooleanType, "test.option");
        assert_eq!(state.name(), "test.option");
    }

    #[test]
    fn test_factory_compact() {
        let factory = EditorStateFactory::compact();
        assert!(factory.compact);
    }
}
