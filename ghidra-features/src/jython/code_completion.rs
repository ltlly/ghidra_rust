//! Jython code completion factory.
//!
//! Ported from `JythonCodeCompletionFactory.java` in the Jython extension.
//!
//! Generates code completions from Python objects, supporting syntax
//! coloring based on object type (function, class, method, etc.).

use std::collections::HashMap;

/// Syntax highlighting color names for Python object types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompletionColor {
    /// Color for `None` objects.
    Null,
    /// Color for function objects.
    Function,
    /// Color for package/module objects.
    Package,
    /// Color for class objects.
    Class,
    /// Color for method objects.
    Method,
    /// Color for anonymous code chunks.
    Code,
    /// Color for instance objects.
    Instance,
    /// Color for sequence objects (list, tuple).
    Sequence,
    /// Color for map/dict objects.
    Map,
    /// Color for number objects.
    Number,
    /// Color for special/Jython-specific objects.
    Special,
}

/// A code completion entry.
#[derive(Debug, Clone)]
pub struct CodeCompletion {
    /// Description shown in the completion popup.
    pub description: String,
    /// The text to insert.
    pub insertion: String,
    /// The syntax color for this completion.
    pub color: CompletionColor,
    /// Number of characters of user input to replace.
    pub chars_to_remove: usize,
}

/// Settings for code completion behavior.
#[derive(Debug, Clone)]
pub struct CompletionSettings {
    /// Whether to include type names in the popup.
    pub include_types: bool,
}

impl Default for CompletionSettings {
    fn default() -> Self {
        Self {
            include_types: true,
        }
    }
}

/// Factory for generating code completions from Python objects.
///
/// Manages the mapping between Python object types and their display
/// colors, and generates completion entries from introspected objects.
#[derive(Debug)]
pub struct JythonCodeCompletionFactory {
    /// Registered class name to color mappings (ordered by priority).
    class_entries: Vec<(String, CompletionColor, String)>,
    /// Settings.
    settings: CompletionSettings,
}

impl JythonCodeCompletionFactory {
    /// Create a new factory with default Python type registrations.
    pub fn new() -> Self {
        let mut factory = Self {
            class_entries: Vec::new(),
            settings: CompletionSettings::default(),
        };
        factory.register_defaults();
        factory
    }

    /// Register the default Python type to color mappings.
    fn register_defaults(&mut self) {
        self.register_class("NoneType", CompletionColor::Null, "'None' (null) objects");
        self.register_class("function", CompletionColor::Function, "Functions");
        self.register_class("builtin_function_or_method", CompletionColor::Function, "Built-in functions");
        self.register_class("type", CompletionColor::Class, "Classes");
        self.register_class("module", CompletionColor::Package, "Modules/Packages");
        self.register_class("method", CompletionColor::Method, "Methods");
        self.register_class("method-wrapper", CompletionColor::Method, "Method wrappers");
        self.register_class("list", CompletionColor::Sequence, "Lists");
        self.register_class("tuple", CompletionColor::Sequence, "Tuples");
        self.register_class("dict", CompletionColor::Map, "Dictionaries");
        self.register_class("int", CompletionColor::Number, "Integers");
        self.register_class("float", CompletionColor::Number, "Floats");
    }

    /// Register a Python class name to color mapping.
    pub fn register_class(
        &mut self,
        class_name: impl Into<String>,
        color: CompletionColor,
        description: impl Into<String>,
    ) {
        self.class_entries
            .push((class_name.into(), color, description.into()));
    }

    /// Look up the color for a Python type name.
    pub fn color_for_type(&self, type_name: &str) -> CompletionColor {
        for (class_name, color, _) in &self.class_entries {
            if class_name == type_name {
                return *color;
            }
        }
        CompletionColor::Code
    }

    /// Create a code completion for a member of a Python object.
    ///
    /// # Parameters
    /// - `user_input`: The text the user has typed so far.
    /// - `member_name`: The name of the member to complete.
    /// - `type_name`: The Python type name of the member.
    pub fn create_completion(
        &self,
        user_input: &str,
        member_name: &str,
        type_name: &str,
    ) -> CodeCompletion {
        let color = self.color_for_type(type_name);

        let insertion = if self.settings.include_types {
            format!("{member_name} ({type_name})")
        } else {
            member_name.to_string()
        };

        CodeCompletion {
            description: format!("{member_name} -- {type_name}"),
            insertion,
            color,
            chars_to_remove: user_input.len(),
        }
    }

    /// Generate completions for members of a Python object.
    ///
    /// `members` maps member names to their type names.
    pub fn generate_completions(
        &self,
        user_input: &str,
        members: &HashMap<String, String>,
    ) -> Vec<CodeCompletion> {
        let mut completions: Vec<CodeCompletion> = members
            .iter()
            .filter(|(name, _)| name.starts_with(user_input))
            .map(|(name, type_name)| self.create_completion(user_input, name, type_name))
            .collect();

        completions.sort_by(|a, b| a.insertion.cmp(&b.insertion));
        completions
    }

    /// Get the current settings.
    pub fn settings(&self) -> &CompletionSettings {
        &self.settings
    }

    /// Update settings.
    pub fn set_settings(&mut self, settings: CompletionSettings) {
        self.settings = settings;
    }
}

impl Default for JythonCodeCompletionFactory {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factory_creation() {
        let factory = JythonCodeCompletionFactory::new();
        assert!(!factory.class_entries.is_empty());
    }

    #[test]
    fn test_color_for_known_type() {
        let factory = JythonCodeCompletionFactory::new();
        assert_eq!(factory.color_for_type("function"), CompletionColor::Function);
        assert_eq!(factory.color_for_type("type"), CompletionColor::Class);
        assert_eq!(factory.color_for_type("int"), CompletionColor::Number);
    }

    #[test]
    fn test_color_for_unknown_type() {
        let factory = JythonCodeCompletionFactory::new();
        assert_eq!(factory.color_for_type("unknown_type"), CompletionColor::Code);
    }

    #[test]
    fn test_create_completion_with_types() {
        let factory = JythonCodeCompletionFactory::new();
        let comp = factory.create_completion("hea", "head", "method");
        assert_eq!(comp.color, CompletionColor::Method);
        assert_eq!(comp.chars_to_remove, 3);
        assert!(comp.insertion.contains("head"));
        assert!(comp.insertion.contains("method"));
    }

    #[test]
    fn test_create_completion_without_types() {
        let mut factory = JythonCodeCompletionFactory::new();
        factory.set_settings(CompletionSettings {
            include_types: false,
        });
        let comp = factory.create_completion("hea", "head", "method");
        assert_eq!(comp.insertion, "head");
    }

    #[test]
    fn test_generate_completions() {
        let factory = JythonCodeCompletionFactory::new();
        let mut members = HashMap::new();
        members.insert("append".to_string(), "method".to_string());
        members.insert("clear".to_string(), "method".to_string());
        members.insert("count".to_string(), "function".to_string());

        let completions = factory.generate_completions("a", &members);
        assert_eq!(completions.len(), 1);
        assert!(completions[0].insertion.starts_with("append"));
    }

    #[test]
    fn test_generate_completions_sorted() {
        let factory = JythonCodeCompletionFactory::new();
        let mut members = HashMap::new();
        members.insert("zebra".to_string(), "method".to_string());
        members.insert("alpha".to_string(), "method".to_string());
        members.insert("beta".to_string(), "method".to_string());

        let completions = factory.generate_completions("", &members);
        assert_eq!(completions.len(), 3);
        for i in 1..completions.len() {
            assert!(completions[i - 1].insertion <= completions[i].insertion);
        }
    }

    #[test]
    fn test_register_custom_class() {
        let mut factory = JythonCodeCompletionFactory::new();
        factory.register_class("MyCustomClass", CompletionColor::Special, "Custom");
        assert_eq!(
            factory.color_for_type("MyCustomClass"),
            CompletionColor::Special
        );
    }

    #[test]
    fn test_completion_settings_default() {
        let settings = CompletionSettings::default();
        assert!(settings.include_types);
    }
}
