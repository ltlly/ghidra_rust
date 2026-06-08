//! GUI bean (component) utility types.
//!
//! Ports `ghidra.util.bean` and `ghidra.util.bean.opteditor` from Ghidra's
//! Java source into idiomatic Rust types.


/// A generic property change event.
///
/// Ports `java.beans.PropertyChangeEvent` usage patterns in Ghidra.
#[derive(Debug, Clone)]
pub struct PropertyChangeEvent {
    /// The source object that fired the event.
    pub source_id: u64,
    /// The property name that changed.
    pub property_name: String,
    /// The old value (as a boxed any).
    pub old_value: Option<PropertyValue>,
    /// The new value (as a boxed any).
    pub new_value: Option<PropertyValue>,
}

impl PropertyChangeEvent {
    /// Create a new property change event.
    pub fn new(
        source_id: u64,
        property_name: impl Into<String>,
        old_value: Option<PropertyValue>,
        new_value: Option<PropertyValue>,
    ) -> Self {
        Self {
            source_id,
            property_name: property_name.into(),
            old_value,
            new_value,
        }
    }
}

/// A property value that can be stored in a PropertyChangeEvent.
#[derive(Debug, Clone, PartialEq)]
pub enum PropertyValue {
    /// A string value.
    String(String),
    /// A boolean value.
    Bool(bool),
    /// An integer value.
    Int(i64),
    /// A floating-point value.
    Float(f64),
}

impl std::fmt::Display for PropertyValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PropertyValue::String(s) => write!(f, "{}", s),
            PropertyValue::Bool(b) => write!(f, "{}", b),
            PropertyValue::Int(i) => write!(f, "{}", i),
            PropertyValue::Float(fl) => write!(f, "{}", fl),
        }
    }
}

/// A listener for property change events.
pub trait PropertyChangeListener: Send + Sync {
    /// Called when a property changes.
    fn property_changed(&mut self, event: &PropertyChangeEvent);
}

/// A model for editable option values in the GUI.
///
/// Ports `ghidra.util.bean.opteditor` option editor types.
#[derive(Debug, Clone)]
pub struct OptionEditorModel {
    /// The option key.
    pub key: String,
    /// The current value.
    pub value: PropertyValue,
    /// The display name.
    pub display_name: String,
    /// The description.
    pub description: String,
    /// Whether the option is enabled for editing.
    pub enabled: bool,
    /// Valid values (for enum-style options).
    pub valid_values: Vec<PropertyValue>,
}

impl OptionEditorModel {
    /// Create a new option editor model.
    pub fn new(
        key: impl Into<String>,
        value: PropertyValue,
        display_name: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            value,
            display_name: display_name.into(),
            description: String::new(),
            enabled: true,
            valid_values: Vec::new(),
        }
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set valid values.
    pub fn with_valid_values(mut self, values: Vec<PropertyValue>) -> Self {
        self.valid_values = values;
        self
    }

    /// Set the value.
    pub fn set_value(&mut self, value: PropertyValue) {
        self.value = value;
    }
}

/// A container for multiple option editor models.
#[derive(Debug, Clone, Default)]
pub struct OptionEditorPanel {
    /// The options in this panel.
    pub options: Vec<OptionEditorModel>,
    /// The panel title.
    pub title: String,
}

impl OptionEditorPanel {
    /// Create a new empty panel.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            options: Vec::new(),
            title: title.into(),
        }
    }

    /// Add an option to the panel.
    pub fn add_option(&mut self, model: OptionEditorModel) {
        self.options.push(model);
    }

    /// Get the number of options.
    pub fn option_count(&self) -> usize {
        self.options.len()
    }

    /// Get an option by key.
    pub fn get_option(&self, key: &str) -> Option<&OptionEditorModel> {
        self.options.iter().find(|o| o.key == key)
    }

    /// Get a mutable option by key.
    pub fn get_option_mut(&mut self, key: &str) -> Option<&mut OptionEditorModel> {
        self.options.iter_mut().find(|o| o.key == key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_change_event() {
        let event = PropertyChangeEvent::new(
            1,
            "text",
            Some(PropertyValue::String("old".into())),
            Some(PropertyValue::String("new".into())),
        );
        assert_eq!(event.property_name, "text");
        assert_eq!(event.old_value, Some(PropertyValue::String("old".into())));
        assert_eq!(event.new_value, Some(PropertyValue::String("new".into())));
    }

    #[test]
    fn test_property_value_display() {
        assert_eq!(PropertyValue::String("hello".into()).to_string(), "hello");
        assert_eq!(PropertyValue::Bool(true).to_string(), "true");
        assert_eq!(PropertyValue::Int(42).to_string(), "42");
        assert_eq!(PropertyValue::Float(3.14).to_string(), "3.14");
    }

    #[test]
    fn test_option_editor_model() {
        let model = OptionEditorModel::new(
            "theme.color.bg",
            PropertyValue::String("#FFFFFF".into()),
            "Background Color",
        )
        .with_description("The background color of the editor");
        assert_eq!(model.key, "theme.color.bg");
        assert!(model.enabled);
        assert_eq!(model.description, "The background color of the editor");
    }

    #[test]
    fn test_option_editor_panel() {
        let mut panel = OptionEditorPanel::new("Theme Options");
        assert_eq!(panel.option_count(), 0);

        panel.add_option(OptionEditorModel::new(
            "color.bg",
            PropertyValue::String("#000000".into()),
            "Background",
        ));
        panel.add_option(OptionEditorModel::new(
            "font.size",
            PropertyValue::Int(12),
            "Font Size",
        ));

        assert_eq!(panel.option_count(), 2);
        assert!(panel.get_option("color.bg").is_some());
        assert!(panel.get_option("nonexistent").is_none());

        if let Some(opt) = panel.get_option_mut("font.size") {
            opt.set_value(PropertyValue::Int(14));
        }
        assert_eq!(panel.get_option("font.size").unwrap().value, PropertyValue::Int(14));
    }
}
