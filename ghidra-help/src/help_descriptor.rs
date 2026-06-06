//! `HelpDescriptor` -- trait for objects that self-describe for help purposes.
//!
//! Ported from `help.HelpDescriptor`.

/// An object that can describe itself for help display.
///
/// In Ghidra, this is used by the `DefaultHelpService` to display
/// diagnostic information about help registration.
pub trait HelpDescriptor {
    /// Returns a descriptive string about the help object this descriptor
    /// represents.
    fn get_help_info(&self) -> String;
}

/// Blanket helper to produce a simple descriptor from a type name.
#[derive(Debug, Clone)]
pub struct SimpleHelpDescriptor {
    /// The name of the described type or component.
    pub type_name: String,
    /// Optional extra info.
    pub extra_info: Option<String>,
}

impl SimpleHelpDescriptor {
    /// Create a new simple descriptor.
    pub fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            extra_info: None,
        }
    }

    /// Create with extra information.
    pub fn with_info(type_name: impl Into<String>, info: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            extra_info: Some(info.into()),
        }
    }
}

impl HelpDescriptor for SimpleHelpDescriptor {
    fn get_help_info(&self) -> String {
        match &self.extra_info {
            Some(info) => format!("{}: {}", self.type_name, info),
            None => self.type_name.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_descriptor_basic() {
        let d = SimpleHelpDescriptor::new("MyWidget");
        assert_eq!(d.get_help_info(), "MyWidget");
    }

    #[test]
    fn test_simple_descriptor_with_info() {
        let d = SimpleHelpDescriptor::with_info("Button", "OK button");
        assert_eq!(d.get_help_info(), "Button: OK button");
    }

    #[test]
    fn test_descriptor_clone() {
        let d = SimpleHelpDescriptor::new("X");
        let d2 = d.clone();
        assert_eq!(d2.type_name, "X");
    }
}
