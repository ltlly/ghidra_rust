//! Dynamic help location that resolves help topics at runtime.
//!
//! Ports `ghidra.util.DynamicHelpLocation` from Ghidra's Java source.
//!
//! Unlike a static `HelpLocation` which points to a fixed help page,
//! a `DynamicHelpLocation` resolves the help topic based on the current
//! state of the application (e.g., the currently selected object).

/// A help location that dynamically resolves its help topic.
///
/// Ports `ghidra.util.DynamicHelpLocation`. This is used when the help
/// topic for an action or component depends on context that is only known
/// at the time help is requested (e.g., the type of the currently selected
/// data in the listing).
#[derive(Debug, Clone)]
pub struct DynamicHelpLocation {
    /// The help book name.
    book_name: String,
    /// The help topic id (may be a template with placeholders).
    topic_id: String,
    /// An anchor within the help page.
    anchor: Option<String>,
    /// The resolver function description (for debugging/logging).
    resolver_description: String,
}

impl DynamicHelpLocation {
    /// Create a new dynamic help location.
    pub fn new(
        book_name: impl Into<String>,
        topic_id: impl Into<String>,
    ) -> Self {
        Self {
            book_name: book_name.into(),
            topic_id: topic_id.into(),
            anchor: None,
            resolver_description: String::new(),
        }
    }

    /// Set an anchor within the help page.
    pub fn with_anchor(mut self, anchor: impl Into<String>) -> Self {
        self.anchor = Some(anchor.into());
        self
    }

    /// Set the resolver description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.resolver_description = desc.into();
        self
    }

    /// Get the help book name.
    pub fn book_name(&self) -> &str {
        &self.book_name
    }

    /// Get the topic id template.
    pub fn topic_id(&self) -> &str {
        &self.topic_id
    }

    /// Get the anchor, if set.
    pub fn anchor(&self) -> Option<&str> {
        self.anchor.as_deref()
    }

    /// Resolve the help location to a concrete topic id.
    ///
    /// In the Java implementation, this calls a resolver callback.
    /// In the Rust port, we resolve template placeholders in the topic id.
    pub fn resolve(&self, context: &HelpContext) -> ResolvedHelpLocation {
        let resolved_topic = self.resolve_topic(context);
        ResolvedHelpLocation {
            book_name: self.book_name.clone(),
            topic_id: resolved_topic,
            anchor: self.anchor.clone(),
        }
    }

    /// Resolve template placeholders in the topic id.
    fn resolve_topic(&self, context: &HelpContext) -> String {
        let mut topic = self.topic_id.clone();
        topic = topic.replace("{CLASS}", &context.class_name);
        topic = topic.replace("{ACTION}", &context.action_name);
        topic = topic.replace("{PLUGIN}", &context.plugin_name);
        topic = topic.replace("{DATA_TYPE}", &context.data_type_name);
        topic
    }
}

/// Context information used to resolve dynamic help topics.
#[derive(Debug, Clone, Default)]
pub struct HelpContext {
    /// The class name of the requesting component.
    pub class_name: String,
    /// The action name.
    pub action_name: String,
    /// The plugin name.
    pub plugin_name: String,
    /// The data type name (e.g., for data in the listing).
    pub data_type_name: String,
}

/// A resolved (concrete) help location with no placeholders.
#[derive(Debug, Clone)]
pub struct ResolvedHelpLocation {
    /// The help book name.
    pub book_name: String,
    /// The resolved topic id.
    pub topic_id: String,
    /// An anchor within the help page.
    pub anchor: Option<String>,
}

impl ResolvedHelpLocation {
    /// Get the full help URL path (book/topic).
    pub fn url_path(&self) -> String {
        match &self.anchor {
            Some(anchor) => format!("{}/{}#{}", self.book_name, self.topic_id, anchor),
            None => format!("{}/{}", self.book_name, self.topic_id),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_help_location_new() {
        let loc = DynamicHelpLocation::new("MyPlugin", "main_topic");
        assert_eq!(loc.book_name(), "MyPlugin");
        assert_eq!(loc.topic_id(), "main_topic");
        assert!(loc.anchor().is_none());
    }

    #[test]
    fn dynamic_help_location_with_anchor() {
        let loc = DynamicHelpLocation::new("MyPlugin", "topic")
            .with_anchor("section1");
        assert_eq!(loc.anchor(), Some("section1"));
    }

    #[test]
    fn dynamic_help_location_with_description() {
        let loc = DynamicHelpLocation::new("MyPlugin", "topic")
            .with_description("Help for the main action");
        assert!(!loc.resolver_description.is_empty());
    }

    #[test]
    fn resolve_no_placeholders() {
        let loc = DynamicHelpLocation::new("MyPlugin", "static_topic");
        let ctx = HelpContext::default();
        let resolved = loc.resolve(&ctx);
        assert_eq!(resolved.topic_id, "static_topic");
        assert_eq!(resolved.book_name, "MyPlugin");
    }

    #[test]
    fn resolve_class_placeholder() {
        let loc = DynamicHelpLocation::new("MyPlugin", "{CLASS}_help");
        let ctx = HelpContext {
            class_name: "ListingPanel".into(),
            ..HelpContext::default()
        };
        let resolved = loc.resolve(&ctx);
        assert_eq!(resolved.topic_id, "ListingPanel_help");
    }

    #[test]
    fn resolve_action_placeholder() {
        let loc = DynamicHelpLocation::new("Actions", "action_{ACTION}");
        let ctx = HelpContext {
            action_name: "CopyAction".into(),
            ..HelpContext::default()
        };
        let resolved = loc.resolve(&ctx);
        assert_eq!(resolved.topic_id, "action_CopyAction");
    }

    #[test]
    fn resolve_multiple_placeholders() {
        let loc = DynamicHelpLocation::new("Plugins", "{PLUGIN}/{CLASS}/{DATA_TYPE}");
        let ctx = HelpContext {
            plugin_name: "decompiler".into(),
            class_name: "DecompilerPanel".into(),
            data_type_name: "int".into(),
            ..HelpContext::default()
        };
        let resolved = loc.resolve(&ctx);
        assert_eq!(resolved.topic_id, "decompiler/DecompilerPanel/int");
    }

    #[test]
    fn resolved_url_path() {
        let loc = DynamicHelpLocation::new("MyBook", "topic1");
        let resolved = loc.resolve(&HelpContext::default());
        assert_eq!(resolved.url_path(), "MyBook/topic1");
    }

    #[test]
    fn resolved_url_path_with_anchor() {
        let loc = DynamicHelpLocation::new("MyBook", "topic1").with_anchor("sec2");
        let resolved = loc.resolve(&HelpContext::default());
        assert_eq!(resolved.url_path(), "MyBook/topic1#sec2");
    }

    #[test]
    fn help_context_default() {
        let ctx = HelpContext::default();
        assert!(ctx.class_name.is_empty());
        assert!(ctx.action_name.is_empty());
        assert!(ctx.plugin_name.is_empty());
        assert!(ctx.data_type_name.is_empty());
    }
}
