//! Help Plugin -- help system integration.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.help` Java package.
//!
//! Provides model-level logic for the Ghidra help system, including
//! help location tracking and help topic management.

use std::collections::HashMap;

/// A help location identifies a specific help topic.
#[derive(Debug, Clone)]
pub struct HelpLocation {
    /// The help topic file (e.g. `"index.html"`).
    pub topic: String,
    /// The anchor within the topic (optional).
    pub anchor: Option<String>,
    /// The help set name.
    pub help_set: String,
}

impl HelpLocation {
    /// Create a new help location.
    pub fn new(help_set: impl Into<String>, topic: impl Into<String>) -> Self {
        Self {
            topic: topic.into(),
            anchor: None,
            help_set: help_set.into(),
        }
    }

    /// Set the anchor within the topic.
    pub fn with_anchor(mut self, anchor: impl Into<String>) -> Self {
        self.anchor = Some(anchor.into());
        self
    }
}

/// A help topic entry.
#[derive(Debug, Clone)]
pub struct HelpTopic {
    /// The topic identifier.
    pub id: String,
    /// The display name.
    pub name: String,
    /// The help content (HTML or plain text).
    pub content: String,
    /// Child topics.
    pub children: Vec<String>,
}

/// Model for the help system.
#[derive(Debug, Default)]
pub struct HelpModel {
    topics: HashMap<String, HelpTopic>,
}

impl HelpModel {
    /// Create a new help model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a help topic.
    pub fn register_topic(&mut self, topic: HelpTopic) {
        self.topics.insert(topic.id.clone(), topic);
    }

    /// Get a help topic by ID.
    pub fn get_topic(&self, id: &str) -> Option<&HelpTopic> {
        self.topics.get(id)
    }

    /// Get all topic IDs.
    pub fn topic_ids(&self) -> Vec<&str> {
        self.topics.keys().map(|s| s.as_str()).collect()
    }

    /// The number of registered topics.
    pub fn topic_count(&self) -> usize {
        self.topics.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_location() {
        let loc = HelpLocation::new("MyPlugin", "index.html").with_anchor("section1");
        assert_eq!(loc.help_set, "MyPlugin");
        assert_eq!(loc.anchor.as_deref(), Some("section1"));
    }

    #[test]
    fn test_help_model() {
        let mut model = HelpModel::new();
        model.register_topic(HelpTopic {
            id: "intro".into(),
            name: "Introduction".into(),
            content: "Welcome to Ghidra".into(),
            children: Vec::new(),
        });
        let topic = model.get_topic("intro").unwrap();
        assert_eq!(topic.name, "Introduction");
    }
}
