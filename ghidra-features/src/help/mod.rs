//! Help Plugin -- help system integration.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.help` Java package.
//!
//! Provides model-level logic for the Ghidra help system, including
//! help location tracking, help topic management, help sets for grouping
//! related topics, topic search, and service-level registration.
//!
//! # Key Types
//!
//! - [`HelpLocation`] -- identifies a specific help topic by set, file, and anchor
//! - [`HelpTopic`] -- a single help entry with content and children
//! - [`HelpSet`] -- a named group of related help topics
//! - [`HelpService`] -- trait for pluggable help system backends
//! - [`HelpModel`] -- default in-memory implementation of the help service

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// HelpLocation
// ---------------------------------------------------------------------------

/// A help location identifies a specific help topic.
///
/// Ported from `ghidra.util.HelpLocation`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

    /// Return a display-friendly string for this location.
    pub fn display_string(&self) -> String {
        match &self.anchor {
            Some(a) => format!("{}::{}#{}", self.help_set, self.topic, a),
            None => format!("{}::{}", self.help_set, self.topic),
        }
    }
}

// ---------------------------------------------------------------------------
// HelpTopic
// ---------------------------------------------------------------------------

/// A help topic entry.
///
/// Ported from topic-related classes in `ghidra.app.plugin.core.help`.
#[derive(Debug, Clone)]
pub struct HelpTopic {
    /// The topic identifier.
    pub id: String,
    /// The display name.
    pub name: String,
    /// The help content (HTML or plain text).
    pub content: String,
    /// Child topic IDs.
    pub children: Vec<String>,
    /// The help set this topic belongs to.
    pub help_set: Option<String>,
}

impl HelpTopic {
    /// Create a new help topic.
    pub fn new(id: impl Into<String>, name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            content: content.into(),
            children: Vec::new(),
            help_set: None,
        }
    }

    /// Set the help set this topic belongs to.
    pub fn with_help_set(mut self, help_set: impl Into<String>) -> Self {
        self.help_set = Some(help_set.into());
        self
    }

    /// Add a child topic ID.
    pub fn add_child(&mut self, child_id: impl Into<String>) {
        self.children.push(child_id.into());
    }

    /// Whether this topic has children.
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }
}

// ---------------------------------------------------------------------------
// HelpSet -- a named group of related help topics
// ---------------------------------------------------------------------------

/// A help set groups related topics under a common name.
///
/// Ported from `javax.help.HelpSet` concept adapted for Ghidra.
#[derive(Debug, Clone)]
pub struct HelpSet {
    /// The name of this help set (e.g. "GhidraHelp").
    pub name: String,
    /// The base URL / path for this help set.
    pub base_url: String,
    /// Topic IDs belonging to this set.
    topic_ids: Vec<String>,
}

impl HelpSet {
    /// Create a new help set.
    pub fn new(name: impl Into<String>, base_url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            base_url: base_url.into(),
            topic_ids: Vec::new(),
        }
    }

    /// Register a topic ID in this set.
    pub fn add_topic_id(&mut self, id: impl Into<String>) {
        self.topic_ids.push(id.into());
    }

    /// Get all topic IDs in this set.
    pub fn topic_ids(&self) -> &[String] {
        &self.topic_ids
    }

    /// Number of topics in this set.
    pub fn topic_count(&self) -> usize {
        self.topic_ids.len()
    }
}

// ---------------------------------------------------------------------------
// HelpService -- trait for pluggable help backends
// ---------------------------------------------------------------------------

/// Trait for help system service implementations.
///
/// Ported from `ghidra.app.plugin.core.help.HelpService`.
pub trait HelpService {
    /// Register a help location for a given component ID.
    fn register_help_location(&mut self, component_id: &str, location: HelpLocation);

    /// Get the help location for a component.
    fn get_help_location(&self, component_id: &str) -> Option<&HelpLocation>;

    /// Remove the help location for a component.
    fn remove_help_location(&mut self, component_id: &str) -> Option<HelpLocation>;

    /// Search topics by keyword (case-insensitive substring match on name/content).
    fn search_topics(&self, query: &str) -> Vec<&HelpTopic>;

    /// Get a topic by ID.
    fn get_topic(&self, id: &str) -> Option<&HelpTopic>;

    /// Register a topic.
    fn register_topic(&mut self, topic: HelpTopic);

    /// The number of registered topics.
    fn topic_count(&self) -> usize;
}

// ---------------------------------------------------------------------------
// HelpModel -- in-memory default implementation
// ---------------------------------------------------------------------------

/// Model for the help system providing an in-memory implementation of
/// [`HelpService`].
#[derive(Debug, Default)]
pub struct HelpModel {
    topics: HashMap<String, HelpTopic>,
    help_sets: HashMap<String, HelpSet>,
    component_locations: HashMap<String, HelpLocation>,
}

impl HelpModel {
    /// Create a new help model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a help set.
    pub fn register_help_set(&mut self, help_set: HelpSet) {
        self.help_sets.insert(help_set.name.clone(), help_set);
    }

    /// Get a help set by name.
    pub fn get_help_set(&self, name: &str) -> Option<&HelpSet> {
        self.help_sets.get(name)
    }

    /// Get all help set names.
    pub fn help_set_names(&self) -> Vec<&str> {
        self.help_sets.keys().map(|s| s.as_str()).collect()
    }

    /// Get all topic IDs.
    pub fn topic_ids(&self) -> Vec<&str> {
        self.topics.keys().map(|s| s.as_str()).collect()
    }
}

impl HelpService for HelpModel {
    fn register_help_location(&mut self, component_id: &str, location: HelpLocation) {
        self.component_locations
            .insert(component_id.to_string(), location);
    }

    fn get_help_location(&self, component_id: &str) -> Option<&HelpLocation> {
        self.component_locations.get(component_id)
    }

    fn remove_help_location(&mut self, component_id: &str) -> Option<HelpLocation> {
        self.component_locations.remove(component_id)
    }

    fn search_topics(&self, query: &str) -> Vec<&HelpTopic> {
        let q = query.to_lowercase();
        self.topics
            .values()
            .filter(|t| {
                t.name.to_lowercase().contains(&q) || t.content.to_lowercase().contains(&q)
            })
            .collect()
    }

    fn get_topic(&self, id: &str) -> Option<&HelpTopic> {
        self.topics.get(id)
    }

    fn register_topic(&mut self, topic: HelpTopic) {
        self.topics.insert(topic.id.clone(), topic);
    }

    fn topic_count(&self) -> usize {
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
        assert_eq!(loc.topic, "index.html");
        assert_eq!(loc.anchor.as_deref(), Some("section1"));
    }

    #[test]
    fn test_help_location_display() {
        let loc = HelpLocation::new("Ghidra", "decompiler.html").with_anchor("syntax");
        assert_eq!(loc.display_string(), "Ghidra::decompiler.html#syntax");

        let loc2 = HelpLocation::new("Ghidra", "intro.html");
        assert_eq!(loc2.display_string(), "Ghidra::intro.html");
    }

    #[test]
    fn test_help_location_equality() {
        let a = HelpLocation::new("Set", "topic").with_anchor("a1");
        let b = HelpLocation::new("Set", "topic").with_anchor("a1");
        assert_eq!(a, b);
    }

    #[test]
    fn test_help_topic_new() {
        let topic = HelpTopic::new("intro", "Introduction", "Welcome to Ghidra");
        assert_eq!(topic.id, "intro");
        assert_eq!(topic.name, "Introduction");
        assert!(!topic.has_children());
    }

    #[test]
    fn test_help_topic_children() {
        let mut topic = HelpTopic::new("root", "Root", "Root topic");
        topic.add_child("child1");
        topic.add_child("child2");
        assert!(topic.has_children());
        assert_eq!(topic.children.len(), 2);
    }

    #[test]
    fn test_help_topic_with_help_set() {
        let topic = HelpTopic::new("t1", "Topic 1", "content").with_help_set("MySet");
        assert_eq!(topic.help_set.as_deref(), Some("MySet"));
    }

    #[test]
    fn test_help_set() {
        let mut hs = HelpSet::new("GhidraHelp", "/help/ghidra");
        hs.add_topic_id("intro");
        hs.add_topic_id("tutorial");
        assert_eq!(hs.topic_count(), 2);
        assert_eq!(hs.topic_ids()[0], "intro");
    }

    #[test]
    fn test_help_model_register_and_get() {
        let mut model = HelpModel::new();
        model.register_topic(
            HelpTopic::new("intro", "Introduction", "Welcome to Ghidra"),
        );
        let topic = model.get_topic("intro").unwrap();
        assert_eq!(topic.name, "Introduction");
    }

    #[test]
    fn test_help_model_search() {
        let mut model = HelpModel::new();
        model.register_topic(HelpTopic::new("t1", "Decompiler", "How to use the decompiler"));
        model.register_topic(HelpTopic::new("t2", "Assembler", "Assembly language basics"));
        model.register_topic(HelpTopic::new("t3", "Debug", "Debugging with Ghidra"));

        let results = model.search_topics("decompiler");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "t1");

        let results2 = model.search_topics("debug");
        assert_eq!(results2.len(), 1);
        assert_eq!(results2[0].id, "t3");

        // case-insensitive
        let results3 = model.search_topics("ASSEMBLY");
        assert_eq!(results3.len(), 1);
    }

    #[test]
    fn test_help_model_component_locations() {
        let mut model = HelpModel::new();
        let loc = HelpLocation::new("GhidraHelp", "decompiler.html");
        model.register_help_location("DecompilerProvider", loc.clone());

        let retrieved = model.get_help_location("DecompilerProvider").unwrap();
        assert_eq!(retrieved.topic, "decompiler.html");

        let removed = model.remove_help_location("DecompilerProvider");
        assert!(removed.is_some());
        assert!(model.get_help_location("DecompilerProvider").is_none());
    }

    #[test]
    fn test_help_model_help_sets() {
        let mut model = HelpModel::new();
        let hs = HelpSet::new("Core", "/help/core");
        model.register_help_set(hs);
        assert_eq!(model.help_set_names().len(), 1);
        assert!(model.get_help_set("Core").is_some());
        assert!(model.get_help_set("Missing").is_none());
    }

    #[test]
    fn test_help_model_topic_count() {
        let mut model = HelpModel::new();
        assert_eq!(model.topic_count(), 0);
        model.register_topic(HelpTopic::new("a", "A", "a"));
        model.register_topic(HelpTopic::new("b", "B", "b"));
        assert_eq!(model.topic_count(), 2);
    }
}
