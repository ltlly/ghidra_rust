//! Constraint-based decision tree framework.
//!
//! Ports Ghidra's `generic.constraint` package. Provides a generic
//! decision-tree engine where each node holds a constraint. Traversing
//! the tree with a test object collects property values from the most
//! specific matching nodes.
//!
//! # Java sources migrated
//!
//! | Java class                          | Rust type                |
//! |-------------------------------------|--------------------------|
//! | `generic.constraint.Constraint`     | [`Constraint`] (trait)   |
//! | `generic.constraint.ConstraintData` | [`ConstraintData`]       |
//! | `generic.constraint.Decision`       | [`Decision`]             |
//! | `generic.constraint.DecisionSet`    | [`DecisionSet`]          |
//! | `generic.constraint.DecisionNode`   | [`DecisionNode`]         |
//! | `generic.constraint.RootDecisionNode`| [`RootDecisionNode`]    |
//! | `generic.constraint.DecisionTree`   | [`DecisionTree`]         |

use std::collections::HashMap;
use std::fmt;

// ============================================================================
// Constraint trait
// ============================================================================

/// A constraint that can be tested against an object.
///
/// Corresponds to Ghidra's abstract `Constraint<T>` class. Each constraint
/// has a name (also used as an XML tag in specification files) and can test
/// whether a given object satisfies it.
pub trait Constraint<T>: Send + Sync {
    /// Returns the name of this constraint.
    fn name(&self) -> &str;

    /// Returns `true` if the given object satisfies this constraint.
    fn is_satisfied(&self, test_object: &T) -> bool;

    /// Returns a description of this constraint with its configuration data.
    fn description(&self) -> String;
}

// ============================================================================
// ConstraintData
// ============================================================================

/// A map of named string values used to configure constraints.
///
/// Corresponds to Ghidra's `ConstraintData`, which converts XML attributes
/// into typed property values.
///
/// # Examples
///
/// ```
/// use ghidra_core::generic::constraint::ConstraintData;
///
/// let mut map = std::collections::HashMap::new();
/// map.insert("name".to_string(), "foo".to_string());
/// map.insert("count".to_string(), "42".to_string());
/// map.insert("enabled".to_string(), "true".to_string());
///
/// let data = ConstraintData::new(map);
/// assert_eq!(data.get_string("name"), Some("foo"));
/// assert_eq!(data.get_int("count"), Some(42));
/// assert_eq!(data.get_boolean("enabled"), Some(true));
/// ```
#[derive(Debug, Clone)]
pub struct ConstraintData {
    map: HashMap<String, String>,
}

/// Error type for constraint data parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintDataError {
    pub field: String,
    pub expected: String,
    pub actual: Option<String>,
}

impl fmt::Display for ConstraintDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.actual {
            Some(val) => write!(
                f,
                "Expected {} value for attribute \"{}\", but was \"{}\"",
                self.expected, self.field, val
            ),
            None => write!(
                f,
                "Missing {} value for attribute \"{}\"",
                self.expected, self.field
            ),
        }
    }
}

impl std::error::Error for ConstraintDataError {}

impl ConstraintData {
    /// Create a new `ConstraintData` from a string map.
    pub fn new(map: HashMap<String, String>) -> Self {
        Self { map }
    }

    /// Create from an iterator of key-value pairs.
    pub fn from_pairs<I, K, V>(iter: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            map: iter.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
        }
    }

    /// Returns `true` if the given field name exists.
    pub fn has_value(&self, name: &str) -> bool {
        self.map.contains_key(name)
    }

    /// Get a string value.
    pub fn get_string(&self, name: &str) -> Option<&str> {
        self.map.get(name).map(|s| s.as_str())
    }

    /// Get an integer value.
    pub fn get_int(&self, name: &str) -> Option<i32> {
        self.map
            .get(name)
            .and_then(|v| v.parse::<i32>().ok())
    }

    /// Get a long integer value.
    pub fn get_long(&self, name: &str) -> Option<i64> {
        self.map
            .get(name)
            .and_then(|v| v.parse::<i64>().ok())
    }

    /// Get a boolean value.
    pub fn get_boolean(&self, name: &str) -> Option<bool> {
        self.map.get(name).and_then(|v| match v.to_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
    }

    /// Get a float value.
    pub fn get_float(&self, name: &str) -> Option<f32> {
        self.map
            .get(name)
            .and_then(|v| v.parse::<f32>().ok())
    }

    /// Get a double value.
    pub fn get_double(&self, name: &str) -> Option<f64> {
        self.map
            .get(name)
            .and_then(|v| v.parse::<f64>().ok())
    }

    /// Get a string value, returning an error if missing.
    pub fn require_string(&self, name: &str) -> Result<&str, ConstraintDataError> {
        self.get_string(name).ok_or_else(|| ConstraintDataError {
            field: name.to_string(),
            expected: "string".to_string(),
            actual: None,
        })
    }

    /// Get an integer value, returning an error if missing or unparseable.
    pub fn require_int(&self, name: &str) -> Result<i32, ConstraintDataError> {
        let value = self.map.get(name).ok_or_else(|| ConstraintDataError {
            field: name.to_string(),
            expected: "int".to_string(),
            actual: None,
        })?;
        value.parse::<i32>().map_err(|_| ConstraintDataError {
            field: name.to_string(),
            expected: "int".to_string(),
            actual: Some(value.clone()),
        })
    }

    /// Get a boolean value, returning an error if missing or unparseable.
    pub fn require_boolean(&self, name: &str) -> Result<bool, ConstraintDataError> {
        let value = self.map.get(name).ok_or_else(|| ConstraintDataError {
            field: name.to_string(),
            expected: "boolean".to_string(),
            actual: None,
        })?;
        match value.to_lowercase().as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(ConstraintDataError {
                field: name.to_string(),
                expected: "boolean".to_string(),
                actual: Some(value.clone()),
            }),
        }
    }
}

// ============================================================================
// Decision
// ============================================================================

/// The result of a successful constraint match in a decision tree.
///
/// Contains the property value, the path of constraint descriptions leading
/// to this decision, and the source file that contributed the value.
#[derive(Debug, Clone)]
pub struct Decision {
    /// The property value that was resolved.
    value: String,
    /// The chain of constraint descriptions leading to this decision.
    decision_path: Vec<String>,
    /// The source file that added this value.
    source: String,
}

impl Decision {
    pub fn new(value: String, decision_path: Vec<String>, source: String) -> Self {
        Self {
            value,
            decision_path,
            source,
        }
    }

    /// Returns the property value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the source file that contributed this decision.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the list of constraint descriptions forming the decision path.
    pub fn decision_path(&self) -> &[String] {
        &self.decision_path
    }

    /// Returns the decision path as a newline-separated string.
    pub fn decision_path_string(&self) -> String {
        self.decision_path.join("\n")
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]", self.value, self.source)
    }
}

// ============================================================================
// DecisionSet
// ============================================================================

/// A collection of decisions found by scanning a decision tree.
///
/// All decisions in the set share the same property name.
#[derive(Debug, Clone)]
pub struct DecisionSet {
    property_name: String,
    decisions: Vec<Decision>,
}

impl DecisionSet {
    pub fn new(property_name: String) -> Self {
        Self {
            property_name,
            decisions: Vec::new(),
        }
    }

    /// Returns the property name this decision set was searching for.
    pub fn property_name(&self) -> &str {
        &self.property_name
    }

    /// Add a decision to the set.
    pub fn add_decision(&mut self, decision: Decision) {
        self.decisions.push(decision);
    }

    /// Returns all decisions.
    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }

    /// Returns just the property values from all decisions.
    pub fn values(&self) -> Vec<&str> {
        self.decisions.iter().map(|d| d.value()).collect()
    }

    /// Returns `true` if no decisions were found.
    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }

    /// Returns the number of decisions.
    pub fn len(&self) -> usize {
        self.decisions.len()
    }
}

// ============================================================================
// DecisionNode
// ============================================================================

/// A node in a decision tree.
///
/// Each node contains a constraint, a map of property values, and child
/// nodes. When traversing with a test object, if the constraint is
/// satisfied, child nodes are tested. If no child produces a more specific
/// match, the current node's property value (if any) is used.
#[derive(Debug)]
pub struct DecisionNode<T> {
    /// The constraint at this node.
    constraint: Box<dyn Constraint<T>>,
    /// Property values stored at this node.
    property_map: HashMap<String, PropertyValue>,
    /// Child nodes.
    children: Vec<DecisionNode<T>>,
}

/// A stored property value with its source.
#[derive(Debug, Clone)]
struct PropertyValue {
    value: String,
    source: String,
}

impl<T> DecisionNode<T> {
    /// Create a new decision node with the given constraint.
    pub fn new(constraint: Box<dyn Constraint<T>>) -> Self {
        Self {
            constraint,
            property_map: HashMap::new(),
            children: Vec::new(),
        }
    }

    /// Get or create a child node for the given constraint.
    ///
    /// If a child with an equal constraint already exists, returns that child.
    /// Otherwise, creates a new child node.
    pub fn get_or_create_child(&mut self, constraint: Box<dyn Constraint<T>>) -> &mut DecisionNode<T> {
        let name = constraint.name().to_string();
        // Look for existing child with the same constraint name
        if let Some(idx) = self.children.iter().position(|c| c.constraint.name() == name) {
            return &mut self.children[idx];
        }
        self.children.push(DecisionNode::new(constraint));
        self.children.last_mut().unwrap()
    }

    /// Set a property value on this node.
    ///
    /// Returns an error if the property is already set.
    pub fn set_property(
        &mut self,
        name: &str,
        value: &str,
        source: &str,
    ) -> Result<(), String> {
        if self.property_map.contains_key(name) {
            return Err(format!(
                "Attempted to overwrite property value for {} in constraint node",
                name
            ));
        }
        self.property_map.insert(
            name.to_string(),
            PropertyValue {
                value: value.to_string(),
                source: source.to_string(),
            },
        );
        Ok(())
    }

    /// Populate decisions by recursively testing constraints.
    ///
    /// Returns `true` if a matching decision was found in this subtree.
    pub fn populate_decisions(
        &self,
        test_object: &T,
        decision_set: &mut DecisionSet,
        property_name: &str,
    ) -> bool {
        if !self.constraint.is_satisfied(test_object) {
            return false;
        }

        let mut found = false;
        for child in &self.children {
            found |= child.populate_decisions(test_object, decision_set, property_name);
        }

        // If no child found a more specific decision, check this node
        if !found {
            if let Some(pv) = self.property_map.get(property_name) {
                let path = self.get_decision_path();
                decision_set.add_decision(Decision::new(
                    pv.value.clone(),
                    path,
                    pv.source.clone(),
                ));
                found = true;
            }
        }

        found
    }

    /// Get the decision path from root to this node.
    fn get_decision_path(&self) -> Vec<String> {
        // For the generic node, we just return the constraint description.
        // RootDecisionNode overrides this to return an empty path.
        vec![self.constraint.description()]
    }

    /// Returns the constraint name.
    pub fn constraint_name(&self) -> &str {
        self.constraint.name()
    }

    /// Returns the number of child nodes.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Returns a reference to the child nodes.
    pub fn children(&self) -> &[DecisionNode<T>] {
        &self.children
    }
}

// ============================================================================
// RootDecisionNode
// ============================================================================

/// A special root node for a decision tree.
///
/// Root nodes don't have a real constraint; a dummy constraint that is
/// always satisfied is used instead. The decision path for a root node
/// is always empty.
pub struct RootDecisionNode<T> {
    inner: DecisionNode<T>,
}

/// A constraint that is always satisfied (used as the root node's constraint).
struct DummyConstraint;

impl<T> Constraint<T> for DummyConstraint {
    fn name(&self) -> &str {
        ""
    }

    fn is_satisfied(&self, _test_object: &T) -> bool {
        true
    }

    fn description(&self) -> String {
        String::new()
    }
}

impl<T> RootDecisionNode<T> {
    /// Create a new root decision node.
    pub fn new() -> Self {
        Self {
            inner: DecisionNode::new(Box::new(DummyConstraint)),
        }
    }

    /// Get or create a child node for the given constraint.
    pub fn get_or_create_child(&mut self, constraint: Box<dyn Constraint<T>>) -> &mut DecisionNode<T> {
        self.inner.get_or_create_child(constraint)
    }

    /// Set a property value on the root node.
    pub fn set_property(
        &mut self,
        name: &str,
        value: &str,
        source: &str,
    ) -> Result<(), String> {
        self.inner.set_property(name, value, source)
    }

    /// Populate decisions by recursively testing constraints.
    pub fn populate_decisions(
        &self,
        test_object: &T,
        decision_set: &mut DecisionSet,
        property_name: &str,
    ) -> bool {
        // Root node's dummy constraint is always satisfied, so just test children
        let mut found = false;
        for child in self.inner.children() {
            found |= child.populate_decisions(test_object, decision_set, property_name);
        }

        // Check root's own properties (default values)
        if !found {
            if let Some(pv) = self.inner.property_map.get(property_name) {
                decision_set.add_decision(Decision::new(
                    pv.value.clone(),
                    vec![],
                    pv.source.clone(),
                ));
                found = true;
            }
        }

        found
    }

    /// Returns the number of child nodes.
    pub fn child_count(&self) -> usize {
        self.inner.child_count()
    }

    /// Returns a reference to the child nodes.
    pub fn children(&self) -> &[DecisionNode<T>] {
        self.inner.children()
    }
}

impl<T> Default for RootDecisionNode<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DecisionTree
// ============================================================================

/// A tree of constraints used to find property values by traversal.
///
/// Each node in the tree has an associated constraint. If the constraint is
/// satisfied for a given test object, its child nodes are tested to find more
/// specific results. When no children match, the current node is checked for
/// a property value.
///
/// Multiple paths may match, producing multiple possible decisions.
///
/// # Examples
///
/// ```
/// use ghidra_core::generic::constraint::*;
/// use std::collections::HashMap;
///
/// // Create a simple constraint
/// struct IsPositive;
/// impl Constraint<i32> for IsPositive {
///     fn name(&self) -> &str { "IsPositive" }
///     fn is_satisfied(&self, t: &i32) -> bool { *t > 0 }
///     fn description(&self) -> String { "value is positive".to_string() }
/// }
///
/// struct IsLarge;
/// impl Constraint<i32> for IsLarge {
///     fn name(&self) -> &str { "IsLarge" }
///     fn is_satisfied(&self, t: &i32) -> bool { *t > 100 }
///     fn description(&self) -> String { "value is large".to_string() }
/// }
///
/// let mut tree: DecisionTree<i32> = DecisionTree::new();
/// // Build tree manually
/// let root = tree.root_mut();
/// let positive_node = root.get_or_create_child(Box::new(IsPositive));
/// positive_node.set_property("category", "positive", "test.xml").unwrap();
/// let large_node = positive_node.get_or_create_child(Box::new(IsLarge));
/// large_node.set_property("category", "large-positive", "test.xml").unwrap();
///
/// let decisions = tree.get_decisions(&150, "category");
/// assert_eq!(decisions.len(), 1);
/// assert_eq!(decisions.values()[0], "large-positive");
/// ```
pub struct DecisionTree<T> {
    root: RootDecisionNode<T>,
}

impl<T> DecisionTree<T> {
    /// Create a new empty decision tree.
    pub fn new() -> Self {
        Self {
            root: RootDecisionNode::new(),
        }
    }

    /// Returns a reference to the root node.
    pub fn root(&self) -> &RootDecisionNode<T> {
        &self.root
    }

    /// Returns a mutable reference to the root node.
    pub fn root_mut(&mut self) -> &mut RootDecisionNode<T> {
        &mut self.root
    }

    /// Search the tree for property values matching the constraints for the
    /// given test object.
    ///
    /// Returns a [`DecisionSet`] containing all matching decisions.
    pub fn get_decisions(&self, test_object: &T, property_name: &str) -> DecisionSet {
        let mut decision_set = DecisionSet::new(property_name.to_string());
        self.root
            .populate_decisions(test_object, &mut decision_set, property_name);
        decision_set
    }

    /// Returns the number of top-level children in the root.
    pub fn child_count(&self) -> usize {
        self.root.child_count()
    }
}

impl<T> Default for DecisionTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test constraints --

    struct IsPositive;
    impl Constraint<i32> for IsPositive {
        fn name(&self) -> &str {
            "IsPositive"
        }
        fn is_satisfied(&self, t: &i32) -> bool {
            *t > 0
        }
        fn description(&self) -> String {
            "value > 0".to_string()
        }
    }

    struct IsLarge;
    impl Constraint<i32> for IsLarge {
        fn name(&self) -> &str {
            "IsLarge"
        }
        fn is_satisfied(&self, t: &i32) -> bool {
            *t > 100
        }
        fn description(&self) -> String {
            "value > 100".to_string()
        }
    }

    struct IsEven;
    impl Constraint<i32> for IsEven {
        fn name(&self) -> &str {
            "IsEven"
        }
        fn is_satisfied(&self, t: &i32) -> bool {
            *t % 2 == 0
        }
        fn description(&self) -> String {
            "value is even".to_string()
        }
    }

    // -- ConstraintData tests --

    #[test]
    fn test_constraint_data_string() {
        let mut map = HashMap::new();
        map.insert("name".to_string(), "foo".to_string());
        let data = ConstraintData::new(map);
        assert_eq!(data.get_string("name"), Some("foo"));
        assert!(data.has_value("name"));
        assert!(!data.has_value("missing"));
    }

    #[test]
    fn test_constraint_data_int() {
        let mut map = HashMap::new();
        map.insert("count".to_string(), "42".to_string());
        map.insert("bad".to_string(), "abc".to_string());
        let data = ConstraintData::new(map);
        assert_eq!(data.get_int("count"), Some(42));
        assert_eq!(data.get_int("bad"), None);
        assert_eq!(data.get_int("missing"), None);
    }

    #[test]
    fn test_constraint_data_boolean() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), "true".to_string());
        map.insert("b".to_string(), "FALSE".to_string());
        map.insert("c".to_string(), "yes".to_string());
        let data = ConstraintData::new(map);
        assert_eq!(data.get_boolean("a"), Some(true));
        assert_eq!(data.get_boolean("b"), Some(false));
        assert_eq!(data.get_boolean("c"), None);
    }

    #[test]
    fn test_constraint_data_long() {
        let mut map = HashMap::new();
        map.insert("big".to_string(), "9999999999".to_string());
        let data = ConstraintData::new(map);
        assert_eq!(data.get_long("big"), Some(9999999999i64));
    }

    #[test]
    fn test_constraint_data_float_double() {
        let mut map = HashMap::new();
        map.insert("f".to_string(), "3.14".to_string());
        map.insert("d".to_string(), "2.718".to_string());
        let data = ConstraintData::new(map);
        assert!((data.get_float("f").unwrap() - 3.14).abs() < 0.001);
        assert!((data.get_double("d").unwrap() - 2.718).abs() < 0.001);
    }

    #[test]
    fn test_constraint_data_require() {
        let mut map = HashMap::new();
        map.insert("name".to_string(), "foo".to_string());
        map.insert("count".to_string(), "42".to_string());
        map.insert("enabled".to_string(), "true".to_string());
        let data = ConstraintData::new(map);

        assert_eq!(data.require_string("name").unwrap(), "foo");
        assert_eq!(data.require_int("count").unwrap(), 42);
        assert!(data.require_boolean("enabled").unwrap());
        assert!(data.require_string("missing").is_err());
        assert!(data.require_int("name").is_err());
    }

    #[test]
    fn test_constraint_data_from_pairs() {
        let data = ConstraintData::from_pairs(vec![
            ("a", "1"),
            ("b", "2"),
        ]);
        assert_eq!(data.get_int("a"), Some(1));
        assert_eq!(data.get_int("b"), Some(2));
    }

    // -- Decision tests --

    #[test]
    fn test_decision_new() {
        let d = Decision::new(
            "value1".to_string(),
            vec!["path1".to_string(), "path2".to_string()],
            "test.xml".to_string(),
        );
        assert_eq!(d.value(), "value1");
        assert_eq!(d.source(), "test.xml");
        assert_eq!(d.decision_path().len(), 2);
        assert_eq!(d.decision_path_string(), "path1\npath2");
    }

    #[test]
    fn test_decision_display() {
        let d = Decision::new(
            "val".to_string(),
            vec![],
            "src.xml".to_string(),
        );
        let s = format!("{}", d);
        assert!(s.contains("val"));
        assert!(s.contains("src.xml"));
    }

    // -- DecisionSet tests --

    #[test]
    fn test_decision_set_empty() {
        let ds = DecisionSet::new("prop".to_string());
        assert!(ds.is_empty());
        assert_eq!(ds.len(), 0);
        assert_eq!(ds.property_name(), "prop");
        assert!(ds.values().is_empty());
    }

    #[test]
    fn test_decision_set_add() {
        let mut ds = DecisionSet::new("prop".to_string());
        ds.add_decision(Decision::new("v1".to_string(), vec![], "s1".to_string()));
        ds.add_decision(Decision::new("v2".to_string(), vec![], "s2".to_string()));
        assert_eq!(ds.len(), 2);
        assert_eq!(ds.values(), vec!["v1", "v2"]);
    }

    // -- DecisionNode tests --

    #[test]
    fn test_decision_node_basic() {
        let node = DecisionNode::<i32>::new(Box::new(IsPositive));
        assert_eq!(node.constraint_name(), "IsPositive");
        assert_eq!(node.child_count(), 0);
    }

    #[test]
    fn test_decision_node_set_property() {
        let mut node = DecisionNode::<i32>::new(Box::new(IsPositive));
        node.set_property("cat", "pos", "src").unwrap();
        // Duplicate should error
        assert!(node.set_property("cat", "other", "src").is_err());
    }

    // -- DecisionTree tests --

    #[test]
    fn test_decision_tree_empty() {
        let tree = DecisionTree::<i32>::new();
        let ds = tree.get_decisions(&42, "prop");
        assert!(ds.is_empty());
    }

    #[test]
    fn test_decision_tree_single_level() {
        let mut tree = DecisionTree::<i32>::new();
        let root = tree.root_mut();
        let pos = root.get_or_create_child(Box::new(IsPositive));
        pos.set_property("category", "positive", "test.xml").unwrap();

        // Positive value matches
        let ds = tree.get_decisions(&42, "category");
        assert_eq!(ds.len(), 1);
        assert_eq!(ds.values()[0], "positive");

        // Negative value does not match
        let ds = tree.get_decisions(&-5, "category");
        assert!(ds.is_empty());
    }

    #[test]
    fn test_decision_tree_nested() {
        let mut tree = DecisionTree::<i32>::new();
        let root = tree.root_mut();
        let pos = root.get_or_create_child(Box::new(IsPositive));
        pos.set_property("category", "positive", "test.xml").unwrap();
        let large = pos.get_or_create_child(Box::new(IsLarge));
        large
            .set_property("category", "large-positive", "test.xml")
            .unwrap();

        // Small positive: matches "positive" (no child match)
        let ds = tree.get_decisions(&42, "category");
        assert_eq!(ds.len(), 1);
        assert_eq!(ds.values()[0], "positive");

        // Large positive: matches "large-positive" (child match takes priority)
        let ds = tree.get_decisions(&200, "category");
        assert_eq!(ds.len(), 1);
        assert_eq!(ds.values()[0], "large-positive");
    }

    #[test]
    fn test_decision_tree_multiple_paths() {
        let mut tree = DecisionTree::<i32>::new();
        let root = tree.root_mut();

        let pos = root.get_or_create_child(Box::new(IsPositive));
        pos.set_property("kind", "positive", "a.xml").unwrap();

        let even = root.get_or_create_child(Box::new(IsEven));
        even.set_property("kind", "even", "b.xml").unwrap();

        // 4 is both positive and even -> two decisions
        let ds = tree.get_decisions(&4, "kind");
        assert_eq!(ds.len(), 2);
    }

    #[test]
    fn test_decision_tree_default_at_root() {
        let mut tree = DecisionTree::<i32>::new();
        let root = tree.root_mut();
        root.set_property("mode", "default", "root.xml").unwrap();

        // Should get root's default
        let ds = tree.get_decisions(&42, "mode");
        assert_eq!(ds.len(), 1);
        assert_eq!(ds.values()[0], "default");
    }

    #[test]
    fn test_root_decision_node_default() {
        let root = RootDecisionNode::<i32>::default();
        assert_eq!(root.child_count(), 0);
    }
}
